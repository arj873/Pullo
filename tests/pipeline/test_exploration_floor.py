"""EXPLORE-FLOOR: the engine-enforced exploration floor of investigator.impact@v2, through the real engine, contracts,
gateway (scripted synthetic provider) and tools.

Invented self-contained fixtures only: no network, key, state, target repository or live call. These tests prove the
mechanics (when the floor triggers, the one fixed continuation, the draft fallback, caps, trace events, identity and
strict replay). They do NOT show that a real model explores more: that is an empirical question for an admitted run."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from reviewer.contracts import validate
from reviewer.contracts.budget import HOST_STOP_RECORDING
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, prompts, retrieval

from tests.pipeline.helpers import (TURN_PLAN, entry, events_of, hid, hyp, ifinal, iturn, judge, model_calls, script,
                                    terr, tool_calls, treq, vfinal)
from tests.pipeline.test_impact_pipeline import IMPACT_PROFILE, POLICY, ImpactRig, doc_of, tcid, w

INV2, VER = prompts.INVESTIGATOR_IMPACT_V2_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
V2_PROFILE = copy.deepcopy(IMPACT_PROFILE)
V2_PROFILE["roles"]["investigator"]["promptVersion"] = INV2
V2_POLICY = RetrievalPolicy(investigator_prompt=INV2, verifier_prompt=VER)

# The impact@v1 first investigator request and config identity of ImpactRig.cross_file_script, recorded from the
# pre-change source (origin/main 754413cd). v1 must stay byte-identical.
V1_FIRST_REQUEST_HASH = "sha256:2d052c809a7adf45a7c3933723c27524174ba5dc4213a089fe44f5ea3becb3fd"
V1_CONFIG_SNAPSHOT_ID = "sha256:560ffbd6d5b95c57410371cb5e154d8ee189a3b6908153e2d1c417b5691a7d73"


def floors(res):
    return [{k: e[k] for k in ("decision", "draftCallId", "finalCallId", "reason", "errorCode") if k in e}
            for e in events_of(res) if e["type"] == "retrieval.floor"]


def inv_calls(res):
    return [e for e in model_calls(res, "INVESTIGATE") if e["role"] == "investigator"]


def call_of(res, ordinal):
    return next(e["callId"] for e in inv_calls(res) if e["ordinal"] == ordinal and e["response"] is not None)


def draft_view(h):
    return {k: h[k] for k in ("claim", "category", "suspectedSeverity", "impact", "location", "mechanism", "reach",
                              "confidence", "evidence") if k in h}


class FloorRig(ImpactRig):
    def record_v2(self, m, scr, **kw):
        kw.setdefault("profile", V2_PROFILE)
        kw.setdefault("retrieval", V2_POLICY)
        return self.record_turn(m, scr, **kw)

    def draft(self, m):
        return hyp(m, "src/lib.py", 1, claim="load_user dropped the cache default", category="breaking-change",
                   impact="crash", evidence=[m.cite("src/lib.py", 1)])

    def cross(self, m):
        return hyp(m, "src/lib.py", 1, claim="load_user no longer has a default for cache; Profile.show calls it with "
                   "one argument", category="breaking-change", impact="crash",
                   mechanism="src/use.py:6 calls load_user(uid) without cache/region: TypeError",
                   evidence=[m.cite("src/lib.py", 1), m.cite("src/use.py", 6)])

    def floor_script(self, m):
        """Hop-0 draft, then the continuation chain: find_references + read the dependent, then a cross-file final."""
        d, h = self.draft(m), self.cross(m)
        scr = script(
            ifinal(0, d),
            iturn(1, [treq("find_references", side="head", symbol="load_user"),
                      treq("read_file", side="head", path="src/use.py", start_line=1, end_line=7)]),
            ifinal(2, h),
            vfinal(0, m, path="src/lib.py", line=1),
            judge(w([hid(0, h)])))
        return scr, d, h


class FloorTriggers(FloorRig):
    def test_turn_one_final_is_a_draft_one_continuation_is_sent_and_the_second_final_is_used(self):
        m = self.case()
        scr, d, h = self.floor_script(m)
        res, spy = self.record_v2(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        calls = inv_calls(res)
        self.assertEqual([(c["ordinal"], c["request"]["hop"]) for c in calls], [(0, 0), (1, 0), (2, 1)])
        # the continuation is a fresh chain of the same agent: hop 0, the same host-prepared context, no continuationOf
        self.assertNotIn("continuationOf", calls[1]["request"])
        self.assertEqual(calls[1]["request"]["contextResults"], calls[0]["request"]["contextResults"])
        self.assertEqual(calls[2]["request"]["continuationOf"], calls[1]["callId"])
        first, cont = doc_of(spy.requests[0]), doc_of(spy.requests[1])
        self.assertEqual(first["task"], prompts.INVESTIGATOR_IMPACT_V2_TASK)
        self.assertNotIn("explorationFloor", first)
        self.assertEqual(cont["explorationFloor"], {"version": "exploration-floor@1",
                                                    "instruction": prompts.EXPLORATION_FLOOR_CONTINUATION,
                                                    "draftHypotheses": [draft_view(d)]})
        # otherwise the very same document (same context, budgets and citable refs), but only the turns left
        self.assertEqual((first["retrieval"]["turnsAllowed"], cont["retrieval"]["turnsAllowed"]),
                         (V2_POLICY.investigator_turns, V2_POLICY.investigator_turns - 1))
        same = lambda doc: {k: v if k != "retrieval" else {**v, "turnsAllowed": None}      # noqa: E731
                            for k, v in doc.items() if k != "explorationFloor"}
        self.assertEqual(same(cont), same(first))
        # exactly one continuation chain
        self.assertEqual(sum(1 for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0
                             and "explorationFloor" in doc_of(r)), 1)
        self.assertEqual(floors(res), [{"decision": "continue", "draftCallId": call_of(res, 0)},
                                       {"decision": "final", "draftCallId": call_of(res, 0),
                                        "finalCallId": call_of(res, 2)}])
        hyps = res.hypotheses
        self.assertEqual([(x["claim"], x["sourceCallId"]) for x in hyps], [(h["claim"], call_of(res, 2))])
        self.assertEqual(len(res.findings), 1)
        self.assertEqual({e["path"] for e in res.findings[0]["evidence"]}, {"src/lib.py", "src/use.py"})

    def test_a_second_first_hop_final_is_accepted_as_it_stands(self):
        m = self.case()
        d = self.draft(m)
        res, spy = self.record_v2(m, script(ifinal(0, d), ifinal(1), judge()))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(len(inv_calls(res)), 2)                      # at most once per agent: no third call
        self.assertEqual([f["decision"] for f in floors(res)], ["continue", "final"])
        self.assertEqual(res.hypotheses, [])     # it may drop the draft

    def test_the_draft_may_be_repeated_and_keeps_its_citations(self):
        m = self.case()
        d = self.draft(m)
        res, _ = self.record_v2(m, script(ifinal(0, d), ifinal(1, d), vfinal(0, m, path="src/lib.py", line=1),
                                          judge(w([hid(0, d)]))))
        self.assertEqual(res.status, "completed", res.incomplete)
        hyps = res.hypotheses
        self.assertEqual([x["sourceCallId"] for x in hyps], [call_of(res, 1)])
        self.assertEqual(len(res.findings), 1)

    def test_no_floor_when_the_model_requested_context_first(self):
        m = self.case()
        d = self.draft(m)
        res, spy = self.record_v2(m, script(iturn(0, [treq("find_references", side="head", symbol="load_user")]),
                                            ifinal(1, d), vfinal(0, m, path="src/lib.py", line=1),
                                            judge(w([hid(0, d)]))))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(floors(res), [])
        self.assertFalse(any("explorationFloor" in doc_of(r) for r in spy.requests))
        self.assertEqual(len(inv_calls(res)), 2)

    def test_impact_v1_never_triggers_the_floor(self):
        m = self.case()
        d = self.draft(m)
        res, spy = self.record_impact(m, script(ifinal(0, d), vfinal(0, m, path="src/lib.py", line=1),
                                                judge(w([hid(0, d)]))))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(floors(res), [])
        self.assertEqual(len(inv_calls(res)), 1)
        self.assertEqual(doc_of(spy.requests[0])["task"], prompts.INVESTIGATOR_IMPACT_TASK)


class FloorFallback(FloorRig):
    def test_a_failed_continuation_falls_back_to_the_draft_and_discloses_it(self):
        m = self.case()
        d = self.draft(m)
        fail = [entry("INVESTIGATE", "investigator", "generalist", 1, a, error=terr("provider-error", "INVESTIGATE"))
                for a in range(3)]
        res, spy = self.record_v2(m, script(ifinal(0, d), *fail, vfinal(0, m, path="src/lib.py", line=1),
                                            judge(w([hid(0, d)]))))
        self.assertEqual(res.status, "partial")
        self.assertEqual(validate_trace(events_of(res)), [])
        draft_id = call_of(res, 0)
        self.assertEqual(floors(res), [{"decision": "continue", "draftCallId": draft_id},
                                       {"decision": "draft", "draftCallId": draft_id, "reason": "call-failed",
                                        "errorCode": "provider-error"}])
        hyps = res.hypotheses
        self.assertEqual([(x["claim"], x["sourceCallId"]) for x in hyps], [(d["claim"], draft_id)])
        inc = [i for i in res.incomplete if i["stage"] == "INVESTIGATE"]
        self.assertEqual([i["reason"] for i in inc], ["agent-failure"])
        self.assertIn("draft answer (1 hypothesis(es)) was used", inc[0]["detail"])
        self.assertEqual(len(res.findings), 1)                       # never lose the draft's findings
        self.assertEqual(len(res.comments), 1)

    def test_exhausted_continuation_turns_fall_back_to_the_draft(self):
        m = self.case()
        d = self.draft(m)
        pol = V2_POLICY.tightened(investigator_turns=3)              # the continuation chain gets the 2 turns left
        scr = script(ifinal(0, d),
                     iturn(1, [treq("find_references", side="head", symbol="load_user")]),
                     iturn(2, [treq("read_file", side="head", path="src/use.py")]),
                     vfinal(0, m, path="src/lib.py", line=1), judge(w([hid(0, d)])))
        res, spy = self.record_v2(m, scr, retrieval=pol)
        self.assertEqual(res.status, "partial")
        self.assertEqual(len(inv_calls(res)), 3)                     # the total turn cap (3) holds across both chains
        self.assertTrue(doc_of(spy.requests[2])["retrieval"]["lastTurn"])
        self.assertEqual(floors(res)[-1], {"decision": "draft", "draftCallId": call_of(res, 0), "reason": "turns"})
        self.assertEqual([i["reason"] for i in res.incomplete if i["stage"] == "INVESTIGATE"],
                         ["tool-calls-exhausted"])
        self.assertEqual([x["sourceCallId"] for x in res.hypotheses],
                         [call_of(res, 0)])
        self.assertEqual(len(res.findings), 1)

    def test_no_budget_left_skips_the_floor_and_the_draft_is_final(self):
        m = self.case()
        d = self.draft(m)
        for name, pol, reason in (("turns", V2_POLICY.tightened(investigator_turns=2), "turns"),
                                  ("tools", V2_POLICY.tightened(agent_tool_calls=0), "tool-calls"),
                                  ("context", V2_POLICY.tightened(context_chars=10), "context-chars")):
            with self.subTest(name):
                res, _ = self.record_v2(m, script(ifinal(0, d), vfinal(0, m, path="src/lib.py", line=1),
                                                  judge(w([hid(0, d)]))), retrieval=pol,
                                        eval_id="evr_" + {"turns": "4", "tools": "5", "context": "6"}[name] * 16)
                self.assertEqual(res.status, "completed", res.incomplete)
                self.assertEqual(len(inv_calls(res)), 1)
                self.assertEqual(floors(res), [{"decision": "skipped", "draftCallId": call_of(res, 0),
                                                "reason": reason}])
                self.assertEqual(len(res.findings), 1)

    def test_a_stage_deadline_during_the_continuation_falls_back_and_replays(self):
        m = self.case()
        d = self.draft(m)
        plan = copy.deepcopy(TURN_PLAN)
        plan["budget"].update(stageCeilingsSec={"INVESTIGATE": 40}, hostStopRecording=HOST_STOP_RECORDING)
        self.clock = lambda: 50.0 * (self.spies[-1].calls if self.spies else 0)
        res, spy = self.record_v2(m, script(ifinal(0, d), vfinal(0, m, path="src/lib.py", line=1),
                                            judge(w([hid(0, d)]))), plan=plan)
        self.assertEqual(len(inv_calls(res)), 1)                     # stopped before the continuation call
        self.assertEqual(floors(res)[-1], {"decision": "draft", "draftCallId": call_of(res, 0), "reason": "stopped",
                                           "errorCode": "deadline-exceeded"})
        self.assertEqual([i["reason"] for i in res.incomplete if i["stage"] == "INVESTIGATE"], ["deadline"])
        self.assertEqual(len(res.findings), 1)
        rep = self.replay(m, res, profile=V2_PROFILE, plan=plan, retrieval=V2_POLICY)
        self.assertEqual((rep.status, rep.error), (res.status, None))
        self.assertEqual(floors(rep), floors(res))


class FloorCaps(FloorRig):
    def test_continuation_tool_calls_count_against_the_same_agent_budget(self):
        m = self.case()
        d = self.draft(m)
        pol = V2_POLICY.tightened(agent_tool_calls=1)
        scr = script(ifinal(0, d),
                     iturn(1, [treq("find_references", side="head", symbol="load_user"),
                               treq("read_file", side="head", path="src/use.py", start_line=1, end_line=7)]),
                     ifinal(2, d), vfinal(0, m, path="src/lib.py", line=1), judge(w([hid(0, d)])))
        res, spy = self.record_v2(m, scr, retrieval=pol)
        self.assertEqual(res.status, "completed", res.incomplete)
        inv_tools = [e for e in tool_calls(res, "INVESTIGATE")]
        self.assertEqual([(e["ordinal"], e["tool"], e["result"]["status"]) for e in inv_tools],
                         [(0, "find_references", "ok"), (1, "read_file", "unavailable")])
        self.assertEqual(doc_of(spy.requests[2])["retrieval"]["toolCallsRemaining"], 0)
        summary = retrieval.summarize(events_of(res))
        inv = [c for c in summary["chains"] if c["role"] == "investigator"]
        self.assertEqual([(c["hops"], c["requestedToolCalls"], c["final"]) for c in inv], [(1, 0, True), (2, 2, True)])

    def test_the_continuation_obeys_the_per_turn_request_cap(self):
        m = self.case()
        d = self.draft(m)
        pol = V2_POLICY.tightened(requests_per_turn=1)
        scr = script(ifinal(0, d),
                     iturn(1, [treq("find_references", side="head", symbol="load_user"),
                               treq("read_file", side="head", path="src/use.py")]),
                     ifinal(2, d), vfinal(0, m, path="src/lib.py", line=1), judge(w([hid(0, d)])))
        res, _ = self.record_v2(m, scr, retrieval=pol)
        self.assertEqual([e["result"]["status"] for e in tool_calls(res, "INVESTIGATE")], ["ok", "denied"])


class FloorIdentityAndReplay(FloorRig):
    def test_strict_replay_reproduces_the_floor_its_events_and_outputs(self):
        m = self.case()
        scr, _, _ = self.floor_script(m)
        res, _ = self.record_v2(m, scr)
        rep = self.replay(m, res, profile=V2_PROFILE, plan=TURN_PLAN, retrieval=V2_POLICY)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(floors(rep), floors(res))
        self.assertEqual(rep.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
        body = lambda r: Path(r.review_path).read_text(encoding="utf-8").replace(r.run_id, "R").split("## Cost")[0]  # noqa: E731
        self.assertEqual(body(rep), body(res))

    def test_strict_replay_of_a_draft_fallback(self):
        m = self.case()
        d = self.draft(m)
        fail = [entry("INVESTIGATE", "investigator", "generalist", 1, a, error=terr("provider-error", "INVESTIGATE"))
                for a in range(3)]
        res, _ = self.record_v2(m, script(ifinal(0, d), *fail, vfinal(0, m, path="src/lib.py", line=1),
                                          judge(w([hid(0, d)]))))
        rep = self.replay(m, res, profile=V2_PROFILE, plan=TURN_PLAN, retrieval=V2_POLICY)
        self.assertEqual((rep.status, rep.error), ("partial", None))
        self.assertEqual(floors(rep), floors(res))
        self.assertEqual(len(rep.findings), 1)

    def test_a_v2_recording_does_not_replay_under_v1(self):
        m = self.case()
        scr, _, _ = self.floor_script(m)
        res, _ = self.record_v2(m, scr)
        with self.assertRaises(PipelineError) as c:
            self.replay(m, res, profile=IMPACT_PROFILE, plan=TURN_PLAN, retrieval=POLICY)
        self.assertEqual(c.exception.code, "identity-mismatch")

    def test_v2_is_bound_into_the_config_identity_and_v1_identity_and_first_request_are_unchanged(self):
        m = self.case()
        s1, _ = self.cross_file_script(m)
        v1, spy1 = self.record_impact(m, s1)
        self.assertEqual(v1.status, "completed", v1.incomplete)
        self.assertEqual(model_calls(v1, "INVESTIGATE")[0]["requestHash"], V1_FIRST_REQUEST_HASH)
        self.assertEqual(v1.run["configSnapshotId"], V1_CONFIG_SNAPSHOT_ID)
        self.assertEqual(floors(v1), [])
        s2, _ = self.cross_file_script(m)
        v2, spy2 = self.record_v2(m, s2, eval_id="evr_" + "3" * 16)
        self.assertNotEqual(v2.run["configSnapshotId"], v1.run["configSnapshotId"])
        a, b = doc_of(spy1.requests[0]), doc_of(spy2.requests[0])
        self.assertEqual({k: v for k, v in a.items() if k != "task"}, {k: v for k, v in b.items() if k != "task"})
        self.assertEqual((a["task"], b["task"]), (prompts.INVESTIGATOR_IMPACT_TASK, prompts.INVESTIGATOR_IMPACT_V2_TASK))
        self.assertEqual(spy2.requests[0]["promptVersion"], INV2)

    def test_templates_v1_digests_frozen_and_v2_adds_the_floor_text(self):
        v1 = prompts.impact_template_digests()
        self.assertEqual(v1, prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_PROMPT))
        self.assertEqual(set(v1), {"investigator", "verifier", "tools"})
        v2 = prompts.impact_template_digests(INV2)
        self.assertEqual(set(v2), {"investigator", "verifier", "tools", "floor"})
        self.assertEqual((v2["verifier"], v2["tools"]), (v1["verifier"], v1["tools"]))
        self.assertNotEqual(v2["investigator"], v1["investigator"])
        self.assertTrue(prompts.INVESTIGATOR_IMPACT_V2_TASK.startswith(prompts.INVESTIGATOR_IMPACT_TASK))
        self.assertIn("DRAFT", prompts.INVESTIGATOR_IMPACT_V2_TASK)
        self.assertEqual(prompts.investigator_task(INV2), prompts.INVESTIGATOR_IMPACT_V2_TASK)
        self.assertEqual(identity.FLOOR_BEHAVIOR, "exploration-floor-pipeline@1")

    def test_floor_event_contract(self):
        base = {"schema": "trace-event@1", "runId": "run_" + "a" * 16, "seq": 3, "type": "retrieval.floor",
                "stage": "INVESTIGATE", "agentId": "generalist", "version": "exploration-floor@1",
                "draftCallId": "call_" + "b" * 16}
        ok = [dict(decision="continue"), dict(decision="skipped", reason="turns"),
              dict(decision="final", finalCallId="call_" + "c" * 16),
              dict(decision="draft", reason="turns"),
              dict(decision="draft", reason="call-failed", errorCode="provider-error")]
        bad = [dict(decision="final"), dict(decision="continue", reason="turns"),
               dict(decision="skipped", reason="call-failed", errorCode="provider-error"),
               dict(decision="draft", reason="call-failed"), dict(decision="draft", reason="turns", errorCode="internal"),
               dict(decision="final", finalCallId="call_" + "b" * 16), dict(decision="draft"),
               dict(decision="continue", stage="VERIFY")]
        for extra in ok:
            self.assertEqual(validate("TraceEvent", {**base, **extra}), [], extra)
        for extra in bad:
            self.assertNotEqual(validate("TraceEvent", {**base, **extra}), [], extra)


if __name__ == "__main__":
    import unittest
    unittest.main()
