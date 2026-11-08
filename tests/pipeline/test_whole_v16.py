"""V16 SIMPLE BASELINE: investigator.impact@v16 = ONE whole-change reviewer (reviewer.pipeline.whole): the PR text, the
diff of every changed file and the changed files' head content in one bounded request, at most 4 hops and 12 reads, at
most 15 hypotheses; then v12's VERIFY (one verifier session per candidate, cap 20) and JUDGE (dynamic cap); a chain that
ends out of schema is asked once more in a new session (schema-reask@1).

Invented self-contained fixtures (the v12 rig), a scripted synthetic provider, the real engine, contracts, gateway and
tools. No network, key, state or live call. These tests prove the mechanics; they do NOT show that a real model finds
more real defects."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from reviewer.config import resolve_config
from reviewer.contracts import validate
from reviewer.contracts.canonical import digest
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, deepcov, identity, prompts, whole
from reviewer.pipeline import load_result

from tests.pipeline.helpers import entry, events_of, hyp, judge, model_calls, resp, script, terr, tool_calls
from tests.pipeline.test_coverage_v12 import (CORE_HEAD, ELIGIBLE, ROOT, SKIPPED, V12_PLAN, V12Rig, final, hid,
                                              inv_calls, md_of, payload, rf, turn, vdone)
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PROFILE

INV16, VER = prompts.INVESTIGATOR_IMPACT_V16_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
V16_PROFILE = copy.deepcopy(V3_PROFILE)
V16_PROFILE["roles"]["investigator"]["promptVersion"] = INV16
V16_POLICY = RetrievalPolicy(investigator_prompt=INV16, verifier_prompt=VER, run_tool_calls=400)
V16_PLAN = copy.deepcopy(V12_PLAN)
V16_PLAN["specialists"] = whole.plan_specialists()
A, R = whole.AGENT, whole.AGENT + whole.REASK_SUFFIX


def bad_turn(agent, ordinal, stage="INVESTIGATE", role="investigator"):
    """An answer out of schema, and its one gateway repair out of schema too: the call ends repair-exhausted."""
    return [entry(stage, role, agent, ordinal, a, response=resp(None, status="invalid-output", raw="{half"))
            for a in (0, 1)]


class V16Rig(V12Rig):
    def record_v16(self, m, scr, **kw):
        kw.setdefault("profile", V16_PROFILE)
        kw.setdefault("retrieval", V16_POLICY)
        kw.setdefault("plan", V16_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v16(self, m, res, **kw):
        kw.setdefault("profile", V16_PROFILE)
        kw.setdefault("retrieval", V16_POLICY)
        kw.setdefault("plan", V16_PLAN)
        return self.replay(m, res, **kw)

    def reviewer(self, agent, hyps):
        """One request turn of three reads, then the answer."""
        return [turn(agent, 0, [rf("src/use.py", 1, 7), rf("src/handlers/a.py"), rf("src/svc.py", 1, 5)]),
                final(agent, 1, *hyps)]

    def e2e(self, m, verifiers=None, judged=(0, 1, 2)):
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = self.reviewer(A, [hl, hb, hs])
        e += verifiers if verifiers is not None else [
            vdone("verifier-01", m, path="src/lib.py", line=1), vdone("verifier-02", m, path="src/handlers/b.py", line=2),
            vdone("verifier-03", m, path="src/svc.py", line=2)]
        e += [judge(*[w([hid(A, n, h)]) for n, h in enumerate((hl, hb, hs)) if n in judged])]
        return script(*e), (hl, hb, hs)


def comments_of(res):
    return json.loads((Path(res.run_dir) / "comments.json").read_text())["comments"]


# ---------------------------------------------------------------- 1. pure rules

class Rules(unittest.TestCase):
    def test_plan_profile_policy_identity(self):
        from reviewer.pilot import repository_profile as RP
        self.assertEqual(RP.IMPACT_VERSIONS[16], INV16)
        t = resolve_config(ROOT / "pullo-terra.toml").models
        p12, p16 = RP.repository_profile(True, t, impact_version=12), RP.repository_profile(True, t, impact_version=16)
        self.assertEqual(validate("ModelProfile", p16), [])
        self.assertEqual(dict(p16, roles=None), dict(p12, roles=None))
        self.assertEqual(p16["roles"]["investigator"]["promptVersion"], INV16)
        for live in (True, False):                                           # v12's clocks, caps and ceiling
            a, b = RP.repository_plan(p12, live_stage_timing=live), RP.repository_plan(p16, live_stage_timing=live)
            self.assertEqual(validate("Plan", b), [])
            self.assertEqual(a["budget"], b["budget"])
            self.assertEqual(b["budget"]["maxUsdMicros"], 4_000_000)
            self.assertEqual(b["specialists"], ["whole"])
            self.assertIn("investigator.impact@v16: one whole-change reviewer", b["reasons"][1])
        pol = RP.repository_policy(True, impact_version=16)
        self.assertEqual((pol.whole_change, pol.specialists, pol.coverage_forced, pol.exploration_floor, pol.impact,
                          pol.run_tool_calls), (True, None, False, False, True, 400))
        self.assertFalse(any(RP.repository_policy(True, impact_version=v).whole_change for v in (1, 2, 3, 4, 5, 7, 10, 12)))
        with self.assertRaises(Exception):                                    # primary investigator model only
            RP.repository_plan(dict(p16, alternates={"investigator": p16["roles"]["investigator"]}))
        t16 = prompts.impact_template_digests(INV16)
        self.assertEqual({k: v for k, v in t16.items() if k != "wholeChange"},
                         prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_PROMPT))
        d = whole.identity_doc(V16_POLICY, V16_PLAN["budget"], 50, 5)
        self.assertEqual((d["context"]["chars"], d["turns"], d["verify"]["maxVerify"], d["reask"]["codes"]),
                         (150_000, {"hops": 4, "reads": 12, "maxHypotheses": 15}, 20,
                          ["schema-invalid", "repair-exhausted"]))

    def test_diff_selection_head_plan_and_read_ranges(self):
        self.assertEqual(whole.select_diffs([("a", 50), ("b", 60), ("c", 10), ("d", 60)], 70),
                         (["a", "c"], [{"path": "b", "chars": 60}, {"path": "d", "chars": 60}]))
        self.assertEqual(whole.select_diffs([("a", 5)], 5), (["a"], []))
        rows = whole.head_plan([("big", [10] * 100), ("small", [10] * 3), ("mid", [10] * 20)], 400)
        self.assertEqual([(r["path"], r["shownLines"], r["lines"]) for r in rows],     # smallest whole, then equal shares
                         [("big", 19, 100), ("small", 3, 3), ("mid", 18, 20)])
        self.assertLessEqual(sum(r["chars"] for r in rows), 400)
        self.assertEqual(whole.head_plan([("a", [5, 5])], 0), [{"path": "a", "lines": 2, "shownLines": 0, "chars": 0}])
        lines = ["x"] * 900 + [""] + ["y"] * 99
        self.assertEqual(whole.read_ranges(lines, 1000), [(1, 400), (401, 800), (801, 1000)])
        lines = ["x"] * 399 + [""] + ["y"] * 10                                    # a read never ends on a blank line
        self.assertEqual(whole.read_ranges(lines, 410), [(1, 399), (401, 410)])
        self.assertEqual(whole.read_ranges(lines, 405), [(1, 399), (401, 405)])     # only the shown prefix
        self.assertEqual(whole.read_ranges(["a", "", ""], 3), [(1, 1)])           # never ends on a blank line
        wide = ["z" * 9_999] * 5                                                    # READ_CHARS binds before READ_LINES
        self.assertEqual(whole.read_ranges(wide, 5), [(1, 2), (3, 4), (5, 5)])
        self.assertEqual(whole.read_ranges(["q" * 30_000], 1), [(1, 1)])          # one over-long line: its own read


# ---------------------------------------------------------------- 2. end to end

class EndToEnd(V16Rig):
    def test_one_reviewer_then_per_candidate_verify_and_the_dynamic_cap(self):
        m = self.case12()
        scr, (hl, hb, hs) = self.e2e(m)
        res, spy = self.record_v16(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual({e["agentId"] for e in inv_calls(res)}, {A})
        inv = payload(res, "INVESTIGATE")
        self.assertEqual([h["specialist"] for h in inv["hypotheses"]], [A, A, A])
        self.assertNotIn("merges", inv)
        self.assertEqual(inv["agents"], [{"agentId": A, "specialist": A, "status": "completed"}])
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")], ["verifier-01", "verifier-02", "verifier-03"])
        self.assertEqual(len(comments_of(res)), 3)
        md = md_of(res)
        self.assertIn("## Whole-change review", md)
        self.assertIn("one reviewer `whole`", md)
        self.assertNotIn("## Coverage-forced investigation", md)

    def test_the_request_carries_every_diff_and_the_head_content(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        res, spy = self.record_v16(m, scr)
        hop0 = [doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0]
        self.assertEqual(len(hop0), 1)
        d = hop0[0]
        self.assertEqual(d["task"], prompts.V16_WHOLE_TASK)
        diffs = [c["args"].get("path") for c in d["context"] if c["tool"] == "diff"]
        changed = sorted(ELIGIBLE + list(SKIPPED))
        self.assertEqual(sorted(p for p in diffs if p), changed)               # tests, docs, generated: every diff
        heads = [c["args"]["path"] for c in d["context"] if c["tool"] == "read_file"]
        self.assertEqual(sorted(heads), sorted(p for p in changed if p in CORE_HEAD))   # the deleted file has no head
        self.assertNotIn("impact_scan", {c["tool"] for c in d["context"]})
        reads = [e for e in tool_calls(res) if e["agentId"] == whole.HEAD_AGENT]
        self.assertTrue(reads and all(e["stage"] == "INVESTIGATE" and "requestedBy" not in e for e in reads))
        b = d["wholeChange"]
        self.assertEqual((b["maxHypotheses"], b["diffsShown"], b["headFilesCut"], b["headFilesShownWhole"]),
                         (15, len(diffs), [], len(heads)))
        self.assertNotIn("diffsNotShown", b)

    def test_strict_replay_load_and_identity(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        res, _ = self.record_v16(m, scr)
        rep = self.replay_v16(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        self.assertEqual(load_result(self.out, res.run_id).status, "completed")
        backend, _ = self.record_backend(scr)
        spec = self.spec(m, backend, profile=V16_PROFILE, plan=V16_PLAN, retrieval=V16_POLICY)
        spec12 = self.spec(m, backend, profile=V3_PROFILE, plan=V12_PLAN, retrieval=RetrievalPolicy(
            investigator_prompt=prompts.INVESTIGATOR_IMPACT_V12_PROMPT, verifier_prompt=VER, run_tool_calls=400))
        self.assertNotEqual(identity.config_snapshot_id(spec), identity.config_snapshot_id(spec12))
        cfg = identity.config_snapshot_id(spec)
        with mock.patch.object(whole, "CONTEXT_CHARS", 149_999):                # the rule constants are bound
            self.assertNotEqual(cfg, identity.config_snapshot_id(spec))
        with self.assertRaises(PipelineError):                                  # the Plan must name the reviewer
            self.record_v16(m, scr, plan=V12_PLAN)



def vfail(agent, code="provider-error"):
    err = {"code": code, "message": "scripted failure", "retryable": True, "stage": "VERIFY",
           "detail": {"outcome": "rejected-before-processing"}}
    return [entry("VERIFY", "verifier", agent, 0, a, error=err) for a in range(3)]


# ---------------------------------------------------------------- 3. bounds and disclosure

class Bounds(V16Rig):
    def diff_chars(self, m):
        scr, _ = self.e2e(m)
        res, spy = self.record_v16(m, scr)
        d = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0)
        self.out = self.tmp / "out-2"
        self.out.mkdir()
        return sum(len(x) for c in d["context"] if c["tool"] == "diff" for x in c["excerpts"])

    def test_the_largest_head_files_are_cut_first_and_every_cut_is_disclosed(self):
        m = self.case12()
        budget = self.diff_chars(m) + 200
        scr, _ = self.e2e(m)
        with mock.patch.object(whole, "CONTEXT_CHARS", budget):
            res, spy = self.record_v16(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        d = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0)
        b = d["wholeChange"]
        cut = {f["path"]: f for f in b["headFilesCut"]}
        self.assertTrue(cut)
        sizes = {p: len(t) for p, t in CORE_HEAD.items()}
        whole_files = [c["args"]["path"] for c in d["context"] if c["tool"] == "read_file" and c["args"]["path"] not in cut]
        self.assertGreaterEqual(min(sizes[p] for p in cut), max(sizes[p] for p in whole_files))   # largest cut first
        shown = sum(len(x) for c in d["context"] for x in c["excerpts"])
        self.assertLessEqual(shown, budget)
        md = md_of(res)
        for p, f in cut.items():
            self.assertIn(f"head file cut: `{p}` lines 1-{f['shownLines']} of {f['lines']}", md)

    def test_diffs_beyond_the_budget_leave_largest_first_and_are_listed(self):
        m = self.case12()
        budget = self.diff_chars(m) - 1
        scr, _ = self.e2e(m)
        with mock.patch.object(whole, "CONTEXT_CHARS", budget):
            res, spy = self.record_v16(m, scr)
        d = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0)
        out = d["wholeChange"]["diffsNotShown"]
        self.assertTrue(out)
        shown = [c for c in d["context"] if c["tool"] == "diff"]
        self.assertEqual(len(shown), d["wholeChange"]["diffsShown"])
        self.assertGreaterEqual(min(x["chars"] for x in out), max(sum(map(len, c["excerpts"])) for c in shown))
        self.assertIn(f"diff not shown: `{out[0]['path']}`", md_of(res))

    def test_stopped_head_reads_are_disclosed_as_what_was_read(self):
        from reviewer.pipeline.engine import Engine
        m = self.case12()
        scr, _ = self.e2e(m)
        real, seen = Engine.tool, []

        def tool(eng, session, name, args, t0):           # the third host head read hits the session cap
            if session.agent_id == whole.HEAD_AGENT:
                seen.append(args["path"])
                if len(seen) == 3:
                    return None, "tool-calls-exhausted"
            return real(eng, session, name, args, t0)
        with mock.patch.object(Engine, "tool", tool):
            res, spy = self.record_v16(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        d = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0)
        cut = {f["path"]: f["shownLines"] for f in d["wholeChange"]["headFilesCut"]}
        self.assertEqual(cut[seen[2]], 0)
        self.assertEqual(len([c for c in d["context"] if c["tool"] == "read_file"]), 2)
        self.assertEqual(d["wholeChange"]["headFilesShownWhole"], 2)
        self.assertIn(f"head content of {seen[2]} from line 1 not read: tool-calls-exhausted", d["omitted"])

    def test_the_reviewer_runs_under_deepcovs_investigate_spend_top(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        with mock.patch.object(deepcov, "spend_top", lambda budget: 0):
            res, _ = self.record_v16(m, scr)
        self.assertNotEqual(res.status, "completed")
        self.assertEqual(model_calls(res, "INVESTIGATE") + model_calls(res, "VERIFY"), [])
        err = next(e["error"] for e in events_of(res) if e["type"] == "error"
                   and e["error"]["code"] == "budget-exhausted")
        self.assertEqual((err["detail"]["scope"], err["detail"]["rule"]), ("whole-share", whole.BUDGET_RULE))

    def test_at_most_twelve_reads_then_a_limit_end_is_re_asked_for_its_answer_only(self):
        m = self.case12()
        hl = self.h_lib(m)
        paths = ["src/use.py", "src/lib.py", "src/svc.py", "src/handlers/a.py", "src/handlers/b.py", "src/handlers/c.py"]
        e = [turn(A, k, [rf(p, 1 + k) for p in paths]) for k in range(3)] + [final(R, 0, hl)]
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), judge(w([hid(R, 0, hl)]))]
        res, _ = self.record_v16(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        ran = [t for t in tool_calls(res) if t["agentId"] == A and "requestedBy" in t and t["result"]["status"] == "ok"]
        self.assertEqual(len(ran), whole.READS)                                    # the 13th to 18th never ran
        self.assertEqual([(a["agentId"], a["status"]) for a in payload(res, "INVESTIGATE")["agents"]],
                         [(A, "failed"), (R, "completed")])
        self.assertEqual(len(inv_calls(res, R)), 1)                                # its answer only
        self.assertEqual(len(comments_of(res)), 1)

    def test_no_fifth_hop_and_a_re_ask_that_still_asks_for_context_ends_partial(self):
        m = self.case12()
        e = [turn(A, k, [rf("src/use.py", 1 + k)]) for k in range(4)] + [turn(R, 0, [rf("src/lib.py")])]
        res, _ = self.record_v16(m, script(*e))
        self.assertEqual(len(inv_calls(res, A)), whole.HOPS)                       # hop 3 is the last turn
        self.assertEqual(len(inv_calls(res, R)), whole.REASK_EXHAUSTED_HOPS)
        self.assertEqual(res.status, "partial")
        self.assertEqual([i["reason"] for i in res.incomplete if i["stage"] == "INVESTIGATE"], ["tool-calls-exhausted"])
        self.assertEqual(payload(res, "INVESTIGATE")["hypotheses"], [])

    def test_only_the_first_max_hypotheses_are_candidates(self):
        m = self.case12()
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = self.reviewer(A, [hl, hb, hs]) + [vdone("verifier-01", m, path="src/lib.py", line=1),
                                             vdone("verifier-02", m, path="src/handlers/b.py", line=2),
                                             judge(w([hid(A, 0, hl)]), w([hid(A, 1, hb)]))]
        with mock.patch.object(whole, "MAX_HYPOTHESES", 2):
            res, _ = self.record_v16(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual([h["id"] for h in payload(res, "INVESTIGATE")["hypotheses"]], [hid(A, 0, hl), hid(A, 1, hb)])
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")], ["verifier-01", "verifier-02"])
        self.assertNotIn(hid(A, 2, hs), json.dumps(payload(res, "VERIFY")))     # the third is no candidate at all

    def test_the_verify_cap_is_v12s(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        with mock.patch.object(deepcov, "MAX_VERIFY", 2):
            res, _ = self.record_v16(m, scr)
        over = [d for d in payload(res, "VERIFY")["drops"] if d["reason"] == "over-cap"]
        self.assertEqual(len(over), 1)
        self.assertIn("more than 2 hypotheses of the whole-change reviewer (deep-verify@1)", over[0]["detail"])


# ---------------------------------------------------------------- 4. schema re-ask (frozen contract: one repair per call)

class Reask(V16Rig):
    def test_the_contract_allows_one_repair_per_call(self):
        from reviewer.contracts.budget import effective_retry_limits
        from reviewer.pilot.profile import CLAUDE_CLI_REPAIRS
        self.assertEqual(effective_retry_limits({"maxRetriesPerCall": 0}, {"maxRetries": 0, "maxRepairs": 2}), (0, 1))
        self.assertEqual(CLAUDE_CLI_REPAIRS, 1)
        p = copy.deepcopy(V16_PROFILE)
        p["roles"]["verifier"]["caps"]["maxRepairs"] = 2
        self.assertTrue(validate("ModelProfile", p))                           # 2 is outside the frozen schema

    def test_an_out_of_schema_reviewer_is_asked_once_more_in_a_new_session(self):
        m = self.case12()
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = [turn(A, 0, [rf("src/use.py", 1, 7)]), *bad_turn(A, 1)] + self.reviewer(R, [hl, hb, hs])
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), vdone("verifier-02", m, path="src/handlers/b.py", line=2),
              vdone("verifier-03", m, path="src/svc.py", line=2),
              judge(w([hid(R, 0, hl)]), w([hid(R, 1, hb)]), w([hid(R, 2, hs)]))]
        res, spy = self.record_v16(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        inv = payload(res, "INVESTIGATE")
        self.assertEqual([(a["agentId"], a["status"]) for a in inv["agents"]], [(A, "failed"), (R, "completed")])
        self.assertEqual(inv["agents"][0]["error"]["code"], "repair-exhausted")
        self.assertEqual({h["specialist"] for h in inv["hypotheses"]}, {R})
        reask0 = next(doc_of(e["request"]) for e in inv_calls(res, R) if e["request"]["hop"] == 0)
        first0 = next(doc_of(e["request"]) for e in inv_calls(res, A) if e["request"]["hop"] == 0)
        self.assertEqual(reask0, first0)                                        # the same question, a fresh chain
        self.assertEqual(len(comments_of(res)), 3)
        self.assertIn("reviewer re-asked 1 time(s)", md_of(res))
        self.assertIn("`whole`: failed (repair-exhausted)", md_of(res))
        rep = self.replay_v16(m, res)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])

    def test_a_second_out_of_schema_answer_fails_investigate_and_nothing_later_runs(self):
        m = self.case12()
        res, _ = self.record_v16(m, script(*bad_turn(A, 0), *bad_turn(R, 0)))
        self.assertEqual(res.status, "failed")
        self.assertEqual(res.error["code"], "repair-exhausted")
        self.assertEqual(model_calls(res, "VERIFY") + model_calls(res, "JUDGE"), [])
        self.assertEqual(validate_trace(events_of(res)), [])

    def test_a_systemic_failure_is_not_re_asked(self):
        m = self.case12()
        err = {"code": "live-calls-disabled", "message": "scripted", "retryable": False, "stage": "INVESTIGATE"}
        res, _ = self.record_v16(m, script(entry("INVESTIGATE", "investigator", A, 0, error=err)))
        self.assertEqual(res.status, "failed")
        self.assertEqual({e["agentId"] for e in inv_calls(res)}, {A})
        self.assertEqual(model_calls(res, "VERIFY"), [])

    def test_a_provider_failure_of_the_reviewer_is_not_re_asked(self):
        m = self.case12()
        err = {"code": "provider-error", "message": "scripted", "retryable": True, "stage": "INVESTIGATE",
               "detail": {"outcome": "rejected-before-processing"}}
        res, _ = self.record_v16(m, script(*[entry("INVESTIGATE", "investigator", A, 0, a, error=err) for a in range(3)]))
        self.assertEqual(res.status, "failed")
        self.assertNotIn(R, {e["agentId"] for e in inv_calls(res)})

    def test_an_out_of_schema_verifier_is_asked_once_more(self):
        m = self.case12()
        scr, (hl, hb, hs) = self.e2e(m, verifiers=[
            *bad_turn("verifier-01", 0, "VERIFY", "verifier"), vdone("verifier-01-reask", m, path="src/lib.py", line=1),
            vdone("verifier-02", m, path="src/handlers/b.py", line=2), vdone("verifier-03", m, path="src/svc.py", line=2)])
        res, _ = self.record_v16(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        v = payload(res, "VERIFY")
        self.assertEqual(len(v["findings"]), 3)
        rec = next(r for r in v["verifications"] if r["hypothesisId"] == hid(A, 0, hl))
        self.assertEqual((rec["verdict"], len(rec["callIds"])), ("confirmed", 3))   # the failed call, its repair, the re-ask
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")],
                         ["verifier-01", "verifier-01", "verifier-01-reask", "verifier-02", "verifier-03"])
        self.assertIn("1 verifier re-ask(s); 0 candidate(s) dropped after their re-ask", md_of(res))
        rep = self.replay_v16(m, res)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        self.assertEqual(load_result(self.out, res.run_id).status, "completed")

    def test_a_verifier_still_out_of_schema_after_its_re_ask_is_a_note(self):
        m = self.case12()
        scr, (hl, hb, hs) = self.e2e(m, verifiers=[
            *bad_turn("verifier-01", 0, "VERIFY", "verifier"), *bad_turn("verifier-01-reask", 0, "VERIFY", "verifier"),
            vdone("verifier-02", m, path="src/handlers/b.py", line=2), vdone("verifier-03", m, path="src/svc.py", line=2)],
            judged=(1, 2))
        res, _ = self.record_v16(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)               # one candidate's format: not partial
        self.assertEqual(validate_trace(events_of(res)), [])
        drop = next(d for d in payload(res, "VERIFY")["drops"] if d["subjectIds"] == [hid(A, 0, hl)])
        self.assertEqual(drop["reason"], "verifier-failed")
        self.assertIn("schema-reask@1: re-asked once, repair-exhausted (a note)", drop["detail"])
        self.assertEqual(len(payload(res, "VERIFY")["findings"]), 2)
        self.assertIn("1 candidate(s) dropped after their re-ask (a note)", md_of(res))

    def test_a_verifier_provider_failure_keeps_v12_handling(self):
        m = self.case12()
        scr, _ = self.e2e(m, verifiers=vfail("verifier-01") + [
            vdone("verifier-02", m, path="src/handlers/b.py", line=2), vdone("verifier-03", m, path="src/svc.py", line=2)])
        res, _ = self.record_v16(m, scr)
        self.assertEqual(res.status, "partial")
        self.assertIn("VERIFY", [i["stage"] for i in res.incomplete])
        self.assertNotIn("verifier-01-reask", {e["agentId"] for e in model_calls(res, "VERIFY")})

    def test_no_verifier_re_ask_past_the_judge_reserve(self):
        from reviewer.pipeline.engine import Engine
        m = self.case12()
        scr, (hl, hb, hs) = self.e2e(m, verifiers=bad_turn("verifier-01", 0, "VERIFY", "verifier"))
        real = Engine.run_spend

        def spend(eng):                          # the JUDGE reserve binds once the first verifier call is logged
            hit = any(e["type"] == "model.call" and e["stage"] == "VERIFY" for e in eng.recorder.events)
            return real(eng) + (10 ** 12 if hit else 0)
        with mock.patch.object(Engine, "run_spend", spend):
            res, _ = self.record_v16(m, scr)
        drop = next(d for d in payload(res, "VERIFY")["drops"] if d["subjectIds"] == [hid(A, 0, hl)])
        self.assertIn("not re-asked (the JUDGE spend reserve)", drop["detail"])
        self.assertNotIn("verifier-01-reask", {e["agentId"] for e in model_calls(res, "VERIFY")})




# ---------------------------------------------------------------- 4b. gate-v16 fixes (L1, L2)

WIDE_BASE = {f"src/w{i:02d}.py": f"def w{i}():\n    return {i}\n" for i in range(120)}
WIDE_HEAD = {q: t.replace("return", "return -") for q, t in WIDE_BASE.items()}


class GateFixes(V16Rig):
    def test_l1_changed_paths_prepare_did_not_collect_are_listed_as_not_shown(self):
        m = self.mini("mini-wide", base=WIDE_BASE, head=WIDE_HEAD)
        h = hyp(m, "src/w00.py", 2, claim="w0 now returns the negated value")
        res, spy = self.record_v16(m, script(final(A, 0, h), vdone("verifier-01", m, path="src/w00.py", line=2),
                                             judge(w([hid(A, 0, h)]))))
        self.assertEqual(validate_trace(events_of(res)), [])
        files = [f["path"] for f in payload(res, "PREPARE")["files"]]
        self.assertEqual(sorted(files), sorted(WIDE_HEAD))                      # every changed path is a PREPARE file
        collected = {t["args"]["path"] for t in tool_calls(res) if t["stage"] == "PREPARE" and t["tool"] == "diff"
                     and t["args"].get("path")}
        missing = [q for q in files if q not in collected]
        self.assertTrue(missing and collected)                                  # the PREPARE tool cap binds
        self.assertIn("PREPARE", [i["stage"] for i in res.incomplete])
        d = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0)
        b = d["wholeChange"]
        nc = [x for x in b["diffsNotShown"] if x.get("reason") == whole.NOT_COLLECTED]
        self.assertEqual([x["path"] for x in nc], missing)                      # in PREPARE order
        self.assertTrue(all(set(x) == {"path", "reason"} for x in nc))          # no char count
        self.assertEqual(b["diffsShown"], len(collected) + 1)                   # + the changed-path listing
        md = md_of(res)
        self.assertIn(f"{b['diffsShown']} diff(s) shown, {len(missing)} not shown", md)
        for q in missing[:whole.LISTED]:
            self.assertIn(f"diff not shown: `{q}` (not collected by PREPARE)", md)
        self.assertGreater(len(missing), whole.LISTED)
        self.assertIn(f"... and {len(missing) - whole.LISTED} more diff(s) not shown (all listed in the request)", md)
        cut = b["headFilesCut"]                                                 # the whole.head session cap binds too
        self.assertTrue(cut)
        self.assertEqual(md.count("head file cut: `"), min(len(cut), whole.LISTED))

    def test_l1_nothing_is_listed_when_prepare_collected_every_diff(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        res, spy = self.record_v16(m, scr)
        d = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0)
        self.assertNotIn("diffsNotShown", d["wholeChange"])

    def test_l2_no_verifier_re_ask_while_the_spend_book_needs_reconciliation(self):
        from reviewer.pipeline.engine import Engine
        m = self.case12()
        scr, (hl, hb, hs) = self.e2e(m, verifiers=[
            *bad_turn("verifier-01", 0, "VERIFY", "verifier"), vdone("verifier-01-reask", m, path="src/lib.py", line=1),
            vdone("verifier-02", m, path="src/handlers/b.py", line=2), vdone("verifier-03", m, path="src/svc.py", line=2)],
            judged=(1, 2))
        real = Engine.verify

        def verify(eng, t0):                     # the spend book needs operator reconciliation when VERIFY starts
            eng.needs_reconciliation = True
            return real(eng, t0)
        with mock.patch.object(Engine, "verify", verify):
            res, _ = self.record_v16(m, scr)
        self.assertNotIn("verifier-01-reask", {e["agentId"] for e in model_calls(res, "VERIFY")})
        drop = next(d for d in payload(res, "VERIFY")["drops"] if d["subjectIds"] == [hid(A, 0, hl)])
        self.assertEqual(drop["reason"], "verifier-failed")
        self.assertIn("schema-reask@1: not re-asked (the spend book needs reconciliation), repair-exhausted; ",
                      drop["detail"])
        self.assertNotIn("(a note)", drop["detail"])                            # v12's incomplete entry stands
        self.assertIn(("VERIFY", "verifier-failure"), [(i["stage"], i["reason"]) for i in res.incomplete])
        self.assertNotIn(hid(A, 0, hl), [f["id"] for f in payload(res, "VERIFY")["findings"]])


# ---------------------------------------------------------------- 5. parity: v1-v12 unchanged

# The impact@v12 end-to-end recording (V12Rig.e2e, pin_of) made on the PRE-CHANGE source 434145d with the same rig
# (/var/tmp/pullo-cap150/v16work/pin_v12.py); this branch must reproduce it byte for byte. v1-v10 identities and the v3/v10
# recordings are pinned in test_coverage_v12 (Parity, V3Parity, V10Parity).
PRE_V16_V12_PIN = json.loads('{"INVESTIGATE": "sha256:a2256e00d7df0f8c35b7117e41d50549ec1b10643ccdc62a4212e62fae08f9ec", "PUBLISH": "sha256:ec392093eb0466ab6ca8919777e6564c3b257814eeca94e761f7dd195c70930c", "VERIFY": "sha256:296f13c969b5a986244042440766a20232e600a154d70b09315d57fadb7c634c", "cfg": "sha256:018cce06ada29fecd1635d296103ffff6c9bd8e7c568631b1c59ba2b6dd3d2ad", "requests": ["sha256:74b2feb0d1607ec2989886301acddbc6cf8f2ebacd3c0694166b34367d9ecf5b", "sha256:9e9f50007e7bf3ac8e22c116bc61d0067b470c45e723eb66ae0273f2bc9c2528", "sha256:a8ecbf2c14681ce57aac69fe655c8f8b68db558d2fbeca4c39134fd7ee226d59", "sha256:0d893ee66fec34696467da86775c089eec69abe8cb3985a63a0abe766879fae9", "sha256:9db982406f4aa5a8d535170787076bef9fa6fe89b7aafb6f5b2aef458502ffd8", "sha256:ac0b4c30e459eb9653f48f5caace7e785d7925dab556786ab7c01e3a7035ca81", "sha256:2ba65dfd744bcb8ad588d91d22b84ac7e410f67bf5671db9f5d4353cd72802d7", "sha256:29402ba84cc1d2afcfca5edf4d3237103f63c49460e000edea6cab8f01f7487c", "sha256:76a47086f0d7ae722543e86c2e0c08d8d081a717f258186d5b75b8eed5bc7ccf", "sha256:0595f8a70de321b58a0c1f2b99cf85d7b744838fd065f6d8c7b53e0b5be6e689", "sha256:353df3b3ff9e80983db349d8f997f571fdf4fd60c94c3019d8566a820b45b042", "sha256:431da217c264a53348ab7102df3acf7d73a02dbbecff95c32a04105f29400602", "sha256:6de4ae243ebe4461bb7b167448b7d55136fe8cb601b30ec7ad43c7d608decc2e", "sha256:f57a080b0aeccd2a833d47435cdef0abeb8a984c7ba9b64e48fbc157b678f919", "sha256:c494727434c1b721df601bcf5ea8b2984d4280ac757ebeaccbcd6abc23841cb2", "sha256:6f1feac6d3d59ba3154869ced4bc545501034e2da99b9da359ce30b1d15fb82f"], "trace": "sha256:0e2b40753024f9b9ccdd99a35170b9e532dd8312bb0b8719c5f3fd35f23160a7"}')


class V12Parity(unittest.TestCase):
    def test_v12_recording_is_byte_identical_to_the_pre_change_source(self):
        from tests.pipeline.test_cross_model_v10 import pin_of

        class Run(V12Rig):
            def runTest(self):
                m = self.case12()
                scr, _ = self.e2e(m)
                res, _ = self.record_v12(m, scr)
                self.assertEqual(pin_of(res), PRE_V16_V12_PIN)
        r = unittest.TextTestRunner(stream=open("/dev/null", "w")).run(Run())
        self.assertTrue(r.wasSuccessful(), r.failures + r.errors)

    def test_versions(self):
        from reviewer.pilot import repository_profile as RP
        self.assertEqual(sorted(RP.IMPACT_VERSIONS), [1, 2, 3, 4, 5, 7, 10, 12, 16, 19, 20, 21])
        self.assertEqual(RP.DEFAULT_IMPACT_VERSION, 2)


if __name__ == "__main__":
    unittest.main()
