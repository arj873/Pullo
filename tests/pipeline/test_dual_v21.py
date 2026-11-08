"""V21 DUAL: investigator.impact@v21 = v16's whole pass (plain claude-cli requests, host head reads) + v20's agentic pass
(`whole-agentic`), a claim-aware union (both passes first, then P0/P1, cap 16), ONE agentic read-only verifier session per
candidate (refute-first, cites code, single vote; admission below the JUDGE reserve; the VERIFY clock degrades to notes),
and v20's JUDGE. reviewer.pipeline.dual.

The v19 rig (invented fixtures; a scripted fake claude-cli adapter that serves plain and agentic requests, the investigator
AND the verifier, standing in for ccprov's runtime; the real engine, contracts, gateway and tools). No network, key, state,
CLI or live call. These tests prove the mechanics; they do NOT show that a real model finds more."""

from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

from reviewer.config import resolve_config
from reviewer.contracts import validate
from reviewer.contracts.entities import validate_trace
from reviewer.gateway import DisabledProvider
from reviewer.pilot import repository as REPO
from reviewer.pilot import repository_profile as RP
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.pipeline import RecordBackend, RetrievalPolicy, agentic, dual, identity, prompts, sweeps, whole
from reviewer.pipeline.engine import Engine
from reviewer.runtime.catalog import claude_cli_agentic_spec

from tests.pipeline import test_agentic_v19 as T19
from tests.pipeline.helpers import NOW, SpyProvider, entry, events_of, judge, model_calls, resp, script, tool_calls
from tests.pipeline.test_agentic_v19 import CLI, USAGE, V19_PLAN, V19Rig, cli, cli_bad
from tests.pipeline.test_coverage_v12 import ROOT, final, hid, inv_calls, md_of, payload, rf, turn, vdone
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PROFILE
from tests.pipeline.test_whole_v16 import bad_turn, comments_of

INV20, INV21, VER = (prompts.INVESTIGATOR_IMPACT_V20_PROMPT, prompts.INVESTIGATOR_IMPACT_V21_PROMPT,
                     prompts.VERIFIER_IMPACT_PROMPT)
CC = resolve_config(ROOT / "pullo-claude-cli-sj.toml").models
_REAL = RP.repository_profile(True, CC, impact_version=21)
V21_PROFILE = copy.deepcopy(V3_PROFILE)        # the real v21 claude-cli investigator AND verifier roles; the judge synthetic
V21_PROFILE["roles"]["investigator"] = copy.deepcopy(_REAL["roles"]["investigator"])
V21_PROFILE["roles"]["verifier"] = copy.deepcopy(_REAL["roles"]["verifier"])
V21_POLICY = RetrievalPolicy(investigator_prompt=INV21, verifier_prompt=VER, run_tool_calls=400)
V21_PLAN = copy.deepcopy(V19_PLAN)
V21_PLAN["specialists"] = dual.plan_specialists()
P, PR = dual.V16_AGENT, dual.V16_AGENT + whole.REASK_SUFFIX              # v16's pass
G, GR = dual.AGENTIC_AGENT, dual.AGENTIC_AGENT + whole.REASK_SUFFIX     # v20's agentic pass


def cc(e, usage=None):
    """A scripted entry answered by the claude-cli adapter (resolved model and measured usage)."""
    if "response" in e:
        e["response"]["resolvedModel"], e["response"]["usage"] = CLI, dict(usage or USAGE)
    return e


def vcc(agent, m, **kw):
    return cc(vdone(agent, m, **kw))


def tool_kill(stage, role, agent, ordinal=0):
    """claude_agentic's end of a session whose model tried a tool outside Read/Grep/Glob (nothing ran)."""
    return entry(stage, role, agent, ordinal, error={
        "code": "provider-error", "message": "the model attempted a tool outside Read/Grep/Glob; re-ask in a fresh session",
        "retryable": False, "stage": stage,
        "detail": {"reason": "agentic-tool-attempt", "itemType": "tool-attempt", "attemptedTools": ["json"],
                   "retryableByReask": True, "requestsSent": 3, "maxRequestsPerCall": 8}})


class FakeCli(T19.FakeAgentic):
    """The fake claude-cli adapter for v21: serves plain requests (v16's pass) and agentic ones (v20's pass, the
    verifiers); records every request."""

    def call(self, request, key):
        self.requests.append(copy.deepcopy(request))
        return self.inner.call(dict(request, provider="synthetic"), key)


class V21Rig(V19Rig):
    def record_backend(self, scr):
        spy = SpyProvider(scr)
        self.spies.append(spy)
        self.agentic = FakeCli(scr)
        providers = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai"), "synthetic": spy,
                     "claude-cli": self.agentic}
        return RecordBackend(self.handle, self.book, providers, lambda: NOW), spy

    def record_v21(self, m, scr, **kw):
        kw.setdefault("profile", V21_PROFILE)
        kw.setdefault("retrieval", V21_POLICY)
        kw.setdefault("plan", V21_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v21(self, m, res, **kw):
        kw.setdefault("profile", V21_PROFILE)
        kw.setdefault("retrieval", V21_POLICY)
        kw.setdefault("plan", V21_PLAN)
        return self.replay(m, res, **kw)

    def v16_pass(self, agent, hyps):
        """v16's reviewer: one request turn of three reads, then the answer (plain claude-cli calls)."""
        return [cc(turn(agent, 0, [rf("src/use.py", 1, 7), rf("src/handlers/a.py"), rf("src/svc.py", 1, 5)])),
                cc(final(agent, 1, *hyps))]

    def run21(self, m, *, v16=None, ag=None, verifiers=None, judged=None, judge_entry=None):
        """v16's pass finds lib and b, the agentic pass lib (a restatement) and svc. Union: G lib (both passes), P b
        (P1), G svc (P2), then P lib (merged). -> (script, ids by key)."""
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        ids = {"l": hid(G, 0, hl), "s": hid(G, 1, hs), "b": hid(P, 1, hb), "pl": hid(P, 0, hl)}
        e = v16 if v16 is not None else self.v16_pass(P, [hl, hb])
        e += ag if ag is not None else [cli(G, 0, {"hypotheses": [hl, hs]})]
        e += verifiers if verifiers is not None else [
            vcc("verifier-01", m, path="src/lib.py", line=1), vcc("verifier-02", m, path="src/handlers/b.py", line=2),
            vcc("verifier-03", m, path="src/svc.py", line=2)]
        if judge_entry is not None:
            e.append(judge_entry)
        else:
            e.append(judge(*[w([ids[k]]) for k in (judged if judged is not None else ("l", "b", "s"))]))
        return script(*[x for x in e if x is not None]), ids

    def drop_of(self, res, hid_):
        return next(d for d in payload(res, "VERIFY")["drops"] if d["subjectIds"] == [hid_])


# ---------------------------------------------------------------- 1. profile, Plan, policy, texts, identity, union

class Rules(unittest.TestCase):
    def test_profile_plan_policy(self):
        self.assertEqual(RP.IMPACT_VERSIONS[21], INV21)
        p20, p21 = RP.repository_profile(True, CC, impact_version=20), _REAL
        self.assertEqual(validate("ModelProfile", p21), [])
        self.assertEqual(claude_cli_agentic_spec({"agentic": dual.verifier_spec()}), dual.verifier_spec())
        self.assertEqual(dual.verifier_spec(), {"mode": "read-only", "maxRequests": 8, "sessionDeadlineSec": 180,
                                                "budgetUsdMicros": 500_000})
        self.assertEqual(p21["roles"]["verifier"]["params"], dict(p20["roles"]["verifier"]["params"],
                                                                 agentic=dual.verifier_spec()))
        self.assertEqual(p21["roles"]["investigator"], dict(p20["roles"]["investigator"], promptVersion=INV21))
        self.assertEqual(p21["roles"]["judge"], p20["roles"]["judge"])
        live, legacy = RP.repository_plan(p21, live_stage_timing=True), RP.repository_plan(p21)
        for plan in (live, legacy):
            self.assertEqual(validate("Plan", plan), [])
            self.assertEqual((plan["specialists"], plan["budget"]["maxUsdMicros"]),
                             (["whole", "whole-agentic", "agentic"], 10_000_000))
            self.assertTrue(plan["reasons"][1].startswith(INV21 + ": v16's whole-change pass and v20's agentic pass"))
        self.assertEqual((live["budget"]["stageCeilingsSec"], live["budget"]["wallClockSec"],
                          live["budget"]["softDeadlineSec"]),
                         ({"INVESTIGATE": 2100, "VERIFY": 1380, "JUDGE": 400}, 4600, 4000))
        p20plan = RP.repository_plan(p20)
        self.assertEqual(legacy["budget"], p20plan["budget"])                    # legacy: v20's
        with self.assertRaises(Exception) as ctx:
            RP.repository_profile(True, None, impact_version=21)
        self.assertIn("needs a claude-cli investigator", str(ctx.exception))
        real_live = RP.live_profile

        def plain_verifier(*a, **k):
            p = real_live(*a, **k)
            p["roles"]["verifier"] = dict(p["roles"]["verifier"], provider="openai")
            return p
        with mock.patch.object(RP, "live_profile", plain_verifier), self.assertRaises(Exception) as ctx:
            RP.repository_profile(True, CC, impact_version=21)
        self.assertIn("investigator.impact@v21 needs a claude-cli verifier", str(ctx.exception))
        pol = RP.repository_policy(True, impact_version=21)
        self.assertEqual(pol, V21_POLICY)
        self.assertEqual((pol.dual_pass, pol.agentic_review, pol.whole_change, pol.broad_agentic, pol.impact,
                          pol.run_tool_calls), (True, True, True, True, True, 400))
        self.assertFalse(any(RP.repository_policy(True, impact_version=v).dual_pass for v in (16, 19, 20)))

    def test_texts_and_identity(self):
        t20, t21 = prompts.impact_template_digests(INV20), prompts.impact_template_digests(INV21)
        self.assertEqual({k: v for k, v in t21.items() if k != "dualPass"}, t20)
        r = prompts.V21_VERIFY_RULE
        for s in ("Try to REFUTE the claim first", "Confirm ONLY if you can cite a concrete failure",
                  "read-only tools (Read, Grep, Glob)", "Leave contextRequests empty"):
            self.assertIn(s, r)
        d = dual.identity_doc(V21_POLICY, V21_PLAN["budget"], 50, 5)
        self.assertEqual((d["passes"], d["unionOrder"], d["union"]["maxVerify"], d["verify"]["maxRequests"],
                          d["clock"]["marginSec"]), (["whole", "whole-agentic"], ["whole-agentic", "whole"], 16, 8, 180))
        self.assertEqual((dual.verify_slice(1380), dual.verify_slice(45), dual.session_need(1), dual.session_need(0)),
                         (1200, 39, 1_000_000, 500_000))

    def test_live_hosts_accept_the_ten_dollar_ceiling_for_a_v21_plan(self):
        class Ledger:
            def totals(self):
                return {"committedUsdMicros": 0}
        p21 = RP.repository_plan(_REAL, live_stage_timing=True)
        self.assertTrue(dual.is_v21_plan(p21) and not agentic.is_v19_plan(p21))
        REPO._check_ceiling(Ledger(), p21)
        with self.assertRaises(REPO.RepositoryError):
            REPO._check_ceiling(Ledger(), dict(p21, budget=dict(p21["budget"], maxUsdMicros=RUN_CEILING_USD_MICROS)))

    def test_union_orders_both_passes_first_then_p0_p1_then_the_rest(self):
        def h(i, path, line, sev, claim, cat="bug"):
            return (f"h{i}", {"id": f"h{i}", "claim": claim, "category": cat, "suspectedSeverity": sev,
                              "location": {"path": path, "line": line}})
        g = [h(1, "a.py", 3, "P2", "total starts at one so an empty list sums wrong"),
             h(2, "b.py", 9, "P2", "cache key ignores the tenant id for every lookup"),
             h(3, "c.py", 5, "P1", "token expiry compared in seconds against milliseconds")]
        p = [h(4, "z.py", 1, "P2", "unused helper left behind after the refactor"),
             h(5, "a.py", 3, "P2", "total starts at one so an empty list sums wrong"),            # restates h1
             h(6, "d.py", 7, "P0", "the delete runs without the ownership check")]
        hyps = {k: v for k, v in g + p}
        order, into, src = dual.union([g, p], hyps)
        self.assertEqual(into, {"h5": "h1"})
        self.assertEqual(src["h1"], [0, 1])
        # tier 0: h1 (both); tier 1 (P0/P1) by rank: h3 and h6 both rank 2, the agentic pass (g) first; tier 2 by rank:
        # h4 (rank 0 in p) before h2 (rank 1 in g); then the merged h5
        self.assertEqual([k for k, _ in order], ["h1", "h3", "h6", "h4", "h2", "h5"])
        unresolved = {k: v for k, v in hyps.items() if k != "h5"}
        _, into2, _ = dual.union([g, p], unresolved)                             # an unresolved draft is never merged
        self.assertEqual(into2, {})


# ---------------------------------------------------------------- 2. end to end through the gateway

class EndToEnd(V21Rig):
    def test_two_passes_a_union_agentic_verifiers_and_the_judge_rule(self):
        m = self.case12()
        scr, ids = self.run21(m, judged=("l", "b"))                              # the judge leaves svc out
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        calls = inv_calls(res)
        self.assertEqual([e["agentId"] for e in calls], [P, P, G])
        for e in calls[:2]:                                                     # v16's pass: plain requests, v16 task
            self.assertNotIn("agentic", e["request"]["params"])
            self.assertEqual(doc_of(e["request"])["task"], prompts.V16_WHOLE_TASK)
        self.assertTrue([t for t in tool_calls(res) if t["agentId"] == whole.HEAD_AGENT])   # with host head reads
        ga = calls[2]["request"]
        self.assertEqual((ga["params"]["agentic"], ga["promptVersion"]), (agentic.spec(), INV21))
        self.assertEqual(doc_of(ga)["task"], prompts.V20_WHOLE_TASK)
        self.assertEqual(doc_of(ga)["agenticReview"], prompts.agentic_block(agentic.spec()))
        self.assertFalse([c for c in doc_of(ga)["context"] if c["tool"] == "read_file"])   # the session reads itself
        vcalls = model_calls(res, "VERIFY")
        self.assertEqual([(e["agentId"], e["request"]["hypothesisId"]) for e in vcalls],
                         [("verifier-01", ids["l"]), ("verifier-02", ids["b"]), ("verifier-03", ids["s"])])
        for e in vcalls:                                                         # one agentic session per candidate
            self.assertEqual((e["request"]["params"]["agentic"], e["request"]["hop"]), (dual.verifier_spec(), 0))
            d = doc_of(e["request"])
            self.assertTrue(d["task"].endswith(prompts.V21_VERIFY_RULE))
            self.assertEqual(d["agenticReview"], prompts.agentic_block(dual.verifier_spec()))
            self.assertTrue(d["retrieval"]["lastTurn"])
        costs = {e["record"]["callId"]: e["record"] for e in events_of(res) if e["type"] == "cost"}
        self.assertEqual({costs[e["callId"]]["reservedUsdMicros"] for e in vcalls}, {dual.VERIFIER_BUDGET_USD_MICROS})
        merged = self.drop_of(res, ids["pl"])
        self.assertEqual(merged["reason"], "merged")
        self.assertIn(f"duplicate of {ids['l']} (dual-union@1", merged["detail"])
        self.assertTrue(doc_of(model_calls(res, "JUDGE")[0]["request"])["task"].endswith(prompts.V19_JUDGE_RULE))
        jd = payload(res, "JUDGE")["drops"]
        self.assertEqual([(x["subjectIds"], x["reason"]) for x in jd], [([ids["s"]], "below-threshold")])
        self.assertEqual(sorted(c["findingIds"][0] for c in comments_of(res)), sorted([ids["l"], ids["b"]]))
        md = md_of(res)
        for s in ("Dual-pass review (dual-pass-agentic-verify@1)", "2 call(s) of `whole` (plain), 1 agentic session(s)",
                  "Union (dual-union@1): 1 restatement(s)", "Agentic verify (agentic-verify@1): 3 verifier session(s)",
                  "Verify admission (agentic-verify-admission@1): 0 candidate(s)",
                  "JUDGE rule (judge-concrete@1): 1 finding(s) left out"):
            self.assertIn(s, md)

    def test_strict_replay_and_its_own_identity(self):
        m = self.case12()
        scr, _ = self.run21(m)
        res, _ = self.record_v21(m, scr)
        rep = self.replay_v21(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        backend, _ = self.record_backend(scr)
        c21 = identity.config_snapshot_id(self.spec(m, backend, profile=V21_PROFILE, plan=V21_PLAN, retrieval=V21_POLICY))
        self.assertEqual(res.run["configSnapshotId"], c21)
        with mock.patch.object(dual, "MAX_VERIFY", 15):
            self.assertNotEqual(c21, identity.config_snapshot_id(
                self.spec(m, backend, profile=V21_PROFILE, plan=V21_PLAN, retrieval=V21_POLICY)))


# ---------------------------------------------------------------- 3. pass ends (V1 and notes)

class Passes(V21Rig):
    def test_an_agentic_pass_without_an_answer_is_a_note_when_v16_answers(self):
        m = self.case12()
        hl, hb = self.h_lib(m), self.h_b(m)
        scr, ids = self.run21(m, ag=[*cli_bad(G, 0), *cli_bad(GR, 0)],
                              verifiers=[vcc("verifier-01", m, path="src/lib.py", line=1),
                                         vcc("verifier-02", m, path="src/handlers/b.py", line=2)], judged=("b", "pl"))
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual([(a["agentId"], a["status"]) for a in payload(res, "INVESTIGATE")["agents"]],
                         [(P, "completed"), (G, "failed"), (GR, "failed")])
        # v16's lib (P1, rank 0) then b (P1, rank 1): nothing to merge with
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")], [ids["pl"], ids["b"]])
        self.assertIn("- `whole-agentic-reask`: failed (repair-exhausted)", md_of(res))

    def test_a_v16_pass_without_an_answer_is_a_note_when_the_agentic_pass_answers(self):
        m = self.case12()
        scr, ids = self.run21(m, v16=[*[cc(x) for x in bad_turn(P, 0)], *[cc(x) for x in bad_turn(PR, 0)]],
                              verifiers=[vcc("verifier-01", m, path="src/svc.py", line=2),
                                         vcc("verifier-02", m, path="src/lib.py", line=1)], judged=("l", "s"))
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual([(a["agentId"], a["status"]) for a in payload(res, "INVESTIGATE")["agents"]],
                         [(P, "failed"), (PR, "failed"), (G, "completed")])
        # single source, lib P1 before svc P2
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")], [ids["l"], ids["s"]])

    def test_no_answer_from_either_pass_fails_investigate_as_v16(self):
        m = self.case12()
        scr, _ = self.run21(m, v16=[*[cc(x) for x in bad_turn(P, 0)], *[cc(x) for x in bad_turn(PR, 0)]],
                            ag=[*cli_bad(G, 0), *cli_bad(GR, 0)], verifiers=[], judged=())
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "failed")
        self.assertEqual(model_calls(res, "VERIFY"), [])

    def test_a_systemic_v16_pass_end_fails_investigate_at_once_v1(self):
        m = self.case12()
        unknown = entry("INVESTIGATE", "investigator", P, 0, error={
            "code": "provider-error", "message": "outcome unknown", "retryable": False, "stage": "INVESTIGATE",
            "detail": {"providerOutcome": "unknown"}})
        scr, _ = self.run21(m, v16=[unknown], verifiers=[], judged=())
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "failed")
        self.assertEqual([e["agentId"] for e in inv_calls(res)], [P])           # the agentic pass never ran

    def test_the_agentic_pass_keeps_v20s_tool_re_ask(self):
        m = self.case12()
        hl, hs = self.h_lib(m), self.h_svc(m)
        scr, _ = self.run21(m, ag=[T19.EndToEnd.tool_kill(self, G), cli(GR, 0, {"hypotheses": [hl, hs]})],
                            judged=())
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(doc_of(inv_calls(res, GR)[0]["request"])["task"],
                         prompts.V20_WHOLE_TASK + " " + prompts.V19_TOOL_NOTE)
        self.assertIn("1 reviewer session(s) ended by a tool outside Read/Grep/Glob", md_of(res))

    def test_a_second_agentic_tool_attempt_is_a_note_when_v16_answers(self):
        m = self.case12()
        scr, ids = self.run21(m, ag=[T19.EndToEnd.tool_kill(self, G), T19.EndToEnd.tool_kill(self, GR)],
                              verifiers=[vcc("verifier-01", m, path="src/lib.py", line=1),
                                         vcc("verifier-02", m, path="src/handlers/b.py", line=2)], judged=("pl", "b"))
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual([(a["agentId"], a["status"]) for a in payload(res, "INVESTIGATE")["agents"]],
                         [(P, "completed"), (G, "failed"), (GR, "failed")])
        self.assertEqual(len(comments_of(res)), 2)


# ---------------------------------------------------------------- 4. the agentic verifier: re-asks, admission, clock

class Verify(V21Rig):
    def test_a_verifier_tool_attempt_is_re_asked_once_with_the_tool_note(self):
        m = self.case12()
        scr, ids = self.run21(m, verifiers=[tool_kill("VERIFY", "verifier", "verifier-01"),
                                            vcc("verifier-01-reask", m, path="src/lib.py", line=1),
                                            vcc("verifier-02", m, path="src/handlers/b.py", line=2),
                                            vcc("verifier-03", m, path="src/svc.py", line=2)])
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)               # the first end is a note
        again = [e for e in model_calls(res, "VERIFY") if e["agentId"] == "verifier-01-reask"]
        self.assertEqual(len(again), 1)
        self.assertTrue(doc_of(again[0]["request"])["task"].endswith(prompts.V21_VERIFY_RULE + " " + prompts.V19_TOOL_NOTE))
        self.assertEqual(again[0]["request"]["params"]["agentic"], dual.verifier_spec())
        self.assertIn(ids["l"], [f["id"] for f in payload(res, "VERIFY")["findings"]])
        self.assertIn("1 verifier session end(s) by a tool attempt", md_of(res))

    def test_a_second_verifier_tool_attempt_is_a_note_and_the_run_completes(self):
        m = self.case12()
        scr, ids = self.run21(m, verifiers=[tool_kill("VERIFY", "verifier", "verifier-01"),
                                            tool_kill("VERIFY", "verifier", "verifier-01-reask"),
                                            vcc("verifier-02", m, path="src/handlers/b.py", line=2),
                                            vcc("verifier-03", m, path="src/svc.py", line=2)], judged=("b", "s"))
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        d = self.drop_of(res, ids["l"])
        self.assertEqual(d["reason"], "verifier-failed")
        self.assertIn("schema-reask@1: re-asked once, provider-error (a note)", d["detail"])

    def test_a_verifier_out_of_schema_is_re_asked_without_the_tool_note(self):
        m = self.case12()
        bad = [cc(x) for x in bad_turn("verifier-01", 0, "VERIFY", "verifier")]
        scr, ids = self.run21(m, verifiers=[*bad, vcc("verifier-01-reask", m, path="src/lib.py", line=1),
                                            vcc("verifier-02", m, path="src/handlers/b.py", line=2),
                                            vcc("verifier-03", m, path="src/svc.py", line=2)])
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        again = [e for e in model_calls(res, "VERIFY") if e["agentId"] == "verifier-01-reask"]
        self.assertTrue(doc_of(again[0]["request"])["task"].endswith(prompts.V21_VERIFY_RULE))

    def test_a_verifier_asking_for_context_is_uncertain_a_note(self):
        m = self.case12()
        ask = cc(entry("VERIFY", "verifier", "verifier-01", 0,
                       response=resp({"contextRequests": [rf("src/use.py", 1, 7)], "output": None})))
        scr, ids = self.run21(m, verifiers=[ask, vcc("verifier-02", m, path="src/handlers/b.py", line=2),
                                            vcc("verifier-03", m, path="src/svc.py", line=2)], judged=("b", "s"))
        res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)               # one hop: no host read, a note
        self.assertEqual(len([e for e in model_calls(res, "VERIFY") if e["agentId"] == "verifier-01"]), 1)
        self.assertFalse([t for t in tool_calls(res) if t["stage"] == "VERIFY" and "requestedBy" in t])
        self.assertEqual(self.drop_of(res, ids["l"])["reason"], "uncertain")

    def test_admission_no_verifier_session_starts_past_the_judge_reserve(self):
        m = self.case12()
        scr, ids = self.run21(m, verifiers=[vcc("verifier-01", m, path="src/lib.py", line=1)], judged=("l",))
        floor = sweeps.judge_reserve_floor(V21_PLAN["budget"])
        real = Engine.run_spend

        def spend(eng):                          # the first verifier session leaves room for no second one
            hit = any(e["type"] == "model.call" and e["agentId"] == "verifier-01" for e in eng.recorder.events)
            return real(eng) + (floor - real(eng) - dual.session_need(1) + 1 if hit else 0)
        with mock.patch.object(Engine, "run_spend", spend):
            res, _ = self.record_v21(m, scr)
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")], ["verifier-01"])
        for k in ("b", "s"):
            d = self.drop_of(res, ids[k])
            self.assertEqual(d["reason"], "budget")
            self.assertIn("agentic-verify-admission@1", d["detail"])
        self.assertEqual(res.status, "partial")                                  # a typed budget stop, as B1
        self.assertIn("Verify admission (agentic-verify-admission@1): 2 candidate(s)", md_of(res))
        self.assertTrue(model_calls(res, "JUDGE"))                                # JUDGE keeps its reserve

    def test_admission_bound_also_holds_inside_model_call(self):
        m = self.case12()
        scr, ids = self.run21(m, verifiers=[], judged=())
        with mock.patch.object(Engine, "_v21_verify_room", lambda eng: False):
            res, _ = self.record_v21(m, scr)
        self.assertEqual(model_calls(res, "VERIFY"), [])
        self.assertEqual({self.drop_of(res, ids[k])["reason"] for k in ("l", "b", "s")}, {"budget"})

    def jump_after(self, agent, seconds):
        """Advance the host clock by `seconds` right after `agent`'s first VERIFY model call returns."""
        real, rig, done = Engine.model_call, self, []

        def call(eng, stage, role, ag, ordinal, request):
            out = real(eng, stage, role, ag, ordinal, request)
            if stage == "VERIFY" and ag == agent and not done:
                done.append(1)
                rig.clock_value[0] += seconds
            return out
        return mock.patch.object(Engine, "model_call", call)

    def test_clock_nothing_new_starts_in_the_verify_margin_and_the_run_completes(self):
        m = self.case12()
        scr, ids = self.run21(m, verifiers=[vcc("verifier-01", m, path="src/lib.py", line=1)], judged=("l",))
        with self.jump_after("verifier-01", dual.verify_slice(45) + 1):         # the rig Plan's legacy 45 s VERIFY
            res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)               # degraded, not partial
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")], ["verifier-01"])
        for k in ("b", "s"):
            d = self.drop_of(res, ids[k])
            self.assertEqual(d["reason"], "deadline")
            self.assertIn("VERIFY clock margin reached (39s of the 45s VERIFY ceiling; verify-clock@1", d["detail"])
        self.assertIn("2 candidate(s) cut by the VERIFY clock (a note, the run completes)", md_of(res))

    def test_clock_control_the_hard_run_deadline_keeps_v12_handling(self):
        m = self.case12()
        scr, ids = self.run21(m, verifiers=[vcc("verifier-01", m, path="src/lib.py", line=1)], judged=("l",))
        with self.jump_after("verifier-01", V21_PLAN["budget"]["wallClockSec"] + 1):
            res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "partial")
        self.assertIn("VERIFY", [i["stage"] for i in res.incomplete])
        self.assertNotIn("verify-clock@1", self.drop_of(res, ids["b"])["detail"])

    def test_the_cap_is_sixteen_distinct_candidates(self):
        self.assertEqual(dual.MAX_VERIFY, 16)
        m = self.case12()
        with mock.patch.object(dual, "MAX_VERIFY", 2):
            scr, ids = self.run21(m, verifiers=[vcc("verifier-01", m, path="src/lib.py", line=1),
                                                vcc("verifier-02", m, path="src/handlers/b.py", line=2)],
                                  judged=("l", "b"))
            res, _ = self.record_v21(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        d = self.drop_of(res, ids["s"])
        self.assertEqual(d["reason"], "over-cap")
        self.assertIn("more than 2 distinct candidates of the two passes (dual-union@1)", d["detail"])
        self.assertEqual(self.drop_of(res, ids["pl"])["reason"], "merged")       # a restatement takes no slot


# ---------------------------------------------------------------- 5. parity: v20 unchanged (v19 and v16: their own pins)

# impact@v20 recordings (e2e, schema re-ask, tool re-ask) made on the PRE-CHANGE source b55df4c
PRE_V21_V20_PINS = json.loads('{"e2e": {"INVESTIGATE": "sha256:9fea9a392c4e2079e921f4074013979ba541a3fbec2ada6ff2b8f47fecfeedae", "PUBLISH": "sha256:90ccb2cf714453a5e060c13b5f5027f9e89431a2a6ea897a8143b3330e466a2e", "VERIFY": "sha256:7d8f236a741dfbda62223a4aa93c8638d1bf68b795cf7ad23e9f4bb71f9d1a71", "cfg": "sha256:7b5b35817ecfcdc3b8f988a70a6e6af908cc88aa3f4479211392d3079aae2a4d", "requests": ["sha256:6cbef9af6a77af0f70f79d399eec0a1832335f25ed2cc44c141b7f0cafe5a87a", "sha256:8509717d1077e9a1566fbd2f47ad0b9e163dee62b5f317052547124607cf8b10", "sha256:7f965a73f4f31cbf7b828bd38f3336a7b81ae7f76a708166de3b939a00af5ae1", "sha256:3914c2de10447086c6939c06eb8b0ae217d2faffd3a6cc3a49776adf246b11ee", "sha256:930f1f5026979035e59d3b80aadc5ae6dcae6dd9b8abe90be613b069e09a1b4f"], "trace": "sha256:76b8ed0fbe06a9e317caf047789ca2d9b129aa30146374d022fff0a09dfa0516"}, "schema_reask": {"INVESTIGATE": "sha256:abaee6b50a7cc3f580c78158fdd0bafec3c46258eb04ef6413eb700eab6a9ac8", "PUBLISH": "sha256:bef98210592c86f576616be07291817b793d50544aafd513f91dae7dd69fa2a8", "VERIFY": "sha256:f3ef367020518d5b13e534742a94d5d762c93569db179e6d03c4a710e70b6548", "cfg": "sha256:7b5b35817ecfcdc3b8f988a70a6e6af908cc88aa3f4479211392d3079aae2a4d", "requests": ["sha256:6cbef9af6a77af0f70f79d399eec0a1832335f25ed2cc44c141b7f0cafe5a87a", "sha256:72ae535a726cdd9ca2f558e80bf96beaee5552b5a5021af837abf1160fef0afc", "sha256:6cbef9af6a77af0f70f79d399eec0a1832335f25ed2cc44c141b7f0cafe5a87a", "sha256:cedb3b5e9f5c46817be94de320e47794a1d870360506da3ddcc8f38343d35af9", "sha256:9ecc11bb31877237bf1c9ae0f0a4a5c2afda49ea5a4a45c02b3bb641a16b509b", "sha256:3603b17f9deb02d5e4533912087025bcfa176eb7e336474b8eece39b0e35100f", "sha256:c6ec9c3db1fe3544f56e1f1e62fd08c540a8487c7b3b1508f65675b9f48241d8"], "trace": "sha256:2ad728b982d56d131c65dcdd931bd77ef37a9807339a9808a8c568446d5e15d0"}, "tool_reask": {"INVESTIGATE": "sha256:d06950abd0a08d9a3edc59a1d896be16f04eac7b030d5d821062b317cd98ec97", "PUBLISH": "sha256:26fd200b91a9b5e3ad7f2752f3650f929a9ccf5242f7d0c2b21edfe5b7cc8f21", "VERIFY": "sha256:86182844f450a064781703098e89e864167866854ffd301ef6fa032400d25a92", "cfg": "sha256:7b5b35817ecfcdc3b8f988a70a6e6af908cc88aa3f4479211392d3079aae2a4d", "requests": ["sha256:6cbef9af6a77af0f70f79d399eec0a1832335f25ed2cc44c141b7f0cafe5a87a", "sha256:a516af20e31088e84ea9bb76144069bc682883c313cdf0bf4851b88170f74c0f", "sha256:cedb3b5e9f5c46817be94de320e47794a1d870360506da3ddcc8f38343d35af9", "sha256:9ecc11bb31877237bf1c9ae0f0a4a5c2afda49ea5a4a45c02b3bb641a16b509b", "sha256:3603b17f9deb02d5e4533912087025bcfa176eb7e336474b8eece39b0e35100f", "sha256:c6ec9c3db1fe3544f56e1f1e62fd08c540a8487c7b3b1508f65675b9f48241d8"], "trace": "sha256:06760c83ce534e81db53dfe6c19a356b497afa8b7f2d31a4d9cc48a5bdb18499"}}')


class V20Parity(unittest.TestCase):
    def test_v20_recordings_are_byte_identical_to_the_pre_change_source(self):
        import io
        import runpy
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            runpy.run_path(str(ROOT / "tests/pipeline/v20_pin_scenarios.py"), run_name="__main__")
        self.assertEqual(json.loads(buf.getvalue()), PRE_V21_V20_PINS)


if __name__ == "__main__":
    unittest.main()
