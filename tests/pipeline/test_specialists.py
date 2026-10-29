"""SPECIALISTS-01: investigator.impact@v3 specialist investigators, through the real engine, contracts, gateway
(scripted synthetic provider) and tools.

Invented self-contained fixtures only: no network, key, state, target repository or live call. These tests prove the
mechanics (three agents in a fixed order with their lens texts, the v2 floor per agent, the budget split, the merge
rule and cap, one-agent failure tolerance, identity binding and strict replay) and that impact@v1/@v2 stay
byte-identical. They do NOT show that lenses make a real model find more defects: that needs an admitted run."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from reviewer.contracts import validate
from reviewer.contracts.budget import HOST_STOP_RECORDING, investigation_limit
from reviewer.contracts.canonical import hypothesis_id
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, prompts, specialists
from reviewer.pipeline.engine import V3_SYSTEMIC_CODES as V3_SYSTEMIC
from reviewer.tools import Limits

from tests.pipeline.helpers import (TURN_PLAN, entry, events_of, hyp, judge, model_calls, resp, script, terr,
                                    tool_calls, treq, vfinal)
from tests.pipeline.test_exploration_floor import V2_POLICY, V2_PROFILE, FloorRig, floors as v2_floors
from tests.pipeline.test_impact_pipeline import doc_of, w

INV3, VER = prompts.INVESTIGATOR_IMPACT_V3_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
AGENTS = ("contracts", "logic", "safety")
V3_PROFILE = copy.deepcopy(V2_PROFILE)
V3_PROFILE["roles"]["investigator"]["promptVersion"] = INV3
V3_POLICY = RetrievalPolicy(investigator_prompt=INV3, verifier_prompt=VER)
V3_PLAN = copy.deepcopy(TURN_PLAN)
V3_PLAN["specialists"] = list(AGENTS)

# impact@v1 / impact@v2 first investigator request hash and config identity of ImpactRig.cross_file_script, and the
# request hashes of FloorRig.floor_script under v2, recorded from the pre-change source (origin/main 26c6ea17).
V1_PIN = ("sha256:2d052c809a7adf45a7c3933723c27524174ba5dc4213a089fe44f5ea3becb3fd",
          "sha256:560ffbd6d5b95c57410371cb5e154d8ee189a3b6908153e2d1c417b5691a7d73")
V2_PIN = ("sha256:ae9ef728ad6d4e964df474a64a76f9c044117bfb11e860c1482701f86e70bf86",
          "sha256:5366bc9792bb1463b224912b82a89b47dc82b624d71d17f0d065e59a2d1ecd5d")
V2_FLOOR_REQUESTS = ["sha256:ae9ef728ad6d4e964df474a64a76f9c044117bfb11e860c1482701f86e70bf86",
                     "sha256:0d0578f4f18a30584fea24c216e3ab0b44b3bc7bb9479531c9bcda80d93e57a4",
                     "sha256:859853288db020a29074d14ba62bf6e98666ae0c7bd7932b347762bef015629a",
                     "sha256:0985954f80525f66621de2f27609eff69e270bea3fb7289dc5e25b9a2831ddb4",
                     "sha256:d3fec584b61a30a3036c8ef423e5e10920b48cdead70cb1e6e16b80230cde29b"]


def sturn(agent, ordinal, requests=None, output=None, attempt=0):
    return entry("INVESTIGATE", "investigator", agent, ordinal, attempt,
                 response=resp({"contextRequests": requests or [], "output": output}))


def sfinal(agent, ordinal, *hyps):
    return sturn(agent, ordinal, output={"hypotheses": list(hyps)})


def sfail(agent, ordinal, code="provider-error", outcome="rejected-before-processing"):
    """A failed specialist call. By default the provider rejected it before processing (released, never charged); with
    outcome=None the synthetic provider reports an unknown outcome (charged at its worst case)."""
    err = terr(code, "INVESTIGATE")
    if outcome is not None:
        err["detail"] = {"outcome": outcome}
    return [entry("INVESTIGATE", "investigator", agent, ordinal, a, error=err) for a in range(3)]


def shid(agent, n, h):
    return hypothesis_id(agent, n, h["claim"], h["location"]["path"], h["location"]["line"])


def ask(agent, ordinal):
    """A first hop that requests context (so the exploration floor does not trigger)."""
    return sturn(agent, ordinal, [treq("find_references", side="head", symbol="load_user")])


def inv_calls(res):
    return [e for e in model_calls(res, "INVESTIGATE") if e["role"] == "investigator"]


def floors(res):
    return [(e["agentId"], e["decision"]) for e in events_of(res) if e["type"] == "retrieval.floor"]


class SpecRig(FloorRig):
    def record_v3(self, m, scr, **kw):
        kw.setdefault("profile", V3_PROFILE)
        kw.setdefault("retrieval", V3_POLICY)
        kw.setdefault("plan", V3_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v3(self, m, res, **kw):
        kw.setdefault("profile", V3_PROFILE)
        kw.setdefault("retrieval", V3_POLICY)
        kw.setdefault("plan", V3_PLAN)
        return self.replay(m, res, **kw)

    def h_contract(self, m):
        return self.cross(m)

    def h_logic(self, m):
        return hyp(m, "src/lib.py", 2, claim="the returned dict drops the region", category="bug",
                   impact="incorrect-result", evidence=[m.cite("src/lib.py", 2)])

    def h_safety(self, m):
        return hyp(m, "src/lib.py", 1, claim="region is not validated", category="security",
                   impact="security-exposure", evidence=[m.cite("src/lib.py", 1)])

    @staticmethod
    def payload(res):
        return json.loads((Path(res.run_dir) / res.stages["INVESTIGATE"]["path"]).read_text())

    def three_script(self, m):
        hc, hl, hs = self.h_contract(m), self.h_logic(m), self.h_safety(m)
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc),
                     ask("logic", 0), sfinal("logic", 1, hl),
                     ask("safety", 0), sfinal("safety", 1, hs),
                     vfinal(0, m, path="src/lib.py", line=1), vfinal(1, m, path="src/lib.py", line=2),
                     vfinal(2, m, path="src/lib.py", line=1),
                     judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hl)]), w([shid("safety", 0, hs)])))
        return scr, (hc, hl, hs)


class Specialists(SpecRig):
    def test_three_agents_run_in_order_with_their_lens_and_the_same_context(self):
        m = self.case()
        scr, (hc, hl, hs) = self.three_script(m)
        res, spy = self.record_v3(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual([(c["agentId"], c["ordinal"]) for c in inv_calls(res)],
                         [(a, k) for a in AGENTS for k in (0, 1)])
        firsts = [r for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0]
        self.assertEqual(len(firsts), 3)
        for agent, r in zip(AGENTS, firsts):
            d = doc_of(r)
            self.assertEqual(r["promptVersion"], INV3)
            self.assertEqual(d["task"], prompts.investigator_v3_task(agent))
            self.assertEqual(d["task"], prompts.INVESTIGATOR_IMPACT_V2_TASK + " " + dict(prompts.SPECIALIST_LENSES)[agent])
            self.assertNotIn("explorationFloor", d)
        # the same document but the lens task and each agent's remaining share of the tool-call pool
        # (Limits() 50 -> ceilings 16/33/50; contracts and logic each used one call before the next agent)
        self.assertEqual([doc_of(r)["retrieval"]["toolCallsRemaining"] for r in firsts], [16, 32, 48])
        same = [{k: v if k != "retrieval" else {**v, "toolCallsRemaining": None}
                 for k, v in doc_of(r).items() if k != "task"} for r in firsts]
        self.assertEqual(same[0], same[1])
        self.assertEqual(same[0], same[2])
        self.assertEqual(firsts[0]["contextResults"], firsts[2]["contextResults"])
        # each agent has its own tool session
        self.assertEqual([e["agentId"] for e in tool_calls(res, "INVESTIGATE")], list(AGENTS))
        self.assertEqual([(h["specialist"], h["claim"]) for h in res.hypotheses],
                         [("contracts", hc["claim"]), ("logic", hl["claim"]), ("safety", hs["claim"])])
        self.assertEqual(sorted(f["specialist"] for f in res.findings), sorted(AGENTS))
        p = self.payload(res)["payload"]
        self.assertEqual(p["agents"], [{"agentId": a, "specialist": a, "status": "completed"} for a in AGENTS])
        self.assertEqual(p["merges"], [])
        self.assertEqual(len(res.comments), 3)

    def test_lens_texts_are_distinct_paragraphs_appended_to_the_v2_task(self):
        lenses = dict(prompts.SPECIALIST_LENSES)
        self.assertEqual(tuple(lenses), AGENTS)
        self.assertEqual(prompts.SPECIALIST_AGENTS, AGENTS)
        self.assertEqual(len(set(lenses.values())), 3)
        for a, words in (("contracts", ("caller", "signatures")), ("logic", ("off-by-one", "copy-paste")),
                         ("safety", ("swallowed", "transactions", "injection", "migrations"))):
            self.assertTrue(prompts.investigator_v3_task(a).startswith(prompts.INVESTIGATOR_IMPACT_V2_TASK + " "))
            for word in words:
                self.assertIn(word, lenses[a])
        with self.assertRaises(ValueError):
            prompts.investigator_v3_task("generalist")
        with self.assertRaises(ValueError):
            prompts.investigator_task(INV3)
        v2, v3 = prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_V2_PROMPT), prompts.impact_template_digests(INV3)
        self.assertEqual(set(v3) - set(v2), {"lenses"})
        self.assertEqual({k: v3[k] for k in v2}, v2)

    def test_every_specialist_gets_the_v2_exploration_floor(self):
        m = self.case()
        hc, hl, hs = self.h_contract(m), self.h_logic(m), self.h_safety(m)
        scr = script(sfinal("contracts", 0, hc), sfinal("contracts", 1, hc),
                     sfinal("logic", 0), sfinal("logic", 1, hl),
                     sfinal("safety", 0, hs), sfinal("safety", 1),
                     vfinal(0, m, path="src/lib.py", line=1), vfinal(1, m, path="src/lib.py", line=2),
                     judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hl)])))
        res, spy = self.record_v3(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(floors(res), [(a, d) for a in AGENTS for d in ("continue", "final")])
        conts = [doc_of(r) for r in spy.requests if r["role"] == "investigator" and "explorationFloor" in doc_of(r)]
        self.assertEqual(len(conts), 3)
        self.assertEqual([c["task"] for c in conts], [prompts.investigator_v3_task(a) for a in AGENTS])
        self.assertEqual([h["specialist"] for h in res.hypotheses], ["contracts", "logic"])   # safety dropped its draft
        self.assertEqual(len(res.findings), 2)


class BudgetSplit(SpecRig):
    def test_split_is_cumulative_and_never_exceeds_the_old_totals(self):
        for pool in (0, 1, 2, 10, 59, 60, 61):
            cum = specialists.cumulative(pool)
            shares = [b - a for a, b in zip([0] + cum[:-1], cum)]
            self.assertEqual(len(cum), 3)
            self.assertEqual(cum[-1], pool)
            self.assertEqual(sum(shares), pool)
            self.assertTrue(all(s >= 0 for s in shares) and max(shares) - min(shares) <= 1, (pool, shares))
        doc = specialists.budget_doc(V3_POLICY, V3_PLAN["budget"], Limits().max_calls)
        pool = min(V3_POLICY.agent_tool_calls, V3_PLAN["budget"]["maxToolCallsPerAgent"], Limits().max_calls)
        self.assertEqual(doc["toolCalls"], {"pool": pool, "cumulative": specialists.cumulative(pool)})
        self.assertLessEqual(doc["toolCalls"]["cumulative"][-1], V3_POLICY.agent_tool_calls)
        self.assertLessEqual(doc["toolCalls"]["cumulative"][-1], V3_POLICY.run_tool_calls)
        self.assertEqual(doc["spendUsdMicros"]["cumulative"][-1], investigation_limit(V3_PLAN["budget"]))
        self.assertEqual(doc["spendUsdMicros"]["cumulative"], specialists.cumulative(investigation_limit(V3_PLAN["budget"])))
        # the pilot's numbers: 60 tool calls -> 20/20/20; $2.80 investigation share -> thirds
        from reviewer.pilot.repository_profile import repository_plan, repository_policy, repository_profile
        prof = repository_profile(True)
        plan = repository_plan(prof)
        d = specialists.budget_doc(repository_policy(True), plan["budget"], Limits.full_repository().max_calls)
        self.assertEqual(d["toolCalls"]["cumulative"], [20, 40, 60])
        self.assertEqual(d["spendUsdMicros"]["cumulative"], [933_333, 1_866_666, 2_800_000])
        self.assertEqual(repository_policy(True).run_tool_calls, 160)          # nothing run-wide is raised

    def test_tool_calls_follow_the_cumulative_ceilings_with_rollover(self):
        m = self.case()
        pol = V3_POLICY.tightened(agent_tool_calls=6)        # pool 6 -> ceilings 2 / 4 / 6
        reqs = [treq("read_file", side="head", path="src/use.py", start_line=k, end_line=k) for k in range(1, 6)]
        scr = script(sturn("contracts", 0, reqs[:3]), sfinal("contracts", 1),
                     sturn("logic", 0, reqs[:1]), sfinal("logic", 1),
                     sturn("safety", 0, reqs[:5]), sfinal("safety", 1),
                     judge())
        res, spy = self.record_v3(m, scr, retrieval=pol)
        self.assertEqual(res.status, "completed", res.incomplete)
        got = [(e["agentId"], e["result"]["status"]) for e in tool_calls(res, "INVESTIGATE")]
        ok = lambda a: sum(1 for x, s in got if x == a and s == "ok")     # noqa: E731
        # contracts logs 3 calls (2 run, 1 unavailable): logic may use 4 - 3 = 1, safety 6 - 4 = 2 (unused room
        # rolls forward; a logged unavailable result counts, as for every tool-call counter)
        self.assertEqual((ok("contracts"), ok("logic"), ok("safety")), (2, 1, 2))
        self.assertLessEqual(sum(1 for _, s in got if s == "ok"), 6)
        self.assertEqual([doc_of(r)["retrieval"]["toolCallsRemaining"] for r in spy.requests
                          if r["role"] == "investigator" and r["hop"] == 0], [2, 1, 2])

    def test_spend_share_stops_a_specialist_before_its_next_call(self):
        m = self.case()
        probe, _ = self.record_v3(m, script(ask("contracts", 0), sfinal("contracts", 1), ask("logic", 0),
                                            sfinal("logic", 1), ask("safety", 0), sfinal("safety", 1), judge()),
                                  eval_id="evr_" + "7" * 16)
        per_call = [e["record"]["usdMicros"] for e in events_of(probe) if e["type"] == "cost"
                    and e["record"]["stage"] == "INVESTIGATE"]
        self.assertTrue(per_call and all(c > 0 for c in per_call), per_call)
        plan = copy.deepcopy(V3_PLAN)
        # an investigation share whose first third is used up by contracts' first call
        plan["budget"]["verifyReserveBp"] = 0
        plan["budget"]["maxUsdMicros"] = 3 * per_call[0]
        hc, hl = self.h_contract(m), self.h_logic(m)
        res, spy = self.record_v3(m, script(ask("contracts", 0), sfinal("contracts", 1, hc), sfinal("logic", 0, hl),
                                            sfinal("logic", 1, hl), ask("safety", 0), sfinal("safety", 1), judge()),
                                  plan=plan)
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([a["status"] for a in agents], ["budget", "completed", "budget"])
        self.assertEqual(agents[0]["error"]["detail"]["scope"], "specialist-share")
        self.assertEqual(agents[0]["error"]["detail"]["ceilingUsdMicros"], per_call[0])
        self.assertEqual([c["ordinal"] for c in inv_calls(res) if c["agentId"] == "contracts"], [0])   # hop 1 never sent
        # the next specialist still starts on the rolled-forward share; its floor continuation is then refused by its
        # own ceiling and the draft is used (floor fallback, disclosed as budget)
        self.assertEqual(floors(res), [("logic", "continue"), ("logic", "draft")])
        self.assertEqual([h["specialist"] for h in res.hypotheses], ["logic"])
        self.assertEqual(agents[2]["error"]["detail"]["scope"], "run")           # the gateway's own admission
        self.assertEqual({i["reason"] for i in res.incomplete if i["stage"] == "INVESTIGATE"}, {"budget"})
        self.assertEqual(validate_trace(events_of(res)), [])


class Merge(SpecRig):
    def H(self, agent, n, path, line, cat, end=None):
        loc = {"path": path, "line": line, **({"endLine": end} if end else {})}
        return {"id": shid(agent, n, {"claim": f"{agent}{n}", "location": loc}), "specialist": agent,
                "claim": f"{agent}{n}", "category": cat, "location": loc}

    def test_merge_rule(self):
        a = self.H("contracts", 0, "x.py", 10, "bug", 12)
        a2 = self.H("contracts", 1, "x.py", 11, "bug")                # same agent: never merged
        b = self.H("logic", 0, "x.py", 12, "bug", 20)                 # overlaps a at 12
        c = self.H("logic", 1, "x.py", 13, "bug")                     # overlaps b only (b is merged: not a base)
        d = self.H("safety", 0, "x.py", 10, "security")               # other category
        e = self.H("safety", 1, "y.py", 10, "bug")                    # other path
        f = self.H("safety", 2, "x.py", 13, "bug")                    # overlaps c (kept, earlier agent)
        g = self.H("safety", 3, "x.py", 11, "bug")                    # overlaps a and a2: the first kept wins
        got = specialists.merge([a, a2, b, c, d, e, f, g])
        self.assertEqual(got, [{"keptId": a["id"], "mergedIds": [b["id"], g["id"]], "rule": "specialist-merge@1"},
                               {"keptId": c["id"], "mergedIds": [f["id"]], "rule": "specialist-merge@1"}])
        self.assertEqual(specialists.merge([a, a2]), [])
        self.assertEqual(specialists.MERGE_RULE, "specialist-merge@1")

    def test_duplicates_are_dropped_before_verify_and_recorded(self):
        m = self.case()
        hc, hs = self.h_contract(m), self.h_safety(m)
        dup = hyp(m, "src/lib.py", 1, end=2, claim="cache default removed (logic view)", category="breaking-change",
                  impact="crash", evidence=[m.cite("src/lib.py", 1)])
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), ask("logic", 0), sfinal("logic", 1, dup),
                     ask("safety", 0), sfinal("safety", 1, hs),
                     vfinal(0, m, path="src/lib.py", line=1), vfinal(1, m, path="src/lib.py", line=1),
                     judge(w([shid("contracts", 0, hc)]), w([shid("safety", 0, hs)])))
        res, spy = self.record_v3(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        kept, merged = shid("contracts", 0, hc), shid("logic", 0, dup)
        p = self.payload(res)["payload"]
        self.assertEqual(p["merges"], [{"keptId": kept, "mergedIds": [merged], "rule": "specialist-merge@1"}])
        self.assertIn(merged, [h["id"] for h in p["hypotheses"]])       # kept in the artifact for audit
        self.assertEqual({e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")},
                         {kept, shid("safety", 0, hs)})                  # no verifier call for the duplicate
        drops = [d for d in res.drops if d["reason"] == "merged"]
        self.assertEqual([d["subjectIds"] for d in drops], [[merged]])
        self.assertIn(kept, drops[0]["detail"])
        self.assertEqual(len(res.findings), 2)

    def test_more_than_the_cap_are_dropped_as_over_cap(self):
        m = self.case()
        cats = ("bug", "performance", "security", "style")
        hs = {a: [hyp(m, "src/lib.py", line, claim=f"{a} {cat} {line}", category=cat, evidence=[m.cite("src/lib.py", line)])
                  for cat in cats[2 * i:2 * i + 2] for line in range(1, 7)] for i, a in enumerate(AGENTS[:2])}
        ids = [shid(a, n, h) for a in AGENTS[:2] for n, h in enumerate(hs[a])]
        self.assertEqual(len(ids), 24)
        vs = [vfinal(k, verdict="uncertain", evidence=[]) for k in range(20)]
        scr = script(ask("contracts", 0), sfinal("contracts", 1, *hs["contracts"]),
                     ask("logic", 0), sfinal("logic", 1, *hs["logic"]),
                     ask("safety", 0), sfinal("safety", 1), *vs, judge())
        res, _ = self.record_v3(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(self.payload(res)["payload"]["merges"], [])
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")], ids[:20])
        self.assertEqual([d["subjectIds"][0] for d in res.drops if d["reason"] == "over-cap"], ids[20:])
        self.assertEqual(specialists.MAX_VERIFY_CANDIDATES, 20)


class Tolerance(SpecRig):
    def test_one_failed_specialist_does_not_fail_the_run(self):
        m = self.case()
        hc, hs = self.h_contract(m), self.h_safety(m)
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), *sfail("logic", 0),
                     ask("safety", 0), sfinal("safety", 1, hs),
                     vfinal(0, m, path="src/lib.py", line=1), vfinal(1, m, path="src/lib.py", line=1),
                     judge(w([shid("contracts", 0, hc)]), w([shid("safety", 0, hs)])))
        res, _ = self.record_v3(m, scr)
        self.assertEqual((res.status, res.incomplete), ("completed", []))     # not a run limit
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([(a["agentId"], a["status"]) for a in agents],
                         [("contracts", "completed"), ("logic", "failed"), ("safety", "completed")])
        self.assertEqual(agents[1]["error"]["code"], "provider-error")
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["contracts", "safety"])
        rep = self.replay_v3(m, res)
        self.assertEqual((rep.status, rep.error), ("completed", None))
        self.assertEqual(len(rep.findings), 2)

    def test_all_specialists_failing_fails_like_v2(self):
        m = self.case()
        res, _ = self.record_v3(m, script(*sfail("contracts", 0), *sfail("logic", 0), *sfail("safety", 0)))
        self.assertEqual((res.status, res.error["code"]), ("failed", "provider-error"))
        self.assertEqual([i["reason"] for i in res.incomplete], ["agent-failure"])
        v2, _ = self.record_v2(m, script(*[entry("INVESTIGATE", "investigator", "generalist", 0, a,
                                                 error=terr("provider-error", "INVESTIGATE")) for a in range(3)]),
                               eval_id="evr_" + "8" * 16)
        self.assertEqual((v2.status, v2.error["code"], v2.incomplete), (res.status, res.error["code"], res.incomplete))

    def test_a_spend_book_failure_fails_the_run_as_v2(self):
        from reviewer.gateway import SpendBook

        class BrokenBook(SpendBook):          # settles contracts' two calls, then fails after the provider answered
            n = 0

            def settle(self, key, usd):
                BrokenBook.n += 1
                if BrokenBook.n >= 3:
                    raise OSError("disk full")
                return super().settle(key, usd)
        self.book = BrokenBook(self.handle)
        m = self.case()
        scr, _ = self.three_script(m)
        res, spy = self.record_v3(m, scr)
        self.assertEqual((res.status, res.error["code"]), ("failed", "internal"))
        self.assertTrue(res.receipt["needsReconciliation"])
        self.assertEqual(spy.calls, 3)                    # logic's first call; safety never starts, no VERIFY
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([a["agentId"] for a in agents], ["contracts", "logic"])
        self.assertEqual((res.hypotheses, res.findings), ([], []))

    def test_a_stage_deadline_stops_the_later_specialists_and_keeps_the_earlier_answers(self):
        m = self.case()
        hc = self.h_contract(m)
        plan = copy.deepcopy(V3_PLAN)
        plan["budget"].update(stageCeilingsSec={"INVESTIGATE": 90}, hostStopRecording=HOST_STOP_RECORDING)
        self.clock = lambda: 50.0 * (self.spies[-1].calls if self.spies else 0)
        scr = script(sfinal("contracts", 0, hc), sfinal("contracts", 1, hc), sfinal("logic", 0), sfinal("safety", 0),
                     vfinal(0, m, path="src/lib.py", line=1), judge(w([shid("contracts", 0, hc)])))
        res, _ = self.record_v3(m, scr, plan=plan)
        self.assertEqual(res.status, "partial")
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([a["status"] for a in agents], ["completed", "failed", "failed"])
        self.assertEqual({a["error"]["code"] for a in agents[1:]}, {"deadline-exceeded"})
        self.assertEqual({i["reason"] for i in res.incomplete if i["stage"] == "INVESTIGATE"}, {"deadline"})
        self.assertEqual(len(res.findings), 1)
        rep = self.replay_v3(m, res, plan=plan)
        self.assertEqual((rep.status, rep.error), (res.status, None))
        self.assertEqual(rep.incomplete, res.incomplete)

    def test_an_unknown_provider_outcome_starts_no_further_specialist(self):
        m = self.case()
        hc = self.h_contract(m)
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), *sfail("logic", 0, outcome=None),
                     ask("safety", 0), sfinal("safety", 1), vfinal(0, m, path="src/lib.py", line=1),
                     judge(w([shid("contracts", 0, hc)])))
        res, _ = self.record_v3(m, scr)
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual(agents[1]["error"]["detail"]["providerOutcome"], "unknown")
        self.assertEqual([(a["agentId"], a["status"]) for a in agents],
                         [("contracts", "completed"), ("logic", "failed"), ("safety", "failed")])
        self.assertFalse([c for c in inv_calls(res) if c["agentId"] == "safety"])     # never multiplied
        self.assertEqual((res.status, len(res.findings)), ("completed", 1))

    def test_a_systemic_failure_starts_no_further_specialist(self):
        from unittest import mock
        from reviewer.gateway import typed_error
        from reviewer.pipeline.engine import Engine
        real = Engine.model_call

        def substituted(eng, stage, role, agent, ordinal, request):     # e.g. a router answering with another model
            if agent == "logic":
                return None, typed_error("contract-violation", "response came from a different model than requested",
                                         stage=stage), []
            return real(eng, stage, role, agent, ordinal, request)
        m = self.case()
        hc = self.h_contract(m)
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), ask("safety", 0), sfinal("safety", 1),
                     vfinal(0, m, path="src/lib.py", line=1), judge(w([shid("contracts", 0, hc)])))
        with mock.patch.object(Engine, "model_call", substituted):
            res, spy = self.record_v3(m, scr)
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([(a["agentId"], a["status"], a["error"]["code"]) for a in agents[1:]],
                         [("logic", "failed", "contract-violation"), ("safety", "failed", "contract-violation")])
        self.assertIn("not started", agents[2]["error"]["message"])
        self.assertFalse([c for c in inv_calls(res) if c["agentId"] == "safety"])
        self.assertEqual((res.status, len(res.findings)), ("completed", 1))
        self.assertEqual(V3_SYSTEMIC, ("live-calls-disabled", "model-unresolved", "contract-violation"))

    def test_review_md_lists_the_specialists_only_for_v3(self):
        m = self.case()
        hc, hs = self.h_contract(m), self.h_safety(m)
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), *sfail("logic", 0),
                     ask("safety", 0), sfinal("safety", 1, hs),
                     vfinal(0, m, path="src/lib.py", line=1), vfinal(1, m, path="src/lib.py", line=1),
                     judge(w([shid("contracts", 0, hc)]), w([shid("safety", 0, hs)])))
        res, _ = self.record_v3(m, scr)
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("## Specialist investigators", md)
        self.assertIn("- logic: failed (`provider-error`); 0 resolved hypothesis(es)", md)
        self.assertIn("- contracts: completed; 1 resolved hypothesis(es)", md)
        s2, _, _ = self.floor_script(m)
        v2, _ = self.record_v2(m, s2, eval_id="evr_" + "6" * 16)
        self.assertNotIn("Specialist", Path(v2.review_path).read_text(encoding="utf-8"))

    def test_exhausted_specialist_is_disclosed_and_the_others_continue(self):
        m = self.case()
        hs = self.h_safety(m)
        pol = V3_POLICY.tightened(investigator_turns=2)
        scr = script(ask("contracts", 0), ask("contracts", 1), sfinal("logic", 0), ask("safety", 0),
                     sfinal("safety", 1, hs), vfinal(0, m, path="src/lib.py", line=1),
                     judge(w([shid("safety", 0, hs)])))
        res, _ = self.record_v3(m, scr, retrieval=pol)
        self.assertEqual(res.status, "partial")
        inc = [i for i in res.incomplete if i["stage"] == "INVESTIGATE"]
        self.assertEqual([i["reason"] for i in inc], ["tool-calls-exhausted"])
        self.assertTrue(inc[0]["detail"].startswith("specialist contracts: "))
        self.assertEqual([a["status"] for a in self.payload(res)["payload"]["agents"]],
                         ["failed", "completed", "completed"])
        self.assertEqual(len(res.findings), 1)


class IdentityAndReplay(SpecRig):
    def test_strict_replay_reproduces_a_v3_run(self):
        m = self.case()
        scr, _ = self.three_script(m)
        res, _ = self.record_v3(m, scr)
        rep = self.replay_v3(m, res)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(rep.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
        self.assertEqual([h["id"] for h in rep.hypotheses], [h["id"] for h in res.hypotheses])
        body = lambda r: Path(r.review_path).read_text(encoding="utf-8").replace(r.run_id, "R").split("## Cost")[0]  # noqa: E731
        self.assertEqual(body(rep), body(res))

    def test_a_v3_recording_does_not_replay_under_v2(self):
        m = self.case()
        scr, _ = self.three_script(m)
        res, _ = self.record_v3(m, scr)
        with self.assertRaises(PipelineError) as c:
            self.replay(m, res, profile=V2_PROFILE, plan=TURN_PLAN, retrieval=V2_POLICY)
        self.assertEqual(c.exception.code, "identity-mismatch")

    def test_v1_and_v2_first_requests_and_identities_are_byte_identical(self):
        m = self.case()
        s1, _ = self.cross_file_script(m)
        v1, _ = self.record_impact(m, s1)
        self.assertEqual((model_calls(v1, "INVESTIGATE")[0]["requestHash"], v1.run["configSnapshotId"]), V1_PIN)
        s2, _ = self.cross_file_script(m)
        v2, _ = self.record_v2(m, s2, eval_id="evr_" + "3" * 16)
        self.assertEqual((model_calls(v2, "INVESTIGATE")[0]["requestHash"], v2.run["configSnapshotId"]), V2_PIN)
        s3, _, _ = self.floor_script(m)
        fl, _ = self.record_v2(m, s3, eval_id="evr_" + "4" * 16)
        self.assertEqual([e["requestHash"] for e in model_calls(fl)], V2_FLOOR_REQUESTS)
        self.assertEqual([f["decision"] for f in v2_floors(fl)], ["continue", "final"])
        self.assertEqual([h["specialist"] for h in fl.hypotheses], ["generalist"])
        self.assertNotIn("merges", self.payload(fl)["payload"])
        v3, _ = self.record_v3(m, self.three_script(m)[0], eval_id="evr_" + "5" * 16)
        self.assertNotIn(v3.run["configSnapshotId"], (V1_PIN[1], V2_PIN[1]))

    def test_lens_k_budget_and_merge_rule_are_bound_into_the_identity(self):
        m = self.case()
        backend, _ = self.record_backend(script())
        spec = self.spec(m, backend, profile=V3_PROFILE, plan=V3_PLAN, retrieval=V3_POLICY)
        base = identity.config_snapshot_id(spec)
        old = prompts.IMPACT_V3_TEMPLATES["lenses"]
        try:
            prompts.IMPACT_V3_TEMPLATES["lenses"] = old[:2]
            self.assertNotEqual(identity.config_snapshot_id(spec), base)
        finally:
            prompts.IMPACT_V3_TEMPLATES["lenses"] = old
        for name, value in (("MAX_VERIFY_CANDIDATES", 19), ("MERGE_TEXT", "x"), ("BUDGET_TEXT", "y"),
                            ("AGENTS", ("contracts", "logic"))):
            orig = getattr(specialists, name)
            try:
                setattr(specialists, name, value)
                self.assertNotEqual(identity.config_snapshot_id(spec), base, name)
            finally:
                setattr(specialists, name, orig)
        self.assertEqual(identity.config_snapshot_id(spec), base)
        doc = specialists.identity_doc(V3_POLICY, V3_PLAN["budget"], identity.tool_limits(spec).max_calls)
        self.assertEqual((doc["behavior"], doc["agents"], doc["merge"]["rule"], doc["budget"]["rule"]),
                         ("specialist-investigators@1", list(AGENTS), "specialist-merge@1", "specialist-budget-split@1"))

    def test_plan_must_name_the_specialists(self):
        m = self.case()
        scr, _ = self.three_script(m)
        with self.assertRaises(PipelineError) as c:
            self.record_v3(m, scr, plan=TURN_PLAN)
        self.assertEqual(c.exception.code, "invalid-input")
        s1, _ = self.cross_file_script(m)
        with self.assertRaises(PipelineError):
            self.record_v2(m, s1, plan=V3_PLAN)

    def test_investigate_payload_contract(self):
        hid0 = "hyp_" + "a" * 16
        base = {"stage": "INVESTIGATE", "hypotheses": [], "agents": []}
        self.assertEqual(validate("StagePayload", base), [])
        ok = dict(base, merges=[{"keptId": hid0, "mergedIds": ["hyp_" + "b" * 16], "rule": "specialist-merge@1"}])
        self.assertEqual(validate("StagePayload", ok), [])
        for bad in ([{"keptId": hid0, "mergedIds": [], "rule": "specialist-merge@1"}],
                    [{"keptId": hid0, "mergedIds": ["hyp_" + "b" * 16], "rule": "other@1"}]):
            self.assertNotEqual(validate("StagePayload", dict(base, merges=bad)), [])


if __name__ == "__main__":
    import unittest
    unittest.main()
