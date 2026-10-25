"""Cancellation, deadlines, budgets, tool caps and the shared spend book. Time is injected (Rig.clock_value)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pipeline import HostConfig, Hooks, PipelineError, RecordBackend

from .helpers import (AUTH, PLAN, PROFILE, Rig, SpyProvider, entry, events_of, hid, hyp, inv, judge, model_calls, script,
                      terr, tool_calls, ver)


def wording(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


class Scenario(Rig):
    def two(self):
        m = self.mini()
        h0, h1 = hyp(m, "src/a.py", 2, claim="first"), hyp(m, "src/a.py", 5, claim="second")
        full = [inv(h0, h1), ver(0, m, path="src/a.py", line=2), ver(1, m, path="src/a.py", line=5),
                judge(wording([hid(0, h0)], "First", "b"), wording([hid(1, h1)], "Second", "b"))]
        return m, h0, h1, full

    def plan(self, **budget):
        p = json.loads(json.dumps(PLAN))
        p["budget"].update(budget)
        return p


class Cancellation(Scenario):
    def test_cancelled_before_any_work_contacts_no_provider_and_agrees_everywhere(self):
        m, *_, full = self.two()
        res, spy = self.record(m, script(*full), cancel=lambda: True)
        self.assertEqual((res.status, res.error["code"]), ("cancelled", "cancelled"))
        self.assertEqual(spy.calls, 0)
        self.assertEqual([i["reason"] for i in res.incomplete], ["cancelled"])
        self.assertEqual(res.stages["PREPARE"]["status"], "failed")
        self.assertEqual([res.stages[s]["status"] for s in ("TRIAGE", "INVESTIGATE", "VERIFY")], ["skipped"] * 3)
        self.assertEqual(events_of(res)[-1]["status"], "cancelled")
        self.assertEqual(json.loads(Path(res.run_dir, "run.json").read_text())["status"], "cancelled")
        self.assertIn("cancelled", Path(res.review_path).read_text())
        self.assertEqual(res.comments, [])

    def test_cancel_after_investigation_stops_verification_and_never_calls_the_provider_again(self):
        m, *_, full = self.two()
        flag = [False]
        hooks = Hooks(after_checkpoint=lambda st, d: flag.__setitem__(0, flag[0] or st == "INVESTIGATE"))
        res, spy = self.record(m, script(*full), cancel=lambda: flag[0], hooks=hooks)
        self.assertEqual((res.status, spy.calls), ("cancelled", 1))
        self.assertEqual([d["reason"] for d in res.drops], ["cancelled", "cancelled"])
        self.assertEqual(res.stages["VERIFY"]["status"], "partial")
        self.assertEqual(res.findings, [])
        self.assertEqual(len(model_calls(res)), 1)

    def test_cancel_mid_verification_publishes_already_verified_findings_without_another_call(self):
        m, h0, h1, full = self.two()
        res, spy = self.record(m, script(*full), cancel=lambda: self.spies[-1].calls >= 2)
        self.assertEqual(res.status, "cancelled")
        self.assertEqual(spy.calls, 2)                              # investigator + first verifier, nothing after
        self.assertEqual([f["id"] for f in res.findings], [hid(0, h0)])
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, h0)]])
        self.assertTrue(res.comments[0]["title"].startswith("bug: first"))     # deterministic wording, no judge call
        self.assertEqual([d["reason"] for d in res.drops], ["cancelled"])
        self.assertEqual(res.stages["JUDGE"]["status"], "partial")
        self.assertEqual({i["reason"] for i in res.incomplete}, {"cancelled"})
        doc = json.loads(Path(res.comments_path).read_text())
        self.assertEqual((doc["status"], len(doc["comments"])), ("cancelled", 1))


class Deadlines(Scenario):
    def test_hard_deadline_mid_run_stops_new_calls_but_local_publication_continues(self):
        m, h0, h1, full = self.two()
        self.clock = lambda: 1000.0 if self.spies[-1].calls >= 2 else 0.0
        res, spy = self.record(m, script(*full))
        self.assertEqual(spy.calls, 2)
        self.assertEqual((res.status, {i["reason"] for i in res.incomplete}), ("partial", {"deadline"}))
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, h0)]])
        self.assertEqual([d["reason"] for d in res.drops], ["deadline"])
        self.assertEqual(res.stages["JUDGE"]["status"], "partial")

    def test_soft_deadline_stops_new_agents_but_lets_verification_drain(self):
        m, h0, h1, full = self.two()
        t = [0.0]
        self.clock = lambda: t[0]
        res, spy = self.record(m, script(*full), hooks=Hooks(after_checkpoint=lambda st, d: t.__setitem__(
            0, 250.0 if st == "INVESTIGATE" else t[0])))
        self.assertEqual((res.status, spy.calls, len(res.comments)), ("completed", 4, 2))   # 240 < 250 < 360
        t2 = [0.0]
        self.clock = lambda: t2[0]
        res2, spy2 = self.record(m, script(*full), eval_id="evr_" + "5" * 16,
                                 hooks=Hooks(after_checkpoint=lambda st, d: t2.__setitem__(
                                     0, 250.0 if st == "TRIAGE" else t2[0])))
        self.assertEqual(spy2.calls, 0)                                    # no new agent after the soft deadline
        self.assertEqual((res2.status, res2.error["code"]), ("failed", "deadline-exceeded"))
        self.assertEqual([i["reason"] for i in res2.incomplete], ["soft-deadline"])

    def test_stage_ceiling_ends_the_stage_not_the_run(self):
        m, h0, h1, full = self.two()
        self.clock = lambda: 50.0 if self.spies[-1].calls >= 2 else 0.0         # VERIFY ceiling is 45 s
        only_first = [*full[:3], judge(wording([hid(0, h0)], "First", "b"))]
        res, spy = self.record(m, script(*only_first))
        # candidate 1 is not started, the judge stage has its own clock and still runs
        self.assertEqual(spy.calls, 3)
        self.assertEqual((res.status, [d["reason"] for d in res.drops]), ("partial", ["deadline"]))
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, h0)]])
        self.assertEqual(res.comments[0]["title"], "First")                     # judge wording was available

    def test_tool_wall_time_is_enforced_by_the_injected_clock(self):
        m, *_, full = self.two()
        t = [0.0]
        self.clock = lambda: (t.__setitem__(0, t[0] + 70.0) or t[0])            # every reading advances 70 s
        res, spy = self.record(m, script(*full))
        self.assertIn(res.status, ("failed", "partial"))
        self.assertEqual(spy.calls, 0)
        self.assertTrue(any(i["reason"] == "deadline" for i in res.incomplete))


class Budget(Scenario):
    def test_budget_refusals_are_typed_per_candidate_and_never_overrun(self):
        m, h0, h1, full = self.two()
        res, spy = self.record(m, script(*full), plan=self.plan(maxUsdMicros=180_000, verifyReserveBp=3000))
        # investigator + first verifier fit; the second verifier and the judge are refused before the provider
        # is contacted, and the verified finding is still published with deterministic wording
        self.assertEqual(spy.calls, 2)
        self.assertEqual(res.status, "partial")
        self.assertEqual({(i["stage"], i["reason"]) for i in res.incomplete}, {("VERIFY", "budget"), ("JUDGE", "budget")})
        self.assertEqual([d["reason"] for d in res.drops], ["budget"])
        self.assertEqual(res.gateway_report["overruns"], [])
        self.assertLessEqual(res.gateway_report["spend"]["committed"], 180_000)
        self.assertEqual((res.stages["VERIFY"]["status"], res.stages["JUDGE"]["status"]), ("partial", "partial"))
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, h0)]])
        self.assertTrue(res.comments[0]["title"].startswith("bug: first"))

    def test_one_durable_spend_book_bounds_the_whole_evaluation_across_cases_and_processes(self):
        store = self.tmp / "book.jsonl"
        auth = json.loads(AUTH)
        auth.update(maxUsdMicrosPerRun=150_000, maxUsdMicrosTotal=150_000)
        (self.tmp / "operator/small.json").write_text(json.dumps(auth))
        handle = trusted_authorization(self.tmp / "operator/small.json")
        plan = self.plan(maxUsdMicros=150_000)
        outcomes = []
        for n in range(3):
            self.book = SpendBook(handle, store=store)                           # a fresh book object each time
            self.handle = handle
            m = self.mini(f"mini-b{n}")
            res, spy = self.record(m, script(inv()), plan=plan, eval_id=f"evr_{n + 1:016d}")
            outcomes.append((res.status, (res.error or {}).get("detail", {}).get("scope"), spy.calls))
        self.assertEqual([o[0] for o in outcomes], ["completed", "completed", "failed"])
        self.assertEqual(outcomes[2][1:], ("total", 0))                          # refused by the shared book, no contact
        total = SpendBook(handle, store=store).totals()
        self.assertLessEqual(total["committed"] + total["inflight"], 150_000)

    def test_unusable_authorization_or_book_is_refused_before_any_run_exists(self):
        m, *_, full = self.two()
        other = dict(json.loads(AUTH), id="other-auth")
        (self.tmp / "operator/o.json").write_text(json.dumps(other))
        h2 = trusted_authorization(self.tmp / "operator/o.json")
        with self.assertRaises(PipelineError) as cm:
            RecordBackend(self.handle, SpendBook(h2), {}, lambda: "2026-10-25T12:00:00Z")
        self.assertEqual(cm.exception.code, "config")
        backend, spy = self.record_backend(script(*full))
        backend.clock = lambda: "2027-01-01T00:00:00Z"                           # authorization expired
        with self.assertRaises(PipelineError) as cm:
            from reviewer.pipeline import run_review
            run_review(self.spec(m, backend))
        self.assertEqual(cm.exception.code, "config")
        self.assertEqual((spy.calls, list(self.out.iterdir())), (0, []))
        unresolved = json.loads(json.dumps(PROFILE))
        unresolved["roles"]["judge"]["resolved"] = False
        backend2, spy2 = self.record_backend(script(*full))
        with self.assertRaises(PipelineError) as cm:
            from reviewer.pipeline import run_review
            run_review(self.spec(m, backend2, profile=unresolved, plan=PLAN))
        self.assertIn(cm.exception.code, ("config", "invalid-input"))
        self.assertEqual(spy2.calls, 0)


class ToolCaps(Scenario):
    def test_global_and_per_agent_tool_caps_hold_across_all_candidates_and_ids_never_collide(self):
        m = self.mini()
        hs = [hyp(m, "src/a.py", 3 * i + 2, claim=f"c{i}") for i in range(4)]
        scr = script(inv(*hs), *[ver(i, m, path="src/a.py", line=3 * i + 2) for i in range(4)],
                     judge(*[wording([hid(i, h)], f"t{i}") for i, h in enumerate(hs)]))
        res, spy = self.record(m, scr, plan=self.plan(maxToolCalls=7, maxToolCallsPerAgent=5))
        tools = tool_calls(res)
        by = {}
        for e in tools:
            by.setdefault((e["stage"], e["agentId"]), []).append(e["ordinal"])
        self.assertLessEqual(len(tools), 7)
        self.assertTrue(all(len(v) <= 5 for v in by.values()), by)
        self.assertTrue(all(v == list(range(len(v))) for v in by.values()), by)
        self.assertEqual(len({e["toolCallId"] for e in tools}), len(tools))
        self.assertEqual(res.status, "partial")
        self.assertIn("tool-calls-exhausted", {i["reason"] for i in res.incomplete})
        # exhausted context is disclosed, and verification still ran for every candidate
        self.assertEqual(len(model_calls(res, "VERIFY")), 4)
        self.assertIn("not collected", json.dumps(model_calls(res, "VERIFY")[3]["request"]))
        self.assertIn("tool-calls-exhausted", Path(res.review_path).read_text())

    def test_prepare_cap_is_reported_and_unlisted_diffs_are_still_changed_paths(self):
        m = self.mini()
        res, _ = self.record(m, script(inv()), plan=self.plan(maxToolCalls=2, maxToolCallsPerAgent=2))
        self.assertEqual(res.status, "partial")
        self.assertEqual(len(tool_calls(res, "PREPARE")), 2)
        files = [f["path"] for f in json.loads(Path(res.run_dir, "artifacts/02-PREPARE.v1.json").read_text())["payload"]["files"]]
        self.assertEqual(files, ["src/a.py", "src/b.py"])
        self.assertIn("PREPARE", [i["stage"] for i in res.incomplete])


if __name__ == "__main__":
    unittest.main()
