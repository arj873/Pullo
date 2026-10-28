"""LIVE-DEADLINE-02 part A: configurable stage ceilings (Plan budget stageCeilingsSec). Time is injected (fake clock)."""

from __future__ import annotations

import json

from reviewer.contracts.budget import HOST_STOP_RECORDING
from reviewer.pipeline import ReviewSpec, engine_identity, identity, run_review

from .helpers import PLAN, PROFILE, Rig, entry, events_of, hid, hyp, inv, judge, model_calls, resp, script, ver


def wording(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


class Scenario(Rig):
    def two(self):
        m = self.mini()
        h0, h1 = hyp(m, "src/a.py", 2, claim="first"), hyp(m, "src/a.py", 5, claim="second")
        full = [inv(h0, h1), ver(0, m, path="src/a.py", line=2), ver(1, m, path="src/a.py", line=5),
                judge(wording([hid(0, h0)], "First", "b"), wording([hid(1, h1)], "Second", "b"))]
        return m, h0, h1, full

    def plan(self, ceilings=None, record=False, **budget):
        p = json.loads(json.dumps(PLAN))
        p["budget"].update(budget)
        if ceilings is not None:
            p["budget"]["stageCeilingsSec"] = ceilings
        if record:
            p["budget"]["hostStopRecording"] = HOST_STOP_RECORDING
        return p

    def per_call_clock(self, step):
        """A fake clock that advances `step` seconds per provider call (a realistic multi-hop stage)."""
        self.clock = lambda: step * self.spies[-1].calls

    def stops(self, res):
        return [(e["stage"], e["scope"], e["code"]) for e in events_of(res) if e["type"] == "host.stop"]


class Legacy(Scenario):
    def test_default_plan_still_stops_verify_at_45s_and_records_no_host_stop(self):
        m, *_, full = self.two()
        self.per_call_clock(50.0)                    # VERIFY candidate 0 ends 50 s after it started
        res, spy = self.record(m, script(*full))
        self.assertEqual((res.status, spy.calls, [d["reason"] for d in res.drops]), ("partial", 3, ["deadline"]))
        self.assertEqual(self.stops(res), [])        # legacy: gate stops are not trace events

    def test_boundary_equality_stops_and_one_below_proceeds(self):
        for at, calls, status in ((45.0, 3, "partial"), (44.0, 4, "completed")):
            with self.subTest(at=at):
                m, *_, full = self.two()
                self.clock = lambda at=at: at if self.spies[-1].calls >= 2 else 0.0
                res, spy = self.record(m, script(*full))
                self.assertEqual((spy.calls, res.status), (calls, status))
                self.setUp()                          # fresh book/out dirs for the next sub-case

    def test_plan_without_the_key_keeps_its_identity_and_the_key_changes_it(self):
        m, *_, full = self.two()
        backend, _ = self.record_backend(script(*full))
        spec = lambda plan: ReviewSpec(case=m.case, base=m.base, head=m.head, profile=PROFILE, plan=plan,
                                       host=self.host(m.id), backend=backend)
        base = identity.config_snapshot_id(spec(PLAN))
        self.assertEqual(identity.config_snapshot_id(spec(self.plan())), base)
        with_key = identity.config_snapshot_id(spec(self.plan({"VERIFY": 240})))
        self.assertNotEqual(with_key, base)
        self.assertEqual(identity.config_snapshot_id(spec(self.plan({"VERIFY": 240}))), with_key)
        self.assertNotEqual(identity.config_snapshot_id(spec(self.plan({"VERIFY": 241}))), with_key)
        self.assertNotEqual(identity.config_snapshot_id(spec(self.plan(record=True))), base)   # recording is pinned


class Configured(Scenario):
    def test_realistic_multi_hop_verify_over_45s_completes_with_a_configured_ceiling(self):
        m, h0, h1, full = self.two()
        self.per_call_clock(50.0)
        res, spy = self.record(m, script(*full), plan=self.plan({"VERIFY": 240}, record=True))
        self.assertEqual((res.status, spy.calls, len(res.comments), res.drops), ("completed", 4, 2, []))
        self.assertEqual(self.stops(res), [])

    def test_ceiling_applies_at_its_boundary_and_other_stages_keep_the_table(self):
        m, h0, h1, full = self.two()
        self.clock = lambda: 60.0 if self.spies[-1].calls >= 2 else 0.0
        res, spy = self.record(m, script(*full), plan=self.plan({"VERIFY": 60}, record=True))
        self.assertEqual((res.status, spy.calls), ("partial", 3))                  # 60 >= 60 stops
        self.assertEqual([s for s in self.stops(res) if s[0] == "VERIFY"][0][2], "stage-deadline")
        self.setUp()
        m, h0, h1, full = self.two()
        self.clock = lambda: 59.0 if self.spies[-1].calls >= 2 else 0.0
        res, spy = self.record(m, script(*full), plan=self.plan({"VERIFY": 60}, record=True))
        self.assertEqual((res.status, spy.calls), ("completed", 4))

    def test_hard_run_deadline_beats_a_larger_stage_ceiling(self):
        m, *_, full = self.two()
        self.clock = lambda: 1000.0 if self.spies[-1].calls >= 2 else 0.0
        res, spy = self.record(m, script(*full), plan=self.plan({"VERIFY": 300}, record=True))
        self.assertEqual(spy.calls, 2)
        self.assertEqual(self.stops(res)[0][2], "hard-deadline")

    def test_cancellation_precedes_a_deadline_and_a_configured_ceiling(self):
        m, *_, full = self.two()
        self.clock = lambda: 1000.0
        res, spy = self.record(m, script(*full), plan=self.plan({"VERIFY": 300}, record=True), cancel=lambda: True)
        self.assertEqual((res.status, spy.calls), ("cancelled", 0))
        self.assertEqual(self.stops(res)[0][2], "cancelled")

    def test_soft_deadline_blocks_only_a_new_agent_and_is_recorded(self):
        m, *_, full = self.two()
        t = [0.0]
        self.clock = lambda: t[0]
        from reviewer.pipeline import Hooks
        res, spy = self.record(m, script(*full), plan=self.plan({"VERIFY": 300}, record=True),
                               hooks=Hooks(after_checkpoint=lambda st, d: t.__setitem__(
                                   0, 250.0 if st == "TRIAGE" else t[0])))
        self.assertEqual((spy.calls, res.error["code"]), (0, "deadline-exceeded"))
        self.assertEqual(self.stops(res), [("INVESTIGATE", "new-agent", "soft-deadline")])

    def test_prompts_models_and_caps_are_untouched_by_timing(self):
        m, *_, full = self.two()
        self.per_call_clock(1.0)
        a, _ = self.record(m, script(*full), plan=self.plan({"VERIFY": 240}, record=True))
        self.setUp()
        m2, *_, full2 = self.two()
        self.per_call_clock(1.0)
        b, _ = self.record(m2, script(*full2))
        self.assertEqual([c["request"] for c in model_calls(a)], [c["request"] for c in model_calls(b)])


class AttemptGuard(Scenario):
    """RunGuard (before every provider attempt, retry and repair) uses the same effective ceilings as Engine.gate."""

    def attempt(self, plan):
        m = self.mini()
        bad = entry("INVESTIGATE", "investigator", "generalist", 0, 0, response=resp(None, status="invalid-output",
                                                                                      raw="{x"))
        backend, spy = self.record_backend(script(bad, inv(hyp(m, "src/a.py", 2), attempt=1)))
        self.clock = lambda: 200.0 if spy.calls >= 1 else 0.0          # past the legacy INVESTIGATE 120 s ceiling
        res = run_review(ReviewSpec(case=m.case, base=m.base, head=m.head, profile=PROFILE, plan=plan,
                                    host=self.host(m.id, clock=self.clock), backend=backend))
        return res, spy

    def test_legacy_ceiling_blocks_the_repair_attempt(self):
        res, spy = self.attempt(PLAN)
        self.assertEqual(spy.calls, 1)
        self.assertEqual([c["error"]["code"] if c.get("error") else "ok" for c in model_calls(res, "INVESTIGATE")],
                         ["ok", "deadline-exceeded"])

    def test_configured_ceiling_admits_the_repair_attempt(self):
        res, spy = self.attempt(self.plan({"INVESTIGATE": 300}))
        calls = model_calls(res, "INVESTIGATE")
        self.assertEqual([(c["attempt"], "error" in c) for c in calls], [(0, False), (1, False)])
        self.assertGreaterEqual(spy.calls, 2)

    def test_configured_ceiling_still_blocks_a_pre_attempt_beyond_it(self):
        res, spy = self.attempt(self.plan({"INVESTIGATE": 150}))
        self.assertEqual(spy.calls, 1)
        refused = [c for c in model_calls(res, "INVESTIGATE") if c.get("error")]
        self.assertEqual((refused[0]["error"]["code"], refused[0]["error"]["detail"]["refusedBy"]),
                         ("deadline-exceeded", "host-guard"))
        costs = {e["record"]["callId"]: e["record"] for e in events_of(res) if e["type"] == "cost"}
        self.assertEqual(costs[refused[0]["callId"]]["usdMicros"], 0)          # a pre-attempt refusal costs nothing
