"""LIVE-DEADLINE-02 part B: recorded Engine.gate host stops replay at the same position (fast clock, zero calls)."""

from __future__ import annotations

from unittest import mock

from reviewer.contracts.budget import HOST_STOP_RECORDING_V1, HOST_STOP_RECORDING_V2
from reviewer.gateway import TraceError, bytes_digest, events_to_bytes, load_trace
from reviewer.pipeline import PipelineError
from reviewer.pipeline.engine import Engine

from .helpers import events_of
from .test_live_stage_deadlines import Scenario, script


class HostStopReplay(Scenario):
    def record_stopped(self, record=True):
        m, *_, full = self.two()
        self.per_call_clock(50.0)                       # VERIFY ceiling (45 s) is crossed after the first verifier
        res, spy = self.record(m, script(*full), plan=self.plan(record=record))
        return m, res, spy

    def replay_fast(self, m, res, **kw):
        self.clock = lambda: 0.0                         # the fast strict-replay clock never trips a deadline
        kw.setdefault("plan", self.plan(record=True))
        return self.replay(m, res, **kw)

    def summary(self, res):
        return (res.status, [(i["stage"], i["reason"]) for i in res.incomplete], len(res.hypotheses),
                [f["id"] for f in res.findings], [{k: v for k, v in c.items() if k != "runId"} for c in res.comments],
                [d["reason"] for d in res.drops])

    def test_deadline_stopped_recording_replays_the_same_partial_with_zero_calls(self):
        m, res, spy = self.record_stopped()
        stops = [e for e in events_of(res) if e["type"] == "host.stop"]
        self.assertEqual([(e["stage"], e["code"]) for e in stops], [("VERIFY", "stage-deadline")])
        self.assertEqual(res.status, "partial")
        before = len(self.spies)
        rep = self.replay_fast(m, res)
        self.assertEqual(self.summary(rep), self.summary(res))
        self.assertEqual(len(self.spies), before)        # no provider object exists in a strict replay
        self.assertEqual([e["afterSeq"] for e in events_of(rep) if e["type"] == "host.stop"],
                         [e["afterSeq"] for e in stops])

    def test_cancel_stop_replays_without_the_cancel_flag(self):
        m, *_, full = self.two()
        res, _ = self.record(m, script(*full), plan=self.plan(record=True), cancel=lambda: self.spies[-1].calls >= 2)
        self.assertEqual(res.status, "cancelled")
        rep = self.replay_fast(m, res)
        self.assertEqual(self.summary(rep), self.summary(res))
        self.assertEqual(rep.error["code"], "cancelled")

    def test_legacy_recording_of_a_gate_stop_still_fails_replay_as_a_documented_limitation(self):
        m, res, _ = self.record_stopped(record=False)
        self.assertEqual([e for e in events_of(res) if e["type"] == "host.stop"], [])    # legacy trace loads, no stops
        rep = self.replay_fast(m, res, plan=self.plan())
        self.assertEqual((rep.status, rep.error["code"]), ("failed", "replay-miss"))

    def tamper(self, res, fn):
        def edit(events):
            fn(events)
            return events
        return self.edited_copy(res, "tampered.jsonl", edit)

    def renumber(self, events):
        for i, e in enumerate(events):
            e["seq"] = i
            if e["type"] == "host.stop":
                e["afterSeq"] = i - 1

    def test_mutated_stop_position_is_rejected_when_the_trace_is_loaded(self):
        m, res, _ = self.record_stopped()
        def bump(events):
            next(e for e in events if e["type"] == "host.stop")["afterSeq"] += 1
        path, dig = self.tamper(res, bump)
        with self.assertRaises(TraceError):
            load_trace(path)

    def test_missing_stop_does_not_invent_one_from_the_fast_clock_it_fails_closed(self):
        m, res, _ = self.record_stopped()
        def drop(events):
            events[:] = [e for e in events if e["type"] != "host.stop"]
            self.renumber(events)
        path, dig = self.tamper(res, drop)
        rep = self.replay_fast(m, res, trace_path=path, digest=dig)
        self.assertEqual(rep.status, "failed")
        self.assertIn(rep.error["code"], ("replay-miss", "replay-mismatch"))

    def test_stop_with_a_different_scope_is_not_accepted_at_that_position(self):
        m, res, _ = self.record_stopped()
        def rescope(events):
            e = next(e for e in events if e["type"] == "host.stop")
            e["scope"] = "retrieval" if e["scope"] != "retrieval" else "tool"
        path, dig = self.tamper(res, rescope)
        rep = self.replay_fast(m, res, trace_path=path, digest=dig)
        self.assertEqual(rep.status, "failed")
        self.assertIn(rep.error["code"], ("replay-miss", "replay-mismatch"))

    def test_a_missing_preceding_event_moves_the_stop_and_is_rejected(self):
        m, res, _ = self.record_stopped()
        def drop_tool(events):
            i = next(i for i, e in enumerate(events) if e["type"] == "tool.call" and e["stage"] == "VERIFY")
            del events[i]
            self.renumber(events)
        path, dig = self.tamper(res, drop_tool)
        rep = self.replay_fast(m, res, trace_path=path, digest=dig)
        self.assertEqual(rep.status, "failed")
        self.assertIn(rep.error["code"], ("replay-miss", "replay-mismatch"))

    def test_tampered_bytes_still_need_the_pinned_digest(self):
        m, res, _ = self.record_stopped()
        path, dig = self.tamper(res, lambda ev: None)
        self.assertEqual(dig, bytes_digest(events_to_bytes(load_trace(res.trace_path).events)))


class AdjacentGates(HostStopReplay):
    """HOST-POSITION-01: two gate checks with no trace event between them share (stage, scope, afterSeq); host-stop@2 tells
    them apart by the stage's gate ordinal. The fake clock crosses the VERIFY ceiling exactly between two adjacent checks."""

    def record_collision(self, version=HOST_STOP_RECORDING_V2):
        m, *_, full = self.two()
        now, seen = [0.0], [0]
        self.clock = lambda: now[0]
        orig = Engine._clock_stop

        def wrapped(eng, stage, stage_t0, new_agent):
            if stage == "VERIFY":
                seen[0] += 1
                if seen[0] == 2:                          # the SECOND VERIFY check crosses the 45 s ceiling
                    now[0] = 60.0
            return orig(eng, stage, stage_t0, new_agent)
        plan = self.plan(record=True)
        plan["budget"]["hostStopRecording"] = version
        with mock.patch.object(Engine, "_clock_stop", wrapped):
            res, spy = self.record(m, script(*full), plan=plan)
        self.assertEqual(res.status, "partial", res.error)           # live MUST be a partial before any replay claim
        return m, res, plan

    def stops(self, res):
        return [e for e in events_of(res) if e["type"] == "host.stop"]

    def replay_with(self, m, res, plan, **kw):
        self.clock = lambda: 0.0
        return self.replay(m, res, plan=plan, **kw)

    def test_adjacent_outer_and_tool_gate_replays_the_same_partial_with_zero_calls(self):
        m, res, plan = self.record_collision()
        stops = self.stops(res)
        self.assertTrue(stops)
        self.assertEqual(stops[0]["gateOrdinal"], 2)                     # the outer gate (check 1) passed silently
        ords = [e["gateOrdinal"] for e in stops if e["stage"] == "VERIFY"]
        self.assertEqual(ords, sorted(set(ords)))                        # unique, strictly increasing within the stage
        before = len(self.spies)
        rep = self.replay_with(m, res, plan)
        self.assertEqual(self.summary(rep), self.summary(res))
        self.assertEqual((rep.status, len(rep.hypotheses)), (res.status, len(res.hypotheses)))
        self.assertEqual([(e["stage"], e["scope"], e["code"], e["afterSeq"], e["gateOrdinal"]) for e in self.stops(rep)],
                         [(e["stage"], e["scope"], e["code"], e["afterSeq"], e["gateOrdinal"]) for e in stops])
        self.assertEqual(len(self.spies), before)

    def test_v1_recording_keeps_its_documented_coarse_position_limitation(self):
        m, res, plan = self.record_collision(HOST_STOP_RECORDING_V1)
        self.assertTrue(all("gateOrdinal" not in e for e in self.stops(res)))     # v1 never writes ordinals
        rep = self.replay_with(m, res, plan)
        self.assertEqual((rep.status, rep.error["code"]), ("failed", "replay-mismatch"))   # not silently treated as @2

    def test_ordinals_are_per_stage_not_global(self):
        m, res, _ = self.record_collision()
        first = self.stops(res)[0]
        self.assertEqual(first["stage"], "VERIFY")
        self.assertEqual(first["gateOrdinal"], 2)        # earlier stages' checks do not shift VERIFY's position

    def test_ordinal_tamper_missing_bool_zero_and_duplicate_are_refused(self):
        m, res, plan = self.record_collision()

        def edit(fn):
            def go(events):
                fn([e for e in events if e["type"] == "host.stop"])
            return self.tamper(res, go)

        def missing(stops):
            del stops[0]["gateOrdinal"]
        path, dig = edit(missing)
        with self.assertRaises(PipelineError) as cm:                     # refused before any gate, i.e. before live access
            self.replay_with(m, res, plan, trace_path=path, digest=dig)
        self.assertEqual(cm.exception.code, "replay-recording")
        for bad in (True, 0, -3, "2", 1.5):
            path, dig = edit(lambda stops, b=bad: stops[0].__setitem__("gateOrdinal", b))
            with self.assertRaises((TraceError, PipelineError), msg=repr(bad)):
                self.replay_with(m, res, plan, trace_path=path, digest=dig)
        stops = self.stops(res)
        if len(stops) > 1:
            path, dig = edit(lambda s: s[1].__setitem__("gateOrdinal", s[0]["gateOrdinal"]))
            with self.assertRaises(PipelineError):
                self.replay_with(m, res, plan, trace_path=path, digest=dig)

    def test_shifted_ordinal_does_not_match_and_fails_closed(self):
        m, res, plan = self.record_collision()

        def shift_last(ev):
            last = [e for e in ev if e["type"] == "host.stop"][-1]       # stays strictly increasing, so it loads
            last["gateOrdinal"] += 1
        path, dig = self.tamper(res, shift_last)
        rep = self.replay_with(m, res, plan, trace_path=path, digest=dig)
        self.assertEqual(rep.status, "failed")
        self.assertIn(rep.error["code"], ("replay-miss", "replay-mismatch"))

    def test_stops_without_a_policy_are_refused_for_replay(self):
        m, res, plan = self.record_collision()
        with self.assertRaises(PipelineError):                           # legacy Plan (no hostStopRecording) vs a recording with stops
            self.replay_with(m, res, self.plan())

    def test_v1_policy_with_injected_ordinals_is_refused(self):
        m, res, plan = self.record_collision(HOST_STOP_RECORDING_V1)
        path, dig = self.tamper(res, lambda ev: next(e for e in ev if e["type"] == "host.stop").__setitem__("gateOrdinal", 1))
        with self.assertRaises(PipelineError) as cm:
            self.replay_with(m, res, plan, trace_path=path, digest=dig)
        self.assertEqual(cm.exception.code, "replay-recording")

    def test_live_cancel_is_still_honored_in_v2_replay(self):
        m, res, plan = self.record_collision()
        before = len(self.spies)
        self.clock = lambda: 0.0
        rep = self.replay(m, res, plan=plan, cancel=lambda: True)
        self.assertIn("cancelled", [e["code"] for e in self.stops(rep)])
        self.assertEqual(len(self.spies), before)
