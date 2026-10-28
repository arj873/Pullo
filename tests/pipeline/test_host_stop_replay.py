"""LIVE-DEADLINE-02 part B: recorded Engine.gate host stops replay at the same position (fast clock, zero calls)."""

from __future__ import annotations

from reviewer.gateway import TraceError, bytes_digest, events_to_bytes, load_trace

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
