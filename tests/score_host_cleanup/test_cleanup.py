"""SELF-PR27-FIX-01: Recorder cleanup regression tests (audit/cleanup only). Fake key/state/transport; no real env/auth/provider/network."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from reviewer import score_host as S
from reviewer.benchmark import allpairs as A
from reviewer.gateway import load_trace
from reviewer.gateway.trace import Recorder
from tests.score_host.test_score_host import EVR, EVR2, Env


class CapRecorder(Recorder):
    made = []

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        CapRecorder.made.append(self)


def open_trace_fds(trace: Path) -> int:
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}") == str(trace):
                n += 1
        except OSError:
            pass
    return n


class Cleanup(Env):
    def setUp(self):
        super().setUp()
        CapRecorder.made = []
        p = mock.patch.object(S, "Recorder", CapRecorder)
        p.start()
        self.addCleanup(p.stop)

    def trace(self, h):
        return self.store / f"{h.run_id}.trace.jsonl"

    def assert_valid_failed(self, h):
        t = load_trace(self.trace(h))                                   # STRICT load: has a typed terminal run.end
        self.assertTrue(t.complete)
        end = t.events[-1]
        self.assertTrue(end["type"].endswith("run.end"))
        self.assertEqual(end["status"], "failed")
        self.assertEqual(end["incomplete"][0]["reason"], "unsent")
        self.assertEqual(open_trace_fds(self.trace(h)), 0)
        self.assertIsNone(CapRecorder.made[-1]._f)

    def test_hold_appearing_after_start_gets_typed_failed_end_and_closed_file(self):
        h = self.host()
        calls = []

        def hold():                                                         # a hold that appears only AFTER the recorder has started
            started = bool(CapRecorder.made and CapRecorder.made[-1].events)
            calls.append(started)
            return {"reason": "orphan"} if started else None
        h.ledger.scoring_startup_hold = hold
        with self.assertRaises(S.ScoreHostError) as cm:
            h.execute_offline()
        self.assertEqual(cm.exception.reason, "scoring-startup-hold")
        self.assertTrue(calls[-1] and not calls[0])
        self.assert_valid_failed(h)
        self.assertEqual((self.transport.bodies, self.intents()), ([], []))

    def test_injected_pipeline_exception_keeps_original_error_and_retained_charges(self):
        h = self.host()
        real = A.run_extract
        seen = []

        def flaky(call, cfg, ref, m, *a, **k):
            if seen:
                seen.append(self.ledger_path.read_bytes())               # accounting at the moment of failure
                raise RuntimeError("boom-original")
            seen.append(None)
            return real(call, cfg, ref, m, *a, **k)
        with mock.patch.object(S.A, "run_extract", flaky):
            with self.assertRaises(RuntimeError) as cm:
                h.execute_offline()
        self.assertEqual(str(cm.exception), "boom-original")              # the ORIGINAL exception, not a cleanup error
        self.assert_valid_failed(h)
        self.assertEqual(len(self.intents()), 1)                          # the call that was admitted stays in the ledger
        self.assertEqual(self.ledger_path.read_bytes(), seen[1])          # cleanup changed no accounting
        self.assertEqual(self.ledger.totals("scoring")["calls"], 1)

    def test_end_failure_falls_back_to_close_and_still_preserves_the_original_exception(self):
        h = self.host()

        def boom_end(self_, *a, **k):
            raise OSError("disk full")
        with mock.patch.object(S.A, "run_extract", side_effect=RuntimeError("boom-original")), \
                mock.patch.object(CapRecorder, "end", boom_end):
            with self.assertRaises(RuntimeError) as cm:
                h.execute_offline()
        self.assertEqual(str(cm.exception), "boom-original")
        self.assertEqual(open_trace_fds(self.trace(h)), 0)                # closed by the fallback
        self.assertIsNone(CapRecorder.made[-1]._f)
        t = load_trace(self.trace(h), allow_partial=True)                 # only the start event survives: a crash-style record
        self.assertFalse(t.complete)

    def test_end_failure_on_normal_completion_closes_and_propagates_the_end_error(self):
        h = self.host()

        def boom_end(self_, *a, **k):
            raise OSError("disk full")
        with mock.patch.object(CapRecorder, "end", boom_end):
            with self.assertRaises(OSError):
                h.execute_offline()
        self.assertEqual(open_trace_fds(self.trace(h)), 0)

    def test_normal_completed_and_partial_runs_are_unchanged_and_closed(self):
        h = self.host()
        rep = h.execute_offline()
        self.assertTrue(rep["complete"])
        t = load_trace(self.trace(h))
        self.assertEqual((t.complete, t.events[-1]["status"]), (True, "completed"))
        self.assertEqual(open_trace_fds(self.trace(h)), 0)
        self.setUp()
        h = self.host(ngold=3, ncomments=60, run_ceiling=900_000)         # complete-set does-not-fit: partial, not failed
        rep = h.execute_offline()
        self.assertEqual(rep["admission"]["reason"], "does-not-fit")
        t = load_trace(self.trace(h))
        self.assertEqual(t.events[-1]["status"], "partial")
        self.assertEqual(open_trace_fds(self.trace(h)), 0)

    def test_same_id_trace_is_immutable_no_overwrite_no_remapping(self):
        h = self.host()
        with mock.patch.object(S.A, "run_extract", side_effect=RuntimeError("boom-original")):
            with self.assertRaises(RuntimeError):
                h.execute_offline()
        before = self.trace(h).read_bytes()
        h2 = self.host()
        with self.assertRaises(FileExistsError):                          # unchanged policy: same id refused by O_EXCL, raw error kept
            h2.execute_offline()
        self.assertEqual(self.trace(h).read_bytes(), before)

    def test_replay_recorder_gets_failed_end_and_original_exception(self):
        h = self.host()
        h.execute_offline()
        from reviewer.gateway.trace import bytes_digest
        pin = bytes_digest(self.trace(h).read_bytes())
        CapRecorder.made = []
        with mock.patch.object(S.A, "run_extract", side_effect=RuntimeError("boom-replay")):
            with self.assertRaises(RuntimeError) as cm:
                h.replay(self.trace(h), pin, EVR2)
        self.assertEqual(str(cm.exception), "boom-replay")
        ev = CapRecorder.made[-1].events
        self.assertEqual((ev[0]["type"].endswith("run.start"), ev[-1]["type"].endswith("run.end"), ev[-1]["status"]), (True, True, "failed"))
        self.assertIsNone(CapRecorder.made[-1]._f)

    def test_gateway_construction_failure_still_closes_before_start(self):
        h = self.host(auth=self.auth(models=["anthropic/claude-sonnet-5.5"]))
        with self.assertRaises(S.ScoreHostError):
            h.execute_offline()
        self.assertEqual(open_trace_fds(self.trace(h)), 0)
        self.assertFalse(self.trace(h).exists() and self.trace(h).stat().st_size)    # no event was ever written

    def test_abort_helper_never_raises_and_leaves_an_ended_trace_alone(self):
        class Dead:
            events = []
            def end(self, *a, **k): raise OSError
            def close(self): raise OSError
        S._abort_trace(Dead())                                            # swallows both failures
        class Ended:
            events = [{"type": "score.run.end"}]
            closed = False
            def end(self, *a, **k): raise AssertionError("must not end twice")
            def close(self): self.closed = True
        e = Ended(); S._abort_trace(e); self.assertTrue(e.closed)


if __name__ == "__main__":
    unittest.main()
