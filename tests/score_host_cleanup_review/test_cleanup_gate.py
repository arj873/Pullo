"""SCORE-HOST-11 independent Recorder-cleanup regressions (behavioural, on-disk trace/ledger; fake key/state/transport only).
Run inside a variant tree: python3 -I -B -m unittest discover -s tests/score_host_cleanup_review -t ."""
from __future__ import annotations

import fcntl
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from reviewer import score_host as S
from reviewer.benchmark import allpairs as A
from reviewer.gateway import load_trace
from reviewer.gateway.trace import Recorder
from tests.score_host.test_score_host import EVR, Env


def trace_file(env):
    return next(env.store.glob("*.trace.jsonl"))


def events(p):
    return [json.loads(x) for x in Path(p).read_text().splitlines() if x.strip()]


def ends(p):
    return [e for e in events(p) if e.get("type", "").endswith("run.end")]


def open_fds(p):
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            n += os.readlink(f"/proc/self/fd/{fd}") == str(p)
        except OSError:
            pass
    return n


class CleanupGate(Env):
    def assert_failed_terminal(self, t):
        e = ends(t)
        self.assertEqual([x["status"] for x in e], ["failed"], "exactly one typed failed terminal event")
        load_trace(t)                                                          # strict loader accepts the trace as complete
        self.assertEqual(open_fds(t), 0, "trace fd leaked")
        fd = os.open(self.store / "scorer.lock", os.O_RDWR | os.O_CREAT, 0o600)   # whole-run lock released
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def test_pipeline_error_after_charged_calls_keeps_charges_original_exception_and_typed_end(self):
        h = self.host()
        with mock.patch.object(A, "run_dedup", side_effect=RuntimeError("boom-original")):
            with self.assertRaises(RuntimeError) as cm:
                h.execute_offline()
        self.assertEqual(str(cm.exception), "boom-original")
        t = trace_file(self)
        self.assert_failed_terminal(t)
        n = len(self.intents())
        self.assertEqual((n, len(self.transport.bodies)), (2, 2))             # extraction charges retained, never released
        self.assertEqual(len(self.intents()), n)

    def test_startup_hold_appearing_after_trace_start_leaves_failed_end_and_no_send(self):
        h = self.host()
        real = h.ledger.scoring_startup_hold

        def hold():                                                           # appears only once the trace has started (post-start)
            started = any(p.stat().st_size > 0 for p in self.store.glob("*.trace.jsonl"))
            return {"reason": "late-hold"} if started else real()
        h.ledger.scoring_startup_hold = hold
        with self.assertRaises(S.ScoreHostError) as cm:
            h.execute_offline()
        self.assertEqual(cm.exception.reason, "scoring-startup-hold")
        self.assertEqual((len(self.transport.bodies), len(self.intents())), (0, 0))
        self.assert_failed_terminal(trace_file(self))

    def test_end_failure_falls_back_to_close_and_never_masks_original(self):
        h = self.host()
        with mock.patch.object(A, "run_dedup", side_effect=ValueError("orig")), \
                mock.patch.object(Recorder, "end", side_effect=OSError("disk full")):
            with self.assertRaises(ValueError) as cm:
                h.execute_offline()
        self.assertEqual(str(cm.exception), "orig")
        t = trace_file(self)
        self.assertEqual(ends(t), [])                                         # end impossible: start-only crash record, still closed
        self.assertEqual(open_fds(t), 0)

    def test_failure_after_completed_end_does_not_add_second_end(self):
        h = self.host()
        with mock.patch.object(S.ScoreHost, "_store", side_effect=OSError("store-fail")):
            with self.assertRaises(OSError) as cm:
                h.execute_offline()
        self.assertEqual(str(cm.exception), "store-fail")
        t = trace_file(self)
        self.assertEqual([x["status"] for x in ends(t)], ["completed"])
        self.assertEqual(open_fds(t), 0)

    def test_keyboard_interrupt_is_typed_and_propagates(self):
        h = self.host()
        with mock.patch.object(A, "run_dedup", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                h.execute_offline()
        self.assert_failed_terminal(trace_file(self))

    def test_same_id_rerun_after_failure_is_immutable_and_normal_runs_unchanged(self):
        h = self.host()
        with mock.patch.object(A, "run_dedup", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                h.execute_offline()
        t = trace_file(self)
        before = t.read_bytes()
        h2 = self.host()
        with self.assertRaises(FileExistsError):
            h2.execute_offline()
        self.assertEqual(t.read_bytes(), before)                              # no overwrite, deletion or extension
        h3 = self.host(evr="evr_9999999999999999")                            # different id completes normally
        rep = h3.execute_offline()
        self.assertTrue(rep["complete"])
        t3 = next(p for p in self.store.glob("*.trace.jsonl") if p != t)
        self.assertEqual([x["status"] for x in ends(t3)], ["completed"])

    def test_partial_run_has_single_partial_end(self):
        h = self.host(run_ceiling=60_000)                                        # complete pair set does not fit the run ceiling -> partial
        rep = h.execute_offline()
        self.assertFalse(rep["complete"])
        self.assertEqual([x["status"] for x in ends(trace_file(self))], ["partial"])

    def test_replay_error_preserves_original_and_adds_no_spend(self):
        h = self.host()
        h.execute_offline()
        t = trace_file(self)
        pin = "sha256:" + __import__("hashlib").sha256(t.read_bytes()).hexdigest()
        n = len(self.intents())
        rep_host = self.host(evr="evr_8888888888888888")
        with mock.patch.object(A, "run_dedup", side_effect=RuntimeError("replay-orig")):
            with self.assertRaises(RuntimeError) as cm:
                rep_host.replay(t, pin, "evr_7777777777777777")
        self.assertEqual(str(cm.exception), "replay-orig")
        self.assertEqual(len(self.intents()), n)


if __name__ == "__main__":
    unittest.main()
