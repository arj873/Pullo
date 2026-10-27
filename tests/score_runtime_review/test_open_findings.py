"""SCORE-RT-04 retained reproductions of an OPEN finding (expected to FAIL on the current candidate; do not weaken).

F1: `RuntimeLedger.finish` is unrestricted, so any code holding the ledger can append a later `not-sent` result for a
scoring call that is an orphan intent or an `unknown` result. That erases its unknown exposure and clears the startup
hold: a release by assertion, not by reconcile. (Pristine main has the same unrestricted `finish`; RT-03 relies on it
being unreachable from the scoring provider, but the ledger API itself is the boundary root named.)"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

SRC = os.environ.get("SCORE_RT_SRC") or str(Path(__file__).resolve().parents[2])   # default: this checkout; env overrides
sys.path.insert(0, SRC)
sys.dont_write_bytecode = True
from reviewer.runtime import RuntimeLedger                      # noqa: E402

OPUS = "anthropic/claude-opus-5.5"
S = dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=20_000_000)


class F1(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.lg = RuntimeLedger(Path(self.d.name) / "l.jsonl", 50_000_000)

    def test_not_sent_cannot_be_appended_to_release_an_orphan_intent(self):
        # RT-06 fixture correction: the original (rt04-original-open-findings-8bfde41d.py) admitted and finished on the SAME
        # live instance, which is a legitimately owned in-flight call, not an orphan. A real orphan is a prior process's
        # intent, so the fixture reopens a fresh ledger after admission. The exposure/hold assertion is unchanged and now
        # runs on every path (the original returned early when finish raised).
        self.lg.admit("orphan", 5_000_000, model=OPUS, **S)
        reopened = RuntimeLedger(Path(self.d.name) / "l.jsonl", 50_000_000)
        try:
            reopened.finish("orphan", outcome="not-sent", errorKind="x", costBasis="unknown")
        except ValueError:
            pass
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.assertEqual(reopened.totals("scoring")["unknownBoundUsdMicros"], 5_000_000)

    def test_later_result_cannot_overwrite_an_unknown_outcome(self):
        self.lg.admit("u", 5_000_000, model=OPUS, **S)
        self.lg.finish("u", outcome="unknown", errorKind="timeout", costBasis="unknown")
        try:
            self.lg.finish("u", outcome="rejected-before-processing", errorKind="x", costBasis="unknown")
        except ValueError:
            return
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})


if __name__ == "__main__":
    unittest.main(verbosity=1)
