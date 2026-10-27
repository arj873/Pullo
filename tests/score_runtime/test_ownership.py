"""SCORE-RT-05: scoring result ownership (no overwrite, no orphan completion by a new instance) and the estimated-exposure hold."""

from __future__ import annotations

import hashlib
import json
from unittest import mock

from reviewer.gateway.errors import AuthorizationError
from reviewer.runtime import RuntimeLedger, receipts
from reviewer.runtime.openrouter import TransportError
from tests.runtime.common import FakeTransport, OPUS, SONNET, completion
from tests.score_runtime.test_score_runtime import LedgerBase, OK_EXTRACT, S, ProviderBase, score_req


class Ownership(LedgerBase):
    def sha(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_owned_completions_work_for_every_outcome(self):
        for i, out in enumerate(("not-sent", "rejected-before-processing", "unknown", "processed")):
            self.lg.admit(f"k{i}", 1000, model=OPUS, **S)
            self.lg.finish(f"k{i}", outcome=out, errorKind="x", costBasis="unknown")
        self.assertEqual(self.lg.totals("scoring")["calls"], 4)

    def test_reopened_instance_cannot_finalize_a_prior_orphan_by_assertion(self):
        self.lg.admit("orphan", 5_000_000, model=OPUS, **S)
        again = RuntimeLedger(self.path, 50_000_000)                      # restart / new instance
        before = self.sha()
        for out in ("not-sent", "rejected-before-processing", "unknown", "processed"):
            with self.subTest(out=out), self.assertRaises(ValueError):
                again.finish("orphan", outcome=out, errorKind="x", costBasis="unknown")
        self.assertEqual(self.sha(), before)
        self.assertEqual(again.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.assertEqual(again.totals("scoring")["unknownBoundUsdMicros"], 5_000_000)

    def test_reopened_instance_cannot_overwrite_a_prior_unknown(self):
        self.lg.admit("u", 5_000_000, model=OPUS, **S)
        self.lg.finish("u", outcome="unknown", errorKind="timeout", costBasis="unknown")
        again = RuntimeLedger(self.path, 50_000_000)
        with self.assertRaises(ValueError):
            again.finish("u", outcome="not-sent", errorKind="x", costBasis="unknown")
        self.assertIsNotNone(again.scoring_startup_hold())

    def test_same_instance_cannot_overwrite_any_scoring_result(self):
        self.lg.admit("u", 5_000_000, model=OPUS, **S)
        self.lg.finish("u", outcome="unknown", errorKind="timeout", costBasis="unknown")
        for out in ("rejected-before-processing", "not-sent", "processed", "unknown"):
            with self.subTest(out=out), self.assertRaises(ValueError):
                self.lg.finish("u", outcome=out, errorKind="x", costBasis="unknown")
        self.assertEqual(sum(r["type"] == "result" for r in self.rows()), 1)

    def test_forked_child_is_not_the_owner(self):
        self.lg.admit("k", 1000, model=OPUS, **S)
        with mock.patch.object(receipts.os, "getpid", return_value=-7):
            with self.assertRaises(ValueError):
                self.lg.finish("k", outcome="not-sent", errorKind="x", costBasis="unknown")
        self.lg.finish("k", outcome="not-sent", errorKind="x", costBasis="unknown")      # the admitting pid still can

    def test_failed_or_refused_admission_grants_no_ownership(self):
        other = RuntimeLedger(self.path, 50_000_000)
        other.admit("k", 7_999_000, model=OPUS, **S)
        self.assertEqual(self.lg.admit("k2", 2000, model=OPUS, **S)["reason"], "scoring-campaign-cap")
        self.assertEqual(self.lg.admit("k", 1, model=OPUS, **S), {"reason": "duplicate-call-key"})
        self.assertEqual(self.lg._owned, {})
        with self.assertRaises(ValueError):
            self.lg.finish("k", outcome="not-sent")

    def test_review_semantics_unchanged(self):
        self.lg.admit("r", 10, model=SONNET)
        again = RuntimeLedger(self.path, 50_000_000)
        again.finish("r", outcome="unknown", errorKind="x", costBasis="unknown")      # not owned: still allowed for review
        again.finish("r", outcome="not-sent", errorKind="x", costBasis="unknown")      # overwrite: legacy behaviour
        self.lg.finish("never-admitted", outcome="not-sent", errorKind="x", costBasis="unknown")

    def test_refusal_is_fixed_and_safe(self):
        self.lg.admit("SENTINEL-key-9", 1234567, model=OPUS, **S)
        try:
            RuntimeLedger(self.path, 50_000_000).finish("SENTINEL-key-9", outcome="not-sent")
        except ValueError as e:
            self.assertNotIn("SENTINEL", str(e))
            self.assertNotIn("1234567", str(e))


class EstimatedHold(ProviderBase):
    def estimated_ledger(self):
        lg = RuntimeLedger(self.ledger_path, 50_000_000)
        lg.admit("e", 3_000_000, model=OPUS, **S)
        lg.finish("e", outcome="processed", generationId="gen-e", routerCostUsdMicros=0, tokenPricedUsdMicros=None,
                  upstreamInferenceCostUsdMicros=None, isByok=None)         # unverifiable zero -> estimated worst case
        t = lg.totals("scoring")
        self.assertEqual((t["unknownBoundUsdMicros"], t["estimatedUsdMicros"]), (0, 3_000_000))
        return lg

    def test_estimated_scoring_exposure_holds_provider_startup_without_mutation(self):
        self.estimated_ledger()
        before = self.ledger_path.read_bytes()
        with self.assertRaises(AuthorizationError) as cm:
            self.sp()
        self.assertIn("prior-unresolved-scoring-exposure", str(cm.exception))
        self.assertEqual(self.ledger_path.read_bytes(), before)

    def test_estimated_clears_only_through_reconcile(self):
        lg = self.estimated_ledger()
        self.assertIsNotNone(lg.scoring_startup_hold())
        lg.reconcile("e", {"id": "gen-e", "total_cost": "0.000250"})
        self.assertIsNone(lg.scoring_startup_hold())
        self.sp()

    def test_estimated_review_exposure_does_not_hold_scoring_or_review(self):
        lg = RuntimeLedger(self.ledger_path, 50_000_000)
        lg.admit("r", 3_000_000, model=SONNET)
        lg.finish("r", outcome="processed", generationId="g", routerCostUsdMicros=0, tokenPricedUsdMicros=None,
                  upstreamInferenceCostUsdMicros=None, isByok=None)
        self.assertGreater(lg.totals()["estimatedUsdMicros"], 0)
        self.sp()
        self.provider(handle=self.auth_opus())


class ProviderLifecycle(ProviderBase):
    def test_provider_not_sent_rejected_and_unknown_complete_on_live_instance(self):
        from reviewer.runtime.openrouter import HttpResponse, TransportTimeout
        p = self.sp(FakeTransport(TransportError(False), HttpResponse(400, {}, b"{}"), TransportTimeout(True),
                                  completion(json.dumps(OK_EXTRACT), model=OPUS)))
        outs = [p.call(score_req(), ("E", "s", "a", i, 0)).outcome for i in range(4)]
        self.assertEqual(outs, ["not-sent", "rejected-before-processing", "unknown", "processed"])

    def test_new_provider_cannot_complete_prior_orphan(self):
        RuntimeLedger(self.ledger_path, 50_000_000).admit("orphan", 1000, model=OPUS, **S)
        with self.assertRaises(AuthorizationError):
            self.sp()                                                         # startup hold
        with self.assertRaises(ValueError):
            RuntimeLedger(self.ledger_path, 50_000_000).finish("orphan", outcome="not-sent")
