"""SCORE-RT-03: a new scoring provider fails closed on prior unresolved scoring exposure. Offline, invented files."""

from __future__ import annotations

import hashlib
import json

from reviewer.gateway.errors import AuthorizationError
from reviewer.runtime import RuntimeLedger
from reviewer.runtime.openrouter import HttpResponse, TransportTimeout
from tests.runtime.common import FakeTransport, OPUS, SONNET, completion, req
from tests.score_runtime.test_score_runtime import KEY, OK_EXTRACT, S, ProviderBase, score_req


class StartupHold(ProviderBase):
    def seed(self):
        return RuntimeLedger(self.ledger_path, 50_000_000)

    def sha(self):
        return hashlib.sha256(self.ledger_path.read_bytes()).hexdigest() if self.ledger_path.exists() else None

    def assert_held(self, **kw):
        before = self.sha()
        with self.assertRaises(AuthorizationError) as cm:
            self.sp(**kw)
        self.assertIn("scoring startup hold", str(cm.exception))
        self.assertEqual(self.sha(), before)                        # no mutation
        self.assertEqual(getattr(self, "transport", FakeTransport()).requests, [])   # no HTTP
        return str(cm.exception)

    def test_unfinished_intent_holds_after_restart(self):
        self.seed().admit("old", 1000, model=OPUS, **S)             # crashed process: intent, no result
        self.assert_held()

    def test_finished_unknown_outcome_holds_after_restart(self):
        lg = self.seed()
        lg.admit("old", 1000, model=OPUS, **S)
        lg.finish("old", outcome="unknown", errorKind="timeout", costBasis="unknown")
        self.assert_held()

    def test_processed_with_unknown_cost_holds_until_reconciled_then_clears(self):
        lg = self.seed()
        lg.admit("old", 5000, model=OPUS, **S)
        lg.finish("old", outcome="processed", generationId="gen-1", costBasis="unknown", tokenPricedUsdMicros=100)
        self.assert_held()
        lg.reconcile("old", {"id": "gen-1", "total_cost": "0.000100"})       # resolved by host-fetched facts only
        self.assertIsNone(lg.scoring_startup_hold())
        self.sp()                                                          # constructs now

    def test_resolved_costs_and_not_processed_do_not_hold(self):
        lg = self.seed()
        lg.admit("a", 1000, model=OPUS, **S)
        lg.finish("a", outcome="processed", routerCostUsdMicros=500, tokenPricedUsdMicros=500,
                  upstreamInferenceCostUsdMicros=None, isByok=None)
        lg.admit("b", 1000, model=OPUS, **S)
        lg.finish("b", outcome="rejected-before-processing", errorKind="http-400", costBasis="unknown")
        self.assertIsNone(lg.scoring_startup_hold())
        self.sp()

    def test_hold_is_read_only_and_never_releases(self):
        lg = self.seed()
        lg.admit("old", 1000, model=OPUS, **S)
        before = self.sha()
        for _ in range(3):
            self.assertEqual(lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.assertEqual(self.sha(), before)
        self.assertEqual(lg.totals("scoring")["unknownBoundUsdMicros"], 1000)
        self.assertFalse(any(hasattr(lg, n) for n in ("release", "reset", "recover", "override", "force")))

    def test_missing_ledger_not_created_and_no_hold(self):
        self.assertFalse(self.ledger_path.exists())
        self.assertIsNone(RuntimeLedger(self.ledger_path, 50_000_000).scoring_startup_hold())
        self.assertFalse(self.ledger_path.exists())

    def test_review_orphans_do_not_hold_scoring_and_review_startup_unchanged(self):
        self.seed().admit("rev-orphan", 9_000_000, model=SONNET)    # review exposure only
        self.sp()                                                    # scoring starts (20M ceiling still applies)
        # and review startup ignores scoring orphans (mixed ledger)
        self.ledger_path.unlink()
        self.seed().admit("s-orphan", 1000, model=OPUS, **S)
        p = self.provider(handle=self.auth_opus())
        self.assertEqual(p.category, "review")
        self.assertEqual(p.call(req(), KEY).outcome, "processed")

    def test_unrecognised_stored_category_or_garbage_ledger_holds(self):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text(json.dumps({"type": "intent", "at": "t", "callKey": "x", "model": OPUS,
                                                "worstCaseUsdMicros": 1, "category": "bogus"}) + "\n")
        self.assertIn("scoring-ledger-unreadable", self.assert_held())
        self.ledger_path.write_text("not json\n")
        self.assertIn("scoring-ledger-unreadable", self.assert_held())

    def test_no_override_arguments(self):
        self.seed().admit("old", 1000, model=OPUS, **S)
        for kw in ({"force": True}, {"allow_unresolved": True}, {"hold": False}):
            with self.assertRaises(TypeError):
                self.sp(**kw)
        self.assert_held()

    def test_own_inflight_request_does_not_poison_the_provider(self):
        p = self.sp(FakeTransport(TransportTimeout(True), completion(json.dumps(OK_EXTRACT), model=OPUS)))
        self.assertEqual(p.call(score_req(), ("E", "s", "a", 0, 0)).outcome, "unknown")
        # the same instance keeps working (guard ran once, at construction)...
        self.assertEqual(p.call(score_req(), ("E", "s", "a", 1, 0)).outcome, "processed")
        # ...but a NEW scoring provider over the same ledger is held by the unresolved unknown.
        before = self.sha()
        with self.assertRaises(AuthorizationError):
            self.provider(handle=self.auth_opus(), **S)
        self.assertEqual(self.sha(), before)

    def test_diagnostic_is_fixed_and_safe(self):
        self.seed().admit("SENTINEL-call-key-77", 1000, model=OPUS, **S)
        msg = self.assert_held()
        self.assertNotIn("SENTINEL", msg)
        self.assertNotIn("1000", msg)
        self.assertNotIn("sk-or-v1", msg)
