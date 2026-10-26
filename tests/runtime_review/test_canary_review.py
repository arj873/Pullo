"""Independent S0B-01a review: canary launcher + gateway seam. Fake transport/key only."""
from __future__ import annotations

import io
import json
import unittest

from reviewer.runtime.openrouter import HttpResponse
from tests.runtime.common import FAKE_KEY, SONNET, FakeTransport, RT, completion, req
from tests.runtime.test_canary import Canary as _Base

KEYINFO = b'{"data":{"limit":50,"usage":0,"limit_remaining":50}}'


class CanaryReview(_Base):
    # reuse the author's fixture builders only (setUp/run_main); the inherited tests are not re-run here
    def test_second_live_canary_in_same_state_dir_after_a_rejection(self):
        """After a 400/404 'rejected-before-processing' (e.g. the strict schema projection is refused) the operator must be
        able to fix and rerun in the SAME state dir (the $50 aggregate depends on it)."""
        rc1, rep1 = self.run_main("--live", "--env", "x", transport=FakeTransport(KEYINFO, HttpResponse(400, {}, b"{}"), KEYINFO))
        self.assertEqual((rc1, rep1["ok"]), (1, False))
        rc2, rep2 = self.run_main("--live", "--env", "x", transport=FakeTransport(KEYINFO, completion(), KEYINFO))
        self.assertEqual(rep2["ok"], True, rep2.get("error"))

    def test_live_canary_request_body_snapshot(self):
        tr = FakeTransport(KEYINFO, completion(), KEYINFO)
        self.run_main("--live", "--env", "x", transport=tr)
        body = json.loads(tr.requests[1].body)
        self.assertEqual((body["model"], body["max_tokens"], body["stream"]), (SONNET, 300, False))
        self.assertEqual(body["provider"], {"order": ["anthropic"], "only": ["anthropic"], "allow_fallbacks": False, "require_parameters": True})
        self.assertNotIn("plugins", body); self.assertNotIn("models", body); self.assertNotIn("tools", body)
        self.assertNotIn(FAKE_KEY, tr.requests[1].body.decode())
        self.assertNotIn(FAKE_KEY, repr(tr.requests))

    def test_canary_stops_on_dated_slug_from_provider(self):
        tr = FakeTransport(KEYINFO, completion(model="anthropic/claude-sonnet-5.5-20260101"), KEYINFO)
        rc, rep = self.run_main("--live", "--env", "x", transport=tr)
        self.assertEqual((rc, rep["ok"]), (1, False))
        self.assertGreater(rep["runtimeLedger"]["knownUsdMicros"], 0)       # processed + charged, honestly recorded


class GatewaySeam(RT):
    def test_wrong_resolved_model_charged_but_not_ok(self):
        p = self.provider(FakeTransport(completion(model="anthropic/claude-opus-5.5")))
        res = self.gateway(p).call("INVESTIGATE", "investigator", "a", 0, req())
        self.assertFalse(res.ok)
        self.assertGreater(self.ledger.totals()["knownUsdMicros"], 0)

    def test_gateway_charge_is_computed_not_billed(self):
        """Observation: SpendBook/gateway settle token-priced figures; the OpenRouter bill is only in runtime-ledger.jsonl."""
        p = self.provider(FakeTransport(completion(usage={"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.5,
                                                          "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}})))
        gw = self.gateway(p)
        gw.call("INVESTIGATE", "investigator", "a", 0, req())
        self.assertEqual(self.ledger.totals()["knownUsdMicros"], 500_000)
        self.assertLess(self.book.totals()["committed"], 500_000)            # book under-counts a $0.50 bill by >100x

    def test_provider_returning_budget_exhausted_error_code_is_not_trusted(self):
        """NEW1 residual: gateway still accepts adapter-supplied 'budget-exhausted' (author's own adapters never emit it)."""
        from reviewer.gateway.errors import typed_error
        from reviewer.gateway.providers import ProviderResult

        class Bad:
            name = "anthropic"
            def call(self, request, key):
                return ProviderResult(None, typed_error("budget-exhausted", "x"), "unknown")
        try:
            res = self.gateway(self.provider(), providers={"anthropic": Bad()}).call("INVESTIGATE", "investigator", "a", 0, req())
        except Exception as e:  # noqa: BLE001
            self.fail(f"gateway raised {type(e).__name__}")
        self.assertFalse(res.ok)


if __name__ == "__main__":
    unittest.main()
