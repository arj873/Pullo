"""Independent S0B-01b re-review: adversarial controls beyond the author's tests/runtime/test_s0b01b.py.
Offline only (fake transports/keys, fake HTTPS connection class, temp ledgers; the repo's saved reconciliation JSON is
read, never written). `expectedFailure` = CONFIRMED defect, assertion states the safe behaviour.

    nice -n 19 python3 -m unittest tests.runtime_review.test_s0b01b_review
"""
from __future__ import annotations

import io
import json
import socket
import time
import unittest
from pathlib import Path
from unittest import mock

from reviewer.runtime import RuntimeLedger, accountable_cost
from reviewer.runtime import openrouter as OR
from reviewer.runtime import reconcile as REC
from reviewer.runtime.catalog import (ALLOWED_ROUTER_MODELS, token_priced_micros, worst_case_input_tokens,
                                      worst_case_router_micros)
from reviewer.runtime.openrouter import HttpResponse, HttpsTransport, TransportTimeout
from tests.runtime.common import SONNET, FakeTransport, RT, completion, req

KEY = ("INVESTIGATE", "investigator", "a", 0, 1)
EVIDENCE = Path(__file__).resolve().parents[2] / "orchestration/validation/first-live-sonnet-canary-reconciliation.json"
GEN = "gen-1792960940-3cCZ9tbdtLSWyvN2JSYb"


def canary_old_rows(worst=3000):
    """Exact pre-fix persisted shape of the first live canary row: router 0, upstream 2814, no isByok/accountable*."""
    return [{"type": "intent", "at": "t", "callKey": "old|k", "model": SONNET, "worstCaseUsdMicros": worst},
            {"type": "result", "at": "t", "callKey": "old|k", "kind": "openrouter", "model": SONNET, "outcome": "processed",
             "generationId": GEN, "routerCostUsd": "0", "routerCostUsdMicros": 0, "upstreamInferenceCostUsd": "0.002814",
             "upstreamInferenceCostUsdMicros": 2814, "tokenPricedUsdMicros": 2814, "costBasis": "router-reported",
             "httpStatus": 200}]


class _Led(RT):
    def write(self, rows):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))
        self.ledger_path.chmod(0o600)
        self.led = RuntimeLedger(self.ledger_path, 50_000_000)
        return self.led

    def cli(self, *extra):
        out = io.StringIO()
        rc = REC.main(["--ledger", str(self.ledger_path), "--evidence", str(EVIDENCE), *extra], out=out)
        return rc, json.loads(out.getvalue())


class OldRowReplay(_Led):
    """Actual BYOK 2814 µUSD row: replays to 2814 with no reset, previews are read-only, apply is append-only + idempotent."""

    def test_old_row_replays_to_2814_known_without_any_reconcile(self):
        t = self.write(canary_old_rows()).totals()
        self.assertEqual((t["committedUsdMicros"], t["knownUsdMicros"], t["estimatedUsdMicros"], t["unknownBoundUsdMicros"]),
                         (2814, 2814, 0, 0))
        self.assertEqual((t["routerReportedUsdMicros"], t["upstreamReportedUsdMicros"]), (0, 2814))

    @unittest.skipUnless(EVIDENCE.is_file(), "optional private input absent: orchestration/validation/first-live-sonnet-canary-reconciliation.json (unpublished host reconciliation evidence)")
    def test_reconcile_cli_preview_then_apply_then_repeat_with_the_repo_evidence(self):
        self.write(canary_old_rows())
        before = self.ledger_path.read_bytes()
        rc, out = self.cli()
        self.assertEqual((rc, out["applied"], out["before"]["committedUsdMicros"], out["after"]["committedUsdMicros"]), (0, False, 2814, 2814))
        self.assertEqual(self.ledger_path.read_bytes(), before)                       # preview wrote nothing
        rc, out = self.cli("--apply")
        self.assertEqual((rc, out["appended"], out["after"]["committedUsdMicros"]), (0, True, 2814))
        after_one = self.ledger_path.read_bytes()
        self.assertTrue(after_one.startswith(before))                                  # strictly append-only
        self.assertEqual(len(after_one.splitlines()), len(before.splitlines()) + 1)
        rc, out = self.cli("--apply")
        self.assertEqual((rc, out["appended"]), (0, False))                            # idempotent
        self.assertEqual(self.ledger_path.read_bytes(), after_one)
        row = json.loads(after_one.splitlines()[-1])
        self.assertEqual((row["type"], row["generationId"], row["isByok"], row["keyRemainingUsd"]), ("reconcile", GEN, True, "49.997186"))
        self.assertEqual(self.led.totals()["committedUsdMicros"], 2814)                # key usage==0 never lowered anything

    @unittest.skipUnless(EVIDENCE.is_file(), "optional private input absent: orchestration/validation/first-live-sonnet-canary-reconciliation.json (unpublished host reconciliation evidence)")
    def test_cli_refuses_missing_ledger_and_unknown_generation(self):
        with self.assertRaises(SystemExit):
            self.cli()                                                                  # no ledger file: never creates a book
        self.assertFalse(self.ledger_path.exists())
        rows = canary_old_rows()
        rows[1]["generationId"] = "gen-other"
        self.write(rows)
        before = self.ledger_path.read_bytes()
        rc, out = self.cli("--apply")
        self.assertEqual((rc, out["ok"]), (1, False))
        self.assertEqual(self.ledger_path.read_bytes(), before)

    def test_scope_does_not_reset_the_aggregate_across_providers(self):
        """Fresh run scopes must not hide earlier spend: two providers on one persistent ledger sum."""
        self.write(canary_old_rows())
        p = self.provider(FakeTransport(completion(usage={"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.004})))
        self.assertEqual(p.call(req(), ("INVESTIGATE", "investigator", "a", 0, 1)).outcome, "processed")
        self.assertEqual(self.ledger.totals()["committedUsdMicros"], 2814 + 4000)
        p2 = self.provider(FakeTransport(completion(usage={"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.004})))
        self.assertEqual(p2.call(req(), ("INVESTIGATE", "investigator", "a", 0, 1)).outcome, "processed")   # same tuple, new scope
        self.assertEqual(self.ledger.totals()["committedUsdMicros"], 2814 + 8000)
        self.assertEqual(p2.call(req(), ("INVESTIGATE", "investigator", "a", 0, 1)).error["detail"]["reason"], "duplicate-call-key")


class ReconcileForgery(_Led):
    def _rows(self, **res):
        rows = canary_old_rows()
        rows[1].update(res)
        return rows

    def test_mismatched_generation_id_is_refused_and_appends_nothing(self):
        led = self.write(canary_old_rows())
        before = self.ledger_path.read_bytes()
        gen = {"id": "gen-forged", "total_cost": 0, "upstream_inference_cost": "0", "is_byok": False}
        with self.assertRaises(ValueError):
            led.reconcile("old|k", gen)
        with self.assertRaises(ValueError):
            led.reconcile("no|such|key", {**gen, "id": GEN})
        with self.assertRaises(ValueError):
            led.reconcile("old|k", {"id": GEN, "total_cost": "garbage"})
        with self.assertRaises(ValueError):
            led.reconcile("old|k", {"id": GEN})                                          # no total_cost
        self.assertEqual(self.ledger_path.read_bytes(), before)

    def test_reconcile_of_a_not_processed_call_is_refused(self):
        led = self.write(self._rows(outcome="not-sent"))
        with self.assertRaises(ValueError):
            led.reconcile("old|k", {"id": GEN, "total_cost": 0})

    def test_a_zero_or_tiny_authoritative_cost_cannot_release_below_the_token_arithmetic_floor(self):
        led = self.write(canary_old_rows())
        r = led.reconcile("old|k", {"id": GEN, "total_cost": "0", "upstream_inference_cost": "0", "is_byok": False})
        self.assertTrue(r["appended"])
        self.assertEqual(r["after"]["committedUsdMicros"], 2814)                         # floored to token-priced, estimated
        self.assertEqual(r["after"]["estimatedUsdMicros"], 2814)

    def test_inclusive_generation_collapses_a_safe_overcount_without_double_count(self):
        """isByok absent + router==upstream -> ambiguous-sum (2x, safe). The authoritative is_byok:false record fixes it to 1x."""
        led = self.write(self._rows(routerCostUsd="0.002814", routerCostUsdMicros=2814))
        self.assertEqual(led.totals()["committedUsdMicros"], 5628)
        r = led.reconcile("old|k", {"id": GEN, "total_cost": "0.002814", "upstream_inference_cost": "0.002814", "is_byok": False})
        self.assertEqual(r["after"]["committedUsdMicros"], 2814)

    def test_generation_without_is_byok_never_lowers_a_known_byok_row_to_zero(self):
        """A later reconcile row with isByok=None overlays a result row that said True; the sum fallback must still count upstream."""
        led = self.write(self._rows(isByok=True))
        r = led.reconcile("old|k", {"id": GEN, "total_cost": 0, "upstream_inference_cost": "0.002814"})
        self.assertEqual(r["after"]["committedUsdMicros"], 2814)

    def test_changed_evidence_for_same_generation_appends_a_new_row_and_old_row_stays(self):
        led = self.write(canary_old_rows())
        a = led.reconcile("old|k", {"id": GEN, "total_cost": 0, "upstream_inference_cost": "0.002814", "is_byok": True})
        b = led.reconcile("old|k", {"id": GEN, "total_cost": 0, "upstream_inference_cost": "0.002814", "is_byok": True})
        c = led.reconcile("old|k", {"id": GEN, "total_cost": 0, "upstream_inference_cost": "0.003", "is_byok": True})
        self.assertEqual((a["appended"], b["appended"], c["appended"]), (True, False, True))
        self.assertEqual([json.loads(x)["type"] for x in self.ledger_path.read_text().splitlines()],
                         ["intent", "result", "reconcile", "reconcile"])
        self.assertEqual(led.totals()["committedUsdMicros"], 3000)


class ZeroUsageHole(RT):
    def test_F11_processed_call_with_all_zero_usage_and_zero_cost_must_not_count_as_free(self):
        """FIXED in S0B-01b-finalfix (was: low). usage {prompt_tokens:0, completion_tokens:0, cost:0} -> token-priced 0 (not None), so
        accountable_cost sees cost 0 and priced 0, skips both guards and returns (0, 'router-only'). The docstring promises
        'a processed call is never trusted at $0'. A processed call that returned model output cannot have used 0 tokens."""
        u = {"prompt_tokens": 0, "completion_tokens": 0, "cost": 0, "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}
        p = self.provider(FakeTransport(completion(usage=u)))
        self.assertEqual(p.call(req(), KEY).outcome, "processed")
        self.assertGreater(self.ledger.totals()["committedUsdMicros"], 0)

    def test_accountable_cost_pure_cases(self):
        w = 20_000
        cases = [   # router, upstream, isByok, priced, expected
            (0, 2814, True, 2814, (2814, "byok-additive")),
            (0, 2814, None, 2814, (2814, "ambiguous-sum")),
            (2814, 2814, False, 2814, (2814, "router-inclusive")),
            (2814, 2814, None, 2814, (5628, "ambiguous-sum")),
            (140, 2814, True, 2814, (2954, "byok-additive")),
            (0, None, True, 2814, (2814, "byok-upstream-missing")),
            (0, None, None, 2814, (2814, "suspect-floored-to-token-priced")),
            (0, 0, True, 2814, (2814, "suspect-floored-to-token-priced")),
            (100, None, False, 2814, (2814, "suspect-floored-to-token-priced")),
            (4000, None, None, 3835, (4000, "router-only")),
            (0, None, None, None, (w, "zero-unverifiable-worst-case")),
            (None, 2814, True, 2814, (w, "unknown-worst-case")),
        ]
        for router, up, byok, priced, want in cases:
            f = {"routerCostUsdMicros": router, "upstreamInferenceCostUsdMicros": up, "isByok": byok, "tokenPricedUsdMicros": priced}
            self.assertEqual(accountable_cost(f, w), want, f)
        bad = {"routerCostUsdMicros": 0, "upstreamInferenceCostUsdMicros": None, "upstreamInferenceCostUsd": "-1",
               "isByok": True, "tokenPricedUsdMicros": 5}
        self.assertEqual(accountable_cost(bad, w), (w, "unknown-worst-case"))


class ByokThroughTheAdapter(RT):
    def _run(self, usage):
        p = self.provider(FakeTransport(completion(usage=usage)))
        self.assertEqual(p.call(req(), KEY).outcome, "processed")
        return self.ledger.totals(), self.receipts()[-1]

    def test_hostile_cost_shapes_are_unknown_worst_case_never_zero_or_huge_ints(self):
        base = {"prompt_tokens": 1000, "completion_tokens": 200}
        for label, extra in [("bool-cost", {"cost": True}), ("list-cost", {"cost": [1]}), ("huge-exp", {"cost": "1e999999999"}),
                             ("neg", {"cost": -1}), ("nan-up", {"cost": 0, "cost_details": {"upstream_inference_cost": "NaN"}}),
                             ("dict-up", {"cost": 0, "cost_details": {"upstream_inference_cost": {"a": 1}}}),
                             ("str-byok", {"cost": 0, "is_byok": "true", "cost_details": {"upstream_inference_cost": "0.0038"}})]:
            self.setUp()
            t, row = self._run({**base, **extra})
            self.assertGreater(t["committedUsdMicros"], 0, label)
            if label != "str-byok":
                self.assertEqual(row["accountableBasis"], "unknown-worst-case", label)
            else:                                                                            # non-bool flag == absent: ambiguous-sum, counted
                self.assertEqual((row["accountableBasis"], t["committedUsdMicros"]), ("ambiguous-sum", 3800))

    def test_two_calls_sum_once_each(self):
        u = {"prompt_tokens": 1347, "completion_tokens": 12, "cost": 0, "is_byok": True,
             "cost_details": {"upstream_inference_cost": 0.002814}, "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}
        p = self.provider(FakeTransport(completion(usage=u), completion(usage=u)))
        p.call(req(), KEY)
        p.call(req(), ("INVESTIGATE", "investigator", "a", 1, 1))
        t = self.ledger.totals()
        self.assertEqual((t["committedUsdMicros"], t["calls"], t["upstreamReportedUsdMicros"]), (5628, 2, 5628))


class PreSendBound(RT):
    def test_bound_dominates_bytes_and_the_observed_canary_ratio(self):
        self.assertGreaterEqual(worst_case_input_tokens(2356), 1347)
        for n in (0, 1, 1000, 100_000, 900_000):
            self.assertGreaterEqual(worst_case_input_tokens(n), n)                        # >= 1 token per UTF-8 byte
        self.assertEqual(worst_case_input_tokens(8 << 20), 1_000_000)                      # context-capped (provider rejects beyond)

    def test_bound_uses_the_dearest_rate_of_every_tier_and_covers_max_output(self):
        for m, spec in ALLOWED_ROUTER_MODELS.items():
            o = spec.get("override", {})
            dearest_in = max(spec["input"], spec["write"], spec["write1h"], o.get("input", 0), o.get("write", 0), o.get("write1h", 0))
            n = 150_000
            w = worst_case_router_micros(m, n, 4000)
            self.assertGreaterEqual(w, n * dearest_in // 1_000_000 + 4000 * max(spec["output"], o.get("output", 0)) // 1_000_000, m)
            # a call whose usage exactly fills the bound can never exceed it at catalogue prices (any cache split)
            self.assertGreaterEqual(w, token_priced_micros(m, n, 0, 0, 4000, n), m)

    def test_dense_non_latin_body_reserve_exceeds_a_one_token_per_byte_price(self):
        text = "☃\U0001f600中" * 20_000                                           # 8 bytes per 3 chars, token-hostile
        p = self.provider(FakeTransport(completion()))
        body, info = p.build_body(req(text=text))
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        w = worst_case_router_micros(SONNET, len(raw), info["maxTokens"])
        self.assertGreaterEqual(w, (len(raw) + 2048) * 4)                                   # bytes x dearest Sonnet input rate ($4/M)
        self.assertEqual(p.call(req(text=text), KEY).outcome, "processed")
        self.assertEqual(json.loads(self.ledger_path.read_text().splitlines()[0])["worstCaseUsdMicros"], w)


class NestedJson(RT):
    DEPTHS = (50, 400, 900, 1100, 5000, 200_000)

    def _assert_one_result(self):
        kinds = [r["type"] for r in self.receipts()]
        self.assertEqual(kinds, ["intent", "result"], kinds)                              # never an orphan intent

    def test_nested_value_inside_valid_model_output_is_invalid_output_with_charged_receipt(self):
        for d in self.DEPTHS:
            self.setUp()
            content = '{"hypotheses":' + "[" * d + "]" * d + "}"
            p = self.provider(FakeTransport(completion(content=content)))
            r = p.call(req(), KEY)
            self.assertEqual((r.outcome, r.response["status"]), ("processed", "invalid-output"), d)
            self._assert_one_result()
            row = self.receipts()[-1]
            self.assertEqual((row["routerCostUsdMicros"], row["generationId"]), (4000, "gen-abc123"), d)
            self.assertEqual(self.ledger.totals()["knownUsdMicros"], 4000, d)

    def test_nested_garbage_in_unused_response_fields_is_harmless(self):
        for d in (400, 900, 5000):
            self.setUp()
            deep = json.loads(completion())
            nest = "[" * d + "]" * d
            raw = completion().decode()[:-1] + ',"extra":' + nest + "}"
            p = self.provider(FakeTransport(raw.encode()))
            r = p.call(req(), KEY)
            self.assertIn(r.outcome, ("processed", "unknown"), d)
            self._assert_one_result()
            self.assertGreater(self.ledger.totals()["committedUsdMicros"], 0)
            self.assertIsInstance(deep, dict)

    def test_nested_inside_usage_is_unknown_or_ok_but_always_counted(self):
        for d in (400, 900, 5000):
            self.setUp()
            usage = '{"prompt_tokens":1000,"completion_tokens":200,"cost":0.004,"x":' + "[" * d + "]" * d + "}"
            raw = completion().decode()
            i = raw.index('"usage"')
            raw = raw[:i] + '"usage":' + usage + "}"
            p = self.provider(FakeTransport(raw.encode()))
            r = p.call(req(), KEY)
            self.assertIn(r.outcome, ("processed", "unknown"), d)
            self._assert_one_result()
            self.assertGreaterEqual(self.ledger.totals()["committedUsdMicros"], 4000)

    def test_deeply_nested_http_body_is_unknown_with_a_result_row_and_worst_case_kept(self):
        for body in (b"[" * 200_000, b'{"a":' * 100_000):
            self.setUp()
            p = self.provider(FakeTransport(HttpResponse(200, {}, body)))
            r = p.call(req(), KEY)
            self.assertEqual(r.outcome, "unknown")
            self._assert_one_result()
            t = self.ledger.totals()
            self.assertEqual((t["unknownBoundUsdMicros"] > 0, t["knownUsdMicros"]), (True, 0))

    def test_gateway_sees_a_typed_provider_error_not_an_adapter_crash(self):
        p = self.provider(FakeTransport(HttpResponse(200, {}, b"[" * 200_000)))
        res = self.gateway(p).call("INVESTIGATE", "investigator", "a", 0, req())
        self.assertFalse(res.ok)
        self.assertNotIn("adapter failed", json.dumps(res.error, default=str))


class _FakeConn:
    """Stand-in for HTTPSConnection: connect() is slow and then succeeds; every send-side call is timestamped."""
    events: list = []
    connect_delay = 1.5
    hang_after_connect = False

    def __init__(self, host, port, timeout=None, context=None):
        self.sock = None

    def connect(self):
        time.sleep(self.connect_delay)
        self.sock = socket.socketpair()[0]        # a real socket: `_abort` shuts it down at OS level

    def putrequest(self, *a, **k):
        self.events.append("putrequest")

    def putheader(self, *a, **k):
        pass

    def endheaders(self, body=None):
        self.events.append("endheaders")

    def getresponse(self):
        if self.hang_after_connect:
            time.sleep(3)
        raise OSError("no response")

    def close(self):
        if self.sock is not None:
            self.sock.close()


class WatchdogRace(RT):
    def setUp(self):
        super().setUp()
        _FakeConn.events = []

    def _transport_call(self, delay, timeout, hang=False):
        conn = type("C", (_FakeConn,), {"events": [], "connect_delay": delay, "hang_after_connect": hang})
        with mock.patch.object(OR.http.client, "HTTPSConnection", conn):
            t0 = time.monotonic()
            try:
                HttpsTransport()(OR.HttpRequest("POST", "/p", {"Authorization": "Bearer x"}, b"{}", timeout, 1 << 16))
                exc = None
            except Exception as e:  # noqa: BLE001
                exc = e
            elapsed = time.monotonic() - t0
            time.sleep(delay + 0.8)                                                      # let a straggling worker act
        return exc, conn.events, elapsed

    def test_control_hang_after_a_completed_connect_is_reported_as_sent(self):
        exc, events, dt = self._transport_call(0.0, 0.6, hang=True)
        self.assertIsInstance(exc, TransportTimeout)
        self.assertTrue(exc.sent)
        self.assertLess(dt, 2.5)

    def test_F12_late_connect_must_not_send_after_the_caller_was_told_not_sent(self):
        """FIXED in S0B-01b-finalfix (was: medium-low). connect()/TLS finishing AFTER the deadline. `_abort` sees `conn.sock is None` (or a
        detached socket during the handshake), so nothing is shut down; the caller gets TransportTimeout(sent=False) -> the
        adapter records outcome 'not-sent' and the tally RELEASES the reservation; then the worker, with no abort flag or
        deadline check, sets sent=True and transmits the request anyway (a billable call outside the ledger).
        Safe behaviour: either no send after a not-sent report, or report sent=True/unknown."""
        exc, events, _ = self._transport_call(3.0, 0.6)      # > deadline + the 1 s post-abort join, which otherwise masks it
        self.assertIsInstance(exc, TransportTimeout)
        if exc.sent is False:
            self.assertEqual(events, [], f"worker transmitted after the caller was told 'not-sent': {events}")

    def test_F12_effect_ledger_releases_the_reservation_of_a_request_that_is_later_sent(self):
        p = self.provider(HttpsTransport())
        r = req()
        r["params"] = {**r["params"], "timeoutSec": 1}
        conn = type("C", (_FakeConn,), {"events": [], "connect_delay": 3.5})
        with mock.patch.object(OR.http.client, "HTTPSConnection", conn):
            res = p.call(r, KEY)
            time.sleep(4.0)
        if res.outcome == "not-sent":
            self.assertEqual(conn.events, [], "ledger released the reservation but the request left afterwards")
            self.assertEqual(self.ledger.totals()["committedUsdMicros"], 0)


if __name__ == "__main__":
    unittest.main()
