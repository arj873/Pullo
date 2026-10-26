"""S0B-01b regression controls: BYOK/upstream accounting, old-ledger replay, run-scoped call keys, total HTTP
deadline, nested-JSON receipts, string-only content, conservative pre-send token bound. Offline only."""
from __future__ import annotations

import http.client
import http.server
import io
import json
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from reviewer.runtime import RuntimeLedger, accountable_cost
from reviewer.runtime import openrouter as OR
from reviewer.runtime import reconcile as REC
from reviewer.runtime.canary import key_limit_delta
from reviewer.runtime.catalog import worst_case_input_tokens, worst_case_router_micros
from reviewer.runtime.openrouter import HttpRequest, HttpResponse, HttpsTransport
from reviewer.runtime.receipts import make_scope, micros_from_usd_text
from tests.runtime.common import FAKE_KEY, SONNET, FakeTransport, RT, completion, req

KEY = ("INVESTIGATE", "investigator", "a", 0, 1)
EVIDENCE = Path(__file__).resolve().parents[2] / "orchestration/validation/first-live-sonnet-canary-reconciliation.json"
BYOK_USAGE = {"prompt_tokens": 1347, "completion_tokens": 12, "cost": 0, "is_byok": True,
              "cost_details": {"upstream_inference_cost": 0.002814},
              "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}


def old_rows(gen="gen-1792960940-3cCZ9tbdtLSWyvN2JSYb"):
    """The first live canary's persisted shape (pre-fix): router 0, upstream 2814, no isByok/accountable fields."""
    return [{"type": "intent", "at": "t", "callKey": "old|k", "model": SONNET, "worstCaseUsdMicros": 3000},
            {"type": "result", "at": "t", "callKey": "old|k", "kind": "openrouter", "model": SONNET, "outcome": "processed",
             "generationId": gen, "routerCostUsd": "0", "routerCostUsdMicros": 0, "upstreamInferenceCostUsdMicros": 2814,
             "tokenPricedUsdMicros": 2814, "costBasis": "router-reported"}]


class Byok(RT):
    def test_observed_byok_call_counts_upstream_cost_and_keeps_raw_facts_separate(self):
        p = self.provider(FakeTransport(completion(usage=BYOK_USAGE)))
        self.assertEqual(p.call(req(), KEY).outcome, "processed")
        t = self.ledger.totals()
        self.assertEqual((t["knownUsdMicros"], t["committedUsdMicros"]), (2814, 2814))
        self.assertEqual((t["routerReportedUsdMicros"], t["upstreamReportedUsdMicros"]), (0, 2814))
        row = self.receipts()[-1]
        self.assertEqual((row["routerCostUsdMicros"], row["upstreamInferenceCostUsdMicros"], row["isByok"]), (0, 2814, True))
        self.assertEqual((row["accountableUsdMicros"], row["accountableBasis"], row["accountableEstimated"]),
                         (2814, "byok-additive", False))

    def test_explicit_non_byok_total_is_inclusive_and_not_double_counted(self):
        u = {"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.004, "is_byok": False,
             "cost_details": {"upstream_inference_cost": 0.0038}}
        self.provider(FakeTransport(completion(usage=u))).call(req(), KEY)
        self.assertEqual(self.ledger.totals()["knownUsdMicros"], 4000)

    def test_byok_router_fee_plus_upstream_are_summed(self):
        u = {**BYOK_USAGE, "cost": 0.0001}
        self.provider(FakeTransport(completion(usage=u))).call(req(), KEY)
        self.assertEqual(self.ledger.totals()["knownUsdMicros"], 2914)

    def test_zero_cost_with_tokens_is_floored_and_labelled_estimate(self):
        u = {"prompt_tokens": 1347, "completion_tokens": 12, "cost": 0,
             "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}
        self.provider(FakeTransport(completion(usage=u))).call(req(), KEY)
        t = self.ledger.totals()
        self.assertEqual((t["knownUsdMicros"], t["estimatedUsdMicros"]), (0, 2814))
        self.assertEqual(self.receipts()[-1]["accountableBasis"], "suspect-floored-to-token-priced")

    def test_zero_cost_without_usable_token_split_is_worst_case(self):
        self.provider(FakeTransport(completion(usage={"cost": 0}))).call(req(), KEY)
        t = self.ledger.totals()
        self.assertEqual((t["knownUsdMicros"], t["estimatedUsdMicros"]), (0, t["committedUsdMicros"]))
        self.assertGreater(t["committedUsdMicros"], 0)

    def test_unusable_or_absurd_cost_values_are_unknown_not_a_crash(self):
        self.assertIsNone(micros_from_usd_text("1e999999999"))
        self.assertIsNone(micros_from_usd_text("-1"))
        self.assertIsNone(micros_from_usd_text("NaN"))
        body = completion(usage={"prompt_tokens": 10, "completion_tokens": 5, "cost": 1, "cost_details": {"upstream_inference_cost": "1e999999999"}})
        res = self.provider(FakeTransport(body)).call(req(), KEY)
        self.assertEqual(res.outcome, "processed")
        self.assertEqual(self.receipts()[-1]["accountableBasis"], "unknown-worst-case")

    def test_byok_without_reported_upstream_cost_is_not_trusted(self):
        v, b = accountable_cost({"routerCostUsdMicros": 100, "isByok": True, "tokenPricedUsdMicros": 2814}, 9999)
        self.assertEqual((v, b), (2914, "byok-upstream-missing"))


class OldLedgerReplay(RT):
    def write(self, rows):
        self.op.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_old_format_row_replays_to_2814_instead_of_zero(self):
        self.write(old_rows())
        t = RuntimeLedger(self.ledger_path, 50_000_000).totals()
        self.assertEqual((t["committedUsdMicros"], t["knownUsdMicros"], t["calls"]), (2814, 2814, 1))

    def test_old_row_without_upstream_but_zero_router_is_floored_not_zero(self):
        r = old_rows()
        del r[1]["upstreamInferenceCostUsdMicros"]
        self.write(r)
        t = RuntimeLedger(self.ledger_path, 50_000_000).totals()
        self.assertEqual((t["estimatedUsdMicros"], t["committedUsdMicros"]), (2814, 2814))

    def test_new_calls_append_to_the_same_old_file_without_reset(self):
        self.write(old_rows())
        before = self.ledger_path.read_bytes()
        p = self.provider(FakeTransport(completion()))
        p.call(req(), KEY)
        self.assertTrue(self.ledger_path.read_bytes().startswith(before))      # append-only
        self.assertEqual(self.ledger.totals()["calls"], 2)
        self.assertGreater(self.ledger.totals()["committedUsdMicros"], 2814)

    def test_reconcile_with_saved_host_evidence_is_append_only_idempotent_and_exact(self):
        ev = json.loads(EVIDENCE.read_text())
        self.write(old_rows(ev["generation"]["id"]))
        before = self.ledger_path.read_bytes()
        led = RuntimeLedger(self.ledger_path, 50_000_000)
        pre = led.reconcile("old|k", ev["generation"], key_status=ev["keyStatus"], apply=False)
        self.assertEqual((pre["appended"], self.ledger_path.read_bytes()), (False, before))
        res = led.reconcile("old|k", ev["generation"], key_status=ev["keyStatus"])
        self.assertEqual((res["appended"], res["after"]["committedUsdMicros"]), (True, 2814))
        row = json.loads(self.ledger_path.read_text().splitlines()[-1])
        self.assertEqual((row["type"], row["isByok"], row["upstreamInferenceCostUsdMicros"], row["keyRemainingUsd"]),
                         ("reconcile", True, 2814, "49.997186"))
        self.assertTrue(self.ledger_path.read_bytes().startswith(before))
        self.assertFalse(led.reconcile("old|k", ev["generation"], key_status=ev["keyStatus"])["appended"])
        self.assertEqual(led.totals()["committedUsdMicros"], 2814)

    def test_reconcile_refuses_a_generation_that_is_not_in_the_ledger_row(self):
        self.write(old_rows())
        with self.assertRaises(ValueError):
            RuntimeLedger(self.ledger_path, 50_000_000).reconcile("old|k", {"id": "gen-other", "total_cost": 0})

    def test_reconcile_cli_previews_then_applies_and_never_creates_a_ledger(self):
        ev = json.loads(EVIDENCE.read_text())
        self.write(old_rows(ev["generation"]["id"]))
        out = io.StringIO()
        self.assertEqual(REC.main(["--ledger", str(self.ledger_path), "--evidence", str(EVIDENCE)], out=out), 0)
        self.assertFalse(json.loads(out.getvalue())["applied"])
        self.assertEqual(len(self.ledger_path.read_text().splitlines()), 2)
        out = io.StringIO()
        self.assertEqual(REC.main(["--ledger", str(self.ledger_path), "--evidence", str(EVIDENCE), "--apply"], out=out), 0)
        self.assertEqual(len(self.ledger_path.read_text().splitlines()), 3)
        with self.assertRaises(SystemExit):
            REC.main(["--ledger", str(self.op / "missing.jsonl"), "--evidence", str(EVIDENCE)], out=io.StringIO())
        self.assertFalse((self.op / "missing.jsonl").exists())

    def test_key_usage_zero_never_releases_a_charge(self):
        self.assertEqual(key_limit_delta({"limit_remaining": "50"}, {"limit_remaining": "49.997186"}), "0.002814")
        self.assertIsNone(key_limit_delta({}, {}))


class TokenBound(unittest.TestCase):
    def test_bound_exceeds_the_observed_canary_ratio_and_one_token_per_byte(self):
        self.assertGreater(worst_case_input_tokens(2356), 1347)
        self.assertGreaterEqual(worst_case_input_tokens(2356), 2356)
        self.assertGreater(worst_case_router_micros(SONNET, 2356, 300), 1347 * 2 + 12 * 10)
        self.assertEqual(worst_case_input_tokens(50_000_000), 1_000_000)        # capped at the 1M context


class RunScope(RT):
    def test_second_run_same_call_tuple_is_admitted_and_duplicates_stay_refused_within_a_scope(self):
        p1 = self.provider(run_scope="run-1")
        self.assertEqual(p1.call(req(), KEY).outcome, "processed")
        self.assertEqual(p1.call(req(), KEY).error["detail"]["reason"], "duplicate-call-key")
        p2 = OR.OpenRouterProvider(enabled=True, key=p1._key, authorization=self.handle_, book=self.book,
                                   ledger=RuntimeLedger(self.ledger_path, 50_000_000), transport=FakeTransport(), run_scope="run-2")
        self.assertEqual(p2.call(req(), KEY).outcome, "processed")
        p3 = OR.OpenRouterProvider(enabled=True, key=p1._key, authorization=self.handle_, book=self.book,
                                   ledger=RuntimeLedger(self.ledger_path, 50_000_000), transport=FakeTransport())
        self.assertEqual(p3.call(req(), KEY).outcome, "processed")             # default: fresh random scope
        self.assertEqual(self.ledger.totals()["calls"], 3)

    def test_scope_is_not_model_visible_and_is_validated(self):
        p = self.provider(run_scope="run-1")
        self.assertNotIn("run-1", json.dumps(p.build_body(req())[0]))
        for bad in ("", "a|b", "x" * 65, "a b", 5):
            with self.assertRaises(ValueError):
                make_scope(bad)


class StringOnlyContent(RT):
    def test_non_string_content_and_odd_messages_are_refused_not_sent(self):
        p = self.provider()
        for content in ([{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "1h"}}], None, 5, {"a": 1}):
            r = req()
            r["messages"][1]["content"] = content
            self.assertEqual(p.call(r, KEY[:4] + (len(str(content)),)).outcome, "not-sent")
        r = req()
        r["messages"][1]["role"] = "function"
        self.assertEqual(p.call(r, ("a", "b", "c", 9, 9)).outcome, "not-sent")
        self.assertEqual(self.transport.requests, [])


class NestedJson(RT):
    def test_nested_model_output_keeps_the_charged_receipt(self):
        p = self.provider(FakeTransport(completion(content="[" * 100_000)))
        res = p.call(req(), KEY)
        self.assertEqual((res.outcome, res.response["status"]), ("processed", "invalid-output"))
        last = self.receipts()[-1]
        self.assertEqual((last["type"], last["generationId"], last["routerCostUsdMicros"]), ("result", "gen-abc123", 4000))

    def test_nested_http_body_leaves_a_result_row_not_an_orphan_intent(self):
        res = self.provider(FakeTransport(HttpResponse(200, {}, b"[" * 200_000))).call(req(), KEY)
        self.assertEqual(res.outcome, "unknown")
        self.assertEqual([r["type"] for r in self.receipts()], ["intent", "result"])

    def test_any_crash_after_the_response_still_finishes_the_intent(self):
        p = self.provider(FakeTransport(completion()))
        with mock.patch.object(OR.OpenRouterProvider, "_interpret", side_effect=RuntimeError(FAKE_KEY)):
            res = p.call(req(), KEY)
        self.assertEqual(res.outcome, "unknown")
        self.assertEqual(self.receipts()[-1]["errorKind"], "interpret-crash")
        self.assertNotIn(FAKE_KEY, self.ledger_path.read_text())
        self.assertNotIn(FAKE_KEY, json.dumps(res.error))


class TotalDeadline(unittest.TestCase):
    def _run(self, handler, timeout):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

        def fake(host, port, timeout=None, context=None):
            return http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=timeout)
        t0 = time.monotonic()
        with mock.patch.object(OR.http.client, "HTTPSConnection", fake):
            with self.assertRaises(OR.TransportTimeout) as c:
                HttpsTransport()(HttpRequest("POST", "/x", {}, b"{}", timeout, 1 << 16))
        return c.exception, time.monotonic() - t0

    def test_slow_drip_body_and_headers_end_at_the_deadline_with_sent_true(self):
        class Body(http.server.BaseHTTPRequestHandler):
            def do_POST(s):
                s.send_response(200); s.send_header("Content-Length", "100000"); s.end_headers()
                try:
                    for _ in range(30):
                        s.wfile.write(b"x"); s.wfile.flush(); time.sleep(0.3)
                except OSError:
                    pass
            def log_message(s, *a): pass

        class Head(http.server.BaseHTTPRequestHandler):
            def do_POST(s):
                try:
                    s.wfile.write(b"HTTP/1.1 200 OK\r\n")
                    for i in range(30):
                        s.wfile.write(b"X-%d: y\r\n" % i); s.wfile.flush(); time.sleep(0.3)
                except OSError:
                    pass
            def log_message(s, *a): pass
        for h in (Body, Head):
            exc, dt = self._run(h, 1.0)
            self.assertTrue(exc.sent)
            self.assertLess(dt, 2.5, h.__name__)


if __name__ == "__main__":
    unittest.main()
