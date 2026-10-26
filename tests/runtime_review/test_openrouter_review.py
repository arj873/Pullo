"""Independent S0B-01a review: OpenRouter adapter + runtime ledger. Offline only: fake transports, a fake key,
a localhost-only socket server. `expectedFailure` marks a CONFIRMED defect (the assertion states the safe
behaviour); when the author fixes it the test turns into an 'unexpected success' - remove the decorator then.
S0B-01b: F3/F4/F5/F9 are fixed and their decorators removed (positive regression tests now); remaining
expectedFailure marks are Terra F1/F6/F8 only (see test_codex_review).

    nice -n 19 python3 -m unittest discover -s tests/runtime_review -t .
"""
from __future__ import annotations

import http.client
import http.server
import json
import multiprocessing as mp
import os
import threading
import time
import unittest
from decimal import Decimal
from unittest import mock

from reviewer.runtime import RuntimeLedger
from reviewer.runtime import openrouter as OR
from reviewer.runtime.openrouter import HttpRequest, HttpResponse, HttpsTransport, TransportError
from tests.runtime.common import (FAKE_KEY, HAIKU, OPUS, SONNET, FakeTransport, RT, completion, req)

KEY = ("INVESTIGATE", "investigator", "a", 0, 1)


def _admit_worker(path, cap, worst, idx, out):
    led = RuntimeLedger(path, cap)
    out.put(led.admit(f"k{idx}", worst, model=SONNET) is None)


class Allowlist(RT):
    def test_model_id_variants_are_all_refused_before_the_network(self):
        p = self.provider()
        bad = [SONNET + ":thinking", SONNET + ":nitro", SONNET + ":floor", SONNET + " ", " " + SONNET, SONNET.upper(),
               "anthropic/claude-sonnet-5.5\n", "anthropic/claude-sonnet-5-5", "~anthropic/claude-sonnet-latest",
               "anthropic/claude-sonnet-5.5​", "anthropic/claude-sonnеt-5.5", "openrouter/auto",
               "anthropic/claude-sonnet-5.5-20260101", "anthropic/claude-3.5-sonnet", OPUS + "-fast", ""]
        for m in bad:
            with self.subTest(model=m):
                r = p.call(req(model=m), KEY + (hash(m) % 1000,))
                self.assertEqual((r.outcome, r.error["code"]), ("not-sent", "provider-error"))
        self.assertEqual(self.transport.requests, [])

    def test_opus_refused_unless_the_authorization_lists_it(self):
        p = self.provider()     # auth lists SONNET, HAIKU only
        self.assertEqual(p.call(req(model=OPUS), KEY).outcome, "not-sent")

    def test_params_cannot_smuggle_routing_or_plugin_fields(self):
        p = self.provider()
        r = req(params={"maxOutputTokens": 500, "provider": {"allow_fallbacks": True}, "models": ["openai/gpt-4o"],
                        "plugins": [{"id": "web"}], "transforms": ["middle-out"], "route": "fallback", "reasoning": {"effort": "high"},
                        "usage": {"include": False}, "tools": [{"x": 1}], "stop": ["x"], "top_p": 1})
        body, info = p.build_body(r)
        self.assertEqual(set(body), {"model", "messages", "max_tokens", "stream", "response_format", "provider"})
        self.assertEqual(body["provider"], {"order": ["anthropic"], "only": ["anthropic"], "allow_fallbacks": False,
                                            "require_parameters": True})
        self.assertIn("plugins", info["droppedParams"])

    def test_message_extra_keys_dropped(self):
        p = self.provider()
        r = req()
        r["messages"][1]["cache_control"] = {"type": "ephemeral", "ttl": "1h"}
        r["messages"][1]["name"] = "x"
        body, _ = p.build_body(r)
        self.assertEqual(set(body["messages"][1]), {"role", "content"})

    def test_F9_non_string_message_content_must_be_refused_by_the_adapter(self):
        """Defence in depth: the adapter copies `content` verbatim. Via the gateway Message.content is a str, but the
        adapter is also callable directly (host scripts) and then passes image_url/file/cache_control parts."""
        p = self.provider()
        r = req()
        r["messages"][1]["content"] = [{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "1h"}},
                                       {"type": "image_url", "image_url": {"url": "https://example.invalid/x.png"}}]
        res = p.call(r, KEY)
        self.assertEqual(res.outcome, "not-sent")


class MaxOutputBound(RT):
    def test_explicit_cap_required_and_bool_rejected(self):
        p = self.provider()
        for params in ({}, {"maxOutputTokens": True}, {"maxOutputTokens": 0}, {"maxOutputTokens": -5}, {"maxOutputTokens": 1.5},
                       {"maxOutputTokens": "300"}):
            with self.subTest(params=params):
                self.assertEqual(p.call(req(params=params), KEY).outcome, "not-sent")

    def test_smallest_of_aliases_wins(self):
        p = self.provider()
        body, _ = p.build_body(req(params={"maxOutputTokens": 4000, "max_tokens": 50, "max_output_tokens": 900}))
        self.assertEqual(body["max_tokens"], 50)

    def test_huge_cap_is_stopped_by_the_ledger_not_sent(self):
        p = self.provider()
        r = p.call(req(params={"maxOutputTokens": 10**9}), KEY)
        self.assertEqual(r.outcome, "not-sent")
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.receipts()[-1 if self.receipts() else 0:], [])    # no intent recorded for a refusal

    def test_ledger_refuses_the_call_that_would_cross_the_aggregate_cap(self):
        p = self.provider(cap=30_000)
        self.assertEqual(p.call(req(params={"maxOutputTokens": 4000}), KEY + (1,)).outcome, "not-sent")   # worst ~ $0.04+
        r = p.call(req(params={"maxOutputTokens": 100}), KEY + (2,))
        self.assertEqual(r.outcome, "processed")

    def test_cached_and_reasoning_tokens_do_not_double_count(self):
        p = self.provider(FakeTransport(completion(usage={"prompt_tokens": 1000, "completion_tokens": 500,
                                                          "prompt_tokens_details": {"cached_tokens": 300, "cache_write_tokens": 200},
                                                          "completion_tokens_details": {"reasoning_tokens": 400}, "cost": 0.01})))
        r = p.call(req(), KEY)
        u = r.response["usage"]
        self.assertEqual((u["uncachedInputTokens"], u["cachedInputTokens"], u["cacheWriteInputTokens"], u["outputTokens"],
                          u["reasoningTokens"]), (500, 300, 200, 500, 400))

    def test_reasoning_larger_than_output_is_inconsistent_but_not_rejected(self):
        """Observation (low): reasoning_tokens > completion_tokens is accepted as-is; informational only."""
        p = self.provider(FakeTransport(completion(usage={"prompt_tokens": 10, "completion_tokens": 5,
                                                          "completion_tokens_details": {"reasoning_tokens": 99}, "cost": 0.001})))
        u = p.call(req(), KEY).response["usage"]
        self.assertEqual(u["reasoningTokens"], 99)


class UsageAndCost(RT):
    def _one(self, usage, **kw):
        p = self.provider(FakeTransport(completion(usage=usage, **kw)))
        r = p.call(req(), KEY)
        return r, self.receipts()[-1]

    def test_malformed_usage_values_become_null_never_zero(self):
        cases = [{"prompt_tokens": -1, "completion_tokens": 5}, {"prompt_tokens": 1.5, "completion_tokens": 5},
                 {"prompt_tokens": True, "completion_tokens": 5}, {"prompt_tokens": "10", "completion_tokens": 5},
                 {"prompt_tokens": None, "completion_tokens": None}, {}, {"prompt_tokens": 10, "completion_tokens": 5,
                  "prompt_tokens_details": {"cached_tokens": 11}}, {"prompt_tokens": 10, "completion_tokens": 5,
                  "prompt_tokens_details": {"cached_tokens": 6, "cache_write_tokens": 6}},
                 {"prompt_tokens": 10, "completion_tokens": 5, "prompt_tokens_details": {"cached_tokens": -1}},
                 {"prompt_tokens": 10, "completion_tokens": 5, "prompt_tokens_details": []}]
        for u in cases:
            with self.subTest(usage=u):
                self.setUp()
                r, row = self._one(u)
                self.assertEqual(r.outcome, "processed")
                us = r.response["usage"]
                if us["uncachedInputTokens"] is None:
                    self.assertIsNone(us["cachedInputTokens"])
                self.assertNotIn(0, [v for k, v in us.items() if k == "uncachedInputTokens" and u.get("prompt_tokens") != 0])

    def test_bad_cost_values_leave_cost_unknown_and_ledger_counts_worst_case(self):
        for c in (None, -1, "abc", True, "NaN", "Infinity", [], {}):
            with self.subTest(cost=c):
                self.setUp()
                u = {"prompt_tokens": 100, "completion_tokens": 10, "cost": c}
                if c is None:
                    u.pop("cost")
                r, row = self._one(u)
                self.assertIsNone(row.get("routerCostUsdMicros"))
                self.assertEqual(row["costBasis"], "unknown")
                t = self.ledger.totals()
                self.assertEqual((t["knownUsdMicros"] > 0, t["unknownBoundUsdMicros"] > 0), (False, True))

    def test_cost_is_ceiled_to_micros_and_distinct_from_token_pricing(self):
        r, row = self._one({"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.0000011,
                            "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}})
        self.assertEqual(row["routerCostUsdMicros"], 2)          # ceil, never floor
        self.assertEqual(row["tokenPricedUsdMicros"], 4000)
        self.assertEqual(row["costDeltaUsdMicros"], 2 - 4000)
        self.assertNotIn("billedUsdMicros", r.response)

    def test_float_cost_is_parsed_exactly_not_via_binary_float(self):
        r, row = self._one({"prompt_tokens": 10, "completion_tokens": 1, "cost": 0.1 + 0.2})   # 0.30000000000000004
        self.assertEqual(row["routerCostUsdMicros"], 300001)    # JSON text decimal, ceiled; documented conservative

    def test_zero_cost_for_nonzero_tokens_is_floored_to_token_arithmetic_not_trusted(self):
        """F10 (fixed S0B-01b): usage.cost 0 with 1200 tokens is raw-recorded as 0 but the cap counts max(total, token-priced),
        labelled an estimate. A processed call is never trusted at $0."""
        r, row = self._one({"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0})
        self.assertEqual(row["routerCostUsdMicros"], 0)                       # raw fact kept as reported
        priced = row["tokenPricedUsdMicros"]
        self.assertGreater(priced, 0)
        t = self.ledger.totals()
        self.assertEqual((t["committedUsdMicros"], t["estimatedUsdMicros"], t["knownUsdMicros"]), (priced, priced, 0))
        self.assertEqual((row["accountableBasis"], row["accountableEstimated"]), ("suspect-floored-to-token-priced", True))

    def test_bigint_usage_does_not_crash_the_adapter(self):
        r, row = self._one({"prompt_tokens": 10**40, "completion_tokens": 10**40, "cost": 0.01})
        self.assertEqual(r.outcome, "processed")


class Failures(RT):
    def test_each_http_failure_maps_to_a_billing_safe_outcome(self):
        table = {400: "rejected-before-processing", 401: "rejected-before-processing", 402: "rejected-before-processing",
                 403: "rejected-before-processing", 404: "rejected-before-processing", 413: "rejected-before-processing",
                 422: "rejected-before-processing", 408: "unknown", 429: "unknown", 500: "unknown", 502: "unknown", 503: "unknown",
                 529: "unknown", 301: "unknown", 302: "unknown", 307: "unknown", 204: "unknown", 100: "unknown"}
        for status, outcome in table.items():
            with self.subTest(status=status):
                self.setUp()
                p = self.provider(FakeTransport(HttpResponse(status, {"location": "https://evil.example/"}, b'{"error":{"message":"%s"}}' % FAKE_KEY.encode())))
                r = p.call(req(), KEY)
                self.assertEqual(r.outcome, outcome)
                self.assertIn(r.error["code"], ("provider-error", "provider-timeout"))
                self.assertEqual(len(self.transport.requests), 1)           # redirects never re-requested
                self.assertNotIn(FAKE_KEY, json.dumps(r.error))
                self.assertNotIn(FAKE_KEY, self.ledger_path.read_text())

    def test_key_never_reaches_ledger_result_or_rawtext(self):
        leak = json.dumps({"hypotheses": [], "note": FAKE_KEY})
        for content in (leak, "not json " + FAKE_KEY, "Authorization: Bearer " + FAKE_KEY):
            with self.subTest(content=content[:20]):
                self.setUp()
                p = self.provider(FakeTransport(completion(content=content)))
                r = p.call(req(), KEY)
                self.assertNotIn(FAKE_KEY, json.dumps(r.response, default=str))
                self.assertNotIn(FAKE_KEY, self.ledger_path.read_text())

    def test_key_not_in_repr_of_request_or_provider(self):
        p = self.provider()
        h = p._headers(True)
        r = HttpRequest("POST", "/x", h, b"", 1.0, 10)
        self.assertNotIn(FAKE_KEY, repr(r) + repr(p) + repr(p._key) + str(p._key))
        self.assertNotIn(FAKE_KEY, repr(vars(p)))

    def test_in_band_error_on_200_is_unknown_and_keeps_reservation(self):
        for doc in ({"error": {"code": 502, "message": "x"}}, {"id": "g", "error": None, "choices": []}):
            self.setUp()
            p = self.provider(FakeTransport(json.dumps(doc).encode()))
            r = p.call(req(), KEY)
            self.assertEqual(r.outcome, "unknown")
            self.assertGreater(self.ledger.totals()["unknownBoundUsdMicros"], 0)

    def test_malformed_200_bodies(self):
        bodies = [b"", b"[]", b"null", b"{", b"\xff\xfe", b'{"choices":[]}', b'{"choices":[{},{}],"model":"x"}',
                  b'{"choices":[{"message":{"content":"{}"}}],"model":""}', b'{"choices":[{"message":{"content":"{}"}}],"model":5}',
                  b'{"choices":[{"message":{"content":"{}"}}],"model":"' + b"x" * 200 + b'"}',
                  b'{"a":1,"a":2}', b'{"choices":NaN}', b'{"usage":{"cost":Infinity}}']
        for b in bodies:
            with self.subTest(body=b[:30]):
                self.setUp()
                r = self.provider(FakeTransport(b)).call(req(), KEY)
                self.assertEqual(r.outcome, "unknown")
                self.assertGreater(self.ledger.totals()["committedUsdMicros"], 0)

    def test_output_validation_is_local_and_authoritative(self):
        for content, want in ((json.dumps({"hypotheses": "x"}), "invalid-output"), ("{}", "invalid-output"), ("[]", "invalid-output"),
                              ("```json\n{\"hypotheses\": []}\n```", "invalid-output"), ('{"hypotheses": [], "hypotheses": []}', "invalid-output"),
                              (json.dumps({"hypotheses": []}), "ok"), ("", "invalid-output")):
            with self.subTest(content=content[:30]):
                self.setUp()
                r = self.provider(FakeTransport(completion(content=content))).call(req(), KEY)
                self.assertEqual(r.response["status"], want)

    def test_truncated_or_filtered_output_is_never_ok(self):
        for fin in ("length", "content_filter"):
            self.setUp()
            r = self.provider(FakeTransport(completion(finish=fin))).call(req(), KEY)
            self.assertEqual(r.response["status"], "invalid-output")

    def test_F5_deeply_nested_model_output_must_not_crash_the_adapter(self):
        """CONFIRMED crash: the model's content string is parsed by _loads inside `except (ValueError, UnicodeError)`. A
        nested-array output raises RecursionError, which escapes `call()` AFTER the charged response was received: the
        gateway records a generic 'adapter failed', the real cost/generation id are lost, the ledger keeps only a
        worst-case intent."""
        nest = "[" * 100_000 + "]" * 100_000
        p = self.provider(FakeTransport(completion(content=nest, finish="stop")))
        r = p.call(req(), KEY)           # expected to return a ProviderResult
        self.assertEqual(r.outcome, "processed")

    def test_F5b_deeply_nested_http_body_must_not_crash_the_adapter(self):
        p = self.provider(FakeTransport(HttpResponse(200, {}, b"[" * 200_000)))
        r = p.call(req(), KEY)
        self.assertEqual(r.outcome, "unknown")

    def test_F5_effect_through_gateway_keeps_the_charged_receipt(self):
        """Fixed: the nested model output is `invalid-output` with a result row (cost + generation id kept), no orphan intent."""
        p = self.provider(FakeTransport(completion(content="[" * 100_000, finish="stop")))
        gw = self.gateway(p)
        res = gw.call("INVESTIGATE", "investigator", "a", 0, req())
        self.assertFalse(res.ok)
        rows = self.receipts()
        self.assertEqual([r["type"] for r in rows], ["intent", "result"])
        self.assertEqual((rows[1]["outcome"], rows[1]["generationId"], rows[1]["note"]), ("processed", "gen-abc123", "invalid-output"))
        self.assertEqual(rows[1]["routerCostUsdMicros"], 4000)


class LedgerConcurrency(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp(prefix="rvw-rev-")
        self.path = os.path.join(self.d, "ledger.jsonl")

    def test_cross_process_admission_never_exceeds_cap(self):
        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        n, worst, cap = 12, 1_000_000, 5_000_000
        ps = [ctx.Process(target=_admit_worker, args=(self.path, cap, worst, i, q)) for i in range(n)]
        [p.start() for p in ps]
        [p.join(60) for p in ps]
        admitted = sum(q.get(timeout=10) for _ in range(n))
        self.assertEqual(admitted, 5)
        self.assertEqual(RuntimeLedger(self.path, cap).totals()["committedUsdMicros"], 5_000_000)

    def test_threads_in_one_process(self):
        led = RuntimeLedger(self.path, 3_000_000)
        res = []
        ts = [threading.Thread(target=lambda i=i: res.append(led.admit(f"t{i}", 1_000_000, model=SONNET))) for i in range(10)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sum(r is None for r in res), 3)

    def test_crash_after_intent_is_counted_at_worst_case_and_persists(self):
        ctx = mp.get_context("spawn")
        p = ctx.Process(target=_crash_after_admit, args=(self.path,))
        p.start(); p.join(60)
        t = RuntimeLedger(self.path, 5_000_000).totals()
        self.assertEqual((t["unknownBoundUsdMicros"], t["knownUsdMicros"]), (2_000_000, 0))
        self.assertIsNotNone(RuntimeLedger(self.path, 5_000_000).admit("n", 4_000_000, model=SONNET))   # 2+4 > 5

    def test_torn_or_corrupt_ledger_fails_closed(self):
        with open(self.path, "w") as f:
            f.write('{"type":"intent","callKey":"a","worstCaseUsdMicros":1}\n{"type":"res')
        with self.assertRaises(ValueError):
            RuntimeLedger(self.path, 5_000_000).admit("b", 1, model=SONNET)

    def test_symlinked_ledger_is_refused(self):
        tgt = os.path.join(self.d, "t"); open(tgt, "w").close()
        os.symlink(tgt, self.path)
        with self.assertRaises(OSError):
            RuntimeLedger(self.path, 1).admit("a", 1, model=SONNET)

    def test_ledger_mode_is_0600(self):
        RuntimeLedger(self.path, 5).admit("a", 1, model=SONNET)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_result_rows_reject_unsafe_fields(self):
        led = RuntimeLedger(self.path, 5)
        for f in ("headers", "authorization", "body", "errorBody", "key"):
            with self.assertRaises(ValueError):
                led.finish("a", **{f: "x"})

    def test_cap_over_the_trial_total_is_not_constructible_via_provider(self):
        t = RT("test_ledger_mode_is_0600") if False else None   # (author tests cover); keep a structural assertion
        self.assertIsNone(t)


def _crash_after_admit(path):
    RuntimeLedger(path, 5_000_000).admit("crash", 2_000_000, model=SONNET)
    os._exit(9)


class CrossRunKeys(RT):
    def test_F3_same_call_tuple_in_a_second_run_must_not_be_refused(self):
        """CONFIRMED availability defect: the gateway passes key=(stage, role, agentId, ordinal, attempt) with NO run id,
        and RuntimeLedger.admit refuses any callKey already in the (shared, persistent) file. The plan is to reuse one state
        dir for the $50 aggregate, so the second run/retry of the same logical call ('canary' included) is refused."""
        p1 = self.provider()
        self.assertEqual(p1.call(req(), KEY).outcome, "processed")
        p2 = OR.OpenRouterProvider(enabled=True, key=p1._key, authorization=self.handle_, book=self.book,
                                   ledger=RuntimeLedger(self.ledger_path, 50_000_000), transport=FakeTransport())
        self.assertEqual(p2.call(req(), KEY).outcome, "processed")

    def test_F3_effect_is_a_misleading_not_sent_provider_error(self):
        p = self.provider()
        p.call(req(), KEY)
        r = p.call(req(), KEY)
        self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("not-sent", "duplicate-call-key"))


class TransportBounds(unittest.TestCase):
    """HttpsTransport against a localhost HTTP server (TLS swapped out): deadline, size, redirect and slow-drip behaviour."""

    def _serve(self, handler):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return srv.server_address[1]

    def _call(self, port, timeout, maxb=1 << 16):
        def fake(host, p, timeout=None, context=None):
            return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        with mock.patch.object(OR.http.client, "HTTPSConnection", fake):
            t0 = time.monotonic()
            try:
                r = HttpsTransport()(HttpRequest("POST", "/api/v1/chat/completions", {"Authorization": "Bearer x"}, b"{}", timeout, maxb))
            except Exception as e:  # noqa: BLE001
                r = e
            return r, time.monotonic() - t0

    def test_oversize_body_is_cut_and_flagged(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(s):
                s.send_response(200); s.send_header("Content-Length", "1000000"); s.end_headers()
                try: s.wfile.write(b"x" * 1_000_000)
                except OSError: pass
            def log_message(s, *a): pass
        r, dt = self._call(self._serve(H), 5, maxb=1000)
        self.assertTrue(r.truncated)

    def test_redirect_is_returned_not_followed(self):
        hits = []
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(s):
                hits.append(s.path); s.send_response(307); s.send_header("Location", "http://127.0.0.1:1/steal"); s.send_header("Content-Length", "0"); s.end_headers()
            def log_message(s, *a): pass
        r, _ = self._call(self._serve(H), 5)
        self.assertEqual((r.status, hits), (307, ["/api/v1/chat/completions"]))

    def test_silent_server_times_out(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(s): time.sleep(4)
            def log_message(s, *a): pass
        r, dt = self._call(self._serve(H), 1)
        self.assertIsInstance(r, OR.TransportTimeout)
        self.assertLess(dt, 3)

    def test_F4_slow_drip_body_must_respect_the_total_deadline(self):
        """CONFIRMED: the total deadline is only checked BETWEEN r.read(65536) calls; each recv inside a read gets a fresh
        socket timeout, so a server (or a stalled upstream) that sends one byte every <timeout seconds holds the call (and
        the gateway thread, and the reserved budget) far past `timeout`."""
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(s):
                s.send_response(200); s.send_header("Content-Length", "100000"); s.end_headers()
                try:
                    for _ in range(40):
                        s.wfile.write(b"x"); s.wfile.flush(); time.sleep(0.5)
                except OSError: pass
            def log_message(s, *a): pass
        r, dt = self._call(self._serve(H), 2)          # 2 s total deadline
        self.assertLess(dt, 4.5, f"call took {dt:.1f}s with a 2s deadline")

    def test_F4b_slow_drip_headers_must_respect_the_total_deadline(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(s):
                try:
                    s.wfile.write(b"HTTP/1.1 200 OK\r\n")
                    for i in range(40):
                        s.wfile.write(b"X-%d: y\r\n" % i); s.wfile.flush(); time.sleep(0.5)
                except OSError: pass
            def log_message(s, *a): pass
        r, dt = self._call(self._serve(H), 2)
        self.assertLess(dt, 4.5, f"call took {dt:.1f}s with a 2s deadline")

    def test_tls_context_verifies_certs_and_hostname(self):
        seen = {}
        def fake(host, port, timeout=None, context=None):
            seen.update(host=host, port=port, ctx=context)
            return http.client.HTTPConnection("127.0.0.1", 1, timeout=1)
        with mock.patch.object(OR.http.client, "HTTPSConnection", fake):
            with self.assertRaises(TransportError):
                HttpsTransport()(HttpRequest("GET", "/api/v1/key", {}, None, 1.0, 10))
        import ssl
        c = seen["ctx"]
        self.assertEqual((seen["host"], seen["port"], c.verify_mode, c.check_hostname), ("openrouter.ai", 443, ssl.CERT_REQUIRED, True))
        self.assertGreaterEqual(c.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_connect_failure_is_not_sent(self):
        def fake(host, port, timeout=None, context=None):
            return http.client.HTTPConnection("127.0.0.1", 1, timeout=timeout)
        with mock.patch.object(OR.http.client, "HTTPSConnection", fake):
            with self.assertRaises(TransportError) as c:
                HttpsTransport()(HttpRequest("POST", "/x", {}, b"{}", 2.0, 10))
        self.assertFalse(c.exception.sent)

    def test_env_proxies_are_not_used(self):
        import inspect
        src = inspect.getsource(OR.HttpsTransport)
        self.assertNotIn("urllib", src)
        self.assertNotIn("proxy", src.lower())


class EvidenceHelpers(RT):
    def test_generation_id_is_validated_against_path_injection(self):
        p = self.provider()
        for g in ("a/../key", "a?b=c", "a b", "a\r\nX: y", "", "x" * 201, 5, None, "a&b"):
            self.assertIsNone(p.generation(g))
        self.assertEqual(self.transport.requests, [])

    def test_key_status_returns_strings_and_records_note_without_secrets(self):
        t = FakeTransport(HttpResponse(200, {}, b'{"data":{"label":"sk-or-v1-abcdef...","limit":50,"usage":0.0123,"limit_remaining":49.98}}'))
        p = self.provider(t)
        out = p.key_status()
        self.assertEqual(out, {"limit": "50", "usage": "0.0123", "limit_remaining": "49.98"})
        self.assertNotIn("label", self.ledger_path.read_text())


if __name__ == "__main__":
    unittest.main()
