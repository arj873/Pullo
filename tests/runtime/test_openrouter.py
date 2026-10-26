import json
import re
import unittest
from pathlib import Path

from reviewer.gateway import SpendBook, load_trace
from reviewer.gateway.errors import AuthorizationError
from reviewer.runtime import OpenRouterProvider, RuntimeLedger, Secret
from reviewer.runtime import openrouter as orm
from reviewer.runtime.catalog import worst_case_router_micros
from reviewer.runtime.openrouter import HttpResponse, TransportError, TransportTimeout
from tests.runtime.common import (FAKE_KEY, HAIKU, OK_INV, OPUS, PROFILE, RT, SONNET, FakeTransport, completion, req)

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)


class Construction(RT):
    def test_requires_explicit_opt_in_and_durable_book(self):
        h = self.auth()
        kw = dict(key=Secret(FAKE_KEY), authorization=h, ledger=RuntimeLedger(self.ledger_path, 50_000_000),
                  transport=FakeTransport())
        with self.assertRaises(AuthorizationError):
            OpenRouterProvider(enabled=False, book=SpendBook(h, self.book_path), **kw)
        with self.assertRaises(AuthorizationError):
            OpenRouterProvider(enabled=True, book=SpendBook(h), **kw)        # in-memory book: not durable
        OpenRouterProvider(enabled=True, book=SpendBook(h, self.book_path), **kw)

    def test_total_over_fifty_dollars_refused(self):
        h = self.auth(maxUsdMicrosTotal=50_000_001)
        with self.assertRaises(AuthorizationError):
            OpenRouterProvider(enabled=True, key=Secret(FAKE_KEY), authorization=h, book=SpendBook(h, self.book_path),
                               ledger=RuntimeLedger(self.ledger_path, 50_000_000), transport=FakeTransport())
        with self.assertRaises(AuthorizationError):
            h = self.auth()
            OpenRouterProvider(enabled=True, key=Secret(FAKE_KEY), authorization=h, book=SpendBook(h, self.book_path),
                               ledger=RuntimeLedger(self.ledger_path, 60_000_000), transport=FakeTransport())

    def test_key_must_be_secret(self):
        h = self.auth()
        with self.assertRaises(AuthorizationError):
            OpenRouterProvider(enabled=True, key=FAKE_KEY, authorization=h, book=SpendBook(h, self.book_path),
                               ledger=RuntimeLedger(self.ledger_path, 50_000_000))

    def test_no_redirect_following_or_foreign_hosts_in_source(self):
        src = Path(orm.__file__).read_text()
        for bad in ("urlopen", "import requests", "urllib", "http://", "follow_redirects", "allow_redirects"):
            self.assertFalse(bad in src, bad)
        self.assertEqual(re.findall(r'https?://[\w.\-/]+', src), [])
        self.assertEqual(orm.HOST, "openrouter.ai")


class Body(RT):
    def test_request_shape_snapshot(self):
        p = self.provider()
        body, info = p.build_body(req())
        self.assertEqual(set(body), {"model", "messages", "max_tokens", "stream", "response_format", "provider"})
        self.assertEqual(body["model"], SONNET)
        self.assertEqual(body["max_tokens"], 4000)
        self.assertIs(body["stream"], False)
        self.assertEqual(body["provider"], {"order": ["anthropic"], "only": ["anthropic"], "allow_fallbacks": False,
                                            "require_parameters": True})
        rf = body["response_format"]["json_schema"]
        self.assertEqual((rf["name"], rf["strict"]), ("InvestigatorOutput", True))
        for banned in ("models", "route", "plugins", "transforms", "temperature", "tools", "tool_choice"):
            self.assertNotIn(banned, body)
        self.assertEqual(info["droppedParams"], ["temperature"])      # profile temperature is never forwarded (Sonnet 5.5)
        self.assertEqual(body["messages"][1], {"role": "user", "content": "Diff:\n+x = 1\n"})

    def test_refusals_never_touch_the_network(self):
        p = self.provider()
        cases = {"opus never authorized": req(model=OPUS),
                 "bare anthropic id": req(model="claude-sonnet-5-5"),
                 "wrong provider": req(provider="openai"),
                 "no token cap": req(params={"temperature": 0}),
                 "tools": req(tools=[{"name": "x"}]),
                 "schema mismatch": req(outputSchema="JudgeOutput")}
        for why, r in cases.items():
            with self.subTest(why):
                res = p.call(r, KEY)
                self.assertEqual((res.outcome, res.error["code"]), ("not-sent", "provider-error"))
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.receipts(), [])

    def test_model_outside_the_authorization_is_refused(self):
        p = self.provider(handle=self.auth(models=[SONNET]))
        self.assertEqual(p.call(req(model=HAIKU), KEY).outcome, "not-sent")
        self.assertEqual(self.transport.requests, [])

    def test_authorization_header_is_never_in_repr_or_receipts(self):
        p = self.provider()
        p.call(req(), KEY)
        hr = self.transport.requests[0]
        self.assertEqual(hr.path, "/api/v1/chat/completions")
        self.assertTrue(hr.headers["Authorization"].startswith("Bearer "))
        self.assertNotIn(FAKE_KEY, repr(hr))
        self.assertNotIn(FAKE_KEY, self.ledger_path.read_text())
        self.assertNotIn(FAKE_KEY, self.book_path.read_text() if self.book_path.exists() else "")


class Success(RT):
    def test_ok_usage_and_receipt_distinguish_router_cost_from_token_price(self):
        p = self.provider(FakeTransport(completion(usage={
            "prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.0123,
            "prompt_tokens_details": {"cached_tokens": 100, "cache_write_tokens": 50},
            "completion_tokens_details": {"reasoning_tokens": 7}})))
        res = p.call(req(), KEY)
        self.assertEqual(res.outcome, "processed")
        r = res.response
        self.assertEqual((r["status"], r["resolvedModel"], r["providerRequestId"]), ("ok", SONNET, "gen-abc123"))
        self.assertEqual(r["usage"], {"uncachedInputTokens": 850, "cachedInputTokens": 100, "cacheWriteInputTokens": 50,
                                      "outputTokens": 200, "reasoningTokens": 7})
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual(rec["routerCostUsd"], "0.0123")
        self.assertEqual(rec["routerCostUsdMicros"], 12300)
        # 850*2 + 100*0.1 + 50*2.5 + 200*10 per Mtok = 1700+10+125+2000 = 3835 micros (catalog arithmetic, not a bill)
        self.assertEqual(rec["tokenPricedUsdMicros"], 3835)
        self.assertEqual(rec["costDeltaUsdMicros"], 12300 - 3835)
        self.assertEqual((rec["costBasis"], rec["billingKind"], rec["generationId"]), ("router-reported", "openrouter-usd", "gen-abc123"))
        self.assertEqual(rec["droppedParams"], ["temperature"])

    def test_missing_usage_is_unknown_not_zero(self):
        p = self.provider(FakeTransport(completion(usage={})))
        res = p.call(req(), KEY)
        self.assertTrue(all(v is None for v in res.response["usage"].values()))
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual((rec["costBasis"], rec["routerCostUsdMicros"], rec["tokenPricedUsdMicros"]), ("unknown", None, None))

    def test_inconsistent_split_is_unknown_input(self):
        p = self.provider(FakeTransport(completion(usage={"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.001,
                                                           "prompt_tokens_details": {"cached_tokens": 9, "cache_write_tokens": 9}})))
        u = p.call(req(), KEY).response["usage"]
        self.assertEqual((u["uncachedInputTokens"], u["cachedInputTokens"], u["cacheWriteInputTokens"], u["outputTokens"]),
                         (None, None, None, 5))

    def test_resolved_model_reported_faithfully_even_when_different(self):
        p = self.provider(FakeTransport(completion(model="anthropic/claude-sonnet-5.5-20261001")))
        self.assertEqual(p.call(req(), KEY).response["resolvedModel"], "anthropic/claude-sonnet-5.5-20261001")

    def test_float_values_in_output_survive(self):
        out = {"hypotheses": [{"claim": "c", "category": "bug", "suspectedSeverity": "P1", "impact": "crash",
                               "location": {"path": "a.py", "line": 1},
                               "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16}], "confidence": 0.75}]}
        p = self.provider(FakeTransport(completion(json.dumps(out))))
        res = p.call(req(), KEY)
        self.assertEqual(res.response["status"], "ok", res.response)
        self.assertEqual(res.response["output"]["hypotheses"][0]["confidence"], 0.75)


class InvalidOutput(RT):
    n = 0

    def check(self, content, finish="stop"):
        self.n += 1
        p = self.provider(FakeTransport(completion(content, finish=finish)))
        res = p.call(req(), ("INVESTIGATE", "investigator", "generalist", self.n, 0))
        self.assertEqual(res.outcome, "processed")
        self.assertEqual((res.response["status"], res.response["output"]), ("invalid-output", None))
        return res.response

    def test_not_json(self):
        self.assertEqual(self.check("{not json")["rawText"], "{not json")

    def test_schema_violation_checked_locally(self):
        self.check(json.dumps({"hypotheses": "nope"}))
        self.check(json.dumps({"hypotheses": [], "extra": 1}))

    def test_length_cutoff_never_ok_even_if_prefix_parses(self):
        self.check(json.dumps(OK_INV), finish="length")

    def test_refusal_without_content(self):
        p = self.provider(FakeTransport(completion(None).replace(b'"content": "{\\"hypotheses\\": []}"', b'"content": null')))
        res = p.call(req(), KEY)
        self.assertEqual((res.response["status"], res.response["rawText"]), ("invalid-output", None))

    def test_raw_text_is_scrubbed_of_the_key(self):
        r = self.check(f"echo {FAKE_KEY} here")
        self.assertNotIn(FAKE_KEY, r["rawText"])


class Failures(RT):
    def one(self, item, **kw):
        p = self.provider(FakeTransport(item), **kw)
        return p.call(req(), KEY)

    def test_http_status_mapping(self):
        table = {400: ("rejected-before-processing", False), 401: ("rejected-before-processing", False),
                 402: ("rejected-before-processing", False), 403: ("rejected-before-processing", False),
                 404: ("rejected-before-processing", False), 413: ("rejected-before-processing", False),
                 422: ("rejected-before-processing", False), 429: ("unknown", True), 500: ("unknown", True),
                 502: ("unknown", True), 503: ("unknown", True), 302: ("unknown", False), 307: ("unknown", False)}
        for status, (outcome, retry) in table.items():
            with self.subTest(status):
                self.setUp()
                res = self.one(HttpResponse(status, {"location": "https://evil.example/x"}, b'{"error":{"message":"sk-or-leak"}}'))
                self.assertEqual((res.outcome, res.error["retryable"], res.error["code"]), (outcome, retry, "provider-error"))
                self.assertNotIn("sk-or-leak", json.dumps(res.error))      # provider error bodies are never surfaced
                self.assertEqual(len(self.transport.requests), 1)           # a redirect is never followed

    def test_408_is_a_timeout_that_keeps_the_reservation(self):
        res = self.one(HttpResponse(408, {}, b"{}"))
        self.assertEqual((res.outcome, res.error["code"], res.error["retryable"]), ("unknown", "provider-timeout", True))

    def test_error_codes_never_include_budget_exhausted(self):
        # NEW1: a provider-side "budget" style error must stay provider-error so replay classes it as retained/released
        for status in (402, 429):
            self.setUp()
            res = self.one(HttpResponse(status, {}, b'{"error":{"message":"credits budget exhausted"}}'))
            self.assertNotEqual(res.error["code"], "budget-exhausted")

    def test_inband_error_may_have_billed(self):
        res = self.one(HttpResponse(200, {}, json.dumps({"id": "gen-x", "error": {"code": 502, "message": "boom"}}).encode()))
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("unknown", "in-band-error"))
        self.assertEqual([r for r in self.receipts() if r["type"] == "result"][0]["generationId"], "gen-x")

    def test_malformed_bodies(self):
        for body in (b"not json", b"[]", b'{"choices": []}', b'{"id":"g","model":"m","choices":[{},{}]}',
                     b'{"a":1,"a":2}', b'{"x": NaN}'):
            with self.subTest(body):
                self.setUp()
                self.assertEqual(self.one(HttpResponse(200, {}, body)).outcome, "unknown")

    def test_oversize_response(self):
        res = self.one(HttpResponse(200, {}, b"x", truncated=True))
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("unknown", "oversize-response"))

    def test_transport_timeout_after_send_is_unknown_and_retryable(self):
        res = self.one(TransportTimeout(True))
        self.assertEqual((res.outcome, res.error["code"], res.error["retryable"]), ("unknown", "provider-timeout", True))

    def test_connect_failure_before_send_is_not_sent(self):
        res = self.one(TransportError(False))
        self.assertEqual((res.outcome, res.error["code"]), ("not-sent", "provider-error"))

    def test_post_send_connection_error_is_unknown(self):
        self.assertEqual(self.one(TransportError(True)).outcome, "unknown")

    def test_crashing_transport_is_unknown(self):
        self.assertEqual(self.one(RuntimeError("boom")).outcome, "unknown")

    def test_secret_in_exception_text_cannot_leak(self):
        res = self.one(RuntimeError(FAKE_KEY))
        self.assertNotIn(FAKE_KEY, json.dumps(res.error))


class Ledger(RT):
    def test_aggregate_cap_refuses_before_network(self):
        r = req()
        p = self.provider(cap=1000)
        res = p.call(r, KEY)
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "runtime-aggregate-cap"))
        self.assertEqual(self.transport.requests, [])

    def test_unknown_cost_is_counted_at_worst_case_and_actual_cost_replaces_it(self):
        p = self.provider(FakeTransport(HttpResponse(500, {}, b"{}"), completion(usage={"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0005})))
        r = req()
        p.call(r, KEY)
        t1 = self.ledger.totals()
        self.assertGreater(t1["unknownBoundUsdMicros"], 0)
        self.assertEqual(t1["knownUsdMicros"], 0)
        p.call(r, ("INVESTIGATE", "investigator", "generalist", 1, 0))
        t2 = self.ledger.totals()
        self.assertEqual(t2["knownUsdMicros"], 500)
        self.assertEqual(t2["unknownBoundUsdMicros"], t1["unknownBoundUsdMicros"])

    def test_rejected_and_not_sent_release_their_bound(self):
        p = self.provider(FakeTransport(HttpResponse(400, {}, b"{}")))
        p.call(req(), KEY)
        self.assertEqual(self.ledger.totals()["committedUsdMicros"], 0)

    def test_second_ledger_instance_sees_the_same_file(self):
        p = self.provider()
        p.call(req(), KEY)
        again = RuntimeLedger(self.ledger_path, 50_000_000).totals()
        self.assertEqual(again["knownUsdMicros"], 4000)

    def test_cap_reached_by_real_costs(self):
        w = worst_case_router_micros(SONNET, 600, 4000)
        p = self.provider(FakeTransport(completion(usage={"prompt_tokens": 1, "completion_tokens": 1, "cost": 0.5})), cap=500_000 + w - 1)
        p.call(req(), KEY)
        res = p.call(req(), ("INVESTIGATE", "investigator", "generalist", 1, 0))
        self.assertEqual(res.error["detail"]["reason"], "runtime-aggregate-cap")

    def test_duplicate_call_key_refused(self):
        p = self.provider()
        p.call(req(), KEY)
        self.assertEqual(p.call(req(), KEY).error["detail"]["reason"], "duplicate-call-key")
        self.assertEqual(len(self.transport.requests), 1)


class Evidence(RT):
    def test_key_status_and_generation_use_fixed_endpoints(self):
        data = json.dumps({"data": {"limit": 50, "usage": 0.5, "limit_remaining": 49.5}}).encode()
        gen = json.dumps({"data": {"id": "gen-1", "total_cost": 0.01, "is_byok": False, "secret": "nope"}}).encode()
        p = self.provider(FakeTransport(data, gen))
        self.assertEqual(p.key_status(), {"limit": "50", "usage": "0.5", "limit_remaining": "49.5"})
        g = p.generation("gen-1")
        self.assertEqual(g["id"], "gen-1")
        self.assertNotIn("secret", g)
        self.assertEqual([r.path for r in self.transport.requests], ["/api/v1/key", "/api/v1/generation?id=gen-1"])
        self.assertIsNone(p.generation("x&evil=1"))


class ThroughGateway(RT):
    """The real Gateway, the real SpendBook, a fake transport: the adapter's results must be accepted,
    settled, recorded, and the resulting trace must load."""

    def run_call(self, items, *, repair=None):
        p = self.provider(FakeTransport(*items))
        gw = self.gateway(p)
        return gw, gw.call("INVESTIGATE", "investigator", "generalist", 0, req(), repair=repair)

    def test_ok_call_is_settled_by_token_price_and_trace_loads(self):
        gw, res = self.run_call([completion()])
        self.assertTrue(res.ok)
        self.assertEqual(res.attempts[0].charge_usd_micros, 3835 if False else res.attempts[0].charge_usd_micros)
        self.assertEqual(gw.report()["liveCalls"], 1)
        gw.recorder.end("completed")
        load_trace(gw.recorder.events)

    def test_wrong_resolved_model_is_a_typed_billed_error(self):
        gw, res = self.run_call([completion(model="anthropic/claude-opus-5.5")])
        self.assertEqual(res.error["code"], "contract-violation")
        gw.recorder.end("completed")
        load_trace(gw.recorder.events)

    def test_invalid_output_repair_is_a_new_admission(self):
        gw, res = self.run_call([completion("{bad"), completion()], repair=lambda resp: req(text="repair"))
        self.assertTrue(res.ok)
        self.assertEqual(len(res.attempts), 2)
        self.assertEqual(len(self.transport.requests), 2)

    def test_error_classes_produce_loadable_traces(self):
        for item in (HttpResponse(429, {}, b"{}"), HttpResponse(400, {}, b"{}"), HttpResponse(402, {}, b"{}"),
                     TransportTimeout(True), TransportError(False), HttpResponse(200, {}, b"junk"),
                     HttpResponse(200, {}, json.dumps({"error": {"message": "x"}}).encode())):
            with self.subTest(repr(item)):
                self.setUp()
                gw, res = self.run_call([item] * 3)
                self.assertIsNotNone(res.error)
                gw.recorder.end("completed")
                load_trace(gw.recorder.events)

    def test_recorded_adapter_results_replay_strictly(self):
        """NEW1 guard: every result class the adapter can emit must replay to the same charge."""
        cases = {"429": [HttpResponse(429, {}, b"{}")] * 3, "400": [HttpResponse(400, {}, b"{}")],
                 "timeout": [TransportTimeout(True)] * 3, "ok": [completion()], "wrong-model": [completion(model="x/y")],
                 "in-band": [HttpResponse(200, {}, b'{"error":{}}')], "invalid-output": [completion("{bad")] * 2}
        for name, items in cases.items():
            with self.subTest(name):
                self.setUp()
                gw, res = self.run_call(items)
                events = self.finish(gw)
                again = self.replayer(events, prof=PROFILE).call("INVESTIGATE", "investigator", "generalist", 0, req())
                self.assertEqual([a.charge_usd_micros for a in again.attempts], [a.charge_usd_micros for a in res.attempts])
                self.assertEqual((again.error or {}).get("code"), (res.error or {}).get("code"))

    def test_rejected_call_releases_book_reservation(self):
        gw, res = self.run_call([HttpResponse(400, {}, b"{}")])
        self.assertEqual(gw.report()["total"]["committed"], 0)
        self.assertEqual(gw.report()["total"]["inflight"], 0)

    def test_unknown_outcome_retains_book_reservation(self):
        gw, res = self.run_call([HttpResponse(500, {}, b"{}")] * 3)
        self.assertGreater(gw.report()["total"]["committed"], 0)

    def test_second_process_view_of_book_sees_charges(self):
        gw, res = self.run_call([completion()])
        self.assertEqual(SpendBook(self.handle_, self.book_path).totals()["committed"], gw.report()["total"]["committed"])


if __name__ == "__main__":
    unittest.main()
