"""S0B-01b-finalfix: F12 (late connect must not send after a not-sent report) and F11 (zero usage is not free).
Run: nice -n 19 python3 -m unittest tests.runtime.test_s0b01b_finalfix"""

import socket
import time
import unittest
from unittest import mock

from reviewer.runtime import accountable_cost
from reviewer.runtime import openrouter as OR
from reviewer.runtime.openrouter import HttpsTransport, TransportTimeout
from tests.runtime.common import FakeTransport, RT, completion, req

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)


class SlowConn:
    """HTTPSConnection stand-in: connect() takes `connect_delay`; every send-side call is recorded."""
    events: list
    connect_delay = 0.0
    hang_after_connect = False

    def __init__(self, host, port, timeout=None, context=None):
        self.sock = None

    def connect(self):
        time.sleep(self.connect_delay)
        self.sock, self.peer = socket.socketpair()

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
        for s in (self.sock, getattr(self, "peer", None)):
            if s is not None:
                s.close()


def conn_class(**attrs):
    return type("C", (SlowConn,), {"events": [], **attrs})


class F12(RT):
    def call(self, delay, timeout, **attrs):
        conn = conn_class(connect_delay=delay, **attrs)
        with mock.patch.object(OR.http.client, "HTTPSConnection", conn):
            try:
                HttpsTransport()(OR.HttpRequest("POST", "/p", {"Authorization": "Bearer x"}, b"{}", timeout, 1 << 16))
                exc = None
            except Exception as e:  # noqa: BLE001
                exc = e
            time.sleep(delay + 0.5)                      # a straggling worker would act now
        return exc, conn.events

    def test_late_connect_never_sends_after_the_deadline(self):
        exc, events = self.call(2.0, 0.5)
        self.assertIsInstance(exc, TransportTimeout)
        self.assertFalse(exc.sent)
        self.assertEqual(events, [])                      # nothing transmitted at all

    def test_late_connect_with_a_long_delay_past_the_watchdog_join(self):
        exc, events = self.call(3.0, 0.3)
        self.assertFalse(exc.sent)
        self.assertEqual(events, [])

    def test_connect_in_time_then_hang_is_still_sent(self):
        exc, events = self.call(0.0, 0.6, hang_after_connect=True)
        self.assertTrue(exc.sent)
        self.assertEqual(events, ["putrequest", "endheaders"])

    def test_fast_exchange_is_unaffected(self):
        exc, events = self.call(0.0, 5.0)
        self.assertNotIsInstance(exc, TransportTimeout)    # connection error from the fake, not a timeout
        self.assertEqual(events, ["putrequest", "endheaders"])

    def test_through_the_provider_the_ledger_never_releases_a_request_that_leaves(self):
        p = self.provider(HttpsTransport())
        r = req()
        r["params"] = {**r["params"], "timeoutSec": 1}
        conn = conn_class(connect_delay=2.5)
        with mock.patch.object(OR.http.client, "HTTPSConnection", conn):
            res = p.call(r, KEY)
            time.sleep(3.0)
        self.assertEqual(res.outcome, "not-sent")
        self.assertEqual(conn.events, [])                  # released only because nothing left
        self.assertEqual(self.ledger.totals()["committedUsdMicros"], 0)


class F11(RT):
    ZERO = {"prompt_tokens": 0, "completion_tokens": 0, "cost": 0,
            "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}

    def test_processed_call_with_zero_usage_and_zero_cost_is_worst_case_not_free(self):
        p = self.provider(FakeTransport(completion(usage=self.ZERO)))
        self.assertEqual(p.call(req(), KEY).outcome, "processed")
        t = self.ledger.totals()
        self.assertGreater(t["committedUsdMicros"], 0)
        self.assertGreater(t["estimatedUsdMicros"], 0)
        self.assertEqual(t["knownUsdMicros"], 0)

    def test_accountable_cost_matrix(self):
        w = 20_000
        cases = [   # facts, expected
            ({"routerCostUsdMicros": 0, "tokenPricedUsdMicros": 0}, (w, "zero-unverifiable-worst-case")),
            ({"routerCostUsdMicros": 0, "upstreamInferenceCostUsdMicros": 0, "isByok": True, "tokenPricedUsdMicros": 0},
             (w, "zero-unverifiable-worst-case")),
            ({"routerCostUsdMicros": 0, "isByok": True, "tokenPricedUsdMicros": 0}, (w, "unknown-worst-case")),
            ({"routerCostUsdMicros": 5, "tokenPricedUsdMicros": 0}, (5, "router-only")),            # a real charge stays
            ({"routerCostUsdMicros": 0, "upstreamInferenceCostUsdMicros": 2814, "isByok": True,
              "tokenPricedUsdMicros": 2814}, (2814, "byok-additive")),                              # earlier fixes intact
            ({"routerCostUsdMicros": 0, "tokenPricedUsdMicros": None}, (w, "zero-unverifiable-worst-case")),
        ]
        for facts, want in cases:
            self.assertEqual(accountable_cost(facts, w), want, facts)


if __name__ == "__main__":
    unittest.main()
