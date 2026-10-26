"""S1-06a-canary: bounded Turn-schema canary launcher. Fake auth/book/ledger/transport only: no real key, state or network."""

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import validate
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.runtime import RuntimeLedger, turn_canary as tc
from reviewer.runtime.envfile import EnvFileError, Secret
from reviewer.runtime.openrouter import CHAT_PATH, KEY_PATH, HttpRequest, HttpResponse, TransportError, TransportTimeout
from tests.runtime.common import FAKE_KEY, SONNET, FakeTransport, completion
from tests.gateway import helpers as H

BASELINE = 70_576
ENTRY_REQ = {"contextRequests": [{"tool": "read_file", "purpose": "canary: read the header", "args": [
    {"key": "path", "value": "src/store.h"}, {"key": "side", "value": "head"},
    {"key": "start_line", "value": 1}, {"key": "end_line", "value": 40}]}], "output": None}
FINAL_VERIFY = {"contextRequests": [], "output": {"verdict": "uncertain", "reachable": False, "impact": "none",
                                                  "evidence": [], "notes": "synthetic canary: no evidence available"}}
# router cost == catalog token price (Sonnet: 1000 in x $2 + 100 out x $10 = 3000 micros), so book and ledger agree
USAGE = {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100, "cost": 0.003,
         "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "completion_tokens_details": {"reasoning_tokens": 0}}


def keyinfo(remaining):
    return json.dumps({"data": {"limit": 50, "usage": 0, "limit_remaining": remaining}}).encode()


class TurnCanary(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        d = Path(os.path.realpath(self._t.name))
        self.state, self.out, self.env = d / "state", d / "out", d / "fake.env"
        self.auth = d / "auth.json"
        self.auth.write_text(json.dumps({**H.AUTH_DOC, "id": "or-trial", "providers": ["anthropic"], "models": [SONNET],
                                         "maxUsdMicrosPerRun": 4_000_000, "maxUsdMicrosTotal": 50_000_000,
                                         "purpose": "t"}))
        os.chmod(self.auth, 0o600)
        self.loads = []

    # ------------------------------------------------------------ fixtures
    def seed(self, *, committed=BASELINE, book_committed=None, inflight=0, auth=None):
        """Durable state as a prior BYOK call left it: one ledger call and one settled book reservation."""
        self.state.mkdir(exist_ok=True)
        h = trusted_authorization(auth or self.auth)
        led = RuntimeLedger(self.state / tc.LEDGER_NAME, 50_000_000)
        led.admit("prior|INVESTIGATE|investigator|generalist|0|0", 100_000, model=SONNET)
        led.finish("prior|INVESTIGATE|investigator|generalist|0|0", outcome="processed", generationId="gen-prior",
                   routerCostUsdMicros=0, upstreamInferenceCostUsdMicros=committed, isByok=True,
                   tokenPricedUsdMicros=committed, costBasis="router-reported")
        book = SpendBook(h, self.state / tc.BOOK_NAME)
        book.reserve("prior", 100_000)
        book.settle("prior", committed if book_committed is None else book_committed)
        if inflight:
            book.reserve("open", inflight)

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()} if self.state.exists() else None

    def loader(self, *a, **k):
        self.loads.append(a)
        return Secret(FAKE_KEY)

    def launch(self, case="investigator-request", *extra, transport=None, live=True, baseline=BASELINE, loader=None):
        args = ["--case", case, "--auth", str(self.auth), "--state-dir", str(self.state)]
        if live:
            args += ["--env", str(self.env), "--out-dir", str(self.out), "--live"]
            if baseline is not None:
                args += ["--baseline-micros", str(baseline)]
        out = io.StringIO()
        rc = tc.main(args + list(extra), transport=transport, key_loader=loader or self.loader, out=out)
        return rc, json.loads(out.getvalue()), out.getvalue()

    def live_ok(self, content, case="investigator-request", after="49.997"):
        return FakeTransport(keyinfo(50), completion(json.dumps(content), usage=USAGE), keyinfo(after))

    def assert_no_secret(self, *texts):
        for t in texts:
            self.assertNotIn(FAKE_KEY, t)
        for root in (self.state, self.out):
            if root.exists():
                for p in root.rglob("*"):
                    if p.is_file():
                        self.assertNotIn(FAKE_KEY, p.read_text())

    # ------------------------------------------------------------ requests and plan
    def test_requests_are_legal_contracts_at_6_hop0_with_correct_subject(self):
        prof = tc.turn_profile()
        self.assertEqual(validate("ModelProfile", prof), [])
        inv, ver = tc.case_request("investigator-request", prof), tc.case_request("verifier-final", prof)
        for r, schema in ((inv, "InvestigatorTurn"), (ver, "VerifierTurn")):
            self.assertEqual(validate("ModelRequest", r), [])
            self.assertEqual((r["outputSchema"], r["hop"], r["contextResults"], r["tools"]), (schema, 0, [], []))
            self.assertNotIn("continuationOf", r)
        self.assertNotIn("hypothesisId", inv)
        self.assertEqual(ver["hypothesisId"], tc.HYPOTHESIS)
        for role in ("investigator", "verifier"):
            self.assertEqual(prof["roles"][role]["caps"], {"maxOutputTokens": 300, "timeoutSec": 60, "maxRetries": 0,
                                                           "maxRepairs": 0})
            self.assertEqual(prof["roles"][role]["model"], SONNET)
        # S1-DECISIONS 11: logical argument names, no hardcoded object/list representation
        user = inv["messages"][1]["content"]
        for name in ("path", "start_line", "end_line", "side", "read_file", "response schema"):
            self.assertIn(name, user)
        for bad in ("{", "[", "key/value", '"key"'):
            self.assertNotIn(bad, user)

    def test_plan_pins_schema_and_bounds_admission(self):
        h = trusted_authorization(self.auth)
        for case, name in (("investigator-request", "InvestigatorTurn"), ("verifier-final", "VerifierTurn")):
            p = tc.plan(case, h)
            self.assertEqual((p["schemaName"], p["schemaSha256"]), (name, tc.EXPECTED_SCHEMA_SHA256[name]))
            self.assertEqual((p["maxTokens"], p["projectionVersion"]), (300, "role-schema-projection@2"))
            self.assertLessEqual(p["worstCaseRouterUsdMicros"], 100_000)
            self.assertGreater(p["requestBytes"], p["schemaBytes"])

    def test_plan_refuses_schema_drift_before_any_key(self):
        self.seed()
        before = self.snapshot()
        with mock.patch.dict(tc.EXPECTED_SCHEMA_SHA256, {"InvestigatorTurn": "0" * 64}):
            rc, rep, _ = self.launch(transport=FakeTransport())
        self.assertEqual((rc, rep["verdict"]), (2, "refused"))
        self.assertIn("reviewed pin", rep["error"])
        self.assertEqual((self.loads, self.snapshot()), ([], before))

    def test_plan_refuses_worst_case_over_run_ceiling(self):
        with mock.patch.object(tc, "CANARY_BUDGET_MICROS", 1000):
            rc, rep, _ = self.launch(live=False)
        self.assertEqual((rc, rep["verdict"]), (2, "refused"))
        self.assertIn("per-run ceiling", rep["error"])

    # ------------------------------------------------------------ dry run
    def test_dry_run_reads_no_key_touches_no_state_and_sends_nothing(self):
        def boom(*a, **k):
            raise AssertionError("dry run must not load a key")
        with mock.patch.object(tc, "HttpsTransport", side_effect=AssertionError("no real transport")):
            rc, rep, text = self.launch(live=False, loader=boom)
        self.assertEqual((rc, rep["verdict"], rep["live"], rep["keyRead"], rep["stateDirOpened"]),
                         (0, "dry-run", False, False, False))
        self.assertFalse(self.state.exists())            # --state-dir is never opened, let alone created
        self.assertFalse(self.out.exists())
        self.assertEqual(rep["http"]["chatPosts"], 1)    # the recording fake, not a network send
        self.assertEqual(rep["dryTransportBodies"][0]["sha256"], rep["plan"]["bodySha256"])
        self.assertEqual(rep["dryTransportBodies"][0]["bytes"], rep["plan"]["requestBytes"])
        self.assertIsNone(rep["trace"]["path"])
        self.assertNotIn(FAKE_KEY, text)

    def test_dry_run_with_live_flags_still_touches_nothing(self):
        self.seed()
        before = self.snapshot()
        rc, rep, _ = self.launch("verifier-final", "--env", str(self.env), "--out-dir", str(self.out), live=False)
        self.assertEqual((rc, rep["verdict"]), (0, "dry-run"))
        self.assertEqual((self.loads, self.snapshot()), ([], before))
        self.assertFalse(self.out.exists())

    def test_request_bytes_carry_no_host_identity_and_are_stable(self):
        _, a, _ = self.launch(live=False)
        _, b, _ = self.launch(live=False)
        self.assertNotEqual((a["runId"], a["scope"], a["evalRunId"]), (b["runId"], b["scope"], b["evalRunId"]))
        self.assertEqual(a["plan"]["bodySha256"], b["plan"]["bodySha256"])
        # the live body is the planned body (OneShotTransport enforces it) and carries none of the live identities
        self.seed()
        tr = self.live_ok(ENTRY_REQ)
        rc, live, _ = self.launch(transport=tr)
        sent = [r.body.decode() for r in tr.requests if r.path == CHAT_PATH]
        self.assertEqual((rc, len(sent), live["http"]["sentBodySha256"]), (0, 1, a["plan"]["bodySha256"]))
        for ident in (live["runId"], live["scope"], live["evalRunId"], live["evalRunId"][4:], str(self.out),
                      str(self.state), live["trace"]["path"]):
            self.assertNotIn(ident, sent[0])

    # ------------------------------------------------------------ live refusals (no key, no append)
    def assert_refused(self, rc, rep, before, fragment):
        self.assertEqual((rc, rep["verdict"], rep["stop"]), (2, "refused", True))
        self.assertIn(fragment, rep["error"])
        self.assertEqual(self.loads, [])
        self.assertEqual(self.snapshot(), before)

    def test_live_refuses_missing_state_dir(self):
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assert_refused(rc, rep, None, "existing directory")

    def test_live_refuses_missing_or_empty_files(self):
        self.state.mkdir()
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assert_refused(rc, rep, self.snapshot(), "lacks the existing spend-book")
        (self.state / tc.BOOK_NAME).write_text("")
        (self.state / tc.LEDGER_NAME).write_text("")
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assert_refused(rc, rep, self.snapshot(), "is empty")

    def test_live_refuses_baseline_and_book_mismatch(self):
        self.seed()
        before = self.snapshot()
        rc, rep, _ = self.launch(transport=FakeTransport(), baseline=BASELINE + 1)
        self.assert_refused(rc, rep, before, "--baseline-micros")
        rc, rep, _ = self.launch(transport=FakeTransport(), baseline=0)
        self.assert_refused(rc, rep, before, "--baseline-micros")

    def test_live_refuses_book_ledger_mismatch_unless_stated(self):
        self.seed(book_committed=BASELINE - 5)
        before = self.snapshot()
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assert_refused(rc, rep, before, "book/ledger mismatch")
        rc, rep, _ = self.launch("investigator-request", "--book-baseline-micros", str(BASELINE - 5),
                                 transport=self.live_ok(ENTRY_REQ))
        self.assertEqual(rep["http"]["chatPosts"], 1)      # an explicitly stated divergence is accepted

    def test_live_refuses_open_reservation(self):
        self.seed(inflight=500)
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assert_refused(rc, rep, self.snapshot(), "in flight")

    def test_live_refuses_book_of_another_authorization(self):
        other = self.auth.parent / "other.json"
        other.write_text(json.dumps({**json.loads(self.auth.read_text()), "id": "other-trial"}))
        os.chmod(other, 0o600)
        self.seed(auth=other)
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assert_refused(rc, rep, self.snapshot(), "another authorization")

    def test_live_needs_explicit_flags(self):
        self.seed()
        with self.assertRaises(SystemExit) as cm, mock.patch("sys.stderr", io.StringIO()):
            self.launch(transport=FakeTransport(), baseline=None)
        self.assertEqual(cm.exception.code, 2)
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
            tc.main(["--auth", str(self.auth), "--state-dir", str(self.state)], out=io.StringIO())   # no --case
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
            tc.main(["--case", "both", "--auth", str(self.auth), "--state-dir", str(self.state)], out=io.StringIO())
        self.assertEqual(self.loads, [])

    def test_live_refuses_out_dir_inside_product_code(self):
        self.seed()
        before = self.snapshot()
        out = io.StringIO()
        rc = tc.main(["--case", "verifier-final", "--auth", str(self.auth), "--state-dir", str(self.state), "--env",
                      str(self.env), "--out-dir", str(tc.REPO / "reviewer" / "x"), "--baseline-micros", str(BASELINE),
                      "--live"], transport=FakeTransport(), key_loader=self.loader, out=out)
        self.assert_refused(rc, json.loads(out.getvalue()), before, "outside the repository")
        self.assertFalse((tc.REPO / "reviewer" / "x").exists())

    def test_key_loader_refusal_is_reported_without_content(self):
        self.seed()
        def bad(*a, **k):
            raise EnvFileError("env file must not be accessible to group/other (chmod 600)")
        tr = FakeTransport()
        rc, rep, _ = self.launch(transport=tr, loader=bad)
        self.assertEqual((rc, rep["verdict"], tr.requests), (2, "refused", []))

    # ------------------------------------------------------------ live success
    def test_live_investigator_request_pass(self):
        self.seed()
        tr = self.live_ok(ENTRY_REQ)
        rc, rep, text = self.launch(transport=tr)
        self.assertEqual((rc, rep["verdict"], rep["exit"], rep["stop"]), (0, "pass", 0, False))
        self.assertEqual([(r.method, r.path) for r in tr.requests], [("GET", KEY_PATH), ("POST", CHAT_PATH), ("GET", KEY_PATH)])
        self.assertEqual(rep["http"]["sentBodySha256"], rep["plan"]["bodySha256"])
        # complete normalized envelope, never unwrapped; raw provider JSON keeps the wire entry form
        self.assertEqual(rep["envelope"], {**ENTRY_REQ, "contextRequests": [{**ENTRY_REQ["contextRequests"][0],
                                                                              "args": tc.READ_ARGS}]})
        self.assertEqual(rep["wireArgsForm"], "entries")
        self.assertEqual(json.loads(rep["rawText"]["text"]), ENTRY_REQ)
        self.assertTrue(rep["expectation"]["met"] and rep["expectation"]["checks"]["argsAsAsked"])
        self.assertEqual((rep["schemaName"], rep["schemaSha256"]), ("InvestigatorTurn", tc.EXPECTED_SCHEMA_SHA256["InvestigatorTurn"]))
        res = [r for r in rep["receipts"] if r["type"] == "result"]
        self.assertEqual(len(res), 1)
        self.assertEqual((res[0]["outcome"], res[0]["generationId"], res[0]["schemaSha256"], res[0]["accountableUsdMicros"]),
                         ("processed", "gen-abc123", rep["schemaSha256"], 3000))
        self.assertTrue(res[0]["callKey"].startswith(rep["scope"] + "|INVESTIGATE|investigator|generalist|0|0"))
        self.assertEqual(rep["ledger"]["before"]["committedUsdMicros"], BASELINE)
        self.assertEqual((rep["ledger"]["delta"]["committedUsdMicros"], rep["book"]["delta"]["committed"]), (3000, 3000))
        self.assertEqual((rep["keyLimitRemainingDeltaUsd"], rep["accounting"]["gaps"]), ("0.003", []))
        self.assertEqual(rep["gateway"]["liveCalls"], 1)
        self.assertNotEqual(rep["scope"], rep["runId"])
        run_dir = Path(rep["trace"]["path"]).parent
        self.assertEqual(run_dir.parent, self.out)
        self.assertEqual(json.loads((run_dir / "report.json").read_text())["verdict"], "pass")
        events = [json.loads(x) for x in Path(rep["trace"]["path"]).read_text().splitlines()]
        self.assertEqual((events[0]["type"], events[-1]["type"], events[-1]["status"]), ("run.start", "run.end", "completed"))
        self.assertIn("not a trusted pin", rep["trace"]["trust"])
        self.assert_no_secret(text)

    def test_live_verifier_final_pass_and_next_invocation_uses_new_baseline(self):
        self.seed()
        rc, rep, _ = self.launch(transport=self.live_ok(ENTRY_REQ))
        self.assertEqual(rc, 0)
        nxt = rep["ledger"]["after"]["committedUsdMicros"]
        rc, rep2, text = self.launch(transport=self.live_ok(ENTRY_REQ), baseline=BASELINE)   # stale baseline: refused
        self.assertEqual((rc, rep2["verdict"]), (2, "refused"))
        rc, rep2, text = self.launch("verifier-final", transport=self.live_ok(FINAL_VERIFY), baseline=nxt)
        self.assertEqual((rc, rep2["verdict"]), (0, "pass"))
        self.assertEqual(rep2["envelope"], FINAL_VERIFY)
        self.assertEqual(rep2["wireArgsForm"], "none")
        self.assertNotEqual((rep["runId"], rep["scope"]), (rep2["runId"], rep2["scope"]))
        self.assertTrue(rep2["receipts"][0]["callKey"].startswith(rep2["scope"] + "|VERIFY|verifier|refute|0|0"))
        self.assertEqual(rep2["ledger"]["after"]["calls"], 3)
        self.assert_no_secret(text)

    # ------------------------------------------------------------ live bounded failures (exactly one POST, stop)
    def assert_stopped(self, rc, rep, tr, verdict):
        self.assertEqual((rc, rep["verdict"], rep["stop"]), (1, verdict, True))
        self.assertEqual(sum(1 for r in tr.requests if r.path == CHAT_PATH), 1)
        self.assertEqual(rep["gateway"]["liveCalls"], 1)

    def test_schema_rejection_stops_without_charge(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), HttpResponse(400, {}, b'{"error":{"message":"schema too complex"}}'), keyinfo(50))
        rc, rep, text = self.launch(transport=tr)
        self.assert_stopped(rc, rep, tr, "schema-rejected")
        self.assertEqual(rep["outcome"], "rejected-before-processing")
        self.assertEqual(rep["ledger"]["delta"]["committedUsdMicros"], 0)
        self.assertNotIn("schema too complex", text)                     # no error body dumps
        events = [json.loads(x) for x in Path(rep["trace"]["path"]).read_text().splitlines()]
        self.assertEqual(events[-1]["status"], "failed")

    def test_invalid_output_is_charged_evidence_and_not_repaired(self):
        self.seed()
        both = {**ENTRY_REQ, "output": {"hypotheses": []}}
        tr = self.live_ok(both)
        rc, rep, _ = self.launch(transport=tr)
        self.assert_stopped(rc, rep, tr, "invalid-output")
        self.assertEqual((rep["status"], rep["envelope"]), ("invalid-output", None))
        self.assertEqual(json.loads(rep["rawText"]["text"]), json.loads(json.dumps(both)))
        self.assertEqual(rep["ledger"]["delta"]["committedUsdMicros"], 3000)
        self.assertEqual([r["note"] for r in rep["receipts"] if r["type"] == "result"], ["invalid-output"])

    def test_valid_but_unexpected_envelope_stops(self):
        self.seed()
        final = {"contextRequests": [], "output": {"hypotheses": []}}
        tr = self.live_ok(final)
        rc, rep, _ = self.launch(transport=tr)
        self.assert_stopped(rc, rep, tr, "unexpected-envelope")
        self.assertEqual(rep["envelope"], final)
        self.assertFalse(rep["expectation"]["checks"]["oneRequest"])

    def test_accounting_gap_when_key_delta_disagrees(self):
        self.seed()
        tr = self.live_ok(ENTRY_REQ, after="50")
        rc, rep, _ = self.launch(transport=tr)
        self.assert_stopped(rc, rep, tr, "accounting-gap")
        self.assertTrue(any("limit_remaining" in g for g in rep["accounting"]["gaps"]))

    def test_unknown_outcome_keeps_worst_case_and_blocks_reuse_of_baseline(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), TransportTimeout(True), keyinfo(50))
        rc, rep, _ = self.launch(transport=tr)
        self.assert_stopped(rc, rep, tr, "provider-error")
        self.assertEqual(rep["outcome"], "unknown")
        worst = rep["plan"]["worstCaseRouterUsdMicros"]
        self.assertEqual(rep["ledger"]["delta"]["unknownBoundUsdMicros"], worst)
        self.assertTrue(any("unknown" in g for g in rep["accounting"]["gaps"]))
        rc, rep2, _ = self.launch(transport=FakeTransport(), baseline=BASELINE)
        self.assertEqual((rc, rep2["verdict"]), (2, "refused"))

    def test_interrupt_preserves_intent_reservation_and_trace(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), keyinfo(50))

        def interrupting(req):                     # Ctrl-C while the request is in flight
            if req.path == CHAT_PATH:
                raise KeyboardInterrupt
            return tr(req)
        rc, rep, _ = self.launch(transport=interrupting)
        self.assertEqual((rc, rep["verdict"], rep["interrupted"], rep["stop"]), (1, "interrupted", "KeyboardInterrupt", True))
        self.assertEqual(rep["ledger"]["delta"]["unknownBoundUsdMicros"], rep["plan"]["worstCaseRouterUsdMicros"])
        self.assertGreater(rep["book"]["after"]["inflight"], 0)                  # reservation stays open for root
        events = [json.loads(x) for x in Path(rep["trace"]["path"]).read_text().splitlines()]
        self.assertEqual((events[-1]["type"], events[-1]["status"]), ("run.end", "cancelled"))
        self.assertIsNone(rep["keyAfter"])
        rc, rep2, _ = self.launch(transport=FakeTransport(), baseline=rep["ledger"]["after"]["committedUsdMicros"])
        self.assertEqual((rc, rep2["verdict"]), (2, "refused"))
        self.assertIn("in flight", rep2["error"])

    # ------------------------------------------------------------ one-shot guard
    def test_one_shot_transport_allows_one_planned_post_and_two_key_gets(self):
        inner = FakeTransport()
        body = b'{"x":1}'
        import hashlib
        g = tc.OneShotTransport(inner, hashlib.sha256(body).hexdigest())
        mk = lambda m, p, b=None: HttpRequest(m, p, {}, b, 1.0, 10)
        with self.assertRaises(TransportError) as cm:
            g(mk("POST", CHAT_PATH, b'{"x":2}'))                 # not the planned body
        self.assertFalse(cm.exception.sent)
        g(mk("POST", CHAT_PATH, body))
        for req in (mk("POST", CHAT_PATH, body), mk("GET", "/api/v1/generation?id=g"), mk("POST", KEY_PATH, body)):
            with self.assertRaises(TransportError):
                g(req)
        g(mk("GET", KEY_PATH)), g(mk("GET", KEY_PATH))
        with self.assertRaises(TransportError):
            g(mk("GET", KEY_PATH))
        self.assertEqual((g.posts, g.gets, len(inner.requests)), (1, 2, 3))


if __name__ == "__main__":
    unittest.main()
