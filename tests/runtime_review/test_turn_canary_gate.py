"""Independent S1-06a-canary gate review: one-call host launcher, state reuse, charging, output, stop gates.
Fake auth/book/ledger/transport/key only. Reuses the author's fixture builders by subclassing; the inherited 25 author tests
re-run here on purpose (focused author25 + the independent cases below)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.runtime import RuntimeLedger, turn_canary as tc
from reviewer.runtime.openrouter import CHAT_PATH, HttpResponse, TransportTimeout
from tests.runtime.common import FAKE_KEY, SONNET, FakeTransport, completion
from tests.runtime.test_turn_canary import (BASELINE, ENTRY_REQ, FINAL_VERIFY, USAGE, TurnCanary as Author, keyinfo)

HANDOFF = {"investigator-request": ("675bf97a5e72f9ce9d2f4d188042b755fa469ce9c4c8da9d0d12b8a16bafaf38", 3900, 26792),
           "verifier-final": ("5143f607a5c31c670303b640eee9e8b0cfc903d911fc04f0d42658086a28bb26", 3219, 24068)}
BODY_KEYS = {"model", "messages", "max_tokens", "stream", "provider", "response_format"}


def posts(tr):
    return [r for r in tr.requests if r.path == CHAT_PATH]


class Gate(Author):
    def read_state(self):
        return {n: (self.state / n).read_bytes() for n in (tc.BOOK_NAME, tc.LEDGER_NAME)}

    def assert_append_only(self, before):
        for n, old in before.items():
            self.assertTrue((self.state / n).read_bytes().startswith(old), f"{n} was rewritten/reset")

    # ---------------------------------------------------------------- exact request body
    def test_dry_plan_matches_handoff_numbers_for_both_cases(self):
        for case, (sha, size, worst) in HANDOFF.items():
            rc, rep, _ = self.launch(case, live=False)
            self.assertEqual((rc, rep["plan"]["bodySha256"], rep["plan"]["requestBytes"],
                              rep["plan"]["worstCaseRouterUsdMicros"]), (0, sha, size, worst), case)

    def test_sent_body_is_exactly_the_sonnet_capped_strict_schema_body(self):
        for case, schema in (("investigator-request", "InvestigatorTurn"), ("verifier-final", "VerifierTurn")):
            self.seed(committed=BASELINE)
            tr = self.live_ok(ENTRY_REQ if case == "investigator-request" else FINAL_VERIFY)
            rc, rep, _ = self.launch(case, transport=tr)
            self.assertEqual(rc, 0, rep.get("error"))
            body = json.loads(posts(tr)[0].body)
            self.assertEqual(set(body), BODY_KEYS)                       # no tools/tool_choice/plugins/models/temperature
            self.assertEqual((body["model"], body["max_tokens"], body["stream"]), (SONNET, 300, False))
            self.assertEqual(body["provider"], {"order": ["anthropic"], "only": ["anthropic"], "allow_fallbacks": False,
                                                "require_parameters": True})
            rf = body["response_format"]
            self.assertEqual((rf["type"], rf["json_schema"]["name"], rf["json_schema"]["strict"]), ("json_schema", schema, True))
            self.assertEqual(tc._schema_sha(rf["json_schema"]["schema"]), tc.EXPECTED_SCHEMA_SHA256[schema])
            self.assertEqual([m["role"] for m in body["messages"]], ["system", "user"])
            self.assertEqual(hashlib.sha256(posts(tr)[0].body).hexdigest(), HANDOFF[case][0])
            self.assertEqual(posts(tr)[0].headers.get("Authorization"), f"Bearer {FAKE_KEY}")
            self.state_reset()

    def test_investigator_schema_wire_form_is_args_entries_and_closed(self):
        self.seed()
        tr = self.live_ok(ENTRY_REQ)
        self.launch(transport=tr)
        schema = json.loads(posts(tr)[0].body)["response_format"]["json_schema"]["schema"]
        text = json.dumps(schema)
        self.assertIn('"key"', text)
        self.assertIn('"value"', text)
        self.assertNotIn('"patternProperties"', text)
        self.assertNotIn('"additionalProperties": true', text)

    # ---------------------------------------------------------------- one POST, no retry/repair/second case
    def test_single_post_for_every_failure_class(self):
        cases = {
            "http429": HttpResponse(429, {"retry-after": "1"}, b'{"error":{"message":"slow down"}}'),
            "http500": HttpResponse(500, {}, b'{"error":{"message":"boom"}}'),
            "http503": HttpResponse(503, {}, b"UPSTREAMBODY"),
            "garbage200": b"not json at all",
            "emptyChoices": json.dumps({"id": "g", "model": SONNET, "choices": [], "usage": USAGE}).encode(),
            "truncated": completion(json.dumps(ENTRY_REQ)[:40], finish="length", usage=USAGE),
            "timeout": TransportTimeout(True),
        }
        for name, resp in cases.items():
            with self.subTest(name):
                self.state_reset()
                self.seed()
                before = self.read_state()
                tr = FakeTransport(keyinfo(50), resp, keyinfo(50))
                rc, rep, text = self.launch(transport=tr)
                self.assertEqual((rc, rep["stop"], rep["exit"]), (1, True, 1))
                self.assertNotEqual(rep["verdict"], "pass")
                self.assertEqual(len(posts(tr)), 1)
                self.assertEqual(rep["http"]["chatPosts"], 1)
                self.assertEqual(len([r for r in rep["receipts"] if r["type"] == "intent"]), 1)
                self.assertEqual(rep["gateway"]["liveCalls"], 1)
                self.assertNotIn("slow down", text)
                self.assertNotIn("boom", text)
                self.assertNotIn("UPSTREAMBODY", text)
                self.assert_append_only(before)

    def state_reset(self):
        import shutil
        shutil.rmtree(self.state, ignore_errors=True)
        shutil.rmtree(self.out, ignore_errors=True)
        self.loads.clear()

    def test_no_repair_for_invalid_output_even_with_repair_callback_absent(self):
        # a charged schema-invalid answer: exactly one POST, charged once, no second intent in the scope
        self.seed()
        tr = self.live_ok({"contextRequests": [], "output": None})   # legal Turn shape? both empty -> invalid for the contract
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual(len(posts(tr)), 1)
        self.assertEqual(sum(1 for r in rep["receipts"] if r["type"] == "intent"), 1)
        self.assertEqual(rc, 1)

    # ---------------------------------------------------------------- dry run
    def test_dry_run_never_calls_open_state_key_loader_env_or_real_transport(self):
        self.seed()
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.state.iterdir()}
        auth_before = self.auth.read_bytes()
        with mock.patch.object(tc, "open_state", side_effect=AssertionError("dry opened state")), \
                mock.patch.object(tc, "HttpsTransport", side_effect=AssertionError("dry built a real transport")), \
                mock.patch.object(tc, "make_run_dir", side_effect=AssertionError("dry made an out dir")), \
                mock.patch.object(tc, "load_openrouter_key", side_effect=AssertionError("dry parsed a key")):
            for case in tc.CASES:
                rc, rep, text = self.launch(case, live=False, loader=mock.Mock(side_effect=AssertionError("key")))
                self.assertEqual((rc, rep["verdict"], rep["keyRead"], rep["networkCalls"]), (0, "dry-run", False, 0))
                self.assertNotIn(FAKE_KEY, text)
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.state.iterdir()})
        self.assertEqual(auth_before, self.auth.read_bytes())
        self.assertEqual(self.loads, [])

    # ---------------------------------------------------------------- state reuse: no creation, reset, or silent mismatch
    def test_live_never_resets_or_rewrites_state_on_success_or_failure(self):
        self.seed()
        b0 = self.read_state()
        rc, rep, _ = self.launch(transport=self.live_ok(ENTRY_REQ))
        self.assertEqual(rc, 0)
        self.assert_append_only(b0)
        self.assertEqual(rep["ledger"]["before"]["committedUsdMicros"], BASELINE)
        self.assertEqual(rep["ledger"]["after"]["committedUsdMicros"], BASELINE + 3000)
        self.assertEqual(rep["book"]["after"]["committed"], BASELINE + 3000)
        b1 = self.read_state()
        rc, rep2, _ = self.launch("verifier-final", baseline=BASELINE + 3000,
                                  transport=FakeTransport(keyinfo(50), HttpResponse(500, {}, b"x"), keyinfo(50)))
        self.assertEqual(rc, 1)
        self.assert_append_only(b1)

    def test_symlinked_state_pieces_are_refused(self):
        self.seed()
        real = self.state.parent / "real-state"
        self.state.rename(real)
        self.state.symlink_to(real)
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assertEqual((rc, rep["verdict"]), (2, "refused"))
        self.state.unlink()
        real.rename(self.state)
        led = self.state / tc.LEDGER_NAME
        alt = self.state / "alt.jsonl"
        led.rename(alt)
        led.symlink_to(alt)
        rc, rep, _ = self.launch(transport=FakeTransport())
        self.assertEqual((rc, rep["verdict"], self.loads), (2, "refused", []))
        self.assertIn("not a regular file", rep["error"])

    def test_explicit_book_baseline_is_exact_not_a_tolerance(self):
        self.seed(book_committed=BASELINE - 5)
        before = self.read_state()
        for wrong in (BASELINE - 4, BASELINE - 6, BASELINE, 0):
            rc, rep, _ = self.launch("investigator-request", "--book-baseline-micros", str(wrong),
                                     transport=FakeTransport())
            self.assertEqual((rc, rep["verdict"]), (2, "refused"), wrong)
        self.assertEqual((self.loads, self.read_state()), ([], before))
        rc, rep, _ = self.launch("investigator-request", "--book-baseline-micros", str(BASELINE - 5),
                                 transport=self.live_ok(ENTRY_REQ))
        self.assertEqual(rep["http"]["chatPosts"], 1)
        # the override is reported honestly: book before/after are the real figures, not the stated ones
        self.assertEqual(rep["book"]["before"]["committed"], BASELINE - 5)
        self.assertEqual(rep["ledger"]["before"]["committedUsdMicros"], BASELINE)

    def test_book_ledger_divergence_after_call_stops_and_next_call_needs_explicit_override(self):
        self.seed()
        # processed BYOK cost differs from token-price arithmetic: ledger and book settle different amounts
        usage = dict(USAGE, cost=0.006)
        tr = FakeTransport(keyinfo(50), completion(json.dumps(ENTRY_REQ), usage=usage), keyinfo(49.994))
        rc, rep, _ = self.launch(transport=tr)
        l, b = rep["ledger"]["delta"]["committedUsdMicros"], rep["book"]["delta"]["committed"]
        if l == b:
            self.skipTest("this adapter settles book and ledger identically here")
        self.assertEqual((rc, rep["verdict"], rep["stop"]), (1, "accounting-gap", True))
        self.assertTrue(any("spend book delta" in g for g in rep["accounting"]["gaps"]))
        new_l = rep["ledger"]["after"]["committedUsdMicros"]
        rc, rep2, _ = self.launch("verifier-final", baseline=new_l, transport=FakeTransport())
        self.assertEqual((rc, rep2["verdict"]), (2, "refused"))
        self.assertIn("book/ledger mismatch", rep2["error"])
        rc, rep3, _ = self.launch("verifier-final", "--book-baseline-micros", str(rep["book"]["after"]["committed"]),
                                  baseline=new_l, transport=self.live_ok(FINAL_VERIFY))
        self.assertEqual(rep3["http"]["chatPosts"], 1)

    def test_ledger_open_intent_with_matching_baseline_is_not_silently_blessed(self):
        """A crashed prior call leaves a ledger intent with no result (counted at worst case). If root states a baseline
        that already includes it and the book shows no reservation, does the launcher still proceed? Records the behavior."""
        self.seed()
        led = RuntimeLedger(self.state / tc.LEDGER_NAME, 50_000_000)
        led.admit("tc-dead|INVESTIGATE|investigator|generalist|0|0", 26_792, model=SONNET)
        new_base = led.totals()["committedUsdMicros"]
        self.assertEqual(new_base, BASELINE + 26_792)
        rc, rep, _ = self.launch("investigator-request", "--book-baseline-micros", str(BASELINE),
                                 baseline=new_base, transport=self.live_ok(ENTRY_REQ))
        self.last_open_intent_result = (rc, rep["verdict"], rep.get("error"))
        # whichever way it goes the unknown bound must never be released/reset by this launcher
        self.assertGreaterEqual(RuntimeLedger(self.state / tc.LEDGER_NAME, 50_000_000).totals()["unknownBoundUsdMicros"], 26_792)

    def test_unknown_outcome_blocks_the_next_case_until_book_and_ledger_are_restated(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), TransportTimeout(True), keyinfo(50))
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual((rc, rep["outcome"]), (1, "unknown"))
        l_after = rep["ledger"]["after"]["committedUsdMicros"]
        # the ledger's unknown bound moved the baseline; the default (equal) book baseline must not match the book
        rc, rep2, _ = self.launch("verifier-final", baseline=l_after, transport=FakeTransport())
        self.assertEqual((rc, rep2["verdict"]), (2, "refused"))

    def test_runtime_cap_refusal_sends_nothing_and_charges_nothing(self):
        self.seed(committed=49_990_000)
        before = self.read_state()
        tr = self.live_ok(ENTRY_REQ)
        rc, rep, _ = self.launch(transport=tr, baseline=49_990_000)
        self.assertEqual(posts(tr), [])
        self.assertEqual(rc, 1)
        self.assertEqual(rep["ledger"]["delta"]["committedUsdMicros"], 0)
        self.assertNotEqual(rep["verdict"], "pass")
        self.assert_append_only(before)

    # ---------------------------------------------------------------- charging / accounting stop gates
    def test_processed_without_generation_id_is_an_accounting_gap(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), completion(json.dumps(ENTRY_REQ), usage=USAGE, gen=""), keyinfo(49.997))
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual(rc, 1)
        self.assertNotEqual(rep["verdict"], "pass")

    def test_missing_cost_in_usage_cannot_pass(self):
        self.seed()
        usage = {k: v for k, v in USAGE.items() if k != "cost"}
        tr = FakeTransport(keyinfo(50), completion(json.dumps(ENTRY_REQ), usage=usage), keyinfo(49.997))
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual((rc, rep["stop"]), (1, True))
        self.assertNotEqual(rep["verdict"], "pass")

    def test_key_metadata_lag_is_a_stop_not_a_pass_and_reports_both_snapshots(self):
        self.seed()
        tr = self.live_ok(ENTRY_REQ, after="50")
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual((rc, rep["verdict"], rep["stop"]), (1, "accounting-gap", True))
        self.assertEqual((rep["keyBefore"]["limit_remaining"], rep["keyAfter"]["limit_remaining"]), ("50", "50"))
        self.assertEqual(rep["envelope"]["contextRequests"][0]["tool"], "read_file")   # output still reported
        self.assertEqual(rep["ledger"]["delta"]["committedUsdMicros"], 3000)          # charge preserved, not zeroed
        self.assertEqual(len(posts(tr)), 1)

    def test_wrong_resolved_model_is_not_a_pass(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), completion(json.dumps(ENTRY_REQ), model="anthropic/claude-opus-5.5", usage=USAGE),
                           keyinfo(49.997))
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual((rc, rep["stop"]), (1, True))
        self.assertNotEqual(rep["verdict"], "pass")
        self.assertEqual(len(posts(tr)), 1)

    def test_charge_preserved_when_response_rejected_after_processing(self):
        self.seed()
        tr = self.live_ok({"contextRequests": [{"tool": "read_file", "purpose": "p", "args": []}], "output": {"hypotheses": []}})
        rc, rep, _ = self.launch(transport=tr)
        self.assertEqual(rep["verdict"], "invalid-output")
        self.assertEqual(rep["ledger"]["delta"]["committedUsdMicros"], 3000)
        self.assertEqual(rep["book"]["delta"]["committed"], 3000)

    # ---------------------------------------------------------------- output hygiene
    def test_secret_echoed_by_model_never_reaches_report_stdout_or_trace(self):
        self.seed()
        leaked = {"contextRequests": [{"tool": "read_file", "purpose": f"leak {FAKE_KEY}", "args": [
            {"key": "path", "value": "src/store.h"}, {"key": "side", "value": "head"},
            {"key": "start_line", "value": 1}, {"key": "end_line", "value": 40}]}], "output": None}
        rc, rep, text = self.launch(transport=self.live_ok(leaked))
        self.assertNotIn(FAKE_KEY, text)
        run_dir = Path(rep["trace"]["path"]).parent
        for p in run_dir.iterdir():
            self.assertNotIn(FAKE_KEY, p.read_text(), p.name)
        self.assert_no_secret(text)

    def test_error_body_with_key_never_reaches_output(self):
        self.seed()
        tr = FakeTransport(keyinfo(50), HttpResponse(401, {}, ('{"error":{"message":"bad key %s"}}' % FAKE_KEY).encode()),
                           keyinfo(50))
        rc, rep, text = self.launch(transport=tr)
        self.assertEqual(rc, 1)
        self.assert_no_secret(text)
        self.assertNotIn("bad key", text)

    def test_fresh_distinct_output_dirs_and_trace_per_invocation(self):
        self.seed()
        _, r1, _ = self.launch(transport=self.live_ok(ENTRY_REQ))
        _, r2, _ = self.launch("verifier-final", baseline=r1["ledger"]["after"]["committedUsdMicros"],
                               transport=self.live_ok(FINAL_VERIFY))
        d1, d2 = Path(r1["trace"]["path"]).parent, Path(r2["trace"]["path"]).parent
        self.assertNotEqual(d1, d2)
        self.assertEqual(sorted(p.name for p in d1.iterdir()), ["report.json", "trace.jsonl"])
        self.assertEqual(oct(d1.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct((d1 / "trace.jsonl").stat().st_mode & 0o777), "0o600")
        self.assertNotEqual((r1["scope"], r1["runId"], r1["evalRunId"]), (r2["scope"], r2["runId"], r2["evalRunId"]))

    def test_out_dir_symlink_into_product_code_is_refused(self):
        self.seed()
        self.out.parent.mkdir(exist_ok=True)
        link = self.out.parent / "lnk"
        link.symlink_to(tc.REPO / "reviewer")
        before = self.read_state()
        out = io.StringIO()
        rc = tc.main(["--case", "verifier-final", "--auth", str(self.auth), "--state-dir", str(self.state), "--env",
                      str(self.env), "--out-dir", str(link), "--baseline-micros", str(BASELINE), "--live"],
                     transport=FakeTransport(), key_loader=self.loader, out=out)
        self.assertEqual((rc, json.loads(out.getvalue())["verdict"]), (2, "refused"))
        self.assertEqual((self.loads, self.read_state()), ([], before))
        self.assertFalse(any(p.name.startswith("turn-canary-") for p in (tc.REPO / "reviewer").iterdir()))

    def test_out_dir_containing_env_or_state_is_refused(self):
        self.seed()
        for outdir, env in ((self.state.parent, self.env), (self.state, self.env)):
            out = io.StringIO()
            rc = tc.main(["--case", "verifier-final", "--auth", str(self.auth), "--state-dir", str(self.state), "--env",
                          str(env), "--out-dir", str(outdir), "--baseline-micros", str(BASELINE), "--live"],
                         transport=FakeTransport(), key_loader=self.loader, out=out)
            self.assertEqual(rc, 2, outdir)
            self.assertEqual(self.loads, [])


if __name__ == "__main__":
    unittest.main()
