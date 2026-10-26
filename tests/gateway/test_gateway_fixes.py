"""S0-05 corrections GW1-GW10 (independent review handoff S0-05-review.md): offline, stdlib only."""

from __future__ import annotations

import copy
import unittest

from reviewer.contracts import ContractViolation, require
from reviewer.contracts.canonical import scoped_key
from reviewer.gateway import (Gateway, GatewayConfigError, ProviderResult, Recorder, SettlementError, SpendBook,
                              TraceError, bytes_digest, default_providers, events_to_bytes, load_trace)
from tests.gateway.helpers import (BUDGET, PROFILE, Env, entry, profile, request, response, run_doc,
                                   script, terr, verifier_out)

INV = ("INVESTIGATE", "investigator", "generalist")
RESERVE = 60_668        # reservation of request() under the smoke profile


def call(gw, ordinal=0, req=None, **kw):
    return gw.call(*INV, ordinal, req or request(), **kw)


class Fx(Env):
    def gw_for(self, handle, rd, rec, providers, **kw):
        return Gateway(mode="live", profile=kw.pop("prof", PROFILE), budget=kw.pop("budget", BUDGET), run_id=rd["id"],
                       providers=providers, authorization=handle, recorder=rec, clock=lambda: "2026-10-25T12:00:00Z",
                       cost_kind="eval", eval_run_id="evr_" + "1" * 16, eval_case_id="case-a", **kw)


class GW1ExplicitBook(Fx):
    def test_live_mode_refuses_to_build_its_own_book(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        for book in (None, object(), h):
            with self.subTest(book=type(book).__name__), self.assertRaises(GatewayConfigError):
                self.gw_for(h, rd, Recorder(rd["id"]), default_providers(script()), book=book)

    def test_one_shared_book_holds_the_total_across_runs(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        book = SpendBook(h)
        budget = {**BUDGET, "maxUsdMicros": 100_000}
        results = [call(self.live(script(entry(response=response())), handle=h, book=book, budget=budget)) for _ in range(3)]
        self.assertEqual([r.ok for r in results], [True, False, False])
        self.assertEqual(results[1].error["detail"]["scope"], "total")
        self.assertLessEqual(book.totals()["committed"], 100_000)

    def test_file_book_is_shared_by_separate_book_objects(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        store = self.tmp / "spend.jsonl"
        budget = {**BUDGET, "maxUsdMicros": 100_000}
        a = call(self.live(script(entry(response=response())), handle=h, book=SpendBook(h, store), budget=budget))
        b = call(self.live(script(entry(response=response())), handle=h, book=SpendBook(h, store), budget=budget))
        self.assertEqual((a.ok, b.ok), (True, False))


class GW2ErroredCharge(Fx):
    def record_timeout(self):
        gw = self.live(script(entry(error=terr("provider-timeout", retryable=False))))
        self.assertEqual(call(gw).attempts[0].charge_usd_micros, RESERVE)
        return self.finish(gw)

    def test_retained_error_with_a_zero_charge_does_not_load(self):
        ev = copy.deepcopy(self.record_timeout())
        next(e for e in ev if e["type"] == "cost")["record"]["usdMicros"] = 0
        with self.assertRaisesRegex(TraceError, "full reservation"):
            load_trace(ev)

    def test_release_stamp_edit_without_the_charge_does_not_load(self):
        ev = copy.deepcopy(self.record_timeout())
        next(e for e in ev if e["type"] == "model.call")["error"]["detail"] = {"providerOutcome": "not-sent"}
        with self.assertRaisesRegex(TraceError, "released call cannot carry a charge"):
            load_trace(ev)

    def test_consistent_edit_is_stopped_by_the_pin_and_by_recomputation(self):
        ev = copy.deepcopy(self.record_timeout())
        pinned = self.pins[ev[0]["runId"]]
        next(e for e in ev if e["type"] == "model.call")["error"]["detail"] = {"providerOutcome": "not-sent"}
        next(e for e in ev if e["type"] == "cost")["record"]["usdMicros"] = 0
        load_trace(ev)                                             # internally consistent: loads
        with self.assertRaises(TraceError):
            self.replayer(ev)                                      # but it is not the pinned recording
        self.assertNotEqual(pinned, bytes_digest(events_to_bytes(ev)))      # the edit changed the bytes

    def test_replay_recomputes_the_retained_charge_under_price_drift(self):
        ev = self.record_timeout()
        price = {**PROFILE["roles"]["investigator"]["price"], "outputPerMTokUsdMicros": 99_000_000}
        rp = self.replayer(ev, prof=profile(investigator={"price": price}))
        self.assertEqual(call(rp).error["code"], "replay-mismatch")
        rp = self.replayer(ev)
        r = call(rp)
        self.assertEqual((r.error["code"], r.attempts[0].charge_usd_micros), ("provider-timeout", RESERVE))
        self.assertEqual(rp.report()["retainedCalls"], [r.attempts[0].call_id])

    def test_released_error_replays_as_not_charged_and_not_retained(self):
        gw = self.live(script(entry(error=terr("provider-error", False, outcome="not-sent"))))
        call(gw)
        rp = self.replayer(self.finish(gw))
        r = call(rp)
        self.assertEqual((r.attempts[0].charge_usd_micros, rp.report()["retainedCalls"]), (0, []))

    def test_script_cannot_forge_the_provider_outcome_stamp(self):
        gw = self.live(script(entry(error=terr("provider-timeout", False, providerOutcome="not-sent"))))
        self.assertEqual(call(gw).attempts[0].charge_usd_micros, RESERVE)

    def test_wrong_model_charge_is_recomputed_from_its_recorded_usage(self):
        class WrongModel:
            name = "synthetic"

            def call(self, req, key):
                usage = {"uncachedInputTokens": 10, "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
                         "outputTokens": 5, "reasoningTokens": None}
                return ProviderResult(response(resolvedModel="gpt-elsewhere", usage=usage), None, "processed")
        gw = self.live(script())
        gw.providers["synthetic"] = WrongModel()
        r = call(gw)
        charge = r.attempts[0].charge_usd_micros
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertLess(0, charge)
        ev = self.finish(gw)
        rp = self.replayer(ev)
        self.assertEqual(call(rp).attempts[0].charge_usd_micros, charge)
        bad = copy.deepcopy(ev)
        next(e for e in bad if e["type"] == "cost")["record"]["usdMicros"] = charge + 1
        rp = self.replayer(bad, pin=bytes_digest(events_to_bytes(bad)))      # a caller who pinned the edit
        self.assertEqual(call(rp).error["code"], "replay-mismatch")


class GW3TracePin(Fx):
    def recorded(self):
        gw = self.live(script(entry(response=response(output={"hypotheses": []}))))
        call(gw)
        return self.finish(gw)

    def kw(self, ev):
        tr = load_trace(ev)
        rd, evr = __import__("tests.gateway.helpers", fromlist=["x"]).replay_run_doc(tr.run_id)
        rec = Recorder(rd["id"])
        rec.start(rd)
        return dict(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id=rd["id"], replay=tr, recorder=rec,
                    cost_kind="eval", eval_run_id=evr, eval_case_id="case-a")

    def test_strict_replay_requires_a_well_formed_pin(self):
        ev = self.recorded()
        for pin in (None, "", "sha256:abc", "sha256:" + "G" * 64, 5):
            with self.subTest(pin=pin), self.assertRaises(GatewayConfigError):
                Gateway(**self.kw(ev), expected_trace_digest=pin)

    def test_the_pin_must_equal_the_trace_bytes(self):
        ev = self.recorded()
        Gateway(**self.kw(ev), expected_trace_digest=self.pins[ev[0]["runId"]])
        with self.assertRaises(TraceError):
            Gateway(**self.kw(ev), expected_trace_digest="sha256:" + "0" * 64)

    def test_edited_response_is_rejected_against_the_original_pin(self):
        ev = self.recorded()
        pin = self.pins[ev[0]["runId"]]
        forged = copy.deepcopy(ev)
        next(e for e in forged if e["type"] == "model.call")["response"]["output"] = {"hypotheses": "FORGED"}
        with self.assertRaises(TraceError):
            Gateway(**self.kw(forged), expected_trace_digest=pin)

    def test_pin_is_over_the_exact_file_bytes(self):
        import json
        ev = self.recorded()
        pin = self.pins[ev[0]["runId"]]
        p = self.tmp / "t.jsonl"
        p.write_bytes(events_to_bytes(ev))
        self.assertEqual(load_trace(p).byte_digest, pin)
        self.assertEqual(load_trace(p.read_bytes()).byte_digest, load_trace(ev).byte_digest)
        p.write_text("".join(json.dumps(e) + "\n" for e in ev))          # same events, different bytes
        reformatted = load_trace(p)
        self.assertEqual(reformatted.events, load_trace(ev).events)
        with self.assertRaises(TraceError):
            Gateway(**{**self.kw(ev), "replay": reformatted}, expected_trace_digest=pin)

    def test_a_file_recorder_reports_the_digest_of_its_file(self):
        gw = self.live(script(entry(response=response())), trace=self.tmp / "rec.jsonl")
        call(gw)
        self.finish(gw)
        self.assertEqual(bytes_digest((self.tmp / "rec.jsonl").read_bytes()), gw.recorder.trace_digest())

    def test_other_modes_reject_a_pin(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        with self.assertRaises(GatewayConfigError):
            self.gw_for(h, rd, Recorder(rd["id"]), default_providers(script()), book=SpendBook(h),
                        expected_trace_digest="sha256:" + "0" * 64)


class GW4CallIdentityReuse(Fx):
    def test_reused_identity_is_refused_before_the_provider_and_keeps_the_trace_loadable(self):
        gw = self.live(script(entry(response=response())))
        self.assertTrue(call(gw).ok)
        again = call(gw, req=request(text="a different prompt"))
        self.assertEqual(again.error["code"], "contract-violation")
        self.assertEqual(gw.provider.calls, 1)
        self.assertEqual(gw.report()["spend"]["committed"], RESERVE)
        self.assertEqual(gw.recorder.events[-1]["type"], "error")
        self.assertEqual(load_trace(self.finish(gw)).model_calls, 1)

    def test_distinct_ordinals_and_retries_are_not_reuse(self):
        gw = self.live(script(entry(error=terr()), entry(attempt=1, response=response()),
                              entry(ordinal=1, response=response())))
        self.assertTrue(call(gw).ok)
        self.assertTrue(call(gw, 1, request(text="b")).ok)

    def test_refusals_before_a_call_id_is_used_do_not_burn_it(self):
        gw = self.live(script(entry(response=response())))
        self.assertEqual(call(gw, req=request(model="elsewhere")).error["code"], "contract-violation")
        self.assertTrue(call(gw).ok)


class GW5RunBinding(Fx):
    def test_run_start_recorded_after_construction_is_still_bound(self):
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = run_doc("live", auth_digest=other.digest)
        rec = Recorder(rd["id"])
        gw = self.gw_for(h, rd, rec, default_providers(script(entry(response=response()))), book=SpendBook(h))
        rec.start(rd)
        r = call(gw)
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(gw.providers["synthetic"].calls, 0)

    def test_a_started_recorder_is_checked_at_construction_too(self):
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = run_doc("live", auth_digest=other.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        with self.assertRaises(GatewayConfigError):
            self.gw_for(h, rd, rec, default_providers(script()), book=SpendBook(h))

    def test_recorder_of_another_run_is_refused(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        with self.assertRaises(GatewayConfigError):
            self.gw_for(h, rd, Recorder("run_" + "f" * 16), default_providers(script()), book=SpendBook(h))

    def test_supplied_recorder_without_run_start_admits_nothing(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        rec = Recorder(rd["id"])
        gw = self.gw_for(h, rd, rec, default_providers(script(entry(response=response()))), book=SpendBook(h))
        self.assertEqual(call(gw).error["code"], "contract-violation")
        self.assertEqual((gw.providers["synthetic"].calls, rec.events), (0, []))
        rec.start(rd)                                    # once the run is started, the same gateway proceeds
        self.assertTrue(call(gw).ok)

    def test_run_start_naming_another_mode_is_refused(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        rec = Recorder(rd["id"])
        gw = self.gw_for(h, rd, rec, default_providers(script(entry(response=response()))), book=SpendBook(h))
        rec.start({**rd, "mode": "fresh-repeat"})
        self.assertFalse(call(gw).ok)


class GW6SettlementFailure(Fx):
    def torn_provider(self, store):
        class Corrupting:
            name, calls = "synthetic", 0

            def call(self, req, key):
                self.calls += 1
                with open(store, "a") as f:
                    f.write("{torn")
                return ProviderResult(response(), None, "processed")
        return Corrupting()

    def test_processed_call_is_recorded_before_the_book_failure_is_raised(self):
        store = self.tmp / "spend.jsonl"
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        prov = self.torn_provider(store)
        gw = self.gw_for(h, rd, rec, {"synthetic": prov}, book=SpendBook(h, store))
        with self.assertRaises(SettlementError):
            call(gw)
        types = [e["type"] for e in rec.events]
        self.assertEqual(types, ["run.start", "model.call", "cost", "error"])
        self.assertEqual(rec.events[2]["record"]["usdMicros"], RESERVE)
        self.assertEqual(rec.events[3]["error"]["code"], "internal")
        self.assertEqual(gw._ledger.spend().committed, RESERVE)            # the run ledger charged it
        self.assertEqual(load_trace(rec.events, allow_partial=True).model_calls, 1)

    def test_book_failure_at_reservation_releases_the_run_reservation_and_skips_the_provider(self):
        store = self.tmp / "spend.jsonl"
        h = self.handle()
        book = SpendBook(h, store)
        book.reserve("seed", 1)
        store.write_text(store.read_text() + "{torn")
        gw = self.live(script(entry(response=response())), handle=h, book=book)
        with self.assertRaises(ValueError):
            call(gw)
        self.assertEqual(gw.provider.calls, 0)
        spend = gw._ledger.spend()
        self.assertEqual((spend.committed, spend.inflight), (0, 0))


class GW7TotalRefusalReplay(Fx):
    def refused_trace(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        book, budget = SpendBook(h), {**BUDGET, "maxUsdMicros": 100_000}
        call(self.live(script(entry(response=response())), handle=h, book=book, budget=budget))
        gw = self.live(script(entry(response=response())), handle=h, book=book, budget=budget)
        self.assertEqual(call(gw).error["detail"]["scope"], "total")
        return self.finish(gw), budget

    def test_recorded_total_refusal_reproduces_and_counts_as_replayed(self):
        ev, budget = self.refused_trace()
        rp = self.replayer(ev, budget=budget)
        r = call(rp)
        self.assertEqual((r.error["code"], r.error["detail"]["scope"]), ("budget-exhausted", "total"))
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["unconsumedRecordedCalls"], rep["spend"]["inflight"]), (1, 0, 0))

    def test_total_refusal_is_a_mismatch_when_the_run_ledger_now_refuses(self):
        ev, _ = self.refused_trace()
        tiny = {**BUDGET, "maxUsdMicros": 1_000}
        self.assertEqual(call(self.replayer(ev, budget=tiny)).error["code"], "replay-mismatch")


class GW8ReplayCounting(Fx):
    def test_mismatches_are_not_replayed_and_stay_unconsumed(self):
        gw = self.live(script(entry(response=response())))
        call(gw)
        drift = profile(investigator={"caps": {**PROFILE["roles"]["investigator"]["caps"], "maxOutputTokens": 3999}})
        rp = self.replayer(self.finish(gw), prof=drift)
        self.assertEqual(call(rp, req=request(params=PROFILE["roles"]["investigator"]["params"])).error["code"],
                         "replay-mismatch")
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["unconsumedRecordedCalls"]), (0, 1))

    def test_successful_matches_are_counted_once_each(self):
        gw = self.live(script(entry(response=response()), entry(ordinal=1, error=terr(retryable=False))))
        call(gw)
        call(gw, 1, request(text="b"))
        rp = self.replayer(self.finish(gw))
        call(rp)
        call(rp, 1, request(text="b"))
        self.assertEqual(rp.report()["replayedCalls"], 2)


class GW9Completeness(Fx):
    def trace(self):
        gw = self.live(script(entry(response=response()), entry(ordinal=1, response=response())))
        call(gw)
        call(gw, 1, request(text="b"))
        return self.finish(gw)

    def test_truncated_trace_does_not_load_by_default(self):
        ev = self.trace()
        for cut in (ev[:3], ev[:-1]):
            with self.subTest(n=len(cut)), self.assertRaisesRegex(TraceError, "run.end"):
                load_trace(cut)

    def test_diagnostic_load_carries_complete_false_and_replay_refuses_it(self):
        ev = self.trace()
        part = load_trace(ev[:-1], allow_partial=True)
        self.assertFalse(part.complete)
        self.assertTrue(load_trace(ev).complete)
        rd, evr = __import__("tests.gateway.helpers", fromlist=["x"]).replay_run_doc(part.run_id)
        with self.assertRaisesRegex(GatewayConfigError, "complete"):
            Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id=rd["id"], replay=part,
                    expected_trace_digest=part.byte_digest)


class GW10Provenance(Fx):
    def chain(self):
        return script(entry(attempt=0, response=response(status="invalid-output")),
                      entry(attempt=1, error=terr()), entry(attempt=2, error=terr()),
                      entry(attempt=3, response=response()))

    def test_only_the_repair_attempt_is_a_repair_and_retries_name_what_they_retry(self):
        gw = self.live(self.chain())
        r = call(gw, repair=lambda resp: request(text="repair"))
        self.assertTrue(r.ok)
        ids = [a.call_id for a in r.attempts]
        calls = {e["attempt"]: e for e in gw.recorder.events if e["type"] == "model.call"}
        costs = {e["record"]["callId"]: e["record"] for e in gw.recorder.events if e["type"] == "cost"}
        self.assertEqual({a: e.get("repairOf") for a, e in calls.items()}, {0: None, 1: ids[0], 2: None, 3: None})
        self.assertEqual([costs[i].get("retryOf") for i in ids], [None, None, ids[1], ids[2]])

    def test_chain_replays_and_provenance_drift_is_a_mismatch(self):
        gw = self.live(self.chain())
        call(gw, repair=lambda resp: request(text="repair"))
        ev = self.finish(gw)
        rp = self.replayer(ev)
        self.assertTrue(call(rp, repair=lambda resp: request(text="repair")).ok)
        self.assertEqual((rp.report()["replayedCalls"], rp.unconsumed()), (4, 0))
        rp = self.replayer(ev)                                    # no repair builder: attempt 1 never repairs
        r = call(rp)
        self.assertEqual(r.error["code"], "schema-invalid")

    def test_plain_retry_is_not_a_repair(self):
        gw = self.live(script(entry(error=terr()), entry(attempt=1, response=response())))
        call(gw)
        self.assertNotIn("repairOf", [k for e in gw.recorder.events if e["type"] == "model.call" for k in e])


class HypothesisIdPassThrough(Fx):
    """ModelRequest.hypothesisId (verifier requests only): the gateway carries it into the hash and the trace."""
    VER = ("VERIFY", "verifier", "verifier")

    def test_optional_subject_is_recorded_hashed_and_replayed(self):
        sub = "hyp_" + "1" * 16
        req = request("verifier", text="candidate", hypothesisId=sub)
        require("ModelRequest", req)
        gw = self.live(script(entry(stage="VERIFY", role="verifier", agent="verifier",
                                    response=response(output=verifier_out("confirmed")))))
        self.assertTrue(gw.call(*self.VER, 0, req).ok)
        ev = self.finish(gw)
        rec = next(e for e in ev if e["type"] == "model.call")
        self.assertEqual(rec["request"]["hypothesisId"], sub)
        self.assertTrue(self.replayer(ev).call(*self.VER, 0, req).ok)
        other = self.replayer(ev).call(*self.VER, 0, request("verifier", text="candidate"))
        self.assertEqual(other.error["code"], "replay-miss")                  # no subject: a different hash
        wrong = self.replayer(ev).call(*self.VER, 0, request("verifier", text="candidate", hypothesisId="hyp_" + "2" * 16))
        self.assertEqual(wrong.error["code"], "replay-miss")

    def test_request_without_subject_is_still_accepted_but_cannot_name_one_for_a_non_verifier(self):
        gw = self.live(script(entry(response=response())))
        self.assertTrue(call(gw).ok)                                           # unrelated calls need no subject
        refused = call(gw, 1, request(hypothesisId="hyp_" + "1" * 16))
        self.assertEqual(refused.error["code"], "contract-violation")
        self.assertEqual(gw.provider.calls, 1)


if __name__ == "__main__":
    unittest.main()
