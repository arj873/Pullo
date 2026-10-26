"""Independent review tests for S1-02 (gateway: D3 local schema validation, D4 attempt guard seam, NEW1 reserved
adapter codes, replay accounting, Turn schema selection). Reviewer-owned, offline, stdlib only, no provider/network.

Conventions (same as test_gateway_review.py / test_gateway_rereview.py):
* `test_CONTROL_*`  pass today and pin intended behaviour.
* `test_ADJ_*`      schema-valid variants of controls that the author's D3 made schema-invalid (purpose kept).
* `test_OPEN_*`     reproduce a defect that is still open; marked expectedFailure so a fix shows as an
                    "unexpected success" and the suite stays readable. They assert the CORRECT behaviour.
Builders come from tests/gateway/helpers.py (read-only) and from test_gateway_rereview.Direct (explicit book,
independently computed pin; no author Env).

Run: nice -n 19 python3 -m unittest discover -s tests/gateway_review -p 'test_gateway_s102_review.py' -v
"""
from __future__ import annotations

import copy
import json
import sys
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

import test_gateway_rereview as R  # noqa: E402  (module import, not class import: its tests are not re-collected)
from reviewer.contracts import REGISTRY  # noqa: E402
from reviewer.contracts.canonical import call_id  # noqa: E402
from reviewer.gateway import ProviderResult  # noqa: E402
from reviewer.gateway import (Gateway, GuardRefusal, SpendBook, TraceError, cancel_guard,  # noqa: E402
                              chain_guards, error_charge_class, load_trace)
from tests.gateway import helpers as H  # noqa: E402

INV, RESERVE = R.INV, R.RESERVE
VER = ("VERIFY", "verifier", "generalist")
USAGE = {**H.ZERO, "uncachedInputTokens": 100, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 50}
BAD = {"hypotheses": "not-a-list"}
SECRET = "sk-ant-api03-" + "A" * 40


def hyp(n):
    """A schema-valid HypothesisDraft; `n` makes it distinguishable."""
    return {"claim": f"claim {n}", "category": "bug", "suspectedSeverity": "P1", "impact": "crash",
            "location": {"path": f"src/f{n}.py", "line": n + 1},
            "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16}]}


def inv_out(n):
    return {"hypotheses": [hyp(n)]}


def good(n=1):
    return H.response(output=inv_out(n), usage=USAGE)


def bad(output=BAD):
    return H.response(output=output, usage=USAGE)


def models(events):
    return [e for e in events if e["type"] == "model.call"]


def costs(events):
    return [e["record"] for e in events if e["type"] == "cost"]


def rcall(gw, ordinal=0, req=None, **kw):
    return gw.call(*INV, ordinal, req or H.request(), **kw)


def again(resp):
    return H.request(text="repair attempt")


class Rv(R.Direct):
    def live(self, *entries, **kw):
        h = self.handle()
        prov = self.synth(*entries)
        gw = self.mk(prov, book=SpendBook(h), handle=h, **kw)
        gw.prov = prov["synthetic"]
        return gw

    def total(self, gw):
        t = gw.book.totals()
        return t["committed"] + t["inflight"]


# ============================================================================================ D3
class D3(Rv):
    def test_CONTROL_schema_valid_answers_are_served_for_every_role(self):
        gw = self.live(H.entry(response=good()),
                       H.entry(stage="VERIFY", role="verifier", response=H.response(output=H.verifier_out("confirmed"))),
                       H.entry(stage="JUDGE", role="judge", response=H.response(output={"comments": []})))
        self.assertTrue(rcall(gw).ok)
        self.assertTrue(gw.call(*VER, 0, H.request("verifier")).ok)
        self.assertTrue(gw.call("JUDGE", "judge", "generalist", 0, H.request("judge")).ok)

    def test_ok_but_schema_invalid_without_repair_keeps_receipt_and_charge_and_fails_typed(self):
        gw = self.live(H.entry(response=bad()))
        r = rcall(gw)
        self.assertEqual(r.error["code"], "schema-invalid")
        self.assertIsNone(r.response)
        self.assertIs(r.error["detail"]["localValidation"], True)
        self.assertEqual(len(r.error["detail"]["issues"]), 1)
        self.assertIn("hypotheses", r.error["detail"]["issues"][0])
        a = r.attempts[0]
        self.assertEqual((a.outcome, len(a.schema_issues)), ("schema-invalid", 1))
        self.assertGreater(a.charge_usd_micros, 0)
        self.assertEqual(gw.report()["newSpendUsdMicros"], a.charge_usd_micros)
        events, _ = self.seal(gw)
        m, = models(events)
        self.assertEqual((m["response"]["status"], m["response"]["output"]), ("ok", BAD))      # as received
        self.assertEqual(costs(events)[0]["usdMicros"], a.charge_usd_micros)
        tail = [e for e in events if e["type"] == "error"]
        self.assertEqual([e["error"]["code"] for e in tail], ["schema-invalid"])
        self.assertTrue(load_trace(events).complete)

    def test_repair_is_a_fresh_charged_admission_with_provenance(self):
        gw = self.live(H.entry(response=bad()), H.entry(attempt=1, response=good()))
        r = rcall(gw, repair=again)
        self.assertTrue(r.ok)
        events, _ = self.seal(gw)
        first, second = models(events)
        self.assertEqual(second["repairOf"], first["callId"])
        self.assertNotIn("repairOf", first)
        c1, c2 = costs(events)
        self.assertTrue(c1["usdMicros"] > 0 and c2["usdMicros"] > 0 and c1["reservedUsdMicros"] > 0 and c2["reservedUsdMicros"] > 0)
        self.assertEqual(gw.report()["newSpendUsdMicros"], c1["usdMicros"] + c2["usdMicros"])
        self.assertEqual(self.total(gw), c1["usdMicros"] + c2["usdMicros"])
        self.assertEqual([a.outcome for a in r.attempts], ["schema-invalid", "ok"])

    def test_second_invalid_answer_is_repair_exhausted_after_exactly_two_provider_calls(self):
        gw = self.live(H.entry(response=bad()), H.entry(attempt=1, response=bad({"hypotheses": 3})),
                       H.entry(attempt=2, response=good()))
        r = rcall(gw, repair=again)
        self.assertEqual((r.error["code"], r.error["detail"]["repairsUsed"], gw.prov.calls), ("repair-exhausted", 1, 2))
        self.assertEqual(gw.report()["newSpendUsdMicros"], sum(a.charge_usd_micros for a in r.attempts))

    def test_repair_with_issues_sees_issue_list_and_raw_text_but_the_recording_is_untouched(self):
        seen = []

        def build(resp, issues):
            seen.append((resp["rawText"], list(issues)))
            return H.request(text="repair attempt")
        gw = self.live(H.entry(response=bad()), H.entry(attempt=1, response=good()))
        self.assertTrue(rcall(gw, repair_with_issues=build).ok)
        self.assertEqual(seen[0][0], json.dumps(BAD, sort_keys=True, ensure_ascii=False))
        self.assertEqual(len(seen[0][1]), 1)
        events, _ = self.seal(gw)
        self.assertIsNone(models(events)[0]["response"]["rawText"])

    def test_issues_are_bounded_to_three_of_two_hundred_chars(self):
        out = {"hypotheses": [], **{f"k{i}" + "x" * 300: 1 for i in range(6)}}
        r = rcall(self.live(H.entry(response=bad(out))))
        issues = r.error["detail"]["issues"]
        self.assertTrue(1 <= len(issues) <= 3 and all(len(i) <= 200 for i in issues), issues)

    def test_secret_shaped_model_text_does_not_reach_the_typed_error_or_the_persisted_trace(self):
        # the scripted provider cannot carry a secret (ModelResponse no-secrets), so a stub adapter returns it raw
        raw = H.response(output={"hypotheses": [], SECRET: 1}, usage=USAGE)

        class Stub:
            name = "synthetic"
            calls = 0

            def call(self, request, key):
                return ProviderResult(copy.deepcopy(raw), None, "processed")
        h = self.handle()
        gw = self.mk({"synthetic": Stub()}, book=SpendBook(h), handle=h)
        r = rcall(gw)
        self.assertEqual(r.error["code"], "schema-invalid")
        self.seal(gw)
        self.assertNotIn(SECRET, json.dumps(r.error))
        self.assertNotIn(SECRET, gw.path.read_text())
        self.assertTrue(load_trace(gw.path).complete)

    def test_the_trusted_profile_not_the_answer_selects_the_schema(self):
        # a perfectly valid InvestigatorOutput is not a VerifierOutput: the verifier role is judged by its own schema
        gw = self.live(H.entry(stage="VERIFY", role="verifier", response=H.response(output=inv_out(1), usage=USAGE)))
        self.assertEqual(gw.call(*VER, 0, H.request("verifier")).error["code"], "schema-invalid")

    def test_request_cannot_name_another_output_schema_than_the_profile_role(self):
        gw = self.live(H.entry(response=good()))
        r = rcall(gw, req=H.request(outputSchema="VerifierOutput"))
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(gw.prov.calls, 0)

    def test_replay_rederives_schema_invalid_and_the_repair_chain_identically(self):
        gw = self.live(H.entry(response=bad()), H.entry(attempt=1, response=good()))
        rcall(gw, repair=again)
        events, pin = self.seal(gw)
        rp = self.replay(gw.path, pin)
        r = rcall(rp, repair=again)
        self.assertTrue(r.ok)
        rep = rp.report()
        self.assertEqual((rep["liveCalls"], rep["replayedCalls"], rep["unconsumedRecordedCalls"], rep["newSpendUsdMicros"]),
                         (0, 2, 0, 0))
        self.assertEqual(rep["replayedUsdMicros"], sum(c["usdMicros"] for c in costs(events)))
        # same recording, no repair builder: the same typed failure as live, and the repair record stays unconsumed
        rp2 = self.replay(gw.path, pin)
        r2 = rcall(rp2)
        self.assertEqual(r2.error["code"], "schema-invalid")
        self.assertEqual(rp2.report()["unconsumedRecordedCalls"], 1)

    def test_old_recording_with_an_invalid_ok_answer_and_no_repair_replay_misses_at_the_repair(self):
        # Compat item 1 of the handoff: a recording from before D3 (ok-but-invalid, no repair attempt recorded).
        gw = self.live(H.entry(response=bad()))
        rcall(gw)
        events, pin = self.seal(gw)
        rp = self.replay(gw.path, pin)
        r = rcall(rp, repair=again)
        self.assertEqual(r.error["code"], "replay-miss")
        self.assertEqual((rp.report()["replayedCalls"], rp.report()["unconsumedRecordedCalls"]), (1, 0))


# ============================================================================================ D4
class D4(Rv):
    def test_guard_runs_before_any_reservation_and_sees_only_coordinates(self):
        snaps = []

        def guard(ctx):
            snaps.append((ctx, gw.book.totals(), gw.report()["newSpendUsdMicros"]))
            return None
        gw = self.live(H.entry(response=good()), guard=guard)
        before = gw.book.totals()
        self.assertTrue(rcall(gw).ok)
        ctx, totals, spend = snaps[0]
        self.assertEqual((ctx.kind, ctx.mode, ctx.attempt, ctx.ordinal), ("first", "live", 0, 0))
        self.assertEqual((totals, spend), (before, 0))

    def test_refused_repair_chain_is_loadable_and_replays_with_the_same_charges(self):
        gw = self.live(H.entry(response=bad()), H.entry(attempt=1, response=good()),
                       guard=lambda ctx: "cancelled" if ctx.kind == "repair" else None)
        r = rcall(gw, repair=again)
        self.assertEqual((r.error["code"], gw.prov.calls), ("cancelled", 1))
        events, pin = self.seal(gw)
        first, refused = models(events)
        self.assertEqual(refused["repairOf"], first["callId"])
        self.assertEqual(refused["error"]["detail"]["refusedBy"], "host-guard")
        c1, c2 = costs(events)
        self.assertEqual((c2["usdMicros"], c2["reservedUsdMicros"]), (0, 0))
        self.assertGreater(c1["usdMicros"], 0)
        self.assertTrue(load_trace(gw.path).complete)
        rp = self.replay(gw.path, pin)
        r2 = rcall(rp, repair=again)
        rep = rp.report()
        self.assertEqual((r2.error["code"], rep["liveCalls"], rep["replayedCalls"], rep["unconsumedRecordedCalls"]),
                         ("cancelled", 0, 2, 0))
        self.assertEqual(rep["replayedUsdMicros"], c1["usdMicros"])
        self.assertEqual(rep["spend"]["reserved"] if "reserved" in (rep["spend"] or {}) else 0, 0)

    def test_refused_retry_keeps_the_retained_first_attempt_and_replays(self):
        gw = self.live(H.entry(error=H.terr("provider-timeout")), H.entry(attempt=1, response=good()),
                       guard=lambda ctx: "deadline-exceeded" if ctx.kind == "retry" else None)
        r = rcall(gw)
        self.assertEqual(r.error["code"], "deadline-exceeded")
        events, pin = self.seal(gw)
        c1, c2 = costs(events)
        self.assertEqual((c1["usdMicros"], c2["usdMicros"], c2.get("retryOf")), (RESERVE, 0, models(events)[0]["callId"]))
        rp = self.replay(gw.path, pin)
        r2 = rcall(rp)
        self.assertEqual((r2.error["code"], rp.report()["replayedCalls"], rp.report()["replayedUsdMicros"],
                          rp.report()["unconsumedRecordedCalls"]), ("deadline-exceeded", 2, RESERVE, 0))

    def test_recorded_refusal_is_reproduced_even_when_the_replay_guard_is_absent(self):
        gw = self.live(H.entry(response=good()), guard=lambda ctx: "cancelled")
        rcall(gw)
        events, pin = self.seal(gw)
        rp = self.replay(gw.path, pin)                      # no guard on the replay gateway
        r = rcall(rp)
        self.assertEqual((r.error["code"], r.error["detail"]["refusedBy"]), ("cancelled", "host-guard"))
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["replayedUsdMicros"], rep["unconsumedRecordedCalls"]), (1, 0, 0))
        self.assertTrue(all(c["basis"] == "replayed" for c in costs(rp.recorder.events)))

    def test_replay_time_refusal_is_an_error_event_leaves_the_recording_unconsumed_and_the_coordinate_reusable(self):
        # Resolves the handoff's descriptions: "a refusal consumes the coordinate" is LIVE-only; in strict replay the
        # refusal writes an `error` event (no model.call), consumes nothing, and the same coordinate can be asked again.
        gw = self.live(H.entry(response=good()))
        rcall(gw)
        events, pin = self.seal(gw)
        state = {"refuse": True}
        rp = self.replay(gw.path, pin, guard=lambda ctx: "cancelled" if state["refuse"] else None)
        r = rcall(rp)
        self.assertEqual(r.error["code"], "cancelled")
        self.assertEqual([e["type"] for e in rp.recorder.events], ["run.start", "error"])
        self.assertEqual(rp.report()["unconsumedRecordedCalls"], 1)
        self.assertEqual(rp.report()["replayedCalls"], 0)
        state["refuse"] = False
        r2 = rcall(rp)
        self.assertTrue(r2.ok)
        self.assertEqual(rp.report()["unconsumedRecordedCalls"], 0)

    def test_live_refusal_consumes_the_coordinate_and_is_a_model_call(self):
        gw = self.live(H.entry(response=good()), guard=lambda ctx: "cancelled")
        rcall(gw)
        events, _ = self.seal(gw)
        self.assertEqual([e["type"] for e in events], ["run.start", "model.call", "cost", "run.end"])

    def test_a_cancel_stops_replay_even_for_a_call_that_would_miss(self):
        gw = self.live(H.entry(response=good()))
        rcall(gw)
        events, pin = self.seal(gw)
        rp = self.replay(gw.path, pin, guard=lambda ctx: "cancelled")
        self.assertEqual(rcall(rp, req=H.request(text="never recorded")).error["code"], "cancelled")

    def test_guard_sees_strict_replay_mode(self):
        gw = self.live(H.entry(response=good()))
        rcall(gw)
        _, pin = self.seal(gw)
        modes = []
        rp = self.replay(gw.path, pin, guard=lambda ctx: modes.append((ctx.mode, ctx.kind)))
        rcall(rp)
        self.assertEqual(modes, [("strict-replay", "first")])

    def test_charged_guard_refusal_in_an_edited_trace_does_not_load(self):
        gw = self.live(H.entry(response=good()), guard=lambda ctx: "cancelled")
        rcall(gw)
        events, _ = self.seal(gw)
        edited = copy.deepcopy(events)
        costs(edited)  # records are the same dicts
        for e in edited:
            if e["type"] == "cost":
                e["record"]["usdMicros"] = 5
        with self.assertRaises(TraceError):
            load_trace(edited)

    def test_marker_stripped_refusal_is_not_trusted_as_a_free_refusal_on_replay(self):
        gw = self.live(H.entry(response=good()), guard=lambda ctx: "cancelled")
        rcall(gw)
        events, _ = self.seal(gw)
        edited = copy.deepcopy(events)
        for e in edited:
            if e["type"] == "model.call":
                e["error"]["detail"].pop("refusedBy")
        p = self.tampered_file("stripped.jsonl", edited)
        rp = self.replay(p, R.sha(p.read_bytes()))         # explicit operator repin of the edited bytes
        r = rcall(rp)
        self.assertEqual(r.error["code"], "replay-mismatch")
        self.assertEqual(rp.report()["unconsumedRecordedCalls"], 1)

    def test_guard_fault_message_is_class_only_and_refusal_text_is_bounded(self):
        def boom(ctx):
            raise GuardRefusal("bogus-code")                # ValueError from the guard's own bad construction
        r = rcall(self.live(H.entry(response=good()), guard=boom))
        self.assertEqual((r.error["code"], r.error["detail"]["guardFault"]), ("cancelled", "ValueError"))
        long = rcall(self.live(H.entry(response=good()), guard=lambda ctx: GuardRefusal("cancelled", "z" * 5000)))
        self.assertLessEqual(len(long.error["message"]), 500)

    def test_guard_is_not_consulted_for_requests_the_gateway_refuses_first(self):
        n = []
        gw = self.live(H.entry(response=good()), guard=lambda ctx: n.append(ctx))
        bad_req = H.request()
        bad_req["profile"] = "someone-else@1"
        self.assertEqual(rcall(gw, req=bad_req).error["code"], "contract-violation")
        self.assertEqual(len(n), 0)
        self.assertTrue(rcall(gw).ok)
        self.assertEqual(rcall(gw).error["code"], "contract-violation")        # duplicate coordinate
        self.assertEqual(len(n), 1)

    def test_chain_and_cancel_helpers(self):
        ev = threading.Event()
        gw = self.live(H.entry(response=good()), H.entry(ordinal=1, response=good()),
                       guard=chain_guards(lambda ctx: None, cancel_guard(ev)))
        self.assertTrue(rcall(gw).ok)
        ev.set()
        self.assertEqual(rcall(gw, 1).error["code"], "cancelled")
        self.assertEqual(gw.prov.calls, 1)

    def test_guard_refusal_with_a_real_provider_profile_never_contacts_the_adapter_and_loads(self):
        # the synthetic provider masks _basis(): exercise the non-synthetic cost record a production refusal writes
        prof = copy.deepcopy(H.PROFILE)
        prof["roles"]["investigator"].update(provider="anthropic", model="claude-sonnet-5-5", family="anthropic")
        h = self.handle(providers=["anthropic", "synthetic"], models=["claude-sonnet-5-5", "synthetic-fixture"])

        class Boom:
            name = "anthropic"

            def call(self, request, key):
                raise AssertionError("the provider adapter was contacted")
        gw = self.mk({"anthropic": Boom()}, book=SpendBook(h), handle=h, prof=prof, guard=lambda ctx: "cancelled")
        req = H.request(provider="anthropic", model="claude-sonnet-5-5")
        self.assertEqual(rcall(gw, req=req).error["code"], "cancelled")
        events, _ = self.seal(gw)
        c, = costs(events)
        self.assertEqual((c["usdMicros"], c["reservedUsdMicros"], c["provider"]), (0, 0, "anthropic"))
        self.assertTrue(load_trace(gw.path).complete)

    def test_refusal_takes_precedence_over_budget_exhaustion_and_consumes_no_budget(self):
        small = {**H.BUDGET, "maxUsdMicros": 1}
        gw = self.live(H.entry(response=good()), budget=small, guard=lambda ctx: "cancelled")
        self.assertEqual(rcall(gw).error["code"], "cancelled")


# ============================================================================================ NEW1
RESERVED = [c for c in REGISTRY["TypedError"].required["code"].values
            if c not in ("provider-error", "provider-timeout", "live-calls-disabled")]


class NEW1(Rv):
    def test_every_gateway_owned_code_from_an_adapter_is_a_non_retried_retained_provider_error(self):
        self.assertGreaterEqual(len(RESERVED), 12)
        for code in RESERVED:
            with self.subTest(code=code):
                gw = self.live(H.entry(error=H.terr(code, True)), H.entry(attempt=1, response=good()))
                r = rcall(gw)
                self.assertEqual((r.error["code"], r.error["retryable"], r.error["detail"]["adapterCode"], gw.prov.calls),
                                 ("provider-error", False, code, 1))
                self.assertEqual(r.attempts[0].charge_usd_micros, RESERVE)
                events, pin = self.seal(gw)
                self.assertTrue(load_trace(gw.path).complete)
                rp = self.replay(gw.path, pin)
                r2 = rcall(rp)
                self.assertEqual((r2.error, rp.report()["replayedUsdMicros"]), (r.error, RESERVE))

    def test_forged_host_guard_marker_is_stripped_and_the_call_stays_charged(self):
        gw = self.live(H.entry(error=H.terr("cancelled", False, refusedBy="host-guard")))
        r = rcall(gw)
        self.assertEqual((r.error["code"], r.attempts[0].charge_usd_micros), ("provider-error", RESERVE))
        self.assertNotIn("refusedBy", r.error["detail"])
        events, _ = self.seal(gw)
        self.assertEqual(error_charge_class(models(events)[0]["error"]), "retained")
        self.assertTrue(load_trace(gw.path).complete)

    def test_forged_billed_class_cannot_be_manufactured_by_an_adapter(self):
        gw = self.live(H.entry(error=H.terr("contract-violation", False, resolvedModel="other-model",
                                            providerOutcome="processed")))
        r = rcall(gw)
        self.assertEqual((r.error["code"], r.attempts[0].charge_usd_micros), ("provider-error", RESERVE))
        self.assertNotIn("resolvedModel", r.error["detail"])
        events, _ = self.seal(gw)
        self.assertEqual(error_charge_class(models(events)[0]["error"]), "retained")

    def test_adapter_cannot_stamp_its_own_provider_outcome_to_get_a_release(self):
        gw = self.live(H.entry(error=H.terr("provider-error", False, providerOutcome="not-sent")))
        r = rcall(gw)
        self.assertEqual((r.error["detail"]["providerOutcome"], r.attempts[0].charge_usd_micros), ("unknown", RESERVE))

    def test_allowed_adapter_codes_are_not_rewritten(self):
        gw = self.live(H.entry(error=H.terr("provider-timeout")), H.entry(attempt=1, response=good()),
                       H.entry(ordinal=1, error=H.terr("live-calls-disabled", False)))
        self.assertTrue(rcall(gw).ok)
        self.assertEqual(gw.prov.calls, 2)
        r = rcall(gw, 1)
        self.assertEqual(r.error["code"], "live-calls-disabled")
        self.assertNotIn("adapterCode", r.error.get("detail", {}))

    def test_CONTROL_old_recording_with_an_unmarked_cancelled_provider_error_still_loads_charged_and_replays(self):
        gw = self.live(H.entry(error=H.terr("provider-error", False)))
        rcall(gw)
        events, _ = self.seal(gw)
        old = copy.deepcopy(events)
        for e in old:
            if e["type"] == "model.call":
                e["error"]["code"] = "cancelled"            # what a pre-NEW1 adapter could have recorded
        p = self.tampered_file("old.jsonl", old)
        self.assertEqual(error_charge_class(models(load_trace(p).events)[0]["error"]), "retained")
        rp = self.replay(p, R.sha(p.read_bytes()))
        r = rcall(rp)
        self.assertEqual((r.error["code"], rp.report()["replayedUsdMicros"]), ("cancelled", RESERVE))


# ============================================================================================ NEW5 (open)
class Forgery(Rv):
    def _forged_replay(self, forged_output):
        gw = self.live(H.entry(response=good(1)))
        rcall(gw)
        events, pin = self.seal(gw)
        tr = load_trace(gw.path)
        for lst in tr.calls.values():
            lst[0]["response"]["output"] = forged_output
        rd = R.rundoc(9006, mode="strict-replay", replay_of=tr.run_id)
        rec = R.Recorder(rd["id"])
        rec.start(rd)
        try:
            rp = Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                         recorder=rec, expected_trace_digest=pin)
        except (TraceError, R.GatewayConfigError):
            return None
        return rcall(rp)

    def test_NEW5_original_mutation_is_now_rejected_only_because_it_is_schema_invalid(self):
        """INCIDENTAL: D3 rejects the repro's forged output because it violates the schema, not because the gateway
        compares the pin with the events it serves. Passing here does NOT mean NEW5 is fixed."""
        r = self._forged_replay({"hypotheses": "MUTATED-AFTER-LOAD"})
        self.assertIsNotNone(r)
        self.assertEqual(r.error["code"], "schema-invalid")

    @unittest.expectedFailure
    def test_OPEN_NEW5_schema_valid_forgery_after_load_is_still_served(self):
        """OPEN. Same mutation as NEW5 but with a schema-valid forged answer: pin passes, forged answer served."""
        r = self._forged_replay(inv_out(7))
        if r is None:
            return                                              # hardened: constructor refused the mutated events
        self.assertNotEqual(r.output, inv_out(7), "a schema-valid forged answer was served under an unchanged pin")


# ============================================================================================ replay accounting / kinds
class Accounting(Rv):
    def test_retry_then_invalid_then_repair_chain_replays_every_attempt_at_the_recorded_charge(self):
        gw = self.live(H.entry(error=H.terr("provider-timeout")), H.entry(attempt=1, response=bad()),
                       H.entry(attempt=2, response=good()))
        r = rcall(gw, repair=again)
        self.assertTrue(r.ok)
        events, pin = self.seal(gw)
        live_total = gw.report()["newSpendUsdMicros"]
        rp = self.replay(gw.path, pin)
        self.assertTrue(rcall(rp, repair=again).ok)
        rep = rp.report()
        self.assertEqual((rep["liveCalls"], rep["replayedCalls"], rep["newSpendUsdMicros"], rep["replayedUsdMicros"],
                          rep["unconsumedRecordedCalls"]), (0, 3, 0, live_total, 0))
        rc = costs(rp.recorder.events)
        self.assertTrue(all(c["basis"] == "replayed" and "replayOf" in c for c in rc))
        self.assertEqual(rc[1].get("retryOf"), models(events)[0]["callId"])
        self.assertTrue(load_trace(events).complete)

    def test_production_judge_wording_is_booked_as_review_cost_in_the_same_book(self):
        gw = self.live(H.entry(response=good()),
                       H.entry(stage="JUDGE", role="judge", response=H.response(output={"comments": []}, usage=USAGE)),
                       cost_kind="review")
        self.assertTrue(rcall(gw).ok)
        self.assertTrue(gw.call("JUDGE", "judge", "generalist", 0, H.request("judge")).ok)
        events, _ = self.seal(gw)
        self.assertEqual({c["kind"] for c in costs(events)}, {"review"})
        self.assertEqual(self.total(gw), sum(c["usdMicros"] for c in costs(events)))


# ============================================================================================ Turn schema selection
TURN_PROFILE = copy.deepcopy(H.PROFILE)
TURN_PROFILE["roles"]["investigator"]["outputSchema"] = "InvestigatorTurn"
ASK = {"contextRequests": [{"tool": "read_file", "args": {"path": "a.py"}, "purpose": "see the definition"}], "output": None}
FINAL = {"contextRequests": [], "output": inv_out(1)}


def treq(**over):
    return H.request(**{"outputSchema": "InvestigatorTurn", "hop": 0, **over})


class TurnSchema(Rv):
    def test_turn_profile_accepts_ask_and_final_envelopes_and_rejects_everything_else(self):
        cases = [(ASK, None), (FINAL, None),
                 ({"contextRequests": ASK["contextRequests"], "output": inv_out(1)}, "schema-invalid"),
                 ({"contextRequests": [], "output": None}, "schema-invalid"),
                 ({"contextRequests": [], "output": BAD}, "schema-invalid"),
                 (inv_out(1), "schema-invalid")]                 # a plain role output cannot pick the plain schema
        gw = self.live(*[H.entry(ordinal=i, response=H.response(output=o, usage=USAGE)) for i, (o, _) in enumerate(cases)],
                       prof=TURN_PROFILE)
        for i, (out, want) in enumerate(cases):
            with self.subTest(i=i):
                r = gw.call(*INV, i, treq())
                self.assertEqual(None if r.ok else r.error["code"], want)

    def test_legacy_profile_rejects_an_envelope_and_a_turn_request_to_it(self):
        gw = self.live(H.entry(response=H.response(output=FINAL, usage=USAGE)))
        self.assertEqual(rcall(gw).error["code"], "schema-invalid")
        self.assertEqual(rcall(gw, 1, treq()).error["code"], "contract-violation")

    def test_plain_request_to_a_turn_profile_is_refused_before_any_provider_call(self):
        gw = self.live(H.entry(response=H.response(output=FINAL)), prof=TURN_PROFILE)
        r = rcall(gw)                                                  # outputSchema InvestigatorOutput
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(gw.prov.calls, 0)

    def test_envelope_is_traced_unchanged_loads_and_replays_identically(self):
        gw = self.live(H.entry(response=H.response(output=ASK, usage=USAGE)),
                       H.entry(ordinal=1, response=H.response(output=FINAL, usage=USAGE)), prof=TURN_PROFILE)
        self.assertTrue(gw.call(*INV, 0, treq()).ok and gw.call(*INV, 1, treq(text="second turn")).ok)
        events, pin = self.seal(gw)
        self.assertEqual([m["response"]["output"] for m in models(events)], [ASK, FINAL])
        self.assertTrue(load_trace(gw.path).complete)
        rp = self.replay(gw.path, pin, prof=TURN_PROFILE)
        self.assertEqual(rp.call(*INV, 0, treq()).output, ASK)

    def test_continuation_turn_passes_the_gateway_and_the_trace_demands_the_tool_calls_it_cites(self):
        # The gateway has no hop loop and no chain check (handoff: not built). The contracts' turn-trace rule is what
        # rejects a continuation citing a tool call that was never logged. No gateway change is needed for that.
        gw = self.live(H.entry(response=H.response(output=ASK, usage=USAGE)),
                       H.entry(ordinal=1, response=H.response(output=FINAL, usage=USAGE)), prof=TURN_PROFILE)
        self.assertTrue(gw.call(*INV, 0, treq()).ok)
        r = gw.call(*INV, 1, treq(text="hop one", hop=1, continuationOf=call_id(*INV, 0, 0),
                                  contextResults=["tool_" + "2" * 16]))
        self.assertTrue(r.ok)
        self.seal(gw)
        with self.assertRaises(TraceError) as cm:
            load_trace(gw.path)
        self.assertIn("turn-trace", str(cm.exception))


# ============================================================================================ adjusted controls
class AdjustedControls(Rv):
    """Schema-valid variants of the three controls that D3 turned red (originals untouched; same purpose)."""

    def test_ADJ_identical_requests_by_two_agents_never_swap_and_extra_occurrence_misses(self):
        # original: tests/gateway_review/test_gateway_review.py Controls.test_CONTROL_identical_requests_by_two_agents...
        # adjustment: distinguishing marker {"n": k} (unknown field => schema-invalid) -> a schema-valid hypothesis per agent.
        h = self.handle()
        gw = self.mk(self.synth(H.entry(agent="a1", response=H.response(output=inv_out(1))),
                                H.entry(agent="a2", response=H.response(output=inv_out(2)))), book=SpendBook(h), handle=h)
        for a in ("a1", "a2"):
            self.assertTrue(gw.call("INVESTIGATE", "investigator", a, 0, H.request()).ok)
        _, pin = self.seal(gw)
        rp = self.replay(gw.path, pin)
        claim = lambda r: r.output["hypotheses"][0]["claim"]          # noqa: E731
        self.assertEqual(claim(rp.call("INVESTIGATE", "investigator", "a2", 0, H.request())), "claim 2")
        self.assertEqual(claim(rp.call("INVESTIGATE", "investigator", "a1", 0, H.request())), "claim 1")
        self.assertEqual(rp.call("INVESTIGATE", "investigator", "a1", 0, H.request()).error["code"], "replay-miss")
        self.assertEqual(rp.call("INVESTIGATE", "investigator", "a3", 0, H.request()).error["code"], "replay-miss")
        self.assertEqual((rp.report()["liveCalls"], rp.unconsumed()), (0, 0))

    def test_ADJ_deliberate_trusted_edited_trace_with_explicit_repin(self):
        # original: test_gateway_rereview.Pin.test_CONTROL_deliberate_trusted_edited_trace_with_explicit_repin
        # adjustment: edited output {"hypotheses": "TRUSTED-EDIT"} (schema-invalid) -> a different schema-valid answer.
        h = self.handle()
        gw = self.mk(self.synth(H.entry(response=H.response(output=inv_out(1)))), book=SpendBook(h), handle=h)
        rcall(gw)
        events, pin = self.seal(gw)
        edited = copy.deepcopy(events)
        for e in edited:
            if e["type"] == "model.call":
                e["response"]["output"] = inv_out(9)
        p = self.tampered_file("trusted-edit.jsonl", edited)
        with self.assertRaises(TraceError):
            self.replay(p, pin)
        r = self.replay(p, R.sha(p.read_bytes())).call(*INV, 0, H.request())
        self.assertEqual(r.output, inv_out(9))

    def test_ADJ_verifier_subject_flows_into_the_hash_and_replay_when_the_contract_has_it(self):
        # original: test_gateway_rereview.HypothesisId.test_verifier_subject_flows_into_the_hash_and_replay...
        # adjustment: scripted verifier answers were {"hypotheses": []} (an investigator shape) -> H.verifier_out().
        probe = H.request("verifier")
        probe["hypothesisId"] = "hyp_" + "1" * 16
        from reviewer.contracts import ContractViolation, require
        try:
            require("ModelRequest", probe)
        except ContractViolation:
            self.skipTest("ModelRequest.hypothesisId not in the contract")
        h = self.handle()
        a, b = "hyp_" + "1" * 16, "hyp_" + "2" * 16

        def req(hyp):
            r = H.request("verifier")
            if hyp:
                r["hypothesisId"] = hyp
            return r
        gw = self.mk(self.synth(H.entry(stage="VERIFY", role="verifier", response=H.response(output=H.verifier_out())),
                                H.entry(stage="VERIFY", role="verifier", ordinal=1,
                                        response=H.response(output=H.verifier_out()))), book=SpendBook(h), handle=h)
        self.assertTrue(gw.call("VERIFY", "verifier", "generalist", 0, req(a)).ok)
        self.assertTrue(gw.call("VERIFY", "verifier", "generalist", 1, req(None)).ok)
        events, pin = self.seal(gw)
        self.assertEqual(len({e["requestHash"] for e in models(events)}), 2)
        rp = self.replay(gw.path, pin)
        self.assertEqual(rp.call("VERIFY", "verifier", "generalist", 0, req(b)).error["code"], "replay-miss")
        self.assertTrue(rp.call("VERIFY", "verifier", "generalist", 0, req(a)).ok)
        self.assertTrue(rp.call("VERIFY", "verifier", "generalist", 1, req(None)).ok)


if __name__ == "__main__":
    unittest.main()
