"""S1-02: D3 local output-schema validation, D4 host attempt guard, NEW1 reserved adapter codes (offline)."""

from __future__ import annotations

import threading
import unittest

from reviewer.contracts import validate
from reviewer.gateway import (Gateway, GatewayConfigError, GuardRefusal, SpendBook, cancel_guard, chain_guards,
                              deadline_guard, error_charge_class, load_trace)
from tests.gateway.helpers import (BUDGET, Env, OK_OUT, entry, profile, request, response, script, terr,
                                   verifier_out)

INV = ("INVESTIGATE", "investigator", "generalist")
VER = ("VERIFY", "verifier", "verifier")
BAD_INV = {"hypotheses": "not-a-list"}
RESERVE = 60_668


def models(events):
    return [e for e in events if e["type"] == "model.call"]


def costs(events):
    return [e["record"] for e in events if e["type"] == "cost"]


class D3LocalValidation(Env):
    def test_valid_ok_output_passes_untouched(self):
        gw = self.live(script(entry(response=response())))
        r = gw.call(*INV, 0, request())
        self.assertTrue(r.ok)
        self.assertEqual([a.outcome for a in r.attempts], ["ok"])
        self.assertEqual(r.attempts[0].schema_issues, [])

    def test_ok_answer_failing_its_schema_is_repaired_and_both_attempts_stay_charged(self):
        seen = []

        def fix(resp):
            seen.append(resp)
            return request(text="again")
        gw = self.live(script(entry(response=response(output=BAD_INV)), entry(attempt=1, response=response())))
        r = gw.call(*INV, 0, request(), repair=fix)
        self.assertTrue(r.ok)
        self.assertEqual([a.outcome for a in r.attempts], ["schema-invalid", "ok"])
        self.assertTrue(r.attempts[0].schema_issues)
        self.assertEqual(gw.provider.calls, 2)
        ev = self.finish(gw)
        m = models(ev)
        self.assertEqual([x["response"]["status"] for x in m], ["ok", "ok"])      # receipt kept as received
        self.assertEqual(m[0]["response"]["output"], BAD_INV)
        self.assertEqual(m[1]["repairOf"], m[0]["callId"])
        c = costs(ev)
        self.assertEqual(len(c), 2)
        self.assertEqual(gw.report()["newSpendUsdMicros"], sum(x["usdMicros"] for x in c))
        self.assertEqual(gw.book.totals()["committed"], gw.report()["newSpendUsdMicros"])
        # the builder saw the answer as data: rawText was null, so it carries the output's JSON
        self.assertIn("not-a-list", seen[0]["rawText"])
        self.assertTrue(load_trace(ev).complete)

    def test_without_a_repair_builder_the_failure_is_typed_and_charged(self):
        gw = self.live(script(entry(response=response(output=BAD_INV))))
        r = gw.call(*INV, 0, request())
        self.assertFalse(r.ok)
        self.assertEqual(r.error["code"], "schema-invalid")
        self.assertTrue(r.error["detail"]["localValidation"])
        self.assertLessEqual(len(r.error["detail"]["issues"]), 3)
        self.assertTrue(all(len(i) <= 200 for i in r.error["detail"]["issues"]))
        self.assertEqual(gw.provider.calls, 1)
        ev = self.finish(gw)
        self.assertEqual(ev[-2]["type"], "error")
        self.assertEqual(costs(ev)[0]["usdMicros"], r.attempts[0].charge_usd_micros)
        self.assertGreater(gw.book.totals()["committed"], -1)

    def test_repair_that_is_still_invalid_is_repair_exhausted_after_exactly_one_repair(self):
        gw = self.live(script(entry(response=response(output=BAD_INV)), entry(attempt=1, response=response(output=BAD_INV)),
                              entry(attempt=2, response=response())))
        r = gw.call(*INV, 0, request(), repair=lambda resp: request(text="again"))
        self.assertEqual(r.error["code"], "repair-exhausted")
        self.assertEqual(gw.provider.calls, 2)
        self.assertEqual(r.error["detail"]["repairsUsed"], 1)

    def test_role_schema_comes_from_the_profile_not_the_response(self):
        gw = self.live(script(entry(stage="VERIFY", role="verifier", agent="verifier", response=response(output=OK_OUT))))
        r = gw.call(*VER, 0, request("verifier"))               # an InvestigatorOutput is not a VerifierOutput
        self.assertEqual(r.error["code"], "schema-invalid")
        gw = self.live(script(entry(stage="VERIFY", role="verifier", agent="verifier",
                                    response=response(output=verifier_out("refuted")))))
        self.assertTrue(gw.call(*VER, 0, request("verifier")).ok)

    def test_issue_list_reaches_a_repair_with_issues_builder(self):
        got = []

        def fix(resp, issues):
            got.append(list(issues))
            return request(text="again")
        gw = self.live(script(entry(response=response(output=BAD_INV)), entry(attempt=1, response=response())))
        self.assertTrue(gw.call(*INV, 0, request(), repair_with_issues=fix).ok)
        self.assertTrue(got and got[0])

    def test_repair_and_repair_with_issues_are_exclusive(self):
        gw = self.live(script())
        with self.assertRaises(ValueError):
            gw.call(*INV, 0, request(), repair=lambda r: r, repair_with_issues=lambda r, i: r)

    def test_zero_repair_cap_gives_schema_invalid_and_no_second_attempt(self):
        caps = {**profile()["roles"]["investigator"]["caps"], "maxRepairs": 0}
        gw = self.live(script(entry(response=response(output=BAD_INV)), entry(attempt=1, response=response())),
                       prof=profile(investigator={"caps": caps}))
        r = gw.call(*INV, 0, request(), repair=lambda resp: request(text="again"))
        self.assertEqual((r.error["code"], gw.provider.calls), ("schema-invalid", 1))

    def test_recorded_chain_replays_identically_with_nothing_unconsumed(self):
        gw = self.live(script(entry(response=response(output=BAD_INV)), entry(attempt=1, response=response())))
        gw.call(*INV, 0, request(), repair=lambda resp: request(text="again"))
        ev = self.finish(gw)
        rp = self.replayer(ev)
        r = rp.call(*INV, 0, request(), repair=lambda resp: request(text="again"))
        self.assertTrue(r.ok)
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["unconsumedRecordedCalls"], rep["newSpendUsdMicros"]), (2, 0, 0))

    def test_unknown_output_schema_name_is_refused_at_construction(self):
        from reviewer.gateway import gateway as g
        real = g.REGISTRY
        try:
            g.REGISTRY = {k: v for k, v in real.items() if k != "VerifierOutput"}
            with self.assertRaises(GatewayConfigError):
                self.live(script())
        finally:
            g.REGISTRY = real

    def test_every_registered_gateway_output_schema_is_validated_by_contracts(self):
        for name in ("InvestigatorOutput", "VerifierOutput", "JudgeOutput"):
            self.assertIsInstance(validate(name, {}), list)


class D4Guard(Env):
    def test_refusal_before_first_attempt_reserves_nothing_and_never_contacts_the_provider(self):
        gw = self.live(script(entry(response=response())), guard=lambda ctx: GuardRefusal("deadline-exceeded"))
        before = gw.book.totals()
        r = gw.call(*INV, 0, request())
        self.assertEqual(r.error["code"], "deadline-exceeded")
        self.assertEqual(r.error["detail"]["refusedBy"], "host-guard")
        self.assertEqual((gw.provider.calls, gw.live_calls, gw.report()["newSpendUsdMicros"]), (0, 0, 0))
        self.assertEqual(gw.book.totals(), before)
        self.assertEqual(gw.report()["spend"]["reserved"] if "reserved" in (gw.report()["spend"] or {}) else 0, 0)
        ev = self.finish(gw)
        m, c = models(ev)[0], costs(ev)[0]
        self.assertEqual((m["error"]["code"], c["usdMicros"], c["reservedUsdMicros"]), ("deadline-exceeded", 0, 0))
        self.assertEqual(error_charge_class(m["error"]), "refused")
        self.assertTrue(load_trace(ev).complete)

    def test_coordinate_is_consumed_by_a_refusal(self):
        refuse = [True]
        gw = self.live(script(entry(response=response())), guard=lambda ctx: "cancelled" if refuse[0] else None)
        gw.call(*INV, 0, request())
        refuse[0] = False
        r = gw.call(*INV, 0, request())
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(gw.provider.calls, 0)

    def test_guard_runs_before_each_retry_and_earlier_attempts_stay_charged(self):
        ctxs = []

        def guard(ctx):
            ctxs.append((ctx.kind, ctx.attempt))
            return GuardRefusal("cancelled") if ctx.kind == "retry" else None
        gw = self.live(script(entry(error=terr("provider-timeout")), entry(attempt=1, response=response())), guard=guard)
        r = gw.call(*INV, 0, request())
        self.assertEqual(r.error["code"], "cancelled")
        self.assertEqual(ctxs, [("first", 0), ("retry", 1)])
        self.assertEqual(gw.provider.calls, 1)
        self.assertEqual([a.charge_usd_micros for a in r.attempts], [RESERVE, 0])
        self.assertEqual(gw.report()["newSpendUsdMicros"], RESERVE)
        self.assertEqual(gw.book.totals()["committed"] + gw.book.totals()["inflight"], RESERVE)
        self.assertTrue(load_trace(self.finish(gw)).complete)

    def test_guard_runs_before_the_repair_and_a_refused_repair_is_not_schema_invalid(self):
        kinds = []

        def guard(ctx):
            kinds.append(ctx.kind)
            return "deadline-exceeded" if ctx.kind == "repair" else None
        gw = self.live(script(entry(response=response(output=BAD_INV)), entry(attempt=1, response=response())), guard=guard)
        r = gw.call(*INV, 0, request(), repair=lambda resp: request(text="again"))
        self.assertEqual((r.error["code"], kinds, gw.provider.calls), ("deadline-exceeded", ["first", "repair"], 1))
        self.assertEqual(gw.report()["newSpendUsdMicros"], r.attempts[0].charge_usd_micros)

    def test_broken_or_odd_guards_fail_closed(self):
        def boom(ctx):
            raise RuntimeError("secret detail")
        for g, fault in ((boom, "RuntimeError"), (lambda ctx: "go-ahead", None), (lambda ctx: 7, None)):
            gw = self.live(script(entry(response=response())), guard=g)
            r = gw.call(*INV, 0, request())
            self.assertEqual((r.error["code"], gw.provider.calls), ("cancelled", 0))
            self.assertEqual(r.error["detail"].get("guardFault"), fault)
            self.assertNotIn("secret", str(r.error))

    def test_non_callable_guard_is_a_config_error(self):
        with self.assertRaises(GatewayConfigError):
            self.live(script(), guard="yes")

    def test_no_guard_changes_nothing(self):
        gw = self.live(script(entry(response=response())), guard=lambda ctx: None)
        self.assertTrue(gw.call(*INV, 0, request()).ok)

    def test_helpers(self):
        t = [0.0]
        ev = threading.Event()
        g = chain_guards(cancel_guard(ev), deadline_guard(10.0, lambda: t[0]))
        self.assertIsNone(g(None))
        t[0] = 10.0
        self.assertEqual(g(None).code, "deadline-exceeded")
        ev.set()
        self.assertEqual(g(None).code, "cancelled")
        with self.assertRaises(ValueError):
            GuardRefusal("budget-exhausted")

    def test_recorded_refusal_is_reproduced_in_strict_replay_at_zero_cost(self):
        n = [0]

        def guard(ctx):
            n[0] += 1
            return GuardRefusal("deadline-exceeded") if n[0] == 2 else None
        gw = self.live(script(entry(response=response())), guard=guard)
        self.assertTrue(gw.call(*INV, 0, request()).ok)
        self.assertEqual(gw.call(*INV, 1, request(text="two")).error["code"], "deadline-exceeded")
        ev = self.finish(gw)
        rp = self.replayer(ev)
        self.assertTrue(rp.call(*INV, 0, request()).ok)
        r = rp.call(*INV, 1, request(text="two"))
        self.assertEqual(r.error["code"], "deadline-exceeded")
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["unconsumedRecordedCalls"], rep["newSpendUsdMicros"]), (2, 0, 0))
        self.assertEqual(r.attempts[0].charge_usd_micros, 0)
        rp.recorder.end("completed")
        self.assertTrue(load_trace(rp.recorder.events).complete)

    def test_replay_guard_refusal_does_not_consume_the_recording(self):
        gw = self.live(script(entry(response=response())))
        gw.call(*INV, 0, request())
        ev = self.finish(gw)
        rp = self.replayer(ev, guard=lambda ctx: GuardRefusal("cancelled"))
        r = rp.call(*INV, 0, request())
        self.assertEqual(r.error["code"], "cancelled")
        self.assertEqual(rp.report()["unconsumedRecordedCalls"], 1)
        self.assertEqual(rp.report()["replayedCalls"], 0)


class NEW1ReservedAdapterCodes(Env):
    RESERVED = ("budget-exhausted", "deadline-exceeded", "cancelled", "replay-miss", "replay-mismatch", "schema-invalid",
                "repair-exhausted", "contract-violation", "model-unresolved", "internal", "tool-denied")

    def test_every_reserved_code_is_normalized_charged_loadable_and_replayable(self):
        for code in self.RESERVED:
            with self.subTest(code=code):
                gw = self.live(script(entry(error=terr(code, False, scope="run", refusedBy="host-guard",
                                                       resolvedModel="x", providerOutcome="processed"))))
                r = gw.call(*INV, 0, request())
                self.assertEqual(r.error["code"], "provider-error")
                self.assertFalse(r.error["retryable"])
                self.assertEqual(r.error["detail"]["adapterCode"], code)
                for k in ("scope", "refusedBy", "resolvedModel"):
                    self.assertNotIn(k, r.error["detail"])
                self.assertEqual(r.attempts[0].charge_usd_micros, RESERVE)
                ev = self.finish(gw)
                self.assertEqual(error_charge_class(models(ev)[0]["error"]), "retained")
                rp = self.replayer(ev)
                rr = rp.call(*INV, 0, request())
                self.assertEqual(rr.error, r.error)
                self.assertEqual(rp.report()["unconsumedRecordedCalls"], 0)

    def test_adapter_codes_pass_through(self):
        for code in ("provider-error", "provider-timeout", "live-calls-disabled"):
            gw = self.live(script(entry(error=terr(code, False))))
            self.assertEqual(gw.call(*INV, 0, request()).error["code"], code)

    def test_released_outcome_of_a_normalized_error_still_releases(self):
        gw = self.live(script(entry(error=terr("budget-exhausted", False, outcome="not-sent"))))
        r = gw.call(*INV, 0, request())
        self.assertEqual(r.error["code"], "provider-error")      # synthetic honours outcome only for provider-error
        self.assertTrue(load_trace(self.finish(gw)).complete)

    def test_provider_error_with_a_guard_code_and_no_marker_stays_retained_in_old_traces(self):
        err = {"code": "deadline-exceeded", "message": "x", "retryable": False, "detail": {"providerOutcome": "unknown"}}
        self.assertEqual(error_charge_class(err), "retained")
        err["detail"]["refusedBy"] = "host-guard"
        self.assertEqual(error_charge_class(err), "refused")


class CostKindAndSpend(Env):
    def test_judge_wording_books_the_same_cost_kind_as_the_other_production_roles(self):
        entries = [entry(response=response()),
                   entry(stage="VERIFY", role="verifier", agent="verifier", response=response(output=verifier_out("refuted"))),
                   entry(stage="JUDGE", role="judge", agent="judge", response=response(output={"comments": []}))]
        gw = self.live(script(*entries))
        gw.call(*INV, 0, request())
        gw.call(*VER, 0, request("verifier"))
        gw.call("JUDGE", "judge", "judge", 0, request("judge"))
        kinds = {c["role"]: c["kind"] for c in costs(self.finish(gw))}
        self.assertEqual(set(kinds), {"investigator", "verifier", "judge"})
        self.assertEqual(len(set(kinds.values())), 1)

    def test_the_spend_book_is_kind_blind_so_every_kind_counts_toward_the_one_total(self):
        import inspect
        self.assertNotIn("kind", inspect.signature(SpendBook.reserve).parameters)


if __name__ == "__main__":
    unittest.main()
