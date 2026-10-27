"""SCORE-GW-02 independent acceptance of the score-family gateway (scratch candidate of SCORE-GW-01).

Real Gateway/Recorder/LoadedTrace/Ledger/SpendBook composition with invented fixtures and fake providers.
Tests state the REQUIRED behaviour. A failing test in a `Repro*` class is a retained defect repro, never an xfail."""

from __future__ import annotations

import copy
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import ContractViolation, validate_score_trace  # noqa: E402
from reviewer.contracts.budget import STANDARD_S0A_BUDGET  # noqa: E402
from reviewer.contracts.canonical import score_run_id  # noqa: E402
from reviewer.gateway import (AuthorizationError, Gateway, GatewayConfigError, Recorder, TraceError,  # noqa: E402
                              bytes_digest, events_to_bytes, load_trace)
from reviewer.gateway.providers import ProviderResult  # noqa: E402
from tests.score_gateway_review import support as S  # noqa: E402
from tests.score_gateway_review.support import Fake, terr  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = self._t.name

    def call(self, gw, role="matcher", ordinal=0, req=None, agent="s1"):
        return gw.call(S.STAGE[role], role, agent, ordinal, req or S.request(role))

    def assertScoreTraceClean(self, rec):
        self.assertEqual(validate_score_trace(rec.events), [])

    def no_stage(self, rec):
        for ev in rec.events:
            if ev["type"] == "error":
                self.assertNotIn("stage", ev["error"])
            if ev["type"] == "score.model.call" and ev.get("error"):
                self.assertNotIn("stage", ev["error"])
            if ev["type"] == "cost":
                self.assertNotIn("stage", ev["record"])
                self.assertEqual(ev["record"]["kind"], "score")


# --------------------------------------------------------------------------------------------- pairings
class Pairings(Base):
    def test_only_the_three_score_stage_role_pairs_run(self):
        for stage in ("EXTRACT", "DEDUP", "MATCH", "INVESTIGATE", "JUDGE"):
            for role in S.ROLES + ("investigator", "judge"):
                p = Fake()
                gw, rec, _ = S.live(self.tmp, p)
                ok = role in S.STAGE and S.STAGE[role] == stage
                if ok:
                    self.assertTrue(gw.call(stage, role, "s1", 0, S.request(role)).ok, (stage, role))
                else:
                    with self.assertRaises(ValueError, msg=(stage, role)):
                        gw.call(stage, role, "s1", 0, S.request("matcher"))
                    self.assertEqual((p.calls, len(rec.events)), (0, 1), (stage, role))

    def test_request_role_and_schema_must_match_call_role_before_provider(self):
        for call_role in S.ROLES:
            for other in S.ROLES:
                if other == call_role:
                    continue
                p = Fake()
                gw, rec, _ = S.live(self.tmp, p)
                r = self.call(gw, call_role, req=S.request(other))
                self.assertEqual(r.error["code"], "contract-violation", (call_role, other))
                self.assertEqual(p.calls, 0)
                # a cross-schema request for the right role
                r = self.call(gw, call_role, 1, S.request(call_role, outputSchema=S.SCHEMA[other]))
                self.assertEqual(r.error["code"], "contract-violation")
                self.assertEqual(p.calls, 0)
                self.no_stage(rec)
                self.assertScoreTraceClean(rec)

    def test_profile_provider_model_prompt_bindings_refused(self):
        for over in ({"provider": "openai"}, {"model": "anthropic/claude-sonnet-5.5"}, {"promptVersion": "bench.other@v9"},
                     {"profile": "score-invented@2"}, {"profile": "smoke-synthetic@1"}):
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            r = self.call(gw, req=S.request(**over))
            self.assertIsNotNone(r.error, over)
            self.assertEqual(p.calls, 0, over)
            self.assertNotIn("stage", r.error)

    def test_family_profile_documents_are_not_interchangeable(self):
        review = json.loads((S.EX / "ModelProfile.smoke-synthetic.json").read_text())
        h = S.auth_handle(self.tmp)
        rid = score_run_id(S.EVR, S.CASE, 0)
        with self.assertRaises(ContractViolation):
            Gateway(mode="live", profile=review, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                    providers={"anthropic": Fake()}, authorization=h, book=S.SpendBook(h), clock=S.NOW,
                    eval_run_id=S.EVR, eval_case_id=S.CASE, repeat=0)
        with self.assertRaises(ContractViolation):
            Gateway(mode="disabled", profile=S.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id="run_" + "1" * 16)

    def test_wrongly_shaped_output_is_a_typed_failure_with_one_provider_call(self):
        for role in S.ROLES:
            for other in S.ROLES:
                if other == role:
                    continue
                p = Fake(lambda q, k, o=other: ProviderResult(S.response(q["role"], output=S.OUT[o]), None, "processed"))
                gw, rec, _ = S.live(self.tmp, p)
                r = self.call(gw, role)
                self.assertEqual(r.error["code"], "schema-invalid", (role, other))
                self.assertEqual(p.calls, 1)
                self.no_stage(rec)
                self.assertScoreTraceClean(rec)

    def test_review_gateway_refuses_score_documents_and_keeps_stage_on_errors(self):
        from tests.gateway import helpers as RH
        h = RH.trusted_authorization.__module__ and None  # noqa: F841 (import check only)
        gw = Gateway(mode="disabled", profile=RH.PROFILE, budget=dict(RH.BUDGET), run_id="run_" + "2" * 16)
        r = gw.call("INVESTIGATE", "investigator", "g", 0, S.request("matcher"))
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(r.error.get("stage"), "INVESTIGATE")          # legacy review errors still carry the Stage
        with self.assertRaises(ValueError):
            gw.call("MATCH", "matcher", "g", 0, S.request("matcher"))


# --------------------------------------------------------------------------------------------- binding
class Binding(Base):
    def test_recorder_run_start_mismatches_refused_at_construction(self):
        h = S.auth_handle(self.tmp)
        cases = {
            "other eval run": dict(evr=S.EVR2),
            "other case": dict(case="u901-t01"),
            "other repeat": dict(repeat=1),
            "other profile": dict(profile="score-invented@2"),
            "other auth": dict(digest="sha256:" + "0" * 64),
            "replay mode": dict(mode="strict-replay"),
        }
        for name, kw in cases.items():
            rid = score_run_id(S.EVR, S.CASE, 0)
            rec = Recorder(rid, family="score")
            doc = S.run_doc(kw.pop("mode", "live"), kw.pop("evr", S.EVR), kw.pop("case", S.CASE), kw.pop("repeat", 0),
                            kw.pop("digest", h.digest) if True else None, **{k: v for k, v in kw.items()})
            if doc["mode"] == "strict-replay":
                doc["replayOf"] = "run_" + "3" * 16
            else:
                doc["id"] = doc["id"]
            try:
                rec.append("run.start", run=doc)
            except Exception:
                # the document itself is not a valid run for this recorder id; still must not construct a gateway
                pass
            if not rec.events:
                continue
            with self.assertRaises((GatewayConfigError, AuthorizationError), msg=name):
                Gateway(mode="live", profile=S.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                        providers={"anthropic": Fake()}, authorization=h, book=S.SpendBook(h), recorder=rec,
                        eval_run_id=S.EVR, eval_case_id=S.CASE, repeat=0, clock=S.NOW)

    def test_late_bad_run_start_refuses_every_call_without_writing(self):
        p = Fake()
        gw, rec, h = S.live(self.tmp, p, start=False)
        rec.start(S.run_doc("live", digest="sha256:" + "0" * 64))
        before = len(rec.events)
        r = self.call(gw)
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual((p.calls, len(rec.events)), (0, before))

    def test_recorder_of_other_family_or_run_refused(self):
        h = S.auth_handle(self.tmp)
        rid = score_run_id(S.EVR, S.CASE, 0)
        for rec in (Recorder(rid), Recorder(score_run_id(S.EVR2, S.CASE, 0), family="score")):
            with self.assertRaises(GatewayConfigError):
                Gateway(mode="live", profile=S.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                        providers={"anthropic": Fake()}, authorization=h, book=S.SpendBook(h), recorder=rec,
                        eval_run_id=S.EVR, eval_case_id=S.CASE, repeat=0, clock=S.NOW)
        with self.assertRaises(GatewayConfigError):       # a score recorder on a review gateway
            from tests.gateway import helpers as RH
            Gateway(mode="disabled", profile=RH.PROFILE, budget=dict(RH.BUDGET), run_id=rid,
                    recorder=Recorder(rid, family="score"))

    def test_identity_and_authorization_bindings(self):
        h = S.auth_handle(self.tmp)
        rid = score_run_id(S.EVR, S.CASE, 0)
        def mk(**o):
            kw = dict(mode="live", profile=S.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                      providers={"anthropic": Fake()}, authorization=h, book=S.SpendBook(h), eval_run_id=S.EVR,
                      eval_case_id=S.CASE, repeat=0, clock=S.NOW)
            kw.update(o)
            return Gateway(**kw)
        mk()
        for name, o in {"run id not derived": dict(run_id=score_run_id(S.EVR2, S.CASE, 0)),
                        "repeat bool": dict(repeat=True), "repeat missing": dict(repeat=None),
                        "bad eval id": dict(eval_run_id="nope", run_id=rid), "no eval case": dict(eval_case_id=None),
                        "review cost kind": dict(cost_kind="review"), "eval cost kind": dict(cost_kind="eval"),
                        "synthetic cost kind": dict(cost_kind="synthetic")}.items():
            with self.assertRaises(GatewayConfigError, msg=name):
                mk(**o)
        for name, doc in {"model not authorized": dict(S.AUTH, models=["anthropic/claude-sonnet-5.5"]),
                          "provider not authorized": dict(S.AUTH, providers=["openai"]),
                          "expired": dict(S.AUTH, expiresAt="2020-01-01T00:00:00Z"),
                          "per-run below plan": dict(S.AUTH, maxUsdMicrosPerRun=100)}.items():
            h2 = S.auth_handle(self.tmp, doc)
            with self.assertRaises(AuthorizationError, msg=name):
                mk(authorization=h2, book=S.SpendBook(h2))
        with self.assertRaises(GatewayConfigError):        # review gateway cannot take score costs or repeat
            from tests.gateway import helpers as RH
            Gateway(mode="disabled", profile=RH.PROFILE, budget=dict(RH.BUDGET), run_id="run_" + "4" * 16,
                    cost_kind="score")
        with self.assertRaises(GatewayConfigError):
            from tests.gateway import helpers as RH
            Gateway(mode="disabled", profile=RH.PROFILE, budget=dict(RH.BUDGET), run_id="run_" + "4" * 16, repeat=0)

    def test_request_hash_binds_exact_bytes_and_each_mutation_misses_replay(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        mutations = {"text": S.request(text="gold g1 vs candidate c1 "),
                     "message order": S.request(messages=list(reversed(S.request()["messages"]))),
                     "params": S.request(params=S.params(temperature=0.5)),
                     "extra system": S.request(messages=S.request()["messages"] + [
                         {"role": "assistant", "content": "x"}])}
        rg, _ = S.replay(tr)
        for name, req in mutations.items():
            r = self.call(rg, req=req)
            self.assertIn(r.error and r.error["code"], ("replay-miss", "replay-mismatch"), name)
        self.assertEqual(rg.report()["liveCalls"], 0)
        self.assertEqual(rg.unconsumed(), 3)


# --------------------------------------------------------------------------------------------- params
class Params(Base):
    def test_legitimate_params_still_accepted(self):
        for extra in ({}, {"temperature": 0}, {"timeoutSec": 120}, {"maxOutputTokens": 100}):
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            self.assertTrue(self.call(gw, req=S.request(params=S.params(**extra))).ok, extra)

    def test_known_hidden_keys_refused_before_provider_any_depth_any_case(self):
        for k in ("tools", "tool_choice", "toolChoice", "TOOLS", "mcp_servers", "functions", "function_call", "provider",
                  "route", "models", "fallbacks", "allow_fallbacks", "extra_body", "base_url", "api-key", "headers"):
            for shape in (lambda v: {k: v}, lambda v: {"x": {"y": [{k: v}]}}):
                p = Fake()
                gw, rec, _ = S.live(self.tmp, p)
                r = self.call(gw, req=S.request(params=S.params(**shape(S.SENT))))
                self.assertIsNotNone(r.error, k)
                self.assertEqual(p.calls, 0, k)
                self.assertNotIn("stage", r.error)
                self.assertNotIn(S.SENT, json.dumps(r.error))      # no echo of the offending content

    def test_pathological_nesting_fails_closed(self):
        deep = cur = {}
        for _ in range(40):
            cur["n"] = {}
            cur = cur["n"]
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p)
        self.assertIsNotNone(self.call(gw, req=S.request(params=S.params(deep=deep))).error)
        self.assertEqual(p.calls, 0)

    def test_tools_and_tool_messages_refused_before_provider(self):
        for over in ({"tools": [{"name": "t", "description": "d", "parameters": {}}]},
                     {"messages": [{"role": "user", "content": "x"}, {"role": "tool", "content": "y"}]}):
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            r = self.call(gw, req=S.request(**over))
            self.assertEqual((r.error["code"], p.calls), ("contract-violation", 0))
            self.assertNotIn("stage", r.error)
            self.assertScoreTraceClean(rec)

    def test_output_token_cap_still_enforced(self):
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p)
        r = self.call(gw, req=S.request(params=S.params(maxOutputTokens=10**6)))
        self.assertIsNotNone(r.error)
        self.assertEqual(p.calls, 0)


class ReproParams(Base):
    """Retained failing repros (see handoff): required behaviour that the candidate does not meet."""

    def test_REPRO_B1_params_timeout_above_profile_cap_refused_before_provider(self):
        cap = S.PROFILE["roles"]["matcher"]["caps"]["timeoutSec"]
        for bad in (cap + 1, 3600, 10**6):
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            r = self.call(gw, req=S.request(params=S.params(timeoutSec=bad)))
            self.assertIsNotNone(r.error, f"params.timeoutSec={bad} > caps.timeoutSec={cap} reached the provider")
            self.assertEqual(p.calls, 0)

    def test_REPRO_N1_routing_like_param_keys_beyond_the_denylist(self):
        keys = ("provider_order", "providerOrder", "provider_options", "providerOptions", "provider_preferences",
                "openrouter", "extra_headers", "api_base", "endpoint", "max_price", "tool_resources", "mcp")
        bypass = []
        for k in keys:
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            self.call(gw, req=S.request(params=S.params(**{k: "x"})))
            if p.calls:
                bypass.append(k)
        self.assertEqual(bypass, [], "routing-like params reached the provider")

    def test_REPRO_N2_params_may_not_differ_from_the_trusted_profile_role_params(self):
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p)
        r = self.call(gw, req=S.request(params=S.params(temperature=1)))
        self.assertIsNotNone(r.error, "ARCH-02 s7: any difference in settings is a mismatch refusal")
        self.assertEqual(p.calls, 0)


# --------------------------------------------------------------------------------------------- costs / errors
class CostsAndErrors(Base):
    def test_live_cost_shape_all_roles(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        costs = [e["record"] for e in rec.events if e["type"] == "cost"]
        self.assertEqual(len(costs), 3)
        for c in costs:
            self.assertEqual((c["kind"], c["evalRunId"], c["evalCaseId"], c["runId"]),
                             ("score", S.EVR, S.CASE, score_run_id(S.EVR, S.CASE, 0)))
            self.assertNotIn("stage", c)
        self.no_stage(rec)
        self.assertScoreTraceClean(rec)
        self.assertEqual(tr.family, "score")
        self.assertEqual(tr.model_calls, 3)

    def test_run_ceiling_refusal_is_stageless_zero_cost_and_never_contacts_provider(self):
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p, ceiling=100)
        r = self.call(gw)
        self.assertEqual(r.error["code"], "budget-exhausted")
        self.assertNotIn("stage", r.error)
        self.assertEqual(p.calls, 0)
        self.no_stage(rec)
        self.assertScoreTraceClean(rec)
        costs = [e["record"] for e in rec.events if e["type"] == "cost"]
        self.assertTrue(costs and all(c["usdMicros"] == 0 for c in costs))

    def test_total_book_refusal_is_stageless(self):
        doc = dict(S.AUTH, maxUsdMicrosTotal=1000)
        try:
            gw, rec, _ = S.live(self.tmp, Fake(), auth_doc=doc)
        except Exception as e:          # an authorization that cannot admit the plan is itself a refusal
            self.assertIsInstance(e, (AuthorizationError, GatewayConfigError, ContractViolation))
            return
        r = self.call(gw)
        self.assertEqual(r.error["code"], "budget-exhausted")
        self.assertNotIn("stage", r.error)
        self.no_stage(rec)
        self.assertScoreTraceClean(rec)

    def test_unknown_outcome_retains_exposure_and_blocks_later_admission(self):
        p = Fake(lambda q, k: ProviderResult(None, terr("provider-timeout", True), "unknown"))
        gw, rec, _ = S.live(self.tmp, p, ceiling=10_000)
        r1 = self.call(gw, ordinal=0)
        self.assertEqual(r1.error["code"], "provider-timeout")
        self.assertEqual(len(gw.retained), 1)
        r2 = self.call(gw, ordinal=1)
        self.assertEqual(r2.error["code"], "budget-exhausted")        # the unknown reservation stays committed
        self.assertEqual(p.calls, 1)
        self.no_stage(rec)
        self.assertScoreTraceClean(rec)
        costs = [e["record"] for e in rec.events if e["type"] == "cost"]
        self.assertEqual(costs[0]["usdMicros"], costs[0]["reservedUsdMicros"])      # full reservation, not zero
        self.assertEqual(gw.report()["newSpendUsdMicros"], costs[0]["usdMicros"])

    def test_released_outcome_frees_exposure(self):
        n = []
        def fn(q, k):
            n.append(1)
            return ProviderResult(None, terr("provider-error", False, outcome="not-sent"), "not-sent")
        gw, rec, _ = S.live(self.tmp, Fake(fn), ceiling=10_000)
        for i in range(3):
            self.assertEqual(self.call(gw, ordinal=i).error["code"], "provider-error")
        self.assertEqual((len(n), gw.retained, gw.report()["newSpendUsdMicros"]), (3, [], 0))
        self.assertScoreTraceClean(rec)

    def test_adapter_exception_and_non_result_are_retained_typed_errors(self):
        for fn in (lambda q, k: (_ for _ in ()).throw(RuntimeError("boom " + S.SENT)), lambda q, k: "garbage",
                   lambda q, k: ProviderResult({"nonsense": 1}, None, "processed")):
            gw, rec, _ = S.live(self.tmp, Fake(fn))
            r = self.call(gw)
            self.assertIsNotNone(r.error)
            self.assertNotIn(S.SENT, json.dumps(r.error))
            self.assertEqual(len(gw.retained), 1)
            self.no_stage(rec)
            self.assertScoreTraceClean(rec)

    def test_adapter_cannot_forge_gateway_owned_codes_or_free_charge(self):
        for code in ("budget-exhausted", "cancelled", "replay-miss", "contract-violation", "live-calls-disabled"):
            e = terr(code, False, refusedBy="host-guard", providerOutcome="not-sent", outcome="not-sent")
            gw, rec, _ = S.live(self.tmp, Fake(lambda q, k, e=e: ProviderResult(None, e, "unknown")))
            r = self.call(gw)
            costs = [x["record"] for x in rec.events if x["type"] == "cost"]
            self.assertEqual(len(gw.retained) + (1 if code == "live-calls-disabled" else 0) >= 1, True, code)
            self.assertTrue(all(c["usdMicros"] != 0 for c in costs), code)    # unknown outcome is never free
            self.assertScoreTraceClean(rec)

    def test_wrong_model_answer_is_billed_error_and_replays_identically(self):
        p = Fake(lambda q, k: ProviderResult(S.response(q["role"], resolvedModel="anthropic/other"), None, "processed"))
        gw, rec, _ = S.live(self.tmp, p)
        r = self.call(gw)
        self.assertEqual(r.error["code"], "contract-violation")
        tr = S.finish(rec)
        rg, rrec = S.replay(tr)
        r2 = self.call(rg)
        self.assertEqual(r2.error, r.error)
        c = [e["record"] for e in rrec.events if e["type"] == "cost"][0]
        self.assertEqual((c["basis"], rg.report()["liveCalls"], rg.report()["newSpendUsdMicros"]), ("replayed", 0, 0))
        self.assertGreater(rg.report()["replayedUsdMicros"], 0)

    def test_recorders_refuse_the_other_family_cost_for_every_kind(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        score_cost = [e["record"] for e in rec.events if e["type"] == "cost"][0]
        sr = Recorder(score_run_id(S.EVR2, S.CASE, 0), family="score")
        for kind in ("review", "eval", "synthetic", "canary", None, 7):
            bad = {**score_cost, "kind": kind}
            with self.assertRaises((TraceError, ContractViolation), msg=kind):
                sr.append("cost", record=bad)
        rr = Recorder("run_" + "5" * 16)
        with self.assertRaises((TraceError, ContractViolation)):
            rr.append("cost", record=score_cost)
        self.assertEqual(sr.events, [])
        self.assertEqual(rr.events, [])

    def test_guard_refusal_is_free_stageless_live_and_replayed(self):
        calls = []
        def guard(ctx):
            calls.append(ctx)
            return ("deadline", "wall-clock deadline reached") if ctx.ordinal == 1 else None
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p, guard=guard)
        self.assertTrue(self.call(gw, ordinal=0).ok)
        r = self.call(gw, ordinal=1)
        self.assertIsNotNone(r.error)
        self.assertNotIn("stage", r.error)
        self.assertEqual(p.calls, 1)
        self.assertEqual(gw.report()["newSpendUsdMicros"], [e["record"] for e in rec.events if e["type"] == "cost"][0]["usdMicros"])
        self.no_stage(rec)
        tr = S.finish(rec)
        rg, rrec = S.replay(tr)
        self.assertTrue(self.call(rg, ordinal=0).ok)
        self.assertEqual(self.call(rg, ordinal=1).error["code"], r.error["code"])
        self.assertEqual((rg.report()["liveCalls"], rg.report()["newSpendUsdMicros"]), (0, 0))
        self.assertScoreTraceClean(rrec)


class ReproErrors(Base):
    def test_REPRO_B3_adapter_error_carrying_a_review_stage_must_not_crash_or_lose_the_charge(self):
        e = terr()
        e["stage"] = "JUDGE"                  # a valid REVIEW stage on an adapter-owned error document
        gw, rec, _ = S.live(self.tmp, Fake(lambda q, k: ProviderResult(None, e, "unknown")))
        r = self.call(gw)                     # must return a typed error, never raise
        self.assertIsNotNone(r.error)
        self.assertNotIn("stage", r.error)
        self.assertEqual(len([x for x in rec.events if x["type"] == "score.model.call"]), 1,
                         "an unknown-outcome call was retained but never recorded")
        self.assertScoreTraceClean(rec)


# --------------------------------------------------------------------------------------------- diagnostics
class Diagnostics(Base):
    BAD_OUTPUTS = {"matcher": [{"match": S.SENT, "confidence": 0.5}, {"match": True, "confidence": S.SENT},
                               {"match": True, "confidence": 0.5, S.SENT: 1}, {S.SENT: S.SENT}],
                   "deduper": [{"groups": [[S.SENT]]}, {"groups": S.SENT}, {S.SENT: []}],
                   "extractor": [{"candidates": [{"sourceCommentId": 1, "text": S.SENT, S.SENT: 1}]},
                                 {"candidates": [{S.SENT: "x"}]}, {S.SENT: 1}]}

    def test_malformed_output_never_raises_and_is_one_provider_call(self):
        for role, outs in self.BAD_OUTPUTS.items():
            for out in outs:
                p = Fake(lambda q, k, o=out: ProviderResult(S.response(q["role"], output=o), None, "processed"))
                gw, rec, _ = S.live(self.tmp, p)
                r = self.call(gw, role)
                self.assertEqual((r.error["code"], p.calls), ("schema-invalid", 1), (role, out))
                self.assertScoreTraceClean(rec)

    def test_REPRO_B2_model_written_text_not_copied_into_public_errors(self):
        leaks = []
        for role, outs in self.BAD_OUTPUTS.items():
            for out in outs:
                p = Fake(lambda q, k, o=out: ProviderResult(S.response(q["role"], output=o), None, "processed"))
                gw, rec, _ = S.live(self.tmp, p)
                r = self.call(gw, role)
                public = json.dumps([r.error, [a.schema_issues for a in r.attempts], gw.report()], default=str)
                if S.SENT in public:
                    leaks.append((role, sorted(out)[:1]))
        self.assertEqual(leaks, [], "validator output echoed model-written keys/values into the public error")

    def test_sentinel_only_in_trusted_trace_for_ok_and_invalid_outputs(self):
        gw, rec, _ = S.live(self.tmp, Fake(lambda q, k: ProviderResult(
            S.response("extractor", output={"candidates": [{"sourceCommentId": "c1", "text": S.SENT}]},
                       rawText=S.SENT), None, "processed")))
        r = self.call(gw, "extractor")
        self.assertTrue(r.ok)
        self.assertNotIn(S.SENT, json.dumps(gw.report()))
        self.assertIn(S.SENT, json.dumps(rec.events))                  # trusted trace keeps it

    def test_request_refusals_never_echo_request_content(self):
        for req in (S.request(text=S.SENT, tools=[{"x": S.SENT}]), S.request(params=S.params(tools=S.SENT)),
                    S.request(messages=[{"role": "tool", "content": S.SENT}]), {"x": S.SENT},
                    S.request(outputSchema=S.SENT), {**S.request(), "role": S.SENT}):
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            r = gw.call("MATCH", "matcher", "s1", 0, req)
            self.assertIsNotNone(r.error)
            self.assertEqual(p.calls, 0)
            self.assertNotIn(S.SENT, json.dumps(r.error))
            self.assertNotIn(S.SENT, json.dumps(gw.report()))


# --------------------------------------------------------------------------------------------- strict replay
class _NoNet:
    """Fail-on-contact: any socket connect or provider construction during replay fails the test."""
    def __enter__(self):
        import reviewer.gateway.gateway as g
        self._c, self._d = socket.socket.connect, g.default_providers
        def boom(*a, **k):
            raise AssertionError("network/provider contact during strict replay")
        socket.socket.connect = boom
        g.default_providers = boom
        return self

    def __exit__(self, *a):
        import reviewer.gateway.gateway as g
        socket.socket.connect, g.default_providers = self._c, self._d


class Replay(Base):
    def test_full_replay_zero_provider_zero_spend_replayed_basis_fresh_ids(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        with _NoNet():
            rg, rrec = S.replay(tr)
            for r in S.ROLES:
                self.assertTrue(self.call(rg, r).ok)
        rep = rg.report()
        self.assertEqual((rep["liveCalls"], rep["newSpendUsdMicros"], rep["replayedCalls"], rep["unconsumedRecordedCalls"]),
                         (0, 0, 3, 0))
        self.assertEqual(rep["replayedUsdMicros"], gw.report()["newSpendUsdMicros"])
        self.assertNotEqual(rg.run_id, gw.run_id)
        run = rrec.events[0]["run"]
        self.assertEqual((run["mode"], run["replayOf"]), ("strict-replay", gw.run_id))
        self.assertNotIn("spendAuthorization", run)
        for e in rrec.events:
            if e["type"] == "cost":
                c = e["record"]
                self.assertEqual((c["basis"], c["kind"], c["runId"], c["evalRunId"]), ("replayed", "score", rg.run_id, S.EVR2))
                self.assertIn("replayOf", c)
        self.assertScoreTraceClean(rrec)
        rl = S.finish(rrec)                       # a replay trace itself loads, family score
        self.assertEqual(rl.family, "score")

    def test_replay_constructor_bindings(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        def mk(**o):
            return S.replay(tr, **o)
        mk()
        for name, o in {"same eval run": dict(evr=S.EVR), "other case": dict(case="u901-t01"),
                        "other repeat": dict(repeat=1)}.items():
            with self.assertRaises(GatewayConfigError, msg=name):
                mk(**o)
        other_profile = copy.deepcopy(S.PROFILE)
        other_profile["version"] = S.PROFILE["version"] + 1
        rid = score_run_id(S.EVR2, S.CASE, 0)
        with self.assertRaises((GatewayConfigError, ContractViolation)):
            Gateway(mode="strict-replay", profile=other_profile, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                    family="score", replay=tr, eval_run_id=S.EVR2, eval_case_id=S.CASE, repeat=0,
                    expected_trace_digest=tr.byte_digest)
        for kw in ({"providers": {"anthropic": Fake()}}, {"authorization": S.auth_handle(self.tmp)}):
            with self.assertRaises(GatewayConfigError):
                mk(**kw)
        with self.assertRaises(GatewayConfigError):       # missing / wrong-shape pin
            mk(digest="nope")
        with self.assertRaises(TraceError):
            mk(digest="sha256:" + "0" * 64)

    def test_review_trace_cannot_replay_in_score_gateway_nor_back(self):
        from tests.score_gateway_review.review_scenarios import review_live_trace
        rv = review_live_trace(self.tmp)
        with self.assertRaises(GatewayConfigError):
            S.replay(rv)
        gw, rec, tr = S.three_role_trace(self.tmp)
        from tests.gateway import helpers as RH
        rid = "run_" + "6" * 16
        with self.assertRaises(GatewayConfigError):          # a score recording in a review strict replay
            Gateway(mode="strict-replay", profile=RH.PROFILE, budget=dict(RH.BUDGET), run_id=rid, replay=tr,
                    expected_trace_digest=tr.byte_digest)

    def test_recorder_start_must_be_a_valid_replay_of_the_recorded_run(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        for name, over in {"wrong replayOf": dict(replay_of="run_" + "9" * 16),
                           "other inputDigest": dict(replay_of=tr.run_id, inputDigest="sha256:" + "1" * 64),
                           "other profile": dict(replay_of=tr.run_id, profile="score-invented@2")}.items():
            rid = score_run_id(S.EVR2, S.CASE, 0)
            rr = Recorder(rid, family="score")
            gwr = Gateway(mode="strict-replay", profile=S.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                          family="score", replay=tr, recorder=rr, eval_run_id=S.EVR2, eval_case_id=S.CASE, repeat=0,
                          expected_trace_digest=tr.byte_digest)
            doc = S.run_doc("strict-replay", S.EVR2, S.CASE, 0, **over)
            try:
                rr.start(doc)
            except Exception:
                continue            # an invalid document cannot even be recorded
            n = len(rr.events)
            r = self.call(gwr)
            self.assertIsNotNone(r.error, name)
            self.assertEqual(len(rr.events), n, name)
            self.assertEqual(gwr.report()["replayedCalls"], 0, name)

    def test_identical_requests_replay_by_call_identity_and_each_only_once(self):
        gw, rec, _ = S.live(self.tmp, Fake())
        for i in range(3):
            self.assertTrue(self.call(gw, ordinal=i).ok)
        gw.call("MATCH", "matcher", "other", 0, S.request())
        tr = S.finish(rec)
        rg, _ = S.replay(tr)
        self.assertTrue(self.call(rg, ordinal=2).ok)                   # out of order is fine
        self.assertTrue(self.call(rg, ordinal=0).ok)
        self.assertEqual(self.call(rg, ordinal=0).error["code"], "replay-mismatch")    # consumed; others are other identities
        self.assertEqual(rg.unconsumed(), 2)
        self.assertEqual(self.call(rg, ordinal=7).error["code"], "replay-mismatch")
        self.assertEqual(rg.unconsumed(), 2)                           # a mismatch consumes nothing
        self.assertEqual(rg.report()["liveCalls"], 0)

    def test_replayed_unknown_outcome_stays_retained_with_no_new_spend(self):
        p = Fake(lambda q, k: ProviderResult(None, terr("provider-timeout", True), "unknown"))
        gw, rec, _ = S.live(self.tmp, p)
        self.call(gw)
        tr = S.finish(rec, "failed")
        live_cost = [e["record"] for e in rec.events if e["type"] == "cost"][0]
        rg, rrec = S.replay(tr)
        r = self.call(rg)
        self.assertEqual(r.error["code"], "provider-timeout")
        rep = rg.report()
        self.assertEqual((rep["liveCalls"], rep["newSpendUsdMicros"], len(rep["retainedCalls"])), (0, 0, 1))
        self.assertEqual(rep["replayedUsdMicros"], live_cost["usdMicros"])
        c = [e["record"] for e in rrec.events if e["type"] == "cost"][0]
        self.assertEqual((c["basis"], c["usdMicros"]), ("replayed", live_cost["usdMicros"]))
        self.assertScoreTraceClean(rrec)

    def test_replay_of_released_budget_and_guard_and_malformed_outputs(self):
        def fn(q, k):
            return {0: ProviderResult(None, terr("provider-error", False, outcome="not-sent"), "not-sent"),
                    1: ProviderResult(S.response(q["role"], output={"match": "no"}), None, "processed")}[k[3]]
        gw, rec, _ = S.live(self.tmp, Fake(fn), ceiling=10_000)
        e0 = self.call(gw, ordinal=0).error
        e1 = self.call(gw, ordinal=1).error
        tr = S.finish(rec, "failed")
        rg, rrec = S.replay(tr, budget=None) if False else S.replay(tr)
        with _NoNet():
            self.assertEqual(self.call(rg, ordinal=0).error, e0)
            self.assertEqual(self.call(rg, ordinal=1).error, e1)
        self.assertEqual((rg.report()["newSpendUsdMicros"], rg.report()["liveCalls"]), (0, 0))
        self.assertEqual(rg.report()["replayedUsdMicros"], gw.report()["newSpendUsdMicros"])
        self.assertScoreTraceClean(rrec)

    def test_replay_refuses_partial_recordings_and_mutated_loaded_traces(self):
        gw, rec, _ = S.live(self.tmp, Fake())
        self.call(gw)
        part = load_trace(list(rec.events), allow_partial=True)
        self.assertFalse(part.complete)
        with self.assertRaises(GatewayConfigError):
            S.replay(part)
        tr = S.finish(rec)
        tr.events[1]["response"]["output"]["confidence"] = 0.9
        self.assertTrue(tr.mutated())
        with self.assertRaises(TraceError):
            S.replay(tr)


# --------------------------------------------------------------------------------------------- trace files
def _paths(obj, prefix=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield prefix + (k,)
            yield from _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield prefix + (i,)
            yield from _paths(v, prefix + (i,))


def _set(root, path, val, delete=False):
    cur = root
    for k in path[:-1]:
        cur = cur[k]
    if delete:
        if isinstance(cur, dict):
            del cur[path[-1]]
        else:
            cur.pop(path[-1])
    else:
        cur[path[-1]] = val


class TraceFiles(Base):
    def good(self):
        p = Path(self.tmp) / "live.jsonl"
        gw, rec, _ = S.live(self.tmp, Fake(), path=str(p))
        for r in S.ROLES:
            self.call(gw, r)
        rec.end("completed")
        return p, p.read_bytes()

    def test_file_roundtrip_digest_and_replay(self):
        p, data = self.good()
        tr = load_trace(p)
        self.assertEqual(tr.byte_digest, bytes_digest(data))
        self.assertEqual(events_to_bytes(tr.events), data)
        self.assertEqual((tr.family, tr.complete, tr.model_calls, len(tr.costs)), ("score", True, 3, 3))
        with _NoNet():
            rg, _ = S.replay(tr)
            self.assertTrue(self.call(rg, "extractor").ok)
        # re-serialised bytes differ -> a pin of the old digest refuses
        resaved = json.dumps(tr.events[0], sort_keys=True, separators=(",", ":")).encode() + b"\n" + data.split(b"\n", 1)[1]
        other = load_trace(resaved)
        with self.assertRaises(TraceError):
            S.replay(other, digest=tr.byte_digest)

    def test_structural_attacks_raise_trace_error_only(self):
        p, data = self.good()
        lines = data.decode().split("\n")[:-1]
        ev = [json.loads(x) for x in lines]
        def enc(events):
            return "".join(json.dumps(e, sort_keys=True) + "\n" for e in events).encode()
        calls = [i for i, e in enumerate(ev) if e["type"] == "score.model.call"]
        costs = [i for i, e in enumerate(ev) if e["type"] == "cost"]
        attacks = {
            "empty": b"", "not utf8": b"\xff\xfe\n", "truncated line": data[:-20], "blank line": data + b"\n",
            "no run.end": enc(ev[:-1]), "dup run.start": enc([ev[0]] + ev), "dup call": enc(ev[:3] + [ev[1], ev[2]] + ev[3:]),
            "drop a cost": enc([e for i, e in enumerate(ev) if i != costs[0]]),
            "drop a call": enc([e for i, e in enumerate(ev) if i != calls[1]]),
            "swap start/end": enc([ev[-1]] + ev[1:-1] + [ev[0]]),
            "reorder seq": enc([ev[0], ev[2], ev[1]] + ev[3:]),
            "review run.start name": enc([{**ev[0], "type": "run.start"}] + ev[1:]),
            "review model.call name": enc(ev[:1] + [{**ev[calls[0]], "type": "model.call"}] + ev[2:]),
            "review schema tag": enc([{**e, "schema": "trace-event@1"} for e in ev]),
            "extra run id": enc(ev[:1] + [{**ev[1], "runId": "run_" + "e" * 16}] + ev[2:]),
        }
        for name, blob in attacks.items():
            try:
                load_trace(blob)
            except TraceError:
                continue
            except Exception as e:            # noqa: BLE001
                self.fail(f"{name}: raised {type(e).__name__}: {str(e)[:120]}")
            self.fail(f"{name}: a damaged score trace loaded")

    def test_field_level_mutations_each_refused_with_trace_error(self):
        p, data = self.good()
        ev = [json.loads(x) for x in data.decode().split("\n")[:-1]]
        ci = next(i for i, e in enumerate(ev) if e["type"] == "score.model.call")
        co = next(i for i, e in enumerate(ev) if e["type"] == "cost")
        def mut(path, val):
            e = copy.deepcopy(ev)
            _set(e, path, val)
            return e
        muts = {
            "request text": mut((ci, "request", "messages", 1, "content"), "tampered"),
            "request role": mut((ci, "request", "role"), "deduper"),
            "request profile": mut((ci, "request", "profile"), "score-invented@2"),
            "requestHash": mut((ci, "requestHash"), "sha256:" + "0" * 64),
            "callId": mut((ci, "callId"), "call_" + "0" * 16),
            "costRecordId": mut((ci, "costRecordId"), "cost_" + "0" * 16),
            "agentId": mut((ci, "agentId"), "zzz"),
            "ordinal": mut((ci, "ordinal"), 99),
            "event role": mut((ci, "role"), "deduper"),
            "event stage": mut((ci, "stage"), "MATCH"),
            "response usage": mut((ci, "response", "usage", "outputTokens"), 11),
            "cost usage": mut((co, "record", "usage", "outputTokens"), 11),
            "cost kind review": mut((co, "record", "kind"), "review"),
            "cost kind eval": mut((co, "record", "kind"), "eval"),
            "cost stage": mut((co, "record", "stage"), "JUDGE"),
            "cost model": mut((co, "record", "model"), "anthropic/other"),
            "cost callId": mut((co, "record", "callId"), "call_" + "0" * 16),
            "cost eval run": mut((co, "record", "evalRunId"), S.EVR2),
            "cost run": mut((co, "record", "runId"), "run_" + "0" * 16),
            "cost basis replayed in live": mut((co, "record", "basis"), "replayed"),
            "run profile": mut((0, "run", "profile"), "score-invented@2"),
            "run family": mut((0, "run", "family"), "review"),
            "unredacted secret": mut((ci, "request", "messages", 1, "content"), "sk-ant-api03-" + "A" * 40),
        }
        for name, events in muts.items():
            try:
                load_trace(events)
            except (TraceError, ContractViolation) as e:
                self.assertIsInstance(e, TraceError, f"{name}: validator exception leaked as {type(e).__name__}")
            except Exception as e:            # noqa: BLE001
                self.fail(f"{name}: raised {type(e).__name__}: {str(e)[:120]}")
            else:
                self.fail(f"{name}: tampered score trace loaded")

    def test_exhaustive_single_field_corruption_never_crashes_the_loader(self):
        p, data = self.good()
        ev = [json.loads(x) for x in data.decode().split("\n")[:-1]]
        crashes, loaded = [], 0
        for ei, e in enumerate(ev):
            for path in _paths(e):
                for how in ("delete", None, 0, "x", [], {}):
                    cand = copy.deepcopy(ev)
                    try:
                        _set(cand[ei], path, how, delete=how == "delete")
                    except Exception:
                        continue
                    try:
                        load_trace(cand)
                        loaded += 1
                    except TraceError:
                        pass
                    except Exception as ex:       # noqa: BLE001
                        crashes.append((ei, path, repr(how), type(ex).__name__))
        self.assertEqual(crashes[:8], [], f"{len(crashes)} corruptions crashed instead of raising TraceError")

    def test_retained_error_trace_loads_and_cross_checks_charge(self):
        p = Fake(lambda q, k: ProviderResult(None, terr("provider-timeout", True), "unknown"))
        gw, rec, _ = S.live(self.tmp, p)
        self.call(gw)
        ev = copy.deepcopy(rec.events) + [{"schema": "score-trace-event@1", "runId": gw.run_id, "seq": len(rec.events),
                                          "type": "score.run.end", "status": "failed", "incomplete": []}]
        load_trace(ev)
        bad = copy.deepcopy(ev)
        next(e for e in bad if e["type"] == "cost")["record"]["usdMicros"] = 0
        with self.assertRaises(TraceError):
            load_trace(bad)                                   # unknown outcome cannot be re-priced to zero
        bad = copy.deepcopy(ev)
        rec_ = next(e for e in bad if e["type"] == "cost")["record"]
        rec_["usdMicros"] = rec_["reservedUsdMicros"] + 1
        with self.assertRaises(TraceError):
            load_trace(bad)


# --------------------------------------------------------------------------------------------- legacy review
class ReviewUnchanged(Base):
    """Differential over the review family: digests pinned from the UNMODIFIED public main f1c62ec tree."""

    def test_review_scenarios_equal_pre_score_gateway(self):
        from tests.score_gateway_review.review_scenarios import run_all
        got = run_all()
        from tests.score_gateway_review.pinned import PRISTINE
        self.assertEqual(got, PRISTINE)


# --------------------------------------------------------------------------------------------- end states / threads
class EndStatesAndThreads(Base):
    def test_run_end_status_and_incomplete_use_the_score_vocabulary(self):
        for status, inc, ok in (("completed", [], True), ("failed", [{"stage": "MATCH", "reason": "provider-failure"}], True),
                                ("failed", [{"stage": "INVESTIGATE", "reason": "provider-failure"}], False),
                                ("failed", [{"stage": "MATCH", "reason": "no-such-reason"}], False),
                                ("exploded", [], False)):
            gw, rec, _ = S.live(self.tmp, Fake())
            self.call(gw)
            if ok:
                rec.end(status, inc)
                load_trace(list(rec.events))
                self.assertScoreTraceClean(rec)
            else:
                with self.assertRaises((ContractViolation, TraceError)):
                    rec.end(status, inc)

    def test_threaded_calls_keep_one_consistent_trace_ledger_and_spend(self):
        import threading
        gw, rec, _ = S.live(self.tmp, Fake())
        errs = []
        def work(i):
            try:
                r = gw.call("MATCH", "matcher", f"t{i}", 0, S.request(text=f"pair {i}"))
                assert r.ok
            except Exception as e:      # noqa: BLE001
                errs.append(repr(e))
        ts = [threading.Thread(target=work, args=(i,)) for i in range(12)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        tr = S.finish(rec)
        self.assertEqual((tr.model_calls, len(tr.costs)), (12, 12))
        self.assertEqual([e["seq"] for e in rec.events], list(range(len(rec.events))))
        total = sum(c["usdMicros"] for c in tr.costs.values())
        self.assertEqual(gw.report()["newSpendUsdMicros"], total)
        self.assertEqual(gw.report()["liveCalls"], 12)
