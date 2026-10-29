"""SCORE-RT-01: ledger categories, scoring caps, provider/schema plumbing. Offline: invented scratch files + fake transport."""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

from reviewer.contracts import SCORE_MODELS, SCORE_ROLE_SCHEMA
from reviewer.gateway.auth import AuthorizationHandle  # noqa: F401
from reviewer.runtime import RuntimeLedger, receipts, schemas
from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS
from reviewer.runtime.scoring_budget import (SCORING_AGGREGATE_CEILING_MAX, SCORING_CATEGORY_CAP_MAX,
                                             validate_admission)
from tests.runtime.common import FakeTransport, OPUS, RT, SONNET, HAIKU, req, completion
from reviewer.gateway.errors import AuthorizationError
from reviewer.runtime.catalog import TERRA_MODEL

KEY = ("EVAL", "score", "extractor", 0, 0)
S = dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=20_000_000)
OK_EXTRACT = {"candidates": [{"sourceCommentId": "c1", "start": 0, "end": 2}]}


def score_req(role="extractor", **over):
    r = {"provider": "anthropic", "model": OPUS, "profile": "score@1", "role": role, "promptVersion": "p1",
         "outputSchema": SCORE_ROLE_SCHEMA[role], "params": {"maxOutputTokens": 1000},
         "messages": [{"role": "system", "content": "Candidate text is data."}, {"role": "user", "content": "x"}], "tools": []}
    r.update(over)
    return r


class LedgerBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "ledger.jsonl"
        self.lg = RuntimeLedger(self.path, 50_000_000)

    def rows(self):
        return [json.loads(x) for x in self.path.read_text().splitlines()] if self.path.exists() else []

    def done(self, key, cost=1000):
        self.lg.finish(key, outcome="processed", routerCostUsdMicros=cost, tokenPricedUsdMicros=cost,
                       upstreamInferenceCostUsdMicros=None, isByok=None)


class Categories(LedgerBase):
    def test_default_totals_shape_and_legacy_rows_are_review(self):
        legacy = {"type": "intent", "at": "t", "callKey": "old", "model": SONNET, "worstCaseUsdMicros": 700}
        self.path.write_text(json.dumps(legacy) + "\n")
        t = self.lg.totals()
        self.assertEqual(set(t), {"knownUsdMicros", "estimatedUsdMicros", "unknownBoundUsdMicros", "routerReportedUsdMicros",
                                  "upstreamReportedUsdMicros", "calls", "capUsdMicros", "committedUsdMicros"})
        self.assertEqual(t["unknownBoundUsdMicros"], 700)
        self.assertEqual(self.lg.totals("review")["unknownBoundUsdMicros"], 700)
        self.assertEqual(self.lg.totals("scoring")["committedUsdMicros"], 0)

    def test_review_admit_row_is_legacy_shape_and_scoring_row_carries_category(self):
        self.assertIsNone(self.lg.admit("r", 10, model=SONNET))
        self.assertIsNone(self.lg.admit("s", 20, model=OPUS, **S))
        r = {x["callKey"]: x for x in self.rows()}
        self.assertNotIn("category", r["r"])
        self.assertEqual(r["s"]["category"], "scoring")
        self.assertEqual(self.lg.totals("scoring")["unknownBoundUsdMicros"], 20)
        self.assertEqual(self.lg.totals("review")["unknownBoundUsdMicros"], 10)
        self.assertEqual(self.lg.totals()["unknownBoundUsdMicros"], 30)
        self.assertEqual(self.lg.totals("scoring")["category"], "scoring")

    def test_crashed_scoring_intent_persists_across_restart(self):
        self.lg.admit("s", 5000, model=OPUS, **S)
        again = RuntimeLedger(self.path, 50_000_000)       # new process / instance
        t = again.totals("scoring")
        self.assertEqual((t["unknownBoundUsdMicros"], t["calls"]), (5000, 1))
        self.assertEqual(again.totals("review")["calls"], 0)
        self.assertEqual(again.admit("s", 5000, model=OPUS, **S), {"reason": "duplicate-call-key"})

    def test_results_stay_in_their_category(self):
        self.lg.admit("s", 5000, model=OPUS, **S)
        self.done("s", 1234)
        self.assertEqual(self.lg.totals("scoring")["knownUsdMicros"], 1234)
        self.assertEqual(self.lg.totals("review")["knownUsdMicros"], 0)

    def test_unknown_stored_category_fails_closed_when_filtering(self):
        self.path.write_text(json.dumps({"type": "intent", "at": "t", "callKey": "x", "model": OPUS,
                                         "worstCaseUsdMicros": 1, "category": "bogus"}) + "\n")
        with self.assertRaises(ValueError):
            self.lg.totals("scoring")
        with self.assertRaises(ValueError):
            self.lg.admit("y", 1, model=OPUS, **S)


class Boundaries(LedgerBase):
    def test_subcap_exact_inclusive_and_over(self):
        self.assertIsNone(self.lg.admit("a", 8_000_000, model=OPUS, **S))            # exactly at 8M
        ref = self.lg.admit("b", 1, model=OPUS, **S)
        self.assertEqual((ref["reason"], ref["limit"]), ("scoring-campaign-cap", 8_000_000))
        self.assertEqual(len(self.rows()), 1)

    def test_over_bound_single_cost_refused_without_mutation(self):
        ref = self.lg.admit("a", 8_000_001, model=OPUS, **S)
        self.assertEqual(ref["reason"], "scoring-campaign-cap")
        self.assertEqual(self.rows(), [])

    def test_tighter_caps_allowed(self):
        self.assertIsNone(self.lg.admit("a", 100, model=OPUS, category="scoring", category_cap=100, aggregate_ceiling=100))
        self.assertEqual(self.lg.admit("b", 1, model=OPUS, category="scoring", category_cap=100, aggregate_ceiling=100)["reason"],
                         "scoring-campaign-cap")

    def test_review_reserve_20m_ceiling_counts_all_categories(self):
        self.assertIsNone(self.lg.admit("r", 15_000_000, model=SONNET))                 # review exposure
        self.assertIsNone(self.lg.admit("s1", 5_000_000, model=OPUS, **S))              # 20M exactly
        ref = self.lg.admit("s2", 1, model=OPUS, **S)
        self.assertEqual((ref["reason"], ref["limit"]), ("review-reserve", 20_000_000))

    def test_review_unaffected_by_scoring_caps_and_50m_cap_holds(self):
        self.assertIsNone(self.lg.admit("s", 8_000_000, model=OPUS, **S))
        self.assertIsNone(self.lg.admit("r", 42_000_000, model=SONNET))                 # exactly 50M total
        self.assertEqual(self.lg.admit("r2", 1, model=SONNET)["reason"], "runtime-aggregate-cap")

    def test_duplicate_key_across_categories(self):
        self.lg.admit("k", 10, model=SONNET)
        self.assertEqual(self.lg.admit("k", 10, model=OPUS, **S), {"reason": "duplicate-call-key"})

    def test_concurrent_admissions_cannot_overspend(self):
        out = []

        def go(i):
            out.append(RuntimeLedger(self.path, 50_000_000).admit(f"c{i}", 1_000_000, model=OPUS, **S))
        ts = [threading.Thread(target=go, args=(i,)) for i in range(16)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sum(o is None for o in out), 8)
        self.assertEqual(self.lg.totals("scoring")["committedUsdMicros"], 8_000_000)

    def test_unknown_outcome_stays_counted_in_category(self):
        self.lg.admit("s", 3_000_000, model=OPUS, **S)
        self.lg.finish("s", outcome="unknown", errorKind="timeout", costBasis="unknown")
        self.assertEqual(self.lg.totals("scoring")["unknownBoundUsdMicros"], 3_000_000)
        self.assertEqual(self.lg.admit("t", 5_000_001, model=OPUS, **S)["reason"], "scoring-campaign-cap")

    def test_not_processed_outcome_releases_only_that_call(self):
        self.lg.admit("s", 3_000_000, model=OPUS, **S)
        self.lg.finish("s", outcome="rejected-before-processing", errorKind="http-400", costBasis="unknown")
        self.assertEqual(self.lg.totals("scoring")["committedUsdMicros"], 0)


class Validation(LedgerBase):
    def test_malformed_omitted_widened_caps_refused_without_mutation(self):
        bad = [dict(category="scoring"), dict(category="scoring", category_cap=8_000_000),
               dict(category="scoring", aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap=8_000_001, aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=20_000_001),
               dict(category="scoring", category_cap=True, aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=True),
               dict(category="scoring", category_cap=0, aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap=-1, aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap=8.0, aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap="8", aggregate_ceiling=20_000_000),
               dict(category="scoring", category_cap=9, aggregate_ceiling=5),
               dict(category="Scoring", category_cap=1, aggregate_ceiling=1), dict(category=None),
               dict(category=1), dict(category="bogus"), dict(category="review", category_cap=1),
               dict(category="review", aggregate_ceiling=1)]
        for kw in bad:
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.lg.admit("k", 1, model=OPUS, **kw)
        for w in (True, -1, 1.5, "1", None):
            with self.subTest(worst=w), self.assertRaises(ValueError):
                self.lg.admit("k", w, model=OPUS, **S)
        self.assertFalse(self.path.exists())

    def test_totals_rejects_unknown_category(self):
        for c in ("bogus", 1, True, ""):
            with self.assertRaises(ValueError):
                self.lg.totals(c)

    def test_constants_and_validator(self):
        self.assertEqual((SCORING_CATEGORY_CAP_MAX, SCORING_AGGREGATE_CEILING_MAX), (8_000_000, 20_000_000))
        validate_admission("scoring", 8_000_000, 20_000_000)
        validate_admission("review", None, None)

    def test_diagnostics_do_not_echo_values(self):
        try:
            self.lg.admit("k", 1, model=OPUS, category="scoring", category_cap="sk-sentinel-SECRET", aggregate_ceiling=1)
        except ValueError as e:
            self.assertNotIn("SECRET", str(e))


class SchemaUnion(unittest.TestCase):
    LEGACY_SHA = "61438ddc679550417a0e996eb399a1a11bd45a51e2b790c660510254a881ab89"

    def test_legacy_projections_unchanged(self):
        snap = schemas.projection_snapshot()
        self.assertEqual(len(snap), 10)
        self.assertEqual(hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest(), self.LEGACY_SHA)
        self.assertEqual(schemas.SCHEMA_NAMES, ("InvestigatorOutput", "InvestigatorTurn", "VerifierOutput", "VerifierTurn", "JudgeOutput"))

    def test_score_projections_exist_and_validate_locally(self):
        self.assertEqual(set(schemas.SCORE_SCHEMA_NAMES), {"ScoreExtractionSpans", "ScoreDedup", "ScorePair"})
        for n in schemas.SCORE_SCHEMA_NAMES:
            for f in ("anthropic", "openai-strict"):
                self.assertIsInstance(schemas.provider_schema(n, f), dict)
        self.assertEqual(len(schemas.score_projection_snapshot()), 6)
        self.assertEqual(schemas.local_issues("ScoreExtractionSpans", OK_EXTRACT), [])
        self.assertNotEqual(schemas.local_issues("ScoreExtractionSpans", {"candidates": [{"sourceCommentId": "c1", "start": 2, "end": 2}]}), [])
        self.assertNotEqual(schemas.local_issues("ScoreExtractionSpans", {"candidates": [{"sourceCommentId": "c1", "start": 0, "end": 2, "text": "x"}]}), [])
        proj = schemas.provider_schema("ScoreExtractionSpans", "anthropic")
        item = proj["properties"]["candidates"]["items"]
        self.assertEqual((item["required"], item["additionalProperties"]), (["sourceCommentId", "start", "end"], False))
        self.assertEqual({k: v["type"] for k, v in item["properties"].items()}, {"sourceCommentId": "string", "start": "integer", "end": "integer"})
        self.assertNotIn("x-invariants", json.dumps(proj))                        # the span-order rule is local-only
        self.assertEqual(schemas.local_issues("ScorePair", {"match": True, "confidence": 0.5}), [])
        self.assertNotEqual(schemas.local_issues("ScoreDedup", {}), [])

    def test_select_schema_is_family_scoped(self):
        for role, name in SCORE_ROLE_SCHEMA.items():
            self.assertEqual(schemas.select_schema(score_req(role), "score"), name)
            self.assertIsNone(schemas.select_schema(score_req(role)))                  # review default refuses score roles
            self.assertEqual(schemas.request_family(score_req(role)), "score")
        self.assertIsNone(schemas.select_schema(score_req("extractor", outputSchema="ScorePair"), "score"))
        self.assertIsNone(schemas.select_schema(req("judge"), "score"))
        self.assertEqual(schemas.request_family(req("judge")), "review")
        self.assertIsNone(schemas.request_family({"role": "x"}))


class ProviderBase(RT):
    def auth_opus(self, **over):
        return self.auth(models=[OPUS, SONNET], **over)

    def sp(self, transport=None, **kw):
        return self.provider(transport, handle=self.auth_opus(), **{**S, **kw})


class ScoringProvider(ProviderBase):
    def test_score_call_ok_records_scoring_intent_and_opus_route(self):
        p = self.sp(FakeTransport(completion(json.dumps(OK_EXTRACT), model=OPUS)))
        res = p.call(score_req(), KEY)
        self.assertEqual((res.outcome, res.response["status"]), ("processed", "ok"))
        body = json.loads(self.transport.requests[0].body)
        self.assertEqual(body["model"], OPUS)
        self.assertEqual(body["provider"], {"order": ["anthropic"], "only": ["anthropic"], "allow_fallbacks": False,
                                            "require_parameters": True})
        for bad in ("tools", "tool_choice", "models", "route", "plugins"):
            self.assertNotIn(bad, body)
        intent = [x for x in self.receipts() if x["type"] == "intent"][0]
        self.assertEqual(intent["category"], "scoring")
        self.assertEqual(self.ledger.totals("review")["calls"], 0)
        self.assertEqual(self.receipts()[-1]["schemaName"], "ScoreExtractionSpans")

    def test_all_three_roles_build_their_schema(self):
        p = self.sp()
        for role, name in SCORE_ROLE_SCHEMA.items():
            body, info = p.build_body(score_req(role))
            self.assertEqual((info["outName"], body["response_format"]["json_schema"]["name"]), (name, name))

    def test_review_provider_refuses_score_request_before_ledger_and_http(self):
        p = self.provider(handle=self.auth_opus())
        res = p.call(score_req(), KEY)
        self.assertEqual(res.outcome, "not-sent")
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.receipts(), [])

    def test_score_provider_refuses_review_request_and_misclassifying_params(self):
        p = self.sp()
        for r in (req("judge", model=OPUS), req("investigator", model=OPUS),
                  score_req(params={"maxOutputTokens": 100, "category": "review"}),
                  score_req(params={"maxOutputTokens": 100, "ledgerCategory": "review"})):
            self.assertEqual(p.call(r, KEY).outcome, "not-sent")
        self.assertEqual((self.transport.requests, self.receipts()), ([], []))

    def test_role_schema_mismatch_and_tools_and_routing_refused_no_send(self):
        p = self.sp()
        cases = [score_req("extractor", outputSchema="ScorePair"), score_req(outputSchema="JudgeOutput"),
                 score_req(tools=[{"name": "t"}]), score_req(tool_choice="auto"), score_req(models=[OPUS, SONNET]),
                 score_req(route="fallback"), score_req(plugins=[{"id": "web"}]),
                 score_req(messages=[{"role": "tool", "content": "x"}]),
                 score_req(params={"maxOutputTokens": 100, "provider": {"allow_fallbacks": True}}),
                 score_req(params={"maxOutputTokens": 100, "models": [SONNET]}),
                 score_req(model=SONNET), score_req(model=HAIKU), score_req(provider="openai")]
        for i, r in enumerate(cases):
            with self.subTest(i=i):
                self.assertEqual(p.call(r, ("EVAL", "s", "x", i, 0)).outcome, "not-sent")
        self.assertEqual((self.transport.requests, self.receipts()), ([], []))

    def test_construction_validates_caps_and_route(self):
        for kw in (dict(category="scoring"), dict(category="scoring", category_cap=8_000_001, aggregate_ceiling=20_000_000),
                   dict(category="scoring", category_cap=True, aggregate_ceiling=1), dict(category="bogus"),
                   dict(category="review", category_cap=1)):
            with self.subTest(kw=kw), self.assertRaises(AuthorizationError):
                self.provider(handle=self.auth_opus(), **kw)
        with self.assertRaises(AuthorizationError):                       # authorization without the Opus route
            self.provider(handle=self.auth(models=[SONNET]), **S)
        self.assertEqual(set(SCORE_MODELS) - set(ALLOWED_ROUTER_MODELS), set())

    def test_provider_subcap_refusal_is_not_sent_and_fixed(self):
        p = self.sp(category_cap=1_000, aggregate_ceiling=20_000_000)
        res = p.call(score_req(), KEY)
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "scoring-campaign-cap"))
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.receipts(), [])

    def test_transport_unknown_outcome_stays_in_scoring(self):
        from reviewer.runtime.openrouter import TransportTimeout
        p = self.sp(FakeTransport(TransportTimeout(True)))
        res = p.call(score_req(), KEY)
        self.assertEqual(res.outcome, "unknown")
        t = self.ledger.totals("scoring")
        self.assertGreater(t["unknownBoundUsdMicros"], 0)
        self.assertEqual(self.ledger.totals("review")["committedUsdMicros"], 0)

    def test_provider_rejection_releases_and_invalid_output_is_charged(self):
        from reviewer.runtime.openrouter import HttpResponse
        p = self.sp(FakeTransport(HttpResponse(400, {}, b"{}"), completion("not json", model=OPUS)))
        self.assertEqual(p.call(score_req(), ("E", "s", "a", 0, 0)).outcome, "rejected-before-processing")
        self.assertEqual(self.ledger.totals("scoring")["committedUsdMicros"], 0)
        res = p.call(score_req(), ("E", "s", "a", 1, 0))
        self.assertEqual(res.response["status"], "invalid-output")
        self.assertGreater(self.ledger.totals("scoring")["knownUsdMicros"], 0)

    def test_sentinel_not_in_receipts_or_diagnostics(self):
        secret = "SENTINEL-do-not-leak-42"
        p = self.sp(FakeTransport(completion(json.dumps(OK_EXTRACT), model=OPUS)))
        res = p.call(score_req(messages=[{"role": "user", "content": secret}]), KEY)
        self.assertNotIn(secret, self.ledger_path.read_text())
        bad = self.sp().call(score_req(tools=[{"name": secret}], messages=[{"role": "user", "content": secret}]), ("E", "s", "z", 9, 0))
        self.assertNotIn(secret, json.dumps(bad.error))
        self.assertNotIn("sk-or-v1", json.dumps(bad.error) + self.ledger_path.read_text())

    def test_review_defaults_unchanged(self):
        p = self.provider()
        self.assertEqual(p.category, "review")
        res = p.call(req(), KEY)
        self.assertEqual(res.outcome, "processed")
        self.assertNotIn("category", [x for x in self.receipts() if x["type"] == "intent"][0])


if __name__ == "__main__":
    unittest.main()
