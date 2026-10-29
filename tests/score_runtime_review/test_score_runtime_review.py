"""SCORE-RT-02 independent gate for SCORE-RT-01 (offline: invented files, fake transport, no keys/network/Git).

Run against the scratch candidate (not the shared tree):
    SCORE_RT_SRC=<candidate root> nice -n 19 python3 -B tests/score_runtime_review/test_score_runtime_review.py
The candidate root is put first on sys.path so every `reviewer.*` and `tests.runtime.common` import comes from it."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import sys
import tempfile
import unittest
from pathlib import Path

SRC = os.environ.get("SCORE_RT_SRC") or str(Path(__file__).resolve().parents[2])   # default: this checkout; env overrides
sys.path.insert(0, SRC)
sys.dont_write_bytecode = True

from reviewer.contracts import SCORE_MODELS, SCORE_ROLE_SCHEMA                      # noqa: E402
from reviewer.contracts.entities import ROLE_SCHEMAS                                 # noqa: E402
from reviewer.gateway.errors import AuthorizationError                               # noqa: E402
from reviewer.runtime import RuntimeLedger, schemas                                  # noqa: E402
from reviewer.runtime.scoring_budget import SCORING_CATEGORY_CAP_MAX                  # noqa: E402
from reviewer.runtime.openrouter import HttpResponse                                 # noqa: E402
from tests.runtime.common import FakeTransport, HAIKU, OPUS, RT, SONNET, completion, req   # noqa: E402

assert Path(schemas.__file__).resolve().is_relative_to(Path(SRC).resolve()), "reviewer imported from outside SCORE_RT_SRC"
S = dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=20_000_000)
CAP, CEIL = 8_000_000, 20_000_000
# Values recorded from the PRISTINE main runtime (candidate patch reverse-applied) for the same sequence.
PRISTINE_LEGACY_LEDGER_SHA = "7c6283d1f77660ee49fa9ec31ab9eae80fd13caf1c3d64b240609b705d35f88a"
PRISTINE_LEGACY_TOTALS = {"calls": 2, "capUsdMicros": 50000000, "committedUsdMicros": 2900, "estimatedUsdMicros": 0,
                          "knownUsdMicros": 900, "routerReportedUsdMicros": 900, "unknownBoundUsdMicros": 2000,
                          "upstreamReportedUsdMicros": 0}
PRISTINE_LEGACY_PROJECTION_SHA = "61438ddc679550417a0e996eb399a1a11bd45a51e2b790c660510254a881ab89"


def score_req(role="extractor", **over):
    r = {"provider": "anthropic", "model": OPUS, "profile": "score@1", "role": role, "promptVersion": "p1",
         "outputSchema": SCORE_ROLE_SCHEMA[role], "params": {"maxOutputTokens": 1000},
         "messages": [{"role": "system", "content": "data"}, {"role": "user", "content": "x"}], "tools": []}
    r.update(over)
    return r


def _race(args):                       # separate process, separate RuntimeLedger instance, same file
    path, i, kind = args
    lg = RuntimeLedger(path, 50_000_000)
    kw = S if kind == "s" else {}
    return kind, lg.admit(f"{kind}{i}", 1_000_000, model=OPUS if kind == "s" else SONNET, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.path = Path(self.d.name) / "l.jsonl"
        self.lg = RuntimeLedger(self.path, 50_000_000)

    def rows(self):
        return [json.loads(x) for x in self.path.read_text().splitlines()]


class LegacyUnchanged(Base):
    def test_review_path_is_byte_identical_to_pristine_main(self):
        t = iter(range(1000))
        lg = RuntimeLedger(self.path, 50_000_000, clock=lambda: "2026-01-01T00:00:%02dZ" % next(t))
        lg.admit("a", 1000, model="m")
        lg.finish("a", outcome="processed", routerCostUsdMicros=900, tokenPricedUsdMicros=900,
                  upstreamInferenceCostUsdMicros=None, isByok=None)
        lg.admit("b", 2000, model="m")
        lg.note(keyRemainingUsd="1")
        self.assertEqual(lg.admit("a", 5, model="m"), {"reason": "duplicate-call-key"})
        self.assertEqual(lg.admit("c", 50_000_000, model="m")["reason"], "runtime-aggregate-cap")
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), PRISTINE_LEGACY_LEDGER_SHA)
        self.assertEqual(lg.totals(), PRISTINE_LEGACY_TOTALS)

    def test_missing_category_rows_count_as_review_and_do_not_use_scoring_budget(self):
        legacy = {"type": "intent", "at": "t", "callKey": "old", "model": SONNET, "worstCaseUsdMicros": 7_000_000}
        self.path.write_text(json.dumps(legacy) + "\n")
        self.assertEqual(self.lg.totals("scoring")["committedUsdMicros"], 0)
        self.assertEqual(self.lg.totals("review")["committedUsdMicros"], 7_000_000)
        self.assertIsNone(self.lg.admit("s", CAP, model=OPUS, **S))          # legacy review spend is not scoring spend

    def test_legacy_projections_and_names_unchanged(self):
        snap = schemas.projection_snapshot()
        self.assertEqual(len(snap), 10)
        self.assertEqual(hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest(), PRISTINE_LEGACY_PROJECTION_SHA)
        self.assertEqual(set(schemas.SCHEMA_NAMES), {n for v in ROLE_SCHEMAS.values() for n in v})
        self.assertEqual(len(schemas.score_projection_snapshot()), 6)
        self.assertFalse(set(schemas.SCHEMA_NAMES) & set(schemas.SCORE_SCHEMA_NAMES))

    def test_roles_and_schemas_of_the_two_families_are_disjoint(self):
        self.assertFalse(set(ROLE_SCHEMAS) & set(SCORE_ROLE_SCHEMA))
        for role, names in ROLE_SCHEMAS.items():
            for n in names:
                self.assertIsNone(schemas.select_schema({"role": role, "outputSchema": n}, "score"))
        for role, n in SCORE_ROLE_SCHEMA.items():
            self.assertIsNone(schemas.select_schema({"role": role, "outputSchema": n}, "review"))
            self.assertEqual(schemas.select_schema({"role": role, "outputSchema": n}, "score"), n)
            self.assertIsNone(schemas.select_schema({"role": role, "outputSchema": "JudgeOutput"}, "score"))


class Caps(Base):
    BAD = [dict(), dict(category_cap=CAP), dict(aggregate_ceiling=CEIL), dict(category_cap=SCORING_CATEGORY_CAP_MAX + 1, aggregate_ceiling=CEIL),
           dict(category_cap=CAP, aggregate_ceiling=CEIL + 1), dict(category_cap=True, aggregate_ceiling=CEIL),
           dict(category_cap=CAP, aggregate_ceiling=True), dict(category_cap=0, aggregate_ceiling=CEIL),
           dict(category_cap=-5, aggregate_ceiling=CEIL), dict(category_cap=float(CAP), aggregate_ceiling=CEIL),
           dict(category_cap="8000000", aggregate_ceiling=CEIL), dict(category_cap=CEIL, aggregate_ceiling=CAP),
           dict(category_cap=CAP, aggregate_ceiling=-1), dict(category_cap=CAP, aggregate_ceiling=CAP - 1), dict(category_cap=None, aggregate_ceiling=None)]

    def test_bad_scoring_caps_refused_before_any_file_access_or_mutation(self):
        for kw in self.BAD:
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.lg.admit("k", 1, model=OPUS, category="scoring", **kw)
        self.assertFalse(self.path.exists())
        self.lg.admit("pre", 10, model=SONNET)
        before = self.path.read_bytes()
        for kw in self.BAD:
            with self.assertRaises(ValueError):
                self.lg.admit("k", 1, model=OPUS, category="scoring", **kw)
        for c in ("Scoring", "", None, 1, True, "bogus", "review ", ["scoring"]):
            with self.subTest(category=c), self.assertRaises(ValueError):
                self.lg.admit("k", 1, model=OPUS, category=c, category_cap=1, aggregate_ceiling=1)
        for kw in (dict(category_cap=1), dict(aggregate_ceiling=1), dict(category_cap=0, aggregate_ceiling=0)):
            with self.assertRaises(ValueError):          # review may not carry (or widen) scoring caps
                self.lg.admit("k", 1, model=SONNET, category="review", **kw)
        self.assertEqual(self.path.read_bytes(), before)

    def test_exact_boundaries_and_tighter_caps(self):
        self.assertIsNone(self.lg.admit("a", CAP, model=OPUS, **S))
        r = self.lg.admit("b", 1, model=OPUS, **S)
        self.assertEqual((r["reason"], r["wouldReach"], r["limit"]), ("scoring-campaign-cap", CAP + 1, CAP))
        self.assertEqual(self.lg.admit("tight", 1, model=OPUS, category="scoring", category_cap=100,
                                       aggregate_ceiling=CEIL)["reason"], "scoring-campaign-cap")
        lg2 = RuntimeLedger(Path(self.d.name) / "t.jsonl", 50_000_000)
        self.assertIsNone(lg2.admit("a", 100, model=OPUS, category="scoring", category_cap=100, aggregate_ceiling=100))
        self.assertEqual(lg2.admit("b", 1, model=OPUS, category="scoring", category_cap=100,
                                   aggregate_ceiling=100)["reason"], "scoring-campaign-cap")

    def test_review_reserve_counts_all_categories_and_50m_still_binds(self):
        self.assertIsNone(self.lg.admit("rev", 12_000_000, model=SONNET))
        self.assertIsNone(self.lg.admit("s1", CAP, model=OPUS, **S))            # 12M + 8M = 20M exactly
        lg = RuntimeLedger(Path(self.d.name) / "b.jsonl", 50_000_000)
        lg.admit("rev", 12_000_001, model=SONNET)
        r = lg.admit("s", CAP, model=OPUS, **S)
        self.assertEqual((r["reason"], r["limit"]), ("review-reserve", CEIL))
        self.assertIsNone(lg.admit("rev2", 30_000_000, model=SONNET))           # reviews keep their 30M+ (no ceiling)
        self.assertEqual(lg.admit("rev3", 8_000_000, model=SONNET)["reason"], "runtime-aggregate-cap")
        lg3 = RuntimeLedger(Path(self.d.name) / "c.jsonl", 10_000_000)          # tighter runtime cap reported first
        self.assertEqual(lg3.admit("s", 10_000_001, model=OPUS, **S)["reason"], "runtime-aggregate-cap")

    def test_duplicate_key_across_categories_refused_and_changes_nothing(self):
        self.lg.admit("k", 10, model=SONNET)
        before = self.path.read_bytes()
        self.assertEqual(self.lg.admit("k", 10, model=OPUS, **S), {"reason": "duplicate-call-key"})
        self.assertEqual(self.path.read_bytes(), before)
        self.lg.admit("s", 10, model=OPUS, **S)
        self.assertEqual(self.lg.admit("s", 10, model=SONNET), {"reason": "duplicate-call-key"})

    def test_cross_process_race_mixed_categories_never_exceeds_either_bound(self):
        self.lg.admit("rev0", 10_000_000, model=SONNET)
        jobs = [(str(self.path), i, k) for i in range(14) for k in ("s", "r")]
        with mp.get_context("fork").Pool(8) as pool:
            res = pool.map(_race, jobs)
        got_s = sum(1 for k, r in res if k == "s" and r is None)
        self.assertTrue(0 < got_s <= 10)                 # reviews race for the same ceiling; the replay below is the real check
        spent_all = spent_s = 0
        for row in self.rows():                          # replay the ledger in write order: each scoring admit was legal
            if row["type"] != "intent":
                continue
            w = row["worstCaseUsdMicros"]
            if row.get("category") == "scoring":
                self.assertLessEqual(spent_s + w, CAP)
                self.assertLessEqual(spent_all + w, CEIL)
                spent_s += w
            spent_all += w
        self.assertLessEqual(spent_s, CAP)
        self.assertLessEqual(spent_all, 50_000_000)


class IntentAndOrphans(Base):
    def test_category_on_intent_survives_crash_unknown_and_reopen(self):
        self.lg.admit("s", 3_000_000, model=OPUS, **S)
        self.assertEqual(self.rows()[0]["category"], "scoring")
        again = RuntimeLedger(self.path, 50_000_000)
        self.assertEqual(again.totals("scoring")["unknownBoundUsdMicros"], 3_000_000)
        self.assertEqual(again.totals("review")["calls"], 0)
        # RT-06 fixture correction: the REOPENED instance does not own the orphan (SCORE-RT-05 F1b), so it can no longer
        # finish it; the owning instance records the unknown outcome. Both retained-exposure assertions are unchanged.
        with self.assertRaises(ValueError):
            again.finish("s", outcome="unknown", errorKind="timeout", costBasis="unknown")
        self.lg.finish("s", outcome="unknown", errorKind="timeout", costBasis="unknown")
        self.assertEqual(RuntimeLedger(self.path, 50_000_000).totals("scoring")["unknownBoundUsdMicros"], 3_000_000)
        self.assertEqual(again.admit("t", CAP - 3_000_000 + 1, model=OPUS, **S)["reason"], "scoring-campaign-cap")

    def test_result_row_cannot_recategorize_an_intent(self):
        self.lg.admit("s", 1000, model=OPUS, **S)
        with self.assertRaises(ValueError):
            self.lg.finish("s", outcome="processed", category="review")        # not an allowed receipt field
        rows = self.rows() + [{"type": "result", "callKey": "s", "outcome": "unknown", "category": "review"}]
        self.path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        self.assertEqual(self.lg.totals("scoring")["unknownBoundUsdMicros"], 1000)
        self.assertEqual(self.lg.totals("review")["calls"], 0)

    def test_unknown_stored_category_fails_closed_for_scoring_admission(self):
        self.path.write_text(json.dumps({"type": "intent", "at": "t", "callKey": "x", "model": OPUS,
                                         "worstCaseUsdMicros": 5, "category": "bogus"}) + "\n")
        before = self.path.read_bytes()
        self.assertEqual(self.lg.totals()["unknownBoundUsdMicros"], 5)          # still counted in the aggregate
        with self.assertRaises(ValueError):
            self.lg.totals("scoring")
        with self.assertRaises(ValueError):
            self.lg.admit("s", 1, model=OPUS, **S)
        self.assertEqual(self.path.read_bytes(), before)

    def test_no_release_reset_or_recovery_surface_and_reconcile_keeps_category(self):
        names = " ".join(n.lower() for n in dir(RuntimeLedger))
        for word in ("release", "reset", "recover", "forget", "clear", "orphan", "assert"):
            self.assertNotIn(word, names)
        self.lg.admit("s", 2_000_000, model=OPUS, **S)
        self.lg.finish("s", outcome="processed", generationId="gen-1", routerCostUsdMicros=0, tokenPricedUsdMicros=500,
                       upstreamInferenceCostUsdMicros=500, isByok=True)
        out = self.lg.reconcile("s", {"id": "gen-1", "total_cost": "0", "upstream_inference_cost": "0.0004", "is_byok": True})
        self.assertTrue(out["appended"])
        self.assertEqual(self.lg.totals("scoring")["calls"], 1)
        self.assertEqual(self.lg.totals("review")["calls"], 0)
        self.assertNotIn("category", self.rows()[-1])                            # append-only; intent stays authoritative
        rows = self.rows()
        self.assertEqual([r["type"] for r in rows], ["intent", "result", "reconcile"])
        self.assertEqual(self.lg.totals("scoring")["committedUsdMicros"], self.lg.totals()["committedUsdMicros"])


class Provider(RT):
    def sp(self, transport=None, **kw):
        kw.setdefault("category", "scoring")
        kw.setdefault("category_cap", CAP)
        kw.setdefault("aggregate_ceiling", CEIL)
        return self.provider(transport, handle=self.auth(models=[SONNET, HAIKU, OPUS]), **kw)

    def test_bad_caps_or_category_refused_at_construction(self):
        for kw in (dict(category="scoring"), dict(category="scoring", category_cap=CAP), dict(category="scoring",
                   category_cap=SCORING_CATEGORY_CAP_MAX + 1, aggregate_ceiling=CEIL), dict(category="nope"), dict(category="review", category_cap=1)):
            with self.subTest(kw=kw), self.assertRaises(AuthorizationError):
                self.provider(handle=self.auth(models=[SONNET, HAIKU, OPUS]), **kw)

    def test_scoring_provider_needs_opus_in_authorization_and_is_opus_only(self):
        with self.assertRaises(AuthorizationError):
            self.provider(handle=self.auth(models=[SONNET, HAIKU]), category="scoring", category_cap=CAP, aggregate_ceiling=CEIL)
        p = self.sp()
        for m in (SONNET, HAIKU, "anthropic/claude-opus-5.4", "openai/gpt-5.6-terra", None):
            self.assertIsNone(p.build_body(score_req(model=m))[0], m)
        self.assertEqual(tuple(p._models), SCORE_MODELS)
        self.assertIsNotNone(p.build_body(score_req())[0])

    def test_family_must_match_the_host_category_in_both_directions_before_ledger_or_http(self):
        sp, rp = self.sp(), None
        for role in SCORE_ROLE_SCHEMA:
            self.assertIsNone(sp.build_body(req("investigator"))[0])
            self.assertIn("family", sp.build_body(req("investigator", model=OPUS))[1]["why"])
            res = sp.call(req("investigator"), ("S", "investigator", "a", 0, 0))
            self.assertIsNone(res.response)
        self.assertEqual(self.transport.requests, [])
        self.assertFalse(self.ledger_path.exists())
        rp = self.provider(handle=self.auth(models=[SONNET, HAIKU, OPUS]))      # default review provider
        for role in SCORE_ROLE_SCHEMA:
            self.assertIsNone(rp.build_body(score_req(role))[0])
            self.assertIn("family", rp.build_body(score_req(role))[1]["why"])
            r = rp.call(score_req(role), ("S", role, "a", 0, 0))
            self.assertIsNone(r.response)
        self.assertEqual(self.transport.requests, [])
        self.assertFalse(self.ledger_path.exists())

    def test_params_cannot_change_category_or_family(self):
        sp = self.sp()
        for extra in ({"category": "review"}, {"ledgerCategory": "review"}, {"purpose": "review"}, {"temperature": 0},
                      {"tool_choice": "auto"}, {"provider": {"allow_fallbacks": True}}, {"models": [SONNET]}):
            body, info = sp.build_body(score_req(params={"maxOutputTokens": 1000, **extra}))
            self.assertIsNone(body, extra)
        for top in ("tool_choice", "toolChoice", "models", "route", "plugins", "provider_options"):
            self.assertIsNone(sp.build_body(score_req(**{top: ["x"]}))[0], top)
        self.assertIsNone(sp.build_body(score_req(tools=[{"name": "t"}]))[0])
        self.assertIsNone(sp.build_body(score_req(messages=[{"role": "tool", "content": "x"}]))[0])
        rp = self.provider(handle=self.auth(models=[SONNET, HAIKU, OPUS]))
        body, _ = rp.build_body(req("investigator", params={"maxOutputTokens": 1000, "category": "scoring"}))
        self.assertIsNotNone(body)
        self.assertNotIn('"scoring"', json.dumps(body))                          # review params never become a category
        self.assertNotIn("scoring", self.receipts() and json.dumps(self.receipts()) or "")

    def test_score_body_is_fixed_no_hidden_params_and_ledger_intent_is_scoring(self):
        p = self.sp(FakeTransport(HttpResponse(200, {}, completion(json.dumps({"candidates": []}), model=OPUS))))
        body, _ = p.build_body(score_req(params={"maxOutputTokens": 1000, "timeoutSec": 30}))
        self.assertEqual(set(body), {"model", "messages", "max_tokens", "stream", "response_format", "provider"})
        self.assertEqual((body["model"], body["stream"], body["max_tokens"]), (OPUS, False, 1000))
        self.assertEqual(body["provider"], {"order": ["anthropic"], "only": ["anthropic"], "allow_fallbacks": False,
                                            "require_parameters": True})
        self.assertEqual(body["response_format"]["json_schema"]["name"], "ScoreExtractionSegments")
        res = p.call(score_req(), ("S", "extractor", "a", 0, 0))
        self.assertEqual(len(self.transport.requests), 1)
        self.assertIsNotNone(res.response)
        row = [r for r in self.receipts() if r["type"] == "intent"][0]
        self.assertEqual(row["category"], "scoring")
        self.assertEqual(self.ledger.totals("scoring")["calls"], 1)

    def test_scoring_provider_refuses_when_campaign_cap_would_be_exceeded_without_sending(self):
        p = self.sp(category_cap=1, aggregate_ceiling=CEIL)                    # tighter than any worst case
        res = p.call(score_req(), ("S", "extractor", "a", 0, 0))
        self.assertIsNone(res.response)
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.ledger.totals("scoring")["calls"], 0)


class StartupHold(RT):
    """SCORE-RT-03/04: a NEW scoring provider refuses prior unresolved scoring exposure at construction."""
    SENT = "SENTINEL-KEY-9"

    def pre(self, rows_fn):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        lg = RuntimeLedger(self.ledger_path, 50_000_000)
        rows_fn(lg)
        return lg

    def scoring(self, **kw):
        return self.provider(handle=self.auth(models=[SONNET, HAIKU, OPUS]), category="scoring", category_cap=CAP,
                             aggregate_ceiling=CEIL, **kw)

    def assert_held(self, reason=None):
        before = self.ledger_path.read_bytes() if self.ledger_path.exists() else None
        book_before = self.book_path.read_bytes() if self.book_path.exists() else None
        with self.assertRaises(AuthorizationError) as cm:
            self.scoring()
        msg = str(cm.exception)
        self.assertIn("scoring startup hold", msg)
        if reason:
            self.assertIn(reason, msg)
        for leak in (self.SENT, "000", "sk-", OPUS):
            self.assertNotIn(leak, msg)
        self.assertEqual(self.ledger_path.read_bytes() if self.ledger_path.exists() else None, before)
        self.assertEqual(self.book_path.read_bytes() if self.book_path.exists() else None, book_before)
        self.assertEqual(self.transport.requests, [])

    def test_unfinished_scoring_intent_holds_a_new_provider_after_reopen(self):
        self.transport = FakeTransport()
        self.pre(lambda lg: lg.admit(self.SENT, 123_456, model=OPUS, **S))
        self.assert_held("prior-unresolved-scoring-exposure")

    def test_finished_unknown_outcomes_hold_and_reconcile_is_the_only_clearing_step(self):
        def rows(lg):
            lg.admit("u", 2_000_000, model=OPUS, **S)
            lg.finish("u", outcome="unknown", errorKind="timeout", costBasis="unknown", generationId="gen-7")
            lg.admit("bad", 1_000_000, model=OPUS, **S)           # processed but cost unusable -> unknown bound
            lg.finish("bad", outcome="processed", routerCostUsdMicros=None, tokenPricedUsdMicros=None,
                      upstreamInferenceCostUsdMicros=None, isByok=None)
        lg = self.pre(rows)
        self.assert_held("prior-unresolved-scoring-exposure")
        self.assertGreater(lg.totals("scoring")["unknownBoundUsdMicros"], 0)
        lg.reconcile("u", {"id": "gen-7", "total_cost": "0", "upstream_inference_cost": "0.0004", "is_byok": True})
        self.assert_held()                                          # 'bad' is still unresolved
        with self.assertRaises(ValueError):
            lg.reconcile("bad", {"id": "gen-x", "total_cost": "0"})  # no generation id on a result: cannot be cleared

    def test_reconciled_resolved_and_unsent_scoring_calls_do_not_hold(self):
        def rows(lg):
            lg.admit("u", 2_000_000, model=OPUS, **S)
            lg.finish("u", outcome="unknown", errorKind="timeout", costBasis="unknown", generationId="gen-7")
            lg.reconcile("u", {"id": "gen-7", "total_cost": "0", "upstream_inference_cost": "0.0004", "is_byok": True})
            lg.admit("ok", 1000, model=OPUS, **S)
            lg.finish("ok", outcome="processed", routerCostUsdMicros=0, tokenPricedUsdMicros=900,
                      upstreamInferenceCostUsdMicros=900, isByok=True)
            lg.admit("ns", 1000, model=OPUS, **S)
            lg.finish("ns", outcome="not-sent", errorKind="x", costBasis="unknown")
            lg.admit("rj", 1000, model=OPUS, **S)
            lg.finish("rj", outcome="rejected-before-processing", errorKind="http-400", costBasis="unknown")
        self.pre(rows)
        p = self.scoring()
        self.assertEqual(p.category, "scoring")

    def test_intent_only_orphan_cannot_be_reconciled_and_stays_held(self):
        lg = self.pre(lambda lg: lg.admit("orphan", 5_000_000, model=OPUS, **S))
        with self.assertRaises(ValueError):
            lg.reconcile("orphan", {"id": "g", "total_cost": "0"})
        self.assert_held()

    def test_review_startup_and_calls_unchanged_with_scoring_unknown_present(self):
        self.pre(lambda lg: lg.admit("orphan", 5_000_000, model=OPUS, **S))
        rp = self.provider(handle=self.auth(models=[SONNET, HAIKU, OPUS]))                 # default review provider
        self.assertEqual(rp.category, "review")
        res = rp.call(req("investigator"), ("E", "investigator", "a", 0, 0))
        self.assertIsNotNone(res.response)                                                  # review proceeds and is sent
        self.assertEqual(len(self.transport.requests), 1)
        self.assertEqual(self.ledger.totals("scoring")["unknownBoundUsdMicros"], 5_000_000)  # still counted, untouched
        # scoring orphans do not change review admission arithmetic except through the shared aggregate
        self.assertEqual(self.ledger.totals("review")["calls"], 1)

    def test_review_orphan_does_not_hold_scoring_and_missing_ledger_is_not_created(self):
        self.pre(lambda lg: lg.admit("revorphan", 5_000_000, model=SONNET))
        self.scoring()
        self.ledger_path.unlink()
        self.scoring()
        self.assertFalse(self.ledger_path.exists())                                          # guard is read-only

    def test_unreadable_or_foreign_category_ledger_holds_fail_closed(self):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_path.write_text("not json\n")
        self.assert_held("scoring-ledger-unreadable")
        self.ledger_path.write_text(json.dumps({"type": "intent", "at": "t", "callKey": "x", "model": OPUS,
                                                "worstCaseUsdMicros": 1, "category": "bogus"}) + "\n")
        self.assert_held("scoring-ledger-unreadable")

    def test_no_override_and_own_inflight_does_not_poison_the_live_instance(self):
        with self.assertRaises(TypeError):
            self.provider(handle=self.auth(models=[SONNET, HAIKU, OPUS]), category="scoring", category_cap=CAP,
                          aggregate_ceiling=CEIL, allow_unresolved=True)
        p = self.scoring(transport=FakeTransport(HttpResponse(200, {}, completion(json.dumps({"candidates": []}), model=OPUS))))
        r = p.call(score_req(), ("S", "extractor", "a", 0, 0))
        self.assertIsNotNone(r.response)
        r2 = p.call(score_req(), ("S", "extractor", "a", 1, 0))                             # same instance keeps working
        self.assertIsNotNone(r2.response)

    def test_hold_runs_before_any_admit_or_http_even_with_a_perfect_request(self):
        self.pre(lambda lg: lg.admit("orphan", 1, model=OPUS, **S))
        with self.assertRaises(AuthorizationError):
            self.scoring(transport=FakeTransport())
        self.assertEqual(self.transport.requests, [])


class Ownership(RT):
    """SCORE-RT-05/06: only the live admitting ledger instance (and pid) may complete a scoring call, once."""
    def led(self):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        return RuntimeLedger(self.ledger_path, 50_000_000)

    def raw(self):
        return self.ledger_path.read_bytes() if self.ledger_path.exists() else b""

    def test_owned_completions_of_every_outcome_work_once(self):
        lg = self.led()
        for i, (outcome, extra) in enumerate((("not-sent", {}), ("rejected-before-processing", {}), ("unknown", {}),
                                              ("processed", dict(routerCostUsdMicros=0, tokenPricedUsdMicros=900,
                                                                  upstreamInferenceCostUsdMicros=900, isByok=True)))):
            lg.admit(f"k{i}", 1000, model=OPUS, **S)
            lg.finish(f"k{i}", outcome=outcome, errorKind="x", costBasis="unknown", **extra)
        t = lg.totals("scoring")
        self.assertEqual((t["calls"], t["unknownBoundUsdMicros"]), (4, 1000))      # only the unknown stays exposed

    def test_duplicate_terminal_result_refused_with_zero_mutation(self):
        lg = self.led()
        lg.admit("a", 1000, model=OPUS, **S)
        lg.finish("a", outcome="unknown", errorKind="timeout", costBasis="unknown")
        before = self.raw()
        for outcome in ("not-sent", "rejected-before-processing", "unknown", "processed"):
            with self.assertRaises(ValueError):
                lg.finish("a", outcome=outcome, errorKind="x", costBasis="unknown")
        self.assertEqual(self.raw(), before)
        self.assertEqual(lg.totals("scoring")["unknownBoundUsdMicros"], 1000)

    def test_new_instance_cannot_complete_a_prior_orphan_any_outcome(self):
        self.led().admit("orphan", 5_000_000, model=OPUS, **S)
        before = self.raw()
        fresh = self.led()
        for outcome in ("not-sent", "rejected-before-processing", "unknown", "processed"):
            with self.assertRaises(ValueError):
                fresh.finish("orphan", outcome=outcome, errorKind="x", costBasis="unknown")
        self.assertEqual(self.raw(), before)
        self.assertEqual(fresh.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})

    def test_ownership_is_per_key_per_instance_and_cannot_be_granted_by_params(self):
        a, b = self.led(), self.led()
        a.admit("ka", 10, model=OPUS, **S)
        b.admit("kb", 10, model=OPUS, **S)
        before = self.raw()
        for lg, k in ((a, "kb"), (b, "ka")):
            with self.assertRaises(ValueError):
                lg.finish(k, outcome="not-sent", errorKind="x", costBasis="unknown")
        for bad in (dict(owner=True), dict(pid=os.getpid()), dict(category="review"), dict(owned=True)):
            with self.assertRaises(ValueError):
                a.finish("ka", outcome="not-sent", **bad)                           # not receipt fields at all
        self.assertEqual(self.raw(), before)
        a.finish("ka", outcome="not-sent", errorKind="x", costBasis="unknown")
        b.finish("kb", outcome="rejected-before-processing", errorKind="x", costBasis="unknown")

    def test_forked_child_does_not_inherit_ownership(self):
        lg = self.led()
        lg.admit("k", 1000, model=OPUS, **S)
        before = self.raw()
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:                                      # child: same object, same fds, different pid
            code = 3
            try:
                lg.finish("k", outcome="not-sent", errorKind="x", costBasis="unknown")
            except ValueError:
                code = 0
            except BaseException:
                code = 2
            os._exit(code)
        _, status = os.waitpid(pid, 0)
        os.close(r), os.close(w)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(self.raw(), before)
        lg.finish("k", outcome="not-sent", errorKind="x", costBasis="unknown")      # the owning pid still can

    def test_refused_admission_grants_no_ownership_so_a_duplicate_readmit_cannot_release_an_orphan(self):
        self.led().admit("orphan", 1_000_000, model=OPUS, **S)
        before = self.raw()
        fresh = self.led()
        self.assertEqual(fresh.admit("orphan", 1_000_000, model=OPUS, **S), {"reason": "duplicate-call-key"})
        self.assertEqual(fresh.admit("big", CAP, model=OPUS, **S)["reason"], "scoring-campaign-cap")
        with self.assertRaises(ValueError):
            fresh.finish("orphan", outcome="not-sent", errorKind="x", costBasis="unknown")
        self.assertEqual(self.raw(), before)

    def test_review_semantics_unchanged_including_overwrite_and_no_intent_keys(self):
        lg = self.led()
        lg.admit("r", 100, model=SONNET)
        lg.finish("r", outcome="unknown", errorKind="x", costBasis="unknown")
        lg.finish("r", outcome="not-sent", errorKind="x", costBasis="unknown")       # legacy: last result wins
        self.assertEqual(lg.totals("review")["unknownBoundUsdMicros"], 0)
        fresh = self.led()
        lg.admit("r2", 100, model=SONNET)
        fresh.finish("r2", outcome="not-sent", errorKind="x", costBasis="unknown")   # review: any instance, as before
        fresh.finish("no-intent", outcome="not-sent", errorKind="x", costBasis="unknown")

    def test_provider_composition_owned_not_sent_rejected_unknown_processed_all_complete(self):
        from reviewer.runtime.openrouter import TransportError
        outcomes = [("not-sent", TransportError(False)), ("rejected-before-processing", HttpResponse(400, {}, b"{}")),
                    ("unknown", TransportError(True)),
                    ("processed", HttpResponse(200, {}, completion(json.dumps({"candidates": []}), model=OPUS)))]
        p = self.provider(FakeTransport(*[o[1] for o in outcomes]), handle=self.auth(models=[SONNET, HAIKU, OPUS]),
                          category="scoring", category_cap=CAP, aggregate_ceiling=CEIL)
        for i, (outcome, _) in enumerate(outcomes):
            res = p.call(score_req(), ("S", "extractor", "a", i, 0))
            self.assertEqual(res.outcome, outcome)
        done = {r["outcome"] for r in self.receipts() if r["type"] == "result"}
        self.assertEqual(done, {o for o, _ in outcomes})
        self.assertEqual(self.ledger.totals("scoring")["calls"], 4)
        self.assertGreater(self.ledger.totals("scoring")["unknownBoundUsdMicros"], 0)    # only the unknown one

    def test_estimated_scoring_exposure_holds_startup_and_clears_only_by_reconcile(self):
        lg = self.led()
        lg.admit("e", 3_000_000, model=OPUS, **S)
        lg.finish("e", outcome="processed", generationId="gen-e", routerCostUsdMicros=0, tokenPricedUsdMicros=None,
                  upstreamInferenceCostUsdMicros=None, isByok=None)
        t = lg.totals("scoring")
        self.assertEqual((t["estimatedUsdMicros"], t["unknownBoundUsdMicros"]), (3_000_000, 0))
        h = dict(handle=self.auth(models=[SONNET, HAIKU, OPUS]), category="scoring", category_cap=CAP, aggregate_ceiling=CEIL)
        before = self.raw()
        with self.assertRaises(AuthorizationError) as cm:
            self.provider(**h)
        self.assertIn("prior-unresolved-scoring-exposure", str(cm.exception))
        self.assertEqual(self.raw(), before)
        self.assertEqual(self.transport.requests, [])
        lg.reconcile("e", {"id": "gen-e", "total_cost": "0", "upstream_inference_cost": "0.0004", "is_byok": True})
        self.assertIsNone(self.led().scoring_startup_hold())
        self.provider(**h)

    def test_review_estimated_or_unknown_never_holds_scoring_startup(self):
        lg = self.led()
        lg.admit("r1", 1000, model=SONNET)                                              # review orphan
        lg.admit("r2", 3_000_000, model=SONNET)
        lg.finish("r2", outcome="processed", routerCostUsdMicros=0, tokenPricedUsdMicros=None,
                  upstreamInferenceCostUsdMicros=None, isByok=None)                     # review estimated
        self.assertGreater(lg.totals("review")["estimatedUsdMicros"], 0)
        self.assertIsNone(self.led().scoring_startup_hold())


if __name__ == "__main__":
    unittest.main(verbosity=1)
