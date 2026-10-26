"""S1-21 reference-compatible counting. Invented judgments only; expected values hand-derived from the pinned semantics."""

import json
import math
import random
import unittest

from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.reference import (MAX_BETA, REFERENCE_PROFILES, ZERO_CONVENTION, evaluate_reference,
                                          pool_reference, reference_is_hidden)


def gold(*specs):
    """specs: (id, text, category)."""
    return [{"id": i, "comment": t, "severity": "High", "category": c} for i, t, c in specs]


def cands(*specs):
    return [{"id": i, "text": t} for i, t in specs]


def judge(golden, candidates, hits=(), errors=()):
    """All pairs; hits {(gid, cid): confidence}, everything else a non-match at 0.9."""
    hits, out = dict(hits), []
    for g in golden:
        for c in candidates:
            k = (g["id"], c["id"])
            if k in errors:
                out.append({"golden": k[0], "candidate": k[1], "error": "Timed out after 30s"})
            else:
                out.append({"golden": k[0], "candidate": k[1], "match": k in hits, "confidence": hits.get(k, 0.9)})
    return out


class Matching(unittest.TestCase):
    def run_ref(self, g, c, hits=(), errors=(), groups=None):
        return evaluate_reference(g, c, judge(g, c, hits, errors), groups)

    def test_one_candidate_matches_many_goldens(self):
        g, c = gold(("g1", "A", "bug"), ("g2", "B", "perf")), cands(("c1", "x"))
        r = self.run_ref(g, c, {("g1", "c1"): 0.8, ("g2", "c1"): 0.7})
        self.assertEqual((r["tp"], r["fp"], r["fn"]), (2, 0, 0))
        self.assertEqual([t["matchedCandidateId"] for t in r["truePositives"]], ["c1", "c1"])

    def test_many_to_one_is_order_sensitive(self):
        g = gold(("g1", "A", "bug"))
        up = self.run_ref(g, cands(("c1", "lo"), ("c2", "hi")), {("g1", "c1"): 0.5, ("g1", "c2"): 0.9})
        self.assertEqual((up["tp"], up["fp"]), (1, 0))  # both improved in turn, so both stay matched
        self.assertEqual(up["truePositives"][0]["matchedCandidateId"], "c2")
        down = self.run_ref(g, cands(("c2", "hi"), ("c1", "lo")), {("g1", "c1"): 0.5, ("g1", "c2"): 0.9})
        self.assertEqual((down["tp"], down["fp"]), (1, 1))
        self.assertEqual(down["falsePositives"], [{"candidate": "lo", "candidateIds": ["c1"]}])

    def test_confidence_tie_keeps_first_and_zero_or_missing_never_matches(self):
        g = gold(("g1", "A", "bug"))
        c = cands(("c1", "x"), ("c2", "y"))
        r = self.run_ref(g, c, {("g1", "c1"): 0.7, ("g1", "c2"): 0.7})
        self.assertEqual((r["truePositives"][0]["matchedCandidateId"], r["fp"]), ("c1", 1))
        for j in ({"match": True, "confidence": 0}, {"match": True, "confidence": 0.0}, {"match": True}):
            r = evaluate_reference(g, c[:1], [{"golden": "g1", "candidate": "c1", **j}])
            self.assertEqual((r["tp"], r["fn"], r["fp"]), (0, 1, 1), j)

    def test_missing_confidence_key_is_distinct_from_explicit_null(self):
        g, c = gold(("g1", "A", "bug")), cands(("c1", "x"), ("c2", "y"))
        # missing key on c1 never improves; a later scored match still does
        j = [{"golden": "g1", "candidate": "c1", "match": True},
             {"golden": "g1", "candidate": "c2", "match": True, "confidence": 0.4}]
        r = evaluate_reference(g, c, j)
        self.assertEqual((r["tp"], r["fp"], r["truePositives"][0]["matchedCandidateId"]), (1, 1, "c2"))
        # explicit null: S3:322 raises TypeError when match is truthy; refused for both match values (D3)
        for match in (True, False):
            bad = [{"golden": "g1", "candidate": "c1", "match": match, "confidence": None}, j[1]]
            with self.subTest(match=match), self.assertRaises(BenchmarkError) as e:
                evaluate_reference(g, c, bad)
            self.assertEqual(e.exception.code, "reference-input")

    def test_judgment_list_order_does_not_change_processing_order(self):
        g, c = gold(("g1", "A", "bug"), ("g2", "B", "bug")), cands(("c1", "x"), ("c2", "y"), ("c3", "z"))
        hits = {("g1", "c3"): 0.9, ("g1", "c1"): 0.4, ("g2", "c2"): 0.6}
        j = judge(g, c, hits)
        base = evaluate_reference(g, c, j)
        random.Random(7).shuffle(j)
        self.assertEqual(evaluate_reference(g, c, j), base)
        self.assertEqual([i["candidate"] for i in base["provenance"]["improvements"]], ["c1", "c3", "c2"])

    def test_literal_duplicate_golden_text_collapses_last_category_wins(self):
        g = gold(("g1", "Same", "style"), ("g2", "Other", "bug"), ("g3", "Same", "bug"))
        c = cands(("c1", "x"))
        r = self.run_ref(g, c, {("g3", "c1"): 0.6})
        self.assertEqual((r["tp"], r["fn"], r["totalGolden"]), (1, 1, 3))
        tp = r["truePositives"][0]
        self.assertEqual((tp["goldenIds"], tp["category"]), (["g1", "g3"], "bug"))
        self.assertEqual(r["provenance"]["goldenCollapse"], {"Same": ["g1", "g3"]})
        self.assertEqual([f["goldenComment"] for f in r["falseNegatives"]], ["Other"])

    def test_literal_duplicate_candidate_text_collapses(self):
        g = gold(("g1", "A", "bug"))
        c = cands(("c1", "dup"), ("c2", "dup"), ("c3", "solo"))
        r = self.run_ref(g, c)
        self.assertEqual((r["fp"], r["totalCandidates"]), (2, 3))
        self.assertEqual(r["falsePositives"][0], {"candidate": "dup", "candidateIds": ["c1", "c2"]})
        r = self.run_ref(g, c, {("g1", "c2"): 0.5})  # either occurrence marks the text
        self.assertEqual((r["tp"], r["fp"]), (1, 1))

    def test_duplicate_siblings_excluded_only_when_their_candidate_matches(self):
        g = gold(("g1", "A", "bug"))
        c = cands(("c1", "p"), ("c2", "q"), ("c3", "r"), ("c4", "s"))
        r = self.run_ref(g, c, {("g1", "c1"): 0.8}, groups=[[0, 1], [2, 3, 9]])
        self.assertEqual(r["fp"], 2)  # q excluded as sibling; r and s unmatched group still both count
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["r", "s"])
        self.assertEqual(r["provenance"]["siblingMarked"], [{"via": "c1", "candidate": "q"}])
        self.assertEqual(r["provenance"]["ignoredGroupIndices"], [[1, 9]])
        self.assertEqual(self.run_ref(g, c, {("g1", "c1"): 0.8}, groups=[])["fp"], 3)

    def test_later_group_overwrites_sibling_map(self):
        g, c = gold(("g1", "A", "bug")), cands(("c1", "p"), ("c2", "q"), ("c3", "r"))
        r = self.run_ref(g, c, {("g1", "c1"): 0.8}, groups=[[0, 1], [0, 2]])
        self.assertEqual(r["provenance"]["siblingMap"]["p"], ["r"])
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["q"])

    def test_error_pairs_are_skipped_and_reported(self):
        g, c = gold(("g1", "A", "bug")), cands(("c1", "x"), ("c2", "y"))
        r = self.run_ref(g, c, {("g1", "c1"): 0.9}, errors={("g1", "c1")})
        self.assertEqual((r["tp"], r["fn"], r["fp"], r["errorsCount"]), (0, 1, 2, 1))
        self.assertEqual(r["errors"][0], {"golden": "g1", "candidate": "c1", "error": "Timed out after 30s"})

    def test_zero_gold_skips_and_zero_candidates_are_uncollapsed_fn(self):
        r = evaluate_reference([], cands(("c1", "x")), [])
        self.assertEqual((r["skipped"], r["reason"]), (True, "No golden comments"))
        g = gold(("g1", "Same", "bug"), ("g2", "Same", "perf"))
        r = evaluate_reference(g, [], [])
        self.assertEqual((r["skipped"], r["fn"], r["fp"], r["tp"]), (False, 2, 0, 0))
        self.assertEqual([f["category"] for f in r["falseNegatives"]], ["bug", "perf"])

    def test_malformed_inputs_refused(self):
        g, c = gold(("g1", "A", "bug")), cands(("c1", "x"), ("c2", "y"))
        ok = judge(g, c)
        bad = {
            "missing pair": (g, c, ok[:1], None),
            "duplicate pair": (g, c, ok + ok[:1], None),
            "unknown id": (g, c, ok + [{"golden": "g9", "candidate": "c1", "match": False, "confidence": 0}], None),
            "duplicate id": (g, cands(("c1", "x"), ("c1", "y")), ok, None),
            "non-bool match": (g, c, [dict(ok[0], match="false"), ok[1]], None),
            "bool confidence": (g, c, [dict(ok[0], confidence=True), ok[1]], None),
            "extra key": (g, c, [dict(ok[0], reasoning="r"), ok[1]], None),
            "error and match": (g, c, [dict(ok[0], error="e"), ok[1]], None),
            "empty candidate text": (g, cands(("c1", ""), ("c2", "y")), ok, None),
            "negative index": (g, c, ok, [[0, -1]]),
            "bool index": (g, c, ok, [[True, 1]]),
            "extra golden key": ([dict(g[0], line=3)], c, ok, None),
            "missing id": ([{"comment": "A"}], c, ok, None),
        }
        for name, args in bad.items():
            with self.subTest(name), self.assertRaises(BenchmarkError) as e:
                evaluate_reference(*args)
            self.assertEqual(e.exception.code, "reference-input")

    def test_hardening_typed_refusals(self):
        g, c = gold(("g1", "A", "bug")), cands(("c1", "x"))
        ok = judge(g, c)
        bad = {
            "F1 unhashable golden id": (g, c, [dict(ok[0], golden=[])]),
            "F1 unhashable candidate id": (g, c, [dict(ok[0], candidate={"c": 1})]),
            "F1 int id": (g, c, [dict(ok[0], golden=1)]),
            "D4 nan": (g, c, [dict(ok[0], match=True, confidence=float("nan"))]),
            "D4 inf": (g, c, [dict(ok[0], match=True, confidence=float("inf"))]),
            "D4 -inf": (g, c, [dict(ok[0], match=False, confidence=float("-inf"))]),
            "F5 list category": ([dict(g[0], category=["bug"])], c, ok),
            "F5 int severity": ([dict(g[0], severity=3)], c, ok),
        }
        for name, args in bad.items():
            with self.subTest(name), self.assertRaises(BenchmarkError) as e:
                evaluate_reference(*args)
            self.assertEqual(e.exception.code, "reference-input")
        r = evaluate_reference([{"id": "g1", "comment": "A", "category": None, "severity": None}], c, ok)
        self.assertEqual(r["falseNegatives"][0]["category"], None)  # null labels remain compatible

    def test_numeric_domain_huge_integer_confidence(self):
        # N1: an int beyond the double range is a typed refusal, never a raw OverflowError, whatever the match value
        g, c = gold(("g1", "A", "bug")), cands(("c1", "x"), ("c2", "y"))
        for conf in (10 ** 400, -10 ** 400, 2 ** 1024):
            for match in (True, False):
                j = judge(g, c)
                j[0].update(match=match, confidence=conf)
                with self.subTest(conf=str(conf)[:6], match=match), self.assertRaises(BenchmarkError) as e:
                    evaluate_reference(g, c, j)
                self.assertEqual(e.exception.code, "reference-input")
        # in-domain extremes still compare exactly as S3 would (int vs float, no float conversion): int(1e308) + 1 is
        # one above the float 1e308, so it improves; converted to a double it would tie and c1 would stay matched
        r = self.run_ref(g, c, {("g1", "c1"): 1e308, ("g1", "c2"): int(1e308) + 1})
        self.assertEqual((r["truePositives"][0]["matchedCandidateId"], r["truePositives"][0]["confidence"]),
                         ("c2", int(1e308) + 1))
        self.assertEqual((r["tp"], r["fp"]), (1, 0))
        json.dumps(r, allow_nan=False)

    def test_zero_candidate_provenance_has_same_keys(self):
        g = gold(("g1", "A", "bug"))
        full = self.run_ref(g, cands(("c1", "x")))["provenance"]
        empty = evaluate_reference(g, [], [], [[0, 2]])["provenance"]
        self.assertEqual(set(empty), set(full))
        self.assertEqual((empty["zeroCandidates"], full["zeroCandidates"]), (True, False))
        self.assertEqual((empty["ignoredGroupIndices"], empty["goldenCollapse"]), ([[0, 0], [0, 2]], {}))


class Pooling(unittest.TestCase):
    def setUp(self):
        g1 = gold(("g1", "A", "bug"), ("g2", "B", "style"), ("g3", "C", None))
        c1 = cands(("c1", "x"), ("c2", "y"), ("c3", "z"))
        e1 = evaluate_reference(g1, c1, judge(g1, c1, {("g1", "c1"): 0.9, ("g2", "c2"): 0.8}))
        g2 = gold(("h1", "D", "perf"))
        e2 = evaluate_reference(g2, cands(("d1", "w")), judge(g2, cands(("d1", "w"))))
        skipped = evaluate_reference([], cands(("d1", "w")), [])
        self.evals = {"case1": {"tool": e1, "greptile": e1, "mra-x": e1},
                      "case2": {"tool": e2, "only-skipped": skipped},
                      "case3": {"tool": skipped}}
        self.lookup = {"C": "security"}  # category fallback for the null-category golden

    def test_profiles_filter_tp_fn_but_not_supplied_fp(self):
        # case1: TP A(bug) B(style), FN C(None->security), FP z; case2: FN D(perf), FP w
        exp = {"strict": (1, 2, 1), "core": (1, 2, 2), "all": (2, 2, 2)}
        for prof, (tp, fp, fn) in exp.items():
            r = pool_reference(self.evals, profile=prof, beta=1.0, golden_categories=self.lookup)["tool"]
            self.assertEqual((r["tp"], r["fp"], r["fn"], r["prs"]), (tp, fp, fn, 2), prof)
        r = pool_reference(self.evals, profile="core", beta=2, golden_categories=self.lookup)
        self.assertEqual(set(r), {"tool"})  # hidden ids/prefix and skipped-only tools absent
        t = r["tool"]
        self.assertAlmostEqual(t["precision"], 1 / 3)
        self.assertAlmostEqual(t["recall"], 1 / 3)
        self.assertAlmostEqual(t["f1"], 1 / 3)
        self.assertAlmostEqual(t["fbeta"], 1 / 3)
        no_lookup = pool_reference(self.evals, profile="strict", beta=1.0)["tool"]
        self.assertEqual(no_lookup["fn"], 0)

    def test_pooled_micro_not_mean_of_cases(self):
        r = pool_reference(self.evals, profile="all", beta=1.0, golden_categories=self.lookup)["tool"]
        self.assertAlmostEqual(r["precision"], 2 / 4)  # mean of per-case precisions would be (2/3 + 0)/2
        self.assertAlmostEqual(r["recall"], 2 / 4)

    def test_reference_zero_convention_is_named(self):
        g = gold(("g1", "A", "style"))
        e = evaluate_reference(g, [], [])
        r = pool_reference({"k": {"t": e}}, profile="strict", beta=1.0)["t"]
        self.assertEqual((r["precision"], r["recall"], r["f1"], r["fbeta"]), (0.0, 0.0, 0.0, 0.0))
        self.assertEqual((r["undefined"], r["zeroConvention"]), (["precision", "recall"], ZERO_CONVENTION))

    def test_supplied_fp_used_unchanged(self):
        r = pool_reference({"k": {"t": {"truePositives": [], "falseNegatives": [], "fp": 7}}}, profile="core", beta=1.0)
        self.assertEqual((r["t"]["fp"], r["t"]["undefined"]), (7, ["recall"]))

    def test_explicit_profile_and_beta_required(self):
        for kw in ({"profile": "default", "beta": 1.0}, {"profile": "core", "beta": 0}, {"profile": "core", "beta": True},
                   {"profile": "core", "beta": float("nan")}):
            with self.subTest(kw), self.assertRaises(BenchmarkError):
                pool_reference(self.evals, **kw)
        with self.assertRaises(BenchmarkError):
            pool_reference({"k": {"t": [1]}}, profile="core", beta=1.0)
        for kw in ({"profile": ["core"], "beta": 1.0}, {"profile": None, "beta": 1.0},
                   {"profile": "core", "beta": float("inf")}):
            with self.subTest(kw), self.assertRaises(BenchmarkError):
                pool_reference(self.evals, **kw)

    def test_numeric_domain_beta(self):
        # N2: SP computes beta*beta in floats; past MAX_BETA it is inf and SP's Fbeta is NaN. Refused, never clamped.
        ev = {"k": {"t": {"truePositives": [{"category": "bug"}], "falseNegatives": [{"category": "bug"}] * 3, "fp": 1}}}
        for beta in (10 ** 400, 10 ** 155, math.nextafter(MAX_BETA, math.inf), 1e200, 1e308):
            with self.subTest(beta=str(beta)[:8]), self.assertRaises(BenchmarkError) as e:
                pool_reference(ev, profile="all", beta=beta)
            self.assertEqual(e.exception.code, "reference-input")
        # p=1/2, r=1/4: hand oracles F1 = 1/3, F2 = 5/18; the int and float spellings of 2 agree exactly
        r1, r2, r2i = (pool_reference(ev, profile="all", beta=b)["t"] for b in (1.0, 2.0, 2))
        self.assertEqual((r1["precision"], r1["recall"]), (0.5, 0.25))
        self.assertAlmostEqual(r1["f1"], 1 / 3)
        self.assertAlmostEqual(r1["fbeta"], 1 / 3)
        self.assertAlmostEqual(r2["fbeta"], 5 / 18)
        self.assertEqual(r2["fbeta"], r2i["fbeta"])
        # boundary values stay finite and approach the limits: recall as beta grows, precision as it shrinks
        for beta, limit in ((MAX_BETA, 0.25), (10 ** 154, 0.25), (5e-324, 0.5), (1e-200, 0.5)):
            t = pool_reference(ev, profile="all", beta=beta)["t"]
            self.assertTrue(math.isfinite(t["fbeta"]), beta)
            self.assertAlmostEqual(t["fbeta"], limit, msg=str(beta))
            json.dumps(t, allow_nan=False)

    def test_numeric_domain_huge_supplied_fp(self):
        # A supplied fp is an exact int (not range-limited); int/int true division keeps the ratios finite
        r = pool_reference({"k": {"t": {"truePositives": [{"category": "bug"}], "fp": 10 ** 400}}},
                           profile="all", beta=2.0)["t"]
        self.assertEqual((r["fp"], r["precision"], r["recall"], r["f1"], r["fbeta"]), (10 ** 400, 0.0, 1.0, 0.0, 0.0))
        json.dumps(r, allow_nan=False)

    def test_malformed_evaluations_refused(self):
        row = {"goldenComment": "A", "category": "bug"}
        bad_evs = [{"fp": "3"}, {"fp": None}, {"fp": -2}, {"fp": True}, {"fp": 1.0}, {"skipped": "yes"},
                   {"truePositives": 5}, {"truePositives": ["x"]}, {"falseNegatives": [dict(row, category=["bug"])]},
                   {"truePositives": [dict(row, goldenComment=None)]}, {"falseNegatives": [dict(row, severity=2)]}]
        for ev in bad_evs:
            with self.subTest(ev), self.assertRaises(BenchmarkError):
                pool_reference({"k": {"t": ev}}, profile="all", beta=1.0)
        # hidden and skipped rows are validated too, though never counted
        for tool in ("greptile", "mra-x"):
            with self.subTest(tool), self.assertRaises(BenchmarkError):
                pool_reference({"k": {tool: {"fp": -1}}}, profile="all", beta=1.0)
        with self.assertRaises(BenchmarkError):
            pool_reference({"k": {"t": {"skipped": True, "fp": "x"}}}, profile="all", beta=1.0)
        for shape in ({"k": {3: {}}}, {"k": {"": {}}}, {3: {"t": {}}}):
            with self.subTest(shape), self.assertRaises(BenchmarkError):
                pool_reference(shape, profile="all", beta=1.0)
        for lookup in ([], {"A": None}, {"A": ["bug"]}, {1: "bug"}):
            with self.subTest(lookup), self.assertRaises(BenchmarkError):
                pool_reference({"k": {"t": {}}}, profile="all", beta=1.0, golden_categories=lookup)

    def test_compatible_minimal_shapes_keep_upstream_defaults(self):
        evs = {"k": {"t": {}, "u": {"skipped": True, "reason": "No golden comments"},
                     "v": {"skipped": False, "fp": 0, "truePositives": [{}, {"category": ""}],
                           "falseNegatives": [{"goldenComment": "B", "category": None, "extra": 1}]}}}
        r = pool_reference(evs, profile="all", beta=1.0, golden_categories={"B": "bug", "": "bug"})
        self.assertEqual(set(r), {"t", "v"})
        self.assertEqual((r["t"]["prs"], r["t"]["fp"], r["t"]["tp"]), (1, 0, 0))
        # missing goldenComment -> "" -> lookup "" (SP:76); explicit "" category also falls back
        self.assertEqual((r["v"]["tp"], r["v"]["fn"]), (2, 1))

    def test_profiles_and_hidden_rules(self):
        self.assertEqual(len(REFERENCE_PROFILES["core"]), 8)
        self.assertTrue(REFERENCE_PROFILES["strict"] < REFERENCE_PROFILES["core"] < REFERENCE_PROFILES["all"])
        for tool, hidden in (("cubic-v2", False), ("greptile-v5", False), ("greptile-v4-1", False),
                             ("coderabbit", False), ("cubic-v3", True), ("greptile-v4", True), ("mra-z", True)):
            self.assertEqual(reference_is_hidden(tool), hidden, tool)


if __name__ == "__main__":
    unittest.main()
