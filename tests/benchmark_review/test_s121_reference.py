"""S1-21 independent gate for reviewer/benchmark/reference.py. Invented data only; oracles hand-computed from the
pinned S3 (step3 evaluate_review) / SP (score_tools) semantics read as text. No product edits."""

import itertools
import json
import math
import unittest
from fractions import Fraction

from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.reference import MAX_BETA, evaluate_reference, pool_reference, reference_is_hidden


def G(i, text, cat=None, sev=None):
    d = {"id": i, "comment": text}
    if sev is not None:
        d["severity"] = sev
    if cat is not None:
        d["category"] = cat
    return d


def C(i, text):
    return {"id": i, "text": text}


def M(g, c, match=False, **kw):
    return {"golden": g, "candidate": c, "match": match, **kw}


def E(g, c, msg="boom"):
    return {"golden": g, "candidate": c, "error": msg}


def full(golds, cs, hits=None, errs=()):
    """Every pair, golden-major; hits {(g,c): conf}; unlisted pairs are non-matches carrying a high confidence."""
    hits = hits or {}
    return [E(g["id"], c["id"]) if (g["id"], c["id"]) in errs
            else M(g["id"], c["id"], (g["id"], c["id"]) in hits, confidence=hits.get((g["id"], c["id"]), 0.99))
            for g in golds for c in cs]


class Counting(unittest.TestCase):
    def test_all_pairs_order_ties_and_earlier_improvers_stay_matched(self):
        golds = [G("g1", "A"), G("g2", "B")]
        cs = [C("c1", "x"), C("c2", "y"), C("c3", "z")]
        hits = {("g1", "c1"): 0.4, ("g1", "c2"): 0.4, ("g1", "c3"): 0.6, ("g2", "c1"): 0.3, ("g2", "c2"): 0.3}
        js = full(golds, cs, hits)
        for order in (js, js[::-1], js[3:] + js[:3]):  # judgment list order is irrelevant
            r = evaluate_reference(golds, cs, order)
            # g1: c1 .4 improves; c2 .4 tie no; c3 .6 improves. g2: c1 .3 improves; c2 .3 tie no.
            self.assertEqual(r["provenance"]["improvements"], [
                {"golden": "g1", "candidate": "c1", "confidence": 0.4},
                {"golden": "g1", "candidate": "c3", "confidence": 0.6},
                {"golden": "g2", "candidate": "c1", "confidence": 0.3}])
            self.assertEqual([(t["goldenComment"], t["matchedCandidateId"], t["confidence"]) for t in r["truePositives"]],
                             [("A", "c3", 0.6), ("B", "c1", 0.3)])
            self.assertEqual(r["falsePositives"], [{"candidate": "y", "candidateIds": ["c2"]}])  # c1 stays matched
            self.assertEqual((r["tp"], r["fp"], r["fn"], r["totalGolden"], r["totalCandidates"]), (2, 1, 0, 2, 3))

    def test_descending_confidence_leaves_later_candidate_unmatched(self):
        golds, cs = [G("g1", "A")], [C("c1", "hi"), C("c2", "lo")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.9, ("g1", "c2"): 0.5}))
        self.assertEqual((r["tp"], r["fp"]), (1, 1))
        self.assertEqual(r["falsePositives"], [{"candidate": "lo", "candidateIds": ["c2"]}])

    def test_strict_improvement_from_zero(self):
        golds, cs = [G("g1", "A")], [C("c1", "x")]
        for extra in ({}, {"confidence": 0}, {"confidence": 0.0}, {"confidence": -0.5}):
            r = evaluate_reference(golds, cs, [M("g1", "c1", True, **extra)])
            self.assertEqual((r["tp"], r["fn"], r["fp"]), (0, 1, 1), extra)
        r = evaluate_reference(golds, cs, [M("g1", "c1", False, confidence=1.0)])
        self.assertEqual((r["tp"], r["fn"], r["fp"]), (0, 1, 1))
        r = evaluate_reference(golds, cs, [M("g1", "c1", True, confidence=1e-9)])
        self.assertEqual((r["tp"], r["fn"], r["fp"]), (1, 0, 0))
        r = evaluate_reference(golds, cs, [M("g1", "c1", True, confidence=1)])
        self.assertEqual(r["truePositives"][0]["confidence"], 1)

    def test_one_to_many_and_many_to_one(self):
        golds, cs = [G("g1", "A"), G("g2", "B")], [C("c1", "x")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5, ("g2", "c1"): 0.5}))
        self.assertEqual((r["tp"], r["fp"], r["fn"]), (2, 0, 0))
        golds, cs = [G("g1", "A")], [C("c1", "x"), C("c2", "y")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5, ("g1", "c2"): 0.5}))
        self.assertEqual((r["tp"], r["fp"], r["fn"]), (1, 0 + 1, 0))  # tie keeps c1; c2 never marked

    def test_duplicate_golden_text_collapses_first_position_last_metadata(self):
        golds = [G("g1", "A", "bug", "High"), G("g2", "B", "api", "Low"), G("g3", "A", "perf", "Low")]
        cs = [C("c1", "x")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5, ("g3", "c1"): 0.5}))
        # g3/c1 ties g1/c1 (best is shared per text) so only g1 improves, but the row exists once.
        self.assertEqual([i["golden"] for i in r["provenance"]["improvements"]], ["g1"])
        self.assertEqual(r["truePositives"], [{"goldenComment": "A", "goldenIds": ["g1", "g3"], "severity": "Low",
                                               "category": "perf", "matchedCandidate": "x", "matchedCandidateId": "c1",
                                               "confidence": 0.5}])
        self.assertEqual(r["falseNegatives"], [{"goldenComment": "B", "goldenIds": ["g2"], "severity": "Low",
                                                "category": "api"}])
        self.assertEqual((r["tp"], r["fn"], r["totalGolden"]), (1, 1, 3))  # totals are uncollapsed
        self.assertEqual(r["provenance"]["goldenCollapse"], {"A": ["g1", "g3"]})

    def test_duplicate_golden_text_later_duplicate_can_improve_shared_best(self):
        golds, cs = [G("g1", "A"), G("g2", "A")], [C("c1", "x"), C("c2", "y")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.3, ("g2", "c2"): 0.8}))
        self.assertEqual(r["truePositives"][0]["matchedCandidateId"], "c2")
        self.assertEqual((r["tp"], r["fp"]), (1, 0))  # c1 improved earlier and stays matched

    def test_duplicate_candidate_text_collapses_first_occurrence(self):
        golds, cs = [G("g1", "A")], [C("c1", "x"), C("c2", "x"), C("c3", "y")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c2"): 0.7}))
        self.assertEqual(r["falsePositives"], [{"candidate": "y", "candidateIds": ["c3"]}])
        self.assertEqual((r["tp"], r["fp"], r["totalCandidates"]), (1, 1, 3))
        self.assertEqual(r["provenance"]["candidateCollapse"], {"x": ["c1", "c2"]})
        self.assertEqual(r["truePositives"][0]["matchedCandidateId"], "c2")
        # nothing matches: one FP row for the text, carrying both ids, before y
        r = evaluate_reference(golds, cs, full(golds, cs))
        self.assertEqual(r["falsePositives"], [{"candidate": "x", "candidateIds": ["c1", "c2"]},
                                               {"candidate": "y", "candidateIds": ["c3"]}])
        self.assertEqual(r["fp"], 2)

    def test_siblings_later_group_overwrites_and_out_of_range_ignored(self):
        golds = [G("g1", "A")]
        cs = [C("c1", "a"), C("c2", "b"), C("c3", "c"), C("c4", "d")]
        groups = [[0, 1], [1, 2], [9]]
        # group0 -> a:{b}, b:{a}; group1 -> b:{c}, c:{b} (b overwritten); group2 index 9 ignored.
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5}), groups)
        self.assertEqual(r["provenance"]["siblingMap"], {"a": ["b"], "b": ["c"], "c": ["b"]})
        self.assertEqual(r["provenance"]["ignoredGroupIndices"], [[2, 9]])
        self.assertEqual(r["provenance"]["siblingMarked"], [{"via": "c1", "candidate": "b"}])
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["c", "d"])  # c not reached from a
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c2"): 0.5}), groups)  # b -> c (not a)
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["a", "d"])
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c3"): 0.5}), groups)  # c -> b
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["a", "d"])
        self.assertEqual((r["tp"], r["fp"]), (1, 2))

    def test_siblings_not_transitive_and_only_on_improvement(self):
        golds, cs = [G("g1", "A"), G("g2", "B")], [C("c1", "a"), C("c2", "b"), C("c3", "c")]
        groups = [[0, 1]]
        # g1 matches c1 at .5 (improves, marks b). g2 matches c3 only at 0 (never improves) -> nothing else marked.
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5}), groups)
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["c"])
        # a tie that does not improve marks no siblings
        golds1 = [G("g1", "A")]
        js = [M("g1", "c1", True, confidence=0.5), M("g1", "c2", False), M("g1", "c3", False)]
        r = evaluate_reference(golds1, cs, js, [[1, 2]])
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["b", "c"])
        # singleton, repeated-index and empty groups give no siblings
        r = evaluate_reference(golds1, cs, js, [[0], [1, 1], []])
        self.assertEqual(r["provenance"]["siblingMap"], {"a": [], "b": []})
        self.assertEqual(r["provenance"]["siblingMarked"], [])
        for none in (None, []):
            self.assertEqual(evaluate_reference(golds1, cs, js, none)["provenance"]["siblingMap"], {})

    def test_sibling_group_over_duplicate_text_excludes_self_text(self):
        golds, cs = [G("g1", "A")], [C("c1", "x"), C("c2", "x"), C("c3", "y")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5}), [[0, 1, 2]])
        # texts {x,y}; x -> {y}; y -> {x}; x and y both end matched.
        self.assertEqual((r["fp"], r["tp"]), (0, 1))
        self.assertEqual(r["provenance"]["siblingMap"], {"x": ["y"], "y": ["x"]})

    def test_pair_errors_are_rows_not_matches(self):
        golds, cs = [G("g1", "A"), G("g2", "B")], [C("c1", "x"), C("c2", "y")]
        errs = {("g1", "c1"), ("g2", "c2")}
        js = full(golds, cs, {("g1", "c1"): 0.9, ("g2", "c1"): 0.4}, errs)
        r = evaluate_reference(golds, cs, js)
        self.assertEqual(r["errors"], [{"golden": "g1", "candidate": "c1", "error": "boom"},
                                       {"golden": "g2", "candidate": "c2", "error": "boom"}])
        self.assertEqual(r["errorsCount"], 2)
        self.assertEqual([t["goldenComment"] for t in r["truePositives"]], ["B"])  # g1's only hit was an error
        self.assertEqual([f["goldenComment"] for f in r["falseNegatives"]], ["A"])
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["y"])

    def test_zero_gold_skip_precedes_candidates(self):
        for cs in ([], [C("c1", "x")]):
            r = evaluate_reference([], cs, [])
            self.assertIs(r["skipped"], True)
            self.assertEqual(r["reason"], "No golden comments")
            for k in ("truePositives", "falsePositives", "falseNegatives", "tp", "fp", "fn"):
                self.assertNotIn(k, r)

    def test_zero_candidates_uncollapsed_false_negatives(self):
        golds = [G("g1", "A", "bug", "High"), G("g2", "A", "perf", "Low"), G("g3", "B")]
        r = evaluate_reference(golds, [], [])
        self.assertEqual([(f["goldenIds"], f["severity"], f["category"]) for f in r["falseNegatives"]],
                         [(["g1"], "High", "bug"), (["g2"], "Low", "perf"), (["g3"], None, None)])
        self.assertEqual((r["tp"], r["fp"], r["fn"], r["totalGolden"], r["totalCandidates"]), (0, 0, 3, 3, 0))
        # contrast: with a candidate present the duplicates collapse to two FN rows
        r2 = evaluate_reference(golds, [C("c1", "x")], full(golds, [C("c1", "x")]))
        self.assertEqual((r2["fn"], r2["totalGolden"]), (2, 3))

    def test_empty_strings_and_missing_optional_fields(self):
        r = evaluate_reference([G("g1", "")], [C("c1", "x")], [M("g1", "c1", True, confidence=0.2)])
        self.assertEqual((r["tp"], r["truePositives"][0]["severity"], r["truePositives"][0]["category"]),
                         (1, None, None))

    def test_output_rows_preserve_input_order_of_first_occurrence(self):
        golds = [G("g2", "Z"), G("g1", "A"), G("g3", "M")]
        cs = [C("c9", "q"), C("c1", "p")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5}))
        self.assertEqual([f["goldenComment"] for f in r["falseNegatives"]], ["Z", "M"])
        self.assertEqual([f["candidate"] for f in r["falsePositives"]], ["q"])

    def test_all_judgment_permutations_give_identical_result(self):
        golds, cs = [G("g1", "A"), G("g2", "B")], [C("c1", "x"), C("c2", "y")]
        js = full(golds, cs, {("g1", "c1"): 0.4, ("g1", "c2"): 0.8, ("g2", "c2"): 0.2}, {("g2", "c1")})
        base = evaluate_reference(golds, cs, js)
        for p in itertools.permutations(js):
            self.assertEqual(evaluate_reference(golds, cs, list(p)), base)


class Malformed(unittest.TestCase):
    g, c = [G("g1", "A")], [C("c1", "x")]

    def refused(self, golds, cs, js, groups=None):
        with self.assertRaises(BenchmarkError) as cm:
            evaluate_reference(golds, cs, js, groups)
        self.assertEqual(cm.exception.code, "reference-input")

    def test_missing_vs_explicit_null_confidence(self):
        ok = evaluate_reference(self.g, self.c, [M("g1", "c1", True)])  # absent key -> default 0, never improves
        self.assertEqual((ok["tp"], ok["fn"]), (0, 1))
        for match in (True, False):  # explicit null never becomes 0, whatever match says
            self.refused(self.g, self.c, [M("g1", "c1", match, confidence=None)])

    def test_bad_numbers_and_flags(self):
        for conf in (True, False, "0.5", [0.5], {}, b"1"):
            self.refused(self.g, self.c, [M("g1", "c1", True, confidence=conf)])
        for match in (1, 0, "true", None, [], "yes"):
            self.refused(self.g, self.c, [{"golden": "g1", "candidate": "c1", "match": match, "confidence": 0.5}])

    def test_pair_set_errors(self):
        good = M("g1", "c1", True, confidence=0.5)
        self.refused(self.g, self.c, [])                                                     # missing
        self.refused(self.g, self.c, [good, good])                                           # duplicate
        self.refused(self.g, self.c, [good, E("g1", "c1")])                                  # duplicate across kinds
        self.refused(self.g, self.c, [M("gX", "c1", True, confidence=0.5)])                  # unknown golden
        self.refused(self.g, self.c, [M("g1", "cX", True, confidence=0.5)])                  # unknown candidate
        self.refused(self.g, self.c, [good, M("g1", "c2", True, confidence=0.5)])            # extra pair
        self.refused(self.g, [C("c1", "x"), C("c2", "y")], [good])                           # one of two pairs
        self.refused([], self.c, [M("g1", "c1")])                                            # judgments with no gold

    def test_shape_errors(self):
        for bad in ({"golden": "g1", "candidate": "c1"},
                    {"golden": "g1", "candidate": "c1", "match": True, "confidence": 0.5, "reasoning": "r"},
                    {"golden": "g1", "candidate": "c1", "match": True, "error": "e"},
                    {"golden": "g1", "candidate": "c1", "error": ""},
                    {"golden": "g1", "candidate": "c1", "error": None},
                    {"golden": "g1", "candidate": "c1", "error": 5},
                    {"golden": "g1", "candidate": "c1", "error": "e", "confidence": 0.5},
                    {"golden": "g1", "match": True, "confidence": 0.5},
                    {"candidate": "c1", "match": True}, "g1/c1", None, 7):
            self.refused(self.g, self.c, [bad])
        self.refused(self.g, self.c, {"golden": "g1"})
        self.refused(self.g, self.c, None)

    def test_golden_candidate_shape(self):
        j = [M("g1", "c1")]
        self.refused([G("g1", "A"), G("g1", "B")], self.c, j)                  # duplicate golden id
        self.refused(self.g, [C("c1", "x"), C("c1", "y")], j)                  # duplicate candidate id
        self.refused([{"id": "", "comment": "A"}], self.c, j)
        self.refused([{"id": True, "comment": "A"}], self.c, j)
        self.refused([{"id": 1, "comment": "A"}], self.c, j)
        self.refused([{"id": "g1", "comment": None}], self.c, j)
        self.refused([{"id": "g1"}], self.c, j)
        self.refused([{"id": "g1", "comment": "A", "extra": 1}], self.c, j)
        self.refused(self.g, [C("c1", "")], j)                                 # empty candidate text
        self.refused(self.g, [{"id": "c1", "text": None}], j)
        self.refused(self.g, [{"id": "c1", "text": "x", "extra": 1}], j)
        self.refused("g", self.c, j)
        self.refused(self.g, {"c1": "x"}, j)
        self.refused([None], self.c, j)

    def test_bad_group_indices(self):
        js = [M("g1", "c1", True, confidence=0.5)]
        for bad in ([[-1]], [[0.0]], [[True]], [["0"]], [[None]], [0], "0", {"0": 1}, [(0,)], ((0,),)):
            self.refused(self.g, self.c, js, bad)

    def test_non_finite_confidence_refused_d4(self):
        # D4 (declared divergence): NaN/+-inf are outside the JSON domain, so they are refused, not Python-compared.
        for conf in (math.nan, math.inf, -math.inf):
            for match in (True, False):
                self.refused(self.g, self.c, [M("g1", "c1", match, confidence=conf)])
        # finite extremes still follow Python comparison
        r = evaluate_reference(self.g, self.c, [M("g1", "c1", True, confidence=1e308)])
        self.assertEqual(r["truePositives"][0]["confidence"], 1e308)

    def test_G1_huge_integer_confidence_is_a_typed_refusal(self):
        # math.isfinite(10**400) raised a raw OverflowError (S1-21 gate G1); fixed as N1 and now a typed refusal.
        self.refused(self.g, self.c, [M("g1", "c1", True, confidence=10 ** 400)])

    def test_F1_unhashable_and_non_string_judgment_ids_are_typed_refusals(self):
        for bad in ([], {}, ["c1"], None, 1, True, 1.5, ""):
            self.refused(self.g, self.c, [{"golden": bad, "candidate": "c1", "match": True, "confidence": 0.5}])
            self.refused(self.g, self.c, [{"golden": "g1", "candidate": bad, "match": True, "confidence": 0.5}])
            self.refused(self.g, self.c, [{"golden": bad, "candidate": "c1", "error": "e"}])

    def test_F5_bad_golden_labels_refused_by_evaluation_before_pooling(self):
        for key in ("category", "severity"):
            for bad in (["x"], {"a": 1}, 3, True, 0, 1.5):
                golds = [{"id": "g1", "comment": "A", key: bad}]
                self.refused(golds, self.c, [M("g1", "c1", True, confidence=0.5)])
                self.refused(golds, [], [])   # zero-candidate path validates too
                self.refused(golds, self.c, [M("g1", "c1", True, confidence=0.5)])
        for ok in (None, "", "bug"):  # null / empty / string accepted, as before
            r = evaluate_reference([{"id": "g1", "comment": "A", "category": ok, "severity": ok}], self.c,
                                   [M("g1", "c1", True, confidence=0.5)])
            self.assertEqual(r["tp"], 1)
            pool_reference({"k": {"t": r}}, profile="all", beta=1)

    def test_refusal_happens_before_any_counting_output(self):
        # an invalid later pair must not yield a partial result
        golds, cs = [G("g1", "A")], [C("c1", "x"), C("c2", "y")]
        js = [M("g1", "c1", True, confidence=0.5), M("g1", "c2", True, confidence=math.nan)]
        self.refused(golds, cs, js)

    def test_outputs_are_strict_json(self):
        import json
        golds, cs = [G("g1", "A", "bug", "High")], [C("c1", "x"), C("c2", "y")]
        r = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5}), [[0, 1], [7]])
        json.dumps(r, allow_nan=False)
        json.dumps(evaluate_reference(golds, [], [], [[0]]), allow_nan=False)
        json.dumps(pool_reference({"k": {"t": r}}, profile="all", beta=2), allow_nan=False)

    def test_zero_candidate_provenance_matches_main_path_keys(self):
        golds = [G("g1", "A"), G("g2", "A")]
        z = evaluate_reference(golds, [], [], [[0, 1], []])
        m = evaluate_reference(golds, [C("c1", "x")], full(golds, [C("c1", "x")]))
        self.assertEqual(set(z["provenance"]), set(m["provenance"]))
        self.assertEqual(set(z) - {"provenance"}, set(m) - {"provenance"})
        p = z["provenance"]
        self.assertIs(p["zeroCandidates"], True)
        self.assertIs(m["provenance"]["zeroCandidates"], False)
        self.assertEqual(p["goldenCollapse"], {})                    # uncollapsed rows: no collapse to report
        self.assertEqual(p["candidateCollapse"], {})
        self.assertEqual((p["improvements"], p["siblingMarked"], p["siblingMap"]), ([], [], {}))
        self.assertEqual(p["ignoredGroupIndices"], [[0, 0], [0, 1]])  # every index is out of range for 0 candidates
        self.assertEqual(len(z["falseNegatives"]), 2)                # duplicates NOT collapsed on this path
        # group validation still applies with zero candidates
        self.refused(golds, [], [], [[-1]])
        self.refused(golds, [], [], "0")


class Pooling(unittest.TestCase):
    def evs(self):
        e1 = {"skipped": False, "fp": 4,
              "truePositives": [{"goldenComment": "A", "category": "bug"}, {"goldenComment": "B", "category": None},
                                {"goldenComment": "C", "category": "style"}],
              "falseNegatives": [{"goldenComment": "D", "category": "perf"}, {"goldenComment": "E", "category": ""}]}
        e2 = {"skipped": False, "fp": 1, "truePositives": [], "falseNegatives": [{"goldenComment": "F", "category": "bug"}]}
        return {"case1": {"t": e1}, "case2": {"t": e2}}

    LOOKUP = {"B": "api", "E": "test_gap"}

    def test_profile_filtering_pooled_micro_and_unchanged_fp(self):
        want = {  # tp, fp, fn per profile, hand-derived: see comment block below
            "strict": (2, 5, 1),   # TP bug,api; style out. FN: D perf out, E test_gap out, F bug in
            "core": (2, 5, 3),     # FN D perf in, E test_gap in, F in
            "all": (3, 5, 3),      # TP style now in
        }
        for prof, (tp, fp, fn) in want.items():
            r = pool_reference(self.evs(), profile=prof, beta=2, golden_categories=self.LOOKUP)["t"]
            self.assertEqual((r["tp"], r["fp"], r["fn"], r["prs"]), (tp, fp, fn, 2), prof)
        r = pool_reference(self.evs(), profile="strict", beta=2, golden_categories=self.LOOKUP)["t"]
        # micro: p=2/7, r=2/3, f1=2pr/(p+r)=8/20=0.4 ; F2=5pr/(4p+r)=(20/21)/(38/21)=10/19
        self.assertAlmostEqual(r["precision"], 2 / 7)
        self.assertAlmostEqual(r["recall"], 2 / 3)
        self.assertAlmostEqual(r["f1"], 0.4)
        self.assertAlmostEqual(r["fbeta"], 10 / 19)
        self.assertEqual((r["beta"], r["profile"], r["undefined"]), (2, "strict", []))

    def test_without_lookup_empty_category_is_excluded(self):
        r = pool_reference(self.evs(), profile="all", beta=1)["t"]
        self.assertEqual((r["tp"], r["fn"]), (2, 3 - 1))  # B (None) and E ('') excluded: TP A,C ; FN D,F

    def test_row_category_beats_lookup(self):
        ev = {"skipped": False, "fp": 0, "truePositives": [{"goldenComment": "A", "category": "style"}],
              "falseNegatives": []}
        r = pool_reference({"k": {"t": ev}}, profile="strict", beta=1, golden_categories={"A": "bug"})["t"]
        self.assertEqual(r["tp"], 0)

    def test_hidden_tools_prefix_and_skipped(self):
        ev = {"skipped": False, "fp": 1, "truePositives": [{"goldenComment": "A", "category": "bug"}],
              "falseNegatives": []}
        skipped = {"skipped": True, "reason": "No golden comments"}
        cases = {"k": {"qodo": ev, "mra-x": ev, "gemini": ev, "mra": ev, "qodo-v3": ev, "vis": ev},
                 "k2": {"vis": skipped, "onlyskipped": skipped}}
        out = pool_reference(cases, profile="all", beta=1)
        self.assertEqual(sorted(out), ["mra", "qodo-v3", "vis"])  # exact-name / 'mra-' prefix only
        self.assertEqual(out["vis"]["prs"], 1)                    # skipped case not counted
        self.assertTrue(reference_is_hidden("mra-anything"))
        self.assertFalse(reference_is_hidden("Qodo"))

    def test_named_zero_conventions(self):
        mk = lambda tp, fp, fn: {"skipped": False, "fp": fp,
                                 "truePositives": [{"goldenComment": f"t{i}", "category": "bug"} for i in range(tp)],
                                 "falseNegatives": [{"goldenComment": f"n{i}", "category": "bug"} for i in range(fn)]}
        out = pool_reference({"k": {"none": mk(0, 0, 0), "fponly": mk(0, 3, 0), "fnonly": mk(0, 0, 2),
                                    "both": mk(0, 1, 1)}}, profile="strict", beta=2)
        self.assertEqual(out["none"]["undefined"], ["precision", "recall"])
        self.assertEqual(out["fponly"]["undefined"], ["recall"])
        self.assertEqual(out["fnonly"]["undefined"], ["precision"])
        self.assertEqual(out["both"]["undefined"], [])
        for t in out.values():
            self.assertEqual((t["tp"], t["f1"], t["fbeta"], t["zeroConvention"]), (0, 0.0, 0.0, "reference-undefined-is-0"))

    def test_profile_filter_can_make_undefined_without_changing_fp(self):
        ev = {"skipped": False, "fp": 2, "truePositives": [{"goldenComment": "A", "category": "style"}],
              "falseNegatives": []}
        s = pool_reference({"k": {"t": ev}}, profile="strict", beta=1)["t"]
        self.assertEqual((s["tp"], s["fp"], s["undefined"]), (0, 2, ["recall"]))
        a = pool_reference({"k": {"t": ev}}, profile="all", beta=1)["t"]
        self.assertEqual((a["tp"], a["fp"], a["undefined"]), (1, 2, []))
        self.assertAlmostEqual(a["precision"], 1 / 3)
        self.assertEqual(a["recall"], 1.0)

    def test_consumes_evaluate_reference_output_with_category_fallback(self):
        golds = [G("g1", "A", "bug"), G("g2", "B"), G("g3", "C", "style")]
        cs = [C("c1", "x"), C("c2", "y")]
        ev = evaluate_reference(golds, cs, full(golds, cs, {("g1", "c1"): 0.5, ("g2", "c1"): 0.5}))
        # tp rows: A(bug), B(None->lookup api); fn: C(style); fp: y -> 1
        r = pool_reference({"k": {"t": ev}}, profile="strict", beta=1, golden_categories={"B": "api"})["t"]
        self.assertEqual((r["tp"], r["fp"], r["fn"]), (2, 1, 0))
        r = pool_reference({"k": {"t": ev}}, profile="strict", beta=1)["t"]
        self.assertEqual((r["tp"], r["fp"], r["fn"]), (1, 1, 0))
        sk = evaluate_reference([], cs, [])
        self.assertEqual(pool_reference({"k": {"t": sk}}, profile="all", beta=1), {})

    def test_bad_beta_profile_and_shape(self):
        ev = {"k": {"t": {"skipped": False, "fp": 0}}}
        for beta in (0, -1, True, None, math.nan, math.inf, "2", [2]):
            with self.assertRaises(BenchmarkError, msg=repr(beta)):
                pool_reference(ev, profile="all", beta=beta)
        for prof in ("Strict", "", None, "ALL", ["all"]):
            with self.assertRaises((BenchmarkError, TypeError), msg=repr(prof)):
                pool_reference(ev, profile=prof, beta=1)
        for bad in (None, [], {"k": []}, {"k": {"t": 3}}):
            with self.assertRaises(BenchmarkError):
                pool_reference(bad, profile="all", beta=1)

    def test_F3_malformed_evaluations_are_typed_refusals_including_hidden_and_skipped(self):
        bad_evs = ({"fp": "3"}, {"fp": None}, {"fp": -2}, {"fp": True}, {"fp": 1.0}, {"truePositives": 5},
                   {"truePositives": ["x"]}, {"falseNegatives": None}, {"falseNegatives": [3]},
                   {"truePositives": [{"goldenComment": 5}]}, {"truePositives": [{"category": ["x"]}]},
                   {"falseNegatives": [{"severity": 3}]}, {"skipped": "yes"}, {"skipped": 1}, {"skipped": None},
                   3, "x", None, [])
        for ev in bad_evs:
            with self.assertRaises(BenchmarkError, msg=repr(ev)) as cm:
                pool_reference({"k": {"t": ev}}, profile="all", beta=1)
            self.assertEqual(cm.exception.code, "reference-input")
            # hidden tools and skipped rows are validated deliberately, not trusted because they are uncounted
            with self.assertRaises(BenchmarkError, msg=repr(ev)):
                pool_reference({"k": {"qodo": ev}}, profile="all", beta=1)
            with self.assertRaises(BenchmarkError, msg=repr(ev)):
                pool_reference({"k": {"mra-x": ev}}, profile="all", beta=1)
        for ev in ({"skipped": True, "fp": -1}, {"skipped": True, "truePositives": [1]}):
            with self.assertRaises(BenchmarkError):
                pool_reference({"k": {"t": ev}}, profile="all", beta=1)

    def test_F3_bad_keys_lookup_and_profile_types(self):
        ok = {"fp": 0}
        for bad_case in (1, None, ("a",)):
            with self.assertRaises(BenchmarkError):
                pool_reference({bad_case: {"t": ok}}, profile="all", beta=1)
        for bad_tool in ("", 1, None, ("a",)):
            with self.assertRaises(BenchmarkError):
                pool_reference({"k": {bad_tool: ok}}, profile="all", beta=1)
        for lk in ([], "x", {"A": 1}, {1: "bug"}, {"A": None}, {"A": ["bug"]}):
            with self.assertRaises(BenchmarkError, msg=repr(lk)):
                pool_reference({"k": {"t": ok}}, profile="all", beta=1, golden_categories=lk)
        for prof in ([], {}, 1, None, ["all"], ("all",)):
            with self.assertRaises(BenchmarkError, msg=repr(prof)):
                pool_reference({"k": {"t": ok}}, profile=prof, beta=1)

    def test_F3_compatible_inputs_and_counts_preserved(self):
        # absent fields take SP defaults; extra keys are ignored; null/'' category falls back to lookup
        ev = {"truePositives": [{"goldenComment": "A", "category": None, "extra": 1}, {"category": "bug"}],
              "falseNegatives": [{"goldenComment": "B", "category": ""}], "note": "x"}
        r = pool_reference({"k": {"t": ev}}, profile="strict", beta=1, golden_categories={"A": "api", "B": "data"})["t"]
        self.assertEqual((r["tp"], r["fp"], r["fn"], r["prs"]), (2, 0, 1, 1))
        self.assertEqual(pool_reference({}, profile="all", beta=1), {})
        self.assertEqual(pool_reference({"k": {}}, profile="all", beta=1), {})
        # big finite beta and zero-count conventions unchanged
        r = pool_reference({"k": {"t": {"fp": 0}}}, profile="all", beta=1e6)["t"]
        self.assertEqual((r["tp"], r["fbeta"], r["undefined"]), (0, 0.0, ["precision", "recall"]))

    def test_G1_huge_integer_beta_is_a_typed_refusal(self):
        with self.assertRaises(BenchmarkError) as cm:
            pool_reference({"k": {"t": {"fp": 0}}}, profile="all", beta=10 ** 400)
        self.assertEqual(cm.exception.code, "reference-input")


class Numeric(unittest.TestCase):
    """S1-21 numeric gate (N1 huge-int confidence/beta, N2 beta*beta overflow). Oracles use exact Fractions and the
    SP formula written independently; domain changes are newly refused inputs (old raw crash / NaN), not history."""
    g, c = [G("g1", "A")], [C("c1", "x")]
    EV = {"k": {"t": {"fp": 0}}}

    def code(self, fn, *a, **kw):
        with self.assertRaises(BenchmarkError) as cm:
            fn(*a, **kw)
        return cm.exception.code

    def pool(self, tp, fp, fn, beta):
        ev = {"skipped": False, "fp": fp, "truePositives": [{"goldenComment": "g", "category": "bug"}] * tp,
              "falseNegatives": [{"goldenComment": "g", "category": "bug"}] * fn}
        return pool_reference({"k": {"t": ev}}, profile="all", beta=beta)["t"]

    def test_N1_signed_huge_ints_and_both_match_values_refused_without_raw_error(self):
        for conf in (10 ** 400, -10 ** 400, 2 ** 1024, -(2 ** 1024), 10 ** 309):
            for match in (True, False):
                self.assertEqual(self.code(evaluate_reference, self.g, self.c, [M("g1", "c1", match, confidence=conf)]),
                                 "reference-input", conf)
        for beta in (10 ** 400, -10 ** 400, 2 ** 1024, 10 ** 309):
            self.assertEqual(self.code(pool_reference, self.EV, profile="all", beta=beta), "reference-input")

    def test_N1_largest_finite_int_accepted_and_exact_int_vs_float_comparison_kept(self):
        big = int(1.7976931348623157e308)                                  # exact value of the max double
        r = evaluate_reference(self.g, self.c + [C("c2", "y")],
                               [M("g1", "c1", True, confidence=1.7976931348623157e308),
                                M("g1", "c2", True, confidence=big + 1)])   # exact int > float: float conversion would tie
        self.assertEqual((r["tp"], r["truePositives"][0]["matchedCandidateId"]), (1, "c2"))
        t = evaluate_reference(self.g, self.c + [C("c2", "y")],
                               [M("g1", "c1", True, confidence=2.0), M("g1", "c2", True, confidence=2)])
        self.assertEqual(t["truePositives"][0]["matchedCandidateId"], "c1")  # int 2 == float 2.0: tie, no improvement

    def test_N1_bool_nan_inf_none_str_still_refused(self):
        for conf in (True, False, math.nan, math.inf, -math.inf, None, "1", [1]):
            self.assertEqual(self.code(evaluate_reference, self.g, self.c, [M("g1", "c1", True, confidence=conf)]),
                             "reference-input")
        for beta in (True, False, math.nan, math.inf, -math.inf, None, "2", 0, -1, 0.0, -0.0):
            self.assertEqual(self.code(pool_reference, self.EV, profile="all", beta=beta), "reference-input")

    def test_N2_max_beta_boundary_accepted_one_ulp_above_refused_never_clamped(self):
        mb = MAX_BETA
        self.assertTrue(math.isfinite(mb * mb))
        self.assertFalse(math.isfinite(math.nextafter(mb, math.inf) * math.nextafter(mb, math.inf)))   # independent derivation of the bound
        r = self.pool(1, 1, 1, mb)
        self.assertEqual(r["beta"], mb)
        for beta in (math.nextafter(mb, math.inf), 1e155, 1e200, 1e308, 1.7976931348623157e308, 10 ** 155, 10 ** 308):
            self.assertEqual(self.code(pool_reference, self.EV, profile="all", beta=beta), "reference-input", beta)
        self.assertEqual(self.pool(1, 1, 1, math.nextafter(mb, 0))["beta"], math.nextafter(mb, 0))

    def test_N2_every_accepted_extreme_beta_gives_finite_strict_json_outputs(self):
        betas = (MAX_BETA, math.nextafter(MAX_BETA, 0), 10 ** 154, 1e100, 1e6, 5e-324, 1e-200, 1e-160, 1.0, 2, 2.0)
        counts = ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 1, 1), (1, 10 ** 300, 1),
                  (3, 1, 5), (10 ** 6, 1, 1))
        for beta in betas:
            for tp, fp, fn in counts:
                out = self.pool(tp, fp, fn, beta)
                json.dumps(out, allow_nan=False)
                for k in ("precision", "recall", "f1", "fbeta"):
                    self.assertTrue(math.isfinite(out[k]) and 0.0 <= out[k] <= 1.0, (beta, tp, fp, fn, k, out[k]))

    def test_N2_beta_1_and_2_keep_hand_oracles_and_exact_fraction_agreement(self):
        out = self.pool(1, 1, 3, 1)                                         # p=1/2 r=1/4 -> F1=1/3
        self.assertAlmostEqual(out["f1"], 1 / 3)
        self.assertAlmostEqual(out["fbeta"], 1 / 3)
        self.assertAlmostEqual(self.pool(1, 1, 3, 2)["fbeta"], 5 / 18)      # (1+4)*.5*.25/(4*.5+.25)
        self.assertEqual(self.pool(1, 1, 3, 2)["fbeta"], self.pool(1, 1, 3, 2.0)["fbeta"])
        for beta in (1, 2, 0.5, 3):
            for tp, fp, fn in ((3, 1, 5), (7, 2, 2), (1, 9, 0)):
                p, r, b2 = Fraction(tp, tp + fp), Fraction(tp, tp + fn), Fraction(beta) ** 2
                self.assertAlmostEqual(self.pool(tp, fp, fn, beta)["fbeta"], float((1 + b2) * p * r / (b2 * p + r)))

    def test_N2_tiny_beta_equals_precision_and_huge_beta_equals_recall(self):
        out = self.pool(1, 1, 3, 5e-324)                                    # b2 underflows to 0: Fbeta == precision (as SP)
        self.assertEqual((out["fbeta"], out["precision"]), (0.5, 0.5))
        self.assertAlmostEqual(self.pool(1, 1, 3, 10 ** 154)["fbeta"], 0.25)  # huge beta -> recall

    def test_N2_zero_precision_or_recall_at_the_boundary_is_zero_not_nan(self):
        for beta in (MAX_BETA, 5e-324):
            self.assertEqual(self.pool(0, 1, 1, beta)["fbeta"], 0.0)
            self.assertEqual(self.pool(0, 0, 0, beta)["fbeta"], 0.0)

    def test_N1_accepted_outputs_are_strict_json_for_extreme_finite_confidence(self):
        for conf in (1e308, -1e308, 5e-324, int(1e308)):
            r = evaluate_reference(self.g, self.c, [M("g1", "c1", True, confidence=conf)])
            json.dumps(r, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
