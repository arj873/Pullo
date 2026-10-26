import copy

from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.scoring import score_case, score_suite

from .helpers import Fx

JUDGE = {"model": "fixture-judge", "extractionPrompt": "e@v1", "dedupPrompt": "d@v1", "matchPrompt": "m@v1",
         "schemaSha256": "s", "runRef": "fixture"}


class Scoring(Fx):
    def setUp(self):
        super().setUp()
        self.src = self.source()
        self.url = next(iter(self.src.cases))
        self.case = self.src.cases[self.url]
        self.g = [g.id for g in self.case.golden]          # bug, perf, style, security
        self.rc = self.case.review("cubic-v2").comments[0].id

    def doc(self, matches, groups=None, n=5, tool="cubic-v2", judge=None):
        cands = [{"id": f"cand:{i}", "sourceCommentId": self.rc, "text": f"issue {i}"} for i in range(1, n + 1)]
        groups = groups if groups is not None else [("cand:1", ["cand:1", "cand:2"])] + [(f"cand:{i}",) * 1 + ([f"cand:{i}"],)
                                                                                         for i in range(3, n + 1)]
        return {"schema": "semantic-judgments@1", "caseUrl": self.url, "tool": tool, "judge": judge or dict(JUDGE),
                "extraction": {"candidates": cands},
                "duplicateGroups": [{"id": f"grp:{k}", "representative": r, "members": m} for k, (r, m) in enumerate(groups)],
                "matches": [{"candidate": c, "golden": g, "reason": "r"} for c, g in matches]}

    def standard(self):
        # reps: cand:1 (dup with cand:2) -> bug, cand:3 -> perf, cand:4 -> style, cand:5 -> unmatched
        return self.doc([("cand:1", self.g[0]), ("cand:3", self.g[1]), ("cand:4", self.g[2]), ("cand:5", None)])

    def test_profiles_matched_excluded_duplicates_and_denominators(self):
        row = score_case(self.case, self.standard())
        self.assertEqual((row["candidates"], row["representatives"], row["duplicateMembersNotCounted"]), (5, 4, 1))
        v = row["views"]
        self.assertEqual(v["strict"]["counts"], {"tp": 1, "fp": 1, "excluded": 2, "goldRecalled": 1, "goldTotal": 2})
        self.assertEqual(v["core"]["counts"], {"tp": 2, "fp": 1, "excluded": 1, "goldRecalled": 2, "goldTotal": 3})
        self.assertEqual(v["all"]["counts"], {"tp": 3, "fp": 1, "excluded": 0, "goldRecalled": 3, "goldTotal": 4})
        self.assertAlmostEqual(v["strict"]["native"]["f1"]["value"], 0.5)
        self.assertAlmostEqual(v["core"]["native"]["f1"]["value"], 2 / 3)
        self.assertAlmostEqual(v["all"]["native"]["precision"]["value"], 0.75)
        # F2 is a different number from F1: P=2/3, R=2/3 gives equal, so use strict-like asymmetry below
        self.assertAlmostEqual(v["core"]["native"]["f2"]["value"], 2 / 3)

    def test_f2_is_not_f1(self):
        d = self.doc([("cand:1", self.g[0]), ("cand:3", None), ("cand:4", None), ("cand:5", None)])
        c = score_case(self.case, d)["views"]["strict"]
        # P = 1/4, R = 1/2
        self.assertAlmostEqual(c["native"]["f1"]["value"], 2 * 0.25 * 0.5 / 0.75)
        self.assertAlmostEqual(c["native"]["f2"]["value"], 5 * 0.25 * 0.5 / (4 * 0.25 + 0.5))

    def test_unmatched_candidates_stay_in_denominator_not_dropped_for_category(self):
        d = self.doc([("cand:1", None), ("cand:3", None), ("cand:4", None), ("cand:5", None)])
        k = score_case(self.case, d)["views"]["core"]["counts"]
        self.assertEqual((k["tp"], k["fp"]), (0, 4))

    def test_duplicate_members_not_independent_false_positives(self):
        d = self.doc([("cand:1", None)], groups=[("cand:1", ["cand:1", "cand:2", "cand:3", "cand:4", "cand:5"])])
        row = score_case(self.case, d)
        self.assertEqual(row["views"]["all"]["counts"]["fp"], 1)

    def test_undefined_native_null_vs_upstream_zero_named_separately(self):
        d = self.doc([], groups=[], n=0)
        v = score_case(self.case, d)["views"]["core"]
        self.assertIsNone(v["native"]["precision"]["value"])
        self.assertIn("denominator", v["native"]["precision"]["undefinedReason"])
        self.assertEqual(v["native"]["recall"]["value"], 0.0)
        self.assertIsNone(v["native"]["f1"]["value"])
        self.assertEqual(v["upstreamCompatZero"]["precision"]["value"], 0.0)
        self.assertEqual(v["upstreamCompatZero"]["f1"]["value"], 0.0)
        self.assertNotIn("upstreamCompatZero", v["native"])

    def test_no_golden_in_profile_recall_undefined(self):
        u2 = list(self.src.cases)[1]
        case = copy.copy(self.src.cases[u2])
        from reviewer.benchmark.model import Golden, ScorerCase
        case = ScorerCase(case.url, case.source_repo, case.original_url, case.index,
                          (Golden("gold:1:1", "x", "Low", "style"),), case.reviews)
        rc = case.review("cubic-v2").comments[0].id
        d = {"schema": "semantic-judgments@1", "caseUrl": case.url, "tool": "cubic-v2", "judge": dict(JUDGE),
             "extraction": {"candidates": [{"id": "cand:1", "sourceCommentId": rc, "text": "t"}]},
             "duplicateGroups": [{"id": "g", "representative": "cand:1", "members": ["cand:1"]}],
             "matches": [{"candidate": "cand:1", "golden": "gold:1:1", "reason": "r"}]}
        v = score_case(case, d)["views"]["strict"]
        self.assertIsNone(v["native"]["recall"]["value"])
        self.assertIsNone(v["native"]["precision"]["value"])      # matched-excluded: empty denominator
        self.assertEqual(v["counts"]["excluded"], 1)

    def test_multi_matched_golden_reported(self):
        d = self.doc([("cand:1", self.g[0]), ("cand:3", self.g[0]), ("cand:4", None), ("cand:5", None)])
        row = score_case(self.case, d)
        self.assertEqual(row["multiMatchedGolden"]["core"], [self.g[0]])
        self.assertEqual(row["views"]["core"]["counts"]["goldRecalled"], 1)

    def test_invalid_judgments_refused_not_scored_zero(self):
        base = self.standard()
        bad = copy.deepcopy(base)
        bad["matches"].pop()
        with self.assertRaises(BenchmarkError) as cm:
            score_case(self.case, bad)
        self.assertEqual(cm.exception.code, "incomplete")
        bad = copy.deepcopy(base)
        bad["matches"].append({"candidate": "cand:2", "golden": None, "reason": "r"})   # a non-representative
        with self.assertRaises(BenchmarkError):
            score_case(self.case, bad)
        bad = copy.deepcopy(base)
        bad["matches"][0]["golden"] = "gold:99:1"
        with self.assertRaises(BenchmarkError):
            score_case(self.case, bad)
        bad = copy.deepcopy(base)
        bad["extraction"]["candidates"][0]["sourceCommentId"] = "rc:forged"
        with self.assertRaises(BenchmarkError):
            score_case(self.case, bad)
        bad = copy.deepcopy(base)
        bad["duplicateGroups"].pop()
        with self.assertRaises(BenchmarkError) as cm:
            score_case(self.case, bad)
        self.assertEqual(cm.exception.code, "incomplete")
        bad = copy.deepcopy(base)
        bad["line"] = 3
        with self.assertRaises(BenchmarkError):
            score_case(self.case, bad)

    def test_suite_pools_reports_missing_and_incomplete_and_judge_mismatch(self):
        urls = list(self.src.cases)[:3]
        good = self.standard()
        incomplete = copy.deepcopy(good)
        incomplete["caseUrl"] = urls[1]
        incomplete["matches"].pop()
        for m in incomplete["matches"]:
            m["golden"] = None if m["golden"] is None else m["golden"].replace("gold:0:", "gold:1:")
        # re-point comment ids for the second case
        for u, d in ((urls[1], incomplete),):
            rc = self.src.cases[u].review("cubic-v2").comments[0].id
            for c in d["extraction"]["candidates"]:
                c["sourceCommentId"] = rc
        rep = score_suite(self.src.cases, [good, incomplete], tools=["cubic-v2"], urls=urls)
        t = rep["tools"]["cubic-v2"]
        self.assertEqual((t["casesExpected"], t["casesScored"]), (3, 1))
        self.assertEqual(t["missing"], [urls[2]])
        self.assertEqual(len(t["incomplete"]), 1)
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["primary"]["name"], "core/F1")
        self.assertIn("strict/F1", rep["secondary"])
        self.assertIn("core/F2", rep["secondary"])
        self.assertIn("not a human-sealed", rep["partitionNotice"])
        other = self.standard()
        other["judge"] = dict(JUDGE, model="other")
        other["tool"] = "cubic-v1"
        for c in other["extraction"]["candidates"]:
            c["sourceCommentId"] = self.case.review("cubic-v1").comments[0].id
        with self.assertRaises(BenchmarkError) as cm:
            score_suite(self.src.cases, [good, other], tools=["cubic-v2", "cubic-v1"], urls=urls[:1])
        self.assertEqual(cm.exception.code, "judge-mismatch")
        with self.assertRaises(BenchmarkError):
            score_suite(self.src.cases, [good, good], tools=["cubic-v2"], urls=urls[:1])

    def test_no_overlap_matching_in_package(self):
        import pathlib
        text = "".join(p.read_text() for p in pathlib.Path("reviewer/benchmark").glob("*.py"))
        self.assertNotIn("overlap(", text)
        self.assertNotIn("difflib", text)
