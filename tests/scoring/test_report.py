import copy
import json
import unittest

from reviewer.contracts import ContractViolation, require, validate
from reviewer.contracts.canonical import config_digest
from reviewer.scoring import (ScoringError, UnscoredSuiteError, build_report, score_case,
                              scored_case_result, unscored_case_result)
from reviewer.scoring.report import zero_cost
from .helpers import SMOKE, make_comment, labels, run_for, smoke_suite, read

EVR = "evr_" + "1" * 16
PROFILES = [{"ref": "smoke-synthetic@1", "digest": "sha256:" + "7" * 64}]
PROMPTS = ["judge.wording@v1", "investigator.generalist@v1", "verifier.refute@v1"]


def comment_at(case_labels, n=0, offset=0):
    b = case_labels["bugs"][0]
    return make_comment(b["path"], b["lines"][0] + offset, b["lines"][1] + offset, n=n)


def run_case(suite, cid, comments, status="completed", incomplete=None, error=None):
    c = suite.cases[cid]
    sc = score_case(suite.manifest, c.labels, comments, status=status, incomplete=incomplete, error=error)
    return scored_case_result(sc, run_id=run_for(cid), status=status, incomplete=incomplete, error=error,
                              latency_original=100, latency_replay=5), sc


def ideal(suite, extra_duplicate=False):
    results = []
    for cid, case in suite.cases.items():
        L = case.labels
        if L["expect"] == "findings":
            cs = [comment_at(L)] + ([comment_at(L, n=1, offset=1)] if extra_duplicate and cid == "smoke-c03" else [])
            results.append(run_case(suite, cid, cs)[0])
        elif L["expect"] == "silence":
            results.append(run_case(suite, cid, [])[0])
        elif L["expect"] == "partial":
            results.append(run_case(suite, cid, [], "partial",
                                    [{"stage": "VERIFY", "reason": L["expectReason"]}])[0])
        else:
            results.append(run_case(suite, cid, [], "failed", error={
                "code": L["expectReason"], "message": "scripted", "retryable": True, "stage": "INVESTIGATE"})[0])
    return results


def report(suite, results, **kw):
    return build_report(suite.manifest, suite.digest, results, eval_run_id=EVR, mode="strict-replay",
                        config_digest=config_digest({"smoke": 1}), profiles=PROFILES,
                        prompt_versions=PROMPTS, cost=zero_cost(synthetic_records=3), scored=True,
                        replay_of="evr_" + "2" * 16, **kw)


class Expectations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = smoke_suite()

    def test_each_expectation_type_is_met_by_its_ideal_outcome(self):
        for r in ideal(self.suite):
            with self.subTest(r["caseId"]):
                self.assertTrue(r["expectationMet"])

    def test_findings_case_unmet_when_bug_missed_or_run_not_completed(self):
        _, miss = run_case(self.suite, "smoke-c01", [])
        self.assertFalse(miss.expectation_met)
        self.assertEqual((miss.true_positives, miss.false_negatives), (0, 1))
        _, partial = run_case(self.suite, "smoke-c01", [comment_at(self.suite.cases["smoke-c01"].labels)],
                              "partial", [{"stage": "VERIFY", "reason": "budget"}])
        self.assertFalse(partial.expectation_met)

    def test_silence_case_unmet_by_any_comment(self):
        _, sc = run_case(self.suite, "smoke-c02", [make_comment("src/report.py", 1, 2)])
        self.assertFalse(sc.expectation_met)
        self.assertEqual((sc.false_positives, sc.true_positives), (1, 0))

    def test_partial_and_failed_need_the_expected_reason(self):
        wrong = [{"stage": "VERIFY", "reason": "budget"}]
        self.assertFalse(run_case(self.suite, "smoke-c05", [], "partial", wrong)[1].expectation_met)
        self.assertFalse(run_case(self.suite, "smoke-c05", [], "completed")[1].expectation_met)
        err = {"code": "provider-error", "message": "x", "retryable": True}
        self.assertFalse(run_case(self.suite, "smoke-c06", [], "failed", error=err)[1].expectation_met)
        self.assertFalse(run_case(self.suite, "smoke-c06", [], "failed")[1].expectation_met)

    def test_labelled_bugs_missed_in_partial_and_failed_cases_are_false_negatives(self):
        self.assertEqual(run_case(self.suite, "smoke-c05", [], "partial",
                                  [{"stage": "VERIFY", "reason": "verifier-failure"}])[1].false_negatives, 1)


class ScoredReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = smoke_suite()

    def test_ideal_run_report_is_contract_valid_with_exact_tallies(self):
        rep = report(self.suite, ideal(self.suite))
        self.assertEqual(validate("EvalReport", rep), [])
        m = rep["metrics"]
        # 3 findings cases matched; c05 and c06 each leave their labelled bug unmatched.
        self.assertEqual((m["precision"]["numerator"], m["precision"]["denominator"]), (3, 3))
        self.assertEqual((m["recall"]["numerator"], m["recall"]["denominator"]), (3, 5))
        self.assertEqual(m["precision"]["value"], 1.0)
        self.assertAlmostEqual(m["f1"]["value"], 2 * 1.0 * 0.6 / 1.6)
        self.assertEqual(rep["coverage"], {"completed": 4, "partial": 1, "failed": 1, "cancelled": 0,
                                           "expectationMet": 6})
        self.assertEqual(rep["matching"], {"rule": "path-line-overlap@1", "scope": "synthetic-smoke"})
        self.assertEqual(rep["cost"]["liveCalls"], 0)
        self.assertEqual(rep["dataset"]["suiteDigest"], self.suite.digest)

    def test_duplicates_are_fp_and_visible_per_case(self):
        rep = report(self.suite, ideal(self.suite, extra_duplicate=True))
        c3 = next(c for c in rep["cases"] if c["caseId"] == "smoke-c03")
        self.assertEqual((c3["truePositives"], c3["falsePositives"], c3["duplicates"], c3["comments"]),
                         (1, 1, 1, 2))
        self.assertEqual(rep["metrics"]["precision"]["denominator"], 4)
        self.assertEqual(validate("EvalReport", rep), [])

    def test_undefined_precision_and_f1_when_nothing_was_commented(self):
        suite = self.suite
        results = [run_case(suite, "smoke-c02", [])[0]] + [
            run_case(suite, cid, [], "failed" if cid == "smoke-c06" else "completed",
                     error=None)[0] for cid in suite.cases if cid != "smoke-c02"]
        # shrink the manifest to avoid unrelated cases: a one-case silence suite
        manifest = copy.deepcopy(suite.manifest)
        manifest["cases"] = [c for c in manifest["cases"] if c["id"] == "smoke-c02"]
        rep = build_report(manifest, suite.digest, [results[0]], eval_run_id=EVR, mode="strict-replay",
                           config_digest=config_digest({"x": 1}), profiles=PROFILES, prompt_versions=PROMPTS,
                           cost=zero_cost(), scored=True, replay_of="evr_" + "2" * 16)
        p, r, f = (rep["metrics"][k] for k in ("precision", "recall", "f1"))
        self.assertEqual((p["value"], p["denominator"]), (None, 0))
        self.assertEqual((r["value"], r["denominator"]), (None, 0))
        self.assertIsNone(f["value"])
        self.assertTrue(p["undefinedReason"] and r["undefinedReason"] and f["undefinedReason"])

    def test_zero_true_positives_gives_defined_zero_not_undefined(self):
        miss = run_case(self.suite, "smoke-c01", [make_comment("src/elsewhere.py", 1, 1)])[0]
        manifest = copy.deepcopy(self.suite.manifest)
        manifest["cases"] = [c for c in manifest["cases"] if c["id"] == "smoke-c01"]
        rep = build_report(manifest, self.suite.digest, [miss], eval_run_id=EVR, mode="strict-replay",
                           config_digest=config_digest({"x": 1}), profiles=PROFILES, prompt_versions=PROMPTS,
                           cost=zero_cost(), scored=True, replay_of="evr_" + "2" * 16)
        self.assertEqual(rep["metrics"]["precision"]["value"], 0.0)
        self.assertEqual(rep["metrics"]["recall"]["value"], 0.0)
        self.assertEqual(rep["metrics"]["f1"]["value"], 0.0)

    def test_report_is_deterministic_and_independent_of_case_order(self):
        a = report(self.suite, ideal(self.suite))
        b = report(self.suite, list(reversed(ideal(self.suite))))
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_missing_extra_or_duplicate_case_results_refused(self):
        res = ideal(self.suite)
        for bad in (res[:-1], res + [res[0]], res[:-1] + [dict(res[0], caseId="nope")]):
            with self.assertRaises(ScoringError):
                report(self.suite, bad)

    def test_tampered_tally_is_caught_by_the_contract(self):
        res = ideal(self.suite)
        res[0] = dict(res[0], truePositives=res[0]["truePositives"] + 1)
        with self.assertRaises(ContractViolation):
            report(self.suite, res)


class RealPrsStayUnscored(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = smoke_suite()
        real = copy.deepcopy(cls.suite.manifest)
        real.update(id="pilot-real-prs", synthetic=False, matching={"rule": "unadjudicated@1"})
        cls.real = real

    def test_manifest_contract_refuses_overlap_on_real_suite(self):
        bad = copy.deepcopy(self.real)
        bad["matching"] = {"rule": "path-line-overlap@1", "lineTolerance": 3}
        self.assertTrue(validate("SuiteManifest", bad))

    def test_score_case_refuses_real_or_unadjudicated_suites(self):
        for manifest in (self.real,):
            with self.assertRaises(UnscoredSuiteError):
                score_case(manifest, labels(("a.py", (1, 2))), [], status="completed")
        synthetic_unadjudicated = copy.deepcopy(self.suite.manifest)
        synthetic_unadjudicated["matching"] = {"rule": "unadjudicated@1"}
        with self.assertRaises(UnscoredSuiteError):
            score_case(synthetic_unadjudicated, labels(("a.py", (1, 2))), [], status="completed")

    def test_build_report_refuses_to_score_real_and_to_leave_smoke_unscored(self):
        res = [unscored_case_result(c["id"], run_id=run_for(c["id"]), status="completed", comments=2)
               for c in self.real["cases"]]
        with self.assertRaises(UnscoredSuiteError):
            build_report(self.real, self.suite.digest, res, eval_run_id=EVR, mode="strict-replay",
                         config_digest=config_digest({"x": 1}), profiles=PROFILES, prompt_versions=PROMPTS,
                         cost=zero_cost(), scored=True, replay_of="evr_" + "2" * 16)
        with self.assertRaises(ScoringError):
            build_report(self.suite.manifest, self.suite.digest, res, eval_run_id=EVR, mode="strict-replay",
                         config_digest=config_digest({"x": 1}), profiles=PROFILES, prompt_versions=PROMPTS,
                         cost=zero_cost(), scored=False, replay_of="evr_" + "2" * 16)

    def test_real_report_has_null_metrics_with_reason_and_null_tallies(self):
        res = [unscored_case_result(c["id"], run_id=run_for(c["id"]), status="completed", comments=2)
               for c in self.real["cases"]]
        rep = build_report(self.real, self.suite.digest, res, eval_run_id=EVR, mode="strict-replay",
                           config_digest=config_digest({"x": 1}), profiles=PROFILES, prompt_versions=PROMPTS,
                           cost=zero_cost(), scored=False, replay_of="evr_" + "2" * 16)
        self.assertEqual(rep["matching"], {"rule": "unadjudicated@1", "scope": "unscored"})
        for k in ("precision", "recall", "f1"):
            self.assertIsNone(rep["metrics"][k]["value"])
            self.assertTrue(rep["metrics"][k]["undefinedReason"])
        for c in rep["cases"]:
            self.assertTrue(all(c[k] is None for k in ("truePositives", "falsePositives",
                                                       "falseNegatives", "duplicates", "expect", "expectationMet")))
            self.assertEqual(c["comments"], 2)
        self.assertEqual(rep["coverage"]["expectationMet"], 0)

    def test_scored_numbers_cannot_be_smuggled_into_an_unscored_report(self):
        res = [unscored_case_result(c["id"], run_id=run_for(c["id"]), status="completed", comments=2)
               for c in self.real["cases"]]
        res[0]["truePositives"] = 1
        with self.assertRaises(ContractViolation):
            build_report(self.real, self.suite.digest, res, eval_run_id=EVR, mode="strict-replay",
                         config_digest=config_digest({"x": 1}), profiles=PROFILES, prompt_versions=PROMPTS,
                         cost=zero_cost(), scored=False, replay_of="evr_" + "2" * 16)

    def test_contract_example_for_real_prs_still_valid(self):
        require("EvalReport", read(SMOKE.parents[1] / "reviewer/contracts/examples/EvalReport.unscored-real.json"))


class InvalidComments(unittest.TestCase):
    def test_invalid_comment_is_refused_not_scored(self):
        suite = smoke_suite()
        bad = make_comment()
        bad["anchor"]["endLine"] = 1
        with self.assertRaises(ScoringError):
            score_case(suite.manifest, suite.cases["smoke-c01"].labels, [bad], status="completed")


if __name__ == "__main__":
    unittest.main()
