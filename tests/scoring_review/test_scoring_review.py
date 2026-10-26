"""Independent review tests for S0-04 (reviewer/scoring, fixtures/smoke). Reviewer-owned, offline, stdlib only.

`test_*` asserts the CORRECT behaviour: FAIL/ERROR = reproduced defect (SD-n ids in
handoffs/S0-04-review.md). `CONTROL_*` pass today. No __init__.py on purpose (the author's
`discover -s tests -t .` must not collect these). Fixtures are only ever read or copied to a temp dir.

Run: nice -n 19 python3 -m unittest discover -s tests/scoring_review -v
"""
from __future__ import annotations

import copy
import itertools
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import budget as B  # noqa: E402
from reviewer.contracts import loads_strict, validate  # noqa: E402
from reviewer.contracts import redaction as R  # noqa: E402
from reviewer.contracts.canonical import comment_fingerprint, comment_id, hypothesis_id  # noqa: E402
from reviewer.scoring import (ScoringError, UnscoredSuiteError, build_report, f1_value,  # noqa: E402
                              match_comments, ratio, score_case, scored_case_result,
                              unscored_case_result)
from reviewer.scoring.scripts import check_case_script  # noqa: E402
from reviewer.scoring.suite import check_isolation, load_suite  # noqa: E402

SMOKE = ROOT / "fixtures" / "smoke"
SNAP = "snap:sha256:" + "a" * 64
RUN = "run_" + "0" * 16


def comment(path="src/a.py", start=10, end=12, n=0, state="draft", snap=SNAP, cid=None):
    claim = f"claim {n} at {path}:{start}"
    fp = comment_fingerprint("bug", path, f"line {start}", claim)
    return {"id": cid or comment_id(fp), "runId": RUN, "findingIds": ["hyp_" + f"{n:016x}"],
            "severity": "P1", "proposedSeverity": "P1", "severityCeiling": "P1", "evidenceStrength": "cited",
            "category": "bug", "anchor": {"path": path, "startLine": start, "endLine": end, "snapshotId": snap},
            "title": f"T{n}", "body": claim,
            "evidence": [{"kind": "code", "path": path, "lines": [start, end], "commit": snap,
                          "excerpt": f"line {start}", "source": "diff"}],
            "qualityScore": None, "fingerprint": fp, "state": state}


def bug(i, path, lo, hi):
    return {"id": f"b{i}", "path": path, "lines": [lo, hi], "category": "bug", "severity": "P1"}


def brute_max(comments, bugs, tol):
    """Independent maximum bipartite matching by exhaustive search."""
    def compat(c, b):
        if c["anchor"]["path"] != b["path"]:
            return False
        s, e = c["anchor"]["startLine"], c["anchor"]["endLine"]
        lo, hi = b["lines"]
        d = s - hi if s > hi else lo - e if e < lo else 0
        return d <= tol
    adj = [[j for j, b in enumerate(bugs) if compat(c, b)] for c in comments]

    def rec(i, used):
        if i == len(adj):
            return 0
        best = rec(i + 1, used)
        for j in adj[i]:
            if not used >> j & 1:
                best = max(best, 1 + rec(i + 1, used | 1 << j))
        return best
    return rec(0, 0), adj


# ================================================================ matching
class M_Matching(unittest.TestCase):
    def test_CONTROL_maximum_cardinality_and_accounting_random(self):
        rng = random.Random(1234)
        for it in range(2500):
            tol = rng.randint(0, 4)
            paths = ["a.py", "b.py"][:rng.randint(1, 2)]
            nb = rng.randint(0, 5)
            bugs = []
            for i in range(nb):
                lo = rng.randint(1, 30)
                bugs.append(bug(i, rng.choice(paths), lo, lo + rng.randint(0, 3)))
            cs = []
            for n in range(rng.randint(0, 6)):
                s = rng.randint(1, 30)
                cs.append(comment(rng.choice(paths), s, s + rng.randint(0, 3), n=n))
            r = match_comments(cs, bugs, tol)
            best, adj = brute_max(cs, bugs, tol)
            self.assertEqual(r.true_positives, best, (it, cs, bugs, tol))
            cid = {c["id"]: i for i, c in enumerate(cs)}
            bid = {b["id"]: j for j, b in enumerate(bugs)}
            self.assertEqual(len({m[0] for m in r.matches}), len(r.matches))
            self.assertEqual(len({m[1] for m in r.matches}), len(r.matches))
            for c, b in r.matches:
                self.assertIn(bid[b], adj[cid[c]])
            self.assertEqual(len(r.matches) + len(r.false_positives), len(cs))
            self.assertEqual(len(r.false_negatives), len(bugs) - len(r.matches))
            self.assertTrue(set(r.duplicates) <= set(r.false_positives))
            matched_bugs = {m[1] for m in r.matches}
            for c in r.false_positives:
                is_dup = any(bugs[j]["id"] in matched_bugs for j in adj[cid[c]])
                self.assertEqual(c in r.duplicates, is_dup)

    def test_CONTROL_order_independence_of_results(self):
        rng = random.Random(9)
        for _ in range(300):
            bugs = [bug(i, "a.py", (lo := rng.randint(1, 12)), lo + rng.randint(0, 2)) for i in range(4)]
            cs = [comment("a.py", (s := rng.randint(1, 14)), s + rng.randint(0, 2), n=n) for n in range(5)]
            base = match_comments(cs, bugs, 2)
            for _k in range(4):
                a, b = cs[:], bugs[:]
                rng.shuffle(a)
                rng.shuffle(b)
                r = match_comments(a, b, 2)
                self.assertEqual((r.matches, r.false_positives, r.duplicates), (base.matches, base.false_positives, base.duplicates))

    def test_SD1_false_negative_ids_are_in_a_canonical_order(self):
        """Result tuples must not depend on the order the labels were listed."""
        bugs = [bug(i, "a.py", 100 + 10 * i, 100 + 10 * i) for i in range(4)]
        a = match_comments([], bugs, 3).false_negatives
        b = match_comments([], list(reversed(bugs)), 3).false_negatives
        self.assertEqual(a, b)

    def test_SD2_long_augmenting_chain_does_not_crash(self):
        """Recursive augment(): a ~1200-long augmenting path exceeds the interpreter recursion limit."""
        n = 1200
        bugs = [bug(i, "a.py", 2 * i + 1, 2 * i + 1) for i in range(n + 1)]
        cs = [comment("a.py", 2 * i + 1, 2 * i + 1, n=i) for i in range(n)]
        cs.append(comment("a.py", 1, 1, n=n))          # competes for bug 0, forcing the whole chain to shift
        try:
            r = match_comments(cs, bugs, 2)
        except RecursionError:
            self.fail("RecursionError on a long (but valid) matching instance")
        self.assertEqual(r.true_positives, brute_len(cs, bugs))

    def test_CONTROL_boundaries(self):
        for tol, start, ok in ((3, 15, True), (3, 16, False), (0, 13, False), (0, 12, True), (3, 5, True), (3, 4, False)):
            with self.subTest((tol, start)):
                r = match_comments([comment("a.py", start, start)], [bug(0, "a.py", 8, 12)], tol)
                self.assertEqual(r.true_positives, 1 if ok else 0)

    def test_CONTROL_zero_denominators_are_undefined_not_zero(self):
        for d in (ratio(0, 0, "none"),):
            self.assertIsNone(d["value"])
            self.assertEqual(validate("Ratio", d), [])
        self.assertEqual(ratio(0, 5, "x")["value"], 0.0)
        with self.assertRaises(ValueError):
            ratio(1, 0, "x")
        p, r = ratio(0, 0, "no comments"), ratio(0, 3, "x")
        f = f1_value(p, r)
        self.assertIsNone(f["value"])
        self.assertIn("precision undefined", f["undefinedReason"])
        self.assertEqual(f1_value(ratio(0, 2, "x"), ratio(0, 2, "x"))["value"], 0.0)

    def test_SD3_comment_must_belong_to_the_case_snapshot(self):
        """Matching ignores anchor.snapshotId: a comment anchored to some other snapshot (another case,
        the base side, a stale run) still scores as a true positive."""
        suite = load_suite(SMOKE)
        sc = suite.cases["smoke-c01"]
        labels = sc.labels
        head = sc.input["head"]["snapshotId"]
        b = labels["bugs"][0]
        good = comment(b["path"], b["lines"][0], b["lines"][1], snap=head)
        foreign = comment(b["path"], b["lines"][0], b["lines"][1], snap=sc.input["base"]["snapshotId"])
        s_good = score_case(suite.manifest, labels, [good], status="completed")
        self.assertEqual(s_good.true_positives, 1)
        try:
            s_bad = score_case(suite.manifest, labels, [foreign], status="completed", head_snapshot_id=head)
        except TypeError:
            s_bad = score_case(suite.manifest, labels, [foreign], status="completed")
        self.assertEqual(s_bad.true_positives, 0, "comment anchored to the BASE snapshot scored as a hit")


def brute_len(cs, bugs):
    # greedy-free exact answer for the chain instance: every bug can be matched by exactly one comment
    return min(len(cs), len(bugs))


# ================================================================ scoring semantics
class S_Semantics(unittest.TestCase):
    def setUp(self):
        self.suite = load_suite(SMOKE)

    def ideal(self, cid, status="completed", **kw):
        case = self.suite.cases[cid]
        b = case.labels["bugs"]
        cs = [comment(x["path"], x["lines"][0], x["lines"][1], n=i, snap=case.input["head"]["snapshotId"])
              for i, x in enumerate(b)]
        return score_case(self.suite.manifest, case.labels, cs, status=status, **kw)

    def test_CONTROL_expectations_per_case_type(self):
        self.assertTrue(self.ideal("smoke-c01").expectation_met)
        self.assertTrue(score_case(self.suite.manifest, self.suite.cases["smoke-c02"].labels, [],
                                   status="completed").expectation_met)
        self.assertTrue(self.ideal("smoke-c05", "partial", incomplete=[{"stage": "VERIFY", "reason": "verifier-failure"}]).expectation_met)
        self.assertTrue(score_case(self.suite.manifest, self.suite.cases["smoke-c06"].labels, [], status="failed",
                                   error={"code": "provider-timeout", "message": "t", "retryable": True}).expectation_met)
        # wrong reason / wrong status do not meet it
        self.assertFalse(self.ideal("smoke-c05", "partial", incomplete=[{"stage": "VERIFY", "reason": "deadline"}]).expectation_met)
        self.assertFalse(score_case(self.suite.manifest, self.suite.cases["smoke-c06"].labels, [], status="failed",
                                    error={"code": "provider-error", "message": "t", "retryable": True}).expectation_met)
        self.assertFalse(score_case(self.suite.manifest, self.suite.cases["smoke-c06"].labels, [], status="partial").expectation_met)

    def test_CONTROL_failed_and_partial_runs_book_labelled_bugs_as_fn(self):
        s = score_case(self.suite.manifest, self.suite.cases["smoke-c06"].labels, [], status="failed",
                       error={"code": "provider-timeout", "message": "t", "retryable": True})
        self.assertEqual((s.true_positives, s.false_positives, s.false_negatives), (0, 0, 1))

    def test_SD4_findings_case_requires_a_completed_run_even_with_a_hit(self):
        s = self.ideal("smoke-c01", status="partial", incomplete=[{"stage": "JUDGE", "reason": "deadline"}])
        self.assertFalse(s.expectation_met)
        self.assertEqual(s.true_positives, 1)

    def test_CONTROL_real_and_unadjudicated_suites_cannot_be_scored(self):
        man = copy.deepcopy(self.suite.manifest)
        man["synthetic"], man["matching"] = False, {"rule": "unadjudicated@1"}
        with self.assertRaises(UnscoredSuiteError):
            score_case(man, self.suite.cases["smoke-c01"].labels, [], status="completed")
        results = [unscored_case_result(c["id"], run_id=RUN, status="completed", comments=2) for c in man["cases"]]
        rep = build_report(man, "sha256:" + "1" * 64, results, eval_run_id="evr_" + "1" * 16, mode="strict-replay",
                           config_digest="sha256:" + "2" * 64, profiles=[{"ref": "smoke-synthetic@1", "digest": "sha256:" + "3" * 64}],
                           prompt_versions=["p@v1"], cost=__import__("reviewer.scoring.report", fromlist=["x"]).zero_cost(),
                           scored=False, replay_of="evr_" + "9" * 16)
        self.assertEqual(rep["matching"], {"rule": "unadjudicated@1", "scope": "unscored"})
        for k in ("precision", "recall"):
            self.assertIsNone(rep["metrics"][k]["value"])
            self.assertTrue(rep["metrics"][k]["undefinedReason"])
        self.assertIsNone(rep["metrics"]["f1"]["value"])
        for c in rep["cases"]:
            self.assertTrue(all(c[k] is None for k in ("truePositives", "falsePositives", "falseNegatives", "duplicates", "expect", "expectationMet")))
        with self.assertRaises(UnscoredSuiteError):
            build_report(man, "sha256:" + "1" * 64, results, eval_run_id="evr_" + "1" * 16, mode="strict-replay",
                         config_digest="sha256:" + "2" * 64, profiles=[], prompt_versions=[], cost={}, scored=True)

    def test_CONTROL_smoke_report_is_scoped_and_honest(self):
        man = self.suite.manifest
        results = []
        for cid, case in self.suite.cases.items():
            expect = case.labels["expect"]
            if expect == "silence":
                sc = score_case(man, case.labels, [], status="completed")
                results.append(scored_case_result(sc, run_id=RUN, status="completed"))
            elif expect == "failed":
                sc = score_case(man, case.labels, [], status="failed", error={"code": "provider-timeout", "message": "t", "retryable": True})
                results.append(scored_case_result(sc, run_id=RUN, status="failed", error={"code": "provider-timeout", "message": "t", "retryable": True}))
            else:
                inc = [{"stage": "VERIFY", "reason": "verifier-failure"}] if expect == "partial" else []
                if inc:          # persistent verifier failure publishes nothing: the labelled bug stays a FN
                    sc = score_case(man, case.labels, [], status="partial", incomplete=inc)
                else:
                    sc = self.ideal(cid, "completed")
                results.append(scored_case_result(sc, run_id=RUN, status="partial" if inc else "completed", incomplete=inc))
        from reviewer.scoring.report import zero_cost
        rep = build_report(man, self.suite.digest, results, eval_run_id="evr_" + "1" * 16, mode="strict-replay",
                           config_digest="sha256:" + "2" * 64, profiles=[{"ref": "smoke-synthetic@1", "digest": "sha256:" + "3" * 64}],
                           prompt_versions=["p@v1"], cost=zero_cost(synthetic_records=3), scored=True, replay_of="evr_" + "9" * 16)
        self.assertEqual(rep["matching"]["scope"], "synthetic-smoke")
        self.assertEqual((rep["metrics"]["precision"]["numerator"], rep["metrics"]["precision"]["denominator"]), (3, 3))
        self.assertEqual((rep["metrics"]["recall"]["numerator"], rep["metrics"]["recall"]["denominator"]), (3, 5))
        self.assertTrue(any("quality" in l for l in rep["limitations"]))


# ================================================================ suite loading, tamper, symlinks, digests
def copy_smoke():
    tmp = Path(tempfile.mkdtemp())
    d = tmp / "smoke"
    shutil.copytree(SMOKE, d, symlinks=True)
    return tmp, d


def cli(*args):
    return subprocess.run([sys.executable, "-m", "reviewer.scoring", *args], cwd=ROOT, capture_output=True, text=True)


class T_Suite(unittest.TestCase):
    def setUp(self):
        self.tmp, self.d = copy_smoke()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_CONTROL_baseline_and_location_independent_digest(self):
        a = load_suite(SMOKE).digest
        self.assertEqual(load_suite(self.d).digest, a)
        self.assertEqual(cli("check").returncode, 0)
        self.assertEqual(cli("build-smoke", "--check").returncode, 0)

    def test_CONTROL_snapshot_tamper_and_symlinks_refused(self):
        h = self.d / "cases/smoke-c01/head/src/auth.py"
        h.write_text(h.read_text() + "\n# tamper\n")
        with self.assertRaises(ScoringError):
            load_suite(self.d)
        h.write_text(h.read_text().replace("\n# tamper\n", ""))
        h.write_text(h.read_text().rstrip("\n") + "\n") if False else None
        shutil.rmtree(self.tmp)
        self.setUp()
        os.symlink("/etc/hostname", self.d / "cases/smoke-c01/head/src/link")
        with self.assertRaises(ScoringError):
            load_suite(self.d)
        shutil.rmtree(self.tmp)
        self.setUp()
        (self.d / "cases/smoke-c01/head/src/extra.py").write_text("x = 1\n")
        with self.assertRaises(ScoringError):
            load_suite(self.d)
        shutil.rmtree(self.tmp)
        self.setUp()
        moved = self.d / "cases-real"
        os.rename(self.d / "cases/smoke-c02", moved)
        os.symlink(moved, self.d / "cases/smoke-c02")
        with self.assertRaises(ScoringError):
            load_suite(self.d)

    def test_CONTROL_symlinked_label_or_input_refused(self):
        lab = self.d / "labels/smoke-c01.json"
        keep = self.d / "labels/real.json"
        os.rename(lab, keep)
        os.symlink(keep, lab)
        with self.assertRaises(ScoringError):
            load_suite(self.d)

    def test_SD5_scripted_responses_are_covered_by_the_config_identity_not_the_dataset_digest(self):
        """Root SD5 ruling (NEXT-WAVE shared decisions): the dataset suiteDigest MAY stay unchanged when only
        scripts change, but synthetic_config_digest must change. Adapted from the original assertion that
        forced the dataset digest to move. Independent edge cases: tests/scoring_review/test_scoring_rereview.py."""
        from reviewer.scoring.suite import synthetic_config_digest
        before_ds, before_cfg = load_suite(self.d).digest, synthetic_config_digest(load_suite(self.d))
        p = self.d / "scripts/smoke-c01.json"
        doc = json.loads(p.read_text())
        for e in doc["entries"]:
            if e["stage"] == "JUDGE":
                e["response"]["output"]["comments"][0]["body"] = "Completely different scripted wording."
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        r = cli("check", str(self.d))
        self.assertEqual(r.returncode, 0, r.stdout)                  # still a valid script...
        after = load_suite(self.d)
        self.assertEqual(after.digest, before_ds, "dataset digest is policy-stable under script edits")
        self.assertNotEqual(synthetic_config_digest(after), before_cfg,   # ...but the run identity moves
                            "changed response fixtures replay under an unchanged synthetic_config_digest")

    def test_SD6_a_scripts_digest_recipe_exists(self):
        import reviewer.contracts.canonical as C
        names = [n for n in dir(C) if "script" in n.lower()]
        import reviewer.scoring.suite as S
        names += [n for n in dir(S) if "script" in n.lower() and "digest" in n.lower()]
        self.assertTrue(names, "no recipe binds scripted responses (or the redaction version) into a config identity")

    def test_SD7_check_cli_fails_cleanly_on_bad_scripts(self):
        p = self.d / "scripts/smoke-c01.json"
        for name, make in (("invalid json", lambda: p.write_text("{nope")),
                           ("symlinked script", lambda: (p.unlink(), os.symlink(self.d / "scripts/smoke-c02.json", p))),
                           ("duplicate keys", lambda: p.write_text('{"schemaVersion":1,"schemaVersion":1,"entries":[]}'))):
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                p = self.d / "scripts/smoke-c01.json"
                make()
                r = cli("check", str(self.d))
                self.assertEqual(r.returncode, 1)
                self.assertNotIn("Traceback", r.stderr, r.stderr[-300:])

    def test_SD8_check_flags_protected_text_in_fixtures(self):
        """The corpus loader rescans for protected text; `reviewer.scoring check` does not, so a regenerated
        suite that contains a secret (snapshot id re-pinned) passes."""
        aws = "AKIAIOSFODNN7EXAMPLE"
        f = self.d / "cases/smoke-c02/head/src/report.py"
        f.write_text(f.read_text() + f'\nKEY = "{aws}"\n')
        from reviewer.contracts.snapshot import build_manifest
        inp = self.d / "cases/smoke-c02/input.json"
        doc = json.loads(inp.read_text())
        doc["head"]["snapshotId"] = build_manifest(self.d / "cases/smoke-c02/head")["snapshotId"]
        inp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        r = cli("check", str(self.d))
        self.assertNotEqual(r.returncode, 0, "check accepted a fixture containing " + aws)

    def test_SD9_labels_are_not_opened_for_a_real_suite(self):
        """load_suite documents that a real suite's labels are never opened, but it hashes them (needs
        read access). A sealed/unreadable labels file must not break loading or leak into the process."""
        man = json.loads((self.d / "suite.json").read_text())
        man["synthetic"] = False
        man["matching"] = {"rule": "unadjudicated@1"}
        (self.d / "suite.json").write_text(json.dumps(man))
        for cid in [c["id"] for c in man["cases"]]:
            ip = self.d / f"cases/{cid}/input.json"
            d = json.loads(ip.read_text())
            d["synthetic"] = False
            ip.write_text(json.dumps(d))
        for p in (self.d / "labels").glob("*.json"):
            p.chmod(0)
        self.addCleanup(lambda: [p.chmod(0o644) for p in (self.d / "labels").glob("*.json")])
        if os.access(self.d / "labels/smoke-c01.json", os.R_OK):
            self.skipTest("running with privileges that ignore file modes")
        try:
            suite = load_suite(self.d)
        except Exception as e:  # noqa: BLE001
            self.fail(f"loading a real suite touched its labels files: {type(e).__name__}: {e}")
        self.assertTrue(all(c.labels is None for c in suite.cases.values()))


# ================================================================ label isolation, scripts and root decisions
class I_Isolation(unittest.TestCase):
    def setUp(self):
        self.tmp, self.d = copy_smoke()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_CONTROL_clean_suite_has_no_leaks_and_inputs_hide_the_answer(self):
        s = load_suite(SMOKE)
        self.assertEqual(check_isolation(s), [])
        for cid, case in s.cases.items():
            raw = json.dumps(case.input)
            for needle in ("silence", "findings", "partial", "verifier-failure", "provider-timeout", "expect", "bugs"):
                self.assertNotIn(needle, raw, cid)
            for b in case.labels["bugs"]:
                self.assertNotIn(b["id"], raw)

    def test_CONTROL_leaks_are_detected(self):
        s0 = load_suite(self.d)
        bug_id = s0.cases["smoke-c01"].labels["bugs"][0]["id"]
        inp = self.d / "cases/smoke-c01/input.json"
        doc = json.loads(inp.read_text())
        doc["pr"]["body"] += f" ({bug_id})"
        inp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        self.assertTrue(check_isolation(load_suite(self.d)))
        shutil.rmtree(self.tmp)
        self.setUp()
        sp = self.d / "scripts/smoke-c01.json"
        sp.write_text(sp.read_text().replace('"notes"', f'"notes": "{bug_id}", "x"', 1)) if False else None
        doc = json.loads(sp.read_text())
        doc["entries"][0]["response"]["output"]["hypotheses"][0]["mechanism"] += f" {bug_id}"
        sp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        self.assertTrue(check_isolation(load_suite(self.d)))

    def test_CONTROL_raw_model_evidence_cannot_self_assert_resolution(self):
        for extra in ({"resolved": True}, {"trusted": True}, {"verified": True}, {"toolCallId": "tool_0123456789abcdef"}):
            doc = json.loads((SMOKE / "scripts/smoke-c01.json").read_text())
            ev = doc["entries"][0]["response"]["output"]["hypotheses"][0]["evidence"][0]
            ev.update(extra)
            p = self.d / "scripts/smoke-c01.json"
            p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            with self.subTest(extra):
                self.assertTrue(check_case_script(load_suite(self.d), "smoke-c01"))
        self.assertTrue(validate("ModelEvidence", {"kind": "code", "path": "a.py", "lines": [1, 1], "commit": "a" * 40,
                                                   "excerpt": "x", "resolved": True}))
        self.assertTrue(validate("ModelEvidence", {"kind": "analyzer", "toolCallId": "tool_0123456789abcdef"}))

    def test_CONTROL_every_script_citation_resolves_against_head(self):
        s = load_suite(SMOKE)
        for cid in s.cases:
            self.assertEqual(check_case_script(s, cid), [], cid)
        # a citation to a line range that does not match is caught
        p = self.d / "scripts/smoke-c01.json"
        doc = json.loads(p.read_text())
        doc["entries"][0]["response"]["output"]["hypotheses"][0]["evidence"][0]["excerpt"] = "not the code"
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        self.assertTrue(check_case_script(load_suite(self.d), "smoke-c01"))

    def test_SD10_script_must_be_complete_for_the_pipeline_it_feeds(self):
        """check_case_script verifies entries it finds but not that every candidate has a verifier entry
        (missing keys become script-miss failures at runtime). Removing verifier ordinal 1 in the
        duplicate case is accepted."""
        p = self.d / "scripts/smoke-c03.json"
        doc = json.loads(p.read_text())
        doc["entries"] = [e for e in doc["entries"] if not (e["stage"] == "VERIFY" and e["ordinal"] == 1)]
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        self.assertTrue(check_case_script(load_suite(self.d), "smoke-c03"),
                        "candidate 1 has no verifier response and the checker did not notice")

    def test_SD11_judge_entry_required_when_a_finding_can_be_confirmed(self):
        p = self.d / "scripts/smoke-c01.json"
        doc = json.loads(p.read_text())
        doc["entries"] = [e for e in doc["entries"] if e["stage"] != "JUDGE"]
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        self.assertTrue(check_case_script(load_suite(self.d), "smoke-c01"))


class D_RootDecisions(unittest.TestCase):
    """Encode the root's answers to the handoff questions against the checked-in fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.suite = load_suite(SMOKE)
        cls.scripts = {cid: json.loads((SMOKE / "scripts" / f"{cid}.json").read_text()) for cid in cls.suite.cases}

    def entries(self, cid, stage):
        return [e for e in self.scripts[cid]["entries"] if e["stage"] == stage]

    def test_CONTROL_hypothesis_ordinal_is_the_investigator_output_index(self):
        for cid in ("smoke-c01", "smoke-c03", "smoke-c04"):
            inv = [e for e in self.entries(cid, "INVESTIGATE") if "response" in e and e["response"]["status"] == "ok"][0]
            hyps = inv["response"]["output"]["hypotheses"]
            ids = [hypothesis_id("generalist", n, h["claim"], h["location"]["path"], h["location"]["line"]) for n, h in enumerate(hyps)]
            verifier_ord = sorted({e["ordinal"] for e in self.entries(cid, "VERIFY")})
            self.assertEqual(verifier_ord, list(range(len(hyps))), cid)
            judge = self.entries(cid, "JUDGE")[0]["response"]["output"]["comments"]
            self.assertTrue(all(f in ids for c in judge for f in c["findingIds"]))

    def test_CONTROL_duplicate_case_yields_one_comment_bound_to_every_merged_finding(self):
        """Current pipeline dedup contract (judging.merge_group): a validated judge group becomes ONE comment that keeps
        every member finding id. Candidate order picks the primary, it never deletes provenance. Replaces the obsolete
        'merges to candidate zero only' expectation."""
        inv = self.entries("smoke-c03", "INVESTIGATE")[0]["response"]["output"]["hypotheses"]
        self.assertEqual(len(inv), 2)
        a, b = inv
        self.assertEqual(a["location"]["path"], b["location"]["path"])
        self.assertTrue(set(range(b["location"]["line"], b["location"].get("endLine", b["location"]["line"]) + 1))
                        & set(range(a["location"]["line"], a["location"].get("endLine", a["location"]["line"]) + 1)))
        ids = [hypothesis_id("generalist", n, h["claim"], h["location"]["path"], h["location"]["line"])
               for n, h in enumerate(inv)]
        self.assertEqual(len(set(ids)), 2)
        judge = self.entries("smoke-c03", "JUDGE")
        self.assertEqual(len(judge), 1)
        comments = judge[0]["response"]["output"]["comments"]
        self.assertEqual(len(comments), 1, "duplicate reports must still produce exactly one comment")
        self.assertEqual(sorted(comments[0]["findingIds"]), sorted(ids))        # all merged findings retained
        self.assertEqual(len(comments[0]["findingIds"]), len(set(comments[0]["findingIds"])))
        self.assertTrue(set(comments[0]["findingIds"]) <= set(ids))             # every reference is a real finding
        # both candidates were verified, so both are legitimate members of the group
        self.assertEqual(sorted(e["ordinal"] for e in self.entries("smoke-c03", "VERIFY")), [0, 1])

    def test_CONTROL_outcome_labels_follow_root_decisions(self):
        l5, l6 = self.suite.cases["smoke-c05"].labels, self.suite.cases["smoke-c06"].labels
        self.assertEqual((l5["expect"], l5["expectReason"]), ("partial", "verifier-failure"))
        self.assertEqual((l6["expect"], l6["expectReason"]), ("failed", "provider-timeout"))
        self.assertFalse(self.entries("smoke-c05", "JUDGE"))
        self.assertTrue(all("error" in e for e in self.entries("smoke-c05", "VERIFY")))
        self.assertTrue(all("error" in e for e in self.entries("smoke-c06", "INVESTIGATE")))
        self.assertFalse(self.entries("smoke-c06", "VERIFY"))

    def test_CONTROL_attempts_follow_min_of_run_and_role_limits(self):
        prof = json.loads((ROOT / "reviewer/contracts/examples/ModelProfile.smoke-synthetic.json").read_text())
        plan = json.loads((ROOT / "reviewer/contracts/examples/Plan.json").read_text())
        for cid, stage, role in (("smoke-c06", "INVESTIGATE", "investigator"), ("smoke-c05", "VERIFY", "verifier")):
            retries, repairs = B.effective_retry_limits(plan["budget"], prof["roles"][role]["caps"])
            atts = sorted(e["attempt"] for e in self.entries(cid, stage))
            self.assertEqual(atts, list(range(retries + 1)), f"{cid}: terminal failure after exactly retries+1 attempts")
        retries, repairs = B.effective_retry_limits(plan["budget"], prof["roles"]["investigator"]["caps"])
        c4 = self.entries("smoke-c04", "INVESTIGATE")
        self.assertEqual([e["attempt"] for e in c4], [0, 1])
        self.assertLessEqual(1, repairs)
        self.assertEqual(c4[0]["response"]["status"], "invalid-output")

    def test_CONTROL_no_script_carries_run_scoped_or_timing_data(self):
        for cid, doc in self.scripts.items():
            raw = json.dumps(doc)
            self.assertNotRegex(raw, r"\brun_[0-9a-f]{16}\b")
            self.assertNotRegex(raw, r"\bevr_[0-9a-f]{16}\b")
            self.assertNotIn("latencyMs", raw)

    def test_CONTROL_fixtures_survive_current_redaction(self):
        changed = []
        for p in SMOKE.rglob("*"):
            if p.is_file():
                t = p.read_text()
                if R.redact(t)[0] != t or R.contains_protected(t):
                    changed.append(str(p.relative_to(SMOKE)))
        self.assertEqual(changed, [])

    def test_SD12_fixtures_record_the_redaction_version_they_were_checked_under(self):
        """Citation excerpts are compared after redaction, so fixtures are only valid under a redaction
        version. Neither suite.json nor any fixture file records one, and the suite digest ignores it."""
        raw = (SMOKE / "suite.json").read_text()
        self.assertIn(R.REDACTION_VERSION.split("@")[0], raw, "suite.json carries no redaction version/provenance")


if __name__ == "__main__":
    unittest.main()
