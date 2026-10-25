"""S0-04 corrections (SD1-SD3, SD5-SD12): author tests. Independent tests live in tests/scoring_review."""
import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import redaction
from reviewer.contracts.snapshot import build_manifest
from reviewer.scoring import UnscoredSuiteError, match_comments, score_case, score_loaded_case
from reviewer.scoring.__main__ import main as cli
from reviewer.scoring.checks import check_suite
from reviewer.scoring.scripts import check_case_script, smoke_limits
from reviewer.scoring.suite import (load_suite, redaction_fingerprint, scripts_digest,
                                    synthetic_config_digest)
from .helpers import RUN, SMOKE, labels, make_comment
from .test_suite import Tmp


def bug(i, path, lo, hi):
    return {"id": f"b{i}", "path": path, "lines": [lo, hi], "category": "bug", "severity": "P1"}


class Matching(unittest.TestCase):
    def test_false_negatives_sorted_regardless_of_label_order(self):
        bugs = [bug(i, "a.py", 100 + 10 * i, 100 + 10 * i) for i in (3, 1, 2, 0)]
        self.assertEqual(match_comments([], bugs, 3).false_negatives, ("b0", "b1", "b2", "b3"))

    def test_long_augmenting_chain_needs_no_recursion(self):
        n = 3000
        bugs = [bug(i, "a.py", 2 * i + 1, 2 * i + 1) for i in range(n + 1)]
        cs = [make_comment("a.py", 2 * i + 1, 2 * i + 1, n=i) for i in range(n)]
        cs.append(make_comment("a.py", 1, 1, n=n))
        self.assertEqual(match_comments(cs, bugs, 2).true_positives, n + 1)

    def test_iterative_matching_still_maximum(self):
        # greedy would give the first comment the only bug the second can use
        bugs = [bug(0, "a.py", 10, 10), bug(1, "a.py", 14, 14)]
        cs = [make_comment("a.py", 12, 12, n=0), make_comment("a.py", 10, 10, n=1)]
        r = match_comments(cs, bugs, 2)
        self.assertEqual(r.true_positives, 2)
        self.assertEqual(r.false_negatives, ())

    def test_foreign_comment_never_matches_and_is_a_plain_fp(self):
        b = [bug(0, "a.py", 10, 12)]
        good, base, other_run = (make_comment("a.py", 10, 12, n=0), make_comment("a.py", 10, 12, n=1),
                                 make_comment("a.py", 10, 12, n=2, run="run_" + "1" * 16))
        base["anchor"] = {**base["anchor"], "snapshotId": "snap:sha256:" + "b" * 64}
        r = match_comments([good, base, other_run], b, 3, head_snapshot_id=good["anchor"]["snapshotId"], run_id=RUN)
        self.assertEqual(r.matches, ((good["id"], "b0"),))
        self.assertEqual(set(r.foreign), {base["id"], other_run["id"]})
        self.assertEqual(set(r.false_positives), set(r.foreign))
        self.assertEqual(r.duplicates, ())          # foreign is not a duplicate of the matched bug

    def test_foreign_only_checks_what_the_caller_names(self):
        c = make_comment("a.py", 10, 12)
        self.assertEqual(match_comments([c], [bug(0, "a.py", 10, 12)], 3).true_positives, 1)


class ScoreLoaded(unittest.TestCase):
    def test_score_loaded_case_uses_the_cases_head_and_the_run(self):
        suite = load_suite(SMOKE)
        sc = suite.cases["smoke-c01"]
        b = sc.labels["bugs"][0]
        head, base = sc.input["head"]["snapshotId"], sc.input["base"]["snapshotId"]

        def mk(snap, run=RUN):
            c = make_comment(b["path"], b["lines"][0], b["lines"][1], run=run)
            c["anchor"] = {**c["anchor"], "snapshotId": snap}
            return c
        ok = score_loaded_case(suite, "smoke-c01", [mk(head)], run_id=RUN, status="completed")
        self.assertEqual((ok.true_positives, ok.foreign, ok.expectation_met), (1, 0, True))
        for bad in (mk(base), mk(head, run="run_" + "2" * 16)):
            s = score_loaded_case(suite, "smoke-c01", [bad], run_id=RUN, status="completed")
            self.assertEqual((s.true_positives, s.false_positives, s.false_negatives, s.foreign, s.expectation_met),
                             (0, 1, 1, 1, False))

    def test_real_suite_cannot_be_scored(self):
        suite = load_suite(SMOKE)
        man = dict(suite.manifest, synthetic=False, matching={"rule": "unadjudicated@1"})
        with self.assertRaises(UnscoredSuiteError):
            score_case(man, labels(), [], status="completed")


class Identity(Tmp):
    def test_scripts_digest_tracks_script_bytes_not_the_dataset_digest(self):
        a = load_suite(self.dir)
        sd_a, cd_a = scripts_digest(a), synthetic_config_digest(a)   # computed from the files on demand
        self.edit("scripts/smoke-c01.json", lambda d: d["entries"][-1]["response"]["output"]["comments"][0]
                  .update(body="different scripted wording"))
        b = load_suite(self.dir)
        self.assertEqual(a.digest, b.digest)                       # dataset identity unchanged by design
        self.assertNotEqual(sd_a, scripts_digest(b))
        self.assertNotEqual(cd_a, synthetic_config_digest(b))

    def test_config_digest_binds_suite_config_and_redaction_policy(self):
        s = load_suite(self.dir)
        base = synthetic_config_digest(s)
        self.assertEqual(base, synthetic_config_digest(load_suite(SMOKE)))      # location independent
        self.assertNotEqual(base, synthetic_config_digest(s, {"plan": "x"}))
        fp = redaction_fingerprint()
        pats = redaction.PROTECTED_PATTERNS + (("extra", __import__("re").compile("zzz")),)
        with mock.patch("reviewer.scoring.suite.PROTECTED_PATTERNS", pats):
            self.assertNotEqual(redaction_fingerprint(), fp)
            self.assertNotEqual(synthetic_config_digest(s), base)
        with mock.patch("reviewer.scoring.suite.REDACTION_VERSION", "redact@99"):
            self.assertNotEqual(synthetic_config_digest(s), base)

    def test_missing_script_has_no_identity(self):
        (self.dir / "scripts/smoke-c02.json").unlink()
        with self.assertRaises(Exception):
            scripts_digest(load_suite(self.dir))

    def test_real_suite_never_opens_labels_and_takes_sealed_hashes(self):
        man = json.loads((self.dir / "suite.json").read_text())
        man["synthetic"], man["matching"] = False, {"rule": "unadjudicated@1"}
        (self.dir / "suite.json").write_text(json.dumps(man))
        for c in man["cases"]:
            self.edit(c["input"], lambda d: d.update(synthetic=False))
        opened = []
        real_bytes, real_text = Path.read_bytes, Path.read_text

        def spy_bytes(path):
            opened.append(str(path))
            return real_bytes(path)

        def spy_text(path, *a, **k):
            opened.append(str(path))
            return real_text(path, *a, **k)
        with mock.patch.object(Path, "read_bytes", spy_bytes), mock.patch.object(Path, "read_text", spy_text):
            suite = load_suite(self.dir)
        self.assertTrue(opened)   # the spy sees the inputs, so an empty labels list means something
        self.assertFalse([p for p in opened if "/labels/" in p])
        self.assertIsNone(suite.digest)
        self.assertTrue(all(c.labels is None for c in suite.cases.values()))
        sealed = {c["labels"]: "ab" * 32 for c in man["cases"]}
        self.assertTrue(load_suite(self.dir, sealed_label_hashes=sealed).digest.startswith("sha256:"))


class Completeness(Tmp):
    def script(self, cid, fn):
        self.edit(f"scripts/{cid}.json", fn)
        return check_case_script(load_suite(self.dir), cid)

    def test_shipped_scripts_are_complete(self):
        self.assertEqual(check_suite(load_suite(SMOKE)), [])

    def test_limits_come_from_the_example_plan_and_profile(self):
        self.assertEqual(smoke_limits(), {"investigator": (2, 1), "verifier": (2, 1), "judge": (2, 1)})

    def test_every_candidate_needs_verifier_entries(self):
        self.assertTrue(self.script("smoke-c03", lambda d: d.update(
            entries=[e for e in d["entries"] if not (e["stage"] == "VERIFY" and e["ordinal"] == 1)])))

    def test_judge_required_when_a_candidate_can_be_confirmed(self):
        self.assertTrue(self.script("smoke-c01", lambda d: d.update(
            entries=[e for e in d["entries"] if e["stage"] != "JUDGE"])))

    def test_judge_must_reference_confirmed_candidates_only(self):
        def to_refuted(d):
            for e in d["entries"]:
                if e["stage"] == "VERIFY":
                    e["response"]["output"].update(verdict="uncertain", evidence=[])
        self.assertTrue(self.script("smoke-c01", to_refuted))   # judge scripted but nothing confirmed

    def test_error_scripts_cover_exactly_the_attempts_the_caps_allow(self):
        for attempts in ([0, 1], [0, 1, 2, 3]):
            with self.subTest(attempts):
                self.setUp()
                self.assertTrue(self.script("smoke-c05", lambda d: d.update(entries=[
                    e for e in d["entries"] if e["stage"] != "VERIFY" or e["attempt"] in attempts]
                    + [dict(e, attempt=3) for e in d["entries"] if e["stage"] == "VERIFY" and e["attempt"] == 2
                       and 3 in attempts])))

    def test_unreachable_entries_are_flagged(self):
        def add_verify(d):
            d["entries"].append(dict(next(e for e in d["entries"] if e["stage"] == "INVESTIGATE")))
        # a silence case with a verifier entry for a candidate that does not exist
        v = load_suite(SMOKE)
        c1 = json.loads((SMOKE / "scripts/smoke-c01.json").read_text())
        verify = next(e for e in c1["entries"] if e["stage"] == "VERIFY")
        self.assertTrue(self.script("smoke-c02", lambda d: d["entries"].append(verify)))
        self.setUp()
        # timeout case plus a verifier entry: unreachable after a terminal investigator failure
        self.assertTrue(self.script("smoke-c06", lambda d: d["entries"].append(verify)))

    def test_attempt_gaps_and_entries_after_ok_are_flagged(self):
        def gap(d):
            for e in d["entries"]:
                if e["stage"] == "INVESTIGATE" and e["attempt"] == 1:
                    e["attempt"] = 2
        self.assertTrue(self.script("smoke-c04", gap))
        self.setUp()
        self.assertTrue(self.script("smoke-c04", lambda d: d["entries"].append(
            dict(next(e for e in d["entries"] if e["stage"] == "INVESTIGATE" and e["attempt"] == 1), attempt=2))))


class Check(Tmp):
    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli(["check", *args])
        return rc, out.getvalue()

    def test_clean_failures_for_bad_scripts(self):
        p = self.dir / "scripts/smoke-c01.json"
        keep = p.read_text()
        for name, make in (("invalid json", lambda: p.write_text("{nope")),
                           ("duplicate keys", lambda: p.write_text('{"schemaVersion":1,"schemaVersion":1,"entries":[]}')),
                           ("symlink", lambda: (p.unlink(), os.symlink(self.dir / "scripts/smoke-c02.json", p)))):
            with self.subTest(name):
                if p.is_symlink() or p.exists():
                    p.unlink()
                p.write_text(keep)
                make()
                rc, out = self.run_cli(str(self.dir))
                self.assertEqual(rc, 1)
                self.assertIn("smoke-c01", out)

    def test_protected_text_anywhere_in_the_suite_fails_check(self):
        f = self.dir / "cases/smoke-c02/head/src/report.py"
        f.write_text(f.read_text() + '\nKEY = "AKIAIOSFODNN7EXAMPLE"\n')
        self.edit("cases/smoke-c02/input.json", lambda d: d["head"].update(
            snapshotId=build_manifest(self.dir / "cases/smoke-c02/head")["snapshotId"]))
        rc, out = self.run_cli(str(self.dir))
        self.assertEqual(rc, 1)
        self.assertIn("protected text", out)

    def test_protected_text_in_a_script_fails_check(self):
        p = self.dir / "scripts/smoke-c01.json"
        self.edit("scripts/smoke-c01.json", lambda d: d["entries"][-1]["response"]["output"]["comments"][0]
                  .update(body="key AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue([x for x in check_suite(load_suite(self.dir)) if "protected text" in x])

    def test_description_must_record_the_current_redaction_version(self):
        with mock.patch("reviewer.scoring.checks.REDACTION_VERSION", "redact@99"):
            self.assertTrue([x for x in check_suite(load_suite(SMOKE)) if "redact@99" in x])
        self.assertIn(redaction.REDACTION_VERSION, load_suite(SMOKE).manifest["description"])
