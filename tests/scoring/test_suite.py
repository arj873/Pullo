import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts import validate
from reviewer.scoring.smoke import build_files, diff_smoke
from reviewer.scoring.suite import ScoringError, check_isolation, load_suite
from reviewer.scoring.__main__ import main as cli
from .helpers import KINDS, SMOKE, smoke_suite


class Tmp(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.dir = Path(self._t.name) / "smoke"
        shutil.copytree(SMOKE, self.dir)

    def edit(self, rel, fn):
        p = self.dir / rel
        doc = json.loads(p.read_text())
        fn(doc)
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


class Fixture(unittest.TestCase):
    def test_checked_in_tree_equals_generator_output(self):
        self.assertEqual(diff_smoke(SMOKE), [])

    def test_generator_is_deterministic(self):
        self.assertEqual(build_files(), build_files())

    def test_suite_loads_and_covers_every_required_case_type(self):
        s = smoke_suite()
        self.assertEqual(validate("SuiteManifest", s.manifest), [])
        self.assertTrue(s.manifest["synthetic"])
        self.assertEqual(s.manifest["matching"], {"rule": "path-line-overlap@1", "lineTolerance": 3})
        self.assertEqual(sorted(s.cases), sorted(KINDS))
        expect = {cid: c.labels["expect"] for cid, c in s.cases.items()}
        self.assertEqual(sorted(expect.values()), ["failed", "findings", "findings", "findings", "partial", "silence"])
        self.assertTrue(s.digest.startswith("sha256:"))
        for c in s.cases.values():
            self.assertTrue(c.input["synthetic"])

    def test_snapshots_are_pinned_and_distinct(self):
        for c in smoke_suite().cases.values():
            self.assertNotEqual(c.input["base"]["snapshotId"], c.input["head"]["snapshotId"])
            self.assertEqual(c.base_manifest["snapshotId"], c.input["base"]["snapshotId"])

    def test_no_protected_text_in_any_fixture_file(self):
        from reviewer.contracts.redaction import contains_protected
        for p in SMOKE.rglob("*"):
            if p.is_file():
                self.assertFalse(contains_protected(p.read_text(encoding="utf-8")), p.name)

    def test_cli_check_passes(self):
        self.assertEqual(cli(["check", str(SMOKE)]), 0)
        self.assertEqual(cli(["build-smoke", "--check", "--out", str(SMOKE)]), 0)

    def test_case_ids_do_not_reveal_the_expectation(self):
        for cid in smoke_suite().cases:
            for word in ("silence", "bug", "positive", "failure", "timeout", "repair", "duplicate"):
                self.assertNotIn(word, cid)


class Pinning(Tmp):
    def test_changed_snapshot_file_is_detected(self):
        p = self.dir / "cases/smoke-c01/head/src/auth.py"
        p.write_text(p.read_text() + "# edited\n")
        with self.assertRaises(ScoringError):
            load_suite(self.dir)

    def test_added_or_symlinked_snapshot_entries_are_refused(self):
        (self.dir / "cases/smoke-c01/head/extra.py").write_text("x = 1\n")
        with self.assertRaises(ScoringError):
            load_suite(self.dir)
        (self.dir / "cases/smoke-c01/head/extra.py").unlink()
        os.symlink("/etc/passwd", self.dir / "cases/smoke-c01/head/link.py")
        with self.assertRaises(ScoringError):
            load_suite(self.dir)

    def test_symlinked_case_directory_refused(self):
        shutil.move(self.dir / "cases/smoke-c02", self.dir / "elsewhere")
        os.symlink(self.dir / "elsewhere", self.dir / "cases/smoke-c02")
        with self.assertRaises(ScoringError):
            load_suite(self.dir)

    def test_snapshot_root_must_not_live_under_labels(self):
        self.edit("cases/smoke-c01/input.json", lambda d: d["head"].__setitem__("root", "labels/x"))
        with self.assertRaises(ScoringError):
            load_suite(self.dir)

    def test_case_input_id_and_labels_case_id_must_match(self):
        self.edit("cases/smoke-c01/input.json", lambda d: d.__setitem__("id", "smoke-c02"))
        with self.assertRaises(ScoringError):
            load_suite(self.dir)

    def test_suite_digest_covers_inputs_and_labels(self):
        base = load_suite(self.dir).digest
        self.edit("labels/smoke-c01.json", lambda d: d["bugs"][0].__setitem__("severity", "P1"))
        changed_labels = load_suite(self.dir).digest
        self.assertNotEqual(base, changed_labels)
        self.edit("cases/smoke-c02/input.json", lambda d: d["pr"].__setitem__("body", "other"))
        self.assertNotEqual(changed_labels, load_suite(self.dir).digest)


class LabelIsolation(Tmp):
    def test_clean_suite_has_no_leaks(self):
        self.assertEqual(check_isolation(load_suite(self.dir)), [])

    def test_case_input_contract_rejects_label_fields(self):
        doc = json.loads((self.dir / "cases/smoke-c01/input.json").read_text())
        for k in ("labels", "expect", "bugs", "fixCommit", "fixCommits", "expectedIssues"):
            bad = copy.deepcopy(doc)
            bad[k] = "x"
            self.assertTrue(validate("CaseInput", bad), k)
            bad = copy.deepcopy(doc)
            bad["pr"][k] = "x"
            self.assertTrue(validate("CaseInput", bad), k)

    def test_bug_id_in_pr_text_snapshot_or_script_is_flagged(self):
        bug = json.loads((self.dir / "labels/smoke-c01.json").read_text())["bugs"][0]["id"]
        self.edit("cases/smoke-c01/input.json", lambda d: d["pr"].__setitem__("body", f"see {bug}"))
        self.assertTrue(any("input.json" in p for p in check_isolation(load_suite(self.dir))))
        self.edit("cases/smoke-c01/input.json", lambda d: d["pr"].__setitem__("body", "ok"))
        # a snapshot edit changes its pinned id, so repin by regenerating input ids
        f = self.dir / "cases/smoke-c03/head/src/service.py"
        f.write_text(f.read_text() + f"# {bug}\n")
        with self.assertRaises(ScoringError):           # pinned snapshot no longer matches
            load_suite(self.dir)
        shutil.copytree(SMOKE, self.dir.parent / "again")
        sp = self.dir.parent / "again/scripts/smoke-c01.json"
        sp.write_text(sp.read_text().replace('"notes"', f'"notes{bug}"'))
        flagged = check_isolation(load_suite(self.dir.parent / "again"))
        self.assertTrue(any("scripts/smoke-c01.json" in p for p in flagged))

    def test_expected_reason_is_not_in_inputs(self):
        s = smoke_suite()
        for cid in ("smoke-c05", "smoke-c06"):
            reason = s.cases[cid].labels["expectReason"]
            text = (SMOKE / f"cases/{cid}/input.json").read_text()
            self.assertNotIn(reason, text)

    def test_labels_never_read_for_a_real_suite(self):
        real = self.dir.parent / "real"
        shutil.copytree(SMOKE, real)
        man = json.loads((real / "suite.json").read_text())
        man.update(id="pilot-real-prs", synthetic=False, matching={"rule": "unadjudicated@1"})
        (real / "suite.json").write_text(json.dumps(man))
        for p in (real / "cases").glob("*/input.json"):
            d = json.loads(p.read_text())
            d["synthetic"] = False
            p.write_text(json.dumps(d))
        shutil.rmtree(real / "labels")
        (real / "labels").mkdir()
        (real / "labels/smoke-c01.json").write_text("{not json: garbage labels must never be parsed")
        suite = load_suite(real)
        self.assertTrue(all(c.labels is None for c in suite.cases.values()))
        self.assertEqual(check_isolation(suite), [])


if __name__ == "__main__":
    unittest.main()
