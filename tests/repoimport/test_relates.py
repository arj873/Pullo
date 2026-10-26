import hashlib
import json
import os
from pathlib import Path

from reviewer.repoimport import RelatesSpec, RepoImportError, import_repository, pin_from_case, verify_import
from reviewer.repoimport.cli import main

from .helpers import Tmp, git

REAL = Path(__file__).resolve().parents[2] / "fixtures/historical/boykopovar--AnyPS5--10815"


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Relates(Tmp):
    def case(self, base_sha, head_sha, *, merge_base=None, files=None, name="o--r--7"):
        d = self.tmp / "case" / name
        (d / "input").mkdir(parents=True)
        base_ref = merge_base or base_sha
        (d / "input/case.json").write_text(json.dumps({
            "schema": "historical-case-input@1", "id": name, "repo": "fix/repo",
            "base": {"sha": base_sha, "mergeBase": merge_base, "textRef": base_ref}, "head": {"sha": head_sha},
            "files": files or []}))
        return d

    def put_blob(self, d, rel, data):
        p = d / "input" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def pair(self):
        w, base = self.fixture({"a.txt": "one\n", "gone.txt": "bye\n", "keep.txt": "k\n"}, name="two")
        (w / "a.txt").write_text("two\n")
        (w / "new.txt").write_text("new\n")
        os.remove(w / "gone.txt")
        git(w, "add", "-A")
        git(w, "commit", "-q", "-m", "2")
        return w, base, git(w, "rev-parse", "HEAD")

    def files(self, d):
        def blob(side, rel, data):
            self.put_blob(d, f"{side}/{rel}", data)
            return {"file": f"{side}/{rel}", "rawSha256": sha(data), "sha256": sha(data), "rawBytes": len(data),
                    "bytes": len(data), "redactions": {}}
        return [
            {"path": "a.txt", "previousPath": None, "status": "modified", "gaps": [],
             "base": blob("base", "a.txt", b"one\n"), "head": blob("head", "a.txt", b"two\n")},
            {"path": "new.txt", "previousPath": None, "status": "added", "gaps": [], "base": None, "head": blob("head", "new.txt", b"new\n")},
            {"path": "gone.txt", "previousPath": None, "status": "removed", "gaps": [], "base": blob("base", "gone.txt", b"bye\n"), "head": None},
        ]

    def test_both_sides_pass_with_exact_textref_and_report_counts(self):
        w, b, h = self.pair()
        d = self.case(b, h)
        d.joinpath("input/case.json").write_text(json.dumps({**json.loads(d.joinpath("input/case.json").read_text()), "files": self.files(d)}))
        ih = import_repository(self.remote(w), h, self.store, relates=RelatesSpec(d, "head", "snap:sha256:" + "a" * 64))
        ib = import_repository(self.remote(w), b, self.store, relates=RelatesSpec(d, "base"))
        for imp, n in ((ih, 3), (ib, 3)):
            r = imp.record["relatesTo"]
            self.assertEqual((r["changedPathsChecked"], r["changedPathsByteEqual"], r["unchecked"]), (n, True, []))
        self.assertIs(ih.record["relatesTo"]["idEqualsPartial"], False)
        self.assertIsNone(ib.record["relatesTo"]["idEqualsPartial"])
        self.assertNotEqual(ih.snapshot_id, "snap:sha256:" + "a" * 64)
        self.assertEqual(verify_import(ih.dir), [])

    def test_mismatches_refuse_and_leave_nothing(self):
        w, b, h = self.pair()
        d = self.case(b, h)
        base_doc = json.loads(d.joinpath("input/case.json").read_text())
        fs = self.files(d)
        mutations = {
            "bytes": lambda f: f[0]["head"].update(rawSha256=sha(b"other\n")),
            "partial-blob-changed": lambda f: self.put_blob(d, "head/a.txt", b"tampered\n"),
            "absent-expected": lambda f: f[1].update(status="added", head=None) or f[1].update(status="removed"),
        }
        for name, m in mutations.items():
            with self.subTest(name):
                case = json.loads(json.dumps(base_doc))
                case["files"] = json.loads(json.dumps(self.files(d)))
                m(case["files"])
                d.joinpath("input/case.json").write_text(json.dumps(case))
                with self.assertRaises(RepoImportError) as c:
                    import_repository(self.remote(w), h, self.store, relates=RelatesSpec(d, "head"))
                self.assertEqual(c.exception.code, "relates-mismatch")
                self.put_blob(d, "head/a.txt", b"two\n")
        self.assertFalse((self.store / "fix--repo" / h).exists())

    def test_wrong_commit_for_side_is_refused_and_textref_is_used_for_base(self):
        w, b, h = self.pair()
        d = self.case(b, h, files=[])
        for commit, side in ((b, "head"), (h, "base")):
            with self.subTest(side), self.assertRaises(RepoImportError) as c:
                import_repository(self.remote(w), commit, self.store, relates=RelatesSpec(d, side))
            self.assertEqual(c.exception.code, "relates-mismatch")
        # advanced baseSha (other) with an older merge base: base commit must be the merge base / textRef
        d2 = self.case(h, h, merge_base=b, files=[], name="o--r--8")
        self.assertEqual(pin_from_case(d2)["baseTextRef"], b)
        imp = import_repository(self.remote(w), b, self.store, relates=RelatesSpec(d2, "base"))
        self.assertEqual(imp.record["relatesTo"]["commitSha"], b)
        with self.assertRaises(RepoImportError):
            import_repository(self.remote(w), h, self.tmp / "s2", relates=RelatesSpec(d2, "base"))

    def test_bad_case_inputs(self):
        w, b, h = self.pair()
        for spec in (RelatesSpec(self.tmp / "nope", "head"), RelatesSpec(self.case(b, h), "middle"),
                     RelatesSpec(self.case(b, h, name="o--r--9"), "head", "snap:bad")):
            with self.subTest(spec=spec), self.assertRaises(RepoImportError):
                import_repository(self.remote(w), h, self.store, relates=spec)

    @staticmethod
    def _skip():
        return not (REAL / "input/case.json").exists()

    def test_actual_a1_case_metadata(self):
        if self._skip():
            self.skipTest("local historical A1 case not present")
        pin = pin_from_case(REAL)
        self.assertEqual(pin["repo"], "boykopovar/AnyPS5")
        self.assertEqual(pin["headSha"], "c5798f8e7a02296ca0ca6481ceae0f3b0cb638f3")
        self.assertEqual(pin["baseTextRef"], "2742004ed28f765c7147db0e0269ff5868e9eb6f")
        self.assertEqual(pin["baseTextRef"], pin["mergeBase"] or pin["baseSha"])
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["pin-from-case", "--case-dir", str(REAL)]), 0)
