import json
import os
import shutil
from pathlib import Path

from reviewer.contracts.canonical import canonical_json
from reviewer.repoimport import (RepoImportError, capture_import_pins, import_repository, load_import_pins, open_import,
                                 verify_import, write_import_pins)
from reviewer.repoimport.fsio import force_remove

from .helpers import Tmp

AT = "2026-10-25T22:00:00Z"
FILES = {"a.txt": "alpha\nbeta\n", "d/b.py": ("x", "print(1)\n"), "bin": b"\x00\x01"}


class Tamper(Tmp):
    def setUp(self):
        super().setUp()
        w, self.sha = self.fixture(FILES, links={"l": "a.txt"})
        self.imp = import_repository(self.remote(w), self.sha, self.store)
        self.pins = capture_import_pins(self.imp.dir, captured_at=AT)

    def copy(self, name="cp"):
        dst = self.tmp / name
        shutil.copytree(self.imp.dir, dst, symlinks=True)
        for dp, dn, fn in os.walk(dst):
            os.chmod(dp, 0o755)
            for f in fn:
                fp = os.path.join(dp, f)
                if not os.path.islink(fp):
                    os.chmod(fp, os.stat(fp).st_mode | 0o200)
        return dst

    def rewrite(self, d, name, fn):
        p = d / name
        doc = json.loads(p.read_bytes())
        fn(doc)
        p.write_bytes(canonical_json(doc))

    def test_pristine_import_verifies_and_opens_with_pins(self):
        self.assertEqual(verify_import(self.imp.dir), [])
        self.assertEqual(verify_import(self.imp.dir, pins=self.pins), [])
        o = open_import(self.imp.dir, pins=self.pins)
        self.assertEqual((o.snapshot_id, o.manifest), (self.imp.snapshot_id, self.imp.manifest))

    def test_each_tamper_is_detected(self):
        def tree_edit(d):
            (d / "tree/a.txt").write_bytes(b"ALPHA\nbeta\n")

        def tree_link(d):
            os.remove(d / "tree/a.txt")
            os.symlink("d/b.py", d / "tree/a.txt")

        def tree_extra(d):
            (d / "tree/new.txt").write_text("x\n")

        def tree_delete(d):
            os.remove(d / "tree/d/b.py")

        cases = {
            "tree-edit": tree_edit, "tree-symlink-swap": tree_link, "tree-extra": tree_extra, "tree-delete": tree_delete,
            "extra-file": lambda d: (d / "stray").write_text("x"),
            "missing-file": lambda d: os.remove(d / "line-anchors.json"),
            "commit-object": lambda d: (d / "commit-object").write_bytes((d / "commit-object").read_bytes() + b"x"),
            "manifest-hash": lambda d: self.rewrite(d, "manifest.json", lambda m: m["entries"][0].update(sha256="0" * 64)),
            "manifest-commit": lambda d: self.rewrite(d, "manifest.json", lambda m: m.update(gitCommit="1" * 40)),
            "git-oid": lambda d: self.rewrite(d, "git-entries.json", lambda g: g[0].__setitem__(1, "2" * 40)),
            "git-dropped": lambda d: self.rewrite(d, "git-entries.json", lambda g: g.pop()),
            "anchors": lambda d: self.rewrite(d, "line-anchors.json", lambda a: a.update({"a.txt": 99})),
            "record-counts": lambda d: self.rewrite(d, "import-record.json", lambda r: r["counts"].update(included=99)),
            "record-omissions": lambda d: self.rewrite(d, "import-record.json", lambda r: r["omissions"]["items"].clear()),
            "record-coverage": lambda d: self.rewrite(d, "import-record.json", lambda r: r["coverage"].update(fullRepositoryCoverage=True, scope="full-repository")),
            "record-redaction": lambda d: self.rewrite(d, "import-record.json", lambda r: r["redaction"].update(filesScanned=0)),
            "record-tree": lambda d: self.rewrite(d, "import-record.json", lambda r: r.update(treeOid="3" * 40)),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                d = self.copy("t-" + name)
                mutate(d)
                self.assertTrue(verify_import(d), name)
                with self.assertRaises(RepoImportError) as c:
                    open_import(d, pins=self.pins)
                self.assertEqual(c.exception.code, "tamper")

    def test_pins_catch_what_internal_consistency_cannot(self):
        d = self.copy("p")
        self.rewrite(d, "import-record.json", lambda r: r["tooling"].update(git="evil 9.9"))
        self.assertEqual(verify_import(d), [])                                  # still self-consistent
        probs = verify_import(d, pins=self.pins)
        self.assertTrue(any("import-record.json differs from the pinned digest" in p for p in probs))
        with self.assertRaises(RepoImportError):
            open_import(d, pins=self.pins)
        with self.assertRaises(RepoImportError):
            open_import(d, pins=None)

    def test_pins_for_another_commit_are_refused(self):
        w2, sha2 = self.fixture({"z": "z\n"}, name="src2")
        other = import_repository(self.remote(w2), sha2, self.store)
        self.assertTrue(verify_import(other.dir, pins=self.pins))

    def test_capture_refuses_a_tampered_import(self):
        d = self.copy("c")
        (d / "tree/a.txt").write_bytes(b"ALPHA\nbeta\n")
        with self.assertRaises(RepoImportError) as c:
            capture_import_pins(d, captured_at=AT)
        self.assertEqual(c.exception.code, "tamper")

    def test_pin_store_conventions(self):
        out = self.tmp / "pins.json"
        write_import_pins(out, self.pins)
        self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o444")
        with self.assertRaises(RepoImportError):
            write_import_pins(out, self.pins)                                    # exclusive create
        self.assertEqual(load_import_pins(out, import_dir=self.imp.dir), self.pins)
        inside = self.copy("in")
        shutil.copy(out, inside / "pins.json")
        with self.assertRaises(RepoImportError) as c:
            load_import_pins(inside / "pins.json", import_dir=inside)
        self.assertEqual(c.exception.code, "bad-pins")
        for bad in ({}, dict(self.pins, extra=1), dict(self.pins, commitSha="x"), dict(self.pins, capturedAt="now"),
                    dict(self.pins, files={})):
            with self.subTest(bad=bad), self.assertRaises(RepoImportError):
                write_import_pins(self.tmp / "never.json", bad)
        self.assertFalse((self.tmp / "never.json").exists())
        with self.assertRaises(RepoImportError):
            capture_import_pins(self.imp.dir, captured_at="yesterday")

    def test_open_import_never_writes_pins(self):
        before = sorted(os.listdir(self.tmp))
        open_import(self.imp.dir, pins=self.pins)
        self.assertEqual(sorted(os.listdir(self.tmp)), before)
