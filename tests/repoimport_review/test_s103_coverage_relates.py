"""S1-03 independent review: coverage_of(record) versus tools.full_view's `full` flag, and the relatesTo head/base.textRef
binding (synthetic cases we own, plus the REAL A1 case.json and its recorded input blobs read-only; no `source/` or `labels/`).

Run: nice -n 19 python3 -W error::ResourceWarning -m unittest discover -s tests/repoimport_review -v
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _support import ROOT, Base, g  # noqa: E402

from reviewer.contracts.snapshot import snapshot_id  # noqa: E402
from reviewer.repoimport import (ImportPolicy, RelatesSpec, RepoImportError, capture_import_pins, coverage_of, full_view_of,  # noqa: E402
                                 import_repository, open_import, pin_from_case, verify_import)
from reviewer.repoimport.relates import check_relates  # noqa: E402
from reviewer.tools import ToolSession  # noqa: E402

A1 = ROOT / "fixtures/historical/boykopovar--AnyPS5--10815"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Coverage(Base):
    def pair(self):
        def sub(w):
            g(w, "update-index", "--add", "--cacheinfo", "160000,%s,vendor/m" % ("c" * 40))
        base = {"ok.txt": "fine\n", "bin.dat": b"\x00\x01", "big.txt": "x" * 3000}
        head = {"ok.txt": "fine\nchanged\n", "bin.dat": b"\x00\x02", "big.txt": "y" * 3000}
        wb, (sb,) = self.repo([(base, {}, sub)], name="b")
        wh, (sh,) = self.repo([(head, {}, sub)], name="h")
        pol = ImportPolicy(max_file_bytes=2000)
        return (import_repository(self.remote(wb), sb, self.store, policy=pol),
                import_repository(self.remote(wh), sh, self.tmp / "store2", policy=pol))

    def test_CONTROL_coverage_of_names_every_omission_and_survives_open_import(self):
        b, h = self.pair()
        cov = coverage_of(h.record)
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"], cov["omittedTotal"]), ("repository-with-omissions", False, 3))
        self.assertEqual(cov["omissionCounts"], {"submodule": 1, "binary": 1, "oversize": 1})
        self.assertIn("may exist", cov["note"])
        pins = capture_import_pins(h.dir, captured_at="2026-10-25T12:00:00Z")
        self.assertEqual(open_import(h.dir, pins=pins).coverage, h.coverage)
        self.assertEqual(h.coverage, cov)

    def test_LIMIT_full_view_still_claims_full_repository_coverage_for_an_import_with_omissions(self):
        """The trap the author documents, reproduced end to end. S1-05 MUST take coverage from coverage_of(record); the
        View, the ToolSession provenance and the 'absent' notices say nothing about omissions."""
        b, h = self.pair()
        v = full_view_of(b, h)
        vc = v.coverage()
        self.assertEqual((vc["scope"], vc["fullRepositoryCoverage"]), ("full-repository", True))     # contradicts coverage_of
        self.assertFalse(coverage_of(h.record)["fullRepositoryCoverage"])
        s = ToolSession(v)
        listing = s.call("list_files", {"side": "head"})
        self.assertEqual(listing.result["completeness"], "exact")                                    # omitted paths are not listed
        self.assertNotIn("bin.dat", listing.result["evidence"][0]["excerpt"])
        self.assertTrue(listing.provenance["coverage"]["fullRepositoryCoverage"])                    # recorded in every tool call
        for omitted in ("bin.dat", "big.txt", "vendor/m"):
            c = s.call("read_file", {"side": "head", "path": omitted})
            self.assertEqual(c.result["status"], "unavailable")
            self.assertIn("is not in the head snapshot view", c.result["notice"])
            self.assertNotIn("omit", c.result["notice"].lower())                                     # no 'it may exist' caveat
        self.assertEqual(s.view.note(), "")

    def test_CONTROL_record_cannot_claim_full_coverage_without_verify_noticing(self):
        b, h = self.pair()
        d = self.writable_copy(h.dir, "forged")
        rc = json.loads((d / "import-record.json").read_bytes())
        rc["coverage"] = {"scope": "full-repository", "fullRepositoryCoverage": True}
        from reviewer.contracts.canonical import canonical_json
        (d / "import-record.json").write_bytes(canonical_json(rc))
        self.assertTrue(any("coverage statement" in p for p in verify_import(d)))
        pins = capture_import_pins(h.dir, captured_at="2026-10-25T12:00:00Z")
        with self.assertRaises(RepoImportError):
            open_import(d, pins=pins)


class SyntheticCase(Base):
    """A case directory we own, shaped like the real input/case.json."""

    def case(self, head, base, files, *, base_sha=None, merge_base=None, repo="fix/repo", blobs=True):
        c = self.tmp / "case"
        (c / "input/base").mkdir(parents=True, exist_ok=True)
        (c / "input/head").mkdir(parents=True, exist_ok=True)
        for d in ("source", "labels"):
            (c / d).mkdir(exist_ok=True)
            os.chmod(c / d, 0o700)                              # case() may be called twice in one test
            (c / d / "canary.json").write_text('{"canary": true}')
            os.chmod(c / d, 0o000)
            self.addCleanup(os.chmod, c / d, 0o700)
        bt = merge_base or base
        doc = {"schema": "case@1", "id": "synthetic--1", "repo": repo, "importer": {}, "redaction": {}, "gaps": [], "coverage": {},
               "base": {"sha": base_sha or base, "mergeBase": merge_base, "textRef": bt}, "head": {"sha": head}, "files": files}
        (c / "input/case.json").write_text(json.dumps(doc))
        return c

    def blobref(self, side, path, data: bytes):
        (self.tmp / "case/input" / side / path).parent.mkdir(parents=True, exist_ok=True)
        (self.tmp / "case/input" / side / path).write_bytes(data)
        return {"file": f"{side}/{path}", "rawSha256": sha256(data), "redactions": {}}

    def make(self):
        """base c1 (textRef) and a LATER branch commit b2 (advanced baseSha), head h."""
        w, (c1, c2) = self.repo([{"keep.txt": "k\n", "mod.txt": "old\n", "gone.txt": "g\n"},
                                 {"keep.txt": "k\n", "mod.txt": "old\n", "gone.txt": "g\n", "later.txt": "l\n"}], name="up")
        wh, (h,) = self.repo([{"keep.txt": "k\n", "mod.txt": "new\n", "added.txt": "a\n"}], name="uphead")
        return w, c1, c2, wh, h

    def files(self, mod_old=b"old\n", mod_new=b"new\n"):
        (self.tmp / "case").mkdir(exist_ok=True)
        (self.tmp / "case/input/base").mkdir(parents=True, exist_ok=True)
        (self.tmp / "case/input/head").mkdir(parents=True, exist_ok=True)
        return [
            {"path": "mod.txt", "previousPath": None, "status": "modified", "gaps": [],
             "base": self.blobref("base", "mod.txt", mod_old), "head": self.blobref("head", "mod.txt", mod_new)},
            {"path": "added.txt", "previousPath": None, "status": "added", "gaps": [], "base": None,
             "head": self.blobref("head", "added.txt", b"a\n")},
            {"path": "gone.txt", "previousPath": None, "status": "removed", "gaps": [],
             "base": self.blobref("base", "gone.txt", b"g\n"), "head": None},
        ]

    def test_CONTROL_head_is_the_case_head_and_base_is_textRef_never_the_advanced_baseSha(self):
        w, c1, c2, wh, h = self.make()
        case = self.case(h, c1, self.files(), base_sha=c2, merge_base=c1)              # baseSha moved on; textRef = mergeBase
        self.assertEqual(pin_from_case(case)["baseTextRef"], c1)
        imp_h = import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        self.assertEqual(imp_h.record["relatesTo"]["changedPathsChecked"], 3)
        self.assertTrue(imp_h.record["relatesTo"]["changedPathsByteEqual"])
        imp_b = import_repository(self.remote(w), c1, self.store, relates=RelatesSpec(case, "base"))
        self.assertEqual(imp_b.record["relatesTo"]["commitSha"], c1)
        n = len(os.listdir(self.store / "fix--repo"))
        with self.assertRaises(RepoImportError) as c:                                  # the advanced baseSha is NOT a valid base
            import_repository(self.remote(w), c2, self.store, relates=RelatesSpec(case, "base"))
        self.assertEqual(c.exception.code, "relates-mismatch")
        with self.assertRaises(RepoImportError) as c:                                  # head commit on the base side, and vice versa
            import_repository(self.remote(wh), h, self.tmp / "s3", relates=RelatesSpec(case, "base"))
        self.assertEqual(c.exception.code, "relates-mismatch")
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), c1, self.tmp / "s4", relates=RelatesSpec(case, "head"))
        self.assertEqual(c.exception.code, "relates-mismatch")
        self.assertEqual(len(os.listdir(self.store / "fix--repo")), n)

    def test_CONTROL_import_never_touches_source_or_labels(self):
        w, c1, c2, wh, h = self.make()
        case = self.case(h, c1, self.files())
        seen, active = [], [True]

        def hook(event, args):                                  # audit events fire for os.open and builtins.open alike
            if active[0] and event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
                seen.append(os.fsdecode(args[0]))
        sys.addaudithook(hook)
        try:
            import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        finally:
            active[0] = False
        mine = [p for p in seen if str(case) in p]
        self.assertTrue(mine)
        self.assertFalse([p for p in mine if "/source" in p or "/labels" in p], mine)
        self.assertTrue(all(p.startswith(str(case / "input")) for p in mine), mine)

    def test_CONTROL_every_mismatch_class_refuses_and_leaves_nothing(self):
        w, c1, c2, wh, h = self.make()
        cases = {
            "head bytes differ from the recorded raw hash": self.files(mod_new=b"NEW\n"),
            "partial blob changed on disk after recording": None,
        }
        case = self.case(h, c1, cases["head bytes differ from the recorded raw hash"])
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        self.assertIn("bytes-differ", str(c.exception))
        case = self.case(h, c1, self.files())
        (case / "input/head/mod.txt").write_bytes(b"tampered\n")                      # disk blob no longer matches rawSha256
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        self.assertIn("partial-input-changed", str(c.exception))
        case = self.case(h, c1, self.files(), repo="Other/Repo")
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        self.assertIn("repository differs", str(c.exception))
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])

    def test_LIMIT_a_changed_path_the_importer_omits_refuses_the_whole_import(self):
        """Fail-closed characterization: a changed file that the full import omits (here a case-fold collision) cannot be
        proven byte-equal, so the import is refused rather than published with an unchecked changed path."""
        wh, (h,) = self.repo([{"A.txt": "upper\n", "a.txt": "lower\n", "ok.txt": "k\n"}], name="coll")
        files = [{"path": "a.txt", "previousPath": None, "status": "modified", "gaps": [], "base": None,
                  "head": None}]
        (self.tmp / "case/input/head").mkdir(parents=True, exist_ok=True)
        files[0]["head"] = self.blobref("head", "a.txt", b"lower\n")
        files[0]["base"] = self.blobref("base", "a.txt", b"old\n")
        case = self.case(h, "b" * 40, files)
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        self.assertEqual(c.exception.code, "relates-mismatch")
        self.assertIn("missing-in-import", str(c.exception))
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])

    def test_CONTROL_unchecked_changed_paths_are_reported_not_silently_counted_as_equal(self):
        w, c1, c2, wh, h = self.make()
        files = self.files()
        files.append({"path": "weird.bin", "previousPath": None, "status": "modified", "gaps": ["binary"], "base": None, "head": None})
        files.append({"path": "noblob.txt", "previousPath": None, "status": "modified", "gaps": [], "base": None, "head": None})
        case = self.case(h, c1, files)
        imp = import_repository(self.remote(wh), h, self.store, relates=RelatesSpec(case, "head"))
        rel = imp.record["relatesTo"]
        self.assertEqual(rel["changedPathsChecked"], 3)
        self.assertEqual(sorted((u["path"], u["reason"]) for u in rel["unchecked"]), [("noblob.txt", "no-blob"), ("weird.bin", "recorded-gap")])
        self.assertEqual(rel["changedPathsByteEqual"], True)                           # true of the CHECKED paths only
        self.assertIsNone(rel["idEqualsPartial"])


@unittest.skipUnless((A1 / "input/case.json").is_file(), "real A1 case not present")
class RealA1CaseMetadata(Base):
    """check_relates against the REAL case.json and its recorded input blobs (read-only; never source/ or labels/)."""

    def manifest_of(self, side):
        case = json.loads((A1 / "input/case.json").read_bytes())
        entries = []
        for f in case["files"]:
            b = f.get(side)
            if b:
                data = (A1 / "input" / b["file"]).read_bytes()
                entries.append({"path": f["path"] if side == "head" else (f.get("previousPath") or f["path"]), "type": "file",
                                "size": len(data), "sha256": sha256(data)})
        entries.sort(key=lambda e: e["path"])
        return {"schema": "snapshot-manifest@1", "snapshotId": snapshot_id(entries), "entries": entries}

    def test_CONTROL_real_case_pins_and_checker_accept_the_recorded_blobs_on_the_right_side_only(self):
        pins = pin_from_case(A1)
        self.assertEqual(pins["headSha"], "c5798f8e7a02296ca0ca6481ceae0f3b0cb638f3")
        self.assertEqual(pins["baseTextRef"], "2742004ed28f765c7147db0e0269ff5868e9eb6f")
        self.assertEqual(pins["repo"], "boykopovar/AnyPS5")
        mh, mb = self.manifest_of("head"), self.manifest_of("base")
        rh = check_relates(RelatesSpec(A1, "head"), pins["headSha"], mh, "boykopovar/AnyPS5")
        rb = check_relates(RelatesSpec(A1, "base"), pins["baseTextRef"], mb, "boykopovar/AnyPS5")
        self.assertEqual((rh["changedPathsChecked"], rh["unchecked"], rh["changedPathsByteEqual"]), (2, [], True))
        self.assertEqual((rb["changedPathsChecked"], rb["unchecked"]), (2, []))
        for spec, commit, man in ((RelatesSpec(A1, "head"), pins["baseTextRef"], mh), (RelatesSpec(A1, "base"), pins["headSha"], mb),
                                  (RelatesSpec(A1, "head"), pins["headSha"], mb), (RelatesSpec(A1, "base"), pins["baseTextRef"], mh)):
            with self.assertRaises(RepoImportError) as c:
                check_relates(spec, commit, man, "boykopovar/AnyPS5")
            self.assertEqual(c.exception.code, "relates-mismatch")
        with self.assertRaises(RepoImportError):
            check_relates(RelatesSpec(A1, "head"), pins["headSha"], mh, "someone/else")
        flipped = json.loads(json.dumps(mh))
        flipped["entries"][0]["sha256"] = "0" * 64
        with self.assertRaises(RepoImportError):
            check_relates(RelatesSpec(A1, "head"), pins["headSha"], flipped, "boykopovar/AnyPS5")
        self.assertEqual(pins["baseSha"], pins["baseTextRef"])                          # equal for A1; the code still keys on textRef


if __name__ == "__main__":
    unittest.main()
