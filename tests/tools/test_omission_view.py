"""S1-03-review F1: a full view over an import WITH omissions must not claim full-repository coverage anywhere."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import ToolSession, ViewError, full_view, import_view, omissions_from_records


def rec(counts):
    return {"omissions": {"counts": counts}}


class OmissionView(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        d = Path(self._t.name)
        for side in ("base", "head"):
            (d / side).mkdir()
            (d / side / "a.py").write_text("x = 1\ny = 2\n")
        self.m = {s: build_manifest(d / s) for s in ("base", "head")}
        self.d = d

    def view(self, om=None):
        return import_view(self.d / "base", self.m["base"], self.d / "head", self.m["head"], om or {})

    def calls(self, view):
        s = ToolSession(view)
        return [s.call("list_files", {"side": "head"}), s.call("read_file", {"side": "head", "path": "bin.dat"}),
                s.call("search_literal", {"side": "head", "query": "zzz"}), s.call("diff", {"path": "bin.dat"}),
                s.call("read_file", {"side": "head", "path": "a.py"})]

    def test_zero_omissions_is_unchanged(self):
        v = self.view(omissions_from_records(rec({"binary": 0}), rec({})))
        self.assertEqual((v.coverage()["scope"], v.coverage()["fullRepositoryCoverage"], v.note()), ("full-repository", True, ""))
        self.assertEqual(v.coverage(), full_view(self.d / "base", self.m["base"], self.d / "head", self.m["head"]).coverage())
        self.assertEqual(self.calls(v)[0].result["completeness"], "exact")

    def test_omissions_end_the_full_repository_claim_everywhere(self):
        v = self.view(omissions_from_records(rec({"binary": 2, "lfs": 0}), rec({"oversize": 1})))
        cov = v.coverage()
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"]), ("repository-with-omissions", False))
        self.assertEqual(cov["omissions"], {"base": {"binary": 2}, "head": {"oversize": 1}})
        lst, missing, search, dif, ok = self.calls(v)
        for call in (lst, missing, search, dif, ok):
            self.assertEqual(call.provenance["coverage"]["scope"], "repository-with-omissions")
            self.assertFalse(call.provenance["coverage"]["fullRepositoryCoverage"])
            self.assertIn("may exist in the repository", call.result["notice"])
        for call in (lst, missing, search, dif):
            self.assertEqual(call.result["completeness"], "approximate")
        self.assertEqual(ok.result["status"], "ok")           # the file that exists is still read exactly

    def test_malformed_records_and_counts_are_refused(self):
        with self.assertRaises(ViewError):
            omissions_from_records({}, rec({}))
        with self.assertRaises(ViewError):
            omissions_from_records(rec({"binary": -1}), rec({}))
        with self.assertRaises(ViewError):
            self.view({"base": {"binary": True}})


if __name__ == "__main__":
    unittest.main()
