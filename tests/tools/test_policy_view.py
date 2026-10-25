import json
import os
import shutil
import unittest
from pathlib import Path

from reviewer.contracts import validate
from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import (Limits, ToolSession, View, ViewError, capture_historical_pins, full_view,
                            historical_input_view, make_layer)
from reviewer.tools import policy
from .helpers import ROOT, TOKEN, Env, make_case, write_tree


class Policy(unittest.TestCase):
    def test_vcs_internals_are_denied_at_any_depth_and_case(self):
        for p in (".git/config", "a/.git/HEAD", ".GIT/x", "vendor/.hg/store", ".svn/entries"):
            self.assertTrue(policy.denied_path(p), p)
            self.assertFalse(policy.permitted(p))

    def test_ordinary_repo_folders_named_source_labels_and_env_examples_are_readable(self):
        for p in ("source/main.py", "labels/en.json", "src/labels/x.ts", ".env.example", "config/credentials.yaml",
                  "deploy/.aws/config.template", "keys/server.pem", ".github/workflows/ci.yml"):
            self.assertTrue(policy.permitted(p), p)

    def test_unsafe_names_are_not_valid(self):
        bad = ["", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a/./b", "a\\b", "a\x00b", "a\nb",
               "http://example.com/x", "file:///etc/passwd", "x" * 600, "~/.ssh/id_rsa" + "/../..",
               f"src/{TOKEN}.py", None, 3, ["a"]]
        for p in bad:
            with self.subTest(p=p):
                self.assertFalse(policy.valid_path(p))


class Layers(Env):
    def test_view_copies_the_manifest(self):
        m = build_manifest(self.base)
        layer = make_layer("base", "full", self.base, m)
        m["entries"].clear()
        m["snapshotId"] = "snap:sha256:" + "0" * 64
        self.assertTrue(layer.entry("src/app.py"))
        self.assertNotEqual(layer.snapshot_id, m["snapshotId"])

    def test_invalid_manifest_is_refused(self):
        m = build_manifest(self.base)
        m["entries"][0]["sha256"] = "0" * 64              # id no longer matches the entries
        with self.assertRaises(Exception):
            make_layer("base", "full", self.base, m)

    def test_same_path_in_two_layers_of_one_side_is_refused(self):
        a = make_layer("a", "changed", self.base, build_manifest(self.base))
        b = make_layer("b", "context", self.base, build_manifest(self.base))
        with self.assertRaises(ViewError):
            View([a, b], [make_layer("h", "full", self.head, build_manifest(self.head))])

    def test_full_view_is_not_partial_and_partial_views_say_so(self):
        self.assertFalse(self.view.partial)
        self.assertTrue(self.view.coverage()["fullRepositoryCoverage"])
        part = View([make_layer("b", "changed", self.base, build_manifest(self.base))],
                    [make_layer("h", "changed", self.head, build_manifest(self.head))])
        self.assertTrue(part.partial)
        self.assertFalse(part.coverage()["fullRepositoryCoverage"])
        self.assertEqual(part.coverage()["scope"], "changed-files-and-selected-context")


class Historical(Env):
    """A corpus-valid case dir (make_case): input/{base,head,context} readable, source/ and labels/ beside it.
    Pins are captured while the case is still known-good, BEFORE any test mutation."""

    def setUp(self):
        super().setUp()
        self.case = make_case(self.tmp, {"src/a.py": "a = 1\n"}, {"src/a.py": "a = 2\nb = 3\n", "src/new.py": "n = 1\n"},
                              context={"head": {"src/util.py": "def u(): pass\n"}})
        self.pins = capture_historical_pins(self.case)
        self.hv = historical_input_view(self.case, pins=self.pins)

    def test_view_is_partial_with_changed_and_context_layers(self):
        self.assertTrue(self.hv.partial)
        self.assertEqual([l.kind for l in self.hv.layers("head")], ["changed", "context"])

    def test_eval_metadata_is_unreachable_by_containment(self):
        s = ToolSession(self.hv)
        for tool, args in (("read_file", {"side": "head", "path": "source/collection.json"}),
                           ("read_file", {"side": "head", "path": "../source/collection.json"}),
                           ("read_file", {"side": "head", "path": "../../labels/expected.json"}),
                           ("search_literal", {"side": "head", "query": "mergedAt"}),
                           ("search_literal", {"side": "base", "query": "mergedAt"})):
            with self.subTest(args=args):
                c = s.call(tool, args)
                self.assertNotIn("2026", json.dumps(c.result))
                self.assertIn(c.result["status"], ("denied", "unavailable", "empty"))
        listing = " ".join(e["excerpt"] for e in s.call("list_files", {"side": "head"}).result["evidence"])
        self.assertNotIn("collection", listing)
        self.assertNotIn("labels", listing)

    def test_missing_context_is_explicit_and_never_pretends_to_be_a_full_repo(self):
        s = ToolSession(self.hv)
        c = s.call("read_file", {"side": "head", "path": "src/other.py"})
        self.assertEqual(c.result["status"], "unavailable")
        self.assertIn("Partial view", c.result["notice"])
        self.assertIn("PREPARE", c.result["notice"])
        lst = s.call("list_files", {"side": "head"}).result
        self.assertEqual(lst["completeness"], "approximate")
        self.assertIn("Partial view", lst["notice"])
        self.assertIn("partial view", lst["evidence"][0]["excerpt"])
        self.assertEqual(s.call("read_file", {"side": "head", "path": "src/util.py"}).result["status"], "ok")

    def test_requires_input_dir_and_honest_case_json(self):
        with self.assertRaises(ViewError):      # no trusted pins: fail closed
            historical_input_view(self.case)
        shutil.rmtree(self.case / "input/head")
        with self.assertRaises(ViewError):
            historical_input_view(self.case, pins=self.pins)
        c2 = make_case(self.tmp, {"a": "x\n"}, {"a": "y\n"}, name="o--r--2")
        pins2 = capture_historical_pins(c2)
        doc = json.loads((c2 / "input/case.json").read_text())
        doc["coverage"]["fullRepositoryCoverage"] = True
        (c2 / "input/case.json").write_text(json.dumps(doc))
        with self.assertRaises(ViewError):
            historical_input_view(c2, pins=pins2)

    def test_symlinked_input_dir_refused(self):
        shutil.move(self.case / "input", self.tmp / "moved-input")
        os.symlink(self.tmp / "moved-input", self.case / "input")
        with self.assertRaises(ViewError):
            historical_input_view(self.case, pins=self.pins)

    @unittest.skipUnless((ROOT / "fixtures/historical/Vencord--Vesktop--1347/input/case.json").exists(), "no fixture")
    def test_real_corpus_fixture_view(self):
        fx = ROOT / "fixtures/historical/Vencord--Vesktop--1347"
        v = historical_input_view(fx, pins=capture_historical_pins(fx))     # pins captured from the checked-in fixture
        s = ToolSession(v)
        files = s.call("list_files", {"side": "head"}).result["evidence"][0]["excerpt"]
        self.assertIn("src/main/mainWindow.ts", files)
        c = s.call("read_file", {"side": "head", "path": "src/main/mainWindow.ts", "start_line": 1, "end_line": 5})
        self.assertEqual(c.result["status"], "ok")
        self.assertTrue(all(e["resolved"] for e in c.result["evidence"]))
        self.assertEqual(validate("ToolResult", c.result), [])
        self.assertEqual(s.call("read_file", {"side": "head", "path": "source/collection.json"}).result["status"], "unavailable")
