"""S0B-02c: partial union layers with per-path changed vs context semantics under ONE snapshot id per side."""

import copy
import inspect
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import (PARTIAL_NOTE, Layer, ToolSession, View, ViewError, full_view, historical_input_view,
                            make_layer, partial_union_view)

from .helpers import TOKEN, Env, write_tree

ROOT = Path(__file__).resolve().parents[2]

# changed files per side (the PR), and selected context per side
B_CHG = {"src/app.py": "import os\n\n\ndef run():\n    return 1\n", "src/gone.py": "x = 1\n", "run.sh": "echo hi\n"}
H_CHG = {"src/app.py": "import os\n\n\ndef run():\n    return 2\n", "src/new.py": "y = 2\n", "run.sh": "echo hi\n"}
B_CTX = {"lib/base_only.py": "BASE_ONLY = 1\n", "lib/both.py": "both = 'base'\n"}
H_CTX = {"lib/head_only.py": f"HEAD_ONLY = 1\nsecret = '{TOKEN}'\n", "lib/both.py": "both = 'head'\n",
         "lib/more.py": "MORE = 3\n"}
CHANGED_ROWS = ["M run.sh", "M src/app.py", "D src/gone.py", "A src/new.py"]


def _tree(root: Path, *parts: dict, exe=()):
    root.mkdir(parents=True)
    for files in parts:
        write_tree(root, files)
    for rel in exe:
        os.chmod(root / rel, 0o755)


class UnionEnv(unittest.TestCase):
    """The same bytes two ways: layered (changed + context layers) and union (one tree per side)."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        t = self.tmp = Path(self._t.name)
        _tree(t / "lb", B_CHG)
        _tree(t / "lh", H_CHG, exe=["run.sh"])
        _tree(t / "lbc", B_CTX)
        _tree(t / "lhc", H_CTX)
        _tree(t / "ub", B_CHG, B_CTX)
        _tree(t / "uh", H_CHG, H_CTX, exe=["run.sh"])
        # trusted-time manifests (captured once, before any review-time access)
        self.m = {k: build_manifest(t / k) for k in ("lb", "lh", "lbc", "lhc", "ub", "uh")}
        self.layered = View([make_layer("base-changed", "changed", t / "lb", self.m["lb"]),
                             make_layer("base-context", "context", t / "lbc", self.m["lbc"])],
                            [make_layer("head-changed", "changed", t / "lh", self.m["lh"]),
                             make_layer("head-context", "context", t / "lhc", self.m["lhc"])])
        self.union = self.make_union()

    def make_union(self, recorded=None, **over):
        spec = {"base": (self.tmp / "ub", self.m["ub"], set(B_CTX), set(B_CHG)),
                "head": (self.tmp / "uh", self.m["uh"], set(H_CTX), set(H_CHG))}
        spec.update(over)
        return partial_union_view(spec["base"], spec["head"], recorded=recorded)

    def call(self, view, tool, **args):
        s = ToolSession(view)
        r = s.call(tool, args).result
        return r, s

    def rows(self, view):
        r, _ = self.call(view, "diff")
        return r["evidence"][0]["excerpt"].split("\n")[1:], r


class HeadOnlyContext(UnionEnv):
    def test_head_only_context_is_readable_searchable_and_never_added(self):
        v = self.union
        rows, r = self.rows(v)
        self.assertEqual(rows, CHANGED_ROWS)
        self.assertNotIn("lib/", r["evidence"][0]["excerpt"])
        self.assertIn("Context files are excluded", r["notice"])
        d, _ = self.call(v, "diff", path="lib/head_only.py")
        self.assertEqual(d["status"], "unavailable")
        self.assertIn("context loaded on one side only", d["notice"])
        self.assertIn("absence on the base side is unknown", d["notice"])
        self.assertEqual(d["evidence"], [])
        rd, s = self.call(v, "read_file", side="head", path="lib/head_only.py")
        self.assertEqual(rd["status"], "ok")
        self.assertIn("from head-union [context]", rd["notice"])
        self.assertIn(PARTIAL_NOTE, rd["notice"])
        ev = rd["evidence"][0]
        self.assertEqual(ev["commit"], self.m["uh"]["snapshotId"])
        self.assertTrue(ev["resolved"])
        self.assertFalse(s.tampered)
        sr, _ = self.call(v, "search_literal", side="head", query="HEAD_ONLY")
        self.assertEqual([(e["path"], e["commit"]) for e in sr["evidence"]],
                         [("lib/head_only.py", self.m["uh"]["snapshotId"])])
        ls, _ = self.call(v, "list_files", side="head", prefix="lib")
        self.assertIn("lib/head_only.py", ls["evidence"][0]["excerpt"])
        self.assertEqual(v.path_kind("head", "lib/head_only.py"), "context")
        self.assertIsNone(v.path_kind("base", "lib/head_only.py"))

    def test_real_changed_paths_keep_their_kind_and_added_file_is_added(self):
        v = self.union
        self.assertEqual(v.changed_paths("head"), frozenset(H_CHG))
        self.assertEqual(v.changed_paths("base"), frozenset(B_CHG))
        self.assertEqual(v.context_paths("head"), frozenset(H_CTX))
        self.assertEqual(v.context_paths("base"), frozenset(B_CTX))
        d, _ = self.call(v, "diff", path="src/new.py")
        self.assertEqual(d["status"], "ok")
        self.assertIn("+y = 2", d["evidence"][0]["excerpt"])
        self.assertIn("base absent", d["evidence"][0]["excerpt"])
        rd, _ = self.call(v, "read_file", side="head", path="src/new.py")
        self.assertIn("from head-union (", rd["notice"])
        self.assertNotIn("[context]", rd["notice"])
        g, _ = self.call(v, "diff", path="src/gone.py")
        self.assertIn("-x = 1", g["evidence"][0]["excerpt"])

    def test_base_only_context_is_not_removed(self):
        rows, _ = self.rows(self.union)
        self.assertNotIn("D lib/base_only.py", rows)
        d, _ = self.call(self.union, "diff", path="lib/base_only.py")
        self.assertEqual(d["status"], "unavailable")
        self.assertIn("absence on the head side is unknown", d["notice"])
        rd, _ = self.call(self.union, "read_file", side="base", path="lib/base_only.py")
        self.assertEqual(rd["evidence"][0]["commit"], self.m["ub"]["snapshotId"])
        self.assertIn("from base-union [context]", rd["notice"])

    def test_context_on_both_sides_is_diffable_but_not_a_change(self):
        rows, _ = self.rows(self.union)
        self.assertNotIn("M lib/both.py", rows)
        d, _ = self.call(self.union, "diff", path="lib/both.py")
        self.assertEqual(d["status"], "ok")
        self.assertIn("+both = 'head'", d["evidence"][0]["excerpt"])

    def test_mode_change_of_a_changed_file(self):
        d, _ = self.call(self.union, "diff", path="run.sh")
        self.assertIn("mode changed file -> executable, contents identical", d["evidence"][0]["excerpt"])
        rows, _ = self.rows(self.union)
        self.assertIn("M run.sh", rows)

    def test_redaction_applies_to_context_paths(self):
        rd, _ = self.call(self.union, "read_file", side="head", path="lib/head_only.py")
        self.assertNotIn(TOKEN, rd["evidence"][0]["excerpt"])
        sr, _ = self.call(self.union, "search_literal", side="head", query=TOKEN[:12])
        self.assertEqual(sr["evidence"], [])


class Equivalence(UnionEnv):
    """A union path in context_paths behaves exactly as the same path in a context layer."""

    CALLS = [("diff", {}), ("diff", {"path": "lib/head_only.py"}), ("diff", {"path": "lib/base_only.py"}),
             ("diff", {"path": "lib/both.py"}), ("diff", {"path": "src/app.py"}), ("diff", {"path": "src/new.py"}),
             ("diff", {"path": "src/gone.py"}), ("diff", {"path": "run.sh"}), ("diff", {"path": "nope.py"}),
             ("list_files", {"side": "head"}), ("list_files", {"side": "base", "prefix": "lib"}),
             ("read_file", {"side": "head", "path": "lib/head_only.py"}),
             ("read_file", {"side": "base", "path": "src/gone.py"}), ("read_file", {"side": "base", "path": "lib/more.py"}),
             ("search_literal", {"side": "head", "query": "="}), ("search_literal", {"side": "base", "query": "both"})]

    def _norm(self, view, result):
        text = repr(result)
        for side in ("base", "head"):
            for l in view.layers(side):
                text = text.replace(l.snapshot_id, side.upper()).replace(l.snapshot_id[:24], side.upper())
        text = re.sub(r"(base|head)-(union \[context\]|union|changed|context)", r"\1-LAYER", text)
        return re.sub(r"'toolCallId': '[^']+'", "", text)

    def test_union_and_layered_views_give_the_same_results(self):
        for tool, args in self.CALLS:
            with self.subTest(tool=tool, args=args):
                a, _ = self.call(self.layered, tool, **args)
                b, _ = self.call(self.union, tool, **args)
                self.assertEqual(self._norm(self.layered, a), self._norm(self.union, b))


class OneIdPerSide(UnionEnv):
    def test_one_computed_snapshot_id_per_side_and_never_full(self):
        v = self.union
        self.assertEqual(set(v.trees()), {self.m["ub"]["snapshotId"], self.m["uh"]["snapshotId"]})
        self.assertTrue(v.partial)
        cov = v.coverage()
        self.assertEqual(cov["scope"], "changed-files-and-selected-context")
        self.assertFalse(cov["fullRepositoryCoverage"])
        self.assertEqual(cov["layers"]["head"], [{"name": "head-union", "kind": "changed",
                                                   "snapshotId": self.m["uh"]["snapshotId"],
                                                   "contextPaths": sorted(H_CTX)}])
        empty = self.make_union(base=(self.tmp / "lb", self.m["lb"], set(), None))
        self.assertTrue(empty.partial)
        self.assertNotIn("contextPaths", empty.coverage()["layers"]["base"][0])
        self.assertEqual(empty.note(), PARTIAL_NOTE)

    def test_supplied_manifest_is_kept_not_rebuilt(self):
        m = copy.deepcopy(self.m["uh"])
        v = self.make_union(head=(self.tmp / "uh", m, set(H_CTX), None))
        m["entries"].clear()                                        # caller scribbles after construction
        write_tree(self.tmp / "uh", {"lib/planted.py": "PLANTED = 1\n"})    # review-time plant
        ls, _ = self.call(v, "list_files", side="head")
        self.assertIn("lib/head_only.py", ls["evidence"][0]["excerpt"])
        self.assertNotIn("planted", ls["evidence"][0]["excerpt"])
        rd, _ = self.call(v, "read_file", side="head", path="lib/planted.py")
        self.assertEqual(rd["status"], "unavailable")

    def test_recorded_gaps_reach_notices_and_coverage(self):
        rec = {"complete": False, "gapKinds": [], "contextGapKinds": ["text-not-found"], "contextGapCount": 1,
               "changedFilesExpected": 4, "changedFilesListed": 4, "changedFilesRecorded": 4}
        v = self.make_union(recorded=rec)
        rd, _ = self.call(v, "read_file", side="head", path="lib/head_only.py")
        self.assertIn("1 selected context file(s) were not recorded (text-not-found)", rd["notice"])
        self.assertEqual(v.coverage()["recorded"], rec)


class Tamper(UnionEnv):
    def test_tampered_context_and_changed_content_is_refused(self):
        for path in ("lib/head_only.py", "src/new.py"):
            with self.subTest(path=path):
                v = self.make_union()
                f = self.tmp / "uh" / path
                saved = f.read_bytes()
                f.write_bytes(saved + b"evil = 1\n")
                try:
                    rd, s = self.call(v, "read_file", side="head", path=path)
                    self.assertEqual(rd["status"], "error")
                    self.assertEqual(rd["evidence"], [])
                    self.assertTrue(s.tampered)
                    sr, s2 = self.call(v, "search_literal", side="head", query="evil")
                    self.assertEqual(sr["evidence"], [])
                    self.assertTrue(s2.tampered)
                finally:
                    f.write_bytes(saved)

    def test_pinned_mode_is_reported_not_the_disk_mode(self):
        # Limit kept from read_verified: a later chmod is not detected by a read, but no tool reports
        # it either; the mode the model sees always comes from the pinned manifest.
        os.chmod(self.tmp / "uh" / "lib" / "head_only.py", 0o755)
        rows, _ = self.rows(self.union)
        self.assertEqual(rows, CHANGED_ROWS)
        self.assertEqual(self.union.find("head", "lib/head_only.py")[1]["type"], "file")

    def test_union_mismatching_disk_reads_fail_closed(self):
        v = self.make_union(head=(self.tmp / "uh", self.m["uh"], set(H_CTX), None))
        shutil.rmtree(self.tmp / "uh" / "lib")
        _tree(self.tmp / "uh" / "lib", {"head_only.py": "HEAD_ONLY = 2\n"})
        rd, s = self.call(v, "read_file", side="head", path="lib/head_only.py")
        self.assertEqual(rd["status"], "error")
        self.assertTrue(s.tampered)


class InvalidSets(UnionEnv):
    def refused(self, why, fn):
        with self.assertRaises(ViewError) as cm:
            fn()
        self.assertIn(why, str(cm.exception))

    def test_invalid_context_and_changed_sets_are_refused(self):
        root, m = self.tmp / "uh", self.m["uh"]
        mk = lambda **kw: make_layer("u", "changed", root, m, **kw)  # noqa: E731
        self.refused("not in the pinned manifest", lambda: mk(context_paths={"lib/ghost.py"}))
        self.refused("not in the pinned manifest", lambda: mk(context_paths={"../labels/x"}))
        self.refused("must be a set", lambda: mk(context_paths="lib/head_only.py"))
        self.refused("must be a set", lambda: mk(context_paths={"lib/head_only.py": 1}))
        self.refused("only path strings", lambda: mk(context_paths=[1]))
        self.refused("both changed and context", lambda: mk(context_paths=set(H_CTX), changed_paths=set(H_CHG) | {"lib/more.py"}))
        self.refused("neither changed nor context", lambda: mk(context_paths=set(H_CTX), changed_paths={"src/app.py"}))
        self.refused("not in the pinned manifest", lambda: mk(context_paths=set(H_CTX), changed_paths=set(H_CHG) | {"x.py"}))
        self.refused("only for a 'changed' union layer", lambda: make_layer("f", "full", root, m, context_paths={"run.sh"}))
        self.refused("only for a 'changed' union layer", lambda: make_layer("c", "context", root, m, context_paths=set()))
        self.refused("only for a 'changed' union layer", lambda: make_layer("f", "full", root, m, changed_paths=set(m)))

    def test_factory_shape_and_forged_manifests_are_refused(self):
        good = (self.tmp / "uh", self.m["uh"], set(H_CTX), None)
        self.refused("must be (root, manifest", lambda: partial_union_view([self.tmp], good))
        self.refused("context_paths is required", lambda: partial_union_view((self.tmp / "ub", self.m["ub"], None, None), good))
        forged = copy.deepcopy(self.m["uh"])
        forged["snapshotId"] = self.m["ub"]["snapshotId"]          # aliased id
        self.refused("not a valid SnapshotManifest", lambda: self.make_union(head=(self.tmp / "uh", forged, set(H_CTX), None)))
        edited = copy.deepcopy(self.m["uh"])
        edited["entries"][0]["sha256"] = "0" * 64
        self.refused("not a valid SnapshotManifest", lambda: self.make_union(head=(self.tmp / "uh", edited, set(H_CTX), None)))

    def test_context_path_from_the_other_side_is_refused(self):
        self.refused("not in the pinned manifest",
                     lambda: self.make_union(head=(self.tmp / "uh", self.m["uh"], set(H_CTX) | {"lib/base_only.py"}, None)))


class FullViewControls(Env):
    def test_full_view_and_signatures_are_unchanged(self):
        v = self.view
        self.assertFalse(v.partial)
        for side in ("base", "head"):
            for l in v.coverage()["layers"][side]:
                self.assertEqual(set(l), {"name", "kind", "snapshotId"})
        self.assertEqual(v.path_kind("head", "src/new.py"), "full")
        self.assertEqual(v.context_paths("head"), frozenset())
        self.assertEqual(list(inspect.signature(full_view).parameters), ["base_root", "base_manifest", "head_root", "head_manifest"])
        params = inspect.signature(make_layer).parameters
        self.assertEqual(list(params)[:4], ["name", "kind", "root", "manifest"])
        self.assertTrue(all(params[k].kind is inspect.Parameter.KEYWORD_ONLY for k in ("context_paths", "changed_paths")))
        self.assertEqual(Layer("x", "changed", self.head, build_manifest(self.head)).context, frozenset())
        r = self.session().call("diff", {}).result
        self.assertEqual(r["evidence"][0]["excerpt"].split("\n")[1:], ["M src/app.py", "D src/gone.py", "A src/new.py"])

    def test_layered_historical_view_has_no_context_marker_in_coverage(self):
        from .helpers import make_case
        from reviewer.tools import capture_historical_pins
        case = make_case(self.tmp / "cases", {"a.py": "1\n"}, {"a.py": "2\n"}, context={"head": {"c.py": "3\n"}})
        v = historical_input_view(case, pins=capture_historical_pins(case))
        self.assertEqual(v.path_kind("head", "c.py"), "context")
        self.assertEqual(v.changed_paths("head"), frozenset({"a.py"}))
        for side in ("base", "head"):
            for l in v.coverage()["layers"][side]:
                self.assertNotIn("contextPaths", l)


class RealFixture1347(unittest.TestCase):
    """The S0B-02c bridge recipe on the real Vesktop 1347 fixture (head = 3 changed + 2 context)."""

    @unittest.skipUnless((ROOT / "fixtures" / "historical" / "Vencord--Vesktop--1347").is_dir(),
                         "optional private input absent: fixtures/historical/Vencord--Vesktop--1347 (unpublished historical fixture)")
    def test_bridge_recipe_keeps_head_context_out_of_the_changed_list(self):
        from reviewer.historical import capture_bridge_pins, materialize
        with tempfile.TemporaryDirectory() as t:
            case = ROOT / "fixtures" / "historical" / "Vencord--Vesktop--1347"
            pins = capture_bridge_pins(case, captured_at="2026-10-25T20:00:00Z")    # trusted time, test-only store
            b = materialize(case, pins=pins, out_dir=Path(t) / "out", forbidden_roots=(ROOT / "fixtures",))
            rec = b.record

            def spec(side):                       # the recipe in orchestration/handoffs/S0B-02c-tools.md
                snap, u = getattr(b, side), rec["unions"][side]
                kinds = {d["name"]: d["kind"] for d in u["derivedFrom"]}
                changed = {p for p, ns in u["provenance"].items() if any(kinds[n] == "changed" for n in ns)}
                return (snap.root, snap.manifest, set(rec["coverage"]["contextPaths"][side]), changed)

            v = partial_union_view(spec("base"), spec("head"), recorded=rec["coverage"]["recorded"])
            self.assertEqual(set(v.trees()), {b.case["base"]["snapshotId"], b.case["head"]["snapshotId"]})
            self.assertEqual(len(v.layers("head")), 1)
            self.assertEqual(v.context_paths("head"), {"src/main/settings.ts", "src/renderer/utils.ts"})
            self.assertEqual(v.context_paths("base"), frozenset())
            self.assertEqual(len(v.changed_paths("head")), 3)
            rows = ToolSession(v).call("diff", {}).result["evidence"][0]["excerpt"].split("\n")[1:]
            self.assertEqual(sorted(r[2:] for r in rows), sorted(v.changed_paths("head")))
            self.assertTrue(all(r.startswith("M ") for r in rows))
            for p in sorted(v.context_paths("head")):
                s = ToolSession(v)
                rd = s.call("read_file", {"side": "head", "path": p}).result
                self.assertIn(rd["status"], ("ok", "partial"))
                self.assertIn("head-union [context]", rd["notice"])
                self.assertIn("were not recorded", rd["notice"])        # the recorded context gap
                self.assertFalse(s.tampered)
                self.assertEqual(s.call("diff", {"path": p}).result["status"], "unavailable")
            self.assertFalse(v.coverage()["fullRepositoryCoverage"])


if __name__ == "__main__":
    unittest.main()
