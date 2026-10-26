"""S0B-02a-finalreview: independent attacks on the S0B-02a-fix seams (`_sealed_output`/`discard`, `_roots`/`_check_out`,
`_plain`/`check_pins`, typed errors, `HistoricalBridge.view()`), beyond the original review file. Offline; real fixtures are
only read. Reuses the fixtures/helpers of test_historical_review (same directory, no package).

    nice -n 19 python3 -m unittest discover -s tests/historical_review
"""
import copy
import json
import os
import shutil
import stat
import unittest
from collections import OrderedDict
from pathlib import Path

from reviewer.historical import (BridgeError, capture_bridge_pins, check_pins, discard, load_pins, materialize, write_pins)
from reviewer.tools import ToolSession
from tests.historical_review.test_historical_review import AT, CORPUS, CTX_CASE, HAVE_CORPUS, REAL, Env, Tmp, make_writable


class SealedDiscard(Env):
    def sealed(self):
        return self.mat()

    def test_user_directories_are_never_removed(self):
        keep = {}
        for name, build in {
            "plain": lambda d: (d / "precious.txt").write_text("x"),
            "base-head-plus-extra": lambda d: ((d / "base").mkdir(), (d / "head").mkdir(), (d / "extra.txt").write_text("x")),
            "files-writable": lambda d: ((d / "base").mkdir(), (d / "head").mkdir(), (d / "base" / "f").write_text("x")),
        }.items():
            d = self.tmp / name
            d.mkdir()
            build(d)
            keep[name] = d
        for target in (*keep.values(), self.corpus, self.case, self.case / "input", self.store, self.tmp, Path("."), Path("/")):
            with self.assertRaises(BridgeError, msg=str(target)):
                discard(target)
        for d in keep.values():
            self.assertTrue(d.exists() and os.listdir(d))
        self.assertTrue((self.case / "input" / "case.json").exists())

    def test_wrong_modes_links_and_special_files_in_a_sealed_shape_are_refused_untouched(self):
        for label, tamper in {
            "setuid-file": lambda b, root: os.chmod(self._f(b), 0o4555),
            "writable-file": lambda b, root: self._reopen_file(b),
            "writable-dir": lambda b, root: os.chmod(root / "base", 0o755),
            "extra-top-entry": lambda b, root: self._extra_top(root),
            "hardlink": lambda b, root: self._hardlink(b, root),
            "symlink-file": lambda b, root: self._symlink_in_tree(b, root),
        }.items():
            with self.subTest(label):
                out = self.tmp / ("o-" + label)
                b = self.mat(out=out)
                root = Path(b.base.root).parent
                tamper(b, root)
                before = sorted(str(p.relative_to(root)) for p in root.rglob("*"))
                for target in (root, b):
                    with self.assertRaisesRegex(BridgeError, "nothing was removed"):
                        discard(target)
                self.assertEqual(sorted(str(p.relative_to(root)) for p in root.rglob("*")), before)
                make_writable(root)
                shutil.rmtree(root)

    def _f(self, b):
        return Path(b.base.root) / b.base.manifest["entries"][0]["path"]

    def _reopen_file(self, b):
        os.chmod(self._f(b), 0o644)

    def _extra_top(self, root):
        os.chmod(root, 0o755)
        (root / "note.txt").write_text("x")
        os.chmod(root, 0o555)

    def _hardlink(self, b, root):
        f = self._f(b)
        os.chmod(f.parent, 0o755)
        os.link(f, f.parent / "hl")
        os.chmod(f.parent, 0o555)

    def _symlink_in_tree(self, b, root):
        f = self._f(b)
        os.chmod(f.parent, 0o755)
        os.symlink(self.case / "input" / "case.json", f.parent / "lnk")
        os.chmod(f.parent, 0o555)

    def test_bridge_object_discard_detects_manifest_drift_and_is_exact_otherwise(self):
        b = self.mat()
        root = Path(b.base.root).parent
        victim = self._f(b)
        os.chmod(victim.parent, 0o755)
        victim.chmod(0o644)
        victim.unlink()                                         # a file of the manifest disappeared
        os.chmod(victim.parent, 0o555)
        with self.assertRaisesRegex(BridgeError, "nothing was removed"):
            discard(b)
        self.assertTrue(root.exists())

    def test_discard_of_a_sealed_output_removes_it_and_only_it(self):
        sib = self.tmp / "sibling.txt"
        sib.write_text("s")
        b = self.sealed()
        discard(b)
        self.assertFalse(self.out.exists())
        self.assertTrue(sib.exists() and self.case.exists() and self.corpus.exists() and self.store.exists())

    def test_symlink_to_a_sealed_output_is_refused(self):
        b = self.sealed()
        lnk = self.tmp / "lnk"
        os.symlink(self.out, lnk)
        with self.assertRaises(BridgeError):
            discard(lnk)
        self.assertEqual(sorted(os.listdir(self.out)), ["base", "head"])

    def test_LIMIT_discard_by_path_is_a_shape_check_an_empty_look_alike_is_accepted(self):
        """Documented limit (author: 'a shape check'): a hand-built 0555 dir with empty 0555 base/ and head/ passes. A real
        bridge output never has empty sides, so passing the HistoricalBridge object (manifest check) is the exact form."""
        d = self.tmp / "lookalike"
        (d / "base").mkdir(parents=True)
        (d / "head").mkdir()
        os.chmod(d / "base", 0o555)
        os.chmod(d / "head", 0o555)
        os.chmod(d, 0o555)
        discard(d)
        self.assertFalse(d.exists())


class Containment(Env):
    def sibling(self):
        case, _ = self.fresh("o--r--8")
        return case

    def refuse_out(self, out, **kw):
        with self.assertRaises(BridgeError, msg=str(out)):
            materialize(self.case, pins=self.pins, out_dir=out, **kw)
        self.assertFalse(os.path.lexists(out))

    def test_corpus_containment_is_mandatory_with_every_spelling_of_forbidden_roots(self):
        sib = self.sibling()
        spots = [self.corpus / "zz", sib / "input" / "zz", sib / "zz", self.case / "zz", self.case / "input" / "zz",
                 self.corpus / ".." / "corpus" / "zz", Path(str(self.corpus) + "/./zz"), self.corpus / "a" / ".." / "zz"]
        for roots in ({}, {"forbidden_roots": ()}, {"forbidden_roots": []}, {"forbidden_roots": "/nonexistent"},
                      {"forbidden_roots": Path("/nonexistent")}, {"forbidden_roots": (self.store,)}, {"forbidden_roots": iter(())}):
            for spot in spots:
                if spot.parent.exists() or spot.parent.parent.exists():
                    with self.subTest(roots=str(roots), spot=str(spot)):
                        self.refuse_out(spot, **{k: (v if k != "forbidden_roots" or not hasattr(v, "__next__") else iter(())) for k, v in roots.items()})
        for d in (self.corpus, sib):
            self.assertEqual(sorted(p.name for p in (d).iterdir()), sorted(p.name for p in d.iterdir()))
        self.assertEqual(sorted(p.name for p in self.corpus.iterdir()), ["o--r--7", "o--r--8"])

    def test_relative_and_symlinked_spellings_of_the_corpus_are_caught(self):
        link = self.tmp / "corpus-link"
        os.symlink(self.corpus, link)
        self.refuse_out(link / "zz")                                           # symlink component: refused outright
        cwd = os.getcwd()
        try:
            os.chdir(self.corpus)
            with self.assertRaises(BridgeError):
                materialize("o--r--7", pins=self.pins, out_dir="zz")           # relative case dir, relative out in the corpus
            with self.assertRaises(BridgeError):
                materialize("o--r--7", pins=self.pins, out_dir="../corpus/zz")
        finally:
            os.chdir(cwd)
        self.assertEqual(sorted(p.name for p in self.corpus.iterdir()), ["o--r--7"])

    def test_forbidden_roots_types_and_relative_string_root(self):
        for bad in (b"/tmp", 5, None, object(), [b"x"], [5], ["ok", None]):
            with self.subTest(bad=repr(bad)), self.assertRaises(BridgeError):
                materialize(self.case, pins=self.pins, out_dir=self.out, forbidden_roots=bad)
            self.assertFalse(os.path.lexists(self.out))
        keep = self.tmp / "keep"
        keep.mkdir()
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp)
            with self.assertRaises(BridgeError):                              # a bare relative string protects that directory
                materialize(self.case, pins=self.pins, out_dir=keep / "zz", forbidden_roots="keep")
            with self.assertRaises(BridgeError):
                materialize(self.case, pins=self.pins, out_dir=keep / "zz", forbidden_roots=[Path("keep")])
        finally:
            os.chdir(cwd)
        self.assertEqual(os.listdir(keep), [])

    def test_unrelated_outside_directory_still_works_and_errors_do_not_name_paths(self):
        b = self.mat(forbidden_roots=())
        self.assertTrue(Path(b.base.root).is_dir())
        discard(b)
        ro = self.tmp / "ro"
        ro.mkdir()
        os.chmod(ro, 0o500)
        try:
            with self.assertRaises(BridgeError) as cm:
                materialize(self.case, pins=self.pins, out_dir=ro / "o")
        finally:
            os.chmod(ro, 0o700)
        if os.geteuid() != 0:
            self.assertNotIn(str(ro), str(cm.exception))


class TypedPins(Env):
    def mut(self, f):
        p = copy.deepcopy(self.pins)
        f(p)
        return p

    def test_hostile_pins_fail_typed_in_check_load_write_and_materialize(self):
        deep = {}
        cur = deep
        for _ in range(200):
            cur["a"] = {}
            cur = cur["a"]
        cyc = copy.deepcopy(self.pins)
        cyc["view"]["self"] = cyc
        cases = {
            "surrogate-value": self.mut(lambda p: p["view"].__setitem__("x", "a\ud800b")),
            "surrogate-key": self.mut(lambda p: p["view"].__setitem__("\udfff", "x")),
            "surrogate-prtext": self.mut(lambda p: p.__setitem__("prText", {"title": "\ud800", "body": "", "asOf": AT, "redactions": {}})),
            "deep": self.mut(lambda p: p["view"].__setitem__("x", deep)),
            "cycle": cyc,
            "bytes": self.mut(lambda p: p["view"].__setitem__("x", b"a")),
            "set": self.mut(lambda p: p["view"].__setitem__("x", {1})),
            "object": self.mut(lambda p: p["view"].__setitem__("x", object())),
            "int-key": self.mut(lambda p: p["view"].__setitem__(1, "x")),
            "str-subclass": self.mut(lambda p: p.__setitem__("caseId", type("S", (str,), {})(p["caseId"]))),
        }
        for label, p in cases.items():
            with self.subTest(label):
                for f in (lambda: check_pins(p), lambda: write_pins(self.tmp / ("w-" + label), p),
                          lambda: materialize(self.case, pins=p, out_dir=self.tmp / ("o-" + label), forbidden_roots=(self.corpus,))):
                    with self.assertRaises(BridgeError):
                        f()
                self.assertFalse((self.tmp / ("w-" + label)).exists() or (self.tmp / ("o-" + label)).exists())

    def test_nested_json_file_and_unreadable_pins_are_typed(self):
        for label, data in {"deep-arrays": b"[" * 100_000, "deep-objects": b'{"a":' * 50_000, "nan": b'{"a": NaN}',
                            "bad-utf8": b"\xff\xfe", "empty": b""}.items():
            with self.subTest(label):
                f = self.store / label
                f.write_bytes(data)
                with self.assertRaises(BridgeError):
                    load_pins(f, case_dir=self.case)
        with self.assertRaises(BridgeError):
            load_pins(self.store / "missing.json", case_dir=self.case)
        with self.assertRaises(BridgeError):
            write_pins(self.tmp / "no-such-dir" / "p.json", self.pins)
        with self.assertRaises(BridgeError):
            write_pins(self.store / "p.json", self.pins)                       # exists: never overwritten

    @unittest.expectedFailure
    def test_F13_write_pins_escapes_with_ValueError_for_non_json_numbers_in_the_view_part(self):
        """CONFIRMED (low, residual of F4): check_pins validates the view part only at materialize time, so NaN/Infinity or an
        integer beyond 2**53 inside `view` passes check_pins and write_pins dies with a raw ValueError from canonical_json
        (no file is created). materialize refuses the same pins with a typed error. Fix: wrap canonical_json in write_pins."""
        for v in (float("nan"), float("inf"), 10 ** 5000):
            p = self.mut(lambda p: p["view"].__setitem__("x", v))
            with self.assertRaises(BridgeError):
                write_pins(self.tmp / "w-num", p)
            self.assertFalse((self.tmp / "w-num").exists())

    def test_F13_effect_materialize_refuses_those_pins_typed_and_leaves_nothing(self):
        for v in (float("nan"), 10 ** 5000, (1, 2)):
            p = self.mut(lambda p: p["view"].__setitem__("x", v))
            with self.assertRaises(BridgeError):
                materialize(self.case, pins=p, out_dir=self.out, forbidden_roots=(self.corpus,))
            self.assertFalse(os.path.lexists(self.out))

    def test_check_pins_returns_a_private_plain_snapshot(self):
        class Lying(dict):
            calls = 0

            def __getitem__(self, k):
                Lying.calls += 1
                return super().__getitem__(k) if Lying.calls < 3 else "lie"

            def get(self, k, d=None):
                return "lie"

            def items(self):
                return [("lie", 1)]

        src = OrderedDict(copy.deepcopy(self.pins))
        src["origin"] = Lying(src["origin"])
        src["view"] = OrderedDict(src["view"])
        got = check_pins(src)
        self.assertEqual(got, self.pins)
        self.assertIs(type(got), dict)
        self.assertIs(type(got["origin"]), dict)
        self.assertIs(type(got["view"]), dict)
        got["origin"]["repo"] = "mutated"
        src["origin"]["repo"] = "mutated-src"
        self.assertEqual(check_pins(self.pins)["origin"]["repo"], self.pins["origin"]["repo"])
        again = check_pins(self.pins)
        again["view"]["schema"] = "x"
        self.assertNotEqual(self.pins["view"]["schema"], "x")

    def test_pins_mutated_while_materializing_cannot_change_the_result(self):
        class Flip(dict):
            """Answers truthfully the first time it is copied, then lies (a TOCTOU between validation and use)."""
            n = 0

            def items(self):
                Flip.n += 1
                return super().items() if Flip.n == 1 else iter([("schema", "x")])

        p = copy.deepcopy(self.pins)
        p["origin"] = Flip(p["origin"])
        b = materialize(self.case, pins=p, out_dir=self.out, forbidden_roots=(self.corpus,))
        self.assertEqual(b.record["origin"], self.pins["origin"])
        p["origin"]["repo"] = "changed-later"
        self.assertEqual(b.record["origin"], self.pins["origin"])


@unittest.skipUnless(HAVE_CORPUS, "optional private input absent: fixtures/historical (unpublished historical corpus)")
class PartialViews(Tmp):
    """All 9 real cases through the fixed `HistoricalBridge.view()`; 1347's two head-only context files are never A/D."""
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.store = Path(tempfile.mkdtemp(prefix="s0b02a-fr-"))
        cls.out = {}
        for c in REAL:
            pins = capture_bridge_pins(CORPUS / c, captured_at=AT)
            cls.out[c] = materialize(CORPUS / c, pins=pins, out_dir=cls.store / c)

    @classmethod
    def tearDownClass(cls):
        make_writable(cls.store)
        shutil.rmtree(cls.store)

    def session(self, c):
        return ToolSession(self.out[c].view(), stage="PREPARE", agent_id="rev")

    def test_all_nine_views_are_partial_one_union_layer_per_side_and_context_matches_the_record(self):
        self.assertEqual(len(REAL), 9)
        for c in REAL:
            with self.subTest(c):
                b = self.out[c]
                v = b.view()
                cov = v.coverage()
                self.assertTrue(v.partial)
                self.assertIs(cov["fullRepositoryCoverage"], False)
                self.assertEqual({s: len(ls) for s, ls in cov["layers"].items()}, {"base": 1, "head": 1})
                self.assertEqual(cov["layers"]["base"][0]["snapshotId"], b.record["unions"]["base"]["snapshotId"])
                self.assertEqual(cov["layers"]["head"][0]["snapshotId"], b.record["unions"]["head"]["snapshotId"])
                for side in ("base", "head"):
                    self.assertEqual(v.context_paths(side), set(b.record["coverage"]["contextPaths"][side]))
                changed = [f["path"] for f in b.record["coverage"]["changedPaths"]]
                rows = self.session(c).call("diff", {}).result["evidence"]
                text = rows[0]["excerpt"] if rows else ""
                for p in changed:
                    self.assertIn(p, text, "a recorded changed file is missing from the diff list")

    def test_1347_context_files_are_context_not_added_or_deleted_on_every_surface(self):
        ctx = ["src/main/settings.ts", "src/renderer/utils.ts"]
        b = self.out[CTX_CASE]
        s = self.session(CTX_CASE)
        self.assertEqual(b.record["coverage"]["contextPaths"], {"base": [], "head": ctx})
        listing = s.call("diff", {}).result["evidence"][0]["excerpt"]
        self.assertEqual([r[0] for r in listing.splitlines()[1:]], ["M", "M", "M"])
        for p in ctx:
            self.assertNotIn(p, listing)
            d = s.call("diff", {"path": p}).result
            self.assertEqual(d["status"], "unavailable")
            self.assertIn("context", d["notice"])
            r = s.call("read_file", {"side": "head", "path": p}).result
            self.assertEqual(r["status"], "ok", p)                              # readable, from the head union only
            base_read = s.call("read_file", {"side": "base", "path": p}).result
            self.assertNotEqual(base_read["status"], "ok", "a head-only context file was served as if it existed on base")
        files = s.call("list_files", {"side": "head"}).result
        blob = json.dumps(files)
        for p in ctx:
            self.assertIn(p, blob)
        self.assertIn("Partial view", files["notice"])
        self.assertIn("not recorded", files["notice"] + s.call("diff", {}).result["notice"])   # the recorded context gap stays visible

    def test_view_manifests_are_private_copies_and_repeated_views_agree(self):
        b = self.out[CTX_CASE]
        v1, v2 = b.view(), b.view()
        self.assertEqual(v1.coverage(), v2.coverage())
        head_id = b.record["unions"]["head"]["snapshotId"]
        self.assertEqual(b.head.manifest["snapshotId"], head_id)
        m = b.head
        m.manifest["entries"].clear()
        self.assertTrue(b.head.manifest["entries"])


if __name__ == "__main__":
    unittest.main()
