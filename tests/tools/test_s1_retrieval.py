"""S1-04: list_files paging, full-repository limits and honest search exhaustion, tools-layer T1."""

import json
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.canonical import tool_call_id
from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import Limits, ToolSession, View, ViewError, full_view, make_layer, normalize, partial_union_view

from .helpers import Clock, Env, write_tree


def listing(result) -> list[str]:
    """Paths shown in a list_files result, in order."""
    rows = "\n".join(e["excerpt"] for e in result["evidence"]).split("\n")[1:]
    return [r.split("  (")[0].split("  [")[0] for r in rows if r]


def next_args(result) -> dict | None:
    n = result["notice"]
    if not n.startswith("Next page: list_files "):
        return None
    return json.loads(n[len("Next page: list_files "):].split("}")[0] + "}")


class Tree(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.n = 0

    def view(self, files, head=None):
        self.n += 1
        b, h = self.tmp / f"b{self.n}", self.tmp / f"h{self.n}"
        for root, f in ((b, files), (h, files if head is None else head)):
            root.mkdir()
            write_tree(root, f)
        return full_view(b, build_manifest(b), h, build_manifest(h))

    def walk(self, view, *, prefix="", limit=None, limits=None, max_pages=500):
        """Follow the visible continuation to the end. -> (paths in order, pages)."""
        s = ToolSession(view, limits=limits or Limits(max_calls=max_pages + 1))
        args = {"side": "head", "prefix": prefix}
        if limit is not None:
            args["limit"] = limit
        out, pages = [], []
        for _ in range(max_pages):
            r = s.call("list_files", args).result
            pages.append(r)
            out += listing(r)
            nxt = next_args(r)
            if nxt is None:
                return out, pages
            args = nxt
        self.fail("paging did not terminate")


class Paging(Tree):
    FILES = {f"d/{i:03d}.txt": "x\n" for i in range(25)} | {"top.txt": "t\n", "e/z.txt": "z\n"}

    def test_walk_visits_every_path_once_in_order_for_several_page_sizes(self):
        v = self.view(self.FILES)
        want = sorted(self.FILES)
        for limit in (1, 2, 7, 27, 28, 500):
            with self.subTest(limit=limit):
                got, pages = self.walk(v, limit=limit)
                self.assertEqual(got, want)
                self.assertEqual(len(pages), -(-len(want) // limit))

    def test_empty_view_and_empty_prefix_and_past_the_end(self):
        v = self.view({"a.txt": "x\n"})
        s = ToolSession(v)
        r = s.call("list_files", {"side": "head", "prefix": "nothing"}).result
        self.assertEqual((r["status"], listing(r), r["truncated"]), ("empty", [], None))
        r = s.call("list_files", {"side": "head", "after": "zzz"}).result
        self.assertEqual((r["status"], listing(r), r["truncated"]), ("empty", [], None))
        self.assertIn("No entries after the cursor", r["notice"])

    def test_exact_boundary_has_no_continuation_one_less_has(self):
        v = self.view({f"f{i}.txt": "x\n" for i in range(5)})
        s = ToolSession(v)
        r = s.call("list_files", {"side": "head", "limit": 5}).result
        self.assertEqual((r["status"], r["truncated"], next_args(r), len(listing(r))), ("ok", None, None, 5))
        r = s.call("list_files", {"side": "head", "limit": 4}).result
        self.assertEqual((r["status"], r["truncated"], len(listing(r))), ("partial", {"shown": 4, "total": 5}, 4))
        self.assertEqual(next_args(r), {"side": "head", "prefix": "", "after": "f3.txt", "limit": 4})
        self.assertEqual(r["completeness"], "approximate")
        last = s.call("list_files", next_args(r)).result
        self.assertEqual((last["status"], last["truncated"], listing(last), last["completeness"]),
                         ("ok", None, ["f4.txt"], "exact"))
        self.assertIn("Last page.", last["notice"])
        self.assertIsNone(next_args(last))

    def test_prefix_is_a_directory_not_a_string_prefix(self):
        v = self.view({"src/a.py": "1\n", "src/b.py": "2\n", "src2/c.py": "3\n", "srcx": "4\n"})
        got, _ = self.walk(v, prefix="src", limit=1)
        self.assertEqual(got, ["src/a.py", "src/b.py"])

    def test_cursor_outside_prefix_is_only_a_lower_bound(self):
        v = self.view({"a/1": "x\n", "b/1": "x\n", "b/2": "x\n"})
        s = ToolSession(v)
        self.assertEqual(listing(s.call("list_files", {"side": "head", "prefix": "b", "after": "a/9"}).result),
                         ["b/1", "b/2"])
        self.assertEqual(listing(s.call("list_files", {"side": "head", "prefix": "b", "after": "b/1"}).result), ["b/2"])

    def test_non_ascii_paths_page_in_code_point_order_without_repeat_or_skip(self):
        names = ["a.txt", "é.txt", "ü/x.txt", "日本/語.txt", "😀.txt", "Z.txt", "z.txt"]
        v = self.view({n: "x\n" for n in names})
        for limit in (1, 2, 3):
            got, _ = self.walk(v, limit=limit)
            self.assertEqual(got, sorted(names), limit)
        r = ToolSession(v).call("list_files", {"side": "head", "limit": 1, "after": "é.txt"}).result
        self.assertEqual(listing(r), ["ü/x.txt"])
        self.assertEqual(next_args(r)["after"], "ü/x.txt")

    def test_output_char_cap_truncation_neither_skips_nor_repeats(self):
        files = {f"dir/file_with_a_long_name_{i:03d}.txt": "x\n" for i in range(60)}
        v = self.view(files)
        lim = Limits(max_calls=400, max_output_chars=420, chunk_chars=200)
        got, pages = self.walk(v, limit=500, limits=lim)
        self.assertEqual(got, sorted(files))
        self.assertGreater(len(pages), 4)
        for r in pages[:-1]:                                  # every cut page says so and names its cursor
            self.assertEqual(r["status"], "partial")
            self.assertLess(r["truncated"]["shown"], r["truncated"]["total"])
            self.assertEqual(next_args(r)["after"], listing(r)[-1])

    def test_a_cap_too_small_for_one_row_offers_no_cursor_and_says_so(self):
        v = self.view({"some/long/path/name.txt": "x\n"})
        r = ToolSession(v, limits=Limits(max_output_chars=10)).call("list_files", {"side": "head"}).result
        self.assertEqual((r["status"], r["truncated"]["shown"], listing(r)), ("partial", 0, []))
        self.assertIsNone(next_args(r))
        self.assertIn("no continuation", r["notice"])

    def test_max_list_still_caps_a_page_and_continues(self):
        v = self.view({f"f{i:02d}": "x\n" for i in range(10)})
        got, pages = self.walk(v, limit=10_000, limits=Limits(max_calls=50, max_list=4))
        self.assertEqual(got, [f"f{i:02d}" for i in range(10)])
        self.assertEqual(len(pages), 3)

    def test_invalid_after_is_a_logged_denial(self):
        v = self.view({"a": "x\n"})
        s = ToolSession(v)
        for bad in (5, None, "/abs", "../x", "a/../b", ".git/config", "x" * 600, "a\x00b", ["a"]):
            r = s.call("list_files", {"side": "head", "after": bad})
            self.assertEqual((r.result["status"], r.args), ("denied", {"rejected": True}), repr(bad)[:30])
        self.assertEqual(len(s.log), 9)
        self.assertTrue(all(row["status"] == "denied" for row in s.log))

    def test_partial_view_paging_keeps_the_view_notice(self):
        h = self.tmp / "ph"
        h.mkdir()
        write_tree(h, {"a.py": "1\n", "b.py": "2\n"})
        b = self.tmp / "pb"
        b.mkdir()
        write_tree(b, {"a.py": "0\n"})
        v = partial_union_view((b, build_manifest(b), set(), {"a.py"}), (h, build_manifest(h), set(), {"a.py", "b.py"}))
        r = ToolSession(v).call("list_files", {"side": "head", "limit": 1}).result
        self.assertEqual(r["completeness"], "approximate")
        self.assertIn("Partial view", r["notice"])
        last = ToolSession(v).call("list_files", {"side": "head", "after": "a.py"}).result
        self.assertEqual((listing(last), last["completeness"]), (["b.py"], "approximate"))


class PagingCompatibility(Tree):
    def test_non_paged_normalized_args_and_ids_are_unchanged(self):
        lim = Limits()
        legacy = {"side": "head", "prefix": "", "limit": lim.max_list}
        self.assertEqual(normalize("list_files", {"side": "head"}, lim), legacy)
        self.assertEqual(normalize("list_files", {"side": "head", "after": ""}, lim), legacy)
        v = self.view({"a": "x\n"})
        call = ToolSession(v).call("list_files", {"side": "head", "after": ""})
        self.assertEqual(call.tool_call_id, tool_call_id("INVESTIGATE", "generalist", 0, "list_files", legacy))
        paged = normalize("list_files", {"side": "head", "after": "a"}, lim)
        self.assertEqual(paged, {**legacy, "after": "a"})
        self.assertNotEqual(tool_call_id("S", "a", 0, "list_files", paged), tool_call_id("S", "a", 0, "list_files", legacy))

    def test_untruncated_non_paged_result_is_byte_identical_to_legacy_format(self):
        v = self.view({"a.txt": "x\n", "b/c.txt": "yy\n"})
        r = ToolSession(v).call("list_files", {"side": "head"}).result
        self.assertEqual(r["evidence"][0]["excerpt"], "# head files under /: 2 of 2; full snapshot\na.txt  (2 bytes)\nb/c.txt  (3 bytes)")
        self.assertEqual((r["status"], r["notice"], r["truncated"]), ("ok", "", None))


class FullRepositoryLimits(Tree):
    def many(self, n, needle_at=None, size_pad=""):
        files = {f"pkg{i // 100:03d}/m{i:05d}.py": f"v = {i}\n{size_pad}" for i in range(n)}
        if needle_at is not None:
            files[f"pkg{needle_at // 100:03d}/m{needle_at:05d}.py"] += "NEEDLE_DEF = 1\n"
        return files

    def test_profile_values_and_legacy_defaults(self):
        p = Limits.full_repository()
        self.assertEqual((p.max_search_files, p.max_search_scan_bytes, p.max_calls), (60_000, 256 << 20, 60))
        self.assertEqual((p.max_file_bytes, p.max_output_chars), (1 << 20, 24_000))
        self.assertGreater(p.search_wall_s, 0)
        d = Limits()
        self.assertEqual((d.max_search_files, d.max_search_scan_bytes, d.max_calls, d.wall_s, d.search_wall_s),
                         (1_000, 16 << 20, 50, 120.0, None))

    def test_profile_overrides_can_only_tighten(self):
        self.assertEqual(Limits.full_repository(max_search_files=10).max_search_files, 10)
        for bad in ({"max_search_files": 60_001}, {"max_search_scan_bytes": (256 << 20) + 1}, {"bogus": 1},
                    {"max_search_files": 0}, {"max_search_files": True}, {"max_search_files": "9"}, {"wall_s": 301}):
            with self.assertRaises(ValueError, msg=str(bad)):
                Limits.full_repository(**bad)

    def test_models_cannot_enlarge_limits_through_arguments(self):
        v = self.view(self.many(30, 29))
        s = ToolSession(v, limits=Limits(max_search_results=1, max_list=3))
        r = s.call("search_literal", {"side": "head", "query": "v =", "limit": 1000}).result
        self.assertEqual(len(r["evidence"]), 1)
        self.assertEqual(len(listing(s.call("list_files", {"side": "head", "limit": 10_000}).result)), 3)
        for extra in ("max_search_files", "wall_s", "search_wall_s"):
            r = s.call("search_literal", {"side": "head", "query": "x", extra: 10**9})
            self.assertEqual(r.result["status"], "denied")

    def test_lookup_beyond_the_old_1000_file_cap(self):
        v = self.view(self.many(1500, needle_at=1400))
        q = {"side": "head", "query": "NEEDLE_DEF"}
        old = ToolSession(v).call("search_literal", q).result
        self.assertEqual((old["status"], old["evidence"]), ("partial", []))        # legacy cap: honest, not "empty"
        self.assertIn("search file cap", old["notice"])
        self.assertIn("1000 of 1500 candidate file(s) visited", old["notice"])
        new = ToolSession(v, limits=Limits.full_repository()).call("search_literal", q).result
        self.assertEqual((new["status"], new["completeness"], [e["path"] for e in new["evidence"]]),
                         ("ok", "exact", ["pkg014/m01400.py"]))

    def test_file_cap_exhaustion_is_deterministic_and_disclosed(self):
        v = self.view(self.many(40, needle_at=39))
        for _ in range(2):
            r = ToolSession(v, limits=Limits.full_repository(max_search_files=25)).call(
                "search_literal", {"side": "head", "query": "NEEDLE_DEF"}).result
            self.assertEqual((r["status"], r["evidence"], r["completeness"]), ("partial", [], "approximate"))
            self.assertIn("search file cap", r["notice"])
            self.assertIn("25 of 40 candidate file(s) visited", r["notice"])

    def test_byte_cap_exhaustion_is_deterministic_and_disclosed(self):
        v = self.view(self.many(40, needle_at=39))
        r = ToolSession(v, limits=Limits.full_repository(max_search_scan_bytes=200)).call(
            "search_literal", {"side": "head", "query": "NEEDLE_DEF"}).result
        self.assertEqual((r["status"], r["evidence"]), ("partial", []))
        self.assertIn("search byte cap", r["notice"])
        self.assertRegex(r["notice"], r"\d+ of 40 candidate file\(s\) visited, \d+ bytes scanned")

    def test_a_skipped_oversized_file_does_not_spend_the_byte_budget(self):
        files = {"a_big.bin.txt": "x" * 5000, "z_small.py": "NEEDLE_DEF\n"}
        v = self.view(files)
        lim = Limits(max_file_bytes=1000, max_search_scan_bytes=100)
        r = ToolSession(v, limits=lim).call("search_literal", {"side": "head", "query": "NEEDLE_DEF"}).result
        self.assertEqual([e["path"] for e in r["evidence"]], ["z_small.py"])
        self.assertIn("1 oversized", r["notice"])
        self.assertEqual(r["status"], "partial")                  # the skipped file is still disclosed

    def test_per_search_wall_budget_stops_deterministically(self):
        v = self.view(self.many(30, needle_at=29))
        # each clock read advances 1s; the budget is 5s, so the scan ends after a fixed number of files
        outs = []
        for _ in range(2):
            lim = Limits.full_repository(search_wall_s=5)
            s = ToolSession(v, limits=lim, clock=Clock(step=1.0))
            outs.append(s.call("search_literal", {"side": "head", "query": "NEEDLE_DEF"}).result)
        self.assertEqual(outs[0], outs[1])
        r = outs[0]
        self.assertEqual((r["status"], r["evidence"], r["completeness"]), ("partial", [], "approximate"))
        self.assertIn("search time cap", r["notice"])
        self.assertIn("of 30 candidate file(s) visited", r["notice"])

    def test_session_wall_still_marks_deadline_incomplete(self):
        v = self.view(self.many(10))
        s = ToolSession(v, limits=Limits(wall_s=3), clock=Clock(step=1.0))
        s.call("search_literal", {"side": "head", "query": "v ="})
        self.assertEqual(s.incomplete, "deadline")

    def test_output_cap_exhaustion_is_disclosed(self):
        v = self.view({f"f{i:02d}.py": f"HIT {'x' * 60}\n" for i in range(30)})
        r = ToolSession(v, limits=Limits(max_output_chars=500)).call(
            "search_literal", {"side": "head", "query": "HIT", "limit": 30}).result
        self.assertEqual(r["status"], "partial")
        self.assertLess(len(r["evidence"]), 30)
        self.assertIn("output size cap", r["notice"])
        self.assertEqual(r["truncated"], {"shown": len(r["evidence"]), "total": 30})

    def test_a_clean_complete_empty_search_is_still_empty_exact(self):
        v = self.view(self.many(20))
        r = ToolSession(v, limits=Limits.full_repository()).call("search_literal", {"side": "head", "query": "NOPE_NOT_HERE"}).result
        self.assertEqual((r["status"], r["completeness"], r["truncated"], r["notice"]), ("empty", "exact", None, ""))

    def test_skipped_scope_is_never_a_bare_empty(self):
        files = {"a.bin": b"\x00\x01NEEDLE", "b.py": "other\n", "c.py": b"\xff\xfeNEEDLE"}
        v = self.view(files)
        r = ToolSession(v, limits=Limits.full_repository()).call("search_literal", {"side": "head", "query": "NEEDLE"}).result
        self.assertEqual((r["status"], r["evidence"]), ("partial", []))
        self.assertIn("binary/non-UTF-8 file(s) skipped", r["notice"])

    def test_listing_60k_scale_paths_pages_without_loss(self):
        # synthetic manifest-only scale check (no bytes on disk are read by list_files)
        n = 3000
        files = {f"d{i % 30:02d}/f{i:05d}": "" for i in range(n)}
        v = self.view(files)
        got, pages = self.walk(v, limit=500, limits=Limits(max_calls=100, max_list=500, max_output_chars=10**6, chunk_chars=6000))
        self.assertEqual(got, sorted(files))
        self.assertEqual(len(pages), 6)


class T1Classification(Tree):
    """tools-layer T1: no invented A/D from cross-side full/changed/context disagreement."""

    def pair(self, base_files, head_files):
        self.n += 1
        b, h = self.tmp / f"tb{self.n}", self.tmp / f"th{self.n}"
        for root, f in ((b, base_files), (h, head_files)):
            root.mkdir()
            write_tree(root, f)
        return b, build_manifest(b), h, build_manifest(h)

    def union(self, base_ctx, head_ctx, base_files=None, head_files=None):
        base_files = base_files or {"a.py": "A=1\n", "p.py": "P=1\n"}
        head_files = head_files or {"a.py": "A=2\n", "p.py": "P=1\n"}
        b, mb, h, mh = self.pair(base_files, head_files)
        return partial_union_view((b, mb, base_ctx, set(base_files) - base_ctx),
                                  (h, mh, head_ctx, set(head_files) - head_ctx))

    def rows(self, view):
        r = ToolSession(view).call("diff", {}).result
        return r["evidence"][0]["excerpt"].split("\n")[1:]

    def test_context_on_one_side_changed_on_the_other_is_refused_both_ways(self):
        for bc, hc in (({"p.py"}, set()), (set(), {"p.py"})):
            with self.subTest(base_context=sorted(bc), head_context=sorted(hc)):
                with self.assertRaisesRegex(ViewError, "classified differently"):
                    self.union(bc, hc)

    def test_conflict_in_a_layered_view_is_refused_too(self):
        b, mb, h, mh = self.pair({"p.py": "P=1\n"}, {"p.py": "P=2\n"})
        for bk, hk in (("changed", "context"), ("context", "changed")):
            with self.assertRaises(ViewError):
                View([make_layer("b", bk, b, mb)], [make_layer("h", hk, h, mh)])

    def test_full_against_partial_is_refused(self):
        b, mb, h, mh = self.pair({"p.py": "P=1\n"}, {"p.py": "P=1\n", "new.py": "N\n"})
        for bk, hk in (("full", "changed"), ("changed", "full"), ("full", "context"), ("context", "full")):
            with self.subTest(bk=bk, hk=hk):
                with self.assertRaisesRegex(ViewError, "full snapshot|full layer"):
                    View([make_layer("b", bk, b, mb)], [make_layer("h", hk, h, mh)])

    def test_full_layer_cannot_share_a_side_with_other_layers(self):
        b, mb, h, mh = self.pair({"p.py": "P=1\n"}, {"p.py": "P=1\n"})
        b2, mb2, _, _ = self.pair({"q.py": "Q\n"}, {"q.py": "Q\n"})
        with self.assertRaisesRegex(ViewError, "full layer"):
            View([make_layer("b", "full", b, mb), make_layer("bc", "context", b2, mb2)], [make_layer("h", "full", h, mh)])

    def test_legitimate_one_sided_context_is_not_an_addition_or_deletion(self):
        base = {"a.py": "A=1\n"}
        head = {"a.py": "A=2\n", "ctx.py": "C=1\n"}
        v = self.union(set(), {"ctx.py"}, base, head)
        self.assertEqual(self.rows(v), ["M a.py"])
        v = self.union({"ctx.py"}, set(), {"a.py": "A=1\n", "ctx.py": "C=1\n"}, {"a.py": "A=2\n"})
        self.assertEqual(self.rows(v), ["M a.py"])

    def test_context_on_both_sides_and_real_add_delete_still_work(self):
        v = self.union({"p.py"}, {"p.py"})
        self.assertEqual(self.rows(v), ["M a.py"])
        v = self.union(set(), set(), {"a.py": "1\n", "gone.py": "g\n"}, {"a.py": "1\n", "new.py": "n\n"})
        self.assertEqual(self.rows(v), ["D gone.py", "A new.py"])

    def test_full_against_full_is_unchanged(self):
        b, mb, h, mh = self.pair({"a": "1\n", "gone": "g\n"}, {"a": "2\n", "new": "n\n"})
        v = full_view(b, mb, h, mh)
        self.assertEqual(self.rows(v), ["M a", "D gone", "A new"])

    def test_error_message_carries_no_file_content(self):
        with self.assertRaises(ViewError) as cm:
            self.union({"p.py"}, set(), {"a.py": "A=1\n", "p.py": "SECRET_BODY\n"}, {"a.py": "A=2\n", "p.py": "SECRET_BODY\n"})
        self.assertNotIn("SECRET_BODY", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
