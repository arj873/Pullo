"""Independent S1-04 gate (reviewer/tools): list_files paging, full-repository limits, honest search scope, tools-layer T1.
Reviewer-owned, offline, stdlib only. No provider, network, target execution or private state.

Conventions as test_tools_review.py: test_CONTROL_* must keep holding, test_LIMIT_* pins a documented limit,
test_NEW*_* is a defect found by this gate (expectedFailure states the DESIRED behaviour, a *_symptom_* test pins what happens today).

Everything here is an ORACLE test: expected pages, orders, counts and ids are computed independently (sorted by UTF-8 bytes, sizes
from the files written, legacy ids recorded from the pre-S1-04 tools at git HEAD), not by calling the code under test twice.

Run: nice -n 19 python3 -W error::ResourceWarning -m unittest discover -s tests/tools_review
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import validate  # noqa: E402
from reviewer.contracts.canonical import tool_call_id  # noqa: E402
from reviewer.contracts.snapshot import build_manifest  # noqa: E402
from reviewer.tools import (Limits, ToolSession, View, ViewError, capture_historical_pins, full_view,  # noqa: E402
                            historical_input_view, make_layer, normalize, partial_union_view, policy)

from tests.tools_review.test_tools_review import Clock, corpus_case, write_tree  # noqa: E402

NEXT = "Next page: list_files "
ROW = re.compile(r"(.*)  \((\d+) bytes\)\Z", re.S)
JSON = json.JSONDecoder()


def rows_of(result: dict) -> list[tuple[str, int]]:
    """(path, size) of every row shown, parsed from the evidence by position (the first line of the first chunk is the header)."""
    out = []
    for i, ev in enumerate(result["evidence"]):
        lines = ev["excerpt"].split("\n")
        for ln in (lines[1:] if i == 0 else lines):
            m = ROW.fullmatch(ln)
            assert m, f"row not in 'path  (N bytes)' form: {ln!r}"
            out.append((m.group(1), int(m.group(2))))
    return out


def cursor_of(result: dict) -> dict | None:
    n = result["notice"]
    if not n.startswith(NEXT):
        return None
    obj, _ = JSON.raw_decode(n[len(NEXT):])
    return obj


class Tmp(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp, self.n = Path(t.name), 0

    def view(self, files, head=None, links=None):
        self.n += 1
        b, h = self.tmp / f"b{self.n}", self.tmp / f"h{self.n}"
        for root, f in ((b, files), (h, files if head is None else head)):
            root.mkdir()
            write_tree(root, f, links if root is h else None)
        return full_view(b, build_manifest(b), h, build_manifest(h))


# ============================================================================================================
# 1. paging
# ============================================================================================================

NAMES = ["a", "a b", "a  (3 bytes)", "a}b", 'q"uote', "{x}", "a-b", "a.b", "a0", "adir/b", "adir/c d/e", "A", "Z", "_", "~t",
         "é", "é", "ñ", "日本/語.txt", "édir/x", "z￿", "z\U00010000", "z\U0001F600", "z",
         "\U0010fffd", " lead", "trail ", "#hash", "# x", "hdir/#", "0", "zdir/é/\U0001F600.py"]
LEGAL = [n for n in NAMES if policy.permitted(n)]
NUMBERED = [f"n/{i:03d}.txt" for i in range(150)]


class PagingOracle(Tmp):
    def tree(self):
        files = {p: f"{p}\n" * (1 + len(p) % 3) for p in LEGAL + NUMBERED}
        self.sizes = {p: len(t.encode()) for p, t in files.items()}
        self.oracle = sorted(files, key=lambda p: p.encode("utf-8"))      # UTF-8 byte order, independent of str comparison
        return self.view(files)

    def test_CONTROL_the_adversarial_names_are_all_legal_and_distinct(self):
        self.assertGreaterEqual(len(LEGAL), len(NAMES) - 1, [n for n in NAMES if n not in LEGAL])
        self.assertEqual(len({n for n in LEGAL}), len(LEGAL))

    def test_CONTROL_every_page_shape_matches_an_independent_oracle_exactly(self):
        view = self.tree()
        # (model limit, max_output_chars, chunk_chars): tiny output and chunk caps force cuts inside a page and between chunks
        for limit, out_cap, chunk in [(1, 24000, 6000), (7, 24000, 6000), (50, 24000, 6000), (500, 24000, 6000),
                                      (500, 330, 6000), (500, 24000, 130), (3, 330, 130), (10000, 400, 200), (None, 600, 100)]:
            with self.subTest(limit=limit, out_cap=out_cap, chunk=chunk):
                s = ToolSession(view, limits=Limits(max_calls=1000, max_output_chars=out_cap, chunk_chars=chunk))
                args = {"side": "head"} | ({} if limit is None else {"limit": limit})
                want_limit = 500 if limit is None else limit
                seen, idx, pages = [], 0, 0
                while True:
                    pages += 1
                    self.assertLessEqual(pages, len(self.oracle) + 1, "no progress: more pages than entries")
                    call = s.call("list_files", args)
                    r = call.result
                    self.assertEqual(validate("ToolResult", r), [])
                    rows = rows_of(r)
                    self.assertEqual([p for p, _ in rows], self.oracle[idx:idx + len(rows)], "repeat, skip or reorder")
                    self.assertTrue(all(self.sizes[p] == n for p, n in rows))
                    self.assertGreaterEqual(len(rows), 1, "a page without progress")
                    seen += [p for p, _ in rows]
                    idx += len(rows)
                    cur = cursor_of(r)
                    if idx < len(self.oracle):
                        self.assertEqual((r["status"], r["completeness"]), ("partial", "approximate"))
                        self.assertEqual(r["truncated"], {"shown": len(rows), "total": len(self.oracle) - (idx - len(rows))})
                        # the cursor is the last row ACTUALLY SHOWN (not the last row selected for the page)
                        self.assertEqual(cur, {"side": "head", "prefix": "", "after": rows[-1][0], "limit": want_limit})
                        args = cur
                    else:
                        self.assertIsNone(cur)
                        self.assertEqual((r["status"], r["truncated"]), ("ok", None))
                        self.assertEqual("Last page." in r["notice"], "after" in args)
                        break
                self.assertEqual(seen, self.oracle)

    def test_CONTROL_a_cursor_may_start_anywhere_and_is_a_strict_lower_bound(self):
        view = self.tree()
        s = ToolSession(view, limits=Limits(max_calls=1000))
        for after in ["", "0", "a", "a-", "adir", "zdir/é", "\U0010fffd", "zzzz", "n/075.txt", "n/075.txt0"]:
            if after and not policy.permitted(after):
                continue
            want = [p for p in self.oracle if after and p.encode() > after.encode()] if after else self.oracle
            r = s.call("list_files", {"side": "head", "limit": 10000, **({"after": after} if after else {})}).result
            self.assertEqual([p for p, _ in rows_of(r)], want[:500], after)
            self.assertEqual(r["status"], "empty" if not want else ("partial" if len(want) > 500 else "ok"), after)

    def test_CONTROL_zero_progress_is_reported_not_skipped_and_not_called_the_end(self):
        long = "m" * 200 + "/" + "n" * 200
        view = self.view({"a.txt": "a\n", "b.txt": "b\n", "zz/" + long: "z\n"})
        tight = ToolSession(view, limits=Limits(max_output_chars=300))
        first = tight.call("list_files", {"side": "head"}).result
        self.assertEqual([p for p, _ in rows_of(first)], ["a.txt", "b.txt"])
        self.assertEqual((first["status"], first["truncated"]), ("partial", {"shown": 2, "total": 3}))
        stuck = tight.call("list_files", cursor_of(first)).result
        self.assertEqual(rows_of(stuck), [])
        self.assertEqual((stuck["status"], stuck["truncated"], stuck["completeness"]), ("partial", {"shown": 0, "total": 1}, "approximate"))
        self.assertIsNone(cursor_of(stuck))
        self.assertNotIn("Last page", stuck["notice"])
        self.assertIn("no continuation", stuck["notice"])
        # it is the cap, not the repository: the same cursor works with a larger cap
        roomy = ToolSession(view).call("list_files", cursor_of(first)).result
        self.assertEqual([p for p, _ in rows_of(roomy)], ["zz/" + long])
        self.assertEqual(roomy["status"], "ok")

    def test_CONTROL_paging_merges_the_layers_of_a_layered_historical_side(self):
        # two layers on the head side (changed + context) whose names interleave; disjoint from base so T1 is satisfied
        self.n += 1
        roots = {}
        for name, files in (("bc", {"b1.py": "1\n", "b9.py": "9\n"}), ("hc", {"a.py": "a\n", "c.py": "c\n", "e.py": "e\n"}),
                            ("hx", {"b.py": "b\n", "d.py": "d\n"})):
            roots[name] = self.tmp / f"{name}{self.n}"
            roots[name].mkdir()
            write_tree(roots[name], files)
        mk = {k: build_manifest(v) for k, v in roots.items()}
        view = View([make_layer("base-changed", "changed", roots["bc"], mk["bc"])],
                    [make_layer("head-changed", "changed", roots["hc"], mk["hc"]), make_layer("head-context", "context", roots["hx"], mk["hx"])])
        s = ToolSession(view, limits=Limits(max_calls=50))
        args, got = {"side": "head", "limit": 2}, []
        while True:
            r = s.call("list_files", args).result
            got += [p for p, _ in rows_of(r)]
            self.assertIn("Partial view", r["notice"])
            self.assertEqual(r["completeness"], "approximate")        # a partial view is never 'exact', even on the last page
            if cursor_of(r) is None:
                break
            args = cursor_of(r)
        self.assertEqual(got, ["a.py", "b.py", "c.py", "d.py", "e.py"])

    def test_NEW1_symptom_a_cursor_bigger_than_the_2000_char_notice_is_cut_mid_json(self):
        r = self.crowded_quote_directory()
        self.assertEqual((r["status"], r["truncated"]), ("partial", {"shown": 5, "total": 30}))
        self.assertEqual(len(r["notice"]), 2000)                       # ToolResult.notice is capped at 2000 characters
        self.assertTrue(r["notice"].startswith(NEXT))
        with self.assertRaises(json.JSONDecodeError):
            JSON.raw_decode(r["notice"][len(NEXT):])                  # the advertised continuation cannot be parsed

    @unittest.expectedFailure
    def test_NEW1_DEFECT_a_truncated_page_always_offers_a_parseable_cursor_or_says_it_cannot(self):
        r = self.crowded_quote_directory()
        try:
            cur = cursor_of(r)
        except json.JSONDecodeError:
            cur = None
        self.assertTrue(cur is not None or "no continuation" in r["notice"], "cut cursor, and no statement that none is offered")

    def crowded_quote_directory(self) -> dict:
        """A hostile repo can name directories with quotes (legal in a path); JSON doubles each one, so a ~510 character
        prefix plus a ~512 character cursor needs > 2000 characters. Needs a model-supplied prefix of that size."""
        pre = '"' * 255 + "/" + '"' * 254
        view = self.view({"x": "x\n"}, head={"x": "x\n", **{f"{pre}/{chr(ord('a') + i)}": "x\n" for i in range(30)}})
        return ToolSession(view).call("list_files", {"side": "head", "prefix": pre, "limit": 5}).result


class Compatibility(Tmp):
    # ids/hashes recorded from the pre-S1-04 tools (git HEAD 8f3befd), stage INVESTIGATE, agent generalist, ordinal = list position
    GOLDEN_IDS = [("list_files", {"side": "head"}, "tool_49c5413734f935ec"),
                  ("list_files", {"side": "base", "prefix": "src", "limit": 7}, "tool_e1af5289ead9d7ba"),
                  ("list_files", {"side": "head", "limit": 500}, "tool_12eba6c83812cdb4"),
                  ("read_file", {"side": "head", "path": "src/a.py"}, "tool_6aae16d743298565"),
                  ("search_literal", {"side": "head", "query": "x"}, "tool_0d0739df109c6cef"),
                  ("diff", {}, "tool_a066c0079f72a775")]

    def test_CONTROL_legacy_calls_keep_the_ids_recorded_before_the_change(self):
        for ordinal, (tool, args, want) in enumerate(self.GOLDEN_IDS):
            norm = normalize(tool, args, Limits())
            self.assertEqual(tool_call_id("INVESTIGATE", "generalist", ordinal, tool, norm), want, (tool, args))
            self.assertNotIn("after", norm)

    def test_CONTROL_after_is_part_of_the_id_only_when_given(self):
        lim = Limits()
        base = normalize("list_files", {"side": "head"}, lim)
        self.assertEqual(normalize("list_files", {"side": "head", "after": ""}, lim), base)
        self.assertEqual(normalize("list_files", {"side": "head", "after": "a"}, lim), base | {"after": "a"})
        ids = {tool_call_id("INVESTIGATE", "generalist", 0, "list_files", normalize("list_files", {"side": "head", **extra}, lim))
               for extra in ({}, {"after": "a"}, {"after": "b"})}
        self.assertEqual(len(ids), 3)

    def test_CONTROL_untruncated_legacy_results_are_byte_identical_and_only_truncated_ones_gain_a_cursor(self):
        files = {"src/a.py": "a = 1\n", "README.md": "# r\n", "old.txt": "x\n"}
        view = self.view(files, head={"src/a.py": "a = 2\n", "src/new.py": "n = 1\n", "README.md": "# r\n"})
        s = ToolSession(view)
        got = [(c.tool_call_id, c.result_hash) for c in (s.call("list_files", {"side": "head"}), s.call("list_files", {"side": "base", "prefix": "src"}),
                                                            s.call("list_files", {"side": "head", "prefix": "nope"}))]
        self.assertEqual(got, [("tool_49c5413734f935ec", "sha256:6b3f127c8f7b8cd7f50b1ba93830fceae79e4eea334da6ba7b14a1eed8a3c87b"),
                               ("tool_8c8e93f9c5292fa6", "sha256:caa259c562664fbc4adb78e61393fc3b0fb096237285e1eb844b71cdec9ec1d3"),
                               ("tool_7fe87aa860bddf11", "sha256:ca4612e4f1b20aca5787e142612d41bba96203325b2631910ab93066c468b81f")])
        cut = s.call("list_files", {"side": "head", "limit": 2})
        self.assertEqual(cut.tool_call_id, "tool_2e7577c6c6366e94")                        # same id as before ...
        self.assertNotEqual(cut.result_hash, "sha256:e46b6c3c3a29a4bb947f81e31129521348ccf72e2799042da6f2b520e5186bd7")   # ... new result bytes
        self.assertTrue(cut.result["notice"].endswith("2 of 3 entries shown."))             # legacy text kept, continuation prepended
        self.assertEqual(cursor_of(cut.result), {"side": "head", "prefix": "", "after": "src/a.py", "limit": 2})

    def test_CONTROL_the_cursor_cannot_probe_paths_the_policy_hides(self):
        shown = {"src/a.py": "a\n", "src/b.py": "b\n"}
        hidden = shown | {".git/config": "g\n", "src/.git/hooks": "h\n", "src/.GIT/x": "x\n"}
        a, b = ToolSession(self.view(shown)), ToolSession(self.view(hidden))
        for args in ({"side": "head"}, {"side": "head", "after": "src/a.py"}, {"side": "head", "prefix": "src", "limit": 1},
                     {"side": "head", "after": "a"}, {"side": "head", "after": "zzz"}):
            self.assertEqual(a.call("list_files", args).result, b.call("list_files", args).result, args)
        for after in (".git/zzz", "src/.git/zzz", "../x", "/abs", "a\\b", "a\x00b", "x" * 513, "ghp_" + "A1b2C3d4" * 5):
            r = b.call("list_files", {"side": "head", "after": after})
            self.assertEqual((r.result["status"], r.result["evidence"], r.args), ("denied", [], {"rejected": True}), after)


# ============================================================================================================
# 2. limits
# ============================================================================================================

class Limits_(Tmp):
    def test_CONTROL_host_overrides_can_only_tighten_and_a_refused_override_leaves_no_trace(self):
        pristine = Limits.full_repository()
        for k, v in [("max_calls", 61), ("wall_s", 301), ("search_wall_s", 90.5), ("search_wall_s", None), ("max_search_files", 60_001),
                     ("max_search_scan_bytes", (256 << 20) + 1), ("max_file_bytes", (1 << 20) + 1), ("max_output_chars", 24_001),
                     ("max_list", 501), ("max_calls", 0), ("max_calls", -1), ("max_calls", float("nan")), ("max_calls", float("inf")),
                     ("max_calls", True), ("max_calls", "5"), ("max_calls", None), ("max_calls", [1]), ("no_such_limit", 1),
                     ("chunk_chars", 6_001), ("max_line_chars", 2_001)]:
            with self.subTest(k=k, v=v), self.assertRaises(ValueError):
                Limits.full_repository(**{k: v})
        for name in ("full_repository", "__class__", "__doc__", "__hash__"):          # attributes that are not limits: refused (TypeError today, not ValueError)
            with self.subTest(name=name), self.assertRaises((ValueError, TypeError)):
                Limits.full_repository(**{name: 1})
        self.assertEqual(Limits.full_repository(), pristine)
        ok = Limits.full_repository(max_calls=60, max_search_files=1, search_wall_s=0.5, max_search_scan_bytes=1)
        self.assertEqual((ok.max_calls, ok.max_search_files, ok.search_wall_s, ok.max_search_scan_bytes), (60, 1, 0.5, 1))
        self.assertEqual((Limits().max_search_files, Limits().max_search_scan_bytes, Limits().search_wall_s, Limits().max_calls), (1000, 16 << 20, None, 50))
        self.assertEqual((pristine.max_calls, pristine.wall_s, pristine.search_wall_s, pristine.max_search_files, pristine.max_search_scan_bytes,
                          pristine.max_file_bytes, pristine.max_output_chars), (60, 300.0, 90.0, 60_000, 256 << 20, 1 << 20, 24_000))

    def test_CONTROL_model_arguments_cannot_enlarge_any_trusted_cap(self):
        files = {f"d/{i:04d}.txt": "needle\n" * 20 for i in range(700)} | {"big.txt": "x" * ((1 << 20) + 1)}
        s = ToolSession(self.view(files), limits=Limits.full_repository(max_calls=6))
        lst = s.call("list_files", {"side": "head", "limit": 10_000}).result
        self.assertEqual(lst["truncated"], {"shown": len(rows_of(lst)), "total": 701})
        self.assertLessEqual(len(rows_of(lst)), 500)
        srch = s.call("search_literal", {"side": "head", "query": "needle", "limit": 1000}).result
        self.assertLessEqual(len(srch["evidence"]), 50)
        rd = s.call("read_file", {"side": "head", "path": "d/0000.txt", "start_line": 1, "end_line": 10 ** 7}).result
        self.assertEqual(rd["status"], "ok")
        too_big = s.call("read_file", {"side": "head", "path": "big.txt"}).result
        self.assertEqual(too_big["status"], "unavailable")
        for kw in ({"max_calls": 10 ** 6}, {"limits": 1}, {"max_list": 10 ** 6}, {"wall_s": 10 ** 9}, {"max_file_bytes": 10 ** 9}):
            r = s.call("list_files", {"side": "head", **kw})
            self.assertEqual((r.result["status"], r.args), ("denied", {"rejected": True}), kw)   # unknown names are refused, never obeyed
        past = s.call("list_files", {"side": "head"})                                          # the 7th call of a 6-call session
        self.assertEqual((past.result["status"], past.incomplete), ("unavailable", "tool-calls-exhausted"))

    def test_CONTROL_search_reaches_past_1000_files_only_under_the_full_profile_and_says_so_otherwise(self):
        n = 2400
        files = {f"src/f{i:04d}.txt": f"line {i}\n" for i in range(n)} | {"zz/last.txt": "NEEDLE_LAST\n"}
        view = self.view(files)
        order = sorted(files)                                               # search visits files in path order
        self.assertEqual(order[-1], "zz/last.txt")
        first_1000_bytes = sum(len(files[p].encode()) for p in order[:1000])
        query = {"side": "head", "query": "NEEDLE_LAST"}
        # legacy profile: honest partial, never empty or ok; exact visited/total/bytes (computed independently)
        legacy = ToolSession(view).call("search_literal", query).result
        self.assertEqual((legacy["status"], legacy["completeness"], legacy["evidence"], legacy["truncated"]), ("partial", "approximate", [], None))
        self.assertIn(f"1000 of {n + 1} candidate file(s) visited, {first_1000_bytes} bytes scanned", legacy["notice"])
        self.assertIn("search file cap", legacy["notice"])
        absent = ToolSession(view).call("search_literal", {"side": "head", "query": "ABSENT_EVERYWHERE"}).result
        self.assertEqual(absent["status"], "partial")                       # a capped search with no hit must not read as 'no such text'
        # narrowing by prefix is the documented way out and is exact
        narrow = ToolSession(view).call("search_literal", query | {"prefix": "zz"}).result
        self.assertEqual((narrow["status"], narrow["completeness"], [e["path"] for e in narrow["evidence"]]), ("ok", "exact", ["zz/last.txt"]))
        # full profile: the same repository is searched completely
        full = ToolSession(view, limits=Limits.full_repository()).call("search_literal", query).result
        self.assertEqual((full["status"], full["completeness"], [e["path"] for e in full["evidence"]]), ("ok", "exact", ["zz/last.txt"]))
        self.assertEqual(full["evidence"][0]["lines"], [1, 1])
        none = ToolSession(view, limits=Limits.full_repository()).call("search_literal", {"side": "head", "query": "ABSENT_EVERYWHERE"}).result
        self.assertEqual((none["status"], none["completeness"], none["evidence"], none["notice"]), ("empty", "exact", [], ""))
        # a host that tightens the profile gets the cap back, with the exact counts
        tight = ToolSession(view, limits=Limits.full_repository(max_search_files=2000)).call("search_literal", query).result
        self.assertEqual((tight["status"], tight["evidence"]), ("partial", []))
        self.assertIn(f"2000 of {n + 1} candidate file(s) visited", tight["notice"])

    def test_CONTROL_every_way_a_search_can_stop_or_skip_is_partial_never_a_bare_empty(self):
        files = {"a.txt": "ok\n", "b.bin": b"\x00\x01needle", "c.txt": "x" * ((1 << 20) + 5), "d.txt": "latin\n", "e.txt": "ok\n"}
        links = {"l.txt": "a.txt"}
        view = self.view(files, links=links)
        s = ToolSession(view, limits=Limits.full_repository())
        r = s.call("search_literal", {"side": "head", "query": "absent"}).result
        self.assertEqual((r["status"], r["completeness"], r["evidence"]), ("partial", "approximate", []))
        self.assertIn("1 oversized and 1 binary/non-UTF-8 file(s) skipped", r["notice"])
        self.assertIn("1 symlink(s) in scope were not searched", r["notice"])
        # deterministic per-search wall: clock advances 1 s per reading
        wall = ToolSession(view, limits=Limits.full_repository(search_wall_s=2.5), clock=Clock(step=1.0)).call(
            "search_literal", {"side": "head", "query": "absent"})
        self.assertEqual((wall.result["status"], wall.incomplete), ("partial", None))        # a per-search stop is not a session deadline
        self.assertIn("search time cap", wall.result["notice"])
        self.assertRegex(wall.result["notice"], r"\d+ of 6 candidate file\(s\) visited")


# ============================================================================================================
# 3. T1 on the direct tools API
# ============================================================================================================

class T1(Tmp):
    def tree(self, name, files):
        self.n += 1
        root = self.tmp / f"{name}{self.n}"
        root.mkdir()
        write_tree(root, files)
        return root, build_manifest(root)

    def union(self, base_ctx, head_ctx, base_body="P=1\n", head_body="P=1\n"):
        rb, mb = self.tree("b", {"a.py": "A=1\n", "p.py": base_body})
        rh, mh = self.tree("h", {"a.py": "A=2\n", "p.py": head_body})
        return partial_union_view((rb, mb, base_ctx, {"a.py"} | ({"p.py"} - base_ctx)),
                                  (rh, mh, head_ctx, {"a.py"} | ({"p.py"} - head_ctx)))

    def test_NEW_T1_every_direct_constructor_refuses_a_cross_side_classification_conflict_for_the_right_reason(self):
        for tag, bc, hc, hb in [("base ctx / head changed", {"p.py"}, set(), "P=1\n"), ("base ctx / head changed, edited", {"p.py"}, set(), "P=2\n"),
                                ("base changed / head ctx", set(), {"p.py"}, "P=1\n"), ("base changed / head ctx, edited", set(), {"p.py"}, "P=2\n")]:
            with self.subTest(via="partial_union_view", case=tag), self.assertRaisesRegex(ViewError, r"1 path\(s\) are classified differently") as cm:
                self.union(bc, hc, head_body=hb)
            self.assertNotIn("p.py", str(cm.exception))                       # names a count and kinds, never a path or content
            self.assertNotIn("P=", str(cm.exception))
        rb, mb = self.tree("b", {"p.py": "P=1\n"})
        rh, mh = self.tree("h", {"p.py": "P=1\n"})
        for kinds in (("context", "changed"), ("changed", "context")):
            with self.subTest(via="View(make_layer)", kinds=kinds), self.assertRaisesRegex(ViewError, "classified differently"):
                View([make_layer("b", kinds[0], rb, mb)], [make_layer("h", kinds[1], rh, mh)])
        with self.subTest(via="layered sides"), self.assertRaisesRegex(ViewError, "classified differently"):
            ra, ma = self.tree("ba", {"a.py": "A=1\n"})
            rc, mc = self.tree("bc", {"q.py": "Q=1\n"})
            rd, md = self.tree("hd", {"a.py": "A=2\n", "q.py": "Q=1\n"})
            View([make_layer("b-ch", "changed", ra, ma), make_layer("b-cx", "context", rc, mc)], [make_layer("h-ch", "changed", rd, md)])

    def test_NEW_T1_full_against_partial_and_mixed_sides_are_refused_before_any_tool_exists(self):
        rb, mb = self.tree("b", {"x.py": "1\n"})
        rh, mh = self.tree("h", {"y.py": "1\n"})
        for base_kind, head_kind in (("full", "changed"), ("changed", "full"), ("full", "context")):
            with self.subTest(sides=f"{base_kind}/{head_kind}"), self.assertRaisesRegex(ViewError, "full snapshot and the other is partial"):
                View([make_layer("b", base_kind, rb, mb)], [make_layer("h", head_kind, rh, mh)])
        rx, mx = self.tree("x", {"z.py": "1\n"})
        for sides in (([("b1", "full", rb, mb), ("b2", "context", rx, mx)], [("h", "full", rh, mh)]),
                      ([("b1", "full", rb, mb), ("b2", "full", rx, mx)], [("h", "full", rh, mh)])):
            with self.subTest("mixed"), self.assertRaisesRegex(ViewError, "full layer cannot be combined"):
                View(*[[make_layer(*layer) for layer in side] for side in sides])

    def test_CONTROL_legitimate_one_sided_and_two_sided_context_stay_valid_and_are_never_added_or_deleted(self):
        rb, mb = self.tree("b", {"a.py": "A=1\n", "only_base_ctx.py": "B=1\n", "both.py": "C=1\n", "gone.py": "G=1\n"})
        rh, mh = self.tree("h", {"a.py": "A=2\n", "only_head_ctx.py": "H=1\n", "both.py": "C=1\n", "new.py": "N=1\n"})
        view = partial_union_view((rb, mb, {"only_base_ctx.py", "both.py"}, {"a.py", "gone.py"}),
                                  (rh, mh, {"only_head_ctx.py", "both.py"}, {"a.py", "new.py"}))
        s = ToolSession(view)
        rows = s.call("diff", {}).result["evidence"][0]["excerpt"].split("\n")[1:]
        self.assertEqual(rows, ["M a.py", "D gone.py", "A new.py"])
        for path in ("only_base_ctx.py", "only_head_ctx.py"):
            d = s.call("diff", {"path": path}).result
            self.assertEqual(d["status"], "unavailable")
            self.assertIn("context loaded on one side only", d["notice"])
            self.assertEqual(s.call("read_file", {"side": "base" if "base" in path else "head", "path": path}).result["status"], "ok")
        self.assertEqual(s.call("diff", {"path": "both.py"}).result["status"], "empty")           # identical context on both sides

    def test_NEW_T1_the_historical_constructor_refuses_the_same_conflicts_and_keeps_one_sided_context(self):
        cases = self.tmp / "cases"
        cases.mkdir()
        for i, (tag, base, head, ctx) in enumerate([("base ctx / head changed", {"a.py": "A=1\n"}, {"a.py": "A=2\n", "p.py": "P=2\n"}, {"base": {"p.py": "P=1\n"}}),
                                                    ("base changed / head ctx", {"a.py": "A=1\n", "p.py": "P=1\n"}, {"a.py": "A=2\n"}, {"head": {"p.py": "P=1\n"}})], 11):
            case = corpus_case(cases, base, head, context=ctx, name=f"o--r--{i}")
            pins = capture_historical_pins(case)
            with self.subTest(tag), self.assertRaisesRegex(ViewError, "classified differently"):
                historical_input_view(case, pins=pins)
        ok = corpus_case(cases, {"a.py": "A=1\n"}, {"a.py": "A=2\n"}, context={"base": {"lib.py": "L=1\n"}, "head": {"lib2.py": "L=2\n"}}, name="o--r--9")
        s = ToolSession(historical_input_view(ok, pins=capture_historical_pins(ok)))
        self.assertEqual(s.call("diff", {}).result["evidence"][0]["excerpt"].split("\n")[1:], ["M a.py"])
        self.assertIn("lib.py", s.call("list_files", {"side": "base"}).result["evidence"][0]["excerpt"])


if __name__ == "__main__":
    unittest.main()
