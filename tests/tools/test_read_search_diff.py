import json
import os
import unittest
from unittest import mock

from reviewer.contracts import validate
from reviewer.contracts.canonical import tool_call_id
from reviewer.contracts.snapshot import SnapshotError, excerpt_matches, build_manifest, read_verified
from reviewer.tools import Limits, ToolSession, ops
from .helpers import KEY, TOKEN, Env, write_tree

BIG = "".join(f"line {i}\n" for i in range(1, 1001))


def ev_text(call):
    return "\n".join(e["excerpt"] for e in call.result["evidence"])


class Read(Env):
    BASE_FILES = {"src/a.py": "a = 1\nb = 2\nc = 3\n", "big.txt": BIG, "wide.txt": "ok\n" + "x" * 3000 + "\nafter\n",
                  "bin.dat": b"\x00\x01\x02binary", "latin.txt": b"caf\xe9\n",
                  "crlf.txt": "one\r\ntwo\r\n", "empty.txt": ""}
    HEAD_FILES = BASE_FILES

    def read(self, path, **kw):
        return self.session().call("read_file", {"side": "head", "path": path, **kw})

    def test_exact_pinned_lines_with_provenance_and_resolution(self):
        c = self.read("src/a.py", start_line=2, end_line=3)
        r = c.result
        self.assertEqual(r["status"], "ok")
        self.assertEqual(validate("ToolResult", r), [])
        (e,) = r["evidence"]
        self.assertEqual((e["path"], e["lines"], e["excerpt"], e["resolved"], e["kind"]),
                         ("src/a.py", [2, 3], "b = 2\nc = 3", True, "code"))
        self.assertEqual(e["commit"], self.view.layers("head")[0].snapshot_id)
        self.assertEqual(e["toolCallId"], c.tool_call_id)
        self.assertIn("src/a.py lines 2-3 of 3", r["notice"])
        # independent oracle: the contracts' own citation check agrees
        data = read_verified(self.head, self.view.layers("head")[0].manifest, "src/a.py")
        self.assertTrue(excerpt_matches(data, e["lines"], e["excerpt"]))

    def test_resolved_is_set_only_by_the_resolver(self):
        with mock.patch.object(ops.View, "resolver", lambda self: (lambda ev: False)):
            c = self.read("src/a.py")
        self.assertEqual(c.result["status"], "error")
        self.assertEqual(c.result["evidence"], [])
        self.assertTrue(all("resolved" not in e for e in c.result["evidence"]))
        with mock.patch.object(ops.View, "resolver", lambda self: (lambda ev: 1)):   # truthy is not True
            self.assertEqual(self.read("src/a.py").result["status"], "error")

    def test_ranges_clamp_and_report_past_end(self):
        c = self.read("src/a.py", start_line=2, end_line=99)
        self.assertEqual(c.result["evidence"][0]["lines"], [2, 3])
        self.assertEqual(self.read("src/a.py", start_line=4).result["status"], "empty")
        self.assertEqual(self.read("empty.txt").result["status"], "empty")
        self.assertEqual(self.read("crlf.txt").result["evidence"][0]["lines"], [1, 2])

    def test_line_and_output_caps_are_reported_not_hidden(self):
        c = self.session(limits=Limits(chunk_chars=500)).call("read_file", {"side": "head", "path": "big.txt"})
        r = c.result                                              # no end_line: whole file requested
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["truncated"], {"shown": 400, "total": 1000})
        self.assertEqual(r["evidence"][-1]["lines"][1], 400)
        self.assertTrue(all(len(e["excerpt"]) <= 520 for e in r["evidence"]))
        self.assertTrue(len(r["evidence"]) >= 2)                  # chunked
        lo = [e["lines"] for e in r["evidence"]]
        self.assertEqual(lo[0][0], 1)
        for a, b in zip(lo, lo[1:]):
            self.assertEqual(b[0], a[1] + 1)                      # contiguous, no gap
        small = self.session(limits=Limits(max_output_chars=500)).call("read_file", {"side": "head", "path": "big.txt"})
        self.assertLessEqual(sum(len(e["excerpt"]) + 1 for e in small.result["evidence"]), 500 + 6)
        self.assertEqual(small.result["status"], "partial")
        self.assertIn("Output cap", small.result["notice"])

    def test_overlong_lines_are_omitted_explicitly(self):
        r = self.read("wide.txt").result
        self.assertEqual(r["status"], "partial")
        self.assertEqual([e["lines"] for e in r["evidence"]], [[1, 1], [3, 3]])
        self.assertIn("longer than", r["notice"])

    def test_binary_non_utf8_and_oversize_are_unavailable(self):
        for p in ("bin.dat", "latin.txt"):
            self.assertEqual(self.read(p).result["status"], "unavailable", p)
        s = self.session(limits=Limits(max_file_bytes=100))
        self.assertEqual(s.call("read_file", {"side": "head", "path": "big.txt"}).result["status"], "unavailable")

    def test_vcs_internals_and_invalid_paths_are_denied_without_hints(self):
        write_tree(self.head, {".git/config": "[core]\n"})
        view = type(self.view)(self.view.layers("base"), [__import__("reviewer.tools", fromlist=["x"]).make_layer(
            "h", "full", self.head, build_manifest(self.head))])
        s = ToolSession(view)
        outs = [s.call("read_file", {"side": "head", "path": p}).result for p in
                (".git/config", "nonexistent/.git/x", "../etc/passwd", "/etc/passwd", "a\\b")]
        self.assertTrue(all(o["status"] == "denied" and o["evidence"] == [] for o in outs))
        self.assertEqual(len({o["notice"] for o in outs[:2]}), 1)         # same answer: no existence oracle


class Secrets(Env):
    BASE_FILES = {"a.py": f"x = 1\nk = '{TOKEN}'\n{KEY}\nz = 3\n", ".env.example": f"API_TOKEN=\"{TOKEN}\"\n"}
    HEAD_FILES = BASE_FILES

    def test_secrets_are_redacted_and_line_numbers_hold(self):
        s = self.session()
        c = s.call("read_file", {"side": "head", "path": "a.py"})
        text = ev_text(c)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn("MIIBOgIBAAJB", text)
        self.assertIn("[REDACTED:", text)
        self.assertTrue(c.redactions)
        self.assertEqual(validate("ToolResult", c.result), [])
        last = [e for e in c.result["evidence"]][-1]
        self.assertEqual(last["excerpt"].split("\n")[-1], "z = 3")
        self.assertEqual(last["lines"][1], 7)                       # the 4-line key block kept its 4 lines

    def test_env_example_is_readable_but_redacted(self):
        c = self.session().call("read_file", {"side": "head", "path": ".env.example"})
        self.assertEqual(c.result["status"], "ok")
        self.assertNotIn(TOKEN, ev_text(c))

    def test_secret_cannot_be_found_by_search_or_named_in_arguments(self):
        s = self.session()
        c = s.call("search_literal", {"side": "head", "query": TOKEN})
        self.assertEqual(c.result["status"], "denied")
        self.assertNotIn(TOKEN, json.dumps(c.trace_fields()))
        self.assertEqual(s.call("search_literal", {"side": "head", "query": "MIIBOgIBAAJB"}).result["status"], "empty")
        self.assertEqual(s.call("search_literal", {"side": "head", "query": "ghp_"}).result["status"], "empty")

    def test_trace_fields_and_logs_never_carry_secrets(self):
        s = self.session()
        for args in ({"side": "head", "path": "a.py"}, {"side": "head", "path": f"{TOKEN}.py"}):
            s.call("read_file", args)
        s.call("diff", {})
        s.call("list_files", {"side": "head"})
        blob = json.dumps([c.trace_fields() for c in s.calls]) + json.dumps(s.log)
        self.assertNotIn(TOKEN, blob)
        self.assertNotIn("MIIBOgIBAAJB", blob)


class Tampering(Env):
    BASE_FILES = {"a.py": "a = 1\nb = 2\n", "b.py": "b = 1\n"}
    HEAD_FILES = BASE_FILES

    def test_content_changed_after_construction_is_caught_on_every_read(self):
        s = self.session()
        self.assertEqual(s.call("read_file", {"side": "head", "path": "a.py"}).result["status"], "ok")
        (self.head / "a.py").write_text("a = 666\nb = 2\n")        # same size, different bytes
        c = s.call("read_file", {"side": "head", "path": "a.py"})
        self.assertEqual((c.result["status"], c.result["evidence"]), ("error", []))
        self.assertTrue(s.tampered)
        self.assertNotIn("666", json.dumps(c.result))
        (self.head / "a.py").write_text("a = 1\nb = 2\n")           # restored: reads work again
        self.assertEqual(s.call("read_file", {"side": "head", "path": "a.py"}).result["status"], "ok")

    def test_every_tool_reverifies_not_just_read(self):
        s = self.session()
        s.call("search_literal", {"side": "head", "query": "a"})
        (self.head / "b.py").write_text("b = X\n")
        c = s.call("search_literal", {"side": "head", "query": "b"})
        self.assertNotIn("b = X", ev_text(c))
        self.assertIn("failed pinned-snapshot verification", c.result["notice"])
        d = s.call("diff", {"path": "b.py"})
        self.assertEqual(d.result["status"], "error")

    def test_file_swapped_for_symlink_or_deleted_or_grown(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("SECRET OUTSIDE\n")
        s = self.session()
        (self.head / "a.py").unlink()
        os.symlink(outside, self.head / "a.py")
        c = s.call("read_file", {"side": "head", "path": "a.py"})
        self.assertEqual(c.result["status"], "error")
        self.assertNotIn("OUTSIDE", json.dumps(c.result))
        (self.head / "a.py").unlink()
        self.assertEqual(s.call("read_file", {"side": "head", "path": "a.py"}).result["status"], "error")
        (self.head / "b.py").write_bytes(b"x" * (2 << 20))
        self.assertEqual(s.call("read_file", {"side": "head", "path": "b.py"}).result["status"], "error")

    def test_race_between_check_and_read_is_not_followed(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("SECRET OUTSIDE\n")
        real = ops.read_verified

        def swap_then_read(root, manifest, path):
            (self.head / path).unlink()
            os.symlink(outside, self.head / path)
            return real(root, manifest, path)
        s = self.session()
        with mock.patch.object(ops, "read_verified", swap_then_read):
            c = s.call("read_file", {"side": "head", "path": "a.py"})
        self.assertEqual(c.result["status"], "error")
        self.assertNotIn("OUTSIDE", json.dumps(c.result))

    def test_symlinks_inside_a_snapshot_are_listed_but_never_read_or_searched(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("SECRET OUTSIDE\n")
        os.symlink(outside, self.head / "link.txt")
        os.symlink("a.py", self.head / "alias.py")
        from reviewer.tools import full_view
        view = full_view(self.base, build_manifest(self.base), self.head, build_manifest(self.head))
        s = ToolSession(view)
        listing = ev_text(s.call("list_files", {"side": "head"}))
        self.assertIn("link.txt  [symlink, not readable]", listing)
        for p in ("link.txt", "alias.py"):
            self.assertEqual(s.call("read_file", {"side": "head", "path": p}).result["status"], "denied")
        c = s.call("search_literal", {"side": "head", "query": "OUTSIDE"})
        self.assertEqual(c.result["evidence"], [])
        self.assertEqual(c.result["status"], "partial")           # TR4c: unsearched links are disclosed
        self.assertIn("2 symlink(s)", c.result["notice"])
        self.assertNotIn("OUTSIDE", listing)

    def test_unlisted_files_on_disk_are_invisible(self):
        (self.head / "extra.py").write_text("x = 'planted'\n")
        s = self.session()
        self.assertNotIn("extra.py", ev_text(s.call("list_files", {"side": "head"})))
        self.assertEqual(s.call("read_file", {"side": "head", "path": "extra.py"}).result["status"], "unavailable")
        self.assertEqual(s.call("search_literal", {"side": "head", "query": "planted"}).result["status"], "empty")


class Search(Env):
    BASE_FILES = {"a.py": "x = foo.bar(1)\nFOO\n", "z.py": "foo\n"}
    HEAD_FILES = {"a.py": "x = foo.bar(1)\nFOO\nre = '.*'\n", "m/b.py": "Foo\nfoo\nfoo\n", "z.py": "foo\n",
                  "bin.bin": b"\x00foo", "long.txt": "foo" + "y" * 3000 + "\n"}

    def go(self, **kw):
        return self.session(limits=kw.pop("limits", Limits())).call("search_literal", {"side": "head", **kw})

    def test_query_is_a_literal_not_a_pattern(self):
        c = self.go(query=".*")
        self.assertEqual([e["excerpt"] for e in c.result["evidence"]], ["re = '.*'"])
        self.assertEqual(self.go(query="foo.bar(").result["evidence"][0]["lines"], [1, 1])
        self.assertEqual(self.go(query="f.o", prefix="a.py").result["status"], "empty")
        self.assertEqual(self.go(query="(?s).*", prefix="a.py").result["status"], "empty")

    def test_case_sensitivity_flag_and_deterministic_order(self):
        r1 = self.go(query="foo").result
        got = [(e["path"], e["lines"][0]) for e in r1["evidence"]]
        self.assertEqual(got, [("a.py", 1), ("m/b.py", 2), ("m/b.py", 3), ("z.py", 1)])
        r2 = self.go(query="foo", case_sensitive=False).result
        self.assertEqual([(e["path"], e["lines"][0]) for e in r2["evidence"]],
                         [("a.py", 1), ("a.py", 2), ("m/b.py", 1), ("m/b.py", 2), ("m/b.py", 3), ("z.py", 1)])
        self.assertEqual(self.go(query="foo").result, r1)             # repeatable

    def test_every_match_is_exact_pinned_and_resolved(self):
        for e in self.go(query="foo").result["evidence"]:
            self.assertTrue(e["resolved"])
            self.assertEqual(validate("Evidence", e), [])
            self.assertEqual(e["lines"][0], e["lines"][1])

    def test_prefix_restricts_and_unknown_prefix_is_empty(self):
        self.assertEqual({e["path"] for e in self.go(query="foo", prefix="m").result["evidence"]}, {"m/b.py"})
        self.assertEqual(self.go(query="foo", prefix="m/b.py").result["status"], "ok")
        self.assertEqual(self.go(query="foo", prefix="nope").result["status"], "empty")
        self.assertEqual(self.go(query="foo", prefix="..").result["status"], "denied")

    def test_result_and_per_file_caps_say_they_stopped(self):
        r = self.go(query="foo", limit=2).result
        self.assertEqual(len(r["evidence"]), 2)
        self.assertEqual(r["status"], "partial")
        self.assertIn("result cap", r["notice"])
        self.assertEqual(r["completeness"], "approximate")
        r = self.go(query="foo", limits=Limits(max_matches_per_file=1)).result
        self.assertEqual(len([e for e in r["evidence"] if e["path"] == "m/b.py"]), 1)

    def test_file_and_scan_byte_caps(self):
        r = self.go(query="foo", limits=Limits(max_search_files=1)).result
        self.assertIn("file cap", r["notice"])
        self.assertEqual(r["status"], "partial")
        r = self.go(query="foo", limits=Limits(max_search_scan_bytes=20)).result
        self.assertIn("byte cap", r["notice"])

    def test_binary_oversize_and_overlong_matches_are_counted_not_shown(self):
        r = self.go(query="foo").result
        self.assertEqual(r["status"], "partial")
        self.assertIn("binary/non-UTF-8", r["notice"])
        self.assertIn("longer than", r["notice"])
        self.assertNotIn("yyyy", json.dumps(r))
        r = self.go(query="foo", limits=Limits(max_file_bytes=15)).result
        self.assertIn("oversized", r["notice"])

    def test_output_cap_limits_model_visible_text(self):
        r = self.go(query="foo", case_sensitive=False, limits=Limits(max_output_chars=30)).result
        self.assertLessEqual(sum(len(e["excerpt"]) + len(e["path"]) for e in r["evidence"]), 30)
        self.assertIn("incomplete", r["notice"])

    def test_query_validation(self):
        s = self.session()
        for q in ("", "x" * 201, "a\nb", "a\x00b", "a\tb\x1b", None, 5, TOKEN):
            c = s.call("search_literal", {"side": "head", "query": q})
            self.assertEqual(c.result["status"], "denied", repr(q))

    def test_deadline_stops_search_and_marks_the_session(self):
        from .helpers import Clock
        clock = Clock(step=1.0)
        s = self.session(limits=Limits(wall_s=5.0), clock=clock)
        c = s.call("search_literal", {"side": "head", "query": "foo", "case_sensitive": False})
        self.assertEqual(s.incomplete, "deadline")
        self.assertEqual(c.incomplete, "deadline")
        self.assertIn("deadline", c.result["notice"])


class Diff(Env):
    def test_changed_path_list(self):
        r = self.session().call("diff", {}).result
        rows = r["evidence"][0]["excerpt"].split("\n")[1:]
        self.assertEqual(rows, ["D src/gone.py", "M src/app.py", "A src/new.py"][:0] or sorted(rows, key=lambda x: x[2:]))
        self.assertEqual(set(rows), {"D src/gone.py", "M src/app.py", "A src/new.py"})
        self.assertEqual(r["completeness"], "exact")

    def test_path_diff_is_a_redacted_unified_diff_with_both_snapshots(self):
        c = self.session().call("diff", {"path": "src/app.py"})
        text = ev_text(c)
        self.assertIn("-    return 1", text)
        self.assertIn("+    return 2", text)
        self.assertIn("--- base/src/app.py", text)
        base, head = (self.view.layers(s)[0].snapshot_id[:24] for s in ("base", "head"))
        self.assertIn(base, text)
        self.assertIn(head, text)
        self.assertEqual(validate("ToolResult", c.result), [])

    def test_added_removed_identical_and_missing(self):
        s = self.session()
        self.assertIn("+y = 2", ev_text(s.call("diff", {"path": "src/new.py"})))
        self.assertIn("-x = 1", ev_text(s.call("diff", {"path": "src/gone.py"})))
        self.assertEqual(s.call("diff", {"path": "README.md"}).result["status"], "empty")
        self.assertEqual(s.call("diff", {"path": "nope.py"}).result["status"], "unavailable")
        self.assertEqual(s.call("diff", {"path": ".git/config"}).result["status"], "denied")

    def test_diff_cap(self):
        write_tree(self.head, {"many.txt": "".join(f"h{i}\n" for i in range(3000))})
        write_tree(self.base, {"many.txt": "".join(f"b{i}\n" for i in range(3000))})
        from reviewer.tools import full_view
        view = full_view(self.base, build_manifest(self.base), self.head, build_manifest(self.head))
        r = ToolSession(view, limits=Limits(max_diff_lines=50, max_diff_input_lines=10_000)).call("diff", {"path": "many.txt"}).result
        self.assertEqual(r["status"], "partial")
        self.assertIn("not shown", r["notice"])

    def test_context_file_on_one_side_cannot_be_called_added_or_removed(self):
        from reviewer.tools import View, make_layer
        ctx = self.tmp / "ctxroot"
        write_tree(ctx, {"util.py": "u = 1\n"})
        view = View([make_layer("b", "changed", self.base, build_manifest(self.base))],
                    [make_layer("h", "changed", self.head, build_manifest(self.head)),
                     make_layer("hc", "context", ctx, build_manifest(ctx))])
        # util.py exists only as head context: its absence from base is unknown
        s = ToolSession(view)
        c = s.call("diff", {"path": "util.py"})
        self.assertEqual(c.result["status"], "unavailable")
        self.assertIn("context", c.result["notice"])
        self.assertNotIn("util.py", ev_text(s.call("diff", {})))


if __name__ == "__main__":
    unittest.main()
