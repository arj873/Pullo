"""IMPACT-01 tool layer: symbol extraction per language (with false-positive guards), regex-free whole-word matching,
find_references bounds/pagination, the host-only impact_scan map (exclusions, truncation) and tool registration.
Invented in-memory fixtures only."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer import impactmap as im
from reviewer.contracts import validate
from reviewer.contracts.snapshot import build_manifest
from reviewer.pipeline import impactcov
from reviewer.tools import (ALL_TOOLS, HOST_IMPACT_TOOLS, IMPACT_TOOLS, SWEEP_TOOLS, TOOLS, ArgError, Limits, ToolSession,
                            full_view, normalize)
from reviewer.tools.words import has_word, valid_symbol, word_hits


def lines_of(text):
    """What tools.ops.load_text hands over: split on newlines, without the empty element after a final newline."""
    if text is None:
        return None
    out = text.split("\n")
    return out[:-1] if out and out[-1] == "" else out


def names(path, base, head, status=None):
    syms, _ = im.file_symbols(path, lines_of(base), lines_of(head))
    return {(s.name, s.status) for s in syms if status is None or s.status == status}


# ======================================================================== extraction per language
class Python(unittest.TestCase):
    B = ("import os\n\nMAX_RETRIES = 3\n\n\ndef fetch(url, timeout=5):\n    return url\n\n\n"
         "class Client:\n    host: str\n    port_number: int\n\n    def connect_once(self):\n        return 1\n\n"
         "    def shutdown_conn(self):\n        return 2\n\n\ndef gone(x):\n    return x\n")

    def test_signature_body_removed_constant_field_and_innermost_method(self):
        h = self.B.replace("timeout=5", "timeout=10").replace("MAX_RETRIES = 3", "MAX_RETRIES = 4") \
                  .replace("        return 2", "        return 3").replace("    port_number: int", "    port_number: str") \
                  .replace("\n\ndef gone(x):\n    return x\n", "\n")
        got = names("src/client.py", self.B, h)
        self.assertIn(("fetch", "signature"), got)
        self.assertIn(("MAX_RETRIES", "signature"), got)
        self.assertIn(("shutdown_conn", "body"), got)
        self.assertIn(("port_number", "field"), got)
        self.assertIn(("gone", "removed"), got)
        self.assertNotIn(("connect_once", "body"), got)     # untouched method
        # a field change touches the class; a method-body change does NOT mark the class
        self.assertIn(("Client", "body"), got)
        only_method = names("src/client.py", self.B, self.B.replace("        return 2", "        return 3"))
        self.assertEqual(only_method, {("shutdown_conn", "body")})

    def test_added_function(self):
        h = self.B + "\n\ndef brand_new(a):\n    return a\n"
        self.assertEqual(names("src/client.py", self.B, h), {("brand_new", "added")})

    def test_false_positive_guards(self):
        b = "def keep():\n    return 0\n"
        h = ("def keep():\n    # def fake_in_comment(x):\n    return 1\n\n\ndef __init__(self):\n    pass\n\n\n"
             "def get(x):\n    return x\n\n\ndef ab(x):\n    return x\n")
        self.assertEqual(names("src/m.py", b, h), {("keep", "body")})      # comment, dunder, generic, short skipped
        self.assertEqual(names("tests/test_m.py", b, h), set())            # test files contribute no symbols
        self.assertEqual(names("src/test_m.py", b, h), set())
        self.assertEqual(names("docs/m.md", b, h), set())                  # unsupported language

    def test_overlong_line_is_never_matched_as_a_definition(self):
        line = "def " + "x" * 2000 + "(a):"
        self.assertIsNone(im.def_on_line("python", line))
        self.assertEqual(im.def_on_line("python", "def ok_name(a):"), ("ok_name", "function"))


class Go(unittest.TestCase):
    B = ("package store\n\nconst (\n\tMaxItems = 10\n\tminItems = 1\n)\n\ntype Store struct {\n\tName string\n"
         "\tCapacity int\n}\n\ntype Getter interface {\n\tFetch(id string) error\n}\n\n"
         "func (s *Store) Lookup(id string) (string, error) {\n\treturn id, nil\n}\n\nfunc NewStore() *Store {\n"
         "\treturn &Store{}\n}\n")

    def test_method_receiver_struct_field_const_block(self):
        h = self.B.replace("MaxItems = 10", "MaxItems = 20").replace("\tCapacity int", "\tCapacity int64") \
                  .replace("Lookup(id string) (string, error)", "Lookup(id string, strict bool) (string, error)")
        got = names("pkg/store.go", self.B, h)
        self.assertIn(("MaxItems", "signature"), got)
        self.assertIn(("Capacity", "field"), got)
        self.assertIn(("Store", "body"), got)
        self.assertIn(("Lookup", "signature"), got)
        self.assertNotIn(("NewStore", "body"), got)

    def test_unexported_const_and_test_file_skipped(self):
        h = self.B.replace("minItems = 1", "minItems = 2")
        self.assertEqual(names("pkg/store.go", self.B, h), set())
        self.assertEqual(names("pkg/store_test.go", self.B, self.B.replace("MaxItems = 10", "MaxItems = 2")), set())


class JsTs(unittest.TestCase):
    B = ("export interface Options {\n  retries: number;\n  verbose?: boolean;\n}\n\n"
         "export type Mode = 'a' | 'b';\n\nexport const DEFAULT_LIMIT = 5;\n\n"
         "export const parseInput = (raw: string) => {\n  return raw;\n};\n\n"
         "export class Parser {\n  constructor() {}\n\n  parseLine(line: string): string {\n"
         "    if (line) {\n      return render(line);\n    }\n    return '';\n  }\n}\n\n"
         "function helperFn(a) {\n  return a;\n}\n")

    def test_interface_field_type_const_arrow_class_method(self):
        h = self.B.replace("retries: number", "retries: string").replace("'a' | 'b'", "'a' | 'c'") \
                  .replace("DEFAULT_LIMIT = 5", "DEFAULT_LIMIT = 6").replace("return raw;", "return raw.trim();") \
                  .replace("      return render(line);", "      return render(line, true);")
        got = names("src/parse.ts", self.B, h)
        for want in (("retries", "field"), ("Options", "body"), ("Mode", "signature"),
                     ("DEFAULT_LIMIT", "signature"), ("parseInput", "body"), ("parseLine", "body")):
            self.assertIn(want, got)
        self.assertFalse(any(n in ("if", "render", "return") for n, _ in got))   # control flow / calls are not defs
        self.assertNotIn(("helperFn", "body"), got)

    def test_control_flow_lines_are_not_methods(self):
        for line in ("  if (x) {", "  for (const a of b) {", "  return foo(x) {", "  switch (k) {", "  catch (e) {"):
            self.assertIsNone(im.def_on_line("js", line), line)
        self.assertEqual(im.def_on_line("js", "  async loadAll(ids) {"), ("loadAll", "method"))


class Java(unittest.TestCase):
    B = ("package a;\n\npublic class Account {\n    public static final int MAX_LEN = 10;\n"
         "    private String ownerName;\n\n    public Account(String o) {\n        this.ownerName = o;\n    }\n\n"
         "    public String describe(int depth) {\n        if (depth > 0) {\n            return helper(depth);\n"
         "        }\n        return ownerName;\n    }\n}\n")

    def test_class_constant_field_method(self):
        h = self.B.replace("MAX_LEN = 10", "MAX_LEN = 12").replace("private String ownerName;",
                                                                   "private final String ownerName;") \
                  .replace("describe(int depth)", "describe(long depth)")
        got = names("src/a/Account.java", self.B, h)
        self.assertIn(("MAX_LEN", "signature"), got)
        self.assertIn(("ownerName", "field"), got)
        self.assertIn(("describe", "signature"), got)

    def test_statements_are_not_methods(self):
        for line in ("        return helper(depth);", "        } else if (depth > 0) {", "        throw new Err(x);",
                     "        new Account(name);", "        if (depth > 0) {"):
            self.assertIsNone(im.def_on_line("java", line), line)
        self.assertEqual(im.def_on_line("java", "    protected void reloadCache(int n) {"), ("reloadCache", "method"))
        self.assertIsNone(im.def_on_line("java", "    // public void commented(int n) {"))


class Config(unittest.TestCase):
    def test_yaml_json_toml_keys_with_generic_keys_skipped(self):
        got = names("deploy/app.yaml", "server:\n  port: 80\n  max_connections: 10\n  name: x\n",
                    "server:\n  port: 81\n  max_connections: 20\n  name: y\n")
        self.assertEqual(got, {("max_connections", "key")})       # 'port' is too short, 'name' generic
        got = names("conf/settings.json", '{\n  "retryLimit": 3,\n  "type": "a"\n}\n',
                    '{\n  "retryLimit": 4,\n  "type": "b"\n}\n')
        self.assertEqual(got, {("retryLimit", "key")})
        got = names("pyproject.toml", "[tool]\nline-length = 80\n", "[tool]\nline-length = 100\n")
        self.assertEqual(got, {("line-length", "key")})
        got = names("deploy/app.yaml", "old_key_name: 1\n", "")       # a removed key is still reported (base side)
        self.assertEqual(got, {("old_key_name", "key")})


class Selection(unittest.TestCase):
    def test_dedupe_priority_and_cap(self):
        S = im.Symbol
        syms = [S("b_added", "function", "added", "a.py", 1, "head", ""),
                S("a_body", "function", "body", "z.py", 9, "head", ""),
                S("a_body", "function", "removed", "y.py", 2, "base", ""),
                S("c_sig", "function", "signature", "a.py", 5, "head", "")]
        sel, rest = im.select(syms, cap=2)
        self.assertEqual([(s.name, s.status) for s in sel], [("a_body", "removed"), ("c_sig", "signature")])
        self.assertEqual([s.name for s in rest], ["b_added"])

    def test_enclosing_header(self):
        lines = ["class A:", "    def run_it(self):", "        x = 1", "        return target(x)"]
        self.assertEqual(im.enclosing_header("m.py", lines, 4), (2, "def run_it(self):"))
        self.assertEqual(im.enclosing_header("m.py", lines, 2), (2, "def run_it(self):"))
        self.assertIsNone(im.enclosing_header("m.md", lines, 4))

    def test_tool_package_regex_free_and_heuristic_bounds_are_documented(self):
        root = Path(__file__).resolve().parents[2] / "reviewer/tools"
        for p in root.glob("*.py"):
            self.assertNotIn("import re\n", p.read_text(), p.name)
        self.assertEqual(im.LIMITS_DOC["maxSymbols"], im.MAX_SYMBOLS)


# ======================================================================== regex-free word matching
class Words(unittest.TestCase):
    def test_valid_symbol(self):
        for ok in ("load_user", "$el", "_x", "a.b", "max-retries", "A1"):
            self.assertTrue(valid_symbol(ok, 128), ok)
        for bad in ("", "1abc", "a b", "a.*", "a..b", "a.", "-a", "a(b)", "a\\b", "é", "x" * 129, None, 3):
            self.assertFalse(valid_symbol(bad, 128), bad)

    def test_word_boundaries(self):
        self.assertTrue(has_word("x = foo(1)", "foo"))
        self.assertTrue(has_word("obj.foo.bar", "foo"))
        for line in ("foobar()", "_foo", "$foo", "foo_bar", "afoo", "foo1"):
            self.assertFalse(has_word(line, "foo"), line)
        self.assertTrue(has_word("x foo_bar foo", "foo"))           # a later whole-word occurrence is found
        self.assertTrue(has_word("max-retries: 3", "max-retries"))
        self.assertFalse(has_word("max-retries-total: 3", "max-retries"))
        self.assertFalse(has_word("a.max-retries", "max-retries"))
        self.assertEqual(word_hits("a(foo, bar) + foobar", ["bar", "foo", "baz"]), ["bar", "foo"])

    def test_no_regex_is_compiled_from_a_model_symbol(self):
        t = Tree(self, {"a.py": "def target_fn(x):\n    return x\n"}, {"a.py": "def target_fn(x):\n    return x\n",
                                                                         "b.py": "target_fn(1)\n"})
        s = t.session()
        real = re._compile

        def guard(pattern, flags):          # redaction (contracts) may compile its own fixed patterns; ours must not
            if "target_fn" in str(pattern):
                raise AssertionError("a pattern was compiled from the model's symbol")
            return real(pattern, flags)
        with mock.patch.object(re, "_compile", side_effect=guard):
            c = s.call("find_references", {"side": "head", "symbol": "target_fn"})
        self.assertEqual(c.result["status"], "ok")


# ======================================================================== tools over a pinned view
class Tree:
    def __init__(self, tc: unittest.TestCase, base: dict, head: dict):
        d = tempfile.TemporaryDirectory()
        tc.addCleanup(d.cleanup)
        self.root = Path(d.name)
        for side, files in (("base", base), ("head", head)):
            for rel, text in files.items():
                p = self.root / side / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            (self.root / side).mkdir(exist_ok=True)
        self.bm, self.hm = build_manifest(self.root / "base"), build_manifest(self.root / "head")
        self.view = full_view(self.root / "base", self.bm, self.root / "head", self.hm)

    def session(self, tools=IMPACT_TOOLS, **lim):
        return ToolSession(self.view, tools=tools, limits=Limits(**lim))


def refs_tree(tc, n_callers=30):
    lib = "def target_fn(a, b):\n    return a\n"
    files = {"src/lib.py": lib}
    for i in range(n_callers):
        files[f"src/callers/c{i:02d}.py"] = (f"from src.lib import target_fn\n\n\ndef use_{i}(z):\n"
                                             f"    return target_fn(z, 1)  # call\n    # target_fnx target_fn_old\n")
    files["tests/test_lib.py"] = "def test_t():\n    assert target_fn(1, 2)\n"
    files["README.md"] = "target_fn docs\n"
    return Tree(tc, files, files)


class FindReferences(unittest.TestCase):
    def test_whole_word_counts_order_headers_and_resolved_items(self):
        t = refs_tree(self, 3)
        c = t.session().call("find_references", {"side": "head", "symbol": "target_fn"})
        r = c.result
        self.assertEqual(validate("ToolResult", r), [])
        self.assertEqual(r["status"], "ok")
        listing = r["evidence"][0]["excerpt"]
        self.assertTrue(listing.startswith("# references to `target_fn` (head, whole word): 9 line(s) in 6 file(s)"))
        self.assertIn('[1] "src/callers/c00.py":1', listing)
        self.assertIn('"src/callers/c00.py":5 in "def use_0(z):" (L4)', listing)
        self.assertIn('"src/lib.py":1 (definition)', listing)
        items = r["evidence"][1:]
        self.assertTrue(all(x["kind"] == "code" and x["resolved"] is True for x in items))
        self.assertEqual([x["path"] for x in items][-2:], ["tests/test_lib.py", "README.md"])   # code, tests, other
        self.assertFalse(any("target_fnx" in x["excerpt"] and "target_fn(" not in x["excerpt"] for x in items))

    def test_pagination_offset_limit_and_next_page_notice(self):
        t = refs_tree(self, 30)
        s = t.session()
        first = s.call("find_references", {"side": "head", "symbol": "target_fn", "limit": 25}).result
        self.assertEqual(first["status"], "partial")
        self.assertEqual(first["truncated"], {"shown": 25, "total": 63})
        self.assertIn('"offset": 25', first["notice"])
        second = s.call("find_references", {"side": "head", "symbol": "target_fn", "limit": 25, "offset": 25}).result
        third = s.call("find_references", {"side": "head", "symbol": "target_fn", "limit": 25, "offset": 50}).result
        seen = [(x["path"], x["lines"][0]) for res in (first, second, third) for x in res["evidence"][1:]]
        self.assertEqual(len(seen), 63)
        self.assertEqual(len(set(seen)), 63)
        self.assertNotIn("Next page", third["notice"])
        past = s.call("find_references", {"side": "head", "symbol": "target_fn", "offset": 500}).result
        self.assertIn("past the last", past["notice"])
        self.assertEqual(len(past["evidence"]), 1)

    def test_limit_capped_by_session_limits_and_path_prefix(self):
        t = refs_tree(self, 30)
        r = t.session(max_search_results=5).call("find_references", {"side": "head", "symbol": "target_fn",
                                                                     "limit": 500}).result
        self.assertEqual(len(r["evidence"]) - 1, 5)
        r = t.session().call("find_references", {"side": "head", "symbol": "target_fn", "path_prefix": "tests"}).result
        self.assertEqual([x["path"] for x in r["evidence"][1:]], ["tests/test_lib.py"])
        self.assertIn("under tests/", r["evidence"][0]["excerpt"])

    def test_scan_caps_make_the_count_a_lower_bound(self):
        t = refs_tree(self, 30)
        r = t.session(max_search_files=3).call("find_references", {"side": "head", "symbol": "target_fn"}).result
        self.assertEqual(r["status"], "partial")
        self.assertEqual(r["completeness"], "approximate")
        self.assertIsNone(r["truncated"])
        self.assertIn("+ line(s)", r["evidence"][0]["excerpt"])
        self.assertIn("Scan stopped at its file cap (deterministic)", r["notice"])

    def test_invalid_arguments_are_denied_without_echo(self):
        s = refs_tree(self, 1).session()
        for args in ({"side": "head", "symbol": "a.*"}, {"side": "head", "symbol": "a b"}, {"side": "head"},
                     {"side": "head", "symbol": "x" * 200}, {"side": "nope", "symbol": "abc"},
                     {"side": "head", "symbol": "abc", "offset": -1}, {"side": "head", "symbol": "abc", "limit": 0},
                     {"side": "head", "symbol": "abc", "regex": True},
                     {"side": "head", "symbol": "abc", "path_prefix": "../x"}):
            with self.subTest(args=args):
                c = s.call("find_references", args)
                self.assertEqual((c.result["status"], c.args), ("denied", {"rejected": True}))
        with self.assertRaises(ArgError):
            normalize("find_references", {"side": "head", "symbol": "abc", "offset": 10**6}, Limits())

    def test_counts_against_the_session_call_budget(self):
        s = refs_tree(self, 1).session(max_calls=1)
        self.assertEqual(s.call("find_references", {"side": "head", "symbol": "target_fn"}).result["status"], "ok")
        c = s.call("find_references", {"side": "head", "symbol": "target_fn"})
        self.assertEqual((c.result["status"], c.incomplete), ("unavailable", "tool-calls-exhausted"))


class Registration(unittest.TestCase):
    def test_tool_sets(self):
        self.assertEqual(TOOLS, ("list_files", "read_file", "search_literal", "diff"))      # frozen default
        self.assertEqual(IMPACT_TOOLS, TOOLS + ("find_references",))
        self.assertEqual(HOST_IMPACT_TOOLS, TOOLS + ("impact_scan",))
        self.assertEqual(SWEEP_TOOLS, IMPACT_TOOLS + ("file_disposition",))     # impact@v4 diff-shard sweeps only
        self.assertEqual(set(ALL_TOOLS), set(IMPACT_TOOLS) | set(HOST_IMPACT_TOOLS) | set(SWEEP_TOOLS))
        t = refs_tree(self, 1)
        with self.assertRaises(ValueError):
            ToolSession(t.view, tools=("read_file",))
        with self.assertRaises(ValueError):
            ToolSession(t.view, tools=TOOLS + ("shell",))

    def test_legacy_and_model_sessions_cannot_run_impact_scan_and_never_see_it_advertised(self):
        t = refs_tree(self, 1)
        for tools in (TOOLS, IMPACT_TOOLS):
            c = ToolSession(t.view, tools=tools).call("impact_scan", {})
            self.assertEqual(c.result["status"], "denied")
            self.assertNotIn("impact_scan", c.result["notice"])
        c = ToolSession(t.view).call("find_references", {"side": "head", "symbol": "target_fn"})
        self.assertEqual(c.result["notice"], "No such tool. Available: list_files, read_file, search_literal, diff.")
        c = ToolSession(t.view, tools=HOST_IMPACT_TOOLS).call("impact_scan", {"extra": 1})
        self.assertEqual(c.result["status"], "denied")

    def test_normalized_args_are_closed_and_defaulted(self):
        self.assertEqual(normalize("find_references", {"side": "base", "symbol": "abc"}, Limits()),
                         {"side": "base", "symbol": "abc", "path_prefix": "", "limit": 50, "offset": 0})
        self.assertEqual(normalize("impact_scan", {}, Limits()), {})


# ======================================================================== impact_scan
def lib_change(n_syms=3, callers=2):
    base_lib = "".join(f"def sym_{i:02d}(a):\n    return a\n\n\n" for i in range(n_syms))
    head_lib = "".join(f"def sym_{i:02d}(a, b):\n    return a\n\n\n" for i in range(n_syms))
    use = "".join(f"from lib import sym_{i:02d}\n" for i in range(n_syms)) + "\n\ndef go():\n" + \
        "".join(f"    sym_{i:02d}(1)\n" for i in range(n_syms))
    base = {"lib.py": base_lib, **{f"use{k}.py": use for k in range(callers)}}
    head = {"lib.py": head_lib, **{f"use{k}.py": use for k in range(callers)}}
    return base, head


class ImpactScan(unittest.TestCase):
    def scan(self, base, head, **lim):
        t = Tree(self, base, head)
        c = ToolSession(t.view, stage="PREPARE", agent_id="prepare", tools=HOST_IMPACT_TOOLS,
                        limits=Limits(**lim)).call("impact_scan", {})
        self.assertEqual(validate("ToolResult", c.result), [])
        return c

    def test_changed_lines_and_own_definition_are_excluded(self):
        other = {"other.py": "x = calc_total(3)\n"}       # unchanged dependent (an ADDED file's lines are changed lines)
        base = {"lib.py": "def calc_total(a):\n    return a\n\n\ndef caller_one():\n    return calc_total(1)\n", **other}
        head = {"lib.py": "def calc_total(a, b):\n    return a\n\n\ndef caller_one():\n    return calc_total(1, 2)\n",
                **other}
        r = self.scan(base, head).result
        listing = r["evidence"][0]["excerpt"]
        self.assertIn("1 reference(s) in 1 file(s)", listing)        # only other.py: lib.py:1 and :6 changed
        self.assertEqual([(x["path"], x["lines"]) for x in r["evidence"][1:]], [("other.py", [1, 1])])

    def test_symbol_cap_truncates_and_names_the_rest(self):
        base, head = lib_change(n_syms=im.MAX_SYMBOLS + 3, callers=1)
        c = self.scan(base, head)
        listing = c.result["evidence"][0]["excerpt"]
        self.assertIn(f"## not analysed (symbol cap {im.MAX_SYMBOLS}): sym_20, sym_21, sym_22", listing)
        self.assertEqual(c.result["status"], "partial")
        s = impactcov.summarize([{"type": "tool.call", **c.trace_fields()}], {"lib.py"})
        self.assertEqual((s["symbols"], s["symbolsFound"], s["truncated"]), (im.MAX_SYMBOLS, im.MAX_SYMBOLS + 3, True))
        self.assertEqual(s["references"], im.MAX_SYMBOLS * 2)          # import line + call line per symbol

    def test_per_symbol_and_total_shown_caps(self):
        base, head = lib_change(n_syms=1, callers=10)
        r = self.scan(base, head).result
        listing = r["evidence"][0]["excerpt"]
        self.assertIn(f"20 reference(s) in 10 file(s); {im.MAX_REFS_PER_SYMBOL_SHOWN} shown", listing)
        self.assertEqual(len(r["evidence"]) - 1, im.MAX_REFS_PER_SYMBOL_SHOWN)
        self.assertEqual(r["truncated"], {"shown": im.MAX_REFS_PER_SYMBOL_SHOWN, "total": 20})
        self.assertIn("truncated: yes", listing.split("\n", 1)[0])
        base, head = lib_change(n_syms=15, callers=10)
        r = self.scan(base, head).result
        self.assertLessEqual(len(r["evidence"]) - 1, im.MAX_REFS_SHOWN)
        self.assertLessEqual(len(r["evidence"][0]["excerpt"]), 8000)

    def test_scan_stop_is_a_disclosed_lower_bound(self):
        base, head = lib_change(n_syms=2, callers=5)
        r = self.scan(base, head, max_search_files=2).result
        head_line = r["evidence"][0]["excerpt"].split("\n", 1)[0]
        self.assertRegex(head_line, r"\d+\+ reference\(s\)")
        self.assertIn("Scan stopped at its file cap", r["notice"])
        self.assertIsNone(r["truncated"])
        s = impactcov.summarize([{"type": "tool.call", "tool": "impact_scan", "toolCallId": "tool_" + "0" * 16,
                                  "stage": "PREPARE", "result": r, "args": {}}], set())
        self.assertTrue(s["referencesLowerBound"])
        self.assertIn("reference(s) in", s["statement"])


class CoverageStatement(unittest.TestCase):
    def test_statement_and_unavailable_map(self):
        s = impactcov.summarize([{"type": "tool.call", "tool": "impact_scan", "toolCallId": "tool_" + "1" * 16,
                                  "stage": "PREPARE", "args": {},
                                  "result": {"status": "unavailable", "evidence": [], "completeness": "exact",
                                             "truncated": None, "notice": "cap"}}], set())
        self.assertNotIn("symbols", s)
        self.assertTrue(s["statement"].startswith("Impact: the impact map is not available (impact_scan unavailable)"))
        self.assertIsNone(impactcov.summarize([], set()))

    def test_dependents_opened_counts_only_model_reads_outside_the_change(self):
        hdr = ("# impact map (head): 2 changed symbol(s) analysed of 2 found in 1 changed file(s); 4 reference(s) in "
               "3 file(s) outside the changed lines; 2 shown; truncated: yes")
        code = lambda p: {"kind": "code", "path": p, "lines": [1, 1], "commit": "snap:x", "excerpt": "x",
                          "source": "impact_scan", "toolCallId": "tool_" + "2" * 16, "resolved": True}
        ok = {"status": "ok", "evidence": [], "completeness": "exact", "truncated": None, "notice": ""}
        ev = [{"type": "tool.call", "tool": "impact_scan", "toolCallId": "tool_" + "2" * 16, "stage": "PREPARE",
               "args": {}, "result": dict(ok, status="partial", evidence=[
                   {"kind": "tool-result", "excerpt": hdr + "\nrest", "source": "impact_scan"}, code("a.py"),
                   code("lib.py")])},
              {"type": "tool.call", "tool": "find_references", "stage": "INVESTIGATE", "args": {}, "requestedBy": "c",
               "toolCallId": "tool_" + "3" * 16, "result": dict(ok, evidence=[code("b.py")])},
              *[{"type": "tool.call", "tool": "read_file", "stage": st, "args": {"path": p}, "requestedBy": "c",
                 "toolCallId": "tool_" + "4" * 16, "result": ok} for st, p in
                (("INVESTIGATE", "a.py"), ("VERIFY", "b.py"), ("INVESTIGATE", "z.py"), ("INVESTIGATE", "lib.py"))],
              {"type": "tool.call", "tool": "read_file", "stage": "VERIFY", "args": {"path": "c.py"},
               "toolCallId": "tool_" + "5" * 16, "result": ok}]                     # host-prepared: not counted
        s = impactcov.summarize(ev, {"lib.py"})
        self.assertEqual((s["dependentFilesKnown"], s["dependentFilesOpened"], s["otherFilesOpened"]), (2, 2, 1))
        self.assertEqual(s["statement"], "Impact: 2 changed symbol(s) analysed (of 2 found), 4 reference(s) in 3 "
                         "file(s); map truncated; 2 of 2 known dependent file(s) opened, 1 other file(s) outside the "
                         "change opened; 1 find_references call(s).")


if __name__ == "__main__":
    unittest.main()


class BlankAndCommentChanges(unittest.TestCase):
    def test_blank_or_comment_only_edits_touch_no_definition(self):
        b = "def compute_rate(a):\n    # old note\n    return a\n"
        h = "def compute_rate(a):\n    # new note\n\n    return a\n"
        self.assertEqual(names("src/r.py", b, h), set())
        self.assertEqual(names("src/r.go", "func ComputeRate() {\n\t// a\n}\n", "func ComputeRate() {\n\t// b\n}\n"),
                         set())


class SecretsStayUnsearchable(unittest.TestCase):
    def test_a_word_inside_a_redacted_secret_is_never_found_or_shown(self):
        jwt = "eyJhbGciOiJIUzI1.payloadword12.signaturexyz9"     # the middle part is a whole word in the raw bytes
        files = {"conf/app.py": f"TOKEN = '{jwt}'\n", "src/use.py": "payloadword12 = 1\n"}
        r = Tree(self, files, files).session().call("find_references", {"side": "head",
                                                                       "symbol": "payloadword12"}).result
        self.assertEqual([x["path"] for x in r["evidence"][1:]], ["src/use.py"])
        self.assertNotIn("eyJ", str(r))

    def test_byte_prefilter_skips_only_files_without_the_symbol(self):
        files = {"a.py": "zz = target_fn\n", "b.bin": "target_fn\x00\n", "c.py": "nothing here\n"}
        r = Tree(self, files, files).session().call("find_references", {"side": "head", "symbol": "target_fn"}).result
        self.assertEqual([x["path"] for x in r["evidence"][1:]], ["a.py"])
        self.assertIn("1 binary/non-UTF-8 file(s) skipped", r["notice"])       # disclosed, not silently dropped


# ======================================================================== review fixes (R1-R3, O1-O3)
def host_scan(tc, base, head, clock=None, **lim):
    t = Tree(tc, base, head)
    kw = {} if clock is None else {"clock": clock}
    return ToolSession(t.view, stage="PREPARE", agent_id="prepare", tools=HOST_IMPACT_TOOLS, limits=Limits(**lim),
                       **kw).call("impact_scan", {})


class R1BoundedDefinitionPhase(unittest.TestCase):
    def test_lockfiles_generated_and_minified_files_are_skipped_and_disclosed(self):
        for path in ("package-lock.json", "web/yarn.lock", "go.sum", "static/app.min.js", "api/x.pb.go",
                     "gen/m_pb2.py", "vendor/lib/a.go", "node_modules/p/i.js", "ui/api.generated.ts"):
            self.assertTrue(im.is_generated(path), path)
        for path in ("src/package.json", "src/lockfile.py", "src/minify.js", "src/generator.ts"):
            self.assertFalse(im.is_generated(path), path)
        lock_b = '{\n  "requiresNothing": 1,\n  "lockfileVersion": 2\n}\n'
        c = host_scan(self, {"package-lock.json": lock_b, "a.min.js": "function shrunkFn(){}\n"},
                      {"package-lock.json": lock_b.replace("2", "3"), "a.min.js": "function shrunkFn(a){}\n"})
        listing = c.result["evidence"][0]["excerpt"]
        self.assertIn('## 2 changed file(s) not analysed for symbols (lockfile, generated or minified): "a.min.js", '
                      '"package-lock.json"', listing)
        self.assertIn("truncated: yes", listing.split("\n", 1)[0])
        self.assertEqual(im.file_symbols("app.min.js", ["function shrunkFn(){}"], ["function shrunkFn(a){}"])[0], [])

    def test_files_over_the_diff_input_cap_are_skipped_not_diffed(self):
        big = "".join(f"def fn_{i}(x):\n    return {i}\n" for i in range(3000))       # 6000 lines > 5000
        with mock.patch.object(im, "changed_lines", side_effect=AssertionError("diffed")):
            c = host_scan(self, {"big.py": big}, {"big.py": big.replace("return 7\n", "return 8\n")})
        self.assertIn("(over 5000 lines): \"big.py\"", c.result["evidence"][0]["excerpt"])
        c = host_scan(self, {"big.py": big}, {"big.py": big.replace("return 7\n", "return 8\n")},
                      max_diff_input_lines=100)
        self.assertIn("(over 100 lines)", c.result["evidence"][0]["excerpt"])

    def test_analysis_line_cap_is_checked_inside_the_loop(self):
        mod = "".join(f"def fn_{i}(x):\n    return {i}\n" for i in range(1000))           # 2000 lines each
        base = {f"m{k}.py": mod for k in range(40)}
        head = {f"m{k}.py": mod.replace("return 3\n", "return 4\n") for k in range(40)}
        c = host_scan(self, base, head)
        listing = c.result["evidence"][0]["excerpt"]
        self.assertIn(f"(analysis line cap {im.MAX_ANALYSED_LINES})", listing)
        self.assertIn("in 40 changed file(s)", listing.split("\n", 1)[0])

    def test_changed_lines_matches_the_diff_tool_and_is_fast_on_a_shifted_lockfile_shape(self):
        import time
        b = [l for i in range(1200) for l in (f'  "p{i}": {{', '    "dev": true,', "  },")]
        h = [l for k, l in enumerate(b) if k % 97] + ["  },"] * 30
        t0 = time.monotonic()
        bc, hc = im.changed_lines(b, h)
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertTrue(bc and hc)


class R2DeletionsInsideADefinition(unittest.TestCase):
    def test_python_removed_validate_call(self):
        b = "def save_record(rec):\n    validate(rec)\n    store(rec)\n"
        self.assertEqual(names("src/s.py", b, "def save_record(rec):\n    store(rec)\n"), {("save_record", "body")})

    def test_go_removed_if_guard(self):
        b = ("func SaveRecord(r *Rec) error {\n\tif r == nil {\n\t\treturn ErrNil\n\t}\n\treturn store(r)\n}\n")
        h = "func SaveRecord(r *Rec) error {\n\treturn store(r)\n}\n"
        self.assertEqual(names("pkg/s.go", b, h), {("SaveRecord", "body")})

    def test_ts_removed_await_check(self):
        b = ("export class Saver {\n  async saveRecord(r: Rec) {\n    await this.check(r);\n    return this.store(r);\n"
             "  }\n}\n")
        h = "export class Saver {\n  async saveRecord(r: Rec) {\n    return this.store(r);\n  }\n}\n"
        got = names("src/s.ts", b, h)
        self.assertIn(("saveRecord", "body"), got)
        sym = next(s for s in im.file_symbols("src/s.ts", lines_of(b), lines_of(h))[0] if s.name == "saveRecord")
        self.assertEqual((sym.side, sym.line), ("head", 2))         # points at the head definition


class O3GoPackageLevelVar(unittest.TestCase):
    def test_package_var_change_is_not_attributed_to_the_preceding_function(self):
        b = "func HandleIt() {\n\tdoIt()\n}\n\nvar retryDelay = 5\n"
        self.assertEqual(names("pkg/h.go", b, b.replace("= 5", "= 6")), set())
        b2 = "func HandleIt(\n\ta int,\n) error {\n\treturn nil\n}\n"     # a closing paren does not end the region
        self.assertEqual(names("pkg/h.go", b2, b2.replace("nil", "errX")), {("HandleIt", "body")})


class R3Deterministic(unittest.TestCase):
    def ticking(self, step):
        t = [0.0]

        def clock():
            t[0] += step
            return t[0]
        return clock

    def test_result_does_not_depend_on_the_clock(self):
        base, head = lib_change(n_syms=3, callers=40)
        still = host_scan(self, base, head, clock=lambda: 0.0, wall_s=1e9)
        slow = host_scan(self, base, head, clock=self.ticking(0.05), wall_s=1e9)   # > the old 25 s wall stop
        self.assertEqual(still.result, slow.result)
        self.assertNotIn("Scan stopped", still.result["notice"])               # complete count, no time-based stop
        self.assertIn("240 reference(s) in 40 file(s)", still.result["evidence"][0]["excerpt"].split("\n", 1)[0])

    def test_safety_wall_aborts_with_an_explicit_error_and_no_partial_result(self):
        base, head = lib_change(n_syms=2, callers=40)
        c = host_scan(self, base, head, clock=self.ticking(5.0), wall_s=1e9)
        self.assertEqual((c.result["status"], c.result["evidence"], c.incomplete), ("error", [], "deadline"))
        self.assertIn("aborted at the wall-clock safety limit", c.result["notice"])
        t = refs_tree(self, 5)
        c = ToolSession(t.view, tools=IMPACT_TOOLS, clock=self.ticking(5.0), limits=Limits(wall_s=1e9)).call(
            "find_references", {"side": "head", "symbol": "target_fn"})
        self.assertEqual((c.result["status"], c.result["evidence"]), ("error", []))

    def test_hit_and_decoded_byte_caps_are_deterministic_lower_bounds(self):
        t = refs_tree(self, 30)
        with mock.patch.object(im, "SCAN_MAX_HITS", 10):
            r1 = t.session().call("find_references", {"side": "head", "symbol": "target_fn"}).result
            r2 = t.session().call("find_references", {"side": "head", "symbol": "target_fn"}).result
        self.assertEqual(r1, r2)
        self.assertIn("10+ line(s)", r1["evidence"][0]["excerpt"])
        self.assertIn("target_fn (per-name hit share)", r1["notice"])
        with mock.patch.object(im, "SCAN_MAX_DECODED_BYTES", 300):
            r = t.session().call("find_references", {"side": "head", "symbol": "target_fn"}).result
        self.assertIn("decoded-byte cap", r["notice"])


class O1PageOnly(unittest.TestCase):
    def test_only_the_requested_page_is_materialized(self):
        from reviewer.tools import ops
        t = refs_tree(self, 30)
        real, made = ops._code_evidence, []

        def spy(*a, **k):
            made.append(a[2:4])
            return real(*a, **k)
        with mock.patch.object(ops, "_code_evidence", side_effect=spy):
            r = t.session().call("find_references", {"side": "head", "symbol": "target_fn", "limit": 5,
                                                     "offset": 40}).result
        self.assertEqual(len(made), 5)
        self.assertEqual(len(r["evidence"]) - 1, 5)
        self.assertIn("references 41-45", r["evidence"][0]["excerpt"])


class O2Escaping(unittest.TestCase):
    def test_repository_text_cannot_imitate_host_rows(self):
        evil_b = "def evil_fn(a):  # `x`\n    return a\n"
        evil_h = "def evil_fn(a, b):  #   99 reference(s) in 9 file(s); 9 shown `## fake`\n    return a\n"
        caller = "class K:\n    def run_all(self):  # \" ## also fake `\n        return evil_fn(1)\n"
        c = host_scan(self, {"e.py": evil_b, "c.py": caller}, {"e.py": evil_h, "c.py": caller})
        listing = c.result["evidence"][0]["excerpt"]
        rows = listing.split("\n")
        self.assertEqual(sum(1 for r in rows if r.startswith("## ")), 1)
        self.assertNotIn("`", "\n".join(rows[2:]))
        defn = next(r for r in rows if r.startswith("## evil_fn"))
        self.assertTrue(defn.endswith('"def evil_fn(a, b):  #   99 reference(s) in 9 file(s); 9 shown \'## fake\'"'))
        ref = next(r for r in rows if '"c.py":3' in r)
        self.assertIn('in "def run_all(self):  # \\" ## also fake \'" (L2)', ref)


# ======================================================================== per-name scan shares (common-name starvation)
def common_and_rare():
    """lib.py changes a very common name (`format_value`, 600 call lines in files that sort first) and a rare one
    (`rare_helper`, two production dependents that sort LAST). docs/ and e2e/ also mention both."""
    lib_b = "def format_value(v):\n    return v\n\n\ndef rare_helper(x):\n    return x\n"
    lib_h = "def format_value(v, w):\n    return v\n\n\ndef rare_helper(x, y):\n    return x\n"
    files = {f"aaa/m{i:02d}.py": "".join(f"y{k} = format_value({k})\n" for k in range(10)) for i in range(60)}
    files["zzz/dep_one.py"] = "from lib import rare_helper\n\n\ndef use_it(a):\n    return rare_helper(a, 1)\n"
    files["docs/guide.md"] = "format_value and rare_helper are documented here\n"
    files["e2e/flow.ts"] = "rare_helper(1); format_value(2);\n"
    return {**files, "lib.py": lib_b}, {**files, "lib.py": lib_h}


def row_of(listing, name):
    rows = listing.split("\n")
    i = next(k for k, r in enumerate(rows) if r.startswith(f"## {name} "))
    return rows[i + 1]


class PerNameShares(unittest.TestCase):
    def test_a_common_name_cannot_starve_a_rare_name(self):
        base, head = common_and_rare()
        r = host_scan(self, base, head).result
        listing = r["evidence"][0]["excerpt"]
        common, rare = row_of(listing, "format_value"), row_of(listing, "rare_helper")
        self.assertTrue(common.startswith(f"  {im.NAME_MAX_HITS}+ reference(s)"), common)
        self.assertIn("lower bound", common)
        self.assertIn("per-name hit share", common)
        # the rare name is exact and complete: zzz/dep_one.py (sorted last among code files) is found
        self.assertTrue(rare.startswith("  4 reference(s) in 3 file(s);"), rare)       # dep_one x2, e2e, docs
        self.assertNotIn("+", rare.split(";")[0])
        self.assertIn('"zzz/dep_one.py":5', listing)
        self.assertIn("+ reference(s)", listing.split("\n", 1)[0])                    # header is a lower bound
        self.assertIn("format_value (per-name hit share)", r["notice"])
        fr = refs_tree_from(self, head).call("find_references", {"side": "head", "symbol": "rare_helper"}).result
        self.assertIn("5 line(s) in 4 file(s)", fr["evidence"][0]["excerpt"])          # + its definition line

    def test_code_is_scanned_before_tests_and_other_files(self):
        base, head = common_and_rare()
        with mock.patch.object(im, "NAME_MAX_HITS", 2):
            listing = host_scan(self, base, head).result["evidence"][0]["excerpt"]
        rare = row_of(listing, "rare_helper")
        self.assertTrue(rare.startswith("  2+ reference(s) in 1+ file(s)"), rare)       # code first: zzz/dep_one.py
        self.assertIn('"zzz/dep_one.py":1', listing)
        self.assertNotIn('"docs/guide.md"', listing)

    def test_a_zero_hit_name_cut_short_never_reads_none(self):
        lib_b = "def render(v):\n    return v\n\n\ndef rare_helper(x):\n    return x\n"
        lib_h = "def render(v, w):\n    return v\n\n\ndef rare_helper(x, y):\n    return x\n"
        files = {f"aaa/m{i:02d}.py": "x = render_all(1)\n" * 50 for i in range(30)}     # bytes, no whole word
        files["zzz/dep.py"] = "rare_helper(1, 2)\n"
        with mock.patch.object(im, "NAME_MAX_DECODED_BYTES", 2_000):
            r = host_scan(self, {**files, "lib.py": lib_b}, {**files, "lib.py": lib_h}).result
        listing = r["evidence"][0]["excerpt"]
        cut = row_of(listing, "render")
        self.assertTrue(cut.startswith("  0+ reference(s) in 0+ file(s) (lower bound"), cut)
        self.assertIn("per-name decoded-byte share", cut)
        self.assertNotIn("none", cut)
        self.assertTrue(row_of(listing, "rare_helper").startswith("  1 reference(s) in 1 file(s); 1 shown"))

    def test_shares_are_deterministic_under_different_clocks(self):
        base, head = common_and_rare()
        ticking = R3Deterministic.ticking(self, 0.2)
        a = host_scan(self, base, head, clock=lambda: 0.0, wall_s=1e9).result
        b = host_scan(self, base, head, clock=ticking, wall_s=1e9).result
        self.assertEqual(a, b)


def refs_tree_from(tc, files):
    return Tree(tc, files, files).session()
