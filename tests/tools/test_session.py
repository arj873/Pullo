import json
import re
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import validate
from reviewer.contracts.canonical import result_hash, tool_call_id
from reviewer.gateway import Recorder
from reviewer.tools import TOOLS, ArgError, Limits, ToolSession, normalize, ops
from .helpers import ROOT, Clock, Env

RUN = "run_" + "0" * 16


class Ids(Env):
    def script(self, s):
        s.call("list_files", {"side": "head"})
        s.call("read_file", {"side": "head", "path": "src/app.py", "end_line": 3})
        s.call("search_literal", {"side": "head", "query": "return"})
        s.call("diff", {})
        return s

    def test_ids_are_deterministic_and_equal_the_contract_recipe(self):
        a, b = self.script(self.session()), self.script(self.session())
        self.assertEqual([c.tool_call_id for c in a.calls], [c.tool_call_id for c in b.calls])
        self.assertEqual([c.result_hash for c in a.calls], [c.result_hash for c in b.calls])
        self.assertEqual(len({c.tool_call_id for c in a.calls}), 4)
        for n, c in enumerate(a.calls):
            self.assertEqual(c.ordinal, n)
            self.assertEqual(c.tool_call_id, tool_call_id("INVESTIGATE", "generalist", n, c.tool, c.args))
            self.assertEqual(c.result_hash, result_hash(c.result))
            for e in c.result["evidence"]:
                self.assertEqual(e["toolCallId"], c.tool_call_id)

    def test_ids_depend_on_agent_stage_ordinal_and_args(self):
        base = self.session().call("diff", {}).tool_call_id
        self.assertNotEqual(base, self.session(agent_id="verifier").call("diff", {}).tool_call_id)
        self.assertNotEqual(base, self.session(stage="VERIFY").call("diff", {}).tool_call_id)
        s = self.session()
        s.call("diff", {})
        self.assertNotEqual(base, s.call("diff", {}).tool_call_id)               # second call, new ordinal

    def test_defaults_do_not_change_identity(self):
        a = self.session().call("read_file", {"side": "head", "path": "README.md"})
        b = self.session().call("read_file", {"side": "head", "path": "README.md", "start_line": 1, "end_line": None})
        self.assertEqual(a.tool_call_id, b.tool_call_id)

    def test_evidence_and_results_are_contract_valid(self):
        for c in self.script(self.session()).calls:
            self.assertEqual(validate("ToolResult", c.result), [], c.tool)
            for e in c.result["evidence"]:
                self.assertEqual(validate("Evidence", e), [])


class RecorderCooperation(Env):
    def test_trace_fields_make_a_valid_tool_call_event_through_the_gateway_recorder(self):
        s = self.session()
        c = s.call("read_file", {"side": "head", "path": "src/app.py"})
        rec = Recorder(RUN)
        ev = rec.append("tool.call", **c.trace_fields())
        self.assertEqual(validate("TraceEvent", ev), [])
        self.assertEqual(ev["resultHash"], result_hash(ev["result"]))
        self.assertEqual(ev["toolCallId"], c.tool_call_id)


class ClosedToolSet(Env):
    def test_only_four_tools_exist(self):
        self.assertEqual(TOOLS, ("list_files", "read_file", "search_literal", "diff"))

    def test_arbitrary_commands_networks_writes_tests_and_posting_never_reach_the_filesystem(self):
        boom = mock.Mock(side_effect=AssertionError("operation ran"))
        with mock.patch.dict(ops.__dict__, {"list_files": boom, "read_file": boom, "search_literal": boom, "diff": boom}), \
             mock.patch.object(ops, "load_text", boom):
            s = ToolSession(self.view)
            for name in ("bash", "shell", "sh", "exec", "run_command", "git", "curl", "fetch_url", "http_get",
                         "write_file", "edit_file", "delete_file", "run_tests", "pytest", "npm", "post_comment",
                         "grep", "regex_search", "find", "cat", "READ_FILE", "read_file ", "", None, 5,
                         "read_file; rm -rf /"):
                c = s.call(name, {"cmd": "rm -rf /", "url": "https://example.com", "path": "x"})
                self.assertEqual(c.result["status"], "denied", repr(name))
                self.assertEqual(c.result["evidence"], [])
                self.assertEqual(c.tool, "unknown-tool")
            boom.assert_not_called()

    def test_arguments_are_a_closed_schema(self):
        s = self.session()
        bad = [("read_file", {"side": "head", "path": "src/app.py", "mode": "w"}),
               ("read_file", {"side": "head", "path": "src/app.py", "url": "https://x.example/a"}),
               ("read_file", {"side": "head", "path": "https://x.example/a"}),
               ("read_file", {"side": "main", "path": "src/app.py"}),
               ("read_file", {"side": "head", "path": "src/app.py", "start_line": 0}),
               ("read_file", {"side": "head", "path": "src/app.py", "start_line": True}),
               ("read_file", {"side": "head", "path": "src/app.py", "start_line": 5, "end_line": 2}),
               ("read_file", {"side": "head", "path": "src/app.py", "start_line": "1"}),
               ("read_file", "src/app.py"), ("read_file", ["x"]),
               ("list_files", {"side": "head", "prefix": "../.."}), ("list_files", {"side": "head", "limit": 0}),
               ("search_literal", {"side": "head", "query": "x", "case_sensitive": "yes"}),
               ("search_literal", {"side": "head", "query": "x", "regex": True}),
               ("diff", {"path": "/etc/passwd"}), ("diff", {"side": "head"})]
        for tool, args in bad:
            with self.subTest(tool=tool, args=args):
                c = s.call(tool, args)
                self.assertEqual(c.result["status"], "denied")
                self.assertEqual(c.args, {"rejected": True})
        self.assertEqual(len(s.calls), len(bad))

    def test_normalize_fills_defaults(self):
        n = normalize("search_literal", {"side": "base", "query": "q"}, Limits())
        self.assertEqual(n, {"side": "base", "query": "q", "prefix": "", "case_sensitive": True, "limit": 50})
        with self.assertRaises(ArgError):
            normalize("diff", {"path": 3}, Limits())

    def test_no_regex_network_process_or_write_code_in_the_tool_package(self):
        banned = [r"\bimport re\b", r"\bfrom re\b", r"re\.(compile|match|search|findall|sub)", "subprocess",
                  "socket", "urllib", "requests", "http.client", "os.system", "os.popen", "shutil",
                  "os.remove", "os.unlink", "os.rename", "os.mkdir", "os.write", "write_text", "write_bytes",
                  r"(?<!os\.)\bopen\(", r"eval\(", r"exec\(", "__import__", "fetch", "importlib"]
        for f in (ROOT / "reviewer/tools").glob("*.py"):
            code = "\n".join(l for l in f.read_text().splitlines() if not l.lstrip().startswith(("#",)))
            code = re.sub(r'""".*?"""', "", code, flags=re.S)
            for pat in banned:
                self.assertIsNone(re.search(pat, code), f"{f.name}: {pat}")
            # os.open is allowed only for read-only, no-follow metadata reads
            for m in re.finditer(r"os\.open\((.*)", code):
                self.assertIn("O_RDONLY", m.group(1), f"{f.name}: {m.group(0)}")
                self.assertTrue(re.search(r"O_NOFOLLOW|flags", m.group(1)), f"{f.name}: {m.group(0)}")
                for w in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"):
                    self.assertNotIn(w, m.group(1), f"{f.name}: {m.group(0)}")


class Caps(Env):
    def test_call_limit_stops_work_and_marks_the_session(self):
        boom = mock.Mock(side_effect=AssertionError("operation ran"))
        s = self.session(limits=Limits(max_calls=2))
        s.call("diff", {})
        s.call("diff", {})
        with mock.patch.dict(ops.__dict__, {"diff": boom}):
            import reviewer.tools.session as sess
            with mock.patch.dict(sess._OPS, {"diff": boom}):
                c = s.call("diff", {})
                c2 = s.call("list_files", {"side": "head"})
        self.assertEqual((c.result["status"], c.incomplete), ("unavailable", "tool-calls-exhausted"))
        self.assertIn("limit", c.result["notice"])
        self.assertEqual(c2.result["evidence"], [])
        self.assertEqual(s.incomplete, "tool-calls-exhausted")
        self.assertEqual(len({x.tool_call_id for x in s.calls}), 4)       # refusals still get unique ids
        boom.assert_not_called()

    def test_wall_clock_limit_before_and_during_a_call(self):
        clock = Clock(t=0.0)
        s = self.session(limits=Limits(wall_s=10.0), clock=clock)
        self.assertEqual(s.call("diff", {}).result["status"], "ok")
        clock.t = 10.0
        c = s.call("read_file", {"side": "head", "path": "README.md"})
        self.assertEqual((c.result["status"], c.incomplete, s.incomplete), ("unavailable", "deadline", "deadline"))
        self.assertEqual(c.result["evidence"], [])

    def test_a_tool_that_raises_is_contained(self):
        import reviewer.tools.session as sess
        s = self.session()
        with mock.patch.dict(sess._OPS, {"diff": mock.Mock(side_effect=RuntimeError("boom " + "ghp_" + "A1b2C3d4" * 5))}):
            c = s.call("diff", {})
        self.assertEqual(c.result["status"], "error")
        self.assertNotIn("boom", json.dumps(c.trace_fields()))

    def test_an_invalid_or_secret_bearing_operation_result_is_withheld(self):
        import reviewer.tools.session as sess
        from .helpers import TOKEN
        leaky = lambda ctx, a: ops.Outcome("ok", [{"kind": "tool-result", "excerpt": TOKEN, "source": "x", "toolCallId": ctx.tcid}])
        s = self.session()
        with mock.patch.dict(sess._OPS, {"diff": leaky}):
            c = s.call("diff", {})
        self.assertEqual(c.result["status"], "error")
        self.assertNotIn(TOKEN, json.dumps(c.trace_fields()))

    def test_session_log_has_ids_and_status_only(self):
        s = self.session()
        s.call("read_file", {"side": "head", "path": "src/app.py"})
        s.call("bash", {"cmd": "id"})
        for rec in s.log:
            self.assertEqual(set(rec), {"ordinal", "tool", "toolCallId", "status", "incomplete"})
        self.assertEqual([r["status"] for r in s.log], ["ok", "denied"])


class Provenance(Env):
    def test_every_call_records_layers_coverage_and_per_read_verification(self):
        c = self.session().call("read_file", {"side": "head", "path": "src/app.py"})
        p = c.provenance
        self.assertEqual(p["side"], "head")
        self.assertEqual(p["layers"], ["head"])
        self.assertTrue(p["manifestVerifiedOnEveryRead"])
        self.assertTrue(p["coverage"]["fullRepositoryCoverage"])
        self.assertEqual(p["coverage"]["layers"]["head"][0]["snapshotId"], self.view.layers("head")[0].snapshot_id)


if __name__ == "__main__":
    unittest.main()
