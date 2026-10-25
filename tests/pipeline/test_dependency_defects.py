"""Defects in OTHER modules that the pipeline met. They are reported to their owners in S0-07.md, never patched or
bypassed here. Each test states the behavior the pipeline needs; `expectedFailure` flips to an unexpected success
(a failure) when the owner fixes the module, which is the signal to remove the marker."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import ToolSession, full_view

from .helpers import Rig, entry, hyp, inv, resp, script


class ToolsContractsDefects(unittest.TestCase):
    @unittest.expectedFailure
    def test_read_file_range_ending_on_a_blank_line_is_not_tamper(self):
        # contracts.snapshot.excerpt_matches strips one trailing newline from the excerpt, so the tool's own
        # evidence for lines 1-2 of "a = 1\n\nb = 2\n" ("a = 1\n") never resolves and read_file reports the pinned
        # file as tampered (session.tampered is set).
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            for side in ("base", "head"):
                (d / side).mkdir()
                (d / side / "f.py").write_text("a = 1\n\nb = 2\n\nc = 3\n")
            m = {s: build_manifest(d / s) for s in ("base", "head")}
            s = ToolSession(full_view(d / "base", m["base"], d / "head", m["head"]))
            call = s.call("read_file", {"side": "head", "path": "f.py", "start_line": 1, "end_line": 2})
            self.assertEqual(call.result["status"], "ok")
            self.assertFalse(s.tampered)


class GatewayDefects(Rig):
    @unittest.expectedFailure
    def test_status_ok_answer_that_fails_its_role_schema_gets_the_one_bounded_repair(self):
        # The gateway only repairs status=invalid-output answers; it never validates response.output against
        # request.outputSchema, so a schema-invalid status=ok answer is final (the pipeline reports schema-invalid).
        m = self.mini()
        broken = entry("INVESTIGATE", "investigator", "generalist", 0, 0, response=resp({"hypotheses": [{"claim": "x"}]}))
        fixed = inv(hyp(m, "src/a.py", 2), attempt=1)
        res, spy = self.record(m, script(broken, fixed))
        self.assertEqual(spy.calls, 2)
