"""Defects in OTHER modules that the pipeline met. They are reported to their owners in S0-07.md, never patched or
bypassed here. Each test states the behavior the pipeline needs; `expectedFailure` flips to an unexpected success
(a failure) when the owner fixes the module, which is the signal to remove the marker. (The gateway D3 test below
lost its marker when S1-02 fixed it; the tools test above had none.)"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import ToolSession, full_view

from .helpers import Rig, entry, hyp, inv, model_calls, resp, script


class ToolsContractsDefects(unittest.TestCase):
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
    """D3 closed in the gateway (S1-02): kept as a regression so the pipeline never relies on its own re-check."""

    def test_status_ok_answer_that_fails_its_role_schema_gets_the_one_bounded_repair(self):
        m = self.mini()
        broken = entry("INVESTIGATE", "investigator", "generalist", 0, 0, response=resp({"hypotheses": [{"claim": "x"}]}))
        fixed = inv(hyp(m, "src/a.py", 2), attempt=1)
        res, spy = self.record(m, script(broken, fixed))
        invest = model_calls(res, "INVESTIGATE")
        self.assertEqual([(c["attempt"], c.get("repairOf") == invest[0]["callId"]) for c in invest],
                         [(0, False), (1, True)])                      # exactly one repair, admitted as its own attempt
        self.assertEqual(len(res.hypotheses), 1)
        self.assertEqual(res.hypotheses[0]["sourceCallId"], invest[1]["callId"])
        self.assertEqual(res.stages["INVESTIGATE"]["status"], "completed")
