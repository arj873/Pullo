"""Independent combined gate for S1-18 (per-hop rendered evidence) and S1-19 (copyable Turn-verifier code evidence).
Owned by the S1-18/19 reviewer, not either author. One chain exercises both changes at once: the verifier's final hop
is a repair attempt that copies the displayed five-field originalEvidence items verbatim AND cites its own hop-0 read by
tool-ref, which only hop 1 renders. Oracles are the logged trace and the scripted provider's requests.

Scripted provider on owned synthetic data; no network, no model call, no key.
"""

from __future__ import annotations

import copy
import json
import unittest

from reviewer.contracts import check_finding_provenance, citable_tool_calls, validate, validate_trace
from reviewer.contracts.canonical import request_hash

from tests.evidence_review.test_s115_citation_gate import tref
from tests.pipeline.helpers import (TURN_PLAN, TURN_PROFILE, Rig, entry, events_of, hid, hyp, ifinal, iturn, judge,
                                    model_calls, resp, script, tcid, treq, vfinal, vturn)
from tests.pipeline.test_verifier_evidence_shape import BASE_U, CODE_FIELDS, HEAD_U

READ = treq("read_file", side="head", path="src/util.py", start_line=1, end_line=2)
INV_READ = tcid("INVESTIGATE", "generalist", 0, "read_file", side="head", path="src/util.py", start_line=1, end_line=2)
V_READ = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/util.py", start_line=1, end_line=2)
BAD = entry("VERIFY", "verifier", "verifier", 1, 0, response=resp({"contextRequests": [], "output": {"verdict": "?"}}))


def doc_of(call) -> dict:
    return json.loads(call["request"]["messages"][1]["content"])


class Combined(Rig):
    def setup_chain(self):
        m = self.mini(base=BASE_U, head=HEAD_U)
        h = hyp(m, "src/a.py", 2, evidence=[m.cite("src/a.py", 2), tref(INV_READ, 0)])
        probe, _ = self.record_turn(m, script(iturn(0, [READ]), ifinal(1, h), vturn(0, [READ]),
                                              vfinal(1, m, verdict="uncertain")), eval_id="evr_" + "c1" * 8)
        shown = doc_of([c for c in model_calls(probe, "VERIFY")][0])["originalEvidence"]
        code = [e for e in shown if e["kind"] == "code"]
        return m, h, code

    def run_chain(self, m, h, evidence, eval_id):
        scr = script(iturn(0, [READ]), ifinal(1, h), vturn(0, [READ]), BAD, vfinal(1, m, evidence=evidence, attempt=1),
                     judge({"findingIds": [hid(0, h)], "title": "T", "body": "B"}))
        return self.record_turn(m, scr, eval_id=eval_id)

    def test_repaired_final_hop_cites_copied_code_and_its_hop1_rendered_ref_and_replays(self):
        m, h, code = self.setup_chain()
        self.assertEqual(len(code), 2)
        for e in code:                                               # host-provided entries are exactly ModelEvidence
            self.assertEqual((set(e), validate("ModelEvidence", e)), (CODE_FIELDS, []))
        res, _ = self.run_chain(m, h, copy.deepcopy(code) + [tref(V_READ, 0)], "evr_" + "c2" * 8)
        self.assertEqual((res.status, len(res.findings), len(res.comments), res.drops), ("completed", 1, 1, []))
        events = events_of(res)
        self.assertEqual(validate_trace(events), [])
        self.assertEqual(check_finding_provenance(res.findings[0], events), [])
        hop1 = [c for c in model_calls(res, "VERIFY") if c["request"]["hop"] == 1]
        self.assertEqual([("repairOf" in c, c["attempt"]) for c in hop1], [(False, 0), (True, 1)])
        hop0 = [c for c in model_calls(res, "VERIFY") if c["request"]["hop"] == 0][0]
        self.assertNotIn(V_READ, hop0["request"]["contextResults"])                 # requested by hop 0, shown in hop 1
        for c in hop1:
            self.assertIn(V_READ, citable_tool_calls(c["callId"], events))
            self.assertNotIn(INV_READ, citable_tool_calls(c["callId"], events))
            self.assertNotIn(INV_READ, json.dumps(doc_of(c)["originalEvidence"]))
        rep = self.replay(m, res, eval_id="evr_" + "c3" * 8, profile=TURN_PROFILE, plan=TURN_PLAN)
        self.assertEqual((rep.status, [f["id"] for f in rep.findings]), ("completed", [f["id"] for f in res.findings]))

    def test_rehashed_hop1_omission_unpromotes_the_ref_on_both_attempts(self):
        m, h, code = self.setup_chain()
        res, _ = self.run_chain(m, h, copy.deepcopy(code) + [tref(V_READ, 0)], "evr_" + "c4" * 8)
        events = copy.deepcopy(events_of(res))
        hop1 = [c for c in events if c["type"] == "model.call" and c["stage"] == "VERIFY" and c["request"]["hop"] == 1]
        hits = 0
        for c in hop1:                       # mark the read as budget-omitted in each hop-1 document and re-hash
            d = doc_of(c)
            for group in [d.get("context"), d.get("pinnedContext")] + [x.get("results") for x in d.get("history", [])]:
                for it in group or []:
                    if isinstance(it, dict) and it.get("toolCallId") == V_READ:
                        it["excerpts"], it["excerptsOmitted"], hits = [], "retrieval context budget", hits + 1
            c["request"]["messages"][1]["content"] = json.dumps(d, sort_keys=True, ensure_ascii=False,
                                                                separators=(",", ":"))
            c["requestHash"] = request_hash(c["request"])
        self.assertGreaterEqual(hits, 2)
        for c in hop1:
            self.assertNotIn(V_READ, citable_tool_calls(c["callId"], events))
        self.assertTrue(check_finding_provenance(res.findings[0], events))           # the copied code alone is not
        # enough to keep the recorded tool-ref evidence valid once hop 1 no longer renders it

    def test_injected_tool_call_id_on_a_copied_item_still_fails_the_combined_chain(self):
        m, h, code = self.setup_chain()
        forged = [dict(code[1], toolCallId=INV_READ)] + [tref(V_READ, 0)]
        res, _ = self.run_chain(m, h, forged, "evr_" + "c5" * 8)
        self.assertEqual((res.findings, res.comments), ([], []))
        self.assertEqual([d["reason"] for d in res.drops], ["verifier-failed"])


if __name__ == "__main__":
    unittest.main()
