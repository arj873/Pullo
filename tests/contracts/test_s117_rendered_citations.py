"""S1-17 author tests: a Turn call may cite only results its chain was shown WITH excerpts (F3 of S1-15-review).

Before: entities._citable unioned every contextResults id, so a result whose excerpts the host request budget or the
in-chain context budget omitted still materialized evidence. "before" is reproduced by patching entities._rendered back
to "every contextResults id is shown". Scripted provider on synthetic data; no network, model or key.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from reviewer.contracts import check_finding_provenance, citable_tool_calls, entities
from reviewer.pipeline import RetrievalPolicy
from reviewer.pipeline import engine as pengine

from tests.evidence_review.test_s115_citation_gate import FEW, tref, turn_pairs
from tests.pipeline.helpers import BASE, EVR2, HEAD, Rig, events_of, hid, hyp, ifinal, iturn, judge, script, treq, vfinal, vturn
from tests.pipeline.test_citable_refs import read, turns


def old_rendered(hop, idx):                         # pre-S1-17 semantics: every listed id counts as shown
    return set(hop["request"].get("contextResults", []))


class RenderedCitations(Rig):
    def case(self, extra=FEW):
        return self.mini("mini-1", base={**BASE, **extra}, head={**HEAD, **extra})

    def host_budget_run(self, cite_diff: bool):
        """Verifier host context: read fits the request budget, diff is omitted. Verifier confirms citing one."""
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        probe, pspy = self.record_turn(m, script(ifinal(0, h), vfinal(0, m, verdict="uncertain")), eval_id=EVR2)
        vdoc = [d for c, d in turn_pairs(probe, pspy) if c["stage"] == "VERIFY"][0]
        read_id, diff_id = [it["toolCallId"] for it in vdoc["pinnedContext"]]
        budget = sum(len(x) for x in vdoc["pinnedContext"][0]["excerpts"])
        scr = script(ifinal(0, h), vturn(0, [treq("read_file", side="head", path="src/util.py")]),
                     vfinal(1, m, evidence=[m.cite("src/a.py", 2), tref(diff_id if cite_diff else read_id)]),
                     judge({"findingIds": [hid(0, h)], "title": "T", "body": "B"}))
        with mock.patch.object(pengine, "CONTEXT_CHARS", budget):
            res, spy = self.record_turn(m, scr)
        return res, spy, read_id, diff_id

    def test_f3_before_host_budget_omitted_result_was_accepted(self):
        with mock.patch.object(entities, "_rendered", old_rendered):
            before, _, _, diff_id = self.host_budget_run(cite_diff=True)
        self.assertEqual(len(before.findings), 1)                                     # F3 reproduced
        self.assertTrue(any(e.get("toolCallId") == diff_id for e in before.findings[0]["verification"]["evidence"]))
        # offline: the finding the old pipeline accepted fails provenance under the fix (strict replay check)
        bad = check_finding_provenance(before.findings[0], events_of(before))
        self.assertTrue(any("not shown to" in i.message for i in bad), bad)

    def test_f3_after_host_budget_omitted_result_is_rejected(self):
        after, spy, read_id, diff_id = self.host_budget_run(cite_diff=True)
        self.assertEqual((after.status, after.findings), ("completed", []))
        self.assertEqual([d["reason"] for d in after.drops], ["invalid-citation"])
        for call, doc in turn_pairs(after, spy):
            if call["stage"] == "VERIFY":
                cit = citable_tool_calls(call["callId"], events_of(after))
                self.assertNotIn(diff_id, cit)
                self.assertIn(read_id, cit)

    def test_rendered_host_result_in_the_same_partial_context_still_confirms(self):
        res, _, read_id, _ = self.host_budget_run(cite_diff=False)
        self.assertEqual((res.status, len(res.findings)), ("completed", 1))
        self.assertTrue(any(e.get("toolCallId") == read_id for e in res.findings[0]["verification"]["evidence"]))
        self.assertEqual(check_finding_provenance(res.findings[0], events_of(res)), [])

    def test_in_chain_budget_omitted_result_is_not_citable(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        probe, pspy = self.record_turn(m, script(iturn(0, [read("src/m1.py", 1, 2)]), ifinal(1, h),
                                                 vfinal(0, m, verdict="uncertain")), eval_id=EVR2)
        shown = RetrievalPolicy().context_chars - turns(probe, pspy, "INVESTIGATE")[0][1]["retrieval"]["contextCharsRemaining"]
        scr = script(iturn(0, [read("src/m1.py", 1, 2)]), ifinal(1, h), vfinal(0, m, verdict="uncertain"))
        res, spy = self.record_turn(m, scr, retrieval=RetrievalPolicy(context_chars=shown + 1))
        tv = turns(res, spy, "INVESTIGATE")
        events = events_of(res)
        omitted = [t["toolCallId"] for t in events if t["type"] == "tool.call" and t.get("requestedBy") == tv[0][0]["callId"]]
        self.assertEqual(tv[1][1]["history"][0]["results"][0].get("excerptsOmitted"), "retrieval context budget")
        self.assertEqual(tv[1][0]["request"]["contextResults"], omitted)              # listed, but not shown
        cit = citable_tool_calls(tv[1][0]["callId"], events)
        self.assertNotIn(omitted[0], cit)
        self.assertTrue(set(tv[0][0]["request"]["contextResults"]) & set(cit))       # rendered host results stay
        with mock.patch.object(entities, "_rendered", old_rendered):
            self.assertIn(omitted[0], citable_tool_calls(tv[1][0]["callId"], events))  # before


class RenderedUnit(unittest.TestCase):
    """_rendered on hand-built hop documents: exact, ordered, complete excerpts only; anything else shows nothing."""

    T = {"toolCallId": "tool_00000000000000a1", "result": {"evidence": [{"excerpt": "a"}, {"excerpt": "b"}]}}
    E = {"toolCallId": "tool_00000000000000e0", "result": {"evidence": []}}

    class Idx:
        def __init__(self, *tools):
            self.t = {t["toolCallId"]: t for t in tools}

        def tool(self, tid):
            return self.t.get(tid)

    def shown(self, content, role="user"):
        hop = {"request": {"messages": [{"role": "system", "content": "s"}, {"role": role, "content": content}]}}
        return entities._rendered(hop, self.Idx(self.T, self.E))

    def doc(self, **kw):
        return json.dumps(kw)

    def test_complete_items_in_context_pinned_context_and_history(self):
        tid = self.T["toolCallId"]
        full = {"toolCallId": tid, "excerpts": ["a", "b"]}
        for d in ({"context": [full]}, {"pinnedContext": [full]}, {"history": [{"results": [full]}]}):
            self.assertEqual(self.shown(json.dumps(d)), {tid}, d)

    def test_omitted_partial_reordered_duplicate_empty_or_unknown_items_show_nothing(self):
        tid = self.T["toolCallId"]
        for it in ({"toolCallId": tid, "excerpts": [], "excerptsOmitted": "retrieval context budget"},
                   {"toolCallId": tid, "excerpts": ["a"]}, {"toolCallId": tid, "excerpts": ["b", "a"]},
                   {"toolCallId": tid, "excerpts": [], "duplicateOf": tid}, {"toolCallId": tid},
                   {"toolCallId": self.E["toolCallId"], "excerpts": []},
                   {"toolCallId": "tool_00000000000000ff", "excerpts": ["a", "b"]}, "x", None):
            self.assertEqual(self.shown(json.dumps({"context": [it], "history": [{"results": [it]}]})), set(), it)

    def test_missing_or_malformed_document_fails_closed(self):
        full = json.dumps({"context": [{"toolCallId": self.T["toolCallId"], "excerpts": ["a", "b"]}]})
        for content, role in (("not json", "user"), ("[1]", "user"), (full, "assistant"),
                              (json.dumps({"context": "x", "history": "y"}), "user"),
                              (json.dumps({"history": [1, {"results": 3}]}), "user")):
            self.assertEqual(self.shown(content, role), set(), content)
        self.assertEqual(entities._rendered({"request": {"messages": [{"role": "system", "content": full}]}},
                                            self.Idx(self.T)), set())


if __name__ == "__main__":
    unittest.main()
