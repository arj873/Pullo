"""S1-18 author tests: a hop renders a result only if the result is in THAT hop's contextResults and was logged before
that hop (F1 of S1-17-review). Before, `_rendered` took any hash-valid item of any hop and the chain union promoted it.
"before" is reproduced by patching entities._rendered back to the S1-17 rule (no per-hop membership, no seq test).
Scripted provider on synthetic data; no network, model or key. Positive controls: honest chains, host context, legacy.
"""

from __future__ import annotations

import copy
import json
import unittest
from unittest import mock

from reviewer.contracts import check_turn_trace, citable_tool_calls, entities, validate_trace
from reviewer.pipeline import RetrievalPolicy

from tests.pipeline.helpers import events_of, hyp, ifinal, script, vfinal, vturn
from tests.s117_review import test_s117_independent as g

READ = g.READ


def s117_rendered(hop, idx):                         # the S1-17 body: any valid-looking item of the hop document counts
    msgs = hop["request"]["messages"]
    try:
        doc = json.loads(msgs[1]["content"]) if len(msgs) > 1 and msgs[1]["role"] == "user" else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        return set()
    items = [doc.get("context"), doc.get("pinnedContext")]
    history = doc.get("history")
    items += [h.get("results") for h in history if isinstance(h, dict)] if isinstance(history, list) else []
    out = set()
    for it in (x for group in items if isinstance(group, list) for x in group):
        tid = it.get("toolCallId") if isinstance(it, dict) else None
        t = idx.tool(tid) if isinstance(tid, str) else None
        if t is not None and t["result"]["evidence"] \
                and it.get("excerpts") == [e["excerpt"] for e in t["result"]["evidence"]]:
            out.add(tid)
    return out


class HopVisibility(g.Gate):
    def omitted_hop1_forgery(self):
        """Hop 1's context budget omits the read result; hop 0's document is then forged (and re-hashed) to render it."""
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        probe, _ = self.rt(m, script(ifinal(0, h), vturn(0, [READ]), vfinal(1, m, verdict="uncertain")))
        p0 = [c for c in events_of(probe) if c["type"] == "model.call" and c["stage"] == "VERIFY"][0]
        used = RetrievalPolicy().context_chars - g.doc_of_call(p0)["retrieval"]["contextCharsRemaining"]
        res, _ = self.rt(m, script(ifinal(0, h), vturn(0, [READ]), vfinal(1, m, path="src/a.py", line=2), g.W(h)),
                         retrieval=RetrievalPolicy(context_chars=used + 1))
        events = copy.deepcopy(events_of(res))
        calls = [e for e in events if e["type"] == "model.call" and e["stage"] == "VERIFY"]
        rid = g.requested_ids(events, calls[0])[0]
        logged = [t for t in events if t.get("toolCallId") == rid][0]
        self.assertNotIn(rid, citable_tool_calls(calls[1]["callId"], events))      # honest: hop 1 omitted it
        d0 = g.doc_of_call(calls[0])
        d0["context"] = d0.get("context", []) + [{"toolCallId": rid,
                                                    "excerpts": [e["excerpt"] for e in logged["result"]["evidence"]]}]
        g.set_doc(calls[0], d0)                                                      # re-hashed forgery
        self.assertEqual((validate_trace(events), check_turn_trace(events)), ([], []))
        return events, calls, rid

    def test_f1_before_forged_hop0_rendering_promoted_the_omitted_hop1_result(self):
        events, calls, rid = self.omitted_hop1_forgery()
        with mock.patch.object(entities, "_rendered", s117_rendered):
            self.assertIn(rid, citable_tool_calls(calls[1]["callId"], events))      # F1 reproduced

    def test_f1_after_forged_hop0_rendering_does_not_promote_it(self):
        events, calls, rid = self.omitted_hop1_forgery()
        self.assertNotIn(rid, citable_tool_calls(calls[1]["callId"], events))
        self.assertNotIn(rid, citable_tool_calls(calls[0]["callId"], events))

    def test_a_tool_logged_at_or_after_the_hop_is_not_rendered_by_it(self):
        events, calls, rid = self.omitted_hop1_forgery()
        idx = entities._Index(events)
        hop0 = idx.call(calls[0]["callId"])
        tool = idx.tool(rid)
        forged = copy.deepcopy(hop0)
        forged["request"]["contextResults"] = list(forged["request"]["contextResults"]) + [rid]   # listed AND rendered
        self.assertGreater(tool["seq"], forged["seq"])
        self.assertNotIn(rid, entities._rendered(forged, idx))                       # seq test alone refuses it
        self.assertIn(rid, s117_rendered(forged, idx))
        forged["seq"] = tool["seq"] + 1                                               # logged before: counts
        self.assertIn(rid, entities._rendered(forged, idx))

    def test_control_honest_chain_cites_rendered_read_result(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.good_run(m, h, requests=[READ])
        events = events_of(res)
        calls = [e for e in events if e["type"] == "model.call" and e["stage"] == "VERIFY"]
        rid = g.requested_ids(events, calls[0])[0]
        self.assertIn(rid, citable_tool_calls(calls[1]["callId"], events))          # hop 1 renders it in history
        self.assertNotIn(rid, citable_tool_calls(calls[0]["callId"], events))       # hop 0 never saw it
        self.assertEqual(check_turn_trace(events), [])

    def test_control_host_context_stays_citable_at_hop0_and_hop1(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.good_run(m, h, requests=[READ])
        events = events_of(res)
        calls = [e for e in events if e["type"] == "model.call" and e["stage"] == "VERIFY"]
        host = calls[0]["request"]["contextResults"]
        self.assertTrue(host)
        for c in calls:
            self.assertTrue(set(host) <= set(citable_tool_calls(c["callId"], events)))

    def test_control_legacy_call_citable_set_is_unchanged(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.rec(m, script(ifinal(0, h), vfinal(0, m, verdict="uncertain")))
        events = events_of(res)
        legacy = [e for e in events if e["type"] == "model.call" and "hop" not in e["request"]]
        self.assertTrue(legacy)
        for c in legacy:
            allowed = entities.HOST_CONTEXT_STAGES.get(c["stage"], ())
            want = {t["toolCallId"] for t in events if t["type"] == "tool.call" and "requestedBy" not in t
                    and t["stage"] in allowed and t["seq"] < c["seq"]}
            self.assertEqual(set(citable_tool_calls(c["callId"], events)), want)


if __name__ == "__main__":
    unittest.main()
