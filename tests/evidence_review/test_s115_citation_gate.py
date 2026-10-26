"""Independent gate for S1-15 (citations.citableRefs in retrieval@2 requests). Owned by the S1-15 reviewer, not the
pipeline author.

Oracles are the request documents the scripted provider was actually handed (what the model saw) and the logged
tool.call events (what exists), never the author's helper outputs: a template is accepted only when its id is rendered
WITH excerpts in that same request and every listed item is a rendered item of that logged event.

Scripted provider on owned synthetic data; no network, no model call, no live key.

Naming: CONTROL = must hold. LIMIT = honest boundary (pre-existing or deliberate), asserted so a later change is noticed;
a LIMIT is not an S1-15 regression unless the handoff says so.
"""

from __future__ import annotations

import json
import unittest
from unittest import mock

from reviewer.contracts import check_finding_provenance, check_turn_trace, citable_tool_calls
from reviewer.contracts.severity import TRUSTED_TOOL_STATUSES, materialize_evidence
from reviewer.pipeline import engine as pengine
from reviewer.pipeline import prompts, retrieval

from tests.pipeline.helpers import (BASE, EVR1, EVR2, HEAD, Rig, events_of, hid, hyp, ifinal, iturn, judge, model_calls,
                                    script, tcid, treq, vfinal, vturn)

UTIL = "def close_stream():\n    return None\n\ndef is_open():\n    return True\n"


def marks(name, n):
    return "".join(f"{name}_{i} = 'MARK {i}'\n" for i in range(n))


FEW = {"src/util.py": UTIL, "src/m1.py": marks("a", 3), "src/m2.py": marks("b", 2)}          # 5 search items
MANY = {"src/util.py": UTIL, **{f"src/m{k}.py": marks(f"v{k}", 8) for k in range(1, 4)}}      # 24 search items
SEARCH = treq("search_literal", side="head", query="MARK")
LEGACY_TEMPLATE_DIGESTS = {   # prompts.template_digests() of the pre-S1-15 tree (/tmp/pullo-cfg02-exact-tree)
    "formats": "sha256:2b00ef28c2365414ff2a1cf35929264bf9dcffa1dfdad816684d4142fac7d2d7",
    "investigator": "sha256:fc2162773b1a7a09f31c656aff7f6cb56d62ca3d74ddba82aa58f28e39841226",
    "judge": "sha256:47940b1d08d749cea46bc89fee3bcd18b19c065533e0c1ea713649ee57a2c5e9",
    "system": "sha256:74c09d41cc972615e4ba90b0e0f26da881ab385049664e25c0be5cbc5daedee6",
    "verifier": "sha256:39c7688baba0dc1c2c56175896f025e3fc95e8662d7c916b58be1a64549b9c7d"}


def doc_of(request) -> dict:
    return json.loads(request["messages"][1]["content"])


def turn_pairs(res, spy):
    logged = model_calls(res)
    assert len(logged) == len(spy.requests)
    return [(c, doc_of(r)) for c, r in zip(logged, spy.requests) if "hop" in c["request"]]


def rendered(doc: dict) -> dict:
    """toolCallId -> excerpt list for every result this document shows WITH excerpts (host context or history)."""
    out = {}
    for it in doc.get("context", []) + doc.get("pinnedContext", []):
        if it["excerpts"]:
            out[it["toolCallId"]] = it["excerpts"]
    for h in doc.get("history", []):
        for it in h["results"]:
            if it["excerpts"] and "duplicateOf" not in it:
                out[it["toolCallId"]] = it["excerpts"]
    return out


def tref(tid, index=None):
    return {"kind": "tool-ref", "toolCallId": tid, **({} if index is None else {"index": index})}


class Gate(Rig):
    def case(self, extra, cid="mini-1"):
        return self.mini(cid, base={**BASE, **extra}, head={**HEAD, **extra})

    def assert_refs_are_rendered_current_chain_items(self, res, spy):
        """Every template in every Turn request: logged, trusted, rendered with excerpts in that request, citable by
        that call, items == the rendered items (first 20), and each indexed / whole cite materializes only rendered
        items. Conversely every trusted non-empty result rendered in the request is listed (nothing shown is hidden)."""
        events = events_of(res)
        tools = {e["toolCallId"]: e for e in events if e["type"] == "tool.call"}
        for call, doc in turn_pairs(res, spy):
            refs = doc["citations"]["citableRefs"]
            shown = rendered(doc)
            citable = citable_tool_calls(call["callId"], events)
            self.assertEqual(doc["citations"]["refsOmitted"], 0)
            listed = [r["toolCallId"] for r in refs]
            self.assertEqual(len(listed), len(set(listed)))
            expect = {t for t in shown if tools[t]["result"]["status"] in TRUSTED_TOOL_STATUSES
                      and tools[t]["result"]["evidence"]}
            self.assertEqual(set(listed), expect, call["callId"])
            for r in refs:
                tid = r["toolCallId"]
                ev = tools[tid]
                logged = ev["result"]["evidence"]
                self.assertIn(tid, citable)
                self.assertLess(ev["seq"], call["seq"])
                self.assertEqual(shown[tid], [x["excerpt"] for x in logged])      # whole event rendered, item for item
                self.assertEqual(r["cite"], tref(tid))
                self.assertEqual(set(r), {"toolCallId", "tool", "cite", "items"})
                self.assertEqual(r["items"], [{"index": i, **({"path": x["path"], "lines": x["lines"]}
                                                               if x["kind"] == "code" else {})}
                                              for i, x in enumerate(logged[:20])])
                whole, p = materialize_evidence([r["cite"]], citable, "t")
                self.assertEqual(p, [])
                self.assertTrue(all(x["excerpt"] in shown[tid] for x in whole))
                for it in r["items"]:
                    one, p = materialize_evidence([tref(tid, it["index"])], citable, "t")
                    self.assertEqual((p, one), ([], [logged[it["index"]]]))
            blob = json.dumps(doc["citations"])
            self.assertNotIn(res.run["id"], blob)
            self.assertNotIn(EVR1, blob)
            self.assertNotIn(EVR2, blob)

    # ---- CONTROL: multi-item results, every hop of both roles, copied indexed ref confirms, identical across evals
    def test_multi_item_refs_are_exactly_rendered_items_and_an_indexed_copy_confirms(self):
        m = self.case(FEW)
        h = hyp(m, "src/a.py", 2)
        inv_search = tcid("INVESTIGATE", "generalist", 0, "search_literal", side="head", query="MARK")
        ver_search = tcid("VERIFY", "verifier", 2, "search_literal", side="head", query="MARK")

        def scr():
            return script(iturn(0, [SEARCH]), ifinal(1, h), vturn(0, [SEARCH]),
                          vfinal(1, m, evidence=[m.cite("src/a.py", 2), tref(ver_search, 3)]),
                          judge({"findingIds": [hid(0, h)], "title": "T", "body": "B"}))
        r1, s1 = self.record_turn(m, scr(), eval_id=EVR1)
        r2, s2 = self.record_turn(m, scr(), eval_id=EVR2)
        self.assertEqual(s1.requests, s2.requests)
        for res, spy in ((r1, s1), (r2, s2)):
            self.assertEqual((res.status, len(res.findings)), ("completed", 1))
            events = events_of(res)
            self.assertEqual(check_turn_trace(events), [])
            self.assertEqual(check_finding_provenance(res.findings[0], events), [])
            self.assert_refs_are_rendered_current_chain_items(res, spy)
        pairs = turn_pairs(r1, s1)
        ver = [d for c, d in pairs if c["stage"] == "VERIFY"]
        self.assertEqual(len(ver[1]["citations"]["citableRefs"][-1]["items"]), 5)
        self.assertNotIn(inv_search, [r["toolCallId"] for r in ver[0]["citations"]["citableRefs"] +
                                      ver[1]["citations"]["citableRefs"]])
        item = [x for x in events_of(r1) if x.get("toolCallId") == ver_search][0]["result"]["evidence"][3]
        self.assertIn(item, r1.findings[0]["verification"]["evidence"])
        self.assertEqual([e for e in r1.findings[0]["verification"]["evidence"] if e.get("toolCallId")], [item])

    # ---- LIMIT: a result with more than 20 items lists 20 with no item-count disclosure
    def test_more_than_twenty_items_lists_first_twenty_without_count(self):
        m = self.case(MANY)
        h = hyp(m, "src/a.py", 2)
        sid = tcid("VERIFY", "verifier", 2, "search_literal", side="head", query="MARK")
        res, spy = self.record_turn(m, script(ifinal(0, h), vturn(0, [SEARCH]),
                                              vfinal(1, m, evidence=[m.cite("src/a.py", 2), tref(sid), tref(sid, 22)]),
                                              judge({"findingIds": [hid(0, h)], "title": "T", "body": "B"})))
        self.assertEqual((res.status, len(res.findings)), ("completed", 1))
        self.assert_refs_are_rendered_current_chain_items(res, spy)
        doc = [d for c, d in turn_pairs(res, spy) if c["stage"] == "VERIFY"][1]
        ref = [r for r in doc["citations"]["citableRefs"] if r["toolCallId"] == sid][0]
        self.assertEqual((len(rendered(doc)[sid]), len(ref["items"])), (24, 20))
        self.assertEqual(doc["citations"]["refsOmitted"], 0)        # counts results only; 4 rendered items unlisted
        logged = [x for x in events_of(res) if x.get("toolCallId") == sid][0]["result"]["evidence"]
        got = [e for e in res.findings[0]["verification"]["evidence"] if e.get("toolCallId") == sid]
        self.assertEqual(got, logged[:20] + [logged[22]])          # whole cite = listed 20; index 22 (rendered) valid
        self.assertEqual(check_finding_provenance(res.findings[0], events_of(res)), [])

    # ---- CONTROL + LIMIT: host-prepared verifier context omitted by the request budget is never a template
    def test_unrendered_host_context_is_not_templated(self):
        m = self.case(FEW)
        h = hyp(m, "src/a.py", 2)
        probe, pspy = self.record_turn(m, script(ifinal(0, h), vfinal(0, m, verdict="uncertain")), eval_id=EVR2)
        vdoc = [d for c, d in turn_pairs(probe, pspy) if c["stage"] == "VERIFY"][0]
        read_id, diff_id = [it["toolCallId"] for it in vdoc["pinnedContext"]]
        budget = sum(len(x) for x in vdoc["pinnedContext"][0]["excerpts"])      # the read fits, the diff does not
        scr = script(ifinal(0, h), vturn(0, [treq("read_file", side="head", path="src/util.py")]),
                     vfinal(1, m, evidence=[m.cite("src/a.py", 2), tref(diff_id)]),
                     judge({"findingIds": [hid(0, h)], "title": "T", "body": "B"}))
        with mock.patch.object(pengine, "CONTEXT_CHARS", budget):
            res, spy = self.record_turn(m, scr)
        self.assert_refs_are_rendered_current_chain_items(res, spy)
        v = [d for c, d in turn_pairs(res, spy) if c["stage"] == "VERIFY"]
        self.assertEqual([bool(it["excerpts"]) for it in v[0]["pinnedContext"]], [True, False])
        for d in v:
            ids = [r["toolCallId"] for r in d["citations"]["citableRefs"]]
            self.assertIn(read_id, ids)
            self.assertNotIn(diff_id, ids)
        # S1-17 (was a LIMIT): the omitted result's id is still in the chain's contextResults, but it was never rendered,
        # so citing it anyway no longer confirms a finding. The rules call it uncitable and contracts now enforce that.
        self.assertEqual((res.status, len(res.findings)), ("completed", 0))
        self.assertEqual([d["reason"] for d in res.drops], ["invalid-citation"])

    # ---- CONTROL: foreign, investigator-original, malformed, out-of-range and excerpt-mismatched cites still fail
    def test_foreign_malformed_and_mismatched_citations_fail(self):
        m = self.case(FEW)
        inv_read = tcid("INVESTIGATE", "generalist", 0, "read_file", side="head", path="src/util.py")
        h1 = hyp(m, "src/a.py", 2)
        h2 = hyp(m, "src/a.py", 5, claim="Other defect")
        hr = hyp(m, "src/a.py", 2, evidence=[m.cite("src/a.py", 2), tref(inv_read, 0)])
        util_read = treq("read_file", side="head", path="src/util.py")
        v1_read = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/util.py")
        good = m.cite("src/a.py", 2)
        orig_code = {**m.cite("src/util.py", 1, 5), "toolCallId": inv_read}       # verbatim originalEvidence item
        single = {   # name -> (investigator hypotheses + its retrieval, verifier final evidence, expected drop)
            "investigator-original tool-ref": ([iturn(0, [util_read]), ifinal(1, hr)], [good, tref(inv_read, 0)],
                                               "invalid-citation"),
            "verbatim originalEvidence code item": ([iturn(0, [util_read]), ifinal(1, hr)], [good, orig_code],
                                                    "verifier-failed"),
            "malformed tool id": ([ifinal(0, h1)], [good, tref("tool_1234")], "verifier-failed"),
            "index out of range": ([ifinal(0, h1)], [good, tref(v1_read, 1)], "invalid-citation"),
            "excerpt from another range": ([ifinal(0, h1)],
                                           [good, m.cite("src/util.py", 1, 5, excerpt=m.lines("src/util.py", 4, 5))],
                                           "invalid-citation"),
        }
        for n, (name, (inv_entries, evidence, reason)) in enumerate(single.items()):
            with self.subTest(name):
                scr = script(*inv_entries, vturn(0, [util_read]), vfinal(1, m, evidence=evidence))
                res, spy = self.record_turn(m, scr, eval_id=f"evr_{n + 5:016x}")
                self.assertEqual((res.findings, res.comments), ([], []))
                self.assertEqual([d["reason"] for d in res.drops], [reason])
                vdocs = [d for c, d in turn_pairs(res, spy) if c["stage"] == "VERIFY"]
                if name.startswith("investigator") or name.startswith("verbatim"):
                    shown_orig = [e.get("toolCallId") for e in vdocs[0]["originalEvidence"]]
                    self.assertIn(inv_read, shown_orig)                       # the id IS visible to the verifier
                    for d in vdocs:
                        self.assertNotIn(inv_read, [r["toolCallId"] for r in d["citations"]["citableRefs"]])
        # another hypothesis's ref: logged, rendered and templated to h1's chain only
        scr = script(ifinal(0, h1, h2), vturn(0, [util_read]), vfinal(1, m, verdict="uncertain"),
                     vfinal(2, m, evidence=[m.cite("src/a.py", 5), tref(v1_read, 0)]))
        res, spy = self.record_turn(m, scr)
        vdocs = [d for c, d in turn_pairs(res, spy) if c["stage"] == "VERIFY"]
        self.assertIn(v1_read, [r["toolCallId"] for r in vdocs[1]["citations"]["citableRefs"]])
        self.assertNotIn(v1_read, [r["toolCallId"] for r in vdocs[2]["citations"]["citableRefs"]])
        self.assertEqual(res.findings, [])
        self.assertEqual([(d["subjectIds"], d["reason"]) for d in res.drops],
                         [([hid(0, h1)], "uncertain"), ([hid(1, h2)], "invalid-citation")])

    # ---- CONTROL: list bound, order and field whitelist of the pure builder
    def test_builder_bound_order_and_no_leaked_fields(self):
        def ev(i):
            return {"type": "tool.call", "runId": "run_" + "9" * 16, "toolCallId": f"tool_{i:016x}", "tool": "read_file",
                    "args": {"path": "secret/arg"}, "resultHash": "sha256:" + "0" * 64,
                    "result": {"status": "ok", "completeness": "exact", "truncated": None, "notice": "n",
                               "evidence": [{"kind": "code", "path": f"p{i}.py", "lines": [1, 2], "excerpt": "EXC",
                                             "commit": "snap:sha256:" + "a" * 64, "resolved": True, "source": "s",
                                             "toolCallId": f"tool_{i:016x}"}]}}
        delivered = {e["toolCallId"]: e for e in map(ev, range(65))}
        refs, omitted = retrieval.citable_refs(delivered)
        self.assertEqual((len(refs), omitted), (60, 5))
        self.assertEqual([r["toolCallId"] for r in refs], [f"tool_{i:016x}" for i in range(5, 65)])
        blob = json.dumps(refs)
        for leaked in ("run_", "EXC", "snap:sha256", "secret/arg", "sha256:", "resolved", "notice"):
            self.assertNotIn(leaked, blob)
        self.assertEqual(retrieval.citable_refs({}), ([], 0))

    # ---- CONTROL: wording and identity
    def test_wording_is_generic_and_legacy_templates_are_unchanged(self):
        self.assertEqual(prompts.template_digests(), LEGACY_TEMPLATE_DIGESTS)
        for task in (prompts.INVESTIGATOR_RETRIEVE_TASK, prompts.VERIFIER_REFUTE_TASK):
            self.assertIn("citations.citableRefs", task)
            self.assertIn("request the implementation", task)
        rules = " ".join(prompts.CITATION_RULES)
        for need in ("character for character", "originalEvidence", "`snapshots`", "Do not adjust a line range"):
            self.assertIn(need, rules)
        text = json.dumps(prompts.RETRIEVAL_TEMPLATES).lower()
        for hint in ("clock", "lease", "millis", "now_seconds", "reap", "scheduler", "worker"):
            self.assertNotIn(hint, text)


if __name__ == "__main__":
    unittest.main()
