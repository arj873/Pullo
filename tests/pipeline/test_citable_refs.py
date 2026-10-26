"""S1-15: citations.citableRefs in retrieval@2 requests. Owned synthetic data and a scripted provider; no network, no
live call. The refs are an evidence-presentation aid: validation, provenance and the repair rules are untouched."""

from __future__ import annotations

import json
import unittest

from reviewer.contracts import check_finding_provenance, check_turn_trace, citable_tool_calls
from reviewer.contracts.severity import materialize_evidence
from reviewer.pipeline import RetrievalPolicy, identity, prompts, retrieval

from .helpers import (BASE, EVR1, EVR2, HEAD, TURN_PLAN, TURN_PROFILE, Rig, events_of, hid, hyp, ifinal, iturn, judge,
                      model_calls, script, tcid, treq, vfinal, vturn)

UTIL_BASE = "def close_stream():\n    return None\n\ndef is_open():\n    return True\n"
BASE_U = {**BASE, "src/util.py": UTIL_BASE}
HEAD_U = {**HEAD, "src/util.py": UTIL_BASE}
RUN_LITERAL = "run_0123456789abcdef"        # run-shaped text that belongs to the repository, not to the host
EVAL_LITERAL = "evr_" + "3" * 16
NOTE = f"# fixture id {RUN_LITERAL} and {EVAL_LITERAL}\n"
BASE_L = {**BASE, "src/ids.py": NOTE}
HEAD_L = {**HEAD, "src/ids.py": NOTE}


def w(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


def doc_of(request) -> dict:
    return json.loads(request["messages"][1]["content"])


def ref_ids(request) -> list:
    return [r["toolCallId"] for r in doc_of(request)["citations"]["citableRefs"]]


def turns(res, spy, stage=None):
    """[(logged model.call, the request document the provider was handed)] for the Turn calls, in call order."""
    logged = model_calls(res)
    assert len(logged) == len(spy.requests)                    # no repair/retry attempt in these scripts
    return [(c, doc_of(r)) for c, r in zip(logged, spy.requests)
            if "hop" in c["request"] and (stage is None or c["stage"] == stage)]


def read(path, a, b):
    return treq("read_file", side="head", path=path, start_line=a, end_line=b)


class Refs(Rig):
    def case(self, base=BASE_U, head=HEAD_U, **kw):
        return self.mini(base=base, head=head, **kw)

    def confirm(self, m, h, *, cite=None):
        """investigator reads util.py then answers; verifier reads util.py then confirms with a tool-ref."""
        vread = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/util.py", start_line=1, end_line=2)
        cite = cite or {"kind": "tool-ref", "toolCallId": vread, "index": 0}
        return script(iturn(0, [read("src/util.py", 1, 2)]), ifinal(1, h),
                      vturn(0, [read("src/util.py", 1, 2)]), vfinal(1, m, evidence=[m.cite("src/a.py", 2), cite]),
                      judge(w([hid(0, h)]))), vread

    # ---- templates are exactly the current chain's delivered, actually rendered, successful results
    def test_templates_resolve_to_current_chain_evidence_and_copied_refs_confirm(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        scr, vread = self.confirm(m, h)
        res, spy = self.record_turn(m, scr)
        self.assertEqual((res.status, len(res.findings)), ("completed", 1))
        events = events_of(res)
        self.assertEqual(check_turn_trace(events), [])
        self.assertEqual(check_finding_provenance(res.findings[0], events), [])
        for c, d in turns(res, spy):
            citable = citable_tool_calls(c["callId"], events)
            refs = d["citations"]["citableRefs"]
            self.assertTrue({r["toolCallId"] for r in refs} <= set(citable))     # each template is citable by that call
            ok, problems = materialize_evidence([r["cite"] for r in refs], citable, "t")
            self.assertEqual(problems, [])
            self.assertEqual(len(ok) > 0, bool(refs))
            self.assertEqual(d["citations"]["rules"], prompts.CITATION_RULES)
            self.assertEqual(d["retrieval"]["version"], "retrieval@2")
        # the verifier's hop-1 request offers the exact object the final answer copies
        ver = turns(res, spy, "VERIFY")
        offered = [r for r in ver[1][1]["citations"]["citableRefs"] if r["toolCallId"] == vread]
        self.assertEqual(offered[0]["cite"], {"kind": "tool-ref", "toolCallId": vread})
        self.assertEqual(offered[0]["items"], [{"index": 0, "path": "src/util.py", "lines": [1, 2]}])
        copied = ver[1][0]["response"]["output"]["output"]["evidence"][1]
        self.assertEqual({k: copied[k] for k in ("kind", "toolCallId")}, offered[0]["cite"])
        fin = res.findings[0]["verification"]["evidence"]
        self.assertTrue(any(e.get("toolCallId") == vread and e["path"] == "src/util.py" for e in fin))
        self.assertNotIn(vread, [r["toolCallId"] for r in ver[0][1]["citations"]["citableRefs"]])   # not yet run

    def test_future_denied_and_foreign_results_are_never_templates(self):
        m = self.case()
        h1, h2 = hyp(m, "src/a.py", 2), hyp(m, "src/a.py", 5, claim="Other defect")
        inv_read = tcid("INVESTIGATE", "generalist", 0, "read_file", side="head", path="src/util.py", start_line=1,
                        end_line=2)
        scr = script(iturn(0, [read("src/util.py", 1, 2)]), ifinal(1, h1, h2),
                     vturn(0, [read("src/b.py", 1, 2), treq("read_file", side="head", path="../../etc/passwd")]),
                     vfinal(1, m, verdict="uncertain"),
                     vturn(2, [read("src/util.py", 3, 4)]), vfinal(3, m, verdict="uncertain"))
        res, spy = self.record_turn(m, scr)
        events = events_of(res)
        tv = turns(res, spy, "VERIFY")
        ver = [c for c, _ in tv]
        ids = [[r["toolCallId"] for r in d["citations"]["citableRefs"]] for _, d in tv]
        self.assertEqual([(c["request"]["hypothesisId"], c["request"]["hop"]) for c in ver],
                         [(hid(0, h1), 0), (hid(0, h1), 1), (hid(1, h2), 0), (hid(1, h2), 1)])
        later = {t["toolCallId"]: t for t in events if t["type"] == "tool.call" and "requestedBy" in t
                 and t["stage"] == "VERIFY"}
        denied = [i for i, t in later.items() if t["result"]["status"] == "denied"]
        mine = [i for i, t in later.items() if t["requestedBy"] == ver[0]["callId"] and i not in denied]
        theirs = [i for i, t in later.items() if t["requestedBy"] == ver[2]["callId"]]
        self.assertEqual((len(denied), len(mine), len(theirs)), (1, 1, 1))
        self.assertFalse(set(mine + denied + theirs) & set(ids[0]))                     # future: not yet run
        self.assertIn(mine[0], ids[1])                                                  # run and shown: listed
        self.assertNotIn(denied[0], ids[1])                                             # denied: never a template
        self.assertNotIn(mine[0], ids[2] + ids[3])                                      # another subject's result
        self.assertNotIn(denied[0], ids[2] + ids[3])
        self.assertIn(theirs[0], ids[3])
        self.assertNotIn(theirs[0], ids[1])
        # investigator-chain results are not verifier refs even though originalEvidence may carry their ids
        self.assertNotIn(inv_read, [i for row in ids for i in row])
        self.assertTrue(all(i in citable_tool_calls(c["callId"], events) for c, row in zip(ver, ids) for i in row))

    def test_omitted_results_are_not_templated_and_unit_filter_matches_materialization(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        probe, pspy = self.record_turn(m, script(iturn(0, [read("src/util.py", 1, 2)]), ifinal(1, h),
                                                 vturn(0, [read("src/util.py", 1, 2)]), vfinal(1, m, verdict="uncertain")))
        # budget = what the investigator's host-prepared results use + 5, so a retrieved excerpt is omitted
        shown = RetrievalPolicy().context_chars - turns(probe, pspy, "INVESTIGATE")[0][1]["retrieval"]["contextCharsRemaining"]
        scr = script(iturn(0, [read("src/util.py", 1, 2)]), iturn(1, [read("src/b.py", 1, 1)]), ifinal(2, h),
                     vturn(0), vfinal(1, m, verdict="uncertain"))
        res, spy = self.record_turn(m, scr, retrieval=RetrievalPolicy(context_chars=shown + 5), eval_id=EVR2)
        tv = turns(res, spy, "INVESTIGATE")
        omitted = [t for t in events_of(res) if t["type"] == "tool.call" and t.get("requestedBy") == tv[0][0]["callId"]]
        self.assertEqual(len(omitted), 1)
        shown_item = tv[1][1]["history"][0]["results"][0]
        self.assertEqual(shown_item.get("excerptsOmitted"), "retrieval context budget")
        self.assertNotIn(omitted[0]["toolCallId"], [r["toolCallId"] for r in tv[1][1]["citations"]["citableRefs"]])
        self.assertTrue(tv[1][1]["citations"]["citableRefs"])                           # host results remain listed

    def test_unit_citable_refs_filters_statuses_empty_results_and_bounds(self):
        def ev(i, status="ok", evidence=True, tool="read_file"):
            items = [{"kind": "code", "path": f"p{i}.py", "lines": [1, 2], "excerpt": "x", "commit": "c",
                      "resolved": True, "source": tool}] if evidence else []
            return {"toolCallId": f"tool_{i:016x}", "tool": tool, "args": {}, "result": {"status": status, "evidence":
                    items, "completeness": "exact", "truncated": None, "notice": ""}}
        d = {e["toolCallId"]: e for e in [ev(1), ev(2, "denied"), ev(3, "unavailable"), ev(4, evidence=False),
                                           ev(5, "empty", evidence=False), ev(6, "partial")]}
        refs, dropped = retrieval.citable_refs(d)
        self.assertEqual([r["toolCallId"] for r in refs], [f"tool_{1:016x}", f"tool_{6:016x}"])
        self.assertEqual(dropped, 0)
        many = {e["toolCallId"]: e for e in [ev(i) for i in range(100)]}
        refs, dropped = retrieval.citable_refs(many)
        self.assertEqual((len(refs), dropped), (retrieval.MAX_REF_RESULTS, 100 - retrieval.MAX_REF_RESULTS))
        self.assertEqual(refs[-1]["toolCallId"], f"tool_{99:016x}")                    # the most recent are kept
        self.assertEqual(retrieval.citable_refs({}), ([], 0))

    # ---- origin-aware identity and determinism
    def test_same_data_across_eval_run_ids_gives_identical_requests_and_run_shaped_source_survives(self):
        m = self.case(base=BASE_L, head=HEAD_L)
        h = hyp(m, "src/a.py", 2)
        vread = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/ids.py", start_line=1, end_line=1)

        def scr():
            return script(iturn(0, [read("src/ids.py", 1, 1)]), ifinal(1, h),
                          vturn(0, [read("src/ids.py", 1, 1)]),
                          vfinal(1, m, evidence=[m.cite("src/a.py", 2), {"kind": "tool-ref", "toolCallId": vread,
                                                                         "index": 0}]), judge(w([hid(0, h)])))
        r1, s1 = self.record_turn(m, scr(), eval_id=EVR1)
        r2, s2 = self.record_turn(m, scr(), eval_id=EVR2)
        self.assertNotEqual(r1.run["id"], r2.run["id"])
        self.assertEqual(s1.requests, s2.requests)
        blob = json.dumps(s1.requests)
        self.assertNotIn(EVR1, blob.replace(EVAL_LITERAL, ""))
        for r in (r1, r2):
            self.assertEqual((r.status, len(r.findings)), ("completed", 1))
            self.assertEqual(check_finding_provenance(r.findings[0], events_of(r)), [])
        hop1 = turns(r1, s1, "VERIFY")[1][1]
        self.assertIn(RUN_LITERAL, json.dumps(hop1["history"]))                        # source text kept verbatim
        self.assertIn(EVAL_LITERAL, json.dumps(hop1["history"]))
        fin = r1.findings[0]["verification"]["evidence"]
        self.assertTrue(any(RUN_LITERAL in e["excerpt"] for e in fin))                 # and citable

    # ---- validation is unchanged: malformed or fabricated citations are still rejected, not repaired or accepted
    def test_fabricated_and_inaccurate_citations_remain_rejected(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        bad_cases = {
            "fabricated tool-ref": {"kind": "tool-ref", "toolCallId": "tool_" + "0" * 16, "index": 0},
            "inaccurate excerpt": m.cite("src/util.py", 1, 2, excerpt="def close_stream():\n    return 1"),
            "other-chain tool-ref": {"kind": "tool-ref",
                                     "toolCallId": tcid("INVESTIGATE", "generalist", 0, "read_file", side="head",
                                                        path="src/util.py", start_line=1, end_line=2)},
        }
        for name, cite in bad_cases.items():
            with self.subTest(name):
                scr = script(iturn(0, [read("src/util.py", 1, 2)]), ifinal(1, h), vturn(0, [read("src/util.py", 1, 2)]),
                             vfinal(1, m, evidence=[cite]))
                res, _ = self.record_turn(m, scr, eval_id=EVR1 if name.startswith("f") else "evr_" + "4" * 16)
                self.assertEqual((res.findings, res.comments), ([], []))
                self.assertEqual([d["reason"] for d in res.drops], ["invalid-citation"])

    def test_malformed_snapshot_id_is_still_a_local_schema_failure(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        bad = m.cite("src/a.py", 2, commit="snap:sha256:" + "6f09" * 15)               # 60 hex digits: malformed
        scr = script(iturn(0, [read("src/util.py", 1, 2)]), ifinal(1, h), vturn(0, [read("src/util.py", 1, 2)]),
                     vfinal(1, m, evidence=[bad]))
        res, _ = self.record_turn(m, scr)
        self.assertEqual((res.findings, res.comments), ([], []))
        self.assertEqual([d["reason"] for d in res.drops], ["verifier-failed"])         # never a refutation or a finding
        final = [c for c in model_calls(res, "VERIFY") if c["request"]["hop"] == 1]
        self.assertEqual(len(final), 2)                  # the answer and the one existing bounded repair; none added
        self.assertIn("repairOf", final[1])
        self.assertIsNotNone(final[1]["error"])

    # ---- identity
    def test_versions_and_identity_effect(self):
        self.assertEqual((retrieval.RETRIEVAL_VERSION, retrieval.INVESTIGATOR_PROMPT, retrieval.VERIFIER_PROMPT),
                         ("retrieval@2", "investigator.retrieve@v2", "verifier.refute@v4"))
        self.assertEqual(identity.RETRIEVAL_BEHAVIOR, "retrieval-pipeline@2")
        self.assertIn("citations", prompts.retrieval_template_digests())
        self.assertNotIn("citations", prompts.template_digests())                       # legacy digests untouched
        doc = retrieval.RetrievalPolicy().to_doc()
        self.assertEqual((doc["version"], doc["investigator_prompt"], doc["verifier_prompt"]),
                         ("retrieval@2", "investigator.retrieve@v2", "verifier.refute@v4"))

    def test_legacy_non_turn_requests_carry_no_citations(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        from .helpers import inv, ver
        res, spy = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        self.assertTrue(all("citations" not in doc_of(r) for r in spy.requests))


if __name__ == "__main__":
    unittest.main()
