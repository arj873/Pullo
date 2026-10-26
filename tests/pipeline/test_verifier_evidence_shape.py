"""S1-19: Turn-verifier originalEvidence code items are copyable as code citations. Owned synthetic data and a scripted
provider; no network, no live call. Validation, provenance, caps and repair rules are untouched."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest

from reviewer.contracts import validate
from reviewer.pipeline import identity, prompts, retrieval

from .helpers import (BASE, EVR1, EVR2, HEAD, TURN_PLAN, TURN_PROFILE, Rig, hid, hyp, ifinal, iturn, judge, model_calls, script, tcid, treq,
                      vfinal, vturn)

UTIL = "def close_stream():\n    return None\n\ndef is_open():\n    return True\n"
BASE_U = {**BASE, "src/util.py": UTIL}
HEAD_U = {**HEAD, "src/util.py": UTIL}
CODE_FIELDS = {"kind", "path", "lines", "commit", "excerpt"}

# Pre-change values (prompts.py / retrieval.py of the read-only exact tree /tmp/pullo-ci117-exact-tree).
BASELINE_LEGACY_DIGESTS = {
    "formats": "sha256:2b00ef28c2365414ff2a1cf35929264bf9dcffa1dfdad816684d4142fac7d2d7",
    "investigator": "sha256:fc2162773b1a7a09f31c656aff7f6cb56d62ca3d74ddba82aa58f28e39841226",
    "judge": "sha256:47940b1d08d749cea46bc89fee3bcd18b19c065533e0c1ea713649ee57a2c5e9",
    "system": "sha256:74c09d41cc972615e4ba90b0e0f26da881ab385049664e25c0be5cbc5daedee6",
    "verifier": "sha256:39c7688baba0dc1c2c56175896f025e3fc95e8662d7c916b58be1a64549b9c7d"}
BASELINE_TURN_DIGESTS = {
    "citations": "sha256:5c1b95c2cf243364402a3473dc1341d866f4928627aefbb9350a6ea42b851357",
    "formats": "sha256:169faeb87a5049bfeeb397fd21343dfe8fe57786bb32d6adae520a2c7a0e5267",
    "investigator": "sha256:1e64c7da5be7ef8052fe70b51f10eaf4dac74f1fa99d3c7f8d3c7c381562a124",
    "system": "sha256:8d29afec1bf40c2bfb56df3dd59e94b6f5f696f7712c2d00f6595f71e09b7547",
    "tools": "sha256:6211830613da24eab4b6d1bbd7a0cc7229fd3da39bdf27fda57f47f2fcda03bb",
    "verifier": "sha256:52d2c5d169253101d3a52166b9789c0932095cd20280914bd3a8ecdbea2b8a7d"}
BASELINE_LEGACY_VERIFIER_DOC = "030f906c56615cc63dd1e3d5928540b29f168ab671ec345383c30345155e57bd"
BASELINE_INVESTIGATOR_TASK = "e9b6ee9f2b1b92a0c3f43f5494c73fecb34a21fc134b2958528c40ad534ab1e9"


def doc_of(request) -> dict:
    return json.loads(request["messages"][1]["content"])


def read(path, a, b):
    return treq("read_file", side="head", path=path, start_line=a, end_line=b)


def sha(x) -> str:
    return hashlib.sha256(x.encode() if isinstance(x, str) else json.dumps(x, sort_keys=True).encode()).hexdigest()


class Shape(Rig):
    def case(self):
        return self.mini(base=BASE_U, head=HEAD_U)

    def verifier_docs(self, res, spy):
        logged = model_calls(res)
        return [doc_of(r) for c, r in zip(logged, spy.requests) if c["stage"] == "VERIFY" and "hop" in c["request"]]

    def chain(self, m, h, *, evidence_of, judged=True):
        """investigator reads util.py then answers with h; verifier reads util.py then answers with evidence_of(shown)."""
        vread = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/util.py", start_line=1, end_line=2)
        return script(iturn(0, [read("src/util.py", 1, 2)]), ifinal(1, h), vturn(0, [read("src/util.py", 1, 2)]),
                      vfinal(1, m, evidence=evidence_of(vread)), *([judge({"findingIds": [hid(0, h)], "title": "T",
                                                                           "body": "B"})] if judged else []))

    def hypothesis(self, m):
        """A hypothesis whose evidence carries an investigator tool-ref, so its stored code item has a toolCallId."""
        inv_read = tcid("INVESTIGATE", "generalist", 0, "read_file", side="head", path="src/util.py", start_line=1,
                        end_line=2)
        return hyp(m, "src/a.py", 2, evidence=[m.cite("src/a.py", 2),
                                               {"kind": "tool-ref", "toolCallId": inv_read, "index": 0}]), inv_read

    # ---- the displayed code evidence is exactly a code citation, and copying it verbatim confirms and replays
    def test_displayed_code_evidence_copies_verbatim_into_a_confirming_chain_that_replays(self):
        m = self.case()
        h, inv_read = self.hypothesis(m)
        def evidence(vread):
            return [{"kind": "code", "path": "src/a.py", "lines": [2, 2], "commit": m.head_id,
                     "excerpt": m.lines("src/a.py", 2)}]
        res0, spy0 = self.record_turn(m, self.chain(m, h, evidence_of=evidence), eval_id="evr_" + "4" * 16)
        shown = self.verifier_docs(res0, spy0)[0]["originalEvidence"]
        code = [e for e in shown if e["kind"] == "code"]
        self.assertTrue(code)
        for e in code:
            self.assertEqual(set(e), CODE_FIELDS)                      # no toolCallId, resolved or other field
            self.assertEqual(validate("ModelEvidence", e), [])         # schema-valid exactly as displayed
        # scripted request whose final answer copies the displayed items character for character
        scr = self.chain(m, h, evidence_of=lambda vread: copy.deepcopy(code))
        res, spy = self.record_turn(m, scr, eval_id=EVR1)
        self.assertEqual((res.status, len(res.findings), len(res.comments), res.drops), ("completed", 1, 1, []))
        self.assertEqual(self.verifier_docs(res, spy)[0]["originalEvidence"], shown)
        # strict replay of the recording emits the same local comment
        rep = self.replay(m, res, eval_id=EVR2, profile=TURN_PROFILE, plan=TURN_PLAN)
        self.assertEqual((rep.status, len(rep.findings), len(rep.comments)), ("completed", 1, 1))
        strip = lambda cs: [{k: v for k, v in c.items() if k not in ("runId", "id")} for c in cs]
        self.assertEqual(strip(rep.comments), strip(res.comments))
        self.assertEqual(rep.findings[0]["id"], res.findings[0]["id"])

    def test_investigator_provenance_stays_out_of_code_items_and_is_not_citable(self):
        m = self.case()
        h, inv_read = self.hypothesis(m)
        res, spy = self.record_turn(m, self.chain(m, h, evidence_of=lambda v: [m.cite("src/a.py", 2)]))
        for d in self.verifier_docs(res, spy):
            self.assertNotIn(inv_read, json.dumps(d["originalEvidence"]))
            self.assertNotIn(inv_read, [r["toolCallId"] for r in d["citations"]["citableRefs"]])
        # citing the investigator's tool ref directly is still not a verifier citation
        res, _ = self.record_turn(m, self.chain(m, h, evidence_of=lambda v: [
            m.cite("src/a.py", 2), {"kind": "tool-ref", "toolCallId": inv_read, "index": 0}]), eval_id=EVR2)
        self.assertEqual((res.findings, res.comments, [d["reason"] for d in res.drops]), ([], [], ["invalid-citation"]))

    # ---- CONTROLS: nothing was relaxed
    def test_injected_tool_call_id_in_model_evidence_still_fails(self):
        m = self.case()
        item = {**m.cite("src/a.py", 2), "toolCallId": "tool_" + "1" * 16}
        self.assertTrue(validate("ModelEvidence", item))                               # schema still rejects the field
        h, _ = self.hypothesis(m)
        res, _ = self.record_turn(m, self.chain(m, h, evidence_of=lambda v: [item]))
        self.assertEqual((res.findings, res.comments, [d["reason"] for d in res.drops]), ([], [], ["verifier-failed"]))

    def test_id_lines_excerpt_stay_pinned_and_foreign_or_omitted_refs_are_rejected(self):
        m = self.case()
        h, _ = self.hypothesis(m)
        good = m.cite("src/a.py", 2)
        foreign = tcid("VERIFY", "verifier", 9, "read_file", side="head", path="src/util.py", start_line=1, end_line=2)
        cases = {
            "wrong excerpt": ([{**good, "excerpt": m.lines("src/a.py", 3)}], "invalid-citation"),
            "wrong lines": ([{**good, "lines": [1, 3]}], "invalid-citation"),
            "wrong commit": ([{**good, "commit": m.base_id}], "invalid-citation"),
            "foreign tool ref": ([good, {"kind": "tool-ref", "toolCallId": foreign, "index": 0}], "invalid-citation"),
            "omitted ref": ([], "verifier-failed"),
        }
        for n, (name, (ev, reason)) in enumerate(cases.items()):
            with self.subTest(name):
                res, _ = self.record_turn(m, self.chain(m, h, evidence_of=lambda v, ev=ev: ev, judged=False),
                                          eval_id=f"evr_{n + 5:016x}")
                self.assertEqual((res.findings, res.comments), ([], []))
                self.assertEqual(len(res.drops), 1)
                self.assertEqual(res.drops[0]["reason"], reason)

    def test_non_code_original_evidence_is_context_not_a_template(self):
        task = prompts.VERIFIER_REFUTE_TASK
        self.assertIn("exactly the five fields", task)
        self.assertIn("not a template", task)
        item = {"kind": "tool-result", "path": "src/a.py", "lines": [1, 1], "commit": "snap:sha256:" + "c" * 64,
                "excerpt": "x", "toolCallId": "tool_" + "3" * 16}
        state = {"hop": 0, "turns": 2, "lastTurn": False, "toolCallsRemaining": 3, "contextCharsRemaining": 10,
                 "toolsExhausted": False, "contextExhausted": False, "history": [], "continuationOf": None,
                 "contextResults": []}
        base_doc = {"task": task, "originalEvidence": [item, {**item, "kind": "code"}], "answerFormat": {}}
        from .helpers import PROFILE
        req = prompts.turn_request(PROFILE, "p@1", "verifier", base_doc, state, 6, retrieval.RETRIEVAL_VERSION)
        shown = doc_of(req)["originalEvidence"]
        self.assertEqual(shown[0], item)                                  # non-code entry is shown untouched
        self.assertEqual(set(shown[1]), CODE_FIELDS)
        inv = prompts.turn_request(PROFILE, "p@1", "investigator", base_doc, state, 6, retrieval.RETRIEVAL_VERSION)
        self.assertEqual(doc_of(inv)["originalEvidence"], base_doc["originalEvidence"])   # projection is verifier-only
        self.assertEqual(base_doc["originalEvidence"][1]["toolCallId"], item["toolCallId"])   # input not mutated

    # ---- deterministic requests
    def test_same_data_across_eval_run_ids_gives_identical_requests(self):
        m = self.case()
        h, _ = self.hypothesis(m)
        r1, s1 = self.record_turn(m, self.chain(m, h, evidence_of=lambda v: [m.cite("src/a.py", 2)]), eval_id=EVR1)
        r2, s2 = self.record_turn(m, self.chain(m, h, evidence_of=lambda v: [m.cite("src/a.py", 2)]), eval_id=EVR2)
        self.assertNotEqual(r1.run["id"], r2.run["id"])
        self.assertEqual(s1.requests, s2.requests)

    # ---- legacy preserved byte for byte; deliberate Turn-verifier identity change
    def test_legacy_requests_and_templates_are_unchanged_against_the_baseline(self):
        self.assertEqual(prompts.template_digests(), BASELINE_LEGACY_DIGESTS)
        case = {"pr": {"title": "T", "body": "B"}, "base": {"snapshotId": "snap:sha256:" + "a" * 64},
                "head": {"snapshotId": "snap:sha256:" + "b" * 64}}
        ev = [{"kind": "code", "path": "src/a.py", "lines": [1, 2], "commit": "snap:sha256:" + "b" * 64,
               "excerpt": "x", "toolCallId": "tool_" + "1" * 16, "resolved": True}]
        h = {"id": "hyp_" + "2" * 16, "claim": "c", "category": "bug", "location": {"path": "src/a.py", "line": 1},
             "evidence": ev}
        doc = prompts.verifier_doc(case, h, [], [], None)
        self.assertEqual(sha(doc), BASELINE_LEGACY_VERIFIER_DOC)
        self.assertEqual(doc["originalEvidence"][0]["toolCallId"], "tool_" + "1" * 16)    # legacy keeps its shape

    def test_only_the_turn_verifier_template_and_version_changed(self):
        now = prompts.retrieval_template_digests()
        self.assertEqual({k for k in now if now[k] != BASELINE_TURN_DIGESTS[k]}, {"verifier"})
        self.assertEqual(sha(prompts.INVESTIGATOR_RETRIEVE_TASK), BASELINE_INVESTIGATOR_TASK)
        self.assertEqual((retrieval.RETRIEVAL_VERSION, retrieval.INVESTIGATOR_PROMPT, retrieval.VERIFIER_PROMPT),
                         ("retrieval@2", "investigator.retrieve@v2", "verifier.refute@v4"))
        self.assertEqual(retrieval.RetrievalPolicy().to_doc()["verifier_prompt"], "verifier.refute@v4")
        self.assertEqual(identity.RETRIEVAL_BEHAVIOR, "retrieval-pipeline@2")          # no behavior bump: wording only


if __name__ == "__main__":
    unittest.main()
