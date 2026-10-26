"""Independent FR/TR5 RE-REVIEW of S0-03 (s0a-contracts@5 / redact@3). Reviewer-owned, offline,
stdlib only, no model/network calls, no target execution. @5 production code and these tests are
authoritative; nothing here edits production or author tests.

Class prefixes (same convention as the earlier rounds):
  P_*  CONTROL   investigator proposal binding
  V_*  CONTROL   verifier subject / evidence / severity binding
  D_*  CONTROL   duplicates and order
  R_*  CONTROL   role / schema
  T_*  CONTROL   tool result / status / index
  RC_* CONTROL   repair chains
  B_*  CONTROL   TR5 bounded read (real files, real fstat/read, no mocks of the guard under test)
  FRR* DEFECT    assert the CORRECT behaviour; a FAIL is a reproduced defect (see S0-03-frrereview.md)
  L_*  LIMIT     pass today; pin an explicit limit so a green run is not read as a guarantee

Every negative asserts its REASON (`contains=`), so it cannot pass vacuously because a fixture
lacked the request subject or carried a stale hash. Run:
  nice -n 19 python3 -m unittest discover -s tests/contract_review -p 'test_contract_frrereview.py' -v
"""
from __future__ import annotations

import copy
import os
import signal
import socket
import unittest
from unittest import mock

import finalreview_support as F
from test_contract_finalreview import ScenarioCase, provenance
from reviewer.contracts import canonical as C
from reviewer.contracts import check_finding_provenance, citable_tool_calls, validate
from reviewer.contracts import severity as S
from reviewer.contracts import snapshot as SN


# ------------------------------------------------------------------ helpers

def hyp_of(sc, **changes):
    """The honest investigator hypothesis, with changes."""
    return {**copy.deepcopy(sc.inv["response"]["output"]["hypotheses"][0]), **changes}


def investigator(sc, hypotheses, *, agent="generalist-0", seq=1):
    return F.model_call(sc.run, "INVESTIGATE", "investigator", agent, 0,
                        {"hypotheses": hypotheses}, seq=seq)


def verifier(sc, f, *, agent=None, ordinal=0, attempt=0, repair_of=None, seq=2, status="ok",
             output="honest", **kw):
    out = {**sc.confirm} if output == "honest" else output
    return F.model_call(sc.run, "VERIFY", "verifier", agent or "v-" + f["id"], ordinal, out,
                        status=status, attempt=attempt, repair_of=repair_of, seq=seq,
                        hyp=kw.pop("hyp", f["id"]), **kw)


def real_tool(run, n_items, *, status="ok", agent="v-tool", tool="pytest", args=None,
              kind="test-run", seq=3, stage="VERIFY"):
    """A tool.call whose evidence items carry the call's own toolCallId (as the tool layer mints).
    S1-01 review: `stage` added (default unchanged). @6 lets a legacy call cite only host tool calls of
    its own stage (or PREPARE) logged before it, so proposer-side fixtures use prop_tool()."""
    args = args if args is not None else {"k": 1}
    tid = C.tool_call_id(stage, agent, 0, tool, args)
    items = [{"kind": kind, "excerpt": f"item {i}", "source": tool, "toolCallId": tid}
             for i in range(n_items)]
    ev = F.tool_call(run, status, items, agent=agent, tool=tool, args=args, seq=seq, stage=stage)
    assert ev["toolCallId"] == tid
    return ev, items


def prop_tool(run, n_items, **kw):
    """S1-01 review adaptation: a tool call the proposer (INVESTIGATE, seq 1) may legitimately cite
    under @6: its own stage, logged before it. Same attack surface as the @5 fixture."""
    return real_tool(run, n_items, **{"stage": "INVESTIGATE", "seq": 0, **kw})


class Hung(BaseException):
    """Not an OSError/Exception: TimeoutError IS an OSError, which the code under test converts into
    SnapshotError, hiding a hang. A BaseException cannot be swallowed that way."""


def with_timeout(seconds):
    class _T:
        def __enter__(self):
            signal.signal(signal.SIGALRM, lambda *a: (_ for _ in ()).throw(Hung("hung")))
            signal.alarm(seconds)

        def __exit__(self, *a):
            signal.alarm(0)
    return _T()


# ====================================================================================== P: proposal

class P_ProposalBinding(ScenarioCase):
    def three_way(self):
        """Source output with the target at index 1 and a decoy at index 0."""
        decoy = hyp_of(self.sc, claim="Another claim", location={"path": "src/other.py", "line": 9})
        target = hyp_of(self.sc)
        inv = investigator(self.sc, [decoy, target])
        f = self.sc.fresh()
        f["id"] = C.hypothesis_id(f["specialist"], 1, f["claim"], f["location"]["path"], f["location"]["line"])
        f["sourceCallId"] = inv["callId"]
        ver = verifier(self.sc, f)
        f["verification"]["callIds"] = [ver["callId"]]
        return f, inv, ver

    def test_P1_the_id_binds_the_entry_index(self):
        f, inv, ver = self.three_way()
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(provenance(self.sc, f, [inv, ver]), [])
        wrong = copy.deepcopy(f)          # same claim and place, but index 0: the decoy sits there
        wrong["id"] = C.hypothesis_id(f["specialist"], 0, f["claim"], f["location"]["path"], f["location"]["line"])
        ver0 = verifier(self.sc, wrong)
        wrong["verification"]["callIds"] = [ver0["callId"]]
        self.assertRejected(wrong, [inv, ver0], "index 0 holds a different hypothesis",
                            "proposed no hypothesis with this id")

    def test_P2_every_proposal_field_must_equal_the_entry(self):
        for name, mutate in {
                "category": lambda f: f.update(category="style"),
                "suspectedSeverity": lambda f: f.update(suspectedSeverity="P2"),
                "impact": lambda f: f.update(impact="crash"),
                "location.endLine (not part of the id)": lambda f: f["location"].update(endLine=99),
        }.items():
            f = self.sc.fresh()
            mutate(f)
            with self.subTest(name):
                self.assertEqual(F.issues("Finding", f), [], "fixture must stay schema-valid")
                self.assertRejected(f, self.sc.events, name, "differs from the proposal")
        # The id is recomputed from the PROPOSAL's claim/location, so editing those on the Finding
        # shows up as a field difference; the specialist label is the one input only the id carries.
        for name, mutate in {"claim": lambda f: f.update(claim="Changed claim"),
                             "location.line": lambda f: f["location"].update(line=f["location"]["line"] + 1),
                             "location.path": lambda f: f["location"].update(path="src/zzz.py")}.items():
            f = self.sc.fresh()
            mutate(f)
            with self.subTest(name):
                self.assertRejected(f, self.sc.events, name, "differs from the proposal")
        f = self.sc.fresh()
        f["specialist"] = "someone-else"
        self.assertRejected(f, self.sc.events, "specialist is an id input", "proposed no hypothesis with this id")

    def test_P3_evidence_sides_are_not_interchangeable(self):
        """The proposer's list may only hold the proposer's citations, the verifier's list only the
        verifier's. The honest Scenario cites two different places, so a swap is detectable."""
        f = self.sc.fresh()
        f["evidence"], f["verification"]["evidence"] = f["verification"]["evidence"], f["evidence"]
        self.assertEqual(F.issues("Finding", f), [])
        got = [i.message for i in check_finding_provenance(f, self.sc.events)]
        self.assertTrue(any("was not cited by the proposal" in m for m in got), got)
        self.assertTrue(any("was not cited by a confirming verifier call" in m for m in got), got)

    def test_P4_a_subset_of_the_proposal_citations_is_fine_and_extra_citations_are_not(self):
        extra = {"kind": "code", "path": "src/b.py", "lines": [3, 4], "commit": "c" * 40, "excerpt": "z"}
        base = self.sc.inv["response"]["output"]["hypotheses"][0]["evidence"][0]
        inv = investigator(self.sc, [hyp_of(self.sc, evidence=[base, extra])])
        f = self.sc.fresh()
        f["sourceCallId"] = inv["callId"]
        self.assertEqual(provenance(self.sc, f, [inv, self.sc.ver]), [])
        g = self.sc.fresh()
        g["evidence"].append({**extra, "source": "investigator", "resolved": True})
        self.assertRejected(g, self.sc.events, "Finding lists a citation the proposer never made",
                            "was not cited by the proposal")

    def test_P5_the_source_output_must_itself_be_a_valid_investigator_output(self):
        bad = hyp_of(self.sc, evidence=[])        # HypothesisDraft needs at least one citation
        inv = investigator(self.sc, [bad])
        f = self.sc.fresh()
        f["sourceCallId"] = inv["callId"]
        self.assertRejected(f, [inv, self.sc.ver], "malformed source output",
                            "not a valid InvestigatorOutput")

    def test_P6_a_resolved_flag_on_the_model_citation_is_not_a_valid_source_output(self):
        forged = {**self.sc.inv["response"]["output"]["hypotheses"][0]["evidence"][0], "resolved": True}
        inv = investigator(self.sc, [hyp_of(self.sc, evidence=[forged])])
        f = self.sc.fresh()
        f["sourceCallId"] = inv["callId"]
        self.assertRejected(f, [inv, self.sc.ver], "the model asserted trust in its own output",
                            "not a valid InvestigatorOutput")


# ====================================================================================== V: verifier

class V_VerifierBinding(ScenarioCase):
    def test_V1_the_subject_is_covered_by_requestHash(self):
        """Editing the subject after hashing breaks the event; re-hashing yields a new call body."""
        other = verifier(self.sc, self.sc.finding, agent="v-hyp_ffffffffffffffff", hyp="hyp_" + "f" * 16)
        edited = copy.deepcopy(other)
        edited["request"]["hypothesisId"] = self.sc.finding["id"]
        self.assertTrue(validate("TraceEvent", edited), "stale requestHash must be detected")
        f = self.sc.fresh()
        f["verification"]["callIds"] = [edited["callId"]]
        self.assertRejected(f, [self.sc.inv, edited], "subject rewritten without re-hashing",
                            "is not a logged model call")
        rehashed = copy.deepcopy(edited)
        rehashed["requestHash"] = C.request_hash(rehashed["request"])
        self.assertNotEqual(rehashed["requestHash"], other["requestHash"])
        self.assertEqual(validate("TraceEvent", rehashed), [])
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, rehashed]), [],
                         "limit C2: a consistent rewrite validates (authenticity is the gateway's job)")

    def test_V2_every_listed_verifier_must_agree_with_severityBasis(self):
        f = self.sc.fresh()
        second = verifier(self.sc, f, agent="v-second", seq=3, output={**self.sc.confirm, "reachable": False})
        agree = verifier(self.sc, f, agent="v-second", seq=3)
        f["verification"]["callIds"] = [self.sc.ver["callId"], second["callId"]]
        self.assertRejected(f, [self.sc.inv, self.sc.ver, second], "second verifier says unreachable",
                            "severityBasis differs")
        f["verification"]["callIds"] = [self.sc.ver["callId"], agree["callId"]]
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, self.sc.ver, agree]), [])
        # the base impact: also checked per call, not only against the first
        lower = verifier(self.sc, f, agent="v-second", seq=3, output={**self.sc.confirm, "impact": "crash"})
        f["verification"]["callIds"] = [self.sc.ver["callId"], lower["callId"]]
        self.assertRejected(f, [self.sc.inv, self.sc.ver, lower], "second verifier names another impact",
                            "severityBasis differs")

    def test_V3_a_refuting_second_listed_verifier_blocks_acceptance(self):
        f = self.sc.fresh()
        ref = verifier(self.sc, f, agent="v-second", seq=3, output={**self.sc.confirm, "verdict": "refuted"})
        f["verification"]["callIds"] = [self.sc.ver["callId"], ref["callId"]]
        self.assertRejected(f, [self.sc.inv, self.sc.ver, ref], "listed refutation", "did not confirm")

    def test_V4_verification_evidence_may_come_from_either_confirming_call_but_only_from_them(self):
        f = self.sc.fresh()
        cite2 = {"kind": "code", "path": "src/x.py", "lines": [5, 6], "commit": "d" * 40, "excerpt": "q"}
        second = verifier(self.sc, f, agent="v-second", seq=3, output={**self.sc.confirm, "evidence": [cite2]})
        f["verification"]["callIds"] = [self.sc.ver["callId"], second["callId"]]
        f["verification"]["evidence"].append({**cite2, "source": "verifier", "resolved": True})
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, self.sc.ver, second]), [])
        # the same citation without the second call in the list is not backed
        g = copy.deepcopy(f)
        g["verification"]["callIds"] = [self.sc.ver["callId"]]
        self.assertRejected(g, [self.sc.inv, self.sc.ver, second], "citation of an unlisted verifier",
                            "was not cited by a confirming verifier call")

    def test_V5_the_two_distinct_verifiers_are_two_logical_calls(self):
        """Different agent labels are distinct logical calls; the same agent + ordinal is one."""
        f = self.sc.fresh()
        same_agent = verifier(self.sc, f, attempt=1, seq=3)       # same agent+ordinal, other attempt
        f["verification"]["callIds"] = [self.sc.ver["callId"], same_agent["callId"]]
        self.assertRejected(f, [self.sc.inv, self.sc.ver, same_agent], "one logical call listed twice",
                            "repeats a listed verification")
        other_ordinal = verifier(self.sc, f, ordinal=1, seq=3)
        f["verification"]["callIds"] = [self.sc.ver["callId"], other_ordinal["callId"]]
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, self.sc.ver, other_ordinal]), [],
                         "ordinal 1 of the same agent is a distinct logical call (pinned, see L_)")


# ====================================================================================== D: duplicates, order

class D_DuplicatesAndOrder(ScenarioCase):
    def test_D1_duplicate_ids_are_unusable_for_every_slot(self):
        twin_inv = copy.deepcopy(self.sc.inv)
        twin_inv["seq"] = 7
        self.assertRejected(self.sc.fresh(), [self.sc.inv, self.sc.ver, twin_inv], "source logged twice",
                            "logged more than once")
        twin_ver = copy.deepcopy(self.sc.ver)
        twin_ver["seq"] = 7
        self.assertRejected(self.sc.fresh(), [self.sc.inv, self.sc.ver, twin_ver], "verifier logged twice",
                            "logged more than once")

    def test_D2_an_invalid_twin_still_poisons_the_id(self):
        bad = copy.deepcopy(self.sc.ver)
        bad["requestHash"] = "sha256:" + "0" * 64
        for name, evs in (("valid first", [self.sc.inv, self.sc.ver, bad]),
                          ("invalid first", [self.sc.inv, bad, self.sc.ver])):
            with self.subTest(name):
                self.assertRejected(self.sc.fresh(), evs, "tampered duplicate of the verifier call",
                                    "logged more than once")

    def test_D3_an_event_of_another_run_does_not_poison_or_satisfy(self):
        foreign = copy.deepcopy(self.sc.ver)
        foreign["runId"] = "run_" + "e" * 16
        foreign["response"]["output"] = {**self.sc.confirm, "verdict": "refuted"}
        self.assertEqual(provenance(self.sc, self.sc.fresh(), [self.sc.inv, foreign, self.sc.ver]), [])
        only_foreign = F.model_call("run_" + "e" * 16, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0,
                                    self.sc.confirm, seq=2)
        self.assertRejected(self.sc.fresh(), [self.sc.inv, only_foreign], "same ids from another run",
                            "is not a logged model call")

    def test_D4_acceptance_does_not_depend_on_list_order_only_on_seq(self):
        self.assertEqual(provenance(self.sc, self.sc.fresh(), [self.sc.ver, self.sc.inv]), [])
        late_inv = copy.deepcopy(self.sc.inv)
        late_inv["seq"] = 5
        self.assertRejected(self.sc.fresh(), [late_inv, self.sc.ver], "verifier seq 2 < source seq 5",
                            "logged before the source call")

    def test_D5_duplicate_tool_call_ids_are_unusable(self):
        tool, items = prop_tool(self.sc.run, 1)
        f = self.sc.fresh()
        f["evidence"].append(items[0])
        inv = investigator(self.sc, [hyp_of(self.sc, evidence=[
            *self.sc.inv["response"]["output"]["hypotheses"][0]["evidence"],
            {"kind": "tool-ref", "toolCallId": tool["toolCallId"]}])])
        f["sourceCallId"] = inv["callId"]
        self.assertEqual(provenance(self.sc, f, [inv, self.sc.ver, tool]), [], "control: once is fine")
        twin = copy.deepcopy(tool)
        twin["seq"] = 9
        self.assertRejected(f, [inv, self.sc.ver, tool, twin], "tool call logged twice",
                            "logged more than once")


# ====================================================================================== R: role / schema

class R_RoleAndSchema(ScenarioCase):
    def rehash(self, ev):
        ev["requestHash"] = C.request_hash(ev["request"])
        return ev

    def test_R1_hypothesisId_is_verifier_only(self):
        hid = self.sc.finding["id"]
        for role, stage, schema in (("investigator", "INVESTIGATE", "InvestigatorOutput"),
                                    ("judge", "JUDGE", "JudgeOutput")):
            ev = F.model_call(self.sc.run, stage, role, "x", 0, {"hypotheses": []}, out_schema=schema)
            ev["request"]["hypothesisId"] = hid
            with self.subTest(role):
                self.assertTrue(validate("ModelRequest", ev["request"]))
                self.assertTrue(any("hypothesisId" in i.path for i in validate("ModelRequest", ev["request"])))
                with self.assertRaises(ValueError):
                    C.request_hash(ev["request"])
        bad = copy.deepcopy(self.sc.ver["request"])
        bad["hypothesisId"] = "hyp_nothex"
        self.assertTrue(validate("ModelRequest", bad))

    def test_R2_request_role_and_schema_must_follow_the_event_role(self):
        roles = {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput", "judge": "JudgeOutput"}
        for ev_role, stage in (("investigator", "INVESTIGATE"), ("verifier", "VERIFY"), ("judge", "JUDGE")):
            base = F.model_call(self.sc.run, stage, ev_role, "x", 0, {"hypotheses": []} if ev_role != "judge"
                                else {"comments": []}, out_schema=roles[ev_role], hyp=False)
            self.assertEqual(validate("TraceEvent", base), [], ev_role)
            for other, schema in roles.items():
                if other == ev_role:
                    continue
                for field, value, path in (("role", other, "$.request.role"),
                                           ("outputSchema", schema, "$.request.outputSchema")):
                    ev = copy.deepcopy(base)
                    ev["request"][field] = value
                    self.rehash(ev)                    # keep the hash honest: only the role rule is violated
                    got = [i.path for i in validate("TraceEvent", ev)]
                    with self.subTest(f"{ev_role} event with request.{field}={value}"):
                        self.assertIn(path, got)

    def test_R3_stage_role_pairing_is_a_provenance_rule(self):
        for role, stage, schema in (("investigator", "VERIFY", "InvestigatorOutput"),
                                    ("judge", "VERIFY", "JudgeOutput"),
                                    ("verifier", "JUDGE", "VerifierOutput"),
                                    ("verifier", "INVESTIGATE", "VerifierOutput")):
            ev = F.model_call(self.sc.run, stage, role, "w", 0, self.sc.confirm if role == "verifier"
                              else {"hypotheses": []} if role == "investigator" else {"comments": []},
                              out_schema=schema, seq=2, hyp=self.sc.finding["id"])
            f = self.sc.fresh()
            f["verification"]["callIds"] = [ev["callId"]]
            with self.subTest(f"{stage}/{role}"):
                self.assertEqual(validate("TraceEvent", ev), [], "a valid event; the wrong pairing is provenance's")
                self.assertRejected(f, [self.sc.inv, ev], "wrong stage/role in the verifier slot",
                                    "not VERIFY/verifier")

    def test_R4_contract_surface_is_versioned_and_exported(self):
        from reviewer.contracts import CONTRACTS_VERSION
        self.assertEqual(CONTRACTS_VERSION, "s0a-contracts@6")      # S1-01 review: expected version bump
        import json
        from pathlib import Path
        bundle = json.loads((Path(F.ROOT) / "reviewer/contracts/schemas/contracts.schema.json").read_text())
        text = json.dumps(bundle)
        self.assertIn("hypothesisId", text)
        for name in ("EvalReport.strict-replay", "EvalReport.unscored-real"):
            # S1-01 review: recorded example documents keep the version that produced them (@5). They
            # are not regenerated by the version bump and must stay valid; pinned so a silent re-stamp shows.
            self.assertEqual(F.ex(name)["contractsVersion"], "s0a-contracts@5")


# ====================================================================================== T: tool evidence

class T_ToolEvidence(ScenarioCase):
    def finding_with_tool(self, items_n, ref, pick, *, status="ok"):
        """A Finding whose proposer cited `ref` (extra tool-ref fields) and lists tool item `pick`."""
        tool, items = prop_tool(self.sc.run, items_n, status=status)
        cite = {"kind": "tool-ref", "toolCallId": tool["toolCallId"], **ref}
        inv = investigator(self.sc, [hyp_of(self.sc, evidence=[
            *self.sc.inv["response"]["output"]["hypotheses"][0]["evidence"], cite])])
        f = self.sc.fresh()
        f["sourceCallId"] = inv["callId"]
        f["evidence"].append(items[pick])
        return f, [inv, self.sc.ver, tool], tool, items, cite

    def test_T1_status_matrix(self):
        for status, accepted in (("ok", True), ("partial", True), ("empty", True),
                                 ("error", False), ("unavailable", False)):
            f, evs, *_ = self.finding_with_tool(1, {}, 0, status=status)
            with self.subTest(status):
                self.assertEqual(F.issues("Finding", f), [])
                if accepted:
                    self.assertEqual(provenance(self.sc, f, evs), [])
                else:
                    self.assertRejected(f, evs, f"{status} tool result", f"whose result is {status}")
        denied, _ = real_tool(self.sc.run, 0, status="denied")
        self.assertEqual(validate("TraceEvent", denied), [])
        self.assertEqual(denied["result"]["evidence"], [], "denied returns nothing to cite")

    def test_T2_index_is_honoured_exactly_like_materialize_evidence(self):
        f, evs, tool, items, cite = self.finding_with_tool(5, {"index": 3}, 3)
        self.assertEqual(provenance(self.sc, f, evs), [])
        # materialize_evidence over the very same reference produces exactly this item
        got, problems = S.materialize_evidence([cite], {tool["toolCallId"]: tool}, "investigator")
        self.assertEqual((got, problems), ([items[3]], []))
        g, evs_g, tool_g, *_ = self.finding_with_tool(5, {"index": 3}, 2)   # a sibling item, not item 3
        # S1-01 review: @6 words every "cited tool call, item outside the cited slice" rejection as
        # "not shown to (citable by)"; the tool IS citable (asserted), so the slice is the reason.
        self.assertIn(tool_g["toolCallId"], citable_tool_calls(evs_g[0]["callId"], evs_g))
        self.assertRejected(g, evs_g, "index 3 cited but item 2 listed", "was not shown to (citable by) the proposal")
        h, evs_h, tool_h, *_ = self.finding_with_tool(5, {"index": 99}, 4)  # index past the end
        self.assertIn(tool_h["toolCallId"], citable_tool_calls(evs_h[0]["callId"], evs_h))
        self.assertRejected(h, evs_h, "index out of range", "was not shown to (citable by) the proposal")

    def test_T3_without_an_index_only_the_first_twenty_items_are_citable(self):
        f19, evs19, *_ = self.finding_with_tool(25, {}, 19)
        self.assertEqual(provenance(self.sc, f19, evs19), [])
        f20, evs20, tool, items, cite = self.finding_with_tool(25, {}, 20)
        got, _ = S.materialize_evidence([cite], {tool["toolCallId"]: tool}, "investigator")
        self.assertNotIn(items[20], got, "materialize_evidence truncates at 20")
        self.assertIn(tool["toolCallId"], citable_tool_calls(evs20[0]["callId"], evs20))   # S1-01 review: see T2
        self.assertRejected(f20, evs20, "item 21 without an index", "was not shown to (citable by) the proposal")
        f_idx, evs_idx, *_ = self.finding_with_tool(25, {"index": 20}, 20)
        self.assertEqual(provenance(self.sc, f_idx, evs_idx), [])

    def test_T4_an_item_must_belong_to_the_call_it_names(self):
        f, evs, tool, items, cite = self.finding_with_tool(2, {}, 0)
        other, other_items = prop_tool(self.sc.run, 1, agent="v-other", tool="grep", args={"k": 2})
        borrowed = copy.deepcopy(items[0])
        borrowed["toolCallId"] = other["toolCallId"]                  # names the other call, text from this one
        g = copy.deepcopy(f)
        g["evidence"][-1] = borrowed
        self.assertRejected(g, [*evs, other], "item copied under another call's id",
                            "is not an item of the named tool call's result")
        h = copy.deepcopy(f)
        h["evidence"][-1] = other_items[0]                            # a real item, of a call nobody cited
        self.assertRejected(h, [*evs, other], "real item of an uncited call", "was not cited by the proposal")

    def test_T5_a_tampered_tool_event_is_not_a_logged_call(self):
        f, evs, tool, items, _ = self.finding_with_tool(1, {}, 0)
        bad = copy.deepcopy(tool)
        bad["result"]["notice"] = "edited after hashing"
        self.assertTrue(validate("TraceEvent", bad))
        self.assertRejected(f, [evs[0], evs[1], bad], "stale resultHash", "names a tool call not logged")

    def test_T7_a_tool_ref_only_backs_items_that_name_that_same_call(self):
        """Stricter than materialize_evidence (which would copy whatever item sits in the cited
        call's result): an item naming call B cannot ride on a tool-ref to call A even if A's
        result happens to contain it. Pinned so S0-07 mints items with their own call's id."""
        b, b_items = prop_tool(self.sc.run, 1, agent="v-b", tool="grep", args={"k": 2})
        a, _ = prop_tool(self.sc.run, 0, agent="v-a")
        a = copy.deepcopy(a)
        a["result"]["evidence"] = [copy.deepcopy(b_items[0])]          # A's result carries B's item
        a["resultHash"] = C.digest(a["result"])
        self.assertEqual(validate("TraceEvent", a), [])
        inv = investigator(self.sc, [hyp_of(self.sc, evidence=[
            *self.sc.inv["response"]["output"]["hypotheses"][0]["evidence"],
            {"kind": "tool-ref", "toolCallId": a["toolCallId"]}])])
        f = self.sc.fresh()
        f["sourceCallId"] = inv["callId"]
        f["evidence"].append(b_items[0])
        self.assertRejected(f, [inv, self.sc.ver, a, b], "item of call B cited through call A",
                            "was not cited by the proposal")

    def test_T6_verifier_side_tool_evidence_is_checked_like_proposer_side(self):
        tool, items = real_tool(self.sc.run, 1, seq=1)      # S1-01 review: VERIFY stage, logged before the verifier (seq 2)
        f = self.sc.fresh()
        ver = verifier(self.sc, f, output={**self.sc.confirm, "evidence": [
            *self.sc.confirm["evidence"], {"kind": "tool-ref", "toolCallId": tool["toolCallId"]}]})
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"].append(items[0])
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, ver, tool]), [])
        # the same item, cited only by the proposer's call, does not back the verifier's list
        g = copy.deepcopy(f)
        g["verification"]["callIds"] = [self.sc.ver["callId"]]
        self.assertRejected(g, [self.sc.inv, self.sc.ver, tool], "tool ref the verifier never made",
                            "was not cited by a confirming verifier call")


# ====================================================================================== RC: repair chains

class RC_RepairChains(ScenarioCase):
    def chain(self, depth, *, statuses=None):
        """V0 <- V1 <- ... (each a repair of the previous). Earlier links default to invalid-output
        (what the gateway produces before a repair); the last is the confirming call."""
        f = self.sc.fresh()
        links, prev = [], None
        for n in range(depth):
            last = n == depth - 1
            st = (statuses or {}).get(n, "ok" if last else "invalid-output")
            ev = verifier(self.sc, f, attempt=n, repair_of=prev, seq=2 + n, status=st,
                          output=self.sc.confirm if st == "ok" else None)
            links.append(ev)
            prev = ev["callId"]
        return f, links

    def test_RC1_a_repair_may_be_listed_alone_but_not_with_any_other_link(self):
        f, (v0, v1, v2) = self.chain(3)
        f["verification"]["callIds"] = [v2["callId"]]
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, v0, v1, v2]), [])
        for pair in ((v0, v2), (v1, v2)):
            g = copy.deepcopy(f)
            g["verification"]["callIds"] = [c["callId"] for c in pair]
            with self.subTest([p["attempt"] for p in pair]):
                got = [i.message for i in check_finding_provenance(g, [self.sc.inv, v0, v1, v2])]
                self.assertTrue(any("repeats a listed verification" in m or "did not return a usable" in m
                                    for m in got), got)
        # two repairs of the same original are one chain
        twin = verifier(self.sc, f, attempt=2, repair_of=v0["callId"], seq=9, agent="v-twin")
        g = copy.deepcopy(f)
        g["verification"]["callIds"] = [v2["callId"], twin["callId"]]
        self.assertRejected(g, [self.sc.inv, v0, v1, v2, twin], "two repairs of one call",
                            "repeats a listed verification")

    def test_RC2_a_chain_that_reaches_the_source_call_in_two_hops_is_refused(self):
        f = self.sc.fresh()
        v1 = verifier(self.sc, f, agent="v-x", attempt=1, repair_of=self.sc.inv["callId"], seq=3,
                      output=None, status="invalid-output")
        v2 = verifier(self.sc, f, agent="v-x", attempt=2, repair_of=v1["callId"], seq=4)
        f["verification"]["callIds"] = [v2["callId"]]
        self.assertRejected(f, [self.sc.inv, v1, v2], "repair of a repair of the source call",
                            "repair of the source call")

    def test_RC3_a_cyclic_chain_terminates(self):
        f = self.sc.fresh()
        a = verifier(self.sc, f, attempt=0, repair_of=C.call_id("VERIFY", "verifier", "v-" + f["id"], 0, 1))
        b = verifier(self.sc, f, attempt=1, repair_of=a["callId"], seq=3)
        f["verification"]["callIds"] = [b["callId"]]
        with with_timeout(5):
            check_finding_provenance(f, [self.sc.inv, a, b])

    def test_RC4_a_pure_retry_without_repairOf_is_still_one_logical_call(self):
        f = self.sc.fresh()
        retry = verifier(self.sc, f, attempt=2, seq=3)
        f["verification"]["callIds"] = [self.sc.ver["callId"], retry["callId"]]
        self.assertRejected(f, [self.sc.inv, self.sc.ver, retry], "attempt 0 and attempt 2",
                            "repeats a listed verification")


# ====================================================================================== B: TR5 bounded read

class SnapCase(unittest.TestCase):
    def tree(self, files: dict):
        repo = F.Repo(self, files)
        return repo, repo.dirs["head"], repo.manifests["head"]

    def instrument(self, *, grow_after_first_read=None):
        """Measure every os.read the module makes and every file/dir open it attempts.
        Returns (context manager, stats). The guard under test is not mocked."""
        stats = {"read": 0, "asked": [], "opens": 0}
        real_read = os.read
        real_open_dir, real_read_regular = SN._open_dir, SN._read_regular

        class W:
            def __getattr__(self, n):
                return getattr(os, n)

            def read(self, fd, n):
                stats["asked"].append(n)
                d = real_read(fd, n)
                stats["read"] += len(d)
                if grow_after_first_read and len(stats["asked"]) == 1:
                    grow_after_first_read()
                return d

        def open_dir(*a, **k):
            stats["opens"] += 1
            return real_open_dir(*a, **k)

        def read_regular(*a, **k):
            stats["opens"] += 1
            return real_read_regular(*a, **k)

        class Ctx:
            def __enter__(self_):
                self_.ps = [mock.patch.object(SN, "os", W()), mock.patch.object(SN, "_open_dir", open_dir),
                            mock.patch.object(SN, "_read_regular", read_regular)]
                for p in self_.ps:
                    p.start()

            def __exit__(self_, *a):
                for p in reversed(self_.ps):
                    p.stop()
        return Ctx(), stats


class B_BoundedRead(SnapCase):
    def test_B1_a_file_grown_after_pinning_is_refused_before_any_read(self):
        repo, head, man = self.tree({"a.py": "x = 1\n"})
        with open(head / "a.py", "r+b") as fh:
            fh.truncate(64 << 20)
        patch, stats = self.instrument()
        with patch, self.assertRaisesRegex(SN.SnapshotError, "read cap"):
            SN.read_verified(head, man, "a.py")
        self.assertEqual(stats["read"], 0, "refused on the descriptor's fstat size, no byte read")
        self.assertEqual(stats["asked"], [])

    def test_B2_concurrent_growth_reads_at_most_cap_plus_one_bytes(self):
        data = b"a" * 1000
        repo, head, man = self.tree({"a.bin": data})
        grow = lambda: open(head / "a.bin", "ab").write(b"b" * (1 << 20))
        patch, stats = self.instrument(grow_after_first_read=grow)
        with patch, self.assertRaisesRegex(SN.SnapshotError, "grew past"):
            SN.read_verified(head, man, "a.bin")
        self.assertEqual(stats["read"], 1001, "exactly cap + 1")
        self.assertLessEqual(max(stats["asked"]), 1001)
        self.assertLessEqual(sum(stats["asked"]), 1002)

    def test_B3_exact_size_and_the_default_cap_is_the_pinned_size(self):
        big = b"z" * (3 << 20)
        repo, head, man = self.tree({"big.bin": big, "empty": b""})
        patch, stats = self.instrument()
        with patch:
            self.assertEqual(SN.read_verified(head, man, "big.bin"), big)
            self.assertEqual(SN.read_verified(head, man, "empty"), b"")
        self.assertEqual(stats["read"], len(big))
        self.assertLessEqual(max(stats["asked"]), 1 << 16)

    def test_B4_max_bytes_rejects_before_opening_and_is_inclusive(self):
        repo, head, man = self.tree({"a.bin": b"x" * 100, "empty": b""})
        patch, stats = self.instrument()
        with patch:
            with self.assertRaisesRegex(SN.SnapshotError, "above max_bytes"):
                SN.read_verified(head, man, "a.bin", max_bytes=99)
            self.assertEqual(stats["opens"], 0, "refused from the manifest, before any open")
            self.assertEqual(len(SN.read_verified(head, man, "a.bin", max_bytes=100)), 100)
            self.assertEqual(len(SN.read_verified(head, man, "a.bin", max_bytes=10 ** 12)), 100)
            self.assertEqual(SN.read_verified(head, man, "empty", max_bytes=0), b"")

    def test_B5_max_bytes_must_be_a_non_negative_int(self):
        repo, head, man = self.tree({"a.bin": b"x"})
        for bad in (True, False, 1.0, "5", -1, 2.5, b"1", [1]):
            with self.subTest(repr(bad)), self.assertRaises(ValueError):
                SN.read_verified(head, man, "a.bin", max_bytes=bad)
        with self.assertRaises(TypeError):
            SN.read_verified(head, man, "a.bin", 100)           # keyword-only

    def test_B6_shrunk_or_rewritten_files_are_refused(self):
        repo, head, man = self.tree({"a.bin": b"x" * 100})
        (head / "a.bin").write_bytes(b"x" * 10)
        with self.assertRaisesRegex(SN.SnapshotError, "pinned at 100"):
            SN.read_verified(head, man, "a.bin")
        (head / "a.bin").write_bytes(b"y" * 100)
        with self.assertRaisesRegex(SN.SnapshotError, "does not match the snapshot"):
            SN.read_verified(head, man, "a.bin")

    def test_B7_a_hand_made_pin_that_overstates_the_size_costs_no_more_than_the_real_file(self):
        repo, head, man = self.tree({"a.bin": b"x" * 100})
        forged = copy.deepcopy(man)
        forged["entries"][0]["size"] = 1 << 40
        patch, stats = self.instrument()
        with patch, self.assertRaisesRegex(SN.SnapshotError, "pinned at"):
            SN.read_verified(head, forged, "a.bin")
        self.assertEqual(stats["read"], 100)
        self.assertLessEqual(max(stats["asked"]), 1 << 16, "no allocation sized by the pin")
        for bad in (-1, True, "100", None, 1.5):
            m = copy.deepcopy(man)
            m["entries"][0]["size"] = bad
            with self.subTest(repr(bad)), self.assertRaises(SN.SnapshotError):
                SN.read_verified(head, m, "a.bin")

    def test_B8_special_files_are_refused_as_snapshot_errors_without_blocking(self):
        import time
        repo, head, man = self.tree({"fifo": b"x" * 10, "sock": b"x", "dir": b"x" * 9000})
        for name in ("fifo", "sock", "dir"):
            (head / name).unlink()
        os.mkfifo(head / "fifo")
        s = socket.socket(socket.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(str(head / "sock"))
        (head / "dir").mkdir()                       # st_size 4096 < pinned 9000: size checks do not help
        writer = os.open(head / "fifo", os.O_RDWR)   # an open writer: a non-blocking read gives EAGAIN
        self.addCleanup(os.close, writer)
        patch, stats = self.instrument()
        t0 = time.monotonic()
        with patch, with_timeout(5):
            for name in ("fifo", "sock", "dir"):
                with self.subTest(name), self.assertRaisesRegex(SN.SnapshotError, "changed during snapshot|cannot open"):
                    SN.read_verified(head, man, name)
        self.assertLess(time.monotonic() - t0, 2.0, "refused promptly, no blocking open/read")
        self.assertEqual(stats["read"], 0)

    def test_B8b_a_fifo_with_no_writer_does_not_hang_the_open(self):
        import time
        repo, head, man = self.tree({"fifo": b""})
        (head / "fifo").unlink()
        os.mkfifo(head / "fifo")
        t0 = time.monotonic()
        with with_timeout(5):
            try:
                SN.read_verified(head, man, "fifo")        # empty pin: content b"" is all a FIFO could give
            except SN.SnapshotError:
                pass
        self.assertLess(time.monotonic() - t0, 2.0, "O_NONBLOCK keeps the open from waiting for a writer")

    def test_B8c_a_symlink_to_a_device_is_stopped_by_nofollow(self):
        repo, head, man = self.tree({"dev": b"x" * 10})
        (head / "dev").unlink()
        os.symlink("/dev/zero", head / "dev")
        patch, stats = self.instrument()
        with patch, with_timeout(5), self.assertRaises(SN.SnapshotError):
            SN.read_verified(head, man, "dev")
        self.assertEqual(stats["read"], 0)

    def test_B9_symlinks_are_never_followed(self):
        repo, head, man = self.tree({"a.py": b"one\n", "d/b.py": b"two\n", "outside": b"o"})
        # The link targets have exactly the pinned sizes, so only the no-follow open (not the size
        # check) can keep their bytes from being read; the hash check would only refuse them later.
        outside = head.parent / "outside_dir"
        outside.mkdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(outside, ignore_errors=True))
        (outside / "secret.txt").write_text("evil")             # 4 bytes, like a.py
        (outside / "b.py").write_text("EVIL")                   # 4 bytes, like d/b.py
        (head / "a.py").unlink()
        os.symlink(outside / "secret.txt", head / "a.py")       # leaf replaced by a link
        (head / "d" / "b.py").unlink()
        (head / "d").rmdir()
        os.symlink(outside, head / "d")                         # parent replaced by a link
        patch, stats = self.instrument()
        with patch:
            for path in ("a.py", "d/b.py"):
                with self.subTest(path), self.assertRaises(SN.SnapshotError):
                    SN.read_verified(head, man, path)
        self.assertEqual(stats["read"], 0)
        # a manifest that itself records a symlink is refused without touching the disk
        sm = SN.build_manifest(head)
        self.assertEqual([e["type"] for e in sm["entries"] if e["path"] == "a.py"], ["symlink"])
        with self.assertRaisesRegex(SN.SnapshotError, "not a regular file"):
            SN.read_verified(head, sm, "a.py")

    def test_B10_the_resolver_inherits_the_pinned_size_bound_and_fails_closed(self):
        repo, head, man = self.tree({"a.py": "one\ntwo\n"})
        cite = repo.cite("a.py", [1, 2], "one\ntwo")
        self.assertTrue(repo.resolver(cite))
        with open(head / "a.py", "r+b") as fh:
            fh.truncate(64 << 20)
        patch, stats = self.instrument()
        with patch:
            self.assertFalse(repo.resolver(cite))
        self.assertEqual(stats["read"], 0)
        _, problems = repo.materialize(cite)
        self.assertEqual(len(problems), 1, "an unresolvable citation is dropped, never marked resolved")

    def test_B11_unsafe_and_unlisted_paths_never_reach_the_disk(self):
        repo, head, man = self.tree({"a.py": b"x"})
        patch, stats = self.instrument()
        with patch:
            for p in ("../a.py", "/etc/passwd", "a.py/../a.py", "nope.py", ""):
                with self.subTest(p), self.assertRaises(SN.SnapshotError):
                    SN.read_verified(head, man, p)
        self.assertEqual(stats["opens"], 0)


# ====================================================================================== FRR defects

class FRR1_ARefutationCanBeLaunderedByARepair(ScenarioCase):
    """The gateway only repairs a response whose status is not `ok` (an `invalid-output` call).
    A chain whose earlier link is a VALID `refuted` (status ok) call is not something the
    gateway can produce, but check_finding_provenance accepts the confirming repair alone, so a
    refutation is forgotten by relabelling the next call as its repair."""

    def test_FRR1_a_repair_of_a_usable_refutation_is_not_a_confirmation(self):
        f = self.sc.fresh()
        refuted = verifier(self.sc, f, attempt=0, seq=2, output={**self.sc.confirm, "verdict": "refuted"})
        repair = verifier(self.sc, f, attempt=1, repair_of=refuted["callId"], seq=3)
        f["verification"]["callIds"] = [repair["callId"]]
        self.assertEqual(F.issues("Finding", f), [])
        self.assertRejected(f, [self.sc.inv, refuted, repair],
                            "confirming call is a 'repair' of a usable refutation")


class FRR2_RepairOfIsNotConstrainedToTheSameLogicalCall(ScenarioCase):
    def test_FRR2_a_source_call_cannot_be_a_repair_of_the_verifier_it_is_listed_with(self):
        """src.repairOf = listed verifier: the proposal is then derived from its own verification."""
        inv = investigator(self.sc, self.sc.inv["response"]["output"]["hypotheses"])
        inv = copy.deepcopy(inv)
        inv["repairOf"] = self.sc.ver["callId"]
        self.assertEqual(validate("TraceEvent", inv), [])
        f = self.sc.fresh()
        f["sourceCallId"] = inv["callId"]
        self.assertRejected(f, [inv, self.sc.ver], "investigator call 'repairing' its own verifier")


class FRR3_ToolCallsHaveNoOrderOrOwner(ScenarioCase):
    """check_finding_provenance only asks that the named tool.call exist once with a usable status
    and contain the item. It does not relate that call to the model call that cites it."""

    def verifier_citing(self, tool, item):
        f = self.sc.fresh()
        ver = verifier(self.sc, f, output={**self.sc.confirm, "evidence": [
            *self.sc.confirm["evidence"], {"kind": "tool-ref", "toolCallId": tool["toolCallId"]}]})
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"].append(item)
        self.assertEqual(F.issues("Finding", f), [])
        return f, [self.sc.inv, ver, tool]

    def test_FRR3a_a_tool_call_logged_after_the_model_call_that_cites_it(self):
        tool, items = real_tool(self.sc.run, 1, seq=50)        # the verifier call has seq 2
        f, evs = self.verifier_citing(tool, items[0])
        self.assertRejected(f, evs, "verifier output cites a tool call that did not exist yet")

    def test_FRR3b_a_tool_call_of_another_stage_and_agent_backs_verifier_evidence(self):
        tool, _ = real_tool(self.sc.run, 1, seq=1, agent="generalist-0")
        t = copy.deepcopy(tool)
        t["stage"] = "INVESTIGATE"                             # the proposer's tool call, not the verifier's
        t["toolCallId"] = C.tool_call_id("INVESTIGATE", t["agentId"], t["ordinal"], t["tool"], t["args"])
        for it in t["result"]["evidence"]:
            it["toolCallId"] = t["toolCallId"]
        t["resultHash"] = C.digest(t["result"])
        self.assertEqual(validate("TraceEvent", t), [])
        f, evs = self.verifier_citing(t, t["result"]["evidence"][0])
        self.assertRejected(f, evs, "verifier evidence backed by another agent's investigate-stage tool call")


# ====================================================================================== L: limits

class L_PinnedLimits(ScenarioCase):
    def test_L1_specialist_is_a_free_label_not_bound_to_the_source_agent(self):
        """The id recipe uses Finding.specialist (accepted deviation). specialist <-> agentId is
        not related by any rule, so an investigator agent 'beta-3' can supply a Finding whose
        specialist is 'alpha'."""
        f = self.sc.fresh()
        f["specialist"] = "alpha"
        f["id"] = C.hypothesis_id("alpha", 0, f["claim"], f["location"]["path"], f["location"]["line"])
        inv = investigator(self.sc, self.sc.inv["response"]["output"]["hypotheses"], agent="beta-3")
        ver = verifier(self.sc, f)
        f["sourceCallId"], f["verification"]["callIds"] = inv["callId"], [ver["callId"]]
        self.assertEqual(provenance(self.sc, f, [inv, ver]), [])

    def test_L2_unlisted_refutations_are_invisible_to_provenance(self):
        """VERIFY policy, not provenance, has to aggregate every verifier call for a hypothesis:
        a Finding that lists only the confirming call passes even when another call refuted it."""
        f = self.sc.fresh()
        ref = verifier(self.sc, f, agent="v-skeptic", seq=3, output={**self.sc.confirm, "verdict": "refuted"})
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, self.sc.ver, ref]), [])

    def test_L3_verifier_request_content_is_not_bound_to_its_subject_label(self):
        """request.hypothesisId is a label. The prompt text is not compared with the hypothesis, so a
        verifier asked about something else but labelled with this id confirms it."""
        f = self.sc.fresh()
        ver = verifier(self.sc, f, content="Check an entirely different claim in other.py")
        f["verification"]["callIds"] = [ver["callId"]]
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, ver]), [])

    def test_L4_verifier_citations_need_not_overlap_the_hypothesis_location(self):
        """The example verifier cites a place the Finding does not point at. Policy (C12 removed):
        independence is a distinct call, not location. A confirmation citing unrelated lines passes."""
        self.assertNotEqual(self.sc.confirm["evidence"][0]["path"], self.sc.finding["location"]["path"])
        self.assertEqual(provenance(self.sc, self.sc.fresh(), self.sc.events), [])

    def test_L5_provenance_never_re_resolves_citations(self):
        """see C1 in test_contract_finalreview; schema-valid is not snapshot-resolved."""
        repo = F.Repo(self, {"src/auth.py": "def f(t):\n    return True\n"})
        ghost = {"kind": "code", "path": "src/auth.py", "lines": [1, 1], "commit": repo.head_id,
                 "excerpt": "NOT WHAT THE FILE SAYS"}
        self.assertFalse(repo.resolver(ghost))
        out, problems = repo.materialize(ghost)
        self.assertEqual((out, len(problems)), ([], 1), "the real path drops it; nothing marks it resolved")
        f = self.sc.fresh()
        hand = {**ghost, "source": "investigator", "resolved": True}      # what a buggy caller could write
        f["evidence"][0], f["verification"]["evidence"][0] = hand, copy.deepcopy(hand)
        self.assertEqual(F.issues("Finding", f), [], "schema-valid ...")
        self.assertFalse(repo.resolver(ghost), "... but not snapshot-resolved")

    def test_L6_resolver_trusts_the_manifest_it_is_given(self):
        """snapshot_resolver/read_verified check bytes against the manifest, not the manifest against
        its snapshotId. A hand-edited manifest keeps the old id; require('SnapshotManifest') (which
        tools/view.py applies) is what catches it."""
        repo = F.Repo(self, {"a.py": "one\n"})
        head, man = repo.dirs["head"], copy.deepcopy(repo.manifests["head"])
        (head / "a.py").write_text("EVIL\n")
        import hashlib
        man["entries"][0].update(sha256=hashlib.sha256(b"EVIL\n").hexdigest(), size=5)
        self.assertTrue(validate("SnapshotManifest", man), "schema rejects the id mismatch")
        res = SN.snapshot_resolver({man["snapshotId"]: (head, man)})
        self.assertTrue(res({"kind": "code", "path": "a.py", "lines": [1, 1], "commit": man["snapshotId"],
                             "excerpt": "EVIL"}), "limit: the resolver does not re-validate the manifest")

    def test_L7_malformed_citation_shapes_raise_instead_of_returning_false(self):
        """Schema-valid citations never reach this; direct callers of the resolver should validate."""
        repo = F.Repo(self, {"a.py": "one\n"})
        for bad in ({"lines": [1]}, {"lines": "ab"}, {"excerpt": None}):
            c = {**repo.cite("a.py", [1, 1], "one"), **bad}
            with self.subTest(bad):
                try:
                    r = repo.resolver(c)
                except Exception as e:      # noqa: BLE001 - recording the behaviour
                    self.assertIsInstance(e, (ValueError, TypeError, AttributeError))
                else:
                    self.assertFalse(r)
                # and materialize_evidence converts either outcome into a dropped citation
                out, problems = S.materialize_evidence([c], {}, "i", resolver=repo.resolver)
                self.assertEqual((out, len(problems)), ([], 1))

    def test_L8_build_manifest_has_no_byte_cap(self):
        """TR5 bounds reads of an already-pinned file. Pinning itself reads whole files; callers
        bound what they snapshot. (Pinned structurally: _walk calls _read_regular without a limit.)"""
        import inspect
        self.assertNotIn("limit=", inspect.getsource(SN._walk))


if __name__ == "__main__":
    unittest.main()
