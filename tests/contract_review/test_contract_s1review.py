"""Independent S1-01 review of s0a-contracts@6 (Turn protocol and causal provenance). Reviewer-owned,
offline, stdlib only, no model/network calls, no target execution, no private state. Production code and
the author tests are authoritative; nothing here edits them.

Class prefixes (same convention as the earlier rounds):
  A_*    CONTROL  honest Turn chains are accepted at event, trace and Finding level
  C_*    CONTROL  continuation / repair causality
  O_*    CONTROL  requestedBy / requestIndex ordering
  E_*    CONTROL  own-chain evidence and verifier independence
  B_*    CONTROL  terminal payload binding
  V_*    CONTROL  verifier subject on every hop
  D2_*   CONTROL  exact read_file materialization (through the real severity.materialize_evidence)
  H_*    CONTROL  same-line legitimate confirmation
  S_*    CONTROL  schema surface of the new fields and envelopes
  D6_*   CONTROL  source literal preservation and the typed host-metadata boundary
  G_*    CONTROL  legacy hashes, legacy documents and trace compatibility
  FRR1H/FRR2H DEFECT  assert the CORRECT behaviour; a FAIL is a reproduced defect (see S1-01-review.md)
  L_*    LIMIT    pass today; pin an explicit limit so a green run is not read as a guarantee

Every negative asserts its REASON (`contains=`), so it cannot pass vacuously because a fixture was
malformed. Fixtures are payload-consistent (turn_support.py recomputes ids/hashes). Run:
  nice -n 19 python3 -m unittest discover -s tests/contract_review -p 'test_contract_s1review.py' -v
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import finalreview_support as F
import turn_support as T
from reviewer.contracts import CONTRACTS_VERSION, ROLE_SCHEMAS, check_finding_provenance, check_turn_trace
from reviewer.contracts import canonical as C
from reviewer.contracts import citable_tool_calls, serves_request, terminal_payload, turn_chain, usable_output
from reviewer.contracts import severity as S
from reviewer.contracts import validate, validate_trace

ROOT = F.ROOT


def prov(finding, events):
    return [i.message for i in check_finding_provenance(finding, events)]


def trace(events):
    return [i.message for i in check_turn_trace(events)]


class Base(unittest.TestCase):
    def setUp(self):
        self.s = T.TurnScenario()

    def assertProv(self, finding, events, why, contains):
        got = prov(finding, events)
        self.assertTrue(got, f"ACCEPTED but must be rejected: {why}")
        self.assertTrue(any(contains in m for m in got), f"rejected for another reason than {contains!r}: {got}")

    def assertTrace(self, events, why, contains):
        got = trace(events)
        self.assertTrue(got, f"ACCEPTED but must be rejected: {why}")
        self.assertTrue(any(contains in m for m in got), f"rejected for another reason than {contains!r}: {got}")

    def vchain(self, **over):
        """The verifier chain's pieces with the event list and Finding rebuilt around a changed final."""
        s = self.s
        hid = s.finding["id"]
        return hid, "v-" + hid

    def with_final(self, *, ver_out=None, inv_out=None, v_hop0=None, v_tool=None, v_cont=None, v_results=None,
                   v_agent=None, v_hyp=None):
        """Rebuild the verifier final (and optionally the investigator final) and the Finding."""
        s, hid = self.s, self.s.finding["id"]
        v0 = v_hop0 or s.v0
        tl = v_tool or s.v_tool
        v1 = T.turn_call(s.run, "verifier", v_agent or "v-" + hid, 1, hop=1,
                         cont=v_cont or v0["callId"], results=v_results if v_results is not None else [tl["toolCallId"]],
                         output=ver_out or T.final_ver(s.base), seq=6, hyp=v_hyp)
        i1 = s.i1
        if inv_out is not None:
            i1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=s.i0["callId"],
                             results=[s.i_tool["toolCallId"]], output=inv_out, seq=3)
        f = s.fresh()
        f["sourceCallId"] = i1["callId"]
        f["verification"]["callIds"] = [v1["callId"]]
        return f, [s.i0, s.i_tool, i1, v0, tl, v1]


# ====================================================================================== A: controls

class A_HonestTurnChains(Base):
    def test_every_event_is_schema_valid_and_the_trace_rules_pass(self):
        for ev in self.s.events:
            self.assertEqual(validate("TraceEvent", ev), [], ev["type"])
        self.assertEqual(trace(self.s.events), [])

    def test_the_finding_is_accepted_and_binds_to_terminal_payloads(self):
        self.assertEqual(F.issues("Finding", self.s.finding), [])
        self.assertEqual(prov(self.s.finding, self.s.events), [])
        self.assertEqual(terminal_payload(self.s.i1), T.final_inv(self.s.base))
        self.assertEqual(terminal_payload(self.s.v1), T.final_ver(self.s.base))
        self.assertIsNone(terminal_payload(self.s.i0), "a requesting hop has no terminal payload")

    def test_trace_keeps_the_envelope_unchanged(self):
        out = self.s.v1["response"]["output"]
        self.assertEqual(set(out), {"contextRequests", "output"})
        self.assertEqual(out["contextRequests"], [])
        self.assertEqual(out["output"], T.final_ver(self.s.base))

    def test_a_whole_run_trace_validates(self):
        run = F.ex("ReviewRun")
        start = {"schema": "trace-event@1", "runId": run["id"], "seq": 0, "type": "run.start", "run": run}
        end = {"schema": "trace-event@1", "runId": run["id"], "seq": 7, "type": "run.end",
               "status": "completed", "incomplete": []}
        self.assertEqual([i.message for i in validate_trace([start, *self.s.events, end])], [])

    def test_chains_are_walkable_root_first_and_citable_sets_are_their_own(self):
        hops, issues = turn_chain(self.s.v1["callId"], self.s.events)
        self.assertEqual((issues, [h["callId"] for h in hops]), ([], [self.s.v0["callId"], self.s.v1["callId"]]))
        self.assertEqual(set(citable_tool_calls(self.s.v1["callId"], self.s.events)), {self.s.v_tool["toolCallId"]})
        self.assertEqual(set(citable_tool_calls(self.s.i1["callId"], self.s.events)), {self.s.i_tool["toolCallId"]})
        self.assertEqual(citable_tool_calls("call_" + "0" * 16, self.s.events), {})


# ====================================================================================== C: continuation / repair

class C_ContinuationCausality(Base):
    def test_invalid_then_repaired_hop_continues_from_the_accepted_attempt(self):
        s, hid = self.s, self.s.finding["id"]
        bad = T.turn_call(s.run, "verifier", "v-" + hid, 1, hop=1, cont=s.v0["callId"], results=[s.v_tool["toolCallId"]],
                          raw_output={"contextRequests": [], "output": None}, seq=6)       # status ok but schema-invalid (D3)
        good = T.turn_call(s.run, "verifier", "v-" + hid, 1, hop=1, cont=s.v0["callId"], results=[s.v_tool["toolCallId"]],
                           output=T.final_ver(s.base), attempt=1, repair_of=bad["callId"], seq=7)
        self.assertFalse(usable_output(bad))
        f = s.fresh()
        f["verification"]["callIds"] = [good["callId"]]
        self.assertEqual(prov(f, [*s.events[:5], bad, good]), [])

    def test_continuing_an_unusable_attempt_is_refused(self):
        """The first attempt of hop 0 is schema-invalid; the repair is usable. hop 1 must continue the repair."""
        s, hid = self.s, self.s.finding["id"]
        bad = T.turn_call(s.run, "verifier", "v-" + hid, 0, raw_output={"contextRequests": [s.v_req], "output": T.final_ver(s.base)},
                          seq=3)
        rep = T.turn_call(s.run, "verifier", "v-" + hid, 0, requests=[s.v_req], attempt=1, repair_of=bad["callId"], seq=4)
        t = T.tool_event(s.run, "VERIFY", "v-" + hid, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")],
                         seq=5, by=rep, index=0)
        v1 = T.turn_call(s.run, "verifier", "v-" + hid, 1, hop=1, cont=bad["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=6)
        self.assertTrace([bad, rep, t, v1], "continues the unusable first attempt", "continues a call whose usable envelope requested no context")
        ok = T.turn_call(s.run, "verifier", "v-" + hid, 1, hop=1, cont=rep["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=6)
        self.assertEqual(trace([bad, rep, t, ok]), [], "control: continuing the repair is accepted")

    def test_tool_requested_by_the_unusable_attempt_is_refused(self):
        s = self.s
        bad = T.turn_call(s.run, "investigator", "generalist-0", 0,
                          raw_output={"contextRequests": [s.i_req], "output": T.final_inv(s.base)}, seq=1)
        rep = T.turn_call(s.run, "investigator", "generalist-0", 0, requests=[s.i_req], attempt=1, repair_of=bad["callId"], seq=2)
        t = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", s.i_req["args"], [T.code_item()], seq=3, by=bad, index=0)
        h1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=rep["callId"], results=[t["toolCallId"]],
                         output=T.final_inv(s.base), seq=4)
        self.assertTrace([bad, rep, t, h1], "tool attributed to an unusable attempt", "the requesting call made no request at this index")

    def test_continuation_rules(self):
        s = self.s
        h0 = s.i0
        res = [s.i_tool["toolCallId"]]
        out = T.final_inv(s.base)
        cases = {
            "a continuation reuses the ordinal": (T.turn_call(s.run, "investigator", "generalist-0", 0, hop=1, cont=h0["callId"],
                                                                 results=res, output=out, attempt=1, seq=3),
                                                  "a continuation needs a later ordinal"),
            "hop skips a level": (T.turn_call(s.run, "investigator", "generalist-0", 1, hop=2, cont=h0["callId"],
                                              results=res, output=out, seq=3), "the continued call is not hop - 1"),
            "another agent continues the chain": (T.turn_call(s.run, "investigator", "generalist-9", 1, hop=1,
                                                              cont=h0["callId"], results=res, output=out, seq=3),
                                                  "continues a call of another stage, role, agent"),
            "another prompt version": (None, "continues a call of another stage, role, agent, subject, prompt or schema"),
            "continues an unlogged call": (T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1,
                                                       cont="call_" + "5" * 16, results=res, output=out, seq=3),
                                           "is not a model call logged once"),
        }
        pv = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=h0["callId"], results=res, output=out, seq=3)
        pv["request"]["promptVersion"] = "investigator.generalist@v2"
        pv["requestHash"] = C.request_hash(pv["request"])
        cases["another prompt version"] = (pv, cases["another prompt version"][1])
        for name, (ev, why) in cases.items():
            with self.subTest(name):
                self.assertEqual(validate("TraceEvent", ev), [], "a valid event; the chain rule is the reason")
                self.assertTrace([h0, s.i_tool, ev], name, why)

    def test_continuing_from_a_later_logged_call_is_refused(self):
        s = self.s
        early = copy.deepcopy(s.i1)
        early["seq"] = 1
        h0 = copy.deepcopy(s.i0)
        h0["seq"] = 3
        t = copy.deepcopy(s.i_tool)
        t["seq"] = 4
        self.assertTrace([early, h0, t], "hop 1 logged before the hop it continues", "continues a call logged later")

    def test_a_fork_is_refused_but_attempts_of_one_logical_call_are_not_a_fork(self):
        s = self.s
        b = T.turn_call(s.run, "investigator", "generalist-0", 2, hop=1, cont=s.i0["callId"],
                        results=[s.i_tool["toolCallId"]], output=T.final_inv(s.base), seq=4)
        self.assertTrace([s.i0, s.i_tool, s.i1, b], "two logical calls continue one hop", "(fork)")
        retry = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=s.i0["callId"],
                            results=[s.i_tool["toolCallId"]], output=T.final_inv(s.base), attempt=1,
                            repair_of=s.i1["callId"], seq=4)
        self.assertEqual(trace([s.i0, s.i_tool, s.i1, retry]), [], "control: a retry of the same logical call")

    def test_multi_hop_chain_with_dedup_inside_the_chain_is_valid(self):
        s = self.s
        i0 = T.turn_call(s.run, "investigator", "generalist-0", 0, requests=[s.i_req], seq=1)
        t0 = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", s.i_req["args"], [T.code_item()], seq=2, by=i0, index=0)
        i1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=i0["callId"], results=[t0["toolCallId"]],
                         requests=[s.i_req], seq=3)
        i2 = T.turn_call(s.run, "investigator", "generalist-0", 2, hop=2, cont=i1["callId"], results=[t0["toolCallId"]],
                         output=T.final_inv(s.base), seq=4)
        self.assertEqual(trace([i0, t0, i1, i2]), [])
        self.assertEqual(set(citable_tool_calls(i2["callId"], [i0, t0, i1, i2])), {t0["toolCallId"]})
        f = s.fresh()
        f["sourceCallId"] = i2["callId"]
        self.assertEqual(prov(f, [i0, t0, i1, i2, s.v0, s.v_tool, s.v1]), [])

    def test_a_chain_cannot_be_cut_by_a_repair_that_forgets_the_hop_metadata(self):
        """Retries must copy hop/continuationOf/contextResults (interface section 2). The 'continuation' attempt that
        shows a different number of results than the hop asked for is refused."""
        s = self.s
        short = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=s.i0["callId"], results=[],
                            output=T.final_inv(s.base), seq=3)
        self.assertTrace([s.i0, s.i_tool, short], "continuation shows 0 results for 1 request", "shows 0 results for 1 requests")


# ====================================================================================== FRR1H / FRR2H: DEFECTS

class FRR1H_RefutationLaunderedThroughANonTerminalHop(Base):
    """FRR1 (S0-03 re-review) was closed for the TERMINAL call: ok_call walks the repairOf chain of each LISTED
    call and refuses a usable predecessor. @6 also made the listed call a Turn chain, but repair links of the
    EARLIER hops (hop 0 .. n-1) are never walked. A usable `refuted` answer can therefore be forgotten by
    relabelling the next attempt of hop 0 as its repair; that attempt then asks for context and the chain ends
    in `confirmed`. The same gateway guarantee FRR1 relied on (only unusable answers are repaired) is what is
    broken here, so the contract must refuse it exactly like the terminal case."""

    def laundered(self, first_output):
        s, hid = self.s, self.s.finding["id"]
        ag = "v-" + hid
        a0 = T.turn_call(s.run, "verifier", ag, 0, output=first_output, seq=4)
        a1 = T.turn_call(s.run, "verifier", ag, 0, requests=[s.v_req], attempt=1, repair_of=a0["callId"], seq=5)
        t = T.tool_event(s.run, "VERIFY", ag, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")], seq=6, by=a1, index=0)
        v1 = T.turn_call(s.run, "verifier", ag, 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=7)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        return f, [s.i0, s.i_tool, s.i1, a0, a1, t, v1], a0

    def test_CONTROL_terminal_repair_of_a_usable_refutation_is_refused_on_turn_calls_too(self):
        s, hid = self.s, self.s.finding["id"]
        ref = T.turn_call(s.run, "verifier", "v-" + hid, 0, output={**T.final_ver(s.base), "verdict": "refuted"}, seq=4)
        fix = T.turn_call(s.run, "verifier", "v-" + hid, 0, output=T.final_ver(s.base), attempt=1, repair_of=ref["callId"], seq=5)
        f = s.fresh()
        f["verification"]["callIds"] = [fix["callId"]]
        self.assertProv(f, [s.i0, s.i_tool, s.i1, ref, fix], "single-hop Turn repair of a usable refutation",
                        "is a repair of a usable response")

    def test_FRR1H_a_usable_refutation_repaired_by_a_context_request_does_not_survive(self):
        f, evs, a0 = self.laundered({**T.final_ver(self.s.base), "verdict": "refuted"})
        self.assertTrue(usable_output(a0))
        self.assertEqual(F.issues("Finding", f), [])
        self.assertProv(f, evs, "hop-0 attempt 0 is a usable refutation; attempt 1 'repairs' it and the chain confirms",
                        "usable")

    def test_FRR1H_a_usable_context_request_repaired_by_a_different_request_is_not_a_hidden_history(self):
        """Same root cause without a verdict: a usable hop is overwritten by a later 'repair' with other requests."""
        s = self.s
        other = T.creq(args={"path": "src/other.py", "side": "head"})
        f, evs, a0 = self.laundered(None)
        a0 = T.turn_call(s.run, "verifier", "v-" + s.finding["id"], 0, requests=[other], seq=4)
        evs[3] = a0
        evs[4] = T.turn_call(s.run, "verifier", "v-" + s.finding["id"], 0, requests=[s.v_req], attempt=1,
                             repair_of=a0["callId"], seq=5)
        evs[5] = T.tool_event(s.run, "VERIFY", "v-" + s.finding["id"], 0, "read_file", s.v_req["args"],
                              [T.code_item(path="src/store.py")], seq=6, by=evs[4], index=0)
        evs[6] = T.turn_call(s.run, "verifier", "v-" + s.finding["id"], 1, hop=1, cont=evs[4]["callId"],
                             results=[evs[5]["toolCallId"]], output=T.final_ver(s.base), seq=7)
        f["verification"]["callIds"] = [evs[6]["callId"]]
        self.assertTrue(usable_output(a0))
        self.assertProv(f, evs, "a usable non-final hop is 'repaired'", "usable")


class FRR2H_RepairLinksOfEarlierHopsAreNotChecked(Base):
    def test_FRR2H_a_hop_attempt_may_not_repair_another_agents_call(self):
        s = self.s
        hid = s.finding["id"]
        ag = "v-" + hid
        other = T.turn_call(s.run, "verifier", "v-other", 0, requests=[s.v_req], seq=3, hyp=hid)
        a1 = T.turn_call(s.run, "verifier", ag, 0, requests=[s.v_req], attempt=1, repair_of=other["callId"], seq=5)
        t = T.tool_event(s.run, "VERIFY", ag, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")], seq=6, by=a1, index=0)
        v1 = T.turn_call(s.run, "verifier", ag, 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=7)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        self.assertProv(f, [s.i0, s.i_tool, s.i1, other, a1, t, v1], "repairOf joins two different logical calls",
                        "repairOf does not name the previous attempt of the same logical call")


# ====================================================================================== O: requestedBy ordering

class O_RequestedByOrdering(Base):
    def two(self):
        s = self.s
        r1, r2 = T.creq(args={"path": "src/a.py", "side": "head"}), T.creq(args={"path": "src/b.py", "side": "head"})
        h0 = T.turn_call(s.run, "investigator", "generalist-0", 0, requests=[r1, r2], seq=1)
        t0 = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", r1["args"], [T.code_item(path="src/a.py")], seq=2, by=h0, index=0)
        t1 = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 1, "read_file", r2["args"], [T.code_item(path="src/b.py")], seq=3, by=h0, index=1)
        h1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=h0["callId"],
                         results=[t0["toolCallId"], t1["toolCallId"]], output=T.final_inv(s.base), seq=4)
        return r1, r2, h0, t0, t1, h1

    def test_control_two_requests_in_order(self):
        _, _, h0, t0, t1, h1 = self.two()
        self.assertEqual(trace([h0, t0, t1, h1]), [])

    def test_ordering_and_ownership_matrix(self):
        r1, r2, h0, t0, t1, h1 = self.two()
        s = self.s

        def moved(ev, **kw):
            c = copy.deepcopy(ev)
            c.update(kw)
            return c

        def rebuilt(**kw):
            ev = T.tool_event(s.run, kw.pop("stage", "INVESTIGATE"), kw.pop("agent", "generalist-0"), kw.pop("ordinal", 0),
                              "read_file", kw.pop("args", r1["args"]), [T.code_item(path="src/a.py")],
                              seq=kw.pop("seq", 2), by=kw.pop("by", h0), index=kw.pop("index", 0), **kw)
            return ev

        def with_hop1(results):
            return T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=h0["callId"], results=results,
                               output=T.final_inv(s.base), seq=4)

        rows = [
            ("tools executed out of index order", [h0, moved(t0, seq=3), moved(t1, seq=2), h1], "requests were executed out of index order"),
            ("a tool logged after the next hop started", [h0, t0, moved(t1, seq=5), h1], "logged after the next hop started"),
            ("a tool logged before the call that requested it", [h0, moved(t0, seq=0), t1, h1], "logged before the call that requested it"),
            ("a tool at an index the hop did not request", [h0, moved(t0, requestIndex=5), t1, h1], "the requesting call made no request at this index"),
            ("two tool calls answer one request", [h0, t0, rebuilt(ordinal=7), t1, h1], "more than one tool call answers this request"),
            ("contextResults permuted (positional)", [h0, t0, t1, with_hop1([t1["toolCallId"], t0["toolCallId"]])],
             "the next hop does not show this result at its request index"),
            ("a result is dropped", [h0, t0, t1, with_hop1([t0["toolCallId"]])], "shows 1 results for 2 requests"),
            ("a request has no tool call and no dedup", [h0, t0, with_hop1([t0["toolCallId"], t0["toolCallId"]])],
             "is neither the tool call made for this request nor an earlier result"),
            ("the tool belongs to another agent", [h0, rebuilt(agent="generalist-9"), t1, h1], "requested by a call of another stage or agent"),
            ("the tool belongs to another stage", [h0, rebuilt(stage="VERIFY"), t1, h1], "requested by a call of another stage or agent"),
            ("an ok result for other arguments than requested", [h0, rebuilt(args={"path": "src/z.py", "side": "head"}), t1, h1],
             "a usable result for another tool or other arguments than requested"),
            ("an ok result of another tool", [h0, T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "grep", r1["args"],
                                                               [T.code_item(path="src/a.py")], seq=2, by=h0, index=0), t1, h1],
             "a usable result for another tool or other arguments than requested"),
        ]
        for name, evs, why in rows:
            with self.subTest(name):
                self.assertTrace(evs, name, why)

    def test_unusable_results_need_not_match_the_request(self):
        """denied/error/unavailable results of a different shape are delivered honestly (control: no false positive)."""
        r1, r2, h0, t0, t1, h1 = self.two()
        s = self.s
        for status in ("denied", "error", "unavailable"):
            den = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", {"path": "src/z.py"},
                               [] if status == "denied" else [T.code_item(path="src/z.py")], status=status, seq=2, by=h0, index=0)
            h1d = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=h0["callId"],
                              results=[den["toolCallId"], t1["toolCallId"]], output=T.final_inv(s.base), seq=4)
            with self.subTest(status):
                self.assertEqual(trace([h0, den, t1, h1d]), [])

    def test_a_finding_citing_through_an_invalid_chain_is_refused(self):
        r1, r2, h0, t0, t1, h1 = self.two()
        s = self.s
        late = copy.deepcopy(t1)
        late["seq"] = 5
        inv_out = T.final_inv(s.base)
        f = s.fresh()
        f["sourceCallId"] = h1["callId"]
        self.assertProv(f, [h0, t0, late, h1, s.v0, s.v_tool, s.v1], "the source chain has a late tool call", "retrieval chain")
        self.assertEqual(citable_tool_calls(h1["callId"], [h0, t0, late, h1]), {}, "an invalid chain shows nothing citable")


# ====================================================================================== E: own-chain evidence

class E_OwnChainEvidence(Base):
    def cite(self, *, ver=(), inv=(), ver_items=(), inv_items=()):
        s = self.s
        inv_out = T.final_inv(s.base)
        inv_out["hypotheses"][0]["evidence"] += [{"kind": "tool-ref", **c} for c in inv]
        ver_out = T.final_ver(s.base)
        ver_out["evidence"] += [{"kind": "tool-ref", **c} for c in ver]
        f, evs = self.with_final(ver_out=ver_out, inv_out=inv_out)
        f["evidence"] += list(inv_items)
        f["verification"]["evidence"] += list(ver_items)
        return f, evs

    def test_control_each_chain_cites_its_own_delivered_result(self):
        s = self.s
        it, vt = s.i_tool["result"]["evidence"][0], s.v_tool["result"]["evidence"][0]
        f, evs = self.cite(inv=[{"toolCallId": s.i_tool["toolCallId"], "index": 0}], inv_items=[it],
                           ver=[{"toolCallId": s.v_tool["toolCallId"], "index": 0}], ver_items=[vt])
        self.assertEqual(prov(f, evs), [])

    def test_verifier_cannot_cite_the_investigator_chains_retrieval(self):
        s = self.s
        it = s.i_tool["result"]["evidence"][0]
        f, evs = self.cite(ver=[{"toolCallId": s.i_tool["toolCallId"], "index": 0}], ver_items=[it])
        self.assertProv(f, evs, "verifier cites investigator-chain tool", "was not shown to (citable by) a confirming verifier call")

    def test_investigator_cannot_cite_the_verifier_chains_retrieval(self):
        s = self.s
        vt = s.v_tool["result"]["evidence"][0]
        f, evs = self.cite(inv=[{"toolCallId": s.v_tool["toolCallId"], "index": 0}], inv_items=[vt])
        self.assertProv(f, evs, "proposal cites a tool result from the verify stage", "was not shown to (citable by) the proposal")

    def test_verifier_chain_cannot_be_shown_the_investigators_result_even_by_dedup(self):
        """hop 1 of the verifier chain lists the investigator-chain tool for a request it serves."""
        s, hid = self.s, self.s.finding["id"]
        v0 = T.turn_call(s.run, "verifier", "v-" + hid, 0, requests=[s.i_req], seq=4)
        v1 = T.turn_call(s.run, "verifier", "v-" + hid, 1, hop=1, cont=v0["callId"], results=[s.i_tool["toolCallId"]],
                         output=T.final_ver(s.base), seq=5)
        self.assertTrue(serves_request(s.i_req, s.i_tool), "the borrowed result would serve the request")
        self.assertTrace([s.i0, s.i_tool, s.i1, v0, v1], "cross-chain dedup",
                         "is neither the tool call made for this request nor an earlier result of this chain")

    def test_a_sibling_chain_of_the_same_agent_is_not_the_same_chain(self):
        s = self.s
        j0 = T.turn_call(s.run, "investigator", "generalist-0", 5, requests=[s.i_req], seq=1)
        tj = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 5, "read_file", s.i_req["args"], [T.code_item()], seq=2, by=j0, index=0)
        k0 = T.turn_call(s.run, "investigator", "generalist-0", 6, requests=[s.i_req], seq=3)
        k1 = T.turn_call(s.run, "investigator", "generalist-0", 7, hop=1, cont=k0["callId"], results=[tj["toolCallId"]],
                         output=T.final_inv(s.base), seq=4)
        self.assertTrace([j0, tj, k0, k1], "dedup against a sibling chain", "is neither the tool call made for this request")

    def test_hop0_shows_only_host_context_of_its_own_stage(self):
        s, hid = self.s, self.s.finding["id"]
        host_prep = T.tool_event(s.run, "PREPARE", "host", 0, "read_file", {"path": "src/h.py"}, [T.code_item(path="src/h.py")], seq=0)
        host_inv = T.tool_event(s.run, "INVESTIGATE", "host", 0, "read_file", {"path": "src/q.py"}, [T.code_item(path="src/q.py")], seq=0)
        host_ver = T.tool_event(s.run, "VERIFY", "host", 0, "read_file", {"path": "src/v.py"}, [T.code_item(path="src/v.py")], seq=0)

        def hop0(role, tool, *, seq=4, agent=None):
            ag = agent or ("v-" + hid if role == "verifier" else "generalist-0")
            return T.turn_call(s.run, role, ag, 0, results=[tool["toolCallId"]], requests=[s.v_req], seq=seq)

        self.assertEqual(trace([host_prep, hop0("verifier", host_prep)]), [], "control: PREPARE context, both roles")
        self.assertEqual(trace([host_prep, hop0("investigator", host_prep)]), [])
        self.assertEqual(trace([host_ver, hop0("verifier", host_ver)]), [], "control: own-stage host context")
        self.assertTrace([host_inv, hop0("verifier", host_inv)], "a verifier is shown INVESTIGATE-stage context",
                         "a VERIFY call is shown ['PREPARE', 'VERIFY'] context, not INVESTIGATE")
        self.assertTrace([host_ver, hop0("investigator", host_ver)], "an investigator is shown VERIFY-stage context",
                         "a INVESTIGATE call is shown ['PREPARE', 'INVESTIGATE'] context, not VERIFY")
        self.assertTrace([s.i0, s.i_tool, hop0("verifier", s.i_tool)], "hop 0 is shown a model-requested result",
                         "hop 0 shows only host-prepared tool calls")
        late = T.tool_event(s.run, "PREPARE", "host", 1, "read_file", {"path": "src/l.py"}, [T.code_item(path="src/l.py")], seq=9)
        self.assertTrace([hop0("verifier", late), late], "shown a result logged later", "is logged after the call that shows it")
        ghost = {"toolCallId": "tool_" + "7" * 16}
        self.assertTrace([hop0("verifier", ghost)], "shown an unlogged result", "is not a tool call logged once")

    def test_a_duplicated_tool_id_is_unusable_for_delivery(self):
        s = self.s
        twin = copy.deepcopy(s.i_tool)
        twin["seq"] = 9
        self.assertTrace([*s.events, twin], "the delivered tool call is logged twice", "logged once in this run")


# ====================================================================================== B: terminal binding

class B_TerminalBinding(Base):
    def test_matrix(self):
        s, hid = self.s, self.s.finding["id"]
        ag = "v-" + hid
        f = s.fresh()
        f["sourceCallId"] = s.i0["callId"]
        self.assertProv(f, s.evs(), "source is a requesting hop", "source call output is not a valid InvestigatorOutput final Turn")
        g = s.fresh()
        g["verification"]["callIds"] = [s.v0["callId"]]
        self.assertProv(g, s.evs(), "verifier is a requesting hop", "verifier call did not confirm")
        rows = {
            "status-ok envelope with both requests and output": {"contextRequests": [s.v_req], "output": T.final_ver(s.base)},
            "unwrapped VerifierOutput under the Turn schema": T.final_ver(s.base),
            "final envelope without an output": {"contextRequests": [], "output": None},
            "envelope with an extra field": {"contextRequests": [], "output": T.final_ver(s.base), "extra": 1},
        }
        for name, raw in rows.items():
            bad = T.turn_call(s.run, "verifier", ag, 1, hop=1, cont=s.v0["callId"], results=[s.v_tool["toolCallId"]],
                              raw_output=raw, seq=6)
            h = s.fresh()
            h["verification"]["callIds"] = [bad["callId"]]
            with self.subTest(name):
                self.assertEqual(validate("TraceEvent", bad), [], "the event is a valid document; D3 usability is the reason")
                self.assertFalse(usable_output(bad))
                self.assertProv(h, [*s.events[:5], bad], name, "verifier call did not confirm")

    def test_a_terminal_refutation_or_uncertain_cannot_confirm(self):
        s = self.s
        for verdict in ("refuted", "uncertain"):
            f, evs = self.with_final(ver_out={**T.final_ver(s.base), "verdict": verdict})
            with self.subTest(verdict):
                self.assertProv(f, evs, f"terminal {verdict}", "verifier call did not confirm")

    def test_severity_basis_is_taken_from_the_terminal_payload(self):
        s = self.s
        f, evs = self.with_final(ver_out={**T.final_ver(s.base), "reachable": not s.finding["severityBasis"]["reachable"]})
        self.assertProv(f, evs, "reachable differs from the terminal payload", "severityBasis differs")

    def test_the_proposal_is_taken_from_the_terminal_payload_not_an_earlier_hop(self):
        s = self.s
        out = T.final_inv(s.base)
        out["hypotheses"][0]["claim"] = "A different claim than the Finding records"
        f, evs = self.with_final(inv_out=out)
        self.assertProv(f, evs, "terminal proposal differs from the Finding", "the source call proposed no hypothesis with this id")

    def test_hop_calls_of_one_chain_count_once(self):
        s = self.s
        retry = T.turn_call(s.run, "verifier", "v-" + s.finding["id"], 1, hop=1, cont=s.v0["callId"],
                            results=[s.v_tool["toolCallId"]], output=T.final_ver(s.base), attempt=1,
                            repair_of=s.v1["callId"], seq=7)
        f = s.fresh()
        f["verification"]["callIds"] = [s.v1["callId"], retry["callId"]]
        self.assertProv(f, [*s.events, retry], "a call and its retry listed as two verifications",
                        "repeats a listed verification")
        g = s.fresh()
        g["verification"]["callIds"] = [s.v1["callId"], s.v1["callId"]]
        self.assertTrue(F.issues("Finding", g), "the same id twice is already a schema error (duplicate items)")

    def test_legacy_and_turn_calls_mix_in_one_finding(self):
        """A plain (legacy) investigator source with a Turn verifier chain, and the reverse, are both accepted."""
        s = self.s
        base = s.base
        f = s.fresh()
        f["sourceCallId"] = base.inv["callId"]
        self.assertEqual(prov(f, [base.inv, s.v0, s.v_tool, s.v1]), [])
        g = s.fresh()
        ver = F.model_call(s.run, "VERIFY", "verifier", "v-" + s.finding["id"], 0, base.confirm, seq=6)
        g["verification"]["callIds"] = [ver["callId"]]
        self.assertEqual(prov(g, [s.i0, s.i_tool, s.i1, ver]), [])


# ====================================================================================== V: verifier subject

class V_VerifierSubject(Base):
    def chain(self, h0_hyp=None, h1_hyp=None, omit0=False, omit1=False):
        s, hid = self.s, self.s.finding["id"]
        ag = "v-" + hid
        v0 = T.turn_call(s.run, "verifier", ag, 0, requests=[s.v_req], seq=4, hyp=h0_hyp, omit_hyp=omit0)
        t = T.tool_event(s.run, "VERIFY", ag, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")], seq=5, by=v0, index=0)
        v1 = T.turn_call(s.run, "verifier", ag, 1, hop=1, cont=v0["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=6, hyp=h1_hyp, omit_hyp=omit1)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        return f, [s.i0, s.i_tool, s.i1, v0, t, v1]

    def test_control_every_hop_names_the_finding(self):
        f, evs = self.chain()
        self.assertEqual(prov(f, evs), [])

    def test_a_hop_that_does_not_name_the_same_subject_breaks_the_chain(self):
        other = "hyp_" + "1" * 16
        for name, kw in (("hop 0 omits it", dict(omit0=True)), ("hop 0 names another", dict(h0_hyp=other)),
                         ("hop 1 omits it", dict(omit1=True)), ("hop 1 names another", dict(h1_hyp=other))):
            f, evs = self.chain(**kw)
            with self.subTest(name):
                self.assertProv(f, evs, name, "continues a call of another stage, role, agent, subject, prompt or schema")

    def test_a_whole_chain_without_or_with_a_wrong_subject_cannot_confirm(self):
        other = "hyp_" + "1" * 16
        for name, kw in (("no hop names it", dict(omit0=True, omit1=True)), ("every hop names another", dict(h0_hyp=other, h1_hyp=other))):
            f, evs = self.chain(**kw)
            with self.subTest(name):
                self.assertProv(f, evs, name, "verifier request does not name this hypothesis")

    def test_only_a_verifier_request_may_name_a_subject(self):
        req = copy.deepcopy(self.s.i0["request"])
        req["hypothesisId"] = self.s.finding["id"]
        self.assertTrue(validate("ModelRequest", req))


# ====================================================================================== D2: exact read_file materialization

class D2_ExactReadFileMaterialization(Base):
    """read_file items are minted by the tool layer as resolved code Evidence carrying their own toolCallId.
    A Finding may list them only through a tool-ref, exactly as severity.materialize_evidence copies them."""

    def setUp(self):
        super().setUp()
        self.repo = F.Repo(self, {"src/store.py": "a = 1\nb = 2\nc = 3\n", "src/auth.py": "x = 1\ny = 2\n"})
        item = self.repo.materialize(self.repo.cite("src/store.py", [1, 2], "a = 1\nb = 2"), source="read_file")[0][0]
        self.item = item
        s = self.s
        s.v_tool = T.tool_event(s.run, "VERIFY", "v-" + s.finding["id"], 0, "read_file", s.v_req["args"],
                                [{k: v for k, v in item.items()}], seq=5, by=s.v0, index=0)
        s.v1 = T.turn_call(s.run, "verifier", "v-" + s.finding["id"], 1, hop=1, cont=s.v0["callId"],
                           results=[s.v_tool["toolCallId"]], output=T.final_ver(s.base), seq=6)

    def finding(self, items, *, cite_index=0, tool=None, ver_out_extra=()):
        s = self.s
        tool = tool or s.v_tool
        out = T.final_ver(s.base)
        out["evidence"] = [*out["evidence"], {"kind": "tool-ref", "toolCallId": tool["toolCallId"],
                                              **({"index": cite_index} if cite_index is not None else {})}, *ver_out_extra]
        v1 = T.turn_call(s.run, "verifier", "v-" + s.finding["id"], 1, hop=1, cont=s.v0["callId"],
                         results=[tool["toolCallId"]], output=out, seq=6)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        f["verification"]["evidence"] = [*f["verification"]["evidence"], *items]
        return f, [s.i0, s.i_tool, s.i1, s.v0, tool, v1], v1

    def test_the_tool_item_is_a_resolved_code_item_naming_its_own_call(self):
        it = self.s.v_tool["result"]["evidence"][0]
        self.assertEqual((it["kind"], it["resolved"], it["source"]), ("code", True, "read_file"))
        self.assertEqual(it["toolCallId"], self.s.v_tool["toolCallId"])
        self.assertEqual(validate("TraceEvent", self.s.v_tool), [])

    def test_materialization_and_provenance_agree_on_the_accepted_item(self):
        f0, evs, v1 = self.finding([])
        got, problems = S.materialize_evidence(
            [{"kind": "tool-ref", "toolCallId": self.s.v_tool["toolCallId"], "index": 0}],
            citable_tool_calls(v1["callId"], evs), "verifier", resolver=self.repo.resolver)
        self.assertEqual(problems, [])
        self.assertEqual(got, [self.s.v_tool["result"]["evidence"][0]])
        f, evs, _ = self.finding(got)
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(prov(f, evs), [])

    def test_every_field_of_the_item_is_exact(self):
        f0, evs, _ = self.finding([])
        base = self.s.v_tool["result"]["evidence"][0]
        edits = {"excerpt": "a = 1\nb = 9", "lines": [1, 3], "path": "src/auth.py", "commit": "snap:sha256:" + "cd" * 32,
                 "source": "grep"}
        for k, v in edits.items():
            x = copy.deepcopy(base)
            x[k] = v
            f, evs, _ = self.finding([x])
            with self.subTest(k):
                self.assertProv(f, evs, f"item with altered {k}", "is not an item of the named tool call's result")
        y = copy.deepcopy(base)
        y.pop("resolved")
        f, evs, _ = self.finding([y])
        self.assertTrue(prov(f, evs), "an item without resolved:true is not trusted code evidence")

    def test_the_materializer_re_resolves_read_file_items_against_the_snapshot(self):
        tool = copy.deepcopy(self.s.v_tool)
        tool["result"]["evidence"][0]["excerpt"] = "a = 1\nb = 9"        # the tool layer 'lied': not what the snapshot holds
        tool["resultHash"] = C.digest(tool["result"])
        got, problems = S.materialize_evidence(
            [{"kind": "tool-ref", "toolCallId": tool["toolCallId"], "index": 0}], {tool["toolCallId"]: tool}, "verifier",
            resolver=self.repo.resolver)
        self.assertEqual(got, [])
        self.assertEqual(problems, ["[0] tool code item does not match the pinned snapshot"])
        unresolved = copy.deepcopy(self.s.v_tool)
        unresolved["result"]["evidence"][0].pop("resolved")
        got, problems = S.materialize_evidence(
            [{"kind": "tool-ref", "toolCallId": unresolved["toolCallId"]}], {unresolved["toolCallId"]: unresolved}, "verifier",
            resolver=self.repo.resolver)
        self.assertEqual((got, len(problems)), ([], 1))

    def test_index_and_first_twenty_slice(self):
        s = self.s
        items = [T.code_item(path="src/store.py", lines=(1, 1), excerpt=f"line {i}") for i in range(25)]
        tool = T.tool_event(s.run, "VERIFY", "v-" + s.finding["id"], 0, "read_file", s.v_req["args"], items, seq=5, by=s.v0, index=0)
        for n, idx, ok in ((19, None, True), (20, None, False), (20, 20, True), (3, 4, False), (99, 99, False)):
            x = tool["result"]["evidence"][n] if n < 25 else tool["result"]["evidence"][0]
            f, evs, _ = self.finding([x], cite_index=idx, tool=tool)
            with self.subTest(f"item {n} cited index={idx}"):
                if ok:
                    self.assertEqual(prov(f, evs), [])
                else:
                    self.assertProv(f, evs, "outside the cited slice", "was not shown to (citable by) a confirming verifier call")

    def test_a_plain_code_citation_cannot_stand_in_for_a_tool_item_and_back(self):
        """An item stripped of its toolCallId is plain code evidence: it must equal a code citation, not a tool item."""
        stripped = {k: v for k, v in self.s.v_tool["result"]["evidence"][0].items() if k != "toolCallId"}
        f, evs, _ = self.finding([stripped])
        self.assertProv(f, evs, "tool item relabelled as plain code", "was not cited by a confirming verifier call")

    def test_the_item_must_be_listed_on_the_side_that_cited_it(self):
        s = self.s
        x = s.v_tool["result"]["evidence"][0]
        f, evs, _ = self.finding([])
        f["evidence"] = [*f["evidence"], x]
        self.assertProv(f, evs, "verifier-cited item listed as proposer evidence", "was not cited by the proposal")

    def test_tool_status_matrix(self):
        s = self.s
        for status, ok in (("ok", True), ("partial", True), ("empty", True), ("error", False), ("unavailable", False)):
            tool = T.tool_event(s.run, "VERIFY", "v-" + s.finding["id"], 0, "read_file", s.v_req["args"],
                                [self.item], status=status, seq=5, by=s.v0, index=0)
            f, evs, _ = self.finding([tool["result"]["evidence"][0]], tool=tool)
            with self.subTest(status):
                if ok:
                    self.assertEqual(prov(f, evs), [])
                else:
                    self.assertProv(f, evs, f"{status} result", f"whose result is {status}")

    def test_the_toolcallid_of_a_code_item_must_name_a_logged_call(self):
        x = copy.deepcopy(self.s.v_tool["result"]["evidence"][0])
        x["toolCallId"] = "tool_" + "9" * 16
        f, evs, _ = self.finding([x])
        self.assertProv(f, evs, "unlogged toolCallId on code evidence", "names a tool call not logged in this run")


# ====================================================================================== H: same-line confirmation

class H_SameLineConfirmation(Base):
    def test_a_verifier_chain_confirms_citing_exactly_the_proposers_lines(self):
        s = self.s
        prop = {k: s.finding["evidence"][0][k] for k in F.Scenario.CODE_KEYS}
        f, evs = self.with_final(ver_out={**T.final_ver(s.base), "evidence": [prop]})
        f["verification"]["evidence"] = copy.deepcopy(f["evidence"])
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(prov(f, evs), [])

    def test_the_same_line_may_also_be_reached_through_the_verifiers_own_read_file(self):
        repo = F.Repo(self, {"src/auth.py": "def f(t):\n    if t is None:\n        return True\n"})
        cite = repo.cite("src/auth.py", [2, 3], "    if t is None:\n        return True")
        s = self.s
        item = repo.materialize(cite, source="read_file")[0][0]
        tool = T.tool_event(s.run, "VERIFY", "v-" + s.finding["id"], 0, "read_file", s.v_req["args"], [item], seq=5, by=s.v0, index=0)
        out = {**T.final_ver(s.base), "evidence": [cite, {"kind": "tool-ref", "toolCallId": tool["toolCallId"], "index": 0}]}
        inv_out = T.final_inv(s.base)
        inv_out["hypotheses"][0]["evidence"] = [cite]
        f, evs = self.with_final(ver_out=out, inv_out=inv_out, v_tool=tool)
        f["evidence"] = [copy.deepcopy(repo.materialize(cite)[0][0])]
        f["verification"]["evidence"] = [copy.deepcopy(repo.materialize(cite, source="verifier")[0][0]), tool["result"]["evidence"][0]]
        for e in f["verification"]["evidence"] + f["evidence"]:
            self.assertEqual(validate("Evidence", e), [])
        self.assertEqual(prov(f, evs), [])

    def test_a_different_line_is_not_the_same_citation(self):
        s = self.s
        prop = {k: s.finding["evidence"][0][k] for k in F.Scenario.CODE_KEYS}
        moved = {**prop, "lines": [prop["lines"][0] + 1, prop["lines"][1] + 1]}
        f, evs = self.with_final(ver_out={**T.final_ver(s.base), "evidence": [prop]})
        f["verification"]["evidence"] = [{**copy.deepcopy(f["evidence"][0]), "lines": moved["lines"]}]
        self.assertProv(f, evs, "listed lines differ from the cited lines", "was not cited by a confirming verifier call")


# ====================================================================================== S: schema surface

class S_SchemaSurface(Base):
    def req(self, **kw):
        r = copy.deepcopy(self.s.v1["request"])
        for k, v in kw.items():
            if v is None:
                r.pop(k, None)
            else:
                r[k] = v
        return validate("ModelRequest", r)

    def test_request_turn_invariants(self):
        self.assertEqual(self.req(), [])
        rows = {
            "Turn schema without hop": dict(hop=None), "hop on a plain schema": dict(outputSchema="VerifierOutput"),
            "hop > 0 without continuationOf": dict(continuationOf=None), "continuationOf at hop 0": dict(hop=0),
            "hop above 15": dict(hop=16), "hop > 0 without contextResults": dict(contextResults=None),
            "201 contextResults": dict(contextResults=["tool_" + "0" * 16] * 201),
            "run_ id in contextResults": dict(contextResults=["run_" + "0" * 16]),
        }
        for name, kw in rows.items():
            with self.subTest(name):
                self.assertTrue(self.req(**kw))
        plain = copy.deepcopy(F.ex("TraceEvent.model-call")["request"])
        plain["contextResults"] = []
        self.assertTrue(validate("ModelRequest", plain), "contextResults only on Turn requests")
        plain2 = copy.deepcopy(F.ex("TraceEvent.model-call")["request"])
        plain2["hop"] = 0
        self.assertTrue(validate("ModelRequest", plain2), "a legacy request may not carry hop")

    def test_role_schema_pairs(self):
        self.assertEqual(dict(ROLE_SCHEMAS), {"investigator": ("InvestigatorOutput", "InvestigatorTurn"),
                                               "verifier": ("VerifierOutput", "VerifierTurn"), "judge": ("JudgeOutput",)})
        s = self.s
        for role, schema in (("investigator", "VerifierTurn"), ("verifier", "InvestigatorTurn"), ("investigator", "JudgeOutput"),
                             ("verifier", "InvestigatorOutput")):
            ev = copy.deepcopy(s.i1 if role == "investigator" else s.v1)
            ev["request"]["outputSchema"] = schema
            ev["request"].pop("hop", None) if schema == "JudgeOutput" else None
            with self.subTest(f"{role}/{schema}"):
                self.assertTrue(validate("TraceEvent", ev))

    def test_tool_call_fields_come_together_and_are_bounded(self):
        t = copy.deepcopy(self.s.i_tool)
        a = copy.deepcopy(t)
        a.pop("requestIndex")
        b = copy.deepcopy(t)
        b.pop("requestedBy")
        c = copy.deepcopy(t)
        c["requestIndex"] = 6
        d = copy.deepcopy(t)
        d["requestedBy"] = "run_" + "0" * 16
        for name, ev in (("index without the call", a), ("call without the index", b), ("index 6", c), ("run_ id as requester", d)):
            with self.subTest(name):
                self.assertTrue(validate("TraceEvent", ev))
        self.assertEqual(validate("TraceEvent", t), [])

    def test_turn_envelope_shapes(self):
        def turn(name, **kw):
            return validate(name, kw)
        cr = T.creq()
        ok = [("InvestigatorTurn", {"contextRequests": [cr], "output": None}),
              ("InvestigatorTurn", {"contextRequests": [], "output": T.final_inv(self.s.base)}),
              ("VerifierTurn", {"contextRequests": [], "output": T.final_ver(self.s.base)})]
        for name, doc in ok:
            with self.subTest(f"valid {name}"):
                self.assertEqual(validate(name, doc), [])
        bad = {
            "both": {"contextRequests": [cr], "output": T.final_inv(self.s.base)},
            "neither": {"contextRequests": [], "output": None},
            "seven requests": {"contextRequests": [cr] * 7, "output": None},
            "extra field": {"contextRequests": [cr], "output": None, "x": 1},
            "output missing": {"contextRequests": [cr]},
            "requests missing": {"output": T.final_inv(self.s.base)},
            "unwrapped payload": T.final_inv(self.s.base),
        }
        for name, doc in bad.items():
            with self.subTest(name):
                self.assertTrue(validate("InvestigatorTurn", doc))

    def test_context_request_args_are_a_closed_scalar_map(self):
        def v(args=None, **kw):
            return validate("ContextRequest", {"tool": "read_file", "args": {} if args is None else args, "purpose": "p", **kw})
        self.assertEqual(v({"a": True, "b": None, "c": -5, "d": "x" * 4096, "e": 0}), [])
        self.assertEqual(v({}), [])
        for name, args in (("float", {"a": 1.0}), ("2**60", {"a": 2 ** 60}), ("nested", {"a": {"b": 1}}), ("list", {"a": [1]}),
                           ("upper key", {"A": 1}), ("17 keys", {f"k{i}": 1 for i in range(17)}), ("long string", {"a": "x" * 4097})):
            with self.subTest(name):
                self.assertTrue(v(args))
        for name, kw in (("empty purpose", dict(purpose="")), ("long purpose", dict(purpose="x" * 301)), ("unknown field", dict(note=1)),
                         ("bad tool name", dict(tool="Read File"))):
            with self.subTest(name):
                self.assertTrue(v(**kw))

    def test_unknown_but_grammatical_tools_are_schema_valid_data(self):
        self.assertEqual(validate("ContextRequest", {"tool": "rm-rf", "args": {"force": True}, "purpose": "anything"}), [])
        self.assertEqual(validate("InvestigatorTurn", {"contextRequests": [{"tool": "nope", "args": {"zz": 1}, "purpose": "p"}], "output": None}), [])

    def test_bool_and_int_are_distinct_types_when_serving_a_request(self):
        req = {"tool": "read_file", "args": {"n": 1}, "purpose": "p"}
        tool = {"tool": "read_file", "args": {"n": True}}
        self.assertFalse(serves_request(req, tool))
        self.assertTrue(serves_request({**req, "args": {"n": True}}, tool))
        self.assertFalse(serves_request({**req, "args": {"n": "1"}}, {"tool": "read_file", "args": {"n": 1}}))

    def test_examples_are_registered_valid_and_regenerated(self):
        for name in ("ContextRequest", "InvestigatorTurn.requests", "VerifierTurn.final", "TraceEvent.model-call-turn",
                     "TraceEvent.tool-call-requested"):
            with self.subTest(name):
                self.assertEqual(validate(name.split(".")[0], F.ex(name)), [])
        out = subprocess.run([sys.executable, "-m", "reviewer.contracts", "export", "--check"], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual((out.returncode, out.stdout.strip()), (0, "schema bundle up to date"), out.stderr)
        self.assertEqual(CONTRACTS_VERSION, "s0a-contracts@6")


# ====================================================================================== D6: literals and the typed boundary

RUNLIKE = ("run_0123456789abcdef", "evr_0123456789abcdef", F.ex("ReviewRun")["id"])


class D6_SourceLiteralsAndTypedBoundary(Base):
    def test_request_hash_preserves_run_shaped_repository_text(self):
        req = F.ex("TraceEvent.model-call")["request"]
        base = C.request_hash(req)
        seen = {base}
        for lit in RUNLIKE:
            r = copy.deepcopy(req)
            r["messages"][0]["content"] += f"\nconst id = '{lit}';  // from the repository"
            h = C.request_hash(r)
            self.assertNotIn(h, seen, "the literal is part of the hashed bytes")
            seen.add(h)
            self.assertEqual(h, C.request_hash(copy.deepcopy(r)), "and the hash is deterministic")

    def test_secrets_are_still_refused(self):
        r = copy.deepcopy(F.ex("TraceEvent.model-call")["request"])
        r["messages"][0]["content"] += " AKIAIOSFODNN7EXAMPLE"
        with self.assertRaises(ValueError):
            C.request_hash(r)

    def test_a_model_call_event_carrying_such_text_is_a_valid_document(self):
        for lit in RUNLIKE:
            ev = T.turn_call(self.s.run, "investigator", "generalist-0", 0, requests=[T.creq()], seq=1,
                             content=f"the repo defines {lit}")
            self.assertEqual(validate("TraceEvent", ev), [], lit)

    def test_run_shaped_literals_stay_citable_end_to_end(self):
        lit = "run_0123456789abcdef"
        text = f"def f():\n    return '{lit}'\n"
        repo = F.Repo(self, {"src/auth.py": text})
        cite = repo.cite("src/auth.py", [2, 2], f"    return '{lit}'")
        mat, problems = repo.materialize(cite)
        self.assertEqual((len(mat), problems), (1, []))
        self.assertIn(lit, mat[0]["excerpt"])
        s = self.s
        inv_out = T.final_inv(s.base)
        inv_out["hypotheses"][0]["evidence"] = [cite]
        ver_out = {**T.final_ver(s.base), "evidence": [cite]}
        f, evs = self.with_final(ver_out=ver_out, inv_out=inv_out)
        f["evidence"] = [mat[0]]
        f["verification"]["evidence"] = [mat[0]]
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(prov(f, evs), [])

    def test_id_bearing_request_fields_refuse_run_and_eval_ids(self):
        r = copy.deepcopy(self.s.v1["request"])
        for field, value in (("hypothesisId", "run_" + "0" * 16), ("hypothesisId", "evr_" + "0" * 16),
                             ("continuationOf", "run_" + "0" * 16), ("contextResults", ["evr_" + "0" * 16]),
                             ("runId", "run_" + "0" * 16), ("evalRunId", "evr_" + "0" * 16), ("at", "2026-10-25T00:00:00Z")):
            with self.subTest(field):
                self.assertTrue(validate("ModelRequest", {**r, field: value}))

    def test_a_host_id_leaking_into_prompt_text_changes_the_hash_so_replay_misses(self):
        """The detection argument of interface section 5(3): same request, different run id in the text => different key."""
        r1 = copy.deepcopy(F.ex("TraceEvent.model-call")["request"])
        r2 = copy.deepcopy(r1)
        r1["messages"][0]["content"] += " run_1111111111111111"
        r2["messages"][0]["content"] += " run_2222222222222222"
        self.assertNotEqual(C.request_hash(r1), C.request_hash(r2))


# ====================================================================================== G: legacy compatibility

PIN = "sha256:57a13826c07c9b0705bdc4e8dec2364b19212087f3689b8c81552658e9855a3e"


class G_LegacyCompatibility(unittest.TestCase):
    def test_the_legacy_example_hash_is_the_pinned_value(self):
        ev = F.ex("TraceEvent.model-call")
        self.assertEqual(ev["requestHash"], PIN)
        self.assertEqual(C.request_hash(ev["request"]), PIN)
        for k in ("hop", "continuationOf", "contextResults", "requestedBy", "requestIndex"):
            self.assertNotIn(k, ev["request"])
        self.assertEqual(validate("TraceEvent", ev), [])

    def test_legacy_call_ids_tool_ids_and_cost_ids_are_unchanged(self):
        # values computed at @5 (HEAD) and pinned here; the recipes are documented as unchanged
        self.assertEqual(C.call_id("VERIFY", "verifier", "v-hyp_9c3143aeef6c1758", 0, 0), self.head_value("call"))
        self.assertEqual(C.tool_call_id("VERIFY", "v-tool", 0, "pytest", {"k": 1}), self.head_value("tool"))
        self.assertEqual(C.cost_id("call_0123456789abcdef"), self.head_value("cost"))

    @staticmethod
    def head_value(kind):
        return _HEAD_IDS.get(kind)

    def test_legacy_traces_validate_and_mix_with_turn_chains(self):
        s = T.TurnScenario()
        run = F.ex("ReviewRun")
        start = {"schema": "trace-event@1", "runId": run["id"], "seq": 0, "type": "run.start", "run": run}
        end = lambda n: {"schema": "trace-event@1", "runId": run["id"], "seq": n, "type": "run.end", "status": "completed", "incomplete": []}
        legacy = s.base
        evs = [start, legacy.inv, legacy.ver]
        evs[1] = {**evs[1], "seq": 1}
        evs[2] = {**evs[2], "seq": 2}
        self.assertEqual([i.message for i in validate_trace([*evs, end(3)])], [])
        mixed = [start, *s.events, end(7)]
        self.assertEqual([i.message for i in validate_trace(mixed)], [])

    def test_legacy_checks_are_not_weakened_by_the_turn_rules(self):
        """The @5 attacks on plain calls still fail (spot controls beyond the original suites)."""
        b = F.Scenario()
        f = b.fresh()
        ref = b.verifier(verdict="refuted")
        fix = F.model_call(b.run, "VERIFY", "verifier", "v-" + f["id"], 0, b.confirm, attempt=1, repair_of=ref["callId"], seq=3)
        f["verification"]["callIds"] = [fix["callId"]]
        self.assertTrue(prov(f, [b.inv, ref, fix]))

    def test_differential_against_the_s0a_contracts_5_tree(self):
        """Run HEAD's (s0a-contracts@5) canonical recipes in a subprocess over a battery of legacy requests and require
        byte-identical request hashes under @6, and that every @5 example document still validates."""
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        head = subprocess.run(["git", "show", "HEAD:reviewer/contracts/__init__.py"], cwd=ROOT, capture_output=True, text=True)
        if head.returncode or 's0a-contracts@5"' not in head.stdout:
            self.skipTest("HEAD is no longer the @5 baseline")
        base = F.ex("TraceEvent.model-call")["request"]
        battery = []
        for i, content in enumerate(("hello", "unicode é中文 \U0001f600", "tabs\tand\nnewlines", "x" * 5000, "run-ish but not an id: run_123")):
            r = copy.deepcopy(base)
            r["messages"][0]["content"] = content
            battery.append(r)
        r = copy.deepcopy(base)
        r["role"], r["outputSchema"], r["hypothesisId"] = "verifier", "VerifierOutput", "hyp_" + "a" * 16
        battery.append(r)
        r = copy.deepcopy(base)
        r["params"], r["tools"] = {"temperature": 0, "maxOutputTokens": 1000, "seed": None}, [{"name": "x", "n": 1}]
        battery.append(r)
        with tempfile.TemporaryDirectory() as td:
            tree = Path(td, "head")
            tree.mkdir()
            tar = subprocess.run(["git", "archive", "HEAD", "reviewer/contracts"], cwd=ROOT, capture_output=True, timeout=120)
            self.assertEqual(tar.returncode, 0, tar.stderr)
            subprocess.run(["tar", "-x", "-C", str(tree)], input=tar.stdout, check=True, timeout=120)
            (tree / "reviewer" / "__init__.py").touch()
            script = Path(td, "probe.py")
            script.write_text("import json,sys\nsys.path.insert(0, sys.argv[1])\n"
                              "from reviewer.contracts import canonical as C, CONTRACTS_VERSION, validate\n"
                              "reqs=json.load(sys.stdin)\nout={'version':CONTRACTS_VERSION,'hashes':[C.request_hash(r) for r in reqs]}\n"
                              "import pathlib\nex=pathlib.Path(sys.argv[1])/'reviewer'/'contracts'/'examples'\n"
                              "out['examples']={p.stem:validate(p.stem.split('.')[0], json.loads(p.read_text())) == [] for p in sorted(ex.glob('*.json'))}\n"
                              "print(json.dumps(out))\n")
            run = subprocess.run([sys.executable, "-I", str(script), str(tree)], input=json.dumps(battery), capture_output=True,
                                 text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr)
            old = json.loads(run.stdout)
        self.assertEqual(old["version"], "s0a-contracts@5")
        self.assertEqual(old["hashes"], [C.request_hash(r) for r in battery], "legacy request hashes changed")
        self.assertTrue(all(old["examples"].values()), old["examples"])
        for stem in old["examples"]:
            with self.subTest(stem):
                self.assertEqual(validate(stem.split(".")[0], F.ex(stem)), [], "an @5-valid example is invalid under @6")


def _head_ids():
    """Ids computed by the HEAD (@5) canonical module, or None when HEAD is not @5 / git is unavailable."""
    try:
        head = subprocess.run(["git", "show", "HEAD:reviewer/contracts/__init__.py"], cwd=ROOT, capture_output=True, text=True, timeout=60)
        if head.returncode or 's0a-contracts@5"' not in head.stdout:
            return {}
        with tempfile.TemporaryDirectory() as td:
            tar = subprocess.run(["git", "archive", "HEAD", "reviewer/contracts"], cwd=ROOT, capture_output=True, timeout=120)
            subprocess.run(["tar", "-x", "-C", td], input=tar.stdout, check=True, timeout=120)
            Path(td, "reviewer", "__init__.py").touch()
            code = ("import sys,json\nsys.path.insert(0, sys.argv[1])\nfrom reviewer.contracts import canonical as C\n"
                    "print(json.dumps({'call':C.call_id('VERIFY','verifier','v-hyp_9c3143aeef6c1758',0,0),"
                    "'tool':C.tool_call_id('VERIFY','v-tool',0,'pytest',{'k':1}),'cost':C.cost_id('call_0123456789abcdef')}))")
            out = subprocess.run([sys.executable, "-I", "-c", code, td], capture_output=True, text=True, timeout=120)
            return json.loads(out.stdout) if out.returncode == 0 else {}
    except Exception:  # noqa: BLE001 - the differential is best effort; the pinned literals below still run
        return {}


_HEAD_IDS = _head_ids()


# ====================================================================================== L: pinned limits

class L_PinnedLimits(Base):
    def test_L1_an_empty_argument_request_is_served_by_any_earlier_result_of_that_tool(self):
        """serves_request is vacuously true for `args: {}`, so a request the host would deny (missing path) can be
        'answered' by deduplicating to an unrelated read_file result of the chain. Honest pipelines log the denial."""
        s = self.s
        empty = T.creq(args={})
        i0 = T.turn_call(s.run, "investigator", "generalist-0", 0, requests=[s.i_req, empty], seq=1)
        t0 = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", s.i_req["args"], [T.code_item()], seq=2, by=i0, index=0)
        i1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=i0["callId"],
                         results=[t0["toolCallId"], t0["toolCallId"]], output=T.final_inv(s.base), seq=3)
        self.assertEqual(trace([i0, t0, i1]), [])

    def test_L2_host_context_is_bound_by_stage_not_by_agent(self):
        """A host-prepared VERIFY-stage tool call made for verifier B can be shown to and cited by verifier A."""
        s, hid = self.s, self.s.finding["id"]
        foreign = T.tool_event(s.run, "VERIFY", "v-someone-else", 0, "read_file", {"path": "src/x.py"}, [T.code_item(path="src/x.py")], seq=0)
        v0 = T.turn_call(s.run, "verifier", "v-" + hid, 0, results=[foreign["toolCallId"]], requests=[s.v_req], seq=4)
        self.assertEqual(trace([foreign, v0]), [])

    def test_L3_a_consistently_relabelled_request_is_indistinguishable_from_host_context(self):
        """A model-requested legacy retrieval logged without requestedBy and on the citing stage is, by construction,
        host context. Trace authenticity belongs to the gateway/pipeline (root-recorded limit)."""
        b = F.Scenario()
        tool, items = _prop_tool(b.run)
        inv = F.model_call(b.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                           {"hypotheses": [{**b.inv["response"]["output"]["hypotheses"][0], "evidence": [
                               *b.inv["response"]["output"]["hypotheses"][0]["evidence"], {"kind": "tool-ref", "toolCallId": tool["toolCallId"]}]}]},
                           seq=1)
        f = b.fresh()
        f["sourceCallId"] = inv["callId"]
        f["evidence"].append(items[0])
        self.assertEqual(prov(f, [tool, inv, b.ver]), [])

    def test_L4_params_tools_and_model_are_open_slots_for_run_shaped_text(self):
        """Interface 5(1) says params/tools come from the trusted profile and the gateway compares them. At the
        contract level they are open Json/Str and accept a run id; only gateway profile comparison and strict-replay
        (hash miss under another runId) can catch a leak there. The gateway currently compares provider, model,
        promptVersion, outputSchema, profile and the output-cap keys of params only (reviewer/gateway/gateway.py
        _check_request); tools and the rest of params are not compared."""
        r = copy.deepcopy(self.s.v1["request"])
        for field, value in (("params", {"user": "run_" + "0" * 16}), ("tools", [{"x": "evr_" + "0" * 16}]), ("model", "run_" + "0" * 16)):
            with self.subTest(field):
                self.assertEqual(validate("ModelRequest", {**r, field: value}), [])

    def test_L5_a_cited_item_outside_the_cited_slice_is_worded_as_not_citable(self):
        """Diagnostics only: _cited reports 'not shown to (citable by)' for a tool that IS citable when the item lies outside
        the cited index/first-20 slice (the @5 wording was 'was not cited by'). The decision is right; the reason is conflated."""
        s = self.s
        it = s.i_tool["result"]["evidence"][0]
        inv_out = T.final_inv(s.base)
        inv_out["hypotheses"][0]["evidence"].append({"kind": "tool-ref", "toolCallId": s.i_tool["toolCallId"], "index": 5})
        f, evs = self.with_final(inv_out=inv_out)
        f["evidence"].append(it)
        self.assertIn(s.i_tool["toolCallId"], citable_tool_calls(evs[2]["callId"], evs))
        self.assertProv(f, evs, "index 5 is out of range", "was not shown to (citable by) the proposal")

    def test_L6_unlisted_verifier_chains_are_invisible_like_unlisted_calls(self):
        """A second verifier chain (another ordinal) that refuted the hypothesis is not seen by provenance, as in @5 (L2)."""
        s, hid = self.s, self.s.finding["id"]
        ref = T.turn_call(s.run, "verifier", "v-skeptic", 9, output={**T.final_ver(s.base), "verdict": "refuted"}, seq=7, hyp=hid)
        self.assertEqual(prov(s.finding, [*s.events, ref]), [])


def _prop_tool(run):
    ev = F.tool_call(run, "ok", [], agent="generalist-0", tool="pytest", args={"k": 1}, seq=0, stage="INVESTIGATE")
    tid = ev["toolCallId"]
    item = {"kind": "test-run", "excerpt": "1 passed", "source": "pytest", "toolCallId": tid}
    return F.tool_call(run, "ok", [item], agent="generalist-0", tool="pytest", args={"k": 1}, seq=0, stage="INVESTIGATE"), [item]


if __name__ == "__main__":
    unittest.main()
