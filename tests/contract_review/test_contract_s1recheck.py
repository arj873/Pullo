"""Independent recheck of the S1-01 repair-link fix (every Turn hop attempt). Reviewer-owned, offline, stdlib
only. Adds only NEW cases the author and s1review tests do not cover; nothing else is edited.

  M_*  middle hop of a 3-hop chain: a usable refutation / request repaired away at hop 1 is refused;
       an unusable hop 1 repaired validly is accepted
  I_*  the investigator (source) chain: same laundering at hop 0 is refused through sourceCallId
  X_*  repair cycles, self-repair and later-logged targets: refused, terminate, one message per defect
  K_*  controls: legacy repair rules and messages unchanged; no duplicate message for a Turn call
  L_*  LIMIT pins: repair links are provenance-only (validate_trace / check_turn_trace accept them)

Every negative asserts its REASON. Run:
  nice -n 19 python3 -m unittest discover -s tests/contract_review -p 'test_contract_s1recheck.py' -v
"""
from __future__ import annotations

import unittest

import finalreview_support as F
import turn_support as T
from reviewer.contracts import check_finding_provenance, check_turn_trace, citable_tool_calls, turn_chain
from reviewer.contracts import usable_output, validate_trace

USABLE = "is a repair of a usable response"
LINK = "repairOf does not name the previous attempt of the same logical call"


def prov(f, evs):
    return [i.message for i in check_finding_provenance(f, evs)]


class Base(unittest.TestCase):
    def setUp(self):
        self.s = T.TurnScenario()
        self.hid = self.s.finding["id"]
        self.ag = "v-" + self.hid

    def refuse(self, f, evs, why, *contains):
        got = prov(f, evs)
        self.assertTrue(got, f"ACCEPTED but must be rejected: {why}")
        for c in contains:
            self.assertTrue(any(c in m for m in got), f"no message containing {c!r}: {got}")
        return got

    def three_hop(self, mid_first=None, mid_repair=True, mid_first_kw=None):
        """Verifier chain v0 -> v1(attempt 0 [, attempt 1 repairing it]) -> v2 final.
        mid_first: output envelope of v1 attempt 0 (None = asks for a file)."""
        s, ag = self.s, self.ag
        r1 = T.creq(args={"path": "src/store.py", "side": "head"})
        r2 = T.creq(args={"path": "src/other.py", "side": "head"})
        v0 = T.turn_call(s.run, "verifier", ag, 0, requests=[r1], seq=4)
        t0 = T.tool_event(s.run, "VERIFY", ag, 0, "read_file", r1["args"], [T.code_item(path="src/store.py")], seq=5, by=v0, index=0)
        kw = dict(mid_first_kw or {})
        if mid_first is None and "raw_output" not in kw:
            kw["requests"] = [r2]
        else:
            kw.setdefault("output", mid_first)
        a0 = T.turn_call(s.run, "verifier", ag, 1, hop=1, cont=v0["callId"], results=[t0["toolCallId"]], seq=6, **kw)
        evs, last = [v0, t0, a0], a0
        if mid_repair:
            a1 = T.turn_call(s.run, "verifier", ag, 1, hop=1, cont=v0["callId"], results=[t0["toolCallId"]],
                             requests=[r2], attempt=1, repair_of=a0["callId"], seq=7)
            evs.append(a1)
            last = a1
        t1 = T.tool_event(s.run, "VERIFY", ag, 1, "read_file", r2["args"], [T.code_item(path="src/other.py")], seq=8, by=last, index=0)
        v2 = T.turn_call(s.run, "verifier", ag, 2, hop=2, cont=last["callId"], results=[t1["toolCallId"]],
                         output=T.final_ver(s.base), seq=9)
        f = s.fresh()
        f["verification"]["callIds"] = [v2["callId"]]
        return f, [s.i0, s.i_tool, s.i1] + evs + [t1, v2], a0, last


class M_MiddleHop(Base):
    def test_control_unusable_middle_hop_repaired_validly_is_accepted(self):
        f, evs, a0, a1 = self.three_hop(mid_first=None, mid_first_kw={"raw_output": {"junk": 1}})
        self.assertFalse(usable_output(a0))
        self.assertEqual(prov(f, evs), [])
        self.assertEqual([i.message for i in check_turn_trace(evs)], [])
        hops, issues = turn_chain(evs[-1]["callId"], evs)
        self.assertEqual((len(hops), issues), (3, []))
        self.assertTrue(citable_tool_calls(evs[-1]["callId"], evs))

    def test_control_status_invalid_output_middle_hop_repaired_validly_is_accepted(self):
        f, evs, a0, _ = self.three_hop(mid_first_kw={"status": "invalid-output", "raw_output": None})
        self.assertFalse(usable_output(a0))
        self.assertEqual(prov(f, evs), [])

    def test_usable_refutation_at_the_middle_hop_cannot_be_repaired_away(self):
        ref = {**T.final_ver(self.s.base), "verdict": "refuted"}
        f, evs, a0, _ = self.three_hop(mid_first=ref)
        self.assertTrue(usable_output(a0))
        self.refuse(f, evs, "refutation at hop 1 forgotten", USABLE, "hop 1")
        self.assertEqual(citable_tool_calls(evs[-1]["callId"], evs), {})

    def test_usable_request_at_the_middle_hop_cannot_be_repaired_away(self):
        f, evs, a0, _ = self.three_hop()
        self.assertTrue(usable_output(a0))
        self.refuse(f, evs, "usable hop-1 request overwritten", USABLE)

    def test_a_middle_hop_repair_of_the_wrong_attempt_number_is_refused(self):
        f, evs, a0, a1 = self.three_hop(mid_first_kw={"raw_output": {"junk": 1}})
        i = evs.index(a1)
        bad = T.turn_call(self.s.run, "verifier", self.ag, 1, hop=1, cont=a1["request"]["continuationOf"],
                          results=a1["request"]["contextResults"], requests=a1["request"] and
                          [T.creq(args={"path": "src/other.py", "side": "head"})], attempt=2, repair_of=a0["callId"], seq=7)
        evs2 = list(evs)
        evs2[i] = bad
        t1 = evs2[i + 1]
        t1 = T.tool_event(self.s.run, "VERIFY", self.ag, 1, "read_file", t1["args"], [T.code_item(path="src/other.py")],
                          seq=8, by=bad, index=0)
        v2 = T.turn_call(self.s.run, "verifier", self.ag, 2, hop=2, cont=bad["callId"], results=[t1["toolCallId"]],
                         output=T.final_ver(self.s.base), seq=9)
        evs2[i + 1], evs2[i + 2] = t1, v2
        f = self.s.fresh()
        f["verification"]["callIds"] = [v2["callId"]]
        self.refuse(f, evs2, "attempt 2 repairs attempt 0", LINK)


class I_InvestigatorChain(Base):
    def laundered(self, first_output):
        s = self.s
        a0 = T.turn_call(s.run, "investigator", "generalist-0", 0, output=first_output, seq=1)
        a1 = T.turn_call(s.run, "investigator", "generalist-0", 0, requests=[s.i_req], attempt=1, repair_of=a0["callId"], seq=2)
        t = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", s.i_req["args"], [T.code_item()], seq=3, by=a1, index=0)
        i1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_inv(s.base), seq=4)
        f = s.fresh()
        f["sourceCallId"] = i1["callId"]
        return f, [a0, a1, t, i1, s.v0, s.v_tool, s.v1], a0

    def test_control_unusable_source_hop_repaired_is_accepted(self):
        f, evs, a0 = self.laundered(None)
        evs[0] = T.turn_call(self.s.run, "investigator", "generalist-0", 0, raw_output={"junk": 1}, seq=1)
        evs[1] = T.turn_call(self.s.run, "investigator", "generalist-0", 0, requests=[self.s.i_req], attempt=1,
                             repair_of=evs[0]["callId"], seq=2)
        evs[2] = T.tool_event(self.s.run, "INVESTIGATE", "generalist-0", 0, "read_file", self.s.i_req["args"],
                              [T.code_item()], seq=3, by=evs[1], index=0)
        evs[3] = T.turn_call(self.s.run, "investigator", "generalist-0", 1, hop=1, cont=evs[1]["callId"],
                             results=[evs[2]["toolCallId"]], output=T.final_inv(self.s.base), seq=4)
        f["sourceCallId"] = evs[3]["callId"]
        self.assertEqual(prov(f, evs), [])

    def test_a_usable_source_request_cannot_be_repaired_away(self):
        f, evs, a0 = self.laundered(None)
        evs[0] = T.turn_call(self.s.run, "investigator", "generalist-0", 0,
                             requests=[T.creq(args={"path": "src/z.py", "side": "head"})], seq=1)
        evs[1] = T.turn_call(self.s.run, "investigator", "generalist-0", 0, requests=[self.s.i_req], attempt=1,
                             repair_of=evs[0]["callId"], seq=2)
        evs[2] = T.tool_event(self.s.run, "INVESTIGATE", "generalist-0", 0, "read_file", self.s.i_req["args"],
                              [T.code_item()], seq=3, by=evs[1], index=0)
        evs[3] = T.turn_call(self.s.run, "investigator", "generalist-0", 1, hop=1, cont=evs[1]["callId"],
                             results=[evs[2]["toolCallId"]], output=T.final_inv(self.s.base), seq=4)
        f["sourceCallId"] = evs[3]["callId"]
        self.assertTrue(usable_output(evs[0]))
        self.refuse(f, evs, "usable source hop overwritten", USABLE)

    def test_a_cross_agent_repair_in_the_source_chain_is_refused(self):
        s = self.s
        other = T.turn_call(s.run, "investigator", "generalist-1", 0, requests=[s.i_req], seq=1)
        a1 = T.turn_call(s.run, "investigator", "generalist-0", 0, requests=[s.i_req], attempt=1, repair_of=other["callId"], seq=2)
        t = T.tool_event(s.run, "INVESTIGATE", "generalist-0", 0, "read_file", s.i_req["args"], [T.code_item()], seq=3, by=a1, index=0)
        i1 = T.turn_call(s.run, "investigator", "generalist-0", 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_inv(s.base), seq=4)
        f = s.fresh()
        f["sourceCallId"] = i1["callId"]
        self.refuse(f, [other, a1, t, i1, s.v0, s.v_tool, s.v1], "cross-agent repair on the source chain", LINK)


class X_Degenerate(Base):
    def test_self_repair_and_two_cycle_terminate_and_are_refused(self):
        s = self.s
        a0 = T.turn_call(s.run, "verifier", self.ag, 0, requests=[s.v_req], seq=4)
        a1 = T.turn_call(s.run, "verifier", self.ag, 0, requests=[s.v_req], attempt=1, repair_of=a0["callId"], seq=5)
        a0["repairOf"] = a1["callId"]  # cycle a0 <-> a1
        t = T.tool_event(s.run, "VERIFY", self.ag, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")], seq=6, by=a1, index=0)
        v1 = T.turn_call(s.run, "verifier", self.ag, 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=7)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        self.refuse(f, [s.i0, s.i_tool, s.i1, a0, a1, t, v1], "repair cycle", "repair")

    def test_repair_target_logged_twice_is_refused(self):
        s = self.s
        a0 = T.turn_call(s.run, "verifier", self.ag, 0, raw_output={"junk": 1}, seq=4)
        a1 = T.turn_call(s.run, "verifier", self.ag, 0, requests=[s.v_req], attempt=1, repair_of=a0["callId"], seq=6)
        t = T.tool_event(s.run, "VERIFY", self.ag, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")], seq=7, by=a1, index=0)
        v1 = T.turn_call(s.run, "verifier", self.ag, 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=8)
        dup = dict(a0, seq=5)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        self.refuse(f, [s.i0, s.i_tool, s.i1, a0, dup, a1, t, v1], "duplicate target", "not a model call logged once")

    def test_repair_target_unlogged_gives_one_message_not_a_cascade(self):
        s = self.s
        a0 = T.turn_call(s.run, "verifier", self.ag, 0, raw_output={"junk": 1}, seq=4)
        a1 = T.turn_call(s.run, "verifier", self.ag, 0, requests=[s.v_req], attempt=1, repair_of=a0["callId"], seq=6)
        t = T.tool_event(s.run, "VERIFY", self.ag, 0, "read_file", s.v_req["args"], [T.code_item(path="src/store.py")], seq=7, by=a1, index=0)
        v1 = T.turn_call(s.run, "verifier", self.ag, 1, hop=1, cont=a1["callId"], results=[t["toolCallId"]],
                         output=T.final_ver(s.base), seq=8)
        f = s.fresh()
        f["verification"]["callIds"] = [v1["callId"]]
        got = self.refuse(f, [s.i0, s.i_tool, s.i1, a1, t, v1], "unlogged repair target", "not a model call logged once")
        self.assertEqual(sum("not a model call logged once" in m for m in got), 1, got)


class K_Controls(Base):
    def test_a_single_turn_refusal_is_reported_once(self):
        s = self.s
        ref = T.turn_call(s.run, "verifier", self.ag, 0, output={**T.final_ver(s.base), "verdict": "refuted"}, seq=4)
        fix = T.turn_call(s.run, "verifier", self.ag, 0, output=T.final_ver(s.base), attempt=1, repair_of=ref["callId"], seq=5)
        f = s.fresh()
        f["verification"]["callIds"] = [fix["callId"]]
        got = self.refuse(f, [s.i0, s.i_tool, s.i1, ref, fix], "terminal turn repair of usable", USABLE)
        self.assertEqual(sum(USABLE in m for m in got), 1, got)

    def test_legacy_repair_rules_and_valid_repair_unchanged(self):
        base = F.Scenario()
        f = base.fresh()
        self.assertEqual(prov(f, base.events), [])
        self.assertTrue(hasattr(base, "events"))

    def test_hop_attempts_after_a_valid_repair_do_not_poison_listing_the_unrepaired_hop_elsewhere(self):
        """Valid unusable-then-repaired verifier chain, run beside an untouched investigator chain: the honest
        scenario is still accepted and the attempt that was repaired stays out of the way."""
        f, evs, a0, a1 = self.three_hop(mid_first_kw={"raw_output": {"junk": 1}})
        self.assertEqual(prov(f, evs), [])
        self.assertEqual(prov(self.s.fresh(), self.s.evs()), [])


class L_Limits(Base):
    def test_LIMIT_trace_level_accepts_a_repair_of_a_usable_earlier_hop(self):
        """Pinned: the repair-link rule is provenance-only. A forged trace is a valid TRACE; only
        check_finding_provenance (the confirm gate) refuses it. Not a guarantee for trace consumers."""
        ref = {**T.final_ver(self.s.base), "verdict": "refuted"}
        f, evs, a0, _ = self.three_hop(mid_first=ref)
        self.assertEqual([i.message for i in check_turn_trace(evs)], [])
        self.assertTrue(prov(f, evs))


if __name__ == "__main__":
    unittest.main()
