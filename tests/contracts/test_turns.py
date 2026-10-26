"""s0a-contracts@6 (S1-01): Turn envelopes, hop/causal metadata, terminal provenance, D2, D6, FRR1-3.
Run: nice -n 19 python3 -m unittest discover -s tests/contracts -t ."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts import (CONTRACTS_VERSION, check_finding_provenance, check_turn_trace,
                                citable_tool_calls, serves_request, terminal_payload, turn_chain,
                                turn_requests, usable_output, validate)
from reviewer.contracts import canonical as C
from reviewer.contracts.severity import materialize_evidence
from reviewer.contracts.snapshot import build_manifest, snapshot_resolver

EXAMPLES = Path(__file__).resolve().parents[2] / "reviewer" / "contracts" / "examples"
USAGE = {k: None for k in ("uncachedInputTokens", "cachedInputTokens", "cacheWriteInputTokens",
                           "outputTokens", "reasoningTokens")}


def ex(name):
    return json.loads((EXAMPLES / f"{name}.json").read_text())


BASE_REQ = ex("TraceEvent.model-call")["request"]
RUN = ex("Finding")["runId"]


def turn_doc(role, hop, results, *, history=(), duplicates=()):
    """Render logged results in the host's context/history shape, never from ids alone."""
    items = []
    for index, ev in enumerate(results):
        res = ev["result"]
        item = {"toolCallId": ev["toolCallId"], "tool": ev["tool"], "args": ev["args"],
                **{k: res[k] for k in ("status", "completeness", "truncated", "notice")},
                "excerpts": [e["excerpt"] for e in res["evidence"]]}
        if hop:
            item["index"] = index
        if ev["toolCallId"] in duplicates:
            item.update(excerpts=[], duplicateOf=ev["toolCallId"])
        items.append(item)
    key = "pinnedContext" if role == "verifier" else "context"
    doc = {key: items if hop == 0 else [], "history": copy.deepcopy(list(history))}
    if hop:
        doc["history"].append({"turn": hop - 1, "results": items})
    return doc


def call(stage, role, agent, ordinal, output, *, seq, attempt=0, status="ok", repair_of=None,
         turn=False, hop=None, cont=None, results=None, hyp=None, content=None,
         history=(), duplicates=()):
    schema = {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput"}[role]
    req = {**BASE_REQ, "role": role, "outputSchema": schema.replace("Output", "Turn") if turn else schema,
           "messages": [{"role": "user", "content": content or f"{stage} {agent} {ordinal}"}]}
    if turn:
        # Legacy calls keep their original text; Turn requests carry host-rendered JSON.
        doc = turn_doc(role, hop, results or [], history=history, duplicates=duplicates)
        req["messages"] = [{"role": "system", "content": "Synthetic Turn contract fixture."},
                           {"role": "user", "content": content if content is not None else json.dumps(doc)}]
        req["hop"] = hop
        if cont:
            req["continuationOf"] = cont
        if results is not None:
            req["contextResults"] = [e["toolCallId"] for e in results]
    if hyp:
        req["hypothesisId"] = hyp
    cid = C.call_id(stage, role, agent, ordinal, attempt)
    ev = {"schema": "trace-event@1", "runId": RUN, "seq": seq, "type": "model.call", "callId": cid,
          "stage": stage, "role": role, "agentId": agent, "ordinal": ordinal, "attempt": attempt,
          "requestHash": C.request_hash(req), "request": req,
          "response": {"status": status, "resolvedModel": "synthetic-fixture", "output": output,
                       "rawText": None, "usage": USAGE},
          "costRecordId": C.cost_id(cid), "redactions": {}}
    if repair_of:
        ev["repairOf"] = repair_of
    assert validate("TraceEvent", ev) == [], validate("TraceEvent", ev)
    return ev


def tool(stage, agent, ordinal, name, args, items, *, seq, status="ok", by=None, index=None):
    """items: callables tid -> Evidence (so each item names the call, as the tool layer mints)."""
    tid = C.tool_call_id(stage, agent, ordinal, name, args)
    res = {"status": status, "evidence": [f(tid) for f in items], "completeness": "exact",
           "truncated": None, "notice": ""}
    ev = {"schema": "trace-event@1", "runId": RUN, "seq": seq, "type": "tool.call", "toolCallId": tid,
          "stage": stage, "agentId": agent, "ordinal": ordinal, "tool": name, "args": args,
          "resultHash": C.result_hash(res), "result": res, "redactions": {}}
    if by is not None:
        ev["requestedBy"], ev["requestIndex"] = by, index
    assert validate("TraceEvent", ev) == [], validate("TraceEvent", ev)
    return ev


def code_item(path="src/store.h", lines=(1, 3), excerpt="void Close() { open = false; }"):
    commit = ex("Finding")["evidence"][0]["commit"]
    return lambda tid: {"kind": "code", "path": path, "lines": list(lines), "commit": commit,
                        "excerpt": excerpt, "source": "read_file", "toolCallId": tid,
                        "resolved": True}


def text_item(text):
    return lambda tid: {"kind": "tool-result", "excerpt": text, "source": "diff", "toolCallId": tid}


READ = {"tool": "read_file", "args": {"side": "head", "path": "src/store.h", "end_line": 3},
        "purpose": "how Close() behaves"}
SHELL = {"tool": "shell", "args": {"cmd": "ls"}, "purpose": "not a tool"}
NORM_READ = {"side": "head", "path": "src/store.h", "start_line": 1, "end_line": 3}


class ChainBase(unittest.TestCase):
    """A legacy INVESTIGATE proposal and a two-hop VERIFY Turn chain that reads an unchanged header."""

    def setUp(self):
        f = ex("Finding")
        self.cite = {k: f["evidence"][0][k] for k in ("kind", "path", "lines", "commit", "excerpt")}
        draft = {k: copy.deepcopy(f[k]) for k in ("claim", "category", "suspectedSeverity", "impact",
                                                  "location")}
        draft["evidence"] = [self.cite]
        self.hid = f["id"]
        self.inv = call("INVESTIGATE", "investigator", "generalist-0", 0, {"hypotheses": [draft]}, seq=1)
        self.host = tool("VERIFY", "verifier", 0, "diff", {"path": "src/auth.py"},
                         [text_item("-ok\n+bad")], seq=2)
        self.v0 = call("VERIFY", "verifier", "verifier", 0,
                       {"contextRequests": [READ, SHELL], "output": None}, seq=3, turn=True, hop=0,
                       results=[self.host], hyp=self.hid)
        self.t0 = tool("VERIFY", "verifier", 1, "read_file", NORM_READ, [code_item()], seq=4,
                       by=self.v0["callId"], index=0)
        self.t1 = tool("VERIFY", "verifier", 2, "unknown-tool", {"requested": "shell"}, [], seq=5,
                       status="denied", by=self.v0["callId"], index=1)
        self.confirm = {"verdict": "confirmed", **f["severityBasis"], "notes": "header only marks closed",
                        "evidence": [{"kind": "tool-ref", "toolCallId": self.t0["toolCallId"],
                                      "index": 0}]}
        self.v1 = self.hop1()
        f["sourceCallId"] = self.inv["callId"]
        f["verification"]["callIds"] = [self.v1["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(self.t0["result"]["evidence"])
        self.f = f

    def hop1(self, results=None, seq=6, ordinal=1, output=None, **kw):
        return call("VERIFY", "verifier", "verifier", ordinal,
                    {"contextRequests": [], "output": output or self.confirm}, seq=seq, turn=True,
                    hop=1, cont=self.v0["callId"], attempt=kw.get("attempt", 0),
                    results=[self.t0, self.t1] if results is None else results,
                    hyp=kw.get("hyp", self.hid))

    @property
    def events(self):
        return [self.inv, self.host, self.v0, self.t0, self.t1, self.v1]

    def msgs(self, f=None, events=None):
        return [i.message for i in check_finding_provenance(f or self.f, events or self.events)]

    def assertRejected(self, contains, f=None, events=None):
        m = self.msgs(f, events)
        self.assertTrue(any(contains in x for x in m), m)


class Chain(ChainBase):
    # ---- positive: D2 + chain
    def test_honest_chain_and_d2_read_file_evidence_are_accepted(self):
        self.assertEqual(validate("Finding", self.f), [])
        self.assertEqual(check_turn_trace(self.events), [])
        self.assertEqual(self.msgs(), [])
        self.assertEqual(self.f["verification"]["evidence"][0]["kind"], "code")

    def test_helpers_unwrap_the_actual_envelope(self):
        self.assertEqual(terminal_payload(self.v1), self.confirm)
        self.assertIsNone(terminal_payload(self.v0))
        self.assertEqual(turn_requests(self.v0), [READ, SHELL])
        self.assertIsNone(turn_requests(self.v1))
        self.assertEqual(self.v1["response"]["output"]["output"], self.confirm)   # trace unchanged
        hops, issues = turn_chain(self.v1["callId"], self.events)
        self.assertEqual(([h["callId"] for h in hops], issues), ([self.v0["callId"], self.v1["callId"]], []))
        self.assertEqual(set(citable_tool_calls(self.v1["callId"], self.events)),
                         {self.host["toolCallId"], self.t0["toolCallId"]})
        self.assertEqual(set(citable_tool_calls(self.v0["callId"], self.events)), {self.host["toolCallId"]})
        self.assertTrue(serves_request(READ, self.t0))
        self.assertFalse(serves_request(SHELL, self.t1))

    def test_rendered_results_are_hashed_and_denied_results_are_status_only(self):
        for ev, group, tools in ((self.v0, "pinnedContext", [self.host]),
                                 (self.v1, "history", [self.t0, self.t1])):
            doc = json.loads(ev["request"]["messages"][1]["content"])
            items = doc[group] if group != "history" else doc[group][0]["results"]
            self.assertEqual([i["toolCallId"] for i in items], [t["toolCallId"] for t in tools])
            self.assertEqual([i["excerpts"] for i in items],
                             [[e["excerpt"] for e in t["result"]["evidence"]] for t in tools])
            self.assertEqual(C.request_hash(ev["request"]), ev["requestHash"])
            self.assertEqual(validate("TraceEvent", ev), [])
        self.assertEqual(items[1]["status"], "denied")
        got, problems = materialize_evidence([{"kind": "tool-ref", "toolCallId": self.t1["toolCallId"]}],
                                             citable_tool_calls(self.v1["callId"], self.events), "verifier")
        self.assertEqual(got, [])
        self.assertTrue(problems)

    def test_omitted_rendering_does_not_materialize_an_otherwise_valid_chain(self):
        v1 = copy.deepcopy(self.v1)
        doc = json.loads(v1["request"]["messages"][1]["content"])
        item = doc["history"][0]["results"][0]
        item.update(excerpts=[], excerptsOmitted="retrieval context budget")
        v1["request"]["messages"][1]["content"] = json.dumps(doc)
        v1["requestHash"] = C.request_hash(v1["request"])
        evs = self.events[:-1] + [v1]
        self.assertEqual(validate("TraceEvent", v1), [])
        self.assertEqual(check_turn_trace(evs), [])
        citable = citable_tool_calls(v1["callId"], evs)
        self.assertEqual(set(citable), {self.host["toolCallId"]})
        got, problems = materialize_evidence(self.confirm["evidence"], citable, "verifier")
        self.assertEqual(got, [])
        self.assertTrue(problems)
        self.assertRejected("not shown to", events=evs)

    def test_materialize_from_citable_calls_rebuilds_the_finding_evidence(self):
        got, problems = materialize_evidence(self.confirm["evidence"],
                                             citable_tool_calls(self.v1["callId"], self.events), "verifier")
        self.assertEqual((got, problems), (self.f["verification"]["evidence"], []))

    def test_repair_inside_a_hop_is_one_logical_call(self):
        bad = call("VERIFY", "verifier", "verifier", 1, {"nope": 1}, seq=6, turn=True, hop=1,
                   cont=self.v0["callId"], results=[self.t0, self.t1],
                   hyp=self.hid)
        self.assertFalse(usable_output(bad))          # status ok but schema-invalid (D3)
        rep = call("VERIFY", "verifier", "verifier", 1, {"contextRequests": [], "output": self.confirm},
                   seq=7, attempt=1, repair_of=bad["callId"], turn=True, hop=1, cont=self.v0["callId"],
                   results=[self.t0, self.t1], hyp=self.hid)
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [rep["callId"]]
        evs = [self.inv, self.host, self.v0, self.t0, self.t1, bad, rep]
        self.assertEqual(check_turn_trace(evs), [])
        self.assertEqual(self.msgs(f, evs), [])

    def test_dedup_recites_an_earlier_result_of_the_same_chain(self):
        v1 = call("VERIFY", "verifier", "verifier", 1, {"contextRequests": [READ], "output": None},
                  seq=6, turn=True, hop=1, cont=self.v0["callId"],
                  results=[self.t0, self.t1], hyp=self.hid)
        v2 = call("VERIFY", "verifier", "verifier", 2, {"contextRequests": [], "output": self.confirm},
                  seq=7, turn=True, hop=2, cont=v1["callId"], results=[self.t0], hyp=self.hid,
                  history=json.loads(v1["request"]["messages"][1]["content"])["history"],
                  duplicates=[self.t0["toolCallId"]])
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [v2["callId"]]
        evs = [self.inv, self.host, self.v0, self.t0, self.t1, v1, v2]
        self.assertEqual(check_turn_trace(evs), [])
        self.assertEqual(self.msgs(f, evs), [])
        doc = json.loads(v2["request"]["messages"][1]["content"])
        self.assertEqual(doc["history"][-1]["results"][0]["excerpts"], [])
        self.assertEqual(doc["history"][-1]["results"][0]["duplicateOf"], self.t0["toolCallId"])
        self.assertEqual(set(citable_tool_calls(v2["callId"], evs)),
                         {self.host["toolCallId"], self.t0["toolCallId"]})
        wrong = call("VERIFY", "verifier", "verifier", 2, {"contextRequests": [], "output": self.confirm},
                     seq=7, turn=True, hop=2, cont=v1["callId"], results=[self.host],
                     hyp=self.hid)                    # an earlier result that does NOT serve READ
        self.assertTrue(check_turn_trace(evs[:-1] + [wrong]))

    def repaired_hop0(self, *earlier):
        """The chain rebuilt so hop 0 is attempt len(earlier), repairing earlier[-1] (logged at seq 3..)."""
        n = len(earlier)
        v0 = call("VERIFY", "verifier", "verifier", 0, {"contextRequests": [READ, SHELL], "output": None},
                  seq=3 + n, turn=True, hop=0, results=[self.host], hyp=self.hid,
                  attempt=n, repair_of=earlier[-1]["callId"])
        t0, t1 = copy.deepcopy(self.t0), copy.deepcopy(self.t1)
        t0["requestedBy"] = t1["requestedBy"] = v0["callId"]
        t0["seq"], t1["seq"] = 4 + n, 5 + n
        v1 = call("VERIFY", "verifier", "verifier", 1, {"contextRequests": [], "output": self.confirm},
                  seq=6 + n, turn=True, hop=1, cont=v0["callId"],
                  results=[self.t0, self.t1], hyp=self.hid)
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [v1["callId"]]
        return f, [self.inv, self.host, *earlier, v0, t0, t1, v1]

    def hop0_attempt(self, output, attempt=0, repair_of=None, agent="verifier", status="ok"):
        return call("VERIFY", "verifier", agent, 0, output, seq=3 + attempt, turn=True, hop=0,
                    results=[self.host], hyp=self.hid, attempt=attempt,
                    repair_of=repair_of, status=status)

    def test_repair_of_an_unusable_earlier_hop_keeps_the_chain(self):
        bad = self.hop0_attempt({"nope": 1})                # status ok, schema-invalid (D3)
        self.assertFalse(usable_output(bad))
        f, evs = self.repaired_hop0(bad)
        self.assertEqual(check_turn_trace(evs), [])
        self.assertEqual(self.msgs(f, evs), [])
        self.assertEqual(turn_chain(f["verification"]["callIds"][0], evs)[1], [])

    def test_frr1_a_usable_earlier_hop_is_never_repaired(self):
        refuted = self.hop0_attempt({"contextRequests": [], "output": {**self.confirm, "verdict": "refuted"}})
        asked = self.hop0_attempt({"contextRequests": [SHELL], "output": None})
        for usable in (refuted, asked):                     # a refutation, or other context requests
            self.assertTrue(usable_output(usable))
            f, evs = self.repaired_hop0(usable)
            self.assertRejected("repair of a usable response", f, evs)
            self.assertEqual(citable_tool_calls(f["verification"]["callIds"][0], evs), {})

    def test_frr1_every_attempt_on_an_earlier_hop_repair_chain_is_checked(self):
        refuted = self.hop0_attempt({"contextRequests": [], "output": {**self.confirm, "verdict": "refuted"}})
        dropped = self.hop0_attempt(None, attempt=1, repair_of=refuted["callId"], status="invalid-output")
        f, evs = self.repaired_hop0(refuted, dropped)       # attempt 2 repairs an unusable attempt 1
        self.assertRejected("repair of a usable response", f, evs)

    def test_frr2_an_earlier_hop_repairs_only_its_own_previous_attempt(self):
        other = self.hop0_attempt({"nope": 1}, agent="verifier-b")
        f, evs = self.repaired_hop0(other)
        self.assertRejected("previous attempt of the same logical call", f, evs)
        f, evs = self.repaired_hop0(self.hop0_attempt({"nope": 1}))
        self.assertRejected("not a model call logged once", f, [e for e in evs if e.get("attempt") != 0
                                                                 or e["callId"] != evs[2]["callId"]])

    # ---- negatives: ordering, delivery, chain shape
    def test_requested_tool_logged_after_the_next_hop_is_refused(self):
        late = copy.deepcopy(self.t0)
        late["seq"] = 9
        evs = [self.inv, self.host, self.v0, self.t1, self.v1, late]
        self.assertTrue(any("after" in i.message for i in check_turn_trace(evs)))
        self.assertRejected("retrieval chain", events=evs)
        self.assertEqual(citable_tool_calls(self.v1["callId"], evs), {})

    def test_results_must_be_shown_in_request_order(self):
        v1 = self.hop1(results=[self.t1, self.t0])
        evs = self.events[:-1] + [v1]
        self.assertTrue(check_turn_trace(evs))
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [v1["callId"]]
        self.assertRejected("retrieval chain", f, evs)

    def test_executed_result_for_other_arguments_is_refused(self):
        t0 = tool("VERIFY", "verifier", 1, "read_file", {**NORM_READ, "path": "src/other.h"},
                  [code_item(path="src/other.h")], seq=4, by=self.v0["callId"], index=0)
        v1 = self.hop1(results=[t0, self.t1])
        msgs = [i.message for i in check_turn_trace([self.inv, self.host, self.v0, t0, self.t1, v1])]
        self.assertTrue(any("other arguments" in m for m in msgs), msgs)

    def test_fork_subject_ordinal_and_final_continuation_are_refused(self):
        fork = self.hop1(seq=7, ordinal=2)
        self.assertTrue(any("fork" in i.message for i in check_turn_trace(self.events + [fork])))
        other = self.hop1(hyp="hyp_" + "f" * 16)
        self.assertTrue(check_turn_trace(self.events[:-1] + [other]))
        same_ordinal = self.hop1(ordinal=0, attempt=1)   # distinct id, same logical call as hop 0
        self.assertTrue(any("later ordinal" in i.message
                            for i in check_turn_trace(self.events[:-1] + [same_ordinal])))
        after_final = call("VERIFY", "verifier", "verifier", 2, {"contextRequests": [], "output": self.confirm},
                           seq=7, turn=True, hop=2, cont=self.v1["callId"], results=[], hyp=self.hid)
        self.assertTrue(any("requested no context" in i.message
                            for i in check_turn_trace(self.events + [after_final])))

    def test_hop0_shows_only_host_prepared_context_of_its_stage(self):
        inv_tool = tool("INVESTIGATE", "generalist-0", 0, "read_file", NORM_READ, [code_item()], seq=2)
        v0 = call("VERIFY", "verifier", "verifier", 0, {"contextRequests": [READ], "output": None}, seq=3,
                  turn=True, hop=0, results=[inv_tool], hyp=self.hid)
        self.assertTrue(any("context, not INVESTIGATE" in i.message
                            for i in check_turn_trace([self.inv, inv_tool, v0])))

    def test_verifier_cannot_cite_investigator_retrieval_frr3b_on_chains(self):
        inv_tool = tool("INVESTIGATE", "generalist-0", 1, "read_file", NORM_READ, [code_item()], seq=2)
        out = {**self.confirm, "evidence": [{"kind": "tool-ref", "toolCallId": inv_tool["toolCallId"]}]}
        v1 = self.hop1(output=out)
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [v1["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(inv_tool["result"]["evidence"])
        self.assertRejected("not shown to", f, [inv_tool] + self.events[:-1] + [v1])

    def test_turn_request_metadata_is_hashed_and_typed(self):
        req = self.v1["request"]
        for k, v in (("hop", 2), ("continuationOf", "call_" + "0" * 16), ("contextResults", [])):
            self.assertNotEqual(C.request_hash({**req, k: v}), self.v1["requestHash"], k)
        bad = copy.deepcopy(req)
        del bad["continuationOf"]
        self.assertTrue(validate("ModelRequest", bad))
        bad = copy.deepcopy(req)
        del bad["contextResults"]
        self.assertTrue(validate("ModelRequest", bad))
        legacy = {**BASE_REQ, "hop": 0}
        self.assertTrue(validate("ModelRequest", legacy))      # hop only on Turn requests
        turn_no_hop = {**BASE_REQ, "outputSchema": "InvestigatorTurn"}
        self.assertTrue(validate("ModelRequest", turn_no_hop))


class LegacyCitable(ChainBase):
    """FRR1-FRR3 on plain (legacy) calls, and legitimate host context staying citable."""

    def legacy_verifier(self, evidence, seq=6, **kw):
        return call("VERIFY", "verifier", "v-" + self.hid, kw.pop("ordinal", 0),
                    {**self.confirm, "evidence": evidence}, seq=seq, hyp=self.hid, **kw)

    def test_prepare_and_verify_host_context_is_citable_and_same_line_reuse_stays_legitimate(self):
        prep = tool("PREPARE", "prepare", 0, "diff", {"path": "src/auth.py"}, [text_item("-a\n+b")], seq=2)
        ver = self.legacy_verifier([{"kind": "tool-ref", "toolCallId": prep["toolCallId"]}, self.cite])
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"] = prep["result"]["evidence"] + copy.deepcopy(self.f["evidence"])
        self.assertEqual(self.msgs(f, [self.inv, prep, ver]), [])

    def test_frr3a_tool_logged_after_the_citing_call(self):
        late = tool("VERIFY", "v-tool", 0, "diff", {"path": "src/auth.py"}, [text_item("x")], seq=50)
        ver = self.legacy_verifier([{"kind": "tool-ref", "toolCallId": late["toolCallId"]}])
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(late["result"]["evidence"])
        self.assertRejected("not shown to", f, [self.inv, ver, late])

    def test_frr3b_and_chain_requested_tools_are_not_legacy_context(self):
        inv_tool = tool("INVESTIGATE", "generalist-0", 0, "diff", {"path": "src/auth.py"}, [text_item("x")], seq=2)
        ver = self.legacy_verifier([{"kind": "tool-ref", "toolCallId": inv_tool["toolCallId"]}])
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(inv_tool["result"]["evidence"])
        self.assertRejected("not shown to", f, [self.inv, inv_tool, ver])
        ver = self.legacy_verifier([{"kind": "tool-ref", "toolCallId": self.t0["toolCallId"], "index": 0}],
                                   seq=9, ordinal=5)
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(self.t0["result"]["evidence"])
        self.assertRejected("not shown to", f, self.events + [ver])    # another chain's retrieval

    def test_frr1_repair_of_a_usable_refutation(self):
        refuted = call("VERIFY", "verifier", "v-" + self.hid, 0, {**self.confirm, "verdict": "refuted",
                                                                  "evidence": [self.cite]}, seq=2, hyp=self.hid)
        rep = call("VERIFY", "verifier", "v-" + self.hid, 0, {**self.confirm, "evidence": [self.cite]},
                   seq=3, attempt=1, repair_of=refuted["callId"], hyp=self.hid)
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [rep["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(self.f["evidence"])
        self.assertRejected("repair of a usable response", f, [self.inv, refuted, rep])

    def test_frr2_repair_links_join_one_logical_call(self):
        ver = self.legacy_verifier([self.cite], seq=2)
        inv = copy.deepcopy(self.inv)
        inv["repairOf"] = ver["callId"]
        f = copy.deepcopy(self.f)
        f["sourceCallId"] = inv["callId"]
        f["verification"]["callIds"] = [ver["callId"]]
        f["verification"]["evidence"] = copy.deepcopy(self.f["evidence"])
        self.assertRejected("previous attempt of the same logical call", f, [inv, ver])

    def test_d2_code_item_must_still_be_an_item_and_cited(self):
        ver = self.legacy_verifier([self.cite])
        host = copy.deepcopy(self.t0)                      # a host-prepared read the verifier never cited
        del host["requestedBy"], host["requestIndex"]
        host["seq"] = 2
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [ver["callId"]]
        self.assertRejected("was not cited by", f, [self.inv, host, ver])
        f["verification"]["evidence"][0]["excerpt"] = "forged"
        self.assertRejected("is not an item", f, [self.inv, host, ver])


class TurnSchemas(unittest.TestCase):
    def test_context_request_is_data(self):
        for tool_name in ("read_file", "shell", "exec-cmd"):
            self.assertEqual(validate("ContextRequest", {**READ, "tool": tool_name}), [], tool_name)
        self.assertEqual(validate("ContextRequest", {**READ, "args": {"unknown_key": None}}), [])
        for bad in ({**READ, "tool": "Rm -rf"}, {**READ, "args": {"path": ["a"]}},
                    {**READ, "args": {"limit": 1.5}}, {**READ, "args": {"Bad": 1}},
                    {**READ, "purpose": ""}, {**READ, "purpose": "x" * 301}, {**READ, "extra": 1},
                    {**READ, "args": {f"k{i}": 1 for i in range(17)}}):
            self.assertTrue(validate("ContextRequest", bad), bad)

    def test_turn_is_requests_xor_output(self):
        out = {"hypotheses": []}
        self.assertEqual(validate("InvestigatorTurn", {"contextRequests": [READ], "output": None}), [])
        self.assertEqual(validate("InvestigatorTurn", {"contextRequests": [], "output": out}), [])
        for bad in ({"contextRequests": [READ], "output": out}, {"contextRequests": [], "output": None},
                    {"contextRequests": [READ] * 7, "output": None},
                    {"contextRequests": [], "output": {"verdict": "x"}}):
            self.assertTrue(validate("InvestigatorTurn", bad), bad)
        self.assertTrue(validate("VerifierTurn", {"contextRequests": [], "output": out}))

    def test_profiles_and_calls_pair_each_role_with_its_own_schemas(self):
        p = ex("ModelProfile.smoke-synthetic")
        q = copy.deepcopy(p)
        q["roles"]["investigator"]["outputSchema"] = "InvestigatorTurn"
        q["roles"]["verifier"]["outputSchema"] = "VerifierTurn"
        self.assertEqual(validate("ModelProfile", q), [])
        for role, schema in (("investigator", "VerifierTurn"), ("judge", "InvestigatorTurn"),
                             ("verifier", "JudgeOutput")):
            q = copy.deepcopy(p)
            q["roles"][role]["outputSchema"] = schema
            self.assertTrue(validate("ModelProfile", q), (role, schema))

    def test_requested_by_and_index_come_together(self):
        t = tool("VERIFY", "verifier", 0, "diff", {"path": "a"}, [], seq=1, status="empty")
        self.assertTrue(validate("TraceEvent", {**t, "requestedBy": "call_" + "0" * 16}))
        self.assertTrue(validate("TraceEvent", {**t, "requestIndex": 0}))
        self.assertTrue(validate("TraceEvent", {**t, "requestedBy": "call_" + "0" * 16, "requestIndex": 6}))

    def test_version(self):
        self.assertEqual(CONTRACTS_VERSION, "s0a-contracts@6")


class D6RepositoryTextIsNeverFiltered(unittest.TestCase):
    def test_run_shaped_literals_hash_unchanged_even_this_runs_own_id(self):
        for text in ("x = 1  # run_0123456789abcdef", f"token {RUN}", "evr_0123456789abcdef"):
            req = copy.deepcopy(BASE_REQ)
            req["messages"][1]["content"] = text
            self.assertEqual(C.request_hash(req), C.digest(req))
            self.assertIn(text, req["messages"][1]["content"])
        self.assertEqual(C.request_hash(BASE_REQ), ex("TraceEvent.model-call")["requestHash"])  # legacy stable

    def test_typed_fields_never_take_run_ids(self):
        for k in ("hypothesisId", "continuationOf"):
            self.assertTrue(validate("ModelRequest", {**BASE_REQ, k: RUN}), k)
        bad = {**BASE_REQ, "outputSchema": "InvestigatorTurn", "hop": 0, "contextResults": [RUN]}
        self.assertTrue(validate("ModelRequest", bad))


class D2Materialize(unittest.TestCase):
    def test_read_file_items_are_rechecked_against_the_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "s.h").write_text("void Close() {\n  open = false;\n}\n")
            m = build_manifest(root)
            res = snapshot_resolver({m["snapshotId"]: (root, m)})
            item = lambda tid: {"kind": "code", "path": "s.h", "lines": [1, 2], "commit": m["snapshotId"],
                                "excerpt": "void Close() {\n  open = false;", "source": "read_file",
                                "toolCallId": tid, "resolved": True}
            t = tool("VERIFY", "verifier", 0, "read_file", {"side": "head", "path": "s.h"}, [item], seq=1)
            ref = [{"kind": "tool-ref", "toolCallId": t["toolCallId"]}]
            got, problems = materialize_evidence(ref, {t["toolCallId"]: t}, "v", res)
            self.assertEqual((got, problems), (t["result"]["evidence"], []))
            (root / "s.h").write_text("void Close() {\n  fclose(f);  \n}\n")
            got, problems = materialize_evidence(ref, {t["toolCallId"]: t}, "v", res)
            self.assertEqual(got, [])
            self.assertTrue(problems)
        denied = tool("VERIFY", "verifier", 1, "unknown-tool", {"requested": "x"}, [], seq=2, status="denied")
        got, problems = materialize_evidence([{"kind": "tool-ref", "toolCallId": denied["toolCallId"]}],
                                             {denied["toolCallId"]: denied}, "v")
        self.assertEqual(got, [])
        self.assertIn("denied", problems[0])


if __name__ == "__main__":
    unittest.main()
