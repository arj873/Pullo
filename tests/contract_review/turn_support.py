"""Builders for the S1-01 independent contracts gate (reviewer-owned, offline, stdlib only).

Everything is payload-consistent: call ids, request hashes, tool-call ids, result hashes and cost
ids are recomputed with the contract's own recipes, so a fixture that is rejected is rejected for
the rule under test and not because of a stale hash. Builders only construct; they never call the
checks they are used to test.
"""
from __future__ import annotations

import copy

import finalreview_support as F
from reviewer.contracts import canonical as C

STAGES = {"investigator": "INVESTIGATE", "verifier": "VERIFY"}
TURN = {"investigator": "InvestigatorTurn", "verifier": "VerifierTurn"}


def creq(tool="read_file", args=None, purpose="check the cited lines"):
    return {"tool": tool, "args": args if args is not None else {"path": "src/auth.py", "side": "head"},
            "purpose": purpose}


def turn_call(run, role, agent, ordinal, *, hop=0, cont=None, results=(), requests=None, output=None,
              seq=0, hyp=None, attempt=0, repair_of=None, status="ok", raw_output="unset",
              stage=None, schema=None, content=None, omit_hyp=False, drop=(), hash_check=True):
    """A Turn model.call. `requests`/`output` build the envelope (exactly one non-empty for a valid
    one); `raw_output` replaces the whole envelope. `drop` removes request keys (schema attacks).
    The verifier request subject is derived from the honest agent label `v-hyp_...` like F.model_call."""
    stage = stage or STAGES[role]
    envelope = ({"contextRequests": list(requests or []), "output": output}
                if raw_output == "unset" else raw_output)
    req = {**F.ex("TraceEvent.model-call")["request"], "role": role,
           "outputSchema": schema or TURN[role],
           "messages": [{"role": "user", "content": content or f"{stage} {role} {agent} {ordinal}"}],
           "hop": hop, "contextResults": list(results)}
    if cont is not None:
        req["continuationOf"] = cont
    if hyp is None and role == "verifier" and agent.startswith("v-hyp_") and not omit_hyp:
        hyp = agent[2:]
    if hyp and role == "verifier":
        req["hypothesisId"] = hyp
    for k in drop:
        req.pop(k, None)
    cid = C.call_id(stage, role, agent, ordinal, attempt)
    ev = {"schema": "trace-event@1", "runId": run, "seq": seq, "type": "model.call",
          "callId": cid, "stage": stage, "role": role, "agentId": agent, "ordinal": ordinal,
          "attempt": attempt, "requestHash": C.request_hash(req), "request": req,
          "response": {"status": status, "resolvedModel": "synthetic-fixture", "output": envelope,
                       "rawText": None, "usage": F.ex("CostRecord.eval-synthetic")["usage"]},
          "costRecordId": C.cost_id(cid), "redactions": {}}
    if repair_of:
        ev["repairOf"] = repair_of
    return ev


def tool_event(run, stage, agent, ordinal, tool, args, items, *, status="ok", seq=0, by=None, index=None):
    """A tool.call. Items get the call's own toolCallId (as the tool layer mints them)."""
    tid = C.tool_call_id(stage, agent, ordinal, tool, args)
    items = [{**it, "toolCallId": tid} for it in items]
    res = {"status": status, "evidence": items if status != "denied" else [],
           "completeness": "exact", "truncated": None, "notice": ""}
    ev = {"schema": "trace-event@1", "runId": run, "seq": seq, "type": "tool.call", "toolCallId": tid,
          "stage": stage, "agentId": agent, "ordinal": ordinal, "tool": tool, "args": args,
          "resultHash": C.digest(res), "result": res, "redactions": {}}
    if by is not None:
        ev["requestedBy"] = by["callId"] if isinstance(by, dict) else by
        ev["requestIndex"] = index
    return ev


def code_item(path="src/auth.py", lines=(1, 2), excerpt="a = 1\nb = 2", commit=None, source="read_file"):
    return {"kind": "code", "path": path, "lines": list(lines),
            "commit": commit or "snap:sha256:" + "ab" * 32, "excerpt": excerpt, "source": source,
            "resolved": True}


def rehash(ev):
    """Recompute the hash/id fields of an event whose request/args were edited on purpose."""
    if ev["type"] == "model.call":
        ev["requestHash"] = C.request_hash(ev["request"])
        ev["callId"] = C.call_id(ev["stage"], ev["role"], ev["agentId"], ev["ordinal"], ev["attempt"])
        ev["costRecordId"] = C.cost_id(ev["callId"])
    return ev


def final_inv(sc):
    return copy.deepcopy(sc.inv["response"]["output"])


def final_ver(sc):
    return copy.deepcopy(sc.confirm)


class TurnScenario:
    """The honest Scenario, rebuilt as two Turn chains (investigator and verifier, two hops each).

    seq plan: 1 inv hop0, 2 inv tool (requested), 3 inv hop1 (final), 4 ver hop0, 5 ver tool,
    6 ver hop1 (final). The terminal payloads are exactly the legacy Scenario's, so the Finding
    needs no change except its call ids and the tool item each chain delivered."""

    def __init__(self, with_tool_cites=False, same_line=False):
        base = F.Scenario()
        self.base = base
        self.run = base.run
        f = base.fresh()
        self.finding = f
        hid = f["id"]
        # investigator chain: asks for one file, then proposes (payload identical to the legacy call)
        self.i_req = creq()
        self.i0 = turn_call(self.run, "investigator", "generalist-0", 0, requests=[self.i_req], seq=1)
        self.i_tool = tool_event(self.run, "INVESTIGATE", "generalist-0", 0, "read_file", self.i_req["args"],
                                 [code_item()], seq=2, by=self.i0, index=0)
        self.i1 = turn_call(self.run, "investigator", "generalist-0", 1, hop=1, cont=self.i0["callId"],
                            results=[self.i_tool["toolCallId"]], output=final_inv(base), seq=3)
        # verifier chain for the Finding's hypothesis
        self.v_req = creq(args={"path": "src/store.py", "side": "head"})
        self.v0 = turn_call(self.run, "verifier", "v-" + hid, 0, requests=[self.v_req], seq=4, hyp=hid)
        self.v_tool = tool_event(self.run, "VERIFY", "v-" + hid, 0, "read_file", self.v_req["args"],
                                 [code_item(path="src/store.py")], seq=5, by=self.v0, index=0)
        self.v1 = turn_call(self.run, "verifier", "v-" + hid, 1, hop=1, cont=self.v0["callId"],
                            results=[self.v_tool["toolCallId"]], output=final_ver(base), seq=6, hyp=hid)
        f["sourceCallId"] = self.i1["callId"]
        f["verification"]["callIds"] = [self.v1["callId"]]

    @property
    def events(self):
        return [self.i0, self.i_tool, self.i1, self.v0, self.v_tool, self.v1]

    def fresh(self):
        return copy.deepcopy(self.finding)

    def evs(self):
        return copy.deepcopy(self.events)
