"""Host-driven retrieval chains (`retrieval@2`).

A retrieval role asks the gateway for the Turn envelope on every hop. The model may only return `contextRequests`
(data); this module alone decides what runs, through one `ToolSession`, and logs every requested call before the
next hop. Nothing here invents a final answer or makes a call that is not one admitted gateway hop.

Counters (exact meaning in orchestration/handoffs/S1-05-interface.md section 2):
  turns     model hops of one chain, the final hop included
  requests  contextRequests the host acts on in one hop
  run/agent/hypothesis tool calls   every logged tool.call (denied/unavailable included, dedup counts nothing)
  context_chars   excerpt characters already shown to a model in one chain
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from reviewer.contracts import serves_request, terminal_payload, turn_requests, usable_output
from reviewer.contracts.canonical import digest, result_hash, tool_call_id
from reviewer.contracts.severity import TRUSTED_TOOL_STATUSES
from reviewer.tools import TOOLS, ArgError, ToolCall, normalize
from reviewer.tools.ops import Outcome

from .prompts import INVESTIGATOR_IMPACT_PROMPT, VERIFIER_IMPACT_PROMPT  # noqa: F401 - impact mode prompt ids
from .prompts import VERIFIER_CONTEXT_CHECK_PROMPT  # noqa: F401 - the opt-in experiment's verifier prompt id

RETRIEVAL_VERSION = "retrieval@2"
MAX_HOPS = 15
MAX_REQUESTS = 6
INVESTIGATOR_PROMPT = "investigator.retrieve@v2"
VERIFIER_PROMPT = "verifier.refute@v4"
MAX_HOST_RESULTS = 200          # ModelRequest.contextResults bound
MAX_REF_RESULTS = 60            # results templated in one request (the most recent ones win)
MAX_REF_ITEMS = 20              # materialize_evidence reads at most 20 items of an un-indexed tool-ref

_NUMERIC = ("investigator_turns", "verifier_turns", "requests_per_turn", "run_tool_calls", "agent_tool_calls",
            "hypothesis_tool_calls", "context_chars")


@dataclass(frozen=True)
class RetrievalPolicy:
    investigator_turns: int = 8
    verifier_turns: int = 4
    requests_per_turn: int = 6
    run_tool_calls: int = 160
    agent_tool_calls: int = 60
    hypothesis_tool_calls: int = 12
    context_chars: int = 240_000
    investigator_prompt: str = INVESTIGATOR_PROMPT
    verifier_prompt: str = VERIFIER_PROMPT

    def __post_init__(self):
        bounds = {"investigator_turns": (1, MAX_HOPS + 1), "verifier_turns": (1, MAX_HOPS + 1),
                  "requests_per_turn": (1, MAX_REQUESTS), "run_tool_calls": (0, 10_000),
                  "agent_tool_calls": (0, 10_000), "hypothesis_tool_calls": (0, 10_000),
                  "context_chars": (0, 10_000_000)}
        for k, (lo, hi) in bounds.items():
            v = getattr(self, k)
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f"retrieval policy {k} must be an integer {lo}..{hi}")
        for k in ("investigator_prompt", "verifier_prompt"):
            if not isinstance(getattr(self, k), str):
                raise ValueError(f"retrieval policy {k} must be a string")

    def tightened(self, **kw) -> "RetrievalPolicy":
        """A copy with lower numeric limits. Raising a limit, or naming anything else, is a host error."""
        for k, v in kw.items():
            if k not in _NUMERIC or isinstance(v, bool) or not isinstance(v, int) or v > getattr(self, k):
                raise ValueError(f"retrieval policy {k!r}: overrides may only lower a numeric limit")
        return dataclasses.replace(self, **kw)

    @property
    def impact(self) -> bool:
        """Impact mode (impact map in PREPARE, find_references, impact prompts) is selected by the investigator
        prompt id alone; every other id keeps the frozen retrieval@2 behaviour byte for byte."""
        return self.investigator_prompt == INVESTIGATOR_IMPACT_PROMPT

    def to_doc(self) -> dict:
        return {"version": RETRIEVAL_VERSION, **dataclasses.asdict(self)}

    @property
    def digest(self) -> str:
        return digest(self.to_doc())


def effective_limits(policy: RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    """What actually binds: the minimum of the policy, the Plan budget and the host tool limits."""
    return {"investigatorTurns": policy.investigator_turns, "verifierTurns": policy.verifier_turns,
            "requestsPerTurn": policy.requests_per_turn,
            "runToolCalls": min(policy.run_tool_calls, budget["maxToolCalls"]),
            "agentToolCalls": min(policy.agent_tool_calls, budget["maxToolCallsPerAgent"], tool_max_calls),
            "hypothesisToolCalls": policy.hypothesis_tool_calls, "contextChars": policy.context_chars,
            "toolOutputCharsPerAgent": budget["maxToolOutputTokensPerAgent"] * 3}


# ---------------------------------------------------------------- results shown to the model

def result_item(index: int, ev: dict, *, duplicate_of: str | None = None, omitted: bool = False) -> dict:
    """One shown result, built only from a logged tool.call event (content-addressed ids, no run data)."""
    res = ev["result"]
    item = {"index": index, "toolCallId": ev["toolCallId"], "tool": ev["tool"], "args": ev["args"],
            "status": res["status"], "completeness": res["completeness"], "truncated": res["truncated"],
            "notice": res["notice"]}
    if duplicate_of is not None:
        item["excerpts"] = []
        item["duplicateOf"] = duplicate_of
        item["notice"] = ("Same request as an earlier result in this conversation; that result is not repeated. "
                          + item["notice"]).strip()
    elif omitted:
        item["excerpts"] = []
        item["excerptsOmitted"] = "retrieval context budget"
        item["notice"] = (item["notice"] + " Excerpts omitted: retrieval context budget.").strip()
    else:
        item["excerpts"] = [e["excerpt"] for e in res["evidence"]]
    return item


def citable_refs(delivered: dict) -> tuple[list[dict], int]:
    """-> (copyable tool-ref templates, number of delivered results not templated because of the list bound).

    `delivered` is a Chain's own map of logged tool.call events the model was actually shown with excerpts and whose
    status is trusted. A template is built from that logged event alone (id, tool, item path/lines): it never
    names a denied, omitted, future or other-chain result, and nothing about it depends on the run."""
    usable = [ev for ev in delivered.values()
              if ev["result"]["status"] in TRUSTED_TOOL_STATUSES and ev["result"]["evidence"]]
    kept = usable[-MAX_REF_RESULTS:]
    out = []
    for ev in kept:
        tid = ev["toolCallId"]
        items = []
        for i, x in enumerate(ev["result"]["evidence"][:MAX_REF_ITEMS]):
            item = {"index": i}
            if x.get("kind") == "code":
                item["path"], item["lines"] = x["path"], list(x["lines"])
            items.append(item)
        out.append({"toolCallId": tid, "tool": ev["tool"], "cite": {"kind": "tool-ref", "toolCallId": tid},
                    "items": items})
    return out, len(usable) - len(kept)


def excerpt_chars(ev: dict) -> int:
    return sum(len(e["excerpt"]) for e in ev["result"]["evidence"])


def host_call(session, rq: dict, notice: str, status: str = "denied") -> ToolCall:
    """A logged result for a request the host will not run (policy cap). Same shape as the tools layer's own
    denied/unavailable results, appended to the session so ordinals and ids stay unique."""
    tool = rq["tool"] if rq["tool"] in getattr(session, "tools", TOOLS) else "unknown-tool"
    args = {"rejected": True}
    ordinal = len(session.calls)
    result = Outcome(status, notice=notice).result()
    call = ToolCall(session.stage, session.agent_id, ordinal, tool, args,
                    tool_call_id(session.stage, session.agent_id, ordinal, tool, args), result, result_hash(result),
                    {}, {"side": None, "layers": [], "coverage": session.view.coverage(),
                         "manifestVerifiedOnEveryRead": True}, None, 0)
    session.calls.append(call)
    return call


# ---------------------------------------------------------------- chain outcome

@dataclass
class ChainEnd:
    """final: payload set. error: a typed error (gateway/guard/replay). exhausted: a named counter ended it."""
    call_ids: list                         # every attempt call id of every hop, in order
    payload: dict | None = None
    final_call: str | None = None
    error: dict | None = None
    exhausted: str | None = None           # turns | tool-calls | context-chars
    unread: list = dataclasses.field(default_factory=list)
    stop: tuple | None = None              # (incomplete reason, TypedError) from a gate during execution
    hops: int = 0
    tool_calls: int = 0


class Chain:
    """One role/agent/subject conversation. `eng` is the Engine (gate, model_call, recorder, ordinals)."""

    def __init__(self, eng, *, stage: str, role: str, agent: str, session, t0: float, turns: int,
                 policy: RetrievalPolicy, hypothesis_id: str | None = None, host_events: list,
                 hyp_calls_used: int = 0, unrendered: frozenset = frozenset()):
        self.eng, self.stage, self.role, self.agent = eng, stage, role, agent
        self.session, self.t0, self.turns, self.policy = session, t0, turns, policy
        self.hypothesis_id = hypothesis_id
        self.host_events = host_events[:MAX_HOST_RESULTS]
        # `unrendered`: host-prepared results listed to the model with their excerpts replaced by the omitted marker.
        # Only what the model was actually shown is "delivered" (dedup target) and counts against the context budget.
        self.delivered: dict[str, dict] = {e["toolCallId"]: e for e in self.host_events
                                           if e["toolCallId"] not in unrendered}
        self.shown_chars = sum(excerpt_chars(e) for e in self.host_events if e["toolCallId"] not in unrendered)
        self.hyp_used = hyp_calls_used
        self.requested_calls = 0
        self.tools_exhausted = False
        self.context_exhausted = self.shown_chars >= policy.context_chars
        self.history: list[dict] = []

    # -- budgets
    def _allowed(self) -> int:
        """Tool calls still allowed right now (>= 0): the smallest remaining of every counter."""
        eng, s = self.eng, self.session
        agent_left = min(eng.agent_limit(), self.policy.agent_tool_calls) - len(s.calls)    # run remainder: below
        run_used = sum(1 for e in eng.recorder.events if e["type"] == "tool.call")
        run_left = min(self.policy.run_tool_calls, eng.budget["maxToolCalls"]) - run_used
        left = min(agent_left, run_left)
        if self.hypothesis_id is not None:
            left = min(left, self.policy.hypothesis_tool_calls - self.hyp_used)
        used_chars = sum(len(x["excerpt"]) for e in eng.recorder.events if e["type"] == "tool.call"
                         and e["stage"] == s.stage and e["agentId"] == s.agent_id for x in e["result"]["evidence"])
        if used_chars > eng.budget["maxToolOutputTokensPerAgent"] * 3:
            left = 0
        return max(0, left)

    def _find_duplicate(self, rq: dict) -> str | None:
        try:
            norm = (normalize(rq["tool"], rq["args"], self.session.limits)
                    if rq["tool"] in getattr(self.session, "tools", TOOLS) else None)
        except ArgError:
            return None
        if norm is None:
            return None
        for tid, ev in self.delivered.items():
            if ev["tool"] == rq["tool"] and ev["args"] == norm and ev["result"]["status"] in TRUSTED_TOOL_STATUSES \
                    and serves_request(rq, ev):
                return tid
        return None

    # -- execute one hop's requests
    def execute(self, requests: list, requested_by: str):
        """-> (items shown, [context result ids], stop|None). Every executed request is logged before returning."""
        eng, items, ids = self.eng, [], []
        for i, rq in enumerate(requests):
            g = eng.gate(self.stage, self.t0)
            if g is not None:
                return items, ids, g
            dup = self._find_duplicate(rq) if i < self.policy.requests_per_turn else None
            if dup is not None:
                items.append(result_item(i, self.delivered[dup], duplicate_of=dup))
                ids.append(dup)
                continue
            if i >= self.policy.requests_per_turn:
                call = host_call(self.session, rq, f"Per-turn request cap ({self.policy.requests_per_turn}) reached; "
                                 "this request was not run.")
            else:
                allowed = self._allowed()
                self.session.limits = dataclasses.replace(self.session.limits, max_calls=len(self.session.calls) + allowed)
                call = self.session.call(rq["tool"], rq["args"])
                if call.result["status"] == "unavailable":
                    self.tools_exhausted = True
            ev = eng.recorder.append("tool.call", **call.trace_fields(), requestedBy=requested_by, requestIndex=i)
            self.requested_calls += 1
            self.hyp_used += 1
            if self.session.tampered:
                eng.fatal_tamper(self.stage)
            omitted = self.shown_chars + excerpt_chars(ev) > self.policy.context_chars
            if omitted:
                self.context_exhausted = True
            else:
                self.shown_chars += excerpt_chars(ev)
            if ev["result"]["status"] in TRUSTED_TOOL_STATUSES and not omitted:
                self.delivered[ev["toolCallId"]] = ev
            items.append(result_item(i, ev, omitted=omitted))
            ids.append(ev["toolCallId"])
        if self._allowed() == 0 and not self.tools_exhausted:
            self.tools_exhausted = True
        return items, ids, None

    # -- the loop
    def run(self, build) -> ChainEnd:
        """The session's own limits are lowered per request to enforce the policy; they are restored afterwards
        so a later hypothesis or host-prepared call is judged against the real session limits again."""
        saved = self.session.limits
        try:
            return self._run(build)
        finally:
            self.session.limits = saved

    def _run(self, build) -> ChainEnd:
        """build(hop, state) -> ModelRequest. state: {history, contextResults, continuationOf, hop, turns,
        toolsExhausted, contextExhausted, toolCallsRemaining, contextCharsRemaining}."""
        eng = self.eng
        end = ChainEnd(call_ids=[])
        context_results = [e["toolCallId"] for e in self.host_events]
        prev_call = None
        for hop in range(self.turns):
            g = eng.gate(self.stage, self.t0)
            if g is not None:
                end.error = g[1]
                end.stop = g
                return end
            state = {"history": list(self.history), "contextResults": list(context_results), "hop": hop,
                     "continuationOf": prev_call, "turns": self.turns, "lastTurn": hop == self.turns - 1,
                     "toolsExhausted": self.tools_exhausted, "contextExhausted": self.context_exhausted,
                     "toolCallsRemaining": self._allowed(),
                     "contextCharsRemaining": max(0, self.policy.context_chars - self.shown_chars)}
            state["citableRefs"], state["refsOmitted"] = citable_refs(self.delivered)
            req = build(hop, state)
            ordinal = eng.next_ordinal(self.stage, self.role, self.agent)
            out, err, attempts = eng.model_call(self.stage, self.role, self.agent, ordinal, req)
            end.call_ids += [a.call_id for a in attempts if a.call_id]
            end.hops += 1
            if err is not None:
                end.error = err
                return end
            accepted = next(a.call_id for a in reversed(attempts) if a.outcome == "ok")
            if out["output"] is not None:
                end.payload, end.final_call = out["output"], accepted
                end.tool_calls = self.requested_calls
                return end
            requests = out["contextRequests"]
            if hop == self.turns - 1:
                end.exhausted, end.unread = "turns", requests
                end.tool_calls = self.requested_calls
                return end
            if self.tools_exhausted or self.context_exhausted:
                end.exhausted = "tool-calls" if self.tools_exhausted else "context-chars"
                end.unread = requests
                end.tool_calls = self.requested_calls
                return end
            items, ids, stop = self.execute(requests, accepted)
            if stop is not None:
                end.stop, end.error = stop, stop[1]
                end.unread = requests[len(ids):]
                end.tool_calls = self.requested_calls
                return end
            self.history.append({"turn": hop, "requested": [{"tool": r["tool"], "arguments": r["args"],
                                                              "purpose": r["purpose"]} for r in requests],
                                 "results": items})
            context_results, prev_call = ids, accepted
        raise AssertionError("unreachable: the last hop always returns")        # pragma: no cover


# ---------------------------------------------------------------- trace summary (pure)

def summarize(events: list) -> dict:
    """Per-chain facts re-derived from the logged trace alone: hops, requested calls by status, whether a usable
    final payload exists and how many requests of the last hop were never run (unread)."""
    calls = [e for e in events if e["type"] == "model.call" and "hop" in e["request"]]
    tools = [e for e in events if e["type"] == "tool.call"]
    by_id = {e["callId"]: e for e in calls}
    # group by walking continuations back to a hop-0 call
    def root(ev):
        seen = 0
        while ev["request"]["hop"] > 0 and seen < 20:
            ev = by_id.get(ev["request"]["continuationOf"])
            if ev is None:
                return None
            seen += 1
        return ev
    groups: dict[str, list] = {}
    for e in calls:
        if not usable_output(e):          # a schema-invalid status-ok attempt is not a hop; its repair is
            continue
        r = root(e)
        if r is not None:
            groups.setdefault(r["callId"], []).append(e)
    out = []
    for rid, hops in sorted(groups.items(), key=lambda kv: by_id[kv[0]]["seq"]):
        hops.sort(key=lambda e: e["request"]["hop"])
        last = hops[-1]
        asked_by = {h["callId"] for h in hops}
        slots = {(h["stage"], h["role"], h["agentId"], h["ordinal"]) for h in hops}
        attempts = sum(1 for c in calls if (c["stage"], c["role"], c["agentId"], c["ordinal"]) in slots)
        mine = [t for t in tools if t.get("requestedBy") in asked_by]
        status: dict = {}
        for t in mine:
            status[t["result"]["status"]] = status.get(t["result"]["status"], 0) + 1
        pending = turn_requests(last)
        unread = 0 if pending is None else len(pending) - sum(1 for t in mine if t.get("requestedBy") == last["callId"])
        out.append({"stage": last["stage"], "role": last["role"], "agentId": last["agentId"],
                    "hypothesisId": last["request"].get("hypothesisId"), "hops": len(hops),
                    "attempts": attempts, "contextRequestTurns": sum(1 for h in hops if turn_requests(h)),
                    "requestedToolCalls": len(mine), "toolStatus": dict(sorted(status.items())),
                    "final": terminal_payload(last) is not None, "unreadRequests": max(0, unread),
                    "truncatedOrPartial": sum(1 for t in mine if t["result"]["truncated"] is not None
                                              or t["result"]["status"] == "partial"),
                    "deniedOrUnavailable": sum(1 for t in mine if t["result"]["status"] in ("denied", "unavailable"))})
    return {"schema": "retrieval-summary@1", "chains": out,
            "hops": sum(c["hops"] for c in out), "attempts": sum(c["attempts"] for c in out),
            "requestedToolCalls": sum(c["requestedToolCalls"] for c in out),
            "unreadRequests": sum(c["unreadRequests"] for c in out)}
