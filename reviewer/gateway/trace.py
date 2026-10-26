"""Trace recording and verified loading.

`Recorder` writes the actual requests/responses a gateway handled as trace-event@1 lines.
`load_trace` is the only way to obtain a replayable trace: nothing is trusted by shape. It
recomputes requestHash, callId, costRecordId, toolCallId and resultHash from the payloads and
cross-checks every model call against its cost record.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from reviewer.contracts import ContractInputError, ContractViolation, loads_strict, require, validate_trace
from reviewer.contracts.budget import release_allowed
from reviewer.contracts.canonical import call_id, cost_id, request_hash, result_hash, tool_call_id
from reviewer.contracts.redaction import redact_json

from .errors import TraceError
from .guard import GUARD_CODES, REFUSED_BY

MAX_TRACE_BYTES = 64 << 20
MAX_EVENTS = 100_000


def events_to_bytes(events: list[dict]) -> bytes:
    """The exact bytes a Recorder writes for these events (one sorted-key JSON object per line)."""
    return "".join(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n" for ev in events).encode("utf-8")


def bytes_digest(data: bytes) -> str:
    """sha256 of raw trace bytes, in the contract Digest shape. This is the value to pin."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Recorder:
    """Thread-safe trace writer for one run. path=None keeps events in memory only."""

    def __init__(self, run_id: str, path=None):
        self.run_id = run_id
        self.events: list[dict] = []
        self._lock = threading.Lock()
        self._f = None
        if path is not None:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            self._f = os.fdopen(fd, "w", encoding="utf-8")

    def append(self, type_: str, **fields) -> dict:
        with self._lock:
            ev = {"schema": "trace-event@1", "runId": self.run_id, "seq": len(self.events),
                  "type": type_, **fields}
            require("TraceEvent", ev)
            self.events.append(ev)
            if self._f is not None:
                self._f.write(json.dumps(ev, sort_keys=True, ensure_ascii=False) + "\n")
                self._f.flush()
            return ev

    def start(self, run: dict) -> dict:
        return self.append("run.start", run=run)

    def end(self, status: str, incomplete: list | None = None) -> dict:
        ev = self.append("run.end", status=status, incomplete=incomplete or [])
        self.close()
        return ev

    def trace_digest(self) -> str:
        """Digest of the trace bytes recorded so far. Pin it OUTSIDE the trace (operator config or a
        separately stored run artifact) before handing the trace to strict replay."""
        with self._lock:
            return bytes_digest(events_to_bytes(self.events))

    def close(self) -> None:
        with self._lock:
            if self._f is not None:
                os.fsync(self._f.fileno())
                self._f.close()
                self._f = None


class LoadedTrace:
    """A verified trace. `byte_digest` is over the exact trace bytes; strict replay compares it with a
    digest pinned outside the trace. `complete` is False for a recording without run.end (only
    obtainable with load_trace(..., allow_partial=True)); strict replay refuses it."""

    def __init__(self, events: list[dict], byte_digest: str):
        self.events = events
        self.run_id = events[0]["runId"]
        self.byte_digest = byte_digest
        self.complete = events[-1]["type"] == "run.end"
        self.calls: dict[str, list[dict]] = {}       # requestHash -> model.call events in order
        self.costs: dict[str, dict] = {}             # costRecordId -> CostRecord
        for ev in events:
            if ev["type"] == "model.call":
                self.calls.setdefault(ev["requestHash"], []).append(ev)
            elif ev["type"] == "cost":
                self.costs[ev["record"]["id"]] = ev["record"]

    @property
    def model_calls(self) -> int:
        return sum(len(v) for v in self.calls.values())


def _fail(i, why):
    raise TraceError(f"event[{i}]: {why}")


def error_charge_class(err: dict) -> str:
    """How a recorded model-call error was settled: `refused` (budget refusal, 0), `released` (the
    provider definitely did not process it, 0), `billed` (a processed answer from an unauthorized
    model, charged from its usage) or `retained` (outcome unknown: the full reservation).
    The gateway stamps detail.providerOutcome on every provider error, so replay can recompute this;
    an error without the stamp is retained (fail closed)."""
    detail = err.get("detail") if isinstance(err.get("detail"), dict) else {}
    if err["code"] == "budget-exhausted":
        return "refused"
    # a host-guard refusal never reached the provider; the marker (stripped from adapter errors) keeps
    # older recordings whose provider errors used these codes loadable and charged
    if err["code"] in GUARD_CODES and detail.get("refusedBy") == REFUSED_BY:
        return "refused"
    outcome = detail.get("providerOutcome")
    if release_allowed(outcome):
        return "released"
    if err["code"] == "contract-violation" and outcome == "processed" and "resolvedModel" in detail:
        return "billed"
    return "retained"


def verify_events(events: list, data: bytes | None = None, *, allow_partial: bool = False) -> LoadedTrace:
    issues = validate_trace(events)
    if issues:
        raise TraceError("trace invalid: " + "; ".join(str(x) for x in issues[:5]))
    if events[-1]["type"] != "run.end" and not allow_partial:
        raise TraceError("trace has no run.end: not a complete recording (diagnostic loads need allow_partial=True)")
    seen_calls, seen_tools, cost_of = set(), set(), {}
    for i, ev in enumerate(events):
        t = ev["type"]
        if t == "model.call":
            req = ev["request"]
            try:
                want = request_hash(req)
            except ValueError as e:
                _fail(i, f"request cannot be hashed: {e}")
            if ev["requestHash"] != want:
                _fail(i, "requestHash does not match the recorded request")
            if redact_json(req)[0] != req or redact_json(ev["response"])[0] != ev["response"]:
                _fail(i, "persisted payload is not in redacted form")
            cid = call_id(ev["stage"], ev["role"], ev["agentId"], ev["ordinal"], ev["attempt"])
            if ev["callId"] != cid:
                _fail(i, "callId does not match stage/role/agentId/ordinal/attempt")
            if ev["costRecordId"] != cost_id(cid):
                _fail(i, "costRecordId does not match cost_id(callId)")
            if req["role"] != ev["role"]:
                _fail(i, "request role differs from the event role")
            if ev["callId"] in seen_calls:
                _fail(i, "duplicate callId")
            seen_calls.add(ev["callId"])
        elif t == "tool.call":
            tid = tool_call_id(ev["stage"], ev["agentId"], ev["ordinal"], ev["tool"], ev["args"])
            if ev["toolCallId"] != tid:
                _fail(i, "toolCallId does not match its arguments")
            if ev["resultHash"] != result_hash(ev["result"]):
                _fail(i, "resultHash does not match the recorded result")
            if "costRecordId" in ev and ev["costRecordId"] != cost_id(tid):
                _fail(i, "costRecordId does not match cost_id(toolCallId)")
            if tid in seen_tools:
                _fail(i, "duplicate toolCallId")
            seen_tools.add(tid)
        elif t == "cost":
            rec = ev["record"]
            if rec["id"] in cost_of:
                _fail(i, "duplicate cost record")
            cost_of[rec["id"]] = (i, rec)
    for i, ev in enumerate(events):
        if ev["type"] == "model.call":
            hit = cost_of.get(ev["costRecordId"])
            if hit is None:
                _fail(i, "model call has no cost record")
            rec = hit[1]
            if rec.get("callId") != ev["callId"]:
                _fail(i, "cost record names a different call")
            if rec.get("provider") != ev["request"]["provider"] or rec.get("model") != ev["request"]["model"]:
                _fail(i, "cost record provider/model differ from the request")
            if ev["response"] is not None and rec["usage"] != ev["response"]["usage"]:
                _fail(i, "cost record usage differs from the response usage")
            if ev["response"] is None:
                klass = error_charge_class(ev["error"])
                if klass != "billed" and any(v is not None for v in rec["usage"].values()):
                    _fail(i, "an errored call cannot carry known usage")
                if klass in ("refused", "released") and rec["usdMicros"] != 0:
                    _fail(i, f"a {klass} call cannot carry a charge")
                if klass == "retained" and rec["usdMicros"] not in (None, rec["reservedUsdMicros"]):
                    _fail(i, "a retained call is charged its full reservation")
    for rid, (i, rec) in cost_of.items():
        if "callId" in rec and rec["callId"] not in seen_calls:
            _fail(i, "cost record for a call that is not in the trace")
        if "toolCallId" in rec and rec["toolCallId"] not in seen_tools:
            _fail(i, "cost record for a tool call that is not in the trace")
    return LoadedTrace(events, bytes_digest(events_to_bytes(events) if data is None else data))


def load_trace(source, *, allow_partial: bool = False) -> LoadedTrace:
    """source: a trace.jsonl path (str/Path), its raw bytes, or a list of event dicts (copied).

    A trace without run.end is refused unless allow_partial=True (diagnostics only; the result has
    complete=False and strict replay will not accept it). Loading verifies internal consistency; it
    does not authenticate the file. Pin `byte_digest` outside the trace for that."""
    if isinstance(source, list):
        import copy
        return verify_events(copy.deepcopy(source), allow_partial=allow_partial)
    if isinstance(source, (str, Path)):
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as e:
            raise TraceError(f"cannot open trace: {e.strerror}") from e
        with os.fdopen(fd, "rb") as f:
            data = f.read(MAX_TRACE_BYTES + 1)
    else:
        data = bytes(source)
    if len(data) > MAX_TRACE_BYTES:
        raise TraceError("trace too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise TraceError("trace is not UTF-8") from e
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or len(lines) > MAX_EVENTS:
        raise TraceError("trace is empty or has too many events")
    events = []
    for n, line in enumerate(lines):
        try:
            events.append(loads_strict(line))
        except ContractInputError as e:
            raise TraceError(f"line {n + 1}: {e}") from e
    return verify_events(events, data, allow_partial=allow_partial)
