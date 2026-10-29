"""ToolSession: a small standalone API a pipeline agent calls; limits and ids live here.

    session = ToolSession(view, stage="INVESTIGATE", agent_id="generalist", limits=Limits())
    call = session.call("read_file", {"side": "head", "path": "src/a.py", "start_line": 1})
    call.result          # contract-valid ToolResult (code Evidence carries resolved: true)
    call.trace_fields()  # keyword fields for a `tool.call` TraceEvent (e.g. Recorder.append)

Only the four tools below exist by default. A session may be opened with a wider fixed set: impact mode adds the
read-only `find_references` (IMPACT_TOOLS) for model requests, and the host-only `impact_scan` (HOST_IMPACT_TOOLS)
for the PREPARE session, which no model can reach. Anything else (shell, regex, URL, write, test run, post) is
refused as an unknown tool and never reaches the filesystem.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from reviewer.contracts import validate
from reviewer.contracts.canonical import result_hash, tool_call_id
from reviewer.contracts.redaction import contains_protected, redact

from . import ops, policy
from .words import valid_symbol
from .ops import DENIED, Ctx, Limits, Outcome
from .view import SIDES, View

TOOLS = ("list_files", "read_file", "search_literal", "diff")
IMPACT_TOOLS = TOOLS + ("find_references",)            # model-requestable in impact mode
HOST_IMPACT_TOOLS = TOOLS + ("impact_scan",)           # the PREPARE (host) session in impact mode
ALL_TOOLS = TOOLS + ("find_references", "impact_scan")
_OPS = {"list_files": ops.list_files, "read_file": ops.read_file,
        "search_literal": ops.search_literal, "diff": ops.diff,
        "find_references": ops.find_references, "impact_scan": ops.impact_scan}
MAX_SYMBOL_CHARS = 128
MAX_OFFSET = 5_000


class ArgError(ValueError):
    pass


def _int(v, name, lo, hi):
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ArgError(f"{name} must be an integer {lo}..{hi}")
    return v


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:       # lone surrogate: cannot be hashed, logged or searched for
        return False
    return True


def _side(v):
    if v not in SIDES:
        raise ArgError("side must be base or head")
    return v


def normalize(tool: str, args, lim: Limits) -> dict:
    """Closed argument schema with defaults filled in, so equal calls have equal ids."""
    if not isinstance(args, dict):
        raise ArgError("arguments must be an object")
    spec = {
        "list_files": {"side": None, "prefix": "", "limit": lim.max_list},
        "read_file": {"side": None, "path": None, "start_line": 1, "end_line": None},
        "search_literal": {"side": None, "query": None, "prefix": "", "case_sensitive": True,
                           "limit": lim.max_search_results},
        "diff": {"path": None},
        "find_references": {"side": None, "symbol": None, "path_prefix": "", "limit": lim.max_search_results,
                            "offset": 0},
        "impact_scan": {},
    }[tool]
    if tool == "list_files":
        spec["after"] = ""            # paging cursor; omitted from the normalized args when empty (stable ids)
    if set(args) - set(spec):
        raise ArgError("unknown argument(s)")      # names are model text: not echoed
    a = {k: args.get(k, d) for k, d in spec.items()}
    if "side" in spec:
        a["side"] = _side(a["side"])
    if tool == "list_files":
        if not policy.valid_prefix(a["prefix"]):
            raise ArgError("prefix")
        a["limit"] = _int(a["limit"], "limit", 1, 10_000)
        if a["after"] == "":
            del a["after"]
        elif not policy.permitted(a["after"]):
            raise ArgError("after")
    elif tool == "read_file":
        if not policy.valid_path(a["path"]):
            raise ArgError("path")
        a["start_line"] = _int(a["start_line"], "start_line", 1, 10**7)
        if a["end_line"] is not None:
            a["end_line"] = _int(a["end_line"], "end_line", a["start_line"], 10**7)
    elif tool == "search_literal":
        q = a["query"]
        if not isinstance(q, str) or not 1 <= len(q) <= lim.max_query_chars or not _encodable(q) \
                or contains_protected(q) or any(ord(c) < 32 or ord(c) == 127 for c in q):
            raise ArgError("query must be 1..%d printable characters without secrets" % lim.max_query_chars)
        if not policy.valid_prefix(a["prefix"]):
            raise ArgError("prefix")
        if not isinstance(a["case_sensitive"], bool):
            raise ArgError("case_sensitive must be a boolean")
        a["limit"] = _int(a["limit"], "limit", 1, 1000)
    elif tool == "find_references":
        sym = a["symbol"]
        if not valid_symbol(sym, MAX_SYMBOL_CHARS) or contains_protected(sym):
            raise ArgError("symbol must be one identifier (letters, digits, _ or $; parts may be joined by . or -), "
                           f"at most {MAX_SYMBOL_CHARS} characters")
        if not policy.valid_prefix(a["path_prefix"]):
            raise ArgError("path_prefix")
        a["limit"] = _int(a["limit"], "limit", 1, 1000)
        a["offset"] = _int(a["offset"], "offset", 0, MAX_OFFSET)
    elif tool == "impact_scan":
        pass
    else:
        if a["path"] is not None and not policy.valid_path(a["path"]):
            raise ArgError("path")
    return a


@dataclass
class ToolCall:
    stage: str
    agent_id: str
    ordinal: int
    tool: str
    args: dict
    tool_call_id: str
    result: dict
    result_hash: str
    redactions: dict
    provenance: dict
    incomplete: str | None = None
    latency_ms: int = 0

    def trace_fields(self) -> dict:
        """Fields of a `tool.call` TraceEvent (the recorder adds schema, runId, seq, at)."""
        return {"toolCallId": self.tool_call_id, "stage": self.stage, "agentId": self.agent_id,
                "ordinal": self.ordinal, "tool": self.tool, "args": self.args,
                "resultHash": self.result_hash, "result": self.result, "redactions": self.redactions,
                "latencyMs": self.latency_ms}


class ToolSession:
    def __init__(self, view: View, *, stage: str = "INVESTIGATE", agent_id: str = "generalist",
                 limits: Limits | None = None, clock=time.monotonic, tools: tuple = TOOLS):
        if not set(tools) <= set(ALL_TOOLS) or not set(TOOLS) <= set(tools):
            raise ValueError("a session's tools are the four base tools plus known impact tools")
        self.view, self.stage, self.agent_id = view, stage, agent_id
        self.tools = tuple(tools)
        self.limits = limits or Limits()
        self.clock, self.started = clock, clock()
        self.calls: list[ToolCall] = []
        self.log: list[dict] = []
        self.incomplete: str | None = None     # first INCOMPLETE_REASONS value a cap produced
        self.tampered = False                  # a read failed pinned-snapshot verification

    def _finish(self, ordinal, tool, args, out: Outcome, ctx: Ctx | None, t0: float) -> ToolCall:
        result = out.result()
        issues = validate("ToolResult", result)
        if issues:   # never hand a malformed or secret-bearing result onward
            out = Outcome("error", notice="Result failed contract validation and was withheld.")
            result = out.result()
        tcid = tool_call_id(self.stage, self.agent_id, ordinal, tool, args)
        if ctx is not None and ctx.tampered:      # any verification failure, even in a partial result
            self.tampered = True
        if out.incomplete and not self.incomplete:
            self.incomplete = out.incomplete
        call = ToolCall(
            self.stage, self.agent_id, ordinal, tool, args, tcid, result, result_hash(result),
            dict(out.redactions),
            {"side": args.get("side"), "layers": out.layers, "coverage": self.view.coverage(),
             "manifestVerifiedOnEveryRead": True},
            out.incomplete, int((self.clock() - t0) * 1000))
        self.calls.append(call)
        rec = {"ordinal": ordinal, "tool": tool, "toolCallId": tcid, "status": result["status"],
               "incomplete": out.incomplete}
        self.log.append({k: (redact(v)[0] if isinstance(v, str) else v) for k, v in rec.items()})
        return call

    def call(self, tool, args=None) -> ToolCall:
        """Never raises: any internal failure becomes a generic `error` result."""
        t0 = self.clock()
        try:
            return self._call(tool, args)
        except Exception:  # noqa: BLE001
            return self._finish(len(self.calls), "unknown-tool", {"rejected": True}, Outcome(
                "error", notice="Internal tool error; nothing was returned."), None, t0)

    def _call(self, tool, args=None) -> ToolCall:
        ordinal = len(self.calls)
        t0 = self.clock()
        if tool not in self.tools:
            name = tool if isinstance(tool, str) and len(tool) <= 64 and tool.replace("_", "").replace("-", "").isalnum() \
                and tool.isascii() else "?"
            offered = [t for t in self.tools if t != "impact_scan"]     # the host-only tool is never advertised
            return self._finish(ordinal, "unknown-tool", {"requested": redact(name[:64])[0]},
                                Outcome("denied", notice="No such tool. Available: " + ", ".join(offered) + "."), None, t0)
        try:
            norm = normalize(tool, args if args is not None else {}, self.limits)
        except ArgError as e:
            return self._finish(ordinal, tool, {"rejected": True},
                                Outcome("denied", notice="Invalid arguments: " + redact(str(e))[0][:300]), None, t0)
        if ordinal >= self.limits.max_calls:
            self.incomplete = self.incomplete or "tool-calls-exhausted"
            return self._finish(ordinal, tool, norm, Outcome(
                "unavailable", incomplete="tool-calls-exhausted",
                notice=f"Tool-call limit ({self.limits.max_calls}) reached; no further calls will run."), None, t0)
        if t0 - self.started >= self.limits.wall_s:
            self.incomplete = self.incomplete or "deadline"
            return self._finish(ordinal, tool, norm, Outcome(
                "unavailable", incomplete="deadline", notice="Tool wall-time limit reached."), None, t0)
        tcid = tool_call_id(self.stage, self.agent_id, ordinal, tool, norm)
        ctx = Ctx(self.view, self.limits, tcid, self.clock, self.started)
        try:
            out = _OPS[tool](ctx, norm)
        except Exception:  # noqa: BLE001 - tools never raise into the agent loop
            out = Outcome("error", notice="Internal tool error; nothing was returned.")
        if self.clock() - self.started >= self.limits.wall_s and not out.incomplete:
            out.incomplete = "deadline"
            out.notice = (out.notice + " Wall-time limit reached during this call.").strip()
        return self._finish(ordinal, tool, norm, out, ctx, t0)
