"""Stage 0A wire contracts (frozen by S0-03, corrected by S0-03-fix).

Names follow 03-data-model-and-glossary.md. Deliberate departures are listed in
orchestration/handoffs/S0-03.md and S0-03-fix.md. Money is integer micro-USD and
fractions are basis points so canonical hashes are stable; every integer is
bounded for JSON interoperability.
"""

from __future__ import annotations

import json

from .canonical import (GITHUB_REPO, call_id, comment_id, cost_id, digest, hypothesis_id,
                        idempotency_key_eval, idempotency_key_local, idempotency_key_pr,
                        request_hash, run_id, tool_call_id)
from .redaction import json_contains_protected
from .schema import (REGISTRY, Arr, Bool, Const, Enum, Int, Invariant, Issue, Json, Map, Nullable,
                     Num, Obj, RelPath, Scalar, Str, Union, define, validate)
from .severity import RANK, STRENGTHS, TRUSTED_TOOL_STATUSES
from .budget import HOST_STOP_RECORDING_VERSIONS
from .stages import (ACCESS_POLICY, ERROR_CODES, INCOMPLETE_REASONS, LIVE_MODES, OFFLINE_MODES,
                     REPLAYABLE_FROM, RUN_MODES, RUN_STATUSES, STAGE_CEILING_SEC, STAGE_STATUSES, STAGES,
                     TRIGGERS)

# ---------------------------------------------------------------- primitives

def Id(prefix: str) -> Str:
    return Str(pattern=prefix + r"_[0-9a-f]{16}")


SLUG_RE = r"[a-z0-9][a-z0-9._-]{0,63}"
Slug = Str(pattern=SLUG_RE)
RepoId = Str(pattern=GITHUB_REPO.pattern + "|" + SLUG_RE).describe(
    "GitHub 'Owner/Name' with display case preserved (identity is case-folded, canonical.repo_key), "
    "or an opaque lowercase slug for synthetic/local fixtures.")
Digest = Str(pattern=r"sha256:[0-9a-f]{64}")
SnapshotId = Str(pattern=r"snap:sha256:[0-9a-f]{64}")
GitSha = Str(pattern=r"[0-9a-f]{40}")
ProfileRef = Str(pattern=SLUG_RE + r"@[0-9]{1,6}")
PromptVersion = Str(pattern=r"[a-z][a-z0-9.-]{0,63}@v[0-9]{1,6}")
IdemKey = Str(pattern=r"idem:(?:pr|local|eval):[0-9a-f]{64}")
Fingerprint = Str(pattern=r"fp2:[0-9a-f]{32}")
UsdMicros = Int(0, 10**12)             # <= $1M per record/aggregate
Tokens = Int(0, 10**10)
Count = Int(0, 10**9)
Line = Int(1, 10**7)
Timestamp = Str(pattern=r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z")
Stage = Enum(*STAGES)

Severity = define("Severity", Enum("P0", "P1", "P2").describe(
    "P0 ships a bug/security hole; P1 likely bug; P2 worthwhile improvement. "
    "Ceilings are executable in severity.py."))
Category = define("Category", Enum(
    "bug", "security", "breaking-change", "duplicate-logic", "test-gap", "ticket-compliance",
    "rule-violation", "performance", "style"))
Tier = define("Tier", Enum("standard", "deep", "max"))
Impact = define("Impact", Enum(
    "data-loss", "auth-bypass", "crash", "security-exposure", "corruption",  # severe
    "incorrect-result", "regression", "breaking-change", "ticket-unmet", "performance",
    "maintainability", "none"))
Strength = define("EvidenceStrength", Enum(*STRENGTHS).describe(
    "Evidence confidence derived from trusted traces (severity.evidence_strength), separate "
    "from impact and severity. Used for ranking, never minted by a model."))


def no_secrets(name: str) -> Invariant:
    return Invariant("no-secrets", f"persisted {name} contains no protected text (redact first)",
                     lambda d: [("", "protected text present")] if json_contains_protected(d) else [])


def _lines_ok(d):
    if "lines" in d and d["lines"][0] > d["lines"][1]:
        yield ".lines", "start line after end line"


Lines = Arr(Line, min_items=2, max_items=2)

TypedError = define("TypedError", Obj(
    required={"code": Enum(*ERROR_CODES), "message": Str(max_len=2000), "retryable": Bool()},
    optional={"stage": Stage, "detail": Json()},
    invariants=[no_secrets("TypedError")],
))

Usage = define("Usage", Obj(
    required={k: Nullable(Tokens) for k in (
        "uncachedInputTokens", "cachedInputTokens", "cacheWriteInputTokens", "outputTokens",
        "reasoningTokens")},
    description="null means unknown, never zero.",
))

# ---------------------------------------------------------------- snapshots

SnapshotEntry = define("SnapshotEntry", Obj(required={
    "path": RelPath(),
    "type": Enum("file", "executable", "symlink"),
    "size": Int(0, 2**53 - 1),
    "sha256": Str(pattern=r"[0-9a-f]{64}"),
}, description="symlink entries hash the link target text; links are never followed."))


def _manifest_ok(d):
    from .snapshot import snapshot_id
    paths = [e["path"] for e in d["entries"]]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        yield ".entries", "entries must be unique and sorted by path"
        return
    present = set(paths)
    for i, p in enumerate(paths):
        parts = p.split("/")
        for j in range(1, len(parts)):
            if "/".join(parts[:j]) in present:
                yield f".entries[{i}]", f"{p} lies under a file or symlink entry"
                break
    if d["snapshotId"] != snapshot_id(d["entries"]):
        yield ".snapshotId", "does not match digest of entries"


SnapshotManifest = define("SnapshotManifest", Obj(
    required={"schema": Const("snapshot-manifest@1"), "snapshotId": SnapshotId,
              "entries": Arr(SnapshotEntry, max_items=200_000)},
    optional={"gitCommit": GitSha},
    invariants=[Invariant("snapshot-digest",
                          "sorted unique entries, none under a file/symlink, id = digest",
                          _manifest_ok)],
))

# ---------------------------------------------------------------- evidence


def _evidence_ok(d):
    if d["kind"] == "code":
        for k in ("path", "lines", "commit"):
            if k not in d:
                yield f".{k}", "required for code evidence"
    elif "toolCallId" not in d:
        yield ".toolCallId", "non-code evidence must trace to a logged tool call"
    yield from _lines_ok(d)


Evidence = define("Evidence", Obj(
    required={"kind": Enum("code", "tool-result", "history", "test-run", "analyzer"),
              "excerpt": Str(max_len=8000), "source": Str(min_len=1, max_len=200)},
    optional={"path": RelPath(), "lines": Lines,
              "commit": Str(pattern=r"snap:sha256:[0-9a-f]{64}|[0-9a-f]{40}"),
              "toolCallId": Id("tool"), "resolved": Const(True)},
    invariants=[Invariant("evidence-shape", "code needs path+lines+commit; others need toolCallId",
                          _evidence_ok), no_secrets("Evidence")],
    description="Pipeline-built evidence. Non-code kinds are copied from trusted tool.call "
                "results (severity.materialize_evidence), never taken from model output. "
                "resolved=true is set only by the pipeline/tool layer after the citation was "
                "checked against the pinned snapshot (snapshot.snapshot_resolver); code evidence "
                "without it is untrusted. ModelEvidence cannot carry it.",
))

ModelEvidence = define("ModelEvidence", Union("kind", {
    "code": Obj(required={"kind": Const("code"), "path": RelPath(), "lines": Lines,
                          "commit": Str(pattern=r"snap:sha256:[0-9a-f]{64}|[0-9a-f]{40}"),
                          "excerpt": Str(max_len=8000)},
                invariants=[Invariant("lines-order", "start <= end", _lines_ok)]),
    "tool-ref": Obj(required={"kind": Const("tool-ref"), "toolCallId": Id("tool")},
                    optional={"index": Int(0, 1000), "note": Str(max_len=1000)}),
}).describe("What a model may cite: a code citation (checked against the snapshot) or a "
            "reference to a logged tool call. Models cannot assert analyzer/test-run/history kinds."))

Location = define("Location", Obj(
    required={"path": RelPath(), "line": Line},
    optional={"endLine": Line},
    invariants=[Invariant("location-order", "endLine >= line",
                          lambda d: [(".endLine", "before line")]
                          if d.get("endLine", d["line"]) < d["line"] else [])],
))

# ---------------------------------------------------------------- model outputs

HypothesisDraft = define("HypothesisDraft", Obj(
    required={"claim": Str(min_len=1, max_len=2000), "category": Category,
              "suspectedSeverity": Severity, "impact": Impact, "location": Location,
              "evidence": Arr(ModelEvidence, min_items=1, max_items=20)},
    optional={"mechanism": Str(max_len=2000), "reach": Str(max_len=2000),
              "confidence": Num(0, 1)},
))

InvestigatorOutput = define("InvestigatorOutput", Obj(
    required={"hypotheses": Arr(HypothesisDraft, max_items=20)},
    description="Investigator role output schema. Empty list = nothing found.",
))


def _verifier_ok(d):
    if d["verdict"] == "confirmed" and not d["evidence"]:
        yield ".evidence", "confirmed needs at least one cited Evidence"


VerifierOutput = define("VerifierOutput", Obj(
    required={"verdict": Enum("confirmed", "refuted", "uncertain"), "reachable": Bool(),
              "impact": Impact, "evidence": Arr(ModelEvidence, max_items=20),
              "notes": Str(max_len=4000)},
    invariants=[Invariant("confirm-cited", "confirmed requires evidence", _verifier_ok)],
    description="An uncited or unresolvable refutation is converted to uncertain by VERIFY (33).",
))

# ---------------------------------------------------------------- retrieval turns (s0a-contracts@6)

MAX_TURN_REQUESTS = 6
MAX_HOP = 15

ContextRequest = define("ContextRequest", Obj(
    required={"tool": Str(pattern=r"[a-z][a-z0-9_-]{0,63}"),
              "args": Map(Scalar(max_len=4096), key_pattern=r"[a-z][a-z0-9_]{0,31}", max_props=16),
              "purpose": Str(min_len=1, max_len=300)},
    description="Data, never authority: any grammatical tool name or argument key is schema-valid "
                "and the host ToolSession alone decides what runs (unknown tools/args/values become a "
                "logged denied ToolResult shown to the model). purpose never reaches a tool and never "
                "changes policy, caps or tools.",
))


def _turn_ok(d):
    if bool(d["contextRequests"]) == (d["output"] is not None):
        yield "", "exactly one of non-empty contextRequests or non-null output"


def _turn(name: str, payload) -> object:
    return define(name, Obj(
        required={"contextRequests": Arr(ContextRequest, max_items=MAX_TURN_REQUESTS),
                  "output": Nullable(payload)},
        invariants=[Invariant("turn-exclusive", "requests context xor returns the role output",
                              _turn_ok)],
        description="Retrieval envelope used for EVERY hop of a retrieval chain. A final envelope "
                    "carries the unchanged legacy role output as `output`; the trace keeps the "
                    "envelope as returned and terminal_payload() unwraps it."))


InvestigatorTurn = _turn("InvestigatorTurn", InvestigatorOutput)
VerifierTurn = _turn("VerifierTurn", VerifierOutput)

ROLE_OUTPUT = {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput",
               "judge": "JudgeOutput"}            # the role's payload schema (plain profiles use it as is)
ROLE_TURN = {"investigator": "InvestigatorTurn", "verifier": "VerifierTurn"}
ROLE_SCHEMAS = {"investigator": ("InvestigatorOutput", "InvestigatorTurn"),
                "verifier": ("VerifierOutput", "VerifierTurn"), "judge": ("JudgeOutput",)}
TURN_PAYLOAD = {"InvestigatorTurn": "InvestigatorOutput", "VerifierTurn": "VerifierOutput"}
OUTPUT_SCHEMAS = ("InvestigatorOutput", "VerifierOutput", "JudgeOutput", "InvestigatorTurn",
                  "VerifierTurn")
# Host-prepared (not model-requested) tool calls a call of this stage may be shown and cite.
HOST_CONTEXT_STAGES = {"INVESTIGATE": ("PREPARE", "INVESTIGATE"), "VERIFY": ("PREPARE", "VERIFY")}

JudgeOutput = define("JudgeOutput", Obj(
    required={"comments": Arr(Obj(
        required={"findingIds": Arr(Id("hyp"), min_items=1, unique=True),
                  "title": Str(min_len=1, max_len=200), "body": Str(min_len=1, max_len=4000)},
        optional={"suggestion": Str(max_len=8000)}), max_items=50)},
    description="Wording only. Severity, dedup, citations, ranking and cap are deterministic.",
))

# ---------------------------------------------------------------- hypotheses/findings

_hyp_fields = {
    "id": Id("hyp"), "runId": Id("run"), "specialist": Slug,
    "claim": Str(min_len=1, max_len=2000), "category": Category, "suspectedSeverity": Severity,
    "impact": Impact, "location": Location, "evidence": Arr(Evidence, min_items=1, max_items=50),
    "modelFamily": Str(min_len=1, max_len=64),
}
_hyp_optional = {"mechanism": Str(max_len=2000), "reach": Str(max_len=2000),
                 "confidence": Num(0, 1), "sourceCallId": Id("call")}

Hypothesis = define("Hypothesis", Obj(
    required=_hyp_fields, optional=_hyp_optional, invariants=[no_secrets("Hypothesis")],
    description="confidence is never a gate or rank key on its own (42)."))


def evidence_key(e: dict) -> tuple:
    """Identity of a citation: what it points at, not its excerpt text."""
    if e["kind"] == "code":
        return ("code", e.get("path"), tuple(e.get("lines", ())), e.get("commit"))
    return (e["kind"], e.get("toolCallId"))


def _finding_ok(d):
    # Verification policy (S0-03-verification-policy.md, supersedes C12): independence comes
    # from a distinct actual verifier call, not from citing a different location. Reusing
    # the proposer's citation is allowed; the provenance is checked against the trace by
    # check_finding_provenance.
    calls = d["verification"]["callIds"]
    if d["sourceCallId"] in calls:
        yield ".verification.callIds", "self-verification: the investigator call cannot verify itself"
    for side, evs in (("evidence", d["evidence"]), ("verification.evidence",
                                                    d["verification"]["evidence"])):
        for i, e in enumerate(evs):
            if e["kind"] == "code" and e.get("resolved") is not True:
                yield f".{side}[{i}]", "code evidence in a Finding must be snapshot-resolved"


Verification = Obj(required={
    "verdict": Const("confirmed"), "refutationAttempts": Int(1, 10),
    "verifierFamily": Str(min_len=1, max_len=64), "notes": Str(max_len=4000),
    "evidence": Arr(Evidence, min_items=1, max_items=50),
    "callIds": Arr(Id("call"), min_items=1, max_items=10, unique=True)})

Finding = define("Finding", Obj(
    required={**_hyp_fields, "sourceCallId": Id("call"), "verification": Verification,
              "severityBasis": Obj(required={"impact": Impact, "reachable": Bool()})},
    optional={k: v for k, v in _hyp_optional.items() if k != "sourceCallId"},
    invariants=[Invariant("independent-confirm", "verifier calls are distinct from the proposer "
                          "call; code evidence is snapshot-resolved", _finding_ok),
                no_secrets("Finding")],
    description="Finding.id equals the Hypothesis id it came from: hypothesis_id(specialist, "
                "index, claim, location.path, location.line) of entry `index` in the output of "
                "sourceCallId, the INVESTIGATE investigator call that proposed it. "
                "verification.callIds are the distinct VERIFY verifier calls whose request names "
                "this id (ModelRequest.hypothesisId) and which confirmed it; severityBasis and "
                "verification.evidence are what those calls returned (check_finding_provenance). "
                "The verifier may cite the same pinned lines as the proposer.",
))

# Finding fields that must equal the proposal they came from (claim and location also enter the id).
PROPOSAL_FIELDS = ("claim", "category", "suspectedSeverity", "impact", "location")
_CITATION_KEYS = ("path", "lines", "commit", "excerpt")


def _repair_chain(cid: str, calls: dict) -> list[str]:
    """cid followed by the calls it repairs, oldest last (cycle-safe)."""
    chain = [cid]
    while (nxt := calls.get(chain[-1], {}).get("repairOf")) and nxt not in chain:
        chain.append(nxt)
    return chain


# ---------------------------------------------------------------- turn helpers (s0a-contracts@6)

def is_turn_schema(name) -> bool:
    return name in TURN_PAYLOAD


def usable_output(call_event) -> bool:
    """A model.call answer the pipeline may act on: status ok AND output valid for the request's own
    outputSchema. A status-ok answer that fails its schema (D3) is not usable."""
    if not isinstance(call_event, dict):
        return False
    req, resp = call_event.get("request"), call_event.get("response")
    if not isinstance(req, dict) or not isinstance(resp, dict) or resp.get("status") != "ok":
        return False
    schema = req.get("outputSchema")
    return schema in OUTPUT_SCHEMAS and not validate(schema, resp.get("output"))


def terminal_payload(call_event):
    """The legacy role output a usable final call returned: the output itself for a plain schema, the
    envelope's `output` for a final Turn. None for unusable or non-final calls. The traced envelope is
    never rewritten; this only reads it."""
    if not usable_output(call_event):
        return None
    out = call_event["response"]["output"]
    return out["output"] if call_event["request"]["outputSchema"] in TURN_PAYLOAD else out


def turn_requests(call_event):
    """contextRequests of a usable non-final Turn call, else None."""
    if not usable_output(call_event) or call_event["request"]["outputSchema"] not in TURN_PAYLOAD:
        return None
    return call_event["response"]["output"]["contextRequests"] or None


def serves_request(context_request, tool_event) -> bool:
    """The tool call ran the requested tool, and every requested argument equals (same JSON type) the
    normalized argument the host executed. Defaults the host filled in are allowed."""
    if not isinstance(context_request, dict) or not isinstance(tool_event, dict):
        return False
    want, got = context_request.get("args"), tool_event.get("args")
    if tool_event.get("tool") != context_request.get("tool") or not isinstance(want, dict) \
            or not isinstance(got, dict):
        return False
    return all(k in got and type(got[k]) is type(v) and got[k] == v for k, v in want.items())


class _Index:
    """Valid events of one run by id. A duplicated id is counted (and so unusable) even if invalid."""

    def __init__(self, events, run: str | None = None):
        self.logged: dict[str, int] = {}
        self.calls: dict[str, dict] = {}
        self.tools: dict[str, dict] = {}
        self.cache: dict[str, dict] = {}
        for ev in events if isinstance(events, list) else []:
            if not isinstance(ev, dict) or (run is not None and ev.get("runId") != run):
                continue
            kind = ev.get("type")
            key = ev.get("callId") if kind == "model.call" else ev.get("toolCallId") \
                if kind == "tool.call" else None
            if not isinstance(key, str):
                continue
            self.logged[key] = self.logged.get(key, 0) + 1
            if not validate("TraceEvent", ev):
                (self.calls if kind == "model.call" else self.tools)[key] = ev
        self.continuations: dict[str, list] = {}
        for ev in self.calls.values():
            if "continuationOf" in ev["request"]:
                self.continuations.setdefault(ev["request"]["continuationOf"], []).append(ev)
        self.requested: dict[tuple, list] = {}
        for t in self.tools.values():
            if "requestedBy" in t:
                self.requested.setdefault((t["requestedBy"], t["requestIndex"]), []).append(t)

    def call(self, cid):
        return self.calls.get(cid) if self.logged.get(cid, 0) == 1 else None

    def tool(self, tid):
        return self.tools.get(tid) if self.logged.get(tid, 0) == 1 else None


_SAME_CHAIN = ("hypothesisId", "outputSchema", "promptVersion", "profile", "provider", "model")


def _hops(ev: dict, idx: _Index) -> tuple[list[dict], list[str]]:
    """The hops of ev's chain root-first, plus any problem walking it."""
    hops = [ev]
    while hops[-1]["request"].get("hop", 0) > 0:
        pid = hops[-1]["request"]["continuationOf"]
        prev = idx.call(pid)
        if prev is None:
            return hops[::-1], [f"continues {pid}, which is not a model call logged once in this run"]
        if prev in hops or prev["request"].get("hop") != hops[-1]["request"]["hop"] - 1:
            return hops[::-1], [f"continues {pid}, which is not the previous hop of this chain"]
        hops.append(prev)
    return hops[::-1], []


def _repair_link_issues(ev: dict, idx: _Index) -> list[tuple[str, str]]:
    """The repairOf link of one model.call (FRR1, FRR2): it names a call logged once that is the
    previous attempt of the same logical call (stage, role, agentId, ordinal; attempt - 1) and whose
    answer was unusable. Empty without repairOf."""
    pid = ev.get("repairOf")
    if pid is None:
        return []
    prev = idx.call(pid)
    if prev is None:
        return [(".repairOf", f"repairs {pid}, which is not a model call logged once in this run")]
    out = []
    if any(ev[k] != prev[k] for k in ("stage", "role", "agentId", "ordinal")) \
            or ev["attempt"] != prev["attempt"] + 1:
        out.append((".repairOf", "repairOf does not name the previous attempt of the same logical call"))
    if usable_output(prev):
        out.append((".repairOf", "is a repair of a usable response; only an unusable answer is repaired"))
    return out


def _turn_call_issues(ev: dict, idx: _Index) -> list[tuple[str, str]]:
    """Rules for one Turn model.call: its continuation link and the results it shows."""
    req, out = ev["request"], []
    if "hop" not in req:
        return out
    results = req.get("contextResults", [])
    if req["hop"] == 0:
        allowed = HOST_CONTEXT_STAGES.get(ev["stage"], ())
        for i, tid in enumerate(results):
            p, t = f".request.contextResults[{i}]", idx.tool(tid)
            if t is None:
                out.append((p, f"{tid} is not a tool call logged once in this run"))
            elif "requestedBy" in t:
                out.append((p, "hop 0 shows only host-prepared tool calls"))
            elif t["stage"] not in allowed:
                out.append((p, f"a {ev['stage']} call is shown {list(allowed)} context, not {t['stage']}"))
            elif t["seq"] >= ev["seq"]:
                out.append((p, "is logged after the call that shows it"))
        return out
    pid, p = req["continuationOf"], ".request.continuationOf"
    prev = idx.call(pid)
    if prev is None:
        return [(p, f"{pid} is not a model call logged once in this run")]
    if any(prev[k] != ev[k] for k in ("stage", "role", "agentId")) or \
            any(prev["request"].get(k) != req.get(k) for k in _SAME_CHAIN):
        out.append((p, "continues a call of another stage, role, agent, subject, prompt or schema"))
    if prev["request"].get("hop") != req["hop"] - 1:
        out.append((p, "the continued call is not hop - 1"))
    if prev["ordinal"] >= ev["ordinal"]:
        out.append((p, "a continuation needs a later ordinal than the hop it continues"))
    if prev["seq"] >= ev["seq"]:
        out.append((p, "continues a call logged later"))
    if len({(c["agentId"], c["ordinal"]) for c in idx.continuations.get(pid, [])}) > 1:
        out.append((p, "the previous hop is continued by more than one logical call (fork)"))
    asked = turn_requests(prev)
    if asked is None:
        return out + [(p, "continues a call whose usable envelope requested no context")]
    if len(results) != len(asked):
        return out + [(".request.contextResults",
                       f"shows {len(results)} results for {len(asked)} requests of the previous hop")]
    earlier = {t["toolCallId"] for (by, _), ts in idx.requested.items() if by == pid for t in ts}
    hops, _ = _hops(prev, idx)
    for h in hops:
        earlier.update(h["request"].get("contextResults", []))
    for i, (cr, tid) in enumerate(zip(asked, results)):
        p, t = f".request.contextResults[{i}]", idx.tool(tid)
        if t is None:
            out.append((p, f"{tid} is not a tool call logged once in this run"))
        elif t["seq"] >= ev["seq"]:
            out.append((p, "is logged after the call that shows it"))
        elif (t.get("requestedBy"), t.get("requestIndex")) == (pid, i):
            continue
        elif not (tid in earlier and serves_request(cr, t)):
            out.append((p, "is neither the tool call made for this request nor an earlier result of "
                           "this chain that serves it"))
    return out


def _requested_tool_issues(t: dict, idx: _Index) -> list[tuple[str, str]]:
    """Rules for one tool.call made because a Turn asked for it."""
    if "requestedBy" not in t:
        return []
    pid, i, out = t["requestedBy"], t["requestIndex"], []
    prev = idx.call(pid)
    if prev is None:
        return [(".requestedBy", f"{pid} is not a model call logged once in this run")]
    if (prev["stage"], prev["agentId"]) != (t["stage"], t["agentId"]):
        out.append((".requestedBy", "requested by a call of another stage or agent"))
    if prev["seq"] >= t["seq"]:
        out.append((".requestedBy", "logged before the call that requested it"))
    asked = turn_requests(prev)
    if asked is None or i >= len(asked):
        return out + [(".requestIndex", "the requesting call made no request at this index")]
    if len(idx.requested.get((pid, i), [])) > 1:
        out.append((".requestIndex", "more than one tool call answers this request"))
    if t["result"]["status"] in TRUSTED_TOOL_STATUSES and not serves_request(asked[i], t):
        out.append((".args", "a usable result for another tool or other arguments than requested"))
    if any(s["seq"] > t["seq"] for j in range(i) for s in idx.requested.get((pid, j), [])):
        out.append((".requestIndex", "requests were executed out of index order"))
    conts = idx.continuations.get(pid, [])
    if conts:
        if t["seq"] >= min(c["seq"] for c in conts):
            out.append((".seq", "logged after the next hop started"))
        if any(c["request"]["contextResults"][i:i + 1] != [t["toolCallId"]] for c in conts):
            out.append((".toolCallId", "the next hop does not show this result at its request index"))
    return out


def _chain_issues(ev: dict, idx: _Index) -> list[str]:
    """Every rule on ev's chain: each hop's link and shown results, the repair links of every attempt
    of each hop (FRR1, FRR2), and each requested tool call the chain made. Empty for a legacy call.
    Repair links are provenance rules, as for legacy calls; check_turn_trace does not apply them."""
    if "hop" not in ev["request"]:
        return []
    hops, bad = _hops(ev, idx)
    out = list(bad)
    for h in hops:
        out += [f"hop {h['request']['hop']} ({h['callId']}){p}: {m}" for p, m in _turn_call_issues(h, idx)]
        for a in _repair_chain(h["callId"], idx.calls)[:-1]:
            out += [f"hop {h['request']['hop']} ({a}){p}: {m}"
                    for p, m in _repair_link_issues(idx.calls[a], idx)]
        for (by, _), ts in idx.requested.items():
            if by == h["callId"]:
                out += [f"{t['toolCallId']}{p}: {m}" for t in ts for p, m in _requested_tool_issues(t, idx)]
    return out


def _rendered(hop: dict, idx: _Index) -> set:
    """toolCallIds this hop's request document shows WITH every excerpt of the logged result, in order (S1-17).
    Only ids in this hop's own contextResults whose tool call was logged before the hop count (S1-18).
    Read from the request-hashed host JSON (messages[1]: host context `context`/`pinnedContext` and
    `history[].results`). An omitted, duplicate-marker or partial item, or a missing/malformed document, shows
    nothing (fail closed)."""
    msgs = hop["request"]["messages"]
    try:
        doc = json.loads(msgs[1]["content"]) if len(msgs) > 1 and msgs[1]["role"] == "user" else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        return set()
    items = [doc.get("context"), doc.get("pinnedContext")]
    history = doc.get("history")
    items += [h.get("results") for h in history if isinstance(h, dict)] if isinstance(history, list) else []
    listed, out = set(hop["request"].get("contextResults", [])), set()
    for it in (x for group in items if isinstance(group, list) for x in group):
        tid = it.get("toolCallId") if isinstance(it, dict) else None
        t = idx.tool(tid) if isinstance(tid, str) else None
        if t is not None and tid in listed and t["seq"] < hop["seq"] and t["result"]["evidence"] \
                and it.get("excerpts") == [e["excerpt"] for e in t["result"]["evidence"]]:
            out.add(tid)
    return out


def _citable(ev: dict, idx: _Index) -> dict:
    cid = ev["callId"]
    if cid not in idx.cache:
        if "hop" in ev["request"]:
            got: dict = {}
            if not _chain_issues(ev, idx):
                hops = _hops(ev, idx)[0]
                shown = set().union(*(_rendered(h, idx) for h in hops))
                for h in hops:
                    for tid in h["request"].get("contextResults", []):
                        if tid in shown:
                            got[tid] = idx.tool(tid)
            idx.cache[cid] = got
        else:
            allowed = HOST_CONTEXT_STAGES.get(ev["stage"], ())
            idx.cache[cid] = {tid: t for tid, t in idx.tools.items()
                              if idx.logged[tid] == 1 and "requestedBy" not in t
                              and t["stage"] in allowed and t["seq"] < ev["seq"]}
    return idx.cache[cid]


def _run_of(call_id, events):
    return next((e.get("runId") for e in events if isinstance(e, dict)
                 and e.get("type") == "model.call" and e.get("callId") == call_id), None) \
        if isinstance(events, list) else None


def turn_chain(call_id: str, events: list) -> tuple[list[dict], list[Issue]]:
    """(hop events root-first, issues) for the chain ending at call_id. A legacy call is its own
    one-element chain with no issues; an unknown or duplicated id gives ([], [issue])."""
    idx = _Index(events, _run_of(call_id, events))
    ev = idx.call(call_id)
    if ev is None:
        return [], [Issue("$", "turn-chain", f"{call_id} is not a model call logged once in this run")]
    hops = _hops(ev, idx)[0] if "hop" in ev["request"] else [ev]
    return hops, [Issue("$", "turn-chain", m) for m in _chain_issues(ev, idx)]


def citable_tool_calls(call_id: str, events: list) -> dict:
    """toolCallId -> tool.call event that the call `call_id` was shown and may cite. Turn call: the
    union of contextResults over its own valid chain that some hop rendered with every excerpt (_rendered;
    {} if the chain is invalid). Legacy call: tool
    calls logged once before it, not model-requested, from HOST_CONTEXT_STAGES[its stage]. Pass this
    to severity.materialize_evidence instead of every tool call of the run."""
    idx = _Index(events, _run_of(call_id, events))
    ev = idx.call(call_id)
    return {} if ev is None else dict(_citable(ev, idx))


def check_turn_trace(events: list) -> list[Issue]:
    """Causal rules of retrieval chains over one run's trace (part of validate_trace). Legacy events
    are unaffected. See ModelRequest/TraceEvent descriptions and S1-01-interface.md section 2."""
    idx = _Index(events)
    out: list[Issue] = []
    for n, ev in enumerate(events if isinstance(events, list) else []):
        if not isinstance(ev, dict):
            continue
        if ev.get("type") == "model.call" and idx.call(ev.get("callId")) is ev:
            out += [Issue(f"[{n}]{p}", "turn-trace", m) for p, m in _turn_call_issues(ev, idx)]
        elif ev.get("type") == "tool.call" and idx.tool(ev.get("toolCallId")) is ev:
            out += [Issue(f"[{n}]{p}", "turn-trace", m) for p, m in _requested_tool_issues(ev, idx)]
    return out


def _cited(e: dict, cited: list, idx: _Index) -> str | None:
    """None when e is what severity.materialize_evidence makes of a citation of one of the `cited`
    (citations, citing call) pairs: the same code citation (excerpt included), or an item copied from
    a tool call the citing call could cite. Otherwise the reason it is not."""
    tid = e.get("toolCallId")
    if tid is None:
        hit = any(c["kind"] == "code" and all(c[k] == e[k] for k in _CITATION_KEYS)
                  for citations, _ in cited for c in citations)
        return None if hit else "was not cited by"
    named = False
    for citations, ev in cited:
        tc = _citable(ev, idx).get(tid)
        for c in citations:
            if c["kind"] != "tool-ref" or c["toolCallId"] != tid:
                continue
            named = True
            if tc is None or tc["seq"] >= ev["seq"]:
                continue
            items = tc["result"]["evidence"]
            items = items[c["index"]:c["index"] + 1] if "index" in c else items[:20]
            if e in items:
                return None
    return ("names a tool call that was not shown to (citable by)" if named
            else "was not cited by")


def check_finding_provenance(finding: dict, events: list) -> list[Issue]:
    """Cross-trace check for one Finding against its run's trace events (s0a-contracts@6).

    - Every referenced call id is logged exactly once in this run (a duplicate id is never used).
    - sourceCallId is a successful INVESTIGATE/investigator model.call whose terminal_payload (the
      plain output, or the final Turn envelope's output) is a valid InvestigatorOutput with an entry
      `index` such that hypothesis_id(specialist, index, claim, path, line) == Finding.id, and the
      Finding's PROPOSAL_FIELDS equal that entry.
    - Every verification callId is a successful VERIFY/verifier model.call logged after the source
      call, whose request.hypothesisId is Finding.id, which is not a repair of the source call, and
      whose terminal_payload is a valid VerifierOutput with verdict 'confirmed' and the Finding's
      severityBasis. A call and its retries/repairs (same agent and ordinal, the same repair chain
      or the same Turn chain) count once.
    - Repairs: each repairOf link joins consecutive attempts of one logical call (stage, role,
      agentId, ordinal; attempt + 1), and every repaired predecessor is logged once and unusable
      (FRR1, FRR2). A Turn call must sit on a valid chain (_chain_issues), which applies the repair
      rule to every attempt of every hop, not only the listed call; the hypothesisId binds every hop
      of a verifier chain.
    - Finding.evidence is materialized from the proposal's citations and verification.evidence
      from the confirming calls' citations. Evidence carrying a toolCallId (any non-code kind, and
      code read through a tool-ref, D2) names a tool.call logged once with a usable status, is an
      item of that call's result within the citation's index/first-20 slice, and the call is
      citable by the citing model call (citable_tool_calls) and logged before it (FRR3). Code
      evidence without toolCallId equals a code citation.

    Event ids are payload-bound (validate TraceEvent), so a relabelled stage, role or request
    cannot reuse another call's id. This detects inconsistency, not a consistently rewritten
    trace (trace authenticity is the gateway's job), and it does not re-resolve citations
    against the snapshot (the pipeline must use snapshot.snapshot_resolver)."""
    out = [Issue(f"$finding{x.path[1:]}", x.code, x.message) for x in validate("Finding", finding)]
    if out:
        return out
    idx = _Index(events, finding["runId"])
    calls, tools, logged = idx.calls, idx.tools, idx.logged

    def issue(path: str, message: str) -> None:
        out.append(Issue(path, "provenance", message))

    def ok_call(cid: str, stage: str, role: str, path: str) -> dict | None:
        ev = calls.get(cid)
        if logged.get(cid, 0) > 1:
            issue(path, f"{cid} is logged more than once in this run")
            return None
        if ev is None:
            issue(path, f"{cid} is not a logged model call of this run")
            return None
        if (ev["stage"], ev["role"]) != (stage, role):
            issue(path, f"{cid} is a {ev['stage']}/{ev['role']} call, not {stage}/{role}")
            return None
        if ev["response"] is None or ev["response"]["status"] != "ok":
            issue(path, f"{cid} did not return a usable response")
            return None
        # A Turn call's repair links (every hop, every attempt) are part of _chain_issues.
        for a in _repair_chain(cid, calls)[:-1] if "hop" not in ev["request"] else ():
            for _, m in _repair_link_issues(calls[a], idx):
                issue(path, m)
            if idx.call(calls[a]["repairOf"]) is None:
                break
        for m in _chain_issues(ev, idx):
            issue(path, f"retrieval chain: {m}")
        return ev

    src = finding["sourceCallId"]
    src_ev = ok_call(src, "INVESTIGATE", "investigator", "$finding.sourceCallId")
    proposal = None
    if src_ev is not None:
        output = terminal_payload(src_ev)
        if output is None:
            issue("$finding.sourceCallId", "source call output is not a valid InvestigatorOutput"
                  + (" final Turn" if "hop" in src_ev["request"] else ""))
        else:
            proposal = next((h for n, h in enumerate(output["hypotheses"]) if hypothesis_id(
                finding["specialist"], n, h["claim"], h["location"]["path"],
                h["location"]["line"]) == finding["id"]), None)
            if proposal is None:
                issue("$finding.id", "the source call proposed no hypothesis with this id")
            for k in PROPOSAL_FIELDS if proposal is not None else ():
                if finding[k] != proposal[k]:
                    issue(f"$finding.{k}", "differs from the proposal in the source call output")

    confirmed: list | None = None
    counted: set = set()
    for i, cid in enumerate(finding["verification"]["callIds"]):
        path = f"$finding.verification.callIds[{i}]"
        ev = ok_call(cid, "VERIFY", "verifier", path)
        if ev is None:
            continue
        if src_ev is not None and ev["seq"] <= src_ev["seq"]:
            issue(path, "verifier call is logged before the source call")
        if ev["request"].get("hypothesisId") != finding["id"]:
            issue(path, "verifier request does not name this hypothesis (request.hypothesisId)")
        chain = _repair_chain(cid, calls)
        if src in chain:
            issue(path, "verifier call is a repair of the source call")
        logical = {("call", ev["agentId"], ev["ordinal"]), ("chain", chain[-1]),
                   ("turn", _hops(ev, idx)[0][0]["callId"])}
        if logical & counted:
            issue(path, "repeats a listed verification (same logical call or its repair)")
        counted |= logical
        output = terminal_payload(ev)
        if output is None or output.get("verdict") != "confirmed":
            issue(path, "verifier call did not confirm")
            continue
        if {"impact": output["impact"], "reachable": output["reachable"]} != finding["severityBasis"]:
            issue(path, "severityBasis differs from this verifier call's impact/reachable")
        confirmed = (confirmed or []) + [(output["evidence"], ev)]

    for side, evs, cited, who in (
            ("evidence", finding["evidence"],
             proposal and [(proposal["evidence"], src_ev)], "the proposal"),
            ("verification.evidence", finding["verification"]["evidence"], confirmed,
             "a confirming verifier call")):
        for i, e in enumerate(evs):
            path = f"$finding.{side}[{i}]"
            tid = e.get("toolCallId")
            if tid is not None:
                tc = tools.get(tid)
                if logged.get(tid, 0) > 1:
                    issue(path, "names a tool call logged more than once in this run")
                    continue
                if tc is None:
                    issue(path, "names a tool call not logged in this run")
                    continue
                if tc["result"]["status"] not in TRUSTED_TOOL_STATUSES:
                    issue(path, f"names a tool call whose result is {tc['result']['status']}")
                    continue
                if e not in tc["result"]["evidence"]:
                    issue(path, "is not an item of the named tool call's result")
                    continue
            why = _cited(e, cited, idx) if cited is not None else None
            if why is not None:
                issue(path, f"{why} {who}")
    return out


VerificationRecord = define("VerificationRecord", Obj(
    required={"hypothesisId": Id("hyp"),
              "verdict": Enum("confirmed", "refuted", "uncertain", "failed"),
              "evidence": Arr(Evidence, max_items=50), "callIds": Arr(Id("call"), max_items=10)},
    optional={"error": TypedError, "notes": Str(max_len=4000)},
    invariants=[Invariant("failed-has-error", "verdict failed carries a TypedError",
                          lambda d: [(".error", "missing")]
                          if d["verdict"] == "failed" and "error" not in d else []),
                no_secrets("VerificationRecord")],
))

DROP_REASONS = ("refuted", "uncertain", "verifier-failed", "invalid-citation", "merged",
                "ignored-by-config", "suppressed", "below-threshold", "over-cap",
                "already-posted", "deadline", "budget", "cancelled")

DropRecord = define("DropRecord", Obj(
    required={"subjectIds": Arr(Id("hyp"), min_items=1, max_items=100, unique=True),
              "stage": Enum("VERIFY", "JUDGE"), "reason": Enum(*DROP_REASONS)},
    optional={"detail": Str(max_len=2000)},
    invariants=[no_secrets("DropRecord")],
))

# ---------------------------------------------------------------- comments


def _comment_ok(d):
    posted_fields = ("postedAt" in d, "hostCommentId" in d)
    if d["state"] == "draft" and any(posted_fields):
        yield "", "draft comments carry no postedAt/hostCommentId"
    if d["state"] == "posted" and not all(posted_fields):
        yield "", "posted comments need postedAt and hostCommentId"
    a = d["anchor"]
    if a["endLine"] < a["startLine"]:
        yield ".anchor", "endLine before startLine"
    if d["id"] != comment_id(d["fingerprint"]):
        yield ".id", "must equal comment_id(fingerprint)"
    if RANK[d["severity"]] < RANK[d["severityCeiling"]]:
        yield ".severity", "exceeds the rubric ceiling"
    if RANK[d["severity"]] < RANK[d["proposedSeverity"]] and "severityReason" not in d:
        yield ".severityReason", "promotion above the proposed severity needs a reason"


Comment = define("Comment", Obj(
    required={"id": Id("cmt"), "runId": Id("run"),
              "findingIds": Arr(Id("hyp"), min_items=1, max_items=50, unique=True),
              "severity": Severity, "proposedSeverity": Severity, "severityCeiling": Severity,
              "evidenceStrength": Strength, "category": Category,
              "anchor": Obj(required={"path": RelPath(), "startLine": Line, "endLine": Line,
                                      "snapshotId": SnapshotId}),
              "title": Str(min_len=1, max_len=200), "body": Str(min_len=1, max_len=4000),
              "evidence": Arr(Evidence, min_items=1, max_items=50),
              "qualityScore": Nullable(Num(0, 1)), "fingerprint": Fingerprint,
              "state": Enum("draft", "posted", "resolved", "retracted", "superseded")},
    optional={"suggestion": Str(max_len=8000), "supersedes": Id("cmt"),
              "severityReason": Str(min_len=1, max_len=1000), "postedAt": Timestamp,
              "hostCommentId": Str(min_len=1, max_len=200)},
    invariants=[Invariant("comment-state", "state fields, anchor, id derivation, severity bounds",
                          _comment_ok), no_secrets("Comment")],
    description="Local/eval PUBLISH writes state=draft (read-only reviews never post). "
                "severity <= severityCeiling; proposedSeverity vs severity shows any cap. "
                "suggestion is explanatory text for the author; it is never applied. "
                "qualityScore null = not scored (no quality model in Stage 0A).",
))

# ---------------------------------------------------------------- plan, profile, run


def _budget_ok(d):
    if d["softDeadlineSec"] > d["wallClockSec"]:
        yield ".softDeadlineSec", "after hard deadline"
    if d["maxToolCallsPerAgent"] > d["maxToolCalls"]:
        yield ".maxToolCallsPerAgent", "exceeds run total"


_SYNC_STAGES = tuple(st for st, sec in STAGE_CEILING_SEC.items() if sec is not None)


def _ceilings_ok(d):
    ceil = d.get("stageCeilingsSec")
    if ceil is not None:
        if not ceil:
            yield ".stageCeilingsSec", "must name at least one stage (omit the key for the legacy ceilings)"
        for st, sec in ceil.items():
            if sec > d["wallClockSec"]:
                yield f".stageCeilingsSec.{st}", "exceeds the hard run deadline (wallClockSec)"


Budget = define("Budget", Obj(
    required={"maxUsdMicros": Int(1, 10**9), "maxToolCalls": Int(0, 10_000),
              "maxToolCallsPerAgent": Int(0, 10_000),
              "maxToolOutputTokensPerAgent": Int(0, 10**8),
              "wallClockSec": Int(1, 86_400), "softDeadlineSec": Int(1, 86_400),
              "verifyReserveBp": Int(0, 10000), "maxRetriesPerCall": Int(0, 3)},
    optional={"stageCeilingsSec": Obj(required={}, optional={st: Int(1, 86_400) for st in _SYNC_STAGES},
                                      description="Optional per-stage ceilings in seconds (synchronous stages "
                                                  "only; LEARN is async). A listed stage replaces its legacy "
                                                  "table ceiling, an unlisted one keeps it; absent = legacy."),
              "hostStopRecording": Enum(*HOST_STOP_RECORDING_VERSIONS)},
    invariants=[Invariant("budget-order", "soft <= hard deadline; per-agent <= total", _budget_ok),
                Invariant("stage-ceilings", "stageCeilingsSec is non-empty and each ceiling <= wallClockSec",
                          _ceilings_ok)],
    description="Hard caps (run ceiling <= $1000). Admission rules in budget.py; calls that "
                "would exceed are refused. Effective retries = min(maxRetriesPerCall, role "
                "caps.maxRetries); repairs <= 1; each is a new admission.",
))

Plan = define("Plan", Obj(
    required={"version": Int(1, 100), "tier": Tier,
              "specialists": Arr(Slug, min_items=1, max_items=50, unique=True),
              "budget": Budget, "modelProfile": ProfileRef, "triage": Str(min_len=1, max_len=64),
              "reasons": Arr(Str(max_len=500), max_items=50)},
    optional={"authorFamily": Str(max_len=64)},
    description="Stage 0A: version 1, tier standard, triage 'fixed-rule@1' (no TRIAGE LLM).",
))

DEV_ONLY_MODELS = frozenset({"gpt-6.1-sol", "claude-opus-5-5"})
PROVIDERS = ("anthropic", "openai", "synthetic")

Price = Obj(required={"priceVersion": Str(min_len=1, max_len=64),
                      "inputPerMTokUsdMicros": UsdMicros,
                      "cachedInputPerMTokUsdMicros": UsdMicros,
                      "cacheWriteInputPerMTokUsdMicros": UsdMicros,
                      "outputPerMTokUsdMicros": UsdMicros})


def _role_ok(d):
    m = d["model"]
    if "latest" in m:
        yield ".model", "aliases are not pinned"
    if m in DEV_ONLY_MODELS:
        yield ".model", "development-only model may not be a runtime role"
    if (d["provider"] == "synthetic") != (d["family"] == "synthetic"):
        yield ".family", "synthetic provider <=> synthetic family"
    if d["resolved"] and d["price"] is None:
        yield ".price", "a resolved model needs a price version"


RoleSpec = Obj(
    required={"provider": Enum(*PROVIDERS), "model": Str(min_len=1, max_len=128),
              "family": Str(min_len=1, max_len=64), "resolved": Bool(),
              "promptVersion": PromptVersion,
              "outputSchema": Enum(*OUTPUT_SCHEMAS),
              "params": Json(),
              "caps": Obj(required={"maxOutputTokens": Int(1, 1_000_000),
                                    "timeoutSec": Int(1, 3600),
                                    "maxRetries": Int(0, 3), "maxRepairs": Int(0, 1)}),
              "price": Nullable(Price),
              "fallbacks": Arr(ProfileRef, max_items=0)},
    invariants=[Invariant("role-pinning", "pinned, runtime-eligible, priced", _role_ok)],
    description="resolved=false (e.g. exact Terra id pending) blocks live use. No fallbacks in "
                "Stage 0A: an unapproved fallback is a typed failure.",
)

ModelProfile = define("ModelProfile", Obj(
    required={"id": Slug, "version": Int(1, 999_999), "tier": Tier,
              "triage": Str(min_len=1, max_len=64),
              "roles": Obj(required={"investigator": RoleSpec, "verifier": RoleSpec,
                                     "judge": RoleSpec})},
    invariants=[Invariant("role-schema", "each role returns its own plain or Turn schema",
                          lambda d: [(f".roles.{r}.outputSchema", f"a {r} role returns one of "
                                      f"{list(ROLE_SCHEMAS[r])}")
                                     for r, s in d["roles"].items()
                                     if s["outputSchema"] not in ROLE_SCHEMAS[r]])],
    description="Immutable; a change is a new version. Referenced as '<id>@<version>'. A "
                "retrieval profile sets investigator/verifier outputSchema to the Turn schema.",
))


def _auth_ok(d):
    if d["maxUsdMicrosPerRun"] > d["maxUsdMicrosTotal"]:
        yield ".maxUsdMicrosPerRun", "exceeds total"
    for i, m in enumerate(d["models"]):
        if m in DEV_ONLY_MODELS:
            yield f".models[{i}]", "development-only model"


SpendAuthorization = define("SpendAuthorization", Obj(
    required={"schema": Const("spend-authorization@1"), "id": Slug,
              "issuedBy": Const("operator"),
              "providers": Arr(Enum(*PROVIDERS), min_items=1, unique=True),
              "models": Arr(Str(min_len=1, max_len=128), min_items=1, max_items=20, unique=True),
              "maxUsdMicrosPerRun": Int(0, 10**9), "maxUsdMicrosTotal": Int(0, 10**12),
              "expiresAt": Timestamp, "purpose": Str(min_len=1, max_len=500)},
    invariants=[Invariant("auth-bounds", "per-run <= total; runtime models only", _auth_ok)],
    description="Trusted, operator-issued, loaded by the gateway from out-of-band config. Never "
                "read from repo, case, PR or model content. ReviewRun.spendAuthorization is its "
                "digest; budget.check_spend_authorization binds it to profile and Plan.",
))

Incomplete = Obj(required={"stage": Stage, "reason": Enum(*INCOMPLETE_REASONS)},
                 optional={"detail": Str(max_len=2000)})


def _run_ok(d):
    pr = "prNumber" in d or "headSha" in d
    if d["source"] == "pull_request":
        if not ("prNumber" in d and "headSha" in d):
            yield "", "pull_request runs need prNumber and headSha"
        if not GITHUB_REPO.fullmatch(d["repo"]):
            yield ".repo", "pull_request runs use a GitHub Owner/Name repo id"
    if d["source"] == "local" and pr:
        yield "", "local runs carry no prNumber/headSha; use snapshot ids"
    if (d["attempt"] > 1) != ("rerunOf" in d):
        yield ".rerunOf", "required exactly when attempt > 1"
    if d["attempt"] > 1 and d["trigger"] != "manual-rerun":
        yield ".trigger", "attempt > 1 only via manual-rerun"
    is_eval = d["trigger"] == "eval"
    if is_eval != ("evalRunId" in d and "evalCaseId" in d and "repeat" in d):
        yield "", "eval trigger <=> evalRunId, evalCaseId and repeat"
    if d["mode"] in OFFLINE_MODES and "replayOf" not in d:
        yield ".replayOf", "replay modes name the recorded run"
    if (d["mode"] == "stage-replay") != ("fromStage" in d):
        yield ".fromStage", "required exactly for stage-replay"
    if d["mode"] in LIVE_MODES and "spendAuthorization" not in d:
        yield ".spendAuthorization", "live modes require a trusted SpendAuthorization digest"
    if d["mode"] in OFFLINE_MODES and "spendAuthorization" in d:
        yield ".spendAuthorization", "offline modes never carry spend authorization"
    st = d["status"]
    if st == "partial" and not d["incomplete"]:
        yield ".incomplete", "partial runs explain what did not finish"
    if st == "failed" and "error" not in d:
        yield ".error", "failed runs carry a TypedError"
    if st == "completed" and (d["incomplete"] or "error" in d):
        yield ".status", "completed runs carry no incomplete[] or error"
    if st in ("queued", "running") and ("error" in d or "endedAt" in d):
        yield ".status", "non-terminal runs carry no error/endedAt"


def _run_identity(d):
    key, attempt = d["idempotencyKey"], d["attempt"]
    want = None
    if d["trigger"] == "eval":
        if all(k in d for k in ("evalRunId", "evalCaseId", "repeat")):
            want = idempotency_key_eval(d["evalRunId"], d["evalCaseId"], d["repeat"],
                                        d["baseSnapshotId"], d["headSnapshotId"])
    elif d["source"] == "pull_request":
        if "prNumber" in d and "headSha" in d:
            want = idempotency_key_pr(d["repo"], d["prNumber"], d["headSha"])
    else:
        want = idempotency_key_local(d["repo"], d["baseSnapshotId"], d["headSnapshotId"])
    if want is not None and key != want:
        yield ".idempotencyKey", "does not match the key recomputed from this run's fields"
    if d["id"] != run_id(key, attempt):
        yield ".id", "must equal run_id(idempotencyKey, attempt)"
    if attempt > 1 and d.get("rerunOf") != run_id(key, attempt - 1):
        yield ".rerunOf", "must equal run_id(idempotencyKey, attempt - 1)"


ReviewRun = define("ReviewRun", Obj(
    required={"id": Id("run"), "idempotencyKey": IdemKey, "attempt": Int(1, 1000),
              "trigger": Enum(*TRIGGERS), "source": Enum("pull_request", "local"),
              "mode": Enum(*RUN_MODES), "access": Const(ACCESS_POLICY), "repo": RepoId,
              "baseSnapshotId": SnapshotId, "headSnapshotId": SnapshotId, "profile": ProfileRef,
              "planVersion": Int(0, 100), "configSnapshotId": Digest,
              "status": Enum(*RUN_STATUSES), "incomplete": Arr(Incomplete, max_items=50)},
    optional={"prNumber": Int(1, 10**9), "headSha": GitSha, "rerunOf": Id("run"),
              "evalRunId": Id("evr"), "evalCaseId": Slug, "repeat": Int(0, 1000),
              "replayOf": Id("run"), "fromStage": Enum(*REPLAYABLE_FROM),
              "spendAuthorization": Digest, "error": TypedError,
              "startedAt": Timestamp, "endedAt": Timestamp},
    invariants=[Invariant("run-rules", "source, rerun, eval, replay, auth and status rules", _run_ok),
                Invariant("run-identity", "id, key and rerunOf recompute from the run's fields",
                          _run_identity)],
    description="id = run_id(idempotencyKey, attempt). Duplicate host events return the existing "
                "run; resume keeps the id; manual rerun = same key, attempt+1. access is always "
                "read-only: no target writes, no target execution, no posting.",
))

# ---------------------------------------------------------------- tools, model calls, cost

ToolResult = define("ToolResult", Obj(
    required={"status": Enum("ok", "partial", "empty", "error", "denied", "unavailable"),
              "evidence": Arr(Evidence, max_items=500), "completeness": Enum("exact", "approximate"),
              "truncated": Nullable(Obj(required={"shown": Count, "total": Count})),
              "notice": Str(max_len=2000)},
    invariants=[Invariant("denied-silent", "denied returns no evidence (no existence hint)",
                          lambda d: [(".evidence", "must be empty")]
                          if d["status"] == "denied" and d["evidence"] else []),
                no_secrets("ToolResult")],
))

Message = Obj(required={"role": Enum("system", "user", "assistant", "tool"),
                        "content": Str(max_len=2_000_000)})

def _request_turn_ok(d):
    turn = d["outputSchema"] in TURN_PAYLOAD
    if turn != ("hop" in d):
        yield ".hop", "present exactly on Turn (retrieval) requests"
    if "contextResults" in d and not turn:
        yield ".contextResults", "only Turn requests list the tool results they show"
    hop = d.get("hop", 0)
    if (hop > 0) != ("continuationOf" in d):
        yield ".continuationOf", "present exactly when hop > 0"
    if hop > 0 and "contextResults" not in d:
        yield ".contextResults", "a continuation shows the previous hop's requested results"


ModelRequest = define("ModelRequest", Obj(
    required={"provider": Enum(*PROVIDERS), "model": Str(min_len=1, max_len=128),
              "profile": ProfileRef, "role": Enum(*ROLE_OUTPUT),
              "promptVersion": PromptVersion,
              "outputSchema": Enum(*OUTPUT_SCHEMAS),
              "params": Json(), "messages": Arr(Message, min_items=1, max_items=1000),
              "tools": Arr(Json(), max_items=100)},
    optional={"hypothesisId": Id("hyp"), "hop": Int(0, MAX_HOP), "continuationOf": Id("call"),
              "contextResults": Arr(Id("tool"), max_items=200)},
    invariants=[Invariant("request-subject", "hypothesisId only on verifier requests",
                          lambda d: [(".hypothesisId", "only a verifier request names a hypothesis")]
                          if "hypothesisId" in d and d["role"] != "verifier" else []),
                Invariant("request-turn", "hop iff Turn schema; continuationOf iff hop > 0; "
                          "contextResults only on Turn requests, required when hop > 0",
                          _request_turn_ok),
                no_secrets("ModelRequest")],
    description="Redacted before hashing; requestHash = canonical.request_hash(request). Closed and "
                "typed: no field carries a run/eval id or timestamp, and prompt text is built from "
                "content-addressed inputs only (D6: host metadata is kept out by construction, a "
                "leak makes strict replay miss; repository text is never filtered). "
                "hypothesisId names the hypothesis a verifier request checks; a verifier call "
                "without it cannot confirm a Finding. Turn requests carry hop (0..15), "
                "continuationOf (callId of the previous hop's accepted attempt, hop > 0) and "
                "contextResults (toolCallIds shown, in order: host-prepared context at hop 0, one "
                "per previous-hop contextRequest after). All are covered by requestHash; "
                "check_turn_trace states the chain rules. Legacy requests omit them.",
))


def _response_ok(d):
    if d["status"] == "ok" and d["output"] is None:
        yield ".output", "ok responses carry parsed output"


ModelResponse = define("ModelResponse", Obj(
    required={"status": Enum("ok", "invalid-output"), "resolvedModel": Str(min_len=1, max_len=128),
              "output": Nullable(Json()), "rawText": Nullable(Str(max_len=2_000_000)),
              "usage": Usage},
    optional={"providerRequestId": Str(max_len=200)},
    invariants=[Invariant("ok-has-output", "ok => output", _response_ok),
                no_secrets("ModelResponse")],
))


def _cost_ok(d):
    k = d["kind"]
    if k == "score":
        # score family (scoring_family.py): attribution is by call and role; the review Stage enum is not used
        from .scoring_family import SCORE_ROLES
        missing = [x for x in ("runId", "evalRunId", "evalCaseId", "callId") if x not in d]
        if missing:
            yield "", "score costs carry runId, evalRunId, evalCaseId and callId"
        if "stage" in d:
            yield ".stage", "score costs omit stage (a review Stage); the score model call names role and stage"
        if "toolCallId" in d:
            yield ".toolCallId", "a score cost covers a model call"
        if d.get("role") not in SCORE_ROLES:
            yield ".role", f"a score cost names one of {list(SCORE_ROLES)}"
        if "retryOf" in d:
            yield ".retryOf", "score calls are never retried"
        if "callId" in d and d["id"] != cost_id(d["callId"]):
            yield ".id", "must equal cost_id(callId)"
    if k in ("review", "chat") and "runId" not in d:
        yield ".runId", f"{k} costs attach to a ReviewRun"
    if k == "eval" and not all(x in d for x in ("runId", "evalRunId", "evalCaseId")):
        yield "", "eval costs carry runId, evalRunId and evalCaseId"
    if k == "index" and "runId" in d:
        yield ".runId", "index builds have no ReviewRun"
    b = d["basis"]
    if b == "measured" and (d["usdMicros"] is None or d["priceVersion"] is None):
        yield ".usdMicros", "measured cost needs usd and priceVersion"
    if b == "unknown" and d["usdMicros"] is not None:
        yield ".usdMicros", "unknown cost must be null"
    if b == "replayed" and "replayOf" not in d:
        yield ".replayOf", "replayed cost names the recorded CostRecord"
    if b == "synthetic" and d.get("provider") not in (None, "synthetic"):
        yield ".provider", "synthetic basis only for the synthetic provider"
    subjects = [d[x] for x in ("callId", "toolCallId") if x in d]
    if k == "score":
        return
    if len(subjects) > 1:
        yield "", "a CostRecord covers one call"
    elif subjects and d["id"] != cost_id(subjects[0]):
        yield ".id", "must equal cost_id(callId or toolCallId)"
    elif not subjects and k != "index":
        yield "", "review/chat/eval costs name their callId or toolCallId"


CostRecord = define("CostRecord", Obj(
    required={"id": Id("cost"), "kind": Enum("review", "chat", "index", "eval", "score"),
              "basis": Enum("measured", "estimated", "unknown", "replayed", "synthetic"),
              "usage": Usage, "usdMicros": Nullable(UsdMicros),
              "reservedUsdMicros": UsdMicros, "priceVersion": Nullable(Str(min_len=1, max_len=64))},
    optional={"runId": Id("run"), "evalRunId": Id("evr"), "evalCaseId": Slug,
              "stage": Stage, "role": Str(min_len=1, max_len=32), "callId": Id("call"),
              "toolCallId": Id("tool"), "provider": Str(min_len=1, max_len=32),
              "model": Str(min_len=1, max_len=128), "toolMs": Nullable(Int(0, 10**9)),
              "retryOf": Id("call"), "replayOf": Id("cost"), "overrun": Bool()},
    invariants=[Invariant("cost-attribution", "kind/basis attribution and id derivation", _cost_ok)],
    description="Eval executions are ReviewRuns booked as kind=eval (amends 14). Replayed records "
                "repeat recorded values and are never summed as new spend. Ids are unique per "
                "run only; aggregate by (runId, id). overrun=true when actual > reservation.",
))

# ---------------------------------------------------------------- trace

_ev_base = {"schema": Const("trace-event@1"), "runId": Id("run"), "seq": Int(0, 10**9)}
_ev_opt = {"at": Timestamp}
Redactions = Json().describe("map patternId -> count applied before persistence")


def _event(type_: str, required: dict, optional: dict | None = None, invariants=None) -> Obj:
    return Obj(required={**_ev_base, "type": Const(type_), **required},
               optional={**_ev_opt, **(optional or {})},
               invariants=[*(invariants or []), no_secrets("TraceEvent")])


def _model_call_ok(d):
    if (d["response"] is None) == ("error" not in d):
        yield "", "exactly one of response or error"
    if d["callId"] != call_id(d["stage"], d["role"], d["agentId"], d["ordinal"], d["attempt"]):
        yield ".callId", "must equal call_id(stage, role, agentId, ordinal, attempt)"
    try:
        if d["requestHash"] != request_hash(d["request"]):
            yield ".requestHash", "must equal request_hash(request)"
    except ValueError as e:
        yield ".request", f"not hashable for replay: {str(e)[:120]}"
    if d["costRecordId"] != cost_id(d["callId"]):
        yield ".costRecordId", "must equal cost_id(callId)"
    if d["request"]["role"] != d["role"]:
        yield ".request.role", "must equal the event role"
    if d["request"]["outputSchema"] not in ROLE_SCHEMAS[d["role"]]:
        yield ".request.outputSchema", (f"a {d['role']} call requests one of "
                                        f"{list(ROLE_SCHEMAS[d['role']])}")


def _tool_call_ok(d):
    if ("requestedBy" in d) != ("requestIndex" in d):
        yield ".requestedBy", "requestedBy and requestIndex come together"
    if d["toolCallId"] != tool_call_id(d["stage"], d["agentId"], d["ordinal"], d["tool"], d["args"]):
        yield ".toolCallId", "must equal tool_call_id(stage, agentId, ordinal, tool, args)"
    if d["resultHash"] != digest(d["result"]):
        yield ".resultHash", "must equal result_hash(result)"
    if "costRecordId" in d and d["costRecordId"] != cost_id(d["toolCallId"]):
        yield ".costRecordId", "must equal cost_id(toolCallId)"


def _review_cost_event_ok(d):
    if d["record"]["kind"] == "score":
        yield ".record.kind", "a review trace carries no score cost"


HOST_STOP_SCOPES = ("tool", "retrieval", "new-agent", "model")
HOST_STOP_CODES = ("cancelled", "hard-deadline", "stage-deadline", "soft-deadline")


def _host_stop_ok(d):
    if d["afterSeq"] != d["seq"] - 1:
        yield ".afterSeq", "must equal seq - 1"


EXPLORATION_FLOOR_VERSION = "exploration-floor@1"
FLOOR_DECISIONS = ("skipped", "continue", "final", "draft")
FLOOR_SKIP_REASONS = ("turns", "tool-calls", "context-chars")
FLOOR_DRAFT_REASONS = FLOOR_SKIP_REASONS + ("stopped", "call-failed")


def _floor_ok(d):
    dec = d["decision"]
    if ("finalCallId" in d) != (dec == "final"):
        yield ".finalCallId", "present exactly when decision is final"
    if ("reason" in d) != (dec in ("skipped", "draft")):
        yield ".reason", "present exactly when decision is skipped or draft"
    elif dec == "skipped" and d["reason"] not in FLOOR_SKIP_REASONS:
        yield ".reason", f"a skipped floor names one of {list(FLOOR_SKIP_REASONS)}"
    if ("errorCode" in d) != (d.get("reason") in ("stopped", "call-failed")):
        yield ".errorCode", "present exactly when the draft was used because of a stop or a failed call"
    if d.get("finalCallId") == d["draftCallId"]:
        yield ".finalCallId", "the accepted final answer is not the draft"


TraceEvent = define("TraceEvent", Union("type", {
    "run.start": _event("run.start", {"run": ReviewRun}),
    "stage.start": _event("stage.start", {"stage": Stage}),
    "stage.end": _event("stage.end", {"stage": Stage, "status": Enum(*STAGE_STATUSES)},
                        {"artifactDigest": Digest, "error": TypedError}),
    "model.call": _event("model.call", {
        "callId": Id("call"), "stage": Stage, "role": Enum("investigator", "verifier", "judge"),
        "agentId": Slug, "ordinal": Int(0, 10**6), "attempt": Int(0, 10),
        "requestHash": Digest, "request": ModelRequest, "response": Nullable(ModelResponse),
        "costRecordId": Id("cost"), "redactions": Redactions},
        {"repairOf": Id("call"), "error": TypedError, "latencyMs": Int(0, 10**9)},
        [Invariant("call-outcome", "response xor error; callId, requestHash and costRecordId "
                   "recompute from the payload; request role and outputSchema match the event "
                   "role", _model_call_ok)]),
    "tool.call": _event("tool.call", {
        "toolCallId": Id("tool"), "stage": Stage, "agentId": Slug, "ordinal": Int(0, 10**6),
        "tool": Slug, "args": Json(), "resultHash": Digest, "result": ToolResult,
        "redactions": Redactions},
        {"costRecordId": Id("cost"), "latencyMs": Int(0, 10**9), "requestedBy": Id("call"),
         "requestIndex": Int(0, MAX_TURN_REQUESTS - 1)},
        [Invariant("tool-identity", "toolCallId, resultHash and costRecordId recompute from the "
                   "payload; requestedBy and requestIndex come together", _tool_call_ok)]),
    "cost": _event("cost", {"record": CostRecord},
                   invariants=[Invariant("review-cost-kind", "a review trace carries no score cost (kind=score "
                                         "belongs to the score family)", _review_cost_event_ok)]),
    "host.stop": _event("host.stop", {
        "stage": Stage, "scope": Enum(*HOST_STOP_SCOPES), "code": Enum(*HOST_STOP_CODES),
        "afterSeq": Int(0, 10**9)},
        {"gateOrdinal": Int(1, 10**9)},
        [Invariant("stop-position", "afterSeq is the seq of the event immediately before the "
                              "decision; gateOrdinal (host-stop@2) is the 1-based count of this stage's gate checks "
                              "including this one", _host_stop_ok)]),
    "retrieval.floor": _event("retrieval.floor", {
        "stage": Enum("INVESTIGATE"), "agentId": Slug, "version": Const(EXPLORATION_FLOOR_VERSION),
        "draftCallId": Id("call"), "decision": Enum(*FLOOR_DECISIONS)},
        {"finalCallId": Id("call"), "reason": Enum(*FLOOR_DRAFT_REASONS), "errorCode": Enum(*ERROR_CODES)},
        [Invariant("floor-decision", "investigator.impact@v2 exploration floor: draftCallId is the agent's first "
                   "final answer, given before any context request. skipped (+reason: no turn/tool/context budget "
                   "left, the draft is final), continue (the host sent its one continuation), final (+finalCallId: "
                   "the continuation's final answer is used), draft (+reason, +errorCode for stopped/call-failed: "
                   "the continuation ended without a final answer and the draft is used)", _floor_ok)]),
    "checkpoint": _event("checkpoint", {"stage": Stage, "planVersion": Int(0, 100),
                                        "artifactDigest": Digest}),
    "error": _event("error", {"error": TypedError}),
    "run.end": _event("run.end", {"status": Enum(*RUN_STATUSES),
                                  "incomplete": Arr(Incomplete, max_items=50)}),
}).describe("One JSON object per line in trace.jsonl. Whole-file rules: entities.validate_trace."))


def validate_trace(events: list) -> list[Issue]:
    """Per-event validation (including payload hash/id recomputation) plus file rules: seq
    0,1,2..., one runId, run.start first (naming the same run), run.end only last, each call id
    logged once, cost records in the file naming the call that references them, and the causal
    rules of retrieval chains (check_turn_trace)."""
    if not isinstance(events, list) or not events:
        return [Issue("$", "trace-empty", "a trace has at least a run.start event")]
    out: list[Issue] = []
    for i, ev in enumerate(events):
        out.extend(Issue(f"[{i}]{x.path[1:]}", x.code, x.message) for x in validate("TraceEvent", ev))
    if out:
        return out
    rid = events[0]["runId"]
    if events[0]["type"] != "run.start" or events[0]["run"]["id"] != rid:
        out.append(Issue("[0]", "trace-order", "first event is run.start for this runId"))
    for i, ev in enumerate(events):
        if ev["seq"] != i:
            out.append(Issue(f"[{i}].seq", "trace-seq", f"expected {i}, got {ev['seq']}"))
        if ev["runId"] != rid:
            out.append(Issue(f"[{i}].runId", "trace-run", "events from more than one run"))
        if ev["type"] == "run.end" and i != len(events) - 1:
            out.append(Issue(f"[{i}]", "trace-order", "run.end must be the last event"))
    seen: set[str] = set()
    costs = {ev["record"]["id"]: ev["record"] for ev in events if ev["type"] == "cost"}
    for i, ev in enumerate(events):
        cid = ev.get("callId") or ev.get("toolCallId")
        if cid is None:
            continue
        if cid in seen:
            out.append(Issue(f"[{i}]", "trace-duplicate", f"{cid} logged twice"))
        seen.add(cid)
        rec = costs.get(ev.get("costRecordId"))
        if rec is not None and rec.get("callId", rec.get("toolCallId")) != cid:
            out.append(Issue(f"[{i}].costRecordId", "trace-cost", "cost record names another call"))
    return out + check_turn_trace(events)

# ---------------------------------------------------------------- stage artifacts

DiffFile = Obj(required={"path": RelPath(), "status": Enum("added", "modified", "deleted",
                                                           "renamed"),
                         "additions": Count, "deletions": Count},
               optional={"oldPath": RelPath()})
AgentStatus = Obj(required={"agentId": Slug, "specialist": Slug,
                            "status": Enum("completed", "failed", "timeout", "cancelled",
                                           "budget")},
                  optional={"error": TypedError})


def _payload(stage: str, required: dict, optional: dict | None = None) -> Obj:
    return Obj(required={"stage": Const(stage), **required}, optional=optional or {})


StagePayload = define("StagePayload", Union("stage", {
    "INGEST": _payload("INGEST", {"run": ReviewRun}),
    "PREPARE": _payload("PREPARE", {"baseSnapshotId": SnapshotId, "headSnapshotId": SnapshotId,
                                    "diffDigest": Digest,
                                    "files": Arr(DiffFile, max_items=100_000)}),
    "TRIAGE": _payload("TRIAGE", {"plan": Plan}),
    "INVESTIGATE": _payload("INVESTIGATE", {"hypotheses": Arr(Hypothesis, max_items=1000),
                                            "agents": Arr(AgentStatus, max_items=100)}),
    "VERIFY": _payload("VERIFY", {"findings": Arr(Finding, max_items=1000),
                                  "verifications": Arr(VerificationRecord, max_items=1000),
                                  "drops": Arr(DropRecord, max_items=1000)}),
    "JUDGE": _payload("JUDGE", {"comments": Arr(Comment, max_items=1000),
                                "drops": Arr(DropRecord, max_items=1000)}),
    "PUBLISH": _payload("PUBLISH", {"sink": Enum("local-file"), "path": RelPath(),
                                    "commentIds": Arr(Id("cmt"), max_items=1000, unique=True),
                                    "summary": Str(max_len=8000)}),
    "LEARN": _payload("LEARN", {"enabled": Bool()}),
}).describe("PUBLISH has one sink, local-file: reviews are read-only and never post."))


def _artifact_ok(d):
    if d["payload"]["stage"] != d["stage"]:
        yield ".payload.stage", "must equal artifact stage"
    if d["stage"] == "LEARN" and d["status"] == "skipped" and d["payload"]["enabled"]:
        yield ".payload.enabled", "skipped LEARN is disabled"
    if d["status"] == "failed" and "error" not in d:
        yield ".error", "failed stage carries a TypedError"
    if d["status"] == "partial" and d["stage"] not in ("INVESTIGATE", "VERIFY", "JUDGE"):
        yield ".status", "only INVESTIGATE..JUDGE may be partial"
    if (d["inputDigest"] is None) != (d["stage"] == "INGEST"):
        yield ".inputDigest", "null exactly for INGEST"


StageArtifact = define("StageArtifact", Obj(
    required={"schema": Const("stage-artifact@1"), "runId": Id("run"), "stage": Stage,
              "planVersion": Int(0, 100), "status": Enum(*STAGE_STATUSES),
              "inputDigest": Nullable(Digest), "payload": StagePayload,
              "costRecordIds": Arr(Id("cost"), max_items=10_000, unique=True)},
    optional={"error": TypedError, "incomplete": Arr(Incomplete, max_items=50)},
    invariants=[Invariant("artifact-stage", "payload/status consistency", _artifact_ok),
                no_secrets("StageArtifact")],
    description="inputDigest = canonical.artifact_digest(previous stage artifact); null for "
                "INGEST. A stage reads only the previous artifact, the run and the Plan.",
))

# ---------------------------------------------------------------- eval: suite, case, labels

CaseInput = define("CaseInput", Obj(
    required={"schema": Const("case-input@1"), "id": Slug, "repo": RepoId, "synthetic": Bool(),
              "base": Obj(required={"snapshotId": SnapshotId, "root": RelPath()}),
              "head": Obj(required={"snapshotId": SnapshotId, "root": RelPath()}),
              "pr": Obj(required={"title": Str(max_len=500), "body": Str(max_len=20000)})},
    description="Everything the reviewer may see. Closed object: labels, fix commits and "
                "expectations cannot be added here.",
))


def _labels_ok(d):
    if d["expect"] == "silence" and d["bugs"]:
        yield ".bugs", "silence cases have no labelled bugs"
    if d["expect"] == "findings" and not d["bugs"]:
        yield ".bugs", "findings cases need labelled bugs"
    if d["expect"] in ("partial", "failed") and "expectReason" not in d:
        yield ".expectReason", "partial/failed cases name the expected reason"
    for i, b in enumerate(d["bugs"]):
        if b["lines"][0] > b["lines"][1]:
            yield f".bugs[{i}].lines", "start after end"


CaseLabels = define("CaseLabels", Obj(
    required={"schema": Const("case-labels@1"), "caseId": Slug,
              "expect": Enum("findings", "silence", "partial", "failed"),
              "bugs": Arr(Obj(required={"id": Slug, "path": RelPath(), "lines": Lines,
                                        "category": Category, "severity": Severity},
                              optional={"note": Str(max_len=2000)}), max_items=1000)},
    optional={"expectReason": Enum(*INCOMPLETE_REASONS, *ERROR_CODES)},
    invariants=[Invariant("labels-consistent", "expectation vs bugs", _labels_ok)],
    description="Scorer-only. Must live under the suite's labels/ directory.",
))

Matching = Union("rule", {
    "path-line-overlap@1": Obj(required={"rule": Const("path-line-overlap@1"),
                                         "lineTolerance": Int(0, 20)}),
    "unadjudicated@1": Obj(required={"rule": Const("unadjudicated@1")}),
}).describe("path-line-overlap@1 is SYNTHETIC SMOKE ONLY: it ignores the claim and its grade. "
            "Real PR datasets use unadjudicated@1 until a human-adjudicated rule exists.")


def _suite_ok(d):
    ids = [c["id"] for c in d["cases"]]
    if len(set(ids)) != len(ids):
        yield ".cases", "duplicate case ids"
    for i, c in enumerate(d["cases"]):
        if not c["labels"].startswith("labels/"):
            yield f".cases[{i}].labels", "labels live under labels/"
        if c["input"].split("/")[0] == "labels":
            yield f".cases[{i}].input", "inputs may not live under labels/"
    if d["matching"]["rule"] == "path-line-overlap@1" and not d["synthetic"]:
        yield ".matching", "overlap matching is for synthetic smoke suites only"


SuiteManifest = define("SuiteManifest", Obj(
    required={"schema": Const("suite@1"), "id": Slug, "version": Int(1, 10**6),
              "synthetic": Bool(), "description": Str(max_len=4000), "matching": Matching,
              "cases": Arr(Obj(required={"id": Slug, "input": RelPath(), "labels": RelPath()}),
                           min_items=1, max_items=100_000)},
    invariants=[Invariant("suite-separation", "unique ids; labels/ separation; smoke-only overlap",
                          _suite_ok)],
))

# ---------------------------------------------------------------- eval report


def _ratio_ok(d):
    if d["denominator"] == 0 and d["value"] is not None:
        yield ".value", "null when denominator is 0"
    if (d["value"] is None) != (d["undefinedReason"] is not None):
        yield ".undefinedReason", "present exactly when value is null"
    if d["numerator"] > d["denominator"]:
        yield ".numerator", "exceeds denominator"
    elif d["denominator"] and d["value"] is not None and abs(
            d["value"] - d["numerator"] / d["denominator"]) > 1e-9:
        yield ".value", "does not equal numerator/denominator"


Ratio = define("Ratio", Obj(
    required={"value": Nullable(Num(0, 1)), "numerator": Count, "denominator": Count,
              "undefinedReason": Nullable(Str(min_len=1, max_len=200))},
    invariants=[Invariant("ratio-defined", "undefined/unscored values are null with reason",
                          _ratio_ok)],
))
Derived = Obj(required={"value": Nullable(Num(0, 1)),
                        "undefinedReason": Nullable(Str(min_len=1, max_len=200))},
              invariants=[Invariant("derived-defined", "value xor reason",
                                    lambda d: [("", "value xor undefinedReason")]
                                    if (d["value"] is None) == (d["undefinedReason"] is None)
                                    else [])])
Pct = Nullable(Int(0, 10**9))
Distribution = Obj(required={"n": Count, "p50": Pct, "p95": Pct, "max": Pct})
CostBucket = Obj(required={"records": Count, "usdMicros": Nullable(UsdMicros)})
NCount = Nullable(Count)
REPORT_STATUSES = ("completed", "partial", "failed", "cancelled")

CaseResult = Obj(
    required={"caseId": Slug, "runId": Id("run"), "status": Enum(*REPORT_STATUSES),
              "expect": Nullable(Enum("findings", "silence", "partial", "failed")),
              "expectationMet": Nullable(Bool()), "truePositives": NCount,
              "falsePositives": NCount, "falseNegatives": NCount, "duplicates": NCount,
              "comments": Count, "incomplete": Arr(Incomplete, max_items=50),
              "error": Nullable(TypedError),
              "latencyMs": Obj(required={"original": Pct, "replay": Pct})})


def _report_ok(d):
    mode, cases, m = d["mode"], d["cases"], d["metrics"]
    rule, scope = d["matching"]["rule"], d["matching"]["scope"]
    scored = rule == "path-line-overlap@1"
    if len(cases) != d["dataset"]["caseCount"]:
        yield ".cases", "one result per dataset case"
    if scope != ("synthetic-smoke" if scored else "unscored"):
        yield ".matching.scope", "overlap => synthetic-smoke; unadjudicated => unscored"
    if scored and not d["dataset"]["synthetic"]:
        yield ".matching", "overlap scoring is synthetic smoke only; real PRs stay unscored"
    keys = ("truePositives", "falsePositives", "falseNegatives", "duplicates")
    if scored:
        if any(c[k] is None for c in cases for k in keys):
            yield ".cases", "scored reports carry TP/FP/FN/duplicates for every case"
            return
        for i, c in enumerate(cases):
            if c["comments"] != c["truePositives"] + c["falsePositives"]:
                yield f".cases[{i}].comments", "comments = TP + FP (duplicates are FP)"
            if c["duplicates"] > c["falsePositives"]:
                yield f".cases[{i}].duplicates", "duplicates are a subset of FP"
        tp = sum(c["truePositives"] for c in cases)
        fp = sum(c["falsePositives"] for c in cases)
        fn = sum(c["falseNegatives"] for c in cases)
        p, r = m["precision"], m["recall"]
        if (p["numerator"], p["denominator"]) != (tp, tp + fp):
            yield ".metrics.precision", "must be TP / (TP + FP) summed over cases"
        if (r["numerator"], r["denominator"]) != (tp, tp + fn):
            yield ".metrics.recall", "must be TP / (TP + FN) summed over cases"
        pv, rv, fv = p["value"], r["value"], m["f1"]["value"]
        want = None if pv is None or rv is None else (
            0.0 if pv + rv == 0 else 2 * pv * rv / (pv + rv))
        if (want is None) != (fv is None) or (want is not None and abs(want - fv) > 1e-9):
            yield ".metrics.f1", "must be the harmonic mean of P and R (null if either is null)"
    else:
        if any(c[k] is not None for c in cases for k in keys):
            yield ".cases", "unscored reports carry null TP/FP/FN/duplicates"
        for k in ("precision", "recall", "f1"):
            if m[k]["value"] is not None:
                yield f".metrics.{k}", "unscored (unadjudicated) metrics are null with reason"
    cov = d["coverage"]
    for st in REPORT_STATUSES:
        if cov[st] != sum(1 for c in cases if c["status"] == st):
            yield f".coverage.{st}", "must equal the count of cases with that status"
    if cov["expectationMet"] != sum(1 for c in cases if c["expectationMet"] is True):
        yield ".coverage.expectationMet", "must equal cases with expectationMet true"
    for b, bucket in d["cost"]["byBasis"].items():
        if bucket["records"] == 0 and bucket["usdMicros"] not in (0, None):
            yield f".cost.byBasis.{b}", "a bucket with no records has no cost"
    if mode in OFFLINE_MODES:
        if d["cost"]["liveCalls"] != 0:
            yield ".cost.liveCalls", "replay makes zero live calls"
        for b in ("measured", "estimated", "unknown"):
            if d["cost"]["byBasis"][b]["records"] != 0:
                yield f".cost.byBasis.{b}", "replay books only replayed/synthetic cost"
        if "replayOf" not in d:
            yield ".replayOf", "replay reports name the recorded EvalRun"


EvalReport = define("EvalReport", Obj(
    required={"schema": Const("eval-report@1"), "evalRunId": Id("evr"), "mode": Enum(*RUN_MODES),
              "dataset": Obj(required={"suiteId": Slug, "suiteVersion": Int(1, 10**6),
                                       "suiteDigest": Digest, "synthetic": Bool(),
                                       "caseCount": Count}),
              "matching": Obj(required={"rule": Enum("path-line-overlap@1", "unadjudicated@1"),
                                        "scope": Enum("synthetic-smoke", "unscored")}),
              "configDigest": Digest,
              "profiles": Arr(Obj(required={"ref": ProfileRef, "digest": Digest}), min_items=1,
                              max_items=20),
              "promptVersions": Arr(PromptVersion, max_items=100, unique=True),
              "contractsVersion": Str(min_len=1, max_len=64),
              "cases": Arr(CaseResult, max_items=100_000),
              "metrics": Obj(required={"precision": Ratio, "recall": Ratio, "f1": Derived}),
              "coverage": Obj(required={k: Count for k in (*REPORT_STATUSES, "expectationMet")}),
              "cost": Obj(required={"liveCalls": Count, "byBasis": Obj(required={
                  b: CostBucket for b in ("measured", "estimated", "unknown", "replayed",
                                          "synthetic")})}),
              "latency": Obj(required={"original": Distribution, "replay": Distribution}),
              "limitations": Arr(Str(min_len=1, max_len=2000), min_items=1, max_items=50)},
    optional={"replayOf": Id("evr"), "createdAt": Timestamp},
    invariants=[Invariant("report-honesty", "tallies, F1, coverage, matching scope and replay "
                          "cost accounting recompute from the cases", _report_ok),
                no_secrets("EvalReport")],
    description="Micro-averaged P/R. Matching path-line-overlap@1 (synthetic smoke only): "
                "duplicates count as false positives and are also reported separately; F1 is "
                "null if P or R is null and 0 if P+R=0. Real-PR datasets are unscored "
                "(unadjudicated@1): metrics null with reason. Never a parity claim.",
))

from . import scoring_family as _scoring_family  # noqa: E402,F401  (registers the isolated score family)

ENTITY_NAMES = tuple(sorted(REGISTRY))
