"""Stage 0A wire contracts (frozen by S0-03, corrected by S0-03-fix).

Names follow 03-data-model-and-glossary.md. Deliberate departures are listed in
orchestration/handoffs/S0-03.md and S0-03-fix.md. Money is integer micro-USD and
fractions are basis points so canonical hashes are stable; every integer is
bounded for JSON interoperability.
"""

from __future__ import annotations

from .canonical import (GITHUB_REPO, call_id, comment_id, cost_id, digest, hypothesis_id,
                        idempotency_key_eval, idempotency_key_local, idempotency_key_pr,
                        request_hash, run_id, tool_call_id)
from .redaction import json_contains_protected
from .schema import (REGISTRY, Arr, Bool, Const, Enum, Int, Invariant, Issue, Json, Nullable,
                     Num, Obj, RelPath, Str, Union, define, validate)
from .severity import RANK, STRENGTHS, TRUSTED_TOOL_STATUSES
from .stages import (ACCESS_POLICY, ERROR_CODES, INCOMPLETE_REASONS, LIVE_MODES, OFFLINE_MODES,
                     REPLAYABLE_FROM, RUN_MODES, RUN_STATUSES, STAGE_STATUSES, STAGES, TRIGGERS)

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


def _cited(e: dict, citations: list, tools: dict) -> bool:
    """e is what severity.materialize_evidence makes of one of the model's `citations`: the same
    code citation (excerpt included), or an item copied from the tool.call a tool-ref names."""
    if e["kind"] == "code":
        return any(c["kind"] == "code" and all(c[k] == e[k] for k in _CITATION_KEYS)
                   for c in citations)
    for c in citations:
        tc = tools.get(c["toolCallId"]) if c["kind"] == "tool-ref" else None
        if tc is None or c["toolCallId"] != e["toolCallId"]:
            continue
        items = tc["result"]["evidence"]
        items = items[c["index"]:c["index"] + 1] if "index" in c else items[:20]
        if e in items:
            return True
    return False


def check_finding_provenance(finding: dict, events: list) -> list[Issue]:
    """Cross-trace check for one Finding against its run's trace events (s0a-contracts@5).

    - Every referenced call id is logged exactly once in this run (a duplicate id is never used).
    - sourceCallId is a valid, successful INVESTIGATE/investigator model.call whose output is a
      valid InvestigatorOutput with an entry `index` such that hypothesis_id(specialist, index,
      claim, path, line) == Finding.id, and the Finding's PROPOSAL_FIELDS equal that entry.
    - Every verification callId is a valid, successful VERIFY/verifier model.call logged after
      the source call, whose request.hypothesisId is Finding.id, which is not a repair of the
      source call, and whose output is a valid VerifierOutput with verdict 'confirmed' and the
      Finding's severityBasis (impact, reachable). A call and its retries/repairs (same agent
      and ordinal, or the same repair chain) count once.
    - Finding.evidence is materialized from the proposal's citations and verification.evidence
      from the confirming calls' citations. Non-code Evidence names a tool.call logged once in
      this run with a usable status, and is an item of that call's result.

    Event ids are payload-bound (validate TraceEvent), so a relabelled stage, role or request
    cannot reuse another call's id. This detects inconsistency, not a consistently rewritten
    trace (trace authenticity is the gateway's job), and it does not re-resolve citations
    against the snapshot (the pipeline must use snapshot.snapshot_resolver)."""
    out = [Issue(f"$finding{x.path[1:]}", x.code, x.message) for x in validate("Finding", finding)]
    if out:
        return out
    run = finding["runId"]
    logged: dict[str, int] = {}
    calls: dict[str, dict] = {}
    tools: dict[str, dict] = {}
    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict) or ev.get("runId") != run:
            continue
        kind = ev.get("type")
        key = ev.get("callId") if kind == "model.call" else ev.get("toolCallId") \
            if kind == "tool.call" else None
        if not isinstance(key, str):
            continue
        logged[key] = logged.get(key, 0) + 1   # counted even if invalid: a twin poisons the id
        if not validate("TraceEvent", ev):
            (calls if kind == "model.call" else tools)[key] = ev

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
        return ev

    src = finding["sourceCallId"]
    src_ev = ok_call(src, "INVESTIGATE", "investigator", "$finding.sourceCallId")
    proposal = None
    if src_ev is not None:
        output = src_ev["response"]["output"]
        if validate("InvestigatorOutput", output):
            issue("$finding.sourceCallId", "source call output is not a valid InvestigatorOutput")
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
        logical = {("call", ev["agentId"], ev["ordinal"]), ("chain", chain[-1])}
        if logical & counted:
            issue(path, "repeats a listed verification (same logical call or its repair)")
        counted |= logical
        output = ev["response"]["output"]
        if validate("VerifierOutput", output) or output.get("verdict") != "confirmed":
            issue(path, "verifier call did not confirm")
            continue
        if {"impact": output["impact"], "reachable": output["reachable"]} != finding["severityBasis"]:
            issue(path, "severityBasis differs from this verifier call's impact/reachable")
        confirmed = (confirmed or []) + output["evidence"]

    for side, evs, cited, who in (
            ("evidence", finding["evidence"], proposal and proposal["evidence"], "the proposal"),
            ("verification.evidence", finding["verification"]["evidence"], confirmed,
             "a confirming verifier call")):
        for i, e in enumerate(evs):
            path = f"$finding.{side}[{i}]"
            if e["kind"] != "code":
                tid = e["toolCallId"]
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
            if cited is not None and not _cited(e, cited, tools):
                issue(path, f"was not cited by {who}")
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


Budget = define("Budget", Obj(
    required={"maxUsdMicros": Int(1, 10**9), "maxToolCalls": Int(0, 10_000),
              "maxToolCallsPerAgent": Int(0, 10_000),
              "maxToolOutputTokensPerAgent": Int(0, 10**8),
              "wallClockSec": Int(1, 86_400), "softDeadlineSec": Int(1, 86_400),
              "verifyReserveBp": Int(0, 10000), "maxRetriesPerCall": Int(0, 3)},
    invariants=[Invariant("budget-order", "soft <= hard deadline; per-agent <= total", _budget_ok)],
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
              "outputSchema": Enum("InvestigatorOutput", "VerifierOutput", "JudgeOutput"),
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
    description="Immutable; a change is a new version. Referenced as '<id>@<version>'.",
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

ROLE_OUTPUT = {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput",
               "judge": "JudgeOutput"}

ModelRequest = define("ModelRequest", Obj(
    required={"provider": Enum(*PROVIDERS), "model": Str(min_len=1, max_len=128),
              "profile": ProfileRef, "role": Enum(*ROLE_OUTPUT),
              "promptVersion": PromptVersion,
              "outputSchema": Enum(*ROLE_OUTPUT.values()),
              "params": Json(), "messages": Arr(Message, min_items=1, max_items=1000),
              "tools": Arr(Json(), max_items=100)},
    optional={"hypothesisId": Id("hyp")},
    invariants=[Invariant("request-subject", "hypothesisId only on verifier requests",
                          lambda d: [(".hypothesisId", "only a verifier request names a hypothesis")]
                          if "hypothesisId" in d and d["role"] != "verifier" else []),
                no_secrets("ModelRequest")],
    description="Redacted before hashing. Must not contain run ids or timestamps. "
                "requestHash = canonical.request_hash(request), which enforces both. "
                "hypothesisId names the hypothesis a verifier request checks and is covered by "
                "requestHash; a verifier call without it cannot confirm a Finding "
                "(check_finding_provenance). Other calls omit it.",
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
    if len(subjects) > 1:
        yield "", "a CostRecord covers one call"
    elif subjects and d["id"] != cost_id(subjects[0]):
        yield ".id", "must equal cost_id(callId or toolCallId)"
    elif not subjects and k != "index":
        yield "", "review/chat/eval costs name their callId or toolCallId"


CostRecord = define("CostRecord", Obj(
    required={"id": Id("cost"), "kind": Enum("review", "chat", "index", "eval"),
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
    if d["request"]["outputSchema"] != ROLE_OUTPUT[d["role"]]:
        yield ".request.outputSchema", f"a {d['role']} call requests {ROLE_OUTPUT[d['role']]}"


def _tool_call_ok(d):
    if d["toolCallId"] != tool_call_id(d["stage"], d["agentId"], d["ordinal"], d["tool"], d["args"]):
        yield ".toolCallId", "must equal tool_call_id(stage, agentId, ordinal, tool, args)"
    if d["resultHash"] != digest(d["result"]):
        yield ".resultHash", "must equal result_hash(result)"
    if "costRecordId" in d and d["costRecordId"] != cost_id(d["toolCallId"]):
        yield ".costRecordId", "must equal cost_id(toolCallId)"


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
        {"costRecordId": Id("cost"), "latencyMs": Int(0, 10**9)},
        [Invariant("tool-identity", "toolCallId, resultHash and costRecordId recompute from the "
                   "payload", _tool_call_ok)]),
    "cost": _event("cost", {"record": CostRecord}),
    "checkpoint": _event("checkpoint", {"stage": Stage, "planVersion": Int(0, 100),
                                        "artifactDigest": Digest}),
    "error": _event("error", {"error": TypedError}),
    "run.end": _event("run.end", {"status": Enum(*RUN_STATUSES),
                                  "incomplete": Arr(Incomplete, max_items=50)}),
}).describe("One JSON object per line in trace.jsonl. Whole-file rules: entities.validate_trace."))


def validate_trace(events: list) -> list[Issue]:
    """Per-event validation (including payload hash/id recomputation) plus file rules: seq
    0,1,2..., one runId, run.start first (naming the same run), run.end only last, each call id
    logged once, and cost records in the file naming the call that references them."""
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
    return out

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

ENTITY_NAMES = tuple(sorted(REGISTRY))
