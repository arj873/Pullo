"""Executable severity rubric, evidence trust and deterministic JUDGE ordering (36).

Rubric (root decision D3). Severity is about impact and reach; evidence
confidence is a separate axis (`evidence_strength`) used for ranking.
- Evidence counts only if it is trusted: a code citation carrying
  `resolved: true`, which only the pipeline/tool layer sets after checking it
  against the pinned snapshot (materialize_evidence with a resolver such as
  snapshot.snapshot_resolver), or evidence copied from a logged tool.call
  result (the tool layer mints kinds; a model can only reference a call id).
  Shape alone never makes a citation trusted.
- P0: bug/security, severe impact (data-loss, auth-bypass, crash,
  security-exposure, corruption), reachable, and at least one trusted citation.
  A verified single-file defect qualifies; file count is not a criterion.
- P1: reachable defect (impact not maintainability/none) in bug, security,
  breaking-change, ticket-compliance or performance, with a trusted citation.
- P2: everything else, including anything without trusted evidence.
- "Verified" (VERIFY confirmed with independent evidence) is enforced by the
  Finding contract, not here. JUDGE may demote freely; promotion above the
  proposed severity needs a recorded reason; nothing exceeds the ceiling.
  Comments record proposedSeverity and severityCeiling so caps are countable.

Uncertainty [HYPOTHESIS]: the impact list, reach judgement and P0/P1 split are
unvalidated; reach comes from the verifier's own re-derivation and can be
wrong. Calibrate against human severity labels before trusting P0 rates.
"""

from __future__ import annotations

from typing import Callable

SEVERE_IMPACTS = frozenset({"data-loss", "auth-bypass", "crash", "security-exposure", "corruption"})
P0_CATEGORIES = frozenset({"bug", "security"})
P1_CATEGORIES = frozenset({"bug", "security", "breaking-change", "ticket-compliance",
                           "performance"})
NON_DEFECT_IMPACTS = frozenset({"maintainability", "none"})
DISABLED_BY_DEFAULT = frozenset({"style"})
TRUSTED_TOOL_STATUSES = frozenset({"ok", "partial", "empty"})   # tool results whose evidence counts

RANK = {"P0": 0, "P1": 1, "P2": 2}
SEVERITY_WEIGHT = {"P0": 5, "P1": 2, "P2": 1}  # V1 expected-value ranking [HYPOTHESIS]; unused in 0A

# Evidence confidence, strongest first. Derived from trusted traces only (D4).
STRENGTHS = ("reproduced", "analyzer", "verifier-traced", "cited", "unsupported")
STRENGTH_RANK = {s: i for i, s in enumerate(STRENGTHS)}

DEFAULT_COMMENT_CAP = 5   # per run, counting already-open Comments (01: median <= 5)
MERGE_LINE_WINDOW = 3     # S0-07 JUDGE: same path + category + anchors within N lines merge


def _trusted_tool_kinds(e: dict, tool_calls: dict | None) -> set[str]:
    """Kinds the tool layer itself minted for the call this evidence references."""
    if not tool_calls:
        return set()
    tc = tool_calls.get(e.get("toolCallId"))
    if not isinstance(tc, dict) or tc.get("type") != "tool.call":
        return set()
    result = tc.get("result") or {}
    if result.get("status") not in TRUSTED_TOOL_STATUSES:
        return set()
    return {x.get("kind") for x in result.get("evidence", []) if isinstance(x, dict)}


def is_trusted(e, tool_calls: dict | None = None) -> bool:
    if not isinstance(e, dict):
        return False
    if e.get("kind") == "code":
        lines = e.get("lines")
        return e.get("resolved") is True and bool(e.get("path")) and bool(e.get("commit")) \
            and isinstance(lines, list) and len(lines) == 2
    return e.get("kind") in _trusted_tool_kinds(e, tool_calls)


def has_strong_evidence(evidence, tool_calls: dict | None = None) -> bool:
    """A trusted test-run or analyzer result. Never true for model-labelled kinds."""
    return any(isinstance(e, dict) and e.get("kind") in ("test-run", "analyzer")
               and is_trusted(e, tool_calls) for e in (evidence or []))


def evidence_strength(evidence, tool_calls: dict | None = None, verifier_evidence=()) -> str:
    ev = list(evidence or []) + list(verifier_evidence or [])
    trusted = [e for e in ev if is_trusted(e, tool_calls)]
    kinds = {e["kind"] for e in trusted}
    if "test-run" in kinds:
        return "reproduced"
    if "analyzer" in kinds:
        return "analyzer"
    if tool_calls and any(isinstance(e, dict) and e.get("toolCallId") in tool_calls
                          and is_trusted(e, tool_calls) for e in (verifier_evidence or [])):
        return "verifier-traced"   # the verifier's own logged tool call supports the claim
    if trusted:
        return "cited"
    return "unsupported"


def severity_ceiling(category: str, impact: str, reachable: bool, evidence,
                     tool_calls: dict | None = None) -> str:
    if not any(is_trusted(e, tool_calls) for e in (evidence or [])):
        return "P2"
    if category in P0_CATEGORIES and impact in SEVERE_IMPACTS and reachable is True:
        return "P0"
    if category in P1_CATEGORIES and reachable is True and impact not in NON_DEFECT_IMPACTS:
        return "P1"
    return "P2"


def judge_severity(proposed: str, suspected: str, ceiling: str,
                   promotion_reason: str | None = None) -> str:
    """Raises ValueError on an unknown severity (fail closed; inputs come from validated docs)."""
    for s in (proposed, suspected, ceiling):
        if s not in RANK:
            raise ValueError(f"unknown severity {s!r}")
    sev = proposed
    if RANK[sev] < RANK[ceiling]:
        sev = ceiling
    if RANK[sev] < RANK[suspected] and not promotion_reason:
        sev = suspected
    return sev


def finding_ceiling(finding: dict, tool_calls: dict | None = None) -> str:
    """Ceiling from the verifier's basis and all trusted Evidence (proposer's + verifier's)."""
    basis = finding["severityBasis"]
    evidence = finding["evidence"] + finding["verification"]["evidence"]
    return severity_ceiling(finding["category"], basis["impact"], basis["reachable"], evidence,
                            tool_calls)


def materialize_evidence(model_evidence: list, tool_calls: dict, source: str,
                         resolver: Callable[[dict], bool] | None = None
                         ) -> tuple[list[dict], list[str]]:
    """Turn validated ModelEvidence into pipeline Evidence. Code citations are checked with
    `resolver` (e.g. snapshot.snapshot_resolver): resolved ones get `resolved: true`; failures
    are dropped and reported. Without a resolver, code citations are copied unresolved and stay
    untrusted (they cannot raise severity or strength). Tool refs copy the tool layer's own
    evidence from the trusted trace. Returns (evidence, problems); a problem means the citation
    is invalid (`invalid-citation`)."""
    out: list[dict] = []
    problems: list[str] = []
    for i, m in enumerate(model_evidence):
        if m["kind"] == "code":
            ev = {"kind": "code", "path": m["path"], "lines": list(m["lines"]),
                  "commit": m["commit"], "excerpt": m["excerpt"], "source": source}
            if resolver is not None:
                try:
                    ok = resolver(ev) is True
                except Exception:  # noqa: BLE001 - a resolver failure is an unresolvable citation
                    ok = False
                if not ok:
                    problems.append(f"[{i}] code citation does not match the pinned snapshot")
                    continue
                ev["resolved"] = True
            out.append(ev)
            continue
        tc = tool_calls.get(m["toolCallId"])
        if not isinstance(tc, dict) or tc.get("type") != "tool.call":
            problems.append(f"[{i}] unknown tool call {m['toolCallId']}")
            continue
        items = tc["result"]["evidence"]
        if "index" in m:
            if m["index"] >= len(items):
                problems.append(f"[{i}] index {m['index']} out of range")
                continue
            items = [items[m["index"]]]
        out.extend(dict(x) for x in items[:20])
    return out, problems


def comment_sort_key(comment: dict) -> tuple:
    """Order: severity, then independently validated evidence strength, then path, line and
    fingerprint as final deterministic tie-breaks. Model confidence is never a key."""
    a = comment.get("anchor", {})
    return (RANK.get(comment.get("severity"), 3),
            STRENGTH_RANK.get(comment.get("evidenceStrength", "unsupported"), len(STRENGTHS)),
            a.get("path", ""), a.get("startLine", 0), comment.get("fingerprint", ""))
