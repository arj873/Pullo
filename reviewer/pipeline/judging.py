"""Deterministic JUDGE logic: duplicate merge, severity ceiling, ranking, cap and Comment construction.

The judge MODEL only supplies wording for findings that survive this logic. It cannot mint findings, anchors,
severity or evidence, and it never decides what is dropped.

Issue key (issue-key@1). Two verified findings are the same issue only when ALL hold: same location path,
category, impact, start line and end line, AND the same set of code citations (path + lines) in the
proposals. Nearby claims that merely share path/category/line window, or that cite different code, stay
separate. The key never reads claim wording, so it merges the same defect described twice but also two
distinct defects that share every one of those fields: that is a stated limit of this conservative rule.
The earliest original candidate index is kept.
"""

from __future__ import annotations

from reviewer.contracts import validate
from reviewer.contracts.canonical import comment_fingerprint, comment_id
from reviewer.contracts.severity import (DEFAULT_COMMENT_CAP, DISABLED_BY_DEFAULT, comment_sort_key,
                                         evidence_strength, finding_ceiling, judge_severity)

ISSUE_KEY_VERSION = "issue-key@1"


def issue_key(f: dict) -> tuple:
    loc = f["location"]
    cites = sorted({(e["path"], tuple(e["lines"])) for e in f["evidence"] if e["kind"] == "code"})
    return (loc["path"], f["category"], f["impact"], loc["line"], loc.get("endLine", loc["line"]), tuple(cites))


def merge_duplicates(items: list[tuple[int, dict]]):
    """items: [(original candidate index, Finding)] in index order. -> (kept, merged_drops).
    merged_drops: [(finding, kept finding)]"""
    kept: dict[tuple, tuple[int, dict]] = {}
    merged = []
    for idx, f in sorted(items, key=lambda t: t[0]):
        k = issue_key(f)
        if k in kept:
            merged.append((f, kept[k][1]))
        else:
            kept[k] = (idx, f)
    return sorted(kept.values(), key=lambda t: t[0]), merged


def severity_for(f: dict, tool_calls: dict) -> tuple[str, str]:
    """-> (severity, ceiling). No promotion happens here: proposed = suspected, so judge_severity can only demote."""
    ceiling = finding_ceiling(f, tool_calls)
    return judge_severity(f["suspectedSeverity"], f["suspectedSeverity"], ceiling), ceiling


def build_comment(f: dict, *, run_id: str, head_snapshot_id: str, anchor: str, tool_calls: dict, title: str,
                  body: str, suggestion: str | None) -> dict:
    sev, ceiling = severity_for(f, tool_calls)
    loc = f["location"]
    fp = comment_fingerprint(f["category"], loc["path"], anchor, f["claim"])
    c = {"id": comment_id(fp), "runId": run_id, "findingIds": [f["id"]], "severity": sev,
         "proposedSeverity": f["suspectedSeverity"], "severityCeiling": ceiling,
         "evidenceStrength": evidence_strength(f["evidence"], tool_calls, f["verification"]["evidence"]),
         "category": f["category"],
         "anchor": {"path": loc["path"], "startLine": loc["line"], "endLine": loc.get("endLine", loc["line"]),
                    "snapshotId": head_snapshot_id},
         "title": title[:200], "body": body[:4000],
         "evidence": (f["evidence"] + f["verification"]["evidence"])[:50],
         "qualityScore": None, "fingerprint": fp, "state": "draft"}
    if suggestion is not None:
        c["suggestion"] = suggestion
    return c


def rank_and_cap(entries: list[tuple[dict, dict]], cap: int):
    """entries: [(finding, comment-skeleton)] -> (kept, over_cap) ordered by comment_sort_key."""
    cap = DEFAULT_COMMENT_CAP if cap is None else cap
    ordered = sorted(entries, key=lambda t: comment_sort_key(t[1]))
    return ordered[:cap], ordered[cap:]


def disabled_by_config(f: dict) -> bool:
    return f["category"] in DISABLED_BY_DEFAULT


def revalidate_comment(c: dict, *, head_snapshot_id: str, resolver, anchor_ok) -> list[str]:
    """Final checks on a Comment: contract, head anchor, anchor lines exist in the pinned head file, every code
    evidence still resolves against the two pinned snapshots, draft state."""
    problems = [str(i) for i in validate("Comment", c)]
    if c["state"] != "draft":
        problems.append("comment is not a draft")
    a = c["anchor"]
    if a["snapshotId"] != head_snapshot_id:
        problems.append("comment is not anchored to the head snapshot")
    elif not anchor_ok(a["path"], a["startLine"], a["endLine"]):
        problems.append("anchor lines do not exist in the pinned head file")
    for i, e in enumerate(c["evidence"]):
        if e["kind"] == "code" and resolver(e) is not True:
            problems.append(f"evidence[{i}] no longer resolves against the pinned snapshots")
    return problems
