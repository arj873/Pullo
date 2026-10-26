"""Deterministic JUDGE logic: duplicate merge, severity ceiling, ranking, cap and Comment construction.

The judge MODEL only supplies wording for findings that survive this logic, plus optional host-validated
groupings of key-candidate duplicates. It cannot mint findings, anchors, severity or evidence, and it never drops
a finding on its own say-so.

Issue key (issue-key@2). The key is only a NECESSARY condition for "same issue": same location path,
category, impact, start line and end line, AND the same set of code citations (path + lines) in the proposals.
Two verified findings that share it are candidate duplicates, never proven duplicates: the key never reads claim
wording, so it also fits two distinct defects on one line. The host therefore drops nothing on the key alone.
A verified finding disappears into another comment only when (a) its comment fingerprint (category, path,
anchor text AND claim) is identical, or (b) the judge model proposes the grouping, the group lies inside one
key-candidate group, every member is a verified survivor, and the merged comment keeps all member ids, all
member evidence and every member claim (see merge_group). The judge cannot add findings, promote severity or
merge across keys.
"""

from __future__ import annotations

import json

from reviewer.contracts import validate
from reviewer.contracts.canonical import comment_fingerprint, comment_id
from reviewer.contracts.severity import (DEFAULT_COMMENT_CAP, DISABLED_BY_DEFAULT, comment_sort_key,
                                         evidence_strength, finding_ceiling, judge_severity)

ISSUE_KEY_VERSION = "issue-key@2"


def issue_key(f: dict) -> tuple:
    loc = f["location"]
    cites = sorted({(e["path"], tuple(e["lines"])) for e in f["evidence"] if e["kind"] == "code"})
    return (loc["path"], f["category"], f["impact"], loc["line"], loc.get("endLine", loc["line"]), tuple(cites))


def candidate_groups(findings: list[dict]) -> list[list[str]]:
    """Finding ids that share an issue key, groups of two or more only, each in input order. Candidates only:
    nothing is merged on this evidence."""
    by_key: dict[tuple, list[str]] = {}
    for f in findings:
        by_key.setdefault(issue_key(f), []).append(f["id"])
    return [ids for ids in by_key.values() if len(ids) > 1]


def merge_group(members: list[tuple[dict, dict]], title: str, body: str, suggestion: str | None) -> dict:
    """members: [(finding, its own Comment)] of one validated judge group, primary first (the most severe, then
    the earliest candidate). The merged Comment is the primary's with: every member id, the union of all member
    evidence (bounded), the judge wording, and a host-written trailer carrying every member claim, so no verified
    claim is lost. Severity, ceiling and proposed severity stay the primary's (nothing is promoted). The id and
    fingerprint stay the primary's."""
    primary_f, primary_c = members[0]
    c = dict(primary_c)
    c["findingIds"] = [f["id"] for f, _ in members][:50]
    seen, evidence = set(), []
    for _, mc in members:
        for e in mc["evidence"]:
            k = json.dumps(e, sort_keys=True)
            if k not in seen:
                seen.add(k)
                evidence.append(e)
    c["evidence"] = evidence[:50]
    trailer = "\n\nAlso verified at this location (merged by the judge as the same issue):" + "".join(
        f"\n- {f['claim']}" for f, _ in members[1:])
    c["title"] = title[:200]
    c["body"] = (body[:max(0, 4000 - len(trailer))] + trailer)[:4000]
    if suggestion is not None:
        c["suggestion"] = suggestion
    return c


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
