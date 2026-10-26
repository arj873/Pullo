"""Local draft outputs: comments.json and the explanatory review.md. Pure functions of validated data.

Nothing here posts anywhere. Every comment is a DRAFT for the author, who decides what to change. Zero comments
means "no supported finding in the inspected context", never a statement that the change is safe.
"""

from __future__ import annotations

import json

from reviewer.contracts import require
from reviewer.contracts.redaction import redact

COMMENTS_SCHEMA = "review-comments@1"
PARTIAL_COMMENTS_SCHEMA = "review-comments@2"     # @1 plus a mandatory `coverage` object; full-view bundles stay @1, byte-identical


def comments_doc(run: dict, status: str, comments: list, coverage: dict | None = None) -> dict:
    """Bundle wrapper only: individual Comment entities are contracts-owned and untouched. A partial run adds a
    bundle-level `coverage` object (and bumps the wrapper to @2) so a sink reading only this file cannot take
    'completed' for a whole-repository review."""
    doc = {"schema": COMMENTS_SCHEMA, "runId": run["id"], "headSnapshotId": run["headSnapshotId"],
           "status": status, "state": "draft", "comments": comments}
    if coverage is not None:
        d = coverage["detail"]
        doc["schema"] = PARTIAL_COMMENTS_SCHEMA
        if d.get("kind") == "repository":
            doc["coverage"] = {"scope": d["scope"], "fullRepositoryCoverage": d["fullRepositoryCoverage"],
                               "partial": False, "coverageDigest": coverage["digest"],
                               "statement": coverage["statement"], "base": d["base"], "head": d["head"],
                               "gapKinds": d["gapKinds"], "relatesTo": d["relatesTo"],
                               "prTextSupplied": d["prTextSupplied"]}
            return doc
        doc["coverage"] = {"scope": d["scope"], "fullRepositoryCoverage": False, "partial": True,
                           "coverageDigest": coverage["digest"], "statement": coverage["statement"],
                           "changedPathCount": d["changedPathCount"], "contextPathCount": d["contextPathCount"],
                           "gapKinds": d["gapKinds"], "contextGap": d["contextGap"]}
    return doc


def comments_bytes(doc: dict) -> bytes:
    for c in doc["comments"]:
        require("Comment", c)
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _ctx_gap(g: dict) -> str:
    if g["kinds"] or g["count"]:
        return f"{g['count'] if g['count'] is not None else 'some'} file(s)" + (f" ({', '.join(g['kinds'])})" if g["kinds"] else "")
    return "record marked incomplete, no reason given" if g["incomplete"] else "none recorded"


def _loc(a: dict) -> str:
    return f"{a['path']}:{a['startLine']}" + (f"-{a['endLine']}" if a["endLine"] != a["startLine"] else "")


def _ev(e: dict) -> str:
    if e["kind"] == "code":
        return f"- `{e['path']}:{e['lines'][0]}-{e['lines'][1]}` ({e['kind']}, pinned & resolved)"
    return f"- {e['kind']} from tool call `{e.get('toolCallId')}`"


def summary_line(status: str, comments: list, incomplete: list, error: dict | None) -> str:
    n = len(comments)
    base = f"Draft review {status}: {n} draft comment{'s' if n != 1 else ''}."
    if incomplete:
        base += " Incomplete: " + ", ".join(f"{i['stage']}/{i['reason']}" for i in incomplete) + "."
    if error:
        base += f" Error: {error['code']}."
    return base[:8000]


def review_md(*, run: dict, status: str, comments: list, drops: list, incomplete: list, error: dict | None,
              changed: list, context_notes: list[str], tool_calls: int, cost_note: str,
              coverage: dict | None = None, retrieval: bool = False) -> str:
    out = ["# Draft code review (local only)", "",
           "> DRAFT. Nothing in this file was posted, applied or executed against the repository. The review is "
           "read-only and explanatory: you decide which changes, if any, to make.", "",
           f"- Status: **{status}**", f"- Run: `{run['id']}`",
           f"- Base snapshot: `{run['baseSnapshotId']}`", f"- Head snapshot: `{run['headSnapshotId']}`", ""]
    if coverage is not None and coverage["detail"].get("kind") == "repository":
        d = coverage["detail"]
        out += ["## Coverage (repository)", "", coverage["statement"], "",
                f"- Scope: `{d['scope']}`; full-repository coverage: {'yes' if d['fullRepositoryCoverage'] else 'NO'}",
                f"- Omitted by the imports: base {d['base']['omittedTotal']}, head {d['head']['omittedTotal']}; "
                f"kinds: {', '.join(d['gapKinds']) or 'none recorded'}",
                f"- Pull request title/body supplied: {'yes' if d['prTextSupplied'] else 'no'}", ""]
    elif coverage is not None:
        d = coverage["detail"]
        out += ["## Coverage (partial)", "", coverage["statement"], "",
                f"- Changed paths recorded: {d['changedPathCount']}; context files: base "
                f"{d['contextPathCount']['base']}, head {d['contextPathCount']['head']}",
                f"- Recorded coverage gaps: {', '.join(d['gapKinds']) or 'none recorded'}",
                f"- Selected context not recorded: {_ctx_gap(d['contextGap'])}",
                *[f"- Recorded on one side only / ambiguous status (no diff, not a known add or delete): `{g['path']}` "
                  f"({g['status']}; sides: {', '.join(g['recordedSides']) or 'none'})"
                  for g in d.get("oneSidedOrAmbiguous", [])],
                "- This is not a full-repository review.", ""]
    if error:
        out += [f"**This review did not finish: `{error['code']}`.** {redact(error['message'])[0]}", ""]
    if incomplete:
        out += ["## Incomplete", ""] + [f"- {i['stage']}: {i['reason']}" + (f" ({i['detail']})" if i.get("detail") else "")
                                       for i in incomplete] + [""]
    out += ["## What was inspected", "", f"- Changed paths found by the diff tool: {len(changed)}"]
    out += [f"  - `{f['path']}` ({f['status']}, +{f['additions']}/-{f['deletions']})" for f in changed[:50]]
    if len(changed) > 50:
        out.append(f"  - ... {len(changed) - 50} more")
    out += [f"- Tool calls logged in PREPARE/VERIFY: {tool_calls}"] + [f"- {n}" for n in context_notes]
    out += ["- Static bounded context only: the models had no autonomous file retrieval in this version." if not retrieval
            else "- Bounded model-requested retrieval over read-only pinned snapshots: every request and its result is "
                 "in the trace; requests that were not run (caps) are listed as incomplete, never as findings.", ""]
    out += [f"## Comments ({len(comments)})", ""]
    if not comments:
        out += ["No supported finding in the inspected context. This is not a certificate that the change is "
                "free of defects: anything outside the inspected context, or that the models did not "
                "surface and verify, was not reviewed.", ""]
    for c in comments:
        out += [f"### [{c['severity']}] {c['title']}", "", f"`{_loc(c['anchor'])}` · {c['category']} · evidence: "
                f"{c['evidenceStrength']} · proposed {c['proposedSeverity']}, ceiling {c['severityCeiling']}", "",
                c["body"], ""]
        if c.get("suggestion"):
            out += ["_Suggestion (explanatory text, never applied):_", "", c["suggestion"], ""]
        out += ["Evidence:"] + [_ev(e) for e in c["evidence"]] + [""]
    if drops:
        out += ["## Candidates not reported", ""]
        for d in drops:
            out.append(f"- {d['stage']}: {d['reason']} - {', '.join(d['subjectIds'])}" +
                       (f" ({d['detail']})" if d.get("detail") else ""))
        out.append("")
    out += ["## Cost", "", cost_note, ""]
    return "\n".join(out)
