"""Local draft outputs: comments.json and the explanatory review.md. Pure functions of validated data.

Nothing here posts anywhere. Every comment is a DRAFT for the author, who decides what to change. Zero comments
means "no supported finding in the inspected context", never a statement that the change is safe.
"""

from __future__ import annotations

import json

from reviewer.contracts import require
from reviewer.contracts.redaction import redact

COMMENTS_SCHEMA = "review-comments@1"


def comments_doc(run: dict, status: str, comments: list) -> dict:
    return {"schema": COMMENTS_SCHEMA, "runId": run["id"], "headSnapshotId": run["headSnapshotId"],
            "status": status, "state": "draft", "comments": comments}


def comments_bytes(doc: dict) -> bytes:
    for c in doc["comments"]:
        require("Comment", c)
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


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
              changed: list, context_notes: list[str], tool_calls: int, cost_note: str) -> str:
    out = ["# Draft code review (local only)", "",
           "> DRAFT. Nothing in this file was posted, applied or executed against the repository. The review is "
           "read-only and explanatory: you decide which changes, if any, to make.", "",
           f"- Status: **{status}**", f"- Run: `{run['id']}`",
           f"- Base snapshot: `{run['baseSnapshotId']}`", f"- Head snapshot: `{run['headSnapshotId']}`", ""]
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
    out += ["- Static bounded context only: the models had no autonomous file retrieval in this version.", ""]
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
