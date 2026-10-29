"""Impact coverage disclosure (`impact-coverage@1`): what the impact pre-pass found and which dependents were opened.

A pure function of the logged trace (and the PREPARE change list), so review.md, the receipt and a resumed or
loaded run all re-derive the same numbers. Legacy runs have no `impact_scan` event and get None (outputs unchanged).

Counts:
  symbols / symbolsFound   changed definitions scanned / detected (from the impact map header the host wrote)
  references / files       whole-word reference lines outside the changed lines, and the files holding them
  truncated                the map hit a cap (symbols, shown references, scan limits) or the scan stopped early
  dependentFilesKnown      distinct referencing files whose path the trace shows (impact map + find_references items)
  dependentFilesOpened     of those, files that a model-requested read_file actually returned (INVESTIGATE/VERIFY)
  otherFilesOpened         other files outside the change that were read
"""

from __future__ import annotations

import re

from reviewer.contracts.severity import TRUSTED_TOOL_STATUSES

SCHEMA = "impact-coverage@1"
_HEADER = re.compile(r"^# impact map \((?:head|base)\): (\d+) changed symbol\(s\) analysed of (\d+) found in (\d+) "
                     r"changed file\(s\); (\d+)(\+?) reference\(s\) in (\d+) file\(s\) outside the changed lines; "
                     r"(\d+) shown; truncated: (yes|no)$")
REVIEW_STAGES = ("INVESTIGATE", "VERIFY")


def _code_paths(ev: dict) -> set:
    return {x["path"] for x in ev["result"]["evidence"] if x.get("kind") == "code"}


def summarize(events: list, changed: set) -> dict | None:
    scans = [e for e in events if e["type"] == "tool.call" and e["tool"] == "impact_scan"]
    if not scans:
        return None
    scan = scans[-1]
    res = scan["result"]
    out = {"schema": SCHEMA, "status": res["status"], "toolCallId": scan["toolCallId"]}
    m = None
    if res["status"] in TRUSTED_TOOL_STATUSES and res["evidence"]:
        m = _HEADER.match(res["evidence"][0]["excerpt"].split("\n", 1)[0])
    known = set()
    if m is not None:
        known |= _code_paths(scan)
        out.update(symbols=int(m.group(1)), symbolsFound=int(m.group(2)), changedFiles=int(m.group(3)),
                   references=int(m.group(4)), referencesLowerBound=m.group(5) == "+", files=int(m.group(6)),
                   shown=int(m.group(7)), truncated=m.group(8) == "yes")
    finds = [e for e in events if e["type"] == "tool.call" and e["tool"] == "find_references"
             and e["result"]["status"] in TRUSTED_TOOL_STATUSES]
    for e in finds:
        known |= _code_paths(e)
    known -= set(changed)
    reads = {e["args"]["path"] for e in events
             if e["type"] == "tool.call" and e["tool"] == "read_file" and e["stage"] in REVIEW_STAGES
             and "requestedBy" in e and e["result"]["status"] in ("ok", "partial") and "path" in e["args"]}
    reads -= set(changed)
    out.update(findReferencesCalls=sum(1 for e in events if e["type"] == "tool.call" and e["tool"] == "find_references"),
               dependentFilesKnown=len(known), dependentFilesOpened=len(reads & known),
               otherFilesOpened=len(reads - known))
    out["statement"] = statement(out)
    return out


def statement(s: dict) -> str:
    if "symbols" not in s:
        return (f"Impact: the impact map is not available (impact_scan {s['status']}); "
                f"{s['dependentFilesOpened'] + s['otherFilesOpened']} file(s) outside the change opened; "
                f"{s['findReferencesCalls']} find_references call(s).")
    refs = f"{s['references']}{'+' if s['referencesLowerBound'] else ''}"
    return (f"Impact: {s['symbols']} changed symbol(s) analysed (of {s['symbolsFound']} found), {refs} reference(s) "
            f"in {s['files']} file(s){'; map truncated' if s['truncated'] else ''}; {s['dependentFilesOpened']} of "
            f"{s['dependentFilesKnown']} known dependent file(s) opened, {s['otherFilesOpened']} other file(s) outside "
            f"the change opened; {s['findReferencesCalls']} find_references call(s).")
