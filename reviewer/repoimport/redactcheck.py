"""Redaction is applied on read by the tools; the importer stores raw bytes and PROVES, per file, that the existing
redactor keeps the line count (so anchors stay valid). Nothing here changes contracts."""

from __future__ import annotations

from reviewer.contracts.canonical import digest
from reviewer.contracts.redaction import PROTECTED_PATTERNS, REDACTION_VERSION, redact


def patterns_digest() -> str:
    return digest([[pid, p.pattern, p.flags] for pid, p in PROTECTED_PATTERNS])


def line_count(text: str) -> int:
    """Same line semantics as pipeline.snaps.head_lines: a final newline ends the last line."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return len(lines)


def probe(text: str):
    """(lines, redaction counts) when redact keeps the line count, else None."""
    try:
        red, counts = redact(text)
    except ValueError:
        return None
    n = line_count(text)
    return (n, counts) if line_count(red) == n else None


def version_doc() -> dict:
    return {"version": REDACTION_VERSION, "patternsSha256": patterns_digest()}
