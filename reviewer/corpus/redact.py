"""Redaction for corpus blobs: the contracts helper, called exactly, plus line/hunk safeguards.

`redact_text` returns `contracts.redaction.redact(text)` unchanged for ordinary text. For a
unified-diff patch it additionally restores the `+`/`-`/space prefix on lines whose start was
swallowed by a multi-line match, so hunk line counts still hold. Newline count is always
preserved and nothing protected may remain, otherwise `RedactionError` is raised.

Staleness policy (RF1): `patterns_digest()` fingerprints the patterns only. A change to the redaction
algorithm (fixpoint loop, marker rule, replacement) that keeps the patterns MUST bump
`contracts.redaction.REDACTION_VERSION`; that bump, not the fingerprint, marks recorded corpora stale.
`refresh-redaction` (reviewer/corpus/refresh.py) then re-stamps a corpus offline only if the current
redaction provably changes none of its text.
"""

from __future__ import annotations

import hashlib
import re

from reviewer.contracts import redaction as _c

REDACTION_VERSION = _c.REDACTION_VERSION
_HUNK = re.compile(r"@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")

__all__ = ["REDACTION_VERSION", "RedactionError", "patterns_digest", "redact_text", "redact_log"]


class RedactionError(ValueError):
    pass


def patterns_digest() -> str:
    """Fingerprint of the active pattern set, so drift inside one version label is detectable."""
    h = hashlib.sha256()
    for pid, pat in _c.PROTECTED_PATTERNS:
        h.update(f"{pid}\0{pat.pattern}\0{pat.flags}\n".encode())
    return h.hexdigest()


def _restore_prefixes(src: str, out: str) -> str:
    a, b = src.split("\n"), out.split("\n")
    if len(a) != len(b):
        raise RedactionError("line count changed")
    for i in range(1, len(a)):
        p = a[i][:1]
        if p in ("+", "-", " ") and a[i] != b[i] and not b[i].startswith(p):
            b[i] = p + b[i]
    return "\n".join(b)


def redact_text(text: str, patch: bool | None = None) -> tuple[str, dict[str, int]]:
    """patch=None auto-detects a unified diff by its leading hunk header."""
    out, counts = _c.redact(text)
    if out.count("\n") != text.count("\n"):
        raise RedactionError("redaction changed the line count")
    if patch is None:
        patch = bool(_HUNK.match(text))
    if patch and out != text:
        out = _restore_prefixes(text, out)
    if out.count("\n") != text.count("\n") or _c.contains_protected(out):
        raise RedactionError("redaction left protected text or changed the line count")
    return out, counts


def redact_log(msg: str) -> str:
    try:
        return redact_text(msg, patch=False)[0]
    except RedactionError:
        return "[log line withheld: redaction failed]"
