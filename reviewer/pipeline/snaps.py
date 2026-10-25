"""Pinned-snapshot helpers used by the pipeline itself (validation, anchors). Every read goes through
contracts snapshot.read_verified, so bytes are checked against the manifest on every use."""

from __future__ import annotations

from reviewer.contracts.redaction import redact
from reviewer.contracts.snapshot import SnapshotError, read_verified


def head_lines(root, manifest: dict, path: str) -> list[str] | None:
    """Redacted lines of a pinned regular text file, or None when it cannot be read/verified."""
    try:
        data = read_verified(root, manifest, path)
        text = redact(data.decode("utf-8"))[0]
    except (SnapshotError, UnicodeDecodeError, OSError, KeyError):
        return None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def location_ok(root, manifest: dict, loc: dict) -> bool:
    lines = head_lines(root, manifest, loc["path"])
    if lines is None:
        return False
    end = loc.get("endLine", loc["line"])
    return 1 <= loc["line"] <= end <= len(lines)


def anchor_text(root, manifest: dict, path: str, start: int, end: int) -> str | None:
    lines = head_lines(root, manifest, path)
    if lines is None or not 1 <= start <= end <= len(lines):
        return None
    return "\n".join(lines[start - 1:end])
