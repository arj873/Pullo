"""Strict unified-diff applier used to prove a redacted patch still maps redacted base to redacted head."""

from __future__ import annotations

import re

_HDR = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _lines(text: str) -> list[str]:
    ls = text.split("\n")
    if ls and ls[-1] == "":
        ls.pop()
    return ls


def _items(text: str) -> list[tuple[str, bool]]:
    """(line, ends-with-newline) pairs; only the last line can lack its newline."""
    ls = text.split("\n")
    last = ls.pop()
    out = [(l, True) for l in ls]
    if last:
        out.append((last, False))
    return out


def _apply_items(base: str, patch: str) -> list[tuple[str, bool]] | None:
    src, pl = _items(base), _lines(patch)
    out, i, k = [], 0, 0
    if not pl or not _HDR.match(pl[0]):
        return None
    while k < len(pl):
        m = _HDR.match(pl[k])
        if not m:
            return None
        k += 1
        old_start, old_len = int(m[1]), int(m[2]) if m[2] is not None else 1
        new_len = int(m[4]) if m[4] is not None else 1
        start = old_start - 1 if old_len else old_start
        if start < i or start > len(src):
            return None
        out += src[i:start]
        i = start
        o = n = 0
        while k < len(pl) and not pl[k].startswith("@@"):
            l, k = pl[k], k + 1
            if l.startswith("\\"):
                continue
            c, body = l[:1], l[1:]
            # A following "\ No newline at end of file" marker removes this line's newline.
            item = (body, not (k < len(pl) and pl[k].startswith("\\")))
            if c == "+":
                out.append(item)
                n += 1
            elif c in ("-", " "):
                if i >= len(src) or src[i] != item:
                    return None
                i += 1
                o += 1
                if c == " ":
                    out.append(item)
                    n += 1
            else:
                return None
        if (o, n) != (old_len, new_len):
            return None
    return out + src[i:]


def apply_patch(base: str, patch: str) -> list[str] | None:
    """Return the patched lines, or None if the patch is malformed or does not apply."""
    got = _apply_items(base, patch)
    return None if got is None else [l for l, _ in got]


def reconstructs(base: str, patch: str, head: str) -> bool:
    """True when the patch turns base into head byte for byte, final newline included."""
    got = _apply_items(base, patch)
    return got is not None and got == _items(head)


def count_changes(patch: str) -> tuple[int, int] | None:
    """(added, removed) line counts of a headerless unified diff, walking hunks by their header
    counts so content such as '+++x' or '---x' is counted as a change line. None if malformed."""
    pl = _lines(patch)
    adds = dels = k = 0
    if not pl:
        return None
    while k < len(pl):
        m = _HDR.match(pl[k])
        if not m:
            return None
        k += 1
        old_left = int(m[2]) if m[2] is not None else 1
        new_left = int(m[4]) if m[4] is not None else 1
        while old_left or new_left or (k < len(pl) and pl[k].startswith("\\")):
            if k >= len(pl):
                return None
            c, k = pl[k][:1], k + 1
            if c == "\\":
                continue
            if c == "+":
                new_left, adds = new_left - 1, adds + 1
            elif c == "-":
                old_left, dels = old_left - 1, dels + 1
            elif c in (" ", ""):
                old_left, new_left = old_left - 1, new_left - 1
            else:
                return None
            if old_left < 0 or new_left < 0:
                return None
    return adds, dels
