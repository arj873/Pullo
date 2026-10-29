"""Regex-free identifier handling for find_references and the impact scan.

A model-supplied symbol is validated character by character and matched with str.find plus explicit boundary
checks, so no model text is ever compiled into a pattern (the tool package has no regular expressions at all).

Word boundary: identifier characters are ASCII letters, digits, `_` and `$`. A symbol that itself contains `.` or
`-` (a configuration key such as `max-retries`) is also bounded by those, so it does not match inside
`max-retries-total`.
"""

from __future__ import annotations

ID_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_$")
ID_CHARS = ID_START | frozenset("0123456789")
JOINERS = frozenset(".-")


def valid_symbol(sym, max_chars: int) -> bool:
    """One identifier, or identifier parts joined by single `.` or `-` (no leading/trailing/double joiner)."""
    if not isinstance(sym, str) or not 1 <= len(sym) <= max_chars or sym[0] not in ID_START:
        return False
    prev_join = False
    for c in sym:
        if c in JOINERS:
            if prev_join:
                return False
            prev_join = True
        elif c in ID_CHARS:
            prev_join = False
        else:
            return False
    return not prev_join


def _bound(name: str) -> frozenset:
    return ID_CHARS | JOINERS if any(c in JOINERS for c in name) else ID_CHARS


def has_word(line: str, name: str) -> bool:
    bound, start, n = _bound(name), 0, len(name)
    while True:
        i = line.find(name, start)
        if i < 0:
            return False
        j = i + n
        if (i == 0 or line[i - 1] not in bound) and (j == len(line) or line[j] not in bound):
            return True
        start = i + 1


def word_hits(line: str, names) -> list[str]:
    """Sorted names that occur in `line` as whole words."""
    return sorted(nm for nm in names if nm in line and has_word(line, nm))
