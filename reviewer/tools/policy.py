"""What the investigator tools may name.

The authority is the supplied snapshot boundary: tools see only files listed in the pinned
manifest of an explicit root, reached without following links. Eval metadata (`source/`,
`labels/`) and host credentials live outside those roots and are unreachable by containment, not
by name. A repository folder that happens to be called `source/` or `labels/`, and committed
config or examples such as `.env.example`, are ordinary untrusted review data: readable, always
redacted, always with provenance. Only version-control internals are refused by name.
"""

from __future__ import annotations

from reviewer.contracts.redaction import contains_protected
from reviewer.contracts.schema import is_safe_relpath

MAX_PATH_CHARS = 512
VCS_DIRS = frozenset({".git", ".hg", ".svn"})


def denied_path(rel: str) -> bool:
    """True for VCS internals at any depth (case-insensitive)."""
    return any(p.lower() in VCS_DIRS for p in rel.split("/"))


def valid_path(rel) -> bool:
    """A name a model may use at all: safe relative path, bounded, no protected text."""
    return (isinstance(rel, str) and 0 < len(rel) <= MAX_PATH_CHARS and "\x00" not in rel
            and is_safe_relpath(rel) and not contains_protected(rel))


def permitted(rel) -> bool:
    return valid_path(rel) and not denied_path(rel)


def valid_prefix(prefix) -> bool:
    """'' (whole view) or a directory-style relative path; same rules as files."""
    return prefix == "" or permitted(prefix)
