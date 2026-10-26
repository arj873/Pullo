"""Pure Git object helpers: tree parsing and offline tree-id reconstruction from leaf entries."""

from __future__ import annotations

import re

from .errors import RepoImportError
from .gitrun import oid_of

DIR_MODE = "40000"
_MODE = re.compile(r"[0-7]{5,6}")
_OID = re.compile(r"[0-9a-f]{40}")


def parse_tree(data: bytes) -> list[tuple[str, bytes, str]]:
    """[(mode, name, oid)] of a raw tree object. Malformed or duplicate entries refuse the import."""
    out, seen, i, n = [], set(), 0, len(data)
    while i < n:
        sp = data.find(b" ", i)
        nul = data.find(b"\0", sp + 1) if sp >= 0 else -1
        if sp < 0 or nul < 0 or nul + 21 > n:
            raise RepoImportError("malformed-object", "truncated tree entry")
        mode = data[i:sp].decode("ascii", "replace")
        name = data[sp + 1:nul]
        if not _MODE.fullmatch(mode) or not name or b"/" in name:
            raise RepoImportError("malformed-object", "bad tree entry mode or name")
        if name in seen:
            raise RepoImportError("malformed-object", "duplicate name in a tree")
        seen.add(name)
        out.append((mode, name, data[nul + 1:nul + 21].hex()))
        i = nul + 21
    return out


def tree_oid_from_leaves(leaves) -> str:
    """Recompute the root tree id from [(mode, oid, path_bytes)]; a mode-40000 leaf is an opaque subtree."""
    root: dict = {}
    for mode, oid, path in leaves:
        parts = path.split(b"/")
        node = root
        for p in parts[:-1]:
            nxt = node.setdefault(p, {})
            if not isinstance(nxt, dict):
                raise RepoImportError("malformed-object", "entry below a non-tree")
            node = nxt
        if parts[-1] in node:
            raise RepoImportError("malformed-object", "duplicate leaf path")
        node[parts[-1]] = (mode, oid)

    def enc(node: dict) -> str:
        items = []
        for name, v in node.items():
            if isinstance(v, dict):
                items.append((name + b"/", DIR_MODE, enc(v)))
            elif v[0] == DIR_MODE:
                items.append((name + b"/", DIR_MODE, v[1]))
            else:
                items.append((name, v[0], v[1]))
        body = b"".join(m.encode() + b" " + k.rstrip(b"/") + b"\0" + bytes.fromhex(o)
                        for k, m, o in sorted(items, key=lambda t: t[0]))
        return oid_of("tree", body)

    return enc(root)


def commit_tree_and_parents(raw: bytes) -> tuple[str, list[str]]:
    head = raw.split(b"\n\n", 1)[0].split(b"\n")
    if not head or not head[0].startswith(b"tree ") or not _OID.fullmatch(head[0][5:].decode("ascii", "replace")):
        raise RepoImportError("malformed-object", "commit has no tree header")
    parents = []
    for line in head[1:]:
        if line.startswith(b"parent "):
            p = line[7:].decode("ascii", "replace")
            if not _OID.fullmatch(p):
                raise RepoImportError("malformed-object", "bad parent header")
            parents.append(p)
    return head[0][5:].decode(), parents
