"""Walk a verified pinned tree and write it. Every object is hash-checked as it is read; nothing is checked out, no
filter/hook/LFS/submodule code runs, symlinks are written as links and never followed."""

from __future__ import annotations

import hashlib
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts.redaction import redact
from reviewer.contracts.schema import is_safe_relpath
from reviewer.contracts.snapshot import MAX_DEPTH, SnapshotError, build_manifest, snapshot_id

from .errors import RepoImportError
from .fsio import TreeWriter
from .gitobjects import DIR_MODE, parse_tree
from .policy import ImportPolicy
from .redactcheck import probe

FILE_MODES = {"100644": "file", "100755": "executable"}
LINK_MODE, SUBMODULE_MODE = "120000", "160000"
LFS_MAGIC = b"version https://git-lfs.github.com/spec/v1\n"
_ASSERT_DEPTH = MAX_DEPTH


@dataclass
class Leaf:
    pb: bytes
    mode: str
    oid: str
    path: str | None = None
    kind: str | None = None          # omission kind once omitted
    reason: str | None = None
    size: int = 0


def _bad_component(name: bytes) -> str | None:
    try:
        s = name.decode("utf-8")
    except UnicodeDecodeError:
        return "non-utf8"
    if len(name) > 255:
        return "name-too-long"
    if s in (".", ".."):
        return "dot-segment"
    plain = "".join(c for c in s if unicodedata.category(c) != "Cf").casefold().rstrip(". ")
    if plain in (".git", "git~1"):
        return "dot-git"
    if not is_safe_relpath(s):
        return "unsafe-name"
    return None


def walk(reader, tree_oid: str, policy: ImportPolicy):
    """(leaves, tree entries visited). A directory that is unsafe or too deep is kept as one opaque mode-40000 leaf."""
    leaves: list[Leaf] = []
    visited = 0
    stack = [(b"", tree_oid, 0)]
    while stack:
        prefix, oid, depth = stack.pop()
        info = reader.info(oid)
        if info is None:
            raise RepoImportError("incomplete-store", f"tree {oid} is missing from the fetched objects")
        if info[0] != "tree":
            raise RepoImportError("malformed-object", f"{oid} is a {info[0]}, expected a tree")
        if info[1] > policy.max_tree_object_bytes:
            raise RepoImportError("too-large", f"tree object above {policy.max_tree_object_bytes} bytes")
        for mode, name, eoid in parse_tree(reader.read(oid, "tree", info[1])):
            visited += 1
            if visited > policy.max_tree_entries:
                raise RepoImportError("too-large", f"more than {policy.max_tree_entries} tree entries")
            full = prefix + name
            if mode == DIR_MODE:
                why = _bad_component(name)
                if why is None and depth + 1 > policy.max_depth:
                    why = "depth"
                if why is not None:
                    leaves.append(Leaf(full, DIR_MODE, eoid, kind="unsafe", reason=why))
                else:
                    stack.append((full + b"/", eoid, depth + 1))
                continue
            leaves.append(Leaf(full, mode, eoid))
            if len(leaves) > policy.max_files:
                raise RepoImportError("too-large", f"more than {policy.max_files} files in the pinned tree")
    leaves.sort(key=lambda l: l.pb)
    return leaves, visited


def _fold(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def classify(leaves: list[Leaf]) -> None:
    eligible = []
    for l in leaves:
        if l.kind is not None:
            continue
        if l.mode == SUBMODULE_MODE:
            l.kind = "submodule"
        elif l.mode not in FILE_MODES and l.mode != LINK_MODE:
            l.kind, l.reason = "unsupported", f"mode {l.mode}"
        else:
            why = next((w for c in l.pb.split(b"/") if (w := _bad_component(c))), None)
            if why is None:
                l.path = l.pb.decode("utf-8")
                if not is_safe_relpath(l.path):
                    why = "unsafe-path"
                elif l.path.count("/") > MAX_DEPTH - 2:
                    why = "depth"
            if why is not None:
                l.kind, l.reason, l.path = "unsafe", why, None
            else:
                eligible.append(l)
    for l in leaves:                                  # display paths for pre-omitted but decodable entries
        if l.path is None and l.kind in ("submodule", "unsupported", "unsafe") \
                and all(_bad_component(c) is None for c in l.pb.split(b"/")):
            l.path = l.pb.decode("utf-8")
    groups: dict[str, list[Leaf]] = {}
    for l in eligible:
        groups.setdefault(_fold(l.path), []).append(l)
    bad: set[int] = set()
    for key, ls in groups.items():
        if len(ls) > 1:
            bad.update(id(x) for x in ls)
        parts = key.split("/")
        for i in range(1, len(parts)):
            if (pre := "/".join(parts[:i])) in groups:
                bad.update(id(x) for x in groups[pre])
                bad.update(id(x) for x in ls)
    for l in eligible:
        if id(l) in bad:
            l.kind, l.reason = "colliding", "case-or-unicode-fold"


def _line_anchor(text: str) -> int | None:
    r = probe(text)
    return r[0] if r else None


def materialize(reader, tree_oid: str, tree_dir: Path, policy: ImportPolicy):
    """Write the tree under `tree_dir` (must not exist). Returns a dict of everything the record needs."""
    leaves, visited = walk(reader, tree_oid, policy)
    classify(leaves)
    deadline = time.monotonic() + policy.read_timeout_s
    writer = TreeWriter(tree_dir)
    entries, anchors, rcounts = [], {}, {}
    total = lines = verified = scanned = with_redactions = line_mismatches = 0
    try:
        for l in leaves:
            if time.monotonic() > deadline:
                raise RepoImportError("timeout", "materialization exceeded its deadline")
            if l.mode in (DIR_MODE, SUBMODULE_MODE):
                continue
            info = reader.info(l.oid)
            if info is None:
                raise RepoImportError("incomplete-store", f"blob {l.oid} is missing from the fetched objects")
            if info[0] != "blob":
                raise RepoImportError("malformed-object", f"{l.oid} is a {info[0]}, expected a blob")
            l.size = info[1]
            if l.kind is not None:
                continue
            if l.mode == LINK_MODE:
                if l.size > policy.max_symlink_bytes:
                    l.kind, l.reason = "unsafe", "symlink-size"
                    continue
                target = reader.read(l.oid, "blob", l.size)
                verified += 1
                try:
                    t = target.decode("utf-8")
                except UnicodeDecodeError:
                    t = ""
                if not t or "\0" in t:
                    l.kind, l.reason = "unsafe", "symlink-target"
                    continue
                writer.link(l.path, t)
                entries.append({"path": l.path, "type": "symlink", "size": len(target),
                                "sha256": hashlib.sha256(target).hexdigest()})
                total += len(target)
                continue
            if l.size > policy.max_file_bytes:
                l.kind = "oversize"
                continue
            data = reader.read(l.oid, "blob", l.size)
            verified += 1
            if l.size <= 1024 and data.startswith(LFS_MAGIC) and b"\noid sha256:" in data:
                l.kind = "lfs"
                continue
            if b"\0" in data:
                l.kind, l.reason = "binary", "nul"
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                l.kind, l.reason = "binary", "invalid-utf8"
                continue
            res = probe(text)
            if res is None:
                l.kind, l.reason = "redaction", "line-count-not-preserved"
                line_mismatches += 1
                continue
            n, counts = res
            if total + len(data) > policy.max_total_bytes:
                raise RepoImportError("too-large", f"more than {policy.max_total_bytes} bytes of text in the pinned tree")
            scanned += 1
            if counts:
                with_redactions += 1
                for k, v in counts.items():
                    rcounts[k] = rcounts.get(k, 0) + v
            writer.put(l.path, data, FILE_MODES[l.mode] == "executable")
            entries.append({"path": l.path, "type": FILE_MODES[l.mode], "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
            anchors[l.path] = n
            lines += n
            total += len(data)
        writer.seal()
    except BaseException:
        writer.close()
        raise
    entries.sort(key=lambda e: e["path"])
    manifest = {"schema": "snapshot-manifest@1", "snapshotId": snapshot_id(entries), "entries": entries}
    try:
        built = build_manifest(tree_dir)
    except SnapshotError as e:
        raise RepoImportError("internal", f"written tree cannot be re-read: {e}") from None
    if built != manifest:
        raise RepoImportError("internal", "written tree differs from the computed manifest")
    return {"leaves": leaves, "visited": visited, "entries": entries, "manifest": manifest, "anchors": anchors,
            "bytes": total, "lines": lines, "verified": verified,
            "redaction": {"filesScanned": scanned, "filesWithRedactions": with_redactions,
                          "counts": dict(sorted(rcounts.items())), "lineMismatches": line_mismatches}}
