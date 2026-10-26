"""Immutable local snapshot identity and verified reads.

A snapshot id is `snap:sha256:<hex>` over the canonical, path-sorted list of
entries {path, type, size, sha256}. Symlinks are recorded (target text hashed)
and never followed, so hostile fixtures stay representable; resolving or
denying them is the tool layer's job (S0-06). Special files are rejected.

Race safety: the walk and `read_verified` open every component relative to its
parent directory descriptor with O_NOFOLLOW, and compare fstat of the opened
descriptor with the lstat taken during listing. A file swapped for a symlink
or a different inode mid-walk raises SnapshotError instead of being followed.
POSIX only (requires dir_fd support); other platforms raise SnapshotError.

The manifest is the only identity: a reader must use `read_verified`, which
checks the bytes against the manifest size and hash, rather than trusting the disk.
`read_verified` is bounded (pinned size, optional `max_bytes`; at most cap + 1
bytes read). `build_manifest` is trusted construction and has no byte cap of its
own: callers bound what they snapshot.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .canonical import canonical_json, sha256_hex
from .redaction import redact
from .schema import is_safe_relpath

MAX_ENTRIES = 200_000
MAX_DEPTH = 64
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class SnapshotError(ValueError):
    pass


def _require_posix() -> None:
    if not (_O_NOFOLLOW and _O_DIRECTORY and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd):
        raise SnapshotError("snapshots require POSIX O_NOFOLLOW/dir_fd support")


def snapshot_id(entries: list[dict]) -> str:
    keyed = [{"path": e["path"], "type": e["type"], "size": e["size"], "sha256": e["sha256"]}
             for e in entries]
    return "snap:sha256:" + sha256_hex(canonical_json(keyed))


def _same(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def _open_dir(name: str, dir_fd: int | None, expect: os.stat_result | None) -> int:
    try:
        fd = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)
    except OSError as e:
        raise SnapshotError(f"cannot open directory {name!r} without following links: {e}") from None
    if expect is not None and not _same(os.fstat(fd), expect):
        os.close(fd)
        raise SnapshotError(f"directory {name!r} changed during snapshot")
    return fd


def _read_regular(name: str, dir_fd: int, expect: os.stat_result | None,
                  limit: int | None = None) -> bytes:
    """Read a regular file without following links. With `limit`, a descriptor larger than
    `limit` bytes is refused before reading, and reading stops after limit + 1 bytes, so a file
    growing concurrently costs at most limit + 1 bytes and is refused."""
    try:
        fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK, dir_fd=dir_fd)
    except OSError as e:
        raise SnapshotError(f"cannot open {name!r} without following links: {e}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (expect is not None and not _same(st, expect)):
            raise SnapshotError(f"{name!r} changed during snapshot")
        if limit is not None and st.st_size > limit:
            raise SnapshotError(f"{name!r} is {st.st_size} bytes, above the {limit}-byte read cap")
        chunks, got = [], 0
        while limit is None or got <= limit:
            want = 1 << 16 if limit is None else min(1 << 16, limit + 1 - got)
            if not (chunk := os.read(fd, want)):
                break
            chunks.append(chunk)
            got += len(chunk)
        if limit is not None and got > limit:
            raise SnapshotError(f"{name!r} grew past the {limit}-byte read cap while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _walk(dir_fd: int, prefix: str, entries: list[dict], depth: int) -> None:
    if depth > MAX_DEPTH:
        raise SnapshotError(f"directory nesting deeper than {MAX_DEPTH}")
    with os.scandir(dir_fd) as it:
        names = sorted(e.name for e in it)
    for name in names:
        rel = prefix + name
        try:
            rel.encode("utf-8")
        except UnicodeEncodeError:
            raise SnapshotError(f"non-UTF-8 path in snapshot: {rel.encode('utf-8', 'replace')!r}") from None
        if not is_safe_relpath(rel):
            raise SnapshotError(f"unsafe path in snapshot: {rel!r}")
        if len(entries) >= MAX_ENTRIES:
            raise SnapshotError(f"more than {MAX_ENTRIES} entries")
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as e:
            raise SnapshotError(f"cannot stat {rel!r}: {e}") from None
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(name, dir_fd=dir_fd).encode("utf-8", "surrogateescape")
            except OSError as e:
                raise SnapshotError(f"{rel!r} changed during snapshot: {e}") from None
            entries.append({"path": rel, "type": "symlink", "size": len(target),
                            "sha256": hashlib.sha256(target).hexdigest()})
        elif stat.S_ISREG(st.st_mode):
            data = _read_regular(name, dir_fd, st)
            kind = "executable" if st.st_mode & 0o111 else "file"
            entries.append({"path": rel, "type": kind, "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        elif stat.S_ISDIR(st.st_mode):
            sub = _open_dir(name, dir_fd, st)
            try:
                _walk(sub, rel + "/", entries, depth + 1)
            finally:
                os.close(sub)
        else:
            raise SnapshotError(f"special file not allowed in snapshot: {rel}")


def build_manifest(root: str | os.PathLike) -> dict:
    """Walk `root` without following links and return a SnapshotManifest document."""
    _require_posix()
    root = Path(root)
    fd = _open_dir(os.fspath(root), None, None)
    try:
        entries: list[dict] = []
        _walk(fd, "", entries, 0)
    finally:
        os.close(fd)
    entries.sort(key=lambda e: e["path"])
    return {"schema": "snapshot-manifest@1", "snapshotId": snapshot_id(entries),
            "entries": entries}


def verify_manifest(root: str | os.PathLike, manifest: dict) -> list[str]:
    """Problems if the tree at `root` no longer matches `manifest` (empty = identical)."""
    try:
        now = build_manifest(root)
    except SnapshotError as e:
        return [str(e)]
    if now["snapshotId"] == manifest.get("snapshotId"):
        return []
    want = {e["path"]: e for e in manifest.get("entries", [])}
    have = {e["path"]: e for e in now["entries"]}
    diff = sorted(p for p in want.keys() | have.keys() if want.get(p) != have.get(p))
    return [f"changed: {p}" for p in diff[:20]] or ["snapshot id mismatch"]


def read_verified(root: str | os.PathLike, manifest: dict, path: str, *,
                  max_bytes: int | None = None) -> bytes:
    """Read a regular file named in `manifest` without following any link, and check its
    bytes against the manifest size and hash. Symlink entries and unlisted paths are refused.

    Bounded: the read cap is the pinned entry size, or `max_bytes` when that is smaller, in
    which case the file is refused before it is opened. A descriptor larger than the cap is
    refused before reading, at most cap + 1 bytes are ever read (a file growing concurrently is
    refused), and a byte length other than the pinned size is refused before hashing."""
    _require_posix()
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise ValueError("max_bytes must be a non-negative int")
    if not is_safe_relpath(path):
        raise SnapshotError(f"unsafe path {path!r}")
    entry = next((e for e in manifest.get("entries", []) if e["path"] == path), None)
    if entry is None or entry["type"] == "symlink":
        raise SnapshotError(f"{path!r} is not a regular file in this snapshot")
    size = entry["size"]
    if type(size) is not int or size < 0:
        raise SnapshotError(f"{path!r} has no valid pinned size")
    if max_bytes is not None and size > max_bytes:
        raise SnapshotError(f"{path!r} is pinned at {size} bytes, above max_bytes={max_bytes}")
    parts = path.split("/")
    fd = _open_dir(os.fspath(root), None, None)
    try:
        for part in parts[:-1]:
            nxt = _open_dir(part, fd, None)
            os.close(fd)
            fd = nxt
        data = _read_regular(parts[-1], fd, None, limit=size)
    finally:
        os.close(fd)
    if len(data) != size:
        raise SnapshotError(f"{path!r} is {len(data)} bytes, pinned at {size}")
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise SnapshotError(f"{path!r} does not match the snapshot")
    return data


def snapshot_resolver(trees: dict[str, tuple[str | os.PathLike, dict]]):
    """Resolver for severity.materialize_evidence. `trees` maps a snapshot id (this run's base
    and head only) to (root, manifest). A citation resolves when its commit is one of those
    snapshots, the file is read through read_verified, and the redacted lines equal the excerpt."""
    def resolve(ev: dict) -> bool:
        tree = trees.get(ev.get("commit"))
        if tree is None or ev.get("kind") != "code":
            return False
        root, manifest = tree
        try:
            data = read_verified(root, manifest, ev["path"])
        except (SnapshotError, KeyError, OSError):
            return False
        return excerpt_matches(data, ev["lines"], ev["excerpt"])
    return resolve


def excerpt_matches(file_bytes: bytes, lines: list[int], excerpt: str) -> bool:
    """Citation check: the redacted file lines [start, end] exist and the (already redacted)
    excerpt equals them joined with "\\n", either exactly or plus one terminating "\\n". A range
    that ends on a blank line joins to text ending in "\\n", which is matched exactly, not stripped.
    A file's final newline ends its last line; it does not start another, so lines past EOF never
    resolve."""
    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    start, end = lines
    redacted = redact(text)[0]
    all_lines = redacted.split("\n")
    if redacted.endswith("\n") or redacted == "":
        all_lines.pop()
    if start < 1 or end < start or end > len(all_lines):
        return False
    joined = "\n".join(all_lines[start - 1:end])
    return joined == excerpt or (excerpt.endswith("\n") and joined == excerpt[:-1])
