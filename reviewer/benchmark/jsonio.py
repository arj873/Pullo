"""Bounded, read-only file and JSON helpers shared by the loaders. Nothing here writes next to its input."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from .errors import BenchmarkError

MAX_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 12
MAX_NODES = 5_000_000


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - Git object id, not a security hash


def sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_regular(path, *, limit: int = MAX_BYTES) -> bytes:
    """Read a regular, non-symlink file of at most `limit` bytes (checked on the open descriptor)."""
    p = Path(path)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise BenchmarkError("io", f"cannot open {p.name}: {e.strerror}") from e
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise BenchmarkError("io", f"{p.name} is not a regular file")
        if st.st_size > limit:
            raise BenchmarkError("size", f"{p.name} is {st.st_size} bytes, over the {limit} bound")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise BenchmarkError("size", f"{p.name} grew past the {limit} bound while reading")
    return data


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise BenchmarkError("json", f"duplicate object key {k[:60]!r}")
        out[k] = v
    return out


def _bad_const(name):
    raise BenchmarkError("json", f"non-finite number {name}")


def _check(v, depth, counter):
    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise BenchmarkError("json", "too many JSON nodes")
    if depth > MAX_DEPTH:
        raise BenchmarkError("json", f"nesting deeper than {MAX_DEPTH}")
    if isinstance(v, dict):
        for x in v.values():
            _check(x, depth + 1, counter)
    elif isinstance(v, list):
        for x in v:
            _check(x, depth + 1, counter)


def parse_json(data: bytes, what: str = "document"):
    try:
        v = json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_bad_const)
    except BenchmarkError:
        raise
    except (ValueError, RecursionError) as e:
        raise BenchmarkError("json", f"{what} is not valid JSON: {str(e)[:120]}") from e
    _check(v, 0, [0])
    return v


def load_json(path, what: str = "document", *, limit: int = MAX_BYTES):
    return parse_json(read_regular(path, limit=limit), what)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(obj) -> str:
    return sha256_of(canonical(obj))


def write_new(path, obj, *, forbidden=()) -> str:
    """Write JSON with O_EXCL. Refuses a path inside (or equal to) any forbidden root."""
    p = Path(path).resolve(strict=False)
    for root in forbidden:
        r = Path(root).resolve(strict=False)
        if p == r or r in p.parents:
            raise BenchmarkError("boundary", f"output {p.name} is inside a forbidden root {r.name}")
    data = (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        raise BenchmarkError("io", f"cannot create {p.name}: {e.strerror}") from e
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return sha256_of(data)
