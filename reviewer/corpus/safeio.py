"""Local writes/reads that cannot escape the output root or follow symlinks (dir_fd + O_NOFOLLOW)."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path

from reviewer.contracts.schema import is_safe_relpath

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class PathError(ValueError):
    pass


def check_rel(rel: str) -> str:
    if not is_safe_relpath(rel):
        raise PathError(f"unsafe relative path: {rel!r}")
    for seg in rel.split("/"):
        if seg.lower() == ".git" or len(seg) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in seg):
            raise PathError(f"disallowed path segment in {rel!r}")
    return rel


def _open_root(root) -> int:
    try:
        return os.open(os.fspath(root), _DIR)
    except OSError as e:
        raise PathError(f"root is not a real directory: {root}: {e.strerror}") from e


def _walk(fd: int, parts: list[str], create: bool) -> int:
    fd = os.dup(fd)
    try:
        for p in parts:
            if create:
                try:
                    os.mkdir(p, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                nfd = os.open(p, _DIR, dir_fd=fd)
            except OSError as e:
                raise PathError(f"cannot enter {p!r}: {e.strerror}") from e
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_file(root, rel: str, data: bytes, *, replace: bool = False) -> None:
    parts = check_rel(rel).split("/")
    rfd = _open_root(root)
    try:
        dfd = _walk(rfd, parts[:-1], True)
        try:
            name = parts[-1]
            tmp = f".{name[:100]}.{os.getpid()}.{secrets.token_hex(4)}.tmp" if replace else name
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o644, dir_fd=dfd)
            except OSError as e:
                raise PathError(f"cannot create {rel!r}: {e.strerror}") from e
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                if replace:
                    os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except BaseException:
                if replace:
                    try:
                        os.unlink(tmp, dir_fd=dfd)
                    except OSError:
                        pass
                raise
        finally:
            os.close(dfd)
    finally:
        os.close(rfd)


def read_file(root, rel: str, max_bytes: int = 64 << 20) -> bytes:
    parts = check_rel(rel).split("/")
    rfd = _open_root(root)
    try:
        dfd = _walk(rfd, parts[:-1], False)
        try:
            try:
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
            except OSError as e:
                raise PathError(f"cannot read {rel!r}: {e.strerror}") from e
            with os.fdopen(fd, "rb") as f:
                data = f.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise PathError(f"{rel!r} exceeds {max_bytes} bytes")
            return data
        finally:
            os.close(dfd)
    finally:
        os.close(rfd)


def write_json(root, rel: str, doc, *, replace: bool = False) -> None:
    data = (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    write_file(root, rel, data, replace=replace)


def read_json(root, rel: str):
    return json.loads(read_file(root, rel).decode("utf-8"))


def tree_digest(root, exclude: tuple[str, ...] = ()) -> str:
    """Digest of (path, sha256) for every regular file; symlinks/special files are errors."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise PathError(f"not a real directory: {root}")
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                raise PathError(f"symlink in tree: {p}")
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            if any(rel == x or rel.startswith(x + "/") for x in exclude):
                continue
            if not p.is_file():
                raise PathError(f"special file in tree: {p}")
            entries.append((rel, hashlib.sha256(p.read_bytes()).hexdigest()))
    entries.sort()
    return hashlib.sha256(json.dumps(entries).encode()).hexdigest()
