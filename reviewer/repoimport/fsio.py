"""No-follow tree writer and small file helpers."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class TreeWriter:
    """Creates `root` (must not exist) and writes files/links relative to descriptors without following links."""

    def __init__(self, root: Path):
        os.mkdir(root, 0o700)
        self._rfd = os.open(root, DIR_FLAGS)
        self._dirs: set[str] = set()
        self._cache: dict[str, int] = {}

    def _dir(self, parts) -> int:
        key = "/".join(parts)
        if key in self._cache:
            return self._cache[key]
        parent = self._dir(parts[:-1]) if parts else self._rfd
        if not parts:
            return self._rfd
        try:
            os.mkdir(parts[-1], 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        fd = os.open(parts[-1], DIR_FLAGS, dir_fd=parent)
        self._cache[key] = fd
        self._dirs.add(key)
        return fd

    def put(self, path: str, data: bytes, executable: bool) -> None:
        parts = path.split("/")
        dfd = self._dir(parts[:-1])
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fchmod(fd, 0o555 if executable else 0o444)
        finally:
            os.close(fd)

    def link(self, path: str, target: str) -> None:
        parts = path.split("/")
        os.symlink(target, parts[-1], dir_fd=self._dir(parts[:-1]))

    def seal(self) -> None:
        for key in sorted(self._dirs, key=lambda d: -d.count("/")):
            os.fchmod(self._cache[key], 0o555)
        os.fchmod(self._rfd, 0o555)
        self.close()

    def close(self) -> None:
        for fd in list(self._cache.values()) + [self._rfd]:
            try:
                os.close(fd)
            except OSError:
                pass
        self._cache.clear()


def force_remove(path) -> None:
    """Delete a tree this package created (restores owner write bits first; never follows links)."""
    path = Path(path)
    if not os.path.lexists(path) or path.is_symlink():
        return
    for dirpath, dirnames, _ in os.walk(path, followlinks=False):
        os.chmod(dirpath, 0o700)
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if not os.path.islink(p):
                os.chmod(p, 0o700)
    shutil.rmtree(path)


def read_nofollow(path, cap: int) -> bytes:
    """Bytes of a regular, non-link file of at most `cap` bytes (never blocks on a FIFO)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise OSError(f"{Path(path).name} cannot be opened as a regular file") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            raise OSError(f"{Path(path).name} is not a regular file within {cap} bytes")
        chunks, got = [], 0
        while got <= cap and (chunk := os.read(fd, min(1 << 16, cap + 1 - got))):
            chunks.append(chunk)
            got += len(chunk)
        if got > cap:
            raise OSError(f"{Path(path).name} grew past {cap} bytes")
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_new(path, data: bytes, mode: int = 0o444) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
