"""Host-owned output directory: containment, symlink refusal, atomic writes, bounded reads.

Layout under `out_root/<runId>/`: trace.jsonl, artifacts/NN-STAGE.vP.json, comments.json, review.md, run.json,
receipt.json. Nothing here is ever created inside a snapshot root or any `forbidden_roots` entry.
All files except trace.jsonl (an append-only Recorder file) are written tmp + fsync + rename.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from reviewer.contracts import ContractInputError, loads_strict

from .errors import PipelineError

MAX_READ_BYTES = 16 << 20       # JSON input limit for every artifact the pipeline reads back
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def resolve_out_root(out_root, forbidden) -> Path:
    """Real path of the output root; refused when it is (inside, or an ancestor of) any forbidden root or is no
    directory. A sibling directory of an input (e.g. a labels dir) is only protected when the host lists it in
    forbidden_roots: the pipeline cannot know what a host keeps next to its snapshots."""
    p = Path(out_root)
    try:
        real = Path(os.path.realpath(p, strict=True))
    except OSError:
        raise PipelineError("path-escape", f"output root {str(p)!r} does not exist") from None
    if not real.is_dir():
        raise PipelineError("path-escape", "output root is not a directory")
    for f in forbidden:
        r = Path(os.path.realpath(f))
        if real == r or r in real.parents:
            raise PipelineError("path-escape", f"output root lies inside the input/fixture root {r}")
        if real in r.parents:
            raise PipelineError("path-escape", f"output root {real} contains the input/fixture root {r}: run "
                                "directories would be created beside protected inputs")
    return real


def sha256_file_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RunDir:
    """An exclusively created run directory addressed through directory file descriptors."""

    def __init__(self, real_out: Path, run_id: str, run_fd: int, created: bool):
        self.real_out, self.run_id, self._fd, self.created = real_out, run_id, run_fd, created
        self.path = real_out / run_id
        self._art_fd: int | None = None

    # ---- opening
    @classmethod
    def open(cls, real_out: Path, run_id: str, *, create: bool) -> "RunDir | None":
        """Existing directory, or (create=True) a new one made with mkdir (the exclusive lock).
        Returns None when absent and create is False. A symlink or non-directory is refused."""
        out_fd = os.open(real_out, _DIR)
        try:
            created = False
            if create:
                try:
                    os.mkdir(run_id, 0o700, dir_fd=out_fd)
                    created = True
                except FileExistsError:
                    pass
            try:
                fd = os.open(run_id, _DIR, dir_fd=out_fd)
            except FileNotFoundError:
                return None
            except OSError as e:
                raise PipelineError("path-escape", f"run directory is not a plain directory: {e.strerror}") from None
        finally:
            os.close(out_fd)
        return cls(real_out, run_id, fd, created)

    def close(self) -> None:
        for fd in (self._art_fd, self._fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._art_fd = self._fd = None

    def _artifacts_fd(self, create: bool) -> int | None:
        if self._art_fd is None:
            if create:
                try:
                    os.mkdir("artifacts", 0o700, dir_fd=self._fd)
                except FileExistsError:
                    pass
            try:
                self._art_fd = os.open("artifacts", _DIR, dir_fd=self._fd)
            except FileNotFoundError:
                return None
            except OSError as e:
                raise PipelineError("path-escape", f"artifacts is not a plain directory: {e.strerror}") from None
        return self._art_fd

    # ---- writing
    def _write(self, fd: int, name: str, data: bytes) -> str:
        if "/" in name or name in ("", ".", "..") or name.startswith("."):
            raise PipelineError("path-escape", f"bad output file name {name!r}")
        tmp = f".{name}.tmp{os.getpid()}"
        f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            with os.fdopen(f, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=fd)
            except OSError:
                pass
            raise
        os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        return sha256_file_bytes(data)

    def write(self, name: str, data: bytes) -> str:
        return self._write(self._fd, name, data)

    def write_artifact(self, name: str, data: bytes) -> str:
        return self._write(self._artifacts_fd(True), name, data)

    # ---- reading (bounded, no symlinks)
    def _read(self, fd: int | None, name: str) -> bytes | None:
        if fd is None:
            return None
        try:
            f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise PipelineError("checkpoint-invalid", f"{name}: cannot open ({e.strerror})") from None
        with os.fdopen(f, "rb") as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PipelineError("checkpoint-invalid", f"{name}: not a regular file")
            data = fh.read(MAX_READ_BYTES + 1)
        if len(data) > MAX_READ_BYTES:
            raise PipelineError("checkpoint-invalid", f"{name}: larger than the {MAX_READ_BYTES}-byte read limit")
        return data

    def read(self, name: str) -> bytes | None:
        return self._read(self._fd, name)

    def read_artifact(self, name: str) -> bytes | None:
        return self._read(self._artifacts_fd(False), name)

    def read_json(self, name: str, *, artifact: bool = False):
        data = self.read_artifact(name) if artifact else self.read(name)
        if data is None:
            return None
        try:
            return loads_strict(data)
        except ContractInputError as e:
            raise PipelineError("checkpoint-invalid", f"{name}: {e}") from None

    def remove(self, name: str) -> None:
        try:
            os.unlink(name, dir_fd=self._fd)
        except FileNotFoundError:
            pass

    def exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self._fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def move_aside(self, name: str, new: str) -> None:
        os.replace(name, new, src_dir_fd=self._fd, dst_dir_fd=self._fd)
        os.fsync(self._fd)

    def remove_empty(self) -> None:
        """Undo a directory this process created when nothing durable was written yet."""
        try:
            for n in os.listdir(self._fd):
                os.unlink(n, dir_fd=self._fd)
        except OSError:
            pass
        out_fd = os.open(self.real_out, _DIR)
        try:
            os.rmdir(self.run_id, dir_fd=out_fd)
        except OSError:
            pass
        finally:
            os.close(out_fd)
