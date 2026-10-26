"""Isolated, bounded Git execution. Argument arrays only (shell=False); bounded wall time, stdout, stderr and
object-store size. HOME and CODEX_HOME are inherited unchanged: isolation comes from explicit config, env and options."""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .errors import RepoImportError

ENV_ALLOW = ("PATH", "HOME", "CODEX_HOME", "LANG", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
             "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")
ENV_FORCE = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "SSH_ASKPASS": "/bin/false",
    "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_LFS_SKIP_SMUDGE": "1", "LC_ALL": "C",
}
BASE_OPTS = (
    "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null",
    "-c", "core.excludesFile=/dev/null", "-c", "credential.helper=", "-c", "credential.interactive=never",
    "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.version=2",
    "-c", "http.sslVerify=true", "-c", "http.followRedirects=initial",
    "-c", "transfer.fsckObjects=true", "-c", "fetch.fsckObjects=true", "-c", "receive.fsckObjects=true",
    "-c", "fetch.unpackLimit=1", "-c", "transfer.unpackLimit=1", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
    "-c", "fetch.recurseSubmodules=false", "-c", "submodule.recurse=false", "-c", "fetch.writeCommitGraph=false",
)
LOCAL_FIXTURE_OPTS = ("-c", "protocol.file.allow=always")


def git_env(environ=None) -> dict:
    src = os.environ if environ is None else environ
    env = {k: src[k] for k in ENV_ALLOW if k in src}
    env.update(ENV_FORCE)
    return env


def git_argv(git_dir, args, *, local_fixture=False) -> list:
    return ["git", "--git-dir", os.fspath(git_dir), *BASE_OPTS, *(LOCAL_FIXTURE_OPTS if local_fixture else ()), *args]


def oid_of(kind: str, data: bytes) -> str:
    h = hashlib.sha1(usedforsecurity=False)
    h.update(f"{kind} {len(data)}\0".encode())
    h.update(data)
    return h.hexdigest()


def tree_size(path, stop_over: int) -> int:
    """Bytes under `path` (no link following); stops early once over `stop_over`."""
    total, stack = 0, [os.fspath(path)]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
        if total > stop_over:
            return total
    return total


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _drain(stream, cap: int, sink: bytearray, over: threading.Event) -> None:
    try:
        while chunk := stream.read(1 << 16):
            room = cap - len(sink)
            if room > 0:
                sink += chunk[:room]
            if len(chunk) > room:
                over.set()
    except (OSError, ValueError):
        pass


@dataclass(frozen=True)
class Done:
    returncode: int
    stdout: bytes
    stderr: bytes


def run(argv, *, env, timeout: float, max_stdout: int, max_stderr: int = 64 << 10, cwd=None,
        watch: Callable[[], None] | None = None, interval: float = 0.2) -> Done:
    """Run `argv` (shell=False) with bounded time/stdout/stderr. `watch` may raise to abort (the process group is
    killed). stdout beyond the cap is a refusal, not a truncation."""
    proc = subprocess.Popen(list(argv), shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, cwd=cwd, close_fds=True, start_new_session=True)
    out, err = bytearray(), bytearray()
    out_over, err_over = threading.Event(), threading.Event()
    threads = [threading.Thread(target=_drain, args=(proc.stdout, max_stdout, out, out_over), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, max_stderr, err, err_over), daemon=True)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                proc.wait(timeout=interval)
                break
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() > deadline:
                _kill(proc)
                raise RepoImportError("timeout", f"git exceeded {timeout:g}s")
            if out_over.is_set():
                _kill(proc)
                raise RepoImportError("too-large", f"git output exceeded {max_stdout} bytes")
            if watch is not None:
                watch()
    except BaseException:
        _kill(proc)
        proc.wait()
        raise
    finally:
        for t in threads:
            t.join(timeout=5)
        for s in (proc.stdout, proc.stderr):
            try:
                s.close()
            except OSError:
                pass
    if out_over.is_set():
        raise RepoImportError("too-large", f"git output exceeded {max_stdout} bytes")
    return Done(proc.returncode, bytes(out), bytes(err))


class ObjectReader:
    """`git cat-file --batch-command` over one bare store: every object is size-checked first (`info`), read only
    when wanted, and its SHA-1 recomputed. A watchdog kills the process at the deadline."""

    def __init__(self, git_dir, *, env, timeout: float, max_stderr: int = 64 << 10):
        self._proc = subprocess.Popen(git_argv(git_dir, ["cat-file", "--batch-command"]), shell=False,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=env, close_fds=True, start_new_session=True)
        self._err, self._over = bytearray(), threading.Event()
        threading.Thread(target=_drain, args=(self._proc.stderr, max_stderr, self._err, self._over), daemon=True).start()
        self.timed_out = False
        self._timer = threading.Timer(timeout, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        self.timed_out = True
        _kill(self._proc)

    def _fail(self, what: str):
        if self.timed_out:
            raise RepoImportError("timeout", "object reading exceeded its deadline")
        raise RepoImportError("git-failed", f"{what}: {bytes(self._err)[:300].decode('utf-8', 'replace')}")

    def _cmd(self, line: str) -> bytes:
        try:
            self._proc.stdin.write(line.encode() + b"\n")
            self._proc.stdin.flush()
            head = self._proc.stdout.readline(256)
        except (OSError, ValueError):
            self._fail("cat-file pipe")
        if not head.endswith(b"\n"):
            self._fail("cat-file ended")
        return head[:-1]

    def info(self, oid: str):
        """(type, size) or None when the object is absent."""
        parts = self._cmd(f"info {oid}").split(b" ")
        if len(parts) == 2 and parts[1] == b"missing":
            return None
        if len(parts) != 3 or parts[0].decode("ascii", "replace") != oid or not parts[2].isdigit():
            raise RepoImportError("malformed-object", "unexpected cat-file info reply")
        return parts[1].decode("ascii", "replace"), int(parts[2])

    def read(self, oid: str, kind: str, size: int) -> bytes:
        """Object bytes; the caller supplies the size from `info` (already capped). SHA-1 identity is checked."""
        parts = self._cmd(f"contents {oid}").split(b" ")
        if len(parts) != 3 or parts[0].decode("ascii", "replace") != oid or parts[1].decode() != kind \
                or not parts[2].isdigit() or int(parts[2]) != size:
            raise RepoImportError("malformed-object", "cat-file contents header disagrees with info")
        try:
            data = self._proc.stdout.read(size)
            tail = self._proc.stdout.read(1)
        except (OSError, ValueError):
            self._fail("cat-file read")
        if len(data) != size or tail != b"\n":
            self._fail("cat-file truncated object")
        if oid_of(kind, data) != oid:
            raise RepoImportError("identity-mismatch", f"{kind} {oid} does not hash to its id")
        return data

    def close(self):
        self._timer.cancel()
        try:
            self._proc.stdin.close()
        except OSError:
            pass
        _kill(self._proc)
        self._proc.wait()
        for s in (self._proc.stdout, self._proc.stderr):
            try:
                s.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
