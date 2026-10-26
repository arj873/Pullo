"""Local owned Git fixtures only: no network, no target code. Fixture Git runs with its own isolated env."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from reviewer.repoimport import fsio
from reviewer.repoimport.remote import local_fixture_remote

ENV = {"PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
       "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
       "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z", "LC_ALL": "C"}


def git(cwd, *args, input=None, env=None):
    r = subprocess.run(["git", *args], cwd=cwd, env={**ENV, "HOME": str(cwd), **(env or {})}, input=input,
                       capture_output=True, check=True)
    return r.stdout.decode().strip()


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="repoimport-")).resolve()
        self.store = self.tmp / "store"
        self.addCleanup(lambda: fsio.force_remove(self.tmp))

    def fixture(self, files: dict, *, links: dict | None = None, name="src", extra=None) -> tuple[Path, str]:
        """Commit `files` ({path: bytes|str}, mode via ('x', bytes)) and `links` ({path: target}) into a repo."""
        w = self.tmp / name
        w.mkdir()
        git(w, "init", "-q", "--initial-branch=main")
        for p, data in files.items():
            exe = isinstance(data, tuple)
            data = data[1] if exe else data
            f = w / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data.encode() if isinstance(data, str) else data)
            if exe:
                f.chmod(0o755)
        for p, t in (links or {}).items():
            (w / p).parent.mkdir(parents=True, exist_ok=True)
            os.symlink(t, w / p)
        git(w, "add", "-A", "-f")
        if extra:
            extra(w)
        git(w, "commit", "-q", "-m", "c", "--no-verify")
        return w, git(w, "rev-parse", "HEAD")

    def remote(self, w):
        return local_fixture_remote(w)

    def raw_commit(self, w, entries: list) -> str:
        """Commit a hand-built root tree. entries: (mode, name_bytes, oid_hex). Bypasses git's path checks."""
        body = b"".join(m.encode() + b" " + n + b"\0" + bytes.fromhex(o) for m, n, o in entries)
        tree = subprocess.run(["git", "hash-object", "-t", "tree", "-w", "--literally", "--stdin"], cwd=w,
                              env={**ENV, "HOME": str(w)}, input=body, capture_output=True, check=True).stdout.decode().strip()
        return git(w, "commit-tree", tree, "-m", "raw")

    def blob(self, w, data: bytes) -> str:
        return subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=w, env={**ENV, "HOME": str(w)},
                              input=data, capture_output=True, check=True).stdout.decode().strip()
