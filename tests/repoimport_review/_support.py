"""Reviewer-owned support for the S1-03 independent importer review. Not collected as tests (no `test` prefix).

Everything here is self-contained: it does NOT import tests/repoimport/helpers. Fixture Git runs with the absolute
/usr/bin/git and a clean env; the importer under review runs with whatever the test puts in os.environ.
Offline only: every remote is a `file://` URL of a bare/non-bare repository the test owns (via the author's
test-only seam `local_fixture_remote`, which is not exported and not on the CLI).
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.repoimport import fsio  # noqa: E402
from reviewer.repoimport.remote import local_fixture_remote  # noqa: E402

GIT = "/usr/bin/git"
CLEAN = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C",
         "GIT_AUTHOR_NAME": "r", "GIT_AUTHOR_EMAIL": "r@example.invalid", "GIT_COMMITTER_NAME": "r",
         "GIT_COMMITTER_EMAIL": "r@example.invalid", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
         "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}


def g(cwd, *args, input=None) -> str:
    r = subprocess.run([GIT, *args], cwd=cwd, env={**CLEAN, "HOME": str(cwd)}, input=input, capture_output=True,
                       check=True)
    return r.stdout.decode().strip()


def alive(pid: int) -> bool:
    """True unless the process is gone or a zombie."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return f.read().rsplit(b") ", 1)[1][:1] != b"Z"
    except OSError:
        return False


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="s103rev-")).resolve()
        self.store = self.tmp / "store"
        self.addCleanup(lambda: fsio.force_remove(self.tmp))

    # ---- fixture repositories (a normal repo; file:// of its work tree path works as a remote)
    def repo(self, commits, name="src", configure=None):
        """`commits`: list of {path: bytes|str} (each a FULL tree) or (dict, links). Returns (path, [shas])."""
        w = self.tmp / name
        w.mkdir()
        g(w, "init", "-q", "--initial-branch=main")
        if configure:
            configure(w)
        shas = []
        for spec in commits:
            files, links, extra = (spec + ({}, None))[:3] if isinstance(spec, tuple) else (spec, {}, None)
            for p in w.iterdir():
                if p.name != ".git":
                    shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
            for p, data in files.items():
                f = w / p
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data.encode() if isinstance(data, str) else data)
            for p, t in (links or {}).items():
                (w / p).parent.mkdir(parents=True, exist_ok=True)
                os.symlink(t, w / p)
            g(w, "add", "-A", "-f")
            if extra:
                extra(w)
            g(w, "commit", "-q", "-m", "c", "--allow-empty", "--no-verify")
            shas.append(g(w, "rev-parse", "HEAD"))
        return w, shas

    def remote(self, w):
        return local_fixture_remote(w)

    def blob(self, w, data: bytes) -> str:
        return g(w, "hash-object", "-w", "--stdin", input=data)

    def raw_tree(self, w, entries) -> str:
        """entries: (mode, name_bytes, oid). Bypasses Git's path checks (--literally)."""
        body = b"".join(m.encode() + b" " + n + b"\0" + bytes.fromhex(o) for m, n, o in entries)
        return g(w, "hash-object", "-t", "tree", "-w", "--literally", "--stdin", input=body)

    def oracle_leaves(self, w, sha):
        """Independent oracle: (mode, oid, path_bytes) for every non-directory leaf, straight from `git ls-tree`."""
        raw = subprocess.run([GIT, "ls-tree", "-r", "-z", "--full-tree", sha], cwd=w, env={**CLEAN, "HOME": str(w)},
                             capture_output=True, check=True).stdout
        out = []
        for rec in filter(None, raw.split(b"\0")):
            meta, path = rec.split(b"\t", 1)
            mode, _typ, oid = meta.decode().split(" ")
            out.append((mode, oid, path))
        return sorted(out, key=lambda t: t[2])

    def assert_matches_git(self, imp, w, sha):
        """The import's Git entries equal what an independent `git ls-tree -r` says, and the tree id agrees."""
        doc = json.loads((imp.dir / "git-entries.json").read_bytes())
        got = sorted(((m, o, (p.encode() if p is not None else bytes.fromhex(h))) for m, o, p, h in doc),
                     key=lambda t: t[2])
        self.assertEqual(got, self.oracle_leaves(w, sha))
        self.assertEqual(imp.record["treeOid"], g(w, "rev-parse", sha + "^{tree}"))
        self.assertEqual(imp.record["commitSha"], sha)

    def writable_copy(self, src: Path, name="copy") -> Path:
        dst = self.tmp / name
        shutil.copytree(src, dst, symlinks=True)
        for dp, dn, fn in os.walk(dst, followlinks=False):
            os.chmod(dp, 0o700)
            for f in fn:
                p = os.path.join(dp, f)
                if not os.path.islink(p):
                    os.chmod(p, 0o600)
        return dst


# ---- a `git` shim that records every invocation (argv + exact env) and can misbehave on demand
SHIM = textwrap.dedent('''\
    #!/usr/bin/python3
    import json, os, subprocess, sys, time
    HERE = os.path.dirname(os.path.abspath(sys.argv[0]))
    args = sys.argv[1:]
    def verb(a):
        i = 0
        while i < len(a):
            if a[i] in ("-c", "--git-dir"):
                i += 2
            elif a[i].startswith("-"):
                if a[i] == "--version":
                    return "--version"
                i += 1
            else:
                return a[i]
        return ""
    v = verb(args)
    with open(os.path.join(HERE, "calls.jsonl"), "a") as f:
        f.write(json.dumps({"verb": v, "argv": args, "env": dict(os.environ)}) + "\\n")
    mp = os.path.join(HERE, "mode")
    mode = open(mp).read().strip() if os.path.exists(mp) else "pass"
    gd = args[args.index("--git-dir") + 1] if "--git-dir" in args else None
    def note(*pids):
        with open(os.path.join(HERE, "pids"), "a") as f:
            f.write("".join(f"{p}\\n" for p in pids))
    if v == "fetch" and mode == "hang-fetch":
        child = subprocess.Popen(["sleep", "300"])
        note(os.getpid(), child.pid)
        time.sleep(300)
    if v == "fetch" and mode == "flood-stdout":
        note(os.getpid())
        sys.stdout.buffer.write(b"x" * (8 << 20)); sys.stdout.buffer.flush()
        time.sleep(120)
    if v == "fetch" and mode == "flood-stderr":
        sys.stderr.buffer.write(b"e" * (40 << 20)); sys.stderr.buffer.flush()
        sys.exit(1)
    if v == "fetch" and mode == "grow":
        note(os.getpid())
        os.makedirs(os.path.join(gd, "objects", "pack"), exist_ok=True)
        with open(os.path.join(gd, "objects", "pack", "tmp_pack_grow"), "wb") as f:
            f.write(b"\\0" * (3 << 20))
        time.sleep(120)
    if v == "cat-file" and mode == "hang-catfile":
        note(os.getpid())
        time.sleep(300)
    os.execv("/usr/bin/git", ["/usr/bin/git"] + args)
''')


class ShimMixin:
    def install_shim(self, mode="pass"):
        d = self.tmp / "shim"
        d.mkdir(exist_ok=True)
        p = d / "git"
        p.write_text(SHIM)
        p.chmod(0o755)
        (d / "mode").write_text(mode)
        patcher = mock.patch.dict(os.environ, {"PATH": f"{d}:{os.environ['PATH']}"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._reap, d)
        self.shim_dir = d
        return d

    def _reap(self, d):
        try:
            for line in (d / "pids").read_text().split():
                try:
                    os.kill(int(line), 9)
                except OSError:
                    pass
        except OSError:
            pass

    def shim_calls(self):
        p = self.shim_dir / "calls.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def shim_pids(self):
        p = self.shim_dir / "pids"
        return [int(x) for x in p.read_text().split()] if p.exists() else []


def modes_of(tree: Path) -> dict:
    return {str(p.relative_to(tree)): stat.S_IMODE(p.lstat().st_mode) for p in tree.rglob("*")}
