"""Fetch one immutable commit into a bare store, materialize it, and publish an import directory atomically."""

from __future__ import annotations

import copy
import hashlib
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts import require
from reviewer.contracts.canonical import canonical_json, digest
from reviewer.contracts.redaction import redact

from . import gitrun
from .errors import RepoImportError
from .fsio import force_remove, read_nofollow, write_new
from .gitobjects import commit_tree_and_parents
from .materialize import materialize
from .policy import OMISSION_KINDS, ImportPolicy
from .redactcheck import version_doc
from .remote import Remote, check_commit

RECORD_SCHEMA = "repo-import@1"
COVERAGE_SCHEMA = "repo-import-coverage@1"
FILES = ("manifest.json", "import-record.json", "git-entries.json", "commit-object", "line-anchors.json")
DIRS = ("tree",)
META_MAX = 256 << 20


@dataclass(frozen=True)
class RepoImport:
    dir: Path
    manifest: dict
    record: dict

    @property
    def root(self) -> str:
        return str(self.dir / "tree")

    @property
    def snapshot_id(self) -> str:
        return self.manifest["snapshotId"]

    @property
    def coverage(self) -> dict:
        return coverage_of(self.record)

    @property
    def snapshot(self):
        from reviewer.pipeline.spec import SnapshotInput      # lazy: keeps this package import-light
        return SnapshotInput(self.root, copy.deepcopy(self.manifest))


def coverage_of(record: dict) -> dict:
    counts = record["omissions"]["counts"]
    total = sum(counts.values())
    return {"schema": COVERAGE_SCHEMA, "scope": "repository-with-omissions" if total else "full-repository",
            "fullRepositoryCoverage": total == 0, "omissionCounts": dict(counts), "omittedTotal": total,
            "commitSha": record["commitSha"], "snapshotId": record["snapshotId"],
            "note": ("Whole pinned tree imported." if not total else
                     f"Pinned tree imported with {total} omitted path(s) ({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))}); "
                     "an absent path may exist in the repository.")}


def full_view_of(base: RepoImport, head: RepoImport):
    from reviewer.tools import import_view, omissions_from_records
    return import_view(base.root, base.manifest, head.root, head.manifest,
                       omissions_from_records(base.record, head.record))


# ------------------------------------------------------------------ store

def check_store(store) -> Path:
    s = Path(os.path.abspath(os.fspath(store)))
    real = Path(os.path.realpath(s))
    for anc in (real, *real.parents):
        if os.path.lexists(anc / ".git"):
            raise RepoImportError("bad-store", "store must be outside every Git repository work tree")
    if {"fixtures", "scorer", "labels", "source"} & set(real.parts):
        raise RepoImportError("bad-store", "store must be outside fixture, scorer and label roots")
    return s


def _mkdirs(path: Path) -> None:
    p = Path(path.anchor)
    for part in path.parts[1:]:
        p = p / part
        try:
            os.mkdir(p, 0o700)
        except FileExistsError:
            pass
        if os.path.islink(p) or not os.path.isdir(p):
            raise RepoImportError("bad-store", "store path has a symlink or non-directory component")


def target_dir(store, remote: Remote, commit: str) -> Path:
    return check_store(store) / remote.slug / check_commit(commit)


# ------------------------------------------------------------------ fetch

def _git(git_dir, args, policy, env, *, local, timeout, max_stdout=1 << 20, watch=None):
    return gitrun.run(gitrun.git_argv(git_dir, args, local_fixture=local), env=env, timeout=timeout,
                      max_stdout=max_stdout, max_stderr=policy.max_stderr_bytes, watch=watch)


def fetch(remote: Remote, commit: str, git_dir: Path, policy: ImportPolicy, env: dict) -> int:
    """Init an empty hardened bare store and fetch exactly `commit` (depth 1). Returns pack bytes."""
    local = remote.kind == "local-fixture"
    r = gitrun.run(["git", "init", "--bare", "--quiet", "--template=", "--object-format=sha1", os.fspath(git_dir)],
                   env=env, timeout=60, max_stdout=1 << 16, max_stderr=policy.max_stderr_bytes, cwd=git_dir.parent)
    if r.returncode:
        raise RepoImportError("git-failed", "git init failed: " + r.stderr[:300].decode("utf-8", "replace"))

    def watch():
        if gitrun.tree_size(git_dir / "objects", policy.max_pack_bytes) > policy.max_pack_bytes:
            raise RepoImportError("too-large", f"fetched objects exceed {policy.max_pack_bytes} bytes")

    r = _git(git_dir, ["fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
                       "--no-auto-gc", "--", remote.url, commit], policy, env, local=local,
             timeout=policy.fetch_timeout_s, watch=watch)
    if r.returncode:
        msg = redact(r.stderr.decode("utf-8", "replace"))[0][:400]
        gone = any(s in msg for s in ("not our ref", "couldn't find remote ref", "did not match any",
                                      "unadvertised object", "not found", "Repository not found"))
        raise RepoImportError("unreproducible" if gone else "fetch-failed", f"git fetch failed: {msg}")
    size = gitrun.tree_size(git_dir / "objects", policy.max_pack_bytes)
    if size > policy.max_pack_bytes:
        raise RepoImportError("too-large", f"fetched objects exceed {policy.max_pack_bytes} bytes")
    return size


# ------------------------------------------------------------------ record

def _omissions(leaves) -> dict:
    items = []
    for l in leaves:
        if l.kind is None:
            continue
        it = {"path": redact(l.path)[0] if l.path is not None else None,
              "pathSha256": hashlib.sha256(l.pb).hexdigest(), "kind": l.kind, "size": l.size, "reason": l.reason}
        if l.path is None:
            it["pathEscaped"] = ascii(l.pb)[:200]
        items.append(it)
    items.sort(key=lambda i: (i["kind"], i["pathSha256"]))
    counts = {k: n for k in OMISSION_KINDS if (n := sum(1 for i in items if i["kind"] == k))}
    return {"counts": counts, "items": items, "sha256": digest(items)}


def git_entries_doc(leaves) -> list:
    out = []
    for l in leaves:
        try:
            p, h = l.pb.decode("utf-8"), None
        except UnicodeDecodeError:
            p, h = None, l.pb.hex()
        out.append([l.mode, l.oid, p, h])
    return out


def leaves_from_doc(doc) -> list:
    out = []
    for mode, oid, p, h in doc:
        out.append((mode, oid, p.encode("utf-8") if p is not None else bytes.fromhex(h)))
    return out


def build_record(remote, commit, tree_oid, parents, pack_bytes, policy, res, git_version) -> dict:
    leaves, entries = res["leaves"], res["entries"]
    om = _omissions(leaves)
    kinds = [e["type"] for e in entries]
    rec = {"schema": RECORD_SCHEMA,
           "repo": {"host": "github.com" if remote.kind == "github" else remote.kind, "owner": remote.owner,
                    "name": remote.name, "url": remote.url},
           "commitSha": commit, "treeOid": tree_oid, "parents": parents,
           "snapshotId": res["manifest"]["snapshotId"], "policy": policy.doc(),
           "counts": {"treeEntries": res["visited"], "leaves": len(leaves), "included": len(entries),
                      "omitted": len(om["items"]), "files": kinds.count("file"), "executables": kinds.count("executable"),
                      "symlinks": kinds.count("symlink"), "bytes": res["bytes"], "lines": res["lines"],
                      "packBytes": pack_bytes, "blobsVerified": res["verified"]},
           "omissions": om,
           "redaction": {**version_doc(), "mode": "raw-bytes-stored-redact-on-read", **res["redaction"]},
           "lineAnchors": {"files": len(res["anchors"]), "totalLines": res["lines"], "sha256": digest(res["anchors"])},
           "gitEntries": {"count": len(leaves), "sha256": digest(git_entries_doc(leaves))},
           "tooling": {"git": git_version}}
    rec["coverage"] = {"scope": "repository-with-omissions" if om["items"] else "full-repository",
                       "fullRepositoryCoverage": not om["items"]}
    return rec


def _git_version(env) -> str:
    r = gitrun.run(["git", "--version"], env=env, timeout=20, max_stdout=1024)
    return r.stdout.decode("ascii", "replace").strip()[:60]


# ------------------------------------------------------------------ publish

def import_repository(remote: Remote, commit: str, store, *, policy: ImportPolicy = ImportPolicy(),
                      relates=None) -> RepoImport:
    if not isinstance(remote, Remote):
        raise RepoImportError("bad-input", "remote must come from github_remote()")
    if not isinstance(policy, ImportPolicy):
        raise RepoImportError("bad-input", "policy must be an ImportPolicy")
    final = target_dir(store, remote, commit)
    if os.path.lexists(final):
        raise RepoImportError("store-exists", f"{final} already exists; verify it instead of re-importing")
    _mkdirs(final.parent)
    env = gitrun.git_env()
    stage = final.parent / f".staging-{os.getpid()}-{secrets.token_hex(6)}"
    os.mkdir(stage, 0o700)
    try:
        git_dir = stage / "git"
        pack = fetch(remote, commit, git_dir, policy, env)
        with gitrun.ObjectReader(git_dir, env=env, timeout=policy.read_timeout_s) as rd:
            info = rd.info(commit)
            if info is None:
                raise RepoImportError("unreproducible", "the commit is absent from the fetched objects")
            if info[0] != "commit" or info[1] > policy.max_commit_bytes:
                raise RepoImportError("malformed-object", "pinned object is not a normal-sized commit")
            raw = rd.read(commit, "commit", info[1])
            tree_oid, parents = commit_tree_and_parents(raw)
            res = materialize(rd, tree_oid, stage / "tree", policy)
        manifest = dict(res["manifest"], gitCommit=commit)
        require("SnapshotManifest", manifest)
        rec = build_record(remote, commit, tree_oid, parents, pack, policy, res, _git_version(env))
        if relates is not None:
            from .relates import check_relates
            rec["relatesTo"] = check_relates(relates, commit, manifest, remote.repo)
        shutil.rmtree(git_dir)
        write_new(stage / "commit-object", raw)
        write_new(stage / "manifest.json", canonical_json(manifest))
        write_new(stage / "git-entries.json", canonical_json(git_entries_doc(res["leaves"])))
        write_new(stage / "line-anchors.json", canonical_json(res["anchors"]))
        write_new(stage / "import-record.json", canonical_json(rec))
        os.chmod(stage, 0o555)
        try:
            os.rename(stage, final)
        except OSError:
            raise RepoImportError("store-exists", "could not publish the import directory") from None
        return RepoImport(final, copy.deepcopy(manifest), copy.deepcopy(rec))
    except BaseException:
        force_remove(stage)
        raise


def discard(import_dir) -> None:
    """Remove an import directory this package published (must contain import-record.json and tree/)."""
    d = Path(import_dir)
    if not (d / "import-record.json").is_file() or not (d / "tree").is_dir() or d.is_symlink():
        raise RepoImportError("bad-input", "not an import directory; nothing was removed")
    force_remove(d)
