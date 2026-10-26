"""Offline verification of an import directory: Git identity (commit -> tree -> every leaf), manifest, on-disk tree,
omission accounting, redaction/line-anchor proof. Needs no network and no git binary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from pathlib import Path

from reviewer.contracts import require
from reviewer.contracts.canonical import digest
from reviewer.contracts.snapshot import SnapshotError, build_manifest, read_verified, snapshot_id

from .errors import RepoImportError
from .fsio import read_nofollow
from .gitobjects import DIR_MODE, commit_tree_and_parents, tree_oid_from_leaves
from .gitrun import oid_of
from .importer import DIRS, FILES, RECORD_SCHEMA, RepoImport, leaves_from_doc
from .pins import check_import_pins
from .redactcheck import patterns_digest, probe

CAP = 1 << 30
TYPE_MODE = {"file": "100644", "executable": "100755", "symlink": "120000"}


def _load(d: Path):
    try:
        names = sorted(os.listdir(d))
    except OSError:
        raise RepoImportError("tamper", "import directory is unreadable") from None
    if names != sorted(FILES + DIRS):
        raise RepoImportError("tamper", f"unexpected import directory contents {names[:8]}")
    for n in names:
        st = os.lstat(d / n)
        if stat.S_ISLNK(st.st_mode) or (n in FILES) != stat.S_ISREG(st.st_mode):
            raise RepoImportError("tamper", f"{n} is not the expected kind of file")
    raw = {n: read_nofollow(d / n, CAP) for n in FILES}
    try:
        return raw, json.loads(raw["manifest.json"]), json.loads(raw["import-record.json"]), \
            json.loads(raw["git-entries.json"]), json.loads(raw["line-anchors.json"])
    except ValueError:
        raise RepoImportError("tamper", "a metadata file is not JSON") from None


def verify_import(import_dir, *, pins=None) -> list[str]:
    """Problems (empty = verified). Without `pins` only internal consistency is established."""
    d = Path(import_dir)
    try:
        raw, manifest, rec, gdoc, anchors = _load(d)
    except RepoImportError as e:
        return [e.detail]
    out: list[str] = []

    def bad(msg):
        out.append(msg)

    try:
        if pins is not None:
            p = check_import_pins(pins)
            for n in FILES:
                if hashlib.sha256(raw[n]).hexdigest() != p["files"][n]:
                    bad(f"{n} differs from the pinned digest")
            for k in ("commitSha", "treeOid", "snapshotId"):
                if rec.get(k) != p[k]:
                    bad(f"record {k} differs from the pins")
            if f"{rec['repo']['owner']}/{rec['repo']['name']}" != p["repo"]:
                bad("record repository differs from the pins")
        if rec.get("schema") != RECORD_SCHEMA:
            return out + ["not a repo-import@1 record"]
        # --- Git identity
        if oid_of("commit", raw["commit-object"]) != rec["commitSha"]:
            bad("commit-object does not hash to the pinned commit")
        tree_oid, parents = commit_tree_and_parents(raw["commit-object"])
        if tree_oid != rec["treeOid"] or parents != rec["parents"]:
            bad("commit tree/parents differ from the record")
        if digest(gdoc) != rec["gitEntries"]["sha256"] or len(gdoc) != rec["gitEntries"]["count"]:
            bad("git-entries.json differs from the record")
        leaves = leaves_from_doc(gdoc)
        if tree_oid_from_leaves(leaves) != tree_oid:
            bad("git entries do not rebuild the pinned tree id")
        # --- manifest and tree
        require("SnapshotManifest", manifest)
        if manifest["snapshotId"] != rec["snapshotId"] or manifest.get("gitCommit") != rec["commitSha"]:
            bad("manifest id or commit differs from the record")
        if manifest["snapshotId"] != snapshot_id(manifest["entries"]):
            bad("manifest id does not match its entries")
        try:
            built = build_manifest(d / "tree")
        except SnapshotError as e:
            return out + [f"tree cannot be read: {e}"]
        if built["entries"] != manifest["entries"]:
            bad("tree on disk differs from the manifest")
        by_path = {pb: (mode, oid) for mode, oid, pb in leaves}
        in_manifest = set()
        lines = nbytes = scanned = withred = 0
        rcounts: dict = {}
        for e in manifest["entries"]:
            pb = e["path"].encode("utf-8")
            in_manifest.add(pb)
            if pb not in by_path or by_path[pb][0] != TYPE_MODE[e["type"]]:
                bad(f"{e['path']}: not a matching Git entry")
                continue
            nbytes += e["size"]
            if e["type"] == "symlink":
                data = os.readlink(d / "tree" / e["path"]).encode("utf-8", "surrogateescape")
            else:
                data = read_verified(d / "tree", manifest, e["path"])
            if oid_of("blob", data) != by_path[pb][1]:
                bad(f"{e['path']}: bytes do not hash to the Git blob id")
            if e["type"] != "symlink":
                res = probe(data.decode("utf-8"))
                if res is None or anchors.get(e["path"]) != res[0]:
                    bad(f"{e['path']}: line anchor or redaction line preservation differs")
                    continue
                lines += res[0]
                scanned += 1
                if res[1]:
                    withred += 1
                    for k, v in res[1].items():
                        rcounts[k] = rcounts.get(k, 0) + v
        # --- omission accounting
        om = rec["omissions"]
        if digest(om["items"]) != om["sha256"]:
            bad("omission list differs from its digest")
        missing = {hashlib.sha256(pb).hexdigest() for pb in by_path if pb not in in_manifest}
        if missing != {i["pathSha256"] for i in om["items"]}:
            bad("omissions do not account for exactly the Git leaves missing from the manifest")
        counts = {k: sum(1 for i in om["items"] if i["kind"] == k) for k in {i["kind"] for i in om["items"]}}
        if counts != om["counts"]:
            bad("omission counts differ from the list")
        types = [e["type"] for e in manifest["entries"]]
        c = rec["counts"]
        want = {"leaves": len(leaves), "included": len(types), "omitted": len(om["items"]), "files": types.count("file"),
                "executables": types.count("executable"), "symlinks": types.count("symlink"), "bytes": nbytes, "lines": lines}
        for k, v in want.items():
            if c.get(k) != v:
                bad(f"count {k} differs from the tree")
        cov = rec["coverage"]
        if cov != {"scope": "repository-with-omissions" if om["items"] else "full-repository",
                   "fullRepositoryCoverage": not om["items"]}:
            bad("coverage statement does not match the omissions")
        # --- anchors and redaction proof
        if digest(anchors) != rec["lineAnchors"]["sha256"] or set(anchors) != {e["path"] for e in manifest["entries"] if e["type"] != "symlink"} \
                or rec["lineAnchors"]["totalLines"] != lines or rec["lineAnchors"]["files"] != len(anchors):
            bad("line anchors differ from the tree")
        r = rec["redaction"]
        if r["patternsSha256"] != patterns_digest():
            bad("redaction patterns changed since the import (re-import)")
        if (r["filesScanned"], r["filesWithRedactions"], r["counts"]) != (scanned, withred, dict(sorted(rcounts.items()))):
            bad("redaction counts differ from the tree")
        if r["lineMismatches"] != sum(1 for i in om["items"] if i["kind"] == "redaction"):
            bad("redaction mismatch count differs from the omissions")
    except RepoImportError as e:
        out.append(e.detail)
    except (KeyError, TypeError, ValueError, SnapshotError, OSError) as e:
        out.append(f"malformed import metadata ({type(e).__name__})")
    return out


def open_import(import_dir, *, pins) -> RepoImport:
    """Verify an import directory against trusted pins and return it. Never captures pins."""
    if pins is None:
        raise RepoImportError("bad-pins", "open_import requires trusted pins")
    bad = verify_import(import_dir, pins=pins)
    if bad:
        raise RepoImportError("tamper", f"{len(bad)} problem(s): " + "; ".join(bad[:5]))
    d = Path(import_dir)
    _, manifest, rec, _, _ = _load(d)
    return RepoImport(d, copy.deepcopy(manifest), copy.deepcopy(rec))
