"""Consistency of a full import with the prior PARTIAL case input (changed-path byte equality). Reads only
`<case>/input/case.json` and the input blobs it names; never `source/` or `labels/`."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts.schema import is_safe_relpath

from .errors import RepoImportError
from .fsio import read_nofollow

RELATES_SCHEMA = "repo-import-relates@1"
META_MAX = 8 << 20
BLOB_MAX = 64 << 20
_SHA = re.compile(r"[0-9a-f]{40}")
_H64 = re.compile(r"[0-9a-f]{64}")
_SNAP = re.compile(r"snap:sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class RelatesSpec:
    case_dir: str | Path
    side: str                                   # "base" | "head"
    partial_snapshot_id: str | None = None


def _case(case_dir) -> dict:
    try:
        case = json.loads(read_nofollow(Path(case_dir) / "input" / "case.json", META_MAX))
        b, h = case["base"], case["head"]
        ok = (isinstance(case["id"], str) and isinstance(case["repo"], str) and isinstance(case["files"], list)
              and _SHA.fullmatch(b["textRef"]) and _SHA.fullmatch(b["sha"]) and _SHA.fullmatch(h["sha"])
              and (b["mergeBase"] is None or _SHA.fullmatch(b["mergeBase"]))
              and b["textRef"] == (b["mergeBase"] or b["sha"]))
    except (OSError, ValueError, KeyError, TypeError):
        raise RepoImportError("bad-input", "case.json is missing or malformed") from None
    if not ok:
        raise RepoImportError("bad-input", "case.json pins are malformed")
    return case


def pin_from_case(case_dir) -> dict:
    """Exact pins from the actual case input: base is the merge base/`textRef`, never a possibly advanced `baseSha`."""
    c = _case(case_dir)
    return {"caseId": c["id"], "repo": c["repo"], "headSha": c["head"]["sha"], "baseTextRef": c["base"]["textRef"],
            "baseSha": c["base"]["sha"], "mergeBase": c["base"]["mergeBase"]}


def check_relates(spec: RelatesSpec, commit: str, manifest: dict, repo: str | None = None) -> dict:
    if spec.side not in ("base", "head"):
        raise RepoImportError("bad-input", "relates side must be 'base' or 'head'")
    if spec.partial_snapshot_id is not None and not _SNAP.fullmatch(spec.partial_snapshot_id):
        raise RepoImportError("bad-input", "partial snapshot id is malformed")
    case = _case(spec.case_dir)
    want = case["head"]["sha"] if spec.side == "head" else case["base"]["textRef"]
    if commit != want:
        raise RepoImportError("relates-mismatch", f"commit is not the case {spec.side} "
                              f"({'head' if spec.side == 'head' else 'textRef'} {want})")
    if repo is not None and repo.lower() != case["repo"].lower():
        raise RepoImportError("relates-mismatch", "repository differs from the case")
    idx = {e["path"]: e for e in manifest["entries"]}
    checked, bad, unchecked = 0, [], []
    for f in case["files"]:
        path, prev, status = f.get("path"), f.get("previousPath"), f.get("status")
        if path is None:
            unchecked.append({"path": None, "reason": "unsafe-path"})
            continue
        p = path if spec.side == "head" else (prev or path)
        blob = f.get(spec.side)
        if blob is None:
            if f.get("gaps"):
                unchecked.append({"path": p, "reason": "recorded-gap"})
            elif (spec.side == "base" and status == "added") or (spec.side == "head" and status == "removed"):
                checked += 1
                if p in idx:
                    bad.append({"path": p, "reason": "present-but-recorded-absent"})
            else:
                unchecked.append({"path": p, "reason": "no-blob"})
            continue
        checked += 1
        raw = blob.get("rawSha256")
        if not isinstance(raw, str) or not _H64.fullmatch(raw):
            bad.append({"path": p, "reason": "case-hash-malformed"})
            continue
        e = idx.get(p)
        if e is None:
            bad.append({"path": p, "reason": "missing-in-import"})
        elif e["type"] == "symlink" or e["sha256"] != raw:
            bad.append({"path": p, "reason": "bytes-differ"})
        if not blob.get("redactions") and isinstance(blob.get("file"), str) and is_safe_relpath(blob["file"]):
            import hashlib
            try:
                disk = hashlib.sha256(read_nofollow(Path(spec.case_dir) / "input" / blob["file"], BLOB_MAX)).hexdigest()
            except OSError:
                disk = None
            if disk != raw:
                bad.append({"path": p, "reason": "partial-input-changed"})
    if bad:
        shown = "; ".join(f"{b['path']}: {b['reason']}" for b in bad[:5])
        raise RepoImportError("relates-mismatch", f"{len(bad)} changed path(s) differ from the partial input ({shown})")
    return {"schema": RELATES_SCHEMA, "caseId": case["id"], "side": spec.side,
            "partialSnapshotId": spec.partial_snapshot_id, "commitSha": commit, "changedPathsChecked": checked,
            "changedPathsByteEqual": True, "unchecked": unchecked,
            "idEqualsPartial": None if spec.partial_snapshot_id is None else spec.partial_snapshot_id == manifest["snapshotId"]}
