"""Trusted pins for an import directory. CAPTURE is a separate, explicit act (right after a reviewed import) and is
never performed by `open_import`/`verify_import`. Pins live outside the import directory."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from reviewer.contracts.canonical import canonical_json

from .errors import RepoImportError
from .fsio import read_nofollow, write_new

PINS_SCHEMA = "repo-import-pins@1"
PINS_MAX = 1 << 20
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SHA = re.compile(r"[0-9a-f]{40}")
_H64 = re.compile(r"[0-9a-f]{64}")
_SNAP = re.compile(r"snap:sha256:[0-9a-f]{64}")
PINNED_FILES = ("manifest.json", "import-record.json", "git-entries.json", "commit-object", "line-anchors.json")


def check_import_pins(pins) -> dict:
    try:
        ok = (isinstance(pins, dict) and set(pins) == {"schema", "capturedAt", "repo", "commitSha", "treeOid", "snapshotId", "files"}
              and pins["schema"] == PINS_SCHEMA and isinstance(pins["capturedAt"], str) and _TS.fullmatch(pins["capturedAt"])
              and isinstance(pins["repo"], str) and re.fullmatch(r"[^/\s]+/[^/\s]+", pins["repo"])
              and _SHA.fullmatch(pins["commitSha"]) and _SHA.fullmatch(pins["treeOid"]) and _SNAP.fullmatch(pins["snapshotId"])
              and isinstance(pins["files"], dict) and set(pins["files"]) == set(PINNED_FILES)
              and all(isinstance(v, str) and _H64.fullmatch(v) for v in pins["files"].values()))
    except (TypeError, KeyError):
        ok = False
    if not ok:
        raise RepoImportError("bad-pins", "not a repo-import-pins@1 document")
    return json.loads(json.dumps(pins))


def capture_import_pins(import_dir, *, captured_at: str) -> dict:
    """TRUSTED TIME ONLY: run once on an import directory known to be good (right after a reviewed import) and
    store the result outside it with `write_import_pins`. Pinning a directory and trusting that pin proves nothing."""
    from .verify import verify_import
    if not isinstance(captured_at, str) or not _TS.fullmatch(captured_at):
        raise RepoImportError("bad-pins", "captured_at must be YYYY-MM-DDTHH:MM:SSZ")
    bad = verify_import(import_dir)
    if bad:
        raise RepoImportError("tamper", "import is not internally consistent: " + "; ".join(bad[:5]))
    d = Path(import_dir)
    rec = json.loads(read_nofollow(d / "import-record.json", 1 << 30))
    files = {n: hashlib.sha256(read_nofollow(d / n, 1 << 30)).hexdigest() for n in PINNED_FILES}
    return check_import_pins({"schema": PINS_SCHEMA, "capturedAt": captured_at, "repo": f"{rec['repo']['owner']}/{rec['repo']['name']}",
                              "commitSha": rec["commitSha"], "treeOid": rec["treeOid"], "snapshotId": rec["snapshotId"],
                              "files": files})


def write_import_pins(path, pins) -> None:
    """Canonical JSON, exclusive create (never overwrites), read-only."""
    data = canonical_json(check_import_pins(pins))
    try:
        write_new(path, data)
    except OSError as e:
        raise RepoImportError("bad-pins", f"cannot create pins file: {e.strerror}") from None


def load_import_pins(path, *, import_dir) -> dict:
    p, d = Path(os.path.realpath(path)), Path(os.path.realpath(import_dir))
    if p == d or d in p.parents:
        raise RepoImportError("bad-pins", "pins must be stored outside the import directory")
    try:
        return check_import_pins(json.loads(read_nofollow(path, PINS_MAX)))
    except RepoImportError:
        raise
    except (OSError, ValueError):
        raise RepoImportError("bad-pins", "pins file is unreadable or not JSON") from None
