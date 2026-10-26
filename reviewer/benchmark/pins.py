"""External trusted source pins and file verification. A pin is never read from the store it verifies."""

from __future__ import annotations

import re
from pathlib import Path

from .errors import BenchmarkError
from .jsonio import MAX_BYTES, git_blob_sha, load_json, read_regular, sha256_of

SCHEMA = "benchmark-source-pins@1"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEYS = {"name", "sourcePath", "bytes", "gitBlobSha", "sha256"}
# Root's actual capture (martian-source-import receipt `files`, `sourcePins` file). Authority is only
# bytes/gitBlobSha/sha256/revision and the logical name derived from sourcePath; the rest is descriptive.
_CAPTURE_KEYS = {"path", "sourcePath", "url", "revision", "bytes", "gitBlobSha", "sha256", "capturedAt",
                 "topType", "topKeys", "topCount"}
_CAPTURE_TOP = {"schema", "revision", "capturedBy", "files"}
_NAMES = {"offline/results/benchmark_data.json": "benchmark_data.json",
          "offline/results/pr_labels.json": "pr_labels.json"}
_RAW = "https://raw.githubusercontent.com/withmartian/code-review-benchmark/{rev}/{src}"
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?\+00:00$")


def _trust_fields(f: dict, label: str) -> None:
    if (not isinstance(f["bytes"], int) or isinstance(f["bytes"], bool) or not 0 < f["bytes"] <= MAX_BYTES
            or not isinstance(f["gitBlobSha"], str) or not _HEX40.match(f["gitBlobSha"])
            or not isinstance(f["sha256"], str) or not _SHA.match(f["sha256"])):
        raise BenchmarkError("pins", f"malformed pin for {label[:40]}")


def _capture_file(f: dict, rev: str) -> dict:
    src = f["sourcePath"]
    name = _NAMES.get(src) if isinstance(src, str) else None
    if name is None:
        raise BenchmarkError("pins", "sourcePath is not a known benchmark source file")
    _trust_fields(f, name)
    if f["revision"] != rev:
        raise BenchmarkError("pins", f"{name}: file revision differs from the pinned revision")
    if f["url"] != _RAW.format(rev=rev, src=src):
        raise BenchmarkError("pins", f"{name}: url does not name the pinned revision and sourcePath")
    path = f["path"]
    if not isinstance(path, str) or path.rsplit("/", 1)[-1] != name:
        raise BenchmarkError("pins", f"{name}: descriptive path does not end in the logical name")
    if not isinstance(f["capturedAt"], str) or not _STAMP.match(f["capturedAt"]):
        raise BenchmarkError("pins", f"{name}: capturedAt is not a UTC timestamp")
    keys, count = f["topKeys"], f["topCount"]
    if (f["topType"] != "dict" or not isinstance(keys, list) or not all(isinstance(k, str) for k in keys)
            or len(set(keys)) != len(keys) or not isinstance(count, int) or isinstance(count, bool)
            or count != len(keys)):
        raise BenchmarkError("pins", f"{name}: top-level shape metadata is inconsistent")
    return {"name": name, "sourcePath": src, "bytes": f["bytes"], "gitBlobSha": f["gitBlobSha"], "sha256": f["sha256"]}


def load_pins(path, *, expect_revision: str | None = None, store_dirs=()) -> dict:
    p = Path(path).resolve()
    for d in store_dirs:
        dd = Path(d).resolve()
        if p.parent == dd or dd in p.parents:
            raise BenchmarkError("pins", "the pins file is inside the store it would verify")
    doc = load_json(p, "pins", limit=1 << 20)
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise BenchmarkError("pins", f"schema must be {SCHEMA}")
    rev = doc.get("revision")
    if not isinstance(rev, str) or not _HEX40.match(rev):
        raise BenchmarkError("pins", "revision must be a 40-hex commit")
    if expect_revision is not None and rev != expect_revision:
        raise BenchmarkError("pins", "revision differs from the expected revision")
    files = doc.get("files")
    if not isinstance(files, list) or not files:
        raise BenchmarkError("pins", "files must be a non-empty list")
    if all(isinstance(f, dict) and set(f) == _CAPTURE_KEYS for f in files):
        if set(doc) != _CAPTURE_TOP or not isinstance(doc["capturedBy"], str):
            raise BenchmarkError("pins", f"capture pins keys must be exactly {sorted(_CAPTURE_TOP)}")
        files = [_capture_file(f, rev) for f in files]
        if sorted(f["name"] for f in files) != sorted(_NAMES.values()):
            raise BenchmarkError("pins", "capture pins must name each benchmark source file exactly once")
        doc = {**doc, "files": files, "format": "capture"}
    names = set()
    for f in files:
        if not isinstance(f, dict) or set(f) != _KEYS:
            raise BenchmarkError("pins", f"file pin keys must be exactly {sorted(_KEYS)}")
        if (not isinstance(f["bytes"], int) or isinstance(f["bytes"], bool) or not 0 < f["bytes"] <= MAX_BYTES
                or not _HEX40.match(str(f["gitBlobSha"])) or not _SHA.match(str(f["sha256"]))
                or not isinstance(f["name"], str) or "/" in f["name"]):
            raise BenchmarkError("pins", f"malformed pin for {str(f.get('name'))[:40]}")
        if f["name"] in names:
            raise BenchmarkError("pins", f"duplicate pin {f['name']}")
        names.add(f["name"])
    return doc


def pin_for(pins: dict, name: str) -> dict:
    for f in pins["files"]:
        if f["name"] == name:
            return f
    raise BenchmarkError("pins", f"no pin for {name}")


def verify_file(path, pin: dict) -> bytes:
    """Return the bytes only if size, sha256 and Git blob id all equal the pin."""
    data = read_regular(path, limit=pin["bytes"])
    if len(data) != pin["bytes"]:
        raise BenchmarkError("tamper", f"{pin['name']}: {len(data)} bytes, pinned {pin['bytes']}")
    if sha256_of(data) != pin["sha256"]:
        raise BenchmarkError("tamper", f"{pin['name']}: sha256 differs from the pin")
    if git_blob_sha(data) != pin["gitBlobSha"]:
        raise BenchmarkError("tamper", f"{pin['name']}: Git blob id differs from the pin")
    return data
