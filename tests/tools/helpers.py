import os
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.snapshot import build_manifest
from reviewer.tools import (Limits, ToolSession, View, full_view, make_layer)

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "ghp_" + "A1b2C3d4" * 5          # fake, token-shaped
KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\nabcdef\n-----END RSA PRIVATE KEY-----"

BASE = {"src/app.py": "import os\n\n\ndef run():\n    return 1\n", "README.md": "# demo\n",
        "src/gone.py": "x = 1\n"}
HEAD = {"src/app.py": "import os\n\n\ndef run():\n    return 2\n", "README.md": "# demo\n",
        "src/new.py": "y = 2\n"}


def write_tree(root: Path, files: dict, links: dict | None = None):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text)
    for rel, target in (links or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, p)


class Env(unittest.TestCase):
    """Temp base/head trees plus a full view."""
    BASE_FILES = BASE
    HEAD_FILES = HEAD
    BASE_LINKS = None
    HEAD_LINKS = None

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.base, self.head = self.tmp / "base", self.tmp / "head"
        self.base.mkdir()
        self.head.mkdir()
        write_tree(self.base, self.BASE_FILES, self.BASE_LINKS)
        write_tree(self.head, self.HEAD_FILES, self.HEAD_LINKS)
        self.view = full_view(self.base, build_manifest(self.base), self.head, build_manifest(self.head))

    def session(self, **kw):
        limits = kw.pop("limits", Limits())
        return ToolSession(kw.pop("view", self.view), limits=limits, **kw)


class Clock:
    def __init__(self, step=0.0, t=0.0):
        self.t, self.step = t, step

    def __call__(self):
        v = self.t
        self.t += self.step
        return v


# ---- corpus-valid historical case builder (validated by reviewer.corpus.inputs.load_reviewer_input)
import difflib
import hashlib
import json

from reviewer.corpus.redact import REDACTION_VERSION, patterns_digest

BASE_SHA, HEAD_SHA = "a" * 40, "b" * 40


def _blob(file: str, text: str) -> dict:
    h = hashlib.sha256(text.encode()).hexdigest()
    return {"file": file, "rawSha256": h, "rawBytes": len(text.encode()), "sha256": h,
            "bytes": len(text.encode()), "redactions": {}}


def make_case(parent: Path, base: dict, head: dict, *, context: dict | None = None, name="o--r--1",
              case_gaps: list | None = None, expected: int | None = None) -> Path:
    """Write <parent>/<name>/{input,source,labels}. `base`/`head` are the CHANGED files (text),
    `context` is {"base": {...}, "head": {...}}. Plain text, nothing redacted. `case_gaps` (list of
    gap kinds) records coverage gaps; `expected` the number of changed files the PR had."""
    case = Path(parent) / name
    inp = case / "input"
    files = []
    for path in sorted(set(base) | set(head)):
        b, h = base.get(path), head.get(path)
        if b == h:
            continue
        bl = [] if b is None else b.splitlines(True)
        hl = [] if h is None else h.splitlines(True)
        patch = "".join(list(difflib.unified_diff(bl, hl, f"a/{path}", f"b/{path}"))[2:])   # corpus patches have no file headers
        if patch and not patch.endswith("\n"):
            patch += "\n"
        adds = sum(1 for l in patch.splitlines() if l.startswith("+"))
        dels = sum(1 for l in patch.splitlines() if l.startswith("-"))
        files.append({"path": path, "previousPath": None, "status": "added" if b is None else "removed" if h is None else "modified",
                      "additions": adds, "deletions": dels, "gaps": [], "patchRedaction": "none",
                      "patch": _blob(f"patches/{path}.patch", patch),
                      "base": None if b is None else _blob(f"base/{path}", b),
                      "head": None if h is None else _blob(f"head/{path}", h)})
        for part, text in (("patches", patch), ("base", b), ("head", h)):
            if text is not None:
                rel = f"{part}/{path}" + (".patch" if part == "patches" else "")
                write_tree(inp, {rel: text})
    ctx_files = []
    for side in ("base", "head"):
        for path, text in ((context or {}).get(side) or {}).items():
            write_tree(inp, {f"context/{side}/{path}": text})
            ctx_files.append({"side": side, "path": path, "ref": HEAD_SHA if side == "head" else BASE_SHA,
                              "status": "ok", **_blob(f"context/{side}/{path}", text)})
    gaps = [{"kind": k, "detail": "test"} for k in (case_gaps or [])]
    kinds = {}
    for g in gaps:
        kinds[g["kind"]] = kinds.get(g["kind"], 0) + 1
    exp = len(files) if expected is None else expected
    case_doc = {"schema": "historical-case-input@1", "id": name, "repo": "o/r", "importer": "test@1",
                "base": {"sha": BASE_SHA, "mergeBase": None, "textRef": BASE_SHA}, "head": {"sha": HEAD_SHA},
                "files": files, "gaps": gaps,
                "coverage": {"scope": "changed-files-and-selected-context", "fullRepositoryCoverage": False,
                             "changedFilesExpected": exp, "changedFilesListed": (len(files) + 1 if "files-omitted-by-limit" in kinds else
                                                                  len(files) if "files-list-incomplete" in kinds else exp),
                             "changedFilesRecorded": len(files), "complete": not kinds, "gapKinds": kinds, "note": "test"},
                "redaction": {"version": REDACTION_VERSION, "patternsSha256": patterns_digest(), "counts": {}}}
    (inp / "case.json").write_text(json.dumps(case_doc))
    if ctx_files:
        (inp / "context.json").write_text(json.dumps({
            "schema": "historical-context@1", "repo": "o/r", "redactionVersion": REDACTION_VERSION,
            "redactionPatternsSha256": patterns_digest(), "coverage": {"fullRepositoryCoverage": False, "note": "test"},
            "selectedPaths": [{k: e[k] for k in ("side", "path", "ref")} for e in ctx_files], "files": ctx_files}))
    write_tree(case, {"source/collection.json": '{"mergedAt": "2026", "later": "OUTCOME_SECRET"}',
                      "labels/expected.json": "LABELS_SECRET", "labels/base/x.txt": "LABELS_DEEP",
                      "labels/head/x.txt": "LABELS_DEEP"})
    return case
