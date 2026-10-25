"""Offline redaction-currency refresh: re-stamp a stored case only when nothing would change.

A corpus recorded under an older redaction version can be brought up to the current contracts
without any fetch when the current redaction provably leaves it as it is: every blob was stored
unredacted (raw == stored, no redactions), re-redacting its text under the current contracts is
the identity and finds nothing protected, and the case still loads under the current contracts
once only the version/fingerprint metadata is replaced. Anything else is refused and needs a
re-import (`import --replace`, `context --refresh`). The blobs are never rewritten.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from reviewer.contracts import redaction as _c

from . import safeio
from .inputs import InputError, load_reviewer_input
from .redact import REDACTION_VERSION, patterns_digest, redact_text


class NotEquivalent(ValueError):
    pass


def _prove_blob(case_dir, meta, patch: bool) -> None:
    where = meta["file"]
    if meta["redactions"] or meta["rawSha256"] != meta["sha256"] or meta["rawBytes"] != meta["bytes"]:
        raise NotEquivalent(f"{where}: stored text differs from the raw text (it was redacted)")
    data = safeio.read_file(case_dir, "input/" + where)
    if hashlib.sha256(data).hexdigest() != meta["sha256"] or len(data) != meta["bytes"]:
        raise NotEquivalent(f"{where}: stored bytes do not match their recorded hash")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise NotEquivalent(f"{where}: not UTF-8") from e
    if _c.contains_protected(text):
        raise NotEquivalent(f"{where}: protected text present")
    out, counts = redact_text(text, patch=patch)
    if counts or out != text:
        raise NotEquivalent(f"{where}: the current redaction would change it")


def _stale(doc, version_key, digest_key, holder=None) -> bool:
    h = doc if holder is None else doc[holder]
    return h[version_key] != REDACTION_VERSION or h[digest_key] != patterns_digest()


def refresh_case(case_dir, apply: bool = True) -> str:
    """-> 'current' | 'refreshed' | 'refreshable' (apply=False). Raises NotEquivalent / InputError."""
    case_dir = Path(case_dir)
    case = safeio.read_json(case_dir, "input/case.json")
    try:
        ctx = safeio.read_json(case_dir, "input/context.json")
    except (safeio.PathError, FileNotFoundError):
        if (case_dir / "input" / "context.json").exists() or (case_dir / "input" / "context.json").is_symlink():
            raise
        ctx = None
    stale_case = _stale(case, "version", "patternsSha256", "redaction")
    stale_ctx = ctx is not None and _stale(ctx, "redactionVersion", "redactionPatternsSha256")
    if not (stale_case or stale_ctx):
        return "current"
    for f in case["files"]:
        for part in ("patch", "base", "head"):
            if f.get(part):
                _prove_blob(case_dir, f[part], part == "patch")
    if ctx is not None:
        for e in ctx["files"]:
            if e.get("status") == "ok":
                _prove_blob(case_dir, e, False)
    for name, doc in (("case.json", case), ("context.json", ctx)):
        if doc is not None and _c.json_contains_protected(doc):
            raise NotEquivalent(f"{name}: protected text present")
    old = ((case["redaction"]["version"], case["redaction"]["patternsSha256"]) if stale_case
           else (ctx["redactionVersion"], ctx["redactionPatternsSha256"]))
    case["redaction"]["version"], case["redaction"]["patternsSha256"] = REDACTION_VERSION, patterns_digest()
    if ctx is not None:
        ctx["redactionVersion"], ctx["redactionPatternsSha256"] = REDACTION_VERSION, patterns_digest()
    # The re-stamped inputs must load under the current contracts, checked on a copy.
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t) / case_dir.name
        shutil.copytree(case_dir / "input", tmp / "input", symlinks=True)
        safeio.write_json(tmp, "input/case.json", case, replace=True)
        if ctx is not None:
            safeio.write_json(tmp, "input/context.json", ctx, replace=True)
        load_reviewer_input(tmp)
    if not apply:
        return "refreshable"
    if ctx is not None and stale_ctx:
        safeio.write_json(case_dir, "input/context.json", ctx, replace=True)
    if stale_case:
        safeio.write_json(case_dir, "input/case.json", case, replace=True)
    try:
        src = safeio.read_json(case_dir, "source/collection.json")
    except (safeio.PathError, FileNotFoundError):
        src = None
    if isinstance(src, dict):
        # redactionRefresh is the latest record; each superseded one is kept, oldest first, in its history.
        prior = src.get("redactionRefresh")
        history = []
        if isinstance(prior, dict):
            history = [*prior.get("history", []), {k: v for k, v in prior.items() if k != "history"}]
        src["redactionRefresh"] = {
            "method": "offline-equivalence: no blob was redacted before or after; metadata re-stamped",
            "files": [n for n, on in (("case.json", stale_case), ("context.json", stale_ctx)) if on],
            "from": f"{old[0]}/{old[1][:12]}", "to": f"{REDACTION_VERSION}/{patterns_digest()[:12]}",
            **({"history": history} if history else {})}
        safeio.write_json(case_dir, "source/collection.json", src, replace=True)
    return "refreshed"


def refresh_index(out_root) -> None:
    """Re-stamp index.json entries (orchestration only) from the cases they describe.
    Entries whose case directory is gone are left as they are (refresh_all reports them)."""
    idx = Path(out_root) / "index.json"
    if not idx.is_file() or idx.is_symlink():
        return
    doc = json.loads(idx.read_text())
    for e in doc["cases"]:
        if not e.get("input") or not _has_case(out_root, e["id"]):
            continue
        case = safeio.read_json(Path(out_root) / e["id"], "input/case.json")["redaction"]
        e["redactionVersion"], e["redactionPatternsSha256"] = case["version"], case["patternsSha256"]
    doc["redactionVersionNow"], doc["redactionPatternsSha256Now"] = REDACTION_VERSION, patterns_digest()
    safeio.write_json(out_root, "index.json", doc, replace=True)


def _has_case(out_root, cid) -> bool:
    d = Path(out_root) / str(cid)
    return d.is_dir() and not d.is_symlink() and (d / "input" / "case.json").is_file()


def refresh_all(out_root, apply: bool = True, log=lambda m: None) -> dict[str, str]:
    results = {}
    for d in sorted(Path(out_root).iterdir()):
        if d.name.startswith(".") or not d.is_dir() or d.is_symlink() or not (d / "input" / "case.json").exists():
            continue
        try:
            results[d.name] = refresh_case(d, apply)
        except (NotEquivalent, InputError, safeio.PathError, OSError, ValueError, KeyError, TypeError) as e:
            results[d.name] = f"refused: {type(e).__name__}: {e}"
        log(f"{d.name}: {results[d.name]}")
    idx = Path(out_root) / "index.json"
    if idx.is_file() and not idx.is_symlink():
        try:
            for e in json.loads(idx.read_text())["cases"]:
                if e.get("input") and e["id"] not in results and not _has_case(out_root, e["id"]):
                    results[str(e["id"])] = "refused: index entry has no case directory"
                    log(f"{e['id']}: {results[str(e['id'])]}")
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as e:
            results["index.json"] = f"refused: {type(e).__name__}: {e}"
    if apply and results and all(not v.startswith("refused") for v in results.values()):
        try:
            refresh_index(out_root)
        except (safeio.PathError, OSError, ValueError, KeyError, TypeError) as e:
            results["index.json"] = f"refused: {type(e).__name__}: {e}"
    return results
