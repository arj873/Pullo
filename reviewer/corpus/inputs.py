"""The only reader of a case for reviewers: loads input/ against closed schemas.

Everything is checked before anything is returned: redaction version and pattern fingerprint
equal the current contracts, schemas are closed, pointers are the canonical path for their
file, refs are the case's pinned refs, the file set under input/ equals the referenced set,
blob hashes match and every blob is re-scanned for protected text. Any problem is InputError.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from reviewer.contracts import redaction as _c

from . import safeio
from .patchcheck import count_changes, reconstructs
from .redact import REDACTION_VERSION, patterns_digest

FORBIDDEN_KEYS = frozenset({
    "merged", "mergedat", "closedat", "state", "body", "title", "comments", "reviews", "labels",
    "labelsstatus", "expectedissues", "expect", "mergecommit", "mergecommitsha", "fixcommits",
    "outcome", "evaluation", "url", "htmlurl", "prnumber", "source",
})
CASE_SCHEMA = "historical-case-input@1"
CONTEXT_SCHEMA = "historical-context@1"
_SHA = re.compile(r"[0-9a-f]{40}")
_H64 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"([A-Za-z0-9._-]+)--([A-Za-z0-9._-]+)--[0-9]+")
_PIDS = frozenset(pid for pid, _ in _c.PROTECTED_PATTERNS)
_STATUSES = frozenset({"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"})
PATCH_REDACTION = frozenset({"none", "no-patch", "reconstructs", "unverified"})


class InputError(ValueError):
    pass


def forbidden_keys_in(doc, path="") -> list[str]:
    hits = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            if str(k).lower() in FORBIDDEN_KEYS:
                hits.append(f"{path}/{k}")
            hits += forbidden_keys_in(v, f"{path}/{k}")
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            hits += forbidden_keys_in(v, f"{path}[{i}]")
    return hits


# ---- tiny closed-schema helpers (stdlib only)
def _bad(where, why):
    raise InputError(f"{where}: {why}")


def _obj(v, where, req, opt=()):
    if not isinstance(v, dict):
        _bad(where, "expected an object")
    extra = set(v) - set(req) - set(opt)
    if extra:
        _bad(where, f"unknown keys {sorted(map(str, extra))}")
    miss = [k for k in req if k not in v]
    if miss:
        _bad(where, f"missing keys {miss}")
    return v


def _str(v, where, nullable=False, maxlen=2048):
    if v is None and nullable:
        return v
    if not isinstance(v, str) or not v or len(v) > maxlen:
        _bad(where, "expected a non-empty string")
    return v


def _int(v, where, nullable=False):
    if v is None and nullable:
        return v
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        _bad(where, "expected a non-negative integer")
    return v


def _bool(v, where):
    if not isinstance(v, bool):
        _bad(where, "expected a boolean")
    return v


def _list(v, where, maxlen=100000):
    if not isinstance(v, list) or len(v) > maxlen:
        _bad(where, "expected a list")
    return v


def _re(v, rx, where, nullable=False):
    if v is None and nullable:
        return v
    if not isinstance(v, str) or not rx.fullmatch(v):
        _bad(where, "bad format")
    return v


def _counts(v, where, pids=None):
    if not isinstance(v, dict):
        _bad(where, "expected an object")
    for k, n in v.items():
        if (pids is not None and k not in pids) or not isinstance(n, int) or isinstance(n, bool) or n < 1:
            _bad(where, f"bad count {k!r}")
    return v


def _blob(v, where):
    _obj(v, where, ("file", "rawSha256", "rawBytes", "sha256", "bytes", "redactions"))
    _str(v["file"], where + ".file")
    _re(v["rawSha256"], _H64, where + ".rawSha256")
    _re(v["sha256"], _H64, where + ".sha256")
    _int(v["rawBytes"], where + ".rawBytes")
    _int(v["bytes"], where + ".bytes")
    _counts(v["redactions"], where + ".redactions", _PIDS)
    same = v["rawSha256"] == v["sha256"] and v["rawBytes"] == v["bytes"]
    if v["redactions"] and same:
        _bad(where, "redactions recorded but the raw and stored text are identical")
    if not v["redactions"] and not same:
        _bad(where, "raw and stored text differ although nothing was redacted")
    return v


def _gap(v, where):
    _obj(v, where, ("kind", "detail"))
    _str(v["kind"], where + ".kind", maxlen=100)
    if not isinstance(v["detail"], str) or len(v["detail"]) > 1000:
        _bad(where + ".detail", "expected a short string")


def _redaction_ok(version, digest, where):
    if version != REDACTION_VERSION or digest != patterns_digest():
        raise InputError(
            f"stale redaction in {where}: stored {version!r}/{str(digest)[:12]}, current "
            f"{REDACTION_VERSION!r}/{patterns_digest()[:12]}; re-import and refresh context")


def _validate_case(case, dirname) -> dict[str, dict]:
    """Closed-schema check; returns {relative file: blob meta} for every referenced blob."""
    _obj(case, "case", ("schema", "id", "repo", "base", "head", "files", "gaps", "coverage", "redaction", "importer"))
    if case["schema"] != CASE_SCHEMA:
        _bad("case.schema", "unexpected schema")
    m = _re(case["id"], _ID, "case.id")
    if case["id"] != dirname:
        _bad("case.id", f"does not match directory {dirname!r}")
    mm = _ID.fullmatch(case["id"])
    if case["repo"] != f"{mm.group(1)}/{mm.group(2)}":
        _bad("case.repo", "does not match case id")
    _str(case["importer"], "case.importer", maxlen=40)
    b = _obj(case["base"], "case.base", ("sha", "mergeBase", "textRef"))
    _re(b["sha"], _SHA, "case.base.sha")
    _re(b["mergeBase"], _SHA, "case.base.mergeBase", nullable=True)
    _re(b["textRef"], _SHA, "case.base.textRef")
    if b["textRef"] != (b["mergeBase"] or b["sha"]):
        _bad("case.base.textRef", "must be the merge base, else the manifest base")
    _re(_obj(case["head"], "case.head", ("sha",))["sha"], _SHA, "case.head.sha")
    r = _obj(case["redaction"], "case.redaction", ("version", "patternsSha256", "counts"))
    _redaction_ok(r["version"], r["patternsSha256"], "case.json")
    _counts(r["counts"], "case.redaction.counts", _PIDS)

    refs, seen, kinds = {}, set(), {}
    for g in _list(case["gaps"], "case.gaps"):
        _gap(g, "case.gaps[]")
        kinds[g["kind"]] = kinds.get(g["kind"], 0) + 1
    for i, f in enumerate(_list(case["files"], "case.files")):
        w = f"case.files[{i}]"
        _obj(f, w, ("path", "previousPath", "status", "additions", "deletions", "patch", "base", "head",
                    "gaps", "patchRedaction"), ("pathSha256",))
        path = _str(f["path"], w + ".path", nullable=True)
        prev = _str(f["previousPath"], w + ".previousPath", nullable=True)
        if f["status"] not in _STATUSES:
            _bad(w + ".status", "unknown status")
        _int(f["additions"], w + ".additions", True)
        _int(f["deletions"], w + ".deletions", True)
        if f["patchRedaction"] not in PATCH_REDACTION:
            _bad(w + ".patchRedaction", "unknown value")
        for g in _list(f["gaps"], w + ".gaps"):
            _gap(g, w + ".gaps[]")
            kinds[g["kind"]] = kinds.get(g["kind"], 0) + 1
        for p in (path, prev):
            if p is not None:
                try:
                    safeio.check_rel(p)
                except safeio.PathError as e:
                    raise InputError(f"{w}: {e}") from e
        if path is None:
            _re(f.get("pathSha256"), _H64, w + ".pathSha256")
            if f["patch"] or f["base"] or f["head"]:
                _bad(w, "a file without a safe path cannot carry blobs")
            continue
        if "pathSha256" in f:
            _bad(w, "pathSha256 only for rejected paths")
        if path.lower() in seen:
            _bad(w, "duplicate path")
        seen.add(path.lower())
        want = {"patch": f"patches/{path}.patch", "base": f"base/{prev or path}", "head": f"head/{path}"}
        for part, rel in want.items():
            if f[part] is None:
                continue
            _blob(f[part], f"{w}.{part}")
            if f[part]["file"] != rel:
                _bad(f"{w}.{part}.file", f"must be the canonical path {rel!r}")
            if refs.setdefault(rel, f[part]) != f[part]:
                _bad(f"{w}.{part}", f"{rel!r} is referenced by several files with different recorded metadata")
        _file_semantics(f, w, path, prev)
    c = _obj(case["coverage"], "case.coverage", ("scope", "fullRepositoryCoverage", "changedFilesExpected",
             "changedFilesListed", "changedFilesRecorded", "complete", "gapKinds", "note"))
    if c["scope"] != "changed-files-and-selected-context" or _bool(c["fullRepositoryCoverage"], "coverage") is not False:
        _bad("case.coverage", "scope/fullRepositoryCoverage must state changed files only")
    for k in ("changedFilesExpected", "changedFilesListed", "changedFilesRecorded"):
        _int(c[k], "case.coverage." + k)
    _str(c["note"], "case.coverage.note")
    if c["gapKinds"] != kinds or _bool(c["complete"], "case.coverage.complete") != (not kinds):
        _bad("case.coverage", "gapKinds/complete disagree with the recorded gaps")
    if c["changedFilesRecorded"] != len(case["files"]):
        _bad("case.coverage.changedFilesRecorded", "does not match files")
    case_kinds = {g["kind"] for g in case["gaps"]}
    omitted = c["changedFilesListed"] - c["changedFilesRecorded"]
    if omitted < 0 or c["changedFilesListed"] > c["changedFilesExpected"]:
        _bad("case.coverage", "listed files must lie between recorded and expected")
    if omitted and "files-omitted-by-limit" not in case_kinds:
        _bad("case.coverage", "listed files were dropped without a files-omitted-by-limit gap")
    if c["changedFilesListed"] < c["changedFilesExpected"] and "files-list-incomplete" not in case_kinds:
        _bad("case.coverage", "fewer files listed than expected without a files-list-incomplete gap")
    totals: dict[str, int] = {}
    for f in case["files"]:
        for part in ("patch", "base", "head"):
            for k, n in ((f[part] or {}).get("redactions") or {}).items():
                totals[k] = totals.get(k, 0) + n
    if r["counts"] != totals:
        _bad("case.redaction.counts", "do not equal the sum over the file blobs")
    return refs


def _gap_kinds(f, prefix) -> bool:
    return any(g["kind"].startswith(prefix) for g in f["gaps"])


def _file_semantics(f, w, path, prev) -> None:
    """Status, gaps and redaction markers must tell the truth about which blobs are present."""
    st, kinds = f["status"], {g["kind"] for g in f["gaps"]}
    if path is None:
        if "unsafe-or-duplicate-path" not in kinds:
            _bad(w, "a file without a safe path needs an unsafe-or-duplicate-path gap")
        return
    if st == "added" and f["base"]:
        _bad(w, "an added file cannot have a base blob")
    if st == "removed" and f["head"]:
        _bad(w, "a removed file cannot have a head blob")
    if prev is not None and st not in ("renamed", "copied"):
        _bad(w, "previousPath only for renamed or copied files")
    if st != "added" and not f["base"] and not _gap_kinds(f, "base-"):
        _bad(w, "base blob missing without a base-* gap")
    if st != "removed" and not f["head"] and not _gap_kinds(f, "head-"):
        _bad(w, "head blob missing without a head-* gap")
    if st in ("renamed", "copied") and prev is None and not _gap_kinds(f, "base-"):
        _bad(w, "a renamed or copied file needs previousPath (or a base-* gap for a rejected one)")
    unknown = f["additions"] is None or f["deletions"] is None
    changed = (f["additions"] or 0) + (f["deletions"] or 0) > 0
    pr = f["patchRedaction"]
    if st == "unchanged" and (changed or f["patch"] is not None):
        _bad(w, "an unchanged file cannot have changed lines or a patch")
    if unknown and "counts-unavailable" not in kinds:
        _bad(w, "additions/deletions are null without a counts-unavailable gap (counts are derived from a patch if present)")
    if f["patch"] is None:
        if changed and not _gap_kinds(f, "patch-"):
            _bad(w, "changed lines but no patch and no patch-* gap")
        if pr != "no-patch" and "patch-write-failed" not in kinds:
            _bad(w + ".patchRedaction", "no patch blob requires 'no-patch'")
    else:
        if pr == "no-patch":
            _bad(w + ".patchRedaction", "a patch blob is present")
        redacted = any(f[p] and f[p]["redactions"] for p in ("patch", "base", "head"))
        if (pr == "none") == redacted:
            _bad(w + ".patchRedaction", "'none' must hold exactly when no blob of the file was redacted")
    if (pr == "unverified") != ("patch-redaction-unverified" in kinds):
        _bad(w + ".patchRedaction", "'unverified' and the patch-redaction-unverified gap must go together")


def _validate_context(ctx, case) -> dict[str, dict]:
    _obj(ctx, "context", ("schema", "repo", "redactionVersion", "redactionPatternsSha256", "selectedPaths",
                          "coverage", "files"))
    if ctx["schema"] != CONTEXT_SCHEMA or ctx["repo"] != case["repo"]:
        _bad("context", "schema/repo mismatch")
    _redaction_ok(ctx["redactionVersion"], ctx["redactionPatternsSha256"], "context.json")
    cov = _obj(ctx["coverage"], "context.coverage", ("fullRepositoryCoverage", "note"))
    if _bool(cov["fullRepositoryCoverage"], "context.coverage") is not False:
        _bad("context.coverage", "fullRepositoryCoverage must be false")
    _str(cov["note"], "context.coverage.note")
    refs, keys = {}, set()
    for i, e in enumerate(_list(ctx["files"], "context.files")):
        w = f"context.files[{i}]"
        _obj(e, w, ("side", "path", "ref", "status"),
             ("gap", "file", "rawSha256", "rawBytes", "sha256", "bytes", "redactions"))
        if e["side"] not in ("base", "head"):
            _bad(w + ".side", "base or head")
        try:
            safeio.check_rel(_str(e["path"], w + ".path"))
        except safeio.PathError as x:
            raise InputError(f"{w}: {x}") from x
        want_ref = case["head"]["sha"] if e["side"] == "head" else case["base"]["textRef"]
        if e["ref"] != want_ref:
            _bad(w + ".ref", "must be the case's pinned ref for that side")
        if (e["side"], e["path"]) in keys:
            _bad(w, "duplicate entry")
        keys.add((e["side"], e["path"]))
        if e["status"] == "ok":
            if set(e) - {"side", "path", "ref", "status", "file", "rawSha256", "rawBytes", "sha256", "bytes", "redactions"} \
                    or "gap" in e:
                _bad(w, "ok entry carries unexpected keys")
            _blob({k: e.get(k) for k in ("file", "rawSha256", "rawBytes", "sha256", "bytes", "redactions")}, w)
            rel = f"context/{e['side']}/{e['path']}"
            if e["file"] != rel:
                _bad(w + ".file", f"must be the canonical path {rel!r}")
            refs[rel] = e
        elif e["status"] == "gap":
            if set(e) != {"side", "path", "ref", "status", "gap"}:
                _bad(w, "gap entry must carry exactly a gap")
            _gap(e["gap"], w + ".gap")
        else:
            _bad(w + ".status", "ok or gap")
    sel = [{"side": e["side"], "path": e["path"], "ref": e["ref"]} for e in ctx["files"]]
    if ctx["selectedPaths"] != sel:
        _bad("context.selectedPaths", "must list exactly the context entries")
    return refs


def _tree_files(root: Path) -> set[str]:
    out = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                raise InputError(f"symlink under input/: {p.relative_to(root)}")
        for name in filenames:
            p = Path(dirpath) / name
            if not p.is_file():
                raise InputError(f"special file under input/: {p.relative_to(root)}")
            out.add(p.relative_to(root).as_posix())
    return out


def _read_blob(case_dir, meta, where) -> str:
    data = safeio.read_file(case_dir, "input/" + meta["file"])
    if hashlib.sha256(data).hexdigest() != meta["sha256"] or len(data) != meta["bytes"]:
        raise InputError(f"integrity mismatch: {meta['file']}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise InputError(f"{meta['file']}: not UTF-8") from e
    if _c.contains_protected(text):
        raise InputError(f"{meta['file']}: protected text present (stale or tampered redaction)")
    return text


def _check_patches(case, texts) -> None:
    """The patch must be the diff the counts and the stored base/head claim."""
    for f in case["files"]:
        if f["path"] is None or not f["patch"]:
            continue
        patch = texts[f["patch"]["file"]]
        got = count_changes(patch)
        if got is None:
            raise InputError(f"{f['path']}: patch is not a well-formed unified diff")
        want = (f["additions"], f["deletions"])
        if None in want:
            f["additions"], f["deletions"] = got        # derived from the patch, never trusted as null
            if f["status"] == "unchanged" and got != (0, 0):
                raise InputError(f"{f['path']}: an unchanged file has changed lines in its patch")
        elif got != want:
            raise InputError(f"{f['path']}: additions/deletions {want} do not match the patch {got}")
        if f["patchRedaction"] == "unverified":
            continue
        have_base = f["base"] or f["status"] == "added"
        have_head = f["head"] or f["status"] == "removed"
        if have_base and have_head and not reconstructs(texts[f["base"]["file"]] if f["base"] else "", patch,
                                                         texts[f["head"]["file"]] if f["head"] else ""):
            raise InputError(f"{f['path']}: the patch does not turn the stored base into the stored head")


def load_reviewer_input(case_dir) -> dict:
    """Return {'case': ..., 'context': ...} from input/ only; source/ is never opened."""
    case_dir = Path(case_dir)
    try:
        return _load(case_dir)
    except (InputError, safeio.PathError):
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OSError) as e:
        raise InputError(f"malformed reviewer input in {case_dir.name}: {type(e).__name__}: {e}") from e


def _load(case_dir: Path) -> dict:
    try:
        case = safeio.read_json(case_dir, "input/case.json")
    except (safeio.PathError, FileNotFoundError, ValueError) as e:
        raise InputError(f"no reviewer input in {case_dir}: {e}") from e
    refs = _validate_case(case, case_dir.name)
    try:
        context = safeio.read_json(case_dir, "input/context.json")
        has_ctx = True
    except safeio.PathError:
        if (case_dir / "input" / "context.json").exists() or (case_dir / "input" / "context.json").is_symlink():
            raise
        context, has_ctx = {"schema": CONTEXT_SCHEMA, "files": []}, False
    ctx_refs = _validate_context(context, case) if has_ctx else {}
    bad = forbidden_keys_in(case) + forbidden_keys_in(context)
    if bad:
        raise InputError(f"forbidden reviewer-input fields: {bad}")
    for name, doc in (("case.json", case), ("context.json", context)):
        if _c.json_contains_protected(doc):
            raise InputError(f"{name}: protected text present")
    allowed = {"case.json", *refs, *ctx_refs} | ({"context.json"} if has_ctx else set())
    actual = _tree_files(case_dir / "input")
    if actual != allowed:
        extra, missing = sorted(actual - allowed), sorted(allowed - actual)
        raise InputError(f"input/ file set differs from the referenced set: unreferenced={extra[:5]} missing={missing[:5]}")
    texts = {meta["file"]: _read_blob(case_dir, meta, meta["file"]) for meta in (*refs.values(), *ctx_refs.values())}
    _check_patches(case, {k: v for k, v in texts.items() if k in refs})
    return {"case": case, "context": context}
