"""Import pinned historical PR inputs and pinned context files. No repository code is run."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
import urllib.parse

from . import safeio
from .http import ALLOWED_REPOS, SHA, Client, FetchError, Limits, check_url
from .inputs import CASE_SCHEMA, CONTEXT_SCHEMA
from .patchcheck import reconstructs
from .redact import REDACTION_VERSION, RedactionError, patterns_digest, redact_text

IMPORTER_VERSION = "r01@2"
SOURCE_SCHEMA = "historical-case-source@1"
INITIAL_CASES = ("boykopovar--AnyPS5--10643", "stablyai--orca--33429", "Vencord--Vesktop--1347")
_ID = re.compile(r"^([A-Za-z0-9._-]+)--([A-Za-z0-9._-]+)--(\d+)$")
_CONTEXT = ("input/context", "input/context.json")


class ManifestError(ValueError):
    pass


def load_manifest(path) -> list[dict]:
    with open(path, "rb") as f:
        doc = json.load(f)
    cases = doc.get("cases")
    if not isinstance(cases, list):
        raise ManifestError("manifest has no cases list")
    for c in cases:
        m = _ID.match(str(c.get("id")))
        if not m or c.get("repository") != f"{m.group(1)}/{m.group(2)}" or c.get("prNumber") != int(m.group(3)):
            raise ManifestError(f"inconsistent case id: {c.get('id')!r}")
        for k in ("baseSha", "headSha"):
            if not re.fullmatch(SHA, str(c.get(k))):
                raise ManifestError(f"{c['id']}: {k} is not a 40-hex sha")
    return cases


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _json(r):
    try:
        return json.loads(r.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise FetchError("bad-json", str(e)) from e


def _raw_url(repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{urllib.parse.quote(path, safe='/')}"


def _fetch_text(client: Client, repo: str, ref: str, path: str, limits: Limits):
    """-> (text|None, rawBytes|None, gap|None). Never raises for per-file problems."""
    try:
        body = client.get(_raw_url(repo, ref, path), max_bytes=limits.file_bytes).body
    except FetchError as e:
        kind = {"not-found": "text-not-found", "too-large": "text-too-large"}.get(e.kind, f"text-fetch-{e.kind}")
        return None, None, {"kind": kind, "detail": str(e)[:200]}
    if b"\x00" in body[:8192]:
        return None, body, {"kind": "binary", "detail": "NUL byte; text not stored"}
    try:
        return body.decode("utf-8"), body, None
    except UnicodeDecodeError:
        return None, body, {"kind": "non-utf8", "detail": "not valid UTF-8; text not stored"}


def _write_blob(root, rel: str, raw: bytes, red: str, counts: dict) -> dict:
    """Write already-redacted text under root/input/<rel>; return provenance metadata."""
    data = red.encode("utf-8")
    safeio.write_file(root, "input/" + rel, data)
    return {"file": rel, "rawSha256": _sha(raw), "rawBytes": len(raw), "sha256": _sha(data),
            "bytes": len(data), "redactions": counts}


def _safe_name(name) -> bool:
    try:
        return isinstance(name, str) and safeio.check_rel(name) == name and redact_text(name)[0] == name
    except (safeio.PathError, RedactionError):
        return False


def _verify(case: dict, pr: dict) -> list[dict]:
    exp = {"state": "closed", "merged": True, "baseSha": case["baseSha"], "headSha": case["headSha"],
           "changedFiles": case["changedFiles"], "additions": case["additions"], "deletions": case["deletions"]}
    obs = {"state": pr.get("state"), "merged": pr.get("merged"),
           "baseSha": (pr.get("base") or {}).get("sha"), "headSha": (pr.get("head") or {}).get("sha"),
           "changedFiles": pr.get("changed_files"), "additions": pr.get("additions"),
           "deletions": pr.get("deletions")}
    bad = [{"field": k, "expected": exp[k], "observed": obs[k]} for k in exp if exp[k] != obs[k]]
    full = ((pr.get("base") or {}).get("repo") or {}).get("full_name")
    if not isinstance(full, str) or full.lower() != case["repository"].lower():
        bad.append({"field": "repository", "expected": case["repository"], "observed": full})
    return bad


def _collect(client, case, limits, tmp, log):
    """Fetch and write everything for one case into tmp. Returns (status, source, input|None)."""
    repo, n = case["repository"], case["prNumber"]
    start = len(client.requests)
    src = {"schema": SOURCE_SCHEMA, "evaluationOnly": True, "id": case["id"], "repository": repo,
           "prNumber": n, "importer": IMPORTER_VERSION,
           "manifest": {k: case[k] for k in ("state", "merged", "mergedAt", "closedAt", "baseSha", "headSha",
                                             "changedFiles", "additions", "deletions")},
           "bodyExcluded": "PR descriptions are mutable after merge and are not collected",
           "observed": None, "verification": None, "requests": None, "failure": None}

    def done(status, inp=None):
        src["status"] = status
        src["requests"] = [{k: r[k] for k in ("url", "status", "error")} for r in client.requests[start:]]
        return status, src, inp

    api = f"https://api.github.com/repos/{repo}"
    client.set_scope(repo, n, {case["baseSha"], case["headSha"]})
    try:
        pr = _json(client.get(f"{api}/pulls/{n}"))
        if not isinstance(pr, dict):
            raise FetchError("bad-json", "pull response is not an object")
    except FetchError as e:
        src["failure"] = {"stage": "pull", "kind": e.kind, "detail": str(e)[:200]}
        return done("failed")
    src["observed"] = {"state": pr.get("state"), "merged": pr.get("merged"), "mergedAt": pr.get("merged_at"),
                       "closedAt": pr.get("closed_at"), "mergeCommitSha": pr.get("merge_commit_sha"),
                       "baseSha": (pr.get("base") or {}).get("sha"), "headSha": (pr.get("head") or {}).get("sha"),
                       "changedFiles": pr.get("changed_files"), "additions": pr.get("additions"),
                       "deletions": pr.get("deletions"),
                       "headRepo": ((pr.get("head") or {}).get("repo") or {}).get("full_name")}
    mism = _verify(case, pr)
    src["verification"] = {"ok": not mism, "mismatches": mism}
    if mism:
        return done("rejected")

    # changed files (paginated, bounded)
    expected = case["changedFiles"]
    files, page, truncated = [], 1, False
    try:
        while True:
            if page > limits.max_pages:
                truncated = True
                break
            arr = _json(client.get(f"{api}/pulls/{n}/files?per_page=100&page={page}"))
            if not isinstance(arr, list):
                raise FetchError("bad-json", "files response is not a list")
            files += arr
            if len(arr) < 100 or len(files) >= limits.max_files:
                break
            page += 1
    except FetchError as e:
        src["failure"] = {"stage": "files", "kind": e.kind, "detail": str(e)[:200]}
        return done("failed")
    case_gaps = []
    omitted = max(0, len(files) - limits.max_files)
    if omitted:
        case_gaps.append({"kind": "files-omitted-by-limit", "detail": f"{omitted} files beyond max_files={limits.max_files}"})
        files = files[:limits.max_files]
    if len(files) + omitted < expected or truncated:
        case_gaps.append({"kind": "files-list-incomplete",
                          "detail": f"listed {len(files) + omitted} of {expected} changed files"})

    # merge base (pre-image of the PR diff); never a branch name
    merge_base = None
    try:
        cmp = _json(client.get(f"{api}/compare/{case['baseSha']}...{case['headSha']}?per_page=1"))
        mb = ((cmp or {}).get("merge_base_commit") or {}).get("sha")
        if isinstance(mb, str) and re.fullmatch(SHA, mb):
            merge_base = mb
            client.pin_sha(mb)
        else:
            raise FetchError("bad-json", "no merge_base_commit.sha")
    except FetchError as e:
        case_gaps.append({"kind": "merge-base-unresolved",
                          "detail": f"{e.kind}; base text taken at manifest baseSha, which may differ from the diff pre-image"})
    src["observed"]["mergeBase"] = merge_base
    base_ref = merge_base or case["baseSha"]
    head_ref = case["headSha"]

    entries, seen, raw_total = [], set(), 0
    for f in sorted(files, key=lambda x: str(x.get("filename"))):
        name, prev, status = f.get("filename"), f.get("previous_filename"), f.get("status")
        adds, dels = f.get("additions"), f.get("deletions")
        e = {"path": name if _safe_name(name) and name.lower() not in seen else None,
             "previousPath": prev if prev and _safe_name(prev) else None, "status": status,
             "additions": adds, "deletions": dels, "patch": None, "base": None, "head": None, "gaps": [], "patchRedaction": "no-patch"}
        gaps = e["gaps"]
        if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in (adds, dels)):
            e["additions"] = e["deletions"] = None
            gaps.append({"kind": "counts-unavailable", "detail": "GitHub returned no usable additions/deletions"})
        if e["path"] is None:
            e["pathSha256"] = _sha(str(name).encode("utf-8", "replace"))
            gaps.append({"kind": "unsafe-or-duplicate-path", "detail": "path rejected; nothing stored for this file"})
            entries.append(e)
            continue
        seen.add(name.lower())
        path = name

        texts = {}   # part -> (rawBytes, text)
        patch = f.get("patch")
        if isinstance(patch, str):
            raw = patch.encode("utf-8")
            if len(raw) > limits.file_bytes:
                gaps.append({"kind": "patch-too-large", "detail": f"{len(raw)} bytes"})
            else:
                texts["patch"] = (raw, patch)
        elif (adds or 0) + (dels or 0) > 0:
            gaps.append({"kind": "patch-unavailable", "detail": "GitHub returned no patch (binary or too large)"})
        # else: pure rename/mode change, no textual patch exists

        base_path = e["previousPath"] if prev else path
        rels = {"patch": f"patches/{path}.patch", "base": f"base/{base_path}", "head": f"head/{path}"}
        sides = []
        if status != "added":
            sides.append(("base", base_ref, base_path, prev is not None and e["previousPath"] is None))
        if status != "removed":
            sides.append(("head", head_ref, path, False))
        for part, ref, p, bad_prev in sides:
            if bad_prev:
                gaps.append({"kind": "base-text-unavailable", "detail": "previous path rejected"})
                continue
            if raw_total >= limits.case_bytes:
                gaps.append({"kind": f"{part}-text-case-byte-limit", "detail": f"case limit {limits.case_bytes}"})
                continue
            text, raw, gap = _fetch_text(client, repo, ref, p, limits)
            raw_total += len(raw or b"")
            if gap:
                gap["kind"] = f"{part}-{gap['kind']}"
                gaps.append(gap)
                continue
            texts[part] = (raw, text)

        red = {}
        for part, (raw, text) in texts.items():
            try:
                red[part] = redact_text(text, patch=(part == "patch"))
            except RedactionError as ex:
                gaps.append({"kind": f"{part}-redaction-failed", "detail": str(ex)[:200]})
        redacted = any(c for _, c in red.values())
        e["patchRedaction"] = "unverified" if redacted else "none"
        if "patch" not in red:
            e["patchRedaction"] = "no-patch"
        elif redacted:
            have_base = "base" in red or status == "added"
            have_head = "head" in red or status == "removed"
            if have_base and have_head:
                if reconstructs(red["base"][0] if "base" in red else "", red["patch"][0],
                                red["head"][0] if "head" in red else ""):
                    e["patchRedaction"] = "reconstructs"
                else:
                    del red["patch"]
                    e["patchRedaction"] = "no-patch"
                    gaps.append({"kind": "patch-redaction-inconsistent",
                                 "detail": "redacted patch does not map redacted base to redacted head; patch withheld"})
            else:
                gaps.append({"kind": "patch-redaction-unverified",
                             "detail": "redacted patch could not be checked against both sides"})
        for part, (text, counts) in red.items():
            try:
                e[part] = _write_blob(tmp, rels[part], texts[part][0], text, counts)
            except (safeio.PathError, RedactionError) as ex:
                gaps.append({"kind": f"{part}-write-failed", "detail": str(ex)[:200]})
        entries.append(e)

    entries.sort(key=lambda x: (x["path"] is None, x["path"] or x["pathSha256"]))
    kinds: dict[str, int] = {}
    for g in case_gaps + [g for e in entries for g in e["gaps"]]:
        kinds[g["kind"]] = kinds.get(g["kind"], 0) + 1
    listed_adds = sum(e["additions"] or 0 for e in entries)
    listed_dels = sum(e["deletions"] or 0 for e in entries)
    if not omitted and not truncated and len(entries) == expected and (
            listed_adds != case["additions"] or listed_dels != case["deletions"]):
        case_gaps.append({"kind": "stats-mismatch", "detail": "file additions/deletions do not sum to PR totals"})
        kinds["stats-mismatch"] = 1
    totals: dict[str, int] = {}
    for e in entries:
        for part in ("patch", "base", "head"):
            for k, v in ((e[part] or {}).get("redactions") or {}).items():
                totals[k] = totals.get(k, 0) + v
    complete = not kinds
    inp = {"schema": CASE_SCHEMA, "id": case["id"], "repo": repo,
           "base": {"sha": case["baseSha"], "mergeBase": merge_base, "textRef": base_ref},
           "head": {"sha": head_ref},
           "files": entries, "gaps": case_gaps,
           "coverage": {"scope": "changed-files-and-selected-context", "fullRepositoryCoverage": False,
                        "changedFilesExpected": expected, "changedFilesListed": len(entries) + omitted,
                        "changedFilesRecorded": len(entries), "complete": complete, "gapKinds": kinds,
                        "note": "Only changed files and explicitly fetched context are present; "
                                "this is never a full-repository snapshot."},
           "redaction": {"version": REDACTION_VERSION, "patternsSha256": patterns_digest(), "counts": totals},
           "importer": IMPORTER_VERSION}
    return done("complete" if complete else "partial", inp)


def _swap(out_root, cid, tmp, replace, log) -> str:
    dest = os.path.join(out_root, cid)
    if not os.path.lexists(dest):
        os.rename(tmp, dest)
        return "written"
    try:
        same = safeio.tree_digest(dest, _CONTEXT) == safeio.tree_digest(tmp)
    except safeio.PathError as e:
        log(f"{cid}: existing tree unreadable ({e}); not touching it")
        shutil.rmtree(tmp)
        return "changed-not-written"
    if same:
        shutil.rmtree(tmp)
        return "unchanged"
    if not replace:
        shutil.rmtree(tmp)
        return "changed-not-written"
    old = f"{dest}.old-{secrets.token_hex(4)}"
    os.rename(dest, old)
    for rel in _CONTEXT:  # keep fetched context across a re-import
        if os.path.lexists(os.path.join(old, rel)) and os.path.isdir(os.path.join(tmp, "input")):
            os.rename(os.path.join(old, rel), os.path.join(tmp, rel))
    os.rename(tmp, dest)
    shutil.rmtree(old)
    return "replaced"


def import_case(client: Client, case: dict, out_root, limits: Limits, *, replace=False, log=lambda m: None) -> dict:
    out_root = os.fspath(out_root)
    os.makedirs(out_root, exist_ok=True)
    os.close(safeio._open_root(out_root))  # root must be a real directory, not a symlink
    tmp = tempfile.mkdtemp(prefix=f".tmp-{case['id']}-", dir=out_root)   # unique; never collides with a crashed run
    os.chmod(tmp, 0o755)
    try:
        status, src, inp = _collect(client, case, limits, tmp, log)
        safeio.write_json(tmp, "source/collection.json", src)
        if inp is not None:
            safeio.write_json(tmp, "input/case.json", inp)
        wrote = _swap(out_root, case["id"], tmp, replace, log)
    finally:
        if os.path.isdir(tmp) and not os.path.islink(tmp):
            shutil.rmtree(tmp)
    gaps = (inp or {}).get("coverage", {}).get("gapKinds", {})
    log(f"{case['id']}: {status} ({wrote}) gaps={gaps}")
    return {"id": case["id"], "status": status, "write": wrote, "gapKinds": gaps, "input": inp is not None,
            "scope": inp["coverage"]["scope"] if inp else None, "fullRepositoryCoverage": False,
            "redactionVersion": inp["redaction"]["version"] if inp else None,
            "redactionPatternsSha256": inp["redaction"]["patternsSha256"] if inp else None}


def fetch_context(client: Client, case_dir, side: str, paths: list[str], limits: Limits,
                  log=lambda m: None) -> dict:
    """Fetch pinned dependency/caller files into input/context/<side>/<path> (repeatable)."""
    if side not in ("base", "head"):
        raise ValueError("side must be base or head")
    case = safeio.read_json(case_dir, "input/case.json")
    if case.get("schema") != CASE_SCHEMA or os.path.basename(os.path.normpath(case_dir)) != case["id"]:
        raise safeio.PathError("case directory does not match its input/case.json")
    repo = case["repo"]
    ref = case["head"]["sha"] if side == "head" else case["base"]["textRef"]
    try:
        ctx = safeio.read_json(case_dir, "input/context.json")
    except safeio.PathError:
        ctx = {"schema": CONTEXT_SCHEMA, "files": []}
    try:
        by_key = {(c["side"], c["path"]): c for c in ctx["files"]}
    except (KeyError, TypeError) as e:
        raise safeio.PathError(f"existing context.json is malformed ({e!r}); refresh it") from e
    client.set_scope(repo, None, {ref})
    for p in paths:
        safeio.check_rel(p)
        if redact_text(p)[0] != p:
            raise safeio.PathError("path contains protected text")
        if (side, p) not in by_key and len(by_key) >= limits.max_context_files:
            raise FetchError("budget", f"context file limit {limits.max_context_files}")
        check_url(_raw_url(repo, ref, p), client.allowed_repos)
        text, raw, gap = _fetch_text(client, repo, ref, p, limits)
        entry = {"side": side, "path": p, "ref": ref, "status": "ok" if gap is None else "gap"}
        if gap:
            entry["gap"] = gap
        else:
            rel = f"context/{side}/{p}"
            red, counts = redact_text(text)
            data = red.encode("utf-8")
            try:
                existing = safeio.read_file(case_dir, "input/" + rel)
            except safeio.PathError:
                existing = None
            if existing is None:
                safeio.write_file(case_dir, "input/" + rel, data)
            elif existing != data:
                raise safeio.PathError(f"pinned content for {p} differs from stored copy; refusing to overwrite")
            entry.update({"file": rel, "rawSha256": _sha(raw), "rawBytes": len(raw), "sha256": _sha(data),
                          "bytes": len(data), "redactions": counts})
        by_key[(side, p)] = entry
    files = [by_key[k] for k in sorted(by_key)]
    doc = {"schema": CONTEXT_SCHEMA, "repo": repo, "redactionVersion": REDACTION_VERSION,
           "redactionPatternsSha256": patterns_digest(),
           "selectedPaths": [{"side": c["side"], "path": c["path"], "ref": c["ref"]} for c in files],
           "coverage": {"fullRepositoryCoverage": False,
                        "note": "Only the selected paths above; callers/dependencies not listed were not fetched."},
           "files": files}
    safeio.write_json(case_dir, "input/context.json", doc, replace=True)
    log(f"context {side}: {[c['path'] for c in files if c['side'] == side]}")
    return doc


def _selected(src_dir) -> list[tuple[str, str]]:
    """(side, path) pairs recorded in a case's context.json; read leniently, validated strictly."""
    try:
        doc = safeio.read_json(src_dir, "input/context.json")
    except safeio.PathError:
        return []
    out = []
    try:
        for e in doc["selectedPaths"]:
            side, path = e["side"], e["path"]
            if side not in ("base", "head"):
                raise ValueError(side)
            safeio.check_rel(path)
            out.append((side, path))
    except (KeyError, TypeError, ValueError) as ex:
        raise safeio.PathError(f"cannot read selectedPaths from {src_dir}: {ex!r}") from ex
    return sorted(set(out))


def refresh_context(client: Client, case_dir, limits: Limits, log=lambda m: None, from_dir=None) -> dict:
    """Re-fetch the recorded context paths under the current redaction.

    from_dir=None refreshes in place: the stored context is moved aside, rebuilt from the same
    selected paths, and restored if anything fails. With from_dir (another corpus copy of the
    same case, read only) the paths are taken from there and fetched into case_dir."""
    case_dir = os.fspath(case_dir)
    pairs = _selected(from_dir or case_dir)
    parked = []
    if from_dir is None:
        tag = secrets.token_hex(4)
        for rel in _CONTEXT:
            src = os.path.join(case_dir, rel)
            if os.path.lexists(src):
                os.rename(src, f"{src}.stale-{tag}")
                parked.append((src, f"{src}.stale-{tag}"))
    try:
        doc = {"files": []}
        for side in ("base", "head"):
            paths = [p for sd, p in pairs if sd == side]
            if paths:
                doc = fetch_context(client, case_dir, side, paths, limits, log)
    except BaseException:
        for src, held in parked:
            if os.path.lexists(src):
                shutil.rmtree(src) if os.path.isdir(src) else os.unlink(src)
            os.rename(held, src)
        raise
    for _, held in parked:
        shutil.rmtree(held) if os.path.isdir(held) else os.unlink(held)
    return doc
