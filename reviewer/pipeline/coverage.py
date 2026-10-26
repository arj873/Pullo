"""Optional host-provided PARTIAL coverage (`historical-coverage@1`), S0B-02b.

The host (reviewer.historical bridge) hands the pipeline the union trees of the changed files plus selected
context, and this document says which paths are changed and which are only context. The pipeline never infers
"changed" from the trees themselves: a head-only context file would otherwise read as an added file.

Everything here is pure (no disk): validation against the PINNED manifests, the identity digest, the changed
rows PREPARE reports, the tools View and the model-visible coverage statement. `coverage=None` never reaches
this module, so full-view behavior is untouched.
"""

from __future__ import annotations

from reviewer.contracts.canonical import digest
from reviewer.contracts.redaction import redact
from reviewer.tools import View, ViewError, partial_union_view

from .errors import PipelineError

SCHEMA = "historical-coverage@1"
SCOPE = "changed-files-and-selected-context"
SIDES = ("base", "head")
STATUSES = frozenset({"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"})
REQUIRED = ("schema", "scope", "fullRepositoryCoverage", "changedPaths", "contextPaths")
OPTIONAL = ("recorded", "unsafePathsOmitted", "note", "pinsDigest")
MAX_PATHS = 100_000


def _bad(msg: str):
    raise PipelineError("invalid-input", f"coverage: {msg}")


def _path(p, what: str) -> str:
    if not isinstance(p, str) or not p or p.startswith("/") or "\\" in p or "\x00" in p \
            or any(part in ("", ".", "..") for part in p.split("/")):
        _bad(f"{what} is not a relative POSIX path")
    return p


def _flag(v, what: str) -> bool:
    if not isinstance(v, bool):
        _bad(f"{what} must be a boolean")
    return v


def rows_of(cov: dict) -> tuple[list[tuple[str, str]], list[dict]]:
    """-> (sorted [(A|D|M, path)], gap entries). Rows follow the RECORDED status, not the base/head flags: the
    flags only say which side's bytes were captured. A real add/delete is reported only when the recorded status
    says so AND the matching side exists. A 'modified'/'changed'/rename whose other side is missing is a GAP row:
    it is listed as changed with no diff and is never presented as an add or a delete. Ambiguous combinations
    (e.g. status added with a base side, removed with a head side) are gaps too. 'unchanged' yields no row."""
    out, gaps = set(), []
    for e in cov["changedPaths"]:
        p, q, b, h, st = e["path"], e["previousPath"], e["base"], e["head"], e["status"]
        if st == "unchanged":
            continue
        if st == "added" and h and not b:
            out.add(("A", p))
        elif st == "removed" and b and not h:
            out.add(("D", p))
        elif st in ("modified", "changed") and b and h and q is None:
            out.add(("M", p))
        elif st == "renamed" and b and h and q is not None and q != p:
            out |= {("D", q), ("A", p)}
        elif st == "copied" and b and h and q is not None and q != p:
            out.add(("A", p))
        else:
            gaps.append(e)
    return sorted(out, key=lambda r: (r[1], r[0])), gaps


def changed_sets(cov: dict) -> dict[str, set]:
    """Paths that are CHANGED on each side (as recorded by the coverage flags)."""
    out = {"base": set(), "head": set()}
    for e in cov["changedPaths"]:
        if e["base"]:
            out["base"].add(e["previousPath"] or e["path"])
        if e["head"]:
            out["head"].add(e["path"])
    return out


def validate(cov, base_manifest: dict, head_manifest: dict) -> str:
    """Closed-shape validation, then agreement with the PINNED union manifests. Returns the coverage digest."""
    if not isinstance(cov, dict):
        _bad("must be an object")
    extra = sorted(set(cov) - set(REQUIRED) - set(OPTIONAL))
    if extra:
        _bad(f"unknown key(s) {extra[:3]}")
    for k in REQUIRED:
        if k not in cov:
            _bad(f"missing {k}")
    if cov["schema"] != SCHEMA or cov["scope"] != SCOPE:
        _bad(f"schema/scope must be {SCHEMA} / {SCOPE}")
    if cov["fullRepositoryCoverage"] is not False:
        _bad("fullRepositoryCoverage must be false: a partial view never claims whole-repository coverage")
    if "pinsDigest" in cov and not (isinstance(cov["pinsDigest"], str) and cov["pinsDigest"].startswith("sha256:")):
        _bad("pinsDigest must be a sha256: digest")
    if "unsafePathsOmitted" in cov and not (isinstance(cov["unsafePathsOmitted"], int)
                                            and not isinstance(cov["unsafePathsOmitted"], bool)
                                            and cov["unsafePathsOmitted"] >= 0):
        _bad("unsafePathsOmitted must be a non-negative integer")
    if "recorded" in cov and not isinstance(cov["recorded"], dict):
        _bad("recorded must be an object")
    ch = cov["changedPaths"]
    if not isinstance(ch, list) or len(ch) > MAX_PATHS:
        _bad("changedPaths must be a list")
    seen = set()
    for i, e in enumerate(ch):
        if not isinstance(e, dict) or set(e) != {"path", "previousPath", "status", "base", "head", "gapKinds"}:
            _bad(f"changedPaths[{i}] has the wrong keys")
        _path(e["path"], f"changedPaths[{i}].path")
        if e["previousPath"] is not None:
            _path(e["previousPath"], f"changedPaths[{i}].previousPath")
        if e["status"] not in STATUSES:
            _bad(f"changedPaths[{i}].status is not a known status")
        _flag(e["base"], f"changedPaths[{i}].base")
        _flag(e["head"], f"changedPaths[{i}].head")
        if not (isinstance(e["gapKinds"], list) and all(isinstance(g, str) for g in e["gapKinds"])):
            _bad(f"changedPaths[{i}].gapKinds must be a list of strings")
        if e["path"] in seen:
            _bad(f"changedPaths lists {e['path']!r} twice")
        seen.add(e["path"])
    ctx = cov["contextPaths"]
    if not isinstance(ctx, dict) or set(ctx) != set(SIDES):
        _bad("contextPaths must be {base: [...], head: [...]}")
    for s in SIDES:
        if not isinstance(ctx[s], list) or len(ctx[s]) > MAX_PATHS or len(set(ctx[s])) != len(ctx[s]):
            _bad(f"contextPaths.{s} must be a list of unique paths")
        for p in ctx[s]:
            _path(p, f"contextPaths.{s} entry")
    try:
        dig = digest(cov)
    except (TypeError, ValueError) as e:
        _bad(f"not canonical JSON: {e}")
    _logical_paths_unique(cov)
    changed = changed_sets(cov)
    for side, manifest in (("base", base_manifest), ("head", head_manifest)):
        if any(e.get("type") not in ("file", "executable") for e in manifest["entries"]):
            _bad(f"{side}: the pinned {side} manifest holds an entry that is not a regular file (symlink?)")
        files = {e["path"] for e in manifest["entries"]}
        context = set(ctx[side])
        if context & changed[side]:
            _bad(f"{side}: a path is both changed and context: {sorted(context & changed[side])[:3]}")
        absent = absent_names(cov)[side] & files
        if absent:
            _bad(f"{side}: a changed entry records the {side} side as absent, yet {sorted(absent)[:3]} is in the "
                 f"pinned {side} manifest (as context): the record contradicts itself")
        claimed = changed[side] | context
        if claimed - files:
            _bad(f"{side}: coverage names path(s) absent from the pinned {side} manifest: "
                 f"{sorted(claimed - files)[:3]}")
        if files - claimed:
            _bad(f"{side}: pinned {side} manifest holds path(s) the coverage does not classify as changed or "
                 f"context: {sorted(files - claimed)[:3]}")
    _kind_conflicts(cov, base_manifest, head_manifest)
    return dig


def absent_names(cov: dict) -> dict[str, set]:
    """Names a changed entry says are NOT on a side (flag false). Same naming as changed_sets: the base side of a
    rename is its previousPath. A flag only says what was captured; a name it disowns must not also be classified
    on that side, or the record contradicts itself (never resolved by guessing which half is true)."""
    out = {"base": set(), "head": set()}
    for e in cov["changedPaths"]:
        if not e["base"]:
            out["base"].add(e["previousPath"] or e["path"])
        if not e["head"]:
            out["head"].add(e["path"])
    return out


def _logical_paths_unique(cov: dict) -> None:
    """One logical path, one entry. A rename source (previousPath) is a path of its own: another entry for the same
    name (a one-sided 'modified x' next to 'x -> y', a chain x -> y -> z, a swap) would give PREPARE two rows with
    different statuses for one path. Ambiguous shapes are refused rather than canonicalised by guesswork."""
    owner: dict[str, int] = {}
    for i, e in enumerate(cov["changedPaths"]):
        for name in {e["path"], e["previousPath"]} - {None}:
            if owner.setdefault(name, i) != i:
                _bad(f"{name!r} is named by more than one changedPaths entry (rename source/target overlap): "
                     "ambiguous, refused")


def _kind_conflicts(cov: dict, base_manifest: dict, head_manifest: dict) -> None:
    """A path present in BOTH pinned unions must be the same kind on both sides (changed/changed or
    context/context): else the manifest delta, the diff tool and the record disagree about the file."""
    ch = changed_sets(cov)
    both = {e["path"] for e in base_manifest["entries"]} & {e["path"] for e in head_manifest["entries"]}
    bad = sorted(p for p in both if (p in ch["base"]) != (p in ch["head"]))
    if bad:
        _bad(f"{bad[0]!r} is present on both sides but changed on one side and only context on the other "
             f"({len(bad)} path(s)): contradictory record, refused")


def build_view(cov: dict, base, head) -> View:
    """One union tree per side through the tools' explicit factory (S0B-02c). Changed and context sets both come
    from the host coverage; the tools refuse any overlap or unclassified path."""
    ch = changed_sets(cov)
    _kind_conflicts(cov, base.manifest, head.manifest)    # the tools API itself accepts these (recorded limit, not fixed there)
    try:
        return partial_union_view(
            base=(base.root, base.manifest, frozenset(cov["contextPaths"]["base"]), frozenset(ch["base"])),
            head=(head.root, head.manifest, frozenset(cov["contextPaths"]["head"]), frozenset(ch["head"])),
            recorded=cov.get("recorded"))
    except ViewError as e:
        raise PipelineError("invalid-input", f"coverage: the tools refused the union view: {str(e)[:300]}") from None


def _kinds(v) -> set:
    return {k for k in (v if isinstance(v, (list, tuple)) else list(v) if isinstance(v, dict) else []) if isinstance(k, str)}


def gap_kinds(cov: dict) -> list[str]:
    """Every recorded gap kind: per-entry gapKinds, recorded.gapKinds AND recorded.contextGapKinds."""
    rec = cov.get("recorded") or {}
    kinds = {g for e in cov["changedPaths"] for g in e["gapKinds"]}
    return sorted(kinds | _kinds(rec.get("gapKinds")) | _kinds(rec.get("contextGapKinds")))


def context_gap(cov: dict) -> dict:
    """Selected context that was NOT recorded (recorded.contextGapKinds/contextGapCount) and whether the host
    marked the whole record incomplete. Never inferred from a missing key: absent keys say nothing."""
    rec = cov.get("recorded") or {}
    n = rec.get("contextGapCount")
    return {"kinds": sorted(_kinds(rec.get("contextGapKinds"))),
            "count": n if isinstance(n, int) and not isinstance(n, bool) and n >= 0 else None,
            "incomplete": rec.get("complete") is False}


def statement(cov: dict) -> str:
    """The sentence the models and review.md get instead of 'Two full pinned snapshots'."""
    n_ch, n_b, n_h = len(cov["changedPaths"]), len(cov["contextPaths"]["base"]), len(cov["contextPaths"]["head"])
    kinds = gap_kinds(cov)
    s = (f"PARTIAL coverage, NOT the whole repository: only the pull request's {n_ch} recorded changed path(s) and "
         f"explicitly selected context ({n_b} base file(s), {n_h} head file(s)) are present. A path that is not "
         "listed may exist in the repository: absence here is not evidence that code, callers, tests or "
         "definitions do not exist. There is no native file retrieval; the context below is static, bounded and "
         "may be truncated or omitted.")
    if kinds:
        s += f" Recorded coverage gaps: {', '.join(kinds)}; the changed-file list, diffs or selected context may be incomplete."
    cg = context_gap(cov)
    if cg["kinds"] or cg["count"]:
        s += (f" Selected context that could NOT be recorded: {cg['count'] if cg['count'] is not None else 'some'} "
              f"file(s)" + (f" ({', '.join(cg['kinds'])})" if cg["kinds"] else "") + "; it is missing from the context below.")
    if cg["incomplete"] and not (kinds or cg["kinds"] or cg["count"]):
        s += " The host marked this coverage record incomplete without naming a reason."
    gaps = rows_of(cov)[1]
    if gaps:
        s += (f" {len(gaps)} changed path(s) were recorded on one side only or with an ambiguous status; they are "
              "listed as changed but have no diff, and are NOT known additions or deletions.")
    if cov.get("unsafePathsOmitted"):
        s += f" {cov['unsafePathsOmitted']} changed path(s) with unsafe names were omitted."
    return redact(s)[0]


def detail(cov: dict, limit: int = 100) -> dict:
    """Bounded machine-readable twin of statement() for the prompts."""
    ch = [{"path": e["path"], "status": e["status"], "gapKinds": list(e["gapKinds"])} for e in cov["changedPaths"]]
    return {"scope": cov["scope"], "fullRepositoryCoverage": False, "changedPathCount": len(ch),
            "changedPaths": ch[:limit], "contextPathCount": {s: len(cov["contextPaths"][s]) for s in SIDES},
            "contextPaths": {s: sorted(cov["contextPaths"][s])[:limit] for s in SIDES}, "gapKinds": gap_kinds(cov),
            "contextGap": context_gap(cov),
            "oneSidedOrAmbiguous": [{"path": e["path"], "status": e["status"], "recordedSides":
                                     [x for x in SIDES if e[x]]} for e in rows_of(cov)[1]][:limit]}
