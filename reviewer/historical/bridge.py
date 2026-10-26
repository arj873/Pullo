"""Materialize one validated corpus case into two immutable host-owned side UNION snapshots.

Per side, the pinned changed layer and the pinned context layer (if any) are merged into one new tree whose
bytes all come from `read_verified` against the PINNED layer manifests. The result is a CaseInput over the
two union snapshot ids, SnapshotInputs for them and a host record (origin, as-of, coverage, provenance).
The tree is a partial view of the repository: changed files plus selected context, never full coverage.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts import require
from reviewer.contracts.canonical import digest
from reviewer.contracts.redaction import redact
from reviewer.contracts.schema import is_safe_relpath
from reviewer.contracts.snapshot import SnapshotError, build_manifest, read_verified, snapshot_id
from reviewer.corpus.inputs import load_reviewer_input
from reviewer.pipeline.spec import SnapshotInput
from reviewer.tools import View, ViewError, historical_input_view, partial_union_view

from .pins import BridgeError, check_pins, origin_of, read_nofollow

RECORD_SCHEMA = "historical-bridge@1"
COVERAGE_SCHEMA = "historical-coverage@1"
SIDES = ("base", "head")
META_MAX_BYTES = 8 << 20
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_SLUG = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
NOT_FULL = ("Partial view: the PR's changed files and explicitly selected context only. A path that is "
            "absent may exist in the repository; this is not full-repository coverage.")


@dataclass(frozen=True)
class BridgeLimits:
    max_entries: int = 20_000            # per side
    max_file_bytes: int = 16 << 20       # per file, passed to read_verified
    max_total_bytes: int = 256 << 20     # per side


def _slug(k) -> str:
    return k if isinstance(k, str) and 0 < len(k) <= 40 and set(k) <= _SLUG and redact(k)[0] == k else "other"


# ------------------------------------------------------------------ union (pure)

def union_entries(layers, limits: BridgeLimits = BridgeLimits()):
    """(sorted entries, {path: [layer names]}, [duplicate records]) for layers of one side, in order.

    A path in several layers is kept once only when type, size and hash are identical; its provenance
    lists every layer. A conflicting duplicate, a symlink entry or a file that is also a directory
    prefix of another path is refused."""
    by_path, prov = {}, {}
    total = 0
    for layer in layers:
        for e in layer.manifest["entries"]:
            p = e["path"]
            if e["type"] not in ("file", "executable"):
                raise BridgeError(f"layer {layer.name}: {p!r} is a {e['type']}, not a regular file")
            if e["size"] > limits.max_file_bytes:
                raise BridgeError(f"layer {layer.name}: {p!r} is above the {limits.max_file_bytes}-byte cap")
            key = {k: e[k] for k in ("path", "type", "size", "sha256")}
            if p in by_path:
                if by_path[p] != key:
                    raise BridgeError(f"{p!r} differs between layers {prov[p][0]!r} and {layer.name!r}")
                prov[p].append(layer.name)
                continue
            by_path[p], prov[p] = key, [layer.name]
            total += e["size"]
            if len(by_path) > limits.max_entries or total > limits.max_total_bytes:
                raise BridgeError(f"union exceeds {limits.max_entries} entries or {limits.max_total_bytes} bytes")
    for p in by_path:
        parts = p.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in by_path:
                raise BridgeError(f"{p!r} lies under a file of the same union")
    dups = [{"path": p, "layers": list(ls)} for p, ls in sorted(prov.items()) if len(ls) > 1]
    return [by_path[p] for p in sorted(by_path)], {p: list(prov[p]) for p in sorted(prov)}, dups


# ------------------------------------------------------------------ writing

def _open_rel(rfd: int, parts, create: bool) -> int:
    fd = os.dup(rfd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_tree(root: Path, files) -> None:
    """Create `root` and write (path, type, bytes) files without following links; then make every file
    and directory read-only (0444 / 0555 executable / 0555 directories)."""
    os.mkdir(root, 0o700)
    rfd = os.open(root, _DIR_FLAGS)
    dirs = set()
    try:
        for path, kind, data in files:
            parts = path.split("/")
            dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
            dfd = _open_rel(rfd, parts[:-1], create=True)
            try:
                ffd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=dfd)
            finally:
                os.close(dfd)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(ffd, view):]
                os.fchmod(ffd, 0o555 if kind == "executable" else 0o444)
            finally:
                os.close(ffd)
        for d in sorted(dirs, key=lambda d: -d.count("/")):
            dfd = _open_rel(rfd, d.split("/"), create=False)
            try:
                os.fchmod(dfd, 0o555)
            finally:
                os.close(dfd)
        os.fchmod(rfd, 0o555)
    finally:
        os.close(rfd)


def _force_remove(path: Path) -> None:
    """Delete a tree this module created (restores owner write permission first; never follows links)."""
    if not os.path.lexists(path) or os.path.islink(path):
        return
    for dirpath, dirnames, _ in os.walk(path, followlinks=False):
        os.chmod(dirpath, 0o700)
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if not os.path.islink(p):
                os.chmod(p, 0o700)
    shutil.rmtree(path)


def _sealed_output(out: Path, manifests: dict | None) -> bool:
    """True only for a tree exactly as `materialize` leaves it: `out` (0555) holds the real directories
    `base` and `head`; below them only directories (0555) and single-link regular files (0444 or 0555);
    with `manifests` ({side: SnapshotManifest}) the file paths and types must also equal the manifests."""
    def mode_ok(st, want):
        return stat.S_IMODE(st.st_mode) == want
    try:
        st = os.lstat(out)
        if not stat.S_ISDIR(st.st_mode) or not mode_ok(st, 0o555) or sorted(os.listdir(out)) != ["base", "head"]:
            return False
        for side in SIDES:
            root = out / side
            st = os.lstat(root)
            if not stat.S_ISDIR(st.st_mode) or not mode_ok(st, 0o555):
                return False
            found = {}
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                for name in dirnames + filenames:
                    q = Path(dirpath) / name
                    st = os.lstat(q)
                    rel = q.relative_to(root).as_posix()
                    if stat.S_ISDIR(st.st_mode) and mode_ok(st, 0o555):
                        continue
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) not in (0o444, 0o555):
                        return False
                    found[rel] = "executable" if mode_ok(st, 0o555) else "file"
            if manifests is not None and found != {e["path"]: e["type"] for e in manifests[side]["entries"]}:
                return False
        return True
    except (OSError, KeyError, TypeError, ValueError):
        return False


def discard(target) -> None:
    """Remove a materialized bridge output and nothing else. `target` is the HistoricalBridge (its
    output must still hold exactly its manifests' paths and types) or the output directory, which
    must look exactly as `materialize` sealed it (read-only 0555/0444 modes, `base` and `head` only,
    no links, special files or hard links). Anything else is refused untouched."""
    if isinstance(target, HistoricalBridge):
        out, manifests = Path(target._snaps["base"][0]).parent, {s: target._snaps[s][1] for s in SIDES}
    else:
        out, manifests = Path(os.path.abspath(target)), None
    if not _sealed_output(out, manifests):
        raise BridgeError("not a sealed bridge output directory; nothing was removed")
    os.chmod(out, 0o700)
    _force_remove(out)


def _roots(forbidden) -> list:
    """`forbidden_roots`: one path or an iterable of paths (str or os.PathLike, not bytes)."""
    if isinstance(forbidden, (str, os.PathLike)):
        forbidden = (forbidden,)
    try:
        roots = list(forbidden)
    except TypeError:
        raise BridgeError("forbidden_roots must be a path or an iterable of paths") from None
    if not all(isinstance(r, (str, os.PathLike)) and not isinstance(r, bytes) for r in roots):
        raise BridgeError("forbidden_roots must hold only str or os.PathLike paths")
    return roots


def _check_out(out_dir, case_dir: Path, forbidden) -> Path:
    """`out_dir` must be new, under real directories, and outside the case directory, the corpus
    directory that holds it (always forbidden: a sibling case must never receive output) and every
    `forbidden_roots` entry."""
    roots = _roots(forbidden)
    out = Path(os.path.abspath(out_dir))
    if os.path.lexists(out):
        raise BridgeError("out_dir must not exist yet")
    p = Path(out.anchor)
    for part in out.parent.parts[1:]:
        p = p / part
        try:
            st = os.lstat(p)
        except OSError:
            raise BridgeError("out_dir parent does not exist") from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise BridgeError("out_dir has a symlink or non-directory component")
    for root in (case_dir, Path(os.path.realpath(case_dir)).parent, *roots):
        r = Path(os.path.realpath(root))
        if out == r or r in out.parents or out in r.parents:
            raise BridgeError("out_dir overlaps the case directory or a forbidden root")
    return out


# ------------------------------------------------------------------ result

class HistoricalBridge:
    """Materialized case. Every accessor returns a private copy; the trees on disk are read-only."""
    __slots__ = ("_case", "_record", "_snaps", "_recorded")

    def __init__(self, case, record, snaps, recorded):
        self._case, self._record, self._snaps, self._recorded = case, record, snaps, recorded

    @property
    def case(self) -> dict:
        return copy.deepcopy(self._case)

    @property
    def record(self) -> dict:
        return copy.deepcopy(self._record)

    @property
    def base(self) -> SnapshotInput:
        root, m = self._snaps["base"]
        return SnapshotInput(root, copy.deepcopy(m))

    @property
    def head(self) -> SnapshotInput:
        root, m = self._snaps["head"]
        return SnapshotInput(root, copy.deepcopy(m))

    def view(self) -> View:
        """Partial tools View: ONE union layer per side under its computed union snapshot id, with
        per-path kinds (tools `partial_union_view`, S0B-02c). Context paths are the record's context
        set; changed paths are those whose provenance includes a pinned CHANGED layer (never a
        base/head manifest delta), so a head-only context file is readable but never reported as
        added. The tools refuse any union path that is unclassified or classified twice."""
        def spec(side):
            root, manifest = self._snaps[side]
            u = self._record["unions"][side]
            kinds = {d["name"]: d["kind"] for d in u["derivedFrom"]}
            changed = {p for p, ns in u["provenance"].items() if any(kinds[n] == "changed" for n in ns)}
            return (root, manifest, set(self._record["coverage"]["contextPaths"][side]), changed)
        try:
            return partial_union_view(spec("base"), spec("head"), recorded=self._recorded)
        except ViewError as e:
            raise BridgeError(f"union view refused: {e}") from None


# ------------------------------------------------------------------ materialize

def _validated(case_dir: Path, pins: dict):
    """(validated historical view, case.json document read from the pinned bytes)."""
    try:
        hv = historical_input_view(case_dir, pins=pins["view"])
        loaded = load_reviewer_input(case_dir)
    except ViewError as e:
        raise BridgeError(f"case refused: {e}") from None
    except Exception as e:  # noqa: BLE001 - InputError, PathError: fail closed
        raise BridgeError(f"case refused by the corpus loader ({type(e).__name__})") from None
    raw = read_nofollow(case_dir / "input" / "case.json", META_MAX_BYTES)
    if hashlib.sha256(raw).hexdigest() != pins["view"]["metaSha256"]["case.json"]:
        raise BridgeError("case.json differs from the pinned digest")
    case = json.loads(raw)
    # the loader derives null counts from the patch in memory; compare with the stored nulls restored
    lf = loaded["case"]["files"]
    same_files = len(lf) == len(case["files"]) and all(
        dict(f, additions=c["additions"], deletions=c["deletions"]) == c for f, c in zip(lf, case["files"]))
    if origin_of(case) != pins["origin"] or origin_of(loaded["case"]) != pins["origin"] or not same_files:
        raise BridgeError("case.json origin or file list differs from the pins")
    return hv, case


def _side(hv, side: str, out: Path, limits: BridgeLimits):
    layers = hv.layers(side)
    entries, prov, dups = union_entries(layers, limits)
    by_name = {l.name: l for l in layers}
    files = []
    try:
        for e in entries:
            datas = [read_verified(by_name[n].root, by_name[n].manifest, e["path"], max_bytes=limits.max_file_bytes)
                     for n in prov[e["path"]]]
            if any(d != datas[0] for d in datas[1:]):
                raise BridgeError(f"{e['path']!r}: duplicate bytes differ")
            files.append((e["path"], e["type"], datas[0]))
    except SnapshotError as x:
        raise BridgeError(f"pinned read failed on side {side}: {redact(str(x))[0][:200]}") from None
    manifest = require("SnapshotManifest", {"schema": "snapshot-manifest@1", "snapshotId": snapshot_id(entries),
                                            "entries": entries})
    root = out / side
    _write_tree(root, files)
    try:
        built = build_manifest(root)
    except SnapshotError as x:
        raise BridgeError(f"union {side} cannot be re-read: {x}") from None
    if built != manifest:
        raise BridgeError(f"union {side} on disk differs from the computed manifest")
    kinds = {l.name: l.kind for l in layers}
    info = {"snapshotId": manifest["snapshotId"], "entries": len(entries), "bytes": sum(e["size"] for e in entries),
            "derivedFrom": [{"name": l.name, "kind": l.kind, "snapshotId": l.snapshot_id} for l in layers],
            "provenance": prov, "duplicates": dups}
    context = sorted(p for p, ns in prov.items() if all(kinds[n] == "context" for n in ns))
    return (str(root), manifest), info, context


def _coverage(case: dict, recorded: dict, context: dict) -> dict:
    changed = [{"path": f["path"], "previousPath": f["previousPath"], "status": f["status"],
                "base": f["base"] is not None, "head": f["head"] is not None,
                "gapKinds": sorted({_slug(g["kind"]) for g in f["gaps"]})}
               for f in case["files"] if f["path"] is not None]
    return {"schema": COVERAGE_SCHEMA, "scope": "changed-files-and-selected-context",
            "fullRepositoryCoverage": False, "recorded": copy.deepcopy(recorded),
            "unsafePathsOmitted": sum(1 for f in case["files"] if f["path"] is None),
            "changedPaths": changed, "contextPaths": context, "note": NOT_FULL}


def materialize(case_dir, *, pins, out_dir, forbidden_roots=(), limits: BridgeLimits = BridgeLimits()
                ) -> HistoricalBridge:
    """Validate `case_dir` against externally stored trusted `pins` and write two read-only union trees
    to `out_dir/{base,head}` (`out_dir` must not exist; nothing is written on refusal). Never captures
    pins and never opens `source/` or `labels/`."""
    pins = check_pins(pins)
    case_dir = Path(case_dir)
    if pins["caseId"] != case_dir.name:
        raise BridgeError("pins are for a different case")
    out = _check_out(out_dir, case_dir, forbidden_roots)
    hv, case = _validated(case_dir, pins)
    cid = case_dir.name.lower()
    try:
        os.mkdir(out, 0o700)
    except FileExistsError:                # created by someone else after _check_out: never touched
        raise BridgeError("out_dir must not exist yet") from None
    except OSError as e:
        raise BridgeError(f"cannot create out_dir: {e.strerror}") from None
    try:                                   # any failure below removes the whole output
        snaps, unions, context = {}, {}, {}
        for side in SIDES:
            snaps[side], unions[side], context[side] = _side(hv, side, out, limits)
        os.chmod(out, 0o555)
        pr = pins["prText"] or {"title": "", "body": ""}
        try:
            case_input = require("CaseInput", {
                "schema": "case-input@1", "id": cid, "repo": case["repo"], "synthetic": False,
                "base": {"snapshotId": unions["base"]["snapshotId"], "root": "base"},
                "head": {"snapshotId": unions["head"]["snapshotId"], "root": "head"},
                "pr": {"title": pr["title"], "body": pr["body"]}})
        except Exception:  # noqa: BLE001
            raise BridgeError("CaseInput could not be built (case id not lowercase-mappable?)") from None
        p = pins["prText"]
        record = {"schema": RECORD_SCHEMA, "caseId": case_dir.name, "caseInputId": cid,
                  "caseInputDigest": digest(case_input), "pinsDigest": digest(pins),
                  "origin": copy.deepcopy(pins["origin"]), "asOf": pins["capturedAt"],
                  "prText": {"supplied": p is not None, "asOf": p and p["asOf"],
                             "redactions": p["redactions"] if p else {}},
                  "unions": unions, "coverage": _coverage(case, hv.recorded, context)}
        return HistoricalBridge(case_input, record, snaps, hv.recorded)
    except BaseException:
        _force_remove(out)
        raise
