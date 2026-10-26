"""Explicit, immutable snapshot views. A view is data: roots plus pinned manifests, no discovery.

A side (base or head) is a list of layers. A *full* layer is a whole repository snapshot. The
historical corpus supplies a PARTIAL view instead: a `changed` layer (the PR's changed files) and
optional `context` layers (explicitly selected files). Tools say so in every result: absence from
a partial view is not absence from the repository.
"""

from __future__ import annotations

import copy
import hashlib
import os
import stat
from pathlib import Path

from reviewer.contracts import require
from reviewer.contracts.redaction import redact
from reviewer.contracts.snapshot import SnapshotError, build_manifest, snapshot_resolver
from reviewer.corpus.inputs import load_reviewer_input

LAYER_KINDS = ("full", "changed", "context")
SIDES = ("base", "head")
PARTIAL_NOTE = ("Partial view: changed files and selected context only. A path that is not listed "
                "may exist in the repository; more context needs a PREPARE broker request.")


OMISSION_NOTE = ("Complete import WITH OMISSIONS: some paths of the repository were not imported ({detail}). A path "
                 "that is missing, unreadable or not listed may exist in the repository; its absence here is not "
                 "evidence that it does not exist.")


def omissions_from_records(base_record: dict, head_record: dict) -> dict:
    """Host-side summary of what two VERIFIED `repo-import@1` records omitted: {side: {kind: count}} (only kinds
    with a non-zero count). Raises ViewError on a malformed record; never reads the tree."""
    out = {}
    for side, rec in (("base", base_record), ("head", head_record)):
        try:
            counts = rec["omissions"]["counts"]
        except (KeyError, TypeError):
            raise ViewError(f"{side} import record has no omissions.counts") from None
        if not isinstance(counts, dict) or any(not isinstance(k, str) or not isinstance(v, int) or isinstance(v, bool)
                                               or v < 0 for k, v in counts.items()):
            raise ViewError(f"{side} import record omission counts are malformed")
        out[side] = {k: v for k, v in sorted(counts.items()) if v}
    return out


class ViewError(ValueError):
    pass


class Layer:
    """One pinned tree: root directory plus its provided manifest (private deep copy).

    A `changed` layer may carry `context`: paths of a partial UNION tree (one snapshot id for the
    side) that are selected context, not PR changes. They behave exactly as a `context` layer's paths."""
    __slots__ = ("name", "kind", "snapshot_id", "root", "manifest", "_index", "context")

    def __init__(self, name: str, kind: str, root, manifest: dict, *, context_paths=None, changed_paths=None):
        if kind not in LAYER_KINDS:
            raise ViewError(f"layer kind must be one of {LAYER_KINDS}")
        m = copy.deepcopy(require("SnapshotManifest", manifest))
        self.name, self.kind, self.snapshot_id = name, kind, m["snapshotId"]
        self.root, self.manifest = str(Path(root)), m
        self._index = {e["path"]: e for e in m["entries"]}
        self.context = frozenset()
        if context_paths is None and changed_paths is None:
            return
        if kind != "changed":
            raise ViewError(f"layer {name!r}: per-path context/changed sets are only for a 'changed' union layer")
        ctx = _path_set(name, "context_paths", context_paths, self._index)
        if changed_paths is not None:
            chg = _path_set(name, "changed_paths", changed_paths, self._index)
            if chg & ctx:
                raise ViewError(f"layer {name!r}: {len(chg & ctx)} path(s) listed as both changed and context")
            if chg | ctx != set(self._index):
                raise ViewError(f"layer {name!r}: {len(set(self._index) - chg - ctx)} manifest path(s) are "
                                "neither changed nor context")
        self.context = ctx

    def entry(self, path: str) -> dict | None:
        return self._index.get(path)

    def path_kind(self, path: str) -> str | None:
        """"full", "changed" or "context" for a path of this layer; None if it is not here."""
        if path not in self._index:
            return None
        return "context" if path in self.context else self.kind

    def label(self, path: str) -> str:
        """Layer name as shown to the model; a union layer marks its context paths."""
        return f"{self.name} [context]" if path in self.context else self.name


def _path_set(name: str, what: str, paths, index: dict) -> frozenset:
    if paths is None:
        return frozenset()
    if isinstance(paths, (str, bytes)) or not isinstance(paths, (set, frozenset, list, tuple)):
        raise ViewError(f"layer {name!r}: {what} must be a set, list or tuple of paths")
    if not all(isinstance(p, str) for p in paths):
        raise ViewError(f"layer {name!r}: {what} must hold only path strings")
    out = frozenset(paths)
    missing = out - set(index)
    if missing:
        raise ViewError(f"layer {name!r}: {len(missing)} path(s) in {what} are not in the pinned manifest")
    return out


def make_layer(name: str, kind: str, root, manifest: dict, *, context_paths=None, changed_paths=None) -> Layer:
    """A pinned layer. `context_paths` (and the optional cross-check `changed_paths`, which must
    partition the manifest with it) are only for a `changed` union layer; see Layer."""
    return Layer(name, kind, root, manifest, context_paths=context_paths, changed_paths=changed_paths)


class View:
    def __init__(self, base: list[Layer], head: list[Layer], recorded: dict | None = None,
                 omissions: dict | None = None):
        self.sides = {"base": tuple(base), "head": tuple(head)}
        # {side: {kind: count}} from verified import records; empty/None = nothing omitted
        self.omissions = {s: dict((omissions or {}).get(s, {})) for s in ("base", "head")}
        if any(any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in d.values())
               for d in self.omissions.values()):
            raise ViewError("omission counts must be non-negative integers")
        self.recorded = copy.deepcopy(recorded)    # corpus-recorded coverage (historical views only)
        for side, layers in self.sides.items():
            if not layers:
                raise ViewError(f"side {side} has no layers")
            seen: dict[str, str] = {}
            for layer in layers:
                for p in layer._index:
                    if p in seen:
                        raise ViewError(f"{side}: {p!r} appears in layers {seen[p]!r} and {layer.name!r}")
                    seen[p] = layer.name
        _check_classification(self.sides)

    @property
    def partial(self) -> bool:
        return any(layer.kind != "full" for layers in self.sides.values() for layer in layers)

    @property
    def omitted(self) -> bool:
        """True when a verified import record says paths of the repository were not imported."""
        return any(sum(d.values()) for d in self.omissions.values())

    @property
    def approximate(self) -> bool:
        """Results about absence or completeness are only approximate: a partial view or an import with omissions."""
        return self.partial or self.omitted

    def omission_detail(self) -> str:
        return "; ".join(f"{s}: " + ", ".join(f"{k}={n}" for k, n in d.items())
                         for s, d in self.omissions.items() if d)

    def layers(self, side: str) -> tuple[Layer, ...]:
        return self.sides[side]

    def find(self, side: str, path: str):
        """(layer, entry) for a path on a side, or None. Pure manifest lookup; no disk access."""
        for layer in self.sides[side]:
            e = layer.entry(path)
            if e is not None:
                return layer, e
        return None

    def path_kind(self, side: str, path: str) -> str | None:
        """"full", "changed" or "context" for a path on a side; None if the view does not hold it."""
        found = self.find(side, path)
        return None if found is None else found[0].path_kind(path)

    def changed_paths(self, side: str) -> frozenset:
        """Paths on a side that are PR changes (or whole-snapshot paths of a full layer)."""
        return frozenset(p for l in self.sides[side] for p in l._index if l.path_kind(p) != "context")

    def context_paths(self, side: str) -> frozenset:
        """Paths on a side that are selected context only."""
        return frozenset(p for l in self.sides[side] for p in l._index if l.path_kind(p) == "context")

    def trees(self) -> dict:
        """{snapshotId: (root, manifest)} for snapshot.snapshot_resolver."""
        return {layer.snapshot_id: (layer.root, layer.manifest)
                for layers in self.sides.values() for layer in layers}

    def resolver(self):
        return snapshot_resolver(self.trees())

    def note(self) -> str:
        """Notice every tool adds for a partial view, including recorded corpus coverage gaps."""
        if not self.partial:
            return OMISSION_NOTE.format(detail=self.omission_detail()) if self.omitted else ""
        r = self.recorded
        if not r or r["complete"]:
            return PARTIAL_NOTE
        parts = [PARTIAL_NOTE]
        if r["gapKinds"]:
            parts.append(f"Recorded coverage gaps ({', '.join(r['gapKinds'])}): {r['changedFilesRecorded']} of "
                         f"{r['changedFilesExpected']} expected changed files are recorded, so the changed-file "
                         "list and diffs may be incomplete.")
        if r["contextGapCount"]:
            parts.append(f"{r['contextGapCount']} selected context file(s) were not recorded "
                         f"({', '.join(r['contextGapKinds'])}) and are absent.")
        return " ".join(parts)

    def coverage(self) -> dict:
        scope = ("changed-files-and-selected-context" if self.partial else
                 "repository-with-omissions" if self.omitted else "full-repository")
        cov = {"scope": scope, "fullRepositoryCoverage": scope == "full-repository",
               "layers": {s: [_layer_cov(l) for l in ls] for s, ls in self.sides.items()}}
        if self.recorded is not None:
            cov["recorded"] = copy.deepcopy(self.recorded)
        if self.omitted:
            cov["omissions"] = {s: dict(d) for s, d in self.omissions.items()}
        return cov


def _check_classification(sides: dict) -> None:
    """T1: base and head must classify the view the same way, or diff would invent A/D rows."""
    full = {side: [l.kind == "full" for l in layers] for side, layers in sides.items()}
    for side, flags in full.items():
        if any(flags) and not all(flags) or sum(flags) > 1:
            raise ViewError(f"{side}: a full layer cannot be combined with other layers")
    if any(f[0] for f in full.values() if f) and not all(f[0] for f in full.values()):
        raise ViewError("one side is a full snapshot and the other is partial; added/deleted would be invented")
    kinds = {side: {p: l.path_kind(p) for l in layers for p in l._index} for side, layers in sides.items()}
    bad = sorted((p, kinds["base"][p], kinds["head"][p]) for p in kinds["base"].keys() & kinds["head"].keys()
                 if kinds["base"][p] != kinds["head"][p])
    if bad:
        raise ViewError(f"{len(bad)} path(s) are classified differently on the two sides "
                        f"(first: base {bad[0][1]} / head {bad[0][2]}); status and diff would be invented")


def _layer_cov(layer: Layer) -> dict:
    d = {"name": layer.name, "kind": layer.kind, "snapshotId": layer.snapshot_id}
    if layer.context:
        d["contextPaths"] = sorted(layer.context)
    return d


def full_view(base_root, base_manifest: dict, head_root, head_manifest: dict) -> View:
    """Two whole-repository snapshots with their provided manifests."""
    return View([make_layer("base", "full", base_root, base_manifest)],
                [make_layer("head", "full", head_root, head_manifest)])


def import_view(base_root, base_manifest: dict, head_root, head_manifest: dict, omissions: dict) -> View:
    """full_view over two imported repositories. `omissions` ({side: {kind: count}}, omissions_from_records) comes
    ONLY from verified import records: with a non-zero count the view stops claiming full-repository coverage in
    coverage(), every note and every completeness."""
    return View([make_layer("base", "full", base_root, base_manifest)],
                [make_layer("head", "full", head_root, head_manifest)], omissions=omissions)


def partial_union_view(base, head, recorded: dict | None = None) -> View:
    """PARTIAL view with ONE union layer per side: `base`/`head` are (root, manifest, context_paths,
    changed_paths). The manifest is the trusted, externally supplied union manifest (kept as given,
    never rebuilt from disk); its snapshotId is the side's only id. `context_paths` are selected
    context (never reported as added/removed/modified); `changed_paths` is the recorded changed set
    and must partition the manifest with `context_paths` (None: every non-context path is changed).
    `recorded` is the corpus-recorded coverage (gap notices), as for historical_input_view."""
    sides = []
    for side, spec in (("base", base), ("head", head)):
        if not isinstance(spec, tuple) or len(spec) != 4:
            raise ViewError(f"{side} must be (root, manifest, context_paths, changed_paths)")
        root, manifest, ctx, chg = spec
        if ctx is None:
            raise ViewError(f"{side}: context_paths is required (use an empty set for none)")
        try:
            layer = make_layer(f"{side}-union", "changed", root, manifest, context_paths=ctx, changed_paths=chg)
        except ViewError:
            raise
        except Exception:  # noqa: BLE001 - contract shape errors: fail closed with one error type
            raise ViewError(f"{side}: manifest is not a valid SnapshotManifest") from None
        sides.append([layer])
    return View(*sides, recorded=recorded)


# ------------------------------------------------------------------ historical views

PINS_SCHEMA = "historical-view-pins@1"
META_MAX_BYTES = 8 << 20
_LAYER_DIRS = {"base-changed": "base", "head-changed": "head",
               "base-context": "context/base", "head-context": "context/head"}
_KIND_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
_HEX = frozenset("0123456789abcdef")


def _is_hex64(v) -> bool:
    return isinstance(v, str) and len(v) == 64 and set(v) <= _HEX


def _real_dir(path: Path, what: str) -> bool:
    """True for a real directory, False if absent. A link or non-directory is an error."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise ViewError(f"{what} is not accessible") from None
    if stat.S_ISLNK(st.st_mode):
        raise ViewError(f"{what} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise ViewError(f"{what} is not a directory")
    return True


def _layer_dirs(case_dir: Path) -> dict[str, Path]:
    """{layer name: directory} for the layers that exist. Every component, including the case
    directory, `input`, `input/context` and the side directories, must be a real directory."""
    if not _real_dir(case_dir, "case directory"):
        raise ViewError("no case directory")
    inp = case_dir / "input"
    if not _real_dir(inp, "input/"):
        raise ViewError("no input/ directory")
    has_ctx = _real_dir(inp / "context", "input/context")
    out = {}
    for name, rel in _LAYER_DIRS.items():
        if rel.startswith("context/") and not has_ctx:
            continue
        if _real_dir(inp / rel, f"input/{rel}"):
            out[name] = inp / rel
    return out


def _read_meta(path: Path):
    """Bytes of a regular, non-link metadata file within the size cap; None if absent. Never blocks
    on a FIFO and never follows a link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise ViewError(f"{path.name} cannot be opened as a regular file") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > META_MAX_BYTES:
            raise ViewError(f"{path.name} is not a regular file within {META_MAX_BYTES} bytes")
        chunks, got = [], 0
        while got <= META_MAX_BYTES and (chunk := os.read(fd, min(1 << 16, META_MAX_BYTES + 1 - got))):
            chunks.append(chunk)
            got += len(chunk)
        if got > META_MAX_BYTES:
            raise ViewError(f"{path.name} grew past {META_MAX_BYTES} bytes")
        return b"".join(chunks)
    except OSError:
        raise ViewError(f"{path.name} cannot be read") from None
    finally:
        os.close(fd)


def _hex(b) -> str | None:
    return None if b is None else hashlib.sha256(b).hexdigest()


def _gap_kind(k) -> str:
    return k if isinstance(k, str) and 0 < len(k) <= 40 and set(k) <= _KIND_CHARS and redact(k)[0] == k else "other"


def _recorded_coverage(case: dict, context: dict) -> dict:
    """Coverage the corpus recorded. Gap kinds are untrusted free text: only slug-shaped kinds
    pass through, anything else is reported as 'other'; `detail` is never copied."""
    cov = case["coverage"]
    ctx_kinds = [e["gap"]["kind"] for e in context.get("files", []) if e.get("status") == "gap"]
    return {"complete": bool(cov["complete"]) and not ctx_kinds,
            "gapKinds": sorted({_gap_kind(k) for k in cov["gapKinds"]}),
            "contextGapKinds": sorted({_gap_kind(k) for k in ctx_kinds}), "contextGapCount": len(ctx_kinds),
            "changedFilesExpected": cov["changedFilesExpected"], "changedFilesListed": cov["changedFilesListed"],
            "changedFilesRecorded": cov["changedFilesRecorded"]}


def _inspect(case_dir) -> tuple[dict, dict, dict]:
    """(layer dirs, metaSha256 as read, recorded coverage) for a corpus-valid case. The case is
    validated by the corpus loader (closed schemas, exact file set, blob hashes, no links)."""
    case_dir = Path(case_dir)
    dirs = _layer_dirs(case_dir)
    inp = case_dir / "input"
    case_b, ctx_b = _read_meta(inp / "case.json"), _read_meta(inp / "context.json")
    if case_b is None:
        raise ViewError("input/case.json is missing")
    try:
        loaded = load_reviewer_input(case_dir)
        if loaded["case"]["id"] != case_dir.name:
            raise ViewError("case.json id does not match the case directory")
        recorded = _recorded_coverage(loaded["case"], loaded["context"])
    except ViewError:
        raise
    except Exception as e:  # noqa: BLE001 - InputError, PathError, shape errors: all fail closed
        raise ViewError(f"input/ is not a valid corpus reviewer input ({type(e).__name__}): "
                        f"{redact(str(e))[0][:200]}") from None
    meta = {"case.json": _hex(case_b), "context.json": _hex(ctx_b)}
    if (_hex(_read_meta(inp / "case.json")), _hex(_read_meta(inp / "context.json"))) != tuple(meta.values()):
        raise ViewError("case.json/context.json changed while being validated")
    return dirs, meta, recorded


def _manifests(dirs: dict) -> dict:
    out = {}
    for name, d in dirs.items():
        try:
            out[name] = build_manifest(d)
        except SnapshotError as e:
            raise ViewError(f"layer {name}: {redact(str(e))[0][:200]}") from None
    return out


def capture_historical_pins(case_dir) -> dict:
    """TRUSTED-TIME capture of the pins `historical_input_view` requires: run it once, on a case
    directory that is known-good (e.g. when the corpus is imported or reviewed), and store the
    result OUTSIDE the case directory (run configuration). Never call it on the directory you are
    about to review and pass the result straight in: that rebuilds whatever is on disk and
    proves nothing. The document holds a SnapshotManifest per changed/context layer and the
    sha256 of case.json and context.json."""
    dirs, meta, _ = _inspect(case_dir)
    return {"schema": PINS_SCHEMA, "caseId": Path(case_dir).name, "layers": _manifests(dirs),
            "metaSha256": meta}


def _check_pins(pins, case_dir: Path) -> dict:
    try:
        if (not isinstance(pins, dict) or set(pins) != {"schema", "caseId", "layers", "metaSha256"}
                or pins["schema"] != PINS_SCHEMA or pins["caseId"] != case_dir.name
                or not isinstance(pins["layers"], dict) or not pins["layers"]
                or set(pins["layers"]) - set(_LAYER_DIRS)):
            raise ViewError("pins are not a historical-view-pins@1 document for this case")
        meta = pins["metaSha256"]
        if (not isinstance(meta, dict) or set(meta) != {"case.json", "context.json"}
                or not _is_hex64(meta["case.json"])
                or not (meta["context.json"] is None or _is_hex64(meta["context.json"]))):
            raise ViewError("pins.metaSha256 is malformed")
        return {n: copy.deepcopy(require("SnapshotManifest", m)) for n, m in pins["layers"].items()}
    except ViewError:
        raise
    except Exception:  # noqa: BLE001
        raise ViewError("pins are malformed (every layer needs a valid SnapshotManifest)") from None


def historical_input_view(case_dir, *, pins=None) -> View:
    """The corpus reviewer-input directory `<case>/input/` as a PARTIAL view: `base/` and `head/`
    hold ONLY the changed files and optional `context/{base,head}/` hold explicitly selected
    context. `source/` and `labels/` are never opened.

    TRUSTED PINS ARE REQUIRED (keyword `pins`, see `capture_historical_pins`): a manifest for
    every changed and context layer plus the case.json/context.json digests, supplied by the
    caller from OUTSIDE the case directory. Without them the call fails closed. Construction
    refuses unless: no component (case dir, input, input/context, side dirs) is a link; the corpus
    loader accepts the directory (closed schemas, exact file set, blob hashes, recorded coverage);
    the layer set on disk equals the pinned layer set; and each tree equals its pinned manifest
    exactly. The case's own hashes are only a consistency check, never trust. The view keeps the
    PINNED manifests, so every later read re-verifies against them."""
    if pins is None:
        raise ViewError("historical views require trusted pins captured outside the case directory "
                        "(historical_input_view(case, pins=capture_historical_pins(...)))")
    case_dir = Path(case_dir)
    manifests_pinned = _check_pins(pins, case_dir)
    dirs, meta, recorded = _inspect(case_dir)
    if meta != pins["metaSha256"]:
        raise ViewError("case.json/context.json differ from the pinned digests")
    if set(dirs) != set(manifests_pinned):
        raise ViewError(f"layers on disk {sorted(dirs)} differ from pinned layers {sorted(manifests_pinned)}")
    built = _manifests(dirs)
    for name, m in built.items():
        if m != manifests_pinned[name]:
            raise ViewError(f"layer {name} differs from its pinned manifest")
    if _layer_dirs(case_dir) != dirs:
        raise ViewError("input layout changed during construction")
    sides = {}
    for side in SIDES:
        layers = [make_layer(f"{side}-{kind}", kind, dirs[f"{side}-{kind}"], manifests_pinned[f"{side}-{kind}"])
                  for kind in ("changed", "context") if f"{side}-{kind}" in dirs]
        if not layers:
            raise ViewError(f"input/ has nothing for side {side}")
        sides[side] = layers
    return View(sides["base"], sides["head"], recorded)
