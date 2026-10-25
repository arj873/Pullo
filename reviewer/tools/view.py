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


class ViewError(ValueError):
    pass


class Layer:
    """One pinned tree: root directory plus its provided manifest (private deep copy)."""
    __slots__ = ("name", "kind", "snapshot_id", "root", "manifest", "_index")

    def __init__(self, name: str, kind: str, root, manifest: dict):
        if kind not in LAYER_KINDS:
            raise ViewError(f"layer kind must be one of {LAYER_KINDS}")
        m = copy.deepcopy(require("SnapshotManifest", manifest))
        self.name, self.kind, self.snapshot_id = name, kind, m["snapshotId"]
        self.root, self.manifest = str(Path(root)), m
        self._index = {e["path"]: e for e in m["entries"]}

    def entry(self, path: str) -> dict | None:
        return self._index.get(path)


def make_layer(name: str, kind: str, root, manifest: dict) -> Layer:
    return Layer(name, kind, root, manifest)


class View:
    def __init__(self, base: list[Layer], head: list[Layer], recorded: dict | None = None):
        self.sides = {"base": tuple(base), "head": tuple(head)}
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

    @property
    def partial(self) -> bool:
        return any(layer.kind != "full" for layers in self.sides.values() for layer in layers)

    def layers(self, side: str) -> tuple[Layer, ...]:
        return self.sides[side]

    def find(self, side: str, path: str):
        """(layer, entry) for a path on a side, or None. Pure manifest lookup; no disk access."""
        for layer in self.sides[side]:
            e = layer.entry(path)
            if e is not None:
                return layer, e
        return None

    def trees(self) -> dict:
        """{snapshotId: (root, manifest)} for snapshot.snapshot_resolver."""
        return {layer.snapshot_id: (layer.root, layer.manifest)
                for layers in self.sides.values() for layer in layers}

    def resolver(self):
        return snapshot_resolver(self.trees())

    def note(self) -> str:
        """Notice every tool adds for a partial view, including recorded corpus coverage gaps."""
        if not self.partial:
            return ""
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
        cov = {"scope": "full-repository" if not self.partial else "changed-files-and-selected-context",
               "fullRepositoryCoverage": not self.partial,
               "layers": {s: [{"name": l.name, "kind": l.kind, "snapshotId": l.snapshot_id}
                              for l in ls] for s, ls in self.sides.items()}}
        if self.recorded is not None:
            cov["recorded"] = copy.deepcopy(self.recorded)
        return cov


def full_view(base_root, base_manifest: dict, head_root, head_manifest: dict) -> View:
    """Two whole-repository snapshots with their provided manifests."""
    return View([make_layer("base", "full", base_root, base_manifest)],
                [make_layer("head", "full", head_root, head_manifest)])


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
