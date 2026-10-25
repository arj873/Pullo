"""Load a suite directory, pin its snapshots, and prove labels stay out of reviewer inputs.

Layout (relative to the suite root):
  suite.json                      SuiteManifest
  cases/<id>/input.json           CaseInput (what the reviewer may see)
  cases/<id>/{base,head}/...      pinned local snapshots named by CaseInput
  labels/<id>.json                CaseLabels (scorer only; never opened for non-synthetic suites)
  scripts/<id>.json               scripted provider responses (see orchestration/SCRIPTED-PROVIDER.md)

Identity. `Suite.digest` is the contract's DATASET digest (manifest + input/labels hashes); it does
not cover scripts/. What produced a synthetic run is `scripts_digest` (the scripted responses) plus
the redaction version and pattern fingerprint, bound together by `synthetic_config_digest`; use that
as the EvalReport.configDigest of a scripted/replayed evaluation so changed response fixtures or a
changed redaction policy can never replay under an unchanged identity.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts import loads_strict, require
from reviewer.contracts.canonical import config_digest, digest, suite_digest
from reviewer.contracts.redaction import MAX_PASSES, PROTECTED_PATTERNS, REDACTION_VERSION
from reviewer.contracts.snapshot import SnapshotError, build_manifest

from .errors import ScoringError


@dataclass(frozen=True)
class SuiteCase:
    id: str
    input: dict
    labels: dict | None
    base_manifest: dict
    head_manifest: dict
    input_path: str
    labels_path: str
    script_path: str


@dataclass(frozen=True)
class Suite:
    root: Path
    manifest: dict
    digest: str | None
    cases: dict[str, SuiteCase]


def _real(root: Path, rel: str) -> Path:
    """A path under root that is not a symlink and does not leave root (checked per component)."""
    p = root
    for part in rel.split("/"):
        p = p / part
        if p.is_symlink():
            raise ScoringError(f"symlink in suite path: {rel}")
    if os.path.commonpath([root.resolve(), p.resolve()]) != str(root.resolve()):
        raise ScoringError(f"suite path escapes root: {rel}")
    return p


def _read_json(root: Path, rel: str):
    p = _real(root, rel)
    try:
        return loads_strict(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ScoringError(f"cannot read {rel}: {e.strerror}") from e


def _sha(root: Path, rel: str) -> str:
    return hashlib.sha256(_real(root, rel).read_bytes()).hexdigest()


def load_suite(root, *, sealed_label_hashes: dict[str, str] | None = None) -> Suite:
    """Validate and load. Labels are opened only when the suite is synthetic. For a real suite the
    labels files are never opened (not even hashed) and `labels` is None; its dataset `digest` is
    None unless the caller supplies `sealed_label_hashes` ({labels path: sha256 hex}) taken from
    sealed metadata, in which case the digest is computed from those and the manifest."""
    root = Path(root)
    manifest = require("SuiteManifest", _read_json(root, "suite.json"))
    cases: dict[str, SuiteCase] = {}
    hashes: dict[str, str] = {}
    for c in manifest["cases"]:
        cid = c["id"]
        doc = require("CaseInput", _read_json(root, c["input"]))
        if doc["id"] != cid:
            raise ScoringError(f"{c['input']}: id {doc['id']!r} does not match suite case {cid!r}")
        if doc["synthetic"] != manifest["synthetic"]:
            raise ScoringError(f"{cid}: input.synthetic disagrees with the suite")
        manifests = {}
        for side in ("base", "head"):
            ref = doc[side]
            if not ref["root"].startswith("cases/") or ref["root"].split("/")[0] == "labels":
                raise ScoringError(f"{cid}: {side} snapshot must live under cases/")
            snap_root = _real(root, ref["root"])
            try:
                built = build_manifest(snap_root)
            except SnapshotError as e:
                raise ScoringError(f"{cid}: {side} snapshot unreadable: {e}") from e
            if built["snapshotId"] != ref["snapshotId"]:
                raise ScoringError(f"{cid}: {side} snapshot does not match its pinned id")
            manifests[side] = built
        labels = None
        if manifest["synthetic"]:
            labels = require("CaseLabels", _read_json(root, c["labels"]))
            if labels["caseId"] != cid:
                raise ScoringError(f"{c['labels']}: caseId {labels['caseId']!r} != {cid!r}")
        hashes[c["input"]] = _sha(root, c["input"])
        if manifest["synthetic"]:
            hashes[c["labels"]] = _sha(root, c["labels"])
        elif sealed_label_hashes and c["labels"] in sealed_label_hashes:
            hashes[c["labels"]] = sealed_label_hashes[c["labels"]]
        cases[cid] = SuiteCase(cid, doc, labels, manifests["base"], manifests["head"],
                               c["input"], c["labels"], f"scripts/{cid}.json")
    try:
        dataset = suite_digest(manifest, hashes)
    except ValueError:
        dataset = None   # real suite without sealed label hashes: the caller supplies a digest
    return Suite(root, manifest, dataset, cases)


def _label_needles(labels: dict) -> list[str]:
    needles = []
    for b in labels["bugs"]:
        needles.append(b["id"])
        if b.get("note"):
            needles.append(b["note"])
    if labels.get("expectReason"):
        needles.append(labels["expectReason"])
    return needles


def check_isolation(suite: Suite) -> list[str]:
    """Problems if label material appears anywhere the reviewer (or its scripted provider) sees:
    input.json, either snapshot tree, or the case's scripted responses. Bug ids and notes must
    not occur anywhere. The expected reason and the labels path must not occur in the input or
    snapshots (a scripted provider error legitimately carries an error code, which may equal it)."""
    problems: list[str] = []
    for cid, case in suite.cases.items():
        if case.labels is None:
            continue
        ids_notes = []
        for b in case.labels["bugs"]:
            ids_notes += [b["id"], *([b["note"]] if b.get("note") else [])]
        input_only = ["case-labels@1", case.labels_path, "labels/" + cid]
        if case.labels.get("expectReason"):
            input_only.append(case.labels["expectReason"])
        views = [(case.input_path, _real(suite.root, case.input_path).read_bytes(), True)]
        for side, man in (("base", case.base_manifest), ("head", case.head_manifest)):
            for e in man["entries"]:
                rel = f"{case.input[side]['root']}/{e['path']}"
                views.append((f"{side}/{e['path']}", _real(suite.root, rel).read_bytes(), True))
        sp = _real(suite.root, case.script_path)
        if sp.is_file():
            views.append((case.script_path, sp.read_bytes(), False))
        for name, data, strict in views:
            text = data.decode("utf-8", "replace")
            for n in ids_notes + (input_only if strict else ["case-labels@1", case.labels_path]):
                if n in text:
                    problems.append(f"{cid}: {name} contains label material {n!r}")
    return problems


# ---------------------------------------------------------------- run identity (scripts + redaction)

def redaction_fingerprint() -> str:
    """Digest of the active redaction policy: version, pass limit and every pattern (id, source,
    flags). Changes when a pattern changes even if the version string was not bumped."""
    return digest({"version": REDACTION_VERSION, "maxPasses": MAX_PASSES,
                   "patterns": [[pid, pat.pattern, pat.flags] for pid, pat in PROTECTED_PATTERNS]})


def scripts_identity(suite: Suite) -> list[list[str]]:
    """Sorted [published path, sha256] of every case's scripted-response file. Raises ScoringError
    if a case has no script (a scripted evaluation needs one per case)."""
    out = []
    for case in sorted(suite.cases.values(), key=lambda c: c.script_path):
        p = _real(suite.root, case.script_path)
        if not p.is_file():
            raise ScoringError(f"{case.id}: no script {case.script_path}")
        out.append([case.script_path, _sha(suite.root, case.script_path)])
    return out


def scripts_digest(suite: Suite) -> str:
    return digest({"scripts": scripts_identity(suite)})


def synthetic_config_digest(suite: Suite, config=None) -> str:
    """EvalReport.configDigest for a scripted synthetic evaluation: binds the dataset digest, the
    scripted responses, the redaction version and fingerprint, and any caller config (plan/profile
    digests, ...). The dataset digest alone (`Suite.digest`) does not."""
    if suite.digest is None:
        raise ScoringError("suite has no dataset digest to bind")
    return config_digest({"schema": "synthetic-run-identity@1", "suiteDigest": suite.digest,
                          "scripts": scripts_identity(suite),
                          "redaction": {"version": REDACTION_VERSION, "fingerprint": redaction_fingerprint()},
                          "config": config})
