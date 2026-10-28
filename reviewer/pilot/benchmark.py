"""Benchmark-pair review host (BENCH-REVIEW-01): a root-admitted benchmark base/head pair plus its two verified complete
repository imports -> `run_review`, in mode plan | live | replay. Host plumbing only; every provider, book, ledger and
loader is the existing reviewed one. See orchestration/handoffs/BENCH-REVIEW-01-interface.md.

    python3 -m reviewer.pilot.benchmark --mode plan --case-url U --cutoff-proof P --admission A --decision D \
        --launch-baseline B --store S --base-import-pins BP --head-import-pins HP --out OUT --auth AUTH

No historical case directory or pins are fabricated, no benchmark data/labels/gold/competitor review path exists in this
API, and the cutoff proof's own status is never read. Scoring is not part of this module (and the scorer-side
`reviewer.benchmark` package is deliberately not imported)."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from reviewer.config import ConfigError, EffectiveConfig, resolve_config
from reviewer.contracts import require
from reviewer.contracts.canonical import canonical_json, digest, sha256_hex
from reviewer.gateway import AuthorizationError, DisabledProvider, SpendBook, trusted_authorization
from reviewer.historical import BridgeError
from reviewer.historical.bridge import _check_out
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReplayBackend,
                               RepositoryImports, ReviewSpec, SnapshotInput, run_review, validate_spec)
from reviewer.pipeline import prompts, repocov
from reviewer.repoimport import RepoImportError, github_remote, load_import_pins, open_import, target_dir
from reviewer.repoimport.fsio import read_nofollow
from reviewer.runtime import EnvFileError, RuntimeLedger, Secret, TRIAL_TOTAL_USD_MICROS, load_openrouter_key
from reviewer.runtime.openrouter import OpenRouterProvider
from reviewer.runtime.turn_canary import Refused, open_state

from .ancestry import AncestryError, check_endpoints, verify_chain
from .launcher import QUALITY, REPO, PilotError, _force_cleanup, _Unused, gateway_costs, ledger_costs, utc_now
from .repository import (BOOK_NAME, LEDGER_NAME, STRICT_REPLAY_ONLY, CapturingTransport, RepositoryError,
                         _check_ceiling, _providers, _remove_if_empty, _request_facts, make_out, provider_scope, write_report)
from .profile import ProfileError
from .repository_profile import check_experiment, repository_plan, repository_policy, repository_profile

MODES = ("plan", "live", "replay")
CONFIG_SCHEMA = "pilot-benchmark-config@1"
REPORT_SCHEMA = "pilot-benchmark-report@1"
PROOF_SCHEMA = "benchmark-cutoff-proof@1"
ADMISSION_SCHEMA = "benchmark-cutoff-admission@1"
BASELINE_SCHEMA = "benchmark-launch-baseline@1"
DOC_MAX = 1 << 20
ENTRIES_MAX = 1 << 28
ORIGIN_KIND = "benchmark-development-case"

PROOF_KEYS = {"schema", "originalUrl", "resolvedRepo", "asOfBase", "asOfHead", "mergeBase", "headCommittedAt", "evidence"}
PROOF_OPTIONAL = {"corroboration", "attestedBy", "attestedAt", "note"}
EVIDENCE_KINDS = {"fork-mapping", "redirect", "commit-time", "review-time", "upstream-pin"}
NOT_PROOF = {"current-pr-head", "merged-head", "merge-commit"}
EVAL_ORG = "ai-code-review-evaluation"
ADMISSION_KEYS = {"schema", "originalUrl", "resolvedRepo", "asOfBase", "asOfHead", "mergeBase", "evidenceDigests",
                  "admittedBy", "admittedAt", "decisionRef"}
DECISION_TRUE = ("mappingAgainstPinnedSourceVerified", "importByteIdentityReverified", "rawCommitObjectsHashVerified",
                 "originalHeadSoleParentIsBase")
ANCESTRY_TRUE = DECISION_TRUE[:3] + ("mergeBaseAncestryVerified",)   # new mode: replaces the legacy sole-parent flag
DECISION_GO = ("GO for cutoff eligibility of this case only", "GO")      # exact values; never a prefix match
BASELINE_KEYS = {"schema", "caseUrl", "proofSha256", "admissionDigest", "decisionSha256", "importPinsDigest",
                 "changedPaths", "reviewConfigDigest", "authorizationSha256"}
BINDING_STATEMENT = ("The launch baseline pins the root documents, the import pins (canonical document digest), the changed "
                     "paths, the review-model config and the authorization FILE bytes. It does NOT bind product code, "
                     "prompts, profile or plan: root must export the exact accepted code bytes/hash and runtime config, pin "
                     "them externally before any real plan or live run, and compare the plan's first-request body hash "
                     "before sending.")
TIME_BINDING = ("headCommittedAt is a proof-declared value only sanity-checked against the commit-time evidence text; it is "
                "not verified here. The binding is the full proofSha256 pin plus the verified imports; root's independent "
                "chronology recheck is the verification.")

_URL_RX = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})/pull/([1-9][0-9]{0,8})")
_REPO_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
_HEX40 = re.compile(r"[0-9a-f]{40}")
_DIGEST_RX = re.compile(r"sha256:[0-9a-f]{64}")
_TS_RX = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_PAYLOAD_NAMES = {"benchmark_data.json", "pr_labels.json"}
_PAYLOAD_PARTS = re.compile(r"gold|label|competitor", re.I)


class BenchmarkLaunchError(Exception):
    """A refusal before (or instead of) a run. Messages never contain keys or file content."""


@dataclass(frozen=True)
class BenchmarkOptions:
    mode: str
    case_url: str
    cutoff_proof: str
    admission: str
    decision: str
    launch_baseline: str
    store: str
    base_import_pins: str
    head_import_pins: str
    out_dir: str
    auth: str | None = None
    state_dir: str | None = None
    env_file: str | None = None
    baseline_micros: int | None = None
    book_baseline_micros: int | None = None
    confirm_live: bool = False
    replay_trace: str | None = None
    trace_digest: str | None = None
    retrieval: bool = True
    repeat: int = 0
    config: str | None = None
    experiment: str = "baseline"      # opt-in prompt arm; the default is the unchanged baseline
    live_stage_timing: bool = False   # opt-in: versioned live stage ceilings + host-stop recording (binds the plan)


@dataclass(frozen=True)
class BenchIngested:
    url: str
    case_id: str
    case: dict                       # CaseInput over the IMPORT content ids
    repo: str                        # resolvedRepo
    proof: dict
    admission: dict
    base: object                     # RepoImport
    head: object
    import_pins: dict
    changed: tuple                   # sorted changed paths (all included on every side that has them)
    hashes: dict                     # proofSha256, admissionDigest, decisionSha256, baselineDigest
    store: Path


# ------------------------------------------------------------------ options

def _real(p) -> Path:
    return Path(os.path.realpath(p))


def check_options(o: BenchmarkOptions) -> None:
    """Mode/argument consistency and path hygiene. Touches nothing on disk."""
    if o.mode not in MODES:
        raise BenchmarkLaunchError("mode must be plan, live or replay")
    try:                                                   # an unsupported selector is refused before key/state/output
        check_experiment(o.experiment, o.retrieval)
    except (ProfileError, TypeError) as e:
        raise BenchmarkLaunchError(str(e)[:200]) from None
    for name in ("case_url", "cutoff_proof", "admission", "decision", "launch_baseline", "store", "base_import_pins",
                 "head_import_pins", "out_dir"):
        if not isinstance(getattr(o, name), str) or not getattr(o, name):
            raise BenchmarkLaunchError(f"{name} is required")
    if not _URL_RX.fullmatch(o.case_url):
        raise BenchmarkLaunchError("case URL must be exactly https://github.com/<org>/<repo>/pull/<n>")
    for name in ("cutoff_proof", "admission", "decision", "launch_baseline", "base_import_pins", "head_import_pins",
                 "replay_trace"):
        _no_payload_path(name, getattr(o, name))
    if type(o.repeat) is not int or not 0 <= o.repeat <= 1000:
        raise BenchmarkLaunchError("repeat must be 0..1000")
    live, replay = o.mode == "live", o.mode == "replay"
    state_args = (o.state_dir, o.env_file, o.baseline_micros, o.book_baseline_micros)
    if live:
        if not o.confirm_live:
            raise BenchmarkLaunchError("--mode live needs --confirm-live")
        if not (o.auth and o.state_dir and o.env_file):
            raise BenchmarkLaunchError("live needs --auth, --state-dir and --env")
        if type(o.baseline_micros) is not int or o.baseline_micros < 0:
            raise BenchmarkLaunchError("live needs an explicit --baseline-micros (non-negative integer)")
        if o.book_baseline_micros is not None and (type(o.book_baseline_micros) is not int or o.book_baseline_micros < 0):
            raise BenchmarkLaunchError("--book-baseline-micros must be a non-negative integer")
    elif any(a is not None for a in state_args) or o.confirm_live:
        raise BenchmarkLaunchError("--state-dir/--env/--baseline-micros/--book-baseline-micros/--confirm-live are live-only")
    if replay:
        if o.auth:
            raise BenchmarkLaunchError("replay uses no authorization")
        if not o.replay_trace or not (isinstance(o.trace_digest, str) and _DIGEST_RX.fullmatch(o.trace_digest)):
            raise BenchmarkLaunchError("replay needs --replay-trace and --trace-digest sha256:<64 hex> from the operator")
    else:
        if o.replay_trace or o.trace_digest:
            raise BenchmarkLaunchError("--replay-trace/--trace-digest are only for replay")
        if not live and not o.auth:
            raise BenchmarkLaunchError("plan needs --auth (read-only check that it covers the profile)")


def _no_payload_path(name: str, path) -> None:
    """The launch API has no benchmark data, label, gold or competitor input. A path that names one is refused."""
    if path is None:
        return
    p = Path(os.path.abspath(path))
    if p.name.lower() in _PAYLOAD_NAMES or any(_PAYLOAD_PARTS.search(part) for part in p.parts[1:]):
        raise BenchmarkLaunchError(f"{name}: benchmark data, label, gold and competitor-review paths are not launch inputs")


# ------------------------------------------------------------------ external documents

def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _bad_const(_):
    raise ValueError("non-finite number")


def read_doc(path, what: str):
    """(document, raw bytes) of a regular, non-link, size-capped, strict-JSON object."""
    try:
        raw = read_nofollow(path, DOC_MAX)
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes, parse_constant=_bad_const)
    except (OSError, ValueError, RecursionError):
        raise BenchmarkLaunchError(f"{what} is unreadable, not a regular file, too large or not strict JSON") from None
    if not isinstance(doc, dict):
        raise BenchmarkLaunchError(f"{what} must be a JSON object")
    return doc, raw


def _sha_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _ts(s) -> bool:
    if not (isinstance(s, str) and _TS_RX.fullmatch(s)):
        return False
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def check_proof(url: str, proof: dict) -> dict:
    """Structure and mapping rules of the cutoff proof. Never reads `status`; never trusts the PR head as proof."""
    extra = set(proof) - PROOF_KEYS - PROOF_OPTIONAL
    if PROOF_KEYS - set(proof) or extra:
        raise BenchmarkLaunchError(f"proof keys must be {sorted(PROOF_KEYS)} plus optional {sorted(PROOF_OPTIONAL)}")
    if proof["schema"] != PROOF_SCHEMA:
        raise BenchmarkLaunchError(f"proof schema must be {PROOF_SCHEMA}")
    if proof["originalUrl"] != url:
        raise BenchmarkLaunchError("proof is for a different case URL")
    for k in ("asOfBase", "asOfHead", "mergeBase"):
        if not (isinstance(proof[k], str) and _HEX40.fullmatch(proof[k])):
            raise BenchmarkLaunchError(f"proof {k} is not a 40-hex commit")
    if proof["asOfBase"] != proof["mergeBase"]:
        raise BenchmarkLaunchError("proof asOfBase must equal mergeBase (the base side is the merge base)")
    if proof["asOfHead"] == proof["mergeBase"]:
        raise BenchmarkLaunchError("proof head equals its base: not a reviewable change")
    repo = proof["resolvedRepo"]
    if not (isinstance(repo, str) and _REPO_RX.fullmatch(repo)):
        raise BenchmarkLaunchError("proof resolvedRepo must be owner/name")
    if not _ts(proof["headCommittedAt"]):
        raise BenchmarkLaunchError("proof headCommittedAt must be a UTC timestamp")
    ev = proof["evidence"]
    if not isinstance(ev, list) or not ev:
        raise BenchmarkLaunchError("proof evidence must be a non-empty list")
    kinds, times = set(), []
    for e in ev:
        if not isinstance(e, dict) or set(e) != {"kind", "source", "observedAt", "value"} \
                or not all(isinstance(e[k], str) and e[k] for k in e) or e["kind"] not in EVIDENCE_KINDS:
            raise BenchmarkLaunchError("malformed proof evidence item")
        if e["source"] in NOT_PROOF:
            raise BenchmarkLaunchError(f"evidence from {e['source']} is not proof of the as-of input")
        kinds.add(e["kind"])
        if e["kind"] == "commit-time":
            times.append(e["value"])
    for need in ("commit-time", "review-time"):
        if need not in kinds:
            raise BenchmarkLaunchError(f"proof lacks {need} evidence")
    m = _URL_RX.fullmatch(url)
    eval_fork = m.group(1).lower() == EVAL_ORG or f"{m.group(1)}/{m.group(2)}".lower() != repo.lower()
    if eval_fork and not kinds & {"fork-mapping", "redirect"}:
        raise BenchmarkLaunchError("the URL repository differs from the resolved one: fork-mapping/redirect evidence required")
    # Sanity statement only (substring of the evidence text), NOT commit-time verification: the full proofSha256 pin in the
    # root decision and launch baseline is the actual binding, and root rechecks the chronology independently (L1).
    if not any(proof["headCommittedAt"] in v for v in times):
        raise BenchmarkLaunchError("proof headCommittedAt is not stated by any commit-time evidence value")
    return proof


def binding(proof: dict) -> dict:
    return {"originalUrl": proof["originalUrl"], "resolvedRepo": proof["resolvedRepo"].lower(),
            "asOfBase": proof["asOfBase"], "asOfHead": proof["asOfHead"], "mergeBase": proof["mergeBase"],
            "evidenceDigests": sorted(digest(e) for e in proof["evidence"])}


def admission_problems(url: str, proof: dict, adm) -> list[str]:
    """Why an external root admission does not bind this proof (empty = binds). Local mirror of the scorer-side check."""
    if not isinstance(adm, dict) or set(adm) != ADMISSION_KEYS or adm.get("schema") != ADMISSION_SCHEMA:
        return [f"admission must be exactly {sorted(ADMISSION_KEYS)} with schema {ADMISSION_SCHEMA}"]
    why = []
    if adm["admittedBy"] != "root":
        why.append("admission is not by root")
    if not (isinstance(adm["admittedAt"], str) and _parse_any(adm["admittedAt"])):
        why.append("admittedAt missing/unparseable")
    if not (isinstance(adm["decisionRef"], str) and adm["decisionRef"].strip()):
        why.append("decisionRef missing")
    ev = adm["evidenceDigests"]
    if not isinstance(ev, list) or not ev or not all(isinstance(x, str) and _DIGEST_RX.fullmatch(x) for x in ev) \
            or ev != sorted(set(ev)):
        why.append("evidenceDigests must be a non-empty sorted unique list of sha256 digests")
    if adm["originalUrl"] != url:
        why.append("admission is for a different case URL")
    want = binding(proof)
    for k in ("resolvedRepo", "asOfBase", "asOfHead", "mergeBase", "evidenceDigests"):
        if adm[k] != want[k]:
            why.append(f"admission {k} differs from the proof")
    return why


def _parse_any(s: str) -> bool:
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _hex_map(v, keys=("base", "head"), rx=_HEX40) -> bool:
    return isinstance(v, dict) and set(v) == set(keys) and all(isinstance(x, str) and rx.fullmatch(x) for x in v.values())


def check_decision(url: str, proof_sha: str, d: dict, proof: dict) -> None:
    """Root decision: exact GO value, URL, full proof pin, the four root checks, no paid calls, and the repository and import
    commits it names must equal the supplied proof. (`importPinsSha256` is checked against the pins FILE bytes separately.)"""
    if not (isinstance(d.get("decision"), str) and d["decision"] in DECISION_GO):
        raise BenchmarkLaunchError("root decision is not an allowed GO value")
    if d.get("caseUrl") != url:
        raise BenchmarkLaunchError("root decision is for a different case URL")
    if d.get("proofSha256") != proof_sha:
        raise BenchmarkLaunchError("root decision does not pin this exact proof file")
    new_mode = "mergeBaseAncestryVerified" in d or "ancestryProof" in d
    if new_mode and "originalHeadSoleParentIsBase" in d:
        raise BenchmarkLaunchError("root decision mixes the legacy sole-parent flag with the ancestry proof")
    for k in (ANCESTRY_TRUE if new_mode else DECISION_TRUE):
        if d.get(k) is not True:
            raise BenchmarkLaunchError(f"root decision does not confirm {k}")
    if new_mode:
        try:
            verify_chain(d.get("ancestryProof"), proof["asOfHead"], proof["mergeBase"])
        except AncestryError as e:
            raise BenchmarkLaunchError(f"root decision {e}") from None
    paid = d.get("newPaidCalls")
    if type(paid) is not int or paid != 0:
        raise BenchmarkLaunchError("root decision newPaidCalls must be the integer 0")
    if not isinstance(d.get("resolvedRepo"), str) or d["resolvedRepo"] != proof["resolvedRepo"]:
        raise BenchmarkLaunchError("root decision resolvedRepo differs from the proof")
    commits = d.get("importCommits")
    if not _hex_map(commits) or commits != {"base": proof["mergeBase"], "head": proof["asOfHead"]}:
        raise BenchmarkLaunchError("root decision importCommits differ from the proof's merge base and head")
    if not _hex_map(d.get("importPinsSha256"), rx=_DIGEST_RX):
        raise BenchmarkLaunchError("root decision importPinsSha256 must be {base, head} sha256 digests")


def file_sha(path, what: str) -> str:
    """sha256 of the exact file bytes (regular, non-link, size-capped)."""
    try:
        return _sha_bytes(read_nofollow(path, DOC_MAX))
    except (OSError, ValueError):
        raise BenchmarkLaunchError(f"{what} is unreadable, not a regular file or too large") from None


def verify_authorization(o: BenchmarkOptions, ing) -> None:
    """The authorization FILE bytes must equal the baseline's pin. Plan and live only; checked before state, output or key."""
    if file_sha(o.auth, "authorization file") != ing.hashes["authorizationSha256"]:
        raise BenchmarkLaunchError("authorization file differs from the launch baseline's authorizationSha256")


def check_baseline(b: dict) -> dict:
    if set(b) != BASELINE_KEYS or b["schema"] != BASELINE_SCHEMA:
        raise BenchmarkLaunchError(f"launch baseline must be exactly {sorted(BASELINE_KEYS)} with schema {BASELINE_SCHEMA}")
    ok = (isinstance(b["caseUrl"], str) and all(isinstance(b[k], str) and _DIGEST_RX.fullmatch(b[k])
                                               for k in ("proofSha256", "admissionDigest", "decisionSha256", "reviewConfigDigest",
                                                       "authorizationSha256"))
          and isinstance(b["importPinsDigest"], dict) and set(b["importPinsDigest"]) == {"base", "head"}
          and all(isinstance(v, str) and _DIGEST_RX.fullmatch(v) for v in b["importPinsDigest"].values())
          and isinstance(b["changedPaths"], list) and b["changedPaths"] == sorted(set(b["changedPaths"]))
          and all(isinstance(p, str) and p for p in b["changedPaths"]))
    if not ok:
        raise BenchmarkLaunchError("launch baseline fields are malformed")
    return b


# ------------------------------------------------------------------ imports and changed files

def _leaves(imp) -> dict:
    try:
        doc = json.loads(read_nofollow(Path(imp.dir) / "git-entries.json", ENTRIES_MAX))
        out = {}
        for mode, oid, path, hexpath in doc:
            out[path if path is not None else ("hex", hexpath)] = (mode, oid)
    except (OSError, ValueError, TypeError):
        raise BenchmarkLaunchError("import git-entries.json is unreadable or malformed") from None
    return out


def changed_paths(base, head) -> tuple:
    """Paths whose (mode, oid) differ between the two pinned trees, omitted ones included. Every one must be present in
    the manifest of each side that has it; otherwise part of the change would be invisible to the reviewer."""
    lb, lh = _leaves(base), _leaves(head)
    changed = [k for k in set(lb) | set(lh) if lb.get(k) != lh.get(k)]
    if any(not isinstance(k, str) for k in changed):
        raise BenchmarkLaunchError("a changed path is not valid UTF-8: refusing a partially visible change")
    present = {s: {e["path"] for e in imp.manifest["entries"]} for s, imp in (("base", base), ("head", head))}
    for p in sorted(changed):
        for side, leaves in (("base", lb), ("head", lh)):
            if p in leaves and p not in present[side]:
                raise BenchmarkLaunchError(f"a changed path is omitted from the {side} import (binary, oversize or "
                                           "submodule): refusing a partially visible change")
    if not changed:
        raise BenchmarkLaunchError("the two pinned trees do not differ")
    return tuple(sorted(changed))


def _open_side(store: Path, repo: str, sha: str, pins_path: str, side: str):
    try:
        d = target_dir(store, github_remote(f"https://github.com/{repo}"), sha)
        ip = load_import_pins(pins_path, import_dir=d)
        if ip["repo"].lower() != repo.lower() or ip["commitSha"] != sha:
            raise BenchmarkLaunchError(f"{side} import pins are not for {repo} at the proof's {side} commit")
        imp = open_import(d, pins=ip)               # Git identity + manifest + tree + omissions vs EXTERNAL pins
    except RepoImportError as e:
        raise BenchmarkLaunchError(f"{side} import refused ({e.code}): {str(e)[:300]}") from None
    rec = imp.record
    if rec["commitSha"] != sha or f"{rec['repo']['owner']}/{rec['repo']['name']}".lower() != repo.lower():
        raise BenchmarkLaunchError(f"{side} import is not the proof's commit of {repo}")
    return imp, ip


def case_input_id(url: str) -> str:
    org, name, n = _URL_RX.fullmatch(url).groups()
    return f"bench--{org}--{name}--{n}".lower()


def ingest(o: BenchmarkOptions, cfg: EffectiveConfig) -> BenchIngested:
    """Every external pin first, then the imports, then the changed-file verification, then the CaseInput."""
    proof_doc, proof_raw = read_doc(o.cutoff_proof, "cutoff proof")
    proof = check_proof(o.case_url, proof_doc)
    proof_sha = _sha_bytes(proof_raw)
    adm, _ = read_doc(o.admission, "root admission")
    bad = admission_problems(o.case_url, proof, adm)
    if bad:
        raise BenchmarkLaunchError("root admission does not bind the proof: " + "; ".join(bad)[:400])
    dec, dec_raw = read_doc(o.decision, "root decision")
    check_decision(o.case_url, proof_sha, dec, proof)
    pin_files = {}
    for side, path in (("base", o.base_import_pins), ("head", o.head_import_pins)):
        pin_files[side] = file_sha(path, f"{side} import pins")
        if pin_files[side] != dec["importPinsSha256"][side]:
            raise BenchmarkLaunchError(f"root decision importPinsSha256.{side} differs from the supplied pins file bytes")
    bl, bl_raw = read_doc(o.launch_baseline, "launch baseline")
    check_baseline(bl)
    hashes = {"proofSha256": proof_sha, "admissionDigest": digest(adm), "decisionSha256": _sha_bytes(dec_raw),
              "baselineDigest": _sha_bytes(bl_raw), "authorizationSha256": bl["authorizationSha256"]}
    for k, want in (("caseUrl", o.case_url), ("proofSha256", hashes["proofSha256"]),
                    ("admissionDigest", hashes["admissionDigest"]), ("decisionSha256", hashes["decisionSha256"]),
                    ("reviewConfigDigest", cfg.models.digest)):
        if bl[k] != want:
            raise BenchmarkLaunchError(f"launch baseline {k} differs from the supplied input")
    repo, store = proof["resolvedRepo"], Path(os.path.abspath(o.store))
    base, bpins = _open_side(store, repo, proof["mergeBase"], o.base_import_pins, "base")
    head, hpins = _open_side(store, repo, proof["asOfHead"], o.head_import_pins, "head")
    for side, ip in (("base", bpins), ("head", hpins)):
        if file_sha(o.base_import_pins if side == "base" else o.head_import_pins, f"{side} import pins") != pin_files[side]:
            raise BenchmarkLaunchError(f"{side} import pins file changed while it was being read")
        if digest(ip) != bl["importPinsDigest"][side]:
            raise BenchmarkLaunchError(f"launch baseline importPinsDigest.{side} differs from the supplied import pins")
    if "ancestryProof" in dec:                       # new mode (validated in check_decision); legacy stays sole-parent
        try:
            check_endpoints(verify_chain(dec["ancestryProof"], proof["asOfHead"], proof["mergeBase"]),
                            head.record, base.record)
        except AncestryError as e:
            raise BenchmarkLaunchError(f"root decision {e}") from None
    elif head.record.get("parents") != [proof["mergeBase"]]:
        raise BenchmarkLaunchError("the head commit's sole parent is not the proof's merge base")
    if base.snapshot_id == head.snapshot_id or base.record["treeOid"] == head.record["treeOid"]:
        raise BenchmarkLaunchError("base and head imports are the same content: not a reviewable change")
    changed = changed_paths(base, head)
    if list(changed) != bl["changedPaths"]:
        raise BenchmarkLaunchError("the changed paths derived from the imports differ from the launch baseline")
    try:
        case = require("CaseInput", {
            "schema": "case-input@1", "id": case_input_id(o.case_url), "repo": repo, "synthetic": False,
            "base": {"snapshotId": base.snapshot_id, "root": "base"},
            "head": {"snapshotId": head.snapshot_id, "root": "head"},
            "pr": {"title": "", "body": ""}})                # PR text stays empty: nothing from the benchmark is passed
    except Exception:  # noqa: BLE001
        raise BenchmarkLaunchError("CaseInput could not be built from the case URL and repository") from None
    return BenchIngested(o.case_url, case["id"], case, repo, proof, adm, base, head, {"base": bpins, "head": hpins},
                         changed, hashes, store)


# ------------------------------------------------------------------ config and identity

def _input_paths(o: BenchmarkOptions) -> list:
    return [p for p in (o.cutoff_proof, o.admission, o.decision, o.launch_baseline, o.base_import_pins,
                        o.head_import_pins, o.store, o.out_dir) if p]


def effective_config(o: BenchmarkOptions, cfg: EffectiveConfig | None = None) -> EffectiveConfig:
    """Resolved (and validated) before any case file, output, state, key or model action."""
    if cfg is not None:
        return cfg
    return resolve_config(o.config, forbidden_roots=tuple(_input_paths(o)))


def _profile_parts(o: BenchmarkOptions, cfg: EffectiveConfig):
    profile = repository_profile(o.retrieval, cfg.models, o.experiment)
    return (profile, repository_plan(profile, live_stage_timing=o.live_stage_timing),
            repository_policy(o.retrieval, o.experiment))


def config_identity(ing: BenchIngested, profile: dict, plan: dict, policy, retrieval: bool, cfg: EffectiveConfig,
                    experiment: str = prompts.EXPERIMENT_BASELINE) -> dict:
    p = ing.proof
    ident = {"schema": CONFIG_SCHEMA, "caseUrl": ing.url, "caseInputId": ing.case_id, "resolvedRepo": ing.repo,
            "asOfBase": p["asOfBase"], "asOfHead": p["asOfHead"], "mergeBase": p["mergeBase"],
            "proofSha256": ing.hashes["proofSha256"], "admissionDigest": ing.hashes["admissionDigest"],
            "decisionSha256": ing.hashes["decisionSha256"], "launchBaselineDigest": ing.hashes["baselineDigest"],
            "authorizationSha256": ing.hashes["authorizationSha256"],
            "importPinsDigest": {s: digest(ing.import_pins[s]) for s in ("base", "head")},
            "importRecordDigest": {"base": digest(ing.base.record), "head": digest(ing.head.record)},
            "importSnapshotIds": {"base": ing.base.snapshot_id, "head": ing.head.snapshot_id},
            "changedPaths": list(ing.changed), "profile": digest(profile), "plan": digest(plan),
            "retrievalPolicy": None if policy is None else policy.digest, "retrieval": retrieval,
            "prTextSupplied": False, "reviewModelsDigest": cfg.models.digest}
    if experiment != prompts.EXPERIMENT_BASELINE:    # absent for the baseline => the default identity is unchanged
        ident["experiment"] = {"id": experiment, "tasks": prompts.experiment_task_digests(),
                               "verifierPrompt": profile["roles"]["verifier"]["promptVersion"],
                               "judgePrompt": profile["roles"]["judge"]["promptVersion"]}
    return ident


def eval_run_id(o: BenchmarkOptions, ident: dict) -> str:
    """Same for plan and live (mode class `live`) so the plan's first request is the live run's; replay adds the trace pin.
    The repeat index enters through EvalIdentity and the provider run scope."""
    parts = ["pilot-benchmark", ident, "live" if o.mode != "replay" else "replay"]
    if o.mode == "replay":
        parts.append(o.trace_digest)
    return "evr_" + sha256_hex(canonical_json(parts))[:16]


def build_spec(o: BenchmarkOptions, ing: BenchIngested, backend, runs: Path, profile, plan, policy, cfg) -> ReviewSpec:
    ident = config_identity(ing, profile, plan, policy, o.retrieval, cfg, o.experiment)
    host = HostConfig(out_root=runs, eval=EvalIdentity(eval_run_id(o, ident), ing.case["id"], o.repeat),
                      config_identity=ident, forbidden_roots=(ing.store,), wall_clock=utc_now, retrieval=policy)
    return ReviewSpec(case=copy.deepcopy(ing.case), base=SnapshotInput(ing.base.root, copy.deepcopy(ing.base.manifest)),
                      head=SnapshotInput(ing.head.root, copy.deepcopy(ing.head.manifest)), profile=profile, plan=plan,
                      host=host, backend=backend,
                      imports=RepositoryImports(copy.deepcopy(ing.base.record), copy.deepcopy(ing.head.record)))


# ------------------------------------------------------------------ disclosure and output

EXPERIMENT_NOTE = ("context-check@1 is a prompt-only arm on the existing schemas: it asks the verifier to check concrete "
                   "subclaims against the evidence and the judge to keep that uncertainty. It is not an audit and no "
                   "correctness claim is made. The deterministic fallback wording (judge unavailable or rejected) is the "
                   "baseline's and can repeat inadequately verified claim, mechanism and verifier-note text.")


def experiment_report(experiment: str, profile: dict) -> dict:
    """Which prompt arm this run selected, by id and by the digest of the actual task text it binds. The prompt ids are
    read from the profile the run uses (retrieval off keeps the v1 verifier), never from the selector or a literal."""
    roles = profile["roles"]
    ids = {"verifierPrompt": roles["verifier"]["promptVersion"], "judgePrompt": roles["judge"]["promptVersion"]}
    if experiment == prompts.EXPERIMENT_BASELINE:
        return {"id": experiment, **ids}
    return {"id": experiment, **ids, "taskDigests": prompts.experiment_task_digests(),
            "schemas": "existing VerifierTurn / JudgeOutput; same models, caps, tools, timeouts, retries and ceiling",
            "audited": False, "fallbackWording": "unchanged baseline fallback; may repeat unverified text",
            "note": EXPERIMENT_NOTE}


def disclosure_header(ing: BenchIngested, o: BenchmarkOptions, profile: dict) -> dict:
    cov = repocov.build(RepositoryImports(ing.base.record, ing.head.record), ing.base.manifest, ing.head.manifest, ing.case)
    p, omitted = ing.proof, cov["base"]["omittedTotal"] + cov["head"]["omittedTotal"]
    return {"origin": {"kind": ORIGIN_KIND, "caseUrl": ing.url, "resolvedRepo": ing.repo, "asOfBase": p["asOfBase"],
                       "asOfHead": p["asOfHead"], "mergeBase": p["mergeBase"], "headCommittedAt": p["headCommittedAt"],
                       "proofSha256": ing.hashes["proofSha256"], "admissionDigest": ing.hashes["admissionDigest"],
                       "decisionSha256": ing.hashes["decisionSha256"], "headCommittedAtBinding": TIME_BINDING},
            "historicalOriginClaimed": False, "benchmarkPayloadPassed": False, "caseInputId": ing.case_id,
            "launchBaselineDigest": ing.hashes["baselineDigest"], "launchBaselineBinds": BINDING_STATEMENT,
            "authorization": {"sha256": ing.hashes["authorizationSha256"],
                              "verification": "file-bytes-verified" if o.mode in ("plan", "live") else
                              "unverified-replay: the baseline's recorded digest; no authorization file was read"},
            "importPinsDigest": {s: digest(ing.import_pins[s]) for s in ("base", "head")},
            "changedPaths": list(ing.changed), "changedPathCount": len(ing.changed),
            "coverage": {"scope": cov["scope"], "fullRepositoryCoverage": cov["fullRepositoryCoverage"],
                         "gapKinds": cov["gapKinds"],
                         "base": {k: cov["base"][k] for k in ("commitSha", "snapshotId", "omissionCounts", "omittedTotal")},
                         "head": {k: cov["head"][k] for k in ("commitSha", "snapshotId", "omissionCounts", "omittedTotal")},
                         "warning": (f"{omitted} path(s) were omitted by the imports; every changed path is included"
                                     if omitted else None),
                         "prText": "OMITTED: the reviewer sees no PR title or body", "statement": repocov.statement(cov)},
            "experiment": experiment_report(o.experiment, profile), "quality": QUALITY}


def check_out(o: BenchmarkOptions, ing: BenchIngested) -> Path:
    """New, under real directories, outside the inputs, store, pins, auth, state, env and product code."""
    forbidden = [ing.store, o.cutoff_proof, o.admission, o.decision, o.launch_baseline, o.base_import_pins,
                 o.head_import_pins, REPO / "reviewer", REPO / "fixtures", REPO / "tests"]
    forbidden += [p for p in (o.auth, o.state_dir, o.env_file, o.replay_trace, o.config) if p]
    anchor = Path(ing.head.dir)                           # `_check_out` also forbids this directory and its parent
    try:
        return _check_out(o.out_dir, anchor, forbidden)
    except BridgeError as e:
        raise BenchmarkLaunchError(str(e)[:200]) from None


# ------------------------------------------------------------------ plan

def plan_mode(o: BenchmarkOptions, ing: BenchIngested, cfg: EffectiveConfig, *, runner=run_review) -> dict:
    verify_authorization(o, ing)                         # the pinned authorization file, before anything else
    check_out(o, ing)                                    # path rules only: nothing is created
    profile, plan, policy = _profile_parts(o, cfg)
    handle = trusted_authorization(o.auth, forbidden_roots=[ing.store, _real(o.out_dir), REPO])
    verify_authorization(o, ing)                         # and again after the handle read it (same bytes)
    scratch = tempfile.TemporaryDirectory(prefix="pilot-benchmark-plan-")
    transport = CapturingTransport()
    problem = result = None
    try:
        root = _real(scratch.name)
        runs = root / "runs"
        runs.mkdir()
        book = SpendBook(handle, root / BOOK_NAME)
        ledger = RuntimeLedger(root / LEDGER_NAME, TRIAL_TOTAL_USD_MICROS)
        evr = eval_run_id(o, config_identity(ing, profile, plan, policy, o.retrieval, cfg, o.experiment))
        provider = OpenRouterProvider(enabled=True, key=Secret("plan-placeholder-not-a-key"), authorization=handle,
                                      book=book, ledger=ledger, transport=transport,
                                      run_scope=provider_scope(evr, ing, o.repeat))
        backend = RecordBackend(handle, book, _providers(provider), utc_now)
        spec = build_spec(o, ing, backend, runs, profile, plan, policy, cfg)
        try:
            validate_spec(spec)
            backend.preflight(profile, plan["budget"])
            result = runner(spec)
        except PipelineError as e:
            problem = {"code": e.code, "message": str(e)[:400]}
        except AuthorizationError as e:
            problem = {"code": "authorization", "message": str(e)[:400]}
    finally:
        _force_cleanup(scratch)
    first = [_request_facts(r) for r in transport.requests]
    ceiling = plan["budget"]["maxUsdMicros"]
    worst = max((f["worstCaseRouterUsdMicros"] for f in first), default=None)
    planned = bool(first) and not any(f["toolsInBody"] for f in first)
    unmet = ["live: durable book/ledger state, --baseline-micros and in-flight are checked only by --mode live",
             "live: independent Opus gate on this host, then root's explicit invocation with real admission files",
             "live: root must export the exact accepted code bytes/hash and runtime config, pin them externally before any "
             "real plan/live, and compare this plan's first-request body hash before sending (the launch baseline does not "
             "bind code, prompts, profile or plan)",
             STRICT_REPLAY_ONLY]
    if worst is not None and worst > ceiling:
        planned = False
        unmet.insert(0, f"worst-case admission {worst} micros exceeds the {ceiling} run ceiling")
    if not first:
        unmet.insert(0, "no first request was captured: the pipeline never reached a model call")
    return {**disclosure_header(ing, o, profile), "schema": REPORT_SCHEMA, "mode": "plan",
            "status": "planned" if planned else "plan-failed", "ok": planned,
            "plan": {"models": cfg.report()["roles"], "retrieval": o.retrieval,
                     "retrievalPolicy": None if policy is None else policy.to_doc(),
                     "profile": f"{profile['id']}@{profile['version']}", "profileDigest": digest(profile),
                     "configIdentityDigest": digest(config_identity(ing, profile, plan, policy, o.retrieval, cfg,
                                                                    o.experiment)),
                     "firstRequestNote": "the first request is the investigator's and is identical in every arm; the "
                     "selected verifier/judge task text appears only in later requests and is bound through "
                     "profileDigest, configIdentityDigest and experiment.taskDigests",
                     "authorization": "covers the profile and run ceiling" if problem is None
                     else "NOT covered / not reached: " + problem["message"],
                     "capturedRequests": first, "capturedCount": len(first), "firstRequest": first[0] if first else None,
                     "worstCaseAdmissionUsdMicros": worst, "runCeilingUsdMicros": ceiling, "retries": 0, "repairs": 0,
                     "outputCaps": {r: s["caps"]["maxOutputTokens"] for r, s in profile["roles"].items()},
                     "providerCalls": 0, "networkCalls": 0, "keyRead": False, "scratchOnly": True,
                     "pipeline": problem if problem else {"status": result.status if result else None,
                                                          "error": result.error and result.error.get("code")},
                     "wouldWriteUnder": str(_real(o.out_dir))},
            "unmetGates": unmet, "note": "plan proves the first actual request only; no bill, no quality claim"}


# ------------------------------------------------------------------ live

def run_report(o, ing, res, profile, *, provider_calls, ledger_before, ledger_after, book) -> dict:
    return {**disclosure_header(ing, o, profile), "schema": REPORT_SCHEMA, "mode": o.mode, "status": res.status,
            "ok": res.status == "completed", "incomplete": res.incomplete,
            "error": res.error and {k: res.error.get(k) for k in ("code", "stage", "message") if k in res.error},
            "idempotent": res.idempotent, "providerCalls": provider_calls, "runId": res.run_id,
            "counts": {"hypotheses": len(res.hypotheses), "findings": len(res.findings),
                       "verifications": len(res.verifications), "drops": len(res.drops), "comments": len(res.comments)},
            "paths": {"runDir": res.run_dir, "review": res.review_path, "comments": res.comments_path,
                      "receipt": res.receipt_path, "trace": res.trace_path},
            "traceDigest": {"value": res.trace_digest, "trust": "self-reported by this run: not a trusted pin "
                            "until the operator stores it outside the output directory"},
            "retrieval": res.retrieval,
            "costs": {"gateway": gateway_costs(res), "runtime": ledger_costs(ledger_before, ledger_after),
                      "spendBook": book, "note": "key/generation reconciliation is root's, outside this tool"},
            "forkAndStageReplay": STRICT_REPLAY_ONLY}


def live_mode(o: BenchmarkOptions, ing: BenchIngested, cfg: EffectiveConfig, *, transport=None,
              key_loader=load_openrouter_key, runner=run_review) -> dict:
    verify_authorization(o, ing)                         # before state, output or key
    out = check_out(o, ing)
    profile, plan, policy = _profile_parts(o, cfg)
    handle = trusted_authorization(o.auth, forbidden_roots=[ing.store, out, REPO])
    verify_authorization(o, ing)
    try:
        book, ledger = open_state(o.state_dir, handle, o.baseline_micros,
                                  o.baseline_micros if o.book_baseline_micros is None else o.book_baseline_micros)
    except Refused as e:
        raise BenchmarkLaunchError(str(e)[:300]) from None
    try:
        _check_ceiling(ledger, plan)
    except RepositoryError as e:
        raise BenchmarkLaunchError(str(e)[:300]) from None
    evr = eval_run_id(o, config_identity(ing, profile, plan, policy, o.retrieval, cfg, o.experiment))
    validate_spec(build_spec(o, ing, _Unused(handle), Path(tempfile.gettempdir()), profile, plan, policy, cfg))
    try:
        RecordBackend(handle, book, _providers(DisabledProvider("anthropic")), utc_now).preflight(profile, plan["budget"])
    except PipelineError as e:
        raise BenchmarkLaunchError(f"authorization does not cover this profile/Plan: {str(e)[:300]}") from None
    runs = make_out(out)
    try:
        key = key_loader(o.env_file, forbidden_roots=[ing.store, out, REPO / "reviewer"])
        provider = OpenRouterProvider(enabled=True, key=key, authorization=handle, book=book, ledger=ledger,
                                      transport=transport, run_scope=provider_scope(evr, ing, o.repeat))
        backend = RecordBackend(handle, book, _providers(provider), utc_now)
        spec = build_spec(o, ing, backend, runs, profile, plan, policy, cfg)
        before = ledger.totals()
        try:
            res = runner(spec)
        except PipelineError as e:             # a typed stop is a result, not a launcher refusal: spend may have occurred
            rep = {**disclosure_header(ing, o, profile), "schema": REPORT_SCHEMA, "mode": o.mode,
                   "status": "pipeline-refused", "ok": False, "error": {"code": e.code, "message": str(e)[:400]}, "providerCalls": provider.calls,
                   "costs": {"runtime": ledger_costs(before, ledger.totals()), "spendBook": book.totals(),
                             "note": "key/generation reconciliation is root's, outside this tool"},
                   "forkAndStageReplay": STRICT_REPLAY_ONLY}
            rep["reportPath"] = write_report(out, rep, scrub=key.scrub)
            return rep
        except BaseException as e:
            _best_effort_report(out, ing, o, profile, e, key, ledger, before, provider)
            raise
        rep = run_report(o, ing, res, profile, provider_calls=provider.calls, ledger_before=before,
                         ledger_after=ledger.totals(), book=book.totals())
        rep["reportPath"] = write_report(out, rep, scrub=key.scrub)
        return rep
    except (EnvFileError, PipelineError):
        _remove_if_empty(out, runs)
        raise


def _best_effort_report(out, ing, o, profile, exc, key, ledger, before, provider) -> None:
    try:
        rep = {**disclosure_header(ing, o, profile), "schema": REPORT_SCHEMA, "mode": o.mode, "status": "interrupted",
               "ok": False, "error": {"type": type(exc).__name__}, "providerCalls": provider.calls,
               "costs": {"runtime": ledger_costs(before, ledger.totals())},
               "note": "an interrupted call keeps its ledger intent (worst case counted); the next invocation "
                       "refuses at the in-flight gate until root reconciles"}
        write_report(out, rep, scrub=key.scrub)
    except Exception:  # noqa: BLE001 - never hides the original interruption
        pass


# ------------------------------------------------------------------ replay

def replay_mode(o: BenchmarkOptions, ing: BenchIngested, cfg: EffectiveConfig, *, runner=run_review) -> dict:
    out = check_out(o, ing)
    profile, plan, policy = _profile_parts(o, cfg)
    backend = ReplayBackend(o.replay_trace, o.trace_digest, "operator-config")
    runs = make_out(out)
    spec = build_spec(o, ing, backend, runs, profile, plan, policy, cfg)
    try:
        res = runner(spec)
    except PipelineError:
        _remove_if_empty(out, runs)
        raise
    cost = res.cost or {}
    live_calls, replayed = cost.get("liveCalls"), cost.get("replayedCalls")
    clean = live_calls == 0 and isinstance(replayed, int) and replayed >= 1
    rep = run_report(o, ing, res, profile, provider_calls=0, ledger_before=None, ledger_after=None, book=None)
    rep["replay"] = {"liveCalls": live_calls, "replayedCalls": replayed, "newSpendUsdMicros": 0 if clean else None,
                     "consumedZeroLive": clean, "traceDigestPin": o.trace_digest, "keyRead": False, "networkCalls": 0}
    rep["ok"] = rep["ok"] and clean
    if not clean:
        rep["status"] = "replay-not-clean"
    rep["reportPath"] = write_report(out, rep)
    return rep


# ------------------------------------------------------------------ entry

def run_benchmark(o: BenchmarkOptions, *, transport=None, key_loader=load_openrouter_key, runner=run_review) -> dict:
    check_options(o)
    cfg = effective_config(o)                            # before ingestion, output, state, key or model
    ing = ingest(o, cfg)
    if o.mode == "plan":
        rep = plan_mode(o, ing, cfg, runner=runner)
    elif o.mode == "live":
        rep = live_mode(o, ing, cfg, transport=transport, key_loader=key_loader, runner=runner)
    else:
        rep = replay_mode(o, ing, cfg, runner=runner)
    rep["reviewModels"] = cfg.report()
    return rep


def render(rep: dict) -> str:
    c, og = rep["coverage"], rep["origin"]
    L = [f"mode: {rep['mode']}   status: {rep['status']}   ok: {rep['ok']}",
         f"origin: {og['kind']} {og['caseUrl']} (historical origin claimed: {rep['historicalOriginClaimed']})",
         f"  as-of base {og['mergeBase'][:12]} head {og['asOfHead'][:12]}; changed paths: {rep['changedPathCount']}",
         f"  coverage: {c['statement']}", f"  PR title/body: {c['prText']}"]
    if c["warning"]:
        L.append(f"  warning: {c['warning']}")
    L.append(f"  experiment: {rep['experiment']['id']} (verifier {rep['experiment']['verifierPrompt']}, "
             f"judge {rep['experiment']['judgePrompt']})")
    L.append(f"  review models: { {r: v['model'] for r, v in rep['reviewModels']['roles'].items()} } "
             f"(config {rep['reviewModels']['source']} {rep['reviewModels']['digest']})")
    if rep["mode"] == "plan":
        p = rep["plan"]
        L += [f"  plan: retrieval={p['retrieval']} ceiling ${p['runCeilingUsdMicros'] / 1e6:.2f} "
              f"worst-case first request ${(p['worstCaseAdmissionUsdMicros'] or 0) / 1e6:.6f}",
              f"  captured requests: {p['capturedCount']}  pipeline: {p['pipeline']}"]
        if p["firstRequest"]:
            f = p["firstRequest"]
            L.append(f"  first request: {f['schemaName']} {f['bodyBytes']} bytes sha256:{f['bodySha256']}")
        L += [f"  unmet gate: {g}" for g in rep["unmetGates"]]
        return "\n".join(L) + "\n"
    if "counts" not in rep:
        return "\n".join(L + [f"  error: {rep.get('error')}", f"  report: {rep.get('reportPath')}"]) + "\n"
    n = rep["counts"]
    L += [f"  run: {rep['runId']} provider calls={rep['providerCalls']} incomplete={rep['incomplete']} error={rep['error']}",
          f"  hypotheses={n['hypotheses']} findings={n['findings']} verified={n['verifications']} "
          f"dropped={n['drops']} comments={n['comments']}"]
    L += [f"  {k}: {v}" for k, v in rep["paths"].items()]
    L.append(f"  trace digest: {rep['traceDigest']['value']} ({rep['traceDigest']['trust']})")
    L.append(f"  gateway computed (not a bill): {rep['costs']['gateway']['computedTokenPricedUsd']}")
    L.append(f"  report: {rep.get('reportPath')}")
    return "\n".join(L) + "\n"


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="reviewer.pilot.benchmark",
                                 description="Admitted benchmark base/head pair review (read-only, unscored).")
    ap.add_argument("--mode", choices=MODES, default="plan")
    ap.add_argument("--case-url", required=True, help="exact benchmark case URL")
    ap.add_argument("--cutoff-proof", required=True, help="benchmark-cutoff-proof@1")
    ap.add_argument("--admission", required=True, help="external benchmark-cutoff-admission@1 (root)")
    ap.add_argument("--decision", required=True, help="root decision JSON pinning the full proof sha256")
    ap.add_argument("--launch-baseline", required=True, help="external benchmark-launch-baseline@1 (root)")
    ap.add_argument("--store", required=True, help="repoimport store holding both sides' imports")
    ap.add_argument("--base-import-pins", required=True, help="external repo-import-pins@1 for the base import")
    ap.add_argument("--head-import-pins", required=True, help="external repo-import-pins@1 for the head import")
    ap.add_argument("--out", required=True, help="fresh output directory (must not exist)")
    ap.add_argument("--auth", help="operator SpendAuthorization JSON; plan and live")
    ap.add_argument("--state-dir", help="EXISTING operator state dir (live)")
    ap.add_argument("--env", help="host .env path (read only with --mode live)")
    ap.add_argument("--baseline-micros", type=int, help="ledger committed micros root expects (live)")
    ap.add_argument("--book-baseline-micros", type=int, help="book committed micros if it differs (live)")
    ap.add_argument("--confirm-live", action="store_true", help="required with --mode live")
    ap.add_argument("--replay-trace", help="recorded trace.jsonl (replay)")
    ap.add_argument("--trace-digest", help="operator-held sha256:<64 hex> of the trace (replay)")
    ap.add_argument("--retrieval", choices=("on", "off"), default="on", help="Turn retrieval roles (ablation switch)")
    ap.add_argument("--experiment", choices=prompts.EXPERIMENTS, default=prompts.EXPERIMENT_BASELINE,
                    help="opt-in prompt arm (default: baseline). Needs --retrieval on; binds the run identity")
    ap.add_argument("--live-stage-timing", action="store_true",
                    help="opt-in: stage ceilings INVESTIGATE 300/VERIFY 300/JUDGE 200 + host-stop recording (binds the plan)")
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--config", help="review-model config (pullo.toml format); default: Pullo's own pullo.toml")
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv=None, *, transport=None, key_loader=load_openrouter_key, out=sys.stdout, err=sys.stderr,
         runner=run_review) -> int:
    a = _parser().parse_args(argv)
    o = BenchmarkOptions(mode=a.mode, case_url=a.case_url, cutoff_proof=a.cutoff_proof, admission=a.admission,
                         decision=a.decision, launch_baseline=a.launch_baseline, store=a.store,
                         base_import_pins=a.base_import_pins, head_import_pins=a.head_import_pins, out_dir=a.out,
                         auth=a.auth, state_dir=a.state_dir, env_file=a.env, baseline_micros=a.baseline_micros,
                         book_baseline_micros=a.book_baseline_micros, confirm_live=a.confirm_live,
                         replay_trace=a.replay_trace, trace_digest=a.trace_digest, retrieval=a.retrieval == "on",
                         repeat=a.repeat, config=a.config, experiment=a.experiment,
                         live_stage_timing=a.live_stage_timing)
    try:
        rep = run_benchmark(o, transport=transport, key_loader=key_loader, runner=runner)
    except (BenchmarkLaunchError, ConfigError, PilotError, EnvFileError, AuthorizationError, PipelineError) as e:
        err.write(f"error: {type(e).__name__}: {str(e)[:400]}\n")
        return 2
    out.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n" if a.json else render(rep))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
