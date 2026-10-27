"""Root-pinned external launch baseline for the scoring host (SCORE-HOST-05). Pure file/pin checks; no key, network,
provider, review-pipeline or gold import. Every failure is a fixed `BaselineError.reason`, never a path, value or content.

The baseline is a JSON file written by ROOT (schema pullo-score-launch-baseline@1). It binds: the declared tool-case set,
the score config + prompt/schema/policy/renderer digests, the root-named source fileset, the input files, the ORIGINAL
state directory (canonical shared scorer lock), original authorization (file hash, digest, expiry), the initial book and
ledger exposure, a fresh catalog proof, an exact-route 3-role canary proof, external trace pins, and the live gate."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

SCHEMA = "pullo-score-launch-baseline@1"
MAX_BYTES = 1 << 20
_KEYS = {"schema", "mode", "declared", "scoreConfig", "promptSha256", "schemaSha256", "policySha256", "rendererSha256",
         "sourceRoot", "sourceFiles", "inputRoot", "inputs", "stateDir", "auth", "initial", "catalogProof", "canaryProof",
         "tracePins", "liveAuthorized", "envFile", "evidenceRoot"}
_SEAL = os.urandom(32)
ROLES = ("extractor", "deduper", "matcher")
ROUTE = "anthropic/claude-opus-5.5"
_CP_KEYS = {"priceVersion", "sha256", "observedAt", "expiresAt", "path"}
_CANARY_KEYS = {"roles", "sha256", "observedAt", "expiresAt", "authDigest", "route", "path"}
CATALOG_EVIDENCE = "pullo-catalog-evidence@1"
CANARY_EVIDENCE = "pullo-canary-evidence@1"


class BaselineError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _need(ok, reason):
    if not ok:
        raise BaselineError(reason)


def read_regular(path, *, root=None, limit=MAX_BYTES, owner_only=False) -> bytes:
    """Regular file only: no symlink at the leaf or any component under `root`, bounded size, optional 0600/owner check."""
    p = Path(path)
    _need(p.is_absolute() or root is not None, "unsafe-path")
    if root is not None:
        r = Path(root)
        p = r / p if not p.is_absolute() else p
        _need(Path(os.path.abspath(p)).is_relative_to(Path(os.path.abspath(r))), "unsafe-path")
        cur = Path(os.path.abspath(r))
        for part in Path(os.path.abspath(p)).relative_to(cur).parts:
            cur = cur / part
            _need(not cur.is_symlink(), "unsafe-path")
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BaselineError("unreadable-file") from None
    try:
        st0 = os.fstat(fd)
        if not stat.S_ISREG(st0.st_mode):
            os.close(fd)
            raise BaselineError("not-regular-file")
    except OSError:
        os.close(fd)
        raise BaselineError("unreadable-file") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        _need(stat.S_ISREG(st.st_mode), "not-regular-file")
        _need(not owner_only or (not st.st_mode & 0o077 and st.st_uid == os.geteuid()), "unsafe-mode")
        data = f.read(limit + 1)
    _need(len(data) <= limit, "file-too-large")
    return data


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ts(v) -> dt.datetime:
    try:
        t = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise BaselineError("bad-timestamp") from None
    _need(t.tzinfo is not None, "bad-timestamp")
    return t


@dataclass(frozen=True)
class Baseline:
    doc: dict
    file_sha256: str

    @property
    def mode(self): return self.doc["mode"]
    @property
    def declared(self): return tuple(tuple(x) for x in self.doc["declared"])
    @property
    def state_dir(self): return Path(self.doc["stateDir"])
    @property
    def lock_path(self): return Path(self.doc["stateDir"]) / "scorer.lock"      # canonical, derived from the ORIGINAL state dir
    @property
    def ledger_path(self): return Path(self.doc["stateDir"]) / "runtime-ledger.jsonl"
    @property
    def book_path(self): return Path(self.doc["stateDir"]) / "spend-book.jsonl"


@dataclass(frozen=True)
class Verified:
    """Issued only by `verify`. Carries what a live entry needs; hand-built instances fail `genuine`."""
    baseline_sha256: str
    mode: str
    live_authorized: bool
    seal: str
    inputs: dict = None                          # {path: bytes}: the exact bytes that were hash-verified (parse THESE, never re-read)

    def genuine(self) -> bool:
        return isinstance(self.seal, str) and hmac.compare_digest(self.seal, _seal_of(self.baseline_sha256, self.mode, self.live_authorized))


def _seal_of(sha, mode, live) -> str:
    return hmac.new(_SEAL, json.dumps([sha, mode, live]).encode(), hashlib.sha256).hexdigest()


def load_baseline(path) -> Baseline:
    data = read_regular(path, owner_only=True)
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise BaselineError("baseline-not-json") from None
    _need(isinstance(doc, dict) and set(doc) == _KEYS and doc["schema"] == SCHEMA, "baseline-shape")
    _need(doc["mode"] in ("campaign", "canary") and type(doc["liveAuthorized"]) is bool, "baseline-shape")
    _need(isinstance(doc["declared"], list) and doc["declared"] and all(isinstance(x, list) and len(x) == 2 and all(isinstance(y, str) for y in x) for x in doc["declared"]), "baseline-shape")
    _need(len({tuple(x) for x in doc["declared"]}) == len(doc["declared"]), "baseline-shape")
    for k in ("sourceRoot", "inputRoot", "stateDir", "evidenceRoot"):
        _need(isinstance(doc[k], str) and os.path.isabs(doc[k]), "baseline-shape")
    ini = doc["initial"]
    _need(isinstance(ini, dict) and set(ini) == {"scoring", "all", "bookCommitted", "bookInflight"} and all(type(v) is int and v >= 0 for v in ini.values()), "baseline-shape")
    return Baseline(doc, sha256_hex(data))


def verify(b: Baseline, *, now: str, config_digest: str, prompt_sha256: dict, schema_sha256: str, policy_sha256: str,
           renderer_sha256: str, auth_handle=None, require_proofs: bool = True) -> Verified:
    """All drift checks BEFORE any key read or send. `auth_handle` is the trusted AuthorizationHandle loaded from the pinned
    file (or None for strict replay, which needs no authorization)."""
    d, t = b.doc, _ts(now)
    sc = d["scoreConfig"]
    _need(isinstance(sc, dict) and set(sc) == {"path", "sha256", "digest"}, "baseline-shape")
    _need(sha256_hex(read_regular(sc["path"], root=d["sourceRoot"])) == sc["sha256"], "source-drift")
    _need(sc["digest"] == config_digest, "config-drift")
    _need(d["promptSha256"] == prompt_sha256, "prompt-drift")
    _need((d["schemaSha256"], d["policySha256"], d["rendererSha256"]) == (schema_sha256, policy_sha256, renderer_sha256), "pin-drift")
    _need(isinstance(d["sourceFiles"], list) and d["sourceFiles"], "baseline-shape")
    claimed = {}
    for f in d["sourceFiles"]:
        _need(isinstance(f, dict) and set(f) == {"path", "sha256"} and isinstance(f["path"], str) and f["path"] not in claimed, "baseline-shape")
        _need(sha256_hex(read_regular(f["path"], root=d["sourceRoot"])) == f["sha256"], "source-drift")
        claimed[f["path"]] = f["sha256"]
    _bind_running_source(d["sourceRoot"], claimed)
    _need(isinstance(d["inputs"], list) and d["inputs"], "baseline-shape")
    inputs = {}
    for f in d["inputs"]:
        _need(isinstance(f, dict) and set(f) == {"path", "sha256"} and isinstance(f["path"], str), "baseline-shape")
        data = read_regular(f["path"], root=d["inputRoot"], limit=64 << 20)          # read ONCE: hashed here, parsed by the caller from these bytes
        _need(sha256_hex(data) == f["sha256"], "input-drift")
        inputs[f["path"]] = data
    if auth_handle is not None:
        a = d["auth"]
        _need(isinstance(a, dict) and set(a) == {"path", "sha256", "digest", "expiresAt"}, "baseline-shape")
        _need(auth_handle.digest == a["digest"] and auth_handle.auth["expiresAt"] == a["expiresAt"], "auth-drift")
        _need(t < _ts(a["expiresAt"]), "auth-expired")
    cp = d["catalogProof"]
    cp_ok = isinstance(cp, dict) and set(cp) == _CP_KEYS
    live = d["liveAuthorized"]
    if require_proofs:
        from reviewer.runtime.catalog import PRICE_VERSION
        _need(cp_ok and cp["priceVersion"] == PRICE_VERSION and _ts(cp["observedAt"]) <= t < _ts(cp["expiresAt"]), "catalog-proof-missing-or-stale")
        _check_evidence_catalog(d, cp)
        if d["mode"] == "campaign":
            c = d["canaryProof"]
            _need(isinstance(c, dict) and set(c) == _CANARY_KEYS and c["roles"] == list(ROLES) and c["route"] == ROUTE
                  and auth_handle is not None and c["authDigest"] == auth_handle.digest
                  and _ts(c["observedAt"]) <= t < _ts(c["expiresAt"]), "canary-proof-missing-or-stale")
            _check_canary_ttl(c["observedAt"], c["expiresAt"])
            _check_evidence_canary(d, c, config_digest, prompt_sha256, schema_sha256, policy_sha256)
    return Verified(b.file_sha256, d["mode"], live, _seal_of(b.file_sha256, d["mode"], live), inputs)


CANARY_MAX_TTL = dt.timedelta(hours=24)                  # root-accepted policy: a canary receipt is valid for at most 24h


def _check_canary_ttl(observed: str, expires: str) -> None:
    span = _ts(expires) - _ts(observed)
    _need(dt.timedelta(0) < span <= CANARY_MAX_TTL, "canary-ttl")


def _bind_running_source(source_root, claimed: dict):
    """The baseline must list EVERY file of the running `reviewer` package with its hash, sourceRoot must be that package's
    parent, and every loaded reviewer.* module must come from it: an unrelated tree or a partial list is refused."""
    pkg = Path(__file__).resolve().parent
    _need(Path(os.path.realpath(source_root)) == pkg.parent, "source-not-running-tree")
    actual = {}
    for p in sorted(pkg.rglob("*")):
        if "__pycache__" in p.parts:
            continue
        _need(not p.is_symlink(), "unsafe-path")
        if p.is_file():
            actual["reviewer/" + p.relative_to(pkg).as_posix()] = sha256_hex(p.read_bytes())
    listed = {k: v for k, v in claimed.items() if k.startswith("reviewer/")}
    _need(listed == actual, "source-not-running-tree")
    for n, m in list(sys.modules.items()):
        if n == "reviewer" or n.startswith("reviewer."):
            f = getattr(m, "__file__", None)
            _need(f is not None and Path(os.path.realpath(f)).is_relative_to(pkg), "source-not-running-tree")


def _evidence(d, proof, schema):
    """Evidence file named by the proof: regular, owner-only 0600, size-capped, sha256 == proof.sha256, schema exact. Parsed
    from the SAME bytes that were hashed."""
    data = read_regular(proof["path"], root=d["evidenceRoot"], owner_only=True, limit=1 << 20)
    _need(sha256_hex(data) == proof["sha256"], "evidence-drift")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise BaselineError("evidence-malformed") from None
    _need(isinstance(doc, dict) and doc.get("schema") == schema, "evidence-malformed")
    return doc


def _check_evidence_catalog(d, cp):
    from reviewer.runtime.catalog import PRICE_VERSION
    e = _evidence(d, cp, CATALOG_EVIDENCE)
    _need(set(e) == {"schema", "priceVersion", "model", "provider", "observedAt", "expiresAt"}
          and e["priceVersion"] == cp["priceVersion"] == PRICE_VERSION and e["model"] == ROUTE and e["provider"] == "anthropic"
          and e["observedAt"] == cp["observedAt"] and e["expiresAt"] == cp["expiresAt"], "evidence-binding")


def _check_evidence_canary(d, c, config_digest, prompt_sha256, schema_sha256, policy_sha256):
    e = _evidence(d, c, CANARY_EVIDENCE)
    if isinstance(e.get("observedAt"), str) and isinstance(e.get("expiresAt"), str):
        _check_canary_ttl(e["observedAt"], e["expiresAt"])                # the ACTUAL receipt, not only the proof fields
    _need(set(e) == {"schema", "roles", "route", "authDigest", "observedAt", "expiresAt", "probes", "configDigest", "promptSha256",
                     "schemaSha256", "policySha256", "outcome"}
          and e["roles"] == list(ROLES) and e["route"] == ROUTE and e["authDigest"] == c["authDigest"]
          and e["observedAt"] == c["observedAt"] and e["expiresAt"] == c["expiresAt"]
          and e["probes"] == {"extractor": 1, "deduper": 1, "matcher": 1} and e["outcome"] == "ok"
          and e["configDigest"] == config_digest and e["promptSha256"] == prompt_sha256 and e["schemaSha256"] == schema_sha256
          and e["policySha256"] == policy_sha256, "evidence-binding")
