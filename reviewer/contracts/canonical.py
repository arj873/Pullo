"""Canonical JSON, digests and deterministic identity.

Canonical form ("python-canonical@2", not RFC 8785): sorted string keys, no
whitespace, UTF-8, ensure_ascii off. Integral floats inside +/-(2**53-1)
(including -0.0) are written as integers, so 1 and 1.0 hash alike. Other floats
use Python's shortest round-trip repr. Only Python recomputes these hashes in
Stage 0A; another language must port `_canon` exactly before comparing digests.
Non-JSON input (non-string keys, tuples, sets, NaN, lone surrogates,
oversized ints, nesting > 64) raises instead of being coerced.

Identity rules (S0-03):
- Content ids (hypotheses, comments, tool/model calls, cost records) never
  include runId, so a strict replay reproduces them. They are unique only
  within one run: every store, ledger or aggregate keys them as (runId, id)
  (`scoped_key`).
- ReviewRun ids derive from (idempotencyKey, attempt). Resume keeps the id; a
  manual rerun increments attempt; eval executions get unique keys.
- GitHub repos are "Owner/Name" with display case preserved; keys use the
  case-folded form because GitHub names are case-insensitive.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

CANONICAL_VERSION = "python-canonical@2"
_MAX_SAFE = 2**53 - 1
_MAX_DEPTH = 64


def _canon(v: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("nesting deeper than 64")
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        if abs(v) > _MAX_SAFE:
            raise ValueError("integer outside +/-(2**53-1)")
        return v
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ValueError("NaN/Infinity are not JSON")
        if v.is_integer() and abs(v) <= _MAX_SAFE:
            return int(v)
        return v
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("string is not valid UTF-8 (lone surrogate)") from None
        return v
    if type(v) is list:
        return [_canon(x, depth + 1) for x in v]
    if type(v) is dict:
        out = {}
        for k, x in v.items():
            if not isinstance(k, str):
                raise TypeError(f"non-string key {k!r}")
            out[_canon(k, depth)] = _canon(x, depth + 1)
        return out
    raise TypeError(f"not JSON: {type(v).__name__}")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(_canon(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    return "sha256:" + sha256_hex(canonical_json(obj))


def derive_id(prefix: str, *parts: Any) -> str:
    if not re.fullmatch(r"[a-z]+", prefix):
        raise ValueError(f"bad id prefix {prefix!r}")
    return f"{prefix}_{sha256_hex(canonical_json(list(parts)))[:16]}"


def scoped_key(run_id: str, content_id: str) -> str:
    """Store/ledger key for a run-scoped content id (D6)."""
    return f"{run_id}/{content_id}"


# ---------------------------------------------------------------- replay comparison
# Exact top-level fields ignored per entity. Opaque Json payloads (tool args/results,
# model requests/responses, params, config) are never inspected or stripped.

COMPARE_IGNORE: dict[str, frozenset[str]] = {
    "ReviewRun": frozenset({"id", "idempotencyKey", "attempt", "rerunOf", "trigger", "mode",
                            "evalRunId", "replayOf", "fromStage", "spendAuthorization",
                            "startedAt", "endedAt"}),
    "CostRecord": frozenset({"runId", "evalRunId", "basis", "replayOf"}),
    "Hypothesis": frozenset({"runId"}),
    "Finding": frozenset({"runId"}),
    "Comment": frozenset({"runId"}),
    "TraceEvent": frozenset({"runId", "at", "latencyMs"}),
    "StageArtifact": frozenset({"runId"}),
    "StagePayload": frozenset(),
    "EvalReport": frozenset({"evalRunId", "replayOf", "createdAt", "mode", "cost", "latency",
                             "limitations"}),
    "CaseResult": frozenset({"runId", "latencyMs"}),
}
_NESTED: dict[str, dict[str, str]] = {
    "TraceEvent": {"run": "ReviewRun", "record": "CostRecord"},
    "StageArtifact": {"payload": "StagePayload"},
    "StagePayload": {"run": "ReviewRun", "hypotheses": "Hypothesis[]", "findings": "Finding[]",
                     "comments": "Comment[]"},
    "EvalReport": {"cases": "CaseResult[]"},
}
_SCHEMA_TAGS = {"trace-event@1": "TraceEvent", "stage-artifact@1": "StageArtifact",
                "eval-report@1": "EvalReport"}


def entity_of(doc: Any) -> str | None:
    """Best-effort entity detection for comparison; None means compare everything."""
    if not isinstance(doc, dict):
        return None
    tag = doc.get("schema")
    if isinstance(tag, str) and tag in _SCHEMA_TAGS:
        return _SCHEMA_TAGS[tag]
    if "idempotencyKey" in doc:
        return "ReviewRun"
    i = doc.get("id")
    if isinstance(i, str):
        if i.startswith("cost_"):
            return "CostRecord"
        if i.startswith("cmt_"):
            return "Comment"
        if i.startswith("hyp_"):
            return "Finding" if "verification" in doc else "Hypothesis"
    return None


def comparable(doc: Any, entity: str | None = None) -> Any:
    entity = entity or entity_of(doc)
    if entity is None or not isinstance(doc, dict):
        return doc
    ignore = COMPARE_IGNORE.get(entity, frozenset())
    nested = _NESTED.get(entity, {})
    out = {}
    for k, v in doc.items():
        if k in ignore:
            continue
        sub = nested.get(k)
        if sub and sub.endswith("[]") and isinstance(v, list):
            v = [comparable(x, sub[:-2]) for x in v]
        elif sub:
            v = comparable(v, sub)
        out[k] = v
    return out


def comparable_digest(doc: Any, entity: str | None = None) -> str:
    """Digest used to decide 'replay reproduced the recording'."""
    return digest(comparable(doc, entity))


# ---------------------------------------------------------------- named digest recipes

def result_hash(tool_result: dict) -> str:
    """TraceEvent tool.call resultHash: digest of the redacted, validated ToolResult."""
    from .schema import require
    return digest(require("ToolResult", tool_result))


def artifact_digest(artifact: dict) -> str:
    """StageArtifact.inputDigest of the next stage and checkpoint artifactDigest."""
    return comparable_digest(artifact, "StageArtifact")


def profile_digest(profile: dict) -> str:
    from .schema import require
    return digest(require("ModelProfile", profile))


def config_digest(config: Any) -> str:
    """ReviewRun.configSnapshotId and EvalReport.configDigest: digest of the opaque config JSON."""
    return digest(config)


def suite_digest(manifest: dict, file_sha256: dict[str, str]) -> str:
    """EvalReport.dataset.suiteDigest: the manifest plus sha256 of every case input/labels file."""
    from .schema import require
    require("SuiteManifest", manifest)
    needed = sorted({c["input"] for c in manifest["cases"]} | {c["labels"] for c in manifest["cases"]})
    missing = [p for p in needed if p not in file_sha256]
    if missing:
        raise ValueError(f"suite_digest missing file hashes: {missing[:3]}")
    return digest({"manifest": manifest, "files": [[p, file_sha256[p]] for p in needed]})


_RUN_SCOPED_TEXT = re.compile(r"(?<![0-9a-z])(?:run|evr)_[0-9a-f]{16}(?![0-9a-f])")


def request_hash(request: dict) -> str:
    """Strict-replay key for a ModelRequest. Rejects (ValueError) requests that are invalid,
    still contain protected text, or embed run-scoped ids (those would make every replay miss)."""
    from .redaction import contains_protected
    from .schema import require
    require("ModelRequest", request)
    text = canonical_json(request).decode("utf-8")
    if contains_protected(text):
        raise ValueError("request contains protected text; redact before hashing")
    if _RUN_SCOPED_TEXT.search(text):
        raise ValueError("request embeds a run-scoped id")
    return digest(request)


# ---------------------------------------------------------------- run identity

GITHUB_REPO = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}")


def repo_key(repo: str) -> str:
    """Identity form of a repo id: GitHub 'Owner/Name' case-folded; opaque slugs unchanged."""
    return repo.lower() if GITHUB_REPO.fullmatch(repo) else repo


def idempotency_key_pr(repo: str, pr_number: int, head_sha: str) -> str:
    return "idem:pr:" + sha256_hex(canonical_json(["pr", repo_key(repo), pr_number, head_sha]))


def idempotency_key_local(repo: str, base_snapshot: str, head_snapshot: str) -> str:
    return "idem:local:" + sha256_hex(canonical_json(
        ["local", repo_key(repo), base_snapshot, head_snapshot]))


def idempotency_key_eval(eval_run_id: str, case_id: str, repeat: int,
                         base_snapshot: str, head_snapshot: str) -> str:
    return "idem:eval:" + sha256_hex(canonical_json(
        ["eval", eval_run_id, case_id, repeat, base_snapshot, head_snapshot]))


def run_id(idempotency_key: str, attempt: int) -> str:
    return derive_id("run", idempotency_key, attempt)


def hypothesis_id(specialist: str, ordinal: int, claim: str, path: str, line: int) -> str:
    return derive_id("hyp", specialist, ordinal, claim, path, line)


def call_id(stage: str, role: str, agent_id: str, ordinal: int, attempt: int) -> str:
    """Model call id: ordinal is the agent's nth logical call; attempt counts retries/repairs."""
    return derive_id("call", stage, role, agent_id, ordinal, attempt)


def tool_call_id(stage: str, agent_id: str, ordinal: int, tool: str, args: Any) -> str:
    return derive_id("tool", stage, agent_id, ordinal, tool, digest(args))


def cost_id(subject_id: str) -> str:
    return derive_id("cost", subject_id)


def comment_fingerprint(category: str, path: str, anchor_text: str, claim: str,
                        symbol: str | None = None) -> str:
    """fp2: anchors on flagged-line content and symbol (case preserved, whitespace collapsed),
    never line numbers. The prose claim is case- and whitespace-insensitive."""
    anchor = " ".join(anchor_text.split())
    prose = " ".join(claim.split()).lower()
    return "fp2:" + sha256_hex(canonical_json([category, path, symbol or "", anchor, prose]))[:32]


def comment_id(fingerprint: str) -> str:
    return derive_id("cmt", fingerprint)
