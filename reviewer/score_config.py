"""Strict file-driven score configuration (SCORE-PROTO-01): `pullo-score.toml`, schema pullo-score-config@1.

Separate from reviewer.config / pullo.toml (neither imports the other). Reads ONLY the path it is given: no environment,
no CLI, no default search. Unknown, malformed or widened values are refused. Sampling and effort are OMITTED on the wire
for every tool: the file may only say `policy = "omit"`; temperature/top_p/top_k/effort keys (including null) are
refused. Prices are never read here: the caller supplies the (unverified-catalog) Price when building the profile."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .benchmark import score_prompts as P

SCHEMA = "pullo-score-config@1"
MODEL = "anthropic/claude-opus-5.5"
# Policy maxima (score-policy: tighter is allowed, wider is refused). Opus 5.5 reasoning tokens count against max_tokens:
# the pair cap was 256 until 2026-10-29, when 3 of 492 real pair calls stopped at finish_reason "length" with 255-256
# reasoning tokens and no JSON. It is 1024 since (profile pullo-score@2); extract and dedup are unchanged.
MAX_OUTPUT = {"extract": 8000, "dedup": 4000, "pair": 1024}
# The ScoreProfile version. Bumped with any change to the profile caps so traces/witnesses of another cap never match.
PROFILE_VERSION = 2
PROFILE_REF = f"pullo-score@{PROFILE_VERSION}"
MAX_TIMEOUT_SEC = 600
MAX_LIMITS = {"max_candidates_per_tool_case": 200, "max_pairs_per_tool_case": 2000, "max_calls_per_score_run": 2002}
EXACT_LIMITS = {"skip_dedup_below": 2, "min_extract_chars": 20}
_TOP = {"schema", "model", "limits", "caps", "sampling", "prompts"}
_STAGES = ("extract", "dedup", "pair")


class ScoreConfigError(ValueError):
    """Fixed-text refusal; never echoes file values."""


def _need(ok, why):
    if not ok:
        raise ScoreConfigError(why)


def _posint(v):
    return type(v) is int and v >= 1


@dataclass(frozen=True)
class ScoreConfig:
    max_output: dict
    timeout_sec: dict
    max_candidates: int
    max_pairs: int
    max_calls: int
    skip_dedup_below: int
    min_extract_chars: int
    prompt_sha256: dict

    def canonical(self) -> dict:
        return {"schema": SCHEMA, "model": MODEL, "maxOutput": dict(self.max_output), "timeoutSec": dict(self.timeout_sec),
                "maxCandidates": self.max_candidates, "maxPairs": self.max_pairs, "maxCalls": self.max_calls,
                "skipDedupBelow": self.skip_dedup_below, "minExtractChars": self.min_extract_chars,
                "promptVersions": dict(P.VERSIONS), "promptSha256": dict(self.prompt_sha256),
                "sampling": "omit", "effort": "omit", "retries": 0, "repairs": 0, "fallbacks": []}

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(json.dumps(self.canonical(), sort_keys=True).encode()).hexdigest()

    def profile(self, price: dict, *, profile_id: str = "pullo-score", version: int = PROFILE_VERSION) -> dict:
        """ScoreProfile document. Params carry ONLY the output cap: no temperature/top_p/top_k/effort, never null."""
        roles = {}
        for stage, role in P.ROLE_OF.items():
            roles[role] = {"provider": "anthropic", "model": MODEL, "family": "anthropic", "resolved": True,
                           "promptVersion": P.VERSIONS[stage],
                           "outputSchema": {"extractor": "ScoreExtractionSegments", "deduper": "ScoreDedup", "matcher": "ScorePair"}[role],
                           "params": {"maxOutputTokens": self.max_output[stage]},
                           "caps": {"maxOutputTokens": self.max_output[stage], "timeoutSec": self.timeout_sec[stage],
                                    "maxRetries": 0, "maxRepairs": 0},
                           "price": dict(price), "fallbacks": []}
        from reviewer.contracts import require
        doc = {"id": profile_id, "version": version, "roles": roles}
        require("ScoreProfile", doc)
        return doc


def parse_score_config(text: str) -> ScoreConfig:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ScoreConfigError("score config is not valid TOML") from None
    _need(set(doc) <= _TOP and {"schema", "model", "limits", "caps", "sampling", "prompts"} <= set(doc), "unknown or missing top-level key")
    _need(doc["schema"] == SCHEMA, "unsupported score config schema")
    _need(doc["model"] == MODEL, "the score model is exactly anthropic/claude-opus-5.5")
    _need(isinstance(doc["sampling"], dict) and doc["sampling"] == {"policy": "omit"},
          "sampling/effort may only be policy = \"omit\" (no temperature, top_p, top_k or effort)")
    lim = doc["limits"]
    _need(isinstance(lim, dict) and set(lim) == set(MAX_LIMITS) | set(EXACT_LIMITS), "limits keys differ")
    for k, mx in MAX_LIMITS.items():
        _need(_posint(lim[k]) and lim[k] <= mx, "a limit is malformed or wider than the policy maximum")
    for k, v in EXACT_LIMITS.items():
        _need(type(lim[k]) is int and lim[k] == v, "a pinned limit differs")
    caps = doc["caps"]
    _need(isinstance(caps, dict) and set(caps) == set(_STAGES), "caps need exactly extract, dedup and pair")
    out, tmo = {}, {}
    for s in _STAGES:
        c = caps[s]
        _need(isinstance(c, dict) and set(c) == {"max_output_tokens", "timeout_sec"}, "a stage cap has unknown or missing keys")
        _need(_posint(c["max_output_tokens"]) and c["max_output_tokens"] <= MAX_OUTPUT[s], "an output cap is malformed or widened")
        _need(_posint(c["timeout_sec"]) and c["timeout_sec"] <= MAX_TIMEOUT_SEC, "a timeout is malformed or widened")
        out[s], tmo[s] = c["max_output_tokens"], c["timeout_sec"]
    pr = doc["prompts"]
    want = {**{f"{k}_version": v for k, v in P.VERSIONS.items()}, **{f"{k}_sha256": v for k, v in P.prompt_digests().items()}}
    _need(isinstance(pr, dict) and pr == want, "prompt versions or digests differ from the pinned prompts")
    return ScoreConfig(out, tmo, lim["max_candidates_per_tool_case"], lim["max_pairs_per_tool_case"],
                       lim["max_calls_per_score_run"], lim["skip_dedup_below"], lim["min_extract_chars"],
                       P.prompt_digests())


def load_score_config(path) -> ScoreConfig:
    """The explicit file only. No environment variable, argument or discovery changes what is read."""
    p = Path(path)
    _need(p.is_file() and not p.is_symlink(), "score config path is not a regular file")
    try:
        text = p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise ScoreConfigError("score config is not valid UTF-8") from None
    except OSError:
        raise ScoreConfigError("score config could not be read") from None
    return parse_score_config(text)
