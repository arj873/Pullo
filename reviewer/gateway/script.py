"""Synthetic provider script loader (frozen interface: orchestration/SCRIPTED-PROVIDER.md).

{"schemaVersion": 1, "entries": [{"stage", "role", "agentId", "ordinal", "attempt",
  exactly one of "response": ModelResponse | "error": TypedError}]}
Lookup key (stage, role, agentId, ordinal, attempt). Duplicate keys, duplicate JSON keys and
unknown fields are rejected. A missing entry is a typed failure, never a live fallback.
"""

from __future__ import annotations

import copy
import os
import re
from pathlib import Path

from reviewer.contracts import ContractInputError, ContractViolation, loads_strict, require
from reviewer.contracts.scoring_family import SCORE_MODELS, SCORE_ROLE_STAGE, SCORE_ROLES, SCORE_STAGES
from reviewer.contracts.stages import STAGES

from .errors import ScriptError

MAX_SCRIPT_BYTES = 16 << 20
MAX_ENTRIES = 5000
ROLES = ("investigator", "verifier", "judge")
SLUG = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
Key = tuple  # (stage, role, agentId, ordinal, attempt)


class Script:
    def __init__(self, entries: dict[Key, tuple[str, dict]], family: str = "review"):
        self._entries = entries
        self.family = family

    def __len__(self):
        return len(self._entries)

    def keys(self) -> list[Key]:
        return sorted(self._entries)

    def lookup(self, key: Key):
        """('response'|'error', document copy) or None."""
        hit = self._entries.get(tuple(key))
        return None if hit is None else (hit[0], copy.deepcopy(hit[1]))


def parse_script(text: str | bytes, *, family: str = "review") -> Script:
    """family="score" accepts only the score stages/roles with their 1:1 pairing and errors without a review stage."""
    if family not in ("review", "score"):
        raise ScriptError("family must be review or score")
    stages, roles = (SCORE_STAGES, SCORE_ROLES) if family == "score" else (STAGES, ROLES)
    try:
        doc = loads_strict(text)
    except ContractInputError as e:
        raise ScriptError(f"script is not strict JSON: {e}") from e
    if not isinstance(doc, dict) or set(doc) != {"schemaVersion", "entries"} or doc["schemaVersion"] != 1 \
            or type(doc["schemaVersion"]) is not int:
        raise ScriptError("script must be exactly {schemaVersion: 1, entries: [...]}")
    entries = doc["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ScriptError(f"entries must be a list of at most {MAX_ENTRIES}")
    out: dict[Key, tuple[str, dict]] = {}
    for i, e in enumerate(entries):
        w = f"entries[{i}]"
        if not isinstance(e, dict):
            raise ScriptError(f"{w}: not an object")
        base = {"stage", "role", "agentId", "ordinal", "attempt"}
        extra = set(e) - base - {"response", "error"}
        if extra:
            raise ScriptError(f"{w}: unknown fields {sorted(map(str, extra))}")
        if not base <= set(e):
            raise ScriptError(f"{w}: missing {sorted(base - set(e))}")
        if ("response" in e) == ("error" in e):
            raise ScriptError(f"{w}: exactly one of response or error")
        if e["stage"] not in stages or e["role"] not in roles:
            raise ScriptError(f"{w}: bad stage or role")
        if family == "score" and SCORE_ROLE_STAGE[e["role"]] != e["stage"]:
            raise ScriptError(f"{w}: a score role runs only in its own score stage")
        if not isinstance(e["agentId"], str) or not SLUG.fullmatch(e["agentId"]):
            raise ScriptError(f"{w}: bad agentId")
        for k, hi in (("ordinal", 10**6), ("attempt", 10)):
            if type(e[k]) is not int or not 0 <= e[k] <= hi:
                raise ScriptError(f"{w}: {k} must be an integer in 0..{hi}")
        kind = "response" if "response" in e else "error"
        try:
            require("ModelResponse" if kind == "response" else "TypedError", e[kind])
        except ContractViolation as ex:
            raise ScriptError(f"{w}.{kind}: {ex}") from ex
        if family == "score" and kind == "error" and "stage" in e[kind]:
            raise ScriptError(f"{w}.error: score errors omit stage")
        key = (e["stage"], e["role"], e["agentId"], e["ordinal"], e["attempt"])
        if key in out:
            raise ScriptError(f"{w}: duplicate key {key}")
        out[key] = (kind, e[kind])
    return Script(out, family)


def load_script(path, *, family: str = "review") -> Script:
    p = Path(path)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise ScriptError(f"cannot open script {p}: {e.strerror}") from e
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_SCRIPT_BYTES + 1)
    if len(data) > MAX_SCRIPT_BYTES:
        raise ScriptError("script too large")
    return parse_script(data, family=family)


class ScriptedScoreProvider:
    """Offline stand-in for the score model adapter (registered under "anthropic" in tests): serves a score
    script, counts calls, never touches the network. A missing entry is a not-sent typed failure."""
    name = "scripted-score"

    def __init__(self, script: Script):
        if script.family != "score":
            raise ScriptError("a scripted score provider needs a score script")
        self.script = script
        self.calls = 0
        self.missing: list[tuple] = []

    def call(self, request: dict, key: tuple):
        from .errors import typed_error
        from .providers import RELEASABLE_OUTCOMES, ProviderResult
        self.calls += 1
        if request.get("provider") != "anthropic" or request.get("model") not in SCORE_MODELS:
            raise ValueError("scripted score provider only serves the score model")
        hit = self.script.lookup(key)
        if hit is None:
            self.missing.append(key)
            return ProviderResult(None, typed_error(
                "provider-error", "no scripted response for this call key (never a live fallback)"), "not-sent")
        kind, doc = hit
        if kind == "response":
            return ProviderResult(doc, None, "processed")
        stated = (doc.get("detail") or {}).get("outcome") if isinstance(doc.get("detail"), dict) else None
        outcome = stated if (doc["code"] == "provider-error" and stated in RELEASABLE_OUTCOMES) else "unknown"
        return ProviderResult(None, doc, outcome)
