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
from reviewer.contracts.stages import STAGES

from .errors import ScriptError

MAX_SCRIPT_BYTES = 16 << 20
MAX_ENTRIES = 5000
ROLES = ("investigator", "verifier", "judge")
SLUG = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
Key = tuple  # (stage, role, agentId, ordinal, attempt)


class Script:
    def __init__(self, entries: dict[Key, tuple[str, dict]]):
        self._entries = entries

    def __len__(self):
        return len(self._entries)

    def keys(self) -> list[Key]:
        return sorted(self._entries)

    def lookup(self, key: Key):
        """('response'|'error', document copy) or None."""
        hit = self._entries.get(tuple(key))
        return None if hit is None else (hit[0], copy.deepcopy(hit[1]))


def parse_script(text: str | bytes) -> Script:
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
        if e["stage"] not in STAGES or e["role"] not in ROLES:
            raise ScriptError(f"{w}: bad stage or role")
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
        key = (e["stage"], e["role"], e["agentId"], e["ordinal"], e["attempt"])
        if key in out:
            raise ScriptError(f"{w}: duplicate key {key}")
        out[key] = (kind, e[kind])
    return Script(out)


def load_script(path) -> Script:
    p = Path(path)
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise ScriptError(f"cannot open script {p}: {e.strerror}") from e
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_SCRIPT_BYTES + 1)
    if len(data) > MAX_SCRIPT_BYTES:
        raise ScriptError("script too large")
    return parse_script(data)
