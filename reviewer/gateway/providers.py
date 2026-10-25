"""Provider adapters. Only the synthetic one answers; live adapters are explicit disabled stubs.

No adapter here reads an API key, opens a socket or imports an SDK."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from reviewer.contracts.budget import RELEASABLE_OUTCOMES

from .errors import typed_error
from .script import Script

OUTCOMES = ("processed", "not-sent", "rejected-before-processing", "unknown")


@dataclass(frozen=True)
class ProviderResult:
    response: dict | None
    error: dict | None
    outcome: str        # processed | not-sent | rejected-before-processing | unknown

    def __post_init__(self):
        if (self.response is None) == (self.error is None) or self.outcome not in OUTCOMES:
            raise ValueError("a provider result is exactly one of response/error with a known outcome")


class SyntheticProvider:
    """Serves scripted responses; counts calls; never touches the network."""
    name = "synthetic"

    def __init__(self, script: Script):
        self.script = script
        self._lock = threading.Lock()
        self.calls = 0
        self.missing: list[tuple] = []

    def call(self, request: dict, key: tuple) -> ProviderResult:
        with self._lock:
            self.calls += 1
        if request.get("provider") != "synthetic":
            raise ValueError("synthetic provider only serves provider=synthetic")
        hit = self.script.lookup(key)
        if hit is None:
            with self._lock:
                self.missing.append(key)
            return ProviderResult(None, typed_error(
                "provider-error", "no scripted response for this call key (never a live fallback)",
                detail={"key": list(key)}), "not-sent")
        kind, doc = hit
        if kind == "response":
            return ProviderResult(doc, None, "processed")
        stated = (doc.get("detail") or {}).get("outcome") if isinstance(doc.get("detail"), dict) else None
        outcome = stated if (doc["code"] == "provider-error" and stated in RELEASABLE_OUTCOMES) else "unknown"
        return ProviderResult(None, doc, outcome)


class DisabledProvider:
    """Live adapter placeholder: always refuses before any I/O."""

    def __init__(self, name: str):
        self.name = name
        self.calls = 0

    def call(self, request: dict, key: tuple) -> ProviderResult:
        return ProviderResult(None, typed_error(
            "live-calls-disabled", f"live provider {self.name} is disabled in Stage 0A"), "not-sent")


def default_providers(script: Script | None = None) -> dict:
    p = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai")}
    if script is not None:
        p["synthetic"] = SyntheticProvider(script)
    return p
