"""Live review profile and Plan for the pilot: Sonnet 5.5 through OpenRouter, no hidden model loops.

Retries and repairs are 0 until gateway D3 (schema check before settle) and D4 (deadline before every attempt)
land: with them off, every billable call is one admitted, traced attempt. Output caps are positive and large
enough for real hypotheses, verifications and comments; they are admission bounds, not prompts. Comment cap and
tool limits are NOT set here: the pipeline defaults apply."""

from __future__ import annotations

from reviewer.config import ReviewModels
from reviewer.contracts.budget import STANDARD_S0A_BUDGET
from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS, gateway_price

MODEL = "anthropic/claude-sonnet-5.5"
PROFILE_ID = "pilot-live"
RUN_CEILING_USD_MICROS = 4_000_000
OUTPUT_CAPS = {"investigator": 16_000, "verifier": 6_000, "judge": 8_000}
TIMEOUTS = {"investigator": 300, "verifier": 150, "judge": 200}
MAX_OUTPUT_CAP = 100_000
WALL_CLOCK_SEC, SOFT_DEADLINE_SEC = 1_200, 900     # live latency: the synthetic 360/240 would cut real runs short
_OUT = {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput", "judge": "JudgeOutput"}
_PV = {"investigator": "investigator.generalist@v1", "verifier": "verifier.refute@v1", "judge": "judge.wording@v1"}


class ProfileError(ValueError):
    pass


def live_profile(model: str | None = None, output_caps: dict | None = None, timeouts: dict | None = None, *,
                 models: ReviewModels | None = None) -> dict:
    """`models` is the per-role selection (from pullo.toml). The legacy single `model` means all three roles and
    may not be combined with `models`. Neither given: the default (Sonnet 5.5 everywhere)."""
    if models is not None and model is not None:
        raise ProfileError("pass either model or models, not both")
    if models is None:
        model = MODEL if model is None else model
        if model not in ALLOWED_ROUTER_MODELS:
            raise ProfileError("model is not in the exact OpenRouter allowlist")
        models = ReviewModels.uniform(model)
    caps = {**OUTPUT_CAPS, **(output_caps or {})}
    tmo = {**TIMEOUTS, **(timeouts or {})}
    for role in _OUT:
        c = caps[role]
        if type(c) is not int or not 1 <= c <= MAX_OUTPUT_CAP:
            raise ProfileError(f"{role} output cap must be an integer in 1..{MAX_OUTPUT_CAP}")

    def role(r):
        m = models.model(r)
        return {"provider": "anthropic", "model": m, "family": "claude", "resolved": True,
                "promptVersion": _PV[r], "outputSchema": _OUT[r], "params": {"maxOutputTokens": caps[r]},
                "caps": {"maxOutputTokens": caps[r], "timeoutSec": tmo[r], "maxRetries": 0, "maxRepairs": 0},
                "price": gateway_price(m), "fallbacks": []}
    return {"id": PROFILE_ID, "version": 1, "tier": "standard", "triage": "fixed-rule@1",
            "roles": {r: role(r) for r in _OUT}}


def live_plan(profile: dict, *, wall_clock_sec: int = WALL_CLOCK_SEC, soft_deadline_sec: int = SOFT_DEADLINE_SEC) -> dict:
    budget = dict(STANDARD_S0A_BUDGET, maxUsdMicros=RUN_CEILING_USD_MICROS, maxRetriesPerCall=0,
                  wallClockSec=wall_clock_sec, softDeadlineSec=soft_deadline_sec)
    return {"version": 1, "tier": "standard", "specialists": ["generalist"], "budget": budget,
            "modelProfile": f"{profile['id']}@{profile['version']}", "triage": "fixed-rule@1",
            "reasons": ["pilot: fixed standard Plan, retries/repairs off pending gateway D3/D4"]}
