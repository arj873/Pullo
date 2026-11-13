"""Live review profile and Plan for the pilot: Sonnet 5.5 through OpenRouter, no hidden model loops.

Retries are 0, and so are repairs, except on claude-cli roles (CLAUDE-CLI-REPAIR1): with gateway D3 (schema check
before settle) and D4 (host guard before every attempt) in place, a claude-cli role gets maxRepairs 1 - Pullo's OWN
gateway repair (repair_with_issues: a new, separately admitted, traced and counted CLI call that shows the local schema
issues), never a CLI-side repair. Every other provider keeps 0, so its profile and Plan bytes are unchanged. Output caps
are positive and large enough for real hypotheses, verifications and comments; they are admission bounds, not prompts.
Comment cap and tool limits are NOT set here: the pipeline defaults apply."""

from __future__ import annotations

from reviewer.config import ReviewModels
from reviewer.contracts import validate
from reviewer.contracts.budget import HOST_STOP_RECORDING, STANDARD_S0A_BUDGET
from reviewer.runtime.catalog import (ALLOWED_ROUTER_MODELS, CLAUDE_CLI_MODELS, OPENCODE_MODELS, TERRA_MODELS,
                                      claude_cli_gateway_price, gateway_price, opencode_gateway_price, terra_gateway_price)

MODEL = "anthropic/claude-sonnet-5.5"
PROFILE_ID = "pilot-live"
RUN_CEILING_USD_MICROS = 4_000_000
OUTPUT_CAPS = {"investigator": 16_000, "verifier": 6_000, "judge": 8_000}
TIMEOUTS = {"investigator": 300, "verifier": 150, "judge": 200}
MAX_OUTPUT_CAP = 100_000
WALL_CLOCK_SEC, SOFT_DEADLINE_SEC = 3_000, 2_400   # live latency: the synthetic 360/240 would cut real runs short
# Explicit live stage ceilings (seconds) for repository live reviews: headroom over the role-call caps (investigator
# 300, verifier 150, judge 200) for multi-hop retrieval. Not derived from findings or gold; other stages stay legacy.
# DEADLINE time successor (2026-11-02, as v6cd): 300/300/200 and 1200/900 were sized on Haiku; a Sonnet 5.5 investigator
# takes about twice the turns (orso3 cal22532: 11 vs 6, cut at the 100 s first time slice), so INVESTIGATE x3 (time
# slices 300/600/900 s), VERIFY x2, JUDGE x2 and the run deadlines to fit. Per-call timeouts and every money/count cap unchanged.
LIVE_STAGE_CEILINGS_SEC = {"INVESTIGATE": 900, "VERIFY": 600, "JUDGE": 400}
_OUT = {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput", "judge": "JudgeOutput"}
_PV = {"investigator": "investigator.generalist@v1", "verifier": "verifier.refute@v1", "judge": "judge.wording@v1"}
CLAUDE_CLI_REPAIRS = 1                  # CLAUDE-CLI-REPAIR1: gateway repairs per claude-cli call (every other provider: 0)
REPAIR_REASON = ("claude-cli roles: one gateway repair per call (repair_with_issues: a separately admitted, traced CLI "
                 "call showing the local schema issues)")


class ProfileError(ValueError):
    pass


def model_fields(provider: str, m: str) -> dict:
    """The model-specific part of a RoleSpec (what an impact@v7 alternate investigator replaces; key order as before).
    An opencode free model carries its catalog family and the PACING price (catalog.OPENCODE_PACING_PRICE; $0 actual)."""
    if m in OPENCODE_MODELS:
        return {"provider": provider, "model": m, "family": OPENCODE_MODELS[m]["family"],
                "price": opencode_gateway_price(m)}
    if m in CLAUDE_CLI_MODELS:                    # CLAUDE-CLI-PROVIDER: the Terra-6 PACING price ($0 actual)
        return {"provider": provider, "model": m, "family": CLAUDE_CLI_MODELS[m]["family"],
                "price": claude_cli_gateway_price(m)}
    return {"provider": provider, "model": m, "family": "gpt" if m in TERRA_MODELS else "claude",
            "price": terra_gateway_price(m) if m in TERRA_MODELS else gateway_price(m)}


def live_profile(model: str | None = None, output_caps: dict | None = None, timeouts: dict | None = None, *,
                 models: ReviewModels | None = None) -> dict:
    """`models` is the per-role selection (from pullo.toml). The legacy single `model` means all three roles and
    may not be combined with `models`. Neither given: the default (Sonnet 5.5 everywhere)."""
    if models is not None and model is not None:
        raise ProfileError("pass either model or models, not both")
    if models is None:
        model = MODEL if model is None else model
        if (model not in ALLOWED_ROUTER_MODELS and model not in TERRA_MODELS and model not in OPENCODE_MODELS
                and model not in CLAUDE_CLI_MODELS):
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
        return {**model_fields(models.provider(r), m), "resolved": True,
                "promptVersion": _PV[r], "outputSchema": _OUT[r], "params": {"maxOutputTokens": caps[r]},
                "caps": {"maxOutputTokens": caps[r], "timeoutSec": tmo[r], "maxRetries": 0,
                         "maxRepairs": CLAUDE_CLI_REPAIRS if models.provider(r) == "claude-cli" else 0},
                "fallbacks": []}
    return {"id": PROFILE_ID, "version": 1, "tier": "standard", "triage": "fixed-rule@1",
            "roles": {r: role(r) for r in _OUT}}


def live_plan(profile: dict, *, wall_clock_sec: int = WALL_CLOCK_SEC, soft_deadline_sec: int = SOFT_DEADLINE_SEC,
              stage_ceilings_sec: dict | None = None, host_stop_recording: bool = False) -> dict:
    """Absent `stage_ceilings_sec`/`host_stop_recording` (the default) leaves the Plan byte-identical to before: the
    legacy stage table applies and Engine.gate stops are not recorded. Both are trusted host options only."""
    budget = dict(STANDARD_S0A_BUDGET, maxUsdMicros=RUN_CEILING_USD_MICROS, maxRetriesPerCall=0,
                  wallClockSec=wall_clock_sec, softDeadlineSec=soft_deadline_sec)
    if stage_ceilings_sec is not None:
        budget["stageCeilingsSec"] = dict(stage_ceilings_sec)
    if host_stop_recording:
        budget["hostStopRecording"] = HOST_STOP_RECORDING
    if stage_ceilings_sec is not None or host_stop_recording:
        issues = validate("Budget", budget)
        if issues:
            raise ProfileError(f"invalid stage timing: {issues[0]}")
    return with_repair_reason({"version": 1, "tier": "standard", "specialists": ["generalist"], "budget": budget,
                               "modelProfile": f"{profile['id']}@{profile['version']}", "triage": "fixed-rule@1",
                               "reasons": ["pilot: fixed standard Plan, retries/repairs off pending gateway D3/D4"]},
                              profile)


def profile_repairs(profile: dict) -> int:
    """The most gateway repairs any role of `profile` may use per call (gateway.effective_retry_limits: at most 1)."""
    return max(min(1, s["caps"]["maxRepairs"]) for s in profile["roles"].values())


def with_repair_reason(plan: dict, profile: dict) -> dict:
    """A Plan whose profile repairs (claude-cli roles) says so: its "retries/repairs off" reasons read "retries off" and
    REPAIR_REASON is added once. Any other Plan is returned unchanged (same bytes)."""
    if profile_repairs(profile) and REPAIR_REASON not in plan["reasons"]:
        plan["reasons"] = [r.replace("retries/repairs off pending gateway D3/D4", "retries off")
                           .replace("retries/repairs off", "retries off") for r in plan["reasons"]] + [REPAIR_REASON]
    return plan
