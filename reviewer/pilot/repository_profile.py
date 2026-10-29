"""Profile, Plan and retrieval policy of the repository-backed pilot (S1-10). Sonnet 5.5 only, no fallback.

Built from the reviewed `live_profile`/`live_plan` so caps, timeouts, retries (0), repairs (0), the $4 run ceiling and
the deadlines are never re-declared. `retrieval=True` switches the investigator and verifier to the Turn schemas and
their retrieval prompts; the judge stays the plain review-cost JudgeOutput. There is no host option to widen anything.

`impact=True` (the default with retrieval) selects impact mode: the PREPARE impact map and the find_references tool,
with the same numeric caps. `impact_version` picks the investigator: 3 (the default) is investigator.impact@v3, three
specialist investigators (contracts, logic, safety) run in turn, each a v2 investigator with its own lens paragraph,
sharing the v2 investigator budgets (reviewer.pipeline.specialists); its Plan lists those specialists. 2 is exactly the
EXPLORE-FLOOR profile, Plan and policy (investigator.impact@v2 with the engine-enforced exploration floor: one
guaranteed extra prompt, not guaranteed tool use), 1 is exactly the IMPACT-01 profile and policy (investigator.impact@v1,
same digests). The verifier is verifier.impact@v1 in all three. `impact=False` is exactly the earlier retrieval@2 profile and
policy (same digests). The older selections are kept for reproducing and replaying earlier runs."""

from __future__ import annotations

from reviewer.pipeline import RetrievalPolicy
from reviewer.pipeline.prompts import (EXPERIMENT_BASELINE, EXPERIMENT_CONTEXT_CHECK, EXPERIMENTS,
                                       INVESTIGATOR_IMPACT_PROMPT, INVESTIGATOR_IMPACT_V2_PROMPT,
                                       INVESTIGATOR_IMPACT_V3_PROMPT, SPECIALIST_AGENTS,
                                       JUDGE_FACT_WORDING_PROMPT,
                                       VERIFIER_CONTEXT_CHECK_PROMPT, VERIFIER_IMPACT_PROMPT)
from reviewer.pipeline.retrieval import INVESTIGATOR_PROMPT, VERIFIER_PROMPT

from .profile import LIVE_STAGE_CEILINGS_SEC, MODEL, ProfileError, live_plan, live_profile

PROFILE_ID = "pilot-repository"
MAX_TOOL_CALLS = 160            # run-wide tool calls (matches RetrievalPolicy.run_tool_calls)
MAX_TOOL_CALLS_PER_AGENT = 60   # per (stage, agent) ToolSession (matches RetrievalPolicy.agent_tool_calls)


def check_experiment(experiment: str, retrieval: bool) -> None:
    """The opt-in prompt experiment must be a known id and needs the retrieval (Turn) verifier. Raises ProfileError."""
    if experiment not in EXPERIMENTS:
        raise ProfileError(f"unknown experiment {experiment!r}; known: {', '.join(EXPERIMENTS)}")
    if experiment != EXPERIMENT_BASELINE and not retrieval:
        raise ProfileError(f"experiment {experiment} needs the retrieval profile (the Turn verifier)")


IMPACT_VERSIONS = {1: INVESTIGATOR_IMPACT_PROMPT, 2: INVESTIGATOR_IMPACT_V2_PROMPT, 3: INVESTIGATOR_IMPACT_V3_PROMPT}
DEFAULT_IMPACT_VERSION = 3


def _prompts(impact: bool, impact_version: int = DEFAULT_IMPACT_VERSION) -> tuple[str, str]:
    if impact_version not in IMPACT_VERSIONS or isinstance(impact_version, bool):
        raise ProfileError(f"unknown impact_version {impact_version!r}; known: {sorted(IMPACT_VERSIONS)}")
    return ((IMPACT_VERSIONS[impact_version], VERIFIER_IMPACT_PROMPT) if impact
            else (INVESTIGATOR_PROMPT, VERIFIER_PROMPT))


def repository_profile(retrieval: bool = True, models=None, experiment: str = EXPERIMENT_BASELINE,
                       impact: bool = True, impact_version: int = DEFAULT_IMPACT_VERSION) -> dict:
    """`experiment` (default baseline) opts into context-check@1: only the verifier and judge prompt ids change, to the
    experiment's; models, schemas, caps, tools, timeouts and retries are the baseline's. `impact` (default on) only
    matters with retrieval: it selects the impact investigator/verifier prompt ids (`impact_version` 3, 2 or 1)."""
    check_experiment(experiment, retrieval)
    profile = live_profile(None if models is not None else MODEL, models=models)
    profile["id"] = PROFILE_ID
    if retrieval:
        inv, ver = _prompts(impact, impact_version)
        profile["roles"]["investigator"].update(outputSchema="InvestigatorTurn", promptVersion=inv)
        profile["roles"]["verifier"].update(outputSchema="VerifierTurn", promptVersion=ver)
    if experiment == EXPERIMENT_CONTEXT_CHECK:
        profile["roles"]["verifier"]["promptVersion"] = VERIFIER_CONTEXT_CHECK_PROMPT
        profile["roles"]["judge"]["promptVersion"] = JUDGE_FACT_WORDING_PROMPT
    return profile


def repository_plan(profile: dict, *, live_stage_timing: bool = False) -> dict:
    """`live_stage_timing` (explicit, default off = the legacy Plan) sets the versioned live stage ceilings and
    host-stop recording together; no repository data selects either. An investigator.impact@v3 profile gets the
    specialist investigators as Plan.specialists (every other profile keeps the one generalist, same Plan bytes)."""
    plan = live_plan(profile, **({"stage_ceilings_sec": LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True}
                                 if live_stage_timing else {}))
    plan["budget"] = dict(plan["budget"], maxToolCalls=MAX_TOOL_CALLS, maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
    plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports"]
    if profile["roles"]["investigator"]["promptVersion"] == INVESTIGATOR_IMPACT_V3_PROMPT:
        plan["specialists"] = list(SPECIALIST_AGENTS)
    return plan


def repository_policy(retrieval: bool, experiment: str = EXPERIMENT_BASELINE,
                      impact: bool = True, impact_version: int = DEFAULT_IMPACT_VERSION) -> RetrievalPolicy | None:
    check_experiment(experiment, retrieval)
    if not retrieval:
        return None
    inv, ver = _prompts(impact, impact_version)
    if experiment == EXPERIMENT_CONTEXT_CHECK:       # the same numeric limits; only the verifier prompt id differs
        ver = VERIFIER_CONTEXT_CHECK_PROMPT
    if (inv, ver) == (INVESTIGATOR_PROMPT, VERIFIER_PROMPT):
        return RetrievalPolicy()
    if inv == INVESTIGATOR_PROMPT:
        return RetrievalPolicy(verifier_prompt=ver)
    return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver)
