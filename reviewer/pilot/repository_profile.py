"""Profile, Plan and retrieval policy of the repository-backed pilot (S1-10). Sonnet 5.5 only, no fallback.

Built from the reviewed `live_profile`/`live_plan` so caps, timeouts, retries (0), repairs (0), the $4 run ceiling and
the deadlines are never re-declared. `retrieval=True` switches the investigator and verifier to the Turn schemas and
their retrieval prompts; the judge stays the plain review-cost JudgeOutput. There is no host option to widen anything."""

from __future__ import annotations

from reviewer.pipeline import RetrievalPolicy
from reviewer.pipeline.prompts import (EXPERIMENT_BASELINE, EXPERIMENT_CONTEXT_CHECK, EXPERIMENTS,
                                       JUDGE_FACT_WORDING_PROMPT, VERIFIER_CONTEXT_CHECK_PROMPT)
from reviewer.pipeline.retrieval import INVESTIGATOR_PROMPT, VERIFIER_PROMPT

from .profile import MODEL, ProfileError, live_plan, live_profile

PROFILE_ID = "pilot-repository"
MAX_TOOL_CALLS = 160            # run-wide tool calls (matches RetrievalPolicy.run_tool_calls)
MAX_TOOL_CALLS_PER_AGENT = 60   # per (stage, agent) ToolSession (matches RetrievalPolicy.agent_tool_calls)


def check_experiment(experiment: str, retrieval: bool) -> None:
    """The opt-in prompt experiment must be a known id and needs the retrieval (Turn) verifier. Raises ProfileError."""
    if experiment not in EXPERIMENTS:
        raise ProfileError(f"unknown experiment {experiment!r}; known: {', '.join(EXPERIMENTS)}")
    if experiment != EXPERIMENT_BASELINE and not retrieval:
        raise ProfileError(f"experiment {experiment} needs the retrieval profile (the Turn verifier)")


def repository_profile(retrieval: bool = True, models=None, experiment: str = EXPERIMENT_BASELINE) -> dict:
    """`experiment` (default baseline) opts into context-check@1: only the verifier and judge prompt ids change, to the
    experiment's; models, schemas, caps, tools, timeouts and retries are the baseline's."""
    check_experiment(experiment, retrieval)
    profile = live_profile(None if models is not None else MODEL, models=models)
    profile["id"] = PROFILE_ID
    if retrieval:
        profile["roles"]["investigator"].update(outputSchema="InvestigatorTurn", promptVersion=INVESTIGATOR_PROMPT)
        profile["roles"]["verifier"].update(outputSchema="VerifierTurn", promptVersion=VERIFIER_PROMPT)
    if experiment == EXPERIMENT_CONTEXT_CHECK:
        profile["roles"]["verifier"]["promptVersion"] = VERIFIER_CONTEXT_CHECK_PROMPT
        profile["roles"]["judge"]["promptVersion"] = JUDGE_FACT_WORDING_PROMPT
    return profile


def repository_plan(profile: dict) -> dict:
    plan = live_plan(profile)
    plan["budget"] = dict(plan["budget"], maxToolCalls=MAX_TOOL_CALLS, maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
    plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports"]
    return plan


def repository_policy(retrieval: bool, experiment: str = EXPERIMENT_BASELINE) -> RetrievalPolicy | None:
    check_experiment(experiment, retrieval)
    if not retrieval:
        return None
    if experiment == EXPERIMENT_CONTEXT_CHECK:       # the same numeric limits; only the verifier prompt id differs
        return RetrievalPolicy(verifier_prompt=VERIFIER_CONTEXT_CHECK_PROMPT)
    return RetrievalPolicy()
