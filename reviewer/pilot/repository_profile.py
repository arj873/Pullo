"""Profile, Plan and retrieval policy of the repository-backed pilot (S1-10). Sonnet 5.5 only, no fallback.

Built from the reviewed `live_profile`/`live_plan` so caps, timeouts, retries (0), repairs (0), the $4 run ceiling and
the deadlines are never re-declared. `retrieval=True` switches the investigator and verifier to the Turn schemas and
their retrieval prompts; the judge stays the plain review-cost JudgeOutput. There is no host option to widen anything."""

from __future__ import annotations

from reviewer.pipeline import RetrievalPolicy
from reviewer.pipeline.retrieval import INVESTIGATOR_PROMPT, VERIFIER_PROMPT

from .profile import MODEL, live_plan, live_profile

PROFILE_ID = "pilot-repository"
MAX_TOOL_CALLS = 160            # run-wide tool calls (matches RetrievalPolicy.run_tool_calls)
MAX_TOOL_CALLS_PER_AGENT = 60   # per (stage, agent) ToolSession (matches RetrievalPolicy.agent_tool_calls)


def repository_profile(retrieval: bool = True) -> dict:
    profile = live_profile(MODEL)
    profile["id"] = PROFILE_ID
    if retrieval:
        profile["roles"]["investigator"].update(outputSchema="InvestigatorTurn", promptVersion=INVESTIGATOR_PROMPT)
        profile["roles"]["verifier"].update(outputSchema="VerifierTurn", promptVersion=VERIFIER_PROMPT)
    return profile


def repository_plan(profile: dict) -> dict:
    plan = live_plan(profile)
    plan["budget"] = dict(plan["budget"], maxToolCalls=MAX_TOOL_CALLS, maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
    plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports"]
    return plan


def repository_policy(retrieval: bool) -> RetrievalPolicy | None:
    return RetrievalPolicy() if retrieval else None
