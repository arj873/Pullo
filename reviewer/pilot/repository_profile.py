"""Profile, Plan and retrieval policy of the repository-backed pilot (S1-10). Sonnet 5.5 only, no fallback.

Built from the reviewed `live_profile`/`live_plan` so caps, timeouts, retries (0), repairs (0), the $4 run ceiling and
the deadlines are never re-declared. `retrieval=True` switches the investigator and verifier to the Turn schemas and
their retrieval prompts; the judge stays the plain review-cost JudgeOutput. There is no host option to widen anything.

`impact=True` (the default with retrieval) selects impact mode: the PREPARE impact map and the find_references tool,
with the same numeric caps. `impact_version` picks the investigator: 2 (the default) is exactly the EXPLORE-FLOOR
profile, Plan and policy (investigator.impact@v2 with the engine-enforced exploration floor: one guaranteed extra prompt,
not guaranteed tool use). 3 (explicit only, until measured) is investigator.impact@v3: three specialist investigators
(contracts, logic, safety) run in turn, each a v2 investigator with its own lens paragraph, sharing the v2 investigator
budgets (reviewer.pipeline.specialists); its Plan lists those specialists. 4 (explicit only, until measured) is
investigator.impact@v4: the v3 specialists unchanged plus deterministic diff-shard sweep investigators
(reviewer.pipeline.sweeps); its Plan lists the specialists and the sweep marker and scales the budgets for the extra
agents (V4_* below; the $4 run ceiling and the spend split are unchanged). 5 (explicit only) is investigator.impact@v5:
the v3 specialists unchanged plus the `consistency` and `hygiene` lanes and a near-duplicate cap
(reviewer.pipeline.lanes); its Plan lists the five lanes (V5_* below). 7 (explicit only) is investigator.impact@v7: the
v5 lanes unchanged plus the logic, consistency and hygiene lenses again on the ALTERNATE investigator model
(`[review.investigator_alt]`, bound as ModelProfile.alternates.investigator; without one, or with the investigator's own
model, the profile is refused: v7 never silently equals v5); its Plan lists the eight lanes and names the alternate
model in its reasons (V7_* below). 10 (explicit only) is investigator.impact@v10: the v3 configuration unchanged (the
three specialists with v3's lens texts and per-lane tool/spend/time numbers, v3 VERIFY and verifier) plus the same three
lenses again as `contracts.alt`, `logic.alt`, `safety.alt` on the ALTERNATE investigator model (refused without one,
exactly as v7), merged restatement-only; its Plan lists the six lanes and names the alternate model in its reasons
(V10_* below). 12 (explicit only) is investigator.impact@v12: coverage-forced deep investigation on the primary
investigator model only (no alternate): the three v3 lenses with a depth paragraph, then one coverage investigator per
unit of a deterministic changed-file partition, a host-enforced depth floor, per-candidate verifier sessions and a
dynamic comment cap (reviewer.pipeline.deepcov); its Plan lists the lenses and the coverage-unit marker (V12_* below).
16 (explicit only) is investigator.impact@v16: ONE whole-change reviewer (reviewer.pipeline.whole) on the primary
investigator model, v12's VERIFY and JUDGE rules, v12's clocks and tool cap, the $4 ceiling; its Plan lists `whole`.
19 (explicit only) is investigator.impact@v19: v16 with its reviewer as ONE agentic read-only claude-cli session (the
investigator role carries params.agentic = agentic.spec(); a claude-cli investigator is required) and the JUDGE
concrete-behaviour rule (reviewer.pipeline.agentic); v16's clocks and tool cap; its Plan carries V19_RUN_CEILING_USD_MICROS
($10, CC_AUTH_V2) and lists `whole`, `agentic`.
20 (explicit only) is investigator.impact@v20: v19 with the reviewer's task replaced by v16's broad task plus "use the read
tools to confirm each claim against the code before reporting it" (agentic.BROAD_RULE); everything else, the Plan included
(the $10 ceiling, `whole`, `agentic`), is v19's, except its Plan reason names v20.
1 is exactly the IMPACT-01 profile and policy
(investigator.impact@v1, same digests). The verifier is verifier.impact@v1 in all four. `impact=False` is exactly the earlier retrieval@2 profile and
policy (same digests). The older selections are kept for reproducing and replaying earlier runs."""

from __future__ import annotations

from reviewer.pipeline import RetrievalPolicy
import copy

from reviewer.pipeline import agentic, deepcov, lanes, whole
from reviewer.pipeline.prompts import (EXPERIMENT_BASELINE, EXPERIMENT_CONTEXT_CHECK, EXPERIMENTS,
                                       INVESTIGATOR_IMPACT_PROMPT, INVESTIGATOR_IMPACT_V2_PROMPT,
                                       INVESTIGATOR_IMPACT_V3_PROMPT, INVESTIGATOR_IMPACT_V4_PROMPT,
                                       INVESTIGATOR_IMPACT_V5_PROMPT, INVESTIGATOR_IMPACT_V7_PROMPT,
                                       INVESTIGATOR_IMPACT_V10_PROMPT, INVESTIGATOR_IMPACT_V12_PROMPT,
                                       INVESTIGATOR_IMPACT_V16_PROMPT, INVESTIGATOR_IMPACT_V19_PROMPT, SPECIALIST_AGENTS,
                                       INVESTIGATOR_IMPACT_V20_PROMPT, AGENTIC_PROMPTS,
                                       V5_AGENTS, V7_AGENTS,
                                       V7_ALT_AGENTS, V10_AGENTS, V10_ALT_AGENTS,
                                       JUDGE_FACT_WORDING_PROMPT,
                                       VERIFIER_CONTEXT_CHECK_PROMPT, VERIFIER_IMPACT_PROMPT)
from reviewer.pipeline.retrieval import INVESTIGATOR_PROMPT, VERIFIER_PROMPT
from reviewer.pipeline.sweeps import plan_specialists as v4_plan_specialists

from .profile import (LIVE_STAGE_CEILINGS_SEC, MODEL, ProfileError, live_plan, live_profile, model_fields,
                      with_repair_reason)

PROFILE_ID = "pilot-repository"
MAX_TOOL_CALLS = 160            # run-wide tool calls (matches RetrievalPolicy.run_tool_calls)
MAX_TOOL_CALLS_PER_AGENT = 60   # per (stage, agent) ToolSession (matches RetrievalPolicy.agent_tool_calls)


def check_experiment(experiment: str, retrieval: bool) -> None:
    """The opt-in prompt experiment must be a known id and needs the retrieval (Turn) verifier. Raises ProfileError."""
    if experiment not in EXPERIMENTS:
        raise ProfileError(f"unknown experiment {experiment!r}; known: {', '.join(EXPERIMENTS)}")
    if experiment != EXPERIMENT_BASELINE and not retrieval:
        raise ProfileError(f"experiment {experiment} needs the retrieval profile (the Turn verifier)")


IMPACT_VERSIONS = {1: INVESTIGATOR_IMPACT_PROMPT, 2: INVESTIGATOR_IMPACT_V2_PROMPT, 3: INVESTIGATOR_IMPACT_V3_PROMPT,
                   4: INVESTIGATOR_IMPACT_V4_PROMPT, 5: INVESTIGATOR_IMPACT_V5_PROMPT, 7: INVESTIGATOR_IMPACT_V7_PROMPT,
                   10: INVESTIGATOR_IMPACT_V10_PROMPT, 12: INVESTIGATOR_IMPACT_V12_PROMPT,
                   16: INVESTIGATOR_IMPACT_V16_PROMPT, 19: INVESTIGATOR_IMPACT_V19_PROMPT,
                   20: INVESTIGATOR_IMPACT_V20_PROMPT}
# the impact versions that run alternate-model lanes and need [review.investigator_alt] (refused without it)
ALT_IMPACT_VERSIONS = {7: INVESTIGATOR_IMPACT_V7_PROMPT, 10: INVESTIGATOR_IMPACT_V10_PROMPT}
DEFAULT_IMPACT_VERSION = 2
# investigator.impact@v4 Plan scaling (only for v4; every other Plan keeps its bytes). The INVESTIGATE ceiling doubles so
# the specialists keep exactly the v3 seconds (they split the first half, reviewer.pipeline.sweeps) and the diff-shard
# sweeps share the second half; VERIFY gets more time for the larger, round-robin candidate list; the hard and soft run
# deadlines move to fit. The run tool-call cap covers up to 6 sweeps (12 + files each) and renewed verifier sessions.
V4_MAX_TOOL_CALLS = 400
V4_LIVE_STAGE_CEILINGS_SEC = {"INVESTIGATE": 600, "VERIFY": 450, "JUDGE": 200}
V4_LIVE_WALL_CLOCK_SEC, V4_LIVE_SOFT_DEADLINE_SEC = 1_500, 1_200
V4_LEGACY_STAGE_CEILINGS_SEC = {"INVESTIGATE": 240}      # twice the legacy table's 120 s
# investigator.impact@v5 Plan scaling (only for v5): five specialist lanes keep the v3 per-lane seconds (100 s live, 40 s
# legacy), VERIFY gets time for the larger round-robin list (cap 28), the run deadlines move to fit; the run tool-call
# cap covers the 100-call lane pool, PREPARE of a 30-file diff and renewed verifier sessions. The $4 ceiling and the
# 30% verify reserve are unchanged (pipeline.lanes keeps INVESTIGATE <= 55% and a JUDGE reserve).
V5_MAX_TOOL_CALLS = 320
V5_LIVE_STAGE_CEILINGS_SEC = {"INVESTIGATE": 500, "VERIFY": 420, "JUDGE": 200}
V5_LIVE_WALL_CLOCK_SEC, V5_LIVE_SOFT_DEADLINE_SEC = 1_500, 1_200
V5_LEGACY_STAGE_CEILINGS_SEC = {"INVESTIGATE": 200}      # 5 x the legacy 40 s per specialist
# investigator.impact@v7 Plan scaling (only for v7): eight lanes keep the v5 per-lane seconds (100 s live, 40 s legacy;
# the five v5 lanes get exactly their v5 slices); the run tool-call cap adds the three alternate lanes' 60-call pool to
# v5's 320; VERIFY keeps v5's 420 s (spend, not time, binds it: pipeline.lanes keeps INVESTIGATE <= 65%); the run deadlines
# move by the extra 300 s. The $4 ceiling and the 30% verify reserve are unchanged.
V7_MAX_TOOL_CALLS = 380
V7_LIVE_STAGE_CEILINGS_SEC = {"INVESTIGATE": 800, "VERIFY": 420, "JUDGE": 200}
V7_LIVE_WALL_CLOCK_SEC, V7_LIVE_SOFT_DEADLINE_SEC = 1_800, 1_500
V7_LEGACY_STAGE_CEILINGS_SEC = {"INVESTIGATE": 320}      # 8 x the legacy 40 s per lane
# investigator.impact@v10 Plan scaling (only for v10): six lanes keep the v3 per-lane seconds (the INVESTIGATE ceiling
# doubles: 600 s live, 240 s legacy, so the three v3 lanes get exactly their v3 slices); VERIFY gets 450 s live (v3's 300 s
# plus 150 s for the alternate lanes' candidates verified after v3's; the legacy Plan has no VERIFY override and keeps
# the table value, as v3's does); JUDGE keeps v3's 200 s; the run tool-call cap adds the three alternate lanes' 60-call
# pool to v3's 160; the live run deadlines move by the extra 300 + 150 s. The $4 ceiling and 30% verify reserve are unchanged.
V10_MAX_TOOL_CALLS = 220
V10_LIVE_STAGE_CEILINGS_SEC = {"INVESTIGATE": 600, "VERIFY": 450, "JUDGE": 200}
V10_LIVE_WALL_CLOCK_SEC, V10_LIVE_SOFT_DEADLINE_SEC = 1_650, 1_350
V10_LEGACY_STAGE_CEILINGS_SEC = {"INVESTIGATE": 240}     # 6 x the legacy 40 s per lane
# investigator.impact@v12 Plan scaling (only for v12; deepcov). INVESTIGATE runs the three lens lanes (deepcov.LENS_TIME_BP
# = 40% of the ceiling: 120 s each live, the v3 lanes' 100 s plus one more request turn) and up to deepcov.MAX_UNITS
# coverage investigators with a depth floor (the other 60%: 135 s each for four units, at ~20 s per Terra hop 3-5 hops
# plus continuations); VERIFY gets 540 s for up to ~16 verified candidates of 1-3 hops each before the JUDGE reserve
# binds (v3 used <= 194 s for 12); JUDGE keeps 200 s; the run deadlines move to fit. The run tool-call cap covers PREPARE
# of a ~30-file diff, the lens reads (3 x 16), the unit reads (6 + 3 per file each), re-shown reads of continuations and
# per-candidate verifier sessions. The $4 ceiling and the 30% verify reserve are unchanged (deepcov keeps INVESTIGATE <=
# 65%, so VERIFY + JUDGE keep >= 35%).
V12_MAX_TOOL_CALLS = 400
# DEADLINE time successor (2026-11-02, as cand12cd): the V12 seconds were sized on Haiku/Terra hops; a Sonnet 5.5 investigator
# takes about twice the turns at the same per-call latency (orso3 cal22532: 11 vs 6), so every live stage ceiling x2 (lens
# slices 240 s, unit slices 270 s) and the run deadlines keep v12's margins x2 (sum 3280 + 720; soft 600 s before hard).
# Per-call timeouts and every money/count cap unchanged.
V12_LIVE_STAGE_CEILINGS_SEC = {"INVESTIGATE": 1800, "VERIFY": 1080, "JUDGE": 400}
V12_LIVE_WALL_CLOCK_SEC, V12_LIVE_SOFT_DEADLINE_SEC = 4_000, 3_400
V12_LEGACY_STAGE_CEILINGS_SEC = {"INVESTIGATE": 280}     # 3 x 40 s lens lanes + 4 x 40 s units
# investigator.impact@v19 only (reviewer.pipeline.agentic): the run ceiling of a v19 Plan ($10, CC_AUTH_V2), so one agentic
# session's PACING budget (agentic.BUDGET_USD_MICROS, reserved whole by the gateway), its re-ask, VERIFY and JUDGE fit. Every
# other Plan keeps profile.RUN_CEILING_USD_MICROS, and the live hosts accept exactly this ceiling for a v19 Plan only.
V19_RUN_CEILING_USD_MICROS = 10_000_000


def _prompts(impact: bool, impact_version: int = DEFAULT_IMPACT_VERSION) -> tuple[str, str]:
    if impact_version not in IMPACT_VERSIONS or isinstance(impact_version, bool):
        raise ProfileError(f"unknown impact_version {impact_version!r}; known: {sorted(IMPACT_VERSIONS)}")
    return ((IMPACT_VERSIONS[impact_version], VERIFIER_IMPACT_PROMPT) if impact
            else (INVESTIGATOR_PROMPT, VERIFIER_PROMPT))


def repository_profile(retrieval: bool = True, models=None, experiment: str = EXPERIMENT_BASELINE,
                       impact: bool = True, impact_version: int = DEFAULT_IMPACT_VERSION) -> dict:
    """`experiment` (default baseline) opts into context-check@1: only the verifier and judge prompt ids change, to the
    experiment's; models, schemas, caps, tools, timeouts and retries are the baseline's. `impact` (default on) only
    matters with retrieval: it selects the impact investigator/verifier prompt ids (`impact_version` 2, 3 or 1)."""
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
    if profile["roles"]["investigator"]["promptVersion"] in AGENTIC_PROMPTS:   # agentic.SESSION_RULE (v19, v20)
        if profile["roles"]["investigator"]["provider"] != "claude-cli":
            raise ProfileError(f"{profile['roles']['investigator']['promptVersion']} needs a claude-cli investigator (its agentic read-only session is "
                               "claude-cli-isolated@6 only)")
        profile["roles"]["investigator"]["params"] = dict(profile["roles"]["investigator"]["params"],
                                                          agentic=agentic.spec())
    if profile["roles"]["investigator"]["promptVersion"] in ALT_IMPACT_VERSIONS.values():
        alt = None if models is None else models.investigator_alt
        if alt is None:
            raise ProfileError(f"impact_version {impact_version} needs an alternate investigator model: set "
                               "[review.investigator_alt] in the review config (refused; "
                               + ("v7 never runs as the v5 lanes alone)" if impact_version == 7
                                  else "v10 never runs as the v3 specialists alone)"))
        cli = (profile["roles"]["investigator"]["provider"] == "claude-cli", models.provider("investigator_alt") == "claude-cli")
        if cli[0] != cli[1]:          # REPAIR1 (gate L1): the alternate is pinned to the investigator's caps (maxRepairs)
            raise ProfileError("a claude-cli investigator needs a claude-cli alternate (gateway repairs must match)" if cli[0]
                               else "a claude-cli alternate needs a claude-cli investigator (gateway repairs must match)")
        spec = copy.deepcopy(profile["roles"]["investigator"])
        spec.update(model_fields(models.provider("investigator_alt"), alt))
        profile["alternates"] = {"investigator": spec}
        problem = lanes.alternate_problem(profile)
        if problem is not None:
            raise ProfileError(problem)
    return profile


def repository_plan(profile: dict, *, live_stage_timing: bool = False) -> dict:
    """_repository_plan; a profile with claude-cli repairs says so in the Plan reasons (profile.with_repair_reason; every
    other Plan keeps its bytes)."""
    return with_repair_reason(_repository_plan(profile, live_stage_timing=live_stage_timing), profile)


def _repository_plan(profile: dict, *, live_stage_timing: bool = False) -> dict:
    """`live_stage_timing` (explicit, default off = the legacy Plan) sets the versioned live stage ceilings and
    host-stop recording together; no repository data selects either. An investigator.impact@v3 profile gets the
    specialist investigators as Plan.specialists, an impact@v4 profile the specialists plus the diff-shard sweep
    marker and the V4_* budget scaling (every other profile keeps the one generalist, same Plan bytes)."""
    inv = profile["roles"]["investigator"]["promptVersion"]
    if inv in (INVESTIGATOR_IMPACT_V16_PROMPT, *AGENTIC_PROMPTS):   # v12's clocks and tool cap (V12_*)
        if "alternates" in profile:
            raise ProfileError(f"{inv} runs on the primary investigator model only (no alternates)")
        plan = live_plan(profile, **({"stage_ceilings_sec": V12_LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True,
                                      "wall_clock_sec": V12_LIVE_WALL_CLOCK_SEC,
                                      "soft_deadline_sec": V12_LIVE_SOFT_DEADLINE_SEC}
                                     if live_stage_timing else {"stage_ceilings_sec": V12_LEGACY_STAGE_CEILINGS_SEC}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=V12_MAX_TOOL_CALLS,
                              maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        plan["specialists"] = whole.plan_specialists()
        plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports",
                           "investigator.impact@v16: one whole-change reviewer (the whole diff and the changed files' "
                           f"head content, at most {whole.MAX_HYPOTHESES} hypotheses), then v12's VERIFY and JUDGE "
                           "(primary investigator model only)"]
        if inv in AGENTIC_PROMPTS:                     # impact@v19/v20: one agentic session, the JUDGE rule, the $10 ceiling
            plan["specialists"] = agentic.plan_specialists()
            plan["budget"] = dict(plan["budget"], maxUsdMicros=V19_RUN_CEILING_USD_MICROS)
            plan["reasons"][1] = (f"{inv}: one agentic read-only claude-cli reviewer session (at most "
                                  f"{agentic.MAX_REQUESTS} requests, {agentic.SESSION_DEADLINE_SEC} s), then v16's VERIFY "
                                  "and JUDGE with the concrete-behaviour rule (primary investigator model only)")
        return plan
    if inv == INVESTIGATOR_IMPACT_V12_PROMPT:    # the v12 scaling (V12_*); primary model only
        if "alternates" in profile:
            raise ProfileError("investigator.impact@v12 runs on the primary investigator model only (no alternates)")
        plan = live_plan(profile, **({"stage_ceilings_sec": V12_LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True,
                                      "wall_clock_sec": V12_LIVE_WALL_CLOCK_SEC,
                                      "soft_deadline_sec": V12_LIVE_SOFT_DEADLINE_SEC}
                                     if live_stage_timing else {"stage_ceilings_sec": V12_LEGACY_STAGE_CEILINGS_SEC}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=V12_MAX_TOOL_CALLS,
                              maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        plan["specialists"] = deepcov.plan_specialists()
        plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports",
                           "investigator.impact@v12: lens lanes contracts, logic, safety, then coverage investigators "
                           f"over at most {deepcov.MAX_UNITS} changed-file units (primary investigator model only)"]
        return plan
    if inv == INVESTIGATOR_IMPACT_V10_PROMPT:    # the v10 scaling (V10_*); the alternate model is named in the reasons
        problem = lanes.alternate_problem(profile)
        if problem is not None:
            raise ProfileError(problem)
        plan = live_plan(profile, **({"stage_ceilings_sec": V10_LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True,
                                      "wall_clock_sec": V10_LIVE_WALL_CLOCK_SEC,
                                      "soft_deadline_sec": V10_LIVE_SOFT_DEADLINE_SEC}
                                     if live_stage_timing else {"stage_ceilings_sec": V10_LEGACY_STAGE_CEILINGS_SEC}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=V10_MAX_TOOL_CALLS,
                              maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        plan["specialists"] = list(V10_AGENTS)
        alt = lanes.alternate(profile)
        plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports",
                           f"investigator.impact@v10: lanes {', '.join(V10_ALT_AGENTS)} on the alternate investigator "
                           f"{alt['provider']}/{alt['model']} (investigator {profile['roles']['investigator']['model']})"]
        return plan
    if inv == INVESTIGATOR_IMPACT_V7_PROMPT:     # the v7 scaling (V7_*); the alternate model is named in the reasons
        problem = lanes.alternate_problem(profile)
        if problem is not None:
            raise ProfileError(problem)
        plan = live_plan(profile, **({"stage_ceilings_sec": V7_LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True,
                                      "wall_clock_sec": V7_LIVE_WALL_CLOCK_SEC,
                                      "soft_deadline_sec": V7_LIVE_SOFT_DEADLINE_SEC}
                                     if live_stage_timing else {"stage_ceilings_sec": V7_LEGACY_STAGE_CEILINGS_SEC}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=V7_MAX_TOOL_CALLS,
                              maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        plan["specialists"] = list(V7_AGENTS)
        alt = lanes.alternate(profile)
        plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports",
                           f"investigator.impact@v7: lanes {', '.join(V7_ALT_AGENTS)} on the alternate investigator "
                           f"{alt['provider']}/{alt['model']} (investigator {profile['roles']['investigator']['model']})"]
        return plan
    if inv == INVESTIGATOR_IMPACT_V5_PROMPT:     # the v5 scaling (V5_*)
        plan = live_plan(profile, **({"stage_ceilings_sec": V5_LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True,
                                      "wall_clock_sec": V5_LIVE_WALL_CLOCK_SEC,
                                      "soft_deadline_sec": V5_LIVE_SOFT_DEADLINE_SEC}
                                     if live_stage_timing else {"stage_ceilings_sec": V5_LEGACY_STAGE_CEILINGS_SEC}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=V5_MAX_TOOL_CALLS,
                              maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        plan["specialists"] = list(V5_AGENTS)
    elif inv == INVESTIGATOR_IMPACT_V4_PROMPT:     # the v4 scaling (V4_*); every other Plan is built exactly as before
        plan = live_plan(profile, **({"stage_ceilings_sec": V4_LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True,
                                      "wall_clock_sec": V4_LIVE_WALL_CLOCK_SEC,
                                      "soft_deadline_sec": V4_LIVE_SOFT_DEADLINE_SEC}
                                     if live_stage_timing else {"stage_ceilings_sec": V4_LEGACY_STAGE_CEILINGS_SEC}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=V4_MAX_TOOL_CALLS,
                              maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        plan["specialists"] = v4_plan_specialists()
    else:
        plan = live_plan(profile, **({"stage_ceilings_sec": LIVE_STAGE_CEILINGS_SEC, "host_stop_recording": True}
                                     if live_stage_timing else {}))
        plan["budget"] = dict(plan["budget"], maxToolCalls=MAX_TOOL_CALLS, maxToolCallsPerAgent=MAX_TOOL_CALLS_PER_AGENT)
        if inv == INVESTIGATOR_IMPACT_V3_PROMPT:
            plan["specialists"] = list(SPECIALIST_AGENTS)
    plan["reasons"] = ["pilot-repository: fixed standard Plan, retries/repairs off, complete pinned repository imports"]
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
    if inv == INVESTIGATOR_IMPACT_V4_PROMPT:         # the run-wide tool-call cap follows the v4 Plan's
        return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver, run_tool_calls=V4_MAX_TOOL_CALLS)
    if inv == INVESTIGATOR_IMPACT_V5_PROMPT:         # likewise for v5
        return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver, run_tool_calls=V5_MAX_TOOL_CALLS)
    if inv == INVESTIGATOR_IMPACT_V7_PROMPT:         # and v7
        return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver, run_tool_calls=V7_MAX_TOOL_CALLS)
    if inv == INVESTIGATOR_IMPACT_V10_PROMPT:        # and v10
        return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver, run_tool_calls=V10_MAX_TOOL_CALLS)
    if inv in (INVESTIGATOR_IMPACT_V12_PROMPT, INVESTIGATOR_IMPACT_V16_PROMPT,     # and v12, v16, v19, v20 (v12's cap)
               *AGENTIC_PROMPTS):
        return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver, run_tool_calls=V12_MAX_TOOL_CALLS)
    return RetrievalPolicy(investigator_prompt=inv, verifier_prompt=ver)
