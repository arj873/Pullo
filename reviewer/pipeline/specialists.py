"""investigator.impact@v3: specialist investigators (pure rules; the engine drives them in Engine._investigate_v3).

INVESTIGATE runs prompts.SPECIALIST_AGENTS one after another in that fixed order. Each agent is one v2 investigator
(own ToolSession and ordinals, the v2 exploration floor, the same prefetched PREPARE context) whose task is the v2 task
plus its lens paragraph. Everything here is a pure function of the policy, the Plan budget, the host tool limits and
the logged trace or artifact, so a resumed run and a strict replay re-derive the same numbers and decisions.

Budget split (BUDGET_RULE). The single impact@v2 investigator could use at most `pool` tool calls (its per-agent cap:
min(policy.agent_tool_calls, Plan maxToolCallsPerAgent, host tool limit)) and INVESTIGATE could spend at most the
Plan investigation share (budget.investigation_limit). v3 gives the K agents CUMULATIVE ceilings of both:
agent i (0-based) may start a tool call only while all INVESTIGATE tool calls so far are below pool*(i+1)//K, and an
investigator model call only while all INVESTIGATE spend so far is below share*(i+1)//K. Unused room of an earlier agent
rolls forward; the last ceiling equals the old total, so the sums never exceed the v2 totals and run_tool_calls, the run
ceiling and the stage deadlines are untouched. Per-agent caps (turns, agent_tool_calls, context chars, tool output chars)
apply to each agent as before. The spend ceiling is checked before each call (a call admitted below it may end above
it; the gateway's own investigation-share and run-ceiling admission still binds every call).

Time slices (TIME_RULE). With a stage ceiling C for INVESTIGATE, agent i may run only until C*(i+1)//K seconds after
the stage started (live ceiling 300 s -> 100 / 200 / 300 s; unused time rolls forward). The slice is enforced by the
same Engine.gate as every deadline, as a `stage-deadline` stop (recorded with host-stop recording, so strict replay
takes it from the recording); a stopped agent falls back to its exploration-floor draft when it has one.

Merge rule (MERGE_RULE). Before VERIFY, hypotheses are taken in agent order, then output order. One is merged into the
first KEPT hypothesis of an EARLIER agent with the same head location path, the same category and anchor start lines
(location.line) at most MERGE_LINE_WINDOW apart; otherwise it is kept. Merged hypotheses stay in the INVESTIGATE
artifact (and its `merges` list). VERIFY takes the remaining candidates round-robin across specialists (contracts 0,
logic 0, safety 0, contracts 1, ...), verifies at most MAX_VERIFY_CANDIDATES (the one-investigator output cap; the rest
are dropped as `over-cap`), and then, for every kept hypothesis that yielded no finding, verifies its first merged
duplicate within the same cap; every other duplicate is dropped as `merged` without a verifier call.
"""

from __future__ import annotations

from reviewer.contracts.budget import investigation_limit, stage_ceiling
from reviewer.contracts.entities import SPECIALIST_MERGE_VERSION

from . import prompts, retrieval

SPECIALIST_BEHAVIOR = "specialist-investigators@1"
BUDGET_RULE = "specialist-budget-split@1"
MERGE_RULE = SPECIALIST_MERGE_VERSION
MERGE_LINE_WINDOW = 3               # anchor start lines at most this far apart
TIME_RULE = "specialist-time-slices@1"
MAX_VERIFY_CANDIDATES = 20          # = InvestigatorOutput.hypotheses max_items: what one v2 investigator could propose
AGENTS = prompts.SPECIALIST_AGENTS

BUDGET_TEXT = ("cumulative ceilings: agent i (0-based, run order) starts a tool call only while INVESTIGATE tool calls "
               "so far < pool*(i+1)//K and an investigator model call only while INVESTIGATE spend so far < "
               "share*(i+1)//K; pool = min(agent_tool_calls, maxToolCallsPerAgent, host max_calls), share = "
               "investigation_limit(budget); per-agent caps unchanged; time: agent i stops at C*(i+1)//K s of the "
              "INVESTIGATE stage ceiling C (a stage-deadline gate stop)")
MERGE_TEXT = ("agent order then output order; merge into the first kept hypothesis of an earlier agent with the same "
              "head location path, same category and |line - line| <= MERGE_LINE_WINDOW; VERIFY order round-robin "
              "across agents; kept beyond MAX_VERIFY_CANDIDATES -> 'over-cap'; a kept hypothesis without a finding "
              "sends its first merged duplicate to VERIFY within the cap; other duplicates -> 'merged'")


def is_v3_plan(plan: dict) -> bool:
    """The Plan of an investigator.impact@v3 run (runner refuses any other pairing of plan and policy)."""
    return plan.get("specialists") == list(AGENTS)


def is_specialist_plan(plan: dict) -> bool:
    """A Plan whose INVESTIGATE runs the specialists: impact@v3, or impact@v4 (the specialists then the diff-shard
    sweep marker, see reviewer.pipeline.sweeps.PLAN_MARKER)."""
    return is_v3_plan(plan) or plan.get("specialists") == list(AGENTS) + ["diff-sweep"]


def time_slices(ceiling_sec: int | None) -> list[int] | None:
    """Cumulative per-agent INVESTIGATE time ceilings (seconds since the stage started), or None without a ceiling."""
    return None if ceiling_sec is None else cumulative(ceiling_sec)


def cumulative(total: int, k: int = len(AGENTS)) -> list[int]:
    """[total*(i+1)//k for i < k]: non-decreasing, the last one equals total."""
    return [total * (i + 1) // k for i in range(k)]


def tool_pool(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> int:
    """What the one impact@v2 investigator agent could use (Engine.agent_limit capped by the policy)."""
    return min(policy.agent_tool_calls, budget["maxToolCallsPerAgent"], tool_max_calls)


def budget_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    """The deterministic split, as bound into the config identity and shown in tests."""
    pool, share = tool_pool(policy, budget, tool_max_calls), investigation_limit(budget)
    return {"rule": BUDGET_RULE, "text": BUDGET_TEXT, "agents": list(AGENTS),
            "toolCalls": {"pool": pool, "cumulative": cumulative(pool)},
            "spendUsdMicros": {"share": share, "cumulative": cumulative(share)},
            "timeSec": {"rule": TIME_RULE, "ceiling": stage_ceiling("INVESTIGATE", budget),
                        "cumulative": time_slices(stage_ceiling("INVESTIGATE", budget))},
            "perAgent": {"investigatorTurns": policy.investigator_turns, "agentToolCalls": policy.agent_tool_calls,
                         "contextChars": policy.context_chars,
                         "toolOutputCharsPerAgent": budget["maxToolOutputTokensPerAgent"] * 3}}


def identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    return {"behavior": SPECIALIST_BEHAVIOR, "lensVersion": prompts.SPECIALIST_LENS_VERSION, "agents": list(AGENTS),
            "budget": budget_doc(policy, budget, tool_max_calls),
            "merge": {"rule": MERGE_RULE, "text": MERGE_TEXT, "lineWindow": MERGE_LINE_WINDOW,
                      "maxVerifyCandidates": MAX_VERIFY_CANDIDATES}}


def duplicate(a: dict, b: dict) -> bool:
    """The merge predicate: same head path, same category, anchor start lines at most MERGE_LINE_WINDOW apart
    (endLine is ignored, so a wide range never swallows unrelated claims)."""
    return (a["location"]["path"] == b["location"]["path"] and a["category"] == b["category"]
            and abs(a["location"]["line"] - b["location"]["line"]) <= MERGE_LINE_WINDOW)


def merge(hypotheses: list[dict], agents: list[str] | None = None) -> list[dict]:
    """-> [{keptId, mergedIds, rule}] for the INVESTIGATE artifact. `hypotheses` are Hypothesis documents in agent
    order then output order (as INVESTIGATE stores them); only a hypothesis of a LATER agent is merged, into the first
    kept one that it duplicates. Kept hypotheses never merge with each other inside one agent. `agents` is the agent
    order (default: the v3 specialists; impact@v4 passes sweeps.merge_order, which appends the diff-shard sweeps)."""
    order = {a: i for i, a in enumerate(AGENTS if agents is None else agents)}
    kept: list[dict] = []
    merged: dict[str, list[str]] = {}
    for h in hypotheses:
        rank = order[h["specialist"]]
        into = next((k for k in kept if order[k["specialist"]] < rank and duplicate(k, h)), None)
        if into is None:
            kept.append(h)
        else:
            merged.setdefault(into["id"], []).append(h["id"])
    return [{"keptId": k["id"], "mergedIds": merged[k["id"]], "rule": MERGE_RULE} for k in kept if k["id"] in merged]
