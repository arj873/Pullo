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

Merge rule (MERGE_RULE). Before VERIFY, hypotheses are taken in agent order, then output order. One is merged into the
first KEPT hypothesis of an EARLIER agent with the same head location path, the same category and an overlapping line
range ([line, endLine or line]); otherwise it is kept. Merged hypotheses stay in the INVESTIGATE artifact (and its
`merges` list); VERIFY drops them with reason `merged` and never spends a verifier call on them. Kept hypotheses beyond
MAX_VERIFY_CANDIDATES (the one-investigator output cap) are dropped in VERIFY with reason `over-cap`.
"""

from __future__ import annotations

from reviewer.contracts.budget import investigation_limit
from reviewer.contracts.entities import SPECIALIST_MERGE_VERSION

from . import prompts, retrieval

SPECIALIST_BEHAVIOR = "specialist-investigators@1"
BUDGET_RULE = "specialist-budget-split@1"
MERGE_RULE = SPECIALIST_MERGE_VERSION
MAX_VERIFY_CANDIDATES = 20          # = InvestigatorOutput.hypotheses max_items: what one v2 investigator could propose
AGENTS = prompts.SPECIALIST_AGENTS

BUDGET_TEXT = ("cumulative ceilings: agent i (0-based, run order) starts a tool call only while INVESTIGATE tool calls "
               "so far < pool*(i+1)//K and an investigator model call only while INVESTIGATE spend so far < "
               "share*(i+1)//K; pool = min(agent_tool_calls, maxToolCallsPerAgent, host max_calls), share = "
               "investigation_limit(budget); per-agent caps unchanged")
MERGE_TEXT = ("agent order then output order; merge into the first kept hypothesis of an earlier agent with the same "
              "head location path, same category and overlapping [line, endLine|line]; merged -> VERIFY drop "
              "'merged'; kept beyond MAX_VERIFY_CANDIDATES -> VERIFY drop 'over-cap'")


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
            "perAgent": {"investigatorTurns": policy.investigator_turns, "agentToolCalls": policy.agent_tool_calls,
                         "contextChars": policy.context_chars,
                         "toolOutputCharsPerAgent": budget["maxToolOutputTokensPerAgent"] * 3}}


def identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    return {"behavior": SPECIALIST_BEHAVIOR, "lensVersion": prompts.SPECIALIST_LENS_VERSION, "agents": list(AGENTS),
            "budget": budget_doc(policy, budget, tool_max_calls),
            "merge": {"rule": MERGE_RULE, "text": MERGE_TEXT, "maxVerifyCandidates": MAX_VERIFY_CANDIDATES}}


def _span(h: dict) -> tuple[int, int]:
    loc = h["location"]
    return loc["line"], loc.get("endLine", loc["line"])


def duplicate(a: dict, b: dict) -> bool:
    """The merge predicate: same head path, same category, overlapping line ranges."""
    if a["location"]["path"] != b["location"]["path"] or a["category"] != b["category"]:
        return False
    (a0, a1), (b0, b1) = _span(a), _span(b)
    return a0 <= b1 and b0 <= a1


def merge(hypotheses: list[dict]) -> list[dict]:
    """-> [{keptId, mergedIds, rule}] for the INVESTIGATE artifact. `hypotheses` are Hypothesis documents in agent
    order then output order (as INVESTIGATE stores them); only a hypothesis of a LATER agent is merged, into the first
    kept one that it duplicates. Kept hypotheses never merge with each other inside one agent."""
    order = {a: i for i, a in enumerate(AGENTS)}
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
