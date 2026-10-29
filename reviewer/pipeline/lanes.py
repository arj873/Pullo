"""investigator.impact@v5: five specialist lanes (pure rules; the engine drives them in Engine._investigate_v3).

The lanes are prompts.V5_AGENTS: the three v3 specialists (contracts, logic, safety) with their lens texts unchanged,
then `consistency` (parallel statements, sibling code paths, helper branches under each flag state) and `hygiene`
(state refresh in loops and retries, initial and default values, cleanup on early exit, test precision). Each lane is
one v2 investigator chain (own session and ordinals, the v2 exploration floor, the same prefetched PREPARE context), as
in v3. Everything here is a pure function of the policy, the Plan budget, the host tool limits and the INVESTIGATE
artifact, so a resumed run and a strict replay re-derive the same numbers and decisions.

Budget split (BUDGET_RULE), the v3 cumulative scheme generalized to K = 5 lanes, with unused room rolling forward:
  tool calls  lane i may start a tool call while INVESTIGATE tool calls < pool*(i+1)//K, pool = min(LANE_TOOL_CALLS*K,
              policy run_tool_calls, Plan maxToolCalls) (100 on the pilot: the v3 lane size of 20 each); the per-agent
              caps (policy agent_tool_calls, Plan maxToolCallsPerAgent, host max_calls) still bind each lane;
  spend       lane i may start an investigator model call while INVESTIGATE spend < top*(i+1)//K, top =
              min(investigation_limit(budget), INVESTIGATE_SPEND_BP of the run ceiling) ($2.20 of $4: $0.44 per lane,
              above the $0.23-0.33 per lane that v3 Terra traces used, so a lane is not cut short on typical diffs; the
              spend share is an API-equivalent estimate on the subscription arm and counts the same way);
  time        lane i stops at C*(i+1)//K seconds after INVESTIGATE started (the v5 Plan sets C = 100 s per lane live,
              as v3's 300/3; 40 s per lane on the legacy table).
VERIFY and JUDGE therefore keep at least 45% of the run ceiling ($1.80): VERIFY starts no candidate once the run's
spend reaches the JUDGE reserve (sweeps.JUDGE_RESERVE_BP, $0.30 of $4); the rest are dropped as `budget` (disclosed).

Merge (unchanged rule specialists.MERGE_RULE, agent order V5_AGENTS): a later lane's hypothesis at the same head path,
same category and start line within 3 of an earlier lane's kept one is merged into it.

Near-duplicate cap (NEAR_DUP_RULE, v5 only). After the merge, the kept hypotheses (every lane, own duplicates included)
are grouped by head path and category; a group anchors at its first start line (in line order, then INVESTIGATE order)
and takes every later one whose start line is at most NEAR_DUP_WINDOW lines away (no chaining, so a long block of
parallel lines is not one group). A group keeps at most NEAR_DUP_CAP hypotheses: the best evidenced (distinct cited
paths, then cited items, then a stated mechanism, then reach, then suspected severity), ties in INVESTIGATE order. The
others are recorded in the INVESTIGATE payload `collapses` and VERIFY drops them as `merged` with this rule, without a
verifier call. The v1-v4 merge behaviour is untouched.

VERIFY (VERIFY_RULE). Candidates round-robin across the five lanes; the cap is min(MAX_VERIFY_CANDIDATES_V5, 20 +
VERIFY_CANDIDATES_PER_LANE * (K - 3)) = 28; the verifier ToolSession is renewed every sweeps.VERIFY_SESSION_CANDIDATES
verified candidates (verifier, verifier-02, ...), as in v4.

Per-call provider timeouts (investigator 300 s, verifier 150 s live) are not clipped to a lane's time slice: a call
started inside its slice may end after it; the gate stops the lane before its next call.
"""

from __future__ import annotations

from reviewer.contracts.budget import investigation_limit, stage_ceiling
from reviewer.contracts.entities import NEAR_DUP_VERSION

from . import prompts, retrieval, specialists, sweeps

LANES_BEHAVIOR = "specialist-lanes@1"
BUDGET_RULE = "lane-budget-split@1"
NEAR_DUP_RULE = NEAR_DUP_VERSION
VERIFY_RULE = "lane-verify@1"
AGENTS = prompts.V5_AGENTS
V3_LANES = len(specialists.AGENTS)

LANE_TOOL_CALLS = 20                  # the v3 lane size (60 / 3)
INVESTIGATE_SPEND_BP = 5500           # INVESTIGATE may reach 55% of the run ceiling; VERIFY + JUDGE keep >= 45%
NEAR_DUP_WINDOW = 2                   # start lines at most this far from the group's anchor
NEAR_DUP_CAP = 2                      # hypotheses kept per (path, category, window) group
VERIFY_CANDIDATES_PER_LANE = 4
MAX_VERIFY_CANDIDATES_V5 = 40
_SEVERITY = {"P0": 2, "P1": 1, "P2": 0}

BUDGET_TEXT = ("K lanes in V5_AGENTS order; lane i: tool calls < pool*(i+1)//K with pool = min(LANE_TOOL_CALLS*K, "
               "run_tool_calls, maxToolCalls), spend < top*(i+1)//K with top = min(investigation_limit, "
               "INVESTIGATE_SPEND_BP of the ceiling), time C*(i+1)//K s; per-agent caps unchanged; VERIFY keeps the "
               "JUDGE reserve")
NEAR_DUP_TEXT = ("after the merge, kept hypotheses grouped by head path and category, anchored at the first start line "
                 "(line order, then INVESTIGATE order), members within NEAR_DUP_WINDOW lines of the anchor; keep the "
                 "NEAR_DUP_CAP best evidenced (distinct cited paths, cited items, mechanism, reach, severity; ties: "
                 "INVESTIGATE order); the rest -> collapses, VERIFY drops them as merged")
VERIFY_TEXT = ("round-robin across the lanes; cap min(MAX_VERIFY_CANDIDATES_V5, 20 + VERIFY_CANDIDATES_PER_LANE*(K-3)); "
               "a new verifier session every sweeps.VERIFY_SESSION_CANDIDATES verified candidates")


def is_v5_plan(plan: dict) -> bool:
    return plan.get("specialists") == list(AGENTS)


def extra_lanes(agents) -> int:
    return max(0, len(agents) - V3_LANES)


def tool_pool(policy: retrieval.RetrievalPolicy, budget: dict, k: int = len(AGENTS)) -> int:
    return min(LANE_TOOL_CALLS * k, policy.run_tool_calls, budget["maxToolCalls"])


def spend_top(budget: dict) -> int:
    return min(investigation_limit(budget), budget["maxUsdMicros"] * INVESTIGATE_SPEND_BP // 10_000)


def verify_cap(k: int = len(AGENTS)) -> int:
    return min(MAX_VERIFY_CANDIDATES_V5, specialists.MAX_VERIFY_CANDIDATES + VERIFY_CANDIDATES_PER_LANE * max(0, k - V3_LANES))


def evidence_score(h: dict) -> tuple:
    ev = h["evidence"]
    return (len({e.get("path") for e in ev if e.get("path")}), len(ev), int(bool(h.get("mechanism"))),
            int(bool(h.get("reach"))), _SEVERITY.get(h["suspectedSeverity"], 0))


def collapse(hypotheses: list[dict], merges: list[dict]) -> list[dict]:
    """-> [{keptIds, collapsedIds, rule}] for the INVESTIGATE artifact (only groups that collapsed something).
    `hypotheses` are in INVESTIGATE order (lane order, then output order)."""
    merged = {m for g in merges for m in g["mergedIds"]}
    pos = {h["id"]: n for n, h in enumerate(hypotheses)}
    kept = [h for h in hypotheses if h["id"] not in merged]
    by_key: dict[tuple, list] = {}
    for h in kept:
        by_key.setdefault((h["location"]["path"], h["category"]), []).append(h)
    groups = []
    for key in sorted(by_key):
        rest = sorted(by_key[key], key=lambda h: (h["location"]["line"], pos[h["id"]]))
        while rest:
            anchor = rest[0]["location"]["line"]
            group = [h for h in rest if h["location"]["line"] - anchor <= NEAR_DUP_WINDOW]
            rest = [h for h in rest if h["location"]["line"] - anchor > NEAR_DUP_WINDOW]
            if len(group) > NEAR_DUP_CAP:
                best = sorted(group, key=lambda h: (tuple(-x for x in evidence_score(h)), pos[h["id"]]))
                keep = sorted(best[:NEAR_DUP_CAP], key=lambda h: pos[h["id"]])
                drop = sorted(best[NEAR_DUP_CAP:], key=lambda h: pos[h["id"]])
                groups.append((pos[keep[0]["id"]], {"keptIds": [h["id"] for h in keep],
                                                    "collapsedIds": [h["id"] for h in drop], "rule": NEAR_DUP_RULE}))
    return [g for _, g in sorted(groups, key=lambda t: t[0])]


def budget_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    k = len(AGENTS)
    pool, top = tool_pool(policy, budget, k), spend_top(budget)
    c = stage_ceiling("INVESTIGATE", budget)
    return {"rule": BUDGET_RULE, "text": BUDGET_TEXT, "agents": list(AGENTS),
            "toolCalls": {"pool": pool, "cumulative": specialists.cumulative(pool, k)},
            "spendUsdMicros": {"top": top, "cumulative": specialists.cumulative(top, k)},
            "timeSec": {"ceiling": c, "cumulative": specialists.time_slices(c, k)},
            "perAgent": {"investigatorTurns": policy.investigator_turns, "agentToolCalls": policy.agent_tool_calls,
                         "hostMaxCalls": tool_max_calls, "contextChars": policy.context_chars}}


def identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    return {"behavior": LANES_BEHAVIOR, "lensVersion": prompts.V5_LENS_VERSION, "v3LensVersion":
            prompts.SPECIALIST_LENS_VERSION, "agents": list(AGENTS), "budget": budget_doc(policy, budget, tool_max_calls),
            "merge": {"rule": specialists.MERGE_RULE, "lineWindow": specialists.MERGE_LINE_WINDOW},
            "nearDuplicates": {"rule": NEAR_DUP_RULE, "text": NEAR_DUP_TEXT, "window": NEAR_DUP_WINDOW,
                               "cap": NEAR_DUP_CAP},
            "verify": {"rule": VERIFY_RULE, "text": VERIFY_TEXT, "maxCandidates": verify_cap(len(AGENTS)),
                       "perLane": VERIFY_CANDIDATES_PER_LANE, "sessionCandidates": sweeps.VERIFY_SESSION_CANDIDATES,
                       "judgeReserveBp": sweeps.JUDGE_RESERVE_BP}}
