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

Near-duplicate cap (NEAR_DUP_RULE, v5 only). It collapses only TRUE near-duplicates: the same claim told again at the
same spot. After the merge, two kept hypotheses (any lanes) are near-duplicates when they have the same head path and
category, their location ranges [line, endLine] overlap, their claim texts are similar (word-set Jaccard >=
NEAR_DUP_SIMILARITY over lower-case words of 3+ letters) AND their claims name exactly the same distinctive tokens
(backticked spans, dotted names, identifiers with an inner capital or underscore, all-caps names and anything with a
digit): "copies user.orgId into dto.userId" and "copies user.teamId into dto.userId" over one block range are two
defects, never collapsed. Distinct defects on adjacent lines (a mapping block with a wrong field on lines 10, 11 and
12) do not overlap and are never collapsed either. Groups anchor at the first hypothesis in
line order, then INVESTIGATE order; a group keeps NEAR_DUP_CAP (the best evidenced: distinct cited paths, then cited
items, then a stated mechanism, then reach, then suspected severity; ties in INVESTIGATE order); the others are
recorded in the INVESTIGATE payload `collapses` (collapsedIds best first). Fallback: when no kept member of a group
yields a finding, VERIFY verifies the best collapsed member (within the cap), as the merge rule retries a duplicate;
every other collapsed member is dropped as `merged` with this rule, without a verifier call. The collapse fallback runs
BEFORE the merge retry, so a collapsed member that is also a merge keptId and was verified without a finding still hands
VERIFY its own first merged duplicate; one that was never verified (its group's kept member was confirmed) is a
duplicate of a confirmed claim, and its own duplicates are dropped as merged. A defect confirmed twice (through a merge
retry and through the collapse fallback) is not merged automatically: JUDGE deduplicates an identical claim and anchor
deterministically and otherwise nominates findings with the same issue key (path, category, impact, location, code
citations) as a duplicate-candidate group, which the judge may merge. The v1-v4 merge behaviour is untouched.

VERIFY (VERIFY_RULE). Each lane's candidates are ordered by value first (suspectedSeverity P0 before P1 before P2,
then the stated confidence, highest first, then output order), then taken round-robin across the five lanes, so a
lane's most valuable hypothesis is verified before anyone's second. On a large diff it is SPEND, not the cap, that
binds: at about $0.07-0.10 per verified candidate, the JUDGE reserve stops VERIFY after roughly 15 candidates; the
rest are dropped as `budget` and disclosed. The cap is min(MAX_VERIFY_CANDIDATES_V5, 20 +
VERIFY_CANDIDATES_PER_LANE * (K - 3)) = 28; the verifier ToolSession is renewed every sweeps.VERIFY_SESSION_CANDIDATES
verified candidates (verifier, verifier-02, ...), as in v4.

Per-call provider timeouts (investigator 300 s, verifier 150 s live) are not clipped to a lane's time slice: a call
started inside its slice may end after it; the gate stops the lane before its next call.
"""

from __future__ import annotations

import re as _re

from reviewer.contracts.budget import investigation_limit, stage_ceiling
from reviewer.contracts.entities import CROSS_MERGE_VERSION, NEAR_DUP_VERSION

from . import prompts, retrieval, specialists, sweeps

LANES_BEHAVIOR = "specialist-lanes@1"
BUDGET_RULE = "lane-budget-split@1"
NEAR_DUP_RULE = NEAR_DUP_VERSION
VERIFY_RULE = "lane-verify@1"
AGENTS = prompts.V5_AGENTS
V3_LANES = len(specialists.AGENTS)

LANE_TOOL_CALLS = 20                  # the v3 lane size (60 / 3)
INVESTIGATE_SPEND_BP = 5500           # INVESTIGATE may reach 55% of the run ceiling; VERIFY + JUDGE keep >= 45%
NEAR_DUP_SIMILARITY = 0.5             # claim word-set Jaccard for two hypotheses at an overlapping spot
NEAR_DUP_CAP = 1                      # hypotheses kept per group of true near-duplicates (the rest: collapsed)
VERIFY_CANDIDATES_PER_LANE = 4
MAX_VERIFY_CANDIDATES_V5 = 40
_SEVERITY = {"P0": 2, "P1": 1, "P2": 0}

BUDGET_TEXT = ("K lanes in V5_AGENTS order; lane i: tool calls < pool*(i+1)//K with pool = min(LANE_TOOL_CALLS*K, "
               "run_tool_calls, maxToolCalls), spend < top*(i+1)//K with top = min(investigation_limit, "
               "INVESTIGATE_SPEND_BP of the ceiling), time C*(i+1)//K s; per-agent caps unchanged; VERIFY keeps the "
               "JUDGE reserve")
NEAR_DUP_TEXT = ("after the merge, kept hypotheses with the same head path and category whose location ranges overlap "
                 "the group anchor's (first in line order, then INVESTIGATE order) and whose claim word sets have "
                 "Jaccard >= NEAR_DUP_SIMILARITY and whose distinctive (code-like) tokens are identical form a group; keep the NEAR_DUP_CAP best evidenced (distinct cited "
                 "paths, cited items, mechanism, reach, severity; ties: INVESTIGATE order); the rest -> collapses "
                 "(best first); VERIFY verifies the best collapsed member when no kept member yields a finding (before the "
                 "merge retry), and drops the others as merged")
VERIFY_TEXT = ("lanes ordered by suspectedSeverity, confidence, output order; round-robin across the lanes; cap min(MAX_VERIFY_CANDIDATES_V5, 20 + VERIFY_CANDIDATES_PER_LANE*(K-3)); "
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


def claim_words(text: str) -> frozenset:
    return frozenset(_re.findall(r"[a-z0-9_]{3,}", text.lower()))


_DISTINCT = _re.compile(r"`[^`]+`|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+|\b\w*\d\w*\b|\b[a-z]+[A-Z]\w*\b"
                        r"|\b[A-Z][a-z0-9]*[A-Z]\w*\b|\b\w+_\w+\b|\b[A-Z]{2,}\b")


def distinctive(text: str) -> frozenset:
    """Code-like tokens of a claim: backticked spans, dotted names, camelCase/PascalCase/snake_case identifiers,
    all-caps names and anything with a digit (case-sensitive)."""
    return frozenset(m.group(0) for m in _DISTINCT.finditer(text))


def similar(a: dict, b: dict) -> bool:
    if distinctive(a["claim"]) != distinctive(b["claim"]):
        return False                     # different identifiers, fields or numbers: different defects
    wa, wb = claim_words(a["claim"]), claim_words(b["claim"])
    return bool(wa | wb) and len(wa & wb) / len(wa | wb) >= NEAR_DUP_SIMILARITY


def overlaps(a: dict, b: dict) -> bool:
    la, lb = a["location"], b["location"]
    return la["line"] <= lb.get("endLine", lb["line"]) and lb["line"] <= la.get("endLine", la["line"])


def near_duplicate(anchor: dict, h: dict) -> bool:
    return (anchor["location"]["path"] == h["location"]["path"] and anchor["category"] == h["category"]
            and overlaps(anchor, h) and similar(anchor, h))


def value_key(d: dict, n: int) -> tuple:
    """VERIFY order inside one v5 lane: higher suspected severity, then higher stated confidence, then output order."""
    c = d.get("confidence")
    return (-_SEVERITY.get(d.get("suspectedSeverity"), 0), -(c if isinstance(c, (int, float)) else 0), n)


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
            anchor = rest[0]
            group = [anchor] + [h for h in rest[1:] if near_duplicate(anchor, h)]
            rest = [h for h in rest if h not in group]
            if len(group) > NEAR_DUP_CAP:
                best = sorted(group, key=lambda h: (tuple(-x for x in evidence_score(h)), pos[h["id"]]))
                keep = sorted(best[:NEAR_DUP_CAP], key=lambda h: pos[h["id"]])
                drop = best[NEAR_DUP_CAP:]                     # best first: the fallback verifies drop[0]
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
            "nearDuplicates": {"rule": NEAR_DUP_RULE, "text": NEAR_DUP_TEXT, "similarity": NEAR_DUP_SIMILARITY,
                               "cap": NEAR_DUP_CAP},
            "verify": {"rule": VERIFY_RULE, "text": VERIFY_TEXT, "maxCandidates": verify_cap(len(AGENTS)),
                       "perLane": VERIFY_CANDIDATES_PER_LANE, "sessionCandidates": sweeps.VERIFY_SESSION_CANDIDATES,
                       "judgeReserveBp": sweeps.JUDGE_RESERVE_BP}}


# ---------------------------------------------------------------- investigator.impact@v7: cross-model lanes
#
# impact@v7 runs the five v5 lanes UNCHANGED on the configured investigator model (lens texts, chains, exploration
# floor, the v5 per-lane tool/spend/time numbers), then prompts.V7_ALT_LENSES (logic, consistency, hygiene) a second time
# as lanes `<lens>.alt` on the ALTERNATE investigator model, ModelProfile.alternates.investigator (same prompt id,
# schema, caps and params; only provider, model, family and price differ). Without an alternate the run is refused
# before any model call (runner.validate_spec, repository_profile): v7 never silently equals v5.
#
# Budget (CROSS_BUDGET_RULE), K = 8 lanes in prompts.V7_AGENTS order, A = 3 alternate lanes:
#   tool calls  lane i may start a tool call while INVESTIGATE tool calls < pool*(i+1)//K, pool = min(LANE_TOOL_CALLS*K,
#               run_tool_calls, maxToolCalls) = 160 (20 per lane: the five v5 lanes keep exactly 20, 40, ... 100);
#   time        lane i stops at C*(i+1)//K s (the v7 Plan sets C = 800 s live, 320 s legacy: 100 s / 40 s per lane, the
#               v5 lanes keep exactly their v5 slices);
#   spend       a v5 lane i (i < 5) may start an investigator call while INVESTIGATE spend < top*(i+1)//5 with the v5
#               top = min(investigation_limit, INVESTIGATE_SPEND_BP of the ceiling) ($2.20 of $4, $0.44 per lane);
#               an alternate lane j may start one while INVESTIGATE spend < min(S + alt*(j+1)//A, v7top), where S is
#               the INVESTIGATE spend when the first alternate lane started (from the logged cost records, so replay
#               re-derives it), alt = ALT_SPEND_BP of the ceiling ($1.20: the alternate model spends at most that,
#               $0.40 per lane with unused room rolling forward) and v7top = min(investigation_limit,
#               V7_INVESTIGATE_SPEND_BP of the ceiling) ($2.60). Unused v5 room never rolls into the alternate lanes.
# VERIFY and JUDGE therefore keep at least 35% of the run ceiling ($1.40; the gateway's investigation share, 70%, still
# binds every call); VERIFY starts no candidate once the run reaches the JUDGE reserve (sweeps.JUDGE_RESERVE_BP).
# Spend shares are API-equivalent estimates on the subscription arm and count the same way. gpt-5.6-terra lists at about
# twice gpt-6.1-terra's input and 2.4x its output rate, so at ~$0.16 per gpt-6.1-terra investigator call an alternate
# call is ~$0.35: about one call plus the exploration-floor continuation per alternate lane.
#
# Merge (CROSS_MERGE_RULE, every cross-lane merge of a v7 run): a later lane's hypothesis is merged into an earlier lane's
# kept one only when the v3 merge predicate holds (same head path and category, start lines within 3) AND the two are
# near-duplicates by the v5 test (overlapping location ranges, claim Jaccard >= NEAR_DUP_SIMILARITY, identical
# distinctive tokens). A distinct defect at a nearby line - exactly where a second model's different findings land - is
# kept and verified on its own; a true restatement is still merged (verified only if the kept one yields no finding).
# The near-duplicate cap and VERIFY are the v5 rules over the eight lanes in V7_AGENTS order; VERIFY takes each lane's candidates by
# value, round-robin across all eight lanes (a lane's best before anyone's second), cap verify_cap(8) = 40 (spend binds
# first). The verifier model is unchanged.

CROSS_BEHAVIOR = prompts.CROSS_MODEL_VERSION
CROSS_MERGE_RULE = CROSS_MERGE_VERSION
CROSS_MERGE_TEXT = ("lane order then output order; a later lane's hypothesis merges into the first kept hypothesis of an "
                    "earlier lane with the same head path and category, |line - line| <= MERGE_LINE_WINDOW, overlapping "
                    "location ranges, claim word-set Jaccard >= NEAR_DUP_SIMILARITY and identical distinctive tokens; "
                    "otherwise it is kept (and verified on its own)")
CROSS_BUDGET_RULE = "cross-model-budget-split@1"
V7_AGENTS = prompts.V7_AGENTS
ALT_AGENTS = prompts.V7_ALT_AGENTS
V7_INVESTIGATE_SPEND_BP = 6500        # all of INVESTIGATE (v5 lanes + alternate lanes) <= 65%: VERIFY + JUDGE keep >= 35%
ALT_SPEND_BP = 3000                   # the alternate model's own INVESTIGATE spend cap (30% of the ceiling)

CROSS_BUDGET_TEXT = ("K = 8 lanes in V7_AGENTS order (the five v5 lanes, then the alternate-model lanes); tool calls < "
                     "pool*(i+1)//K with pool = min(LANE_TOOL_CALLS*K, run_tool_calls, maxToolCalls); time C*(i+1)//K "
                     "s; spend: v5 lane i < top*(i+1)//5 with the v5 top; alternate lane j < min(S + alt*(j+1)//A, v7top) "
                     "with S = INVESTIGATE spend when the first alternate lane started, alt = ALT_SPEND_BP and v7top = "
                     "min(investigation_limit, V7_INVESTIGATE_SPEND_BP) of the ceiling; per-agent caps unchanged; "
                     "VERIFY keeps the JUDGE reserve")


def cross_duplicate(a: dict, b: dict) -> bool:
    """The impact@v7 merge predicate: the v3 merge predicate AND the v5 near-duplicate test."""
    return specialists.duplicate(a, b) and overlaps(a, b) and similar(a, b)


def cross_merge(hypotheses: list[dict]) -> list[dict]:
    """impact@v7 merges ([{keptId, mergedIds, rule: CROSS_MERGE_RULE}]) over the eight lanes in V7_AGENTS order."""
    return specialists.merge(hypotheses, list(V7_AGENTS), predicate=cross_duplicate, rule=CROSS_MERGE_RULE)


def lane_merge(plan: dict, hypotheses: list[dict]) -> list[dict]:
    """The merge record a v5, v7 or v10 Plan's INVESTIGATE artifact must carry."""
    if is_v10_plan(plan):
        return v10_merge(hypotheses)
    return cross_merge(hypotheses) if is_v7_plan(plan) else specialists.merge(hypotheses, list(AGENTS))


def is_v7_plan(plan: dict) -> bool:
    return plan.get("specialists") == list(V7_AGENTS)


def lane_order(plan: dict) -> list | None:
    """The lane (merge) order of a v5 or v7 Plan, else None."""
    return list(AGENTS) if is_v5_plan(plan) else list(V7_AGENTS) if is_v7_plan(plan) else None


def v7_spend_top(budget: dict) -> int:
    return min(investigation_limit(budget), budget["maxUsdMicros"] * V7_INVESTIGATE_SPEND_BP // 10_000)


def alt_spend_top(budget: dict) -> int:
    return min(v7_spend_top(budget), budget["maxUsdMicros"] * ALT_SPEND_BP // 10_000)


def primary_spend_cumulative(budget: dict) -> list[int]:
    """The v5 lanes' spend ceilings, exactly as impact@v5 computes them."""
    return specialists.cumulative(spend_top(budget), len(AGENTS))


def alt_spend_ceiling(start: int, j: int, budget: dict) -> int:
    """Alternate lane j (0-based): INVESTIGATE spend ceiling given S = `start`, the spend when the first one started."""
    return min(start + specialists.cumulative(alt_spend_top(budget), len(ALT_AGENTS))[j], v7_spend_top(budget))


def alternate(profile: dict) -> dict | None:
    """ModelProfile.alternates.investigator, or None."""
    return (profile.get("alternates") or {}).get("investigator")


def alternate_problem(profile: dict) -> str | None:
    """Why `profile` cannot run its cross-model impact version, impact@v7 or impact@v10 (None when it can). The message
    names the profile's own investigator prompt (an impact@v7 profile keeps the v7 text byte for byte)."""
    v10 = profile["roles"]["investigator"].get("promptVersion") == prompts.INVESTIGATOR_IMPACT_V10_PROMPT
    name, lanes_alone = ("investigator.impact@v10", "the v3 specialists") if v10 else ("investigator.impact@v7",
                                                                                       "the v5 lanes")
    alt = alternate(profile)
    if alt is None:
        return (f"{name} needs an alternate investigator model (ModelProfile.alternates.investigator, "
                f"from [review.investigator_alt]); refused instead of running {lanes_alone} alone")
    if alt["model"] == profile["roles"]["investigator"]["model"]:
        return f"{name} needs an alternate investigator model different from the investigator's"
    return None


def cross_budget_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    k, a = len(V7_AGENTS), len(ALT_AGENTS)
    pool = tool_pool(policy, budget, k)
    c = stage_ceiling("INVESTIGATE", budget)
    return {"rule": CROSS_BUDGET_RULE, "text": CROSS_BUDGET_TEXT, "agents": list(V7_AGENTS),
            "altAgents": list(ALT_AGENTS),
            "toolCalls": {"pool": pool, "cumulative": specialists.cumulative(pool, k)},
            "spendUsdMicros": {"top": spend_top(budget), "cumulative": primary_spend_cumulative(budget),
                               "altTop": alt_spend_top(budget),
                               "altCumulative": specialists.cumulative(alt_spend_top(budget), a),
                               "v7Top": v7_spend_top(budget), "investigateSpendBp": INVESTIGATE_SPEND_BP,
                               "altSpendBp": ALT_SPEND_BP, "v7InvestigateSpendBp": V7_INVESTIGATE_SPEND_BP},
            "timeSec": {"ceiling": c, "cumulative": specialists.time_slices(c, k)},
            "perAgent": {"investigatorTurns": policy.investigator_turns, "agentToolCalls": policy.agent_tool_calls,
                         "hostMaxCalls": tool_max_calls, "contextChars": policy.context_chars}}


def cross_identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int, profile: dict) -> dict:
    """The impact@v7 lane identity: the v5 lens texts, the alternate lanes, the alternate model and the budget split."""
    alt = alternate(profile)
    return {"behavior": CROSS_BEHAVIOR, "lanesBehavior": LANES_BEHAVIOR, "lensVersion": prompts.V5_LENS_VERSION,
            "v3LensVersion": prompts.SPECIALIST_LENS_VERSION, "agents": list(V7_AGENTS),
            "altLanes": {a: prompts.lens_of(a) for a in ALT_AGENTS},
            "alternateInvestigator": None if alt is None else {k: alt[k] for k in ("provider", "model", "family")},
            "budget": cross_budget_doc(policy, budget, tool_max_calls),
            "merge": {"rule": CROSS_MERGE_RULE, "text": CROSS_MERGE_TEXT, "lineWindow": specialists.MERGE_LINE_WINDOW,
                      "similarity": NEAR_DUP_SIMILARITY},
            "nearDuplicates": {"rule": NEAR_DUP_RULE, "text": NEAR_DUP_TEXT, "similarity": NEAR_DUP_SIMILARITY,
                               "cap": NEAR_DUP_CAP},
            "verify": {"rule": VERIFY_RULE, "text": VERIFY_TEXT, "maxCandidates": verify_cap(len(V7_AGENTS)),
                       "perLane": VERIFY_CANDIDATES_PER_LANE, "sessionCandidates": sweeps.VERIFY_SESSION_CANDIDATES,
                       "judgeReserveBp": sweeps.JUDGE_RESERVE_BP}}


# ---------------------------------------------------------------- investigator.impact@v10: v3 lanes + cross-model lanes
#
# impact@v10 is the impact@v3 configuration UNCHANGED - the three specialists (contracts, logic, safety) with the v3
# lens texts, chains, exploration floor and the v3 per-lane tool-call, spend and time ceilings (specialists.BUDGET_RULE,
# TIME_RULE) - followed by the same three lenses again as lanes `contracts.alt`, `logic.alt`, `safety.alt` on the
# ALTERNATE investigator model, ModelProfile.alternates.investigator (same prompt id, schema, caps and params; only
# provider, model, family and price differ). Without an alternate, or with the investigator's own model, the run is
# refused before any model call (runner.validate_spec, repository_profile): v10 never silently equals v3.
#
# Budget (V10_BUDGET_RULE), K = 6 lanes in prompts.V10_AGENTS order, A = 3 alternate lanes, p = the v3 tool pool
# (specialists.tool_pool: min(agent_tool_calls, maxToolCallsPerAgent, host max_calls), 60 on the pilot):
#   tool calls  lane i may start a tool call while INVESTIGATE tool calls < (2p)*(i+1)//K: exactly p*(i+1)//3 for the
#               three v3 lanes (20, 40, 60 on the pilot), then 80, 100, 120 for the alternate lanes;
#   time        lane i stops at C*(i+1)//K s, C = the v10 Plan's INVESTIGATE ceiling, twice v3's (600 s live, 240 s
#               legacy), so the v3 lanes keep exactly their v3 slices (100/200/300 s live, 40/80/120 s legacy);
#   spend       (each share is checked BEFORE a call: an admitted call may end above it, so a lane can overshoot its
#               share by at most one call's cost; the gateway's investigation-share admission, which reserves the
#               call's worst case, keeps all of INVESTIGATE <= $2.80 as a hard bound)
#               a v3 lane i (i < 3) may start an investigator call while INVESTIGATE spend < share*(i+1)//3 with the
#               v3 share = investigation_limit(budget) ($2.80 of $4: exactly v3's numbers); an alternate lane j may
#               start one while INVESTIGATE spend < alt_top = min(share, S + V10_ALT_ROOM_USD_MICROS), where S is the
#               INVESTIGATE spend when the first alternate lane started (from the logged cost records, so replay
#               re-derives it): the alternate lanes POOL at most $1.50 (never past v3's share); there is no per-lane
#               share, the final-answer reserve below decides how far each lane explores. All of INVESTIGATE then
#               reaches at most $2.20-2.40 for v3 lanes at $0.7-0.9, leaving VERIFY + JUDGE at least $1.60-1.80.
# All of INVESTIGATE therefore stays within v3's own investigation share (hard-bounded at $2.80 by the gateway's
# admission, whatever the per-lane overshoot), so VERIFY and JUDGE keep at least what v3 reserves for them
# (verifyReserveBp, 30% = $1.20).
#
# Final-answer reserve (V10_FINAL_RULE). Before each alternate-lane hop that is not already its last turn, with r = the
# gateway's worst-case reservation of that request on the alternate model (reservation(price, estimated input tokens,
# maxOutputTokens): about $0.29-0.42 for gpt-5.6-terra at 40k-90k input tokens), alternate lane j (of A) may explore
# only while INVESTIGATE spend + r + r_final <= alt_top - (A-1-j) * r, r_final = r * V10_FINAL_GROWTH_BP (125%: the
# final request carries this hop's results too) and r standing in for each LATER lane's final-answer reservation (so
# every later lane keeps room for its final answer); the LAST alternate lane also keeps a margin of r *
# V10_LAST_LANE_MARGIN_BP (25%). Otherwise the hop is sent as the lane's final-answer turn (the retrieval "last turn":
# no tools run, it must answer from what it has seen), and the exploration floor is skipped (reason `turns`). A lane
# that starts below its ceiling therefore always makes its final-answer call; only if that call itself fails or is
# refused does the coverage-note path apply (a final-answer turn that still requests context is noted as `turns`).
#
# VERIFY keeps the JUDGE reserve (as v4/v5: sweeps.judge_reserve_floor, 7.5% of the ceiling), so JUDGE always runs. A
# reserve stop that cuts only alternate-lane candidates (verified after all of v3's) is a coverage note
# ("alt-candidates-unverified: ..."), not an incomplete entry; one that cuts a v3 candidate is a VERIFY budget
# incomplete entry.
#
# Optional alternate lanes (V10_ALT_OPTIONAL_TEXT, v10_optional_error). An alternate lane that reaches its OWN cap
# (its spend share, its tool calls, its time slice - the last lane's slice is the stage ceiling) or whose model call
# ends with provider-error, provider-timeout, repair-exhausted or schema-invalid ends alone: what it already answered
# is kept (an exploration-floor draft included), its agent status says why, and v10_alt_coverage discloses it in
# review.md ("alt-lane-capped: <lane> (...)" / "alt-lane-failed: ...") - not as an incomplete entry. Every other end
# of an alternate lane is an INVESTIGATE incomplete entry exactly as in v3 (the systemic codes live-calls-disabled,
# model-unresolved, contract-violation -> agent-failure; the run's hard or soft deadline -> deadline/soft-deadline),
# and a run in which NO alternate lane answered gets an agent-failure entry `no-alternate-answer`, so a v10 run never
# silently equals v3. Host-level ends (replay failure, cancellation, an internal or spend-book error) fail the stage as
# in v3.
#
# Merge (V10_MERGE_TEXT). First the three v3 lanes' hypotheses are merged exactly as v3 merges them
# (specialists.merge, specialist-merge@2, v3 order). Then each alternate-lane hypothesis (V10_AGENTS order, output
# order) is merged into the first kept hypothesis of an earlier lane (a v3 lane's, or an earlier alternate lane's) only
# when it restates it - the v3 predicate AND the near-duplicate test (overlapping location ranges, claim Jaccard >=
# NEAR_DUP_SIMILARITY, identical distinctive tokens): cross-model-merge@1; otherwise it is kept. No near-duplicate cap.
# VERIFY and the verifier are v3's, unchanged, on the v3 lanes: their candidates round-robin in v3 order, at most
# specialists.MAX_VERIFY_CANDIDATES (20; the rest `over-cap`), then v3's merge retry. Only then the alternate lanes'
# kept candidates (round-robin across the alternate lanes) are verified within the same cap; an alternate restatement
# is dropped as `merged` without a retry. With no alternate hypothesis, VERIFY is exactly v3's.

V10_AGENTS = prompts.V10_AGENTS
V10_ALT_AGENTS = prompts.V10_ALT_AGENTS
V10_BEHAVIOR = "v3-cross-model-lanes@1"
V10_BUDGET_RULE = "v3-cross-model-budget-split@3"
V10_BUDGET_TEXT = ("K = 6 lanes in V10_AGENTS order (the three v3 specialists, then their alternate-model lanes); tool "
                   "calls < (2*pool)*(i+1)//K with the v3 pool; time C*(i+1)//K s with C twice the v3 INVESTIGATE "
                   "ceiling; spend: v3 lane i < share*(i+1)//3 with share = investigation_limit (exactly v3); "
                   "every alternate lane < alt_top = min(share, S + V10_ALT_ROOM_USD_MICROS) with S = INVESTIGATE "
                   "spend when the first alternate lane started (one pooled alternate room, no per-lane share); lane "
                   "j explores while spend + r + r*V10_FINAL_GROWTH_BP <= alt_top - (A-1-j)*r (the last lane: minus "
                   "r*V10_LAST_LANE_MARGIN_BP), else its hop is its final-answer turn; per-agent caps unchanged")
V10_ALT_ROOM_USD_MICROS = 1_500_000  # the alternate lanes split at most $1.50 of INVESTIGATE (never past v3's share)
V10_FINAL_RULE = "alt-final-answer-reserve@3"
V10_FINAL_GROWTH_BP = 12_500          # the final-answer call's worst case: 125% of this hop's (input growth)
V10_LAST_LANE_MARGIN_BP = 2_500       # the last alternate lane also keeps 25% of r below its ceiling (the cap)
V10_FINAL_TEXT = ("alternate lane j's hop that is not its last turn is sent as its final-answer turn (last turn, no "
                  "tools run; the exploration floor is skipped) when INVESTIGATE spend + r + r*V10_FINAL_GROWTH_BP > "
                  "alt_top - (A-1-j)*r (the last alternate lane: also minus r*V10_LAST_LANE_MARGIN_BP), r = the "
                  "gateway's worst-case reservation of that request on the alternate model, also the estimate of "
                  "each later lane's final-answer reservation")
V10_VERIFY_RESERVE_TEXT = ("VERIFY starts no candidate once the run's spend reaches the JUDGE reserve "
                           "(sweeps.judge_reserve_floor); a stop that cuts only alternate-lane candidates is a coverage "
                           "note, one that cuts a v3 candidate a VERIFY budget incomplete entry")
V10_VERIFY_TEXT = ("v3 VERIFY unchanged on the v3 lanes (round-robin in v3 order, output order inside a lane; beyond "
                   "specialists.MAX_VERIFY_CANDIDATES -> 'over-cap'; the merge retry), then the alternate lanes' kept "
                   "candidates round-robin within the same cap; alternate restatements -> 'merged' without a retry")
V10_MERGE_TEXT = ("the v3 lanes merged exactly as v3 (specialist-merge@2); then an alternate-lane hypothesis merges into "
                  "the first kept hypothesis of an earlier lane only when it restates it (cross-model-merge@1: same "
                  "head path and category, |line - line| <= MERGE_LINE_WINDOW, overlapping location ranges, claim "
                  "word-set Jaccard >= NEAR_DUP_SIMILARITY, identical distinctive tokens); otherwise it is kept")
V10_ALT_OPTIONAL_TEXT = ("an alternate lane that reaches its own cap (spend share, tool calls, its time slice) or whose "
                         "model call ends with provider-error, provider-timeout, repair-exhausted or schema-invalid ends "
                         "alone: its answer so far is kept and it is a coverage note, not an incomplete entry; every "
                         "other end (systemic codes, a run hard or soft deadline) is an INVESTIGATE incomplete entry as "
                         "in v3; no alternate answer at all is an agent-failure incomplete entry (no-alternate-answer); "
                         "host-level ends (replay, cancellation, internal, spend book) fail as in v3")
V10_CAPPED_CODES = ("budget-exhausted", "deadline-exceeded", "tool-calls-exhausted", "turns")
V10_OPTIONAL_PROVIDER_CODES = ("provider-error", "provider-timeout", "repair-exhausted", "schema-invalid")
V10_LANE_TIME_PREFIXES = ("INVESTIGATE time slice of ", "INVESTIGATE stage ceiling reached")   # Engine.gate messages
NO_ALT_ANSWER = "no-alternate-answer"


def v10_deadline_cause(err: dict) -> str:
    """Which clock stopped an INVESTIGATE agent (from the Engine.gate message): the lane's own time slice (the last
    lane's slice is the stage ceiling), or the run's hard or soft deadline."""
    m = err.get("message", "")
    if m.startswith(V10_LANE_TIME_PREFIXES[0]) or m.startswith(V10_LANE_TIME_PREFIXES[1]):
        return "lane time slice"
    return "soft run deadline" if m.startswith("soft deadline") else "hard run deadline"


def v10_optional_error(err: dict | None) -> bool:
    """An alternate lane's end that is OPTIONAL (coverage note only): no error (its tool calls were exhausted without
    an answer), its spend share (budget-exhausted), its own time slice, or one of V10_OPTIONAL_PROVIDER_CODES."""
    if err is None:
        return True
    code = err["code"]
    if code == "deadline-exceeded":
        return v10_deadline_cause(err) == "lane time slice"
    return code == "budget-exhausted" or code in V10_OPTIONAL_PROVIDER_CODES


def is_v10_plan(plan: dict) -> bool:
    return plan.get("specialists") == list(V10_AGENTS)


def v10_merge(hypotheses: list[dict]) -> list[dict]:
    """impact@v10 merges: the v3 lanes' groups exactly as v3 gives them (specialist-merge@2), then the alternate
    restatement groups (cross-model-merge@1) in kept order. A kept v3 hypothesis may head one group of each rule."""
    v3 = [h for h in hypotheses if h["specialist"] in specialists.AGENTS]
    out = specialists.merge(v3)
    gone = {m for g in out for m in g["mergedIds"]}
    order = {a: i for i, a in enumerate(V10_AGENTS)}
    kept = [h for h in v3 if h["id"] not in gone]
    merged: dict[str, list[str]] = {}
    for h in hypotheses:
        if h["specialist"] not in V10_ALT_AGENTS:
            continue
        into = next((k for k in kept if order[k["specialist"]] < order[h["specialist"]] and cross_duplicate(k, h)),
                    None)
        if into is None:
            kept.append(h)
        else:
            merged.setdefault(into["id"], []).append(h["id"])
    return out + [{"keptId": k["id"], "mergedIds": merged[k["id"]], "rule": CROSS_MERGE_RULE}
                  for k in kept if k["id"] in merged]


def _cause(code: str, err: dict | None) -> str:
    if code == "deadline-exceeded" and err is not None:
        return f"`{code}`: {v10_deadline_cause(err)}"
    return f"`{code}`"


JUDGE_RESERVE_DROP = "VERIFY stopped before this candidate to keep the JUDGE spend reserve"   # Engine.verify text


def _last_turn_sent(lane: str, events: list) -> bool:
    """Whether the lane's last INVESTIGATE request was its last turn (a final-answer turn that still asked for context
    ends `turns`, not at a tool-call limit)."""
    import json as _json
    for e in reversed(events):
        if e["type"] == "model.call" and e["stage"] == "INVESTIGATE" and e["agentId"] == lane:
            try:
                return bool(_json.loads(e["request"]["messages"][1]["content"])["retrieval"]["lastTurn"])
            except (ValueError, KeyError, IndexError, TypeError):
                return False
    return False


def v10_alt_coverage(payload: dict, events: list, incomplete: list = (), verify_drops: list = ()) -> list[str]:
    """impact@v10 coverage notes for the alternate lanes (a pure function of the INVESTIGATE payload, the trace and the
    run's incomplete entries): every alternate lane that ended before its own answer, or whose exploration-floor
    continuation ended without one so its first-hop draft was used. An optional end (v10_optional_error) is
    alt-lane-capped (its cap) or alt-lane-failed (its provider); any other end says it is counted as incomplete."""
    out = []
    for a in payload.get("agents", ()):
        lane = a["agentId"]
        if not prompts.is_alt_lane(lane):
            continue
        if a["status"] != "completed":
            err = a.get("error")
            code = err["code"] if err is not None else ("turns" if _last_turn_sent(lane, events)
                                                         else "tool-calls-exhausted")
            if v10_optional_error(err):
                kind = "alt-lane-capped" if code in V10_CAPPED_CODES else "alt-lane-failed"
                out.append(f"{kind}: {lane} ({_cause(code, err)}; status {a['status']})")
            else:
                out.append(f"alt-lane-stopped: {lane} ({_cause(code, err)}; status {a['status']}; counted as "
                           "incomplete)")
            continue
        counted = any(i["stage"] == "INVESTIGATE" and f"specialist {lane}: the exploration-floor" in i.get("detail", "")
                      for i in incomplete)
        for e in events:
            if e["type"] == "retrieval.floor" and e["agentId"] == lane and e["decision"] == "draft" \
                    and "errorCode" in e:
                if counted:
                    out.append(f"alt-lane-stopped: {lane} (`{e['errorCode']}`; its first-hop draft answer was used; "
                               "counted as incomplete)")
                else:
                    kind = "alt-lane-capped" if e["errorCode"] in V10_CAPPED_CODES else "alt-lane-failed"
                    out.append(f"{kind}: {lane} (`{e['errorCode']}`; its first-hop draft answer was used)")
    alt_ids = {h["id"] for h in payload.get("hypotheses", ()) if prompts.is_alt_lane(h["specialist"])}
    cut = [d for d in verify_drops if d["reason"] == "budget" and d.get("detail", "").startswith(JUDGE_RESERVE_DROP)
           and set(d["subjectIds"]) <= alt_ids]
    if cut:
        out.append(f"alt-candidates-unverified: {len(cut)} alternate-lane candidate(s) not verified (`budget-exhausted`:"
                   " VERIFY kept the JUDGE reserve)")
    if any(prompts.is_alt_lane(a["agentId"]) for a in payload.get("agents", ())) \
            and not any(prompts.is_alt_lane(a["agentId"]) and a["status"] == "completed" for a in payload["agents"]):
        out.append(f"{NO_ALT_ANSWER}: no alternate lane answered (counted as incomplete)")
    return out


def v10_tool_pool(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> int:
    """Twice the v3 pool, so cumulative(v10 pool, 6)[i] == cumulative(v3 pool, 3)[i] for the three v3 lanes."""
    return 2 * specialists.tool_pool(policy, budget, tool_max_calls)


def v10_tool_cumulative(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> list[int]:
    return specialists.cumulative(v10_tool_pool(policy, budget, tool_max_calls), len(V10_AGENTS))


def v10_spend_top(budget: dict) -> int:
    """All of a v10 INVESTIGATE: v3's own investigation share."""
    return investigation_limit(budget)


def v10_primary_spend_cumulative(budget: dict) -> list[int]:
    """The v3 lanes' spend ceilings, exactly as impact@v3 computes them."""
    return specialists.cumulative(investigation_limit(budget))


def v10_alt_top(start: int, budget: dict) -> int:
    """The alternate lanes' cumulative INVESTIGATE cap: min(v3's share, S + V10_ALT_ROOM_USD_MICROS)."""
    return min(v10_spend_top(budget), start + V10_ALT_ROOM_USD_MICROS)


def v10_alt_spend_ceiling(start: int, j: int, budget: dict) -> int:
    """v10 alternate lane j (0-based): its INVESTIGATE spend ceiling given S = `start`, the spend when the first
    started. The alternate room is pooled: every alternate lane's ceiling is the hard alternate cap v10_alt_top."""
    return v10_alt_top(start, budget)


def v10_final_answer_due(spent: int, alt_top: int, r: int, j: int = len(V10_ALT_AGENTS) - 1) -> bool:
    """V10_FINAL_RULE: True when alternate lane j's hop must be its final-answer turn: exploring could leave no
    worst-case room for its own final answer (r_final) and one final answer (~r) per later alternate lane."""
    later = len(V10_ALT_AGENTS) - 1 - j
    r_final = -(-r * V10_FINAL_GROWTH_BP // 10_000)
    margin = -(-r * V10_LAST_LANE_MARGIN_BP // 10_000) if later == 0 else 0
    return spent + r + r_final > alt_top - later * r - margin


def v10_time_slices(ceiling_sec: int | None) -> list[int] | None:
    return specialists.time_slices(ceiling_sec, len(V10_AGENTS))


def v10_budget_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    k, a = len(V10_AGENTS), len(V10_ALT_AGENTS)
    c = stage_ceiling("INVESTIGATE", budget)
    return {"rule": V10_BUDGET_RULE, "text": V10_BUDGET_TEXT, "v3Rule": specialists.BUDGET_RULE,
            "timeRule": specialists.TIME_RULE, "agents": list(V10_AGENTS), "altAgents": list(V10_ALT_AGENTS),
            "toolCalls": {"v3Pool": specialists.tool_pool(policy, budget, tool_max_calls),
                          "pool": v10_tool_pool(policy, budget, tool_max_calls),
                          "cumulative": v10_tool_cumulative(policy, budget, tool_max_calls)},
            "spendUsdMicros": {"share": v10_spend_top(budget), "cumulative": v10_primary_spend_cumulative(budget),
                               "alt": "pooled: every alternate lane's ceiling is alt_top = min(share, S + "
                                      "altRoomUsdMicros), S = INVESTIGATE spend when the first alternate lane started; "
                                      f"lane j (A = {a}) explores while spend + r + 1.25r <= alt_top - (A-1-j)*r "
                                      "(last lane: - 0.25r)",
                               "altRoomUsdMicros": V10_ALT_ROOM_USD_MICROS,
                               "finalAnswer": {"rule": V10_FINAL_RULE, "text": V10_FINAL_TEXT,
                                               "growthBp": V10_FINAL_GROWTH_BP,
                                               "lastLaneMarginBp": V10_LAST_LANE_MARGIN_BP},
                               "verifyJudgeReserve": {"text": V10_VERIFY_RESERVE_TEXT,
                                                      "judgeReserveBp": sweeps.JUDGE_RESERVE_BP}},
            "timeSec": {"ceiling": c, "cumulative": v10_time_slices(c)},
            "perAgent": {"investigatorTurns": policy.investigator_turns, "agentToolCalls": policy.agent_tool_calls,
                         "hostMaxCalls": tool_max_calls, "contextChars": policy.context_chars,
                         "toolOutputCharsPerAgent": budget["maxToolOutputTokensPerAgent"] * 3},
            "lanes": k}


def v10_identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int, profile: dict) -> dict:
    """The impact@v10 lane identity: the v3 lens texts, the alternate lanes, the alternate model, the budget split, the
    restatement-only merge and the (unchanged) v3 VERIFY rule."""
    alt = alternate(profile)
    return {"behavior": V10_BEHAVIOR, "crossModel": CROSS_BEHAVIOR, "v3Behavior": specialists.SPECIALIST_BEHAVIOR,
            "lensVersion": prompts.SPECIALIST_LENS_VERSION, "agents": list(V10_AGENTS),
            "altLanes": {a: prompts.lens_of(a) for a in V10_ALT_AGENTS},
            "alternateInvestigator": None if alt is None else {k: alt[k] for k in ("provider", "model", "family")},
            "budget": v10_budget_doc(policy, budget, tool_max_calls),
            "merge": {"v3Rule": specialists.MERGE_RULE, "rule": CROSS_MERGE_RULE, "text": V10_MERGE_TEXT,
                      "lineWindow": specialists.MERGE_LINE_WINDOW, "similarity": NEAR_DUP_SIMILARITY},
            "altLanesOptional": {"text": V10_ALT_OPTIONAL_TEXT, "cappedCodes": list(V10_CAPPED_CODES),
                                 "providerCodes": list(V10_OPTIONAL_PROVIDER_CODES),
                                 "laneTime": list(V10_LANE_TIME_PREFIXES), "noAnswer": NO_ALT_ANSWER},
            "verify": {"text": V10_VERIFY_TEXT, "maxCandidates": specialists.MAX_VERIFY_CANDIDATES}}
