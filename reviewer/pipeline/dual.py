"""investigator.impact@v21: v16's whole-change pass AND v20's agentic pass, a claim-aware union, and an AGENTIC verifier per
candidate (pure rules; the engine drives them in Engine._investigate_v21 and Engine.verify).

Why (tuning, match ids only): v16 one run 23 ids, v20 one run 19, v20 two runs 22, v16+v20 union 26. v16 and v20 are
different samplers (host context vs tool exploration), so their union adds recall; v20's tool grounding gave the best
precision, so v21 checks every candidate against the code with the same read-only tools.

Rule (BEHAVIOR):
  passes     PASSES run in turn: v16's reviewer `whole` exactly (whole.CONTEXT_RULE context with the host's head reads,
             V16_WHOLE_TASK, whole.HOPS hops, whole.READS reads, its schema-reask@1 re-ask; its requests carry NO
             params.agentic, so it is a plain claude-cli call), then v20's agentic reviewer `whole-agentic` exactly (the
             diffs only, V20_WHOLE_TASK, one hop, its re-asks incl. agentic-tool-reask@1, agentic.ADMISSION_RULE); both under
             deepcov's INVESTIGATE spend top;
  V1         a replay failure, cancellation, an internal error, a systemic code or an unknown provider outcome, a fatal
             stop or a spend book needing reconciliation fails INVESTIGATE at once; any other end of a pass without an
             answer is a note when the other pass answers (an agentic pass's second tool attempt included: the
             adapter marks it retryableByReask and nothing ran, although the gateway records its outcome as unknown);
             with no answer at all INVESTIGATE ends exactly as v16's;
  union      (UNION_RULE) the agentic pass's candidates in its order, then v16's; a candidate that restates an earlier kept
             one (lanes.cross_duplicate: same head path and category, near overlapping lines, similar claim) is dropped as
             merged before any verifier call (the earlier, i.e. the code-grounded agentic one, is kept; its sources grow);
             the kept ones are ordered: found by BOTH passes first, then single-source P0/P1, then the rest, each tier
             interleaved by rank within its pass (the agentic pass first at equal rank); at most MAX_VERIFY are verified
             ('over-cap' beyond);
  verify     (VERIFY_RULE) one agentic read-only session per candidate (verifier_spec(): VERIFIER_MAX_REQUESTS requests,
             VERIFIER_DEADLINE_SEC, VERIFIER_BUDGET_USD_MICROS PACING) on the host's starting context (the head window and
             the diff, as v16), one hop, with prompts.V21_VERIFY_RULE appended to the verifier task (refute-first; it
             confirms only with a cited concrete failure); single vote; v16's schema-reask@1 re-ask, and a session ended by a
             tool outside Read/Grep/Glob is re-asked once with prompts.V19_TOOL_NOTE (a second end is a note); a session
             that answers with context requests instead of a verdict is uncertain (a note);
  admission  (VERIFY_ADMISSION_RULE) a verifier session (and its re-ask) starts only while run spend + its worst case
             (VERIFIER_BUDGET_USD_MICROS x (1 + repairs)) fits below the JUDGE reserve floor (sweeps.judge_reserve_floor),
             else a typed budget stop for this and every later candidate; so VERIFY never eats the JUDGE reserve;
  clock      (CLOCK_RULE) no candidate or re-ask starts in VERIFY's last VERIFY_MARGIN_SEC (one verifier session; at most
             VERIFY_MARGIN_BP of the ceiling); what the VERIFY stage clock cuts is a disclosed note ('deadline'), so the run
             completes instead of going partial; the run's soft and hard deadlines and a cancellation keep v12's handling;
  unverified (UNVERIFIED_RULE) a session that ends WITHOUT a verdict or answer because the adapter stopped it at its
             agentic cap (AGENTIC_STOP_REASONS: request cap, session deadline, session budget), or an upstream HTTP 5xx
             (at most SERVER_ERROR_NOTES per run; a later one keeps its incomplete entry, so an outage stays partial),
             or (@2) an agentic isolation kill of an ISOLATION_NOTE_ITEMS kind (the CLI's extra user turn after its
             tool results: the work-dir audit, forwarder cap and refusals already passed, the output is discarded, the
             adapter stays enabled; at most ISOLATION_NOTES per run, a later one keeps its incomplete entry),
             is a disclosed note, never an incomplete entry: a verifier session's candidate is DROPPED (verdict failed,
             drop verifier-failed; fail closed for precision); the agentic INVESTIGATE pass contributes no candidates and
             v16's pass still counts (with no answer at all INVESTIGATE ends as before); other isolation kills, replay,
             cancel, internal and limit/latch ends keep their handling;
  JUDGE      v20's (judge-concrete@1, v16's dynamic cap).
"""

from __future__ import annotations

from . import agentic, deepcov, lanes, prompts, sweeps, whole

BEHAVIOR = "dual-pass-agentic-verify@1"
UNION_RULE = "dual-union@1"
MERGE_RULE = lanes.CROSS_MERGE_RULE
VERIFY_RULE = prompts.AGENTIC_VERIFY_VERSION
VERIFY_ADMISSION_RULE = "agentic-verify-admission@1"
CLOCK_RULE = "verify-clock@1"
UNVERIFIED_RULE = "verify-unverified@2"   # @2: + ISOLATION_NOTE_ITEMS
AGENTIC_STOP_REASONS = ("agentic-max-requests", "agentic-deadline", "agentic-budget")   # runtime.claude_agentic.STOP_REASONS
SERVER_ERROR_NOTES = 1                        # upstream HTTP 5xx session ends per run that are notes (UNVERIFIED_RULE)
ISOLATION_NOTE_ITEMS = ("extra-turn",)        # agentic isolation kills that are notes (UNVERIFIED_RULE @2); never
                                              # forbidden-work-entry (adapter disabled), extra-request, init-surface, forwarder:*
ISOLATION_NOTES = 1                           # such kills per run that are notes; a later one keeps its incomplete entry
V16_AGENT = whole.AGENT                       # v16's pass (plain requests)
AGENTIC_AGENT = whole.AGENT + "-agentic"      # v20's pass (the investigator role's params.agentic)
PASSES = (V16_AGENT, AGENTIC_AGENT)           # run order
UNION_ORDER = (AGENTIC_AGENT, V16_AGENT)      # union order: a duplicate keeps the code-grounded version
MAX_VERIFY = 16
VERIFIER_MAX_REQUESTS = 8
VERIFIER_DEADLINE_SEC = 180
VERIFIER_BUDGET_USD_MICROS = 500_000
VERIFY_MARGIN_SEC = VERIFIER_DEADLINE_SEC     # nothing new starts in VERIFY's last 180 s (one verifier session)
VERIFY_MARGIN_BP = 1500                       # ... at most 15% of the ceiling (live 1380 s: 180 s; legacy 45 s: 6 s)
HIGH = ("P0", "P1")

TEXT = ("v16's whole-change reviewer (host context, no tools, plain requests) then v20's agentic reviewer (Read/Grep/Glob, "
        "the broad task); the union keeps the agentic pass's version of a restated candidate, orders candidates found by "
        "both passes first, then P0/P1, then the rest, and verifies at most MAX_VERIFY; each candidate gets ONE agentic "
        "read-only verifier session (VERIFIER_MAX_REQUESTS requests, VERIFIER_DEADLINE_SEC, VERIFIER_BUDGET_USD_MICROS "
        "PACING) that tries to refute it and confirms only with a cited concrete failure; a verifier session starts only "
        "while it fits below the JUDGE reserve; nothing new starts in VERIFY's last VERIFY_MARGIN_SEC and what the VERIFY "
        "clock cuts is a note; a session the adapter stopped at its cap without a verdict (or one upstream 5xx, or one "
        "agentic extra-turn isolation kill, per run) is a note: the candidate is dropped, an agentic pass adds nothing; "
        "JUDGE as v20")


def verifier_spec() -> dict:
    """The params.agentic of a v21 verifier role (catalog.claude_cli_agentic_spec validates it)."""
    return {"mode": "read-only", "maxRequests": VERIFIER_MAX_REQUESTS, "sessionDeadlineSec": VERIFIER_DEADLINE_SEC,
            "budgetUsdMicros": VERIFIER_BUDGET_USD_MICROS}


def unverified_end(err) -> str | None:
    """UNVERIFIED_RULE: 'stop' for a provider-error the adapter typed as an agentic cap stop (AGENTIC_STOP_REASONS),
    'server-error' for a claude-cli upstream HTTP 5xx (errorType claude.server-error), 'isolation' for an agentic
    isolation-violation of an ISOLATION_NOTE_ITEMS kind that stayed within its request cap (integer requestsSent <=
    maxRequestsPerCall, as claude_agentic's violation() always reports), else None. Pure; the per-run
    SERVER_ERROR_NOTES / ISOLATION_NOTES counts are the engine's."""
    if not isinstance(err, dict) or err.get("code") != "provider-error":
        return None
    d = err.get("detail") if isinstance(err.get("detail"), dict) else {}
    if d.get("reason") in AGENTIC_STOP_REASONS:
        return "stop"
    s = d.get("httpStatus")
    if d.get("errorType") == "claude.server-error" and type(s) is int and 500 <= s <= 599:
        return "server-error"
    n, cap = d.get("requestsSent"), d.get("maxRequestsPerCall")
    if (d.get("reason") == "isolation-violation" and d.get("itemType") in ISOLATION_NOTE_ITEMS
            and type(n) is int and type(cap) is int and 0 <= n <= cap):
        return "isolation"
    return None


def plan_specialists() -> list[str]:
    return [V16_AGENT, AGENTIC_AGENT, agentic.PLAN_MARKER]


def is_v21_plan(plan: dict) -> bool:
    return plan.get("specialists") == plan_specialists()


def pass_agents(base: str) -> tuple:
    return (base, base + whole.REASK_SUFFIX)


def verify_slice(ceiling: int) -> int:
    """CLOCK_RULE: seconds into VERIFY after which nothing new starts."""
    return max(0, ceiling - min(VERIFY_MARGIN_SEC, ceiling * VERIFY_MARGIN_BP // 10_000))


def session_need(max_repairs: int) -> int:
    """VERIFY_ADMISSION_RULE: the worst case of one agentic verifier call (its session and up to one gateway repair)."""
    return VERIFIER_BUDGET_USD_MICROS * (1 + min(1, max(0, max_repairs)))


def union(passes: list[list], hyps: dict) -> tuple[list, dict, dict]:
    """UNION_RULE. `passes`: per pass in UNION_ORDER, [(hypothesis id, draft)] in that pass's order; `hyps`: the resolved
    Hypothesis documents by id (a draft that did not resolve is never merged). -> ([(id, draft)] kept in VERIFY order,
    then the merged ones; {merged id: kept id}; {kept id: sorted pass indexes that found it})."""
    flat = [(p, r, hid, d) for p, lane in enumerate(passes) for r, (hid, d) in enumerate(lane)]
    kept: list = []
    into: dict = {}
    sources: dict = {}
    for p, r, hid, d in flat:
        h = hyps.get(hid)
        k = None if h is None else next((x for x in kept if x[2] in hyps and lanes.cross_duplicate(hyps[x[2]], h)), None)
        if k is None:
            kept.append((p, r, hid, d))
            sources[hid] = {p}
        else:
            into[hid] = k[2]
            sources[k[2]].add(p)

    def tier(x) -> int:
        sev = (hyps.get(x[2]) or x[3]).get("suspectedSeverity")
        return 0 if len(sources[x[2]]) > 1 else 1 if sev in HIGH else 2
    ordered = sorted(kept, key=lambda x: (tier(x), x[1], x[0]))
    merged = [x for x in flat if x[2] in into]
    return ([(hid, d) for _, _, hid, d in ordered + merged], into,
            {hid: sorted(s) for hid, s in sources.items()})


def coverage_lines(payload: dict, events: list, drops: list) -> list[str]:
    """review.md disclosure of an impact@v21 run (pure): v16's lines (its pass's context), then the passes, the union,
    the agentic verifier, its admission, the VERIFY clock and the JUDGE rule."""
    lines = whole.coverage_lines(payload, events, drops)
    lines[0] = (f"- Dual-pass review ({BEHAVIOR}): passes `{V16_AGENT}` and `{AGENTIC_AGENT}`; " + TEXT + ".")
    calls = [e for e in events if e["type"] == "model.call"]
    inv = [e for e in calls if e["stage"] == "INVESTIGATE" and "agentic" in (e["request"].get("params") or {})]
    ver = [e for e in calls if e["stage"] == "VERIFY" and "agentic" in (e["request"].get("params") or {})]
    sessions = sorted({e["agentId"] for e in ver})
    tools = sum(1 for a in payload.get("agents", []) if agentic.is_tool_attempt(a.get("error")))
    vtools = sum(1 for e in ver if agentic.is_tool_attempt(e.get("error")))
    merged = sum(1 for d in drops if d["reason"] == "merged" and UNION_RULE in d.get("detail", ""))
    admit = sum(1 for d in drops if d["reason"] == "budget" and VERIFY_ADMISSION_RULE in d.get("detail", ""))
    cut = sum(1 for d in drops if d["reason"] == "deadline" and CLOCK_RULE in d.get("detail", ""))
    dropped = sum(1 for d in drops if d["reason"] == "below-threshold" and agentic.JUDGE_RULE in d.get("detail", ""))
    lines.append(f"- Passes: {len([e for e in calls if e['stage'] == 'INVESTIGATE' and e['agentId'] in pass_agents(V16_AGENT)])} "
                 f"call(s) of `{V16_AGENT}` (plain), {len(inv)} agentic session(s) of `{AGENTIC_AGENT}`; {tools} reviewer "
                 "session(s) ended by a tool outside Read/Grep/Glob (re-asked once).")
    lines.append(f"- Union ({UNION_RULE}): {merged} restatement(s) of an earlier candidate dropped as merged; candidates "
                 f"found by both passes first, then P0/P1; at most {MAX_VERIFY} verified.")
    lines.append(f"- Agentic verify ({VERIFY_RULE}): {len(sessions)} verifier session(s) (claude-cli-isolated@6, read-only, "
                 f"at most {VERIFIER_MAX_REQUESTS} requests and {VERIFIER_DEADLINE_SEC} s each), refute-first, single vote; "
                 f"{vtools} verifier session end(s) by a tool attempt (re-asked once with the tool note).")
    lines.append(f"- Verify admission ({VERIFY_ADMISSION_RULE}): {admit} candidate(s) not verified because a verifier "
                 "session no longer fit below the JUDGE reserve.")
    lines.append(f"- VERIFY clock ({CLOCK_RULE}): nothing new starts in the last {VERIFY_MARGIN_SEC} s of the VERIFY "
                 f"ceiling (at most {VERIFY_MARGIN_BP} bp of it); {cut} candidate(s) cut by the VERIFY clock (a note, the "
                 "run completes).")
    lines.append(f"- JUDGE rule ({agentic.JUDGE_RULE}): {dropped} finding(s) left out by the judge as without a concrete "
                 "wrong behaviour (dropped, not published).")
    return lines


def identity_doc(policy, budget: dict, tool_max_calls: int, comment_cap_base: int) -> dict:
    """Everything about impact@v21 that is not a template digest or v16's / v20's (bound into the config identity)."""
    return {"behavior": BEHAVIOR, "passes": list(PASSES), "unionOrder": list(UNION_ORDER), "text": TEXT,
            "union": {"rule": UNION_RULE, "merge": MERGE_RULE, "nearDup": lanes.NEAR_DUP_SIMILARITY,
                      "maxVerify": MAX_VERIFY, "high": list(HIGH)},
            "verify": {"rule": VERIFY_RULE, **verifier_spec(), "hops": agentic.HOPS},
            "admission": {"rule": VERIFY_ADMISSION_RULE, "sessionsPerCall": 2, "judgeReserveBp": sweeps.JUDGE_RESERVE_BP},
            "clock": {"rule": CLOCK_RULE, "marginSec": VERIFY_MARGIN_SEC, "marginBp": VERIFY_MARGIN_BP},
            "unverified": {"rule": UNVERIFIED_RULE, "stops": list(AGENTIC_STOP_REASONS), "serverErrorNotes": SERVER_ERROR_NOTES,
                           "isolationItems": list(ISOLATION_NOTE_ITEMS), "isolationNotes": ISOLATION_NOTES},
            "investigateTopBp": deepcov.INVESTIGATE_TOP_BP}
