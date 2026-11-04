"""investigator.impact@v19: impact@v16 with its one reviewer run as ONE agentic read-only claude-cli session
(claude-cli-isolated@6, reviewer.runtime.claude_agentic) and a JUDGE rule that leaves out findings without a concrete
wrong behaviour (pure rules; the engine drives them in Engine._investigate_v16 and Engine._judge_findings).

Why (held-out, one shot): v13 0.386 and v16 0.350 against comparators at 0.62-0.82; precision collapses on unseen
repositories and the host-mediated reads (at most 12) are the suspected limit; on held-out, P2 bugs were 3 of 14 true,
breaking-change remarks 0 of 5, performance remarks 0 of 3.

Rule (BEHAVIOR):
  admission  (ADMISSION_RULE) INVESTIGATE makes at most two agentic calls (the reviewer and its schema-reask@1 re-ask),
             each of at most two sessions (the call and its one gateway repair, each reserving BUDGET_USD_MICROS); a call
             is sent only while INVESTIGATE spend so far + session_need (BUDGET_USD_MICROS x (1 + repairs)) fits deepcov's
             INVESTIGATE top (6.5M of the 10M v19 ceiling), else it is a typed budget stop; so INVESTIGATE never spends past
             the top and VERIFY + JUDGE keep at least 3.5M (the re-ask runs only while the first call spent <= 2.5M);
  tools      (TOOL_REASK_RULE) a session the adapter ended because the model tried a tool outside Read/Grep/Glob, e.g. a
             `json` tool to emit its answer (is_tool_attempt: provider-error whose detail.reason is TOOL_ATTEMPT_REASON with
             retryableByReask, claude_agentic ecdc1f1; nothing ran) is re-asked like schema-reask@1: ONE fresh session
             `whole-reask` whose task ends with prompts.V19_TOOL_NOTE, under ADMISSION_RULE; the first end is a note
             (review.md counts it); a second end of any kind fails INVESTIGATE (V1);
  session    the investigator role of a v19 profile carries params.agentic = spec() (catalog.claude_cli_agentic_spec:
             read-only, MAX_REQUESTS relayed requests, SESSION_DEADLINE_SEC, BUDGET_USD_MICROS PACING, which the gateway
             reserves for the call); a v19 profile needs a claude-cli investigator (refused otherwise) and the live host
             opens the claude-cli adapter with agentic=True and the run's PR snapshot (head and base exported from the
             pinned imports to a private directory outside home and the repository, removed after the run); the CLI
             explores with Read/Grep/Glob only, inside its sandbox, and answers once;
  request    v16's reviewer (agent `whole`): the PR text, the PREPARE diff of every changed file within
             whole.CONTEXT_CHARS (largest out first, uncollected ones listed) and the wholeChange block, but NO host head
             reads (the session reads what it needs), the agenticReview block and V19's task; one hop (the Turn request
             is its last turn); at most whole.MAX_HYPOTHESES hypotheses; v16's schema-reask@1 re-ask (a second session);
  VERIFY     v16's (non-agentic verifier, one vote, cap deepcov.MAX_VERIFY);
  JUDGE      (JUDGE_RULE) the judge sees every surviving finding with prompts.V19_JUDGE_RULE appended to its task; a
             finding its valid output leaves out is dropped as 'below-threshold' (disclosed) before v16's dynamic cap;
             when the judge is unavailable or its output is rejected, nothing is dropped (deterministic wording, as v16);
  ceiling    v19 Plans carry repository_profile.V19_RUN_CEILING_USD_MICROS ($10, CC_AUTH_V2), and the live hosts accept
             exactly that for a v19 Plan (every other Plan keeps the pilot ceiling); v12's clocks (INVESTIGATE 1800 s live:
             a 900 s session and its re-ask).

investigator.impact@v20 (BROAD_RULE) is v19 with ONE change: the reviewer's task is prompts.V20_WHOLE_TASK, v16's broad
task (every issue a senior reviewer would raise: defects, API/contract, missing tests, performance, documentation; up to
whole.MAX_HYPOTHESES, each with severity, a changed-line location and a concrete reason) plus "use the read tools to
confirm each claim against the code before reporting it". Why (11 tuning PRs x 2): v19 had the best precision (.50/.67)
but proposed 21-23 hypotheses against v16's 58-62, so it was too conservative at generation. The session, admission,
re-asks, VERIFY, the JUDGE rule and the $10 ceiling are v19's (same Plan); review.md and the config identity say which
task ran.
"""

from __future__ import annotations

from . import deepcov, prompts, whole

BEHAVIOR = "agentic-whole-review@1"
SESSION_RULE = prompts.AGENTIC_REVIEW_VERSION
JUDGE_RULE = prompts.JUDGE_CONCRETE_VERSION
AGENT = whole.AGENT
PLAN_MARKER = "agentic"
MAX_REQUESTS = 30                 # catalog.CLAUDE_CLI_AGENTIC_MAX_REQUESTS
SESSION_DEADLINE_SEC = 900        # catalog.CLAUDE_CLI_AGENTIC_MAX_DEADLINE_SEC
BUDGET_USD_MICROS = 2_000_000     # PACING per session (gate-v19 B1): see ADMISSION_RULE
ADMISSION_RULE = "agentic-admission@1"
TOOL_REASK_RULE = prompts.TOOL_REASK_VERSION
TOOL_ATTEMPT_REASON = "agentic-tool-attempt"    # claude_agentic (ecdc1f1): error.detail.reason of the kill, retryableByReask
HOPS = 1
BROAD_RULE = prompts.AGENTIC_BROAD_VERSION       # investigator.impact@v20 only: the broad task with the confirm rule

TEXT = ("one agentic read-only claude-cli session (Read/Grep/Glob over the PR snapshot, at most MAX_REQUESTS requests "
        "within SESSION_DEADLINE_SEC and BUDGET_USD_MICROS PACING) with v16's diff context and no host head reads; at most "
        "two agentic calls (the reviewer and its re-ask), each of at most two sessions (the call and its repair), each "
        "call sent only while INVESTIGATE spend + BUDGET_USD_MICROS x 2 fits deepcov's INVESTIGATE top; a session "
        "ended by a tool outside Read/Grep/Glob is re-asked once with the tool note; one "
        "answer of at most whole.MAX_HYPOTHESES hypotheses, v16's re-ask; VERIFY as v16; the judge leaves out findings "
        "without a concrete wrong behaviour and the host drops them (below-threshold) before v16's cap")


def spec() -> dict:
    """The params.agentic of a v19 investigator role (catalog.claude_cli_agentic_spec validates it)."""
    return {"mode": "read-only", "maxRequests": MAX_REQUESTS, "sessionDeadlineSec": SESSION_DEADLINE_SEC,
            "budgetUsdMicros": BUDGET_USD_MICROS}


def is_tool_attempt(err: dict | None) -> bool:
    """TOOL_REASK_RULE: the adapter ended the session because the model tried a tool outside Read/Grep/Glob (nothing ran;
    claude_agentic marks the kill reason TOOL_ATTEMPT_REASON, retryableByReask)."""
    if not isinstance(err, dict):
        return False
    d = err.get("detail") if isinstance(err.get("detail"), dict) else {}
    return (err.get("code") == "provider-error" and d.get("reason") == TOOL_ATTEMPT_REASON
            and d.get("retryableByReask") is True)


def session_need(request: dict, max_repairs: int) -> int:
    """ADMISSION_RULE: the worst case of one agentic call (its session and up to one gateway repair session), 0 when the
    request is not agentic."""
    a = (request.get("params") or {}).get("agentic") if isinstance(request, dict) else None
    return a["budgetUsdMicros"] * (1 + min(1, max(0, max_repairs))) if isinstance(a, dict) else 0


def plan_specialists() -> list[str]:
    return [AGENT, PLAN_MARKER]


def is_v19_plan(plan: dict) -> bool:
    return plan.get("specialists") == plan_specialists()


def is_agentic_profile(profile: dict) -> bool:
    """A profile with at least one role in agentic mode (the live host must give the adapter a PR snapshot)."""
    return any(isinstance(r.get("params"), dict) and "agentic" in r["params"]
               for r in [*profile["roles"].values(), *profile.get("alternates", {}).values()])


def coverage_lines(payload: dict, events: list, drops: list) -> list[str]:
    """review.md disclosure of an impact@v19 run (pure): v16's lines, then the session and the JUDGE rule."""
    lines = whole.coverage_lines(payload, events, drops)
    lines[0] = f"- Agentic whole-change review ({BEHAVIOR}): one reviewer `{AGENT}`; " + TEXT + "."
    calls = [e for e in events if e["type"] == "model.call" and e["stage"] == "INVESTIGATE"]
    agentic = [e for e in calls if isinstance(e["request"].get("params"), dict) and "agentic" in e["request"]["params"]]
    dropped = sum(1 for d in drops if d["reason"] == "below-threshold" and JUDGE_RULE in d.get("detail", ""))
    tools = sum(1 for a in payload.get("agents", []) if is_tool_attempt(a.get("error")))
    broad = any(e["request"].get("promptVersion") == prompts.INVESTIGATOR_IMPACT_V20_PROMPT for e in agentic)
    lines.append(f"- Session ({SESSION_RULE}): {len(agentic)} agentic session(s) (claude-cli-isolated@6, read-only, at "
                 f"most {MAX_REQUESTS} requests and {SESSION_DEADLINE_SEC} s each).")
    if broad:                                    # impact@v20 only => v19's review.md is unchanged
        lines.append(f"- Task ({BROAD_RULE}): the reviewer was asked for every issue a senior reviewer would raise "
                     "(defects, API and contract, missing tests, performance, documentation) and to confirm each claim "
                     "against the code with the read tools before reporting it.")
    lines.append(f"- Tool re-ask ({TOOL_REASK_RULE}): {tools} session(s) ended because the model tried a tool outside "
                 "Read/Grep/Glob (nothing ran); each first one is re-asked once in a fresh session told which tools exist.")
    lines.append(f"- JUDGE rule ({JUDGE_RULE}): {dropped} finding(s) left out by the judge as without a concrete wrong "
                 "behaviour (dropped, not published).")
    return lines


def identity_doc(policy, budget: dict, tool_max_calls: int, comment_cap_base: int) -> dict:
    """Everything about impact@v19 that is not a template digest or v16's (bound into the config identity); impact@v20
    adds its task rule (absent for v19 => v19 run ids are unchanged)."""
    doc = {"behavior": BEHAVIOR, "agent": AGENT, "planMarker": PLAN_MARKER, "text": TEXT, "hops": HOPS,
            "session": {"rule": SESSION_RULE, **spec()}, "judge": {"rule": JUDGE_RULE, "dropReason": "below-threshold"},
            "toolReask": {"rule": TOOL_REASK_RULE, "code": "provider-error",
                          "detail": {"reason": TOOL_ATTEMPT_REASON, "retryableByReask": True}},
            "admission": {"rule": ADMISSION_RULE, "maxAgenticCalls": 2, "sessionsPerCall": 2,
                          "investigateTopBp": deepcov.INVESTIGATE_TOP_BP},
            "verify": {"rule": deepcov.VERIFY_RULE, "maxVerify": deepcov.MAX_VERIFY},
            "whole": whole.identity_doc(policy, budget, tool_max_calls, comment_cap_base)}
    if policy.broad_agentic:
        doc["task"] = {"rule": BROAD_RULE, "prompt": prompts.INVESTIGATOR_IMPACT_V20_PROMPT}
    return doc
