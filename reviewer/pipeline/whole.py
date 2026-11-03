"""investigator.impact@v16: ONE whole-change reviewer (pure rules; the engine drives them in Engine._investigate_v16).
Primary investigator model only.

Why (held-out result, 2026-11-03): the multi-agent structure (lens lanes, coverage units, hunk ledger) did not
generalize; v16 tests whether one reviewer that sees the whole change does better. As simple as the engine allows.

Rule (BEHAVIOR):
  context    (CONTEXT_RULE) the PR title/body when supplied, the PREPARE diff of EVERY changed file (tests and docs
             included), then the head content of the changed files read by the host (read_file calls of the session
             HEAD_AGENT, at most READ_LINES lines and READ_CHARS characters each, never ending on a blank line), all
             within CONTEXT_CHARS excerpt characters: when the diffs alone exceed it, the largest diffs are left out
             first (then path order); the head files fill what is left smallest first, each up to an equal share of
             what remains, so the LARGEST files are cut first, to a line prefix. Every cut is listed in the
             model-visible wholeChange block and in review.md. No impact map, lanes, units, hunk questions, floors or
             merges;
  turns      one chain of at most HOPS hops (HOPS - 1 read turns, then the answer), at most READS requested reads;
  shares     its spend ceiling is deepcov's INVESTIGATE top (deepcov.spend_top, FINAL_RULE as every v12 agent); it
             runs until the INVESTIGATE ceiling (v12's clocks);
  answer     at most MAX_HYPOTHESES hypotheses, the first ones in the model's order (the rest are not candidates);
  V1         a systemic code or an unknown provider outcome (engine.v3_stops_later_specialists), or any end without a
             usable answer, fails INVESTIGATE: nothing later runs (as v12 with no usable lane);
  VERIFY     the candidates in output order, one verifier session each (deepcov.verifier_agent), at most
             deepcov.MAX_VERIFY, the JUDGE-reserve stop; JUDGE: deepcov.CAP_RULE (v12, unchanged);
  re-ask     (REASK_RULE) the frozen contract allows ONE gateway repair per logical call (ProfileRoleSpec maxRepairs <= 1,
             budget.effective_retry_limits) and a second call at the same hop of a Turn chain is a fork the trace
             checker refuses; so when the reviewer's or a verifier's chain ends with a REASK_CODES code, the host asks
             the same question ONCE more in a new session `<agent>` + REASK_SUFFIX (a fresh chain from hop 0; every
             call separately admitted, guarded and traced, with its own repair). A reviewer chain that a turn, read or
             context limit ends without an answer (a lone reviewer would leave the review empty) is re-asked the same
             way with REASK_EXHAUSTED_HOPS hop: its answer from the request context. The first end is then a note. A
             verifier re-ask that ends with a REASK_CODES code again drops the candidate as verifier-failed, a note
             (the run is not partial for one candidate's answer format); every other end keeps v12's handling.
"""

from __future__ import annotations

from . import deepcov, prompts

BEHAVIOR = "whole-change-review@1"
CONTEXT_RULE = prompts.WHOLE_CHANGE_VERSION
BUDGET_RULE = "whole-budget@1"
REASK_RULE = "schema-reask@1"
AGENT = "whole"
HEAD_AGENT = "whole.head"          # host session of the head-content reads
REASK_SUFFIX = "-reask"
CONTEXT_CHARS = 150_000            # diffs + head content, excerpt characters of the first request
READ_LINES = 400                   # reviewer.tools Limits.max_read_lines
READ_CHARS = 20_000                # per host read (Limits.max_output_chars is 24_000)
HOPS = 4                           # three read turns, then the answer
READS = 12
MAX_HYPOTHESES = 15
REASK_CODES = ("schema-invalid", "repair-exhausted")
REASK_EXHAUSTED_HOPS = 1           # a reviewer chain ended by a limit without an answer: re-asked for its answer only

TEXT = ("one reviewer: the PR text when supplied, every changed file's diff and the changed files' head content in "
        "one request of at most CONTEXT_CHARS excerpt characters (largest diffs out first beyond it; head files "
        "smallest first, each up to an equal share of what remains, so the largest are cut first, to a line prefix; "
        "every cut disclosed), at most HOPS hops and READS requested reads, deepcov's INVESTIGATE spend top, until the "
        "INVESTIGATE ceiling; at most MAX_HYPOTHESES hypotheses in the model's order; VERIFY in output order, one "
        "verifier session each, at most deepcov.MAX_VERIFY; JUDGE deepcov.CAP_RULE")
REASK_TEXT = ("a chain of the reviewer or a verifier that ends with schema-invalid or repair-exhausted is asked once "
              "more in a new session <agent>-reask (fresh chain; each call admitted, guarded, traced, with its own "
              "one repair); a reviewer chain ended by a turn, read or context limit without an answer is asked once "
              "more for its answer only (REASK_EXHAUSTED_HOPS hop); the first end is a note; a verifier re-ask that "
              "ends out of schema again drops the candidate as verifier-failed, a note; every other end keeps v12's "
              "handling")


def plan_specialists() -> list[str]:
    return [AGENT]


def is_v16_plan(plan: dict) -> bool:
    return plan.get("specialists") == plan_specialists()


def is_reask(agent: str) -> bool:
    return agent.endswith(REASK_SUFFIX)


def select_diffs(diffs: list[tuple[str, int]], budget: int | None = None) -> tuple[list[str], list[dict]]:
    """(shown paths in input order, [{path, chars}] not shown): the largest diffs (then path order) leave until the
    rest fits `budget` characters (default CONTEXT_CHARS, read at call time)."""
    budget = CONTEXT_CHARS if budget is None else budget
    total = sum(c for _, c in diffs)
    out: set = set()
    for p, c in sorted(diffs, key=lambda x: (-x[1], x[0])):
        if total <= budget:
            break
        out.add(p)
        total -= c
    return ([p for p, _ in diffs if p not in out], [{"path": p, "chars": c} for p, c in diffs if p in out])


def head_plan(files: list[tuple[str, list[int]]], budget: int) -> list[dict]:
    """[(path, [characters of each head line, newline included])] -> [{path, lines, shownLines, chars}] in input
    order: smallest files first, each up to an equal share of what is left, so the largest files are cut first (to
    a line prefix)."""
    left, n, out = max(0, budget), len(files), {}
    for i, (p, ls) in enumerate(sorted(files, key=lambda t: (sum(t[1]), t[0]))):
        share = left // (n - i)
        used = shown = 0
        for c in ls:
            if used + c > share:
                break
            used += c
            shown += 1
        out[p] = {"path": p, "lines": len(ls), "shownLines": shown, "chars": used}
        left -= used
    return [out[p] for p, _ in files]


def read_ranges(lines: list[str], shown: int) -> list[tuple[int, int]]:
    """1-based inclusive line ranges covering lines[:shown] in reads of at most READ_LINES lines and READ_CHARS
    characters, none ending on a blank line (a range ending on a blank line can never resolve as a code citation:
    engine.context_window); a blank tail is not read."""
    out, start = [], 1
    while start <= shown:
        end, chars = start - 1, 0
        while end < shown and end - start + 1 < READ_LINES and chars + len(lines[end]) + 1 <= READ_CHARS:
            chars += len(lines[end]) + 1
            end += 1
        end = max(end, start)                     # one over-long line still gets its own read
        last = end
        while last >= start and lines[last - 1] == "":
            last -= 1
        if last >= start:
            out.append((start, last))
        start = end + 1
    return out


def coverage_lines(payload: dict, events: list, drops: list) -> list[str]:
    """review.md disclosure of an impact@v16 run (pure, from the INVESTIGATE payload, the trace and VERIFY drops)."""
    block = None
    for e in events:
        if e["type"] == "model.call" and e["stage"] == "INVESTIGATE" and e["agentId"] in (AGENT, AGENT + REASK_SUFFIX):
            block = deepcov._doc(e).get("wholeChange")
            if isinstance(block, dict):
                break
    out = [f"- Whole-change review ({BEHAVIOR}): one reviewer `{AGENT}`; " + TEXT + "."]
    if isinstance(block, dict):
        cut = block.get("headFilesCut", [])
        out.append(f"- Context ({CONTEXT_RULE}): {block.get('diffsShown', 0)} diff(s) shown, "
                   f"{len(block.get('diffsNotShown', []))} not shown; {block.get('headFilesShownWhole', 0)} head "
                   f"file(s) shown whole, {len(cut)} cut; pull request text {block.get('pullRequestText')}.")
        out += [f"  - diff not shown: `{d['path']}` ({d['chars']} chars)" for d in block.get("diffsNotShown", [])[:20]]
        out += [f"  - head file cut: `{f['path']}` lines 1-{f['shownLines']} of {f['lines']}" for f in cut[:20]]
    for a in payload.get("agents", []):
        if a["status"] != "completed":
            err = a.get("error") or {}
            out.append(f"- `{a['agentId']}`: {a['status']}" + (f" ({err.get('code')})" if err else ""))
    n = sum(1 for a in payload.get("agents", []) if is_reask(a["agentId"]))
    v = sorted({e["agentId"] for e in events if e["type"] == "model.call" and e["stage"] == "VERIFY"
                and is_reask(e["agentId"])})
    failed = sum(1 for d in drops if d["reason"] == "verifier-failed" and REASK_RULE in d.get("detail", ""))
    out.append(f"- Re-ask ({REASK_RULE}): {REASK_TEXT}; reviewer re-asked {n} time(s); {len(v)} verifier "
               f"re-ask(s); {failed} candidate(s) dropped after their re-ask (a note).")
    return out


def identity_doc(policy, budget: dict, tool_max_calls: int, comment_cap_base: int) -> dict:
    """Everything about impact@v16 that is not a template digest (bound into the config identity)."""
    return {"behavior": BEHAVIOR, "agent": AGENT, "headAgent": HEAD_AGENT, "text": TEXT,
            "context": {"rule": CONTEXT_RULE, "chars": CONTEXT_CHARS, "readLines": READ_LINES, "readChars": READ_CHARS},
            "turns": {"hops": HOPS, "reads": READS, "maxHypotheses": MAX_HYPOTHESES},
            "budget": {"rule": BUDGET_RULE, "investigateTopBp": deepcov.INVESTIGATE_TOP_BP},
            "verify": {"rule": deepcov.VERIFY_RULE, "maxVerify": deepcov.MAX_VERIFY},
            "judge": {"rule": deepcov.CAP_RULE, "base": comment_cap_base, "maxComments": deepcov.MAX_COMMENTS,
                      "strongEvidence": list(deepcov.STRONG_EVIDENCE)},
            "reask": {"rule": REASK_RULE, "suffix": REASK_SUFFIX, "codes": list(REASK_CODES),
                      "exhaustedHops": REASK_EXHAUSTED_HOPS, "text": REASK_TEXT},
            "policy": {"runToolCalls": min(policy.run_tool_calls, budget["maxToolCalls"]), "hostMaxCalls": tool_max_calls}}
