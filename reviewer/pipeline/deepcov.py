"""investigator.impact@v12: coverage-forced deep investigation (pure rules; the engine drives them in
Engine._investigate_v12, Engine.verify and Engine._judge_findings). Primary investigator model only.

Why (gold-blind funnel of impact@v3 on 12 PRs): the run is hypothesis-limited, not budget-limited. Every lane answered
within 1-2 hops after at most one batch of reads (one 28-file PR: no read at all), hypotheses touched 13 of 57 changed
files on the held-out PRs, VERIFY refuted nothing, and no spend, time or tool cap bound. v12 keeps the three v3 lenses
and adds (1) COVERAGE: one coverage investigator per unit of a deterministic partition of the changed files, required
to read each of its files and their immediate context, and (2) DEPTH: a host-enforced floor of request turns and reads
before an answer is accepted, with prompts that ask for several candidate defects per file, each with a concrete
failing scenario.

How v12 differs from impact@v4 (diff-shard sweeps) and impact@v6 (hunk audit), which did not beat v3 on the dev set:
  * v4 let a sweep satisfy coverage by DECLARING a file examined (file_disposition, a one-line reason, no read
    needed), with 12 reads for up to 10 files, no exploration floor, and a spend cap whose exhaustion was an
    INVESTIGATE `budget` incomplete entry (the 28-file PR became partial and unscorable). v12 has no disposition tool:
    a file counts as examined only when the trace shows its coverage investigator READ it (read_file of the head file)
    and read context beyond its own files; the floor re-prompts until that holds or nothing is left to read.
  * v6 audited diff hunks line by line with the hunk text only and a pooled allowance of about 20 reads, i.e. without
    the callers, callees and siblings that decide the miss categories (sibling guard omission, a callee contract under
    another flag, copy-paste across repeated blocks); it also ran on v5's lanes and lossy merge. v12 units are
    file-group investigators with the impact tools, per-unit read shares that grow with the unit's files, and the v3
    lenses (not v5's) with v3's merge for the lens lanes only.
  * Both ended a capped lane with a `budget` incomplete entry. v12 sends an agent's hop as its final-answer turn
    before its spend share is used up (FINAL_RULE), so a lane or unit always answers, and an own-cap or provider end of
    a coverage investigator is a disclosed coverage note, not an incomplete run.

Partition (PARTITION_RULE). PREPARE's changed files in path order; a file is SKIPPED, with its reason, when it is
deleted, generated (reviewer.impactmap.is_generated: lockfiles, minified, codegen, vendored), has no text diff, has no
code change (only blank or re-indented lines), is documentation (DOC_EXTENSIONS), is a localisation catalogue, or is a
test file (TEST rules) while the change also has non-test eligible files. The rest are ELIGIBLE and every eligible file
is in exactly one unit: k = min(MAX_UNITS, n, max(ceil(n / UNIT_MAX_FILES), ceil(chars / UNIT_DIFF_CHARS))) units of
consecutive files (siblings in one directory stay together), balanced by weight = diff chars + FILE_WEIGHT_CHARS. Agent
ids cover-01.. . Coverage invariant: changed files = eligible (in a unit) + skipped (with a reason), disjoint.

Budget (BUDGET_RULE), every number a fraction of the Plan's run ceiling C (maxUsd), on the engine's own spend
estimate (the one the $4 ceiling and the gateway's investigation share are checked against):
  INVESTIGATE  all agents together start no model call once INVESTIGATE spend reaches spend_top = min(investigation
               share, INVESTIGATE_TOP_BP of C) (65%: $2.60 of $4), so VERIFY + JUDGE keep >= 35% ($1.40), more than
               v3's floor (the 30% verify reserve, $1.20);
  lens lanes   lane i (contracts, logic, safety) may start a call while INVESTIGATE spend < its ceiling, a FAIR SHARE
               of what is left of lens_top = LENS_SPEND_BP of C (30%: $1.20) when it starts: S + (lens_top - S)//(3 - i),
               S = INVESTIGATE spend at its start (from the logged cost records, so replay re-derives it); unused room
               and an earlier lane's final-turn overshoot spread evenly over the later lanes; a lens lane always gets at
               least its final-answer turn (ceiling >= S + 1), as v3 lanes never end at a spend share;
  units        unit j (of k) likewise: S + (spend_top - S)//(k - j); a unit that starts with no room left is not run
               (a coverage note);
  final turn   (FINAL_RULE) with r = the gateway's worst-case reservation of the next request (on the Terra arm the
               charge IS that reservation: the Codex CLI reports no cache-write count, so settle() charges max(reserve,
               partial)), an agent explores while spent + r <= its ceiling; otherwise its hop is sent as its
               final-answer turn (no tools run), so it answers instead of ending at its share. That final call may end
               above the ceiling by one call; later agents' fair shares absorb it and the gateway's
               investigation-share admission (70%: $2.80) bounds all of INVESTIGATE, so VERIFY + JUDGE always keep at
               least v3's floor;
  reads        lens lane i may start a tool call while INVESTIGATE requested reads < LENS_TOOL_CALLS*(i+1); unit j while
               they are below base + sum over units <= j of (UNIT_BASE_READS + UNIT_READS_PER_FILE * files), base =
               requested reads when the units start (re-shown earlier reads of a continuation are host calls of their
               own session and do not count); the per-agent and run caps still bind;
  time         lane i stops at L*(i+1)//3 s, L = LENS_TIME_BP of the INVESTIGATE ceiling T; unit j at L + (T-L)*(j+1)//k s.
VERIFY keeps the JUDGE reserve (sweeps.JUDGE_RESERVE_BP, 7.5% of C).

Depth floor (FLOOR_RULE), checked on every final answer of a v12 agent against the logged trace:
  lens lane  >= LENS_FLOOR_TURNS request turn(s) that ran at least one read and >= LENS_FLOOR_READS distinct executed
             reads (a repeated request is answered from the earlier result and is not a read);
  unit       >= UNIT_FLOOR_TURNS request turns and >= max(UNIT_FLOOR_READS, 2 * files) distinct reads, every unit file
             read with read_file on the head side, and >= min(files, UNIT_CONTEXT_READS) reads beyond its own files.
Unmet and not waived: the answer is a DRAFT; the host sends a depth continuation chain (prompts.V12_FLOOR_CONTINUATION
with the unmet list and the draft), at most MAX_CONTINUATIONS per agent, CONTINUATION_HOPS hops each. A continuation is
a new retrieval chain (a final hop cannot be continued), so the agent's earlier reads are RE-SHOWN as host-prepared
calls of the session `<agent>.reread` (at most REREAD_MAX calls, REREAD_CHARS characters): they stay citable. Waivers
(the answer is accepted as it stands; "nothing left to read"), all derived from the logged trace: `continuations`
(MAX_CONTINUATIONS used), `turns` (fewer than 2 turns left), `spend` (the answer was a forced final-answer turn),
`tool-calls` (no tool call left when it answered), `context-chars` (context budget used up), `nothing-new` (its last
request turn ran no new read). A continuation that ends without a final answer leaves the draft in force.

Merge (MERGE_TEXT). The lens lanes exactly as v3 (specialists.merge, specialist-merge@2); then each unit hypothesis
merges into the first kept hypothesis of an earlier agent only when it RESTATES it (lanes.cross_duplicate: the v3
predicate AND overlapping ranges, claim Jaccard >= 0.5, identical code-like tokens), recorded under that predicate's
contract id cross-model-merge@1; otherwise it is kept and verified on its own.

VERIFY (VERIFY_RULE). The lens candidates exactly in v3's order (round-robin, output order, v3's merge retry), then the
units' kept candidates round-robin across units, each unit's by value (lanes.value_key: severity, confidence, output
order); at most MAX_VERIFY candidates (`over-cap` beyond). EVERY verified candidate gets its own verifier session
(verifier-01, verifier-02, ...), so the per-agent tool-output limit (maxToolOutputTokensPerAgent) applies per
hypothesis and an early candidate can no longer starve later ones. A JUDGE-reserve stop that cuts only unit candidates
is a coverage note; one that cuts a lens candidate is a VERIFY budget incomplete entry (as v10 for its v3 lanes).

Comment cap (CAP_RULE). Comments ranked as v3 (severity, then independently validated evidence strength); the first
`base` (HostConfig.comment_cap, 5) as v3; further ones, up to MAX_COMMENTS (8), only while the next ranked comment is P0
or P1 AND its evidence strength is one of STRONG_EVIDENCE. Every v3 precision rule (verification, citations, anchors,
dedup, severity ceiling) is unchanged.
"""

from __future__ import annotations

import json
import re

from reviewer import impactmap
from reviewer.contracts import usable_output
from reviewer.contracts.budget import investigation_limit, stage_ceiling
from reviewer.contracts.entities import CROSS_MERGE_VERSION
from reviewer.contracts.severity import RANK

from . import lanes, prompts, retrieval, specialists, sweeps

BEHAVIOR = "coverage-forced-deep@1"
PARTITION_RULE = "coverage-partition@1"
BUDGET_RULE = "deep-budget-split@1"
FINAL_RULE = "deep-final-answer@1"
FLOOR_RULE = prompts.DEPTH_FLOOR_VERSION
VERIFY_RULE = "deep-verify@1"
CAP_RULE = "dynamic-comment-cap@1"
MERGE_RULE = CROSS_MERGE_VERSION
PLAN_MARKER = "coverage-units"
LENS_AGENTS = prompts.SPECIALIST_AGENTS
UNIT_PREFIX = "cover-"
REREAD_SUFFIX = ".reread"

# ---- partition
MAX_UNITS = 4
UNIT_MAX_FILES = 4
UNIT_DIFF_CHARS = 16_000
FILE_WEIGHT_CHARS = 1_500
MAX_RANGES = 20
DOC_EXTENSIONS = (".md", ".mdx", ".rst", ".txt", ".adoc", ".asciidoc")
DOC_NAMES = ("changelog", "changes", "license", "licence", "notice", "authors", "contributors", "codeowners")
L10N_DIRS = frozenset({"locales", "locale", "i18n", "l10n", "translations", "lang", "langs"})
L10N_EXTENSIONS = (".json", ".properties", ".po", ".pot", ".yml", ".yaml", ".xliff", ".xlf", ".strings", ".arb",
                   ".resx", ".ftl")
_L10N_NAME = re.compile(r"^messages(_[a-z]{2,3}([_-][a-z0-9]{2,4})?)?\.properties$", re.I)
TEST_DIRS = frozenset({"test", "tests", "__tests__", "testsuite", "spec", "specs", "__mocks__", "testing", "e2e"})
_TEST_NAME = re.compile(r"^(test_.*\.py|.*_test\.(py|go|rb|js|ts|jsx|tsx)|conftest\.py|.*tests?\.(java|kt|cs|swift|scala)"
                        r"|.*\.(test|spec|mock)\.[cm]?[jt]sx?|.*_spec\.rb)$", re.I)
SKIP_REASONS = ("deleted", "generated", "no-text-diff", "no-code-change", "docs", "localisation", "tests")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# ---- budget (basis points of the Plan's run ceiling)
INVESTIGATE_TOP_BP = 6500
LENS_SPEND_BP = 3000
LENS_TOOL_CALLS = 16
UNIT_BASE_READS = 6
UNIT_READS_PER_FILE = 3
LENS_TIME_BP = 4000

# ---- depth floor
LENS_FLOOR_TURNS = 1
LENS_FLOOR_READS = 6
UNIT_FLOOR_TURNS = 2
UNIT_FLOOR_READS = 8
UNIT_CONTEXT_READS = 4
MAX_CONTINUATIONS = 2
CONTINUATION_HOPS = 4
REREAD_MAX = 12
REREAD_CHARS = 48_000
NOT_READS = ("denied", "unavailable")
WAIVERS = ("continuations", "turns", "spend", "tool-calls", "context-chars", "nothing-new")

# ---- VERIFY and JUDGE
MAX_VERIFY = 32
MAX_COMMENTS = 8
STRONG_EVIDENCE = ("reproduced", "analyzer", "verifier-traced")
EXTRA_SEVERITIES = ("P0", "P1")

FLOOR_TEXT = (f"lens lane: >= {LENS_FLOOR_TURNS} request turn(s) that ran a read and >= {LENS_FLOOR_READS} distinct "
              f"executed reads; coverage unit: >= {UNIT_FLOOR_TURNS} such turns, >= max({UNIT_FLOOR_READS}, 2 x files) "
              "distinct reads, every unit file read with read_file (head), >= min(files, "
              f"{UNIT_CONTEXT_READS}) reads beyond the unit's files; otherwise the answer is a draft and comes back "
              f"(at most {MAX_CONTINUATIONS} times) unless no turn, tool call, context or spend is left or the last "
              "request turn ran no new read")
PARTITION_TEXT = ("changed files in path order; skipped with a reason: deleted, generated, no text diff, no code change, "
                  "docs, localisation, tests (only while non-test files are eligible); eligible files in k = min("
                  "MAX_UNITS, n, max(ceil(n/UNIT_MAX_FILES), ceil(chars/UNIT_DIFF_CHARS))) consecutive units balanced "
                  "by diff chars + FILE_WEIGHT_CHARS")
BUDGET_TEXT = ("INVESTIGATE < min(investigation share, INVESTIGATE_TOP_BP of the ceiling); lens lane i < S + (lens_top - "
               "S)//(3 - i) (at least S + 1), lens_top = LENS_SPEND_BP of the ceiling; unit j < S + (top - S)//(k - j); "
               "S = INVESTIGATE spend when the agent starts; an agent's hop is its final-answer turn when "
               "spent + r > its ceiling (that call may end above it by one call); reads: lens LENS_TOOL_CALLS each, unit UNIT_BASE_READS + UNIT_READS_PER_FILE "
               "x files, cumulative; time: lenses split LENS_TIME_BP of the INVESTIGATE ceiling, units the rest; VERIFY "
               "keeps the JUDGE reserve")
MERGE_TEXT = ("lens lanes merged exactly as v3 (specialist-merge@2); a unit hypothesis merges into the first kept "
              "hypothesis of an earlier agent only when it restates it (lanes.cross_duplicate, recorded as "
              "cross-model-merge@1); otherwise it is kept")
VERIFY_TEXT = ("lens candidates in v3 order with v3's merge retry, then unit candidates round-robin across units, each "
               "unit by value; at most MAX_VERIFY; one verifier session per verified candidate; a JUDGE-reserve stop "
               "cutting only unit candidates is a coverage note")
CAP_TEXT = ("rank as v3 (severity, evidence strength); the first `base` comments as v3; more, up to MAX_COMMENTS, only "
            "while the next ranked comment is P0/P1 with evidence strength in STRONG_EVIDENCE")


# ---------------------------------------------------------------- plan, ids

def plan_specialists() -> list[str]:
    return list(LENS_AGENTS) + [PLAN_MARKER]


def is_v12_plan(plan: dict) -> bool:
    return plan.get("specialists") == plan_specialists()


def unit_id(j: int) -> str:
    return f"{UNIT_PREFIX}{j + 1:02d}"


def is_unit(agent: str) -> bool:
    return agent.startswith(UNIT_PREFIX) and agent[len(UNIT_PREFIX):].isdigit()


def agent_order(agents) -> list[str]:
    """Merge order: the lens lanes, then the units in id order."""
    units = sorted({a for a in agents if is_unit(a)}, key=lambda a: int(a[len(UNIT_PREFIX):]))
    return list(LENS_AGENTS) + units


def verifier_agent(position: int) -> str:
    """The verifier session (agent id) of the position-th verified candidate (0-based): one per candidate."""
    return f"verifier-{position + 1:02d}"


# ---------------------------------------------------------------- partition

def is_test(path: str) -> bool:
    parts = path.lower().split("/")
    return any(p in TEST_DIRS for p in parts[:-1]) or bool(_TEST_NAME.match(path.rsplit("/", 1)[-1]))


def _file_reason(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1]
    low = name.lower()
    stem = low.rsplit(".", 1)[0]
    if impactmap.is_generated(path):
        return "generated"
    if low.endswith(DOC_EXTENSIONS) or stem in DOC_NAMES:
        return "docs"
    parts = path.lower().split("/")
    if (low.endswith(L10N_EXTENSIONS) and any(p in L10N_DIRS for p in parts[:-1])) or _L10N_NAME.match(name):
        return "localisation"
    return None


def diff_rows(ev: dict) -> list[str]:
    """The unified-diff rows of a logged PREPARE per-file diff result (header lines dropped)."""
    out = []
    for e in ev["result"]["evidence"]:
        for line in e["excerpt"].split("\n"):
            if line.startswith("# ") or line.startswith("--- ") or line.startswith("+++ "):
                continue
            out.append(line)
    return out


def changed_ranges(rows: list[str]) -> list[list[int]]:
    """Head line ranges of the hunks ([start, end], 1-based, merged when adjacent; at most MAX_RANGES)."""
    out: list[list[int]] = []
    for r in rows:
        m = _HUNK.match(r)
        if m is None:
            continue
        start, n = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
        a, b = max(1, start), max(1, start + max(n, 1) - 1)
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out[:MAX_RANGES]


def code_changed(rows: list[str]) -> bool:
    """False when the diff changes no code: no row, or only blank lines and pure re-indentation."""
    added = sorted(r[1:].strip() for r in rows if r.startswith("+"))
    removed = sorted(r[1:].strip() for r in rows if r.startswith("-"))
    added, removed = [x for x in added if x], [x for x in removed if x]
    return bool(added or removed) and added != removed


def plan(files: list[dict], diffs: dict) -> dict:
    """The deterministic coverage plan, a pure function of the PREPARE payload's file list and its logged per-file
    `diff` tool.call events (path -> event): {"units": [{agentId, files: [{path, status, changedHeadLines}],
    diffChars}], "skipped": [{path, reason}], "eligible": n, "changed": total}. Every changed file is in exactly one
    unit or in `skipped`."""
    cand, skipped = [], []
    for f in sorted(files, key=lambda f: f["path"]):
        p, ev = f["path"], diffs.get(f["path"])
        if f["status"] == "deleted":
            skipped.append({"path": p, "reason": "deleted"})
            continue
        reason = _file_reason(p)
        if reason is None and (ev is None or ev["result"]["status"] not in sweeps.TEXT_DIFF_STATUSES
                               or not ev["result"]["evidence"]):
            reason = "no-text-diff"
        rows = [] if reason is not None else diff_rows(ev)
        if reason is None and not code_changed(rows):
            reason = "no-code-change"
        if reason is not None:
            skipped.append({"path": p, "reason": reason})
            continue
        chars = sum(len(x["excerpt"]) for x in ev["result"]["evidence"])
        cand.append({"path": p, "status": f["status"], "changedHeadLines": changed_ranges(rows), "chars": chars})
    if any(not is_test(c["path"]) for c in cand):
        skipped += [{"path": c["path"], "reason": "tests"} for c in cand if is_test(c["path"])]
        cand = [c for c in cand if not is_test(c["path"])]
    groups = partition([(c["path"], c["chars"]) for c in cand])
    by = {c["path"]: c for c in cand}
    units = [{"agentId": unit_id(j),
              "files": [{k: by[p][k] for k in ("path", "status", "changedHeadLines")} for p, _ in g],
              "diffChars": sum(c for _, c in g)} for j, g in enumerate(groups)]
    return {"rule": PARTITION_RULE, "units": units, "skipped": sorted(skipped, key=lambda s: s["path"]),
            "eligible": len(cand), "changed": len(files)}


def unit_count(n: int, chars: int) -> int:
    if n == 0:
        return 0
    return min(MAX_UNITS, n, max(1, -(-n // UNIT_MAX_FILES), -(-chars // UNIT_DIFF_CHARS)))


def partition(files: list[tuple[str, int]]) -> list[list[tuple[str, int]]]:
    """Consecutive groups of (path, chars), balanced by weight, none empty (pure, order-preserving)."""
    n = len(files)
    k = unit_count(n, sum(c for _, c in files))
    out, i = [], 0
    weight = [c + FILE_WEIGHT_CHARS for _, c in files]
    for g in range(k):
        left = k - g
        if left == 1:
            out.append(files[i:])
            break
        target = -(-sum(weight[i:]) // left)
        take, acc = [files[i]], weight[i]
        i += 1
        while i < n and n - i > left - 1 and acc + weight[i] <= target:
            take.append(files[i])
            acc += weight[i]
            i += 1
        out.append(take)
    return out


# ---------------------------------------------------------------- budgets

def _bp(budget: dict, bp: int) -> int:
    return budget["maxUsdMicros"] * bp // 10_000


def spend_top(budget: dict) -> int:
    return min(investigation_limit(budget), _bp(budget, INVESTIGATE_TOP_BP))


def lens_top(budget: dict) -> int:
    return min(spend_top(budget), _bp(budget, LENS_SPEND_BP))


def agent_ceiling(unit: bool, j: int, spent: int, budget: dict, k: int) -> int:
    """BUDGET_RULE: the INVESTIGATE spend ceiling of the j-th agent (0-based) of its phase (the k = 3 lens lanes, or
    the k units) that starts when INVESTIGATE has spent `spent`: a fair share of what is left of its phase's top."""
    top = spend_top(budget) if unit else lens_top(budget)
    fair = spent + max(0, top - spent) // (k - j)
    return fair if unit else max(fair, spent + 1)


def lens_tool_cumulative() -> list[int]:
    return [LENS_TOOL_CALLS * (i + 1) for i in range(len(LENS_AGENTS))]


def unit_reads(files: int) -> int:
    return UNIT_BASE_READS + UNIT_READS_PER_FILE * files


def unit_tool_ceilings(base: int, file_counts: list[int]) -> list[int]:
    out, acc = [], base
    for n in file_counts:
        acc += unit_reads(n)
        out.append(acc)
    return out


def time_slices(ceiling: int | None, k: int) -> tuple[list | None, list | None]:
    """(lens slices, unit slices): cumulative seconds since INVESTIGATE started."""
    if ceiling is None:
        return None, None
    lens = ceiling * LENS_TIME_BP // 10_000
    return ([lens * (i + 1) // len(LENS_AGENTS) for i in range(len(LENS_AGENTS))],
            [lens + (ceiling - lens) * (j + 1) // k for j in range(k)])


def final_answer_due(spent: int, ceiling: int, r: int) -> bool:
    """FINAL_RULE: this hop's worst case no longer fits under the agent's ceiling, so it is sent as the final-answer
    turn (admitted while spent < ceiling: an exploring hop admitted with spent + r <= ceiling leaves spent <= ceiling)."""
    return spent + r > ceiling


# ---------------------------------------------------------------- depth floor (pure, from the logged trace)

def _doc(e: dict) -> dict:
    try:
        d = json.loads(e["request"]["messages"][1]["content"])
    except (ValueError, KeyError, IndexError, TypeError):
        return {}
    return d if isinstance(d, dict) else {}


def agent_calls(events: list, agent: str) -> list[dict]:
    """The agent's usable INVESTIGATE investigator model calls (one per hop), in log order."""
    return [e for e in events if e["type"] == "model.call" and e["stage"] == "INVESTIGATE"
            and e["role"] == "investigator" and e["agentId"] == agent and usable_output(e)]


def agent_reads(events: list, agent: str) -> list[dict]:
    """The agent's executed reads: tool calls it requested that ran (denied/unavailable results are not reads)."""
    return [e for e in events if e["type"] == "tool.call" and e["stage"] == "INVESTIGATE" and e["agentId"] == agent
            and "requestedBy" in e and e["result"]["status"] not in NOT_READS]


def _key(e: dict) -> str:
    return e["tool"] + json.dumps(e["args"], sort_keys=True)


def floor_status(events: list, agent: str, files: list[str] | None) -> dict:
    """The agent's depth-floor state. `files` is a unit's file list (None: a lens lane)."""
    reads = agent_reads(events, agent)
    distinct = list({_key(e): e for e in reads}.values())
    turns = len({e["requestedBy"] for e in reads})
    out = {"requestTurns": turns, "reads": len(distinct)}
    if files is None:
        need = {"requestTurns": LENS_FLOOR_TURNS, "reads": LENS_FLOOR_READS}
    else:
        mine = set(files)
        read = sorted({e["args"].get("path") for e in distinct if e["tool"] == "read_file"
                       and e["args"].get("side") == "head" and e["args"].get("path") in mine})
        ctx = sum(1 for e in distinct if not ((e["tool"] in ("read_file", "diff")) and e["args"].get("path") in mine))
        out.update(filesRead=read, contextReads=ctx)
        need = {"requestTurns": UNIT_FLOOR_TURNS, "reads": max(UNIT_FLOOR_READS, 2 * len(files)),
                "filesRead": len(files), "contextReads": min(len(files), UNIT_CONTEXT_READS)}
    out["need"] = need
    out["met"] = all((len(out[k]) if k == "filesRead" else out[k]) >= v for k, v in need.items())
    return out


def unmet(status: dict, files: list[str] | None) -> list[str]:
    """Model-visible list of what the floor still misses."""
    n, out = status["need"], []
    if status["requestTurns"] < n["requestTurns"]:
        out.append(f"request turns that ran a read: {status['requestTurns']} of {n['requestTurns']}")
    if status["reads"] < n["reads"]:
        out.append(f"distinct reads that ran: {status['reads']} of {n['reads']}")
    if files is not None:
        out += [f"not yet read with read_file (side head): {p}" for p in files if p not in status["filesRead"]]
        if status["contextReads"] < n["contextReads"]:
            out.append(f"reads beyond your own files (callees, callers, siblings): {status['contextReads']} of "
                       f"{n['contextReads']}")
    return out


def continuations(events: list, agent: str) -> int:
    """Depth-floor continuation chains the host started for the agent (hop-0 requests carrying a depthFloor block)."""
    return sum(1 for e in agent_calls(events, agent) if e["request"].get("hop") == 0 and "depthFloor" in _doc(e))


def waiver(events: list, agent: str, final_call: str, turns: int) -> str | None:
    """Why an answer that misses the floor is accepted as it stands (WAIVERS), or None: the host continues. A pure
    function of the logged trace (the final call's own retrieval state, the agent's hops and requests)."""
    calls = agent_calls(events, agent)
    final = next((e for e in calls if e["callId"] == final_call), None)
    if final is None:
        return "turns"
    if continuations(events, agent) >= MAX_CONTINUATIONS:
        return "continuations"
    if len(calls) > turns - 2:
        return "turns"
    r = _doc(final).get("retrieval", {})
    if r.get("lastTurn"):
        return "turns" if r.get("turn") == r.get("turnsAllowed", 0) - 1 else "spend"
    if r.get("toolsExhausted") or r.get("toolCallsRemaining") == 0:
        return "tool-calls"
    if r.get("contextExhausted"):
        return "context-chars"
    prev = final["request"].get("continuationOf")
    if prev is not None and not any(e.get("requestedBy") == prev for e in agent_reads(events, agent)):
        return "nothing-new"
    return None


def reread_events(events: list, agent: str) -> list[dict]:
    """The agent's earlier executed reads to re-show in a continuation (distinct, trusted, with evidence; in log
    order), bounded by REREAD_MAX calls and REREAD_CHARS excerpt characters (later reads win when over)."""
    seen, out = set(), []
    for e in agent_reads(events, agent):
        if _key(e) in seen or e["result"]["status"] not in retrieval.TRUSTED_TOOL_STATUSES \
                or not e["result"]["evidence"]:
            continue
        seen.add(_key(e))
        out.append(e)
    kept, chars = [], 0
    for e in reversed(out):
        c = retrieval.excerpt_chars(e)
        if len(kept) >= REREAD_MAX or chars + c > REREAD_CHARS:
            continue
        kept.append(e)
        chars += c
    return list(reversed(kept))


# ---------------------------------------------------------------- merge, VERIFY, JUDGE

def merge(hypotheses: list[dict]) -> list[dict]:
    """impact@v12 merges: the lens lanes' groups exactly as v3 (specialist-merge@2), then the unit restatement groups
    (lanes.cross_duplicate, rule cross-model-merge@1) in kept order."""
    lens = [h for h in hypotheses if h["specialist"] in LENS_AGENTS]
    out = specialists.merge(lens)
    gone = {m for g in out for m in g["mergedIds"]}
    order = {a: i for i, a in enumerate(agent_order(h["specialist"] for h in hypotheses))}
    kept = [h for h in lens if h["id"] not in gone]
    merged: dict[str, list[str]] = {}
    for h in hypotheses:
        if not is_unit(h["specialist"]):
            continue
        into = next((k for k in kept if order[k["specialist"]] < order[h["specialist"]]
                     and lanes.cross_duplicate(k, h)), None)
        if into is None:
            kept.append(h)
        else:
            merged.setdefault(into["id"], []).append(h["id"])
    return out + [{"keptId": k["id"], "mergedIds": merged[k["id"]], "rule": MERGE_RULE}
                  for k in kept if k["id"] in merged]


def qualifies(comment: dict) -> bool:
    return comment["severity"] in EXTRA_SEVERITIES and comment.get("evidenceStrength") in STRONG_EVIDENCE


def comment_cap(entries: list[tuple[dict, dict]], base: int) -> int:
    """CAP_RULE: the number of ranked comments to keep. `entries` are (finding, comment) pairs in any order."""
    from reviewer.contracts.severity import comment_sort_key
    ranked = [c for _, c in sorted(entries, key=lambda t: comment_sort_key(t[1]))]
    n = min(base, len(ranked))
    hard = min(max(base, MAX_COMMENTS), len(ranked))
    while n < hard and qualifies(ranked[n]):
        n += 1
    return n


# ---------------------------------------------------------------- coverage disclosure (pure, render time)

def coverage_lines(plan_doc: dict, payload: dict, events: list, verify_drops=(), limit: int = 60) -> list[str]:
    """review.md lines: per unit and per eligible file what was read, the skipped files with reasons, the floor
    state of every v12 agent, and unit candidates VERIFY did not reach. A pure function of the PREPARE-derived plan, the
    INVESTIGATE payload and the logged trace."""
    agents = {a["agentId"]: a for a in payload.get("agents", ())}
    hyps = payload.get("hypotheses", ())
    out = [f"- Partition ({PARTITION_RULE}): {plan_doc['changed']} changed file(s); {plan_doc['eligible']} eligible in "
           f"{len(plan_doc['units'])} coverage unit(s); {len(plan_doc['skipped'])} skipped with a reason"]
    examined = 0
    rows = []
    for u in plan_doc["units"]:
        a = agents.get(u["agentId"])
        files = [f["path"] for f in u["files"]]
        st = floor_status(events, u["agentId"], files)
        status = "not run" if a is None else a["status"] + (f" (`{a['error']['code']}`)" if a.get("error") else "")
        out.append(f"- Coverage investigator {u['agentId']} ({len(files)} file(s)): {status}; "
                   f"{_floor_text(events, u['agentId'], st)}")
        done = a is not None and a["status"] == "completed"
        for p in files:
            n = sum(1 for h in hyps if h["specialist"] == u["agentId"] and h["location"]["path"] == p)
            ok = done and p in st["filesRead"]
            examined += ok
            rows.append(f"  - `{p}` ({u['agentId']}): " + ("read and investigated" if ok else
                                                            "NOT READ by its coverage investigator")
                        + f"; {n} hypothesis(es) from it")
    out.append(f"- Eligible files read and investigated by their coverage investigator: {examined} of "
               f"{plan_doc['eligible']}")
    out += rows[:limit] + ([f"  - ... {len(rows) - limit} more"] if len(rows) > limit else [])
    if plan_doc["skipped"]:
        shown = ", ".join(f"`{s['path']}` ({s['reason']})" for s in plan_doc["skipped"][:30])
        more = f" (+{len(plan_doc['skipped']) - 30} more)" if len(plan_doc["skipped"]) > 30 else ""
        out.append(f"- Not given to a coverage investigator (the lens lanes still saw their diffs): {shown}{more}")
    for lane in LENS_AGENTS:
        if lane in agents:
            out.append(f"- Lens lane {lane}: {_floor_text(events, lane, floor_status(events, lane, None))}")
    unit_ids = {h["id"] for h in hyps if is_unit(h["specialist"])}
    cut = [d for d in verify_drops if d["reason"] == "budget"
           and d.get("detail", "").startswith(lanes.JUDGE_RESERVE_DROP) and set(d["subjectIds"]) <= unit_ids]
    if cut:
        out.append(f"- unit-candidates-unverified: {len(cut)} coverage-unit candidate(s) not verified "
                   "(`budget-exhausted`: VERIFY kept the JUDGE reserve)")
    out.append("- 'Read and investigated' means the trace shows the investigator read the file; it is not a "
               "certificate that the file is free of defects.")
    return out


def _floor_text(events: list, agent: str, st: dict) -> str:
    c = continuations(events, agent)
    s = f"{st['requestTurns']} request turn(s), {st['reads']} distinct read(s)"
    if "filesRead" in st:
        s += f", {len(st['filesRead'])} own file(s) read, {st['contextReads']} context read(s)"
    s += f"; depth floor {'met' if st['met'] else 'NOT met'}"
    return s + (f" after {c} continuation(s)" if c else "")


# ---------------------------------------------------------------- identity

def identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int, comment_cap_base: int) -> dict:
    """Everything about impact@v12 that is not a template digest (bound into the config identity)."""
    c = stage_ceiling("INVESTIGATE", budget)
    return {"behavior": BEHAVIOR, "lensVersion": prompts.SPECIALIST_LENS_VERSION, "lensAgents": list(LENS_AGENTS),
            "planMarker": PLAN_MARKER, "v3Behavior": specialists.SPECIALIST_BEHAVIOR,
            "partition": {"rule": PARTITION_RULE, "text": PARTITION_TEXT, "maxUnits": MAX_UNITS,
                          "unitMaxFiles": UNIT_MAX_FILES, "unitDiffChars": UNIT_DIFF_CHARS,
                          "fileWeightChars": FILE_WEIGHT_CHARS, "skipReasons": list(SKIP_REASONS),
                          "docExtensions": list(DOC_EXTENSIONS), "docNames": list(DOC_NAMES),
                          "l10nDirs": sorted(L10N_DIRS), "l10nExtensions": list(L10N_EXTENSIONS),
                          "l10nName": _L10N_NAME.pattern, "testDirs": sorted(TEST_DIRS), "testName": _TEST_NAME.pattern,
                          "maxRanges": MAX_RANGES},
            "budget": {"rule": BUDGET_RULE, "text": BUDGET_TEXT, "investigateTopBp": INVESTIGATE_TOP_BP,
                       "lensSpendBp": LENS_SPEND_BP, "spendTop": spend_top(budget),
                       "lensTop": lens_top(budget), "lensToolCalls": LENS_TOOL_CALLS,
                       "unitBaseReads": UNIT_BASE_READS, "unitReadsPerFile": UNIT_READS_PER_FILE,
                       "lensTimeBp": LENS_TIME_BP, "stageCeiling": c, "finalRule": FINAL_RULE,
                       "judgeReserveBp": sweeps.JUDGE_RESERVE_BP, "investigationShare": investigation_limit(budget),
                       "perAgent": {"investigatorTurns": policy.investigator_turns,
                                    "agentToolCalls": policy.agent_tool_calls, "hostMaxCalls": tool_max_calls,
                                    "contextChars": policy.context_chars,
                                    "toolOutputCharsPerAgent": budget["maxToolOutputTokensPerAgent"] * 3}},
            "floor": {"rule": FLOOR_RULE, "text": FLOOR_TEXT, "lensTurns": LENS_FLOOR_TURNS,
                      "lensReads": LENS_FLOOR_READS, "unitTurns": UNIT_FLOOR_TURNS, "unitReads": UNIT_FLOOR_READS,
                      "unitContextReads": UNIT_CONTEXT_READS, "maxContinuations": MAX_CONTINUATIONS,
                      "continuationHops": CONTINUATION_HOPS, "rereadMax": REREAD_MAX, "rereadChars": REREAD_CHARS,
                      "rereadSuffix": REREAD_SUFFIX, "waivers": list(WAIVERS)},
            "merge": {"v3Rule": specialists.MERGE_RULE, "rule": MERGE_RULE, "text": MERGE_TEXT,
                      "lineWindow": specialists.MERGE_LINE_WINDOW, "similarity": lanes.NEAR_DUP_SIMILARITY},
            "verify": {"rule": VERIFY_RULE, "text": VERIFY_TEXT, "maxCandidates": MAX_VERIFY,
                       "v3MaxCandidates": specialists.MAX_VERIFY_CANDIDATES, "sessions": "one per verified candidate"},
            "commentCap": {"rule": CAP_RULE, "text": CAP_TEXT, "base": comment_cap_base, "max": MAX_COMMENTS,
                           "strongEvidence": list(STRONG_EVIDENCE), "extraSeverities": list(EXTRA_SEVERITIES),
                           "rank": sorted(RANK, key=RANK.get)}}
