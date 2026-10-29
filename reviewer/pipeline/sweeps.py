"""investigator.impact@v4: deterministic diff-shard sweep investigators (pure rules; the engine drives them in
Engine._sweep_phase, after the unchanged v3 specialists of reviewer.pipeline.specialists).

Why: traces of impact@v3 runs showed investigators attending to 1-4 files whatever the diff size. v4 keeps the three
v3 specialists and adds one sweep investigator per SHARD of the reviewable changed files. Each sweep sees its shard's
PREPARE diffs and the changed-path list, has the impact tools plus `file_disposition`, and must give EVERY shard file a
disposition: a resolved hypothesis located in it, or a file_disposition record ("examined, no issue" + reason).

Everything here is a pure function of the PREPARE artifact, the logged trace, the Plan budget and the policy, so a
resumed run and a strict replay re-derive the same shards, ceilings and decisions.

Reviewable files (SHARD_RULE). PREPARE's changed files in path order, except: deleted (no head file can hold a
location), generated (reviewer.impactmap.is_generated: lockfiles, minified bundles, source maps, codegen, vendored
trees), and files whose PREPARE per-file diff is not a text diff (missing, binary, non-UTF-8, too long to diff,
identical content or a recorded coverage gap). Tests and docs stay in.

Shards. Fewer than MIN_SWEEP_FILES reviewable files: no shards, and v4 behaves exactly as v3 (apart from version tags
and the time rule below). Otherwise k = min(MAX_SHARDS, max(ceil(n / MAX_FILES_PER_SHARD), ceil(diff chars /
SHARD_DIFF_CHARS))) shards of consecutive files in path order, as even as possible (the first n mod k shards hold one
file more). At most MAX_FILES_PER_SHARD_HARD files per shard: files past k * MAX_FILES_PER_SHARD_HARD are excluded as
`shard-limit` (disclosed). Diff chars are the excerpt characters of the PREPARE diff result.

Budgets (BUDGET_RULE). Specialists: exactly the v3 split (specialists.BUDGET_RULE) of tool calls and spend; their
cumulative time slices are taken over HALF of the INVESTIGATE ceiling C (the v4 Plan doubles the v3 ceiling, so they
keep the v3 seconds). Sweeps, in shard order, with cumulative ceilings that roll unused room forward:
  tool calls  sweep j may start a tool call while INVESTIGATE tool calls < base + sum_{i<=j} (SWEEP_TOOL_CALLS + files_i),
              base = INVESTIGATE tool calls when the sweep phase starts (the per-agent caps still apply);
  spend       sweep j may start a model call while INVESTIGATE spend < s0 + (share - s0) * (j+1) // k, s0 = INVESTIGATE
              spend when the sweep phase starts, share = investigation_limit(budget);
  time        sweep j stops at C//2 + (C - C//2) * (j+1) // k seconds after INVESTIGATE started (a stage-deadline
              gate stop, recorded with host-stop recording so strict replay takes it from the recording).

Disposition check (DISPOSITION_RULE). After a sweep's first final answer, a shard file without a disposition sends ONE
fixed continuation (prompts.SWEEP_DISPOSITION_CONTINUATION; a new chain of the same agent and session, at most
CONTINUATION_HOPS hops). Its final answer's hypotheses are ADDED to the first answer's. Files still without a
disposition are `uncovered`. Every decision is a `sweep.disposition` trace event; the per-file summary is the
INVESTIGATE payload `sweep` (SweepCoverage) and an `investigate.coverage` trace event. A sweep failure never fails
the run: it is disclosed (agents + incomplete) like a failed v3 specialist and its files stay uncovered unless it
recorded dispositions before failing.

VERIFY (VERIFY_RULE). Candidates round-robin across ALL lanes (contracts 0, logic 0, safety 0, sweep-01 0, ...,
contracts 1, ...); the cap is min(MAX_VERIFY_CANDIDATES_V4, 20 + VERIFY_CANDIDATES_PER_SHARD * k) (20 with no shards,
as v3); over-cap candidates are dropped as `over-cap` (disclosed). With shards, the verifier ToolSession (per-agent
tool cap, tool wall time) is renewed every VERIFY_SESSION_CANDIDATES verified candidates (agent ids verifier,
verifier-02, ...), so later candidates are not starved by one session's cap; the run tool-call cap still binds.
"""

from __future__ import annotations

from reviewer import impactmap
from reviewer.contracts.budget import investigation_limit, stage_ceiling
from reviewer.contracts.entities import SWEEP_COVERAGE_VERSION, SWEEP_DISPOSITION_VERSION

from . import prompts, retrieval, specialists

SWEEP_BEHAVIOR = "diff-shard-sweeps@1"
SHARD_RULE = "diff-shards@1"
BUDGET_RULE = "sweep-budget-split@1"
DISPOSITION_RULE = SWEEP_DISPOSITION_VERSION
VERIFY_RULE = "sweep-verify@1"
COVERAGE_VERSION = SWEEP_COVERAGE_VERSION
PLAN_MARKER = "diff-sweep"            # Plan.specialists of a v4 Plan: the three specialists, then this marker

MIN_SWEEP_FILES = 4                   # fewer reviewable files: no shards (v4 == v3)
MAX_FILES_PER_SHARD = 5
SHARD_DIFF_CHARS = 40_000             # diff excerpt chars per shard that start another shard (well under CONTEXT_CHARS)
MAX_SHARDS = 6
MAX_FILES_PER_SHARD_HARD = 10         # with MAX_SHARDS: at most 60 swept files; later ones are `shard-limit`
SWEEP_TOOL_CALLS = 12                 # per sweep, plus one per shard file (room for its file_disposition record)
CONTINUATION_HOPS = 3                 # hops of the one disposition continuation chain
VERIFY_CANDIDATES_PER_SHARD = 4
MAX_VERIFY_CANDIDATES_V4 = 40
VERIFY_SESSION_CANDIDATES = 10
TEXT_DIFF_STATUSES = ("ok", "partial")
NOTE_TINY = (f"fewer than {MIN_SWEEP_FILES} reviewable changed files: no diff shards; the specialists review every "
             "file (v3 behaviour)")

RULE_TEXT = ("reviewable = PREPARE changed files in path order minus deleted, generated (impactmap.is_generated) and "
             "files whose PREPARE diff is not a text diff (status not ok/partial); n < MIN_SWEEP_FILES: no shards; "
             "k = min(MAX_SHARDS, max(ceil(n/MAX_FILES_PER_SHARD), ceil(chars/SHARD_DIFF_CHARS))) consecutive shards, "
             "sizes as even as possible (first n mod k one larger), at most MAX_FILES_PER_SHARD_HARD each (rest: "
             "shard-limit); agent ids sweep-01..")
BUDGET_TEXT = ("specialists: the v3 tool/spend split, time slices over C//2; sweep j: tool calls < base + "
               "sum(SWEEP_TOOL_CALLS + files_i, i<=j), spend < s0 + (share - s0)*(j+1)//k, time C//2 + (C - "
               "C//2)*(j+1)//k s")
DISPOSITION_TEXT = ("a shard file has a disposition when the sweep agent has a resolved hypothesis located in it or a "
                    "logged ok file_disposition call for it; after the first final answer, missing files send one "
                    "continuation (CONTINUATION_HOPS hops) whose hypotheses are added; still missing -> uncovered")
VERIFY_TEXT = ("round-robin across specialist and sweep lanes; cap min(MAX_VERIFY_CANDIDATES_V4, 20 + "
               "VERIFY_CANDIDATES_PER_SHARD*k); with shards a new verifier session every VERIFY_SESSION_CANDIDATES "
               "verified candidates")


def is_v4_plan(plan: dict) -> bool:
    """The Plan of an investigator.impact@v4 run (runner refuses any other pairing of plan and policy)."""
    return plan.get("specialists") == list(specialists.AGENTS) + [PLAN_MARKER]


def plan_specialists() -> list[str]:
    return list(specialists.AGENTS) + [PLAN_MARKER]


def agent_id(j: int) -> str:
    return f"sweep-{j + 1:02d}"


# ---------------------------------------------------------------- partition

def reviewable(files: list[dict], diffs: dict) -> tuple[list[tuple[str, int]], list[dict]]:
    """-> ([(path, diff chars)] in path order, [{path, reason}] excluded). `files` is the PREPARE payload's file list,
    `diffs` maps a path to its logged PREPARE per-file `diff` tool.call event."""
    keep, out = [], []
    for f in sorted(files, key=lambda f: f["path"]):
        p, ev = f["path"], diffs.get(f["path"])
        if f["status"] == "deleted":
            out.append({"path": p, "reason": "deleted"})
        elif impactmap.is_generated(p):
            out.append({"path": p, "reason": "generated"})
        elif ev is None or ev["result"]["status"] not in TEXT_DIFF_STATUSES or not ev["result"]["evidence"]:
            out.append({"path": p, "reason": "no-text-diff"})
        else:
            keep.append((p, sum(len(x["excerpt"]) for x in ev["result"]["evidence"])))
    return keep, out


def shards(files: list[tuple[str, int]]) -> tuple[list[list[tuple[str, int]]], list[str]]:
    """-> (shards of (path, chars), paths left out by the shard limit). Pure and order-preserving."""
    n = len(files)
    if n < MIN_SWEEP_FILES:
        return [], []
    total = sum(c for _, c in files)
    k = min(MAX_SHARDS, max(-(-n // MAX_FILES_PER_SHARD), -(-total // SHARD_DIFF_CHARS), 1), n)
    cap = k * MAX_FILES_PER_SHARD_HARD
    files, over = files[:cap], [p for p, _ in files[cap:]]
    n = len(files)
    out, at = [], 0
    for i in range(k):
        size = n // k + (1 if i < n % k else 0)
        out.append(files[at:at + size])
        at += size
    return out, over


# ---------------------------------------------------------------- budgets

def specialist_ceiling(ceiling: int | None) -> int | None:
    """The INVESTIGATE seconds the v4 specialists split as v3 does (half of the v4 ceiling: the v3 ceiling)."""
    return None if ceiling is None else ceiling // 2


def time_slices(ceiling: int | None, k: int) -> list[int] | None:
    if ceiling is None:
        return None
    lo = specialist_ceiling(ceiling)
    return [lo + (ceiling - lo) * (j + 1) // k for j in range(k)]


def tool_ceilings(base: int, sizes: list[int]) -> list[int]:
    out, cum = [], base
    for s in sizes:
        cum += SWEEP_TOOL_CALLS + s
        out.append(cum)
    return out


def spend_ceilings(spent0: int, share: int, k: int) -> list[int]:
    s0 = min(spent0, share)
    return [s0 + (share - s0) * (j + 1) // k for j in range(k)]


def verify_cap(k: int) -> int:
    return min(MAX_VERIFY_CANDIDATES_V4, specialists.MAX_VERIFY_CANDIDATES + VERIFY_CANDIDATES_PER_SHARD * k)


def verifier_agent(position: int, k: int, base: str = "verifier") -> str:
    """The verifier session (agent id) of the position-th verified candidate (0-based)."""
    group = 0 if k == 0 else position // VERIFY_SESSION_CANDIDATES
    return base if group == 0 else f"{base}-{group + 1:02d}"


def merge_order(agents: list[dict]) -> list[str]:
    """Agent order of the v4 merge rule: the specialists, then every other agent as INVESTIGATE lists it."""
    rest = [a["agentId"] for a in agents if a["agentId"] not in specialists.AGENTS]
    return list(specialists.AGENTS) + rest


# ---------------------------------------------------------------- coverage

def coverage(n_reviewable: int, shard_list: list[dict], excluded: list[dict], files: list[dict],
             note: str | None = None) -> dict:
    """The SweepCoverage document (bounded lists; counts are exact)."""
    s = {"swept": len(files), "issue": sum(1 for f in files if f["disposition"] == "issue"),
         "noIssue": sum(1 for f in files if f["disposition"] == "no-issue"),
         "uncovered": sum(1 for f in files if f["disposition"] == "uncovered")}
    doc = {"version": COVERAGE_VERSION, "rule": SHARD_RULE, "reviewable": n_reviewable, "shards": shard_list,
           "files": files[:1000], "excluded": excluded[:1000], "excludedTotal": len(excluded), "summary": s}
    if note:
        doc["note"] = note[:500]
    return doc


def statement(cov: dict) -> str:
    s = cov["summary"]
    if not cov["shards"]:
        return (f"Diff-shard sweep: no shards ({cov.get('note', 'no reviewable files')}); "
                f"{cov['excludedTotal']} changed file(s) not reviewable.")
    return (f"Diff-shard sweep: {cov['reviewable']} reviewable changed file(s) in {len(cov['shards'])} shard(s); "
            f"{s['issue'] + s['noIssue']} of {s['swept']} swept file(s) got a disposition ({s['issue']} with a "
            f"hypothesis, {s['noIssue']} examined with no issue), {s['uncovered']} uncovered; "
            f"{cov['excludedTotal']} changed file(s) not swept (deleted, generated, no text diff or shard limit).")


# ---------------------------------------------------------------- identity

def identity_doc(policy: retrieval.RetrievalPolicy, budget: dict, tool_max_calls: int) -> dict:
    """Everything about the sweep behaviour that is not a template digest (bound into the config identity)."""
    c = stage_ceiling("INVESTIGATE", budget)
    return {"behavior": SWEEP_BEHAVIOR, "version": prompts.SWEEP_VERSION, "planMarker": PLAN_MARKER,
            "shards": {"rule": SHARD_RULE, "text": RULE_TEXT, "minFiles": MIN_SWEEP_FILES,
                       "maxFilesPerShard": MAX_FILES_PER_SHARD, "shardDiffChars": SHARD_DIFF_CHARS,
                       "maxShards": MAX_SHARDS, "maxFilesPerShardHard": MAX_FILES_PER_SHARD_HARD},
            "budget": {"rule": BUDGET_RULE, "text": BUDGET_TEXT, "sweepToolCalls": SWEEP_TOOL_CALLS,
                       "investigationShare": investigation_limit(budget), "stageCeiling": c,
                       "specialistCeiling": specialist_ceiling(c),
                       "specialistToolPool": specialists.tool_pool(policy, budget, tool_max_calls)},
            "disposition": {"rule": DISPOSITION_RULE, "text": DISPOSITION_TEXT, "continuationHops": CONTINUATION_HOPS},
            "verify": {"rule": VERIFY_RULE, "text": VERIFY_TEXT, "perShard": VERIFY_CANDIDATES_PER_SHARD,
                       "maxCandidates": MAX_VERIFY_CANDIDATES_V4, "sessionCandidates": VERIFY_SESSION_CANDIDATES},
            "coverage": COVERAGE_VERSION}
