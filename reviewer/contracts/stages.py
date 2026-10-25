"""Canonical stages, run lifecycle, modes, error codes and timeout ceilings."""

from __future__ import annotations

# Canonical names and order (02-system-architecture.md). Do not rename or add.
STAGES: tuple[str, ...] = (
    "INGEST", "PREPARE", "TRIAGE", "INVESTIGATE", "VERIFY", "JUDGE", "PUBLISH", "LEARN",
)

RUN_STATUSES = ("queued", "running", "completed", "partial", "superseded", "cancelled", "failed")
TERMINAL_STATUSES = frozenset({"completed", "partial", "superseded", "cancelled", "failed"})
RUN_TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"running", "cancelled", "superseded", "failed"}),
    "running": frozenset({"completed", "partial", "superseded", "cancelled", "failed"}),
    **{s: frozenset() for s in TERMINAL_STATUSES},
}
STAGE_STATUSES = ("completed", "partial", "skipped", "failed")

# Run modes. Exactly one meaning each (resolves 11/14/31 naming drift):
#   live          - provider calls, trace recorded. Requires a trusted SpendAuthorization
#                   (operator-issued, loaded by the gateway from out-of-band config, never from
#                   repo, case or model input) whose provider allow-list and ceiling cover the
#                   profile and Plan. In Stage 0A the only issuable authorization allows the
#                   `synthetic` provider (scripted responses, no spend) for recording fixtures.
#   fresh-repeat  - a new live run of the same case for model-variance measurement. Same
#                   requirements as live. Repeating a strict replay is NOT a fresh repeat.
#   strict-replay - zero live calls. Every model request must match a recorded request
#                   hash + occurrence (fail closed: replay-miss); tool results must hash-match
#                   the recording (replay-mismatch). Replaces 31's "trace replay"/14's "replay".
#   stage-replay  - load stored artifacts before `fromStage`, run fromStage..LEARN. ALWAYS
#                   offline: the gateway runs in strict-replay; a stage-replay never carries a
#                   spend authorization. (A live stage re-run would be a new `live` run.)
RUN_MODES = ("live", "fresh-repeat", "strict-replay", "stage-replay")
LIVE_MODES = frozenset({"live", "fresh-repeat"})
OFFLINE_MODES = frozenset({"strict-replay", "stage-replay"})
GATEWAY_MODES = ("live", "strict-replay", "disabled")

# Every Stage 0A/0B review is read-only toward the target: no writes to the target repo,
# no execution of target code, no posting to the host. Output is local draft Comments
# that explain; the PR author decides which fixes to make.
ACCESS_POLICY = "read-only@1"

TRIGGERS = ("host-event", "manual-rerun", "eval", "cli")

# Why a run or stage is incomplete. Partial runs list one or more of these.
INCOMPLETE_REASONS = (
    "deadline", "soft-deadline", "budget", "cancelled", "verifier-failure", "agent-failure",
    "tool-calls-exhausted", "disabled-in-eval",
)

ERROR_CODES = (
    "replay-miss",          # strict replay: no recorded response for this request hash/occurrence
    "replay-mismatch",      # strict replay: tool result hash differs from recording
    "live-calls-disabled",  # live call attempted without mode + authorization
    "model-unresolved",     # profile role has resolved=false (e.g. Terra id pending)
    "schema-invalid",       # model output failed its output schema
    "repair-exhausted",     # schema-invalid after the single allowed repair
    "provider-error",
    "provider-timeout",
    "budget-exhausted",     # admission refused; never an overrun
    "deadline-exceeded",
    "cancelled",
    "tool-denied",
    "path-escape",
    "invalid-citation",     # Evidence does not resolve against the pinned snapshot
    "contract-violation",   # a document failed validation at a module boundary
    "internal",
)

# Standard-tier ceilings in seconds (15-job-orchestration.md). These are ceilings, not
# expectations; they supersede 31's "twice the budget row" rule for Stage 0A.
STAGE_CEILING_SEC: dict[str, int | None] = {
    "INGEST": 10, "PREPARE": 60, "TRIAGE": 20, "INVESTIGATE": 120, "VERIFY": 45,
    "JUDGE": 20, "PUBLISH": 30, "LEARN": None,  # LEARN is async and outside latency
}

# Stage-replay may start at these stages (INGEST/PREPARE re-derive from snapshots anyway).
REPLAYABLE_FROM = ("TRIAGE", "INVESTIGATE", "VERIFY", "JUDGE", "PUBLISH")

# Stages that may end in "partial" and still hand verified output to PUBLISH (15).
PARTIAL_CAPABLE = frozenset({"INVESTIGATE", "VERIFY", "JUDGE"})


def stage_index(stage: str) -> int:
    return STAGES.index(stage)


def next_stage(stage: str) -> str | None:
    i = stage_index(stage)
    return STAGES[i + 1] if i + 1 < len(STAGES) else None


def can_transition(src: str, dst: str) -> bool:
    return dst in RUN_TRANSITIONS.get(src, frozenset())


def artifact_name(stage: str, plan_version: int) -> str:
    """Checkpoint file name inside a run directory: artifacts/<NN>-<STAGE>.v<plan>.json"""
    return f"{stage_index(stage) + 1:02d}-{stage}.v{plan_version}.json"
