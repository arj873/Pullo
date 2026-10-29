"""Isolated semantic-scoring contract family (s0a-contracts@7). Owner: contracts.

A separate family for an offline reference scorer that calls one explicit model for three jobs: extract
candidate findings from a tool's review (EXTRACT), group duplicates (DEDUP) and judge one gold/candidate pair
(MATCH). It shares nothing closed with the review family except `ModelResponse`, `Usage`, `Price`, `Message`,
`TypedError`, `Redactions` and `CostRecord`:

- Review `Stage`, `STAGES`, `ModelRequest`, `ModelProfile`, `RoleSpec`, `ReviewRun`, `TraceEvent`, `TypedError`
  are NOT widened (TraceEvent only refuses a score cost in its cost variant). Score documents never carry a review Stage: score errors and score `CostRecord`s omit
  `stage`; the `score.model.call` event names the score stage and role (1:1, see SCORE_ROLE_STAGE).
- `CostRecord` (`kind` gains "score"; see entities._cost_ok) and `TraceEvent` (its cost variant refuses
  kind=score; entities._review_cost_event_ok) are the two shared definitions that change.
- The contract allowlist (SCORE_MODELS) is NOT a permission to call anything. Live use still needs the
  operator's SpendAuthorization, the runtime catalog and the host. Retries and repairs are fixed at zero.
- The extractor answers `ScoreExtractionSegments` (bench.extract@v3): a source comment id and an inclusive, 1-based
  range of the host's numbered segments of that comment (score_prompts.segments). It never copies text; the producer
  joins the trusted segments locally, so the candidate is an exact substring of the comment by construction. The older copy shape `ScoreExtraction` (model-written `text`, bench.extract@v1/v2) stays defined so
  historical documents still validate, but it is no longer legal for any score role. No output schema has a
  reasoning, explanation or error text field, and nothing here copies model text into an error or incomplete record.
  Local semantic validators (segment range, partition, ids, counts, finiteness) remain mandatory in the producer.
"""

from __future__ import annotations

from .canonical import call_id, cost_id, score_request_hash, score_run_id
from .entities import (DEV_ONLY_MODELS, Digest, Id, Message, ModelResponse, Price, ProfileRef,
                       PromptVersion, Redactions, Slug, Timestamp, TypedError, CostRecord, no_secrets)
from .schema import (Arr, Bool, Const, Enum, Int, Invariant, Issue, Json, Nullable, Num, Obj, Str,
                     Union, define, validate)
from .stages import RUN_STATUSES, STAGE_STATUSES

SCORE_STAGES = ("EXTRACT", "DEDUP", "MATCH")
SCORE_ROLES = ("extractor", "deduper", "matcher")
SCORE_ROLE_SCHEMA = {"extractor": "ScoreExtractionSegments", "deduper": "ScoreDedup", "matcher": "ScorePair"}
SCORE_ROLE_STAGE = {"extractor": "EXTRACT", "deduper": "DEDUP", "matcher": "MATCH"}
SCORE_OUTPUT_SCHEMAS = tuple(SCORE_ROLE_SCHEMA.values())
# Literal on purpose: contracts cannot import the runtime catalog. A test pins SCORE_MODELS to the catalog's
# ALLOWED_ROUTER_MODELS. Membership here grants nothing by itself (L4).
SCORE_MODELS = ("anthropic/claude-opus-5.5",)
INCOMPLETE_SCORE_REASONS = ("budget", "provider-failure", "extraction-invalid", "dedup-invalid", "oversize",
                            "unsent", "cancelled", "guard")
SCORE_MODES = ("live", "strict-replay")

ScoreStage = define("ScoreStage", Enum(*SCORE_STAGES))
ScoreRole = define("ScoreRole", Enum(*SCORE_ROLES))

# ---------------------------------------------------------------- model outputs (closed, strict-projectable)
# Bounds are contract ceilings; the producer's pinned limits (candidate count, text length) are stricter and
# enforced by local validators. Strict providers drop these keywords, so they only ever guide.

ScoreExtraction = define("ScoreExtraction", Obj(
    required={"candidates": Arr(Obj(required={"sourceCommentId": Str(min_len=1, max_len=200),
                                             "text": Str(min_len=1, max_len=100_000)}),
                                max_items=1000)},
    description="LEGACY copy shape (bench.extract@v1/v2); not legal for any score role. Candidate findings extracted "
                "from one tool's review. text is required data and is kept exactly as supplied, including "
                "whitespace-only non-empty strings."))


ScoreExtractionSegments = define("ScoreExtractionSegments", Obj(
    required={"candidates": Arr(Obj(required={"sourceCommentId": Str(min_len=1, max_len=200),
                                             "startSegment": Int(1, 10**6), "endSegment": Int(1, 10**6)}),
                                max_items=1000)},
    description="Candidate findings of one tool's review BY REFERENCE (bench.extract@v3): each names a source comment "
                "id and the inclusive 1-based range startSegment..endSegment of that comment's numbered segments. No "
                "model-written text. Order (start <= end), the upper bound (<= segment count) and the id lookup are "
                "local producer checks against the trusted segmentation, so they classify as extraction-invalid."))
ScoreDedup = define("ScoreDedup", Obj(
    required={"groups": Arr(Arr(Int(0, 10**6), min_items=1, max_items=1000), max_items=1000)},
    description="Groups of 0-based candidate indices judged duplicates. Partition checks are local."))
ScorePair = define("ScorePair", Obj(
    required={"match": Bool(), "confidence": Num()},
    description="One gold/candidate judgment; confidence is a finite number, not clamped."))

# ---------------------------------------------------------------- profile


def _model_ok(d):
    m = d["model"]
    if "latest" in m:
        yield ".model", "aliases are not pinned"
    if m in DEV_ONLY_MODELS:
        yield ".model", "development-only model may not be a score model"
    if m not in SCORE_MODELS:
        yield ".model", f"the score model is one of {list(SCORE_MODELS)}"


def _role_spec(role: str) -> Obj:
    return Obj(
        required={"provider": Const("anthropic"), "model": Enum(*SCORE_MODELS),
                  "family": Const("anthropic"), "resolved": Const(True),
                  "promptVersion": PromptVersion, "outputSchema": Const(SCORE_ROLE_SCHEMA[role]),
                  "params": Json(),
                  "caps": Obj(required={"maxOutputTokens": Int(1, 1_000_000), "timeoutSec": Int(1, 3600),
                                        "maxRetries": Const(0), "maxRepairs": Const(0)}),
                  "price": Price, "fallbacks": Arr(ProfileRef, max_items=0)},
        invariants=[Invariant("score-model", "the one explicit score model; no alias, no dev-only model",
                              _model_ok)])


ScoreProfile = define("ScoreProfile", Obj(
    required={"id": Slug, "version": Int(1, 999_999),
              "roles": Obj(required={r: _role_spec(r) for r in SCORE_ROLES})},
    description="Immutable; referenced as '<id>@<version>'. Exactly the three score roles, one model, zero "
                "retries/repairs, priced, no fallbacks. Not a ModelProfile: it cannot be used for review."))

# ---------------------------------------------------------------- request

ScoreRequest = define("ScoreRequest", Obj(
    required={"provider": Const("anthropic"), "model": Enum(*SCORE_MODELS), "profile": ProfileRef,
              "role": Enum(*SCORE_ROLES), "promptVersion": PromptVersion,
              "outputSchema": Enum(*SCORE_OUTPUT_SCHEMAS), "params": Json(),
              "messages": Arr(Message, min_items=1, max_items=1000), "tools": Arr(Json(), max_items=0)},
    invariants=[Invariant("score-role-schema", "each score role requests its own output schema",
                          lambda d: [(".outputSchema", f"a {d['role']} request asks for "
                                      f"{SCORE_ROLE_SCHEMA[d['role']]}")]
                          if d["outputSchema"] != SCORE_ROLE_SCHEMA[d["role"]] else []),
                no_secrets("ScoreRequest")],
    description="Redacted before hashing; score_request_hash(request) is the strict-replay key. Closed and "
                "typed: no field carries a run/eval id or timestamp (host metadata is kept out by "
                "construction), no tools, no hop/hypothesis fields. Distinct from ModelRequest, which it "
                "never validates as, and vice versa."))

# ---------------------------------------------------------------- run


def _no_stage(d, key="error"):
    if key in d and isinstance(d[key], dict) and "stage" in d[key]:
        yield f".{key}.stage", "score errors omit stage (a review Stage); attribution is by role and call"


ScoreIncomplete = Obj(required={"stage": ScoreStage, "reason": Enum(*INCOMPLETE_SCORE_REASONS)},
                      description="What did not finish. No free text: a reason class only.")


def _score_run_ok(d):
    live, replay = d["mode"] == "live", d["mode"] == "strict-replay"
    if live and "spendAuthorization" not in d:
        yield ".spendAuthorization", "live runs require a trusted SpendAuthorization digest"
    if live and "replayOf" in d:
        yield ".replayOf", "live runs replay nothing"
    if replay and "replayOf" not in d:
        yield ".replayOf", "replay runs name the recorded run"
    if replay and "spendAuthorization" in d:
        yield ".spendAuthorization", "offline replay never carries spend authorization"
    if d.get("replayOf") == d["id"]:
        yield ".replayOf", "a replay runs under a different run id than the recording"
    st = d["status"]
    if st == "partial" and not d["incomplete"]:
        yield ".incomplete", "partial runs explain what did not finish"
    if st == "failed" and "error" not in d:
        yield ".error", "failed runs carry a TypedError"
    if st == "completed" and (d["incomplete"] or "error" in d):
        yield ".status", "completed runs carry no incomplete[] or error"
    if st in ("queued", "running") and ("error" in d or "endedAt" in d):
        yield ".status", "non-terminal runs carry no error/endedAt"
    yield from _no_stage(d)


def _score_run_identity(d):
    if d["id"] != score_run_id(d["evalRunId"], d["evalCaseId"], d["repeat"]):
        yield ".id", "must equal score_run_id(evalRunId, evalCaseId, repeat)"


ScoreRun = define("ScoreRun", Obj(
    required={"schema": Const("score-run@1"), "id": Id("run"), "family": Const("score"),
              "evalRunId": Id("evr"), "evalCaseId": Slug, "repeat": Int(0, 1000), "profile": ProfileRef,
              "mode": Enum(*SCORE_MODES), "inputDigest": Digest, "status": Enum(*RUN_STATUSES),
              "incomplete": Arr(ScoreIncomplete, max_items=50)},
    optional={"spendAuthorization": Digest, "replayOf": Id("run"), "error": TypedError,
              "startedAt": Timestamp, "endedAt": Timestamp},
    invariants=[Invariant("score-run-rules", "mode, authorization, replay and status rules", _score_run_ok),
                Invariant("score-run-identity", "id = score_run_id(evalRunId, evalCaseId, repeat)",
                          _score_run_identity)],
    description="id is run_<16 hex> (so CostRecord.runId fits) but derived by canonical.score_run_id, never "
                "run_id. inputDigest digests the external store's rendered inputs, never text. A strict "
                "replay uses a fresh evalRunId, hence a different id, with replayOf pinned. No repo, "
                "snapshot, trigger, PR or prompt fields."))


def check_score_replay(recorded: dict, replay: dict) -> list[Issue]:
    """Cross-document rules for a strict replay of a recorded ScoreRun (both already valid): a different run id
    and a fresh evalRunId, replayOf pinned to the recording, and the same case, repeat, profile and inputs."""
    out: list[Issue] = []
    if replay.get("replayOf") != recorded["id"]:
        out.append(Issue("$.replayOf", "score-replay", "replayOf must be the recorded run's id"))
    if replay["id"] == recorded["id"]:
        out.append(Issue("$.id", "score-replay", "a replay must run under a different run id"))
    if replay["evalRunId"] == recorded["evalRunId"]:
        out.append(Issue("$.evalRunId", "score-replay", "a replay must use a fresh evalRunId"))
    if replay["mode"] != "strict-replay":
        out.append(Issue("$.mode", "score-replay", "a replay is strict-replay"))
    for k in ("evalCaseId", "repeat", "profile", "inputDigest"):
        if replay[k] != recorded[k]:
            out.append(Issue(f"$.{k}", "score-replay", f"{k} must equal the recording's"))
    return out

# ---------------------------------------------------------------- trace

_ev_base = {"schema": Const("score-trace-event@1"), "runId": Id("run"), "seq": Int(0, 10**9)}
_ev_opt = {"at": Timestamp}


def _event(type_: str, required: dict, optional: dict | None = None, invariants=None) -> Obj:
    return Obj(required={**_ev_base, "type": Const(type_), **required},
               optional={**_ev_opt, **(optional or {})},
               invariants=[*(invariants or []), no_secrets("ScoreTraceEvent")])


def _score_call_ok(d):
    if (d["response"] is None) == ("error" not in d):
        yield "", "exactly one of response or error"
    if d["callId"] != call_id(d["stage"], d["role"], d["agentId"], d["ordinal"], d["attempt"]):
        yield ".callId", "must equal call_id(stage, role, agentId, ordinal, attempt)"
    try:
        if d["requestHash"] != score_request_hash(d["request"]):
            yield ".requestHash", "must equal score_request_hash(request)"
    except ValueError as e:
        yield ".request", f"not hashable for replay: {str(e)[:120]}"
    if d["costRecordId"] != cost_id(d["callId"]):
        yield ".costRecordId", "must equal cost_id(callId)"
    if d["request"]["role"] != d["role"]:
        yield ".request.role", "must equal the event role"
    if d["request"]["outputSchema"] != SCORE_ROLE_SCHEMA[d["role"]]:
        yield ".request.outputSchema", f"a {d['role']} call requests {SCORE_ROLE_SCHEMA[d['role']]}"
    if d["stage"] != SCORE_ROLE_STAGE[d["role"]]:
        yield ".stage", f"a {d['role']} call runs in {SCORE_ROLE_STAGE[d['role']]}"
    yield from _no_stage(d)


def _score_cost_event_ok(d):
    if d["record"]["kind"] != "score":
        yield ".record.kind", "a score trace carries only score costs"


ScoreTraceEvent = define("ScoreTraceEvent", Union("type", {
    "score.run.start": _event("score.run.start", {"run": ScoreRun}),
    "score.stage.start": _event("score.stage.start", {"stage": ScoreStage}),
    "score.stage.end": _event("score.stage.end", {"stage": ScoreStage, "status": Enum(*STAGE_STATUSES)},
                              {"artifactDigest": Digest, "error": TypedError},
                              [Invariant("score-stage-error", "no review Stage on the error", _no_stage)]),
    "score.model.call": _event("score.model.call", {
        "callId": Id("call"), "stage": ScoreStage, "role": ScoreRole, "agentId": Slug,
        "ordinal": Int(0, 10**6), "attempt": Int(0, 0), "requestHash": Digest, "request": ScoreRequest,
        "response": Nullable(ModelResponse), "costRecordId": Id("cost"), "redactions": Redactions},
        {"error": TypedError, "latencyMs": Int(0, 10**9)},
        [Invariant("score-call-outcome", "response xor error; callId, requestHash and costRecordId recompute "
                   "from the payload; request role/schema and stage match the event role; the error omits "
                   "stage", _score_call_ok)]),
    "cost": _event("cost", {"record": CostRecord},
                   invariants=[Invariant("score-cost-kind", "only score costs", _score_cost_event_ok)]),
    "error": _event("error", {"error": TypedError},
                    invariants=[Invariant("score-error", "no review Stage on the error", _no_stage)]),
    "score.run.end": _event("score.run.end", {"status": Enum(*RUN_STATUSES),
                                              "incomplete": Arr(ScoreIncomplete, max_items=50)}),
}).describe("One JSON object per line in a score trace. Whole-file rules: scoring_family.validate_score_trace. "
            "The review TraceEvent changes only by its cost variant refusing kind=score."))


def validate_score_trace(events: list) -> list[Issue]:
    """Per-event validation (including payload hash/id recomputation) plus file rules: seq 0,1,2..., one runId,
    score.run.start first and naming the same run, score.run.end only last, each call id logged once, cost
    records naming the call that references them and the run's evalRunId/evalCaseId; in a strict-replay run every
    cost has basis replayed."""
    if not isinstance(events, list) or not events:
        return [Issue("$", "trace-empty", "a score trace has at least a score.run.start event")]
    out: list[Issue] = []
    for i, ev in enumerate(events):
        out.extend(Issue(f"[{i}]{x.path[1:]}", x.code, x.message) for x in validate("ScoreTraceEvent", ev))
    if out:
        return out
    rid = events[0]["runId"]
    if events[0]["type"] != "score.run.start" or events[0]["run"]["id"] != rid:
        out.append(Issue("[0]", "trace-order", "first event is score.run.start for this runId"))
    run = events[0].get("run", {})
    for i, ev in enumerate(events):
        if ev["seq"] != i:
            out.append(Issue(f"[{i}].seq", "trace-seq", f"expected {i}, got {ev['seq']}"))
        if ev["runId"] != rid:
            out.append(Issue(f"[{i}].runId", "trace-run", "events from more than one run"))
        if ev["type"] == "score.run.start" and i != 0:
            out.append(Issue(f"[{i}]", "trace-order", "a trace names exactly one run document"))
        if ev["type"] == "score.run.end" and i != len(events) - 1:
            out.append(Issue(f"[{i}]", "trace-order", "score.run.end must be the last event"))
    seen: set[str] = set()
    costs = {ev["record"]["id"]: ev["record"] for ev in events if ev["type"] == "cost"}
    replay = run.get("mode") == "strict-replay"
    for i, ev in enumerate(events):
        if ev["type"] == "cost":
            r = ev["record"]
            if replay and r["basis"] != "replayed":
                # strict replay makes no call: every cost, including a recorded failure's, repeats the recorded
                # record (basis replayed, replayOf pinned; usdMicros may stay null) and is never new spend
                out.append(Issue(f"[{i}].record.basis", "trace-cost",
                                 "a strict-replay run carries only replayed costs, never new spend"))
            if r.get("runId") != rid or r.get("evalRunId") != run.get("evalRunId") \
                    or r.get("evalCaseId") != run.get("evalCaseId"):
                out.append(Issue(f"[{i}].record", "trace-cost", "cost record names another run, eval run or case"))
        cid = ev.get("callId")
        if cid is None:
            continue
        if cid in seen:
            out.append(Issue(f"[{i}]", "trace-duplicate", f"{cid} logged twice"))
        seen.add(cid)
        rec = costs.get(ev.get("costRecordId"))
        if rec is not None and rec.get("callId") != cid:
            out.append(Issue(f"[{i}].costRecordId", "trace-cost", "cost record names another call"))
        if rec is not None and rec.get("role") != ev["role"]:
            out.append(Issue(f"[{i}].costRecordId", "trace-cost", "cost record names another role"))
    return out
