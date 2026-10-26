"""Offline replay from a stage (`stage-replay`): stages before `fromStage` are ADOPTED from a pinned recording,
the rest is re-executed against the gateway in strict replay.

Trust model. The recording trace is pinned by digest outside the trace (ReplayBackend). Everything adopted is
checked against THAT trace, never against a receipt or a file beside it:
  * the stored artifact of each adopted stage must be contract-valid, belong to the recorded run, chain to the
    previous artifact and hash to the checkpoint event that sits in the pinned trace;
  * the adopted events are the pinned trace's own stage segments, re-stamped only for run identity and cost basis
    (`replayed`, `replayOf`), exactly as the gateway's strict replay writes them.
Nothing is copied from the recording's receipt. Mutating loaded events under an unchanged pin is the gateway
owner's concern (NEW5) and is not claimed here.
"""

from __future__ import annotations

import copy
from pathlib import Path

from reviewer.contracts import ContractInputError, ContractViolation, loads_strict, require
from reviewer.contracts.canonical import artifact_digest
from reviewer.contracts.stages import REPLAYABLE_FROM, STAGES, artifact_name

from .compare import segment
from .errors import PipelineError
from .store import RunDir

FORK_NOT_IMPLEMENTED = (
    "fork (zero-cost recorded prefix + live suffix) is not implemented: a live Gateway cannot account a recorded "
    "prefix inside one run (its recorder binding is live-xor-strict-replay), and the pipeline will not forge a prefix "
    "it cannot re-verify. It needs a gateway fork seam (routed to the gateway owner); use StageReplay for offline replay.")


def check_request(spec) -> None:
    sr = spec.stage_replay
    if sr.from_stage not in REPLAYABLE_FROM:
        raise PipelineError("invalid-input", f"stage replay can start at {REPLAYABLE_FROM}, not {sr.from_stage!r}")
    if getattr(spec.backend, "mode", None) != "strict-replay":
        raise PipelineError("config", "stage replay is always offline: the backend must be a pinned ReplayBackend")
    if spec.fork is not None:
        raise PipelineError("invalid-input", "stage replay and fork are different operations; give one")


def _restamp_cost(rec: dict, run: dict, cost_kind: str, ev) -> dict:
    """The record the gateway's strict replay writes for a recorded cost (same recipe, new run identity)."""
    doc = {k: v for k, v in rec.items() if k not in ("runId", "evalRunId", "evalCaseId", "replayOf", "basis")}
    doc.update(basis="replayed", replayOf=rec["id"], runId=run["id"])
    if cost_kind == "eval":
        doc["kind"] = "eval"
        doc["evalRunId"], doc["evalCaseId"] = run["evalRunId"], run["evalCaseId"]
    else:
        doc["kind"] = cost_kind
    return require("CostRecord", doc)


def _restamp_artifact(art: dict, run: dict) -> dict:
    a = copy.deepcopy(art)
    a["runId"] = run["id"]
    p = a["payload"]
    if p["stage"] == "INGEST":
        p["run"] = run
    for k in ("hypotheses", "findings", "comments"):
        for x in p.get(k, []):
            x["runId"] = run["id"]
    return a


def adopt(spec, run: dict, recording, orig: dict, cost_kind: str) -> dict:
    """-> {prefix events (run.start first), artifacts, model_calls, consumed callIds}. Raises PipelineError."""
    sr = spec.stage_replay
    stages = STAGES[:STAGES.index(sr.from_stage)]
    recorded_run = recording.events[0]["run"]
    rdir = Path(sr.recording_dir)
    if rdir.name != recorded_run["id"]:
        raise PipelineError("checkpoint-invalid", "recording_dir is not the directory of the pinned recording's run")
    rd = RunDir.open(Path(rdir.parent).resolve(), rdir.name, create=False)
    if rd is None:
        raise PipelineError("checkpoint-invalid", "recording_dir does not exist")
    try:
        artifacts, prev = {}, None
        for st in stages:
            raw = rd.read_artifact(artifact_name(st, spec.plan["version"]))
            if raw is None:
                raise PipelineError("checkpoint-invalid", f"recorded {st} artifact is missing")
            try:
                art = require("StageArtifact", loads_strict(raw))
            except (ContractInputError, ContractViolation) as e:
                raise PipelineError("checkpoint-invalid", f"recorded {st} artifact is invalid: {str(e)[:200]}") from None
            cp = orig[st][-1]
            if art["stage"] != st or art["runId"] != recorded_run["id"] or art["planVersion"] != spec.plan["version"]:
                raise PipelineError("checkpoint-invalid", f"recorded {st} artifact belongs to another run/plan")
            if artifact_digest(art) != cp["artifactDigest"]:
                raise PipelineError("checkpoint-invalid", f"recorded {st} artifact does not match the pinned trace's "
                                    "checkpoint digest (tampered or from another recording)")
            if art["inputDigest"] != (None if prev is None else artifact_digest(prev)):
                raise PipelineError("checkpoint-invalid", f"recorded {st} artifact is not chained to the previous one")
            if art["status"] == "failed":
                raise PipelineError("checkpoint-invalid", f"recorded {st} failed; a failed stage cannot be adopted")
            artifacts[st] = prev = _restamp_artifact(art, run)
    finally:
        rd.close()
    for st in STAGES[STAGES.index(sr.from_stage):]:
        for e in orig[st]:
            if e["type"] == "model.call" and e.get("error", {}).get("code") == "budget-exhausted":
                raise PipelineError("checkpoint-invalid", "the recording has a budget refusal at or after the replay "
                                    "stage; the replay ledger cannot be seeded with prior-stage spend")
    prefix = [{"type": "run.start", "run": run}]
    consumed = []
    for st in stages:
        for e in orig[st]:
            body = {k: v for k, v in copy.deepcopy(e).items() if k not in ("schema", "runId", "seq", "type")}
            if e["type"] == "cost":
                body["record"] = _restamp_cost(e["record"], run, cost_kind, e)
            if e["type"] == "model.call":
                consumed.append(e["callId"])
            prefix.append({"type": e["type"], **body})
    return {"prefix": prefix, "artifacts": artifacts, "model_calls": len(consumed), "consumed": consumed}
