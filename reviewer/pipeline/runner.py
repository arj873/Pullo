"""run_review: pre-flight, idempotency, recovery/resume, execution and result assembly.

Order of decisions (all before any provider could be contacted):
  1. validate every input document and cross-check ids (labels/SuiteCase refused);
  2. derive the run id and configSnapshotId; for a replay, compare them with the recording's run;
  3. resolve the host output root (outside every input/fixture root, no symlinks);
  4. look at out_root/<runId>/: a completed run with the same identity is returned untouched (idempotent, no
     provider call, no rewrite); a different identity is refused; an interrupted RECORDING raises
     recovery-required (provider contact is unknown, so nothing is re-issued); an interrupted REPLAY resumes
     from its last validated checkpoint.
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path

from reviewer.contracts import ContractInputError, ContractViolation, loads_strict, require, validate
from reviewer.contracts.canonical import artifact_digest, comparable, digest
from reviewer.contracts.stages import STAGES, artifact_name
from reviewer.gateway import Recorder, TraceError, bytes_digest, load_trace
from reviewer.tools import Limits

from . import coverage as cov_mod
from . import identity, impactcov, repocov, retrieval, specialists, stagereplay
from .compare import first_difference, split_recording
from .engine import Engine, render_outputs
from .errors import PipelineError
from .runguard import RunGuard
from .spec import ReviewSpec, RunResult
from .store import RunDir, resolve_out_root

BASIS = ("measured", "estimated", "unknown", "replayed", "synthetic")
IDENTITY_KEYS = ("idempotencyKey", "attempt", "mode", "repo", "baseSnapshotId", "headSnapshotId", "profile",
                 "planVersion", "configSnapshotId", "evalRunId", "evalCaseId", "repeat", "replayOf",
                 "spendAuthorization", "trigger", "source")


# ---------------------------------------------------------------- validation (no side effects)

def validate_spec(spec: ReviewSpec) -> None:
    case = spec.case
    if not isinstance(case, dict) or hasattr(case, "labels"):
        raise PipelineError("invalid-input", "case must be a CaseInput document (never a SuiteCase or labels)")
    try:
        require("CaseInput", case)
        for name, snap, ref in (("base", spec.base, case["base"]), ("head", spec.head, case["head"])):
            require("SnapshotManifest", snap.manifest)
            if snap.manifest["snapshotId"] != ref["snapshotId"]:
                raise PipelineError("identity-mismatch", f"{name} manifest {snap.manifest['snapshotId'][:24]}... "
                                    f"is not CaseInput.{name}.snapshotId")
            if not Path(snap.root).is_dir():
                raise PipelineError("invalid-input", f"{name} snapshot root is not a directory")
        require("ModelProfile", spec.profile)
        require("Plan", spec.plan)
    except ContractViolation as e:
        raise PipelineError("invalid-input", str(e)[:500]) from e
    plan, prof = spec.plan, spec.profile
    ref = identity.profile_ref(prof)
    if plan["modelProfile"] != ref:
        raise PipelineError("identity-mismatch", f"Plan names profile {plan['modelProfile']}, supplied {ref}")
    if (plan["version"], plan["tier"], plan["triage"]) != (1, "standard", "fixed-rule@1") \
            or prof["tier"] != "standard" or prof["triage"] != "fixed-rule@1":
        raise PipelineError("invalid-input", "first slice runs only the fixed standard Plan v1 (fixed-rule@1)")
    if plan["specialists"] != identity.plan_specialists(spec):
        if identity.plan_specialists(spec) == ["generalist"]:
            raise PipelineError("invalid-input", "first slice supports exactly one specialist, 'generalist'")
        raise PipelineError("invalid-input", "investigator.impact@v3 needs Plan.specialists "
                            f"{identity.plan_specialists(spec)} (the specialist investigators, in run order)")
    host = spec.host
    if not (isinstance(host.attempt, int) and not isinstance(host.attempt, bool) and 1 <= host.attempt <= 1000):
        raise PipelineError("invalid-input", "attempt must be an integer >= 1")
    if host.eval is not None:
        if host.attempt != 1:
            raise PipelineError("invalid-input", "an eval execution is attempt 1; a repeat is a new eval run id")
        if host.eval.case_id != case["id"]:
            raise PipelineError("identity-mismatch", "EvalIdentity.case_id differs from CaseInput.id")
    if not (isinstance(host.comment_cap, int) and 1 <= host.comment_cap <= 50):
        raise PipelineError("invalid-input", "comment_cap must be 1..50")
    if host.tool_limits is not None and not isinstance(host.tool_limits, Limits):
        raise PipelineError("invalid-input", "tool_limits must be reviewer.tools.Limits")
    try:
        digest(host.config_identity)
    except (TypeError, ValueError) as e:
        raise PipelineError("invalid-input", f"config_identity is not canonical JSON: {e}") from e
    if getattr(spec.backend, "mode", None) not in ("live", "strict-replay"):
        raise PipelineError("config", "backend must be a RecordBackend or ReplayBackend")
    if spec.coverage is not None:
        cov_mod.validate(spec.coverage, spec.base.manifest, spec.head.manifest)
    identity.check_retrieval_inputs(spec)
    if spec.imports is not None:
        repocov.build(spec.imports, spec.base.manifest, spec.head.manifest, spec.case)   # raises invalid-input


# ---------------------------------------------------------------- entry point

def run_review(spec: ReviewSpec) -> RunResult:
    validate_spec(spec)
    if spec.fork is not None:
        raise PipelineError("config", stagereplay.FORK_NOT_IMPLEMENTED)
    if spec.stage_replay is not None:
        stagereplay.check_request(spec)
    backend = spec.backend
    cfg = identity.config_snapshot_id(spec)
    run = identity.build_run(spec, backend, cfg)
    # run.mode stays "strict-replay": the gateway binds its mode to run.start and has no stage-replay seam yet
    # (routed to the gateway owner). The stage-replay facts live in receipt.stageReplay, checked on idempotent reuse.
    try:
        require("ReviewRun", run)
    except ContractViolation as e:
        raise PipelineError("invalid-input", f"run document invalid: {str(e)[:300]}") from e
    if backend.mode == "strict-replay":
        recorded = backend.recording.events[0]["run"]
        if comparable(recorded, "ReviewRun") != comparable(run, "ReviewRun"):
            diff = sorted(k for k in set(recorded) | set(run) if comparable(recorded, "ReviewRun").get(k)
                          != comparable(run, "ReviewRun").get(k))
            raise PipelineError("identity-mismatch", "inputs/config differ from the recorded run in: "
                                + ", ".join(diff[:6]))
    orig = split_recording(backend.recording.events) if backend.mode == "strict-replay" else None
    forbidden = [spec.base.root, spec.head.root, *spec.host.forbidden_roots]
    real_out = resolve_out_root(spec.host.out_root, forbidden)
    backend.preflight(spec.profile, spec.plan["budget"])
    rd = RunDir.open(real_out, run["id"], create=False)
    if rd is None:
        rd = RunDir.open(real_out, run["id"], create=True)
        if rd.created:
            adopted = None
            if spec.stage_replay is not None:
                try:
                    a = stagereplay.adopt(spec, run, backend.recording, orig, "eval" if spec.host.eval else "review")
                except BaseException:
                    rd.remove_empty()
                    rd.close()
                    raise
                for st, art in a["artifacts"].items():        # the new run directory holds its own copies
                    rd.write_artifact(artifact_name(st, spec.plan["version"]),
                                      (json.dumps(art, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode())
                adopted = _Resume(a["prefix"], a["artifacts"], a["model_calls"])
                adopted.consumed = a["consumed"]
            return _execute(spec, run, rd, resume=adopted, orig=orig)
    try:
        return _existing(spec, run, rd, orig)
    finally:
        rd.close()


def _existing(spec, run, rd, orig) -> RunResult:
    receipt, runjson = rd.read_json("receipt.json"), rd.read_json("run.json")
    if receipt is not None or runjson is not None:
        if receipt is None or runjson is None:
            raise PipelineError("checkpoint-invalid", "run.json/receipt.json are incomplete in the output directory")
        for k in IDENTITY_KEYS:
            if runjson.get(k) != run.get(k):
                raise PipelineError("identity-mismatch", f"output directory {run['id']} is bound to a different "
                                    f"{k}; use a new output root or a new attempt")
        want = None if spec.stage_replay is None else spec.stage_replay.from_stage
        if (receipt.get("stageReplay") or {}).get("fromStage") != want:
            raise PipelineError("identity-mismatch", f"output directory {run['id']} was produced by a different "
                                "replay start stage; use a new eval run id")
        return load_run_result(rd, spec.plan["version"], idempotent=True)
    trace = rd.read("trace.jsonl")
    if spec.backend.mode == "live":
        if trace is not None and trace.strip():
            raise PipelineError("recovery-required", f"run {run['id']} was interrupted after {len(trace.splitlines())} "
                                "trace event(s); provider contact is unknown, so nothing is re-issued and its spend "
                                "reservations stay charged. Reconcile, then record under a new eval run id.")
        rd.remove("trace.jsonl")
        return _execute(spec, run, rd, resume=None, orig=orig)
    return _execute(spec, run, rd, resume=_load_resume(spec, run, rd, orig), orig=orig)


# ---------------------------------------------------------------- resume validation

class _Resume:
    def __init__(self, prefix, artifacts, model_calls):
        self.prefix, self.artifacts, self.model_calls = prefix, artifacts, model_calls
        self.consumed: list = []          # stage replay: recorded callIds adopted from the pinned recording


def _read_events(data: bytes) -> list:
    data = data[:data.rfind(b"\n") + 1]                 # drop a torn final line
    out = []
    for n, line in enumerate(data.split(b"\n")[:-1]):
        try:
            out.append(loads_strict(line))
        except ContractInputError as e:
            raise PipelineError("checkpoint-invalid", f"trace line {n + 1}: {e}") from None
    return out


def _load_resume(spec, run, rd, orig) -> "_Resume | None":
    data = rd.read("trace.jsonl")
    if data is None:
        return None
    events = _read_events(data)
    last = max((i for i, e in enumerate(events) if isinstance(e, dict) and e.get("type") == "checkpoint"), default=None)
    if last is None:
        return None
    prefix = events[:last + 1]
    try:
        load_trace(prefix, allow_partial=True)
    except TraceError as e:
        raise PipelineError("checkpoint-invalid", f"interrupted trace is inconsistent: {e}") from None
    if prefix[0]["type"] != "run.start" or prefix[0]["run"]["id"] != run["id"] \
            or comparable(prefix[0]["run"], "ReviewRun") != comparable(run, "ReviewRun"):
        raise PipelineError("checkpoint-invalid", "interrupted trace was started under a different run/config")
    # exactly run.start + k complete, ordered stage segments
    pos, k = 1, 0
    for st in STAGES:
        if pos >= len(prefix):
            break
        seg = [prefix[pos]]
        if prefix[pos]["type"] != "stage.start" or prefix[pos]["stage"] != st:
            raise PipelineError("checkpoint-invalid", f"trace is not in stage order at {st}")
        j = pos + 1
        while j < len(prefix) and prefix[j]["type"] != "checkpoint":
            seg.append(prefix[j])
            j += 1
        if j >= len(prefix) or prefix[j]["stage"] != st:
            raise PipelineError("checkpoint-invalid", f"{st} segment has no matching checkpoint")
        pos, k = j + 1, k + 1
    if pos != len(prefix):
        raise PipelineError("checkpoint-invalid", "stray events between stage segments")
    artifacts = {}
    prev = None
    for st in STAGES[:k]:
        raw = rd.read_artifact(artifact_name(st, spec.plan["version"]))
        if raw is None:
            raise PipelineError("checkpoint-invalid", f"{st} artifact is missing")
        try:
            art = require("StageArtifact", loads_strict(raw))
        except (ContractInputError, ContractViolation) as e:
            raise PipelineError("checkpoint-invalid", f"{st} artifact is invalid: {str(e)[:200]}") from None
        want = next(e for e in prefix if e["type"] == "checkpoint" and e["stage"] == st)["artifactDigest"]
        if art["stage"] != st or art["runId"] != run["id"] or art["planVersion"] != spec.plan["version"]:
            raise PipelineError("checkpoint-invalid", f"{st} artifact belongs to another run/plan")
        if artifact_digest(art) != want:
            raise PipelineError("checkpoint-invalid", f"{st} artifact does not match its checkpoint digest (tampered)")
        if art["inputDigest"] != (None if prev is None else artifact_digest(prev)):
            raise PipelineError("checkpoint-invalid", f"{st} artifact is not chained to the previous artifact")
        if st == "INGEST" and comparable(art["payload"]["run"], "ReviewRun") != comparable(run, "ReviewRun"):
            raise PipelineError("checkpoint-invalid", "INGEST artifact binds a different run/config")
        artifacts[st] = prev = art
    # the validated prefix must equal the pinned recording, stage by stage
    for st in STAGES[:k]:
        seg = _segment_of(prefix, st)
        diff = first_difference(orig[st], seg)
        if diff is not None:
            raise PipelineError("checkpoint-invalid", f"checkpointed {st} differs from the recording: {diff}")
    for st in STAGES[k:]:
        for e in orig[st]:
            if e["type"] == "model.call" and e.get("error", {}).get("code") == "budget-exhausted":
                raise PipelineError("checkpoint-invalid", "the recording has a budget refusal at or after the resume "
                                    "stage; the replay ledger cannot be seeded with prior-stage spend, so a safe resume "
                                    "is impossible. Replay from scratch in a new output root.")
    return _Resume(prefix, artifacts, sum(1 for e in prefix if e["type"] == "model.call"))


def _segment_of(events, stage):
    from .compare import segment
    return segment(events, stage)


# ---------------------------------------------------------------- execution

def _execute(spec, run, rd, *, resume: "_Resume | None", orig) -> RunResult:
    host, backend = spec.host, spec.backend
    path = str(rd.path / "trace.jsonl")
    if resume is not None and rd.exists("trace.jsonl"):
        n = 1
        while rd.exists(f"trace.interrupted-{n}.jsonl"):
            n += 1
        rd.move_aside("trace.jsonl", f"trace.interrupted-{n}.jsonl")
    elif backend.mode == "strict-replay" and rd.exists("trace.jsonl"):
        n = 1
        while rd.exists(f"trace.interrupted-{n}.jsonl"):
            n += 1
        rd.move_aside("trace.jsonl", f"trace.interrupted-{n}.jsonl")
    guard = RunGuard(host, spec.plan["budget"])
    if not _accepts_guard(backend.make_gateway):
        raise PipelineError("config", "the backend's make_gateway cannot take the host attempt guard: a retry or "
                            "repair could not be stopped after cancellation or a deadline")
    recorder = Recorder(run["id"], path)
    try:
        if resume is None:
            recorder.start(run)
        else:
            for ev in resume.prefix:
                recorder.append(ev["type"], **{k: v for k, v in ev.items() if k not in ("schema", "runId", "seq", "type")})
        ev_cfg = host.eval
        gw = backend.make_gateway(run_id=run["id"], profile=spec.profile, budget=spec.plan["budget"],
                                  recorder=recorder, cost_kind="eval" if ev_cfg else "review",
                                  eval_run_id=ev_cfg.eval_run_id if ev_cfg else None,
                                  eval_case_id=ev_cfg.case_id if ev_cfg else None, guard=guard)
    except PipelineError:
        recorder.close()
        if resume is None and rd.created and not any(e["type"] == "model.call" for e in recorder.events):
            rd.remove_empty()
        rd.close()
        raise
    try:
        eng = Engine(spec, run, rd, recorder, gw, orig=orig, prior_artifacts=resume.artifacts if resume else None,
                     prior_model_calls=resume.model_calls if resume else 0, guard=guard)
        eng.check_adopted_outputs()
    except BaseException:
        recorder.close()
        raise
    try:
        eng.run_all()
        return _finalize(spec, run, rd, eng, recorder, gw, resume.consumed if resume is not None else ())
    except BaseException:
        recorder.close()
        raise
    finally:
        rd.close()


def _finalize(spec, run, rd, eng, recorder, gw, consumed=()) -> RunResult:
    host = spec.host
    status, incomplete, error = eng.terminal()
    recorder.end(status, incomplete)
    raw = rd.read("trace.jsonl")
    tdigest = bytes_digest(raw)
    if tdigest != recorder.trace_digest():
        raise PipelineError("checkpoint-invalid", "trace file bytes differ from the recorded events")
    final = identity.final_run(run, status, incomplete, error, host.wall_clock)
    run_bytes = (json.dumps(final, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    outputs = {"run.json": rd.write("run.json", run_bytes)}
    for name in ("comments.json", "review.md"):
        outputs[name] = _sha(rd.read(name))
    if eng.coverage_record is not None:
        outputs["coverage.json"] = rd.write("coverage.json", _json_bytes(eng.coverage_record))
    events = list(recorder.events)
    cost = cost_summary(events)
    latency = {"totalMs": int(max(0.0, eng.clock() - eng.t0) * 1000),
               "stagesMs": {s: eng.stage_ms.get(s) for s in STAGES}}
    report = gw.report()
    # a resumed replay consumed its earlier stages in the interrupted process: account for them explicitly
    report["priorStageModelCalls"] = eng.expected_unconsumed
    report["unconsumedRecordedCalls"] -= eng.expected_unconsumed
    changed = {f["path"] for f in eng.artifacts["PREPARE"]["payload"]["files"]} if "PREPARE" in eng.artifacts else set()
    receipt = build_receipt(spec, final, eng.digests, tdigest, outputs, cost, latency, report,
                            eng.resumed_from, eng.needs_reconciliation, events=events,
                            coverage=eng.coverage_record, guard=eng.guard,
                            impact=impactcov.summarize(events, changed) if eng.impact else None)
    if spec.stage_replay is not None:
        receipt["stageReplay"] = {
            "fromStage": spec.stage_replay.from_stage, "replayOf": final["replayOf"],
            "recordingTraceDigest": spec.backend.expected_trace_digest, "pinSource": spec.backend.pin_source,
            "adoptedStages": list(STAGES[:STAGES.index(spec.stage_replay.from_stage)]),
            "consumedPrefixCallIds": list(consumed),
            "consumptionComplete": bool(eng.fatal is None and report["unconsumedRecordedCalls"] == 0)}
    problems = identity.validate_receipt(receipt)
    if problems:
        raise PipelineError("checkpoint-invalid", "receipt invalid: " + "; ".join(problems))
    rd.write("receipt.json", (json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode())
    return assemble(rd, final, eng.artifacts, events, receipt, cost, latency, idempotent=False,
                    resumed_from=eng.resumed_from, gateway_report=report, pv=spec.plan["version"])


def _accepts_guard(fn) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return "guard" in params or any(p.kind is p.VAR_KEYWORD for p in params.values())


def _json_bytes(doc) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- receipt, cost, result

def cost_summary(events: list) -> dict:
    records = [e["record"] for e in events if e["type"] == "cost"]
    by = {b: {"records": 0, "usdMicros": 0} for b in BASIS}
    for r in records:
        b = by[r["basis"]]
        b["records"] += 1
        b["usdMicros"] = None if (b["usdMicros"] is None or r["usdMicros"] is None) else b["usdMicros"] + r["usdMicros"]
    for b in by.values():
        if b["records"] == 0:
            b["usdMicros"] = 0
    actual = [by[x]["usdMicros"] for x in ("measured", "estimated", "unknown")]
    return {"records": records, "byBasis": by, "liveCalls": sum(1 for r in records if r["basis"] != "replayed"),
            "replayedCalls": by["replayed"]["records"],
            "actualProviderUsdMicros": None if any(a is None for a in actual) else sum(actual),
            "syntheticUsdMicros": by["synthetic"]["usdMicros"], "replayedUsdMicros": by["replayed"]["usdMicros"],
            "note": "Synthetic and replayed amounts are not provider spend. No per-review cost target is claimed."}


def retrieval_section(spec, events: list, guard=None) -> dict | None:
    """Receipt/result section for retrieval profiles: the policy in force, what actually bound, and per-chain
    facts re-derived from the trace. None for legacy profiles (their receipts are unchanged)."""
    pol = identity.retrieval_policy(spec)
    if pol is None:
        return None
    lim = identity.tool_limits(spec)
    sec = {"policy": pol.to_doc(), "policyDigest": pol.digest, "turnRoles": identity.turn_roles(spec.profile),
           "effective": retrieval.effective_limits(pol, spec.plan["budget"], lim.max_calls),
           "summary": retrieval.summarize(events)}
    if guard is not None:
        sec["guardRefusals"] = list(guard.refusals)
    return sec


def build_receipt(spec, final, digests, tdigest, outputs, cost, latency, gw_report, resumed_from, recon, *,
                  events, coverage=None, guard=None, impact=None) -> dict:
    backend = spec.backend
    ident = identity.engine_identity()
    rsec = retrieval_section(spec, events, guard)
    return {
        "schema": identity.RECEIPT_SCHEMA, "runId": final["id"], "mode": final["mode"], "status": final["status"],
        "caseId": spec.case["id"], "evalRunId": final.get("evalRunId"), "configSnapshotId": final["configSnapshotId"],
        "versions": {"pipeline": ident["pipeline"], "contracts": ident["contracts"], "canonical": ident["canonical"],
                     "redaction": ident["redaction"], "prompts": ident["prompts"], "issueKey": ident["issueKey"]},
        "profile": {"ref": final["profile"], "digest": digest_of_profile(spec.profile)},
        "plan": {"version": spec.plan["version"], "digest": digest(spec.plan)},
        "snapshots": {"base": final["baseSnapshotId"], "head": final["headSnapshotId"]},
        "caseInputDigest": digest(spec.case), "hostConfigIdentity": digest(spec.host.config_identity),
        "authorization": final.get("spendAuthorization"), "replayOf": final.get("replayOf"),
        "pin": None if backend.mode == "live" else {"traceDigest": backend.expected_trace_digest,
                                                    "source": backend.pin_source},
        "traceDigest": tdigest, "artifactDigests": dict(digests), "outputs": outputs,
        "cost": {k: v for k, v in cost.items() if k != "records"}, "latency": latency,
        "gateway": {k: gw_report[k] for k in ("liveCalls", "replayedCalls", "retainedCalls", "unconsumedRecordedCalls",
                                              "priorStageModelCalls")},
        **({} if coverage is None else {"coverageDigest": digest(coverage)}),
        **({} if rsec is None else {"retrieval": rsec}),
        **({} if impact is None else {"impact": impact}),       # impact-coverage@1, impact mode only
        "resumedFrom": resumed_from, "needsReconciliation": bool(recon),
        "limits": ["hashes detect inconsistent edits and equality with a trusted pin; they do not authenticate a "
                   "maliciously rewritten whole trace", "synthetic pricing is not provider spend"]}


def digest_of_profile(profile: dict) -> str:
    from reviewer.contracts.canonical import profile_digest
    return profile_digest(profile)


def assemble(rd, final, artifacts, events, receipt, cost, latency, *, idempotent, resumed_from, gateway_report,
             pv) -> RunResult:
    v, j = artifacts["VERIFY"]["payload"], artifacts["JUDGE"]["payload"]
    stages = {s: {"status": a["status"], "artifactDigest": artifact_digest(a), "costRecordIds": a["costRecordIds"],
                  "path": f"artifacts/{artifact_name(s, pv)}"} for s, a in artifacts.items()}
    return RunResult(
        run_id=final["id"], run=final, status=final["status"], incomplete=final["incomplete"],
        error=final.get("error"), hypotheses=artifacts["INVESTIGATE"]["payload"]["hypotheses"],
        findings=v["findings"], verifications=v["verifications"], drops=list(v["drops"]) + list(j["drops"]),
        comments=j["comments"], stages=stages, cost=cost, latency=latency, run_dir=str(rd.path),
        trace_path=str(rd.path / "trace.jsonl"), trace_digest=receipt["traceDigest"], receipt=receipt,
        receipt_path=str(rd.path / "receipt.json"), comments_path=str(rd.path / "comments.json"),
        review_path=str(rd.path / "review.md"), idempotent=idempotent, resumed_from=resumed_from,
        gateway_report=gateway_report, retrieval=receipt.get("retrieval"), impact=receipt.get("impact"))


def load_run_result(rd: RunDir, pv: int, *, idempotent: bool = False) -> RunResult:
    """Rebuild a RunResult from a COMPLETED run directory, validating everything it reads: receipt, final run,
    every stage artifact (contract + chain + checkpoint digests) and the trace (consistency + pinned digest)."""
    receipt, runjson = rd.read_json("receipt.json"), rd.read_json("run.json")
    if receipt is None or runjson is None:
        raise PipelineError("checkpoint-invalid", "run directory has no receipt.json/run.json")
    bad = identity.validate_receipt(receipt)
    if bad:
        raise PipelineError("checkpoint-invalid", "receipt invalid: " + "; ".join(bad))
    try:
        final = require("ReviewRun", runjson)
    except ContractViolation as e:
        raise PipelineError("checkpoint-invalid", f"run.json invalid: {str(e)[:200]}") from None
    raw = rd.read("trace.jsonl")
    if raw is None or bytes_digest(raw) != receipt["traceDigest"]:
        raise PipelineError("checkpoint-invalid", "trace.jsonl does not match the receipt digest")
    try:
        trace = load_trace(raw)
    except TraceError as e:
        raise PipelineError("checkpoint-invalid", f"trace invalid: {e}") from None
    if trace.run_id != final["id"] or final["status"] != receipt["status"]:
        raise PipelineError("checkpoint-invalid", "run.json, receipt and trace disagree")
    end = trace.events[-1]
    if end["status"] != final["status"] or end["incomplete"] != final["incomplete"]:
        raise PipelineError("checkpoint-invalid", "run.end disagrees with run.json")
    artifacts, prev = {}, None
    for st in STAGES:
        data = rd.read_artifact(artifact_name(st, pv))
        if data is None:
            raise PipelineError("checkpoint-invalid", f"{st} artifact is missing")
        try:
            art = require("StageArtifact", loads_strict(data))
        except (ContractInputError, ContractViolation) as e:
            raise PipelineError("checkpoint-invalid", f"{st} artifact invalid: {str(e)[:200]}") from None
        dig = artifact_digest(art)
        cp = next((e for e in trace.events if e["type"] == "checkpoint" and e["stage"] == st), None)
        if cp is None or cp["artifactDigest"] != dig or receipt["artifactDigests"].get(st) != dig \
                or art["runId"] != final["id"]:
            raise PipelineError("checkpoint-invalid", f"{st} artifact does not match its checkpoint/receipt")
        if art["inputDigest"] != (None if prev is None else artifact_digest(prev)):
            raise PipelineError("checkpoint-invalid", f"{st} artifact is not chained")
        artifacts[st] = prev = art
    inv = artifacts["INVESTIGATE"]["payload"]
    if specialists.is_v3_plan(artifacts["TRIAGE"]["payload"]["plan"]):    # impact@v3: the merge record is re-derived
        try:
            again = specialists.merge(inv["hypotheses"])
        except KeyError:
            again = None
        if inv.get("merges") != again:
            raise PipelineError("checkpoint-invalid", "INVESTIGATE merges are not what the merge rule gives for its "
                                "hypotheses")
    elif "merges" in inv:
        raise PipelineError("checkpoint-invalid", "INVESTIGATE merges in a run without specialist investigators")
    for name, key in (("comments.json", "comments.json"), ("review.md", "review.md"), ("run.json", "run.json")):
        data = rd.read(name)
        if data is None or _sha(data) != receipt["outputs"].get(key):
            raise PipelineError("checkpoint-invalid", f"{name} does not match the receipt")
    cov = None
    if "coverageDigest" in receipt:
        cov = rd.read_json("coverage.json")
        data = rd.read("coverage.json")
        if cov is None or digest(cov) != receipt["coverageDigest"] or _sha(data) != receipt["outputs"].get("coverage.json"):
            raise PipelineError("checkpoint-invalid", "coverage.json does not match the receipt coverageDigest")
        if repocov.is_repository(cov):
            repocov.check(cov)
        elif cov.get("fullRepositoryCoverage") is not False:
            raise PipelineError("checkpoint-invalid", "coverage.json claims full-repository coverage")
    # the files a human reads must be what the judged artifacts render, not just what a (self-edited) receipt hashes
    cbytes, mbytes, _ = render_outputs(final, final["status"], final["incomplete"], final.get("error"), artifacts,
                                       list(trace.events), cov)
    for name, want in (("comments.json", cbytes), ("review.md", mbytes)):
        if rd.read(name) != want:
            raise PipelineError("checkpoint-invalid", f"{name} is not what the JUDGE/VERIFY artifacts and the trace "
                                "render: it was edited after PUBLISH or does not belong to this run")
    cost = cost_summary(trace.events)
    return assemble(rd, final, artifacts, trace.events, receipt, cost, receipt["latency"], idempotent=idempotent,
                    resumed_from=receipt.get("resumedFrom"), gateway_report=None, pv=pv)


def load_result(out_root, run_id: str, plan_version: int = 1) -> RunResult:
    """Public: load a completed run directory (e.g. for S0-08 reports or independent checks)."""
    real = resolve_out_root(out_root, ())
    rd = RunDir.open(real, run_id, create=False)
    if rd is None:
        raise PipelineError("checkpoint-invalid", f"no run directory {run_id}")
    try:
        return load_run_result(rd, plan_version)
    finally:
        rd.close()
