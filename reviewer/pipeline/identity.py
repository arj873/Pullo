"""Run identity: engine/config versions, the ReviewRun document and the run receipt.

configSnapshotId binds, in one digest: engine + prompt template versions, contracts/canonical/redaction
versions and redaction policy fingerprint, the ModelProfile and Plan digests, the case input, both snapshot
ids, the tool limits, the comment cap and the host-supplied `config_identity` (for synthetic suites that is
`scoring.suite.synthetic_config_digest`, which already covers scripts and the dataset). It deliberately does
not contain the mode, run id, eval run id, authorization or clock, so a strict replay of the same case has
the same configSnapshotId as its recording.
"""

from __future__ import annotations

import dataclasses

from reviewer.contracts import CONTRACTS_VERSION, require, validate
from reviewer.contracts.canonical import (CANONICAL_VERSION, config_digest, digest, idempotency_key_eval,
                                          idempotency_key_local, profile_digest, run_id)
from reviewer.contracts.redaction import MAX_PASSES, PROTECTED_PATTERNS, REDACTION_VERSION
from reviewer.tools import Limits

from . import prompts
from .judging import ISSUE_KEY_VERSION

PIPELINE_VERSION = "pipeline@1"
RECEIPT_SCHEMA = "run-receipt@1"


def redaction_fingerprint() -> str:
    """Same recipe as scoring.suite.redaction_fingerprint (a test pins them equal)."""
    return digest({"version": REDACTION_VERSION, "maxPasses": MAX_PASSES,
                   "patterns": [[pid, pat.pattern, pat.flags] for pid, pat in PROTECTED_PATTERNS]})


def engine_identity() -> dict:
    """Everything about the engine that changes behavior: pass this as `config=` to synthetic_config_digest."""
    return {"pipeline": PIPELINE_VERSION, "contracts": CONTRACTS_VERSION, "canonical": CANONICAL_VERSION,
            "redaction": {"version": REDACTION_VERSION, "fingerprint": redaction_fingerprint()},
            "prompts": prompts.template_digests(), "issueKey": ISSUE_KEY_VERSION,
            "firstSlice": {"views": "full_view", "triage": "fixed-rule@1", "specialists": ["generalist"],
                           "investigatorToolContinuations": False}}


def profile_ref(profile: dict) -> str:
    return f"{profile['id']}@{profile['version']}"


def config_snapshot_id(spec) -> str:
    lim = spec.host.tool_limits or Limits()
    return config_digest({
        "schema": "pipeline-run-config@1", "engine": engine_identity(),
        "profile": profile_digest(spec.profile), "plan": digest(spec.plan), "case": digest(spec.case),
        "snapshots": {"base": spec.base.manifest["snapshotId"], "head": spec.head.manifest["snapshotId"]},
        "toolLimits": dataclasses.asdict(lim), "commentCap": spec.host.comment_cap,
        "host": spec.host.config_identity})


def build_run(spec, backend, cfg_id: str) -> dict:
    case, host = spec.case, spec.host
    base_id, head_id = case["base"]["snapshotId"], case["head"]["snapshotId"]
    ev = host.eval
    if ev is not None:
        key = idempotency_key_eval(ev.eval_run_id, ev.case_id, ev.repeat, base_id, head_id)
        trigger = "eval"
    else:
        key = idempotency_key_local(case["repo"], base_id, head_id)
        trigger = "manual-rerun" if host.attempt > 1 else "cli"
    run = {"id": run_id(key, host.attempt), "idempotencyKey": key, "attempt": host.attempt, "trigger": trigger,
           "source": "local", "mode": backend.mode, "access": "read-only@1", "repo": case["repo"],
           "baseSnapshotId": base_id, "headSnapshotId": head_id, "profile": profile_ref(spec.profile),
           "planVersion": spec.plan["version"], "configSnapshotId": cfg_id, "status": "running", "incomplete": []}
    if host.attempt > 1:
        run["rerunOf"] = run_id(key, host.attempt - 1)
    if ev is not None:
        run.update(evalRunId=ev.eval_run_id, evalCaseId=ev.case_id, repeat=ev.repeat)
    if backend.mode == "live":
        run["spendAuthorization"] = backend.authorization_digest
    else:
        run["replayOf"] = backend.replay_of
    if host.wall_clock is not None:
        run["startedAt"] = host.wall_clock()
    return run


def final_run(run: dict, status: str, incomplete: list, error: dict | None, wall_clock) -> dict:
    out = dict(run)
    out["status"], out["incomplete"] = status, incomplete
    if error is not None:
        out["error"] = error
    if wall_clock is not None:
        out["endedAt"] = wall_clock()
    return require("ReviewRun", out)


def validate_receipt(doc) -> list[str]:
    """Structural check of a run receipt (pipeline-owned document, not a contract entity)."""
    need = {"schema": str, "runId": str, "mode": str, "status": str, "caseId": str, "configSnapshotId": str,
            "versions": dict, "profile": dict, "plan": dict, "snapshots": dict, "traceDigest": str,
            "artifactDigests": dict, "outputs": dict, "cost": dict, "authorization": (str, type(None)),
            "replayOf": (str, type(None)), "pin": (dict, type(None))}
    if not isinstance(doc, dict):
        return ["receipt is not an object"]
    out = [f"missing/invalid {k}" for k, t in need.items() if not isinstance(doc.get(k), t)]
    if doc.get("schema") != RECEIPT_SCHEMA:
        out.append("wrong schema")
    return out
