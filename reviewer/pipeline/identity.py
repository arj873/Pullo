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

from reviewer.contracts import CONTRACTS_VERSION, is_turn_schema, require, validate
from reviewer.contracts.canonical import (CANONICAL_VERSION, config_digest, digest, idempotency_key_eval,
                                          idempotency_key_local, profile_digest, run_id)
from reviewer.contracts.redaction import MAX_PASSES, PROTECTED_PATTERNS, REDACTION_VERSION
from reviewer.tools import Limits

from . import prompts, repocov, retrieval
from .errors import PipelineError
from .judging import ISSUE_KEY_VERSION

PIPELINE_VERSION = "pipeline@1"
# Behaviour of the PARTIAL path that is not in a prompt template digest: coverage wording (statement/review.md),
# the judge's coverage disclosure, the review-comments@2 wrapper, coverage validation rules. Bumped on any change
# to it; bound only when coverage is present, so full-view run ids/receipts/outputs stay byte-identical.
#   partial-disclosure@2: C1 absent-side flag vs manifest, C2 logical-path uniqueness, C3 contextGap in statement,
#   C4 judge coverage + comments.json coverage; @1 was the S0B-02b/addendum behaviour.
PARTIAL_BEHAVIOR = "partial-disclosure@2"
# Behaviour of the retrieval chains (hop/ordinal allocation, dedup, caps, honest ends, history rendering). Bound only
# when a role returns the Turn envelope, so legacy profiles keep their ids.
#   @2: citations.citableRefs (S1-15) are built from the chain's delivered results; @1 had none.
RETRIEVAL_BEHAVIOR = "retrieval-pipeline@2"
# Behaviour of the opt-in context-check prompt arm that is not in a template digest (task selection by prompt id, the
# unchanged deterministic fallback wording). Bound only when the experiment is selected.
EXPERIMENT_BEHAVIOR = "context-check-arm@1"
RECEIPT_SCHEMA = "run-receipt@1"


def redaction_fingerprint() -> str:
    """Same recipe as scoring.suite.redaction_fingerprint (a test pins them equal)."""
    return digest({"version": REDACTION_VERSION, "maxPasses": MAX_PASSES,
                   "patterns": [[pid, pat.pattern, pat.flags] for pid, pat in PROTECTED_PATTERNS]})


def engine_identity() -> dict:
    """Everything about the engine that changes behavior: pass this as `config=` to synthetic_config_digest.
    The identity always names the software actually running. A pre-@6 recording is replayed by the frozen old
    software, never by this engine under an old identity."""
    return {"pipeline": PIPELINE_VERSION, "contracts": CONTRACTS_VERSION,
            "canonical": CANONICAL_VERSION,
            "redaction": {"version": REDACTION_VERSION, "fingerprint": redaction_fingerprint()},
            "prompts": prompts.template_digests(), "issueKey": ISSUE_KEY_VERSION,
            "firstSlice": {"views": "full_view", "triage": "fixed-rule@1", "specialists": ["generalist"],
                           "investigatorToolContinuations": False}}


def profile_ref(profile: dict) -> str:
    return f"{profile['id']}@{profile['version']}"


def turn_roles(profile: dict) -> list[str]:
    return [r for r in ("investigator", "verifier") if is_turn_schema(profile["roles"][r]["outputSchema"])]


def retrieval_policy(spec):
    """The RetrievalPolicy in force, or None when no role returns the Turn envelope."""
    if not turn_roles(spec.profile):
        return None
    return spec.host.retrieval or retrieval.RetrievalPolicy()


def tool_limits(spec) -> Limits:
    """The trusted ToolSession limits: the host's, else the full-repository profile for imports, else legacy."""
    if spec.host.tool_limits is not None:
        return spec.host.tool_limits
    return Limits.full_repository() if spec.imports is not None else Limits()


def check_retrieval_inputs(spec) -> None:
    """Policy/profile/imports consistency (before any provider could be contacted)."""
    turns = turn_roles(spec.profile)
    pol = spec.host.retrieval
    if pol is not None and not isinstance(pol, retrieval.RetrievalPolicy):
        raise PipelineError("invalid-input", "retrieval must be a RetrievalPolicy")
    if pol is not None and not turns:
        raise PipelineError("invalid-input", "a retrieval policy needs a profile role that returns the Turn schema")
    if turns:
        p = retrieval_policy(spec)
        want = {"investigator": p.investigator_prompt, "verifier": p.verifier_prompt}
        for r in turns:
            if spec.profile["roles"][r]["promptVersion"] != want[r]:
                raise PipelineError("invalid-input", f"profile {r}.promptVersion must equal the retrieval policy's "
                                    f"{want[r]!r}")
    if spec.imports is not None and spec.coverage is not None:
        raise PipelineError("invalid-input", "repository imports and a partial historical coverage are exclusive")
    if experiment_id(spec) != prompts.EXPERIMENT_BASELINE and "verifier" not in turns:
        raise PipelineError("invalid-input", "the context-check experiment needs a verifier role that returns the Turn schema")


def experiment_id(spec) -> str:
    """The opt-in prompt experiment the profile and policy select (`baseline` unless both experimental prompt ids are
    named). Half a selection is a typed refusal, never a silent baseline."""
    pol = retrieval_policy(spec)
    try:
        return prompts.experiment_in_force(None if pol is None else pol.verifier_prompt,
                                           spec.profile["roles"]["judge"]["promptVersion"])
    except ValueError as e:
        raise PipelineError("invalid-input", str(e)) from None


def config_snapshot_id(spec) -> str:
    lim = tool_limits(spec)
    extra = {} if spec.coverage is None else {"coverage": digest(spec.coverage), "partialBehavior": PARTIAL_BEHAVIOR}   # absent => full-view ids unchanged
    pol = retrieval_policy(spec)
    if pol is not None:
        extra["retrieval"] = {"behavior": RETRIEVAL_BEHAVIOR, "policy": pol.to_doc(), "turnRoles": turn_roles(spec.profile),
                              "prompts": prompts.retrieval_template_digests(),
                              "effective": retrieval.effective_limits(pol, spec.plan["budget"], lim.max_calls)}
    exp = experiment_id(spec)
    if exp != prompts.EXPERIMENT_BASELINE:       # absent for the baseline => default ids unchanged by this experiment
        extra["experiment"] = {"id": exp, "behavior": EXPERIMENT_BEHAVIOR, "tasks": prompts.experiment_task_digests(),
                               "verifierPrompt": pol.verifier_prompt,
                               "judgePrompt": spec.profile["roles"]["judge"]["promptVersion"]}
    if spec.imports is not None:
        extra["imports"] = {"base": digest(spec.imports.base), "head": digest(spec.imports.head),
                            "behavior": repocov.BEHAVIOR}
    return config_digest({**extra,
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
