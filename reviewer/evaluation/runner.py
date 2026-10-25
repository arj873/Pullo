"""Smoke evaluation: record all six synthetic cases through the real pipeline, then strictly replay them.

The evaluator is the only component that sees labels and scripts. The engine gets a CaseInput, the two pinned
snapshot roots/manifests from the frozen suite copy, the profile, the Plan, host configuration and a backend.
Scripts reach only the synthetic provider inside RecordBackend; labels reach only score_loaded_case.

Record writes `eval.json` at the evaluation root (outside every run directory). It is the operator pin that a
later replay trusts: per case the ORIGINAL trace byte digest, the outcome digest and the config identity.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path

import reviewer
from reviewer.contracts import CONTRACTS_VERSION, ContractInputError, ContractViolation, loads_strict, require
from reviewer.contracts.canonical import (CANONICAL_VERSION, comparable, derive_id, digest,
                                          idempotency_key_eval, profile_digest, run_id as derive_run_id)
from reviewer.contracts.redaction import REDACTION_VERSION
from reviewer.gateway import SpendBook, bytes_digest, default_providers, parse_script, trusted_authorization
from reviewer.gateway.errors import typed_error
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReplayBackend,
                               ReviewSpec, SnapshotInput, engine_identity, run_review)
from reviewer.scoring import ScoringError, build_report, score_loaded_case, scored_case_result
from reviewer.scoring.report import SMOKE_LIMITATIONS
from reviewer.scoring.suite import scripts_identity, synthetic_config_digest
from reviewer.tools import Limits

from .errors import EvalError
from .freeze import freeze_suite, load_frozen, script_bytes
from .summary import render_summary

EVALUATOR_VERSION = "evaluation@1"
MANIFEST_SCHEMA = "evaluation-manifest@1"
OUTCOME_SCHEMA = "case-outcome@1"
COMMENT_CAP = 5
MAX_JSON_BYTES = 16 << 20
DEFAULT_SUITE = Path(reviewer.__file__).resolve().parent.parent / "fixtures" / "smoke"
_EXAMPLES = Path(reviewer.__file__).resolve().parent / "contracts" / "examples"
RUN_RE = re.compile(r"run_[0-9a-f]{16}")
EVR_RE = re.compile(r"evr_[0-9a-f]{16}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
PIPELINE_TO_TYPED = {"path-escape": "path-escape", "replay-pin": "replay-mismatch",
                     "replay-recording": "replay-mismatch", "invalid-input": "contract-violation",
                     "identity-mismatch": "contract-violation"}
COMPARED = (("hypotheses", "Hypothesis"), ("findings", "Finding"), ("verifications", None), ("drops", None),
            ("comments", "Comment"))


@dataclass
class CaseOutcome:
    case_id: str
    run_id: str
    ran: bool
    status: str
    case_result: dict
    outcome: dict
    problems: list = field(default_factory=list)
    comparison: dict | None = None
    result: object = None               # the engine's RunResult, None when no run happened
    manifest_entry: dict | None = None


@dataclass
class EvalOutcome:
    eval_run_id: str
    mode: str
    out_dir: Path
    report: dict | None
    report_path: Path | None
    manifest_path: Path
    manifest_digest: str
    summary: str
    cases: list
    problems: list
    exit_code: int


# ------------------------------------------------------------------ small helpers

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(doc) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_bytes_strict(path: Path, limit: int = MAX_JSON_BYTES) -> bytes:
    """A regular non-symlink file of at most `limit` bytes (no FIFO blocking)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as e:
        raise EvalError("recording", f"cannot open {path}: {e.strerror}") from None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise EvalError("recording", f"not a regular file: {path}")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise EvalError("recording", f"file too large: {path}")
    return data


def _load_json(data: bytes, what: str):
    try:
        return loads_strict(data)
    except ContractInputError as e:
        raise EvalError("recording", f"{what} is not strict JSON: {e}") from None


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def prepare_out(out, forbidden: list[Path]) -> Path:
    """Create (or adopt an empty) output directory that is not a symlink and not inside a forbidden root."""
    p = Path(out)
    if p.is_symlink():
        raise EvalError("output", f"output path {str(p)!r} is a symlink")
    real = Path(os.path.realpath(p))
    for f in forbidden:
        if _inside(real, f) or _inside(f, real):
            raise EvalError("output", f"output directory overlaps the input root {f}")
    if p.exists():
        if not p.is_dir():
            raise EvalError("output", f"output path {str(p)!r} is not a directory")
        if any(p.iterdir()):
            raise EvalError("output", f"output directory {str(p)!r} is not empty; use a clean directory")
    else:
        try:
            p.mkdir(parents=True)
        except OSError as e:
            raise EvalError("output", f"cannot create {str(p)!r}: {e.strerror}") from None
    return Path(os.path.realpath(p))


def default_profile_plan(profile=None, plan=None) -> tuple[dict, dict]:
    def ex(name):
        return loads_strict((_EXAMPLES / name).read_bytes())
    try:
        profile = require("ModelProfile", copy.deepcopy(profile) if profile is not None
                          else ex("ModelProfile.smoke-synthetic.json"))
        plan = require("Plan", copy.deepcopy(plan) if plan is not None else ex("Plan.json"))
    except ContractViolation as e:
        raise EvalError("config", str(e)) from None
    bad = sorted(r for r, d in profile["roles"].items() if d["provider"] != "synthetic")
    if bad:
        raise EvalError("config", f"smoke evaluation is synthetic-only; roles {bad} name a real provider")
    return profile, plan


def eval_config(profile: dict, plan: dict) -> dict:
    """Caller config bound into synthetic_config_digest (and so into EvalReport.configDigest)."""
    return {"engine": engine_identity(), "profile": profile_digest(profile), "plan": digest(plan),
            "toolLimits": dataclasses.asdict(Limits()), "commentCap": COMMENT_CAP, "evaluator": EVALUATOR_VERSION}


def expected_run_id(eval_run_id: str, case: dict) -> str:
    key = idempotency_key_eval(eval_run_id, case["id"], 0, case["base"]["snapshotId"], case["head"]["snapshotId"])
    return derive_run_id(key, 1)


def synthetic_authorization(now: dt.datetime) -> dict:
    """Built-in synthetic-only authorization for the convenience command: no real provider, short expiry."""
    return require("SpendAuthorization", {
        "schema": "spend-authorization@1", "id": "s0a-smoke-record", "issuedBy": "operator",
        "purpose": "python3 -m reviewer smoke record: scripted synthetic responses only; no provider spend.",
        "providers": ["synthetic"], "models": ["synthetic-fixture"],
        "maxUsdMicrosPerRun": 4_000_000, "maxUsdMicrosTotal": 100_000_000,
        "expiresAt": (now + dt.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")})


# ------------------------------------------------------------------ per-case execution

def _spec(suite, cid, profile, plan, host, backend) -> ReviewSpec:
    case = suite.cases[cid]
    root = suite.root
    return ReviewSpec(case=copy.deepcopy(case.input),
                      base=SnapshotInput(root / case.input["base"]["root"], copy.deepcopy(case.base_manifest)),
                      head=SnapshotInput(root / case.input["head"]["root"], copy.deepcopy(case.head_manifest)),
                      profile=copy.deepcopy(profile), plan=copy.deepcopy(plan), host=host, backend=backend)


def _harness_error(e: Exception) -> dict:
    if isinstance(e, PipelineError):
        code = PIPELINE_TO_TYPED.get(e.code, "internal")
        return typed_error(code, f"pipeline refused the case: {e}", detail={"pipelineCode": e.code})
    if isinstance(e, EvalError):
        return typed_error("replay-mismatch" if e.code == "recording" else "internal", str(e),
                           detail={"evaluatorCode": e.code})
    return typed_error("internal", f"engine raised {type(e).__name__}: {e}")


def _cost_summary(result) -> dict:
    """Cost buckets from the run's CostRecords plus the gateway's own call counters (the unconsumed-recording
    counter is reported by the gateway, not by the cost block)."""
    cost, gw = result.cost, result.gateway_report or {}
    keys = ("byBasis", "liveCalls", "replayedCalls", "actualProviderUsdMicros", "syntheticUsdMicros", "note")
    out = {k: cost.get(k) for k in keys}
    out["recordIds"] = [r.get("id") for r in cost.get("records", [])]
    out["gateway"] = {k: gw.get(k) for k in ("liveCalls", "replayedCalls", "retainedCalls", "unconsumedRecordedCalls")}
    return out


def _reconcile(result, problems: list) -> None:
    """CostRecords agree with the engine's cost buckets, belong to this run and no real spend happened."""
    cost = result.cost
    recs = cost.get("records", [])
    booked = sum(b.get("records", 0) for b in cost.get("byBasis", {}).values())
    if booked != len(recs):
        problems.append(f"cost buckets book {booked} records but the run has {len(recs)} CostRecords")
    if any(r.get("runId") != result.run_id for r in recs):
        problems.append("a CostRecord belongs to another run")
    if cost.get("actualProviderUsdMicros") not in (0, None):
        problems.append(f"actual provider spend reported: {cost.get('actualProviderUsdMicros')} usdMicros")


def run_case(suite, cid, *, eval_run_id, profile, plan, host_kw, backend_factory, latency_original=None,
             replay=False) -> CaseOutcome:
    """Run one case through run_review and score the actual result. A refusal or engine exception becomes an
    honest failed case; it never stops the other cases."""
    case = suite.cases[cid]
    want_id = expected_run_id(eval_run_id, case.input)
    problems: list[str] = []
    result, err = None, None
    try:
        backend = backend_factory(cid)
        host = HostConfig(eval=EvalIdentity(eval_run_id, cid, 0), attempt=1, **host_kw)
        result = run_review(_spec(suite, cid, profile, plan, host, backend))
    except Exception as e:   # noqa: BLE001 - recorded as a failed case; never hidden, never a fake success
        err = _harness_error(e)
        problems.append(f"no run: {err['message']}")
    if result is None:
        status, incomplete, comments, rid = "failed", [], [], want_id
        outcome = {"schema": OUTCOME_SCHEMA, "caseId": cid, "runId": rid, "ran": False, "status": status,
                   "incomplete": [], "error": err, "hypotheses": [], "findings": [], "verifications": [],
                   "drops": [], "comments": [], "cost": None, "latencyMs": None, "traceDigest": None,
                   "configSnapshotId": None, "stages": None}
        latency = None
    else:
        rid = result.run_id
        if not (isinstance(rid, str) and RUN_RE.fullmatch(rid) and result.run.get("id") == rid and rid == want_id):
            problems.append(f"engine returned run id {rid!r}; expected canonical {want_id}")
            rid = want_id    # score against the run we asked for: foreign comments count as false positives
        status, incomplete, err, comments = result.status, list(result.incomplete), result.error, result.comments
        _reconcile(result, problems)
        latency = result.latency.get("totalMs")
        outcome = {"schema": OUTCOME_SCHEMA, "caseId": cid, "runId": rid, "ran": True, "status": status,
                   "incomplete": incomplete, "error": err, "hypotheses": result.hypotheses,
                   "findings": result.findings, "verifications": result.verifications, "drops": result.drops,
                   "comments": comments, "cost": _cost_summary(result), "latencyMs": latency,
                   "traceDigest": result.trace_digest, "configSnapshotId": result.run.get("configSnapshotId"),
                   "stages": {st: v.get("status") for st, v in result.stages.items()},
                   "idempotent": result.idempotent, "resumedFrom": result.resumed_from}
    try:
        score = score_loaded_case(suite, cid, comments, run_id=rid, status=status, incomplete=incomplete, error=err)
    except ScoringError as e:
        problems.append(f"scorer refused the engine's comments: {e}")
        score = score_loaded_case(suite, cid, [], run_id=rid, status=status, incomplete=incomplete, error=err)
    cr = scored_case_result(score, run_id=rid, status=status, incomplete=incomplete, error=err,
                            latency_original=latency if not replay else latency_original,
                            latency_replay=latency if replay else None)
    return CaseOutcome(cid, rid, result is not None, status, cr, outcome, problems, result=result)


# ------------------------------------------------------------------ report assembly

def _sum_cost(cases: list[CaseOutcome]) -> dict:
    by = {b: {"records": 0, "usdMicros": 0} for b in ("measured", "estimated", "unknown", "replayed", "synthetic")}
    unknown_usd = {b: False for b in by}
    live = 0
    for c in cases:
        cost = c.outcome.get("cost")
        if not cost:
            continue
        live += cost.get("liveCalls") or 0
        for b, bucket in (cost.get("byBasis") or {}).items():
            if b not in by:
                continue
            by[b]["records"] += bucket.get("records", 0)
            if bucket.get("usdMicros") is None:
                unknown_usd[b] = unknown_usd[b] or bucket.get("records", 0) > 0
            else:
                by[b]["usdMicros"] += bucket["usdMicros"]
    for b in by:
        if by[b]["records"] == 0 or unknown_usd[b]:
            by[b]["usdMicros"] = None
    return {"liveCalls": live, "byBasis": by}


def _finish(out: Path, *, mode, eval_run_id, suite, cfg_digest, cfg, profile, plan, cases, problems,
            manifest_extra, replay_of, limitations, created_at) -> EvalOutcome:
    prompt_versions = sorted({r["promptVersion"] for r in profile["roles"].values()})
    profiles = [{"ref": f"{profile['id']}@{profile['version']}", "digest": profile_digest(profile)}]
    report, report_path = None, out / "report.json"
    try:
        report = build_report(suite.manifest, suite.digest, [c.case_result for c in cases],
                              eval_run_id=eval_run_id, mode=mode, config_digest=cfg_digest, profiles=profiles,
                              prompt_versions=prompt_versions, cost=_sum_cost(cases), scored=True,
                              replay_of=replay_of, limitations=limitations, created_at=created_at)
        write_atomic(report_path, _json_bytes(report))
    except (ScoringError, ValueError) as e:
        problems.append(f"EvalReport did not validate: {e}")
        report_path = None
    manifest = {"schema": MANIFEST_SCHEMA, "mode": mode, "evalRunId": eval_run_id, "createdAt": created_at,
                "suite": {"id": suite.manifest["id"], "version": suite.manifest["version"], "digest": suite.digest,
                          "frozen": "suite", "scripts": scripts_identity(suite)},
                "configDigest": cfg_digest, "config": cfg,
                "profile": profiles[0], "plan": {"digest": digest(plan), "version": plan["version"]},
                "versions": {"contracts": CONTRACTS_VERSION, "canonical": CANONICAL_VERSION,
                             "redaction": REDACTION_VERSION, "evaluator": EVALUATOR_VERSION},
                "report": None if report_path is None else {"path": "report.json",
                                                            "sha256": _sha(report_path.read_bytes())},
                "cases": [c.manifest_entry for c in cases], "problems": problems, **manifest_extra}
    if replay_of:
        manifest["replayOf"] = replay_of
    met = sum(1 for c in cases if c.case_result["expectationMet"] is True)
    ok = (report is not None and not problems and met == len(cases) and all(not c.problems for c in cases)
          and all(c.comparison is None or c.comparison["equal"] for c in cases))
    summary = render_summary(mode=mode, eval_run_id=eval_run_id, out=out, report=report, cases=cases,
                             problems=problems, manifest=manifest, ok=ok)
    write_atomic(out / "summary.txt", summary.encode("utf-8"))
    data = _json_bytes(manifest)
    write_atomic(out / "eval.json", data)
    mdig = "sha256:" + _sha(data)
    summary += f"\nmanifest {out / 'eval.json'} {mdig}\n"
    return EvalOutcome(eval_run_id, mode, out, report, report_path, out / "eval.json", mdig, summary, cases,
                       problems, 0 if ok else 1)


# ------------------------------------------------------------------ record

def _freeze(suite_dir, out: Path, profile, plan):
    src = Path(os.path.realpath(suite_dir))
    frozen = freeze_suite(src, out / "suite")
    suite = load_frozen(src, frozen, profile, plan)
    cfg = eval_config(profile, plan)
    cfg_digest = synthetic_config_digest(suite, cfg)
    identity = scripts_identity(suite)
    return src, suite, cfg, cfg_digest, identity


def record_smoke(out_dir, *, suite_dir=DEFAULT_SUITE, profile=None, plan=None, clock=None, wall_clock=utc_now,
                 auth_clock=utc_now, host_extra=None) -> EvalOutcome:
    """Record every case of a synthetic suite with the scripted provider and score each actual result.

    `host_extra(case_id) -> dict` adds HostConfig fields (cancel, hooks, tool_limits) for fault tests."""
    profile, plan = default_profile_plan(profile, plan)
    src = Path(os.path.realpath(suite_dir))
    out = prepare_out(out_dir, [src])
    src, suite, cfg, cfg_digest, identity = _freeze(src, out, profile, plan)
    created = utc_now()
    eval_run_id = derive_id("evr", "record", cfg_digest, secrets.token_hex(16))

    op = out / "operator"
    op.mkdir()
    auth_path = op / "authorization.json"
    write_atomic(auth_path, _json_bytes(synthetic_authorization(dt.datetime.now(dt.timezone.utc))), 0o600)
    runs = out / "runs"
    runs.mkdir()
    (out / "outcomes").mkdir()
    forbidden = (src, suite.root, op)
    handle = trusted_authorization(auth_path, forbidden_roots=(src, suite.root, runs))
    book = SpendBook(handle, store=op / "spend-book.jsonl")      # ONE durable book for all cases

    scripts = {cid: script_bytes(suite, cid, identity) for cid in sorted(suite.cases)}

    def backend_factory(cid):
        return RecordBackend(handle, book, default_providers(parse_script(scripts[cid])), auth_clock)

    cases = []
    for cid in sorted(suite.cases):
        host_kw = {"out_root": runs, "config_identity": cfg_digest, "forbidden_roots": forbidden,
                   "comment_cap": COMMENT_CAP, "wall_clock": wall_clock}
        if clock is not None:
            host_kw["clock"] = clock
        if host_extra:
            host_kw.update(host_extra(cid))
        co = run_case(suite, cid, eval_run_id=eval_run_id, profile=profile, plan=plan, host_kw=host_kw,
                      backend_factory=backend_factory)
        _seal_record(out, co)
        cases.append(co)

    totals = book.totals()
    problems = []
    if totals["inflight"]:
        problems.append(f"spend book has {totals['inflight']} usdMicros of open reservations after the evaluation")
    extra = {"authorization": {"id": handle.auth["id"], "digest": handle.digest, "path": "operator/authorization.json",
                               "providers": handle.auth["providers"]},
             "spendBook": {"path": "operator/spend-book.jsonl", "totals": totals, "shared": "all cases, one store"},
             "sourceSuite": str(src)}
    lim = SMOKE_LIMITATIONS + [
        "Scripted synthetic provider: cost is synthetic pricing (not provider spend); latency is local mechanics.",
        "No CLI resume or stage-replay entry point in this slice."]
    return _finish(out, mode="live", eval_run_id=eval_run_id, suite=suite, cfg_digest=cfg_digest, cfg=cfg,
                   profile=profile, plan=plan, cases=cases, problems=problems, manifest_extra=extra, replay_of=None,
                   limitations=lim, created_at=created)


def _seal_record(out: Path, co: CaseOutcome) -> None:
    """Write the evaluator's outcome file and the manifest entry that pins it and the ORIGINAL trace bytes."""
    entry = {"caseId": co.case_id, "runId": co.run_id, "ran": co.ran, "status": co.status,
             "outcome": f"outcomes/{co.case_id}.json", "latencyMs": co.outcome.get("latencyMs"),
             "problems": co.problems}
    r = co.result
    if r is not None:
        run_dir = Path(r.run_dir)
        trace = Path(r.trace_path)
        if run_dir != out / "runs" / co.run_id or trace != run_dir / "trace.jsonl":
            co.problems.append(f"engine wrote outside the expected run directory: {run_dir}")
        tdig = bytes_digest(read_bytes_strict(trace, 1 << 30))
        if tdig != r.trace_digest:
            co.problems.append("trace bytes on disk differ from the engine's reported trace digest")
        entry.update(runDir=f"runs/{co.run_id}", traceDigest=tdig, configSnapshotId=r.run.get("configSnapshotId"),
                     receiptSha256=_sha(read_bytes_strict(Path(r.receipt_path))),
                     commentsSha256=_sha(read_bytes_strict(Path(r.comments_path))))
    data = _json_bytes(co.outcome)
    write_atomic(out / "outcomes" / f"{co.case_id}.json", data)
    entry["outcomeSha256"] = _sha(data)
    co.manifest_entry = entry


# ------------------------------------------------------------------ replay

def _load_recording(rec: Path, manifest_digest: str | None) -> tuple[dict, str]:
    data = read_bytes_strict(rec / "eval.json")
    mdig = "sha256:" + _sha(data)
    if manifest_digest is not None and mdig != manifest_digest:
        raise EvalError("recording", "recording manifest bytes do not match --manifest-digest")
    m = _load_json(data, "eval.json")
    if not isinstance(m, dict) or m.get("schema") != MANIFEST_SCHEMA or m.get("mode") != "live":
        raise EvalError("recording", "eval.json is not a recording manifest (evaluation-manifest@1, mode live)")
    if not isinstance(m.get("evalRunId"), str) or not EVR_RE.fullmatch(m["evalRunId"]):
        raise EvalError("recording", "recording manifest has no valid evalRunId")
    if not isinstance(m.get("configDigest"), str) or not DIGEST_RE.fullmatch(m["configDigest"]):
        raise EvalError("recording", "recording manifest has no valid configDigest")
    if not isinstance(m.get("cases"), list):
        raise EvalError("recording", "recording manifest has no case list")
    return m, mdig


def _recorded_case(rec: Path, entry, cid: str) -> tuple[dict, dict]:
    """(manifest entry, recorded outcome) after checking the pins; EvalError if the entry is malformed."""
    if not isinstance(entry, dict) or entry.get("caseId") != cid:
        raise EvalError("recording", f"manifest entry for {cid} is malformed")
    if entry.get("outcome") != f"outcomes/{cid}.json" or not SHA_RE.fullmatch(str(entry.get("outcomeSha256"))):
        raise EvalError("recording", f"{cid}: manifest does not pin the recorded outcome")
    data = read_bytes_strict(rec / "outcomes" / f"{cid}.json")
    if _sha(data) != entry["outcomeSha256"]:
        raise EvalError("recording", f"{cid}: recorded outcome bytes do not match the manifest pin")
    outcome = _load_json(data, f"outcomes/{cid}.json")
    if entry.get("ran"):
        rid = entry.get("runId")
        if not (isinstance(rid, str) and RUN_RE.fullmatch(rid) and entry.get("runDir") == f"runs/{rid}"
                and outcome.get("runId") == rid):
            raise EvalError("recording", f"{cid}: manifest run id/directory is malformed")
        if not DIGEST_RE.fullmatch(str(entry.get("traceDigest"))):
            raise EvalError("recording", f"{cid}: manifest has no trace digest pin")
    return entry, outcome


def _trace_path(rec: Path, rid: str) -> Path:
    p = rec
    for part in ("runs", rid, "trace.jsonl"):
        p = p / part
        if p.is_symlink():
            raise EvalError("recording", f"symlink in recording path {p}")
    return p


def compare_outcomes(recorded: dict, replayed: dict) -> dict:
    """Entity-aware comparison of what the replay recomputed with what the recording produced."""
    diffs = []
    for k in ("status", "incomplete", "error"):
        if recorded.get(k) != replayed.get(k):
            diffs.append(f"{k} differs")
    for k, entity in COMPARED:
        a, b = recorded.get(k) or [], replayed.get(k) or []
        if len(a) != len(b):
            diffs.append(f"{k}: recorded {len(a)}, replayed {len(b)}")
        elif [comparable(x, entity) for x in a] != [comparable(x, entity) for x in b]:
            diffs.append(f"{k} differ")
    rc, pc = recorded.get("cost") or {}, replayed.get("cost") or {}
    rg, pg = rc.get("gateway") or {}, pc.get("gateway") or {}
    if pc.get("liveCalls") != 0 or pg.get("liveCalls") != 0:
        diffs.append(f"replay made live calls ({pc.get('liveCalls')}/{pg.get('liveCalls')})")
    if pg.get("unconsumedRecordedCalls") != 0:
        diffs.append(f"recorded calls not consumed: {pg.get('unconsumedRecordedCalls')!r}")
    if not (rc.get("liveCalls") == pc.get("replayedCalls") and rg.get("liveCalls") == pg.get("replayedCalls")):
        diffs.append(f"recorded {rc.get('liveCalls')}/{rg.get('liveCalls')} model calls, replay consumed "
                     f"{pc.get('replayedCalls')}/{pg.get('replayedCalls')}")
    return {"equal": not diffs, "differences": diffs,
            "compared": ["status", "incomplete", "error", *(k for k, _ in COMPARED), "model-call counts"]}


def replay_smoke(recording_dir, out_dir, *, suite_dir=DEFAULT_SUITE, manifest_digest=None, profile=None,
                 plan=None, clock=None, wall_clock=utc_now, host_extra=None) -> EvalOutcome:
    """Strictly replay a recording made by record_smoke. Zero provider calls; pins come from the recording
    manifest, never from the traces; config/inputs must be unchanged."""
    rec = Path(recording_dir)
    if rec.is_symlink() or not rec.is_dir():
        raise EvalError("recording", f"recording {str(rec)!r} is not a directory")
    rec = Path(os.path.realpath(rec))
    m, mdig = _load_recording(rec, manifest_digest)
    profile, plan = default_profile_plan(profile, plan)
    src = Path(os.path.realpath(suite_dir))
    out = prepare_out(out_dir, [src, rec])
    src, suite, cfg, cfg_digest, _ = _freeze(src, out, profile, plan)
    if cfg_digest != m["configDigest"]:
        raise EvalError("config-drift", "suite, scripts, engine, profile, Plan or redaction changed since the "
                        f"recording (config digest {cfg_digest} != recorded {m['configDigest']})")
    by_case = {e.get("caseId"): e for e in m["cases"] if isinstance(e, dict)}
    if sorted(by_case) != sorted(suite.cases) or len(by_case) != len(m["cases"]):
        raise EvalError("recording", "recording does not hold exactly one entry per suite case")
    recorded = {cid: _recorded_case(rec, by_case[cid], cid) for cid in sorted(suite.cases)}
    created = utc_now()
    eval_run_id = derive_id("evr", "replay", m["evalRunId"], mdig, secrets.token_hex(16))
    runs = out / "runs"
    runs.mkdir()
    (out / "outcomes").mkdir()

    def backend_factory(cid):
        entry, _ = recorded[cid]
        if not entry.get("ran"):
            raise EvalError("recording", f"{cid} has no recorded run")   # caught below per case
        return ReplayBackend(_trace_path(rec, entry["runId"]), entry["traceDigest"], pin_source="recording-manifest")

    cases = []
    for cid in sorted(suite.cases):
        entry, rec_outcome = recorded[cid]
        host_kw = {"out_root": runs, "config_identity": cfg_digest, "forbidden_roots": (src, suite.root, rec),
                   "comment_cap": COMMENT_CAP, "wall_clock": wall_clock}
        if clock is not None:
            host_kw["clock"] = clock
        if host_extra:
            host_kw.update(host_extra(cid))
        if not entry.get("ran"):
            co = _unreplayable(suite, cid, eval_run_id, entry)
        else:
            co = run_case(suite, cid, eval_run_id=eval_run_id, profile=profile, plan=plan, host_kw=host_kw,
                          backend_factory=backend_factory, latency_original=entry.get("latencyMs"), replay=True)
            r = co.result
            if r is not None and r.run.get("replayOf") != entry["runId"]:
                co.problems.append(f"replay names replayOf {r.run.get('replayOf')!r}, not {entry['runId']}")
        co.comparison = compare_outcomes(rec_outcome, co.outcome)
        _seal_replay(out, co, entry)
        cases.append(co)
    extra = {"recording": {"path": str(rec), "manifestDigest": mdig, "evalRunId": m["evalRunId"],
                           "pinSource": "recording-manifest"},
             "sourceSuite": str(src)}
    lim = SMOKE_LIMITATIONS + [
        "Strict replay of one recording does not measure model variance.",
        "Original latency is the recording's local mechanics time; replay latency is this replay's own.",
        "No CLI resume or stage-replay entry point in this slice."]
    return _finish(out, mode="strict-replay", eval_run_id=eval_run_id, suite=suite, cfg_digest=cfg_digest, cfg=cfg,
                   profile=profile, plan=plan, cases=cases, problems=[], manifest_extra=extra,
                   replay_of=m["evalRunId"], limitations=lim, created_at=created)


def _unreplayable(suite, cid, eval_run_id, entry) -> CaseOutcome:
    err = typed_error("replay-miss", "the recording has no run for this case; nothing to replay")
    rid = expected_run_id(eval_run_id, suite.cases[cid].input)
    score = score_loaded_case(suite, cid, [], run_id=rid, status="failed", incomplete=[], error=err)
    cr = scored_case_result(score, run_id=rid, status="failed", incomplete=[], error=err,
                            latency_original=entry.get("latencyMs"), latency_replay=None)
    outcome = {"schema": OUTCOME_SCHEMA, "caseId": cid, "runId": rid, "ran": False, "status": "failed",
               "incomplete": [], "error": err, "cost": None, "latencyMs": None}
    return CaseOutcome(cid, rid, False, "failed", cr, outcome, ["recording has no run for this case"])


def _seal_replay(out: Path, co: CaseOutcome, rec_entry: dict) -> None:
    entry = {"caseId": co.case_id, "runId": co.run_id, "ran": co.ran, "status": co.status,
             "replayOf": rec_entry.get("runId"), "outcome": f"outcomes/{co.case_id}.json",
             "latencyMs": {"original": rec_entry.get("latencyMs"), "replay": co.outcome.get("latencyMs")},
             "comparison": co.comparison, "problems": co.problems}
    r = co.result
    if r is not None:
        entry.update(runDir=f"runs/{co.run_id}", traceDigest=r.trace_digest,
                     pinnedRecordingTrace=rec_entry.get("traceDigest"))
    data = _json_bytes(co.outcome)
    write_atomic(out / "outcomes" / f"{co.case_id}.json", data)
    entry["outcomeSha256"] = _sha(data)
    co.manifest_entry = entry


__all__ = ["DEFAULT_SUITE", "EvalOutcome", "CaseOutcome", "record_smoke", "replay_smoke", "compare_outcomes",
           "expected_run_id", "eval_config"]
