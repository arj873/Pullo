"""Repository-backed pilot host path (S1-10): a pinned historical case plus its two verified complete repository
imports -> `run_review`, in mode plan | live | replay. Host plumbing only; every loader, provider, book and ledger is
the existing reviewed one. See orchestration/handoffs/S1-10-interface.md.

    python3 -m reviewer.pilot.repository --mode plan --case-dir C --case-pins P --case-baseline B --store S \
        --base-import-pins BP --head-import-pins HP --out OUT --auth AUTH

Plan reads case, pins, imports and the authorization only. Live (root, after independent gates) additionally needs
--confirm-live, an existing durable state dir, --baseline-micros and the one trusted key loader. Replay needs a trace
and its externally held digest, no key, auth or book. Nothing is retried, no state is created, no flag widens a cap."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from reviewer import historical
from reviewer.config import ConfigError, EffectiveConfig, resolve_config
from reviewer.contracts import require
from reviewer.contracts.canonical import canonical_json, digest, idempotency_key_eval, run_id, sha256_hex
from reviewer.gateway import AuthorizationError, DisabledProvider, SpendBook, trusted_authorization
from reviewer.historical.bridge import _check_out, _validated
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReplayBackend,
                               RepositoryImports, ReviewSpec, SnapshotInput, run_review, validate_spec)
from reviewer.pipeline import repocov
from reviewer.repoimport import (RepoImportError, github_remote, load_import_pins, open_import, target_dir)
from reviewer.runtime import EnvFileError, RuntimeLedger, Secret, TRIAL_TOTAL_USD_MICROS, load_openrouter_key
from reviewer.runtime.catalog import worst_case_router_micros
from reviewer.runtime.openrouter import CHAT_PATH, OpenRouterProvider, TransportError
from reviewer.runtime.schemas import PROJECTION_VERSION
from reviewer.runtime.turn_canary import Refused, open_state

from .launcher import QUALITY, REPO, gateway_costs, ledger_costs, load_baseline, utc_now
from .launcher import PilotError, _Unused, _force_cleanup
from .providers import (TERRA_STATE_NOTE, ReviewProviders, TerraStateError, live_arm, live_terra, needs,
                        open_terra_state, plan_providers, scrub_of, worst_case)
from .profile import RUN_CEILING_USD_MICROS
from .repository_profile import repository_plan, repository_policy, repository_profile

MODES = ("plan", "live", "replay")
CONFIG_SCHEMA = "pilot-repository-config@1"
REPORT_SCHEMA = "pilot-repository-report@1"
BOOK_NAME, LEDGER_NAME = "spend-book.jsonl", "runtime-ledger.jsonl"
_DIGEST_RX = re.compile(r"sha256:[0-9a-f]{64}")
_CASE_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
STRICT_REPLAY_ONLY = ("strict replay only: offline stage replay is not driven by this launcher and fork is not "
                      "implemented (the pipeline refuses ForkFrom)")


class RepositoryError(Exception):
    """A refusal before (or instead of) a run. Messages never contain keys or file content."""


@dataclass(frozen=True)
class RepositoryOptions:
    mode: str
    case_dir: str
    case_pins: str
    case_baseline: str
    store: str
    base_import_pins: str
    head_import_pins: str
    out_dir: str
    auth: str | None = None
    state_dir: str | None = None
    env_file: str | None = None
    baseline_micros: int | None = None
    book_baseline_micros: int | None = None
    confirm_live: bool = False
    replay_trace: str | None = None
    trace_digest: str | None = None
    retrieval: bool = True
    repeat: int = 0
    config: str | None = None


@dataclass(frozen=True)
class Ingested:
    case_id: str
    case: dict                      # CaseInput over the IMPORT content ids
    base: object                    # RepoImport
    head: object
    pins: dict                      # historical-bridge-pins@1 (verified against the baseline)
    import_pins: dict               # {"base": ..., "head": ...}
    partial: dict                   # {"base": [layer...], "head": [layer...]} original partial ids, information only
    case_dir: Path
    store: Path


# ------------------------------------------------------------------ options

def _real(p) -> Path:
    return Path(os.path.realpath(p))


def check_options(o: RepositoryOptions) -> None:
    """Mode/argument consistency. Touches nothing on disk."""
    if o.mode not in MODES:
        raise RepositoryError("mode must be plan, live or replay")
    for name in ("case_dir", "case_pins", "case_baseline", "store", "base_import_pins", "head_import_pins", "out_dir"):
        if not isinstance(getattr(o, name), str) or not getattr(o, name):
            raise RepositoryError(f"{name} is required")
    if type(o.repeat) is not int or not 0 <= o.repeat <= 1000:
        raise RepositoryError("repeat must be 0..1000")
    live, replay = o.mode == "live", o.mode == "replay"
    state_args = (o.state_dir, o.env_file, o.baseline_micros, o.book_baseline_micros)
    if live:
        if not o.confirm_live:
            raise RepositoryError("--mode live needs --confirm-live")
        if not (o.auth and o.state_dir):           # --env is checked once the arm is known (a Terra arm reads no key)
            raise RepositoryError("live needs --auth, --state-dir and --env (--env only for an OpenRouter arm)")
        if type(o.baseline_micros) is not int or o.baseline_micros < 0:
            raise RepositoryError("live needs an explicit --baseline-micros (non-negative integer)")
        if o.book_baseline_micros is not None and (type(o.book_baseline_micros) is not int or o.book_baseline_micros < 0):
            raise RepositoryError("--book-baseline-micros must be a non-negative integer")
    elif any(a is not None for a in state_args) or o.confirm_live:
        raise RepositoryError("--state-dir/--env/--baseline-micros/--book-baseline-micros/--confirm-live are live-only")
    if replay:
        if o.auth:
            raise RepositoryError("replay uses no authorization")
        if not o.replay_trace or not (isinstance(o.trace_digest, str) and _DIGEST_RX.fullmatch(o.trace_digest)):
            raise RepositoryError("replay needs --replay-trace and --trace-digest sha256:<64 hex> from the operator")
    else:
        if o.replay_trace or o.trace_digest:
            raise RepositoryError("--replay-trace/--trace-digest are only for replay")
        if not live and not o.auth:
            raise RepositoryError("plan needs --auth (read-only check that it covers the profile)")


# ------------------------------------------------------------------ ingestion

def _relates_ok(side: str, rec: dict, case_id: str, sha: str, n_files: int) -> dict:
    r = rec.get("relatesTo")
    if not isinstance(r, dict):
        raise RepositoryError(f"{side} import carries no relatesTo: it was not checked against the case input")
    if (r.get("caseId"), r.get("side"), r.get("commitSha")) != (case_id, side, sha):
        raise RepositoryError(f"{side} import relatesTo names another case, side or commit")
    if r.get("changedPathsByteEqual") is not True:
        raise RepositoryError(f"{side} import is not byte-equal to the case's changed files")
    if r.get("unchecked") != []:
        raise RepositoryError(f"{side} import has unchecked changed files: refusing to treat them as equal")
    if r.get("changedPathsChecked") != n_files:
        raise RepositoryError(f"{side} import relatesTo checked {r.get('changedPathsChecked')!r} paths, "
                              f"the pinned case has {n_files}")
    return copy.deepcopy(r)


def ingest(o: RepositoryOptions) -> Ingested:
    """Pins first, then the case, then both imports, then the CaseInput. Raises RepositoryError on any mismatch."""
    case_dir = Path(os.path.abspath(o.case_dir))
    if os.path.islink(case_dir) or not case_dir.is_dir() or not _CASE_RX.fullmatch(case_dir.name):
        raise RepositoryError("case dir must be a real directory with a plain case id as its name")
    try:
        pins = historical.load_pins(o.case_pins, case_dir=case_dir)
        baseline = load_baseline(o.case_baseline)
    except (historical.BridgeError, PilotError) as e:
        raise RepositoryError(str(e)[:300]) from None
    case_id = case_dir.name
    if baseline.get(case_id) != digest(pins):
        raise RepositoryError(f"case pins for {case_id} differ from the operator baseline (or the baseline has none)")
    try:
        hv, case_doc = _validated(case_dir, pins)           # BEFORE input/case.json is trusted for anything else
    except historical.BridgeError as e:
        raise RepositoryError(f"case refused: {str(e)[:300]}") from None
    origin = pins["origin"]
    store = Path(os.path.abspath(o.store))
    imports, import_pins = {}, {}
    for side, sha, pins_path in (("base", origin["textRef"], o.base_import_pins),
                                 ("head", origin["headSha"], o.head_import_pins)):
        try:
            d = target_dir(store, github_remote(f"https://github.com/{origin['repo']}"), sha)
            ip = load_import_pins(pins_path, import_dir=d)
            if ip["repo"].lower() != origin["repo"].lower() or ip["commitSha"] != sha:
                raise RepositoryError(f"{side} import pins are not for the case's {side} commit of {origin['repo']}")
            imp = open_import(d, pins=ip)                    # Git identity + manifest + tree + omissions vs EXTERNAL pins
        except RepoImportError as e:
            raise RepositoryError(f"{side} import refused ({e.code}): {str(e)[:300]}") from None
        rec = imp.record
        if rec["commitSha"] != sha or f"{rec['repo']['owner']}/{rec['repo']['name']}".lower() != origin["repo"].lower():
            raise RepositoryError(f"{side} import is not the pinned commit of the case repository")
        _relates_ok(side, rec, case_id, sha, len(case_doc["files"]))
        imports[side], import_pins[side] = imp, ip
    base, head = imports["base"], imports["head"]
    if base.snapshot_id == head.snapshot_id:
        raise RepositoryError("base and head imports are the same content: not a reviewable change")
    try:
        case = require("CaseInput", {
            "schema": "case-input@1", "id": case_id.lower(), "repo": case_doc["repo"], "synthetic": False,
            "base": {"snapshotId": base.snapshot_id, "root": "base"},
            "head": {"snapshotId": head.snapshot_id, "root": "head"},
            "pr": {"title": "", "body": ""}})                # PR text stays omitted for comparability
    except Exception:  # noqa: BLE001
        raise RepositoryError("CaseInput could not be built (case id not lowercase-mappable?)") from None
    partial = {s: [{"name": l.name, "kind": l.kind, "snapshotId": l.snapshot_id} for l in hv.layers(s)]
               for s in ("base", "head")}
    return Ingested(case_id, case, base, head, pins, import_pins, partial, case_dir, store)


# ------------------------------------------------------------------ identity

def effective_config(o: RepositoryOptions, cfg: EffectiveConfig | None = None) -> EffectiveConfig:
    """Resolved (and validated) before any case file, output, state, key or model action."""
    if cfg is not None:
        return cfg
    case_dir = Path(os.path.abspath(o.case_dir))
    return resolve_config(o.config, forbidden_roots=(case_dir, case_dir.parent, o.store, o.out_dir))


def _profile_parts(o: RepositoryOptions, cfg: EffectiveConfig | None = None):
    cfg = effective_config(o, cfg)
    profile = repository_profile(o.retrieval, cfg.models)
    return profile, repository_plan(profile), repository_policy(o.retrieval)


def config_identity(ing: Ingested, profile: dict, plan: dict, policy, retrieval: bool) -> dict:
    return {"schema": CONFIG_SCHEMA, "caseId": ing.case_id, "casePinsDigest": digest(ing.pins),
            "importPinsDigest": {s: digest(ing.import_pins[s]) for s in ("base", "head")},
            "importRecordDigest": {"base": digest(ing.base.record), "head": digest(ing.head.record)},
            "importSnapshotIds": {"base": ing.base.snapshot_id, "head": ing.head.snapshot_id},
            "originalPartialIds": {s: [l["snapshotId"] for l in ing.partial[s]] for s in ("base", "head")},
            "profile": digest(profile), "plan": digest(plan),
            "retrievalPolicy": None if policy is None else policy.digest, "retrieval": retrieval,
            "prTextSupplied": False}


def eval_run_id(o: RepositoryOptions, cfg: dict) -> str:
    """Same for plan and live (mode class `live`) so the plan's first request is the live run's; replay adds the trace pin."""
    parts = ["pilot-repository", cfg, "live" if o.mode != "replay" else "replay"]
    if o.mode == "replay":
        parts.append(o.trace_digest)
    return "evr_" + sha256_hex(canonical_json(parts))[:16]


def provider_scope(evr: str, ing: Ingested, repeat: int) -> str:
    """The run id the pipeline derives (attempt 1); only keys the ledger's call keys, never sent to a model."""
    case = ing.case
    return run_id(idempotency_key_eval(evr, case["id"], repeat, case["base"]["snapshotId"], case["head"]["snapshotId"]), 1)


def build_spec(o: RepositoryOptions, ing: Ingested, backend, runs: Path, profile, plan, policy) -> ReviewSpec:
    cfg = config_identity(ing, profile, plan, policy, o.retrieval)
    evr = eval_run_id(o, cfg)
    host = HostConfig(out_root=runs, eval=EvalIdentity(evr, ing.case["id"], o.repeat), config_identity=cfg,
                      forbidden_roots=(ing.case_dir.parent, ing.store), wall_clock=utc_now, retrieval=policy)
    return ReviewSpec(case=copy.deepcopy(ing.case), base=SnapshotInput(ing.base.root, copy.deepcopy(ing.base.manifest)),
                      head=SnapshotInput(ing.head.root, copy.deepcopy(ing.head.manifest)), profile=profile, plan=plan,
                      host=host, backend=backend,
                      imports=RepositoryImports(copy.deepcopy(ing.base.record), copy.deepcopy(ing.head.record)))


# ------------------------------------------------------------------ disclosure

def coverage_doc(ing: Ingested) -> dict:
    spec_imports = RepositoryImports(ing.base.record, ing.head.record)
    cov = repocov.build(spec_imports, ing.base.manifest, ing.head.manifest, ing.case)
    return {"scope": cov["scope"], "fullRepositoryCoverage": cov["fullRepositoryCoverage"],
            "gapKinds": cov["gapKinds"], "base": {k: cov["base"][k] for k in ("commitSha", "snapshotId", "omissionCounts", "omittedTotal")},
            "head": {k: cov["head"][k] for k in ("commitSha", "snapshotId", "omissionCounts", "omittedTotal")},
            "relatesTo": cov["relatesTo"], "prText": "OMITTED: the reviewer sees no PR title or body",
            "statement": repocov.statement(cov),
            "originalPartial": ing.partial, "originalPartialNote": "information only: never used as an identity"}


def disclosure_header(ing: Ingested) -> dict:
    return {"case": ing.case_id, "caseInputId": ing.case["id"], "repo": ing.case["repo"],
            "casePinsDigest": digest(ing.pins), "importPinsDigest": {s: digest(ing.import_pins[s]) for s in ("base", "head")},
            "coverage": coverage_doc(ing), "quality": QUALITY}


# ------------------------------------------------------------------ output

def _out_forbidden(o: RepositoryOptions, ing: Ingested) -> list:
    paths = [ing.store, o.case_pins, o.case_baseline, o.base_import_pins, o.head_import_pins,
             REPO / "reviewer", REPO / "fixtures", REPO / "tests"]
    paths += [p for p in (o.auth, o.state_dir, o.env_file, o.replay_trace) if p]
    return paths


def check_out(o: RepositoryOptions, ing: Ingested) -> Path:
    """New, under real directories, outside the case/corpus, store, pins, auth, state, env and product code."""
    try:
        return _check_out(o.out_dir, ing.case_dir, _out_forbidden(o, ing))
    except historical.BridgeError as e:
        raise RepositoryError(str(e)[:200]) from None


def make_out(out: Path) -> Path:
    try:
        os.mkdir(out, 0o700)
    except FileExistsError:
        raise RepositoryError("output directory already exists") from None
    runs = out / "runs"
    os.mkdir(runs, 0o700)
    return runs


def write_report(out: Path, report: dict, scrub=lambda t: t) -> str:
    path = out / "report.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(scrub(json.dumps(report, indent=1, sort_keys=True, default=str)) + "\n")
    return str(path)


# ------------------------------------------------------------------ plan

class CapturingTransport:
    """Records the actual HTTP request the real adapter built, then refuses it as NOT SENT. Nothing leaves."""

    def __init__(self):
        self.requests = []

    def __call__(self, req):
        if req.method == "POST" and req.path == CHAT_PATH:
            self.requests.append(req)
        raise TransportError(False)


def _providers(anthropic) -> dict:
    return {"anthropic": anthropic, "openai": DisabledProvider("openai"), "synthetic": DisabledProvider("synthetic")}


def _request_facts(req) -> dict:
    raw = bytes(req.body or b"")
    body = json.loads(raw)
    js = body["response_format"]["json_schema"]
    schema_raw = json.dumps(js["schema"], sort_keys=True)
    msgs = json.dumps(body["messages"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {"schemaName": js["name"], "model": body["model"], "maxTokens": body["max_tokens"],
            "bodyBytes": len(raw), "bodySha256": hashlib.sha256(raw).hexdigest(), "messagesBytes": len(msgs),
            "messagesSha256": hashlib.sha256(msgs).hexdigest(),
            "schemaBytes": len(json.dumps(js["schema"], separators=(",", ":")).encode()),
            "schemaSha256": hashlib.sha256(schema_raw.encode()).hexdigest(), "projectionVersion": PROJECTION_VERSION,
            "toolsInBody": "tools" in body or "tool_choice" in body,
            "worstCaseRouterUsdMicros": worst_case_router_micros(body["model"], len(raw), body["max_tokens"])}


def plan_mode(o: RepositoryOptions, ing: Ingested, *, runner=run_review, cfg=None) -> dict:
    cfg = effective_config(o, cfg)
    check_out(o, ing)                                    # path rules only: nothing is created
    profile, plan, policy = _profile_parts(o, cfg)
    handle = trusted_authorization(o.auth, forbidden_roots=[ing.case_dir.parent, ing.store, _real(o.out_dir), REPO])
    scratch = tempfile.TemporaryDirectory(prefix="pilot-repository-plan-")
    transport = CapturingTransport()
    capture = None
    problem = result = None
    try:
        root = _real(scratch.name)
        runs = root / "runs"
        runs.mkdir()
        book = SpendBook(handle, root / BOOK_NAME)
        ledger = RuntimeLedger(root / LEDGER_NAME, TRIAL_TOTAL_USD_MICROS)
        evr = eval_run_id(o, config_identity(ing, profile, plan, policy, o.retrieval))
        providers, capture = plan_providers(profile, transport, lambda: OpenRouterProvider(
            enabled=True, key=Secret("plan-placeholder-not-a-key"), authorization=handle, book=book,
            ledger=ledger, transport=transport, run_scope=provider_scope(evr, ing, o.repeat)))
        backend = RecordBackend(handle, book, providers.mapping, utc_now)
        spec = build_spec(o, ing, backend, runs, profile, plan, policy)
        try:
            validate_spec(spec)
            backend.preflight(profile, plan["budget"])
            result = runner(spec)
        except PipelineError as e:
            problem = {"code": e.code, "message": str(e)[:400]}
        except AuthorizationError as e:
            problem = {"code": "authorization", "message": str(e)[:400]}
    finally:
        _force_cleanup(scratch)
    first = capture.facts(transport.requests, _request_facts) if capture else []
    ceiling = plan["budget"]["maxUsdMicros"]
    worst = worst_case(first)
    planned = bool(first) and not any(f.get("toolsInBody", False) for f in first)
    unmet = ["live: durable book/ledger state, --baseline-micros and in-flight are checked only by --mode live",
             "live: independent pipeline, tools and launcher acceptance, then root's explicit invocation",
             STRICT_REPLAY_ONLY]
    if needs(profile, "openai"):
        unmet.insert(0, TERRA_STATE_NOTE)
    if worst is not None and worst > ceiling:
        planned = False
        unmet.insert(0, f"worst-case admission {worst} micros exceeds the {ceiling} run ceiling")
    if not first:
        unmet.insert(0, "no first request was captured: the pipeline never reached a model call")
    rep = {**disclosure_header(ing), "schema": REPORT_SCHEMA, "mode": "plan",
           "status": "planned" if planned else "plan-failed", "ok": planned,
           "plan": {"model": cfg.models.summary(), "models": cfg.report()["roles"], "retrieval": o.retrieval, "retrievalPolicy": None if policy is None else policy.to_doc(),
                    "profile": f"{profile['id']}@{profile['version']}", "authorization": "covers the profile and run ceiling"
                    if problem is None or problem["code"] != "config" else "NOT covered: " + problem["message"],
                    "capturedRequests": first, "capturedCount": len(first),
                    "firstRequest": first[0] if first else None, "worstCaseAdmissionUsdMicros": worst,
                    "runCeilingUsdMicros": ceiling, "retries": 0, "repairs": 0,
                    "outputCaps": {r: s["caps"]["maxOutputTokens"] for r, s in profile["roles"].items()},
                    "providerCalls": 0, "networkCalls": 0, "keyRead": False, "scratchOnly": True,
                    "pipeline": problem if problem else {"status": result.status if result else None,
                                                         "error": result.error and result.error.get("code")},
                    "wouldWriteUnder": str(_real(o.out_dir))},
           "unmetGates": unmet,
           "note": "plan proves the first actual request only; no bill, no quality claim"}
    return rep


# ------------------------------------------------------------------ live

def _check_ceiling(ledger: RuntimeLedger, plan: dict) -> None:
    t = ledger.totals()
    if t["committedUsdMicros"] + plan["budget"]["maxUsdMicros"] > TRIAL_TOTAL_USD_MICROS:
        raise RepositoryError("aggregate allowance cannot cover the run ceiling")
    if plan["budget"]["maxUsdMicros"] != RUN_CEILING_USD_MICROS:
        raise RepositoryError("run ceiling differs from the reviewed pilot ceiling")


def run_report(o, ing, res, *, provider_calls, ledger_before, ledger_after, book) -> dict:
    return {**disclosure_header(ing), "schema": REPORT_SCHEMA, "mode": o.mode, "status": res.status,
            "ok": res.status == "completed", "incomplete": res.incomplete,
            "error": res.error and {k: res.error.get(k) for k in ("code", "stage", "message") if k in res.error},
            "idempotent": res.idempotent, "providerCalls": provider_calls, "runId": res.run_id,
            "counts": {"hypotheses": len(res.hypotheses), "findings": len(res.findings),
                       "verifications": len(res.verifications), "drops": len(res.drops), "comments": len(res.comments)},
            "paths": {"runDir": res.run_dir, "review": res.review_path, "comments": res.comments_path,
                      "receipt": res.receipt_path, "trace": res.trace_path},
            "traceDigest": {"value": res.trace_digest, "trust": "self-reported by this run: not a trusted pin "
                            "until the operator stores it outside the output directory"},
            "retrieval": res.retrieval,
            "costs": {"gateway": gateway_costs(res), "runtime": ledger_costs(ledger_before, ledger_after),
                      "spendBook": book,
                      "note": "key/generation reconciliation is root's, outside this tool"},
            "forkAndStageReplay": STRICT_REPLAY_ONLY}


def live_mode(o: RepositoryOptions, ing: Ingested, *, transport=None, key_loader=load_openrouter_key,
              runner=run_review, cfg=None) -> dict:
    cfg = effective_config(o, cfg)
    out = check_out(o, ing)
    profile, plan, policy = _profile_parts(o, cfg)
    handle = trusted_authorization(o.auth, forbidden_roots=[ing.case_dir.parent, ing.store, out, REPO])
    try:
        arm = live_arm(profile)
        if arm == "terra":       # its own Terra state dir; the OpenRouter trial state is never opened or written
            book, ledger = open_terra_state(o.state_dir, handle, o.baseline_micros)
        else:
            if not o.env_file:
                raise RepositoryError("live needs --auth, --state-dir and --env (--env only for an OpenRouter arm)")
            book, ledger = open_state(o.state_dir, handle, o.baseline_micros,
                                      o.baseline_micros if o.book_baseline_micros is None else o.book_baseline_micros)
    except (Refused, TerraStateError) as e:
        raise RepositoryError(str(e)[:300]) from None
    _check_ceiling(ledger, plan)
    evr = eval_run_id(o, config_identity(ing, profile, plan, policy, o.retrieval))
    validate_spec(build_spec(o, ing, _Unused(handle), Path(tempfile.gettempdir()), profile, plan, policy))
    try:
        RecordBackend(handle, book, _providers(DisabledProvider("anthropic")), utc_now).preflight(profile, plan["budget"])
    except PipelineError as e:
        raise RepositoryError(f"authorization does not cover this profile/Plan: {str(e)[:300]}") from None
    terra = live_terra(profile, ledger, provider_scope(evr, ing, o.repeat))
    runs = make_out(out)
    key = None
    try:
        router = DisabledProvider("anthropic")
        if needs(profile, "anthropic"):
            key = key_loader(o.env_file, forbidden_roots=[ing.case_dir.parent, ing.store, out, REPO / "reviewer"])
            router = OpenRouterProvider(enabled=True, key=key, authorization=handle, book=book, ledger=ledger,
                                        transport=transport, run_scope=provider_scope(evr, ing, o.repeat))
        provider = ReviewProviders(router, terra)
        backend = RecordBackend(handle, book, provider.mapping, utc_now)
        spec = build_spec(o, ing, backend, runs, profile, plan, policy)
        before = ledger.totals()
        try:
            res = runner(spec)
        except PipelineError as e:             # a typed stop is a result, not a launcher refusal: spend may have occurred
            rep = {**disclosure_header(ing), "schema": REPORT_SCHEMA, "mode": o.mode, "status": "pipeline-refused",
                   "ok": False, "error": {"code": e.code, "message": str(e)[:400]}, "providerCalls": provider.calls,
                   "costs": {"runtime": ledger_costs(before, ledger.totals()), "spendBook": book.totals(),
                             "note": "key/generation reconciliation is root's, outside this tool"},
                   "forkAndStageReplay": STRICT_REPLAY_ONLY}
            rep["reportPath"] = write_report(out, rep, scrub=scrub_of(key))
            return rep
        except BaseException as e:
            _best_effort_report(out, ing, o, e, key, ledger, before, provider)
            raise
        after = ledger.totals()
        rep = run_report(o, ing, res, provider_calls=provider.calls, ledger_before=before, ledger_after=after,
                         book=book.totals())
        rep["reportPath"] = write_report(out, rep, scrub=scrub_of(key))
        return rep
    except (EnvFileError, PipelineError):
        _remove_if_empty(out, runs)
        raise


def _best_effort_report(out, ing, o, exc, key, ledger, before, provider) -> None:
    try:
        rep = {**disclosure_header(ing), "schema": REPORT_SCHEMA, "mode": o.mode, "status": "interrupted", "ok": False,
               "error": {"type": type(exc).__name__}, "providerCalls": provider.calls,
               "costs": {"runtime": ledger_costs(before, ledger.totals())},
               "note": "an interrupted call keeps its ledger intent (worst case counted); the next invocation "
                       "refuses at the in-flight gate until root reconciles"}
        write_report(out, rep, scrub=scrub_of(key))
    except Exception:  # noqa: BLE001 - never hides the original interruption
        pass


def _remove_if_empty(out: Path, runs: Path) -> None:
    try:
        if not any(runs.iterdir()):
            runs.rmdir()
            if not any(out.iterdir()):
                out.rmdir()
    except OSError:
        pass


# ------------------------------------------------------------------ replay

def replay_mode(o: RepositoryOptions, ing: Ingested, *, runner=run_review, cfg=None) -> dict:
    cfg = effective_config(o, cfg)
    out = check_out(o, ing)
    profile, plan, policy = _profile_parts(o, cfg)
    backend = ReplayBackend(o.replay_trace, o.trace_digest, "operator-config")
    runs = make_out(out)
    spec = build_spec(o, ing, backend, runs, profile, plan, policy)
    try:
        res = runner(spec)
    except PipelineError:
        _remove_if_empty(out, runs)
        raise
    cost = res.cost or {}
    live_calls, replayed = cost.get("liveCalls"), cost.get("replayedCalls")
    clean = live_calls == 0 and isinstance(replayed, int) and replayed >= 1
    rep = run_report(o, ing, res, provider_calls=0, ledger_before=None, ledger_after=None, book=None)
    rep["replay"] = {"liveCalls": live_calls, "replayedCalls": replayed, "newSpendUsdMicros": 0 if clean else None,
                     "consumedZeroLive": clean, "traceDigestPin": o.trace_digest, "keyRead": False, "networkCalls": 0}
    rep["ok"] = rep["ok"] and clean
    if not clean:
        rep["status"] = "replay-not-clean"
    rep["reportPath"] = write_report(out, rep)
    return rep


# ------------------------------------------------------------------ entry

def run_repository(o: RepositoryOptions, *, transport=None, key_loader=load_openrouter_key, runner=run_review) -> dict:
    check_options(o)
    cfg = effective_config(o)                            # before ingestion, output, state, key or model
    ing = ingest(o)
    if o.mode == "plan":
        rep = plan_mode(o, ing, runner=runner, cfg=cfg)
    elif o.mode == "live":
        rep = live_mode(o, ing, transport=transport, key_loader=key_loader, runner=runner, cfg=cfg)
    else:
        rep = replay_mode(o, ing, runner=runner, cfg=cfg)
    rep["reviewModels"] = cfg.report()
    return rep


def render(rep: dict) -> str:
    c = rep["coverage"]
    L = [f"mode: {rep['mode']}   status: {rep['status']}   ok: {rep['ok']}", f"case: {rep['case']}",
         f"  coverage: {c['statement']}", f"  PR title/body: {c['prText']}"]
    L.append(f"  review models: { {r: v['model'] for r, v in rep['reviewModels']['roles'].items()} } "
             f"(config {rep['reviewModels']['source']} {rep['reviewModels']['digest']})")
    if rep["mode"] == "plan":
        p = rep["plan"]
        L += [f"  plan: {p['model']} retrieval={p['retrieval']} ceiling ${p['runCeilingUsdMicros'] / 1e6:.2f} "
              f"worst-case first request ${(p['worstCaseAdmissionUsdMicros'] or 0) / 1e6:.6f}",
              f"  captured requests: {p['capturedCount']}  pipeline: {p['pipeline']}"]
        if p["firstRequest"]:
            f = p["firstRequest"]
            L.append(f"  first request: {f['schemaName']} {f['bodyBytes']} bytes sha256:{f['bodySha256']} "
                     f"schema {f['schemaBytes']} bytes sha256:{f['schemaSha256']}")
        L += [f"  unmet gate: {g}" for g in rep["unmetGates"]]
        return "\n".join(L) + "\n"
    n = rep["counts"]
    L += [f"  run: {rep['runId']} provider calls={rep['providerCalls']} incomplete={rep['incomplete']} error={rep['error']}",
          f"  hypotheses={n['hypotheses']} findings={n['findings']} verified={n['verifications']} "
          f"dropped={n['drops']} comments={n['comments']}"]
    L += [f"  {k}: {v}" for k, v in rep["paths"].items()]
    L.append(f"  trace digest: {rep['traceDigest']['value']} ({rep['traceDigest']['trust']})")
    if rep.get("replay"):
        L.append(f"  replay: {rep['replay']}")
    rt = rep["costs"]["runtime"]
    if rt:
        for part in ("thisCase", "cumulative"):
            L.append(f"  cost ledger {part}: " + "  ".join(f"{k}=${v['usd']}" for k, v in rt[part].items()))
    L.append(f"  gateway computed (not a bill): {rep['costs']['gateway']['computedTokenPricedUsd']}")
    L.append(f"  report: {rep.get('reportPath')}")
    return "\n".join(L) + "\n"


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="reviewer.pilot.repository",
                                 description="Repository-backed pinned historical PR review (read-only).")
    ap.add_argument("--mode", choices=MODES, default="plan")
    ap.add_argument("--case-dir", required=True, help="historical case directory (input/ only is read)")
    ap.add_argument("--case-pins", required=True, help="external historical-bridge-pins@1 for the case")
    ap.add_argument("--case-baseline", required=True, help="external operator-pin-baseline@1; must match the case pins")
    ap.add_argument("--store", required=True, help="repoimport store holding both sides' imports")
    ap.add_argument("--base-import-pins", required=True, help="external repo-import-pins@1 for the base import")
    ap.add_argument("--head-import-pins", required=True, help="external repo-import-pins@1 for the head import")
    ap.add_argument("--out", required=True, help="fresh output directory (must not exist)")
    ap.add_argument("--auth", help="operator SpendAuthorization JSON; plan and live")
    ap.add_argument("--state-dir", help="EXISTING operator state dir (live)")
    ap.add_argument("--env", help="host .env path (read only with --mode live)")
    ap.add_argument("--baseline-micros", type=int, help="ledger committed micros root expects (live)")
    ap.add_argument("--book-baseline-micros", type=int, help="book committed micros if it differs (live)")
    ap.add_argument("--confirm-live", action="store_true", help="required with --mode live")
    ap.add_argument("--replay-trace", help="recorded trace.jsonl (replay)")
    ap.add_argument("--trace-digest", help="operator-held sha256:<64 hex> of the trace (replay)")
    ap.add_argument("--retrieval", choices=("on", "off"), default="on", help="Turn retrieval roles (ablation switch)")
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--config", help="review-model config (pullo.toml format); default: Pullo's own pullo.toml")
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv=None, *, transport=None, key_loader=load_openrouter_key, out=sys.stdout, err=sys.stderr,
         runner=run_review) -> int:
    a = _parser().parse_args(argv)
    o = RepositoryOptions(mode=a.mode, case_dir=a.case_dir, case_pins=a.case_pins, case_baseline=a.case_baseline,
                          store=a.store, base_import_pins=a.base_import_pins, head_import_pins=a.head_import_pins,
                          out_dir=a.out, auth=a.auth, state_dir=a.state_dir, env_file=a.env,
                          baseline_micros=a.baseline_micros, book_baseline_micros=a.book_baseline_micros,
                          confirm_live=a.confirm_live, replay_trace=a.replay_trace, trace_digest=a.trace_digest,
                          retrieval=a.retrieval == "on", repeat=a.repeat, config=a.config)
    try:
        rep = run_repository(o, transport=transport, key_loader=key_loader, runner=runner)
    except (RepositoryError, ConfigError, PilotError, EnvFileError, AuthorizationError, PipelineError) as e:
        err.write(f"error: {type(e).__name__}: {str(e)[:400]}\n")
        return 2
    out.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n" if a.json else render(rep))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
