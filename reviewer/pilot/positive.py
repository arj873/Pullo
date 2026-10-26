"""Real-provider positive review control (S1-12): the owned synthetic fixture `fixtures/retrieval-positive` ->
`run_review` with the repository pilot profile (Sonnet 5.5, Turn retrieval, $4 run ceiling), in mode plan | live | replay.
Host plumbing only. The model decides what it finds; this tool never scripts, compares or retries a result.
See orchestration/handoffs/S1-12-interface.md.

    python3 -m reviewer.pilot.positive --mode plan --source-baseline BASELINE.json --out OUT --auth AUTH

The expected issue lives only in tests. Live is root's, after independent review: it needs --confirm-live, an existing
durable state dir, --baseline-micros and the one trusted key loader. Replay needs a trace and its external digest."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts import require
from reviewer.contracts.canonical import canonical_json, digest, idempotency_key_eval, run_id, sha256_hex
from reviewer.contracts.snapshot import SnapshotError, build_manifest
from reviewer.gateway import AuthorizationError, DisabledProvider, SpendBook, trusted_authorization
from reviewer.historical import BridgeError
from reviewer.historical.bridge import _check_out
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReplayBackend, ReviewSpec,
                               SnapshotInput, run_review, validate_spec)
from reviewer.runtime import EnvFileError, RuntimeLedger, Secret, TRIAL_TOTAL_USD_MICROS, load_openrouter_key
from reviewer.runtime.openrouter import OpenRouterProvider
from reviewer.runtime.turn_canary import Refused, open_state

from .launcher import REPO, PilotError, _Unused, _force_cleanup, gateway_costs, ledger_costs, utc_now
from .profile import MODEL
from .repository import (BOOK_NAME, RepositoryError, LEDGER_NAME, STRICT_REPLAY_ONLY, CapturingTransport, _check_ceiling,
                         _best_effort_report, _providers, _remove_if_empty, _request_facts, make_out, write_report)
from .repository_profile import repository_plan, repository_policy, repository_profile

MODES = ("plan", "live", "replay")
CONFIG_SCHEMA = "pilot-positive-config@1"
REPORT_SCHEMA = "pilot-positive-report@1"
FIXTURE = REPO / "fixtures" / "retrieval-positive"
CASE_ID = "retrieval-positive-1"
CASE_REPO = "owned/lease-scheduler"
SCOPES = ("reviewer/", "fixtures/retrieval-positive/")
QUALITY = ("synthetic mechanics control, model-decided: not recall, not competitive quality, not a measured "
           "midsized-repository cost; a hit or miss is judged outside this tool")
_DIGEST_RX = re.compile(r"sha256:[0-9a-f]{64}")
_SHA_RX = re.compile(r"[0-9a-f]{64}")


class PositiveError(Exception):
    """A refusal before (or instead of) a run. Messages never contain keys or file content."""


@dataclass(frozen=True)
class PositiveOptions:
    mode: str
    source_baseline: str
    out_dir: str
    auth: str | None = None
    state_dir: str | None = None
    env_file: str | None = None
    baseline_micros: int | None = None
    book_baseline_micros: int | None = None
    confirm_live: bool = False
    replay_trace: str | None = None
    trace_digest: str | None = None


@dataclass(frozen=True)
class Prepared:
    case: dict
    base: SnapshotInput
    head: SnapshotInput
    source: dict            # {"scopeDigest", "fileCount", "baselineCapturedAt"}
    fixture: Path


def check_options(o: PositiveOptions) -> None:
    if o.mode not in MODES:
        raise PositiveError("mode must be plan, live or replay")
    for name in ("source_baseline", "out_dir"):
        if not isinstance(getattr(o, name), str) or not getattr(o, name):
            raise PositiveError(f"{name} is required")
    live, replay = o.mode == "live", o.mode == "replay"
    state_args = (o.state_dir, o.env_file, o.baseline_micros, o.book_baseline_micros)
    if live:
        if not o.confirm_live:
            raise PositiveError("--mode live needs --confirm-live")
        if not (o.auth and o.state_dir and o.env_file):
            raise PositiveError("live needs --auth, --state-dir and --env")
        if type(o.baseline_micros) is not int or o.baseline_micros < 0:
            raise PositiveError("live needs an explicit --baseline-micros (non-negative integer)")
        if o.book_baseline_micros is not None and (type(o.book_baseline_micros) is not int or o.book_baseline_micros < 0):
            raise PositiveError("--book-baseline-micros must be a non-negative integer")
    elif any(a is not None for a in state_args) or o.confirm_live:
        raise PositiveError("--state-dir/--env/--baseline-micros/--book-baseline-micros/--confirm-live are live-only")
    if replay:
        if o.auth:
            raise PositiveError("replay uses no authorization")
        if not o.replay_trace or not (isinstance(o.trace_digest, str) and _DIGEST_RX.fullmatch(o.trace_digest)):
            raise PositiveError("replay needs --replay-trace and --trace-digest sha256:<64 hex> from the operator")
    else:
        if o.replay_trace or o.trace_digest:
            raise PositiveError("--replay-trace/--trace-digest are only for replay")
        if not o.auth:
            raise PositiveError(f"{o.mode} needs --auth")


# ------------------------------------------------------------------ trusted source baseline

def _scope_files(repo: Path) -> dict:
    """sha256 of every regular file in the two scopes, never following links."""
    out = {}
    for scope in SCOPES:
        top = repo / scope
        if not top.is_dir() or os.path.islink(top):
            raise PositiveError(f"{scope} is missing or a link")
        for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for n in filenames:
                p = Path(dirpath) / n
                if n.endswith(".pyc"):
                    continue
                if os.path.islink(p) or not p.is_file():
                    raise PositiveError(f"{p.relative_to(repo)} is not a regular file")
                out[str(p.relative_to(repo))] = sha256_hex(p.read_bytes())
    return out


def load_source_baseline(path: str, repo: Path = REPO) -> dict:
    """software-baseline@1 held OUTSIDE the checkout. Scoped files must match exactly: no extra, missing or changed."""
    p = Path(os.path.abspath(path))
    real, root = Path(os.path.realpath(p)), Path(os.path.realpath(repo))
    if real == root or root in real.parents:
        raise PositiveError("the source baseline must be held outside the checkout")
    try:
        doc = json.loads(real.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise PositiveError("source baseline is absent or not valid JSON") from None
    files = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(doc, dict) or doc.get("schema") != "software-baseline@1" or not isinstance(files, dict):
        raise PositiveError("source baseline is not a software-baseline@1 document")
    if not all(isinstance(k, str) and isinstance(v, str) and _SHA_RX.fullmatch(v) for k, v in files.items()):
        raise PositiveError("source baseline lists a malformed file entry")
    want = {k: v for k, v in files.items() if k.startswith(SCOPES)}
    have = _scope_files(root)
    if want != have:
        missing, extra = sorted(have.keys() - want.keys()), sorted(want.keys() - have.keys())
        changed = sorted(k for k in want.keys() & have.keys() if want[k] != have[k])
        raise PositiveError("source differs from the trusted baseline: " + "; ".join(
            f"{n} {sorted(v)[:4]}" for n, v in (("not in baseline", missing), ("not on disk", extra),
                                                ("changed", changed)) if v))
    return {"scopeDigest": digest(have), "fileCount": len(have), "baselineCapturedAt": doc.get("capturedAt")}


# ------------------------------------------------------------------ preparation

def prepare(o: PositiveOptions) -> Prepared:
    source = load_source_baseline(o.source_baseline)             # BEFORE anything of the checkout is trusted
    snaps = {}
    for side in ("base", "head"):
        try:
            m = build_manifest(FIXTURE / side)
        except SnapshotError as e:
            raise PositiveError(f"fixture {side} is not a plain snapshot: {str(e)[:200]}") from None
        snaps[side] = SnapshotInput(FIXTURE / side, m)
    ids = {s: snaps[s].manifest["snapshotId"] for s in snaps}
    if ids["base"] == ids["head"]:
        raise PositiveError("fixture base and head are identical")
    case = require("CaseInput", {
        "schema": "case-input@1", "id": CASE_ID, "repo": CASE_REPO, "synthetic": True,
        "base": {"snapshotId": ids["base"], "root": "base"}, "head": {"snapshotId": ids["head"], "root": "head"},
        "pr": {"title": "", "body": ""}})
    return Prepared(case, snaps["base"], snaps["head"], source, FIXTURE)


def _profile_parts():
    profile = repository_profile(True)
    return profile, repository_plan(profile), repository_policy(True)


def config_identity(prep: Prepared, profile: dict, plan: dict, policy) -> dict:
    return {"schema": CONFIG_SCHEMA, "caseId": CASE_ID, "sourceScopeDigest": prep.source["scopeDigest"],
            "snapshotIds": {"base": prep.case["base"]["snapshotId"], "head": prep.case["head"]["snapshotId"]},
            "profile": digest(profile), "plan": digest(plan), "retrievalPolicy": policy.digest,
            "prTextSupplied": False}


def eval_run_id(o: PositiveOptions, cfg: dict) -> str:
    """Same for plan and live (mode class `live`): the plan's first request is the live run's. Replay adds the pin."""
    parts = ["pilot-positive", cfg, "replay" if o.mode == "replay" else "live"]
    if o.mode == "replay":
        parts.append(o.trace_digest)
    return "evr_" + sha256_hex(canonical_json(parts))[:16]


def provider_scope(evr: str, prep: Prepared) -> str:
    c = prep.case
    return run_id(idempotency_key_eval(evr, c["id"], 0, c["base"]["snapshotId"], c["head"]["snapshotId"]), 1)


def build_spec(o, prep: Prepared, backend, runs: Path, profile, plan, policy) -> ReviewSpec:
    cfg = config_identity(prep, profile, plan, policy)
    host = HostConfig(out_root=runs, eval=EvalIdentity(eval_run_id(o, cfg), CASE_ID, 0), config_identity=cfg,
                      forbidden_roots=(prep.fixture,), wall_clock=utc_now, retrieval=policy)
    return ReviewSpec(case=copy.deepcopy(prep.case), base=SnapshotInput(prep.base.root, copy.deepcopy(prep.base.manifest)),
                      head=SnapshotInput(prep.head.root, copy.deepcopy(prep.head.manifest)), profile=profile,
                      plan=plan, host=host, backend=backend)


def header(prep: Prepared) -> dict:
    return {"case": CASE_ID, "repo": CASE_REPO, "synthetic": True, "sourceBaseline": prep.source,
            "snapshotIds": {"base": prep.case["base"]["snapshotId"], "head": prep.case["head"]["snapshotId"]},
            "prText": "OMITTED: the reviewer sees no PR title or body",
            "outcome": "model-decided: this tool never scripts, scores or retries the result", "quality": QUALITY}


# ------------------------------------------------------------------ output

def check_out(o: PositiveOptions) -> Path:
    forbidden = [REPO / "reviewer", REPO / "fixtures", REPO / "tests", o.source_baseline]
    forbidden += [p for p in (o.auth, o.state_dir, o.env_file, o.replay_trace) if p]
    try:
        return _check_out(o.out_dir, FIXTURE, forbidden)
    except BridgeError as e:
        raise PositiveError(str(e)[:200]) from None


# ------------------------------------------------------------------ plan

def plan_mode(o: PositiveOptions, prep: Prepared, *, runner=run_review) -> dict:
    check_out(o)
    profile, plan, policy = _profile_parts()
    handle = trusted_authorization(o.auth, forbidden_roots=[REPO, Path(os.path.realpath(o.out_dir))])
    scratch = tempfile.TemporaryDirectory(prefix="pilot-positive-plan-")
    transport = CapturingTransport()
    problem = result = None
    try:
        root = Path(os.path.realpath(scratch.name))
        runs = root / "runs"
        runs.mkdir()
        book = SpendBook(handle, root / BOOK_NAME)
        ledger = RuntimeLedger(root / LEDGER_NAME, TRIAL_TOTAL_USD_MICROS)
        evr = eval_run_id(o, config_identity(prep, profile, plan, policy))
        provider = OpenRouterProvider(enabled=True, key=Secret("plan-placeholder-not-a-key"), authorization=handle,
                                      book=book, ledger=ledger, transport=transport, run_scope=provider_scope(evr, prep))
        backend = RecordBackend(handle, book, _providers(provider), utc_now)
        spec = build_spec(o, prep, backend, runs, profile, plan, policy)
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
    first = [_request_facts(r) for r in transport.requests]
    ceiling = plan["budget"]["maxUsdMicros"]
    worst = max((f["worstCaseRouterUsdMicros"] for f in first), default=None)
    planned = bool(first) and not any(f["toolsInBody"] for f in first)
    unmet = ["live: durable book/ledger state, --baseline-micros and in-flight are checked only by --mode live",
             "live: independent review of this harness, then root's explicit invocation",
             STRICT_REPLAY_ONLY]
    if worst is not None and worst > ceiling:
        planned = False
        unmet.insert(0, f"worst-case admission {worst} micros exceeds the {ceiling} run ceiling")
    if not first:
        unmet.insert(0, "no first request was captured: the pipeline never reached a model call")
    return {**header(prep), "schema": REPORT_SCHEMA, "mode": "plan", "status": "planned" if planned else "plan-failed",
            "ok": planned,
            "plan": {"model": MODEL, "retrievalPolicy": policy.to_doc(), "profile": f"{profile['id']}@{profile['version']}",
                     "capturedRequests": first, "capturedCount": len(first), "firstRequest": first[0] if first else None,
                     "worstCaseAdmissionUsdMicros": worst, "runCeilingUsdMicros": ceiling, "retries": 0, "repairs": 0,
                     "toolBudget": {k: plan["budget"][k] for k in ("maxToolCalls", "maxToolCallsPerAgent")},
                     "outputCaps": {r: s["caps"]["maxOutputTokens"] for r, s in profile["roles"].items()},
                     "providerCalls": 0, "networkCalls": 0, "keyRead": False, "scratchOnly": True,
                     "pipeline": problem if problem else {"status": result.status if result else None,
                                                          "error": result.error and result.error.get("code")},
                     "wouldWriteUnder": str(Path(os.path.realpath(o.out_dir)))},
            "unmetGates": unmet, "note": "plan proves the first actual request only; no bill, no quality claim"}


# ------------------------------------------------------------------ live

def run_report(o, prep, res, *, provider_calls, ledger_before, ledger_after, book) -> dict:
    return {**header(prep), "schema": REPORT_SCHEMA, "mode": o.mode, "status": res.status,
            "ok": res.status == "completed", "incomplete": res.incomplete,
            "error": res.error and {k: res.error.get(k) for k in ("code", "stage", "message") if k in res.error},
            "providerCalls": provider_calls, "runId": res.run_id,
            "counts": {"hypotheses": len(res.hypotheses), "findings": len(res.findings),
                       "verifications": len(res.verifications), "drops": len(res.drops), "comments": len(res.comments)},
            "paths": {"runDir": res.run_dir, "review": res.review_path, "comments": res.comments_path,
                      "receipt": res.receipt_path, "trace": res.trace_path},
            "traceDigest": {"value": res.trace_digest, "trust": "self-reported by this run: not a trusted pin "
                            "until the operator stores it outside the output directory"},
            "retrieval": res.retrieval,
            "costs": {"gateway": gateway_costs(res), "runtime": ledger_costs(ledger_before, ledger_after),
                      "spendBook": book, "note": "key/generation reconciliation is root's, outside this tool"},
            "forkAndStageReplay": STRICT_REPLAY_ONLY}


def live_mode(o: PositiveOptions, prep: Prepared, *, transport=None, key_loader=load_openrouter_key,
              runner=run_review) -> dict:
    out = check_out(o)
    profile, plan, policy = _profile_parts()
    handle = trusted_authorization(o.auth, forbidden_roots=[REPO, out])
    try:
        book, ledger = open_state(o.state_dir, handle, o.baseline_micros,
                                  o.baseline_micros if o.book_baseline_micros is None else o.book_baseline_micros)
    except Refused as e:
        raise PositiveError(str(e)[:300]) from None
    try:
        _check_ceiling(ledger, plan)
    except RepositoryError as e:
        raise PositiveError(str(e)[:300]) from None
    evr = eval_run_id(o, config_identity(prep, profile, plan, policy))
    validate_spec(build_spec(o, prep, _Unused(handle), Path(tempfile.gettempdir()), profile, plan, policy))
    try:
        RecordBackend(handle, book, _providers(DisabledProvider("anthropic")), utc_now).preflight(profile, plan["budget"])
    except PipelineError as e:
        raise PositiveError(f"authorization does not cover this profile/Plan: {str(e)[:300]}") from None
    runs = make_out(out)
    try:
        key = key_loader(o.env_file, forbidden_roots=[REPO / "reviewer", REPO / "fixtures", out])
        provider = OpenRouterProvider(enabled=True, key=key, authorization=handle, book=book, ledger=ledger,
                                      transport=transport, run_scope=provider_scope(evr, prep))
        backend = RecordBackend(handle, book, _providers(provider), utc_now)
        spec = build_spec(o, prep, backend, runs, profile, plan, policy)
        before = ledger.totals()
        try:
            res = runner(spec)
        except PipelineError as e:             # a typed stop is a result: spend may have occurred
            rep = {**header(prep), "schema": REPORT_SCHEMA, "mode": o.mode, "status": "pipeline-refused", "ok": False,
                   "error": {"code": e.code, "message": str(e)[:400]}, "providerCalls": provider.calls,
                   "costs": {"runtime": ledger_costs(before, ledger.totals()), "spendBook": book.totals(),
                             "note": "key/generation reconciliation is root's, outside this tool"},
                   "forkAndStageReplay": STRICT_REPLAY_ONLY}
            rep["reportPath"] = write_report(out, rep, scrub=key.scrub)
            return rep
        except BaseException as e:
            _interrupted(out, prep, o, e, key, ledger, before, provider)
            raise
        rep = run_report(o, prep, res, provider_calls=provider.calls, ledger_before=before,
                         ledger_after=ledger.totals(), book=book.totals())
        rep["reportPath"] = write_report(out, rep, scrub=key.scrub)
        return rep
    except (EnvFileError, PipelineError):
        _remove_if_empty(out, runs)
        raise


def _interrupted(out, prep, o, exc, key, ledger, before, provider) -> None:
    try:
        rep = {**header(prep), "schema": REPORT_SCHEMA, "mode": o.mode, "status": "interrupted", "ok": False,
               "error": {"type": type(exc).__name__}, "providerCalls": provider.calls,
               "costs": {"runtime": ledger_costs(before, ledger.totals())},
               "note": "an interrupted call keeps its ledger intent; the next invocation refuses at the in-flight "
                       "gate until root reconciles"}
        write_report(out, rep, scrub=key.scrub)
    except Exception:  # noqa: BLE001 - never hides the original interruption
        pass


# ------------------------------------------------------------------ replay

def replay_mode(o: PositiveOptions, prep: Prepared, *, runner=run_review) -> dict:
    out = check_out(o)
    profile, plan, policy = _profile_parts()
    backend = ReplayBackend(o.replay_trace, o.trace_digest, "operator-config")
    runs = make_out(out)
    spec = build_spec(o, prep, backend, runs, profile, plan, policy)
    try:
        res = runner(spec)
    except PipelineError:
        _remove_if_empty(out, runs)
        raise
    cost = res.cost or {}
    live_calls, replayed = cost.get("liveCalls"), cost.get("replayedCalls")
    clean = live_calls == 0 and isinstance(replayed, int) and replayed >= 1
    rep = run_report(o, prep, res, provider_calls=0, ledger_before=None, ledger_after=None, book=None)
    rep["replay"] = {"liveCalls": live_calls, "replayedCalls": replayed, "newSpendUsdMicros": 0 if clean else None,
                     "consumedZeroLive": clean, "traceDigestPin": o.trace_digest, "keyRead": False, "networkCalls": 0}
    rep["ok"] = rep["ok"] and clean
    if not clean:
        rep["status"] = "replay-not-clean"
    rep["reportPath"] = write_report(out, rep)
    return rep


# ------------------------------------------------------------------ entry

def run_positive(o: PositiveOptions, *, transport=None, key_loader=load_openrouter_key, runner=run_review) -> dict:
    check_options(o)
    prep = prepare(o)
    if o.mode == "plan":
        return plan_mode(o, prep, runner=runner)
    if o.mode == "live":
        return live_mode(o, prep, transport=transport, key_loader=key_loader, runner=runner)
    return replay_mode(o, prep, runner=runner)


def render(rep: dict) -> str:
    L = [f"mode: {rep['mode']}   status: {rep['status']}   ok: {rep['ok']}", f"case: {rep['case']} ({rep['repo']})",
         f"  source baseline: {rep['sourceBaseline']['fileCount']} files scope {rep['sourceBaseline']['scopeDigest']}",
         f"  {rep['quality']}"]
    if rep["mode"] == "plan":
        p = rep["plan"]
        L += [f"  plan: {p['model']} ceiling ${p['runCeilingUsdMicros'] / 1e6:.2f} tools {p['toolBudget']} "
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
    ap = argparse.ArgumentParser(prog="reviewer.pilot.positive",
                                 description="Owned synthetic positive review control (read-only, model-decided).")
    ap.add_argument("--mode", choices=MODES, default="plan")
    ap.add_argument("--source-baseline", required=True, help="external software-baseline@1 of reviewer/ and the fixture")
    ap.add_argument("--out", required=True, help="fresh output directory (must not exist)")
    ap.add_argument("--auth", help="operator SpendAuthorization JSON; plan and live")
    ap.add_argument("--state-dir", help="EXISTING operator state dir (live)")
    ap.add_argument("--env", help="host .env path (read only with --mode live)")
    ap.add_argument("--baseline-micros", type=int, help="ledger committed micros root expects (live)")
    ap.add_argument("--book-baseline-micros", type=int, help="book committed micros if it differs (live)")
    ap.add_argument("--confirm-live", action="store_true", help="required with --mode live")
    ap.add_argument("--replay-trace", help="recorded trace.jsonl (replay)")
    ap.add_argument("--trace-digest", help="operator-held sha256:<64 hex> of the trace (replay)")
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv=None, *, transport=None, key_loader=load_openrouter_key, out=sys.stdout, err=sys.stderr,
         runner=run_review) -> int:
    a = _parser().parse_args(argv)
    o = PositiveOptions(mode=a.mode, source_baseline=a.source_baseline, out_dir=a.out, auth=a.auth,
                        state_dir=a.state_dir, env_file=a.env, baseline_micros=a.baseline_micros,
                        book_baseline_micros=a.book_baseline_micros, confirm_live=a.confirm_live,
                        replay_trace=a.replay_trace, trace_digest=a.trace_digest)
    try:
        rep = run_positive(o, transport=transport, key_loader=key_loader, runner=runner)
    except (PositiveError, PilotError, EnvFileError, AuthorizationError, PipelineError) as e:
        err.write(f"error: {type(e).__name__}: {str(e)[:400]}\n")
        return 2
    out.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n" if a.json else render(rep))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
