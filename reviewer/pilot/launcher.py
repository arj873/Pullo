"""Pilot launcher core: pins -> bridge -> ReviewSpec -> run_review, with one shared SpendBook/RuntimeLedger.

Three mutually exclusive modes. `plan` and `replay` never read a key and never open the operator state dir.
`live` loads the authorization and (lazily, after the first case validated) the key, and refuses a state dir that
does not already hold the durable book and ledger. Labels, `source/` and PR outcomes are never opened."""

from __future__ import annotations

import copy
import datetime as dt
import inspect
import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from reviewer import historical
from reviewer.contracts.canonical import canonical_json, digest, idempotency_key_eval, run_id, sha256_hex
from reviewer.gateway import DisabledProvider, ProviderResult, SpendBook, trusted_authorization, typed_error
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReplayBackend, ReviewSpec,
                               run_review, validate_spec)
from reviewer.runtime import RuntimeLedger, TRIAL_TOTAL_USD_MICROS, load_openrouter_key
from reviewer.runtime.catalog import worst_case_router_micros
from reviewer.runtime.openrouter import OpenRouterProvider

from .profile import (MODEL, SOFT_DEADLINE_SEC, WALL_CLOCK_SEC, live_plan, live_profile)

REPO = Path(__file__).resolve().parents[2]
BOOK_NAME, LEDGER_NAME = "spend-book.jsonl", "runtime-ledger.jsonl"
MODES = ("plan", "live", "replay")
_CASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
QUALITY = "not scored: unlabelled real case; merge status is not evidence of correctness"
LEDGER_FIELDS = ("knownUsdMicros", "estimatedUsdMicros", "unknownBoundUsdMicros", "routerReportedUsdMicros",
                 "upstreamReportedUsdMicros", "committedUsdMicros", "calls")


class PilotError(Exception):
    """A refusal before (or instead of) a run. Messages never contain keys or file content."""


@dataclass(frozen=True)
class PilotOptions:
    corpus_root: str
    pins_dir: str
    out_dir: str
    cases: tuple
    mode: str = "plan"
    auth: str | None = None
    state_dir: str | None = None
    env_file: str | None = None
    pins_baseline: str | None = None
    repeat: int = 0
    model: str = MODEL
    output_caps: dict = field(default_factory=dict)
    wall_clock_sec: int = WALL_CLOCK_SEC
    soft_deadline_sec: int = SOFT_DEADLINE_SEC
    replay_trace: str | None = None
    trace_digest: str | None = None
    keep_going: bool = False


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ paths

def _real(p) -> Path:
    return Path(os.path.realpath(p))


def _inside(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def _overlap(a: Path, b: Path) -> bool:
    return _inside(a, b) or _inside(b, a)


@dataclass(frozen=True)
class Paths:
    corpus: Path
    pins: Path
    out: Path
    auth: Path | None
    state: Path | None
    env: Path | None


def check_options(o: PilotOptions) -> Paths:
    """Mode/argument consistency and containment. Touches nothing on disk."""
    if o.mode not in MODES:
        raise PilotError("mode must be plan, live or replay")
    if not o.cases or len(set(o.cases)) != len(o.cases) or not all(isinstance(c, str) and _CASE.fullmatch(c) for c in o.cases):
        raise PilotError("cases must be one or more distinct case ids")
    if type(o.repeat) is not int or not 0 <= o.repeat <= 1000:
        raise PilotError("repeat must be 0..1000")
    live, replay = o.mode == "live", o.mode == "replay"
    if live and not (o.state_dir and o.env_file):
        raise PilotError("--live needs --state-dir and --env")
    if not live and (o.state_dir or o.env_file):
        raise PilotError("--state-dir/--env are only for --live; plan and replay never read them")
    if not live and not replay and not o.auth:
        raise PilotError("plan mode needs --auth (read-only check that it covers the profile)")
    if live and not o.auth:
        raise PilotError("--live needs --auth")
    if replay:
        if o.auth:
            raise PilotError("replay uses no authorization")
        if not o.replay_trace or not (isinstance(o.trace_digest, str) and _DIGEST.fullmatch(o.trace_digest)):
            raise PilotError("replay needs --replay-trace and --trace-digest sha256:<64 hex> from the operator")
        if len(o.cases) != 1:
            raise PilotError("a trace belongs to one case: replay exactly one --case")
    elif o.replay_trace or o.trace_digest:
        raise PilotError("--replay-trace/--trace-digest are only for replay")
    corpus = _real(o.corpus_root)
    if not corpus.is_dir():
        raise PilotError("corpus root is not a directory")
    out = _real(o.out_dir)
    paths = Paths(corpus, _real(o.pins_dir), out, _real(o.auth) if o.auth else None,
                  _real(o.state_dir) if o.state_dir else None, _real(o.env_file) if o.env_file else None)
    if _overlap(out, corpus) or _inside(out, REPO / "reviewer") or _inside(out, REPO / "fixtures"):
        raise PilotError("output directory must lie outside the corpus, fixtures and product code")
    operator = {"pins": paths.pins, "auth": paths.auth, "state": paths.state, "env": paths.env,
                "replay trace": _real(o.replay_trace) if o.replay_trace else None,
                "pins baseline": _real(o.pins_baseline) if o.pins_baseline else None}
    for name, p in operator.items():
        if p is None:
            continue
        if _overlap(p, corpus):
            raise PilotError(f"{name} must lie outside the corpus")
        if name not in ("replay trace", "pins baseline") and _overlap(p, out):
            raise PilotError(f"{name} must lie outside the output directory")
    return paths


def _case_dir(corpus: Path, case: str) -> Path:
    d = corpus / case
    if os.path.islink(d) or not d.is_dir() or _real(d).parent != corpus:
        raise PilotError(f"case {case!r} is not a directory directly inside the corpus root")
    return d


# ------------------------------------------------------------------ pins

def load_baseline(path) -> dict:
    """{case: pinsDigest} from the root's operator-pin-baseline@1. Paths in the file are ignored."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f:
            doc = json.loads(f.read(1 << 20))
        assert doc["schema"] == "operator-pin-baseline@1"
        out = {r["case"]: r["pinsDigest"] for r in doc["records"] if r["action"] == "captured"}
        assert all(isinstance(k, str) and isinstance(v, str) and _DIGEST.fullmatch(v) for k, v in out.items())
        return out
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        raise PilotError("pins baseline is unreadable or not operator-pin-baseline@1") from None


def _load_pins(paths: Paths, case: str, case_dir: Path) -> dict:
    p = paths.pins / f"{case}.json"
    if _inside(_real(p), paths.corpus):
        raise PilotError("pins file lies inside the corpus")
    kw = {}
    if "forbidden_roots" in inspect.signature(historical.load_pins).parameters:
        kw["forbidden_roots"] = (paths.corpus,)
    try:
        return historical.load_pins(p, case_dir=case_dir, **kw)
    except historical.BridgeError as e:
        raise PilotError(f"pins for {case}: {str(e)[:200]}") from None


def _materialize(paths: Paths, case: str, case_dir: Path, pins: dict, work_root: Path):
    out = work_root / f"{case}-{secrets.token_hex(4)}"
    try:
        b = historical.materialize(case_dir, pins=pins, out_dir=out, forbidden_roots=(paths.corpus, paths.pins))
    except historical.BridgeError as e:
        raise PilotError(f"bridge refused {case}: {str(e)[:300]}") from None
    return b, out


def _coverage_of(bridge) -> dict:
    cov = getattr(bridge, "coverage", None)
    if cov is None:
        cov = bridge.record.get("coverage")
    if not isinstance(cov, dict):
        raise PilotError("bridge provides no coverage document: refusing to run a partial case as a full view")
    return copy.deepcopy(cov)


def _discard(bridge, out: Path) -> str | None:
    try:
        m = getattr(bridge, "discard", None)
        m() if callable(m) else historical.discard(out)
    except Exception as e:  # noqa: BLE001 - reported, never hides the run result
        return f"{type(e).__name__}: work tree left at {out}"
    return None


# ------------------------------------------------------------------ plan-mode provider

class PlanProvider:
    """Records what WOULD be sent. Never sends. Used only in plan mode, inside a scratch directory."""
    name = "anthropic"

    def __init__(self):
        self.requests = []
        self.calls = 0

    def call(self, request, key):
        self.calls += 1
        self.requests.append(request)
        return ProviderResult(None, typed_error("provider-error", "plan mode: nothing is sent", retryable=False),
                              "not-sent")


# ------------------------------------------------------------------ spec

def _identity(o: PilotOptions, case: str, pins_digest: str, profile: dict, plan: dict) -> str:
    parts = ["pilot", case, pins_digest, profile, plan, o.mode if o.mode != "plan" else "live"]
    if o.mode == "replay":
        parts.append(o.trace_digest)
    return "evr_" + sha256_hex(canonical_json(parts))[:16]


def _run_id(o, bridge, record, profile, plan) -> str:
    """The run id the pipeline will derive (same recipe as pipeline.identity.build_run, attempt 1)."""
    case = bridge.case
    evr = _identity(o, record["caseId"], record["pinsDigest"], profile, plan)
    return run_id(idempotency_key_eval(evr, case["id"], o.repeat, case["base"]["snapshotId"],
                                       case["head"]["snapshotId"]), 1)


def _spec(o, paths, bridge, record, profile, plan, backend, runs: Path) -> ReviewSpec:
    case = bridge.case
    evr = _identity(o, record["caseId"], record["pinsDigest"], profile, plan)
    host = HostConfig(out_root=runs, eval=EvalIdentity(evr, case["id"], o.repeat),
                      config_identity={"schema": "pilot-config@1", "pinsDigest": record["pinsDigest"],
                                       "prTextSupplied": record["prText"]["supplied"]},
                      forbidden_roots=(paths.corpus, paths.pins), wall_clock=utc_now)
    return ReviewSpec(case=case, base=bridge.base, head=bridge.head, profile=profile, plan=plan, host=host,
                      backend=backend, coverage=_coverage_of(bridge))


# ------------------------------------------------------------------ reporting

def disclosure(record: dict) -> dict:
    cov = record["coverage"]
    kinds = {g for e in cov["changedPaths"] for g in e["gapKinds"]}
    rec = cov.get("recorded") or {}
    gk = rec.get("gapKinds") if isinstance(rec, dict) else None
    kinds |= set(gk if isinstance(gk, (list, dict)) else [])
    n_ch, ctx = len(cov["changedPaths"]), cov["contextPaths"]
    return {"scope": cov["scope"], "fullRepositoryCoverage": False, "changedPaths": n_ch,
            "contextPaths": {"base": len(ctx["base"]), "head": len(ctx["head"])},
            "gapKinds": sorted(k for k in kinds if isinstance(k, str)),
            "unsafePathsOmitted": cov.get("unsafePathsOmitted", 0),
            "statement": (f"PARTIAL coverage: {n_ch} changed path(s) plus selected context "
                          f"({len(ctx['base'])} base / {len(ctx['head'])} head file(s)); not the whole repository. "
                          "Absence of a file or caller in the view is not evidence it does not exist."),
            "prText": ("supplied via pins (host-trusted)" if record["prText"]["supplied"] else
                       "OMITTED: the reviewer saw no PR title or body"),
            "textRef": record["origin"]["textRef"]}


def _micros(v) -> str | None:
    return None if v is None else f"{v / 1_000_000:.6f}"


def ledger_costs(before: dict | None, after: dict | None) -> dict | None:
    if before is None or after is None:
        return None
    delta = {k: after[k] - before[k] for k in LEDGER_FIELDS}
    names = {"routerBilled": "routerReportedUsdMicros", "upstreamReported": "upstreamReportedUsdMicros",
             "accountable": "committedUsdMicros", "estimated": "estimatedUsdMicros",
             "unknownBound": "unknownBoundUsdMicros", "known": "knownUsdMicros"}
    view = lambda t: {n: {"usdMicros": t[k], "usd": _micros(t[k])} for n, k in names.items()}
    return {"thisCase": view(delta), "cumulative": view(after), "ledgerCalls": {"thisCase": delta["calls"],
            "cumulative": after["calls"]}, "capUsdMicros": after.get("capUsdMicros"),
            "note": "RuntimeLedger is the cost truth (BYOK: router bills ~0, upstream carries the charge); "
                    "'accountable' counts estimates and unknown worst-case bounds"}


def gateway_costs(res) -> dict:
    c = res.cost
    return {"computedTokenPricedUsdMicros": c.get("actualProviderUsdMicros"),
            "computedTokenPricedUsd": _micros(c.get("actualProviderUsdMicros")),
            "liveCalls": c.get("liveCalls"), "replayedCalls": c.get("replayedCalls"),
            "byBasis": c.get("byBasis"),
            "note": "gateway price computed from catalog tokens; NOT a provider bill"}


def case_report(o, record, res, *, provider_calls, ledger_before, ledger_after, book, discard_note) -> dict:
    return {"case": record["caseId"], "status": res.status, "incomplete": res.incomplete,
            "error": res.error and {k: res.error.get(k) for k in ("code", "stage", "message") if k in res.error},
            "idempotent": res.idempotent, "providerCalls": provider_calls, "runId": res.run_id,
            "mode": o.mode, "disclosure": disclosure(record), "pinsDigest": record["pinsDigest"],
            "counts": {"hypotheses": len(res.hypotheses), "findings": len(res.findings),
                       "verifications": len(res.verifications), "drops": len(res.drops),
                       "comments": len(res.comments)},
            "paths": {"runDir": res.run_dir, "review": res.review_path, "comments": res.comments_path,
                      "receipt": res.receipt_path, "trace": res.trace_path},
            "traceDigest": {"value": res.trace_digest, "trust": "self-reported by this run: not a trusted pin "
                            "until the operator stores it outside the output directory"},
            "costs": {"gateway": gateway_costs(res), "runtime": ledger_costs(ledger_before, ledger_after),
                      "spendBook": book},
            "quality": QUALITY, "cleanup": discard_note}


def write_summary(out: Path, report: dict, scrub=lambda t: t) -> str:
    d = out / "summaries"
    d.mkdir(mode=0o700, exist_ok=True)
    path = d / f"{report['runId']}.{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(scrub(json.dumps(report, indent=1, sort_keys=True, default=str)) + "\n")
    return str(path)


# ------------------------------------------------------------------ state (live)

def _state_files(state: Path) -> tuple[Path, Path]:
    out = []
    for name in (BOOK_NAME, LEDGER_NAME):
        p = state / name
        try:
            st = os.lstat(p)
        except OSError:
            raise PilotError(f"state dir lacks the existing {name}: refusing to create fresh aggregate spend "
                             "state") from None
        if not stat.S_ISREG(st.st_mode):
            raise PilotError(f"{name} is not a regular file")
        out.append(p)
    return out[0], out[1]


# ------------------------------------------------------------------ entry

def run_cases(o: PilotOptions, *, transport=None, key_loader=load_openrouter_key) -> dict:
    """-> {"mode", "ok", "cases": [report | refusal]}. Plan and replay never call `key_loader`."""
    paths = check_options(o)
    profile = live_profile(o.model, o.output_caps)
    plan = live_plan(profile, wall_clock_sec=o.wall_clock_sec, soft_deadline_sec=o.soft_deadline_sec)
    baseline = load_baseline(o.pins_baseline) if o.pins_baseline else None
    pre = []
    for case in o.cases:                       # cheap checks for EVERY case before any spend
        cd = _case_dir(paths.corpus, case)
        pins = _load_pins(paths, case, cd)
        if baseline is not None and baseline.get(case) != digest(pins):
            raise PilotError(f"pins for {case} differ from the operator baseline")
        pre.append((case, cd, pins))
    scratch = tempfile.TemporaryDirectory(prefix="pilot-scratch-") if o.mode != "live" else None
    handle = book = ledger = None
    box: list = []
    results, ok = [], True
    try:
        if o.mode != "replay":
            handle = trusted_authorization(paths.auth, forbidden_roots=[paths.corpus, paths.out, REPO])
        if o.mode == "live":
            bfile, lfile = _state_files(paths.state)
            book, ledger = SpendBook(handle, bfile), RuntimeLedger(lfile, TRIAL_TOTAL_USD_MICROS)
            runs, work = _out_dirs(paths.out)
        else:
            sroot = _real(scratch.name)
            runs, work = sroot / "runs", sroot / "work"
            runs.mkdir(), work.mkdir()
            if handle is not None:
                book = SpendBook(handle, sroot / BOOK_NAME)
                ledger = RuntimeLedger(sroot / LEDGER_NAME, TRIAL_TOTAL_USD_MICROS)
        for case, cd, pins in pre:
            rep = _one(o, paths, case, cd, pins, profile, plan, handle, book, ledger, runs, work, transport,
                       lambda: _key(box, o, paths, key_loader))
            results.append(rep)
            if rep.get("status") not in ("completed", "planned"):
                ok = False
                if not o.keep_going:
                    break
    finally:
        if scratch is not None:
            _force_cleanup(scratch)
    return {"mode": o.mode, "ok": ok and len(results) == len(pre), "cases": results,
            "notRun": [c for c, *_ in pre][len(results):]}


def _key(box: list, o, paths, key_loader):
    if not box:
        box.append(key_loader(paths.env, forbidden_roots=[paths.corpus, paths.out, REPO / "reviewer"]))
    return box[0]


def _out_dirs(out: Path) -> tuple[Path, Path]:
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    runs, work = out / "runs", out / "work"
    for d in (runs, work):
        d.mkdir(mode=0o700, exist_ok=True)
        if os.path.islink(d):
            raise PilotError("output subdirectory is a symlink")
    return _real(runs), _real(work)


def _force_cleanup(tmp: tempfile.TemporaryDirectory) -> None:
    root = Path(tmp.name)
    for dirpath, dirnames, _ in os.walk(root):
        for d in [dirpath, *[os.path.join(dirpath, x) for x in dirnames]]:
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    tmp.cleanup()


def _one(o, paths, case, cd, pins, profile, plan, handle, book, ledger, runs, work, transport, get_key) -> dict:
    bridge = out = None
    try:
        bridge, out = _materialize(paths, case, cd, pins, work)
        record = bridge.record
        if o.mode == "plan":
            rep = _plan_case(o, paths, record, bridge, profile, plan, handle, book, runs)
            _discard(bridge, out)
            return rep
        if o.mode == "replay":
            backend, provider, key = ReplayBackend(o.replay_trace, o.trace_digest, "operator-config"), None, None
        else:
            # validate everything before the key is read or any provider exists
            validate_spec(_spec(o, paths, bridge, record, profile, plan, _Unused(handle), runs))
            key = get_key()
            provider = OpenRouterProvider(enabled=True, key=key, authorization=handle, book=book, ledger=ledger,
                                          transport=transport, run_scope=_run_id(o, bridge, record, profile, plan))
            backend = RecordBackend(handle, book, _providers(provider), utc_now)
        spec = _spec(o, paths, bridge, record, profile, plan, backend, runs)
        live = o.mode == "live"
        before = ledger.totals() if live else None
        res = run_review(spec)
        after = ledger.totals() if live else None
        rep = case_report(o, record, res, provider_calls=provider.calls if provider else 0, ledger_before=before,
                          ledger_after=after, book=book.totals() if live else None,
                          discard_note=_discard(bridge, out))
        if live:
            rep["summary"] = write_summary(paths.out, rep, scrub=key.scrub)
        return rep
    except (PilotError, PipelineError, historical.BridgeError) as e:
        if bridge is not None:
            _discard(bridge, out)
        code = getattr(e, "code", None) or type(e).__name__
        return {"case": case, "refused": True, "status": "refused", "error": {"code": code, "message": str(e)[:400]},
                "quality": QUALITY}
    except BaseException:
        if bridge is not None:
            _discard(bridge, out)
        raise


class _Unused:
    """Backend stand-in for pre-key validation: `validate_spec` reads only `.mode`. It has no provider."""
    mode = "live"

    def __init__(self, handle):
        self.authorization_digest = handle.digest


def _plan_case(o, paths, record, bridge, profile, plan, handle, book, runs) -> dict:
    """Run the REAL pipeline in a scratch dir against a provider that sends nothing: proves inputs, coverage,
    authorization and prompt building, and records the first request sizes. Touches nothing under --out."""
    prov = PlanProvider()
    backend = RecordBackend(handle, book, _providers(prov), utc_now)
    spec = _spec(o, paths, bridge, record, profile, plan, backend, runs)
    validate_spec(spec)
    backend.preflight(profile, plan["budget"])
    try:
        res = run_review(spec)
        dry = {"status": res.status, "error": res.error and res.error.get("code")}
    except PipelineError as e:
        dry = {"status": "refused", "error": e.code}
    reqs = []
    for r in prov.requests:
        size = len(json.dumps(r.get("messages"), ensure_ascii=False).encode("utf-8"))
        cap = r["params"]["maxOutputTokens"]
        reqs.append({"role": r.get("role"), "approxRequestBytes": size,
                     "worstCaseRouterUsdMicros": worst_case_router_micros(r["model"], size, cap)})
    return {"case": record["caseId"], "status": "planned", "mode": "plan", "disclosure": disclosure(record),
            "pinsDigest": record["pinsDigest"], "quality": QUALITY,
            "plan": {"model": o.model, "authorization": "covers the profile and run ceiling",
                     "firstRequests": reqs, "providerCalls": 0, "networkCalls": 0, "keyRead": False,
                     "scratchPipelineRun": dry, "wouldWriteUnder": str(_real(o.out_dir)),
                     "runCeilingUsdMicros": plan["budget"]["maxUsdMicros"], "retries": 0, "repairs": 0,
                     "outputCaps": {r: s["caps"]["maxOutputTokens"] for r, s in profile["roles"].items()}}}


def _providers(anthropic) -> dict:
    return {"anthropic": anthropic, "openai": DisabledProvider("openai"), "synthetic": DisabledProvider("synthetic")}
