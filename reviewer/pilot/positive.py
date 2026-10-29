"""Real-provider positive review control (S1-12): the owned synthetic fixture `fixtures/retrieval-positive` ->
`run_review` with the repository pilot profile (Sonnet 5.5, Turn retrieval, $4 run ceiling), in mode plan | live | replay.
Host plumbing only. The model decides what it finds; this tool never scripts, compares or retries a result.
See orchestration/handoffs/S1-12-interface.md.

    python3 -m reviewer.pilot.positive --mode plan --source-baseline BASELINE.json --out OUT --auth AUTH

The expected issue lives only in tests. Live is root's, after independent review: it needs --confirm-live, an existing
durable state dir, --baseline-micros and the one trusted key loader. Replay needs a trace and its external digest.

Optional private control (DOGFOOD-CONTROL-HOST-01): --control-dir DIR (holding exactly base/ and head/), --control-id,
--control-repo and --control-pins PINS, all four together, replace the checked-in fixture as the two snapshots. PINS is an
operator-held control-pins@1 document OUTSIDE the checkout and the control: {"schema", "caseId", "repo", "base": {path:
sha256}, "head": {path: sha256}}. It must bind every file of both trees exactly (no extra, missing or changed file, no link,
no executable); the host source baseline is still checked as before."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from reviewer.config import ConfigError, EffectiveConfig, resolve_config
from reviewer.contracts import ContractInputError, loads_strict, require
from reviewer.contracts.canonical import GITHUB_REPO, canonical_json, digest, idempotency_key_eval, run_id, sha256_hex
from reviewer.contracts.schema import is_safe_relpath
from reviewer.contracts.snapshot import SnapshotError, build_manifest
from reviewer.gateway import AuthorizationError, DisabledProvider, SpendBook, trusted_authorization
from reviewer.historical import BridgeError
from reviewer.historical.bridge import _check_out
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReplayBackend, ReviewSpec,
                               SnapshotInput, run_review, validate_spec)
from reviewer.runtime import EnvFileError, RuntimeLedger, Secret, TRIAL_TOTAL_USD_MICROS, load_openrouter_key
from reviewer.runtime.openrouter import OpenRouterProvider
from reviewer.runtime.turn_canary import Refused, open_state

from .providers import ReviewProviders, live_terra, needs, plan_providers, scrub_of, worst_case
from .launcher import REPO, PilotError, _Unused, _force_cleanup, gateway_costs, ledger_costs, utc_now

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
CONTROL_PINS_SCHEMA = "control-pins@1"
CONTROL_LABEL = ("private synthetic control, operator-supplied and self-authored: not historical, not independent "
                 "evidence, no recall or quality rate; any expected result is held outside both trees and every request")
_ID_RX = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
MAX_PINS_BYTES = 4 << 20
MAX_CONTROL_FILES = 20_000
MAX_CONTROL_FILE_BYTES = 8 << 20
MAX_CONTROL_DEPTH = 32


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
    config: str | None = None
    control_dir: str | None = None       # the four control options are all given or all absent
    control_id: str | None = None
    control_repo: str | None = None
    control_pins: str | None = None


@dataclass(frozen=True)
class Prepared:
    case: dict
    base: SnapshotInput
    head: SnapshotInput
    source: dict            # {"scopeDigest", "fileCount", "baselineCapturedAt"}
    fixture: Path           # the snapshot parent: the checked-in fixture, or the real path of the control
    control: dict | None = None     # {"pinsDigest", "fileCounts"} only when a control was selected


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
    check_control_options(o)


# ------------------------------------------------------------------ optional private control

def _real(p) -> Path:
    return Path(os.path.realpath(os.path.abspath(p)))


def _overlap(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def _control_roots(o: PositiveOptions) -> tuple:
    """Untrusted content the trust boundaries (config, auth, env, state, output, trace) must stay out of."""
    return (o.control_dir, o.control_pins) if o.control_dir is not None else ()


def check_control_options(o: PositiveOptions) -> None:
    """Syntax and path overlaps only (no file content is read): refused before any config, auth, state, key or output."""
    given = (o.control_dir, o.control_id, o.control_repo, o.control_pins)
    if all(v is None for v in given):
        return
    if not all(isinstance(v, str) and v for v in given):
        raise PositiveError("--control-dir, --control-id, --control-repo and --control-pins are needed together")
    if not _ID_RX.fullmatch(o.control_id) or not GITHUB_REPO.fullmatch(o.control_repo) \
            or o.control_repo != o.control_repo.lower():
        raise PositiveError("--control-id and --control-repo must be lowercase slugs (id, owner/name)")
    if o.control_id == CASE_ID or o.control_repo == CASE_REPO:
        raise PositiveError("--control-id/--control-repo may not reuse the checked-in fixture's identity")
    if os.path.islink(os.path.abspath(o.control_dir)):
        raise PositiveError("the control directory may not be a link")
    ctl, repo, pins = _real(o.control_dir), _real(REPO), _real(o.control_pins)
    if _overlap(ctl, repo):
        raise PositiveError("the control must lie outside the checkout")
    if _overlap(pins, repo):
        raise PositiveError("the control pins must be held outside the checkout")
    if pins == _real(o.source_baseline):
        raise PositiveError("the control pins and the source baseline must be separate files")
    for name, path in (("source baseline", o.source_baseline), ("control pins", o.control_pins), ("output", o.out_dir),
                       ("authorization", o.auth), ("state", o.state_dir), ("env file", o.env_file),
                       ("replay trace", o.replay_trace), ("config", o.config)):
        if path and _overlap(ctl, _real(path)):
            raise PositiveError(f"the {name} path overlaps the control")


def _read_pins(o: PositiveOptions) -> dict:
    try:
        fd = os.open(os.path.abspath(o.control_pins), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise PositiveError("control pins are absent, unreadable or a link") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise PositiveError("control pins are not a regular file")
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_PINS_BYTES + 1)
    if len(data) > MAX_PINS_BYTES:
        raise PositiveError("control pins are too large")
    try:
        doc = loads_strict(data)
    except ContractInputError:
        raise PositiveError("control pins are not strict JSON (malformed or a duplicate key)") from None
    if not isinstance(doc, dict) or set(doc) != {"schema", "caseId", "repo", "base", "head"} \
            or doc["schema"] != CONTROL_PINS_SCHEMA:
        raise PositiveError(f"control pins are not exactly a {CONTROL_PINS_SCHEMA} document")
    if doc["caseId"] != o.control_id or doc["repo"] != o.control_repo:
        raise PositiveError("control pins bind a different case id or repo than the options")
    for side in ("base", "head"):
        files = doc[side]
        if not isinstance(files, dict) or not 0 < len(files) <= MAX_CONTROL_FILES or not all(
                isinstance(k, str) and is_safe_relpath(k) and isinstance(v, str) and _SHA_RX.fullmatch(v)
                for k, v in files.items()):
            raise PositiveError(f"control pins list a malformed or empty {side} tree")
    return doc


def _hash_regular(path: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise PositiveError("a control file is unreadable or a link") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CONTROL_FILE_BYTES:
            raise PositiveError("a control file is not regular or exceeds the size cap")
        data = f.read(MAX_CONTROL_FILE_BYTES + 1)
    if len(data) > MAX_CONTROL_FILE_BYTES:
        raise PositiveError("a control file grew past the size cap")
    return sha256_hex(data)


def _control_tree(root: Path, side: str, pinned: dict) -> dict:
    """Hash every pinned file under `root`; unpinned files are listed (value None) and never read. Links, special files
    and executables are refused."""
    have = {}

    def visit(d: str, prefix: str, depth: int) -> None:
        if depth > MAX_CONTROL_DEPTH:
            raise PositiveError(f"control {side} nests too deeply")
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            raise PositiveError(f"control {side} is unreadable") from None
        for e in entries:
            rel = prefix + e.name
            if e.is_symlink():
                raise PositiveError(f"control {side}/{rel!a} is a symlink")
            if e.is_dir(follow_symlinks=False):
                visit(e.path, rel + "/", depth + 1)
                continue
            mode = e.stat(follow_symlinks=False).st_mode
            if not stat.S_ISREG(mode) or mode & 0o111 or not is_safe_relpath(rel):
                raise PositiveError(f"control {side}/{rel!a} is not a plain non-executable file")
            if len(have) >= MAX_CONTROL_FILES:
                raise PositiveError(f"control {side} has too many files")
            have[rel] = _hash_regular(e.path) if rel in pinned else None
    visit(str(root), "", 0)
    return have


def load_control(o: PositiveOptions) -> tuple:
    """(pins document, real control path) once EVERY file of both trees equals its pin. Nothing else is accepted."""
    check_control_options(o)
    doc = _read_pins(o)
    ctl = _real(o.control_dir)
    if not ctl.is_dir() or sorted(os.listdir(ctl)) != ["base", "head"]:
        raise PositiveError("the control directory must hold exactly base/ and head/")
    for side in ("base", "head"):
        if os.path.islink(ctl / side) or not (ctl / side).is_dir():
            raise PositiveError(f"control {side} is not a plain directory")
        pinned, have = doc[side], _control_tree(ctl / side, side, doc[side])
        missing, extra = sorted(pinned.keys() - have.keys()), sorted(k for k, v in have.items() if v is None)
        changed = sorted(k for k, v in have.items() if v is not None and v != pinned[k])
        if missing or extra or changed:
            raise PositiveError(f"control {side} differs from its pins: " + "; ".join(
                f"{n} {v[:4]}" for n, v in (("unpinned", extra), ("missing", missing), ("changed", changed)) if v))
    return doc, ctl


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
    pins = None
    root, case_id, case_repo = FIXTURE, CASE_ID, CASE_REPO
    if o.control_dir is not None:
        pins, root = load_control(o)                             # every file of both trees, before a snapshot is built
        case_id, case_repo = o.control_id, o.control_repo
    snaps = {}
    for side in ("base", "head"):
        try:
            m = build_manifest(root / side)
        except SnapshotError as e:
            raise PositiveError(f"fixture {side} is not a plain snapshot: {str(e)[:200]}") from None
        if pins is not None and {e["path"]: (e["type"], e["sha256"]) for e in m["entries"]} != {
                k: ("file", v) for k, v in pins[side].items()}:
            raise PositiveError(f"control {side} changed while it was being pinned")
        snaps[side] = SnapshotInput(root / side, m)
    ids = {s: snaps[s].manifest["snapshotId"] for s in snaps}
    if ids["base"] == ids["head"]:
        raise PositiveError("fixture base and head are identical")
    case = require("CaseInput", {
        "schema": "case-input@1", "id": case_id, "repo": case_repo, "synthetic": True,
        "base": {"snapshotId": ids["base"], "root": "base"}, "head": {"snapshotId": ids["head"], "root": "head"},
        "pr": {"title": "", "body": ""}})
    control = pins and {"pinsDigest": digest(pins), "fileCounts": {s: len(pins[s]) for s in ("base", "head")}}
    return Prepared(case, snaps["base"], snaps["head"], source, root, control)


def effective_config(o: PositiveOptions, cfg: EffectiveConfig | None = None) -> EffectiveConfig:
    """Resolved (and validated) before the fixture, output, state, key or any model action."""
    if cfg is not None:
        return cfg
    return resolve_config(o.config, forbidden_roots=(FIXTURE, o.out_dir, o.source_baseline, *_control_roots(o)))


def _profile_parts(cfg: EffectiveConfig | None = None):
    cfg = cfg or resolve_config()
    profile = repository_profile(True, cfg.models)
    return profile, repository_plan(profile), repository_policy(True)


def config_identity(prep: Prepared, profile: dict, plan: dict, policy) -> dict:
    ident = {"schema": CONFIG_SCHEMA, "caseId": prep.case["id"], "sourceScopeDigest": prep.source["scopeDigest"],
             "snapshotIds": {"base": prep.case["base"]["snapshotId"], "head": prep.case["head"]["snapshotId"]},
             "profile": digest(profile), "plan": digest(plan), "retrievalPolicy": policy.digest,
             "prTextSupplied": False}
    if prep.control:                    # absent by default: the checked-in fixture's identity is unchanged
        ident["control"] = {"pinsDigest": prep.control["pinsDigest"], "caseId": prep.case["id"], "repo": prep.case["repo"]}
    return ident


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
    host = HostConfig(out_root=runs, eval=EvalIdentity(eval_run_id(o, cfg), prep.case["id"], 0), config_identity=cfg,
                      forbidden_roots=(prep.fixture,), wall_clock=utc_now, retrieval=policy)
    return ReviewSpec(case=copy.deepcopy(prep.case), base=SnapshotInput(prep.base.root, copy.deepcopy(prep.base.manifest)),
                      head=SnapshotInput(prep.head.root, copy.deepcopy(prep.head.manifest)), profile=profile,
                      plan=plan, host=host, backend=backend)


def header(prep: Prepared) -> dict:
    rep = {"case": prep.case["id"], "repo": prep.case["repo"], "synthetic": True, "sourceBaseline": prep.source,
           "snapshotIds": {"base": prep.case["base"]["snapshotId"], "head": prep.case["head"]["snapshotId"]},
           "prText": "OMITTED: the reviewer sees no PR title or body",
           "outcome": "model-decided: this tool never scripts, scores or retries the result", "quality": QUALITY}
    if prep.control:
        rep["control"] = {"label": CONTROL_LABEL, **prep.control}
    return rep


# ------------------------------------------------------------------ output

def check_out(o: PositiveOptions) -> Path:
    forbidden = [REPO / "reviewer", REPO / "fixtures", REPO / "tests", o.source_baseline, *_control_roots(o)]
    forbidden += [p for p in (o.auth, o.state_dir, o.env_file, o.replay_trace) if p]
    try:
        return _check_out(o.out_dir, Path(o.control_dir) if o.control_dir is not None else FIXTURE, forbidden)
    except BridgeError as e:
        raise PositiveError(str(e)[:200]) from None


# ------------------------------------------------------------------ plan

def plan_mode(o: PositiveOptions, prep: Prepared, *, runner=run_review, cfg=None) -> dict:
    cfg = effective_config(o, cfg)
    check_out(o)
    profile, plan, policy = _profile_parts(cfg)
    handle = trusted_authorization(o.auth, forbidden_roots=[REPO, Path(os.path.realpath(o.out_dir)), *_control_roots(o)])
    scratch = tempfile.TemporaryDirectory(prefix="pilot-positive-plan-")
    transport = CapturingTransport()
    capture = None
    problem = result = None
    try:
        root = Path(os.path.realpath(scratch.name))
        runs = root / "runs"
        runs.mkdir()
        book = SpendBook(handle, root / BOOK_NAME)
        ledger = RuntimeLedger(root / LEDGER_NAME, TRIAL_TOTAL_USD_MICROS)
        evr = eval_run_id(o, config_identity(prep, profile, plan, policy))
        providers, capture = plan_providers(profile, transport, lambda: OpenRouterProvider(
            enabled=True, key=Secret("plan-placeholder-not-a-key"), authorization=handle, book=book, ledger=ledger,
            transport=transport, run_scope=provider_scope(evr, prep)))
        backend = RecordBackend(handle, book, providers.mapping, utc_now)
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
    first = capture.facts(transport.requests, _request_facts) if capture else []
    ceiling = plan["budget"]["maxUsdMicros"]
    worst = worst_case(first)
    planned = bool(first) and not any(f.get("toolsInBody", False) for f in first)
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
            "plan": {"model": cfg.models.summary(), "models": cfg.report()["roles"], "retrievalPolicy": policy.to_doc(), "profile": f"{profile['id']}@{profile['version']}",
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
              runner=run_review, cfg=None) -> dict:
    cfg = effective_config(o, cfg)
    out = check_out(o)
    profile, plan, policy = _profile_parts(cfg)
    if needs(profile, "openai"):                  # gate S1: this host's state is the OpenRouter trial state
        raise PositiveError("live Terra arms run through the repository/benchmark hosts with their own Terra state "
                            "dir; the positive-control host only plans them")
    handle = trusted_authorization(o.auth, forbidden_roots=[REPO, out, *_control_roots(o)])
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
    terra = live_terra(profile, ledger, provider_scope(evr, prep))
    runs = make_out(out)
    key = None
    try:
        router = DisabledProvider("anthropic")
        if needs(profile, "anthropic"):
            key = key_loader(o.env_file, forbidden_roots=[REPO / "reviewer", REPO / "fixtures", out, *_control_roots(o)])
            router = OpenRouterProvider(enabled=True, key=key, authorization=handle, book=book, ledger=ledger,
                                        transport=transport, run_scope=provider_scope(evr, prep))
        provider = ReviewProviders(router, terra)
        backend = RecordBackend(handle, book, provider.mapping, utc_now)
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
            rep["reportPath"] = write_report(out, rep, scrub=scrub_of(key))
            return rep
        except BaseException as e:
            _interrupted(out, prep, o, e, key, ledger, before, provider)
            raise
        rep = run_report(o, prep, res, provider_calls=provider.calls, ledger_before=before,
                         ledger_after=ledger.totals(), book=book.totals())
        rep["reportPath"] = write_report(out, rep, scrub=scrub_of(key))
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
        write_report(out, rep, scrub=scrub_of(key))
    except Exception:  # noqa: BLE001 - never hides the original interruption
        pass


# ------------------------------------------------------------------ replay

def replay_mode(o: PositiveOptions, prep: Prepared, *, runner=run_review, cfg=None) -> dict:
    cfg = effective_config(o, cfg)
    out = check_out(o)
    profile, plan, policy = _profile_parts(cfg)
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
    cfg = effective_config(o)                            # before the fixture, output, state, key or model
    prep = prepare(o)
    if o.mode == "plan":
        rep = plan_mode(o, prep, runner=runner, cfg=cfg)
    elif o.mode == "live":
        rep = live_mode(o, prep, transport=transport, key_loader=key_loader, runner=runner, cfg=cfg)
    else:
        rep = replay_mode(o, prep, runner=runner, cfg=cfg)
    rep["reviewModels"] = cfg.report()
    return rep


def render(rep: dict) -> str:
    L = [f"mode: {rep['mode']}   status: {rep['status']}   ok: {rep['ok']}", f"case: {rep['case']} ({rep['repo']})",
         f"  source baseline: {rep['sourceBaseline']['fileCount']} files scope {rep['sourceBaseline']['scopeDigest']}",
         f"  {rep['quality']}"]
    if rep.get("control"):
        L.append(f"  control: {rep['control']['label']} (pins {rep['control']['pinsDigest']})")
    L.append(f"  review models: { {r: v['model'] for r, v in rep['reviewModels']['roles'].items()} } "
             f"(config {rep['reviewModels']['source']} {rep['reviewModels']['digest']})")
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
    ap.add_argument("--control-dir", help="private control: directory holding exactly base/ and head/ (needs the three below)")
    ap.add_argument("--control-id", help="private control: neutral lowercase case id")
    ap.add_argument("--control-repo", help="private control: neutral lowercase owner/name")
    ap.add_argument("--control-pins", help="private control: external control-pins@1 binding every file of both trees")
    ap.add_argument("--config", help="review-model config (pullo.toml format); default: Pullo's own pullo.toml")
    ap.add_argument("--json", action="store_true")
    return ap


def main(argv=None, *, transport=None, key_loader=load_openrouter_key, out=sys.stdout, err=sys.stderr,
         runner=run_review) -> int:
    a = _parser().parse_args(argv)
    o = PositiveOptions(mode=a.mode, source_baseline=a.source_baseline, out_dir=a.out, auth=a.auth,
                        state_dir=a.state_dir, env_file=a.env, baseline_micros=a.baseline_micros,
                        book_baseline_micros=a.book_baseline_micros, confirm_live=a.confirm_live,
                        replay_trace=a.replay_trace, trace_digest=a.trace_digest, config=a.config,
                        control_dir=a.control_dir, control_id=a.control_id, control_repo=a.control_repo,
                        control_pins=a.control_pins)
    try:
        rep = run_positive(o, transport=transport, key_loader=key_loader, runner=runner)
    except (PositiveError, ConfigError, PilotError, EnvFileError, AuthorizationError, PipelineError) as e:
        err.write(f"error: {type(e).__name__}: {str(e)[:400]}\n")
        return 2
    out.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n" if a.json else render(rep))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
