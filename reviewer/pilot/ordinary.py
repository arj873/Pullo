"""Ordinary current-PR host path (ORDINARY-PR-01): an OPEN pull request's pinned base/head commits plus their two
verified complete repository imports -> the existing repository host (`repository.plan_mode/live_mode/replay_mode`).

This is NOT a historical case: there is no case input, no bridge pins, no merged/closed status and no cutoff
claim. The only new trust input is an external `ordinary-pr-pins@1` (what root says the PR's commits are, and that it
was open at `capturedAt`) whose digest root also holds in an `operator-pin-baseline@1`. This module checks the pin
and the baseline digest; it does NOT check GitHub: current PR state and commits are verified by root outside it.

    python3 -m reviewer.pilot.ordinary --mode plan --case-dir D --pr-pins P --pr-baseline B --store S \
        --base-import-pins BP --head-import-pins HP --out OUT --auth AUTH

`--case-dir` is a plain, empty-or-metadata-only directory named like the case id (`<owner>--<repo>--<number>`); it is
never read, only used as a forbidden-root anchor. Modes, authorization, state, caps, retries and replay pins are the
repository host's, unchanged."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

from reviewer.config import ConfigError
from reviewer.contracts import require
from reviewer.contracts.canonical import digest
from reviewer.gateway import AuthorizationError
from reviewer.pipeline import PipelineError, run_review
from reviewer.repoimport import RepoImportError, github_remote, load_import_pins, open_import, target_dir
from reviewer.repoimport.fsio import read_nofollow
from reviewer.runtime import EnvFileError, load_openrouter_key

from . import repository as R
from .launcher import PilotError, load_baseline, utc_now

PINS_SCHEMA = "ordinary-pr-pins@1"
ORIGIN_SCHEMA = "ordinary-pr-origin@1"
PINS_MAX_BYTES = 1 << 16
_KEYS = {"schema", "caseId", "repo", "prNumber", "baseSha", "mergeBase", "textRef", "headSha", "state", "capturedAt"}
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SHA = re.compile(r"[0-9a-f]{40}")
_REPO = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})")
VERIFICATION = ("current GitHub PR state and commits are verified by root outside this module; the code checks only "
                "the external pin, its operator-baseline digest and the two pinned import identities")


class OrdinaryError(R.RepositoryError):
    """A refusal before (or instead of) a run. Messages never contain keys or file content."""


# ------------------------------------------------------------------ pins

def _unique(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _no_constant(name):
    raise ValueError("non-finite number")


def check_pins(doc) -> dict:
    """Closed-shape check of `ordinary-pr-pins@1`; returns a private plain copy."""
    bad = OrdinaryError("pins are not a valid ordinary-pr-pins@1 document")
    if not isinstance(doc, dict) or set(doc) != _KEYS or doc["schema"] != PINS_SCHEMA:
        raise bad
    str_keys = ("caseId", "repo", "baseSha", "textRef", "headSha", "state", "capturedAt")
    if not all(type(doc[k]) is str for k in str_keys) or (doc["mergeBase"] is not None and type(doc["mergeBase"]) is not str):
        raise bad
    m = _REPO.fullmatch(doc["repo"])
    n = doc["prNumber"]
    if m is None or type(n) is not int or not 1 <= n <= 9_999_999_999:
        raise bad
    if doc["caseId"] != f"{m.group(1)}--{m.group(2)}--{n}":
        raise OrdinaryError("pins caseId does not match repo and prNumber")
    if doc["state"] != "open":
        raise OrdinaryError("pins state must be exactly 'open': this host reviews an ordinary current PR only")
    if not all(_SHA.fullmatch(doc[k]) for k in ("baseSha", "textRef", "headSha")) \
            or (doc["mergeBase"] is not None and not _SHA.fullmatch(doc["mergeBase"])):
        raise bad
    if doc["textRef"] != (doc["mergeBase"] or doc["baseSha"]):
        raise OrdinaryError("pins textRef must be the merge base if supplied, else the base sha")
    if not _TS.fullmatch(doc["capturedAt"]):
        raise bad
    try:
        dt.datetime.strptime(doc["capturedAt"], "%Y-%m-%dT%H:%M:%SZ")
        for v in doc.values():
            if type(v) is str:
                v.encode("utf-8")
    except (ValueError, UnicodeEncodeError):
        raise bad from None
    if doc["capturedAt"] > utc_now():
        raise OrdinaryError("pins capturedAt lies in the future")
    return copy.deepcopy(doc)


def _inside(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def load_pins(path, *, case_dir, store) -> dict:
    """External pins: regular non-link file within the cap, strict JSON, outside the case dir and the store."""
    p = Path(os.path.realpath(path))
    for name, root in (("case directory", case_dir), ("import store", store)):
        if _inside(p, Path(os.path.realpath(root))):
            raise OrdinaryError(f"pins must be stored outside the {name}")
    try:
        raw = read_nofollow(path, PINS_MAX_BYTES)
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_no_constant)
    except (OSError, ValueError, RecursionError):                    # incl. UnicodeDecodeError, duplicate keys, NaN
        raise OrdinaryError("pins file is unreadable, oversized, not strict JSON or has duplicate keys") from None
    return check_pins(doc)


# ------------------------------------------------------------------ ingestion

def ingest_ordinary(o: R.RepositoryOptions) -> R.Ingested:
    """Pins, baseline digest, then both full imports against their external import pins, then the CaseInput."""
    case_dir = Path(os.path.abspath(o.case_dir))
    if os.path.islink(case_dir) or not case_dir.is_dir() or not R._CASE_RX.fullmatch(case_dir.name):
        raise OrdinaryError("case dir must be a real directory with a plain case id as its name")
    store = Path(os.path.abspath(o.store))
    pins = load_pins(o.case_pins, case_dir=case_dir, store=store)
    if pins["caseId"] != case_dir.name:
        raise OrdinaryError("pins are for a different case than the case directory name")
    try:
        baseline = load_baseline(o.case_baseline)
    except PilotError as e:
        raise OrdinaryError(str(e)[:300]) from None
    if baseline.get(pins["caseId"]) != digest(pins):
        raise OrdinaryError(f"pins for {pins['caseId']} differ from the operator baseline (or the baseline has none)")
    imports, import_pins = {}, {}
    for side, sha, pins_path in (("base", pins["textRef"], o.base_import_pins), ("head", pins["headSha"], o.head_import_pins)):
        try:
            d = target_dir(store, github_remote(f"https://github.com/{pins['repo']}"), sha)
            ip = load_import_pins(pins_path, import_dir=d)
            if ip["repo"].lower() != pins["repo"].lower() or ip["commitSha"] != sha:
                raise OrdinaryError(f"{side} import pins are not for the PR's {side} commit of {pins['repo']}")
            imp = open_import(d, pins=ip)
        except RepoImportError as e:
            raise OrdinaryError(f"{side} import refused ({e.code}): {str(e)[:300]}") from None
        rec = imp.record
        if rec["commitSha"] != sha or f"{rec['repo']['owner']}/{rec['repo']['name']}".lower() != pins["repo"].lower():
            raise OrdinaryError(f"{side} import is not the pinned commit of the PR repository")
        if "relatesTo" in rec:
            raise OrdinaryError(f"{side} import claims a relation to a historical case: not an ordinary PR import")
        imports[side], import_pins[side] = imp, ip
    base, head = imports["base"], imports["head"]
    if base.snapshot_id == head.snapshot_id:
        raise OrdinaryError("base and head imports are the same content: not a reviewable change")
    try:
        case = require("CaseInput", {
            "schema": "case-input@1", "id": pins["caseId"].lower(), "repo": pins["repo"], "synthetic": False,
            "base": {"snapshotId": base.snapshot_id, "root": "base"},
            "head": {"snapshotId": head.snapshot_id, "root": "head"},
            "pr": {"title": "", "body": ""}})                       # PR text stays omitted
    except Exception:  # noqa: BLE001
        raise OrdinaryError("CaseInput could not be built (case id not lowercase-mappable?)") from None
    return R.Ingested(pins["caseId"], case, base, head, pins, import_pins, {"base": [], "head": []}, case_dir, store)


def origin_doc(ing: R.Ingested) -> dict:
    p = ing.pins
    return {"schema": ORIGIN_SCHEMA, "kind": "ordinary current-PR snapshot: not a historical, merged or closed case",
            "repo": p["repo"], "prNumber": p["prNumber"], "caseId": p["caseId"], "state": p["state"],
            "stateNote": "as pinned at capturedAt; not re-checked by this module", "capturedAt": p["capturedAt"],
            "baseSha": p["baseSha"], "mergeBase": p["mergeBase"], "textRef": p["textRef"], "headSha": p["headSha"],
            "pinsDigest": digest(p), "prText": "OMITTED: the reviewer sees no PR title or body",
            "historicalClaim": "none", "verification": VERIFICATION}


def _write_origin(out_dir: str, origin: dict) -> str | None:
    """Beside the host's report.json (which carries `casePinsDigest`), once the output directory exists."""
    d = Path(out_dir)
    if not d.is_dir() or os.path.islink(d):
        return None
    path = d / "origin.json"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(origin, indent=1, sort_keys=True) + "\n")
    except OSError:
        return None
    return str(path)


# ------------------------------------------------------------------ entry

def run_ordinary(o: R.RepositoryOptions, *, transport=None, key_loader=load_openrouter_key, runner=run_review) -> dict:
    R.check_options(o)
    cfg = R.effective_config(o)                          # before ingestion, output, state, key or model
    ing = ingest_ordinary(o)
    if o.mode == "plan":
        rep = R.plan_mode(o, ing, runner=runner, cfg=cfg)
    elif o.mode == "live":
        rep = R.live_mode(o, ing, transport=transport, key_loader=key_loader, runner=runner, cfg=cfg)
    else:
        rep = R.replay_mode(o, ing, runner=runner, cfg=cfg)
    rep["reviewModels"] = cfg.report()
    rep["origin"] = origin = origin_doc(ing)
    if o.mode != "plan":
        rep["originPath"] = _write_origin(o.out_dir, origin)
    return rep


def render(rep: dict) -> str:
    og = rep["origin"]
    head = (f"origin: ordinary current-PR snapshot {og['repo']}#{og['prNumber']} state={og['state']} "
            f"captured {og['capturedAt']} base {og['textRef'][:12]} head {og['headSha'][:12]}\n"
            f"  not a historical/merged case; {VERIFICATION}\n")
    return head + R.render(rep)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="reviewer.pilot.ordinary",
                                 description="Ordinary CURRENT open PR review over two pinned complete imports (read-only).")
    ap.add_argument("--mode", choices=R.MODES, default="plan")
    ap.add_argument("--case-dir", required=True, help="plain directory named <owner>--<repo>--<number> (never read)")
    ap.add_argument("--pr-pins", required=True, help="external ordinary-pr-pins@1 for the current PR")
    ap.add_argument("--pr-baseline", required=True, help="external operator-pin-baseline@1 holding the pins digest")
    ap.add_argument("--store", required=True, help="repoimport store holding both sides' imports")
    ap.add_argument("--base-import-pins", required=True, help="external repo-import-pins@1 for the base (textRef) import")
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
    o = R.RepositoryOptions(mode=a.mode, case_dir=a.case_dir, case_pins=a.pr_pins, case_baseline=a.pr_baseline,
                            store=a.store, base_import_pins=a.base_import_pins, head_import_pins=a.head_import_pins,
                            out_dir=a.out, auth=a.auth, state_dir=a.state_dir, env_file=a.env,
                            baseline_micros=a.baseline_micros, book_baseline_micros=a.book_baseline_micros,
                            confirm_live=a.confirm_live, replay_trace=a.replay_trace, trace_digest=a.trace_digest,
                            retrieval=a.retrieval == "on", repeat=a.repeat, config=a.config)
    try:
        rep = run_ordinary(o, transport=transport, key_loader=key_loader, runner=runner)
    except (R.RepositoryError, ConfigError, PilotError, EnvFileError, AuthorizationError, PipelineError) as e:
        err.write(f"error: {type(e).__name__}: {str(e)[:400]}\n")
        return 2
    out.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n" if a.json else render(rep))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
