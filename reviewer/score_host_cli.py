"""Operator entry for the trusted scoring host (SCORE-HOST-05): `plan | live | canary | replay | reconcile`.

    python -I -B -m reviewer.score_host_cli plan   --config pullo-score.toml --baseline B.json --store DIR
    python -I -B -m reviewer.score_host_cli live   ... --confirm-live            (root-gated; refuses without every control)
    python -I -B -m reviewer.score_host_cli canary ... --confirm-live            (only the preregistered three-role probe)
    python -I -B -m reviewer.score_host_cli replay ... --trace T --eval-run-id evr_...
    python -I -B -m reviewer.score_host_cli reconcile --baseline B.json --evidence E.json [--apply]

Models, caps, retries, sampling and prompts come ONLY from the strict score config; there is no flag to change them. The
root-pinned launch baseline binds sources, inputs, config, authorization, state and proofs. Nothing here reads the
environment, a key or the network at import, plan or replay; the env-file loader and the HTTPS transport are imported
inside the gated live/canary path only. Errors print a fixed reason code, never paths, values or content."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from . import score_host as H
from .benchmark.model import Golden, ScorerCase, ToolReview
from .score_baseline import BaselineError, load_baseline, read_regular, sha256_hex, verify
from .score_config import ScoreConfigError, load_score_config
from .score_render import adapt

EVR = re.compile(r"evr_[0-9a-f]{16}")
PLAN_EVR = "evr_0000000000000000"


class CliError(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _cases(baseline, verified) -> dict:
    """Inputs file 'cases.json' (pinned in the baseline): {"cases":[{url,repo,golden:[{id,comment,severity,category}],
    reviews:[{tool,comments:[{id,path,line,origin,title,body,ts}]}]}]}. Pullo title+body rendered once; competitor raw."""
    pinned = {f["path"] for f in baseline.doc["inputs"]}
    if "cases.json" not in pinned:
        raise CliError("inputs-missing-cases")
    doc = json.loads(verified.inputs["cases.json"].decode("utf-8"))                  # the SAME bytes that were hash-verified
    out = {}
    for c in doc["cases"]:
        golden = tuple(Golden(g["id"], g["comment"], g["severity"], g["category"]) for g in c["golden"])
        revs = tuple(ToolReview(r["tool"], c["repo"], None, tuple(adapt(x["origin"], x["id"], x["path"], x["line"], x.get("title"), x["body"], x["ts"])
                                                                   for x in r["comments"])) for r in c["reviews"])
        out[c["url"]] = ScorerCase(c["url"], c["repo"], None, 1, golden, revs)
    return out


def _units(declared, cases):
    units = []
    for n, (url, tool) in enumerate(declared, 1):
        if url not in cases:
            raise CliError("declared-case-missing")
        units.append(H.ScoreUnit(cases[url], tool, f"u001-t{n:02d}"))
        cases[url].review(tool)
    return units


def _launch(doc, declared, cfg) -> H.LaunchBaseline:
    i = doc["initial"]
    return H.LaunchBaseline(tuple(declared), cfg.digest, tuple(sorted(cfg.prompt_sha256.items())), i["scoring"], i["all"],
                            (i["bookCommitted"], i["bookInflight"]))


def _pins(cfg):
    from . import score_render
    return dict(config_digest=cfg.digest, prompt_sha256=dict(cfg.prompt_sha256), schema_sha256=H.schema_sha256(),
                policy_sha256=H.policy_digest(), renderer_sha256=sha256_hex(Path(score_render.__file__).read_bytes()))


def _auth(b):
    """Hash the file once, load the handle, then bind the loaded content to the pinned canonical digest: a file swapped between
    the hash and the load cannot yield a different accepted authorization (the digest is over what was parsed)."""
    from .gateway.auth import trusted_authorization
    a = b.doc["auth"]
    first = read_regular(a["path"], root=None, owner_only=True)
    if sha256_hex(first) != a["sha256"]:
        raise CliError("auth-file-drift")
    handle = trusted_authorization(a["path"], forbidden_roots=(b.doc["inputRoot"], b.doc["sourceRoot"]))
    if sha256_hex(read_regular(a["path"], root=None, owner_only=True)) != a["sha256"]:      # the digest pin itself is checked by verify()
        raise CliError("auth-file-drift")
    return handle


def _reconcile(reconcile, b, a, out, fail) -> int:
    argv2 = ["--ledger", str(b.ledger_path), "--evidence", a.evidence] + (["--apply"] if a.apply else [])
    try:
        return reconcile.main(argv2, out=out)                          # the accepted append-only mechanism; nothing invented here
    except SystemExit:
        return fail("reconcile-refused")


def _recheck_inputs(b, v):
    """Immediately before any live send: the files must still be the verified bytes (detects a swap; never used as input)."""
    for f in b.doc["inputs"]:
        if read_regular(f["path"], root=b.doc["inputRoot"], limit=64 << 20) != v.inputs[f["path"]]:
            raise CliError("input-drift")


def main(argv=None, *, out=sys.stdout, now=None, _transport_factory=None, _key_loader=None) -> int:
    ap = argparse.ArgumentParser(prog="reviewer.score_host_cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "live", "canary", "replay"):
        p = sub.add_parser(name)
        p.add_argument("--config", required=True)
        p.add_argument("--baseline", required=True)
        p.add_argument("--store", required=True)
        p.add_argument("--eval-run-id", default=None)
        if name in ("live", "canary"):
            p.add_argument("--confirm-live", action="store_true")
        if name == "replay":
            p.add_argument("--trace", required=True)
    r = sub.add_parser("reconcile")
    r.add_argument("--baseline", required=True)
    r.add_argument("--evidence", required=True)
    r.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)

    def fail(reason):
        out.write(json.dumps({"ok": False, "reason": reason}) + "\n")
        return 2
    try:
        import datetime as dt
        stamp = now or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        b = load_baseline(a.baseline)
        if a.cmd == "reconcile":
            from .runtime import reconcile
            if not b.state_dir.is_dir():
                raise CliError("state-dir-missing")                        # never create the ORIGINAL state dir
            lock_fd = H.acquire_lock(b.lock_path)                          # the canonical shared scorer lock, held for the whole reconcile
            try:
                return _reconcile(reconcile, b, a, out, fail)
            finally:
                os.close(lock_fd)
        cfg_bytes = read_regular(a.config, limit=1 << 20)                       # the --config file must be the pinned bytes
        if sha256_hex(cfg_bytes) != b.doc["scoreConfig"]["sha256"]:
            raise CliError("source-drift")
        cfg = load_score_config(a.config)
        evr = a.eval_run_id or (PLAN_EVR if a.cmd == "plan" else None)
        if evr is None or not EVR.fullmatch(evr):
            raise CliError("needs-fresh-eval-run-id")
        live = a.cmd in ("live", "canary")
        if live and not a.confirm_live:
            raise CliError("live-needs-confirm")
        if live and (a.cmd == "canary") != (b.mode == "canary"):
            raise CliError("mode-mismatch")
        if a.cmd == "canary" and b.declared != H.CANARY_DECLARED:
            raise CliError("canary-set-not-preregistered")
        handle = None if a.cmd == "replay" else _auth(b)
        # both paid commands need the full catalog evidence; verify() requires a canary receipt only for a campaign baseline
        v = verify(b, now=stamp, auth_handle=handle, require_proofs=live, **_pins(cfg))
        cases = {H.CANARY_CASE_URL: H.canary_case()} if a.cmd == "canary" else _cases(b, v)
        units = _units(b.declared, cases)
        launch = _launch(b.doc, b.declared, cfg)
        from .runtime.catalog import gateway_price
        price = gateway_price("anthropic/claude-opus-5.5")
        store = Path(a.store)
        if a.cmd == "plan":
            from .gateway import SpendBook
            from .runtime import RuntimeLedger, Secret
            with tempfile.TemporaryDirectory() as scratch:      # scratch accounting only: the original state is never opened
                zero = H.LaunchBaseline(launch.declared, launch.config_digest, launch.prompt_sha256, 0, 0)
                host = H.ScoreHost(cfg, zero, units, profile_ref="pullo-score@1", price=price, auth=handle,
                                   book=SpendBook(handle, Path(scratch) / "book.jsonl"), ledger=RuntimeLedger(Path(scratch) / "ledger.jsonl", 50_000_000),
                                   key=Secret(H.PLACEHOLDER_KEY), transport=H.CaptureTransport(), store_dir=store, eval_run_id=evr)
                rep = host.execute_offline()
            rep.update(plan=True, synthetic=True, realScoring=False)
        elif a.cmd == "replay":
            host = H.ScoreHost(cfg, launch, units, profile_ref="pullo-score@1", price=price, auth=None, book=None, ledger=None, key=None,
                               transport=None, store_dir=store, eval_run_id="evr_1111111111111111")
            trace = Path(a.trace)
            pin = "sha256:" + sha256_hex(read_regular(trace, limit=256 << 20))
            if pin not in b.doc["tracePins"]:
                raise CliError("trace-pin-not-in-baseline")
            rep = host.replay(trace, pin, evr)
            rep.pop("documents", None)                           # model text stays out of the printed report
            rep.update(replay=True)
        else:
            from .gateway import SpendBook
            from .runtime import RuntimeLedger
            if not v.live_authorized:
                raise CliError("live-not-authorized")
            if _key_loader is None:
                from .runtime.envfile import load_openrouter_key as _key_loader     # imported only in the gated live path
            if _transport_factory is None:
                from .runtime.openrouter import HttpsTransport as _transport_factory
                H.register_real_transport(_transport_factory)                        # identity token for the real-scoring label
            if not isinstance(b.doc["envFile"], str):
                raise CliError("live-needs-env-file")
            key = _key_loader(b.doc["envFile"], forbidden_roots=(b.doc["inputRoot"], b.doc["sourceRoot"]))
            _recheck_inputs(b, v)
            transport = _transport_factory()
            b.state_dir.mkdir(parents=True, exist_ok=True)
            host = H.ScoreHost(cfg, launch, units, profile_ref="pullo-score@1", price=price, auth=handle,
                               book=SpendBook(handle, b.book_path), ledger=RuntimeLedger(b.ledger_path, 50_000_000), key=key,
                               transport=transport, store_dir=store, eval_run_id=evr, lock_path=b.lock_path)
            host.baseline_file_sha256 = b.file_sha256
            run = host.execute_canary if a.cmd == "canary" else host.execute_live
            rep = run(transport=transport, key=key, verified=v, confirm=True)
            rep["canary"] = a.cmd == "canary"
        out.write(json.dumps(rep, sort_keys=True) + "\n")
        return 0
    except (H.ScoreHostError, BaselineError, CliError) as e:
        return fail(e.reason)
    except ScoreConfigError:
        return fail("score-config-refused")
    except Exception:  # noqa: BLE001 - one fixed code; no exception text, path or content is echoed
        return fail("internal")


if __name__ == "__main__":
    sys.exit(main())
