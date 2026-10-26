"""python -m reviewer.pilot: plan (default) | --live | --replay-trace. See orchestration/handoffs/S0B-01c-api.md."""

from __future__ import annotations

import argparse
import json
import sys

from reviewer.runtime import load_openrouter_key, EnvFileError
from reviewer.gateway import AuthorizationError

from .launcher import PilotError, PilotOptions, run_cases
from .profile import (MAX_OUTPUT_CAP, MODEL, OUTPUT_CAPS, SOFT_DEADLINE_SEC, WALL_CLOCK_SEC, ProfileError)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="reviewer.pilot", description="Pinned historical PR review trial (read-only).")
    ap.add_argument("--corpus-root", required=True, help="historical corpus root (never written, source/labels never read)")
    ap.add_argument("--pins-dir", required=True, help="operator pin store holding <case>.json, outside the corpus")
    ap.add_argument("--out", required=True, help="output root (outside corpus); live/replay write runs/ summaries/ work/")
    ap.add_argument("--case", action="append", required=True, help="case id (repeatable); cases share one book/ledger")
    ap.add_argument("--pins-baseline", help="operator-pin-baseline@1: each case's pinsDigest must match before any spend")
    ap.add_argument("--auth", help="operator SpendAuthorization JSON (outside corpus/out); not used by replay")
    ap.add_argument("--live", action="store_true", help="send REAL requests: loads --env and uses --state-dir")
    ap.add_argument("--state-dir", help="EXISTING operator state dir with spend-book.jsonl and runtime-ledger.jsonl")
    ap.add_argument("--env", help="host .env path (read only with --live)")
    ap.add_argument("--replay-trace", help="recorded trace.jsonl to replay strictly (no provider, no key)")
    ap.add_argument("--trace-digest", help="operator-held sha256 of the recorded trace")
    ap.add_argument("--repeat", type=int, default=0, help="new eval identity, e.g. after recovery-required")
    ap.add_argument("--model", default=MODEL, help="exact allowlisted OpenRouter model id (default Sonnet 5.5)")
    for r, v in OUTPUT_CAPS.items():
        ap.add_argument(f"--{r}-max-output-tokens", type=int, default=v, help=f"1..{MAX_OUTPUT_CAP} (default {v})")
    ap.add_argument("--wall-clock-sec", type=int, default=WALL_CLOCK_SEC)
    ap.add_argument("--soft-deadline-sec", type=int, default=SOFT_DEADLINE_SEC)
    ap.add_argument("--keep-going", action="store_true", help="continue to the next case after a non-completed case")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    return ap


def render(rep: dict) -> str:
    L = [f"mode: {rep['mode']}   ok: {rep['ok']}"]
    for c in rep["cases"]:
        L.append("")
        L.append(f"case: {c['case']}   status: {c['status']}")
        if c.get("refused"):
            L.append(f"  refused: {c['error']['code']}: {c['error']['message']}")
            continue
        d = c["disclosure"]
        L += [f"  coverage: {d['statement']}", f"  PR title/body: {d['prText']}", f"  pins: {c['pinsDigest']}"]
        if c["mode"] == "plan":
            p = c["plan"]
            L += [f"  plan: {p['model']}  ceiling ${p['runCeilingUsdMicros'] / 1e6:.2f}  retries={p['retries']} "
                  f"repairs={p['repairs']}  caps={p['outputCaps']}", f"  authorization: {p['authorization']}",
                  f"  first requests (nothing sent): {p['firstRequests']}",
                  f"  scratch pipeline run: {p['scratchPipelineRun']}   would write under: {p['wouldWriteUnder']}"]
            continue
        n = c["counts"]
        L += [f"  run: {c['runId']}  idempotent={c['idempotent']}  provider calls={c['providerCalls']}"
              f"  incomplete={c['incomplete']}  error={c['error']}",
              f"  hypotheses={n['hypotheses']} findings={n['findings']} verified={n['verifications']} "
              f"dropped={n['drops']} comments={n['comments']}"]
        L += [f"  {k}: {v}" for k, v in c["paths"].items()]
        L.append(f"  trace digest: {c['traceDigest']['value']}  ({c['traceDigest']['trust']})")
        g = c["costs"]["gateway"]
        L.append(f"  cost gateway computed (token-priced, not a bill): {g['computedTokenPricedUsd']}")
        r = c["costs"]["runtime"]
        if r:
            for part in ("thisCase", "cumulative"):
                L.append(f"  cost ledger {part}: " + "  ".join(f"{k}=${v['usd']}" for k, v in r[part].items()))
        L.append(f"  quality: {c['quality']}")
        if c.get("summary"):
            L.append(f"  summary: {c['summary']}")
        if c.get("cleanup"):
            L.append(f"  cleanup: {c['cleanup']}")
    if rep["notRun"]:
        L += ["", f"not run: {rep['notRun']}"]
    return "\n".join(L) + "\n"


def main(argv=None, *, transport=None, key_loader=load_openrouter_key, out=sys.stdout, err=sys.stderr) -> int:
    ap = _parser()
    a = ap.parse_args(argv)
    if a.live and a.replay_trace:
        ap.error("--live and --replay-trace are mutually exclusive")
    mode = "live" if a.live else "replay" if a.replay_trace else "plan"
    caps = {r: getattr(a, f"{r}_max_output_tokens") for r in OUTPUT_CAPS}
    o = PilotOptions(corpus_root=a.corpus_root, pins_dir=a.pins_dir, out_dir=a.out, cases=tuple(a.case), mode=mode,
                     auth=a.auth, state_dir=a.state_dir, env_file=a.env, pins_baseline=a.pins_baseline,
                     repeat=a.repeat, model=a.model, output_caps=caps, wall_clock_sec=a.wall_clock_sec,
                     soft_deadline_sec=a.soft_deadline_sec, replay_trace=a.replay_trace, trace_digest=a.trace_digest,
                     keep_going=a.keep_going)
    try:
        rep = run_cases(o, transport=transport, key_loader=key_loader)
    except (PilotError, ProfileError, EnvFileError, AuthorizationError) as e:
        err.write(f"error: {type(e).__name__}: {str(e)[:400]}\n")
        return 2
    out.write(json.dumps(rep, indent=1, sort_keys=True, default=str) + "\n" if a.json else render(rep))
    return 0 if rep["ok"] else 1
