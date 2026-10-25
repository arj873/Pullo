"""CLI: python3 -m reviewer smoke {record,replay} ... (offline; synthetic provider only, no network)."""

from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m reviewer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    smoke = sub.add_parser("smoke", help="record or strictly replay the synthetic smoke suite")
    ss = smoke.add_subparsers(dest="action", required=True)
    r = ss.add_parser("record", help="record every case with the scripted synthetic provider")
    r.add_argument("--out", required=True, help="new or empty output directory")
    r.add_argument("--suite", help="synthetic suite directory (default: fixtures/smoke)")
    p = ss.add_parser("replay", help="strictly replay a recording; zero provider calls")
    p.add_argument("--recording", required=True, help="output directory of `smoke record`")
    p.add_argument("--out", required=True, help="new or empty output directory")
    p.add_argument("--suite", help="synthetic suite directory (default: fixtures/smoke)")
    p.add_argument("--manifest-digest", help="expected sha256 of the recording's eval.json (printed by record)")
    a = ap.parse_args(argv)

    try:
        from reviewer.evaluation import DEFAULT_SUITE, EvalError, record_smoke, replay_smoke
    except ImportError as e:
        print(f"error: evaluation runner unavailable: {e}", file=sys.stderr)
        return 2
    suite = a.suite or DEFAULT_SUITE
    try:
        if a.action == "record":
            res = record_smoke(a.out, suite_dir=suite)
        else:
            res = replay_smoke(a.recording, a.out, suite_dir=suite, manifest_digest=a.manifest_digest)
    except EvalError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(res.summary, end="")
    return res.exit_code


if __name__ == "__main__":
    sys.exit(main())
