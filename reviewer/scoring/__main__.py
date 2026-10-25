"""CLI: python3 -m reviewer.scoring {build-smoke,check} ... (offline; no network, no model calls)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks import check_suite
from .smoke import diff_smoke, write_smoke
from .suite import load_suite

DEFAULT = "fixtures/smoke"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m reviewer.scoring")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build-smoke", help="regenerate fixtures/smoke from reviewer/scoring/smoke.py")
    b.add_argument("--out", default=DEFAULT)
    b.add_argument("--check", action="store_true", help="only report drift; write nothing")
    c = sub.add_parser("check", help="validate a suite: schemas, snapshots, isolation, scripts")
    c.add_argument("suite", nargs="?", default=DEFAULT)
    a = ap.parse_args(argv)
    if a.cmd == "build-smoke":
        if a.check:
            problems = diff_smoke(a.out)
            print("\n".join(problems) if problems else "fixtures/smoke is up to date")
            return 1 if problems else 0
        write_smoke(a.out)
        print(f"wrote {a.out}")
        return 0
    try:
        suite = load_suite(Path(a.suite))
        problems = check_suite(suite)
    except Exception as e:  # noqa: BLE001 - the CLI reports, it never prints a traceback
        print(f"FAIL: {type(e).__name__}: {e}")
        return 1
    print("\n".join(problems) if problems else f"ok: {len(suite.cases)} cases, digest {suite.digest}")
    return 1 if problems else 0

if __name__ == "__main__":
    sys.exit(main())
