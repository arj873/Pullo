"""Root-callable CLI. Reads pinned scorer data, writes JSON reports with O_EXCL outside reviewer roots."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .boundary import assert_report_location
from .cutoff import select_cases
from .errors import BenchmarkError
from .jsonio import load_json, write_new
from .loader import load_proposal, load_source
from .pins import load_pins, pin_for, verify_file
from .projection import project_metadata, resolve_versions
from .reference_graph import score_reference_suite
from .scoring import score_suite

REPO = Path(__file__).resolve().parents[2]
REVIEWER_ROOTS = [REPO / "reviewer", REPO / "fixtures", REPO / "tests"]


def _emit(args, doc: dict, stores) -> int:
    if args.out:
        assert_report_location(args.out, REVIEWER_ROOTS, stores)
        doc["reportSha256"] = write_new(args.out, doc)
    print(json.dumps(doc, indent=1, sort_keys=True))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="reviewer.benchmark")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("verify-pins", "inspect", "project", "select", "score"):
        p = sub.add_parser(name)
        for a in ("pins", "data", "labels", "proposal", "projection", "proofs", "rules", "judgments", "out"):
            p.add_argument(f"--{a}")
        p.add_argument("--expect-revision")
        p.add_argument("--tools", nargs="*", default=[])
    rp = sub.add_parser("reference-score")
    for a in ("pins", "data", "labels", "proposal", "judgments", "out"):
        rp.add_argument(f"--{a}")
    rp.add_argument("--expect-revision")
    rp.add_argument("--tools", nargs="*", default=[])
    rp.add_argument("--cases", nargs="*", default=None)
    args = ap.parse_args(argv)
    try:
        return _run(args)
    except BenchmarkError as e:
        print(json.dumps({"status": "refused", "code": e.code, "message": e.message}), file=sys.stderr)
        return 1 if e.code not in ("io", "boundary", "args") else 2


def _need(args, *names):
    for n in names:
        if not getattr(args, n):
            raise BenchmarkError("args", f"--{n} is required for {args.cmd}")


def _run(args) -> int:
    if args.cmd == "select":
        _need(args, "projection", "proposal", "proofs")
        sel = select_cases(load_proposal(args.proposal), load_json(args.projection, "projection"),
                           load_json(args.proofs, "proofs"))
        return _emit(args, sel, [])
    _need(args, "pins", "data", "labels")
    stores = [Path(args.data).absolute().parent.resolve(), Path(args.labels).absolute().parent.resolve()]
    if args.cmd == "verify-pins":
        pins = load_pins(args.pins, expect_revision=args.expect_revision, store_dirs=stores)
        for name, path in (("benchmark_data.json", args.data), ("pr_labels.json", args.labels)):
            verify_file(path, pin_for(pins, name))
        return _emit(args, {"status": "verified", "revision": pins["revision"]}, stores)
    _need(args, "proposal")
    src = load_source(args.pins, args.data, args.labels, args.proposal, expect_revision=args.expect_revision)
    if args.cmd == "inspect":
        return _emit(args, src.report(), stores)
    if args.cmd == "project":
        proj = project_metadata(src)
        proj["versions"] = resolve_versions(proj, load_json(args.rules, "rules") if args.rules else None)
        return _emit(args, proj, stores)
    _need(args, "judgments", "tools")
    docs = load_json(args.judgments, "judgments")
    if args.cmd == "reference-score":
        docs = docs if isinstance(docs, list) else [docs]
        return _emit(args, score_reference_suite(src.cases, docs, tools=args.tools, urls=args.cases, source=src), stores)
    rep = score_suite(src.cases, docs if isinstance(docs, list) else [docs], tools=args.tools)
    return _emit(args, rep, stores)


if __name__ == "__main__":
    raise SystemExit(main())
