"""python3 -m reviewer.repoimport {fetch,capture-pins,verify,pin-from-case}. JSON on stdout; exit 0 ok, 1 refused, 2 usage.
Heavy runs: prefix with `nice -n 19` (this CLI does not nice itself)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import fields

from .errors import RepoImportError
from .importer import import_repository, target_dir
from .pins import capture_import_pins, load_import_pins, write_import_pins
from .policy import ImportPolicy
from .relates import RelatesSpec, pin_from_case
from .remote import github_remote
from .verify import open_import

DEFAULT_STORE = "~/.local/state/pullo/repos"


def _emit(doc, code=0):
    sys.stdout.write(json.dumps(doc, sort_keys=True, indent=1) + "\n")
    return code


def _parser():
    ap = argparse.ArgumentParser(prog="python3 -m reviewer.repoimport")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("fetch", "capture-pins", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True, help="https://github.com/<owner>/<repo>")
        p.add_argument("--commit", required=True, help="exact 40-hex commit")
        p.add_argument("--store", default=DEFAULT_STORE)
        if name == "fetch":
            p.add_argument("--case-dir")
            p.add_argument("--side", choices=("base", "head"))
            p.add_argument("--partial-snapshot-id")
            for f in fields(ImportPolicy):
                p.add_argument("--" + f.name.replace("_", "-"), type=int, dest="p_" + f.name)
        elif name == "capture-pins":
            p.add_argument("--out", required=True)
            p.add_argument("--captured-at", required=True, help="YYYY-MM-DDTHH:MM:SSZ (trusted time only)")
        else:
            p.add_argument("--pins", required=True)
    p = sub.add_parser("pin-from-case")
    p.add_argument("--case-dir", required=True)
    return ap


def main(argv=None, *, _remote=None) -> int:
    try:
        a = _parser().parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        if a.cmd == "pin-from-case":
            return _emit(pin_from_case(a.case_dir))
        remote = _remote or github_remote(a.repo)
        store = os.path.expanduser(a.store)
        d = target_dir(store, remote, a.commit)
        if a.cmd == "fetch":
            kw = {f.name: v for f in fields(ImportPolicy) if (v := getattr(a, "p_" + f.name)) is not None}
            relates = None
            if a.case_dir or a.side:
                if not (a.case_dir and a.side):
                    raise RepoImportError("bad-input", "--case-dir and --side go together")
                relates = RelatesSpec(a.case_dir, a.side, a.partial_snapshot_id)
            imp = import_repository(remote, a.commit, store, policy=ImportPolicy(**kw), relates=relates)
            return _emit({"status": "imported", "dir": str(imp.dir), "snapshotId": imp.snapshot_id,
                          "coverage": imp.coverage, "counts": imp.record["counts"],
                          "relatesTo": imp.record.get("relatesTo")})
        if a.cmd == "capture-pins":
            pins = capture_import_pins(d, captured_at=a.captured_at)
            write_import_pins(a.out, pins)
            return _emit({"status": "pins-written", "out": a.out, "snapshotId": pins["snapshotId"]})
        imp = open_import(d, pins=load_import_pins(a.pins, import_dir=d))
        return _emit({"status": "verified", "dir": str(imp.dir), "snapshotId": imp.snapshot_id,
                      "coverage": imp.coverage, "counts": imp.record["counts"]})
    except RepoImportError as e:
        return _emit({"status": "refused", "code": e.code, "detail": e.detail}, 1)
