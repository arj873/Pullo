"""CLI: python3 -m reviewer.corpus {import,context,check} ... (public anonymous GET only)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import safeio
from .http import ALLOWED_REPOS, Client, FetchError, Limits
from .importer import INITIAL_CASES, fetch_context, import_case, load_manifest, refresh_context
from .inputs import InputError, load_reviewer_input
from .refresh import refresh_all
from .redact import REDACTION_VERSION, patterns_digest, redact_log


def log(msg: str) -> None:
    print(redact_log(msg), file=sys.stderr)


def _limits(a) -> Limits:
    d = Limits()
    return Limits(**{k: getattr(a, k, None) or getattr(d, k) for k in
                     ("timeout", "max_files", "max_requests", "file_bytes", "case_bytes", "max_context_files")}
                  | {"api_bytes": d.api_bytes, "request_deadline": d.request_deadline,
                     "max_pages": d.max_pages, "max_total_bytes": d.max_total_bytes})


def _common(p):
    p.add_argument("--timeout", type=float, help="seconds per socket operation (default 20)")
    p.add_argument("--max-files", type=int, dest="max_files")
    p.add_argument("--max-requests", type=int, dest="max_requests")
    p.add_argument("--file-bytes", type=int, dest="file_bytes")
    p.add_argument("--case-bytes", type=int, dest="case_bytes")
    p.add_argument("--max-context-files", type=int, dest="max_context_files")


def _check(out: Path) -> int:
    """Validate every case (a bad one never hides later ones) and the index against the cases."""
    bad, seen = 0, {}
    for d in sorted(out.iterdir()):
        if not d.is_dir() and not d.is_symlink() or d.name.startswith("."):
            continue
        try:
            r = load_reviewer_input(d)
            seen[d.name] = r["case"]
            print(f"ok   {d.name}: complete={r['case']['coverage']['complete']} "
                  f"redaction={r['case']['redaction']['version']}")
        except Exception as e:  # noqa: BLE001 - every failure is reported, none aborts the run
            bad += 1
            print(f"FAIL {d.name}: {redact_log(f'{type(e).__name__}: {e}')}")
    idx = out / "index.json"
    if idx.is_file() and not idx.is_symlink():
        try:
            for e in json.loads(idx.read_text())["cases"]:
                c = seen.get(e["id"])
                if e.get("input") and c is not None and (
                        e.get("redactionVersion") != c["redaction"]["version"]
                        or e.get("redactionPatternsSha256") != c["redaction"]["patternsSha256"]
                        or e.get("fullRepositoryCoverage") is not False
                        or e.get("scope") != c["coverage"]["scope"]):
                    bad += 1
                    print(f"FAIL index.json: entry {e['id']} disagrees with its case (stale scope/redaction version)")
        except Exception as e:  # noqa: BLE001
            bad += 1
            print(f"FAIL index.json: {redact_log(f'{type(e).__name__}: {e}')}")
    print(f"checked {len(seen) + bad} entries, {bad} failed")
    return 3 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m reviewer.corpus", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("import", help="import PR cases from the pilot manifest")
    pi.add_argument("--manifest", default="orchestration/corpus/pilot-manifest.json")
    pi.add_argument("--out", default="fixtures/historical")
    g = pi.add_mutually_exclusive_group()
    g.add_argument("--initial", action="store_true", help="the three initial cases")
    g.add_argument("--all", action="store_true", help="every manifest case")
    g.add_argument("--case", action="append", help="case id (repeatable)")
    pi.add_argument("--replace", action="store_true", help="overwrite a case whose imported result differs")
    pi.add_argument("--context-from", help="another corpus root (read only): re-fetch its recorded context paths "
                                           "into each imported case under the current redaction")
    pi.add_argument("--refresh-context", action="store_true",
                    help="rebuild each imported case's own context from its recorded paths")
    _common(pi)
    pc = sub.add_parser("context", help="fetch pinned context files for an imported case")
    pc.add_argument("--case-dir", required=True)
    pc.add_argument("--side", choices=("base", "head"), default="head")
    pc.add_argument("--path", action="append")
    pc.add_argument("--refresh", action="store_true",
                    help="rebuild the recorded context under the current redaction (no --path)")
    pc.add_argument("--from", dest="from_dir", help="with --refresh: take paths from this other case dir (read only)")
    _common(pc)
    pr = sub.add_parser("refresh-redaction", help="offline: re-stamp cases to the current redaction when the "
                        "current redaction provably changes none of their text (no fetch); otherwise re-import")
    pr.add_argument("--out", default="fixtures/historical")
    pr.add_argument("--dry-run", action="store_true", help="prove equivalence and report; write nothing")
    pk = sub.add_parser("check", help="validate reviewer inputs under an output directory")
    pk.add_argument("--out", default="fixtures/historical")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "check":
            return _check(Path(a.out))
        if a.cmd == "refresh-redaction":
            res = refresh_all(a.out, apply=not a.dry_run, log=lambda m: print(redact_log(m)))
            bad = sum(v.startswith("refused") for v in res.values())
            print(f"{len(res)} cases, {bad} refused")
            return 3 if bad else 0
        client = Client(limits=_limits(a), log=log)
        if a.cmd == "context":
            if a.refresh == bool(a.path):
                print("give either --path (fetch) or --refresh", file=sys.stderr)
                return 2
            if a.refresh:
                refresh_context(client, a.case_dir, client.limits, log, from_dir=a.from_dir)
            else:
                fetch_context(client, a.case_dir, a.side, a.path, client.limits, log)
            return 0
        cases = load_manifest(a.manifest)
        ids = {c["id"] for c in cases}
        want = list(INITIAL_CASES) if a.initial or not (a.all or a.case) else [c["id"] for c in cases] if a.all else a.case
        unknown = [w for w in want if w not in ids]
        if unknown:
            print(f"unknown case ids: {unknown}", file=sys.stderr)
            return 2
        results = []
        for w in want:
            r = import_case(client, next(c for c in cases if c["id"] == w), a.out, client.limits,
                            replace=a.replace, log=log)
            if r["input"] and r["write"] != "changed-not-written" and (a.context_from or a.refresh_context):
                src = Path(a.context_from) / w if a.context_from else None
                try:
                    refresh_context(client, Path(a.out) / w, client.limits, log, from_dir=src)
                except (FetchError, safeio.PathError, OSError) as e:
                    r["contextError"] = redact_log(str(e))
            results.append(r)
        idx_path = Path(a.out) / "index.json"
        old = {r["id"]: r for r in json.loads(idx_path.read_text())["cases"]} if idx_path.is_file() else {}
        old.update({r["id"]: r for r in results})
        safeio.write_json(a.out, "index.json", {"schema": "historical-index@1", "allowedRepos": list(ALLOWED_REPOS),
                                                "note": "orchestration only; not reviewer input. Each entry's scope is the "
                                                "whole claim: changed files and selected context, never a full repository.",
                                                "redactionVersionNow": REDACTION_VERSION,
                                                "redactionPatternsSha256Now": patterns_digest(),
                                                "cases": [old[k] for k in sorted(old)]}, replace=True)
        print(json.dumps(results, indent=2))
        return 3 if any(r["status"] in ("rejected", "failed") or r["write"] == "changed-not-written"
                        or "contextError" in r for r in results) else 0
    except (FetchError, safeio.PathError, InputError, ValueError, OSError) as e:
        print(f"error: {redact_log(str(e))}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
