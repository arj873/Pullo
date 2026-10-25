"""python3 -m reviewer.contracts {export [--check] | validate <Entity> <file.json|file.jsonl>}

Files are parsed with loads_strict (duplicate keys, NaN/Infinity and unsafe JSON are errors).
For TraceEvent .jsonl files the whole-file trace rules (seq, single run, ordering) also apply.
Exit codes: 0 ok, 1 invalid document / stale bundle, 2 usage error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from . import (CONTRACTS_VERSION, REGISTRY, ContractInputError, export_bundle, loads_strict,
               validate, validate_trace)

BUNDLE = Path(__file__).with_name("schemas") / "contracts.schema.json"


def _bundle_text() -> str:
    return json.dumps(export_bundle(CONTRACTS_VERSION), indent=2, sort_keys=True) + "\n"


def _validate_file(name: str, path: Path) -> int:
    try:
        raw = path.read_bytes()
    except OSError as e:
        print(f"{path}: cannot read: {e.strerror}")
        return 2
    docs: list = []
    bad = 0
    lines = raw.split(b"\n") if path.suffix == ".jsonl" else [raw]
    for n, line in enumerate(lines, 1):
        if path.suffix == ".jsonl" and not line.strip():
            continue
        try:
            docs.append(loads_strict(line))
        except ContractInputError as e:
            print(f"{path}:{n}: invalid-json: {e}")
            bad += 1
    if bad:
        print(f"{bad} issue(s)")
        return 1
    if name == "TraceEvent" and path.suffix == ".jsonl":
        issues = validate_trace(docs)
    else:
        issues = [i for d in docs for i in validate(name, d)]
    for issue in issues:
        print(f"{path}: {issue}")
    print("ok" if not issues else f"{len(issues)} issue(s)")
    return 1 if issues else 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["export"]:
        text = _bundle_text()
        if "--check" in argv:
            if not BUNDLE.exists() or BUNDLE.read_text() != text:
                print(f"stale: {BUNDLE} (run: python3 -m reviewer.contracts export)")
                return 1
            print("schema bundle up to date")
            return 0
        BUNDLE.write_text(text)
        print(f"wrote {BUNDLE}")
        return 0
    if len(argv) == 3 and argv[0] == "validate":
        if argv[1] not in REGISTRY:
            print(f"unknown entity {argv[1]}; known: {', '.join(sorted(REGISTRY))}")
            return 2
        return _validate_file(argv[1], Path(argv[2]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
