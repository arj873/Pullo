"""Host/root tool: append authoritative generation facts to the durable runtime ledger (append-only, no reset).

    python -m reviewer.runtime.reconcile --ledger LEDGER --evidence FILE            # preview, writes nothing
    python -m reviewer.runtime.reconcile --ledger LEDGER --evidence FILE --apply    # append one `reconcile` row

FILE is a saved reconciliation record `{"generation": <GET /api/v1/generation data>, "keyStatus": {...}}` that the
host fetched; this tool makes NO network call, opens no key file and never reads `.env`. The call is found by
the generation id already recorded in the ledger's result rows; no match -> refuse. Raw router and upstream
facts are kept as reported; the cap then counts them through `accountable_cost` (BYOK upstream spend included, an
inclusive total not double-counted). Key `usage == 0` is never used to release a charge."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import TRIAL_TOTAL_USD_MICROS
from .receipts import RuntimeLedger


def find_call_key(path, generation_id: str) -> str:
    keys = set()
    for line in Path(path).read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("type") == "result" and r.get("generationId") == generation_id:
                keys.add(r["callKey"])
    if len(keys) != 1:
        raise ValueError(f"expected exactly one ledger call with generation id {generation_id!r}, found {len(keys)}")
    return keys.pop()


def main(argv=None, *, out=sys.stdout) -> int:
    ap = argparse.ArgumentParser(prog="reviewer.runtime.reconcile")
    ap.add_argument("--ledger", required=True, help="existing runtime-ledger.jsonl (never created here)")
    ap.add_argument("--evidence", required=True, help="saved generation/key reconciliation JSON")
    ap.add_argument("--apply", action="store_true", help="append the reconcile row (default: preview only)")
    a = ap.parse_args(argv)
    if not Path(a.ledger).is_file():
        ap.error("ledger does not exist; refusing to create a new book")
    ev = json.loads(Path(a.evidence).read_text())
    gen, keys = ev.get("generation"), ev.get("keyStatus")
    ledger = RuntimeLedger(a.ledger, TRIAL_TOTAL_USD_MICROS)
    try:
        ck = find_call_key(a.ledger, gen.get("id") if isinstance(gen, dict) else None)
        res = ledger.reconcile(ck, gen, key_status=keys, apply=a.apply)
    except ValueError as e:
        out.write(json.dumps({"ok": False, "error": str(e)}) + "\n")
        return 1
    out.write(json.dumps({"ok": True, "callKey": ck, "applied": a.apply, **res}, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
