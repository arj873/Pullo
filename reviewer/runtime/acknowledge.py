"""Host/root tool: acknowledge ONE unresolvable scoring call for the scoring startup hold (append-only, no reset).

    python -m reviewer.runtime.acknowledge --ledger LEDGER --evidence FILE            # preview, writes nothing
    python -m reviewer.runtime.acknowledge --ledger LEDGER --evidence FILE --apply    # append one `acknowledge` row

FILE is a saved host record `{"generationId": "...", "callKey": "..." (optional cross-check), "evidence": {
"reasonCode": "generation-not-found", "keyRemainingBeforeMicros": int, "keyRemainingAfterMicros": int,
"sumOtherOfficialMicros": int, "note": "..." (optional)}}`. This tool makes NO network call, opens no key file and
never reads `.env`. The call is found by the generation id already recorded in the ledger's result rows; no match
-> refuse. The acknowledged call's worst-case charge STAYS counted in every total and cap: an acknowledgement only
lets a new scoring process start past that one call. Key `usage == 0` is never used to release a charge."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import TRIAL_TOTAL_USD_MICROS
from .receipts import RuntimeLedger
from .reconcile import find_call_key


def main(argv=None, *, out=sys.stdout) -> int:
    ap = argparse.ArgumentParser(prog="reviewer.runtime.acknowledge")
    ap.add_argument("--ledger", required=True, help="existing runtime-ledger.jsonl (never created here)")
    ap.add_argument("--evidence", required=True, help="saved host acknowledgement evidence JSON")
    ap.add_argument("--apply", action="store_true", help="append the acknowledge row (default: preview only)")
    a = ap.parse_args(argv)
    if not Path(a.ledger).is_file():
        ap.error("ledger does not exist; refusing to create a new book")
    ledger = RuntimeLedger(a.ledger, TRIAL_TOTAL_USD_MICROS)
    try:
        doc = json.loads(Path(a.evidence).read_text())
        if not isinstance(doc, dict) or set(doc) - {"generationId", "callKey", "evidence"}:
            raise ValueError("evidence file must be an object with generationId, evidence and optional callKey")
        gid = doc.get("generationId")
        if not isinstance(gid, str) or not gid:
            raise ValueError("evidence file has no generationId")
        ck = find_call_key(a.ledger, gid)
        if "callKey" in doc and doc["callKey"] != ck:
            raise ValueError("evidence callKey does not match the ledger call with that generation id")
        res = ledger.acknowledge(ck, gid, evidence=doc.get("evidence"), apply=a.apply)
    except (ValueError, OSError) as e:
        out.write(json.dumps({"ok": False, "error": str(e)}) + "\n")
        return 1
    out.write(json.dumps({"ok": True, "callKey": ck, "generationId": gid, "applied": res["appended"], **res},
                         indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
