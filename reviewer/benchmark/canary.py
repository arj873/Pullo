"""Label canary: a random scorer-side sentinel plus gold text must be absent from everything a reviewer can see."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Sentinel:
    token: str
    gold_texts: tuple = ()

    @staticmethod
    def new(*gold_texts: str) -> "Sentinel":
        return Sentinel("CANARY-" + secrets.token_hex(16), tuple(t for t in gold_texts if t))

    def needles(self) -> dict:
        """label -> bytes. Labels never contain the needle itself, so a finding is safe to print."""
        out = {"sentinel": self.token.encode()}
        for i, t in enumerate(self.gold_texts):
            out[f"gold{i}"] = t.encode("utf-8")
            out[f"gold{i}-json"] = json.dumps(t, ensure_ascii=True)[1:-1].encode()
        return out

    def scan_bytes(self, data: bytes, where: str) -> list[dict]:
        return [{"where": where, "needle": label} for label, n in self.needles().items() if n and n in data]

    def scan_requests(self, requests) -> list[dict]:
        found = []
        for i, r in enumerate(requests):
            found += self.scan_bytes(json.dumps(r, sort_keys=True, default=str, ensure_ascii=False).encode()
                                     + json.dumps(r, sort_keys=True, default=str).encode(), f"request[{i}]")
        return found

    def scan_events(self, events, types=("tool.call",)) -> list[dict]:
        found = []
        for i, e in enumerate(events):
            if e.get("type") in types:
                found += self.scan_bytes(json.dumps(e, sort_keys=True, default=str, ensure_ascii=False).encode(),
                                         f"event[{i}]:{e.get('type')}")
        return found

    def scan_tree(self, root) -> list[dict]:
        found = []
        for p in sorted(Path(root).rglob("*")):
            rel = str(p.relative_to(root))
            found += self.scan_bytes(rel.encode(), f"path:{rel[:80]}")
            if p.is_file() and not p.is_symlink():
                found += self.scan_bytes(p.read_bytes(), f"file:{rel[:80]}")
        return found
