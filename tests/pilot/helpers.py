"""Rig for the pilot launcher: a synthetic corpus case with canary labels/source, trusted pins, an operator
authorization, existing durable state files, and a FAKE OpenRouter transport. No real key, network or .env."""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.canonical import hypothesis_id
from reviewer.historical import capture_bridge_pins, discard, load_pins, materialize, write_pins
from reviewer.pilot import main
from reviewer.runtime import Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.tools.helpers import make_case

AT = "2026-10-25T20:00:00Z"
FAKE_KEY = "sk-or-v1-" + "f4k3" * 12
SONNET = "anthropic/claude-sonnet-5.5"
LABEL_CANARIES = ("OUTCOME_SECRET", "LABELS_SECRET", "LABELS_DEEP")
BASE = {"src/a.py": "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(6)),
        "src/b.py": "def g(x):\n    return x\n"}
HEAD = {"src/a.py": "".join(f"def f{i}(x):\n    return x - {i}\n\n" for i in range(6)),
        "src/b.py": "def g(x):\n    return x * 2\n"}
CTX = {"head": {"src/util.py": "def helper():\n    return 1\n"}, "base": {"src/other.py": "VALUE = 1\n"}}
AUTH = {"schema": "spend-authorization@1", "id": "pilot-test", "issuedBy": "operator",
        "expiresAt": "2099-01-01T00:00:00Z", "purpose": "offline pilot test, fake transport",
        "providers": ["anthropic"], "models": [SONNET], "maxUsdMicrosPerRun": 4_000_000,
        "maxUsdMicrosTotal": 50_000_000}


def fake_key_loader(path, *, forbidden_roots=()):
    return Secret(FAKE_KEY)


def boom_key_loader(path, *, forbidden_roots=()):
    raise AssertionError("the key loader must not be called")


class Model:
    """A fake OpenRouter: answers by role (the response_format schema name) like a well-behaved reviewer."""

    def __init__(self, head_id, *, fail_with=None, byok=True):
        self.head_id, self.fail_with, self.byok = head_id, fail_with, byok
        self.requests, self.roles = [], []
        self.claim = "a.py f0 now subtracts"

    def cite(self):
        return {"kind": "code", "path": "src/a.py", "lines": [2, 2], "commit": self.head_id,
                "excerpt": "    return x - 0"}

    def hypothesis(self):
        return {"claim": self.claim, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
                "location": {"path": "src/a.py", "line": 2}, "mechanism": "The sign flipped.",
                "evidence": [self.cite()]}

    def content(self, role):
        if role == "InvestigatorOutput":
            return {"hypotheses": [self.hypothesis()]}
        if role == "VerifierOutput":
            return {"verdict": "confirmed", "reachable": True, "impact": "incorrect-result",
                    "evidence": [self.cite()], "notes": "checked"}
        hid = hypothesis_id("generalist", 0, self.claim, "src/a.py", 2)
        return {"comments": [{"findingIds": [hid], "title": "Sign flip", "body": "f0 returns x - 0."}]}

    def __call__(self, http_req):
        self.requests.append(http_req)
        if self.fail_with is not None:
            return self.fail_with
        body = json.loads(http_req.body)
        role = body["response_format"]["json_schema"]["name"]
        self.roles.append(role)
        u = {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200, "cost": 0,
             "is_byok": self.byok, "cost_details": {"upstream_inference_cost": 0.0042},
             "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
             "completion_tokens_details": {"reasoning_tokens": 0}}
        d = {"id": f"gen-{len(self.requests)}", "model": body["model"], "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": json.dumps(self.content(role))}}], "usage": u}
        return HttpResponse(200, {}, json.dumps(d).encode())


class Rig(unittest.TestCase):
    cases = ("o--r--1",)

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._rm)
        self.tmp = Path(os.path.realpath(self._t.name))
        self.corpus = self.tmp / "corpus"
        self.corpus.mkdir()
        for name in self.cases:
            make_case(self.corpus, BASE, HEAD, context=CTX, name=name)
        self.operator = self.tmp / "operator"
        self.pins = self.operator / "pins"
        self.state = self.operator / "state"
        self.pins.mkdir(parents=True)
        self.state.mkdir()
        for name in self.cases:
            write_pins(self.pins / f"{name}.json", capture_bridge_pins(self.corpus / name, captured_at=AT))
        self.auth = self.operator / "auth.json"
        self.auth.write_text(json.dumps(AUTH))
        for n in ("spend-book.jsonl", "runtime-ledger.jsonl"):
            (self.state / n).touch(mode=0o600)
        self.env = self.operator / "dot.env"
        self.env.write_text("openrouter_key=not-read-in-tests\n")
        self.out = self.tmp / "out"
        self.head_id = self._head_id(self.cases[0])

    def _rm(self):
        for dirpath, dirnames, _ in os.walk(self.tmp):
            for d in [dirpath, *[os.path.join(dirpath, x) for x in dirnames]]:
                try:
                    os.chmod(d, 0o700)
                except OSError:
                    pass
        self._t.cleanup()

    def _head_id(self, name):
        cd = self.corpus / name
        out = self.tmp / f"ids-{name}"
        b = materialize(cd, pins=load_pins(self.pins / f"{name}.json", case_dir=cd), out_dir=out,
                        forbidden_roots=(self.corpus,))
        hid = b.record["unions"]["head"]["snapshotId"]
        discard(out)
        return hid

    def argv(self, *extra, cases=None, live=True, auth=True, state=True):
        a = ["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--out", str(self.out)]
        for c in cases or self.cases:
            a += ["--case", c]
        if auth:
            a += ["--auth", str(self.auth)]
        if live:
            a += ["--live", "--env", str(self.env)]
            if state:
                a += ["--state-dir", str(self.state)]
        return a + list(extra)

    def run_main(self, argv, *, transport=None, key_loader=fake_key_loader):
        out, err = io.StringIO(), io.StringIO()
        code = main(argv, transport=transport, key_loader=key_loader, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def run_json(self, argv, **kw):
        code, out, err = self.run_main([*argv, "--json"], **kw)
        return code, (json.loads(out) if out.strip() else None), err

    def ledger_rows(self):
        return [json.loads(x) for x in (self.state / "runtime-ledger.jsonl").read_text().splitlines()]

    def model(self, **kw):
        return Model(self.head_id, **kw)


def tree_listing(root: Path):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")) if root.exists() else None
