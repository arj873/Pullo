"""Test rig for the pipeline: custom mini cases, scripted provider responses, a provider spy and a host rig.

Everything runs against the REAL contracts, gateway (synthetic provider), tools and snapshot code. The rig plays the
role of the evaluation host: it alone holds scripts, labels, the authorization and the spend book.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.canonical import hypothesis_id, tool_call_id
from reviewer.contracts.snapshot import build_manifest
from reviewer.gateway import (DisabledProvider, SpendBook, SyntheticProvider, bytes_digest, events_to_bytes, load_trace,
                              parse_script, trusted_authorization)
from reviewer.pipeline import (EvalIdentity, HostConfig, Hooks, RecordBackend, ReplayBackend, ReviewSpec,
                               SnapshotInput, engine_identity, run_review)
from reviewer.tools import Limits, normalize

ROOT = Path(__file__).resolve().parents[2]
EX = ROOT / "reviewer/contracts/examples"
SMOKE = ROOT / "fixtures/smoke"
PROFILE = json.loads((EX / "ModelProfile.smoke-synthetic.json").read_text())
PLAN = json.loads((EX / "Plan.json").read_text())
AUTH = (EX / "SpendAuthorization.synthetic-recording.json").read_text()
NOW = "2026-10-25T12:00:00Z"
ZERO = {k: None for k in ("uncachedInputTokens", "cachedInputTokens", "cacheWriteInputTokens", "outputTokens",
                          "reasoningTokens")}
EVR1, EVR2 = "evr_" + "1" * 16, "evr_" + "2" * 16

# ---- a retrieval profile/plan: the same synthetic roles, but investigator and verifier return the Turn envelope
TURN_PROFILE = copy.deepcopy(PROFILE)
TURN_PROFILE["id"] = "smoke-synthetic-retrieval"
TURN_PROFILE["roles"]["investigator"].update(outputSchema="InvestigatorTurn", promptVersion="investigator.retrieve@v2")
TURN_PROFILE["roles"]["verifier"].update(outputSchema="VerifierTurn", promptVersion="verifier.refute@v3")
TURN_PLAN = copy.deepcopy(PLAN)
TURN_PLAN["modelProfile"] = f"{TURN_PROFILE['id']}@{TURN_PROFILE['version']}"
TURN_PLAN["budget"].update(maxToolCalls=160, maxToolCallsPerAgent=60)


class Crash(BaseException):
    """Simulated process death (not an Exception, so the engine cannot 'handle' it)."""


class SpyProvider:
    """The only object that sees scripted responses. Records every request it is handed."""
    name = "synthetic"

    def __init__(self, script):
        self.inner = SyntheticProvider(script)
        self.requests: list = []

    @property
    def calls(self):
        return self.inner.calls

    def call(self, request, key):
        self.requests.append(copy.deepcopy(request))
        return self.inner.call(request, key)


def write_tree(root: Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


class Mini:
    """A synthetic case: two snapshots on disk, their manifests and the CaseInput document."""

    def __init__(self, tmp: Path, cid: str, base: dict, head: dict, *, title="Change", body="Body", repo="fixture-mini"):
        self.id, self.base_files, self.head_files = cid, base, head
        self.root = tmp / "cases" / cid
        write_tree(self.root / "base", base)
        write_tree(self.root / "head", head)
        self.base_manifest = build_manifest(self.root / "base")
        self.head_manifest = build_manifest(self.root / "head")
        self.base_id, self.head_id = self.base_manifest["snapshotId"], self.head_manifest["snapshotId"]
        self.case = {"schema": "case-input@1", "id": cid, "repo": repo, "synthetic": True,
                     "base": {"root": f"cases/{cid}/base", "snapshotId": self.base_id},
                     "head": {"root": f"cases/{cid}/head", "snapshotId": self.head_id},
                     "pr": {"title": title, "body": body}}

    @property
    def base(self):
        return SnapshotInput(self.root / "base", self.base_manifest)

    @property
    def head(self):
        return SnapshotInput(self.root / "head", self.head_manifest)

    def lines(self, path, a, b=None, side="head"):
        text = (self.head_files if side == "head" else self.base_files)[path]
        return "\n".join(text.split("\n")[a - 1:(b or a)])

    def cite(self, path, a, b=None, *, commit=None, excerpt=None):
        b = b or a
        return {"kind": "code", "path": path, "lines": [a, b], "commit": commit or self.head_id,
                "excerpt": self.lines(path, a, b) if excerpt is None else excerpt}


def hyp(mini, path, line, *, end=None, claim="Something is wrong here", category="bug", severity="P1",
        impact="incorrect-result", mechanism="It breaks.", evidence=None, **extra):
    h = {"claim": claim, "category": category, "suspectedSeverity": severity, "impact": impact,
         "location": {"path": path, "line": line, **({"endLine": end} if end else {})},
         "mechanism": mechanism, "evidence": evidence if evidence is not None else [mini.cite(path, line, end)]}
    h.update(extra)
    return h


def resp(output, status="ok", raw=None):
    return {"status": status, "resolvedModel": "synthetic-fixture", "output": output if status == "ok" else None,
            "rawText": raw, "usage": dict(ZERO)}


def entry(stage, role, agent, ordinal, attempt=0, **kw):
    return {"stage": stage, "role": role, "agentId": agent, "ordinal": ordinal, "attempt": attempt, **kw}


def inv(*hyps, attempt=0):
    return entry("INVESTIGATE", "investigator", "generalist", 0, attempt, response=resp({"hypotheses": list(hyps)}))


def ver(n, mini=None, *, verdict="confirmed", reachable=True, impact="incorrect-result", evidence=None, notes="checked",
        attempt=0, path=None, line=1):
    if evidence is None and verdict == "confirmed":
        evidence = [mini.cite(path, line)]
    return entry("VERIFY", "verifier", "verifier", n, attempt, response=resp(
        {"verdict": verdict, "reachable": reachable, "impact": impact, "evidence": evidence or [], "notes": notes}))


def treq(tool, purpose="needed to decide the claim", **args):
    return {"tool": tool, "args": args, "purpose": purpose}


def iturn(ordinal, requests=None, output=None, attempt=0):
    """An investigator Turn envelope: requests context, or (output) the final role payload."""
    return entry("INVESTIGATE", "investigator", "generalist", ordinal, attempt,
                 response=resp({"contextRequests": requests or [], "output": output}))


def ifinal(ordinal, *hyps, attempt=0):
    return iturn(ordinal, output={"hypotheses": list(hyps)}, attempt=attempt)


def vturn(ordinal, requests=None, output=None, attempt=0):
    return entry("VERIFY", "verifier", "verifier", ordinal, attempt,
                 response=resp({"contextRequests": requests or [], "output": output}))


def vfinal(ordinal, mini=None, *, verdict="confirmed", reachable=True, impact="incorrect-result", evidence=None,
           notes="checked", path=None, line=1, attempt=0):
    if evidence is None and verdict == "confirmed":
        evidence = [mini.cite(path, line)]
    return vturn(ordinal, output={"verdict": verdict, "reachable": reachable, "impact": impact,
                                  "evidence": evidence or [], "notes": notes}, attempt=attempt)


def tcid(stage, agent, ordinal, tool, **args):
    """The content id the host gives a tool call (so a scripted model can cite a result it will be shown)."""
    return tool_call_id(stage, agent, ordinal, tool, normalize(tool, args, Limits()))


def judge(*comments, attempt=0):
    return entry("JUDGE", "judge", "judge", 0, attempt, response=resp({"comments": list(comments)}))


def terr(code, stage, retryable=True, message="scripted failure"):
    return {"code": code, "message": message, "retryable": retryable, "stage": stage}


def script(*entries):
    return parse_script(json.dumps({"schemaVersion": 1, "entries": list(entries)}))


def hid(n, h):
    return hypothesis_id("generalist", n, h["claim"], h["location"]["path"], h["location"]["line"])


# a simple two-file repo with a few distinct buggy lines
BASE = {"src/a.py": "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(12)),
        "src/b.py": "def g(x):\n    return x\n"}
HEAD = {"src/a.py": "".join(f"def f{i}(x):\n    return x - {i}\n\n" for i in range(12)),
        "src/b.py": "def g(x):\n    return x * 2\n"}


class Rig(unittest.TestCase):
    """Per-test host: temp dirs, operator authorization, ONE shared spend book, output root."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        (self.tmp / "operator").mkdir()
        (self.tmp / "operator/auth.json").write_text(AUTH)
        self.suite_root = self.tmp / "suite"
        self.suite_root.mkdir()
        self.handle = trusted_authorization(self.tmp / "operator/auth.json", forbidden_roots=[self.tmp / "cases"])
        self.book = SpendBook(self.handle)
        self.out = self.tmp / "out"
        self.out.mkdir()
        self.clock_value = [0.0]
        self.spies: list = []

    def mini(self, cid="mini-1", base=None, head=None, **kw):
        return Mini(self.tmp, cid, base or BASE, head or HEAD, **kw)

    def clock(self):
        return self.clock_value[0]

    def host(self, cid, *, eval_id=EVR1, **kw):
        d = dict(out_root=self.out, eval=EvalIdentity(eval_id, cid, 0), config_identity={"test": "cfg"},
                 forbidden_roots=(self.tmp / "cases",), clock=self.clock)
        d.update(kw)
        return HostConfig(**d)

    def record_backend(self, scr):
        spy = SpyProvider(scr)
        self.spies.append(spy)
        providers = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai"), "synthetic": spy}
        return RecordBackend(self.handle, self.book, providers, lambda: NOW), spy

    def spec(self, mini, backend, *, profile=None, plan=None, imports=None, **hostkw):
        return ReviewSpec(case=mini.case, base=mini.base, head=mini.head, profile=profile or PROFILE,
                          plan=plan or PLAN, host=self.host(mini.id, **hostkw), backend=backend, imports=imports)

    def record(self, mini, scr, *, profile=None, plan=None, imports=None, **hostkw):
        backend, spy = self.record_backend(scr)
        res = run_review(self.spec(mini, backend, profile=profile, plan=plan, imports=imports, **hostkw))
        return res, spy

    def record_turn(self, mini, scr, **kw):
        """A retrieval-profile record (Turn schemas, plan with the retrieval tool budget)."""
        kw.setdefault("profile", TURN_PROFILE)
        kw.setdefault("plan", TURN_PLAN)
        return self.record(mini, scr, **kw)

    def replay_backend(self, res, *, digest=None, trace_path=None):
        return ReplayBackend(trace_path or res.trace_path, digest or res.receipt["traceDigest"], "test-pin")

    def replay(self, mini, res, *, eval_id=EVR2, out=None, profile=None, plan=None, digest=None, trace_path=None,
               imports=None, **hostkw):
        if out is not None:
            hostkw["out_root"] = out
        backend = self.replay_backend(res, digest=digest, trace_path=trace_path)
        return run_review(self.spec(mini, backend, profile=profile, plan=plan, eval_id=eval_id, imports=imports,
                                    **hostkw))

    # ---- trace surgery
    def edited_copy(self, res, name, fn):
        """Copy the recording's events through fn(events) -> events, write them to a new file; return (path, digest)."""
        events = copy.deepcopy(load_trace(res.trace_path).events)
        events = fn(events) or events
        data = events_to_bytes(events)
        p = self.tmp / name
        p.write_bytes(data)
        return str(p), bytes_digest(data)


def events_of(res):
    return load_trace(res.trace_path).events


def model_calls(res, stage=None):
    return [e for e in events_of(res) if e["type"] == "model.call" and (stage is None or e["stage"] == stage)]


def tool_calls(res, stage=None):
    return [e for e in events_of(res) if e["type"] == "tool.call" and (stage is None or e["stage"] == stage)]


def all_bytes(run_dir) -> bytes:
    out = b""
    for p in sorted(Path(run_dir).rglob("*")):
        if p.is_file():
            out += p.read_bytes()
    return out
