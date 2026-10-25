"""Shared builders for the S0-03 final policy review (reviewer-owned, offline, stdlib only).

Everything here is payload-consistent: call ids, request hashes and cost ids are recomputed with
the contract's own recipes, so a fixture that is rejected is rejected for the property under test
and not because of a stale hash. Code evidence is minted through the real
`severity.materialize_evidence` + `snapshot.snapshot_resolver` path over a temp snapshot, never
by writing `"resolved": True` by hand.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import canonical as C  # noqa: E402
from reviewer.contracts import severity as S  # noqa: E402
from reviewer.contracts import snapshot as SN  # noqa: E402
from reviewer.contracts import validate  # noqa: E402

EX = ROOT / "reviewer" / "contracts" / "examples"


def ex(name: str) -> dict:
    return json.loads((EX / f"{name}.json").read_text())


# ------------------------------------------------------------------ snapshots and resolution

class Repo:
    """A base and head snapshot of a tiny tree, plus the run's snapshot_resolver."""

    def __init__(self, test, base_files: dict, head_files: dict | None = None):
        self.dirs = {}
        self.manifests = {}
        for label, files in (("base", base_files), ("head", head_files or base_files)):
            td = tempfile.TemporaryDirectory()
            test.addCleanup(td.cleanup)
            root = Path(td.name)
            for rel, data in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(data if isinstance(data, bytes) else data.encode())
            self.dirs[label] = root
            self.manifests[label] = SN.build_manifest(root)
        self.base_id = self.manifests["base"]["snapshotId"]
        self.head_id = self.manifests["head"]["snapshotId"]
        self.resolver = SN.snapshot_resolver(
            {self.base_id: (self.dirs["base"], self.manifests["base"]),
             self.head_id: (self.dirs["head"], self.manifests["head"])})

    def cite(self, path: str, lines: list[int], excerpt: str, side: str = "head") -> dict:
        return {"kind": "code", "path": path, "lines": lines,
                "commit": self.head_id if side == "head" else self.base_id, "excerpt": excerpt}

    def materialize(self, *citations, source="investigator"):
        return S.materialize_evidence(list(citations), {}, source, resolver=self.resolver)


# ------------------------------------------------------------------ trace events

def model_call(run_id, stage, role, agent, ordinal, output, *, status="ok", repair_of=None,
               attempt=0, seq=0, req_role=None, out_schema=None, content=None, hyp=None):
    """A payload-consistent model.call event. `req_role`/`out_schema` let a test make the
    request disagree with the event on purpose.

    s0a-contracts@5 request subject: a verifier request names the hypothesis it checks
    (`request.hypothesisId`, covered by requestHash). `hyp=None` derives it from the honest
    agent label `v-hyp_<16 hex>`; `hyp="hyp_..."` sets it explicitly; `hyp=False` omits it. Only
    verifier requests may carry it (schema invariant `request-subject`), so other roles never do."""
    schema = out_schema or {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput"}[role]
    req = {**ex("TraceEvent.model-call")["request"], "role": req_role or role,
           "outputSchema": schema,
           "messages": [{"role": "user", "content": content or f"{stage} {role} {agent} {ordinal}"}]}
    if hyp is None and role == "verifier" and agent.startswith("v-hyp_"):
        hyp = agent[2:]
    if hyp and (req_role or role) == "verifier":
        req["hypothesisId"] = hyp
    cid = C.call_id(stage, role, agent, ordinal, attempt)
    ev = {"schema": "trace-event@1", "runId": run_id, "seq": seq, "type": "model.call",
          "callId": cid, "stage": stage, "role": role, "agentId": agent, "ordinal": ordinal,
          "attempt": attempt, "requestHash": C.request_hash(req), "request": req,
          "response": {"status": status, "resolvedModel": "synthetic-fixture", "output": output,
                       "rawText": None, "usage": ex("CostRecord.eval-synthetic")["usage"]},
          "costRecordId": C.cost_id(cid), "redactions": {}}
    if repair_of:
        ev["repairOf"] = repair_of
    return ev


def tool_call(run_id, status, evidence, *, agent="v-tool", ordinal=0, tool="pytest", args=None,
              seq=0):
    args = args if args is not None else {"k": 1}
    res = {"status": status, "evidence": evidence, "completeness": "exact", "truncated": None,
           "notice": ""}
    tid = C.tool_call_id("VERIFY", agent, ordinal, tool, args)
    return {"schema": "trace-event@1", "runId": run_id, "seq": seq, "type": "tool.call",
            "toolCallId": tid, "stage": "VERIFY", "agentId": agent, "ordinal": ordinal,
            "tool": tool, "args": args, "resultHash": C.digest(res), "result": res,
            "redactions": {}}


# ------------------------------------------------------------------ a consistent confirmed Finding

class Scenario:
    """A Finding plus the trace that honestly supports it.

    Honest means: the investigator call output lists this very hypothesis; one distinct
    VERIFY/verifier call confirmed it with the same reachable/impact the Finding records and the
    same citations the Finding lists as verification evidence; events are in seq order.
    Tests copy it and break exactly one thing."""

    CODE_KEYS = ("kind", "path", "lines", "commit", "excerpt")

    def __init__(self):
        f = ex("Finding")
        self.run = f["runId"]
        proposer_cite = {k: f["evidence"][0][k] for k in self.CODE_KEYS}
        verifier_cite = {k: f["verification"]["evidence"][0][k] for k in self.CODE_KEYS}
        hypothesis = {"claim": f["claim"], "category": f["category"],
                      "suspectedSeverity": f["suspectedSeverity"], "impact": f["impact"],
                      "location": f["location"], "evidence": [proposer_cite]}
        self.inv = model_call(self.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                              {"hypotheses": [hypothesis]}, seq=1)
        self.confirm = {"verdict": "confirmed", "reachable": f["severityBasis"]["reachable"],
                        "impact": f["severityBasis"]["impact"], "evidence": [verifier_cite],
                        "notes": "confirmed"}
        self.ver = model_call(self.run, "VERIFY", "verifier", "v-" + f["id"], 0, self.confirm,
                              seq=2)
        # The example's verification evidence carries a toolCallId on a code citation; keep the
        # citation pure so the only tool dependency is the one a test adds on purpose.
        f["verification"]["evidence"][0].pop("toolCallId", None)
        f["sourceCallId"] = self.inv["callId"]
        f["verification"]["callIds"] = [self.ver["callId"]]
        self.finding = f

    @property
    def events(self):
        return [self.inv, self.ver]

    def fresh(self):
        return copy.deepcopy(self.finding)

    def verifier(self, **changes):
        """A VERIFY/verifier call with the same identity as the honest one but changed output."""
        return model_call(self.run, "VERIFY", "verifier", "v-" + self.finding["id"], 0,
                          {**self.confirm, **changes}, seq=2)


def issues(entity, doc):
    return [str(i) for i in validate(entity, doc)]
