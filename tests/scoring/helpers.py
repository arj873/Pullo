import json
from pathlib import Path

from reviewer.contracts.canonical import comment_fingerprint, comment_id, run_id, idempotency_key_eval
from reviewer.scoring.suite import load_suite

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "fixtures" / "smoke"
SNAP = "snap:sha256:" + "a" * 64
RUN = "run_" + "0" * 16
KINDS = {"smoke-c01": "positive", "smoke-c02": "silence", "smoke-c03": "duplicate",
         "smoke-c04": "repair", "smoke-c05": "verifier-failure", "smoke-c06": "timeout"}


def make_comment(path="src/a.py", start=10, end=12, *, n=0, state="draft", run=RUN):
    claim = f"claim {n} at {path}:{start}"
    fp = comment_fingerprint("bug", path, f"line {start}", claim)
    return {
        "id": comment_id(fp), "runId": run, "findingIds": ["hyp_" + f"{n:016x}"],
        "severity": "P1", "proposedSeverity": "P1", "severityCeiling": "P1",
        "evidenceStrength": "cited", "category": "bug",
        "anchor": {"path": path, "startLine": start, "endLine": end, "snapshotId": SNAP},
        "title": f"Title {n}", "body": claim,
        "evidence": [{"kind": "code", "path": path, "lines": [start, end], "commit": SNAP,
                      "excerpt": f"line {start}", "source": "diff"}],
        "qualityScore": None, "fingerprint": fp, "state": state}


def labels(*bugs, expect="findings", case="c1", reason=None):
    d = {"schema": "case-labels@1", "caseId": case, "expect": expect,
         "bugs": [{"id": f"b{i}", "path": p, "lines": list(l), "category": "bug", "severity": "P1"}
                  for i, (p, l) in enumerate(bugs)]}
    if reason:
        d["expectReason"] = reason
    return d


def smoke_suite():
    return load_suite(SMOKE)


def run_for(case_id, eval_run="evr_" + "1" * 16, repeat=0):
    return run_id(idempotency_key_eval(eval_run, case_id, repeat, SNAP, SNAP), 0)


def read(path):
    return json.loads(Path(path).read_text())
