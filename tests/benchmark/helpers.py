"""Invented benchmark fixtures: tiny roster, made-up gold/review text, real hashes. Nothing here is real benchmark data."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from reviewer.benchmark.jsonio import git_blob_sha, sha256_of
from reviewer.benchmark.loader import load_source

REV = "a" * 40
REPOS = {"alpha": "https://github.com/acme/alpha/pull/", "beta": "https://github.com/acme/beta/pull/",
         "gamma": "https://github.com/ai-code-review-evaluation/gamma-fork/pull/"}
GOLD = {1: [("GOLDTEXT null deref on empty list", "High", "bug"), ("GOLDTEXT slow loop", "Low", "perf"),
            ("GOLDTEXT naming nit", "Low", "style"), ("GOLDTEXT token leak", "High", "security")]}
TOOLS = ("cubic-v1", "cubic-v2", "coderabbit-v1", "greptile-v1")


def urls_ranked():
    """repo -> two URLs in ascending sha256 rank order."""
    out = {}
    for repo, pre in REPOS.items():
        us = [pre + str(n) for n in (1, 2)]
        out[repo] = sorted(us, key=lambda u: hashlib.sha256(u.encode()).hexdigest())
    return out


def make_proposal(universe=None) -> dict:
    uni = universe or urls_ranked()
    item = lambda u: {"url": u, "urlSha256": hashlib.sha256(u.encode()).hexdigest()}
    return {"schema": "benchmark-partition-proposal@1", "sourceRevision": REV,
            "rankedUniverse": {r: [item(u) for u in us] for r, us in uni.items()},
            "preImportDevCandidates": [{"repo": r, **item(us[0])} for r, us in uni.items()],
            "preImportFrozenCandidates": [{"repo": r, **item(us[1])} for r, us in uni.items()]}


def entry(url, n_gold=4, tools=TOOLS, stamp="2025-02-01T10:00:00Z"):
    gold = [{"comment": t, "severity": s, "category": c} for t, s, c in GOLD[1][:n_gold]]
    reviews = [{"tool": t, "repo_name": "acme/x", "pr_url": url,
                "review_comments": [{"path": "a.py", "line": 3, "body": f"BODYTEXT {t} issue", "created_at": stamp}]}
               for t in tools]
    return {"pr_title": "TITLETEXT", "original_url": None, "source_repo": "acme/x", "golden_comments": gold,
            "golden_source_file": "g.json", "az_comment": None, "reviews": reviews}


def make_data(proposal) -> dict:
    return {u["url"]: entry(u["url"]) for us in proposal["rankedUniverse"].values() for u in us}


def make_labels(data, fixture=True) -> dict:
    labels = {u: {"derived": {"num_golden_comments": len(e["golden_comments"])}} for u, e in data.items()}
    if fixture:
        labels["https://example/pr"] = {"derived": {"num_golden_comments": 0}}
    return labels


class Fx(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.store, self.ops = self.tmp / "store", self.tmp / "ops"
        self.store.mkdir()
        self.ops.mkdir()
        self.proposal = make_proposal()
        self.data = make_data(self.proposal)
        self.write_all()

    def write_all(self, *, labels=None, data=None, proposal=None):
        data = self.data if data is None else data
        labels = make_labels(data) if labels is None else labels
        proposal = proposal or self.proposal
        self.dp, self.lp = self.store / "benchmark_data.json", self.store / "pr_labels.json"
        self.dp.write_text(json.dumps(data))
        self.lp.write_text(json.dumps(labels))
        self.pp = self.ops / "proposal.json"
        self.pp.write_text(json.dumps(proposal))
        self.pins_path = self.ops / "pins.json"
        self.pins_path.write_text(json.dumps(self.pins()))

    def pins(self, **over) -> dict:
        files = []
        for name, p in (("benchmark_data.json", self.dp), ("pr_labels.json", self.lp)):
            b = p.read_bytes()
            files.append({"name": name, "sourcePath": f"offline/results/{name}", "bytes": len(b),
                          "gitBlobSha": git_blob_sha(b), "sha256": sha256_of(b)})
        return {"schema": "benchmark-source-pins@1", "repository": "x/y", "revision": REV, "files": files, **over}

    def source(self):
        return load_source(self.pins_path, self.dp, self.lp, self.pp)
