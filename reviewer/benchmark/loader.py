"""Strict read-only loader: verifies the pinned files, the roster against the declared proposal, and builds ScorerCases."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .errors import BenchmarkError
from .jsonio import load_json, parse_json
from .model import LABEL_FIXTURE_URL, ScorerCase, build_case
from .pins import load_pins, pin_for, verify_file

PROPOSAL_SCHEMA = "benchmark-partition-proposal@1"


@dataclass(frozen=True)
class Proposal:
    revision: str
    universe: dict          # repo -> [url] in rank order
    dev: tuple              # (repo, url)
    frozen: tuple
    document: dict

    @property
    def roster(self) -> list[str]:
        return [u for urls in self.universe.values() for u in urls]


def load_proposal(path) -> Proposal:
    d = load_json(path, "proposal", limit=1 << 20)
    if not isinstance(d, dict) or d.get("schema") != PROPOSAL_SCHEMA:
        raise BenchmarkError("proposal", f"schema must be {PROPOSAL_SCHEMA}")
    uni = d.get("rankedUniverse")
    if not isinstance(uni, dict) or not uni:
        raise BenchmarkError("proposal", "rankedUniverse missing")
    universe = {}
    for n, (repo, items) in enumerate(uni.items(), 1):
        if not isinstance(repo, str) or not isinstance(items, list):
            raise BenchmarkError("proposal", f"rankedUniverse entry {n} must map a repository name to a list")
        urls = []
        for it in items:
            if not isinstance(it, dict) or not isinstance(it.get("url"), str) or not isinstance(it.get("urlSha256"), str):
                raise BenchmarkError("proposal", f"rankedUniverse entry {n} holds an item that is not {{url, urlSha256}} strings")
            url, h = it["url"], it["urlSha256"]
            if h != hashlib.sha256(url.encode("utf-8")).hexdigest():
                raise BenchmarkError("proposal", f"rankedUniverse entry {n}: urlSha256 does not recompute")
            urls.append((h, url))
        if [h for h, _ in urls] != sorted(h for h, _ in urls):
            raise BenchmarkError("proposal", f"rankedUniverse entry {n}: not in ascending sha256 rank order")
        universe[repo] = [u for _, u in urls]
    flat = [u for urls in universe.values() for u in urls]
    if len(set(flat)) != len(flat):
        raise BenchmarkError("proposal", "a URL appears twice in the ranked universe")
    parts = {}
    for key in ("preImportDevCandidates", "preImportFrozenCandidates"):
        rows = d.get(key, [])
        if not isinstance(rows, list):
            raise BenchmarkError("proposal", f"{key} must be a list")
        for it in rows:
            if not isinstance(it, dict) or not isinstance(it.get("repo"), str) or not isinstance(it.get("url"), str):
                raise BenchmarkError("proposal", f"{key} holds an item that is not {{repo, url}} strings")
        parts[key] = tuple((it["repo"], it["url"]) for it in rows)
    declared = [u for _, u in parts["preImportDevCandidates"]] + [u for _, u in parts["preImportFrozenCandidates"]]
    if sorted(declared) != sorted(flat):
        raise BenchmarkError("proposal", "dev + frozen candidates do not partition the ranked universe")
    for repo, url in parts["preImportDevCandidates"] + parts["preImportFrozenCandidates"]:
        if repo not in universe or url not in universe[repo]:
            raise BenchmarkError("proposal", "a declared candidate is in the wrong repository list")
    return Proposal(str(d.get("sourceRevision")), universe, parts["preImportDevCandidates"],
                    parts["preImportFrozenCandidates"], d)


@dataclass(frozen=True)
class Source:
    revision: str
    cases: dict                 # url -> ScorerCase, in roster order
    excluded_fixtures: tuple    # label URLs that are not benchmark cases
    label_count: int
    label_gold_counts: dict     # url -> derived.num_golden_comments (audit only)
    proposal: Proposal
    file_digests: dict

    def report(self) -> dict:
        diag = {u: {"goldenCount": len(c.golden), "labelsGoldenCount": self.label_gold_counts.get(u),
                    "agree": len(c.golden) == self.label_gold_counts.get(u)} for u, c in self.cases.items()}
        return {"schema": "benchmark-import-report@1", "revision": self.revision, "cases": len(self.cases),
                "goldenTotal": sum(len(c.golden) for c in self.cases.values()),
                "labelEntries": self.label_count, "excludedFixtures": list(self.excluded_fixtures),
                "scoredCaseCount": len(self.cases), "fileDigests": self.file_digests,
                "goldenCountDisagreements": sorted(u for u, v in diag.items() if not v["agree"])}


def load_source(pins_path, data_path, labels_path, proposal_path, *, expect_revision: str | None = None) -> Source:
    data_p, labels_p = Path(data_path).absolute(), Path(labels_path).absolute()
    pins = load_pins(pins_path, expect_revision=expect_revision, store_dirs={data_p.parent.resolve(), labels_p.parent.resolve()})
    prop = load_proposal(proposal_path)
    if prop.revision != pins["revision"]:
        raise BenchmarkError("proposal", "proposal sourceRevision differs from the pinned revision")
    data = parse_json(verify_file(data_p, pin_for(pins, "benchmark_data.json")), "benchmark_data")
    labels = parse_json(verify_file(labels_p, pin_for(pins, "pr_labels.json")), "pr_labels")
    if not isinstance(data, dict) or not isinstance(labels, dict):
        raise BenchmarkError("shape", "both sources must be objects keyed by PR URL")
    roster = prop.roster
    if set(data) != set(roster) or len(data) != len(roster):
        raise BenchmarkError("roster", f"benchmark_data URLs ({len(data)}) differ from the declared roster ({len(roster)})")
    fixtures = tuple(sorted(u for u in labels if u == LABEL_FIXTURE_URL))
    real = [u for u in labels if u != LABEL_FIXTURE_URL]
    if set(real) != set(roster) or len(real) != len(roster):
        raise BenchmarkError("roster", f"pr_labels URLs minus the fixture ({len(real)}) differ from the roster")
    counts = {}
    for u in real:
        derived = labels[u].get("derived") if isinstance(labels[u], dict) else None
        n = derived.get("num_golden_comments") if isinstance(derived, dict) else None
        counts[u] = n if isinstance(n, int) and not isinstance(n, bool) else None
    cases = {u: build_case(u, i, data[u]) for i, u in enumerate(roster)}
    return Source(pins["revision"], cases, fixtures, len(labels), counts, prop,
                  {f["name"]: f["sha256"] for f in pins["files"]})
