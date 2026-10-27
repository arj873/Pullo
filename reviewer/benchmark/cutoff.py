"""Cutoff proof format, resolver and pre-score case selection. A current PR/merged head is never proof."""

from __future__ import annotations

import re

from .errors import BenchmarkError
from .jsonio import digest
from .projection import parse_ts

PROOF_SCHEMA = "benchmark-cutoff-proof@1"
SELECTION_SCHEMA = "benchmark-selection@1"
ADMISSION_SCHEMA = "benchmark-cutoff-admission@1"
ADMISSION_KEYS = {"schema", "originalUrl", "resolvedRepo", "asOfBase", "asOfHead", "mergeBase", "evidenceDigests",
                  "admittedBy", "admittedAt", "decisionRef"}
EVIDENCE_KINDS = {"fork-mapping", "redirect", "commit-time", "review-time", "upstream-pin"}
NOT_PROOF = {"current-pr-head", "merged-head", "merge-commit"}
EVAL_ORG = "ai-code-review-evaluation"
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPO = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/pull/\d+$")


def url_repo(url: str) -> str | None:
    m = _REPO.match(url)
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def attestation_binding(proof: dict) -> dict:
    """What a root admission must bind for this proof: exact URL, resolved repo, base/head/merge-base and the digest of
    every evidence item. Root adds admittedBy/admittedAt/decisionRef after an independent recheck; this module never
    creates an admission."""
    ev = proof.get("evidence") if isinstance(proof.get("evidence"), list) else []
    return {"originalUrl": proof.get("originalUrl"), "resolvedRepo": str(proof.get("resolvedRepo", "")).lower(),
            "asOfBase": proof.get("asOfBase"), "asOfHead": proof.get("asOfHead"), "mergeBase": proof.get("mergeBase"),
            "evidenceDigests": sorted(digest(e) for e in ev)}


def check_admission(url: str, proof: dict, admission) -> list[str]:
    """Reasons an externally supplied admission does not bind this proof (empty list = it binds)."""
    if not isinstance(admission, dict) or set(admission) != ADMISSION_KEYS or admission.get("schema") != ADMISSION_SCHEMA:
        return [f"admission must be exactly {sorted(ADMISSION_KEYS)} with schema {ADMISSION_SCHEMA}"]
    why = []
    if admission["admittedBy"] != "root":
        why.append("admission is not by root")
    if not (isinstance(admission["admittedAt"], str) and parse_ts(admission["admittedAt"])):
        why.append("admittedAt missing/unparseable")
    if not (isinstance(admission["decisionRef"], str) and admission["decisionRef"].strip()):
        why.append("decisionRef missing")
    ev = admission["evidenceDigests"]
    if not isinstance(ev, list) or not ev or not all(isinstance(x, str) and _DIGEST.match(x) for x in ev) or ev != sorted(set(ev)):
        why.append("evidenceDigests must be a non-empty sorted unique list of sha256 digests")
    if admission["originalUrl"] != url:
        why.append("admission is for a different original URL")
    want = attestation_binding(proof)
    for k in ("resolvedRepo", "asOfBase", "asOfHead", "mergeBase", "evidenceDigests"):
        if admission[k] != want[k]:
            why.append(f"admission {k} differs from the attested proof")
    return why


def resolve_cutoff(url: str, proof, case: dict | None, admission=None) -> dict:
    """case: the projection entry for `url` (review timestamps only). Returns {status, reasons}.

    Statuses: `unproven` (checks fail), `attested` (the proof is structurally plausible but is only a self-attestation;
    never eligible for automatic selection) and `proven` (attested AND an external root admission binds the exact
    URL/repo/base/head/merge-base/evidence digests). The proof's own `status` field is never read. The temporal check
    compares against competitor review times, which are 2026 re-created runs, so it is a sanity check only."""
    why = []
    if proof is None:
        return {"url": url, "status": "unproven", "reasons": ["no cutoff proof supplied"]}
    if not isinstance(proof, dict) or proof.get("schema") != PROOF_SCHEMA:
        return {"url": url, "status": "unproven", "reasons": [f"schema must be {PROOF_SCHEMA}"]}
    if proof.get("originalUrl") != url:
        why.append("proof is for a different original URL")
    for k in ("asOfBase", "asOfHead", "mergeBase"):
        if not (isinstance(proof.get(k), str) and _HEX40.match(proof[k])):
            why.append(f"{k} is not a 40-hex commit")
    ev = proof.get("evidence") if isinstance(proof.get("evidence"), list) else []
    good = []
    for e in ev:
        if not isinstance(e, dict) or set(e) != {"kind", "source", "observedAt", "value"} \
                or not all(isinstance(e[k], str) and e[k] for k in e) or e["kind"] not in EVIDENCE_KINDS:
            why.append("malformed evidence item")
        elif e["source"] in NOT_PROOF:
            why.append(f"evidence from {e['source']} is not proof of the as-of input")
        else:
            good.append(e)
    kinds = {e["kind"] for e in good}
    for need in ("commit-time", "review-time"):
        if need not in kinds:
            why.append(f"missing {need} evidence")
    repo, resolved = url_repo(url), str(proof.get("resolvedRepo", "")).lower()
    if not resolved:
        why.append("resolvedRepo missing")
    elif (repo != resolved or (repo or "").startswith(EVAL_ORG + "/")) and not kinds & {"fork-mapping", "redirect"}:
        why.append("URL repository differs from the resolved or is an evaluation fork; fork-mapping/redirect evidence required")
    head_t = parse_ts(proof.get("headCommittedAt", ""))
    reviews = [r["firstCreatedAt"] for r in (case or {}).get("reviews", []) if r.get("firstCreatedAt")]
    first = min((parse_ts(x) for x in reviews if parse_ts(x)), default=None)
    if head_t is None:
        why.append("headCommittedAt missing/unparseable")
    elif first is None:
        why.append("no parseable competitor review timestamp to compare against")
    elif head_t > first:
        why.append("as-of head was committed after the earliest competitor review")
    if why:
        return {"url": url, "status": "unproven", "reasons": why}
    binding = attestation_binding(proof)
    if admission is None:
        return {"url": url, "status": "attested", "binding": binding,
                "reasons": ["structurally plausible self-attestation only; a separate root admission record is required"]}
    bad = check_admission(url, proof, admission)
    if bad:
        return {"url": url, "status": "attested", "binding": binding, "reasons": ["admission does not bind: " + "; ".join(bad)]}
    return {"url": url, "status": "proven", "binding": binding, "reasons": [],
            "admittedAt": admission["admittedAt"], "decisionRef": admission["decisionRef"]}


def select_cases(proposal, projection: dict, proofs: dict, admissions: dict | None = None) -> dict:
    """Walk each repository's declared rank; PROVEN cases (proof + external root admission) fill the dev quota then the
    frozen quota. Attested-only cases are excluded with that reason. Reads no score."""
    admissions = admissions or {}
    if not isinstance(admissions, dict) or set(admissions) - set(proposal.roster):
        raise BenchmarkError("roster", "admissions must be an object keyed by roster URL")
    by_url = {c["url"]: c for c in projection["cases"]}
    dev_q, fro_q = {}, {}
    for repo, _ in proposal.dev:
        dev_q[repo] = dev_q.get(repo, 0) + 1
    for repo, _ in proposal.frozen:
        fro_q[repo] = fro_q.get(repo, 0) + 1
    dev, frozen, exclusions, resolutions = [], [], [], {}
    for repo, urls in proposal.universe.items():
        d_left, f_left = dev_q.get(repo, 0), fro_q.get(repo, 0)
        for rank, url in enumerate(urls, 1):
            if url not in by_url:
                raise BenchmarkError("roster", "ranked URL is absent from the projection")
            res = resolutions[url] = resolve_cutoff(url, proofs.get(url), by_url[url], admissions.get(url))
            if res["status"] != "proven":
                exclusions.append({"url": url, "repo": repo, "rank": rank, "reasons": res["reasons"]})
            elif d_left:
                dev.append(url)
                d_left -= 1
            elif f_left:
                frozen.append(url)
                f_left -= 1
            else:
                exclusions.append({"url": url, "repo": repo, "rank": rank, "reasons": ["quota already filled"]})
    declared_dev, declared_fro = [u for _, u in proposal.dev], [u for _, u in proposal.frozen]
    return {"schema": SELECTION_SCHEMA, "dev": dev, "frozen": frozen, "exclusions": exclusions, "resolutions": resolutions,
            "coverage": {"dev": f"{len(dev)}/{len(declared_dev)}", "frozen": f"{len(frozen)}/{len(declared_fro)}",
                         "reproducible": len(dev) + len(frozen), "universe": len(proposal.roster)},
            "differsFromDeclared": sorted(dev) != sorted(declared_dev) or sorted(frozen) != sorted(declared_fro),
            "allReproducible": len(dev) + len(frozen) == len(proposal.roster),
            "attested": sorted(u for u, r in resolutions.items() if r["status"] == "attested"),
            "scoresRead": False, "selectionDigest": digest({"dev": dev, "frozen": frozen, "exclusions": exclusions})}
