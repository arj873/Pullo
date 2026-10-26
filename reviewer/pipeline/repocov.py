"""Repository coverage (`repository-coverage@1`) from two host-verified `repo-import@1` records.

A complete import is its own immutable snapshot (new snapshot id, never an alias of a partial one). Whether the
review saw the whole repository is decided here from BOTH records' omission counts, never from the tools View's
`full` flag. The document is host data: validated against the supplied manifests, digest-bound into the run
config, and rendered into the model statement, comments.json and review.md. Pure; no disk.
"""

from __future__ import annotations

from reviewer.contracts.canonical import digest
from reviewer.contracts.redaction import redact

from reviewer.repoimport.policy import OMISSION_KINDS

from .errors import PipelineError

SCHEMA = "repository-coverage@1"
SCOPE_FULL = "repository"
SCOPE_OMISSIONS = "repository-with-omissions"
BEHAVIOR = "repository-disclosure@1"        # bumped on any change to the wording/rules below (bound into identity)
SIDES = ("base", "head")


def _bad(msg: str):
    raise PipelineError("invalid-input", f"imports: {msg}")


def _side(name: str, rec, manifest: dict) -> dict:
    if not isinstance(rec, dict):
        _bad(f"{name} record must be an object")
    for k in ("commitSha", "snapshotId", "omissions", "coverage"):
        if k not in rec:
            _bad(f"{name} record has no {k}")
    if rec["snapshotId"] != manifest["snapshotId"]:
        _bad(f"{name} record is for snapshot {str(rec['snapshotId'])[:24]}..., the supplied {name} manifest is "
             f"{manifest['snapshotId'][:24]}...")
    om = rec["omissions"]
    if not isinstance(om, dict) or not isinstance(om.get("counts"), dict):
        _bad(f"{name} record omissions.counts is missing")
    counts = om["counts"]
    unknown = sorted(str(k)[:40] for k in counts if k not in OMISSION_KINDS)
    if unknown:
        _bad(f"{name} record omission kinds are not the importer's vocabulary: {unknown[:3]}")
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in counts.values()):
        _bad(f"{name} record omission counts are not non-negative integers")
    total = sum(counts.values())
    cov = rec["coverage"]            # genuine repo-import@1: {"scope": ..., "fullRepositoryCoverage": bool}
    want = {"scope": "repository-with-omissions" if total else "full-repository", "fullRepositoryCoverage": total == 0}
    if not isinstance(cov, dict) or set(cov) != set(want) or cov["scope"] != want["scope"] \
            or cov["fullRepositoryCoverage"] is not want["fullRepositoryCoverage"]:
        _bad(f"{name} record claims coverage {cov!r} but its omission counts say {want!r}")
    if total and not isinstance(om.get("items"), list):
        _bad(f"{name} record lists omissions but carries no items")
    if manifest.get("gitCommit") not in (None, rec["commitSha"]):
        _bad(f"{name} manifest gitCommit differs from the record's commit")
    return {"commitSha": rec["commitSha"], "snapshotId": rec["snapshotId"], "coverage": dict(rec["coverage"]),
            "omissionCounts": dict(sorted(counts.items())), "omittedTotal": total,
            "omissionsSha256": om.get("sha256"), "recordDigest": digest(rec)}


def build(imports, base_manifest: dict, head_manifest: dict, case: dict) -> dict:
    sides = {"base": _side("base", imports.base, base_manifest), "head": _side("head", imports.head, head_manifest)}
    full = all(s["omittedTotal"] == 0 for s in sides.values())
    kinds = sorted({k for s in sides.values() for k, n in s["omissionCounts"].items() if n})
    rel = {}
    for name, rec in (("base", imports.base), ("head", imports.head)):
        r = rec.get("relatesTo")
        if isinstance(r, dict):
            rel[name] = {k: r.get(k) for k in ("caseId", "side", "partialSnapshotId", "commitSha",
                                                "changedPathsChecked", "changedPathsByteEqual", "idEqualsPartial",
                                                "unchecked") if k in r}
    pr = case["pr"]
    return {"schema": SCHEMA, "scope": SCOPE_FULL if full else SCOPE_OMISSIONS, "fullRepositoryCoverage": full,
            "base": sides["base"], "head": sides["head"], "gapKinds": kinds, "relatesTo": rel,
            "prTextSupplied": bool(pr["title"].strip() or pr["body"].strip()),
            "behavior": BEHAVIOR}


def is_repository(cov) -> bool:
    return isinstance(cov, dict) and cov.get("schema") == SCHEMA


def check(cov: dict) -> None:
    """Re-validate a stored document (resume / load): internally consistent, claims only what its parts say."""
    if not is_repository(cov) or cov.get("behavior") != BEHAVIOR:
        raise PipelineError("checkpoint-invalid", "repository coverage document is not repository-coverage@1")
    total = sum(cov[s]["omittedTotal"] for s in SIDES)
    if cov["fullRepositoryCoverage"] != (total == 0) or cov["scope"] != (SCOPE_FULL if total == 0 else SCOPE_OMISSIONS):
        raise PipelineError("checkpoint-invalid", "repository coverage claims more than its import records support")


def statement(cov: dict) -> str:
    b, h = cov["base"], cov["head"]
    s = (f"REPOSITORY coverage: the complete pinned repository trees at base {b['commitSha'][:12]} and head "
         f"{h['commitSha'][:12]} are available through read-only retrieval requests (list, read, search, diff); the "
         "starting context is only a bounded selection and is not the whole tree.")
    if cov["fullRepositoryCoverage"]:
        s += " Both imports record no omitted path."
    else:
        parts = [f"{n}: base {b['omissionCounts'].get(k, 0)}, head {h['omissionCounts'].get(k, 0)}"
                 for k in cov["gapKinds"] for n in [k]]
        s += (f" NOT every path is present: {b['omittedTotal']} base and {h['omittedTotal']} head path(s) were "
              f"omitted by the import ({'; '.join(parts)}). A path you cannot find may exist in the repository.")
    if not cov["prTextSupplied"]:
        s += " The pull request title and body were not supplied to the reviewer."
    s += (" Retrieval is bounded: a result may be truncated, denied or unavailable, and a request that was not run "
          "is not evidence about the code.")
    return redact(s)[0]


def detail(cov: dict, limit: int = 100) -> dict:
    return {"kind": "repository", "scope": cov["scope"], "fullRepositoryCoverage": cov["fullRepositoryCoverage"],
            "base": {k: cov["base"][k] for k in ("commitSha", "snapshotId", "omissionCounts", "omittedTotal")},
            "head": {k: cov["head"][k] for k in ("commitSha", "snapshotId", "omissionCounts", "omittedTotal")},
            "gapKinds": list(cov["gapKinds"]), "relatesTo": cov["relatesTo"], "prTextSupplied": cov["prTextSupplied"]}
