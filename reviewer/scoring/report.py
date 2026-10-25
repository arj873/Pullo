"""EvalReport assembly. Scored only for synthetic smoke suites; real datasets are unscored."""

from __future__ import annotations

from reviewer.contracts import CONTRACTS_VERSION, require

from .cases import SMOKE_RULE
from .errors import ScoringError, UnscoredSuiteError
from .metrics import f1_value, percentile, ratio

UNADJUDICATED = "unadjudicated: no human labels"
STATUSES = ("completed", "partial", "failed", "cancelled")
SMOKE_LIMITATIONS = [
    "Synthetic smoke data; says nothing about review quality or parity.",
    "Path/line overlap ignores the claim and its grade; it checks mechanics only.",
]
UNSCORED_LIMITATIONS = [
    "Real PRs without adjudicated labels: no precision/recall is reported.",
    "Read-only review: comments are local drafts; the author chooses fixes.",
]


def _dist(values: list) -> dict:
    known = [v for v in values if v is not None]
    return {"n": len(known), "p50": percentile(known, 0.5), "p95": percentile(known, 0.95),
            "max": max(known) if known else None}


def zero_cost(synthetic_records: int = 0, replayed_records: int = 0) -> dict:
    """Offline cost block: no live calls, no measured/estimated/unknown cost booked."""
    def b(n):
        return {"records": n, "usdMicros": None}
    return {"liveCalls": 0, "byBasis": {"measured": b(0), "estimated": b(0), "unknown": b(0),
                                        "replayed": b(replayed_records), "synthetic": b(synthetic_records)}}


def build_report(manifest: dict, suite_digest: str, case_results: list[dict], *, eval_run_id: str,
                 mode: str, config_digest: str, profiles: list[dict], prompt_versions: list[str],
                 cost: dict, scored: bool, replay_of: str | None = None,
                 limitations: list[str] | None = None, created_at: str | None = None) -> dict:
    """Build and validate an EvalReport.

    scored=True requires a synthetic suite using path-line-overlap@1 and scored case results;
    scored=False (the only legal choice for real PRs) emits unadjudicated@1 with null metrics.
    """
    require("SuiteManifest", manifest)
    smoke = manifest["synthetic"] and manifest["matching"]["rule"] == SMOKE_RULE
    if scored and not smoke:
        raise UnscoredSuiteError("only synthetic smoke suites can be scored; real PRs stay unscored")
    if not scored and manifest["synthetic"] and smoke:
        raise ScoringError("a synthetic smoke suite must be reported as scored")
    want = {c["id"] for c in manifest["cases"]}
    got = [c["caseId"] for c in case_results]
    if sorted(got) != sorted(want) or len(set(got)) != len(got):
        raise ScoringError("exactly one result per suite case is required")
    cases = sorted(case_results, key=lambda c: c["caseId"])

    if scored:
        tp = sum(c["truePositives"] for c in cases)
        fp = sum(c["falsePositives"] for c in cases)
        fn = sum(c["falseNegatives"] for c in cases)
        precision = ratio(tp, tp + fp, "no scored comments in any case (TP+FP = 0)")
        recall = ratio(tp, tp + fn, "no labelled bugs in any case (TP+FN = 0)")
        metrics = {"precision": precision, "recall": recall, "f1": f1_value(precision, recall)}
        matching = {"rule": SMOKE_RULE, "scope": "synthetic-smoke"}
        lim = limitations or SMOKE_LIMITATIONS
    else:
        null = {"value": None, "numerator": 0, "denominator": 0, "undefinedReason": UNADJUDICATED}
        metrics = {"precision": dict(null), "recall": dict(null),
                   "f1": {"value": None, "undefinedReason": UNADJUDICATED}}
        matching = {"rule": "unadjudicated@1", "scope": "unscored"}
        lim = limitations or UNSCORED_LIMITATIONS

    coverage = {s: sum(1 for c in cases if c["status"] == s) for s in STATUSES}
    coverage["expectationMet"] = sum(1 for c in cases if c["expectationMet"] is True)
    doc = {
        "schema": "eval-report@1", "evalRunId": eval_run_id, "mode": mode,
        "dataset": {"suiteId": manifest["id"], "suiteVersion": manifest["version"],
                    "suiteDigest": suite_digest, "synthetic": manifest["synthetic"],
                    "caseCount": len(cases)},
        "matching": matching, "configDigest": config_digest, "profiles": profiles,
        "promptVersions": sorted(prompt_versions), "contractsVersion": CONTRACTS_VERSION,
        "cases": cases, "metrics": metrics, "coverage": coverage, "cost": cost,
        "latency": {"original": _dist([c["latencyMs"]["original"] for c in cases]),
                    "replay": _dist([c["latencyMs"]["replay"] for c in cases])},
        "limitations": lim,
    }
    if replay_of:
        doc["replayOf"] = replay_of
    if created_at:
        doc["createdAt"] = created_at
    return require("EvalReport", doc)
