"""Per-case scoring and honest CaseResult builders."""

from __future__ import annotations

import re
from dataclasses import dataclass

from reviewer.contracts import require, validate

from .errors import ScoringError, UnscoredSuiteError
from .matching import SCORED_STATES, MatchResult, match_comments

SMOKE_RULE = "path-line-overlap@1"
RUN_ID = re.compile(r"run_[0-9a-f]{16}")   # contracts.schema.json run id pattern


def require_smoke_suite(manifest: dict) -> int:
    """Overlap scoring is allowed only for synthetic suites that declare it. Returns tolerance."""
    require("SuiteManifest", manifest)
    if not manifest["synthetic"] or manifest["matching"]["rule"] != SMOKE_RULE:
        raise UnscoredSuiteError(
            "overlap matching is synthetic-smoke only; real PRs stay unscored (null metrics)")
    return manifest["matching"]["lineTolerance"]


@dataclass(frozen=True)
class CaseScore:
    case_id: str
    expect: str
    expectation_met: bool
    true_positives: int
    false_positives: int
    false_negatives: int
    duplicates: int
    comments: int
    match: MatchResult
    foreign: int = 0   # scored comments anchored to another snapshot/run (already counted in false_positives)


def _expectation_met(labels: dict, status: str, comments: int, fn: int, incomplete: list,
                     error: dict | None) -> bool:
    expect = labels["expect"]
    if expect == "findings":
        return status == "completed" and fn == 0
    if expect == "silence":
        return status == "completed" and comments == 0
    reason = labels["expectReason"]
    if expect == "partial":
        return status == "partial" and any(i["reason"] == reason for i in incomplete)
    return status == "failed" and error is not None and error["code"] == reason


def score_case(manifest: dict, labels: dict, comments: list[dict], *, status: str,
               incomplete: list[dict] | None = None, error: dict | None = None,
               head_snapshot_id: str | None = None, run_id: str | None = None) -> CaseScore:
    """Score one synthetic smoke case. Raises UnscoredSuiteError for non-smoke suites.

    `expectationMet` (separate from P/R): findings = run completed and every labelled bug matched;
    silence = completed with no scored comment; partial = status partial and the expected reason
    is among `incomplete`; failed = status failed with the expected error code. Labelled bugs not
    matched are false negatives in every case type, including partial/failed (the tool missed them).

    `head_snapshot_id` / `run_id`: when given, a comment anchored to another snapshot (for example the
    base side) or belonging to another run cannot match; it is booked as a false positive. Pass both
    for any real scoring (`score_loaded_case` does); they are optional only so unit tests can score
    hand-built comments without a suite.
    """
    tolerance = require_smoke_suite(manifest)
    require("CaseLabels", labels)
    for c in comments:
        issues = validate("Comment", c)
        if issues:
            raise ScoringError(f"invalid Comment {c.get('id')!r}: {issues[0]}")
    result = match_comments(comments, labels["bugs"], tolerance,
                            head_snapshot_id=head_snapshot_id, run_id=run_id)
    scored = sum(1 for c in comments if c["state"] in SCORED_STATES)
    tp, fp, fn = result.true_positives, len(result.false_positives), len(result.false_negatives)
    inc = incomplete or []
    return CaseScore(labels["caseId"], labels["expect"],
                     _expectation_met(labels, status, scored, fn, inc, error),
                     tp, fp, fn, len(result.duplicates), scored, result, len(result.foreign))


def score_loaded_case(suite, case_id: str, comments: list[dict], *, run_id: str, status: str,
                      incomplete: list[dict] | None = None, error: dict | None = None) -> CaseScore:
    """Score a case of a loaded synthetic suite against ITS pinned head snapshot and the given run."""
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ScoringError(f"run_id must be a canonical non-empty run id, got {run_id!r}")
    case = suite.cases.get(case_id) if isinstance(case_id, str) else None
    if case is None:
        raise ScoringError(f"unknown case {case_id!r}")
    if case.labels is None:
        raise UnscoredSuiteError("labels are not loaded for this suite; it cannot be scored")
    return score_case(suite.manifest, case.labels, comments, status=status, incomplete=incomplete,
                      error=error, head_snapshot_id=case.input["head"]["snapshotId"], run_id=run_id)


def _result(case_id, run_id, status, incomplete, error, lat_original, lat_replay, **tallies):
    return {"caseId": case_id, "runId": run_id, "status": status, "incomplete": incomplete or [],
            "error": error, "latencyMs": {"original": lat_original, "replay": lat_replay},
            **tallies}


def scored_case_result(score: CaseScore, *, run_id: str, status: str,
                       incomplete: list[dict] | None = None, error: dict | None = None,
                       latency_original: int | None = None, latency_replay: int | None = None) -> dict:
    return _result(score.case_id, run_id, status, incomplete, error, latency_original, latency_replay,
                   expect=score.expect, expectationMet=score.expectation_met,
                   truePositives=score.true_positives, falsePositives=score.false_positives,
                   falseNegatives=score.false_negatives, duplicates=score.duplicates,
                   comments=score.comments)


def unscored_case_result(case_id: str, *, run_id: str, status: str, comments: int,
                         incomplete: list[dict] | None = None, error: dict | None = None,
                         latency_original: int | None = None, latency_replay: int | None = None) -> dict:
    """Real or unadjudicated case: only observed facts, every label-derived field null."""
    return _result(case_id, run_id, status, incomplete, error, latency_original, latency_replay,
                   expect=None, expectationMet=None, truePositives=None, falsePositives=None,
                   falseNegatives=None, duplicates=None, comments=comments)
