"""Deterministic smoke-only matching: path + line overlap, one comment per bug.

SYNTHETIC SMOKE ONLY (rule `path-line-overlap@1`). It ignores what a comment claims and its
grade, so it can say "the mechanics found the planted bug" and nothing about review quality.
Real PRs are never matched with this module (see cases.require_smoke_suite).

Rules
- A comment and a bug are *compatible* when they share the exact path and the closed line
  intervals are within `tolerance` lines of each other (distance 0 when they overlap).
- Assignment is one-to-one with MAXIMUM cardinality (augmenting paths). Comments are visited in
  canonical order (path, start, end, id); each comment tries its compatible bugs by (distance,
  bug id). Among equally large matchings this picks a deterministic one, not necessarily the
  one with the smallest total distance. Input order never matters.
- Every unmatched comment is a false positive. It is a *duplicate* false positive when it is
  compatible with at least one bug that another comment matched. Duplicates are a subset of FP.
- Unmatched bugs are false negatives.
- Only comments in state draft or posted are scored; other states are reported as ignored.
- Anchor provenance: when the caller names the case's head snapshot (and the run), a scored comment
  anchored to any other snapshot, or belonging to another run, is *foreign*. A foreign comment can
  never match a bug; it is booked as a plain false positive (never a duplicate) and listed in
  `foreign`, so a base-side or stale comment cannot earn a true positive.
- Result tuples are canonical (sorted); they do not depend on the order labels or comments arrive in.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ScoringError

SCORED_STATES = ("draft", "posted")


@dataclass(frozen=True)
class MatchResult:
    matches: tuple[tuple[str, str], ...]          # (comment id, bug id), sorted
    false_positives: tuple[str, ...]              # all unmatched comment ids (incl. duplicates)
    duplicates: tuple[str, ...]                   # subset of false_positives
    false_negatives: tuple[str, ...]              # unmatched bug ids
    ignored: tuple[str, ...] = field(default=())  # comments not in a scored state
    foreign: tuple[str, ...] = field(default=())  # scored comments with the wrong snapshot/run (subset of FP)

    @property
    def true_positives(self) -> int:
        return len(self.matches)


def _span(comment: dict) -> tuple[str, int, int]:
    a = comment["anchor"]
    return a["path"], a["startLine"], a["endLine"]


def _distance(c: tuple[str, int, int], b: dict) -> int | None:
    """Distance between closed intervals (nearest line numbers), or None if the paths differ."""
    path, start, end = c
    if path != b["path"]:
        return None
    lo, hi = b["lines"]
    if start > hi:
        return start - hi
    if end < lo:
        return lo - end
    return 0


def match_comments(comments: list[dict], bugs: list[dict], tolerance: int, *,
                   head_snapshot_id: str | None = None, run_id: str | None = None) -> MatchResult:
    if not isinstance(tolerance, int) or isinstance(tolerance, bool) or not 0 <= tolerance <= 20:
        raise ScoringError("tolerance must be an integer 0..20")
    ids = [c.get("id") for c in comments]
    if len(set(ids)) != len(ids):
        raise ScoringError("duplicate comment ids")
    bug_ids = [b["id"] for b in bugs]
    if len(set(bug_ids)) != len(bug_ids):
        raise ScoringError("duplicate bug ids")

    scored = sorted((c for c in comments if c.get("state") in SCORED_STATES),
                    key=lambda c: (*_span(c), c["id"]))
    ignored = tuple(sorted(c["id"] for c in comments if c.get("state") not in SCORED_STATES))
    bugs_by_id = {b["id"]: b for b in bugs}

    def is_foreign(c: dict) -> bool:
        return ((head_snapshot_id is not None and c["anchor"].get("snapshotId") != head_snapshot_id)
                or (run_id is not None and c.get("runId") != run_id))

    foreign = {c["id"] for c in scored if is_foreign(c)}
    compat: dict[str, list[tuple[int, str]]] = {}
    for c in scored:
        if c["id"] in foreign:
            compat[c["id"]] = []
            continue
        span = _span(c)
        cands = []
        for b in bugs:
            d = _distance(span, b)
            if d is not None and d <= tolerance:
                cands.append((d, b["id"]))
        compat[c["id"]] = sorted(cands)

    owner: dict[str, str] = {}   # bug id -> comment id

    def augment(start: str) -> bool:
        """Kuhn's augmenting path, iterative (no recursion limit) and in the same visiting order
        as the recursive form: candidates by (distance, bug id), depth first."""
        seen: set[str] = set()
        stack = [(start, iter(compat[start]))]
        path: list[tuple[str, str]] = []   # (comment, bug) hops taken so far
        while stack:
            cid, candidates = stack[-1]
            for _, bid in candidates:
                if bid in seen:
                    continue
                seen.add(bid)
                path.append((cid, bid))
                if bid not in owner:
                    for c_id, b_id in path:
                        owner[b_id] = c_id
                    return True
                stack.append((owner[bid], iter(compat[owner[bid]])))
                break
            else:
                stack.pop()
                if path:
                    path.pop()
        return False

    for c in scored:
        augment(c["id"])

    matched_comments = set(owner.values())
    matches = tuple(sorted((cid, bid) for bid, cid in owner.items()))
    fps = tuple(c["id"] for c in scored if c["id"] not in matched_comments)
    matched_bugs = set(owner)
    dups = tuple(cid for cid in fps if any(bid in matched_bugs for _, bid in compat[cid]))
    fns = tuple(sorted(b["id"] for b in bugs if b["id"] not in matched_bugs))
    assert set(dups) <= set(fps) and len(matches) + len(fps) == len(scored)
    assert all(bid in bugs_by_id for _, bid in matches)
    return MatchResult(matches, fps, dups, fns, ignored, tuple(sorted(foreign)))
