"""Trusted scoring-budget maxima (SCORE-RT-01). Constants and a pure validator; no I/O.

Scoring spends inside the trial aggregate (catalog.TRIAL_TOTAL_USD_MICROS: $50, $150 from 2026-11-01): a scoring sub-cap of 60M
micros (8M until 2026-10-29, 16M until 2026-10-30, 30M until 2026-11-01) and a scoring-time aggregate ceiling of 100M (20M, then
34M under the $50 total). A scoring call is refused when it would take the ALL-category total past 100M, so at least 50M of the
150M total always stays for reviews. The host passes tighter-or-equal bounds from pinned policy; model output and request params
never reach these values."""

from __future__ import annotations

CATEGORIES = ("review", "scoring")
DEFAULT_CATEGORY = "review"
SCORING_CATEGORY_CAP_MAX = 60_000_000                 # 8M -> 16M (2026-10-29, "you can do $16") -> 30M (2026-10-30, "raise to 30") -> 60M (CAP150)
SCORING_AGGREGATE_CEILING_MAX = 100_000_000           # 20M -> 34M (2026-10-30) -> 100M (CAP150, 2026-11-01: $150 total, >= $50 kept for reviews)
REVIEW_RESERVE_USD_MICROS = 30_000_000


def _pos_int(v) -> bool:
    return type(v) is int and v >= 1


def validate_admission(category, category_cap, aggregate_ceiling) -> None:
    """Raises ValueError (fixed text, no values echoed) unless the combination is admissible. Review takes no
    caps. Scoring requires BOTH caps, positive ints (bool refused), no wider than the approved maxima."""
    if type(category) is not str or category not in CATEGORIES:
        raise ValueError("unknown ledger category")
    if category == "review":
        if category_cap is not None or aggregate_ceiling is not None:
            raise ValueError("review admission takes no scoring caps")
        return
    if not _pos_int(category_cap) or not _pos_int(aggregate_ceiling):
        raise ValueError("scoring admission requires both caps as positive integers")
    if category_cap > SCORING_CATEGORY_CAP_MAX or aggregate_ceiling > SCORING_AGGREGATE_CEILING_MAX:
        raise ValueError("scoring caps exceed the approved maxima")
    if category_cap > aggregate_ceiling:
        raise ValueError("scoring sub-cap exceeds the scoring aggregate ceiling")
