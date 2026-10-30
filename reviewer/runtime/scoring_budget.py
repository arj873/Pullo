"""Trusted scoring-budget maxima (SCORE-RT-01). Constants and a pure validator; no I/O.

Scoring spends inside the original $50 trial aggregate: a scoring sub-cap of 30M micros (8M until 2026-10-29, 16M until
2026-10-30) and a scoring-time aggregate ceiling of 34M (raised from 20M by the same +14M, so the ~4M of non-scoring headroom
inside it is unchanged; the review reserve that remains under the 50M total shrinks accordingly). The host passes tighter-or-equal bounds
from pinned policy; model output and request params never reach these values."""

from __future__ import annotations

CATEGORIES = ("review", "scoring")
DEFAULT_CATEGORY = "review"
SCORING_CATEGORY_CAP_MAX = 30_000_000                 # 8M -> 16M (2026-10-29, "you can do $16") -> 30M (2026-10-30, "raise to 30")
SCORING_AGGREGATE_CEILING_MAX = 34_000_000            # 20M -> 34M (2026-10-30): +14M with the scoring cap, other headroom unchanged
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
