"""Ratio semantics. A ratio with denominator 0 is undefined (null + reason), never 0 or 1."""

from __future__ import annotations


def ratio(numerator: int, denominator: int, undefined_reason: str) -> dict:
    """A contract `Ratio`: value = numerator/denominator, or null with a reason when the
    denominator is 0 (numerator must then be 0)."""
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError(f"impossible ratio {numerator}/{denominator}")
    if denominator == 0:
        return {"value": None, "numerator": 0, "denominator": 0, "undefinedReason": undefined_reason}
    return {"value": numerator / denominator, "numerator": numerator, "denominator": denominator,
            "undefinedReason": None}


def f1_value(precision: dict, recall: dict) -> dict:
    """A contract `Derived`: harmonic mean; null if either input is undefined; 0.0 if P+R == 0."""
    reasons = []
    if precision["value"] is None:
        reasons.append("precision undefined: " + str(precision["undefinedReason"]))
    if recall["value"] is None:
        reasons.append("recall undefined: " + str(recall["undefinedReason"]))
    if reasons:
        return {"value": None, "undefinedReason": "; ".join(reasons)[:200]}
    p, r = precision["value"], recall["value"]
    return {"value": 0.0 if p + r == 0 else 2 * p * r / (p + r), "undefinedReason": None}


def percentile(values: list[int], q: float) -> int | None:
    """Nearest-rank percentile over known values; None if there are none."""
    vals = sorted(values)
    if not vals:
        return None
    import math
    return vals[max(1, math.ceil(q * len(vals))) - 1]
