"""Host attempt guard: a trusted deadline/cancel hook the gateway calls before EVERY provider attempt.

The pipeline owner passes `Gateway(guard=...)`. A guard sees only coordinates (never request content) and
returns None to proceed or a refusal. It cannot interrupt a call already in flight."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

GUARD_CODES = ("deadline-exceeded", "cancelled")
REFUSED_BY = "host-guard"


@dataclass(frozen=True)
class AttemptContext:
    stage: str
    role: str
    agent_id: str
    ordinal: int
    attempt: int
    kind: str            # first | retry | repair
    mode: str            # live | strict-replay


@dataclass(frozen=True)
class GuardRefusal:
    code: str
    message: str = "attempt refused by the host guard"

    def __post_init__(self):
        if self.code not in GUARD_CODES or not isinstance(self.message, str):
            raise ValueError(f"guard refusal code must be one of {GUARD_CODES}")


AttemptGuard = Callable[[AttemptContext], "GuardRefusal | str | None"]


def deadline_guard(deadline: float, now: Callable[[], float]) -> AttemptGuard:
    """Refuse once now() >= deadline (same unit as `now`, e.g. time.monotonic)."""
    def guard(ctx: AttemptContext):
        return GuardRefusal("deadline-exceeded", "host deadline reached") if now() >= deadline else None
    return guard


def cancel_guard(event: threading.Event) -> AttemptGuard:
    def guard(ctx: AttemptContext):
        return GuardRefusal("cancelled", "host cancelled the run") if event.is_set() else None
    return guard


def chain_guards(*guards: AttemptGuard) -> AttemptGuard:
    """First refusal wins; order is the argument order."""
    def guard(ctx: AttemptContext):
        for g in guards:
            r = g(ctx)
            if r is not None:
                return r
        return None
    return guard


def normalize_refusal(r) -> GuardRefusal:
    """Guard return value -> GuardRefusal; anything unrecognized fails closed as `cancelled`."""
    if isinstance(r, GuardRefusal):
        return r
    if isinstance(r, str) and r in GUARD_CODES:
        return GuardRefusal(r)
    return GuardRefusal("cancelled", "host guard returned an unrecognized value")
