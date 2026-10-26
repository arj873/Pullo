"""The host attempt guard for one run: cancellation, hard deadline and stage ceilings, checked by the gateway
before EVERY provider attempt, retry and repair (live and replay).

The engine shares this object: it records the run start and each stage start, so the guard decides from the same
clock and the same state that `Engine.gate` uses between tool and model steps. The guard never sees request
content (only coordinates) and cannot interrupt a call already in flight; adapter timeouts own that.
"""

from __future__ import annotations

from reviewer.contracts.budget import deadline_state, stage_deadline_exceeded
from reviewer.gateway import GuardRefusal


class RunGuard:
    def __init__(self, host, budget: dict):
        self.host, self.budget = host, budget
        self.t0: float | None = None             # set by the engine at run start
        self.stage_t0: dict[str, float] = {}
        self.refusals: list[dict] = []           # what the guard actually refused (audit, not identity)

    def __call__(self, ctx):
        host = self.host
        if host.cancel is not None and host.cancel():
            return self._refuse(ctx, GuardRefusal("cancelled", "run cancelled by the host"))
        if self.t0 is None:
            return None
        now = host.clock()
        if deadline_state(self.budget, max(0.0, now - self.t0)) == "hard":
            return self._refuse(ctx, GuardRefusal("deadline-exceeded", "hard run deadline reached"))
        st = self.stage_t0.get(ctx.stage)
        if st is not None and stage_deadline_exceeded(ctx.stage, max(0.0, now - st)):
            return self._refuse(ctx, GuardRefusal("deadline-exceeded", f"{ctx.stage} stage ceiling reached"))
        return None

    def _refuse(self, ctx, refusal):
        self.refusals.append({"stage": ctx.stage, "role": ctx.role, "ordinal": ctx.ordinal, "attempt": ctx.attempt,
                              "kind": ctx.kind, "code": refusal.code})
        return refusal
