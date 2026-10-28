"""Budget semantics (one contract for 15/31/37/RUNTIME).

- `maxUsdMicros` is a hard per-run ceiling. A call is admitted only if
  committed + in-flight reservations + its worst-case reservation fit. Calls
  that would exceed are refused (`budget-exhausted`).
- INVESTIGATE may use at most (1 - verifyReserveBp/10000) of the ceiling, so
  investigation cannot starve VERIFY and JUDGE.
- A reservation is worst-case: every estimated input token at the dearest input
  rate (max of plain and cache-write) plus the role's full maxOutputTokens.
- Retries and repairs are new admissions; they never bypass the cap or the
  deadline. Effective limits: retries = min(Budget.maxRetriesPerCall, role
  caps.maxRetries); repairs = min(1, caps.maxRepairs) (D7).
- Settlement uses reported usage. If any input split or output usage is
  unknown the full reservation stays charged (basis `estimated`).
- Release (D2): a reservation is returned only when the provider definitely did
  not process the call: `not-sent` (refused before any network I/O) or
  `rejected-before-processing` (a documented non-billed rejection, e.g. 400/401/
  403/404/413/422 with no usage). Timeouts, stream cuts, 5xx and anything else
  unknown keep the reservation charged.
- 0% overrun holds while reservations bound actual cost. The input estimate is
  a heuristic, so `settle` reports `overrun` when actual > reserved; the ledger
  charges the actual amount and refuses further calls once the ceiling is hit.
- Output price applies to outputTokens only; providers report reasoning inside
  outputTokens, so reasoningTokens is informational.
- Strict replay recomputes the same reservations from recorded requests and
  settles from recorded usage, so budget exhaustion reproduces exactly.
- Wall clock: soft deadline stops new agents and lets VERIFY drain; hard
  deadline stops all calls and JUDGE/PUBLISH use what is verified. The clock
  starts at run start (local) and is injected by the caller (`elapsed_sec`).
- Live spend needs a trusted SpendAuthorization (D5): `check_spend_authorization`.
"""

from __future__ import annotations

import datetime
import re
import threading
from dataclasses import dataclass, fields

from .canonical import canonical_json, digest
from .stages import STAGE_CEILING_SEC

STANDARD_S0A_BUDGET = {
    # ~$4 is a planning target, not a hard ceiling (RUNTIME.md). Live use needs an explicit
    # ceiling in the spend authorization; Stage 0A runs offline.
    "maxUsdMicros": 4_000_000, "maxToolCalls": 60, "maxToolCallsPerAgent": 30,
    "maxToolOutputTokensPerAgent": 60_000, "wallClockSec": 360, "softDeadlineSec": 240,
    "verifyReserveBp": 3000, "maxRetriesPerCall": 2,
}

RELEASABLE_OUTCOMES = frozenset({"not-sent", "rejected-before-processing"})
_MAX = 2**53 - 1


def _amount(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= _MAX:
        raise ValueError(f"{name} must be a non-negative integer, got {v!r}")
    return v


@dataclass(frozen=True)
class Spend:
    committed: int = 0
    inflight: int = 0
    committed_investigate: int = 0
    inflight_investigate: int = 0

    def __post_init__(self):
        for f in fields(self):
            _amount(getattr(self, f.name), f.name)


def investigation_limit(budget: dict) -> int:
    return budget["maxUsdMicros"] * (10_000 - budget["verifyReserveBp"]) // 10_000


def estimate_input_tokens(request: dict) -> int:
    """Conservative heuristic: one token per 2 UTF-8 bytes of the canonical request
    (unverified against real tokenizers; `settle` flags any overrun)."""
    return -(-len(canonical_json(request)) // 2)


def _cost(tokens: int, per_mtok: int) -> int:
    return -(-tokens * per_mtok // 1_000_000)


def reservation(price: dict, input_tokens: int, max_output_tokens: int) -> int:
    _amount(input_tokens, "input_tokens")
    _amount(max_output_tokens, "max_output_tokens")
    in_rate = max(price["inputPerMTokUsdMicros"], price["cacheWriteInputPerMTokUsdMicros"],
                  price["cachedInputPerMTokUsdMicros"])
    return _cost(input_tokens, in_rate) + _cost(max_output_tokens, price["outputPerMTokUsdMicros"])


def _refuse(stage: str, msg: str, detail: dict) -> dict:
    return {"code": "budget-exhausted", "message": msg, "retryable": False, "stage": stage,
            "detail": detail}


def admit_model_call(budget: dict, spend: Spend, stage: str, reserve: int) -> dict | None:
    """None if admitted, else a TypedError document. Pure; use Ledger for concurrency."""
    _amount(reserve, "reserve")
    if not isinstance(spend, Spend):
        raise TypeError("spend must be a Spend")
    total = spend.committed + spend.inflight + reserve
    if total > budget["maxUsdMicros"]:
        return _refuse(stage, "run ceiling", {"wouldReach": total, "limit": budget["maxUsdMicros"]})
    if stage == "INVESTIGATE":
        inv = spend.committed_investigate + spend.inflight_investigate + reserve
        if inv > investigation_limit(budget):
            return _refuse(stage, "investigation share", {
                "wouldReach": inv, "limit": investigation_limit(budget)})
    return None


def admit_tool_call(budget: dict, run_calls: int, agent_calls: int, stage: str) -> dict | None:
    _amount(run_calls, "run_calls")
    _amount(agent_calls, "agent_calls")
    if run_calls + 1 > budget["maxToolCalls"]:
        return _refuse(stage, "run tool-call cap", {"limit": budget["maxToolCalls"]})
    if agent_calls + 1 > budget["maxToolCallsPerAgent"]:
        return _refuse(stage, "agent tool-call cap", {"limit": budget["maxToolCallsPerAgent"]})
    return None


def settle(reserve: int, usage: dict, price: dict) -> tuple[int, str, bool]:
    """Return (usdMicros, basis, overrun) for a completed live call."""
    _amount(reserve, "reserve")
    needed = ("uncachedInputTokens", "cachedInputTokens", "cacheWriteInputTokens", "outputTokens")
    if any(usage.get(k) is None for k in needed):
        partial = sum(_cost(usage[k] or 0, price[p]) for k, p in (
            ("uncachedInputTokens", "inputPerMTokUsdMicros"),
            ("cachedInputTokens", "cachedInputPerMTokUsdMicros"),
            ("cacheWriteInputTokens", "cacheWriteInputPerMTokUsdMicros"),
            ("outputTokens", "outputPerMTokUsdMicros")))
        usd = max(reserve, partial)
        return usd, "estimated", usd > reserve
    for k in needed:
        _amount(usage[k], k)
    usd = (_cost(usage["uncachedInputTokens"], price["inputPerMTokUsdMicros"])
           + _cost(usage["cachedInputTokens"], price["cachedInputPerMTokUsdMicros"])
           + _cost(usage["cacheWriteInputTokens"], price["cacheWriteInputPerMTokUsdMicros"])
           + _cost(usage["outputTokens"], price["outputPerMTokUsdMicros"]))
    return usd, "measured", usd > reserve


class Ledger:
    """Per-run, thread-safe reservation ledger. Keys are call ids (unique within the run;
    across runs use canonical.scoped_key). Every reserve ends in exactly one of settle,
    retain (outcome unknown: charge the reservation) or release (definitely not billed)."""

    def __init__(self, budget: dict):
        from .schema import require
        self.budget = require("Budget", budget)
        self._lock = threading.Lock()
        self._open: dict[str, tuple[str, int]] = {}
        self._committed = self._committed_inv = 0
        self.overruns: list[str] = []

    def spend(self) -> Spend:
        with self._lock:
            return self._spend()

    def _spend(self) -> Spend:
        inflight = sum(a for _, a in self._open.values())
        inflight_inv = sum(a for s, a in self._open.values() if s == "INVESTIGATE")
        return Spend(self._committed, inflight, self._committed_inv, inflight_inv)

    def reserve(self, key: str, stage: str, amount: int) -> dict | None:
        """Atomically admit and hold `amount`; returns a TypedError document on refusal."""
        _amount(amount, "amount")
        with self._lock:
            if key in self._open:
                raise ValueError(f"reservation {key} already open")
            err = admit_model_call(self.budget, self._spend(), stage, amount)
            if err is None:
                self._open[key] = (stage, amount)
            return err

    def _close(self, key: str, charge: int) -> None:
        if key not in self._open:
            raise ValueError(f"reservation {key!r} is not open")
        stage, amount = self._open.pop(key)
        self._committed += charge
        if stage == "INVESTIGATE":
            self._committed_inv += charge
        if charge > amount:
            self.overruns.append(key)

    def settle(self, key: str, usd_micros: int) -> None:
        _amount(usd_micros, "usd_micros")
        with self._lock:
            self._close(key, usd_micros)

    def retain(self, key: str) -> int:
        """Outcome unknown (timeout, stream cut, 5xx): charge the full reservation."""
        with self._lock:
            if key not in self._open:
                raise ValueError(f"reservation {key!r} is not open")
            amount = self._open[key][1]
            self._close(key, amount)
            return amount

    def release(self, key: str, outcome: str) -> None:
        if not release_allowed(outcome):
            raise ValueError(f"cannot release on outcome {outcome!r}; use retain()")
        with self._lock:
            self._close(key, 0)


def release_allowed(outcome: str) -> bool:
    """True only when the provider definitely did not process (bill) the call (D2)."""
    return outcome in RELEASABLE_OUTCOMES


def effective_retry_limits(budget: dict, caps: dict) -> tuple[int, int]:
    """(retries, repairs) for one logical call (D7)."""
    return (min(budget["maxRetriesPerCall"], caps["maxRetries"]), min(1, caps["maxRepairs"]))


def deadline_state(budget: dict, elapsed_sec: float) -> str:
    """'ok' | 'soft' (no new agents, VERIFY drains) | 'hard' (stop all calls)."""
    if not isinstance(elapsed_sec, (int, float)) or isinstance(elapsed_sec, bool) \
            or elapsed_sec != elapsed_sec or elapsed_sec < 0:
        raise ValueError("elapsed_sec must be a non-negative number")
    if elapsed_sec >= budget["wallClockSec"]:
        return "hard"
    if elapsed_sec >= budget["softDeadlineSec"]:
        return "soft"
    return "ok"


HOST_STOP_RECORDING_V1 = "host-stop@1"  # experimental: stop position = (stage, scope, afterSeq); adjacent gates at one seq collide
HOST_STOP_RECORDING_V2 = "host-stop@2"  # adds a per-stage gateOrdinal, unique across EVERY Engine.gate check
HOST_STOP_RECORDING_VERSIONS = (HOST_STOP_RECORDING_V1, HOST_STOP_RECORDING_V2)
HOST_STOP_RECORDING = HOST_STOP_RECORDING_V2   # Plan budget `hostStopRecording`: Engine.gate stops are trace events (latest)


def stage_ceiling(stage: str, budget: dict | None = None) -> int | None:
    """Effective ceiling of a stage: the Plan budget's `stageCeilingsSec` entry, else the legacy table value.
    A budget without the key (every core and legacy Plan) keeps the table exactly."""
    configured = (budget or {}).get("stageCeilingsSec")
    if configured is not None and stage in configured:
        return configured[stage]
    return STAGE_CEILING_SEC[stage]


def stage_deadline_exceeded(stage: str, stage_elapsed_sec: float, budget: dict | None = None) -> bool:
    ceiling = stage_ceiling(stage, budget)
    return ceiling is not None and stage_elapsed_sec >= ceiling


_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z")


def parse_timestamp(ts) -> tuple:
    """Comparable UTC instant for a contract Timestamp; ValueError for anything else."""
    m = _TS.fullmatch(ts) if isinstance(ts, str) else None
    if m is None:
        raise ValueError(f"not a contract timestamp: {ts!r}")
    base = datetime.datetime(*(int(x) for x in m.groups()[:6]), tzinfo=datetime.timezone.utc)
    return base, int((m.group(7) or "0").ljust(9, "0"))


def check_spend_authorization(auth: dict, profile: dict, budget: dict,
                              now_iso: str) -> list[str]:
    """Problems that forbid a live run under `auth` (empty list = allowed). `auth` must come
    from trusted operator config; ReviewRun.spendAuthorization = authorization_digest(auth)."""
    from .schema import validate
    problems = [str(i) for i in validate("SpendAuthorization", auth)]
    problems += [str(i) for i in validate("ModelProfile", profile)]
    problems += [str(i) for i in validate("Budget", budget)]
    if problems:
        return problems
    if parse_timestamp(now_iso) >= parse_timestamp(auth["expiresAt"]):
        problems.append("authorization expired")
    for name, role in profile["roles"].items():
        if role["provider"] not in auth["providers"]:
            problems.append(f"{name}: provider {role['provider']} not authorized")
        if role["model"] not in auth["models"]:
            problems.append(f"{name}: model {role['model']} not authorized")
        if not role["resolved"]:
            problems.append(f"{name}: model not resolved")
    if budget["maxUsdMicros"] > auth["maxUsdMicrosPerRun"]:
        problems.append("Plan ceiling exceeds the authorized per-run ceiling")
    return problems


def authorization_digest(auth: dict) -> str:
    return digest(auth)


def check_request_authorized(auth: dict, request: dict) -> list[str]:
    """GATEWAY DUTY (RR8): call before every live ModelRequest, not only per profile."""
    problems = []
    if request.get("provider") not in auth["providers"]:
        problems.append(f"provider {request.get('provider')!r} not authorized")
    if request.get("model") not in auth["models"]:
        problems.append(f"model {request.get('model')!r} not authorized")
    return problems


def admit_total(auth: dict, spent_total_usd_micros: int, reserve: int, stage: str) -> dict | None:
    """GATEWAY DUTY (RR7): maxUsdMicrosTotal spans runs. The contract cannot see other runs;
    the gateway must persist spend per authorization (outside this ledger) and call this
    before each reservation. Nothing enforces the total unless the gateway does."""
    total = _amount(spent_total_usd_micros, "spent_total") + _amount(reserve, "reserve")
    if total > auth["maxUsdMicrosTotal"]:
        return _refuse(stage, "authorization total", {
            "wouldReach": total, "limit": auth["maxUsdMicrosTotal"]})
    return None
