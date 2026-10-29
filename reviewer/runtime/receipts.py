"""Runtime-only billing receipts and the independent aggregate trial ledger.

Receipts are append-only JSONL (0600, O_NOFOLLOW, flock). They record usage, the provider-reported
cost and generation IDs - never request bodies, Authorization headers, secrets or error bodies.

Cost vocabulary, never mixed:
  routerCostUsdMicros      what OpenRouter reported charging (`usage.cost` / generation `total_cost`)
  upstreamInferenceCost... what the upstream provider charged (`cost_details.upstream_inference_cost`). For a
                           BYOK call (`isByok`) this is billed to the provider account, NOT inside the router
                           cost, and still draws down the key limit while `key.usage` stays 0
  tokenPricedUsdMicros     catalog token prices x reported tokens; a computation, not a bill
  accountableUsdMicros     what the aggregate cap counts for the call (see `accountable_cost`); labelled by
                           `accountableBasis`. Raw facts above are kept as reported; this is derived
  apiEquivalentEstimate... Terra via subscription CLI; an estimate, NOT a paid API dollar
Unknown is null, never zero. A key `usage` of 0 is never evidence that a call was free.

`RuntimeLedger` is a second, defence-in-depth cap on top of the gateway's SpendBook: it sums actual
router-reported costs and counts any call with unknown cost at its worst-case bound."""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import secrets
import threading
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
from pathlib import Path

from reviewer.contracts.redaction import redact_json

from .scoring_budget import CATEGORIES, DEFAULT_CATEGORY, validate_admission

MAX_LOG_BYTES = 32 << 20
SAFE_KEYS = frozenset({
    "type", "at", "callKey", "kind", "model", "resolvedModel", "resolvedModelSource", "generationId",
    "httpStatus", "outcome", "errorKind", "finishReason", "usage", "routerCostUsd", "routerCostUsdMicros",
    "upstreamInferenceCostUsdMicros", "tokenPricedUsdMicros", "costDeltaUsdMicros", "costBasis",
    "billingKind", "apiEquivalentEstimateUsdMicros", "worstCaseUsdMicros", "requestBytes", "responseBytes",
    "latencyMs", "droppedParams", "isolation", "schemaProjection", "schemaName", "schemaSha256", "contentSha256", "priceVersion", "note", "providerSlug",
    "isByok", "upstreamInferenceCostUsd", "accountableUsdMicros", "accountableBasis", "accountableEstimated",
    "keyLimitUsd", "keyRemainingUsd"})
ESTIMATED_BASES = frozenset({"unknown-worst-case", "zero-unverifiable-worst-case", "suspect-floored-to-token-priced",
                             "byok-upstream-missing"})
ACK_REASONS = frozenset({"generation-not-found"})    # host lookup of the call's generation id returned no record
ACK_MICROS_FIELDS = ("keyRemainingBeforeMicros", "keyRemainingAfterMicros", "sumOtherOfficialMicros")
ACK_EVIDENCE_FIELDS = frozenset({"reasonCode", *ACK_MICROS_FIELDS, "note"})
ACK_NOTE_MAX = 500
_SCOPE = re.compile(r"[A-Za-z0-9._-]{1,64}")
MAX_USD = Decimal(1_000_000)           # an absurd reported dollar value is unusable (-> unknown), not a huge int


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def micros_from_usd_text(text) -> int | None:
    """Exact ceil of a decimal-dollar value to micros; None for anything unusable (non-numeric, negative,
    non-finite or absurdly large, so a hostile exponent cannot force a giant integer)."""
    try:
        d = Decimal(str(text))
    except (InvalidOperation, ValueError):
        return None
    if not d.is_finite() or d < 0 or d > MAX_USD:
        return None
    with localcontext() as ctx:                 # any rounding inside the arithmetic errs upward
        ctx.prec, ctx.rounding = 100, ROUND_CEILING
        return int((d * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


def make_scope(value=None) -> str:
    """Execution scope for ledger call keys. The gateway's key tuple carries no run id, so each host run (or
    provider instance) owns a scope; duplicate detection applies within it. Not part of any model request."""
    if value is None:
        return "s" + secrets.token_hex(8)
    if not isinstance(value, str) or _SCOPE.fullmatch(value) is None:
        raise ValueError("run_scope must match [A-Za-z0-9._-]{1,64}")
    return value


def accountable_cost(f: dict, worst: int) -> tuple[int, str]:
    """-> (USD micros the aggregate cap counts for one call, basis). Never trusts a zero for a processed call.

      router unknown                  -> worst-case bound            unknown-worst-case
      upstream value unusable         -> worst-case bound            unknown-worst-case
      upstream absent, isByok True    -> router + token-priced       byok-upstream-missing
      upstream absent                 -> router                      router-only
      isByok False (explicit)         -> max(router, upstream)       router-inclusive  (upstream is inside the total)
      isByok True                     -> router + upstream           byok-additive
      isByok absent, upstream known   -> router + upstream           ambiguous-sum     (may double count: safe side)
      then, against the catalog token arithmetic:
        total 0 or < 1/10 of it       -> max(total, token-priced)    suspect-floored-to-token-priced
        total 0, token-priced unknown -> worst-case bound            zero-unverifiable-worst-case
    """
    router, up = f.get("routerCostUsdMicros"), f.get("upstreamInferenceCostUsdMicros")
    priced, byok = f.get("tokenPricedUsdMicros"), f.get("isByok")
    if router is None or (up is None and f.get("upstreamInferenceCostUsd") is not None):   # unusable value: unknown
        return worst, "unknown-worst-case"
    if up is None and byok is True:                     # BYOK bills upstream; none reported: router fee + arithmetic
        return (router + priced, "byok-upstream-missing") if priced else (worst, "unknown-worst-case")
    if up is None:
        cost, basis = router, "router-only"
    elif byok is False:
        cost, basis = max(router, up), "router-inclusive"
    else:
        cost, basis = router + up, "byok-additive" if byok is True else "ambiguous-sum"
    if not priced:                                       # None (no arithmetic) or 0 (a processed call cannot use 0 tokens)
        return (worst, "zero-unverifiable-worst-case") if cost == 0 else (cost, basis)
    if cost * 10 < priced:
        return priced, "suspect-floored-to-token-priced"
    return cost, basis


def _intent_category(intent: dict) -> str:
    c = intent.get("category", DEFAULT_CATEGORY)
    if type(c) is not str or c not in CATEGORIES:
        raise ValueError("ledger holds an intent with an unknown category; refusing")
    return c


class RuntimeLedger:
    def __init__(self, path, cap_usd_micros: int, *, clock=_now):
        if type(cap_usd_micros) is not int or cap_usd_micros < 1:
            raise ValueError("cap must be a positive integer of USD micros")
        self.path, self.cap, self._clock = Path(path), cap_usd_micros, clock
        self._lock = threading.Lock()
        self._owned: dict[str, int] = {}     # scoring call key -> pid of the live admission in THIS instance

    def _txn(self, fn):
        with self._lock:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                size = os.fstat(fd).st_size
                if size > MAX_LOG_BYTES:
                    raise ValueError("runtime ledger too large; refusing")
                rows = [json.loads(x) for x in os.pread(fd, size, 0).decode("utf-8").splitlines() if x.strip()]
                result, new = fn(rows)
                if new:
                    blob = "".join(json.dumps(r, sort_keys=True) + "\n" for r in new).encode()
                    os.write(fd, blob)
                    os.fsync(fd)
                return result
            finally:
                os.close(fd)

    @staticmethod
    def _calls(rows, category=None) -> tuple[list, int]:
        """-> ([(callKey, result row or None, facts or None, micros, basis or None)], counted intents) for every intent
        (in `category` if given). A call recorded as not processed is omitted (it counts nothing); basis None = no
        result row (crashed/in flight, counted at its worst case). Row types other than intent/result/reconcile
        (note, acknowledge, ...) carry no cost and are ignored here."""
        intents, results, recon = {}, {}, {}
        for r in rows:
            t = r["type"]
            (intents if t == "intent" else results if t == "result" else recon if t == "reconcile" else {})[r.get("callKey")] = r
        if category is not None:
            intents = {k: i for k, i in intents.items() if _intent_category(i) == category}
        out = []
        for k, i in intents.items():
            res = results.get(k)
            if res is None:
                out.append((k, None, None, i["worstCaseUsdMicros"], None))
                continue
            if res["outcome"] in ("not-sent", "rejected-before-processing"):
                continue
            facts = {**res, **{x: recon[k][x] for x in ("routerCostUsdMicros", "upstreamInferenceCostUsdMicros", "isByok")
                               if k in recon and x in recon[k]}}
            micros, basis = accountable_cost(facts, i["worstCaseUsdMicros"])
            out.append((k, res, facts, micros, basis))
        return out, len(intents)

    @classmethod
    def _tally(cls, rows, category=None) -> dict:
        """Replays every row, old or new, through `accountable_cost` (rows written before the BYOK fix carry no
        `isByok`/`accountable*` fields and are re-derived from their raw facts). A `reconcile` row overlays the
        authoritative generation facts for its call key; nothing is ever rewritten. An `acknowledge` row is not
        cost and changes no total.

        `category` (None = every call, the legacy shape) keeps only intents of that category. An intent without a
        `category` is a legacy review row; an unrecognised stored category fails closed when filtering."""
        calls, n = cls._calls(rows, category)
        known = estimated = unknown = router_sum = upstream_sum = 0
        for _k, _res, facts, micros, basis in calls:
            if basis is None:
                unknown += micros                         # crashed/in flight: bounded, counted
                continue
            router_sum += facts.get("routerCostUsdMicros") or 0
            upstream_sum += facts.get("upstreamInferenceCostUsdMicros") or 0
            if basis == "unknown-worst-case":
                unknown += micros
            elif basis in ESTIMATED_BASES:
                estimated += micros
            else:
                known += micros
        return {"knownUsdMicros": known, "estimatedUsdMicros": estimated, "unknownBoundUsdMicros": unknown,
                "routerReportedUsdMicros": router_sum, "upstreamReportedUsdMicros": upstream_sum, "calls": n}

    @classmethod
    def _unresolved_scoring(cls, rows) -> dict:
        """-> {callKey: (result row or None, micros, basis or None)}: the scoring calls that make up the category's
        unknownBound + estimated total (no result, unknown-worst-case or an ESTIMATED basis after any reconcile
        overlay), with a non-zero amount."""
        return {k: (res, m, b) for k, res, _f, m, b in cls._calls(rows, "scoring")[0]
                if m > 0 and (b is None or b == "unknown-worst-case" or b in ESTIMATED_BASES)}

    @staticmethod
    def _acknowledged(rows) -> set:
        return {(r.get("callKey"), r.get("generationId")) for r in rows if r["type"] == "acknowledge"}

    @classmethod
    def _hold(cls, rows) -> dict | None:
        """Startup-hold decision over parsed rows (raises ValueError on an unrecognised stored category). An unresolved
        scoring call is passed over only when an `acknowledge` row names its call key AND the generation id of its
        result row; an intent without a result (or a result without a generation id) is never acknowledged."""
        acks = cls._acknowledged(rows)
        for k, (res, _m, _b) in cls._unresolved_scoring(rows).items():
            gid = res.get("generationId") if res is not None else None
            if not (isinstance(gid, str) and gid and (k, gid) in acks):
                return {"reason": "prior-unresolved-scoring-exposure"}
        return None

    @staticmethod
    def _committed(t: dict) -> int:
        return t["knownUsdMicros"] + t["estimatedUsdMicros"] + t["unknownBoundUsdMicros"]

    def totals(self, category=None) -> dict:
        """Default (category None) is the legacy all-calls shape. A category filter adds a `category` key."""
        if category is not None and (type(category) is not str or category not in CATEGORIES):
            raise ValueError("unknown ledger category")
        t = self._txn(lambda rows: (self._tally(rows, category), []))
        out = {**t, "capUsdMicros": self.cap, "committedUsdMicros": self._committed(t)}
        return out if category is None else {**out, "category": category}

    def scoring_startup_hold(self) -> dict | None:
        """Read-only startup guard for a NEW scoring process. None = no prior unresolved scoring exposure; else a
        fixed dict. Unresolved = a scoring intent with no result row, or a scoring call whose cost is still unknown
        (e.g. outcome `unknown`) or only ESTIMATED (unverifiable-zero, byok-upstream-missing, suspect-floored), not
        overlaid by a reconcile row and not acknowledged (see `acknowledge`: one call by call key + generation id,
        whose worst-case charge stays counted in every total and cap). Resolved/reconciled costs and review exposure
        never hold. Never mutates (a missing ledger file is not created) and never releases or edits anything;
        an unreadable ledger or unrecognised stored category also holds (fail closed)."""
        if not os.path.lexists(self.path):
            return None
        try:
            return self._txn(lambda rows: (self._hold(rows), []))
        except (ValueError, OSError):
            return {"reason": "scoring-ledger-unreadable"}

    def admit(self, call_key: str, worst_case: int, *, model: str, category: str = DEFAULT_CATEGORY,
              category_cap: int | None = None, aggregate_ceiling: int | None = None) -> dict | None:
        """Atomically record intent; None = admitted, else a refusal detail dict (nothing was sent).

        Review (default) is the legacy admission. Scoring needs both trusted caps (validated before any file
        access): `scoring-campaign-cap` when scoring committed + worst > category_cap, `review-reserve` when
        all-category committed + worst > aggregate_ceiling, plus the unchanged runtime cap and duplicate check, all
        inside one flock transaction. The category is stored on the intent, so a crashed or in-flight call stays in it."""
        if type(worst_case) is not int or worst_case < 0:
            raise ValueError("worst_case must be a non-negative integer of USD micros")
        validate_admission(category, category_cap, aggregate_ceiling)

        def f(rows):
            t = self._tally(rows)
            used = self._committed(t)
            if used + worst_case > self.cap:
                return {"reason": "runtime-aggregate-cap", "wouldReach": used + worst_case, "limit": self.cap}, []
            if category == "scoring":
                sc = self._committed(self._tally(rows, "scoring"))
                if sc + worst_case > category_cap:
                    return {"reason": "scoring-campaign-cap", "wouldReach": sc + worst_case, "limit": category_cap}, []
                if used + worst_case > aggregate_ceiling:
                    return {"reason": "review-reserve", "wouldReach": used + worst_case, "limit": aggregate_ceiling}, []
            if any(r["type"] == "intent" and r["callKey"] == call_key for r in rows):
                return {"reason": "duplicate-call-key"}, []
            row = {"type": "intent", "at": self._clock(), "callKey": call_key, "model": model,
                   "worstCaseUsdMicros": worst_case}
            if category != DEFAULT_CATEGORY:
                row["category"] = category           # review rows stay byte-identical to the legacy shape
            return None, [row]
        res = self._txn(f)
        if res is None and category == "scoring":
            self._owned[call_key] = os.getpid()      # trusted live admission by this instance in this process
        return res

    def finish(self, call_key: str, **fields) -> None:
        bad = set(fields) - SAFE_KEYS
        if bad:
            raise ValueError(f"unsafe receipt fields: {sorted(bad)}")
        if "type" in fields or "callKey" in fields:     # a result row's type and call key are never caller-chosen
            raise ValueError("finish() fields cannot set the row type or call key")
        row, _ = redact_json({"type": "result", "at": self._clock(), "callKey": call_key, **fields})

        def f(rows):
            intent = next((r for r in reversed(rows) if r["type"] == "intent" and r.get("callKey") == call_key), None)
            if intent is not None and intent.get("category") == "scoring":      # review keeps the legacy rules
                if any(r["type"] == "result" and r.get("callKey") == call_key for r in rows):
                    raise ValueError("a scoring call already has a result; it cannot be overwritten")
                if self._owned.get(call_key) != os.getpid():
                    raise ValueError("a scoring result needs the live admission of this ledger instance")
            return None, [row]
        self._txn(f)

    def note(self, **fields) -> None:
        """Append a non-call receipt (e.g. key status snapshots)."""
        bad = set(fields) - SAFE_KEYS - {"keyLimitUsd", "keyUsageUsd", "keyRemainingUsd"}
        if bad:
            raise ValueError(f"unsafe receipt fields: {sorted(bad)}")
        if fields.get("type", "note") != "note":         # a note can never forge an intent/result/reconcile/acknowledge row
            raise ValueError("note() can only append a row of type 'note'")
        self._txn(lambda rows: (None, [{"type": "note", "at": self._clock(), **fields}]))

    def reconcile(self, call_key: str, generation: dict, *, key_status: dict | None = None, apply: bool = True) -> dict:
        """Append-only: overlay authoritative generation facts (`GET /api/v1/generation` data, fetched by the
        host/root, not here) for a call that already has a result row with the same generation id. Returns
        {"appended": bool, "before": totals, "after": totals}; apply=False
        only previews. Refuses (ValueError) a mismatched or unusable
        record; an idempotent repeat appends nothing. The key's `usage` is never consulted to lower a charge."""
        gid = generation.get("id") if isinstance(generation, dict) else None
        if not isinstance(gid, str) or not gid:
            raise ValueError("generation record has no id")
        router = micros_from_usd_text(generation.get("total_cost")) if generation.get("total_cost") is not None else None
        up = generation.get("upstream_inference_cost")
        up_m = micros_from_usd_text(up) if up is not None else None
        byok = generation.get("is_byok") if type(generation.get("is_byok")) is bool else None
        if router is None:
            raise ValueError("generation record has no usable total_cost")
        row = {"type": "reconcile", "at": self._clock(), "callKey": call_key, "generationId": gid,
               "routerCostUsd": str(generation["total_cost"]), "routerCostUsdMicros": router, "isByok": byok,
               "note": "host-fetched generation metadata"}
        if up is not None:
            row.update(upstreamInferenceCostUsd=str(up), upstreamInferenceCostUsdMicros=up_m)
        if isinstance(key_status, dict):
            for src, dst in (("limit", "keyLimitUsd"), ("limit_remaining", "keyRemainingUsd")):
                if key_status.get(src) is not None:
                    row[dst] = str(key_status[src])
        row, _ = redact_json(row)
        same = ("generationId", "routerCostUsdMicros", "upstreamInferenceCostUsdMicros", "isByok")

        def f(rows):
            res = [r for r in rows if r["type"] == "result" and r.get("callKey") == call_key]
            if not res or res[-1].get("generationId") != gid:
                raise ValueError("no result row for this call key carries that generation id")
            if res[-1]["outcome"] in ("not-sent", "rejected-before-processing"):
                raise ValueError("call was recorded as not processed")
            last = [r for r in rows if r["type"] == "reconcile" and r.get("callKey") == call_key]
            before = self._tally(rows)
            if last and all(last[-1].get(x) == row.get(x) for x in same):
                return {"appended": False, "before": before, "after": before}, []
            after = self._tally(rows + [row])
            return {"appended": apply, "before": before, "after": after}, [row] if apply else []
        out = self._txn(f)
        for side in ("before", "after"):
            out[side] = {**out[side], "capUsdMicros": self.cap, "committedUsdMicros": self._committed(out[side])}
        return out

    @staticmethod
    def _ack_evidence(evidence) -> dict:
        """Fixed-shape host evidence for `acknowledge`; stored as an audit record, never used to compute money."""
        if not isinstance(evidence, dict):
            raise ValueError("acknowledge evidence must be an object")
        bad = set(evidence) - ACK_EVIDENCE_FIELDS
        missing = {"reasonCode", *ACK_MICROS_FIELDS} - set(evidence)
        if bad or missing:
            raise ValueError(f"acknowledge evidence fields: unexpected {sorted(bad)}, missing {sorted(missing)}")
        if evidence["reasonCode"] not in ACK_REASONS:
            raise ValueError(f"acknowledge reasonCode must be one of {sorted(ACK_REASONS)}")
        for k in ACK_MICROS_FIELDS:
            v = evidence[k]
            if type(v) is not int or v < 0 or v > int(MAX_USD) * 1_000_000:
                raise ValueError(f"acknowledge evidence {k} must be a non-negative integer of USD micros")
        note = evidence.get("note")
        if note is not None and (type(note) is not str or len(note) > ACK_NOTE_MAX):
            raise ValueError(f"acknowledge evidence note must be a string of at most {ACK_NOTE_MAX} characters")
        out = {k: evidence[k] for k in ("reasonCode", *ACK_MICROS_FIELDS)}
        if note is not None:
            out["note"] = note
        return out

    def acknowledge(self, call_key: str, generation_id: str, *, evidence: dict, apply: bool) -> dict:
        """Append-only recovery for the scoring startup hold, for ONE scoring call whose cost can never be resolved
        (e.g. the host's `GET /api/v1/generation` lookup returns no record, so `reconcile` is impossible).

        The `acknowledge` row names the call by call key + generation id and stores the host evidence (redacted).
        Effect: `scoring_startup_hold` passes over that one call. Nothing else changes: the call's worst-case or
        estimated charge stays counted in every total, so committed spend, the runtime cap, the scoring category
        cap and the review reserve are exactly as before (`before == after` in the result). Evidence is an audit
        record and a consistency gate only; it never lowers a charge (key usage/remaining is not proof of $0).

        Refuses (ValueError) unless: the ledger exists (never created); the call's last result row carries
        `generation_id`; the call is a scoring intent; its cost basis is `unknown-worst-case` (no cost facts at all,
        not overlaid by a reconcile row; estimated bases are refused); and the evidence is
        consistent: keyRemainingBefore - keyRemainingAfter - sumOtherOfficial (the implied charge of this call) lies
        within [0, the amount the ledger counts for it]. A repeat with the same evidence appends nothing; a repeat
        with different evidence is refused.
        apply=False only previews. Returns {"appended", "alreadyAcknowledged", "before", "after", "scoringBefore",
        "scoringAfter", "holdBefore", "holdAfter", "countedUsdMicros", "countedBasis", "impliedCallUsdMicros"}."""
        if not os.path.lexists(self.path):              # never creates a ledger, not even in preview
            raise ValueError("ledger does not exist; refusing to create a new book")
        if not isinstance(call_key, str) or not call_key:
            raise ValueError("call key must be a non-empty string")
        if not isinstance(generation_id, str) or not generation_id or len(generation_id) > 200:
            raise ValueError("generation id must be a non-empty string")
        if type(apply) is not bool:
            raise ValueError("apply must be a bool")
        ev = self._ack_evidence(evidence)
        implied = ev["keyRemainingBeforeMicros"] - ev["keyRemainingAfterMicros"] - ev["sumOtherOfficialMicros"]
        row, _ = redact_json({"type": "acknowledge", "at": self._clock(), "callKey": call_key,
                              "generationId": generation_id, "scope": "scoring-startup-hold",
                              "impliedCallUsdMicros": implied, **ev})
        if row["callKey"] != call_key or row["generationId"] != generation_id:
            raise ValueError("call key or generation id would not survive redaction; refusing")

        def f(rows):
            res = [r for r in rows if r["type"] == "result" and r.get("callKey") == call_key]
            if not res or res[-1].get("generationId") != generation_id:
                raise ValueError("no result row for this call key carries that generation id")
            intent = next((r for r in reversed(rows) if r["type"] == "intent" and r.get("callKey") == call_key), None)
            if intent is None or intent.get("category") != "scoring":
                raise ValueError("not a scoring call; only the scoring startup hold can be acknowledged")
            before, sb, hb = self._tally(rows), self._tally(rows, "scoring"), self._hold(rows)
            if (call_key, generation_id) in self._acknowledged(rows):
                prior = [r for r in rows if r["type"] == "acknowledge" and r.get("callKey") == call_key
                         and r.get("generationId") == generation_id][-1]
                if any(prior.get(k) != row.get(k) for k in ACK_EVIDENCE_FIELDS):
                    raise ValueError("call is already acknowledged with different evidence; nothing appended")
                return {"appended": False, "alreadyAcknowledged": True, "before": before, "after": before,
                        "scoringBefore": sb, "scoringAfter": sb, "holdBefore": hb, "holdAfter": hb}, []
            unresolved = self._unresolved_scoring(rows)
            if call_key not in unresolved:
                raise ValueError("call cost is resolved (known, reconciled or not processed); nothing to acknowledge")
            _r, counted, basis = unresolved[call_key]
            if basis != "unknown-worst-case":            # only a call with no cost facts at all; estimates stay held
                raise ValueError("only an unknown-worst-case call can be acknowledged")
            if implied < 0 or implied > counted:
                raise ValueError("evidence is inconsistent: implied charge is outside [0, counted charge]")
            full = {**row, "countedUsdMicros": counted, "countedBasis": basis}     # audit only; never read as cost
            new = rows + [full]
            after, sa = self._tally(new), self._tally(new, "scoring")
            if after != before or sa != sb:                  # defence in depth: an acknowledgement never moves money
                raise ValueError("acknowledge would change ledger totals; refusing")
            return {"appended": apply, "alreadyAcknowledged": False, "before": before, "after": after,
                    "scoringBefore": sb, "scoringAfter": sa, "holdBefore": hb, "holdAfter": self._hold(new),
                    "countedUsdMicros": counted, "countedBasis": basis, "impliedCallUsdMicros": implied}, \
                [full] if apply else []
        out = self._txn(f)
        for side in ("before", "after"):
            out[side] = {**out[side], "capUsdMicros": self.cap, "committedUsdMicros": self._committed(out[side])}
        for side in ("scoringBefore", "scoringAfter"):
            out[side] = {**out[side], "committedUsdMicros": self._committed(out[side])}
        return out
