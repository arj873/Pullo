"""The model gateway: live (synthetic only in Stage 0A), strict replay, or disabled.

One `Gateway` serves one run. Every attempt (first call, retry, repair) is a new admission:
the request is redacted, validated against the profile role and (live) the trusted
authorization, hashed, reserved against the run ledger AND the total spend book, then answered
by the provider adapter (live) or by the verified recording (strict replay). Replay owns no
provider adapters at all, so it cannot make a real call.
"""

from __future__ import annotations

import copy
import datetime as dt
import hmac
import re
import threading
from dataclasses import dataclass, field
from typing import Callable

from reviewer.contracts import ContractViolation, require
from reviewer.contracts.budget import (Ledger, check_spend_authorization, effective_retry_limits,
                                       estimate_input_tokens, release_allowed, reservation, settle)
from reviewer.contracts.canonical import call_id, cost_id, request_hash, scoped_key
from reviewer.contracts.redaction import redact_json
from reviewer.contracts.stages import STAGES

from .auth import AuthorizationHandle, SpendBook, parse_ts
from .errors import AuthorizationError, GatewayConfigError, SettlementError, TraceError, typed_error
from .providers import ProviderResult, default_providers
from .script import ROLES, SLUG
from .trace import LoadedTrace, Recorder, error_charge_class

MODES = ("live", "strict-replay", "disabled")
RETRYABLE_CODES = frozenset({"provider-error", "provider-timeout"})
_OUTPUT_PARAM_KEYS = ("maxOutputTokens", "max_tokens", "max_output_tokens")


@dataclass
class AttemptInfo:
    call_id: str | None
    attempt: int
    outcome: str                     # ok | invalid-output | error code
    charge_usd_micros: int = 0
    overrun: bool = False


@dataclass
class CallResult:
    response: dict | None
    error: dict | None
    attempts: list[AttemptInfo] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.response is not None and self.response["status"] == "ok"

    @property
    def output(self):
        return None if self.response is None else self.response["output"]


class Gateway:
    def __init__(self, *, mode: str, profile: dict, budget: dict, run_id: str,
                 providers: dict | None = None, authorization: AuthorizationHandle | None = None,
                 book: SpendBook | None = None, replay: LoadedTrace | None = None,
                 recorder: Recorder | None = None, clock: Callable[[], str] | None = None,
                 cost_kind: str = "review", eval_run_id: str | None = None, eval_case_id: str | None = None,
                 expected_trace_digest: str | None = None):
        if mode not in MODES:
            raise GatewayConfigError(f"mode must be one of {MODES}")
        self.mode = mode
        self.profile = require("ModelProfile", copy.deepcopy(profile))
        self.budget = require("Budget", copy.deepcopy(budget))
        if not isinstance(run_id, str) or not re.fullmatch(r"run_[0-9a-f]{16}", run_id):
            raise GatewayConfigError("run_id must be a contract run id")
        self.run_id = run_id
        self.profile_ref = f"{self.profile['id']}@{self.profile['version']}"
        self.cost_kind, self.eval_run_id, self.eval_case_id = cost_kind, eval_run_id, eval_case_id
        self._own_recorder = recorder is None
        self.recorder = recorder or Recorder(run_id)
        if self.recorder.run_id != run_id:
            raise GatewayConfigError("recorder belongs to a different run id than this gateway")
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self._lock = threading.Lock()
        self.live_calls = self.replayed_calls = 0
        self.new_spend_usd_micros = self.replayed_usd_micros = 0
        self.retained: list[str] = []
        self.overruns: list[dict] = []
        self._consumed: set[int] = set()
        self._used_calls: set[str] = set()
        self.auth = authorization
        self.book = book
        self.providers: dict = {}
        self.replay = replay
        ceiling = self.budget["maxUsdMicros"]
        if mode == "live":
            if not isinstance(authorization, AuthorizationHandle):
                raise AuthorizationError("live mode needs a trusted AuthorizationHandle")
            if replay is not None:
                raise GatewayConfigError("live mode takes no replay trace")
            problems = check_spend_authorization(authorization.auth, self.profile, self.budget, self._now())
            if problems:
                raise AuthorizationError("; ".join(problems))
            if not isinstance(book, SpendBook):
                raise GatewayConfigError(
                    "live mode needs an explicit SpendBook shared by every gateway under this authorization: "
                    "a shared in-memory book covers one process, a file-backed book covers other processes "
                    "and continued evaluations; a gateway never creates its own")
            if book.handle.digest != authorization.digest:
                raise AuthorizationError("spend book belongs to a different authorization")
            self.book = book
            self.providers = dict(providers) if providers is not None else default_providers()
            ceiling = min(ceiling, authorization.auth["maxUsdMicrosPerRun"])
        elif mode == "strict-replay":
            if authorization is not None or providers or book is not None:
                raise GatewayConfigError("strict replay is offline: no authorization, providers or spend book")
            if not isinstance(replay, LoadedTrace):
                raise GatewayConfigError("strict replay needs a trace from load_trace()")
            if not isinstance(expected_trace_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_trace_digest):
                raise GatewayConfigError(
                    "strict replay needs expected_trace_digest: the sha256 of the recorded trace bytes, taken from "
                    "trusted configuration or a separately pinned run artifact, never from the trace itself")
            if not replay.complete:
                raise GatewayConfigError("strict replay needs a complete recording (the trace has no run.end)")
            if not hmac.compare_digest(replay.byte_digest, expected_trace_digest):
                raise TraceError("trace bytes do not match the pinned expected_trace_digest")
        else:
            if replay is not None or authorization is not None:
                raise GatewayConfigError("disabled gateway takes neither trace nor authorization")
        if mode != "strict-replay" and expected_trace_digest is not None:
            raise GatewayConfigError("expected_trace_digest only applies to strict replay")
        self._ledger = Ledger({**self.budget, "maxUsdMicros": ceiling}) if ceiling >= 1 else None
        if self.recorder.events:
            bad = self._binding_problem()
            if bad is not None:
                raise (AuthorizationError if bad[0] == "auth" else GatewayConfigError)(bad[1])

    def _binding_problem(self) -> tuple[str, str] | None:
        """Recorder run.start versus this gateway (id, mode, authorization). Checked at construction
        when already started and again on EVERY attempt, so the order of construction and
        Recorder.start() cannot skip it. An internally created recorder has no run to bind to."""
        events = self.recorder.events
        if not events:
            if self._own_recorder:
                return None
            return "config", "the recorder has no run.start yet: record it before the first call"
        started = events[0]
        if started["type"] != "run.start":
            return "config", "the recorder's first event is not run.start"
        run = started["run"]
        if run["id"] != self.run_id or (self.mode != "disabled" and run["mode"] != self.mode):
            return "config", "recorder run.start does not match this gateway's run id/mode"
        if self.mode == "live" and run.get("spendAuthorization") != self.auth.digest:
            return "auth", "run.spendAuthorization is not the digest of the trusted authorization"
        return None

    # ------------------------------------------------------------------ public
    @property
    def authorization_digest(self) -> str | None:
        return None if self.auth is None else self.auth.digest

    def report(self) -> dict:
        return {"mode": self.mode, "liveCalls": self.live_calls, "replayedCalls": self.replayed_calls,
                "newSpendUsdMicros": self.new_spend_usd_micros, "replayedUsdMicros": self.replayed_usd_micros,
                "retainedCalls": list(self.retained), "overruns": list(self.overruns),
                "spend": None if self._ledger is None else vars(self._ledger.spend()),
                "total": None if self.book is None else self.book.totals(),
                "unconsumedRecordedCalls": self.unconsumed()}

    def unconsumed(self) -> int:
        """Recorded model calls a replay never asked for (0 for non-replay gateways)."""
        if self.replay is None:
            return 0
        return self.replay.model_calls - len(self._consumed)

    def call(self, stage: str, role: str, agent_id: str, ordinal: int, request: dict, *,
             repair: Callable[[dict], dict] | None = None) -> CallResult:
        """One logical call: retries (retryable provider errors) and at most one repair
        (invalid-output), each admitted separately. Never raises for request content."""
        if stage not in STAGES or role not in ROLES or not isinstance(agent_id, str) \
                or not SLUG.fullmatch(agent_id) or type(ordinal) is not int or not 0 <= ordinal <= 10**6:
            raise ValueError("stage/role/agent_id/ordinal are not valid call coordinates")
        spec = self.profile["roles"][role]
        retries, repairs = effective_retry_limits(self.budget, spec["caps"])
        res = CallResult(None, None)
        attempt = retries_used = repairs_used = 0
        repair_of = retry_of = None
        while True:
            out = self._attempt(stage, role, agent_id, ordinal, attempt, request, repair_of, retry_of)
            repair_of = retry_of = None          # provenance names only the attempt it belongs to
            res.attempts.append(out["info"])
            if out["error"] is not None:
                err = out["error"]
                if err["retryable"] and err["code"] in RETRYABLE_CODES and retries_used < retries:
                    retries_used += 1
                    attempt += 1
                    retry_of = out["info"].call_id
                    continue
                res.error = err
                return res
            resp = out["response"]
            if resp["status"] == "ok":
                res.response = resp
                return res
            if repair is not None and repairs_used < repairs:
                try:
                    request = repair(copy.deepcopy(resp))
                except Exception as e:  # noqa: BLE001 - a broken repair builder must not crash the run
                    res.error = typed_error("internal", f"repair builder failed: {type(e).__name__}", stage=stage)
                    return res
                repairs_used += 1
                attempt += 1
                repair_of = out["info"].call_id
                continue
            code = "repair-exhausted" if repairs_used else "schema-invalid"
            res.response = None
            res.error = typed_error(code, "model output failed its schema", stage=stage,
                                    detail={"repairsUsed": repairs_used})
            self.recorder.append("error", error=res.error)
            return res

    # ------------------------------------------------------------------ one admitted attempt
    def _now(self) -> str:
        return self._clock()

    def _refuse(self, info: AttemptInfo, err: dict, record: bool = True) -> dict:
        info.outcome = err["code"]
        # a trace cannot begin with an error event: with no run.start yet there is nothing to append to
        if record and self.recorder.events:
            self.recorder.append("error", error=err)
        return {"error": err, "response": None, "info": info}

    def _bound(self, c) -> dict | None:
        """A refusal when the recorder's run.start no longer matches this gateway, else None."""
        bad = self._binding_problem()
        if bad is None:
            return None
        return self._refuse(c["info"], typed_error("contract-violation", bad[1], stage=c["stage"]))

    def _check_request(self, role: str, req: dict) -> dict | None:
        spec = self.profile["roles"][role]
        def bad(why, code="contract-violation"):
            return typed_error(code, why)
        if req["role"] != role:
            return bad("request role differs from the call role")
        if req["profile"] != self.profile_ref:
            return bad("request profile is not this run's profile")
        for k in ("provider", "model", "promptVersion", "outputSchema"):
            if req[k] != spec[k]:
                return bad(f"request {k} differs from the profile role")
        if not spec["resolved"]:
            return bad("profile role is unresolved", "model-unresolved")
        params = req["params"]
        if isinstance(params, dict):
            for k in _OUTPUT_PARAM_KEYS:
                v = params.get(k)
                if v is not None and (type(v) is not int or v > spec["caps"]["maxOutputTokens"]):
                    return bad(f"params.{k} exceeds the role output cap")
        return None

    def _attempt(self, stage, role, agent_id, ordinal, attempt, request, repair_of, retry_of=None) -> dict:
        info = AttemptInfo(None, attempt, "")
        if not isinstance(request, dict):
            return self._refuse(info, typed_error("contract-violation", "request is not an object", stage=stage))
        req, red = redact_json(request)
        try:
            require("ModelRequest", req)
            rhash = request_hash(req)
        except (ContractViolation, ValueError) as e:
            return self._refuse(info, typed_error("contract-violation", f"request rejected: {e}", stage=stage))
        err = self._check_request(role, req)
        if err is not None:
            return self._refuse(info, err)
        cid = info.call_id = call_id(stage, role, agent_id, ordinal, attempt)
        key = (stage, role, agent_id, ordinal, attempt)
        ctx = dict(stage=stage, role=role, agent_id=agent_id, ordinal=ordinal, attempt=attempt, req=req,
                   rhash=rhash, cid=cid, red=red, repair_of=repair_of, retry_of=retry_of, info=info, key=key)
        if self.mode == "disabled":
            return self._refuse(info, typed_error("live-calls-disabled", "gateway is disabled", stage=stage))
        if self.mode == "strict-replay":
            return self._bound(ctx) or self._replay_attempt(ctx)
        return self._live_attempt(ctx)

    # -- live / recording
    def _live_attempt(self, c) -> dict:
        req, stage, info = c["req"], c["stage"], c["info"]
        auth = self.auth.auth
        try:
            expired = parse_ts(self._now()) >= parse_ts(auth["expiresAt"])
        except ValueError:
            expired = True            # an unreadable clock fails closed
        if expired:
            return self._refuse(info, typed_error("live-calls-disabled", "authorization expired or clock invalid", stage=stage))
        if req["provider"] not in auth["providers"] or req["model"] not in auth["models"]:
            return self._refuse(info, typed_error("live-calls-disabled",
                                                  "request provider/model is not authorized", stage=stage))
        provider = self.providers.get(req["provider"])
        if provider is None:
            return self._refuse(info, typed_error("live-calls-disabled", "no adapter for this provider", stage=stage))
        unbound = self._bound(c)
        if unbound is not None:
            return unbound
        spec = self.profile["roles"][c["role"]]
        amount = reservation(spec["price"], estimate_input_tokens(req), spec["caps"]["maxOutputTokens"])
        rkey = scoped_key(self.run_id, c["cid"])
        with self._lock:
            reused = c["cid"] in self._used_calls
            self._used_calls.add(c["cid"])
        if reused:
            return self._refuse(info, typed_error(
                "contract-violation", "this call identity (stage, role, agentId, ordinal, attempt) was already used "
                "in this run; every logical call needs its own agentId/ordinal", stage=stage))
        refuse = self._reserve(rkey, stage, amount)
        if refuse is not None:
            return self._finish_error(c, refuse, amount, 0, None, refused=True)
        with self._lock:
            self.live_calls += 1
        try:
            result = provider.call(copy.deepcopy(req), c["key"])
            if not isinstance(result, ProviderResult):
                raise TypeError("adapter returned a non-ProviderResult")
        except Exception as e:  # noqa: BLE001 - adapter crashed after the request may have left: charge it
            book_err = self._retain(rkey)
            err = typed_error("provider-error", f"adapter failed: {type(e).__name__}", stage=stage)
            return self._settled(c, book_err, self._finish_error(c, err, amount, amount, None, retained=True))
        if result.error is not None:
            return self._settle_error(c, result, rkey, amount)
        return self._settle_response(c, result, rkey, amount, spec)

    def _reserve(self, rkey, stage, amount) -> dict | None:
        if self._ledger is None:
            return typed_error("budget-exhausted", "run ceiling is zero", stage=stage, detail={"scope": "run"})
        err = self._ledger.reserve(rkey, stage, amount)
        if err is not None:
            err["detail"] = {**(err.get("detail") or {}), "scope": "run"}
            return err
        if self.book is not None:
            try:
                err = self.book.reserve(rkey, amount)
            except Exception:
                self._ledger.release(rkey, "not-sent")      # the provider was never contacted
                raise
            if err is not None:
                self._ledger.release(rkey, "not-sent")
                err["stage"] = stage
                return err
        return None

    # The run ledger is closed first and cannot fail; the book may (torn line, size cap, disk). A
    # book failure after provider contact must not erase the evidence, so these return the book
    # exception and `_settled` records the call before raising it.
    def _book_close(self, op, *args):
        if self.book is None:
            return None
        try:
            getattr(self.book, op)(*args)
        except Exception as e:  # noqa: BLE001
            return e
        return None

    def _retain(self, rkey):
        self._ledger.retain(rkey)
        return self._book_close("retain", rkey)

    def _commit(self, rkey, usd):
        self._ledger.settle(rkey, usd)
        return self._book_close("settle", rkey, usd)

    def _release(self, rkey, outcome):
        self._ledger.release(rkey, outcome)
        return self._book_close("release", rkey, outcome)

    def _settled(self, c, book_err, out):
        """Return `out`, or - when the book failed after the call was processed - record that and raise."""
        if book_err is None:
            return out
        self.recorder.append("error", error=typed_error(
            "internal", f"spend book failed after provider contact ({type(book_err).__name__}); the book "
            "reservation stays open and the charge is recorded here", stage=c["stage"],
            detail={"callId": c["cid"]}))
        raise SettlementError(f"spend book failed after the provider answered call {c['cid']}: "
                              f"{type(book_err).__name__}") from book_err

    def _settle_error(self, c, result, rkey, amount) -> dict:
        err = redact_json(result.error)[0]
        try:
            require("TypedError", err)
        except ContractViolation:
            err = typed_error("provider-error", "provider returned an invalid error document", stage=c["stage"])
            result = ProviderResult(None, err, "unknown")
        # the adapter's outcome decides release versus retain; stamp it so replay can recompute the charge
        err = require("TypedError", {**err, "detail": {**(err["detail"] if isinstance(err.get("detail"), dict) else {}),
                                                        "providerOutcome": result.outcome}})
        if release_allowed(result.outcome):
            book_err = self._release(rkey, result.outcome)
            return self._settled(c, book_err, self._finish_error(c, err, amount, 0, None))
        book_err = self._retain(rkey)
        return self._settled(c, book_err, self._finish_error(c, err, amount, amount, None, retained=True))

    def _settle_response(self, c, result, rkey, amount, spec) -> dict:
        resp, rcounts = redact_json(result.response)
        try:
            require("ModelResponse", resp)
        except ContractViolation:
            book_err = self._retain(rkey)
            err = typed_error("contract-violation", "provider response failed its schema", stage=c["stage"],
                              detail={"providerOutcome": "processed"})
            return self._settled(c, book_err, self._finish_error(c, err, amount, amount, None, retained=True))
        usd, basis, over = settle(amount, resp["usage"], spec["price"])
        book_err = self._commit(rkey, usd)
        for k, n in rcounts.items():
            c["red"][k] = c["red"].get(k, 0) + n
        if resp["resolvedModel"] != c["req"]["model"]:
            # billed for the call, but the answer came from a model nobody authorized; its usage is
            # recorded (and only here) so replay can recompute the charge
            err = typed_error("contract-violation", "response came from a different model than requested",
                              stage=c["stage"], detail={"resolvedModel": resp["resolvedModel"],
                                                        "providerOutcome": "processed"})
            return self._settled(c, book_err, self._finish_error(c, err, amount, usd, resp["usage"], over=over,
                                                                 billed=True))
        return self._settled(c, book_err, self._finish_ok(c, resp, amount, usd, over, basis))

    # -- shared event/cost bookkeeping
    def _basis(self, provider, settled_basis, *, known_none=False):
        if provider == "synthetic":
            return "synthetic"
        return settled_basis or ("measured" if known_none else "estimated")

    def _cost_doc(self, c, amount, usd, usage, basis, over, *, replay_of=None):
        doc = {"id": cost_id(c["cid"]), "kind": self.cost_kind, "basis": basis, "usage": copy.deepcopy(usage),
               "usdMicros": usd, "reservedUsdMicros": amount, "priceVersion": self.profile["roles"][c["role"]]["price"]["priceVersion"]
               if self.profile["roles"][c["role"]]["price"] else None,
               "runId": self.run_id, "stage": c["stage"], "role": c["role"], "callId": c["cid"],
               "provider": c["req"]["provider"], "model": c["req"]["model"]}
        if self.cost_kind == "eval":
            doc["evalRunId"], doc["evalCaseId"] = self.eval_run_id, self.eval_case_id
        if over:
            doc["overrun"] = True
        if c.get("retry_of"):
            doc["retryOf"] = c["retry_of"]
        if replay_of:
            doc["replayOf"] = replay_of
        if basis in ("measured", "estimated") and doc["priceVersion"] is None:
            doc["priceVersion"] = "unpriced@0"
        return require("CostRecord", doc)

    def _emit_call(self, c, response, error, cost):
        fields = dict(callId=c["cid"], stage=c["stage"], role=c["role"], agentId=c["agent_id"],
                      ordinal=c["ordinal"], attempt=c["attempt"], requestHash=c["rhash"],
                      request=copy.deepcopy(c["req"]), response=copy.deepcopy(response),
                      costRecordId=cost["id"], redactions=dict(c["red"]))
        if c["repair_of"]:
            fields["repairOf"] = c["repair_of"]
        if error is not None:
            fields["error"] = copy.deepcopy(error)
        self.recorder.append("model.call", **fields)
        self.recorder.append("cost", record=copy.deepcopy(cost))

    def _account(self, c, usd, over, kind):
        info = c["info"]
        info.charge_usd_micros, info.overrun = usd, over
        with self._lock:
            if kind == "live":
                self.new_spend_usd_micros += usd
            else:
                self.replayed_usd_micros += usd
                self.replayed_calls += 1
            if over:
                self.overruns.append({"callId": c["cid"], "chargedUsdMicros": usd})

    def _finish_ok(self, c, resp, amount, usd, over, basis, *, replay_cost=None):
        info = c["info"]
        info.outcome = resp["status"]
        if replay_cost is None:
            cost = self._cost_doc(c, amount, usd, resp["usage"], self._basis(c["req"]["provider"], basis), over)
            self._account(c, usd, over, "live")
        else:
            cost = replay_cost
            self._account(c, usd, over, "replay")
        self._emit_call(c, resp, None, cost)
        return {"error": None, "response": copy.deepcopy(resp), "info": info}

    def _finish_error(self, c, err, amount, usd, usage, *, retained=False, refused=False, over=False,
                      billed=False, replay_cost=None) -> dict:
        info = c["info"]
        info.outcome = err["code"]
        if retained:
            with self._lock:
                self.retained.append(c["cid"])
        if replay_cost is None:
            nulls = {k: None for k in ("uncachedInputTokens", "cachedInputTokens", "cacheWriteInputTokens",
                                       "outputTokens", "reasoningTokens")}
            basis = self._basis(c["req"]["provider"], "estimated" if (retained or billed) else None,
                                known_none=not retained and not billed)
            # a billed wrong-model answer keeps its usage: it is the only input to recompute that charge
            cost = self._cost_doc(c, amount, usd, usage if billed else nulls, basis, over)
            self._account(c, usd, over, "live")
        else:
            cost = replay_cost
            self._account(c, usd, over, "replay")
        self._emit_call(c, None, err, cost)
        return {"error": copy.deepcopy(err), "response": None, "info": info}

    # -- strict replay
    def _replay_attempt(self, c) -> dict:
        stage, info = c["stage"], c["info"]
        cands = self.replay.calls.get(c["rhash"])
        if not cands:
            return self._refuse(info, typed_error("replay-miss", "no recorded call has this request hash",
                                                  stage=stage, detail={"requestHash": c["rhash"]}))
        with self._lock:
            rec = None
            for ev in cands:
                if id(ev) in self._consumed:
                    continue
                if (ev["stage"], ev["role"], ev["agentId"], ev["ordinal"], ev["attempt"]) == c["key"]:
                    rec = ev
                    self._consumed.add(id(ev))
                    break
            if rec is None:
                free = [e for e in cands if id(e) not in self._consumed]
        if rec is None:
            if free:
                return self._refuse(info, typed_error(
                    "replay-mismatch", "this request hash is recorded only under a different call identity",
                    stage=stage, detail={"requestHash": c["rhash"]}))
            return self._refuse(info, typed_error(
                "replay-miss", "every recorded occurrence of this request hash was already consumed",
                stage=stage, detail={"requestHash": c["rhash"], "recorded": len(cands)}))
        out = self._replay_matched(c, rec)
        if out["error"] is not None and out["error"]["code"] == "replay-mismatch":
            with self._lock:
                self._consumed.discard(id(rec))      # nothing was reproduced: the recording is still unconsumed
        return out

    def _replay_matched(self, c, rec) -> dict:
        stage = c["stage"]
        recorded_cost = self.replay.costs[rec["costRecordId"]]
        if rec.get("repairOf") != c["repair_of"] or recorded_cost.get("retryOf") != c["retry_of"]:
            return self._mismatch(c, "repair/retry provenance differs from the recording")
        spec = self.profile["roles"][c["role"]]
        amount = reservation(spec["price"], estimate_input_tokens(c["req"]), spec["caps"]["maxOutputTokens"])
        rkey = scoped_key(self.run_id, c["cid"])
        if amount != recorded_cost["reservedUsdMicros"]:
            return self._mismatch(c, "recomputed reservation differs from the recording (profile or request drift)")
        refuse = self._reserve(rkey, stage, amount)
        recorded_refusal = rec.get("error", {}).get("code") == "budget-exhausted"
        if refuse is not None or recorded_refusal:
            # Only the run ledger exists offline. A recorded refusal reproduces when this run's ledger
            # refuses in the same scope; a recorded TOTAL refusal (a spend book that replay does not have)
            # reproduces when the run ledger admits, since the live order is run ledger first, then total.
            if recorded_refusal:
                scope = (rec["error"].get("detail") or {}).get("scope")
                ok = (refuse is None and scope == "total") or \
                     (refuse is not None and scope == "run" and (refuse.get("detail") or {}).get("scope") == "run")
            else:
                ok = False
            if refuse is None:
                self._ledger.release(rkey, "not-sent")
            if not ok:
                return self._mismatch(c, "budget admission differs from the recording")
            return self._finish_error(c, copy.deepcopy(rec["error"]), amount, 0, None,
                                      replay_cost=self._replayed_cost(c, recorded_cost, amount))
        resp = rec["response"]
        if resp is not None:
            usd, _, over = settle(amount, resp["usage"], spec["price"])
            if usd != recorded_cost["usdMicros"]:
                self._ledger.release(rkey, "not-sent")
                return self._mismatch(c, "recomputed charge differs from the recorded cost")
            self._ledger.settle(rkey, usd)
            return self._finish_ok(c, copy.deepcopy(resp), amount, usd, over, None,
                                   replay_cost=self._replayed_cost(c, recorded_cost, amount))
        # errored call: recompute the charge from the recorded error exactly as the live path decided it
        err = rec["error"]
        klass = error_charge_class(err)
        usd = 0 if klass in ("refused", "released") else amount
        over = False
        if klass == "billed":
            usd, _, over = settle(amount, recorded_cost["usage"], spec["price"])
        if recorded_cost["usdMicros"] not in (usd, None) or (recorded_cost["usdMicros"] is None and usd != amount):
            self._ledger.release(rkey, "not-sent")
            return self._mismatch(c, "recomputed charge of the errored call differs from the recorded cost")
        self._ledger.settle(rkey, usd)
        return self._finish_error(c, copy.deepcopy(err), amount, usd, None,
                                  retained=klass == "retained", over=over,
                                  replay_cost=self._replayed_cost(c, recorded_cost, amount))

    def _replayed_cost(self, c, recorded, amount) -> dict:
        doc = {k: v for k, v in recorded.items() if k not in ("runId", "evalRunId", "evalCaseId", "replayOf", "basis")}
        doc.update(basis="replayed", replayOf=recorded["id"], runId=self.run_id)
        if self.cost_kind == "eval":
            doc["kind"] = "eval"
            doc["evalRunId"], doc["evalCaseId"] = self.eval_run_id, self.eval_case_id
        else:
            doc["kind"] = self.cost_kind
        return require("CostRecord", doc)

    def _mismatch(self, c, why) -> dict:
        return self._refuse(c["info"], typed_error("replay-mismatch", why, stage=c["stage"],
                                                   detail={"requestHash": c["rhash"]}))
