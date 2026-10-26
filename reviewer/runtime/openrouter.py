"""OpenRouter bridge: ProviderResult for provider=anthropic requests.

Hard rules: opt-in construction; authenticated HTTPS to openrouter.ai only; fixed endpoints; no redirect
following; exact model-ID allowlist; provider pinned with fallbacks off; no `models`, `route` or `plugins`
fields; bounded request/response/time; errors map to a fixed set of codes (never `budget-exhausted`, so a
provider refusal cannot be mistaken for an admission refusal on replay - gateway NEW1); the key and error
bodies are never persisted."""

from __future__ import annotations

import http.client
import hashlib
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal

from reviewer.contracts import is_turn_schema
from reviewer.contracts.redaction import redact
from reviewer.gateway.auth import AuthorizationHandle
from reviewer.gateway.errors import AuthorizationError, typed_error
from reviewer.gateway.providers import ProviderResult

from . import schemas
from .catalog import (ALLOWED_ROUTER_MODELS, PRICE_VERSION, TRIAL_TOTAL_USD_MICROS, token_priced_micros,
                      worst_case_router_micros)
from .envfile import Secret
from .receipts import RuntimeLedger, accountable_cost, make_scope, micros_from_usd_text, ESTIMATED_BASES

HOST = "openrouter.ai"
CHAT_PATH = "/api/v1/chat/completions"
KEY_PATH = "/api/v1/key"
GENERATION_PATH = "/api/v1/generation"
MAX_REQUEST_BYTES = 8 << 20
MAX_RESPONSE_BYTES = 4 << 20
DEFAULT_TIMEOUT_SEC = 120
MAX_RAW_TEXT = 1_000_000
MAX_WATCHDOG_JOIN_SEC = 1.0
MESSAGE_ROLES = ("system", "user", "assistant")
_PARSE_ERRORS = (ValueError, UnicodeError, RecursionError, MemoryError)
TOKEN_PARAM_KEYS = ("maxOutputTokens", "max_tokens", "max_output_tokens")
PROVIDER_SLUG = "anthropic"
_REJECTED = frozenset({400, 401, 402, 403, 404, 413, 422})     # documented not-processed rejections
_ERROR_CODES = ("provider-error", "provider-timeout")


class TransportTimeout(Exception):
    def __init__(self, sent: bool):
        self.sent = sent


class TransportError(Exception):
    def __init__(self, sent: bool):
        self.sent = sent


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str
    headers: dict = field(repr=False)          # carries Authorization: never repr'd or persisted
    body: bytes | None
    timeout: float
    max_response_bytes: int


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict
    body: bytes
    truncated: bool = False


class HttpsTransport:
    """The only real network code. Host is fixed; certificates are verified; redirects are returned,
    never followed; the body is read in bounded chunks. `req.timeout` is a TOTAL wall-clock deadline for the
    whole exchange (connect, TLS, request, headers, body): the exchange runs in a daemon worker, the caller
    waits at most until the deadline, and on expiry the socket is shut down so a slow-drip peer cannot hold the
    call (or the reservation) past it."""

    def __call__(self, req: HttpRequest) -> HttpResponse:
        deadline = time.monotonic() + req.timeout
        st = {"conn": None, "sent": False, "out": None, "aborted": False}
        lock, done = threading.Lock(), threading.Event()

        def left() -> float:
            return deadline - time.monotonic()

        def work():
            conn = None
            try:
                conn = http.client.HTTPSConnection(HOST, 443, timeout=max(0.05, left()), context=ssl.create_default_context())
                with lock:
                    st["conn"] = conn
                conn.connect()                     # a failure here means nothing was sent
                with lock:                         # F12 fence: after the caller aborted, NOTHING may be sent
                    if st["aborted"]:
                        raise TransportTimeout(False)
                    st["sent"] = True              # from here the request may have left, even if a write fails midway
                conn.putrequest(req.method, req.path, skip_host=False, skip_accept_encoding=True)
                for k, v in req.headers.items():
                    conn.putheader(k, v)
                if req.body is not None:
                    conn.putheader("Content-Length", str(len(req.body)))
                self._settimeout(conn, left())
                conn.endheaders(req.body)
                self._settimeout(conn, left())
                r = conn.getresponse()
                chunks, total, truncated = [], 0, False
                while True:
                    if left() <= 0:
                        raise TransportTimeout(True)
                    self._settimeout(conn, left())
                    piece = r.read1(65536)
                    if not piece:
                        break
                    total += len(piece)
                    if total > req.max_response_bytes:
                        truncated = True
                        break
                    chunks.append(piece)
                st["out"] = HttpResponse(r.status, {k.lower(): v for k, v in r.getheaders()}, b"".join(chunks), truncated)
            except TransportTimeout as e:
                st["out"] = e
            except (socket.timeout, TimeoutError):
                st["out"] = TransportTimeout(st["sent"])
            except (OSError, http.client.HTTPException, ssl.SSLError, ValueError, AttributeError):
                st["out"] = TransportError(st["sent"])
            except BaseException:  # noqa: BLE001 - never leave the caller waiting on a crashed worker
                st["out"] = TransportError(st["sent"])
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                done.set()

        worker = threading.Thread(target=work, name="openrouter-exchange", daemon=True)
        worker.start()
        if not done.wait(max(0.0, left())):
            with lock:                         # decide sent/not-sent and forbid any later send in ONE step
                st["aborted"] = True
                sent = st["sent"]
            self._abort(st, lock)
            worker.join(MAX_WATCHDOG_JOIN_SEC)
            raise TransportTimeout(sent)
        out = st["out"]
        if isinstance(out, Exception):
            raise out from None
        return out

    @staticmethod
    def _settimeout(conn, seconds: float) -> None:
        if conn.sock is not None:
            conn.sock.settimeout(max(0.05, seconds))

    @staticmethod
    def _abort(st, lock) -> None:
        """Deadline expired: shut the socket down at the OS level (bypassing the TLS layer, which would otherwise
        drop its state under the worker) so any blocked recv in the worker returns at once."""
        with lock:
            conn = st["conn"]
        sock = None if conn is None else conn.sock
        if sock is not None:
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except (OSError, ValueError):
                pass


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _loads(data: bytes):
    def bad(_):
        raise ValueError("non-finite number")
    return json.loads(data.decode("utf-8"), parse_float=Decimal, parse_constant=bad, object_pairs_hook=_no_dupes)


def _tok(v):
    return v if type(v) is int and v >= 0 else None


def _usage(u: dict, model: str) -> tuple[dict, dict]:
    """-> (contract Usage, receipt facts). Unknown stays None. prompt_tokens includes cached and cache-write
    tokens (assumption verified by the canary: tokenPriced vs router cost in the receipt)."""
    u = u if isinstance(u, dict) else {}
    prompt, out = _tok(u.get("prompt_tokens")), _tok(u.get("completion_tokens"))
    det = u.get("prompt_tokens_details") if isinstance(u.get("prompt_tokens_details"), dict) else {}
    cached = _tok(det.get("cached_tokens")) if "cached_tokens" in det else 0 if prompt is not None else None
    write = _tok(det.get("cache_write_tokens")) if "cache_write_tokens" in det else 0 if prompt is not None else None
    cdet = u.get("completion_tokens_details") if isinstance(u.get("completion_tokens_details"), dict) else {}
    reasoning = _tok(cdet.get("reasoning_tokens"))
    uncached = None
    if prompt is not None and cached is not None and write is not None and prompt >= cached + write:
        uncached = prompt - cached - write
    else:
        cached = write = None            # inconsistent split: the whole input split is unknown
    usage = {"uncachedInputTokens": uncached, "cachedInputTokens": cached, "cacheWriteInputTokens": write,
             "outputTokens": out, "reasoningTokens": reasoning}
    priced = None
    if None not in (uncached, cached, write, out):
        priced = token_priced_micros(model, uncached, cached, write, out, prompt)
    cost = u.get("cost")
    up = (u.get("cost_details") or {}).get("upstream_inference_cost") if isinstance(u.get("cost_details"), dict) else None
    facts = {"routerCostUsd": None if cost is None else str(cost)[:64], "routerCostUsdMicros": micros_from_usd_text(cost)
             if cost is not None else None, "tokenPricedUsdMicros": priced,
             "upstreamInferenceCostUsd": None if up is None else str(up)[:64],
             "upstreamInferenceCostUsdMicros": micros_from_usd_text(up) if up is not None else None,
             "isByok": u.get("is_byok") if type(u.get("is_byok")) is bool else None}
    facts["costBasis"] = "router-reported" if facts["routerCostUsdMicros"] is not None else "unknown"
    if priced is not None and facts["routerCostUsdMicros"] is not None:
        facts["costDeltaUsdMicros"] = facts["routerCostUsdMicros"] - priced
    return usage, facts


def _content_text(message) -> str | None:
    c = message.get("content") if isinstance(message, dict) else None
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        parts = [p.get("text") for p in c if isinstance(p, dict) and p.get("type") == "text"]
        if parts and all(isinstance(x, str) for x in parts):
            return "".join(parts)
    return None


class OpenRouterProvider:
    """Not constructible without an explicit opt-in, a Secret, a trusted authorization capped at the $50
    trial total, a durable SpendBook and a RuntimeLedger. `call` never raises for request content."""
    name = "anthropic"

    def __init__(self, *, enabled: bool, key: Secret, authorization: AuthorizationHandle, book, ledger: RuntimeLedger,
                 transport=None, default_timeout_sec: int = DEFAULT_TIMEOUT_SEC, run_scope: str | None = None):
        if enabled is not True:
            raise AuthorizationError("live OpenRouter adapter requires enabled=True (opt-in)")
        if not isinstance(key, Secret):
            raise AuthorizationError("key must be a Secret from load_openrouter_key")
        if not isinstance(authorization, AuthorizationHandle):
            raise AuthorizationError("needs a trusted AuthorizationHandle")
        auth = authorization.auth
        if "anthropic" not in auth["providers"]:
            raise AuthorizationError("authorization does not cover provider anthropic")
        if not set(auth["models"]) & set(ALLOWED_ROUTER_MODELS) or auth["maxUsdMicrosTotal"] > TRIAL_TOTAL_USD_MICROS:
            raise AuthorizationError("authorization must name an allowed router model and total <= the $50 trial cap")
        if getattr(book, "store", None) is None or book.handle.digest != authorization.digest:
            raise AuthorizationError("a durable (file-backed) SpendBook for this authorization is required")
        if not isinstance(ledger, RuntimeLedger) or ledger.cap > TRIAL_TOTAL_USD_MICROS:
            raise AuthorizationError("a RuntimeLedger capped at <= $50 is required")
        self._key, self._ledger = key, ledger
        self.scope = make_scope(run_scope)     # F3: execution scope for ledger call keys; never sent to the provider
        self._models = frozenset(set(auth["models"]) & set(ALLOWED_ROUTER_MODELS))
        self._transport = transport or HttpsTransport()
        self._timeout = default_timeout_sec
        self.calls = 0

    # ------------------------------------------------------------------ helpers
    def _err(self, code, msg, outcome, *, retryable=False, **detail) -> ProviderResult:
        assert code in _ERROR_CODES or outcome == "not-sent"
        text = self._key.scrub(msg)
        d = {k: v for k, v in detail.items() if v is not None}
        return ProviderResult(None, typed_error(code, text, retryable=retryable, detail=d or None), outcome)

    def _headers(self, with_body: bool) -> dict:
        h = {"Authorization": "Bearer " + self._key.reveal(), "Accept": "application/json",
             "User-Agent": "reviewer-runtime/S0B-01a"}
        if with_body:
            h["Content-Type"] = "application/json"
        return h

    def call_key(self, key: tuple) -> str:
        """Ledger key = execution scope + the gateway's (stage, role, agentId, ordinal, attempt). The gateway tuple
        has no run id, so without the scope a second run on the shared durable ledger would collide with the
        first. Duplicates are detected within one scope. The scope is not part of the model-visible request."""
        return self.scope + "|" + "|".join(str(x) for x in key)

    def build_body(self, request: dict) -> tuple[dict | None, dict]:
        """-> (body, info). body None => refusal with info['why']. Pure; used by snapshot tests."""
        if request.get("provider") != "anthropic":
            return None, {"why": "OpenRouter adapter serves provider=anthropic only"}
        model = request.get("model")
        if model not in self._models:
            return None, {"why": "model is not in the exact authorized router allowlist"}
        out_name = schemas.select_schema(request)      # request.outputSchema, legal for the role; Turn schemas included
        if out_name is None:
            return None, {"why": "role/outputSchema mismatch"}
        if request.get("tools"):
            return None, {"why": "tool requests are not supported by this adapter (no native tool continuations)"}
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        caps = [params[k] for k in TOKEN_PARAM_KEYS if type(params.get(k)) is int and params[k] > 0]
        if not caps:
            return None, {"why": "params must carry an explicit positive output token cap (maxOutputTokens)"}
        max_tokens = min(caps)
        raw_msgs = request["messages"]
        if not isinstance(raw_msgs, list) or not raw_msgs or not all(isinstance(m, dict) for m in raw_msgs):
            return None, {"why": "messages must be a non-empty list of objects"}
        if any(m.get("role") == "tool" for m in raw_msgs):
            return None, {"why": "tool-role messages are not supported"}
        if any(m.get("role") not in MESSAGE_ROLES or type(m.get("content")) is not str for m in raw_msgs):
            return None, {"why": "every message must have a system/user/assistant role and string-only content"}
        msgs = [{"role": m["role"], "content": m["content"]} for m in raw_msgs]
        dropped = sorted(k for k in params if k not in TOKEN_PARAM_KEYS and k != "timeoutSec")
        body = {"model": model, "messages": msgs, "max_tokens": max_tokens, "stream": False,
                "response_format": {"type": "json_schema", "json_schema": {
                    "name": out_name, "strict": True, "schema": schemas.provider_schema(out_name, "anthropic")}},
                "provider": {"order": [PROVIDER_SLUG], "only": [PROVIDER_SLUG], "allow_fallbacks": False,
                             "require_parameters": True}}
        timeout = params.get("timeoutSec") if type(params.get("timeoutSec")) is int and params["timeoutSec"] > 0 else self._timeout
        return body, {"maxTokens": max_tokens, "droppedParams": dropped, "timeout": min(timeout, 900), "outName": out_name}

    # ------------------------------------------------------------------ the gateway seam
    def call(self, request: dict, key: tuple) -> ProviderResult:
        self.calls += 1
        ck = self.call_key(key)
        try:
            body, info = self.build_body(request)
        except Exception:  # noqa: BLE001 - malformed request content must refuse, not crash
            body, info = None, {"why": "request could not be projected"}
        if body is None:
            return self._err("provider-error", info["why"], "not-sent", reason="request-refused")
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(raw) > MAX_REQUEST_BYTES:
            return self._err("provider-error", "request body exceeds the adapter bound", "not-sent", reason="request-too-large")
        worst = info["worst"] = worst_case_router_micros(body["model"], len(raw), info["maxTokens"])
        refusal = self._ledger.admit(ck, worst, model=body["model"])
        if refusal is not None:
            return self._err("provider-error", "runtime aggregate trial ledger refused the call", "not-sent", **refusal)
        t0 = time.monotonic()
        base = {"callKey": ck, "kind": "openrouter", "model": body["model"], "requestBytes": len(raw),
                "droppedParams": info["droppedParams"], "priceVersion": PRICE_VERSION,
                "schemaProjection": schemas.PROJECTION_VERSION, "schemaName": info["outName"],
                "schemaSha256": hashlib.sha256(json.dumps(body["response_format"]["json_schema"]["schema"], sort_keys=True).encode()).hexdigest(),
                "billingKind": "openrouter-usd"}
        req = HttpRequest("POST", CHAT_PATH, self._headers(True), raw, float(info["timeout"]), MAX_RESPONSE_BYTES)
        try:
            resp = self._transport(req)
        except TransportTimeout as e:
            return self._finish_err(base, t0, "provider-timeout", "provider request timed out", "unknown" if e.sent else "not-sent",
                                    retryable=True, errorKind="timeout")
        except TransportError as e:
            return self._finish_err(base, t0, "provider-error", "provider connection failed", "unknown" if e.sent else "not-sent",
                                    retryable=True, errorKind="connection")
        except Exception:  # noqa: BLE001 - a broken transport after the intent record: outcome unknown
            return self._finish_err(base, t0, "provider-error", "transport failed", "unknown", errorKind="transport-crash")
        try:
            return self._interpret(resp, base, t0, info)
        except Exception:  # noqa: BLE001 - a charged response must leave a result row, never an orphan intent
            return self._finish_err(base, t0, "provider-error", "provider response could not be processed", "unknown",
                                    errorKind="interpret-crash", http=resp.status,
                                    responseBytes=len(resp.body) if isinstance(resp.body, (bytes, bytearray)) else None)

    def _finish_err(self, base, t0, code, msg, outcome, *, retryable=False, errorKind, http=None, generation=None,
                    responseBytes=None):
        self._ledger.finish(base["callKey"], **{k: v for k, v in base.items() if k != "callKey"}, outcome=outcome,
                            errorKind=errorKind, httpStatus=http, generationId=generation, responseBytes=responseBytes,
                            latencyMs=int((time.monotonic() - t0) * 1000), costBasis="unknown")
        return self._err(code, msg, outcome, retryable=retryable, reason=errorKind, httpStatus=http)

    def _interpret(self, resp: HttpResponse, base, t0, info) -> ProviderResult:
        st = resp.status
        if resp.truncated:
            return self._finish_err(base, t0, "provider-error", "provider response exceeded the size bound", "unknown",
                                    errorKind="oversize-response", http=st)
        if st in _REJECTED:
            return self._finish_err(base, t0, "provider-error", f"provider rejected the request (HTTP {st})",
                                    "rejected-before-processing", errorKind=f"http-{st}", http=st)
        if st == 408:
            return self._finish_err(base, t0, "provider-timeout", "provider reported a timeout", "unknown",
                                    retryable=True, errorKind="http-408", http=st)
        if st != 200:
            return self._finish_err(base, t0, "provider-error", f"provider returned HTTP {st}", "unknown",
                                    retryable=st == 429 or st >= 500, errorKind=f"http-{st}", http=st)
        try:
            doc = _loads(resp.body)
            if not isinstance(doc, dict):
                raise ValueError("not an object")
        except _PARSE_ERRORS:            # incl. RecursionError on a deeply nested body
            return self._finish_err(base, t0, "provider-error", "provider returned an unreadable body", "unknown",
                                    errorKind="malformed-body", http=st, responseBytes=len(resp.body))
        gen = doc.get("id") if isinstance(doc.get("id"), str) and len(doc["id"]) <= 200 else None
        if "error" in doc:        # errors during generation can arrive with HTTP 200; assume it may have billed
            return self._finish_err(base, t0, "provider-error", "provider reported an in-band error", "unknown",
                                    errorKind="in-band-error", http=st, generation=gen)
        choices = doc.get("choices")
        choice = choices[0] if isinstance(choices, list) and len(choices) == 1 and isinstance(choices[0], dict) else None
        resolved = doc.get("model")
        if choice is None or not isinstance(resolved, str) or not 0 < len(resolved) <= 128:
            return self._finish_err(base, t0, "provider-error", "provider response missing choice or model", "unknown",
                                    errorKind="malformed-response", http=st, generation=gen)
        usage, facts = _usage(doc.get("usage"), base["model"])
        acc, basis = accountable_cost(facts, info["worst"])
        facts.update(accountableUsdMicros=acc, accountableBasis=basis, accountableEstimated=basis in ESTIMATED_BASES)
        text = _content_text(choice.get("message"))
        finish = choice.get("finish_reason") if isinstance(choice.get("finish_reason"), str) else None
        status, output = "invalid-output", None
        if text is not None and finish not in ("length", "content_filter"):
            try:
                value = _loads(text.encode("utf-8"))
                value = schemas.normalize_output(info["outName"], json.loads(json.dumps(value, default=float)), "anthropic")
                if not schemas.local_issues(info["outName"], value):
                    status, output = "ok", value
            except _PARSE_ERRORS:        # nested/odd model output: charged, recorded as invalid-output, never a crash
                pass
        raw_text = None
        # Turn answers keep the original provider JSON (entry-form args) beside the normalized envelope; plain ok answers do not.
        if text is not None and (status != "ok" or is_turn_schema(info["outName"])):
            raw_text = self._key.scrub(redact(text[:MAX_RAW_TEXT])[0])
        response = {"status": status, "resolvedModel": resolved, "output": output, "rawText": raw_text, "usage": usage}
        if gen:
            response["providerRequestId"] = gen
        prov = doc.get("provider") if isinstance(doc.get("provider"), str) and len(doc["provider"]) <= 64 else None
        self._ledger.finish(base["callKey"], **{k: v for k, v in base.items() if k != "callKey"}, outcome="processed",
                            httpStatus=st, generationId=gen, resolvedModel=resolved, finishReason=finish,
                            usage=usage, providerSlug=prov, responseBytes=len(resp.body),
                            latencyMs=int((time.monotonic() - t0) * 1000), note=None if status == "ok" else "invalid-output",
                            contentSha256=None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest(),
                            **facts)
        return ProviderResult(response, None, "processed")

    # ------------------------------------------------------------------ evidence helpers (host launcher)
    def key_status(self) -> dict | None:
        """GET /api/v1/key -> {limit, usage, remaining} in USD (strings) or None. Evidence for cost deltas."""
        try:
            r = self._transport(HttpRequest("GET", KEY_PATH, self._headers(False), None, 30.0, 1 << 16))
            d = _loads(r.body).get("data") if r.status == 200 else None
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(d, dict):
            return None
        out = {k: (None if d.get(k) is None else str(d[k])) for k in ("limit", "usage", "limit_remaining")}
        self._ledger.note(type="note", keyLimitUsd=out["limit"], keyUsageUsd=out["usage"], keyRemainingUsd=out["limit_remaining"])
        return out

    def generation(self, generation_id: str) -> dict | None:
        """GET /api/v1/generation?id= -> selected cost/token facts for reconciliation, or None."""
        if not isinstance(generation_id, str) or not generation_id.replace("-", "").replace("_", "").isalnum() or len(generation_id) > 200:
            return None
        try:
            r = self._transport(HttpRequest("GET", f"{GENERATION_PATH}?id={generation_id}", self._headers(False), None, 30.0, 1 << 18))
            d = _loads(r.body).get("data") if r.status == 200 else None
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(d, dict):
            return None
        keep = ("id", "total_cost", "upstream_inference_cost", "model", "tokens_prompt", "tokens_completion",
                "native_tokens_prompt", "native_tokens_completion", "native_tokens_cached", "native_tokens_reasoning",
                "is_byok", "provider_name", "finish_reason")
        return {k: (str(d[k]) if isinstance(d.get(k), Decimal) else d[k]) for k in keep if k in d}
