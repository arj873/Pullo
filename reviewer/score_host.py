"""Trusted scoring host, first OFFLINE milestone (SCORE-HOST-01). NOT a live entry: `run_live` refuses until the
full ticket is accepted (see ABSENT). Composes the pure producer (`reviewer.benchmark.allpairs`), strict
`pullo-score.toml`, the real score-family Gateway and the real OpenRouterProvider(category="scoring"); tests inject a
fake transport and scratch ledger/book/authorization. No gold/reviewer-pipeline imports, no env/argv/key discovery.

Phase order across the DECLARED set: all extraction -> all dedup -> gate(declared) -> exact complete-set pair fit ->
only then pair sends. A failure or does-not-fit leaves every remaining unit/phase `unsent`. Reports carry ids, counts,
digests and fixed classes only; documents (with model text) go to the external 0600 store, never into reports."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from reviewer.benchmark import allpairs as A
from reviewer.benchmark import score_prompts as P
from reviewer.benchmark.jsonio import canonical
from reviewer.benchmark.model import ScorerCase
from reviewer.contracts.budget import STANDARD_S0A_BUDGET, estimate_input_tokens, reservation
from reviewer.contracts.canonical import score_run_id
from reviewer.gateway import Gateway, Recorder, load_trace
from reviewer.gateway.errors import AuthorizationError, GatewayConfigError
from reviewer.runtime import RuntimeLedger, Secret, schemas
from reviewer.runtime.catalog import worst_case_router_micros
from reviewer.runtime.openrouter import HttpResponse, MAX_REQUEST_BYTES, OpenRouterProvider
from reviewer.runtime.scoring_budget import SCORING_AGGREGATE_CEILING_MAX, SCORING_CATEGORY_CAP_MAX
from reviewer.score_config import ScoreConfig

PER_RUN_MAX = 4_000_000
CANARY_TTL_HOURS = 24
# Requirements of SCORE-HOST-01 that this milestone does NOT implement (live entry stays refused while any remain).
ABSENT = (
    "operator launch via pullo.toml/CLI entrypoint (library API only)",
    "real env-file key loading and real HttpsTransport wiring (plan/tests use a placeholder Secret and capture transport)",
    "root-pinned launch baseline file loader; schema/policy/renderer digests beyond config+prompt pins",
    "Pullo title+body renderer into RawComment and corpus/dataset loading",
    "fresh catalog/key evidence and exact-route 3-role canary gate",
    "official cost reconcile (router 0 / upstream charge) wiring",
    "cross-process review/scoring exclusion (root serializes; only a same-process scorer lock here)",
    "full-ticket acceptance by an independent gate",
)
FULL_ACCEPTANCE = False


class ScoreHostError(ValueError):
    """Fixed-class refusal; `reason` is a short code. Never carries model, gold, path or secret text."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _need(ok, reason):
    if not ok:
        raise ScoreHostError(reason)


@dataclass(frozen=True)
class ScoreUnit:
    case: ScorerCase
    tool: str
    agent: str                                   # neutral gateway agent id (slug), assigned by the host


@dataclass(frozen=True)
class LaunchBaseline:
    """Root-pinned facts checked BEFORE the first send. Real values come from root; tests invent them."""
    declared: tuple                              # ((case_url, tool), ...) the full declared tool-case set
    config_digest: str
    prompt_sha256: tuple                         # sorted ((kind, sha256), ...)
    initial_scoring_committed: int               # runtime-ledger scoring committed at launch
    initial_all_committed: int                   # runtime-ledger all-category committed at launch
    initial_book: tuple | None = None            # (book committed, book inflight) pinned by the root baseline (live)

    @property
    def digest(self) -> str:
        core = [sorted(self.declared), self.config_digest, list(self.prompt_sha256),
                self.initial_scoring_committed, self.initial_all_committed]
        if self.initial_book is not None:
            core.append(list(self.initial_book))
        return "sha256:" + hashlib.sha256(canonical(core)).hexdigest()


def policy_digest() -> str:
    """Pinned scoring policy constants (model, omitted sampling, run/scoring/aggregate/total ceilings)."""
    return hashlib.sha256(canonical({"model": "anthropic/claude-opus-5.5", "sampling": "omit", "perRun": PER_RUN_MAX,
                                     "scoring": SCORING_CATEGORY_CAP_MAX, "aggregate": SCORING_AGGREGATE_CEILING_MAX,
                                     "total": 50_000_000, "retries": 0, "fallbacks": 0})).hexdigest()


# Preregistered canary: ONE fixed invented case, one tool, one reference; the three role probes are extract, dedup, pair.
CANARY_CASE_URL = "https://example.invalid/pullo-score-canary/1"
CANARY_TOOL = "canary-tool"
CANARY_DECLARED = ((CANARY_CASE_URL, CANARY_TOOL),)


def canary_case() -> ScorerCase:
    from reviewer.benchmark.model import Golden, RawComment, ToolReview
    c1 = "Canary comment one: the loop bound is off by one and skips the last element of the list."
    c2 = "Canary comment two: the error path returns without releasing the lock that was taken above."
    return ScorerCase(CANARY_CASE_URL, "canary/repo", None, 1, (Golden("CANARY-G1", "Off by one in the loop bound", "high", "bug"),),
                      (ToolReview(CANARY_TOOL, "canary/repo", None, (RawComment("CANARY-C1", "a.py", 1, c1, "2026-01-01T00:00:00Z"),
                                                                     RawComment("CANARY-C2", "a.py", 2, c2, "2026-01-01T00:00:00Z"))),))


PLACEHOLDER_KEY = "sk-or-v1-" + "f4k3" * 12      # the only key value the offline entry accepts (a fake, never a credential)


class CaptureTransport:
    """Fake transport for plan/tests: records requests (never the Authorization header) and answers schema-valid
    canned outputs derived from the request. This class itself opens no socket. TRUST CLAIM (honest scope): the offline
    entry accepts only an EXACT CaptureTransport instance (no subclass, no other callable). An optional `respond`
    callback is trusted Python test code the host cannot sandbox; it is not a no-network proof against a hostile callback.
    Plan/tests that need no callback should leave it None (fixed built-in script)."""

    def __init__(self, respond=None):
        self.bodies, self.respond = [], respond

    def __call__(self, req):
        body = json.loads(req.body.decode("utf-8"))
        self.bodies.append(body)
        if self.respond is not None:
            out = self.respond(body)
            if isinstance(out, Exception):
                raise out
            if isinstance(out, HttpResponse):
                return out
        else:
            out = self._default(body)
        usage = {"prompt_tokens": 300, "completion_tokens": 20, "total_tokens": 320, "cost": 0.001,
                 "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                 "completion_tokens_details": {"reasoning_tokens": 0}}
        d = {"id": f"gen-{len(self.bodies):04d}", "model": body["model"], "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(out)}}],
             "usage": usage}
        return HttpResponse(200, {}, json.dumps(d).encode())

    @staticmethod
    def _default(body):
        name = body["response_format"]["json_schema"]["name"]
        data = json.loads(body["messages"][-1]["content"])
        if name == "ScoreExtractionSegments":          # one whole-comment range per non-empty comment (bench.extract@v3)
            return {"candidates": [{"sourceCommentId": c["id"], "startSegment": 1, "endSegment": len(c["segments"])}
                                   for c in data["comments"] if c["segments"]]}
        if name == "ScoreDedup":
            return {"groups": [[c["index"]] for c in data["candidates"]]}
        return {"match": False, "confidence": 0.5}


def schema_sha256() -> str:
    return hashlib.sha256(canonical({n: schemas.provider_schema(n, "anthropic")
                                     for n in schemas.SCORE_SCHEMA_NAMES})).hexdigest()


def acquire_lock(path) -> int:
    """Non-blocking exclusive flock on the scorer lock file (0600, no symlink). The canonical shared lock for live, canary and
    reconcile is `<original stateDir>/scorer.lock`; contention is the fixed refusal `scorer-lock-held`. Caller closes the fd."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise ScoreHostError("scorer-lock-held") from None
    return fd


def _abort_trace(rec) -> None:
    """Cleanup/audit only: after `rec.start`, any exception leaves a VALID typed terminal event (`failed`) when possible, else the
    recorder is closed. Never raises, so the caller re-raises the ORIGINAL exception; charges and holds stay in the ledger
    untouched. A trace that already ended is left alone. The same-id trace is never deleted or overwritten (O_EXCL stays)."""
    try:
        if rec.events and str(rec.events[-1].get("type", "")).endswith("run.end"):
            rec.close()
            return
        rec.end("failed", [{"reason": "unsent", "stage": "MATCH"}])
    except BaseException:  # noqa: BLE001 - fallback must not mask the original error
        try:
            rec.close()
        except BaseException:  # noqa: BLE001
            pass


class ScoreHost:
    def __init__(self, cfg: ScoreConfig, baseline: LaunchBaseline, units, *, profile_ref: str, price: dict, auth, book,
                 ledger: RuntimeLedger, key: Secret, transport, store_dir, eval_run_id: str, eval_case_id: str = "campaign",
                 repeat: int = 0, clock=None, run_ceiling: int = PER_RUN_MAX, lock_path=None):
        units = tuple(units)
        self.cfg, self.baseline, self.units = cfg, baseline, units
        self.profile_ref, self.profile = profile_ref, cfg.profile(price)
        self.auth, self.book, self.ledger, self.key, self.transport = auth, book, ledger, key, transport
        self.store = Path(store_dir)
        self.evr, self.case_id, self.repeat, self.clock = eval_run_id, eval_case_id, repeat, clock
        self.run_id = score_run_id(eval_run_id, eval_case_id, repeat)
        self.fit_reason = None
        _need(type(run_ceiling) is int and 1 <= run_ceiling <= PER_RUN_MAX, "run-ceiling-invalid")   # may only tighten the 4M ScoreRun
        self.run_ceiling = run_ceiling
        self.lock_path = None if lock_path is None else Path(lock_path)      # canonical shared lock (live); else per-store (offline)
        self.fit_totals = None
        self.baseline_file_sha256 = None                       # set by the operator entry from the loaded baseline file

    # ------------------------------------------------------------ pins checked before any send
    def _check_offline_inputs(self):
        """Offline entry only: refuse BEFORE any lock, request, intent or state change. Exact fake transport, placeholder key."""
        import hmac
        t = self.transport
        _need(type(t) is CaptureTransport and set(vars(t)) == {"bodies", "respond"}
              and (t.respond is None or callable(t.respond)), "offline-needs-capture-transport")
        _need(isinstance(self.key, Secret) and hmac.compare_digest(self.key.reveal().encode(), PLACEHOLDER_KEY.encode()),
              "offline-needs-placeholder-key")

    def _check_static_pins(self):
        """Declared set, config and prompt pins only: no auth, book, ledger, key or transport access."""
        b = self.baseline
        declared = tuple(sorted((u.case.url, u.tool) for u in self.units))
        _need(self.units, "no-declared-units")
        _need(len(set(declared)) == len(declared) and len({u.agent for u in self.units}) == len(self.units), "duplicate-unit")
        _need(declared == tuple(sorted(b.declared)), "declared-set-drift")
        _need(self.cfg.digest == b.config_digest and tuple(sorted(self.cfg.prompt_sha256.items())) == tuple(b.prompt_sha256),
              "config-or-prompt-drift")

    def _check_pins(self):
        self._check_static_pins()
        b = self.baseline
        _need(self.ledger.scoring_startup_hold() is None, "scoring-startup-hold")
        sc, al = self.ledger.totals("scoring")["committedUsdMicros"], self.ledger.totals()["committedUsdMicros"]
        _need((sc, al) == (b.initial_scoring_committed, b.initial_all_committed), "ledger-state-drift")
        if b.initial_book is not None:
            bt = self.book.totals()
            _need((bt["committed"], bt["inflight"]) == tuple(b.initial_book), "book-state-drift")

    def _lock(self):
        self.store.mkdir(parents=True, exist_ok=True, mode=0o700)
        return acquire_lock(self.lock_path or (self.store / "scorer.lock"))

    def _gateway(self, provider, rec):
        budget = {**STANDARD_S0A_BUDGET, "maxUsdMicros": self.run_ceiling}
        try:
            return Gateway(mode="live", profile=self.profile, budget=budget, run_id=self.run_id, family="score",
                           providers={"anthropic": provider}, authorization=self.auth, book=self.book, recorder=rec,
                           eval_run_id=self.evr, eval_case_id=self.case_id, repeat=self.repeat, clock=self.clock)
        except AuthorizationError:
            raise ScoreHostError("authorization-coverage") from None
        except GatewayConfigError:
            raise ScoreHostError("gateway-config") from None

    # ------------------------------------------------------------ exact complete-set fit
    def _fit(self, gw, provider, plans, calls_used: int) -> bool:
        """Worst-case sum of EVERY pair request (gateway reservation and adapter wire/cap) against run, book, runtime-cap,
        scoring 8M and all-category 20M ceilings plus the campaign call budget. No partial admission, no splitting."""
        spec = self.profile["roles"]["matcher"]
        G = W = n = 0
        for p in plans:
            for _, _, req in p.requests:
                body, info = provider.build_body(req)
                if body is None:
                    self.fit_reason = "request-refused"
                    return False
                raw = len(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                if raw > MAX_REQUEST_BYTES:
                    self.fit_reason = "request-too-large"
                    return False
                G += reservation(spec["price"], estimate_input_tokens(req), spec["caps"]["maxOutputTokens"])
                W += worst_case_router_micros(body["model"], raw, info["maxTokens"])
                n += 1
        sp = gw._ledger.spend()
        bt = self.book.totals()
        t_all, t_sc = self.ledger.totals(), self.ledger.totals("scoring")
        checks = (
            ("call-budget", calls_used + n <= self.cfg.max_calls),
            ("run-ceiling", sp.committed + sp.inflight + G <= gw._ledger.budget["maxUsdMicros"]
             and sp.committed + sp.inflight + G <= self.auth.auth["maxUsdMicrosPerRun"]),
            ("book-total", bt["committed"] + bt["inflight"] + G <= bt["limit"]),
            ("runtime-cap", t_all["committedUsdMicros"] + W <= self.ledger.cap),
            ("scoring-cap", t_sc["committedUsdMicros"] + W <= SCORING_CATEGORY_CAP_MAX),
            ("aggregate-ceiling", t_all["committedUsdMicros"] + W <= SCORING_AGGREGATE_CEILING_MAX),
        )
        for name, ok in checks:
            if not ok:
                self.fit_reason = name
                return False
        self.fit_reason = None
        self.fit_totals = {"pairs": n, "gatewayReservationUsdMicros": G, "adapterWorstCaseUsdMicros": W,
                           "kind": "worst-case reservation, not a bill"}
        return True

    # ------------------------------------------------------------ the one pipeline (live-shaped or strict replay)
    def _pipeline(self, gw, provider, *, money: bool):
        cfg, ref, mappings = self.cfg, self.profile_ref, []
        for u in self.units:
            mappings.append(A.build_mapping(u.case, u.tool, u.agent))
        exts = [A.run_extract(gw.call, cfg, ref, m) for m in mappings]                       # phase 1: ALL units
        dds = [A.run_dedup(gw.call, cfg, ref, m, e) for m, e in zip(mappings, exts)]         # phase 2: ALL units
        declared = [(m.tool, m.case_url) for m in mappings]
        g = A.gate(exts, dds, declared)
        plans, over, adm, results = (), (), None, []
        if g.ok:
            plans, over = A.plan_pairs(cfg, ref, list(zip(mappings, exts)))
            used = sum(e.calls for e in exts) + sum(d.calls for d in dds)
            adm = A.admit_complete_set(g, plans, over, lambda ps: (self._fit(gw, provider, ps, used) if money else True))
            if adm.admitted:
                for p in plans:
                    results.append(A.run_pairs(gw.call, adm, p))
        return mappings, exts, dds, g, plans, adm, results

    def _documents(self, mappings, exts, dds, results, run_ref):
        judge = {"model": "anthropic/claude-opus-5.5", "extractionPrompt": P.VERSIONS["extract"], "dedupPrompt": P.VERSIONS["dedup"],
                 "matchPrompt": P.VERSIONS["pair"], "schemaSha256": schema_sha256(), "runRef": run_ref}
        by = {(r.tool, r.case_url): r for r in results}
        return [A.build_document(m, e, d, by[(m.tool, m.case_url)], judge) for m, e, d in zip(mappings, exts, dds)
                if (m.tool, m.case_url) in by]

    def _report(self, mappings, exts, dds, g, adm, results, status, docs_path):
        att = A.attempt_set(exts, dds, adm, results)
        sc = self.ledger.totals("scoring") if status != "strict-replay" else None      # replay reads no ledger state
        return {"schema": "pullo-score-host-report@1", "mode": status, "baselineDigest": self.baseline.digest,
                "configDigest": self.cfg.digest, "declaredUnits": len(self.units),
                "gate": {"ok": g.ok, "failures": [list(f) for f in g.failures]},
                "admission": None if adm is None else {"reason": adm.reason, "pairs": adm.pairs},
                "fitRefusal": self.fit_reason, "fitTotals": self.fit_totals, "attemptSet": att, "complete": att["complete"],
                "headline": None if not att["complete"] else "complete (mechanics only; no quality claim)",
                "scoringLedger": None if sc is None else {k: sc[k] for k in ("knownUsdMicros", "estimatedUsdMicros", "unknownBoundUsdMicros", "calls")},
                "documentsStored": docs_path is not None, "absentRequirements": len(ABSENT), "fullAcceptance": FULL_ACCEPTANCE}

    def _store(self, name, obj) -> str:
        p = self.store / name
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, sort_keys=True)
        return name

    def execute_offline(self) -> dict:
        """The composition under test: real Gateway + real OpenRouterProvider over the injected (fake) transport.
        Same-process scorer lock held for the whole call. Documents (model text) go to the 0600 store only."""
        self._check_offline_inputs()

        def execute_offline():                                  # the immediate pre-first-send recheck (named for the retained probe)
            _need(self.ledger.scoring_startup_hold() is None, "scoring-startup-hold")
        return self._execute("offline-fake-transport", pre_send=execute_offline)

    def _live_guards(self, transport, key, verified, confirm) -> bool:
        _need(confirm is True, "live-needs-confirm")
        _need(verified is not None and verified.genuine() and verified.live_authorized is True, "live-not-authorized")
        _need(verified.baseline_sha256 == self.baseline_file_sha256 and self.baseline_file_sha256, "live-baseline-mismatch")
        _need(self.lock_path is not None and self.baseline.initial_book is not None, "live-needs-canonical-lock-and-book-pin")
        _need(isinstance(self.key, Secret) and self.key is key and self.transport is transport and callable(transport),
              "live-inputs-mismatch")
        _need(self.key.reveal() != PLACEHOLDER_KEY, "live-needs-real-key")
        # "real" only for the exact runtime HTTPS transport class (identity, never a name string)
        return _REAL_TRANSPORT[0] is not None and type(transport) is _REAL_TRANSPORT[0]

    def execute_canary(self, *, transport, key, verified, confirm) -> dict:
        """The preregistered canary: exactly THREE role/schema probes (extractor, deduper, matcher; one call each) through the same
        Gateway/runtime/accounting/config/caps as the campaign. Not a comparative case: no pair loop, no quality headline. The
        evidence document is derived from the calls actually sent and their validated results; any failed or invalid probe stops
        the run and writes no evidence."""
        real = self._live_guards(transport, key, verified, confirm)
        _need(verified.mode == "canary" and tuple((u.case.url, u.tool) for u in self.units) == CANARY_DECLARED, "canary-set-not-preregistered")

        def pre_first_canary_send():
            self._check_pins()
            _need(self.ledger.scoring_startup_hold() is None, "scoring-startup-hold")
        return self._execute("canary" if real else "canary-synthetic-transport", real=real, pre_send=pre_first_canary_send, probes=True)

    def _probes(self, gw, rec, label) -> dict:
        import datetime as dt
        cfg, ref, u = self.cfg, self.profile_ref, self.units[0]
        m = A.build_mapping(u.case, u.tool, u.agent)
        sent = {"extractor": 0, "deduper": 0, "matcher": 0}

        def call(stage, role, agent, ordinal, request):
            sent[role] += 1
            return gw.call(stage, role, agent, ordinal, request)
        texts = [t for _, t in m.comment_texts][:2]
        out = {"extractor": "unsent", "deduper": "unsent", "matcher": "unsent"}
        ext = A.run_extract(call, cfg, ref, m)
        out["extractor"] = "ok" if ext.status == "ok" and sent["extractor"] == 1 else "failed"
        if out["extractor"] == "ok":
            res = call(A.STAGE["dedup"], "deduper", m.agent, 0, A._request(cfg, ref, "dedup", P.dedup_data([("k0001", texts[0]), ("k0002", texts[1])])))
            out["deduper"] = "ok" if res.ok and A.parse_dedup(res.output, 2) is not None else "failed"
        if out["deduper"] == "ok":
            res = call(A.STAGE["pair"], "matcher", m.agent, 0, A._request(cfg, ref, "pair", P.pair_data(m.gold_texts[m.gold_order[0]], texts[0])))
            out["matcher"] = "ok" if res.ok and A.parse_pair(res.output)[0] == "ok" else "failed"
        ok = all(v == "ok" for v in out.values()) and sent == {"extractor": 1, "deduper": 1, "matcher": 1}
        rec.end("completed" if ok else "partial", None if ok else [{"reason": "unsent", "stage": "MATCH"}])
        evidence = None
        if ok:
            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            evidence = self._store(f"{self.run_id}.canary-evidence.json", {
                "schema": "pullo-canary-evidence@1", "roles": ["extractor", "deduper", "matcher"], "route": "anthropic/claude-opus-5.5",
                "authDigest": self.auth.digest, "observedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiresAt": (now + dt.timedelta(hours=CANARY_TTL_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ"), "probes": dict(sent),
                "configDigest": self.cfg.digest, "promptSha256": dict(self.cfg.prompt_sha256), "schemaSha256": schema_sha256(),
                "policySha256": policy_digest(), "outcome": "ok"})
        sc = self.ledger.totals("scoring")
        trace = self.store / f"{self.run_id}.trace.jsonl"
        return {"schema": "pullo-score-host-report@1", "mode": label, "canary": True, "baselineDigest": self.baseline.digest,
                "configDigest": self.cfg.digest, "probes": out, "probeCalls": dict(sent), "canaryOk": ok, "evidenceFile": evidence,
                "traceSha256": hashlib.sha256(trace.read_bytes()).hexdigest() if trace.exists() else None, "realScoring": False,
                "headline": None, "note": "synthetic role/schema probes; no quality or comparison claim",
                "scoringLedger": {k: sc[k] for k in ("knownUsdMicros", "estimatedUsdMicros", "unknownBoundUsdMicros", "calls")}}

    def execute_live(self, *, transport, key, verified, confirm) -> dict:
        """Guarded live-shaped entry. Refuses (before lock, key use, request or intent) unless: explicit confirm, a genuine
        `Verified` for THIS baseline with the root live gate set, the canonical shared lock path, a real
        authorization/book/ledger, and a Secret key. The result is labelled `real` only for the exact HttpsTransport; any
        other transport (tests) is labelled synthetic and can never be reported as real scoring."""
        real = self._live_guards(transport, key, verified, confirm)
        def pre_first_live_send():
            self._check_pins()                                  # state/inflight/unknown/estimated + book pin, immediately before the first send
            _need(self.ledger.scoring_startup_hold() is None, "scoring-startup-hold")
        return self._execute("live" if real else "live-synthetic-transport", real=real, pre_send=pre_first_live_send)

    def _execute(self, label, real=False, *, pre_send, probes=False) -> dict:
        fd = self._lock()
        try:
            self._check_pins()
            try:
                provider = OpenRouterProvider(enabled=True, key=self.key, authorization=self.auth, book=self.book,
                                              ledger=self.ledger, transport=self.transport, run_scope=self.run_id,
                                              category="scoring", category_cap=SCORING_CATEGORY_CAP_MAX,
                                              aggregate_ceiling=SCORING_AGGREGATE_CEILING_MAX)
            except AuthorizationError:
                raise ScoreHostError("authorization-coverage") from None
            trace_path = self.store / f"{self.run_id}.trace.jsonl"
            rec = Recorder(self.run_id, trace_path, family="score")
            try:
                gw = self._gateway(provider, rec)
            except BaseException:
                rec.close()
                raise
            rec.start({"schema": "score-run@1", "id": self.run_id, "family": "score", "evalRunId": self.evr,
                       "evalCaseId": self.case_id, "repeat": self.repeat, "profile": self.profile_ref, "mode": "live",
                       "inputDigest": self.baseline.digest, "status": "running", "incomplete": [],
                       "spendAuthorization": self.auth.digest})
            try:
                pre_send()
                if probes:
                    return self._probes(gw, rec, label)
                mappings, exts, dds, g, plans, adm, results = self._pipeline(gw, provider, money=True)
                att_complete = A.attempt_set(exts, dds, adm, results)["complete"]
                rec.end("completed" if att_complete else "partial", None if att_complete else [{"reason": "unsent", "stage": "MATCH"}])
                docs = self._documents(mappings, exts, dds, results, self.evr) if att_complete else []
                stored = self._store(f"{self.run_id}.documents.json", docs) if docs else None
                rep = self._report(mappings, exts, dds, g, adm, results, label, stored)
                rep["realScoring"] = bool(real and rep["complete"])                              # synthetic results are never real scoring
                return rep
            except BaseException:
                _abort_trace(rec)                    # typed failed end (or close); the ORIGINAL exception propagates
                raise
        finally:
            os.close(fd)

    def replay(self, trace_path, expected_digest: str, new_eval_run_id: str) -> dict:
        """Strict replay: no key, authorization, book, ledger, transport or new spend. Fresh evalRunId, externally
        pinned trace digest. Produces the same documents from the recorded outputs."""
        fd = self._lock()
        try:
            self._check_static_pins()                                  # declared set + config/prompt pins; no ledger totals
            _need(new_eval_run_id != self.evr, "replay-needs-fresh-run-id")
            rid = score_run_id(new_eval_run_id, self.case_id, self.repeat)
            try:
                trace = load_trace(trace_path)
                rec = Recorder(rid, family="score")
                gw = Gateway(mode="strict-replay", profile=self.profile, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                             family="score", replay=trace, recorder=rec, eval_run_id=new_eval_run_id,
                             eval_case_id=self.case_id, repeat=self.repeat, expected_trace_digest=expected_digest)
            except Exception:  # noqa: BLE001 - any trace/pin problem is one fixed refusal, no detail echoed
                raise ScoreHostError("replay-trace-refused") from None
            rec.start({"schema": "score-run@1", "id": rid, "family": "score", "evalRunId": new_eval_run_id,
                       "evalCaseId": self.case_id, "repeat": self.repeat, "profile": self.profile_ref,
                       "mode": "strict-replay", "inputDigest": self.baseline.digest, "status": "running", "incomplete": [],
                       "replayOf": trace.run_id})
            try:
                mappings, exts, dds, g, plans, adm, results = self._pipeline(gw, None, money=False)
                ok = A.attempt_set(exts, dds, adm, results)["complete"]
                rec.end("completed" if ok else "partial", None if ok else [{"reason": "unsent", "stage": "MATCH"}])
                docs = self._documents(mappings, exts, dds, results, new_eval_run_id) if ok else []
                report = self._report(mappings, exts, dds, g, adm, results, "strict-replay", None)
                report["liveCalls"] = gw.live_calls
                report["documents"] = docs                       # returned to the trusted caller only (never in a public report)
                return report
            except BaseException:
                _abort_trace(rec)                    # typed failed end (or close); the ORIGINAL exception propagates
                raise
        finally:
            os.close(fd)


_REAL_TRANSPORT = [None]


def register_real_transport(cls) -> None:
    """Called only by the operator CLI's gated live branch with the class it imported from the runtime. Identity, not a
    module/qualname string, decides what may be labelled real scoring; a subclass or look-alike never matches."""
    import sys
    mod = sys.modules.get("reviewer.runtime.openrouter")                    # the class must BE the runtime module's attribute
    _need(isinstance(cls, type) and mod is not None and getattr(mod, "HttpsTransport", None) is cls
          and _REAL_TRANSPORT[0] in (None, cls), "transport-identity")
    _REAL_TRANSPORT[0] = cls


def run_live(*_a, **_k):
    """Live entry is refused: this milestone lacks required controls (see ABSENT). No argument can enable it."""
    raise ScoreHostError("live-refused-controls-missing")
