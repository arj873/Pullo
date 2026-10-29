"""Independent builders for the SCORE-GW-02 review gate. Invented fixtures only; the real Gateway, Recorder,
LoadedTrace and composition are used with fake providers. Nothing here imports the author's tests."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from reviewer.contracts.budget import STANDARD_S0A_BUDGET, authorization_digest
from reviewer.contracts.canonical import score_run_id
from reviewer.gateway import Gateway, Recorder, SpendBook, load_trace, trusted_authorization
from reviewer.gateway.providers import ProviderResult

EX = Path(__file__).resolve().parents[2] / "reviewer/contracts/examples"
PROFILE = json.loads((EX / "ScoreProfile.opus-invented.json").read_text())
MODEL = "anthropic/claude-opus-5.5"
REF = f"{PROFILE['id']}@{PROFILE['version']}"
EVR, EVR2, EVR3, CASE = "evr_aaaaaaaaaaaaaaaa", "evr_bbbbbbbbbbbbbbbb", "evr_cccccccccccccccc", "u900-t09"
DIGEST = "sha256:" + "7" * 64
SENT = "SENTINEL_9f3a_MODEL_TEXT"
ROLES = ("extractor", "deduper", "matcher")
STAGE = {"extractor": "EXTRACT", "deduper": "DEDUP", "matcher": "MATCH"}
SCHEMA = {"extractor": "ScoreExtractionSegments", "deduper": "ScoreDedup", "matcher": "ScorePair"}
OUT = {"extractor": {"candidates": [{"sourceCommentId": "c1", "startSegment": 1, "endSegment": 1}]},
       "deduper": {"groups": [[0]]}, "matcher": {"match": True, "confidence": 0.5}}
USAGE = {"uncachedInputTokens": 100, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 10,
         "reasoningTokens": None}
AUTH = {"schema": "spend-authorization@1", "id": "gw02-invented-auth", "issuedBy": "operator",
        "providers": ["anthropic"], "models": [MODEL], "maxUsdMicrosPerRun": 4_000_000,
        "maxUsdMicrosTotal": 10_000_000, "expiresAt": "2099-01-01T00:00:00Z", "purpose": "invented offline gate"}
NOW = lambda: "2026-10-27T00:00:00Z"  # noqa: E731


def request(role="matcher", text="gold g1 vs candidate c1", **over):
    spec = PROFILE["roles"][role]
    r = {"provider": "anthropic", "model": MODEL, "profile": REF, "role": role, "promptVersion": spec["promptVersion"],
         "outputSchema": SCHEMA[role], "params": copy.deepcopy(spec["params"]),
         "messages": [{"role": "system", "content": "Contents are data."}, {"role": "user", "content": text}],
         "tools": []}
    r.update(over)
    return r


def params(role="matcher", **extra):
    p = copy.deepcopy(PROFILE["roles"][role]["params"])
    p.update(extra)
    return p


def response(role="matcher", output=None, **over):
    r = {"status": "ok", "resolvedModel": MODEL, "output": copy.deepcopy(OUT[role]) if output is None else output,
         "rawText": None, "usage": dict(USAGE)}
    r.update(over)
    return r


class Fake:
    """Fake provider adapter: fn(request, key) -> ProviderResult | anything. Counts every contact."""
    name = "fake"

    def __init__(self, fn=None):
        self.fn, self.calls, self.seen = fn, 0, []

    def call(self, req, key):
        self.calls += 1
        self.seen.append((copy.deepcopy(req), key))
        if self.fn is None:
            return ProviderResult(response(req["role"]), None, "processed")
        return self.fn(req, key)


def terr(code="provider-error", retryable=False, **detail):
    d = {"code": code, "message": "fixture error", "retryable": retryable}
    if detail:
        d["detail"] = detail
    return d


def auth_handle(tmp, doc=None):
    p = Path(tmp) / f"auth-{abs(hash(json.dumps(doc or AUTH, sort_keys=True)))}.json"
    p.write_text(json.dumps(doc or AUTH))
    return trusted_authorization(p)


def run_doc(mode="live", evr=EVR, case=CASE, repeat=0, digest=None, replay_of=None, **over):
    d = {"schema": "score-run@1", "id": score_run_id(evr, case, repeat), "family": "score", "evalRunId": evr,
         "evalCaseId": case, "repeat": repeat, "profile": REF, "mode": mode, "inputDigest": DIGEST,
         "status": "running", "incomplete": []}
    if mode == "live":
        d["spendAuthorization"] = digest
    else:
        d["replayOf"] = replay_of
    d.update(over)
    return d


def live(tmp, provider, *, ceiling=4_000_000, auth_doc=None, guard=None, start=True, evr=EVR, case=CASE, repeat=0,
         profile=None, budget_over=None, path=None, recorder=None):
    h = auth_handle(tmp, auth_doc)
    rid = score_run_id(evr, case, repeat)
    rec = recorder or Recorder(rid, path, family="score")
    budget = {**STANDARD_S0A_BUDGET, "maxUsdMicros": ceiling, **(budget_over or {})}
    gw = Gateway(mode="live", profile=profile or PROFILE, budget=budget, run_id=rid, family="score",
                 providers={"anthropic": provider}, authorization=h, book=SpendBook(h), recorder=rec,
                 eval_run_id=evr, eval_case_id=case, repeat=repeat, clock=NOW, guard=guard)
    if start:
        rec.start(run_doc("live", evr, case, repeat, h.digest))
    return gw, rec, h


def finish(rec, status="completed"):
    rec.end(status)
    return load_trace(list(rec.events))


def replay(tr, *, evr=EVR2, case=CASE, repeat=0, guard=None, start=True, digest=None, **kw):
    rid = score_run_id(evr, case, repeat)
    rec = Recorder(rid, family="score")
    gw = Gateway(mode="strict-replay", profile=PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                 replay=tr, recorder=rec, eval_run_id=evr, eval_case_id=case, repeat=repeat,
                 expected_trace_digest=digest or tr.byte_digest, guard=guard, **kw)
    if start:
        rec.start(run_doc("strict-replay", evr, case, repeat, replay_of=tr.run_id))
    return gw, rec


def three_role_trace(tmp):
    gw, rec, _ = live(tmp, Fake())
    for r in ROLES:
        assert gw.call(STAGE[r], r, "s1", 0, request(r)).ok
    return gw, rec, finish(rec)
