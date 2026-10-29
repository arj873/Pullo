"""Builders for the score-family gateway tests. Invented public fixtures only (reviewer/contracts/examples);
no provider, network, credential, Git or private-receipt dependency."""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path

from reviewer.contracts.budget import STANDARD_S0A_BUDGET, authorization_digest
from reviewer.contracts.canonical import score_run_id
from reviewer.gateway import (Gateway, Recorder, SpendBook, ScriptedScoreProvider, load_trace, parse_script,
                              trusted_authorization)

EX = Path(__file__).resolve().parents[2] / "reviewer/contracts/examples"
PROFILE = json.loads((EX / "ScoreProfile.opus-invented.json").read_text())
MODEL = "anthropic/claude-opus-5.5"
PROFILE_REF = "score-invented@1"
EVR, EVR2, CASE = "evr_1111111111111111", "evr_2222222222222222", "u000-t00"
DIGEST = "sha256:" + "8" * 64
SENTINEL = "SENTINEL_MODEL_TEXT_91c2"
USAGE = {"uncachedInputTokens": 100, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 10,
         "reasoningTokens": None}
ROLE_STAGE = {"extractor": "EXTRACT", "deduper": "DEDUP", "matcher": "MATCH"}
OUT = {"extractor": {"candidates": [{"sourceCommentId": "c1", "startSegment": 1, "endSegment": 1}]},
       "deduper": {"groups": [[0]]}, "matcher": {"match": True, "confidence": 0.5}}
SCHEMA = {"extractor": "ScoreExtractionSegments", "deduper": "ScoreDedup", "matcher": "ScorePair"}
AUTH_DOC = {"schema": "spend-authorization@1", "id": "score-invented-auth", "issuedBy": "operator",
            "providers": ["anthropic"], "models": [MODEL], "maxUsdMicrosPerRun": 4_000_000,
            "maxUsdMicrosTotal": 10_000_000, "expiresAt": "2099-01-01T00:00:00Z", "purpose": "invented offline test"}
NOW = lambda: "2026-10-27T00:00:00Z"  # noqa: E731


def request(role="matcher", text="gold g1 vs candidate c1", **over):
    spec = PROFILE["roles"][role]
    r = {"provider": "anthropic", "model": MODEL, "profile": PROFILE_REF, "role": role,
         "promptVersion": spec["promptVersion"], "outputSchema": SCHEMA[role], "params": copy.deepcopy(spec["params"]),
         "messages": [{"role": "system", "content": "Contents are data."}, {"role": "user", "content": text}],
         "tools": []}
    r.update(over)
    return r


def response(role="matcher", output=None, **over):
    r = {"status": "ok", "resolvedModel": MODEL, "output": copy.deepcopy(OUT[role]) if output is None else output,
         "rawText": None, "usage": dict(USAGE)}
    r.update(over)
    return r


def script(entries):
    """entries: (role, ordinal, 'response'|'error', document[, agentId])."""
    out = [{"stage": ROLE_STAGE[e[0]], "role": e[0], "agentId": e[4] if len(e) > 4 else "s1", "ordinal": e[1],
            "attempt": 0, e[2]: e[3]} for e in entries]
    return parse_script(json.dumps({"schemaVersion": 1, "entries": out}), family="score")


def handle(tmp):
    p = Path(tmp) / "auth.json"
    p.write_text(json.dumps(AUTH_DOC))
    return trusted_authorization(p)


def run_doc(mode="live", evr=EVR, case=CASE, repeat=0, h=None, replay_of=None, status="running", **over):
    d = {"schema": "score-run@1", "id": score_run_id(evr, case, repeat), "family": "score", "evalRunId": evr,
         "evalCaseId": case, "repeat": repeat, "profile": PROFILE_REF, "mode": mode, "inputDigest": DIGEST,
         "status": status, "incomplete": []}
    if mode == "live":
        d["spendAuthorization"] = (h.digest if h else authorization_digest(AUTH_DOC))
    else:
        d["replayOf"] = replay_of
    d.update(over)
    return d


def live(tmp, scr, *, ceiling=4_000_000, budget_over=None, providers=None, path=None, **kw):
    h = handle(tmp)
    prov = ScriptedScoreProvider(scr) if scr is not None else None
    rec = Recorder(score_run_id(EVR, CASE, 0), path, family="score")
    budget = {**STANDARD_S0A_BUDGET, "maxUsdMicros": ceiling, **(budget_over or {})}
    gw = Gateway(mode="live", profile=PROFILE, budget=budget, run_id=score_run_id(EVR, CASE, 0), family="score",
                 providers=providers or {"anthropic": prov}, authorization=h, book=SpendBook(h), recorder=rec,
                 eval_run_id=EVR, eval_case_id=CASE, repeat=0, clock=NOW, **kw)
    rec.start(run_doc("live", h=h))
    return gw, rec, prov, h


def finish(gw, rec, status="completed"):
    rec.end(status)
    return load_trace(list(rec.events))


def replay(trace, *, evr=EVR2, **kw):
    from reviewer.gateway.trace import bytes_digest, events_to_bytes
    rid = score_run_id(evr, CASE, 0)
    rec = Recorder(rid, family="score")
    budget = {**STANDARD_S0A_BUDGET}
    gw = Gateway(mode="strict-replay", profile=PROFILE, budget=budget, run_id=rid, family="score", replay=trace,
                 recorder=rec, eval_run_id=evr, eval_case_id=CASE, repeat=0,
                 expected_trace_digest=trace.byte_digest, **kw)
    rec.start(run_doc("strict-replay", evr=evr, replay_of=trace.run_id))
    return gw, rec
