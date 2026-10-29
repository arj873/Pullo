"""Common-judge all-pairs producer for `reference-judgments@1` (SCORE-PROTO-01). Pure and phase-oriented.

The Gateway is injected as a `call(stage, role, agent_id, ordinal, request) -> CallResult` callable (Gateway.call, family
"score"). There is deliberately NO per-case loop that goes from extraction to pairs: the host runs `run_extract` for ALL
units, then `run_dedup` for ALL units, then `gate`/`plan_pairs`/`admit_complete_set` for the whole set, and only an
`Admission` returned by `admit_complete_set` lets `run_pairs` send anything. Real ids, tool names, paths and lines live in
the host `Mapping`; requests carry neutral ids and body text. Model text is trusted-input only: reports and errors carry
fixed classes and counts, never model or comment text. Every non-empty string (including whitespace-only) is preserved."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
from dataclasses import dataclass

from . import score_prompts as P
from .jsonio import canonical, digest
from .model import ScorerCase
from .reference import PINNED  # noqa: F401  (documents the pinned reference convention this producer feeds)

JUDGMENTS_SCHEMA = "reference-judgments@1"
STAGE = {"extract": "EXTRACT", "dedup": "DEDUP", "pair": "MATCH"}
PAIR_ERRORS = ("schema-invalid", "non-finite", "provider-error", "provider-timeout", "budget-refused", "unsent")
OK_STATUSES = {"extract": ("ok", "no-extraction"), "dedup": ("ok", "skipped")}
_SEAL_KEY = os.urandom(32)                       # process-local: only objects issued by this module verify (not a defence against trusted host memory)


def _seal(obj) -> str:
    return hmac.new(_SEAL_KEY, canonical(obj), hashlib.sha256).hexdigest()


def _sealed(obj, seal) -> bool:
    return isinstance(seal, str) and hmac.compare_digest(_seal(obj), seal)


# ------------------------------------------------------------------ host mapping (never sent to a model)
@dataclass(frozen=True)
class Mapping:
    case_url: str
    tool: str
    agent: str                                  # neutral agent id for the gateway, e.g. u001-t01
    comment_ids: dict                           # neutral c001.. -> real comment id
    comment_texts: tuple                        # ((neutral id, body text), ...) in review order
    gold_ids: dict                              # neutral g001.. -> real golden id
    gold_texts: dict                            # real golden id -> text, golden order kept in gold_order
    gold_order: tuple


def build_mapping(case: ScorerCase, tool: str, agent: str) -> Mapping:
    review = case.review(tool)                  # raises `missing` for a tool with no review here
    cids = {f"c{n:03d}": c.id for n, c in enumerate(review.comments, 1)}
    texts = tuple((f"c{n:03d}", c.body) for n, c in enumerate(review.comments, 1))
    gids = {f"g{n:03d}": g.id for n, g in enumerate(case.golden, 1)}
    return Mapping(case.url, tool, agent, cids, texts, gids, {g.id: g.comment for g in case.golden},
                   tuple(g.id for g in case.golden))


# Finite, explicit Gateway error code -> fixed pair/phase class. Every ERROR_CODES entry is listed; an unlisted or missing code
# is also `provider-error` (a failure, never a no-match). Model text and error messages are never read.
ERROR_CLASS = {
    "schema-invalid": "schema-invalid", "repair-exhausted": "schema-invalid",
    "provider-timeout": "provider-timeout", "deadline-exceeded": "provider-timeout",
    "budget-exhausted": "budget-refused",
    "provider-error": "provider-error", "replay-miss": "provider-error", "replay-mismatch": "provider-error",
    "live-calls-disabled": "provider-error", "model-unresolved": "provider-error", "cancelled": "provider-error",
    "tool-denied": "provider-error", "path-escape": "provider-error", "invalid-citation": "provider-error",
    "contract-violation": "provider-error", "internal": "provider-error",
}


def classify_error(err) -> str:
    code = err.get("code") if isinstance(err, dict) else None
    return ERROR_CLASS.get(code, "provider-error") if isinstance(code, str) else "provider-error"


def _request(cfg, profile_ref: str, kind: str, data: dict) -> dict:
    # Params carry ONLY the output cap (equal to the trusted profile role): no temperature/top_p/top_k/effort, no null.
    return {"provider": "anthropic", "model": "anthropic/claude-opus-5.5", "profile": profile_ref, "role": P.ROLE_OF[kind],
            "promptVersion": P.VERSIONS[kind],
            "outputSchema": {"extract": "ScoreExtractionSegments", "dedup": "ScoreDedup", "pair": "ScorePair"}[kind],
            "params": {"maxOutputTokens": cfg.max_output[kind]}, "messages": P.messages(kind, data), "tools": []}


# ------------------------------------------------------------------ phase 1: extraction
@dataclass(frozen=True)
class Extraction:
    tool: str
    case_url: str
    status: str                                  # ok | no-extraction | extraction-invalid | oversize | provider-failure
    candidates: tuple = ()                       # ({"id": "k0001", "text": str, "src": real comment id}, ...)
    error: str | None = None                     # fixed class only
    calls: int = 0


def parse_extraction(output, m: Mapping, cfg):
    """bench.extract@v3 (ScoreExtractionSegments) -> (status, candidates). The model returns references, never text: each
    candidate is {sourceCommentId, startSegment, endSegment}, an inclusive 1-based range of P.segments(comment text), and
    its text is rebuilt HERE as the exact joined segments (an exact substring of the trusted comment; never trimmed).
    Non-int or bool numbers, start < 1, end > segment count, start > end, an unknown or non-str id and extra/missing keys
    are `extraction-invalid`; more than max_candidates is `oversize`. Candidate ids and `src` are as before, so
    dedup/pair/metrics are unchanged."""
    if not isinstance(output, dict) or set(output) != {"candidates"} or not isinstance(output["candidates"], list):
        return "extraction-invalid", ()
    if len(output["candidates"]) > cfg.max_candidates:
        return "oversize", ()
    segs = {cid: P.segments(text) for cid, text in m.comment_texts}
    out = []
    for n, c in enumerate(output["candidates"], 1):
        if (not isinstance(c, dict) or set(c) != {"sourceCommentId", "startSegment", "endSegment"}
                or not isinstance(c["sourceCommentId"], str) or c["sourceCommentId"] not in m.comment_ids
                or c["sourceCommentId"] not in segs or type(c["startSegment"]) is not int or type(c["endSegment"]) is not int):
            return "extraction-invalid", ()
        s, e, parts = c["startSegment"], c["endSegment"], segs[c["sourceCommentId"]]
        if not 1 <= s <= e <= len(parts):
            return "extraction-invalid", ()
        out.append({"id": f"k{n:04d}", "text": "".join(parts[s - 1:e]), "src": m.comment_ids[c["sourceCommentId"]]})
    return "ok", tuple(out)


def run_extract(call, cfg, profile_ref: str, m: Mapping, ordinal: int = 0) -> Extraction:
    joined = "\n".join(t for _, t in m.comment_texts)
    if len(joined) < cfg.min_extract_chars:
        return Extraction(m.tool, m.case_url, "no-extraction")           # explicit status, zero candidates, no call
    res = call(STAGE["extract"], "extractor", m.agent, ordinal, _request(cfg, profile_ref, "extract", P.extract_data(list(m.comment_texts))))
    if not res.ok:
        return Extraction(m.tool, m.case_url, "provider-failure", error=classify_error(res.error), calls=1)
    status, cands = parse_extraction(res.output, m, cfg)
    return Extraction(m.tool, m.case_url, status, cands, calls=1)


# ------------------------------------------------------------------ phase 2: dedup
@dataclass(frozen=True)
class Dedup:
    tool: str
    case_url: str
    status: str                                  # ok | skipped | dedup-invalid | provider-failure | unsent
    groups: tuple = ()
    list_sha256: str | None = None
    error: str | None = None
    calls: int = 0


def candidate_digest(cands) -> str:
    return digest([[c["id"], c["text"]] for c in cands])


def parse_dedup(output, n: int):
    """Exact partition of 0..n-1: non-empty groups of distinct in-range ints (bool refused). No singleton fallback."""
    if not isinstance(output, dict) or set(output) != {"groups"} or not isinstance(output["groups"], list):
        return None
    seen = []
    for g in output["groups"]:
        if not isinstance(g, list) or not g or not all(type(i) is int and 0 <= i < n for i in g):
            return None
        seen.extend(g)
    return tuple(tuple(g) for g in output["groups"]) if sorted(seen) == list(range(n)) else None


def run_dedup(call, cfg, profile_ref: str, m: Mapping, ext: Extraction, ordinal: int = 0) -> Dedup:
    if ext.status not in OK_STATUSES["extract"]:
        return Dedup(m.tool, m.case_url, "unsent")                       # extraction failed: nothing is sent for this unit
    n = len(ext.candidates)
    h = candidate_digest(ext.candidates)
    if n < cfg.skip_dedup_below:
        return Dedup(m.tool, m.case_url, "skipped", (), h)               # explicit skip; groups=[] is the document value
    res = call(STAGE["dedup"], "deduper", m.agent, ordinal, _request(cfg, profile_ref, "dedup", P.dedup_data([(c["id"], c["text"]) for c in ext.candidates])))
    if not res.ok:
        return Dedup(m.tool, m.case_url, "provider-failure", list_sha256=h, error=classify_error(res.error), calls=1)
    groups = parse_dedup(res.output, n)
    return Dedup(m.tool, m.case_url, "dedup-invalid" if groups is None else "ok", groups or (), h, calls=1)


# ------------------------------------------------------------------ gate + complete-set admission (host-driven)
def _unit_record(e: Extraction) -> list:
    return [e.tool, e.case_url, e.status, len(e.candidates), candidate_digest(e.candidates)]


def _dedup_consistent(e: Extraction, d: Dedup) -> str | None:
    """None when the dedup record belongs to EXACTLY this extraction's current ordered candidate list, else a fixed reason."""
    if d.status not in OK_STATUSES["dedup"]:
        return d.status
    if d.list_sha256 != candidate_digest(e.candidates):
        return "stale-dedup"                                              # stored digest vs the CURRENT exact ordered list
    n = len(e.candidates)
    if d.status == "skipped":
        return None if (not d.groups and n < 2) else "dedup-invalid"
    return None if parse_dedup({"groups": [list(g) for g in d.groups]}, n) is not None and n >= 2 else "dedup-invalid"


@dataclass(frozen=True)
class Gate:
    ok: bool
    failures: tuple                              # ((tool, case_url, phase, status), ...)
    units: tuple = ()                            # per-unit records bound by the gate (empty unless issued by `gate`)
    seal: str = ""


def gate(extractions, dedups, declared=None) -> Gate:
    """Pairs may start only if EVERY declared unit finished extraction and dedup with a dedup that matches its current
    candidate list. The declared set is `declared` ((tool, case_url) pairs; the host's planned units) or, when omitted,
    the extraction units. Missing, undeclared, duplicate, stale, invalid and failed units block; an empty set is refused."""
    extractions, dedups = tuple(extractions), tuple(dedups)
    want = None if declared is None else tuple((t, c) for t, c in declared)
    bad = []
    if want is not None and len(set(want)) != len(want):
        bad.append(("", "", "declared", "duplicate-unit"))
    keys = [(e.tool, e.case_url) for e in extractions]
    if len(set(keys)) != len(keys):
        bad.append(("", "", "extract", "duplicate-unit"))
    dkeys = [(d.tool, d.case_url) for d in dedups]
    if len(set(dkeys)) != len(dkeys):
        bad.append(("", "", "dedup", "duplicate-unit"))
    universe = set(want) if want is not None else set(keys)
    if not universe:
        bad.append(("", "", "declared", "empty"))
    ebykey, dbykey = dict(zip(keys, extractions)), dict(zip(dkeys, dedups))
    for k in sorted(universe | set(keys) | set(dkeys)):
        e, d = ebykey.get(k), dbykey.get(k)
        if k not in universe:
            bad.append((k[0], k[1], "declared", "undeclared"))
        if e is None:
            bad.append((k[0], k[1], "extract", "missing"))
        elif e.status not in OK_STATUSES["extract"]:
            bad.append((k[0], k[1], "extract", e.status))
        elif e.status == "no-extraction" and e.candidates:
            bad.append((k[0], k[1], "extract", "extraction-invalid"))
        if d is None:
            bad.append((k[0], k[1], "dedup", "missing"))
        elif d.status not in OK_STATUSES["dedup"]:
            bad.append((k[0], k[1], "dedup", d.status))
        elif e is not None and e.status in OK_STATUSES["extract"]:
            why = _dedup_consistent(e, d)
            if why:
                bad.append((k[0], k[1], "dedup", why))
        elif e is not None:
            bad.append((k[0], k[1], "dedup", "unbound"))                  # a dedup record cannot stand in for a failed extraction
    units = tuple(tuple(_unit_record(ebykey[k])) for k in sorted(universe) if k in ebykey)
    ok = not bad
    return Gate(ok, tuple(bad), units, _seal(["gate", ok, [list(u) for u in units]]) if ok else "")


def _gate_genuine(g) -> bool:
    return isinstance(g, Gate) and g.ok is True and bool(g.units) and _sealed(["gate", True, [list(u) for u in g.units]], g.seal)


def _plan_core(p) -> list:
    m, e = p.mapping, p.extraction
    return [m.tool, m.case_url, m.agent, [[g, digest(m.gold_texts[g])] for g in m.gold_order], _unit_record(e),
            [[g, cid, req] for g, cid, req in p.requests]]


@dataclass(frozen=True)
class PairPlan:
    mapping: Mapping
    extraction: Extraction
    requests: tuple                              # ((real golden id, candidate id, ScoreRequest), ...) golden-major
    digest: str = ""                             # sha256 of the full plan content (units, gold, every request) when issued
    seal: str = ""

    def current_digest(self) -> str:
        return digest(_plan_core(self))

    def genuine(self) -> bool:
        """Issued by plan_pairs AND unchanged since: the digest is recomputed from the live content."""
        try:
            now = self.current_digest()
        except (TypeError, ValueError, KeyError):
            return False
        return bool(self.digest) and now == self.digest and _sealed(["plan", now], self.seal)


def plan_pairs(cfg, profile_ref: str, units) -> tuple:
    """units: [(Mapping, Extraction)] after a passing gate. Builds EVERY gold x candidate request, no reduction.
    -> (plans, oversize) where oversize lists units whose pair count exceeds the per-tool-case limit (never truncated)."""
    plans, oversize = [], []
    for m, ext in units:
        n = len(m.gold_order) * len(ext.candidates)
        if n > cfg.max_pairs or n + 2 > cfg.max_calls:
            oversize.append((m.tool, m.case_url))
            continue
        reqs = tuple((g, c["id"], _request(cfg, profile_ref, "pair", P.pair_data(m.gold_texts[g], c["text"])))
                     for g in m.gold_order for c in ext.candidates)             # golden-major, candidate-minor
        p = PairPlan(m, ext, reqs)
        d = p.current_digest()
        plans.append(PairPlan(m, ext, reqs, d, _seal(["plan", d])))
    return tuple(plans), tuple(oversize)


@dataclass(frozen=True)
class Admission:
    admitted: bool
    reason: str                                  # fixed: admitted | gate-failed | oversize | plan-mismatch | does-not-fit
    pairs: int = 0
    plan_digests: tuple = ()                     # exactly the complete planned set this admission authorizes
    units_digest: str = ""                       # the gate's units this admission is for
    seal: str = ""


def _admission_core(plan_digests, units_digest, pairs) -> list:
    return ["admission", sorted(plan_digests), units_digest, pairs]


def admission_genuine(a) -> bool:
    return (isinstance(a, Admission) and a.admitted is True and isinstance(a.plan_digests, tuple)
            and _sealed(_admission_core(a.plan_digests, a.units_digest, a.pairs), a.seal))


def _plans_match_gate(g: Gate, plans) -> bool:
    """Plans are issued, unchanged, one per unit (no extras, none duplicated) and cover every unit that has candidates."""
    if not all(isinstance(p, PairPlan) and p.genuine() for p in plans):
        return False
    units = {(u[0], u[1]): u for u in g.units}
    seen = {}
    for p in plans:
        k = (p.mapping.tool, p.mapping.case_url)
        if k in seen or k not in units or list(units[k]) != _unit_record(p.extraction):
            return False
        seen[k] = p
    return all(k in seen for k, u in units.items() if u[3] > 0)


def admit_complete_set(gate_result: Gate, plans, oversize, reserve) -> Admission:
    """All-or-none. `reserve(plans) -> bool` is the host's exact complete-set reservation (it holds the ledger/book);
    nothing is partially admitted and no tool-case is dropped to make it fit. The admission is bound to the gate's units
    and to the digests of exactly these plans."""
    plans = tuple(plans)
    if not _gate_genuine(gate_result):
        return Admission(False, "gate-failed")
    if oversize:
        return Admission(False, "oversize")
    if not _plans_match_gate(gate_result, plans):
        return Admission(False, "plan-mismatch")
    n = sum(len(p.requests) for p in plans)
    if reserve(plans) is not True:
        return Admission(False, "does-not-fit", n)
    ud = digest([list(u) for u in gate_result.units])
    pds = tuple(sorted(p.digest for p in plans))
    return Admission(True, "admitted", n, pds, ud, _seal(_admission_core(pds, ud, n)))


@dataclass(frozen=True)
class PairResults:
    tool: str
    case_url: str
    pairs: tuple                                 # in request order; sent pairs only
    unsent: int = 0
    plan_digest: str = ""                        # the admitted plan these results were produced from


def parse_pair(output):
    """-> ("ok", match, confidence) or ("error", class). Strict bool, finite non-bool number; no coercion."""
    if not isinstance(output, dict) or set(output) != {"match", "confidence"} or not isinstance(output["match"], bool):
        return ("error", "schema-invalid")
    c = output["confidence"]
    if not isinstance(c, (int, float)) or isinstance(c, bool):
        return ("error", "schema-invalid")
    try:
        return ("ok", output["match"], c) if math.isfinite(c) else ("error", "non-finite")
    except OverflowError:
        return ("error", "non-finite")


def run_pairs(call, admission: Admission, plan: PairPlan, ordinal_start: int = 0) -> PairResults:
    """Sends only a plan that is part of the exact complete set `admission` was issued for and is unchanged since."""
    if not admission_genuine(admission):
        raise PermissionError("pairs need an admitted complete-set reservation")
    if not isinstance(plan, PairPlan) or not plan.genuine() or plan.digest not in admission.plan_digests:
        raise PermissionError("this plan is not part of the admitted complete request set")
    out = []
    for i, (g, cid, req) in enumerate(plan.requests):
        res = call(STAGE["pair"], "matcher", plan.mapping.agent, ordinal_start + i, req)
        if not res.ok:
            out.append({"golden": g, "candidate": cid, "error": classify_error(res.error)})
            continue
        r = parse_pair(res.output)
        out.append({"golden": g, "candidate": cid, "error": r[1]} if r[0] == "error"
                   else {"golden": g, "candidate": cid, "match": r[1], "confidence": r[2]})
    return PairResults(plan.mapping.tool, plan.mapping.case_url, tuple(out), plan_digest=plan.digest)


# ------------------------------------------------------------------ document + attempt set
def build_document(m: Mapping, ext: Extraction, dd: Dedup, pairs: PairResults, judge: dict) -> dict:
    """reference-judgments@1 for reference_graph. Candidate sourceCommentId is the REAL comment id (host-mapped).
    Refuses (ValueError, fixed text) a dedup whose STORED digest is not the current exact ordered candidate list, or units
    that do not belong together; the digest in the document is the dedup's own, never a fresh one blessing stale groups."""
    if not (m.tool == ext.tool == dd.tool == pairs.tool and m.case_url == ext.case_url == dd.case_url == pairs.case_url):
        raise ValueError("document parts belong to different units")
    if ext.status not in OK_STATUSES["extract"] or _dedup_consistent(ext, dd) is not None:
        raise ValueError("dedup does not match the current candidate list")
    return {"schema": JUDGMENTS_SCHEMA, "caseUrl": m.case_url, "tool": m.tool, "judge": dict(judge),
            "extraction": {"candidates": [{"id": c["id"], "sourceCommentId": c["src"], "text": c["text"]} for c in ext.candidates]},
            "duplicateGroups": {"candidateListSha256": dd.list_sha256, "groups": [list(g) for g in dd.groups]},
            "pairs": [dict(p) for p in pairs.pairs]}


def attempt_set(extractions, dedups, admission: Admission | None, pair_results=()) -> dict:
    """Every planned unit with a fixed status; later phases that never ran are `unsent`. No text, no model diagnostics.
    `complete` needs a genuine admission for THESE units, a non-empty set, every unit with candidates sent, no pair error."""
    extractions, dedups = tuple(extractions), tuple(dedups)
    units = [{"tool": e.tool, "case": e.case_url, "phase": "extract", "status": e.status, "calls": e.calls,
              "candidates": len(e.candidates), "error": e.error} for e in extractions]
    units += [{"tool": d.tool, "case": d.case_url, "phase": "dedup", "status": d.status, "calls": d.calls, "error": d.error}
              for d in dedups]
    done = {(p.tool, p.case_url): p for p in pair_results}
    g = gate(extractions, dedups)
    bound = (admission_genuine(admission) and g.ok
             and admission.units_digest == digest([list(u) for u in g.units]))
    for e in extractions:
        p = done.get((e.tool, e.case_url))
        units.append({"tool": e.tool, "case": e.case_url, "phase": "pair",
                      "status": "sent" if p else ("not-needed" if bound and not e.candidates else "unsent"),
                      "pairs": len(p.pairs) if p else 0})
    complete = (bound and bool(extractions)
                and all((e.tool, e.case_url) in done for e in extractions if e.candidates)
                and all(p.plan_digest in admission.plan_digests and all("error" not in q for q in p.pairs) for p in done.values()))
    return {"schema": "score-attempt-set@1", "units": units, "admission": None if admission is None else admission.reason,
            "complete": bool(complete), "headline": "withheld unless complete"}
