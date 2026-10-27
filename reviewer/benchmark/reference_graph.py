"""Offline all-pairs reference report (S1-22). Validates `reference-judgments@1` documents against the pinned case,
counts with reference.evaluate_reference and pools with reference.pool_reference. A separately named view: the native
scorer (scoring.py, semantic-judgments@1) is untouched, and v1 matches are never expanded into pairs. No text/line
heuristics, no model calls. Reports carry ids, fixed status classes and counts only: no golden or candidate text and no free-form producer strings
except the declared ids and judge block, which are echoed verbatim and labelled producer-declared/unverified."""

from __future__ import annotations

import math

from .errors import BenchmarkError
from .jsonio import digest
from .model import ScorerCase
from .reference import (EVALUATION_SCHEMA, PINNED, REFERENCE_PROFILES, REFERENCE_VERSION, ZERO_CONVENTION,
                        evaluate_reference, pool_reference, reference_is_hidden)
from .scoring import JUDGE_KEYS, PARTITION_NOTICE

JUDGMENTS_SCHEMA = "reference-judgments@1"
REPORT_SCHEMA = "reference-score-report@1"
PRIMARY = {"profile": "core", "metric": "f1", "name": "core/F1"}
SECONDARY = ["strict/F1", "all/F1", "core/F2", "strict/F2", "all/F2"]
VIEW_LABEL = ("reference-count view (S1-21 evaluate_reference/pool_reference over supplied all-pairs judgments). Not the "
              "native null-valued scorer; undefined ratios are 0 under the named convention. No parity claim.")
UNRESOLVED = ["U1 source fact resolved (S1-23: dedup and step3 index the post-truthiness-filter list); the graph's "
              "candidateListSha256 is a separate strengthening upstream lacks (it stores no digest), and whitespace-only "
              "text is kept, not trimmed or dropped",
              "U2 raw judge reply -> match/confidence/error mapping is not built; pairs are supplied pre-mapped",
              "U3 golden category lookup is the pinned case's own category (normalized), not a glob-ordered file lookup",
              "U4 review-level timeouts have no document here: they are `missing`, never silently absent",
              "U5 evaluations with pair errors are pooled as upstream does, but the case/tool is not complete"]
NOTICES = [PARTITION_NOTICE, "A different judge's scores (including upstream Opus4.5/Sonnet4.5/GPT5.2) are not comparable.",
           "A tool entry that is not complete has no headline pooled numbers; partialPooled is not a score.",
           "Candidate ids and the judge block (model, prompts, schemaSha256, runRef) are producer declarations echoed "
           "verbatim: unverified, bound to no prompt or schema text, and not proved opaque or free of sensitive text.",
           "sourcePins is a binding check against the supplied Source object, not a cryptographic attestation; see "
           "SOURCE_ATTESTATION."]
SOURCE_ATTESTATION = ("The supplied Source object's cases for every attempted URL compare equal to the cases scored. Revision "
                      "and file digests are copied from that in-memory object as the loader recorded them; this scorer does "
                      "not re-read or re-verify the files and this is not a signature or cryptographic proof. Without a "
                      "bound source the report carries no score claim.")
PAIR_ERROR_CLASS = "judge-error"
_TOP = {"schema", "caseUrl", "tool", "judge", "extraction", "duplicateGroups", "pairs"}


def _bad(msg: str, code: str = "judgments"):
    raise BenchmarkError(code, msg)


def _int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _finite(x) -> bool:
    if not isinstance(x, (int, float)) or isinstance(x, bool):
        return False
    try:
        return math.isfinite(x)
    except OverflowError:
        return False


def _judge(j) -> dict:
    if not isinstance(j, dict) or set(j) != set(JUDGE_KEYS) or not all(isinstance(j[k], str) and j[k] for k in JUDGE_KEYS):
        _bad(f"judge block must have exactly non-empty string keys {list(JUDGE_KEYS)}")
    return dict(j)


def _validate(case: ScorerCase, doc, judges: list) -> tuple[dict, list, list, list]:
    """Return (judge, candidates, groups, pairs). All structural checks run first; the validated judge block is appended
    to `judges` before any `missing` (no review) or `incomplete` (missing pairs) refusal so those documents still take part
    in the judge-consistency check."""
    if not isinstance(doc, dict):
        _bad("a judgment document is not an object")
    if doc.get("schema") != JUDGMENTS_SCHEMA:
        _bad(f"schema must be {JUDGMENTS_SCHEMA} (semantic-judgments@1 matches cannot express all pairs and are never "
             "converted)")
    if set(doc) != _TOP:
        _bad("unexpected or missing top-level keys")
    if doc["caseUrl"] != case.url:
        _bad("caseUrl differs from the case")
    if not isinstance(doc["tool"], str) or not doc["tool"]:
        _bad("tool must be a non-empty string")
    judge = _judge(doc["judge"])
    ext = doc["extraction"]
    if not isinstance(ext, dict) or set(ext) != {"candidates"} or not isinstance(ext["candidates"], list):
        _bad("extraction must be exactly {candidates: [...]}")
    cands, ids = [], set()
    for c in ext["candidates"]:
        if (not isinstance(c, dict) or set(c) != {"id", "sourceCommentId", "text"} or not isinstance(c["id"], str)
                or not c["id"] or not isinstance(c["text"], str) or not c["text"]
                or not isinstance(c["sourceCommentId"], str)):
            _bad("malformed candidate (id, sourceCommentId, non-empty text)")
        if c["id"] in ids:
            _bad("duplicate candidate ids")
        ids.add(c["id"])
        cands.append({"id": c["id"], "text": c["text"], "src": c["sourceCommentId"]})
    dg = doc["duplicateGroups"]
    if not isinstance(dg, dict) or set(dg) != {"candidateListSha256", "groups"} or not isinstance(dg["groups"], list):
        _bad("duplicateGroups must be exactly {candidateListSha256, groups: [...]}")
    if dg["candidateListSha256"] != digest([[c["id"], c["text"]] for c in cands]):
        _bad("duplicateGroups.candidateListSha256 does not match the ordered candidate list")
    for g in dg["groups"]:
        if (not isinstance(g, list) or not g or not all(_int(i) and 0 <= i < len(cands) for i in g)
                or len(set(g)) != len(g)):
            _bad("duplicate group must be a non-empty list of distinct in-range candidate indices")
    pairs = doc["pairs"]
    if not isinstance(pairs, list):
        _bad("pairs must be a list")
    gold_ids = {g.id for g in case.golden}
    seen = set()
    for p in pairs:
        if not isinstance(p, dict) or not {"golden", "candidate"} <= set(p):
            _bad("pair needs golden and candidate ids")
        if set(p) == {"golden", "candidate", "error"}:
            if not isinstance(p["error"], str) or not p["error"]:
                _bad("pair error must be a non-empty string")
        elif set(p) == {"golden", "candidate", "match", "confidence"}:
            if not isinstance(p["match"], bool):
                _bad("pair match must be a boolean")
            if not _finite(p["confidence"]):
                _bad("pair confidence must be a finite number (null, bool, non-numeric and missing are refused; "
                     "the value is not range-limited or clamped: upstream compares unbounded numbers)")
        else:
            _bad("pair must be {golden, candidate, match, confidence} or {golden, candidate, error}")
        if not isinstance(p["golden"], str) or not isinstance(p["candidate"], str) \
                or p["golden"] not in gold_ids or p["candidate"] not in ids:
            _bad("pair references an unknown golden or candidate id")
        key = (p["golden"], p["candidate"])
        if key in seen:
            _bad("duplicate pair")
        seen.add(key)
    judges.append(judge)
    comment_ids = {c.id for c in case.review(doc["tool"]).comments}          # `missing` if the tool has no review here
    if any(c["src"] not in comment_ids for c in cands):
        _bad("a candidate cites a comment that is not in this tool's review")
    expected = len(case.golden) * len(cands)
    if len(seen) < expected:
        _bad(f"{expected - len(seen)} golden x candidate pair(s) have no judgment", "incomplete")
    return judge, cands, dg["groups"], pairs


def _sanitize(ev: dict, text_ids: dict) -> dict:
    """Ids and counts only. The reference evaluation is keyed by text; the report must hold no gold/candidate text."""
    prov = ev.get("provenance", {})
    out = {"schema": EVALUATION_SCHEMA, "referenceVersion": REFERENCE_VERSION, "skipped": bool(ev.get("skipped"))}
    if out["skipped"]:
        return {**out, "reason": ev.get("reason")}
    out.update(
        truePositives=[{k: r[k] for k in ("goldenIds", "severity", "category", "matchedCandidateId", "confidence")}
                       for r in ev["truePositives"]],
        falseNegatives=[{k: r[k] for k in ("goldenIds", "severity", "category")} for r in ev["falseNegatives"]],
        falsePositives=[{"candidateIds": r["candidateIds"]} for r in ev["falsePositives"]],
        errors=[{"golden": e["golden"], "candidate": e["candidate"], "status": PAIR_ERROR_CLASS}
                for e in ev["errors"]],          # the judge's free error string is never copied into the report
        **{k: ev[k] for k in ("tp", "fp", "fn", "errorsCount", "totalCandidates", "totalGolden")},
        provenance={"processing": prov.get("processing"), "zeroCandidates": bool(prov.get("zeroCandidates")),
                    "improvements": prov.get("improvements", []), "siblingMarked": [{"via": m["via"], "candidateIds": text_ids[m["candidate"]]}
                                      for m in prov.get("siblingMarked", [])],
                    "ignoredGroupIndices": prov.get("ignoredGroupIndices", []),
                    "goldenCollapsedIds": list(prov.get("goldenCollapse", {}).values()),
                    "candidateCollapsedIds": list(prov.get("candidateCollapse", {}).values())})
    return out


def _evaluate(case: ScorerCase, doc, judges: list) -> tuple[dict, dict, dict]:
    judge, cands, groups, pairs = _validate(case, doc, judges)
    golden = [{"id": g.id, "comment": g.comment, "severity": g.severity, "category": g.category} for g in case.golden]
    judgments = [dict(p) for p in pairs]
    ev = evaluate_reference(golden, [{"id": c["id"], "text": c["text"]} for c in cands], judgments, groups or None)
    cited = {c["src"] for c in cands}
    text_ids: dict = {}
    for c in cands:
        text_ids.setdefault(c["text"], []).append(c["id"])
    comments = case.review(doc["tool"]).comments
    overlap = len(sum(groups, [])) - len({i for g in groups for i in g})
    row = {"caseUrl": case.url, "tool": doc["tool"], "judge": judge,
           "status": "skipped-zero-gold" if ev.get("skipped") else "scored",
           "candidates": len(cands), "goldenCount": len(case.golden), "pairsExpected": len(case.golden) * len(cands),
           "pairErrors": sum(1 for p in pairs if "error" in p), "duplicateGroups": len(groups),
           "overlappingGroupIndices": overlap, "rawComments": len(comments),
           "uncoveredCommentIds": [c.id for c in comments if c.id not in cited],
           "evaluation": _sanitize(ev, text_ids), "judgmentsDigest": digest(doc)}
    return row, ev, judge


def score_reference_case(case: ScorerCase, doc) -> dict:
    return _evaluate(case, doc, [])[0]


def _views(tool: str, evals: dict) -> dict:
    out = {}
    for prof in REFERENCE_PROFILES:
        r = pool_reference(evals, profile=prof, beta=2)[tool]
        out[prof] = {"counts": {k: r[k] for k in ("tp", "fp", "fn", "prs")}, "precision": r["precision"],
                     "recall": r["recall"], "f1": r["f1"], "f2": r["fbeta"], "undefined": r["undefined"],
                     "zeroConvention": ZERO_CONVENTION}
    return out


def _bind(source, cases: dict, urls: list):
    """Return the sourcePins block, or None when `source` is None (explicitly unbound). A supplied source must hold exactly
    the cases being scored for every attempted URL; an unrelated or non-Source object is refused."""
    if source is None:
        return None
    rev, files, held = (getattr(source, a, None) for a in ("revision", "file_digests", "cases"))
    if not (isinstance(rev, str) and rev and isinstance(files, dict) and isinstance(held, dict)):
        raise BenchmarkError("source", "source must be a loaded Source (revision, file_digests, cases)")
    if any(held.get(u) != cases[u] for u in urls):
        raise BenchmarkError("source", "source does not hold the cases being scored; sourcePins would not bind them")
    return {"revision": rev, "files": dict(files), "boundCaseUrls": list(urls), "attestation": SOURCE_ATTESTATION}


def score_reference_suite(cases: dict, docs: list, *, tools: list, urls: list | None = None, source=None) -> dict:
    """`source=None` is an explicit unbound convenience for synthetic use: the report is never complete and pools are
    labelled not-a-score."""
    if not isinstance(tools, list) or not tools or not all(isinstance(t, str) and t for t in tools) \
            or len(set(tools)) != len(tools):
        raise BenchmarkError("args", "tools must be a non-empty list of distinct names")
    urls = list(cases) if urls is None else list(urls)
    if len(set(urls)) != len(urls):
        raise BenchmarkError("roster", "score request repeats a URL")
    if not urls or any(u not in cases for u in urls):
        raise BenchmarkError("roster", "score request is empty or names a URL that is not a case")
    pins = _bind(source, cases, urls)
    if not isinstance(docs, list):
        raise BenchmarkError("judgments", "judgments must be a list of documents")
    by_key = {}
    for d in docs:
        if not isinstance(d, dict):
            raise BenchmarkError("judgments", "a judgment document is not an object")
        key = (d.get("caseUrl"), d.get("tool"))
        if not all(isinstance(k, str) for k in key):
            raise BenchmarkError("judgments", "caseUrl and tool must be strings")
        if key in by_key:
            raise BenchmarkError("judgments", "two judgment documents for one (case, tool)")
        by_key[key] = d
    wanted = {(u, t) for u in urls for t in tools}
    extra = [k for k in by_key if k not in wanted]
    if extra:
        raise BenchmarkError("judgments", f"{len(extra)} judgment document(s) are for cases/tools not requested; "
                             "refusing to ignore them")
    judges, entries = [], {}
    for tool in tools:
        rows, evals, missing, incomplete = [], {}, [], []
        for u in urls:
            d = by_key.get((u, tool))
            if d is None:
                missing.append(u)
                continue
            try:
                row, ev, judge = _evaluate(cases[u], d, judges)
            except BenchmarkError as e:
                if e.code in ("incomplete", "missing"):
                    incomplete.append({"caseUrl": u, "reason": e.message})
                    continue
                raise
            rows.append(row)
            if row["status"] == "scored":
                evals[u] = {tool: ev}
        scored = [r for r in rows if r["status"] == "scored"]
        hidden = reference_is_hidden(tool)
        err_cases = sorted(r["caseUrl"] for r in rows if r["pairErrors"])
        complete = bool(scored) and not missing and not incomplete and not err_cases and not hidden and pins is not None
        views = _views(tool, evals) if scored and not hidden else None
        entries[tool] = {
            "casesExpected": len(urls), "casesScored": len(scored),
            "zeroGoldSkipped": sorted(r["caseUrl"] for r in rows if r["status"] == "skipped-zero-gold"),
            "missing": missing, "incomplete": incomplete, "pairErrorCases": err_cases, "referenceHidden": hidden,
            "sourceBound": pins is not None, "complete": complete, "pooled": views if complete else None,
            "partialPooled": None if complete or views is None else {"notAScore": True, "views": views},
            "extractionCoverage": {"rawComments": sum(r["rawComments"] for r in rows),
                                   "uncoveredComments": sum(len(r["uncoveredCommentIds"]) for r in rows),
                                   "casesWithUncovered": sorted(r["caseUrl"] for r in rows if r["uncoveredCommentIds"])},
            "cases": rows}
    if any(j != judges[0] for j in judges):
        raise BenchmarkError("judge-mismatch", "judgments come from different judge configurations; not comparable")
    return {"schema": REPORT_SCHEMA, "referenceView": {"label": VIEW_LABEL, "version": REFERENCE_VERSION,
                                                        "pinnedSources": dict(PINNED), "zeroConvention": ZERO_CONVENTION,
                                                        "nativeNullView": "separate; see score/benchmark-score-report@1"},
            "attempted": {"urls": urls, "tools": list(tools), "subset": set(urls) != set(cases)},
            "sourcePins": pins, "sourceBound": pins is not None,
            "judge": judges[0] if judges else None, "judgeStatus": "producer-declared, unverified",
            "judgeDigest": digest(judges[0]) if judges else None, "primary": dict(PRIMARY), "secondary": list(SECONDARY),
            "tools": entries, "unresolved": list(UNRESOLVED), "notices": list(NOTICES),
            "complete": bool(entries) and all(t["complete"] for t in entries.values())}
