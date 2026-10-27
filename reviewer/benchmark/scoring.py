"""Score supplied (external, already validated) semantic judgments. No matching logic lives here: a candidate is a
true positive only because a judgment says it matches a golden id. No line/path overlap, no text heuristics."""

from __future__ import annotations

from .errors import BenchmarkError
from .jsonio import digest
from .model import PROFILES, ScorerCase

JUDGMENTS_SCHEMA = "semantic-judgments@1"
REPORT_SCHEMA = "benchmark-score-report@1"
JUDGE_KEYS = ("model", "extractionPrompt", "dedupPrompt", "matchPrompt", "schemaSha256", "runRef")
PRIMARY = ("core", 1)
SECONDARY = (("strict", 1), ("all", 1), ("core", 2), ("strict", 2), ("all", 2))
PARTITION_NOTICE = ("Frozen public45 is not a human-sealed set and public dev5 is descriptive/tuning-eligible only. "
                    "Offline metric mechanics are not competitive quality.")
UNVERIFIED = ("Pooled (micro) aggregation matches the pinned reference (score_profiles.py lines 110-118). "
              "Counting is NOT reference-compatible: native counts treat every matched representative as a true positive "
              "(upstream: one TP per matched distinct golden, order-sensitive on confidence; native reports multiMatchedGolden), count an unmatched duplicate "
              "group once (upstream: every member), and score zero-golden cases (upstream skips them); the match schema "
              "cannot represent one candidate matching several goldens. B2/B3 are on HOLD; no reference-compatible view exists.")
ZERO_VIEW_LABEL = ("native counts with the upstream undefined->0 convention ONLY; not the reference formula "
                   "(see unverifiedSemantics)")
REFERENCE_VIEW = {"status": "unavailable", "reason": "reference-formula reduction not implemented (B2/B3 HOLD); "
                  "neither native nor upstreamCompatZero may be read as upstream-equivalent"}


def ratio(num: int, den: int, reason: str) -> dict:
    if den == 0:
        return {"value": None, "numerator": 0, "denominator": 0, "undefinedReason": reason}
    return {"value": num / den, "numerator": num, "denominator": den, "undefinedReason": None}


def fbeta(p: dict, r: dict, beta: int) -> dict:
    why = [f"{n} undefined: {x['undefinedReason']}" for n, x in (("precision", p), ("recall", r)) if x["value"] is None]
    if why:
        return {"value": None, "undefinedReason": "; ".join(why)[:240]}
    pv, rv, b2 = p["value"], r["value"], beta * beta
    return {"value": 0.0 if pv + rv == 0 else (1 + b2) * pv * rv / (b2 * pv + rv), "undefinedReason": None}


def _zero(x: dict) -> dict:
    return {"value": 0.0 if x["value"] is None else x["value"], "numerator": x.get("numerator"),
            "denominator": x.get("denominator"), "undefinedReason": None}


def views(c: dict) -> dict:
    """Metric views from raw counts {profile: {tp, fp, excluded, goldRecalled, goldTotal}}."""
    out = {}
    for name, k in c.items():
        p = ratio(k["tp"], k["tp"] + k["fp"], "no candidate left in the precision denominator")
        r = ratio(k["goldRecalled"], k["goldTotal"], "no golden comment in this profile")
        native = {"precision": p, "recall": r, "f1": fbeta(p, r, 1), "f2": fbeta(p, r, 2)}
        pz, rz = _zero(p), _zero(r)
        zero = {"label": ZERO_VIEW_LABEL, "precision": pz, "recall": rz,
                "f1": {"value": fbeta(pz, rz, 1)["value"], "undefinedReason": None},
                "f2": {"value": fbeta(pz, rz, 2)["value"], "undefinedReason": None}}
        out[name] = {"counts": dict(k), "native": native, "upstreamCompatZero": zero}
    return out


def _check_judge(j) -> dict:
    if not isinstance(j, dict) or set(j) != set(JUDGE_KEYS) or not all(isinstance(j[k], str) and j[k] for k in JUDGE_KEYS):
        raise BenchmarkError("judgments", f"judge block must have exactly non-empty string keys {list(JUDGE_KEYS)}")
    return dict(j)


def _validate(case: ScorerCase, doc: dict) -> tuple[dict, list, dict]:
    if not isinstance(doc, dict) or doc.get("schema") != JUDGMENTS_SCHEMA:
        raise BenchmarkError("judgments", f"schema must be {JUDGMENTS_SCHEMA}")
    if set(doc) != {"schema", "caseUrl", "tool", "judge", "extraction", "duplicateGroups", "matches"}:
        raise BenchmarkError("judgments", "unexpected or missing top-level keys")
    if doc["caseUrl"] != case.url:
        raise BenchmarkError("judgments", "caseUrl differs from the case")
    review = case.review(doc["tool"])
    judge = _check_judge(doc["judge"])
    comment_ids = {c.id for c in review.comments}
    cands = doc["extraction"].get("candidates") if isinstance(doc["extraction"], dict) else None
    if not isinstance(cands, list):
        raise BenchmarkError("incomplete", "extraction.candidates missing")
    ids = []
    for c in cands:
        if not isinstance(c, dict) or set(c) != {"id", "sourceCommentId", "text"} or not isinstance(c["id"], str) \
                or not isinstance(c["text"], str) or not c["text"]:
            raise BenchmarkError("judgments", "malformed candidate")
        if c["sourceCommentId"] not in comment_ids:
            raise BenchmarkError("judgments", f"candidate {c['id']} cites a comment not in this tool's review")
        ids.append(c["id"])
    if len(set(ids)) != len(ids):
        raise BenchmarkError("judgments", "duplicate candidate ids")
    seen, reps = set(), {}
    groups = doc["duplicateGroups"]
    if not isinstance(groups, list):
        raise BenchmarkError("incomplete", "duplicateGroups missing")
    for g in groups:
        if not isinstance(g, dict) or set(g) != {"id", "representative", "members"} or not isinstance(g["members"], list):
            raise BenchmarkError("judgments", "malformed duplicate group")
        mem = g["members"]
        if not mem or len(set(mem)) != len(mem) or g["representative"] not in mem or not set(mem) <= set(ids):
            raise BenchmarkError("judgments", f"group {g.get('id')}: representative/members invalid or unknown")
        if seen & set(mem):
            raise BenchmarkError("judgments", "a candidate belongs to two duplicate groups")
        seen |= set(mem)
        reps[g["representative"]] = list(mem)
    if seen != set(ids):
        raise BenchmarkError("incomplete", f"{len(set(ids) - seen)} candidate(s) are in no duplicate group")
    gold_ids = {g.id for g in case.golden}
    matched = {}
    for m in doc["matches"]:
        if not isinstance(m, dict) or set(m) != {"candidate", "golden", "reason"} or not isinstance(m["reason"], str):
            raise BenchmarkError("judgments", "malformed match entry")
        if m["candidate"] not in reps:
            raise BenchmarkError("judgments", f"match for {m['candidate']!r}, which is not a group representative")
        if m["candidate"] in matched:
            raise BenchmarkError("judgments", f"two matches for {m['candidate']}")
        if m["golden"] is not None and m["golden"] not in gold_ids:
            raise BenchmarkError("judgments", f"match cites unknown golden {m['golden']!r}")
        matched[m["candidate"]] = m["golden"]
    if set(matched) != set(reps):
        raise BenchmarkError("incomplete", f"{len(set(reps) - set(matched))} representative(s) have no judgment")
    return judge, list(reps), matched


def score_case(case: ScorerCase, doc: dict) -> dict:
    judge, reps, matched = _validate(case, doc)
    cat = {g.id: g.category for g in case.golden}
    counts, multi = {}, {}
    for name, cats in PROFILES.items():
        in_gold = {g for g, c in cat.items() if c in cats}
        tp = fp = excl = 0
        hits: dict[str, int] = {}
        for rep in reps:
            g = matched[rep]
            if g is None:
                fp += 1
            elif g in in_gold:
                tp += 1
                hits[g] = hits.get(g, 0) + 1
            else:
                excl += 1
        counts[name] = {"tp": tp, "fp": fp, "excluded": excl, "goldRecalled": len(hits), "goldTotal": len(in_gold)}
        multi[name] = sorted(g for g, n in hits.items() if n > 1)
    all_cands = len(doc["extraction"]["candidates"])
    cited = {c["sourceCommentId"] for c in doc["extraction"]["candidates"]}
    uncovered = [c.id for c in case.review(doc["tool"]).comments if c.id not in cited]
    return {"caseUrl": case.url, "tool": doc["tool"], "judge": judge, "status": "scored",
            "candidates": all_cands, "representatives": len(reps), "duplicateMembersNotCounted": all_cands - len(reps),
            "rawComments": len(case.review(doc["tool"]).comments), "uncoveredCommentIds": uncovered,
            "views": views(counts), "multiMatchedGolden": multi, "judgmentsDigest": digest(doc)}


def _add(a: dict, b: dict) -> dict:
    return {k: a[k] + b[k] for k in a}


def score_suite(cases: dict, docs: list, *, tools: list[str], urls: list[str] | None = None) -> dict:
    """cases: url -> ScorerCase. Each tool is expected on every url in `urls` (default: all). Missing/incomplete cases
    are listed and stay out of the pooled counts; `complete` says whether the pooled number covers everything."""
    urls = list(cases) if urls is None else list(urls)
    unknown = [u for u in urls if u not in cases]
    if unknown:
        raise BenchmarkError("roster", "score request names a URL that is not a case")
    by_key, judges = {}, []
    for d in docs:
        if not isinstance(d, dict):
            raise BenchmarkError("judgments", "a judgment document is not an object")
        key = (d.get("caseUrl"), d.get("tool"))
        if key in by_key:
            raise BenchmarkError("judgments", "two judgment documents for one (case, tool)")
        by_key[key] = d
    wanted = {(u, t) for u in urls for t in tools}
    extra = sorted(((str(u)[:80], str(t)[:40]) for u, t in by_key if (u, t) not in wanted))
    if extra:
        raise BenchmarkError("judgments", f"{len(extra)} judgment document(s) are for cases/tools not requested, "
                             f"e.g. {extra[:3]}; refusing to ignore them")
    report_tools = {}
    for tool in tools:
        rows, pooled, missing, incomplete = [], None, [], []
        for u in urls:
            d = by_key.get((u, tool))
            if d is None:
                missing.append(u)
                continue
            try:
                row = score_case(cases[u], d)
            except BenchmarkError as e:
                if e.code in ("incomplete", "missing"):
                    incomplete.append({"caseUrl": u, "reason": e.message})
                    continue
                raise
            rows.append(row)
            judges.append(row["judge"])
            c = {n: row["views"][n]["counts"] for n in PROFILES}
            pooled = c if pooled is None else {n: _add(pooled[n], c[n]) for n in PROFILES}
        report_tools[tool] = {"casesExpected": len(urls), "casesScored": len(rows), "missing": missing,
                              "incomplete": incomplete, "complete": not missing and not incomplete,
                              "pooled": views(pooled) if pooled else None, "cases": rows,
                              "extractionCoverage": {
                                  "rawComments": sum(r["rawComments"] for r in rows),
                                  "uncoveredComments": sum(len(r["uncoveredCommentIds"]) for r in rows),
                                  "casesWithUncovered": sorted(r["caseUrl"] for r in rows if r["uncoveredCommentIds"])}}
    if any(j != judges[0] for j in judges):
        raise BenchmarkError("judge-mismatch", "judgments come from different judge configurations; not comparable")
    pooled_ok = [t for t in report_tools.values() if t["pooled"]]
    return {"schema": REPORT_SCHEMA, "primary": {"profile": PRIMARY[0], "beta": PRIMARY[1], "name": "core/F1"},
            "secondary": [f"{p}/F{b}" for p, b in SECONDARY], "judge": judges[0] if judges else None,
            "tools": report_tools, "referenceCompatibleView": dict(REFERENCE_VIEW), "partitionNotice": PARTITION_NOTICE, "unverifiedSemantics": UNVERIFIED,
            "judgeComparability": "A different judge's scores (including upstream Opus4.5/Sonnet4.5/GPT5.2) are not comparable.",
            "complete": bool(pooled_ok) and all(t["complete"] for t in report_tools.values())}
