"""Reference-compatible counting over externally supplied all-pairs semantic judgments (S1-21). Pure and offline.

Independently reimplements the counting of the pinned upstream sources (read as text, never executed or imported):
`S3` = offline/code_review_benchmark/step3_judge_comments.py, `SP` = offline/analysis/score_profiles.py at
revision e616e849. Upstream quirks are preserved on purpose (literal-text collapse, strict confidence improvement,
order-sensitive matched candidates, uncollapsed zero-candidate FN rows, undefined ratios as 0). This is a separately
named view: it does not replace or alter the native null-valued scorer in scoring.py. See
orchestration/handoffs/S1-21-interface.md for line references, divergences and unresolved seams.
"""

from __future__ import annotations

import math

from .errors import BenchmarkError

REFERENCE_VERSION = "martian-reference-count@e616e849/1"
EVALUATION_SCHEMA = "reference-evaluation@1"
PINNED = {
    "revision": "e616e849755441da38f18bf3adba2c9583b03803",
    "step3_judge_comments.py": "sha256:7370dfb21bed01655aada1d4d75f32e07c92e4c4c86dfc6cf6d47058a65ce16d",
    "score_profiles.py": "sha256:b5d474a373f008f0899dbcbe8deca5f596d8081bc9579b75391971f6f2959f52",
}
ZERO_CONVENTION = "reference-undefined-is-0"
MAX_BETA = 1.3407807929942596e154  # sqrt(max double): the largest beta whose square is finite (N2)
SKIP_REASON = "No golden comments"  # S3:249-253
PROCESSING = "golden-major, candidate-minor, input order; strict confidence improvement from 0.0 (S3:275-330)"

# SP:19-26
REFERENCE_PROFILES = {
    "strict": frozenset({"bug", "security", "concurrency", "data", "api"}),
    "core": frozenset({"bug", "security", "concurrency", "data", "api", "perf", "test_gap", "doc_defect"}),
    "all": frozenset({"bug", "security", "concurrency", "data", "api", "perf", "test_gap", "doc_defect",
                      "style", "speculative"}),
}
# SP:28-35
REFERENCE_HIDDEN_TOOLS = frozenset({
    "qodo", "greptile", "linearb", "bito", "sentry", "vercel", "kodus", "cubic-dev", "cubic-v3", "greptile-v4",
    "mergemonkey", "qodo-v22", "qodo-v2-2", "qodo-extended-summary", "qodo-extended", "entelligence", "mesa",
    "codeant", "propel", "propel-v2", "gemini", "gitar", "deepsource",
})
REFERENCE_HIDDEN_PREFIXES = ("mra-",)


def _bad(message: str):
    raise BenchmarkError("reference-input", message)


def _id(x, what: str) -> str:
    if not isinstance(x, str) or not x:
        _bad(f"{what} id must be a non-empty string")
    return x


def _rows(items, keys: set, required: set, what: str) -> list:
    if not isinstance(items, list):
        _bad(f"{what} must be a list")
    for r in items:
        if not isinstance(r, dict) or not required <= set(r) <= keys:
            _bad(f"{what} entries need keys {sorted(required)} (allowed {sorted(keys)})")
    ids = [_id(r["id"], what) for r in items]
    if len(set(ids)) != len(ids):
        _bad(f"duplicate {what} id")
    return items


def _number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _finite(x) -> bool:
    """D4: JSON-domain numbers representable as a finite double. NaN/inf are refused, not compared with Python semantics;
    an int beyond the double range (e.g. 10**400) is refused too (N1), where math.isfinite would raise OverflowError."""
    if not _number(x):
        return False
    try:
        return math.isfinite(x)
    except OverflowError:
        return False


def _label(row: dict, key: str, what: str) -> None:
    """category/severity: optional, str or null (SP:76 treats any falsy category as absent)."""
    if row.get(key) is not None and not isinstance(row[key], str):
        _bad(f"{what} {key} must be a string or null")


def _judgments(judgments, golden: list, candidates: list) -> dict:
    """Index judgments by (golden index, candidate index); exactly one per pair, as S3 judges every pair."""
    if not isinstance(judgments, list):
        _bad("judgments must be a list")
    gi = {g["id"]: i for i, g in enumerate(golden)}
    ci = {c["id"]: i for i, c in enumerate(candidates)}
    out = {}
    for j in judgments:
        if not isinstance(j, dict) or not {"golden", "candidate"} <= set(j):
            _bad("judgment needs golden and candidate ids")
        _id(j["golden"], "judgment golden")  # F1: type-check before hashing into the id maps
        _id(j["candidate"], "judgment candidate")
        if set(j) == {"golden", "candidate", "error"}:
            if not isinstance(j["error"], str) or not j["error"]:
                _bad("judgment error must be a non-empty string")
        elif set(j) in ({"golden", "candidate", "match", "confidence"}, {"golden", "candidate", "match"}):
            if not isinstance(j["match"], bool):
                _bad("judgment match must be a boolean (raw judge truthiness is the caller's mapping)")
            # Absent key = S3 get("confidence", 0) default. Explicit null is refused (D3): S3:322 raises TypeError on
            # None > best when match is truthy and never reads it otherwise; it is not the same as the default 0.
            if "confidence" in j and not _finite(j["confidence"]):
                _bad("judgment confidence must be a finite number or absent (explicit null is not the missing-key "
                     "default; NaN/inf refused, D4)")
        else:
            _bad("judgment must be {golden, candidate, match[, confidence]} or {golden, candidate, error}")
        if j["golden"] not in gi or j["candidate"] not in ci:
            _bad(f"judgment references unknown id {j['golden']!r}/{j['candidate']!r}")
        key = (gi[j["golden"]], ci[j["candidate"]])
        if key in out:
            _bad(f"duplicate judgment for {j['golden']!r}/{j['candidate']!r}")
        out[key] = j
    if len(out) != len(golden) * len(candidates):
        missing = next((g["id"], c["id"]) for a, g in enumerate(golden) for b, c in enumerate(candidates)
                       if (a, b) not in out)
        _bad(f"missing judgment for {missing[0]!r}/{missing[1]!r}")
    return out


def _sibling_map(texts: list, groups) -> tuple[dict, list]:
    """S3:222-238: text -> sibling texts; later groups overwrite; out-of-range indices silently ignored (reported)."""
    if groups is not None and not isinstance(groups, list):
        _bad("duplicate_groups must be a list of index lists or null")
    for g in groups or ():
        if not isinstance(g, list) or not all(isinstance(i, int) and not isinstance(i, bool) and i >= 0 for i in g):
            _bad("duplicate group must be a list of non-negative integer indices")
    if not groups:
        return {}, []
    smap, ignored = {}, []
    for k, group in enumerate(groups):
        group_texts = {texts[i] for i in group if i < len(texts)}
        ignored += [[k, i] for i in group if i >= len(texts)]
        for i in group:
            if i < len(texts):
                smap[texts[i]] = group_texts - {texts[i]}
    return smap, ignored


def _collapse(items: list, key: str) -> dict:
    """Literal text -> input ids, first-occurrence order."""
    out: dict = {}
    for r in items:
        out.setdefault(r[key], []).append(r["id"])
    return out


def evaluate_reference(golden, candidates, judgments, duplicate_groups=None) -> dict:
    """Per-case evaluation equivalent to S3 `evaluate_review` given the same pair judgments in the same order."""
    golden = _rows(golden, {"id", "comment", "severity", "category"}, {"id", "comment"}, "golden")
    candidates = _rows(candidates, {"id", "text"}, {"id", "text"}, "candidate")
    if not all(isinstance(g["comment"], str) for g in golden):
        _bad("golden comment must be a string")
    for g in golden:  # F5
        _label(g, "category", "golden")
        _label(g, "severity", "golden")
    if not all(isinstance(c["text"], str) and c["text"] for c in candidates):
        _bad("candidate text must be a non-empty string (S3 get_candidates drops empty text before evaluation)")
    pairs = _judgments(judgments, golden, candidates)
    texts = [c["text"] for c in candidates]
    sibling_map, ignored = _sibling_map(texts, duplicate_groups)
    base = {"schema": EVALUATION_SCHEMA, "referenceVersion": REFERENCE_VERSION}

    if not golden:
        return {**base, "skipped": True, "reason": SKIP_REASON}
    if not candidates:  # S3:255-273: one FN per golden input, no text collapse
        fns = [{"goldenComment": g["comment"], "goldenIds": [g["id"]], "severity": g.get("severity"),
                "category": g.get("category")} for g in golden]
        # F4: same provenance keys as the main path; no golden collapse because these rows are uncollapsed
        return {**base, "skipped": False, "truePositives": [], "falsePositives": [], "falseNegatives": fns,
                "errors": [], "totalCandidates": 0, "totalGolden": len(golden), "tp": 0, "fp": 0, "fn": len(fns),
                "errorsCount": 0,
                "provenance": {"processing": PROCESSING, "zeroCandidates": True, "improvements": [],
                               "siblingMarked": [], "siblingMap": {}, "ignoredGroupIndices": ignored,
                               "goldenCollapse": {}, "candidateCollapse": {}}}

    gold_ids = _collapse(golden, "comment")
    cand_ids = _collapse(candidates, "text")
    state = {t: {"severity": None, "category": None, "matched": False, "best": 0.0, "cand": None, "candId": None}
             for t in gold_ids}
    for g in golden:  # S3:294-304 dict comprehension: last duplicate's severity/category win
        state[g["comment"]].update(severity=g.get("severity"), category=g.get("category"))
    matched = dict.fromkeys(cand_ids, False)
    errors, improvements, sibling_marked = [], [], []

    for a, g in enumerate(golden):
        for b, c in enumerate(candidates):
            j = pairs[(a, b)]
            if "error" in j:
                errors.append({"golden": g["id"], "candidate": c["id"], "error": j["error"]})
                continue
            conf = j.get("confidence", 0)  # S3:322 missing-key default; null already refused
            s = state[g["comment"]]
            if j["match"] and conf > s["best"]:
                s.update(matched=True, best=conf, cand=c["text"], candId=c["id"])
                matched[c["text"]] = True
                improvements.append({"golden": g["id"], "candidate": c["id"], "confidence": conf})
                for sib in sorted(sibling_map.get(c["text"], ())):
                    if not matched[sib]:
                        sibling_marked.append({"via": c["id"], "candidate": sib})
                    matched[sib] = True

    tps, fns = [], []
    for text, s in state.items():
        row = {"goldenComment": text, "goldenIds": gold_ids[text], "severity": s["severity"], "category": s["category"]}
        if s["matched"]:
            tps.append({**row, "matchedCandidate": s["cand"], "matchedCandidateId": s["candId"], "confidence": s["best"]})
        else:
            fns.append(row)
    fps = [{"candidate": t, "candidateIds": cand_ids[t]} for t, m in matched.items() if not m]
    return {**base, "skipped": False, "truePositives": tps, "falsePositives": fps, "falseNegatives": fns,
            "errors": errors, "totalCandidates": len(candidates), "totalGolden": len(golden), "tp": len(tps),
            "fp": len(fps), "fn": len(fns), "errorsCount": len(errors),
            "provenance": {"processing": PROCESSING, "zeroCandidates": False, "improvements": improvements,
                           "siblingMarked": sibling_marked,
                           "siblingMap": {t: sorted(v) for t, v in sibling_map.items()},
                           "ignoredGroupIndices": ignored,
                           "goldenCollapse": {t: v for t, v in gold_ids.items() if len(v) > 1},
                           "candidateCollapse": {t: v for t, v in cand_ids.items() if len(v) > 1}}}


def reference_is_hidden(tool: str) -> bool:
    return tool in REFERENCE_HIDDEN_TOOLS or tool.startswith(REFERENCE_HIDDEN_PREFIXES)


def _evaluation(ev) -> None:
    """F3: shapes SP reads (SP:97, 103-108), with its optional defaults. Every row is checked, hidden/skipped too."""
    if not isinstance(ev, dict):
        _bad("evaluation must be an object")
    if "skipped" in ev and not isinstance(ev["skipped"], bool):
        _bad("evaluation skipped must be a boolean")
    fp = ev.get("fp", 0)
    if not isinstance(fp, int) or isinstance(fp, bool) or fp < 0:
        _bad("evaluation fp must be a non-negative integer")
    for key in ("truePositives", "falseNegatives"):
        rows = ev.get(key, [])
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            _bad(f"evaluation {key} must be a list of objects")
        for r in rows:
            if not isinstance(r.get("goldenComment", ""), str):
                _bad(f"{key} goldenComment must be a string")
            _label(r, "category", key)
            _label(r, "severity", key)


def _fbeta(p: float, r: float, beta: float) -> float:  # SP:79-82; pool_reference bounds beta so b2 is finite (N2)
    b2 = beta * beta
    den = b2 * p + r
    return (1 + b2) * p * r / den if den > 0 else 0.0


def pool_reference(evaluations, *, profile: str, beta, golden_categories=None) -> dict:
    """SP `score_tools`: per-tool pooled (micro) counts over cases, profile-filtered TP/FN, supplied FP unchanged."""
    if not isinstance(profile, str) or profile not in REFERENCE_PROFILES:
        _bad(f"profile must be one of {sorted(REFERENCE_PROFILES)}")
    if not _finite(beta) or beta <= 0:
        _bad("beta must be an explicit positive finite number")
    if not math.isfinite(float(beta) * float(beta)):  # N2: SP would get b2=inf and emit NaN; refused, never clamped
        _bad(f"beta must satisfy beta*beta < inf (beta <= {MAX_BETA!r}); larger values make SP's Fbeta NaN")
    if golden_categories is not None and not (isinstance(golden_categories, dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in golden_categories.items())):
        _bad("golden_categories must be null or {golden comment text: category string}")
    if not isinstance(evaluations, dict):
        _bad("evaluations must be {case: {tool: evaluation}}")
    for case, per_tool in evaluations.items():
        if not isinstance(case, str) or not isinstance(per_tool, dict):
            _bad("evaluations must be {case: {tool: evaluation}}")
        for tool, ev in per_tool.items():
            if not isinstance(tool, str) or not tool:
                _bad("tool must be a non-empty string")
            _evaluation(ev)
    cats, lookup = REFERENCE_PROFILES[profile], golden_categories or {}

    def category(row: dict) -> str:  # SP:75-76
        return row.get("category") or lookup.get(row.get("goldenComment", ""), "")

    totals: dict = {}
    for per_tool in evaluations.values():
        for tool, ev in per_tool.items():
            if reference_is_hidden(tool) or ev.get("skipped"):
                continue
            t = totals.setdefault(tool, {"tp": 0, "fp": 0, "fn": 0, "prs": 0})
            t["tp"] += sum(1 for row in ev.get("truePositives", []) if category(row) in cats)
            t["fn"] += sum(1 for row in ev.get("falseNegatives", []) if category(row) in cats)
            t["fp"] += ev.get("fp", 0)
            t["prs"] += 1
    out = {}
    for tool, t in totals.items():
        undefined = [n for n, d in (("precision", t["tp"] + t["fp"]), ("recall", t["tp"] + t["fn"])) if d == 0]
        p = t["tp"] / (t["tp"] + t["fp"]) if "precision" not in undefined else 0.0
        r = t["tp"] / (t["tp"] + t["fn"]) if "recall" not in undefined else 0.0
        out[tool] = {**t, "precision": p, "recall": r, "f1": _fbeta(p, r, 1.0), "fbeta": _fbeta(p, r, beta),
                     "beta": beta, "profile": profile, "zeroConvention": ZERO_CONVENTION, "undefined": undefined,
                     "referenceVersion": REFERENCE_VERSION}
    return out
