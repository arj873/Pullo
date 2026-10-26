"""SAFE metadata projection and tool-version policy. No bodies, paths, titles, labels or gold text leave this module."""

from __future__ import annotations

from datetime import datetime, timezone

from .errors import BenchmarkError
from .jsonio import digest

PROJECTION_SCHEMA = "benchmark-metadata-projection@1"
RULES_SCHEMA = "benchmark-version-rules@1"
RULES_SCHEMA_V2 = "benchmark-version-rules@2"
FAMILIES = ("cubic", "coderabbit", "greptile")


def parse_ts(s: str) -> datetime | None:
    try:
        t = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def project_metadata(source) -> dict:
    cases = []
    for url, c in source.cases.items():
        reviews = []
        for r in c.reviews:
            ts = [parse_ts(x.created_at) for x in r.comments]
            ok = all(t is not None for t in ts)
            stamps = sorted(x.created_at for x, t in zip(r.comments, ts) if t is not None)
            reviews.append({"tool": r.tool, "repoName": r.repo_name, "prUrl": r.pr_url, "commentCount": len(r.comments),
                            "summaryCommentCount": sum(1 for x in r.comments if x.path is None),
                            "firstCreatedAt": stamps[0] if stamps else None, "lastCreatedAt": stamps[-1] if stamps else None,
                            "timestampsParseable": ok})
        cases.append({"url": url, "sourceRepo": c.source_repo, "originalUrl": c.original_url,
                      "goldenCount": len(c.golden), "reviews": reviews,
                      "diagnostics": {"hasReviews": bool(reviews),
                                      "allTimestampsParseable": all(r["timestampsParseable"] for r in reviews),
                                      "urlMatchesOriginal": c.original_url in (None, url)}})
    return {"schema": PROJECTION_SCHEMA, "revision": source.revision, "excludedFixtures": list(source.excluded_fixtures),
            "cases": cases}


def _check_rules(rules) -> int:
    """Validate a rules document; return its version (1 or 2).

    v1: `superseded` = exact ids to drop; with several survivors nothing is chosen.
    v2: `upstreamHidden` = ONLY ids hidden by the pinned upstream rules. `primary` is root's explicit, pre-score project
    choice among survivors (not an upstream fact; needs `primaryBasis`); `secondary` are retained named comparisons."""
    ok = isinstance(rules, dict) and rules.get("schema") in (RULES_SCHEMA, RULES_SCHEMA_V2) \
        and isinstance(rules.get("families"), dict)
    if not ok:
        raise BenchmarkError("rules", f"schema must be {RULES_SCHEMA} or {RULES_SCHEMA_V2} with families")
    v2 = rules["schema"] == RULES_SCHEMA_V2
    hidden_key = "upstreamHidden" if v2 else "superseded"
    base = {"prefix", hidden_key, "skipped", "source"}
    if v2 and set(rules) != {"schema", "families", "selectionDecision"}:
        raise BenchmarkError("rules", "v2 rules need exactly schema, families and selectionDecision")
    if v2 and (not isinstance(rules["selectionDecision"], dict) or not rules["selectionDecision"]):
        raise BenchmarkError("rules", "selectionDecision must record who decided the primary choices and when")
    for fam, r in rules["families"].items():
        keys_ok = isinstance(r, dict) and (set(r) == base or (v2 and set(r) == base | {"primary", "primaryBasis", "secondary"}))
        if fam not in FAMILIES or not keys_ok:
            raise BenchmarkError("rules", f"family {fam!r} keys/name invalid")
        if not isinstance(r["prefix"], str) or not r["prefix"] or not isinstance(r[hidden_key], list) \
                or not all(isinstance(x, str) for x in r[hidden_key]) \
                or not isinstance(r["skipped"], list) or not isinstance(r["source"], dict) or not r["source"]:
            raise BenchmarkError("rules", f"family {fam} malformed")
        for s in r["skipped"]:
            if not isinstance(s, dict) or set(s) != {"tool", "prUrl"}:
                raise BenchmarkError("rules", f"family {fam}: skipped entries need tool and prUrl")
            if not all(isinstance(s[k], str) for k in s) or not s["prUrl"]:
                raise BenchmarkError("rules", f"family {fam}: skipped tool must be a string and prUrl a non-empty string")
        if "primary" in r:
            sec = r["secondary"]
            if not isinstance(r["primary"], str) or not r["primary"] or not isinstance(r["primaryBasis"], str) \
                    or not r["primaryBasis"] or not isinstance(sec, list) or not all(isinstance(x, str) and x for x in sec) \
                    or len(set(sec)) != len(sec) or r["primary"] in sec:
                raise BenchmarkError("rules", f"family {fam}: primary/primaryBasis/secondary malformed")
    return 2 if v2 else 1


def _is_family_id(tool: str, fam: str) -> bool:
    return tool == fam or tool.startswith(fam + "-")


def _audit_family(fam: str, r: dict, observed: list, hidden: list) -> tuple[list, list]:
    """Every observed id of the family with its status; also the survivors (in prefix, not hidden)."""
    rows, alive = [], []
    for t in observed:
        if not _is_family_id(t, fam):
            continue
        if not t.startswith(r["prefix"]):
            rows.append({"id": t, "status": "excluded", "reason": f"outside the rule prefix {r['prefix']!r}"})
        elif t in hidden:
            rows.append({"id": t, "status": "excluded", "reason": "hidden by the pinned upstream rules"})
        else:
            rows.append({"id": t, "status": "survives", "reason": "in prefix and not hidden"})
            alive.append(t)
    return rows, alive


def _eligibility(cases: list, chosen: dict, skipped: set) -> tuple[list, dict]:
    common, omitted = [], {}
    for c in cases:
        have = {r["tool"]: r for r in c["reviews"]}
        why = []
        for tool in chosen.values():
            r = have.get(tool)
            if r is None:
                why.append(f"{tool}: no review")
            elif (tool, r["prUrl"]) in skipped or (tool, c["url"]) in skipped:
                why.append(f"{tool}: marked skipped")
            elif not r["timestampsParseable"]:
                why.append(f"{tool}: unparseable timestamps")
        if why:
            omitted[c["url"]] = why
        else:
            common.append(c["url"])
    return common, omitted


def resolve_versions(projection: dict, rules: dict | None) -> dict:
    """Choose the exact Cubic/CodeRabbit/Greptile ids BEFORE any score. Unprovable -> unresolved, nothing chosen.

    A v2 `primary` is an explicit project choice recorded as such (`choiceBasis`); it never claims upstream hid the
    other survivors. Secondary ids keep their own common eligible sets."""
    cases = projection["cases"]
    base = {"schema": "benchmark-version-resolution@1", "attempted": [c["url"] for c in cases]}
    if rules is None:
        return {**base, "status": "unresolved", "reason": "no pinned upstream exclusion rules were supplied",
                "families": {}, "commonEligibleSet": None, "omitted": {}}
    version = _check_rules(rules)
    hidden_key = "upstreamHidden" if version == 2 else "superseded"
    observed = sorted({r["tool"] for c in cases for r in c["reviews"]})
    fams, chosen, secondary = {}, {}, {}
    for fam in FAMILIES:
        r = rules["families"].get(fam)
        if r is None:
            fams[fam] = {"candidates": [], "chosen": None, "reason": "family has no rule", "audit": [
                {"id": t, "status": "excluded", "reason": "family has no rule"} for t in observed if _is_family_id(t, fam)]}
            continue
        audit, alive = _audit_family(fam, r, observed, r[hidden_key])
        entry = {"candidates": alive, "chosen": None, "audit": audit, "choiceBasis": None}
        primary = r.get("primary")
        if primary is not None:
            if primary not in alive:
                entry["reason"] = f"declared primary {primary!r} is not an observed surviving id"
            elif any(x not in alive for x in r["secondary"]):
                entry["reason"] = "a declared secondary is not an observed surviving id"
            else:
                entry.update(chosen=primary, choiceBasis="explicit-primary", reason="ok", primaryBasis=r["primaryBasis"],
                             secondary=list(r["secondary"]))
                for a in audit:
                    if a["status"] == "survives" and a["id"] != primary:
                        a["status"] = "not-selected"
                        a["reason"] = ("declared secondary comparison" if a["id"] in r["secondary"]
                                       else "survives upstream rules but is neither declared primary nor secondary")
                secondary[fam] = list(r["secondary"])
        elif len(alive) == 1:
            entry.update(chosen=alive[0], choiceBasis="single-survivor", reason="ok")
        else:
            entry["reason"] = f"{len(alive)} non-hidden ids remain; rules do not single one out"
        fams[fam] = entry
        if entry["chosen"]:
            chosen[fam] = entry["chosen"]
    out = {**base, "families": fams, "rulesDigest": digest(rules), "rulesVersion": version}
    if version == 2:
        out["selectionDecision"] = rules["selectionDecision"]
    if len(chosen) != len(FAMILIES):
        return {**out, "status": "unresolved", "reason": "version policy not provable for every family",
                "commonEligibleSet": None, "omitted": {}}
    skipped = {(s["tool"], s["prUrl"]) for r in rules["families"].values() for s in r["skipped"]}
    common, omitted = _eligibility(cases, chosen, skipped)
    out.update(status="resolved", chosen=chosen, commonEligibleSet=common, omitted=omitted)
    if secondary:
        out["secondaryComparisons"] = []
        for fam, ids in secondary.items():
            for tool in ids:
                c2, o2 = _eligibility(cases, {**chosen, fam: tool}, skipped)
                out["secondaryComparisons"].append({"family": fam, "tool": tool, "chosen": {**chosen, fam: tool},
                                                    "commonEligibleSet": c2, "omitted": o2})
    return out
