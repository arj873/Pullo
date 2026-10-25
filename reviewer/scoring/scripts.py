"""Checks for scripted-provider fixture files (interface fixed in orchestration/SCRIPTED-PROVIDER.md).

S0-05 owns the real loader and gateway. This module only proves OUR fixture content obeys the
fixed interface and the case it belongs to, so the loader has nothing ambiguous to reject.
"""

from __future__ import annotations

import json
from pathlib import Path

import reviewer.contracts as _contracts
from reviewer.contracts import loads_strict, validate
from reviewer.contracts.budget import effective_retry_limits
from reviewer.contracts.canonical import hypothesis_id
from reviewer.contracts.snapshot import SnapshotError, excerpt_matches, read_verified
from reviewer.gateway.gateway import RETRYABLE_CODES

from .suite import Suite, _real

ENTRY_KEYS = {"stage", "role", "agentId", "ordinal", "attempt"}
STAGE_ROLE = {"INVESTIGATE": ("investigator", "generalist", "InvestigatorOutput"),
              "VERIFY": ("verifier", "verifier", "VerifierOutput"),
              "JUDGE": ("judge", "judge", "JudgeOutput")}
SPECIALIST = "generalist"


def smoke_limits() -> dict[str, tuple[int, int]]:
    """{role: (retries, repairs)} under the example Plan budget and smoke-synthetic profile caps
    (min of run and role limits; the same D7 rule the gateway applies)."""
    ex = Path(_contracts.__file__).parent / "examples"
    plan = json.loads((ex / "Plan.json").read_text(encoding="utf-8"))
    prof = json.loads((ex / "ModelProfile.smoke-synthetic.json").read_text(encoding="utf-8"))
    return {role: effective_retry_limits(plan["budget"], r["caps"]) for role, r in prof["roles"].items()}


def _int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def check_script(doc) -> list[str]:
    """Interface-level problems (empty = obeys SCRIPTED-PROVIDER.md)."""
    problems: list[str] = []
    if not isinstance(doc, dict) or set(doc) != {"schemaVersion", "entries"} or doc.get("schemaVersion") != 1:
        return ["script must be exactly {schemaVersion: 1, entries: [...]}"]
    if not isinstance(doc["entries"], list) or not doc["entries"]:
        return ["entries must be a non-empty list"]
    seen = set()
    for i, e in enumerate(doc["entries"]):
        where = f"entries[{i}]"
        if not isinstance(e, dict):
            problems.append(f"{where}: not an object")
            continue
        body = {"response", "error"} & set(e)
        extra = set(e) - ENTRY_KEYS - {"response", "error"}
        if extra:
            problems.append(f"{where}: unknown fields {sorted(extra)}")
        if len(body) != 1:
            problems.append(f"{where}: exactly one of response/error is required")
        if not ENTRY_KEYS <= set(e):
            problems.append(f"{where}: missing key fields")
            continue
        if not all(isinstance(e[k], str) for k in ("stage", "role", "agentId")):
            problems.append(f"{where}: stage/role/agentId must be strings")
            continue
        if not (_int(e["ordinal"]) and _int(e["attempt"])):
            problems.append(f"{where}: ordinal/attempt must be non-negative integers")
            continue
        stage = e["stage"]
        if stage not in STAGE_ROLE or (e["role"], e["agentId"]) != STAGE_ROLE[stage][:2]:
            problems.append(f"{where}: stage/role/agentId combination not in the initial smoke suite")
        key = (stage, e["role"], e["agentId"], e["ordinal"], e["attempt"])
        if key in seen:
            problems.append(f"{where}: duplicate key {key}")
        seen.add(key)
        if "response" in e:
            issues = validate("ModelResponse", e["response"])
            if issues:
                problems.append(f"{where}.response: {issues[0]}")
            elif e["response"]["status"] == "ok" and stage in STAGE_ROLE:
                out = validate(STAGE_ROLE[stage][2], e["response"]["output"])
                if out:
                    problems.append(f"{where}.response.output: {out[0]}")
            elif e["response"]["status"] == "invalid-output" and (
                    e["response"]["output"] is not None or not isinstance(e["response"]["rawText"], str)):
                problems.append(f"{where}.response: invalid-output needs null output and rawText")
        if "error" in e:
            issues = validate("TypedError", e["error"])
            if issues:
                problems.append(f"{where}.error: {issues[0]}")
    return problems


def _groups(entries: list[dict]) -> dict[tuple, list[dict]]:
    g: dict[tuple, list[dict]] = {}
    for e in entries:
        g.setdefault((e["stage"], e["role"], e["agentId"], e["ordinal"]), []).append(e)
    for v in g.values():
        v.sort(key=lambda e: e["attempt"])
    return g


def _retried(e: dict) -> bool:
    """Would gateway.call() retry after this scripted error? (same test as gateway.py)"""
    err = e["error"]
    return bool(err.get("retryable")) and err.get("code") in RETRYABLE_CODES


def _call_outcome(group: list[dict], retries: int, repairs: int, label: str, problems: list[str]) -> str | None:
    """'ok' | 'failed' for a logical call whose attempts are scripted,
    else (None, None) with a problem. Follows gateway.call(): attempts are exactly 0..m; the call ends
    at its first ok; an error before the last attempt must be a retryable provider error (anything else
    ends the call there, so later attempts are unreachable); an error ends the call terminally when it is
    not retryable or after retries+1 error attempts; invalid output consumes repairs (repairs+1 invalid
    outputs fail terminally)."""
    atts = [e["attempt"] for e in group]
    if atts != list(range(len(atts))):
        problems.append(f"{label}: attempts {atts} are not exactly 0..{len(atts) - 1}")
        return None
    kinds = ["error" if "error" in e else e["response"]["status"] for e in group]
    if "ok" in kinds[:-1]:
        problems.append(f"{label}: scripted attempts continue after an ok response")
        return None
    for e, k in zip(group[:-1], kinds[:-1]):
        if k == "error" and not _retried(e):
            problems.append(f"{label}: attempt {e['attempt']} is an error the gateway does not retry "
                            f"(code {e['error'].get('code')!r}, retryable {e['error'].get('retryable')!r}); "
                            "later attempts are unreachable")
            return None
    n_err, n_bad = kinds.count("error"), kinds.count("invalid-output")
    if n_err > retries + 1 or n_bad > repairs + 1:
        problems.append(f"{label}: more error/invalid attempts than the caps allow "
                        f"(retries {retries}, repairs {repairs})")
        return None
    last = kinds[-1]
    if last == "ok":
        if n_err > retries or n_bad > repairs:
            problems.append(f"{label}: success needs more retries/repairs than the caps allow")
            return None
        return "ok"
    if last == "error" and n_bad <= repairs and (not _retried(group[-1]) or n_err == retries + 1):
        return "failed"
    if last == "invalid-output" and n_bad == repairs + 1 and n_err <= retries:
        return "failed"
    problems.append(f"{label}: ends in {last!r} but is neither a success nor a terminal failure under "
                    f"the caps (retries {retries}, repairs {repairs}); script every attempt")
    return None


def _terminal_code(group: list[dict], repairs: int) -> str:
    """Error code of a terminally failed call: the last error's code, else what gateway.call() reports
    for exhausted invalid output (repair-exhausted if a repair was spent, else schema-invalid)."""
    last = group[-1]
    if "error" in last:
        return last["error"]["code"]
    return "repair-exhausted" if repairs else "schema-invalid"


def check_completeness(case_id: str, doc: dict, limits: dict[str, tuple[int, int]], *,
                       expect_error_code: str | None = None) -> list[str]:
    """Can this (interface-valid) script drive the whole pipeline for its case? Every logical call the
    scripted path makes must have all attempts scripted, and no unreachable call may be scripted."""
    problems: list[str] = []
    groups = _groups(doc["entries"])
    outcomes: dict[tuple, str | None] = {}
    for key, grp in groups.items():
        role = key[1]
        retries, repairs = limits[role]
        outcomes[key] = _call_outcome(grp, retries, repairs, f"{case_id}: {key[0]} #{key[3]}", problems)
    inv_key = ("INVESTIGATE", "investigator", "generalist", 0)
    if inv_key not in groups:
        return problems + [f"{case_id}: no INVESTIGATE entry"]
    stray = [k for k in groups if k[0] == "INVESTIGATE" and k != inv_key]
    problems += [f"{case_id}: unexpected investigator call {k}" for k in stray]
    inv_ok = outcomes[inv_key] == "ok"
    code = _terminal_code(groups[inv_key], limits["investigator"][1]) if outcomes[inv_key] == "failed" else None
    if expect_error_code is not None and code != expect_error_code:
        problems.append(f"{case_id}: the investigator ends with error {code!r}, "
                        f"but the label expects {expect_error_code!r}")
    cands: list[dict] = []
    if inv_ok:
        cands = groups[inv_key][-1]["response"]["output"]["hypotheses"]
    verify = {k[3]: k for k in groups if k[0] == "VERIFY"}
    judge = [k for k in groups if k[0] == "JUDGE"]
    if not inv_ok or not cands:
        why = "investigator fails" if not inv_ok else "no candidates"
        problems += [f"{case_id}: {k[0]} #{k[3]} is scripted but unreachable ({why})"
                     for k in list(verify.values()) + judge]
        return problems
    confirmed = []
    for n in range(len(cands)):
        if n not in verify:
            problems.append(f"{case_id}: candidate {n} has no verifier entries "
                            "(script every candidate, with error attempts for an explicit verifier failure)")
            continue
        k = verify[n]
        if outcomes.get(k) == "ok" and groups[k][-1]["response"]["output"]["verdict"] == "confirmed":
            confirmed.append(n)
    if not confirmed:
        problems += [f"{case_id}: JUDGE is scripted but no candidate is confirmed" for _ in judge]
        return problems
    if not judge:
        return problems + [f"{case_id}: candidate(s) {confirmed} can be confirmed but there is no JUDGE entry"]
    if judge != [("JUDGE", "judge", "judge", 0)]:
        problems.append(f"{case_id}: judge entries must be a single call with ordinal 0")
    elif outcomes[judge[0]] == "ok":
        ok_ids = {hypothesis_id(SPECIALIST, n, cands[n]["claim"], cands[n]["location"]["path"],
                                cands[n]["location"]["line"]) for n in confirmed}
        used = [f for c in groups[judge[0]][-1]["response"]["output"]["comments"] for f in c["findingIds"]]
        if not used:
            problems.append(f"{case_id}: judge output references no finding")
        for fid in used:
            if fid not in ok_ids:
                problems.append(f"{case_id}: judge references {fid}, which is not a confirmed candidate")
    return problems


def check_case_script(suite: Suite, case_id: str, *, limits: dict[str, tuple[int, int]] | None = None) -> list[str]:
    """Interface + case-level checks: citations resolve against the pinned head snapshot, verifier
    ordinals address real candidates, judge ids are the derived hypothesis ids, and the script is
    complete for the pipeline it feeds (`check_completeness`; `limits` defaults to `smoke_limits()`)."""
    case = suite.cases[case_id]
    path = _real(suite.root, case.script_path)
    if not path.is_file():
        return [f"{case_id}: no script {case.script_path}"]
    doc = loads_strict(path.read_text(encoding="utf-8"))
    problems = check_script(doc)
    if problems:
        return problems
    head_root = _real(suite.root, case.input["head"]["root"])
    commit = case.input["head"]["snapshotId"]
    hyps: dict[int, str] = {}   # candidate ordinal -> derived id (from the first valid attempt)
    for e in doc["entries"]:
        resp = e.get("response")
        if not resp or resp["status"] != "ok":
            continue
        out = resp["output"]
        evid = []
        if e["stage"] == "INVESTIGATE":
            for n, h in enumerate(out["hypotheses"]):
                loc = h["location"]
                hyps.setdefault(n, hypothesis_id(SPECIALIST, n, h["claim"], loc["path"], loc["line"]))
                evid += h["evidence"]
        elif e["stage"] == "VERIFY":
            evid += out["evidence"]
        for ev in evid:
            if ev["kind"] != "code":
                continue
            if ev["commit"] != commit:
                problems.append(f"{case_id}: citation commit is not the head snapshot id")
            try:
                data = read_verified(head_root, case.head_manifest, ev["path"])
            except SnapshotError as ex:
                problems.append(f"{case_id}: citation path {ev['path']}: {ex}")
                continue
            if not excerpt_matches(data, ev["lines"], ev["excerpt"]):
                problems.append(f"{case_id}: excerpt does not match {ev['path']}:{ev['lines']}")
    for e in doc["entries"]:
        if e["stage"] == "VERIFY" and e["ordinal"] not in hyps:
            problems.append(f"{case_id}: verifier ordinal {e['ordinal']} has no candidate")
        if e["stage"] == "JUDGE" and "response" in e and e["response"]["status"] == "ok":
            for c in e["response"]["output"]["comments"]:
                for fid in c["findingIds"]:
                    if fid not in hyps.values():
                        problems.append(f"{case_id}: judge references unknown finding id {fid}")
    if not problems:
        want = case.labels["expectReason"] if case.labels and case.labels["expect"] == "failed" else None
        problems += check_completeness(case_id, doc, limits or smoke_limits(), expect_error_code=want)
    return problems
