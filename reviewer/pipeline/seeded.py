"""investigator.impact@v24 (root card ccfilter-1 2026-11-12): v21's VERIFY -> JUDGE -> PUBLISH on a SEEDED candidate list
(pure rules; the engine drives them in Engine._investigate_v24 and Engine.candidates).

Why (tuning, match ids only): on QTUNE-1 plain Claude Opus (the baseline arm ccbo: ONE `claude -p` call, no tools, the fixed
baseline prompt plus the PR diff) finds 31/39 gold at precision 0.534; impact@v21 finds 21/39 at precision 0.750. v21's
agentic refute-first verifier is its precision filter, so v24 keeps v21's VERIFY, JUDGE and PUBLISH exactly and only replaces
the candidate source: INVESTIGATE makes NO model call; its candidates are the comments of one plain baseline answer, supplied
by the host as a seed document (BenchmarkOptions.seed_candidates).

Rule (SEED_RULE):
  seed       a JSON object of exactly {"schema": SEED_SCHEMA, "mode", "source", "items"} (load): mode is "reuse" (the settled
             baseline review's own answer, 0 new candidate calls) or "live" (a fresh baseline call made for this run); source is
             the host's provenance (SOURCE_KEYS: the baseline arm, case, model, prompt sha256, the sha256 of its comments.json and its
             settle receipt's sha256), recorded, never shown to a model; items are at most MAX_ITEMS objects of exactly
             {"file" (non-empty string), "line" (integer >= 1), "body" (non-empty string), "id" (the baseline comment's own
             id, e.g. ccbo-dify4-3; unique, SEED_ID_RE)} in the answer's order. SEED ID (root add-on): every seeded
             hypothesis and finding carries its item's id in seedRef.id, and comments.json maps each published comment to
             the seed ids of its findings (seedIds; comment_seed_ids). The seed's
             canonical sha256 enters the run's config identity (so its run id), the INVESTIGATE artifact and the review.md
             disclosure; a strict replay needs the same seed.
  drafts     (drafts) each item becomes one HypothesisDraft in item order: claim = the body (its first CLAIM_MAX characters;
             'truncated' is recorded), category CATEGORY, suspectedSeverity SEVERITY, impact IMPACT (fixed: the baseline answer
             has no such fields; VERIFY and JUDGE decide), location {path: file, line}, and ONE code evidence item made by the
             host: the head snapshot's own (redacted) line at file:line, which the snapshot resolver re-checks. An item whose
             file is not a valid relative path ('bad-path'), not a file this change modified on the head side
             ('not-a-changed-file') or whose line is not in the pinned head file ('no-such-line') is dropped BEFORE VERIFY and
             disclosed; nothing else is changed or added.
  union      v21's dual.UNION_RULE over the one seed lane (dual.union): a restatement of an earlier kept candidate
             (lanes.cross_duplicate) is dropped as merged before any verifier call; every seed has the same severity, so the
             VERIFY order is the answer's order; at most dual.MAX_VERIFY are verified ('over-cap' beyond), as v21.
  verify     v21's exactly (dual.VERIFY_RULE, VERIFY_ADMISSION_RULE, CLOCK_RULE, UNVERIFIED_RULE), JUDGE v21's (v20's).
  Profile, Plan (specialists, clocks, the $10 ceiling) and policy are v21's but the investigator promptVersion (and so the Plan
  reason and template digests); no investigator call is ever made.
"""

from __future__ import annotations

import hashlib
import json
import re

BEHAVIOR = "seeded-verify@1"
SEED_SCHEMA = "pullo-seed-candidates@1"
SEED_RULE = "seeded-candidates@1"
AGENT = "seed"                       # the INVESTIGATE artifact's one agent entry and every seeded hypothesis's specialist
MODES = ("reuse", "live")
SOURCE_KEYS = ("arm", "case", "model", "promptSha256", "commentsSha256", "settleReceiptSha256")
MAX_ITEMS = 200
MAX_SEED_BYTES = 2_000_000
MAX_BODY_CHARS = 100_000             # an item body longer than this is refused at load (the claim keeps CLAIM_MAX)
CLAIM_MAX = 2000                     # contracts Hypothesis.claim maxLength
CATEGORY, SEVERITY, IMPACT = "bug", "P1", "incorrect-result"
DROP_REASONS = ("bad-path", "not-a-changed-file", "no-such-line")
_HEX64 = re.compile(r"[0-9a-f]{64}")
SEED_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}")
_PATH = re.compile(r"^(?!/)(?![\s\S]*\\)(?![\s\S]*[\x00-\x1f\x7f])(?!(?:[\s\S]*/)?\.{1,2}(?:/|$))(?![\s\S]*//)(?![\s\S]*/$).+$")


class SeedError(ValueError):
    """A seed document that is not exactly the SEED_SCHEMA shape (refused before any run starts)."""


def _pairs(kv):
    out = {}
    for k, v in kv:
        if k in out:
            raise SeedError("the seed repeats a key")
        out[k] = v
    return out


def load(raw: bytes, version: int = 24) -> dict:
    """The seed document from its bytes, checked (SeedError otherwise). Pure. `version` is the run's impact version: 24 takes
    exactly SEED_SCHEMA, 26 exactly consensus.SEED_SCHEMA (pullo-seed-candidates@2, consensus.check); every other one refuses."""
    if version not in (24, 26):
        raise SeedError("only impact_version 24 (pullo-seed-candidates@1) and 26 (pullo-seed-candidates@2) take a seed")
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_SEED_BYTES:
        raise SeedError(f"the seed is not at most {MAX_SEED_BYTES} bytes")
    try:
        doc = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError) as e:
        if isinstance(e, SeedError):
            raise
        raise SeedError("the seed is not UTF-8 JSON") from None
    if version == 26:                            # investigator.impact@v26 (reviewer.pipeline.consensus)
        from . import consensus
        return consensus.check(doc)
    if not isinstance(doc, dict) or set(doc) != {"schema", "mode", "source", "items"}:
        raise SeedError("the seed is not an object of exactly schema, mode, source, items")
    if doc["schema"] != SEED_SCHEMA:
        raise SeedError(f"the seed schema is not {SEED_SCHEMA}")
    if doc["mode"] not in MODES:
        raise SeedError(f"the seed mode is not one of {MODES}")
    src = doc["source"]
    if not isinstance(src, dict) or set(src) != set(SOURCE_KEYS):
        raise SeedError(f"the seed source is not an object of exactly {SOURCE_KEYS}")
    for k in ("arm", "case", "model"):
        if not isinstance(src[k], str) or not 0 < len(src[k]) <= 200:
            raise SeedError(f"the seed source {k} is not a short string")
    for k in ("promptSha256", "commentsSha256", "settleReceiptSha256"):
        if not isinstance(src[k], str) or not _HEX64.fullmatch(src[k]):
            raise SeedError(f"the seed source {k} is not a sha256")
    check_items(doc["items"])
    return doc


def check_items(items) -> None:
    """A seed block's items: a list of at most MAX_ITEMS objects of exactly file, line, body, id, the ids unique (SeedError)."""
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise SeedError(f"the seed items are not a list of at most {MAX_ITEMS}")
    for it in items:
        if not isinstance(it, dict) or set(it) != {"file", "line", "body", "id"}:
            raise SeedError("a seed item is not an object of exactly file, line, body, id")
        if not isinstance(it["id"], str) or not SEED_ID_RE.fullmatch(it["id"]):
            raise SeedError("a seed item id is not a short slug")
        if not isinstance(it["file"], str) or not it["file"] or len(it["file"]) > 1024:
            raise SeedError("a seed item file is not a non-empty string")
        if type(it["line"]) is not int or not 1 <= it["line"] <= 10_000_000:
            raise SeedError("a seed item line is not an integer >= 1")
        if not isinstance(it["body"], str) or not it["body"].strip() or len(it["body"]) > MAX_BODY_CHARS:
            raise SeedError("a seed item body is not a non-empty string")
    if len({it["id"] for it in items}) != len(items):
        raise SeedError("the seed item ids are not unique")


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(doc: dict) -> str:
    """The seed's canonical sha256 (bound into the config identity)."""
    return hashlib.sha256(canonical(doc)).hexdigest()


def drafts(doc: dict, head_lines, head_id: str, changed) -> tuple[list, list, int]:
    """DRAFT rule. `head_lines(path)` -> the pinned head file's redacted lines or None; `changed` = the head-side paths this
    change modified (None = unknown: the changed-file requirement is not applied, as Engine._hypotheses). ->
    ([(item index, HypothesisDraft)], [{"index", "reason"}], number of truncated claims)."""
    out, dropped, cut = [], [], 0
    for n, it in enumerate(doc["items"]):
        path, line = it["file"], it["line"]
        if not _PATH.fullmatch(path):
            dropped.append({"index": n, "reason": "bad-path"})
            continue
        if changed is not None and path not in changed:
            dropped.append({"index": n, "reason": "not-a-changed-file"})
            continue
        lines = head_lines(path)
        if lines is None or line > len(lines):
            dropped.append({"index": n, "reason": "no-such-line"})
            continue
        claim = it["body"][:CLAIM_MAX]
        cut += claim != it["body"]
        out.append((n, {"claim": claim, "category": CATEGORY, "suspectedSeverity": SEVERITY, "impact": IMPACT,
                        "location": {"path": path, "line": line},
                        "evidence": [{"kind": "code", "path": path, "lines": [line, line], "commit": head_id,
                                      "excerpt": lines[line - 1]}]}))
    return out, dropped, cut


def comment_seed_ids(comments: list, findings: list) -> dict:
    """SEED ID: {published comment id: [the seed ids of its findings, in findingIds order]} (host data)."""
    by = {f["id"]: f["seedRef"]["id"] for f in findings if isinstance(f.get("seedRef"), dict)}
    return {c["id"]: [by[h] for h in c["findingIds"] if h in by] for c in comments}


def summary(doc: dict, dropped: list, cut: int, kept: int) -> dict:
    """The INVESTIGATE artifact's `seed` record (host data; no item text)."""
    return {"rule": SEED_RULE, "schema": SEED_SCHEMA, "mode": doc["mode"], "sha256": digest(doc), "source": dict(doc["source"]),
            "items": len(doc["items"]), "candidates": kept, "dropped": list(dropped), "truncatedClaims": cut}


def identity_doc(doc: dict) -> dict:
    """The run identity's seed record: the rule, the seed's digest and mode, and the fixed draft fields."""
    return {"rule": SEED_RULE, "behavior": BEHAVIOR, "schema": SEED_SCHEMA, "mode": doc["mode"], "sha256": digest(doc),
            "items": len(doc["items"]), "category": CATEGORY, "suspectedSeverity": SEVERITY, "impact": IMPACT,
            "claimMax": CLAIM_MAX, "maxItems": MAX_ITEMS}


def is_seeded_payload(payload: dict) -> bool:
    """An impact@v24 INVESTIGATE payload (its seed record or its one `seed` agent entry)."""
    return payload.get("seed") is not None or any(a.get("agentId") == AGENT for a in payload.get("agents", ()))


def coverage_lines(payload: dict, events: list, drops: list) -> list[str]:
    """review.md disclosure of an impact@v24 run (pure): the seed's lines in place of v21's pass lines, then v21's re-ask,
    verifier, admission, clock and JUDGE lines (dual.coverage_lines) and the union line for the one seed lane."""
    from . import dual
    seed = payload.get("seed")
    if not seed:
        head = [f"- Seeded review ({BEHAVIOR}): no seed record (INVESTIGATE did not complete)."]
    else:
        by = {r: sum(1 for d in seed["dropped"] if d["reason"] == r) for r in DROP_REASONS}
        src = seed["source"]
        head = [f"- Seeded review ({BEHAVIOR}, {SEED_RULE}): the candidates are the {seed['items']} comment(s) of ONE plain "
                f"`{src['model']}` baseline answer (arm `{src['arm']}`, candidate mode `{seed['mode']}`: "
                + ("the settled baseline review's own answer, no new candidate call" if seed["mode"] == "reuse"
                   else "a fresh baseline call for this run")
                + f"; seed sha256 {seed['sha256'][:16]}); INVESTIGATE made no model call.",
                f"- Seed: {seed['candidates']} candidate(s) kept, {len(seed['dropped'])} dropped before VERIFY "
                f"({by['bad-path']} bad path, {by['not-a-changed-file']} not in a changed file, {by['no-such-line']} line "
                f"not in the head file); {seed['truncatedClaims']} claim(s) cut at {CLAIM_MAX} characters; every candidate "
                f"is {CATEGORY} / {SEVERITY} / {IMPACT} until VERIFY and JUDGE decide."]
    merged = sum(1 for d in drops if d["reason"] == "merged" and dual.UNION_RULE in d.get("detail", ""))
    union = (f"- Union ({dual.UNION_RULE}, one seed lane): {merged} restatement(s) of an earlier candidate dropped as merged; "
             f"the rest in the answer's order; at most {dual.MAX_VERIFY} verified.")
    keep = ("- Re-ask", "- Agentic verify", "- Verify admission", "- VERIFY clock", "- JUDGE rule")
    v21 = [ln for ln in dual.coverage_lines(payload, events, drops) if ln.startswith(keep)]
    return head + [union] + v21
