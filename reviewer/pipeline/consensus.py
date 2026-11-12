"""investigator.impact@v26 (res2 CARD-v26-build e24326b1, root GO 2026-11-12T08:25Z): K6 consensus inside Pullo (pure rules;
the engine drives them in Engine._investigate_v26, _verify_v26 and _judge_v26).

Why (tuning, match ids only, gold-blind rule): on QTUNE-1 the plain Opus baseline (ccbo, ONE `claude -p` call, the fixed baseline
prompt plus the PR diff) reaches recall 31/39 at precision .534; keeping only the ccbo comments that ONE independent plain Sonnet
answer (ccbs, the same prompt and diff) also raised, by a deterministic same-defect matcher, measured F1 .707 (E3) / .712 (E4),
while v21's VERIFY and JUDGE on the same candidates (impact@v24) scored .495 and cost $0.148/PR PACING. So v26 makes NO model
call: the host supplies the candidate answer and its witness answer(s) as one seed document (BenchmarkOptions.seed_candidates)
and the run keeps exactly the supported candidates, verbatim.

Rule (RULE, k6-plain-witness@1):
  seed       a JSON object of exactly {"schema": SEED_SCHEMA, "mode", "rule", "candidates", "witnesses"} (check): mode reuse|live;
             rule {"id": RULE, "n" in WITNESS_COUNTS, "k" in 1..n}; candidates {"source", "items"} and witnesses a list of exactly
             n such blocks. A source is exactly SOURCE_KEYS (the host's provenance of one settled plain answer, never shown to a
             model); items are v24's (seeded.check_items: {file, line, body, id}, ids unique within the block). The candidate
             model is CANDIDATE_MODEL and every witness model WITNESS_MODEL; EQUAL_KEYS agree across all blocks (the same case,
             prompt, request body, diff, CLI, export and reviewer manifest: the measured witness); no runId repeats.
  match      per witness j separately, support.py's assign (MATCHER, vendored byte for byte below): same file; a pair matches if
             d<=3 and (jac>=.06 or kov>=.34), or d<=15 and (jac>=.18 or kov>=.5), or jac>=.30 and kov>=.5; score
             jac + .5*kov - .004*min(d,50); greedy one-to-one over sorted((score, i, j), reverse=True).
  vote       votes(c) = the number of witnesses whose pairs include c; c is supported iff votes(c) >= k; an unsupported
             candidate is dropped as 'no-witness' (disclosed with its votes).
  locate     v24's location ingest (seeded.drafts) on the supported candidates only, after matching: 'bad-path',
             'not-a-changed-file' and 'no-such-line' drops are disclosed by id. A supported candidate whose body (or title) cannot
             be a Comment verbatim (longer than BODY_MAX characters, or protected text) is dropped as 'unpublishable-body'.
  publish    each kept candidate is one hypothesis -> one finding (verification VERDICT, the witness refs, no call) -> one
             comment: body = the item body byte for byte, title = title_of(body), anchor (file, line, line), evidence = the
             host's head line, no suggestion. No union, merge, cap or JUDGE call (an exact same-claim same-anchor repeat keeps
             JUDGE's identical-claim rule: one comment, both finding ids).
"""

from __future__ import annotations

import hashlib
import json
import re

from . import seeded

BEHAVIOR = "consensus.k6@v26"
RULE = "k6-plain-witness@1"
SEED_SCHEMA = "pullo-seed-candidates@2"
VERDICT = "witness-supported"
MATCHER_ID = "res2-lexical-1to1@1"
MODES = seeded.MODES
WITNESS_COUNTS = (1, 2, 3)
CANDIDATE_MODEL, WITNESS_MODEL = "claude-cli/claude-opus-5-5", "claude-cli/claude-sonnet-5-5"
SOURCE_KEYS = ("arm", "case", "runId", "model", "settleReceiptSha256", "commentsSha256", "promptTextSha256", "bodySha256",
               "diffSha256", "cliVersion", "exportVersion", "reviewerManifestSha256")
EQUAL_KEYS = ("case", "promptTextSha256", "bodySha256", "diffSha256", "cliVersion", "exportVersion", "reviewerManifestSha256")
_SHA_KEYS = ("settleReceiptSha256", "commentsSha256", "promptTextSha256", "bodySha256", "diffSha256", "reviewerManifestSha256")
DROP_REASONS = ("no-witness",) + seeded.DROP_REASONS + ("unpublishable-body",)
BODY_MAX, TITLE_MAX, TITLE_FALLBACK = 4000, 120, "Review comment"     # contracts Comment.body maxLength; title_of
VENDORED_FROM = "res2 proto/support.py sha256 baa2cb2878014a9469342ce856189834ebe547322c6313735fed46b6c7e0d4d7 lines 7-64"
VENDORED_SHA256 = "3061579621b806d2e3aeabfa41828f56df5585424e0feadd91474d0548ccfa5e"   # sha256 of the block between the markers
_BEGIN, _END = "# --- vendored from res2 proto/support.py (byte for byte) ---\n", "# --- end vendored ---\n"

# --- vendored from res2 proto/support.py (byte for byte) ---
STOP = set('the a an and or of to in is it this that for on with as be by are was not now no from at its if when which '
           'than then so but can will would should could may might also only any all every each one two into after before '
           'still does do because there their they them other same new old used use uses using call called calls value '
           'values code line lines returns return function method file make makes made instead just like such way'.split())
TOK = re.compile(r'[A-Za-z_][A-Za-z0-9_]{2,}')
TICK = re.compile(r'`([^`\n]{1,80})`')


def toks(text):
    return {t.lower() for t in TOK.findall(text) if t.lower() not in STOP}


def ticks(text):
    out = set()
    for m in TICK.findall(text):
        out |= {t.lower() for t in TOK.findall(m)}
    return out


def similarity(a, b):
    """(jaccard over word tokens, overlap over `code` tokens, line distance); None when the files differ."""
    if a['file'] != b['file']:
        return None
    A, B = toks((a.get('title') or '') + ' ' + a['body']), toks((b.get('title') or '') + ' ' + b['body'])
    KA, KB = ticks(a['body']), ticks(b['body'])
    jac = len(A & B) / max(1, len(A | B))
    kov = len(KA & KB) / max(1, min(len(KA), len(KB))) if KA and KB else 0.0
    return jac, kov, abs(a['line'] - b['line'])


def same_defect(a, b):
    """True when a and b plausibly describe the same defect (necessary condition; see assign() for one-to-one)."""
    s = similarity(a, b)
    if s is None:
        return False
    jac, kov, d = s
    if d <= 3 and (jac >= 0.06 or kov >= 0.34):
        return True
    if d <= 15 and (jac >= 0.18 or kov >= 0.5):
        return True
    return jac >= 0.30 and kov >= 0.5                              # same file, far apart, clearly the same story


def score(a, b):
    jac, kov, d = similarity(a, b)
    return jac + 0.5 * kov - 0.004 * min(d, 50)


def assign(targets, others):
    """One-to-one: each comment of ONE other review supports at most one target (its best match) and each target takes at
    most one supporter from that review. Greedy by descending score. -> set of supported target indices."""
    cand = sorted(((score(t, o), i, j) for i, t in enumerate(targets) for j, o in enumerate(others) if same_defect(t, o)),
                  reverse=True)
    used_t, used_o = set(), set()
    for _, i, j in cand:
        if i not in used_t and j not in used_o:
            used_t.add(i); used_o.add(j)
    return used_t
# --- end vendored ---


def vendored_block(source: str) -> str:
    """The vendored block's text inside `source` (this module's own file text): between the markers, exclusive."""
    a = source.index(_BEGIN) + len(_BEGIN)
    return source[a:source.index(_END, a)]


MATCHER = {"id": MATCHER_ID, "vendoredFrom": VENDORED_FROM, "vendoredSha256": VENDORED_SHA256,
           "stop": sorted(STOP), "tokenRegex": TOK.pattern, "tickRegex": TICK.pattern,
           "text": "word tokens of (title or '') + ' ' + body, code tokens of each `...` span of body; lower-cased, STOP removed",
           "sameFile": True, "jaccard": "len(A & B) / max(1, len(A | B))",
           "codeOverlap": "len(KA & KB) / max(1, min(len(KA), len(KB))) if KA and KB else 0.0",
           "match": [{"maxLineDistance": 3, "jac": 0.06, "kov": 0.34}, {"maxLineDistance": 15, "jac": 0.18, "kov": 0.5},
                     {"maxLineDistance": None, "jacAnd": 0.30, "kovAnd": 0.5}],
           "score": {"jac": 1.0, "kov": 0.5, "lineDistance": -0.004, "lineDistanceCap": 50},
           "assign": "greedy one-to-one over sorted(((score, i, j) for matching pairs), reverse=True)"}


def matcher_sha() -> str:
    return hashlib.sha256(seeded.canonical(MATCHER)).hexdigest()


MATCHER_SHA = matcher_sha()


def assign_pairs(targets, others) -> list:
    """support.py's assign (one-to-one, greedy by descending (score, i, j)), returning the matched (target, other) index pairs
    in that greedy order: {i for i, _ in assign_pairs(t, o)} == assign(t, o)."""
    cand = sorted(((score(t, o), i, j) for i, t in enumerate(targets) for j, o in enumerate(others) if same_defect(t, o)),
                  reverse=True)
    used_t, used_o, out = set(), set(), []
    for _, i, j in cand:
        if i not in used_t and j not in used_o:
            used_t.add(i); used_o.add(j); out.append((i, j))
    return out


# ---------------------------------------------------------------- the seed document (pullo-seed-candidates@2)

def _source(src, where: str) -> None:
    if not isinstance(src, dict) or set(src) != set(SOURCE_KEYS):
        raise seeded.SeedError(f"the {where} source is not an object of exactly {SOURCE_KEYS}")
    for k in ("arm", "case", "runId", "model", "cliVersion"):
        if not isinstance(src[k], str) or not 0 < len(src[k]) <= 200:
            raise seeded.SeedError(f"the {where} source {k} is not a short string")
    for k in _SHA_KEYS:
        if not isinstance(src[k], str) or not seeded._HEX64.fullmatch(src[k]):
            raise seeded.SeedError(f"the {where} source {k} is not a sha256")
    if type(src["exportVersion"]) is not int or not 1 <= src["exportVersion"] <= 10_000:
        raise seeded.SeedError(f"the {where} source exportVersion is not an integer >= 1")


def check(doc) -> dict:
    """RULE's seed shape (seeded.load(raw, 26) calls this on the parsed document; SeedError otherwise). Pure."""
    if not isinstance(doc, dict) or set(doc) != {"schema", "mode", "rule", "candidates", "witnesses"}:
        raise seeded.SeedError("the seed is not an object of exactly schema, mode, rule, candidates, witnesses")
    if doc["schema"] != SEED_SCHEMA:
        raise seeded.SeedError(f"the seed schema is not {SEED_SCHEMA}")
    if doc["mode"] not in MODES:
        raise seeded.SeedError(f"the seed mode is not one of {MODES}")
    rule = doc["rule"]
    if not isinstance(rule, dict) or set(rule) != {"id", "n", "k"} or rule["id"] != RULE:
        raise seeded.SeedError(f"the seed rule is not exactly {{id: {RULE}, n, k}}")
    if type(rule["n"]) is not int or rule["n"] not in WITNESS_COUNTS:
        raise seeded.SeedError(f"the seed rule n is not one of {WITNESS_COUNTS}")
    if type(rule["k"]) is not int or not 1 <= rule["k"] <= rule["n"]:
        raise seeded.SeedError("the seed rule k is not an integer in 1..n")
    ws = doc["witnesses"]
    if not isinstance(ws, list) or len(ws) != rule["n"]:
        raise seeded.SeedError("the seed witnesses are not a list of exactly n blocks")
    blocks = [("candidate", doc["candidates"])] + [(f"witness {j}", w) for j, w in enumerate(ws)]
    for where, b in blocks:
        if not isinstance(b, dict) or set(b) != {"source", "items"}:
            raise seeded.SeedError(f"the {where} block is not an object of exactly source, items")
        _source(b["source"], where)
        seeded.check_items(b["items"])
    if doc["candidates"]["source"]["model"] != CANDIDATE_MODEL:
        raise seeded.SeedError(f"the candidate model is not {CANDIDATE_MODEL}")
    if any(w["source"]["model"] != WITNESS_MODEL for w in ws):
        raise seeded.SeedError(f"a witness model is not {WITNESS_MODEL}")
    for k in EQUAL_KEYS:
        if len({json.dumps(b["source"][k]) for _, b in blocks}) != 1:
            raise seeded.SeedError(f"the seed blocks differ in source {k}")
    if len({b["source"]["runId"] for _, b in blocks}) != len(blocks):
        raise seeded.SeedError("a seed block repeats a runId")
    return doc


# ---------------------------------------------------------------- the rule

def table(doc: dict) -> list:
    """match + vote: one row per candidate, in candidate order: {index, seedId, votes, supported, pairs: [{witness, witnessId,
    jac, kov, d, score}] in witness order}. Pure; `doc` is a checked seed (or any document of the same shape)."""
    cands = doc["candidates"]["items"]
    rows = [{"index": i, "seedId": c["id"], "votes": 0, "supported": False, "pairs": []} for i, c in enumerate(cands)]
    for j, w in enumerate(doc["witnesses"]):
        for i, jj in assign_pairs(cands, w["items"]):
            jac, kov, d = similarity(cands[i], w["items"][jj])
            rows[i]["pairs"].append({"witness": j, "witnessId": w["items"][jj]["id"], "jac": jac, "kov": kov, "d": d,
                                     "score": score(cands[i], w["items"][jj])})
    for r in rows:
        r["pairs"].sort(key=lambda p: p["witness"])
        r["votes"] = len(r["pairs"])
        r["supported"] = r["votes"] >= doc["rule"]["k"]
    return rows


consensus = table


def title_of(body: str) -> str:
    """The comment title: the body's first non-empty line, leading markdown (#, *, -, >, backticks) and spaces stripped, cut
    after the first ". " (the period kept) or at TITLE_MAX characters, whichever comes first; TITLE_FALLBACK when nothing is left."""
    line = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
    line = line.lstrip("#*->` \t")
    cut = line.find(". ")
    if cut >= 0:
        line = line[:cut + 1]
    line = line[:TITLE_MAX].rstrip()
    return line or TITLE_FALLBACK


def table_digest(rows: list) -> str:
    return hashlib.sha256(seeded.canonical(rows)).hexdigest()


def event_record(doc: dict, rows: list) -> dict:
    """The seed.input event's `consensus` object: what check_finding_provenance binds a witness-supported Finding to."""
    return {"rule": RULE, "matcherSha256": MATCHER_SHA, "n": doc["rule"]["n"], "k": doc["rule"]["k"],
            "tableSha256": table_digest(rows), "table": rows}


def identity_doc(doc: dict) -> dict:
    """The run identity's consensus record: the rule, the seed's digest and mode, (n, k), the matcher and the fixed fields."""
    return {"rule": RULE, "behavior": BEHAVIOR, "schema": SEED_SCHEMA, "mode": doc["mode"], "sha256": seeded.digest(doc),
            "n": doc["rule"]["n"], "k": doc["rule"]["k"], "candidates": len(doc["candidates"]["items"]),
            "witnessItems": [len(w["items"]) for w in doc["witnesses"]], "matcher": MATCHER_ID, "matcherSha256": MATCHER_SHA,
            "verdict": VERDICT, "category": seeded.CATEGORY, "suspectedSeverity": seeded.SEVERITY, "impact": seeded.IMPACT,
            "claimMax": seeded.CLAIM_MAX, "bodyMax": BODY_MAX, "titleMax": TITLE_MAX, "maxItems": seeded.MAX_ITEMS}


def summary(doc: dict, rows: list, dropped: list, cut: int, kept: list) -> dict:
    """The INVESTIGATE artifact's `consensus` record (host data; ids, numbers and the kept drafts, no other item text)."""
    return {"rule": RULE, "behavior": BEHAVIOR, "schema": SEED_SCHEMA, "mode": doc["mode"], "sha256": seeded.digest(doc),
            "n": doc["rule"]["n"], "k": doc["rule"]["k"], "matcher": MATCHER_ID, "matcherSha256": MATCHER_SHA,
            "candidateSource": dict(doc["candidates"]["source"]),
            "witnessSources": [dict(w["source"]) for w in doc["witnesses"]],
            "items": len(doc["candidates"]["items"]), "witnessItems": [len(w["items"]) for w in doc["witnesses"]],
            "table": rows, "tableSha256": table_digest(rows), "supported": sum(1 for r in rows if r["supported"]),
            "candidates": len(kept), "dropped": list(dropped), "truncatedClaims": cut, "drafts": kept}


def witness_ids(comments: list, findings: list) -> dict:
    """comments.json `witnessIds`: {published comment id: [[witness j, witness item id], ...] of its findings, in findingIds
    then witness order} (host data)."""
    by = {f["id"]: [[r["witness"], r["witnessId"]] for r in f["verification"].get("witnessRefs", ())] for f in findings}
    return {c["id"]: [x for h in c["findingIds"] for x in by.get(h, ())] for c in comments}


def is_consensus_payload(payload: dict) -> bool:
    """An impact@v26 INVESTIGATE payload (its consensus record)."""
    return payload.get("consensus") is not None


def coverage_lines(payload: dict) -> list:
    """review.md disclosure of an impact@v26 run (pure)."""
    rec = payload.get("consensus")
    if not rec:
        return [f"- Consensus review ({BEHAVIOR}): no consensus record (INVESTIGATE did not complete); 0 model calls in this run."]
    by = {r: sum(1 for d in rec["dropped"] if d["reason"] == r) for r in DROP_REASONS}
    src = rec["candidateSource"]
    ids = lambda r: ", ".join(d["id"] for d in rec["dropped"] if d["reason"] == r) or "none"   # noqa: E731
    return [f"- Consensus review ({BEHAVIOR}, {RULE}): the candidates are the {rec['items']} comment(s) of ONE plain "
            f"`{src['model']}` baseline answer (arm `{src['arm']}`); witnesses: {rec['n']} plain `{WITNESS_MODEL}` answer(s) on "
            f"the same prompt and diff (" + ", ".join(f"`{w['arm']}` {n} comment(s)" for w, n in
                                                    zip(rec["witnessSources"], rec["witnessItems"]))
            + f"); candidate mode `{rec['mode']}` (" + ("the settled baseline answers, no new call" if rec["mode"] == "reuse"
                                                        else "fresh baseline calls made by the host for this run")
            + f"); seed sha256 {rec['sha256'][:16]}. 0 model calls in this run.",
            f"- Rule: a candidate is published when at least {rec['k']} of {rec['n']} witness(es) raised the same defect "
            f"(matcher `{MATCHER_ID}`, sha256 {rec['matcherSha256'][:16]}: same file, line distance and word/code-token "
            f"overlap, one-to-one per witness); {rec['supported']} of {rec['items']} supported.",
            f"- Dropped: {by['no-witness']} without witness support ({ids('no-witness')}); location {by['bad-path']} bad path, "
            f"{by['not-a-changed-file']} not in a changed file, {by['no-such-line']} line not in the head file "
            f"({', '.join(d['id'] for d in rec['dropped'] if d['reason'] in seeded.DROP_REASONS) or 'none'}); "
            f"{by['unpublishable-body']} body not publishable verbatim ({ids('unpublishable-body')}).",
            f"- Published: {rec['candidates']} comment(s), each a supported candidate's own text verbatim (title = its first "
            f"line); no verifier, judge or rewrite (verification `{VERDICT}`); severity at most P2 (no verifier established "
            f"reachability)."]
