"""Phase B INTERFACE (published, not executed): bounded extraction / dedup / semantic-match requests, exact prompts,
schemas and validators. No model call, no HTTP, no import of a provider here. Calls must go through a gateway/ledger
path that tags them `scoring`; see SEAM for what the review contracts cannot yet represent."""

from __future__ import annotations

from .errors import BenchmarkError
from .jsonio import digest
from .model import ScorerCase, ToolReview, sha16
from .scoring import JUDGMENTS_SCHEMA

EXTRACT_V, DEDUP_V, MATCH_V = "bench.extract@v1", "bench.dedup@v1", "bench.match@v1"
MAX_ITEMS = 200
ACCOUNTING = {"category": "scoring", "countsTowardAggregateCap": True, "reviewCost": False,
              "note": "separate evaluation call; the production JUDGE role stays review cost"}
SEAM = {"status": "unresolved", "callsMade": 0,
        "needs": ["a contracts-owner scoring Role/Output schema (ModelProfile.roles is closed to investigator|verifier|judge "
                  "and outputSchema is an enum without extraction/dedup/match; JudgeOutput is review wording and is NOT reused)",
                  "a gateway/ledger entry tagging calls `scoring` inside the single existing $50 allowance"],
        "forbidden": ["untracked direct HTTP loop", "inventing findings", "patching other owners' contracts/runtime"]}

PROMPTS = {
    EXTRACT_V: ("You split one code-review tool's comments into individual, self-contained issues. A summary comment may "
                "hold several issues; an inline comment is usually one. Copy each issue's meaning faithfully, add nothing, "
                "and cite the id of the comment it came from. Output only the JSON object required by the schema."),
    DEDUP_V: ("You group candidate issues that describe the same underlying concern. Every candidate id must appear in exactly "
              "one group; a candidate with no duplicate is a group of one. Choose one member as the representative. "
              "Output only the JSON object required by the schema."),
    MATCH_V: ("For each representative candidate, decide whether it describes the same underlying issue as one reference "
              "issue (semantic equivalence, not shared file or line). Answer the reference id, or null when none is the same "
              "issue. Give a short reason. Output only the JSON object required by the schema."),
}


def _obj(props: dict, required: list) -> dict:
    return {"type": "object", "additionalProperties": False, "properties": props, "required": required}


_S = {"type": "string", "minLength": 1, "maxLength": 4000}
SCHEMAS = {
    EXTRACT_V: _obj({"candidates": {"type": "array", "maxItems": MAX_ITEMS,
                                    "items": _obj({"sourceCommentId": _S, "text": _S}, ["sourceCommentId", "text"])}},
                    ["candidates"]),
    DEDUP_V: _obj({"groups": {"type": "array", "maxItems": MAX_ITEMS,
                              "items": _obj({"representative": _S, "members": {"type": "array", "minItems": 1, "maxItems": MAX_ITEMS,
                                                                                 "items": _S}}, ["representative", "members"])}},
                  ["groups"]),
    MATCH_V: _obj({"matches": {"type": "array", "maxItems": MAX_ITEMS,
                               "items": _obj({"candidate": _S, "golden": {"anyOf": [_S, {"type": "null"}]},
                                              "reason": {"type": "string", "maxLength": 400}},
                                             ["candidate", "golden", "reason"])}}, ["matches"]),
}
SCHEMA_SHA256 = {k: digest(v) for k, v in SCHEMAS.items()}


def _request(version: str, user: str) -> dict:
    return {"promptVersion": version, "schemaSha256": SCHEMA_SHA256[version], "schema": SCHEMAS[version],
            "messages": [{"role": "system", "content": PROMPTS[version]}, {"role": "user", "content": user}],
            "accounting": dict(ACCOUNTING), "maxItems": MAX_ITEMS}


def _bounded(items: list, what: str) -> None:
    if len(items) > MAX_ITEMS:
        raise BenchmarkError("bounds", f"{what}: {len(items)} items exceed the {MAX_ITEMS} bound")


def extraction_request(review: ToolReview) -> dict:
    _bounded(review.comments, "comments")
    body = "\n".join(f"[{c.id}] ({c.path}:{c.line}) {c.body}" for c in review.comments)
    return _request(EXTRACT_V, "Comments:\n" + body)


def validate_extraction(review: ToolReview, reply: dict) -> list[dict]:
    ids = {c.id for c in review.comments}
    items = _items(reply, "candidates", {"sourceCommentId", "text"})
    out = []
    for it in items:
        if it["sourceCommentId"] not in ids:
            raise BenchmarkError("judgments", "extraction cites a comment id that is not in the review")
        out.append({"id": "cand:" + sha16(review.tool, it["sourceCommentId"], it["text"]),
                    "sourceCommentId": it["sourceCommentId"], "text": it["text"]})
    if len({c["id"] for c in out}) != len(out):
        raise BenchmarkError("judgments", "extraction produced duplicate candidates")
    return out


def dedup_request(candidates: list[dict]) -> dict:
    _bounded(candidates, "candidates")
    return _request(DEDUP_V, "Candidates:\n" + "\n".join(f"[{c['id']}] {c['text']}" for c in candidates))


def validate_dedup(candidates: list[dict], reply: dict) -> list[dict]:
    ids = [c["id"] for c in candidates]
    groups = _items(reply, "groups", {"representative", "members"})
    seen, out = set(), []
    for n, g in enumerate(groups, 1):
        mem = g["members"]
        if not isinstance(mem, list) or g["representative"] not in mem or seen & set(mem) or not set(mem) <= set(ids):
            raise BenchmarkError("judgments", "dedup group invalid (representative, overlap or unknown id)")
        seen |= set(mem)
        out.append({"id": f"grp:{n}", "representative": g["representative"], "members": list(mem)})
    if seen != set(ids):
        raise BenchmarkError("incomplete", "dedup reply is not a full partition of the candidates")
    return out


def match_request(representatives: list[dict], case: ScorerCase) -> dict:
    _bounded(representatives, "representatives")
    ref = "\n".join(f"[{g.id}] {g.comment}" for g in case.golden)
    cand = "\n".join(f"[{c['id']}] {c['text']}" for c in representatives)
    return _request(MATCH_V, f"Reference issues:\n{ref}\n\nCandidates:\n{cand}")


def validate_match(reps: list[str], case: ScorerCase, reply: dict) -> list[dict]:
    gold = {g.id for g in case.golden}
    out = []
    for m in _items(reply, "matches", {"candidate", "golden", "reason"}):
        if m["golden"] is not None and m["golden"] not in gold:
            raise BenchmarkError("judgments", "match cites an unknown reference id")
        out.append({"candidate": m["candidate"], "golden": m["golden"], "reason": str(m["reason"])[:400]})
    if sorted(m["candidate"] for m in out) != sorted(reps):
        raise BenchmarkError("incomplete", "match reply does not cover exactly the representatives")
    return out


def assemble(case: ScorerCase, tool: str, judge: dict, candidates: list, groups: list, matches: list) -> dict:
    """The semantic-judgments@1 document scoring.score_case consumes (it re-validates everything)."""
    return {"schema": JUDGMENTS_SCHEMA, "caseUrl": case.url, "tool": tool, "judge": judge,
            "extraction": {"candidates": candidates}, "duplicateGroups": groups, "matches": matches}


def _items(reply, key: str, fields: set) -> list:
    items = reply.get(key) if isinstance(reply, dict) and set(reply) == {key} else None
    if not isinstance(items, list):
        raise BenchmarkError("judgments", f"reply must be exactly {{{key}: [...]}}")
    _bounded(items, key)
    for it in items:
        if not isinstance(it, dict) or set(it) != fields:
            raise BenchmarkError("judgments", f"{key} item keys must be exactly {sorted(fields)}")
    return items
