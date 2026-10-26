"""Scorer-native representation. Everything here is scorer-only; nothing is imported by the review pipeline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .errors import BenchmarkError

STRICT = frozenset({"bug", "security", "concurrency", "data", "api"})
CORE = STRICT | {"perf", "test_gap", "doc_defect"}
ALL = CORE | {"style", "speculative"}
PROFILES = {"strict": STRICT, "core": CORE, "all": ALL}
LABEL_FIXTURE_URL = "https://example/pr"
# Exact severity strings observed in the pinned source (orchestration/benchmarks/martian-severity-vocabulary-20261026.json).
# Matching is exact: no case folding, trimming or inference. Anything else is refused.
KNOWN_SEVERITIES = frozenset({"Critical", "High", "Low", "Medium"})
RAW_COMMENT_ID_VERSION = "rc2"


def sha16(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(len(p)).encode() + b":" + p.encode("utf-8"))
    return h.hexdigest()[:16]


def typed_id(prefix: str, *fields) -> str:
    """Id over canonical JSON of the typed fields, so null, "None", 3 and "3" all hash differently."""
    data = json.dumps(list(fields), separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return f"{prefix}:{hashlib.sha256(data).hexdigest()[:16]}"


@dataclass(frozen=True)
class Golden:
    id: str
    comment: str
    severity: str
    category: str


@dataclass(frozen=True)
class RawComment:
    id: str
    path: str | None        # None with line None is a summary comment; None with an int line is refused
    line: int | None
    body: str
    created_at: str


@dataclass(frozen=True)
class ToolReview:
    tool: str
    repo_name: str
    pr_url: str | None      # the pinned source has literal null links on a few reviews; never substituted
    comments: tuple[RawComment, ...]


@dataclass(frozen=True)
class ScorerCase:
    url: str
    source_repo: str
    original_url: str | None
    index: int
    golden: tuple[Golden, ...]
    reviews: tuple[ToolReview, ...] = field(default_factory=tuple)

    def review(self, tool: str) -> ToolReview:
        for r in self.reviews:
            if r.tool == tool:
                return r
        raise BenchmarkError("missing", f"no review by {tool!r} for this case")


def _expect(cond: bool, what: str) -> None:
    if not cond:
        raise BenchmarkError("shape", what)


def build_case(url: str, index: int, entry: dict) -> ScorerCase:
    keys = {"pr_title", "original_url", "source_repo", "golden_comments", "golden_source_file", "az_comment", "reviews"}
    _expect(isinstance(entry, dict) and set(entry) == keys, f"case {index}: keys differ from the shape receipt")
    _expect(isinstance(entry["source_repo"], str), f"case {index}: source_repo")
    _expect(entry["original_url"] is None or isinstance(entry["original_url"], str), f"case {index}: original_url")
    _expect(isinstance(entry["golden_comments"], list) and isinstance(entry["reviews"], list), f"case {index}: lists")
    gold = []
    for n, g in enumerate(entry["golden_comments"], 1):
        _expect(isinstance(g, dict) and set(g) == {"comment", "severity", "category"}, f"case {index}: golden {n} keys")
        _expect(all(isinstance(g[k], str) and g[k] for k in g), f"case {index}: golden {n} types")
        if g["severity"] not in KNOWN_SEVERITIES:
            raise BenchmarkError("severity", f"case {index}: golden {n} has unknown severity {g['severity'][:30]!r}")
        cat = g["category"].strip().lower()
        if cat not in ALL:
            raise BenchmarkError("category", f"case {index}: golden {n} has unknown category {g['category'][:30]!r}")
        gold.append(Golden(f"gold:{index}:{n}", g["comment"], g["severity"], cat))
    reviews, tools_seen = [], set()
    for r in entry["reviews"]:
        _expect(isinstance(r, dict) and set(r) == {"tool", "repo_name", "pr_url", "review_comments"},
                f"case {index}: review keys")
        _expect(all(isinstance(r[k], str) for k in ("tool", "repo_name"))
                and (r["pr_url"] is None or isinstance(r["pr_url"], str)) and isinstance(r["review_comments"], list),
                f"case {index}: review types")
        if r["tool"] in tools_seen:
            raise BenchmarkError("shape", f"case {index}: more than one review by tool {r['tool'][:40]!r}")
        tools_seen.add(r["tool"])
        cs = []
        for c in r["review_comments"]:
            _expect(isinstance(c, dict) and set(c) == {"path", "line", "body", "created_at"}, f"case {index}: comment keys")
            path, line = c["path"], c["line"]
            _expect(isinstance(c["body"], str) and isinstance(c["created_at"], str), f"case {index}: comment types")
            _expect(path is None or isinstance(path, str), f"case {index}: comment types")
            _expect(line is None or (isinstance(line, int) and not isinstance(line, bool)), f"case {index}: comment types")
            _expect(path is not None or line is None, f"case {index}: comment has a line but no path")
            cs.append(RawComment(typed_id(RAW_COMMENT_ID_VERSION, url, r["tool"], path, line, c["created_at"], c["body"]),
                                 path, line, c["body"], c["created_at"]))
        reviews.append(ToolReview(r["tool"], r["repo_name"], r["pr_url"], tuple(cs)))
    return ScorerCase(url, entry["source_repo"], entry["original_url"], index, tuple(gold), tuple(reviews))
