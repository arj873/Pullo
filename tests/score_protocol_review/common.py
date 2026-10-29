"""SCORE-PROTO-02 independent gate helpers. Offline: invented data, fake `call`, real score-family Gateway + scripted provider.
Candidate tree = SCORE_PROTO_SRC when set (explicit, optional), else this checkout root derived from __file__."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

SRC = os.environ.get("SCORE_PROTO_SRC") or str(Path(__file__).resolve().parents[2])
sys.path.insert(0, SRC)
sys.dont_write_bytecode = True
import tests  # noqa: E402
if str(Path(SRC) / "tests") not in tests.__path__:       # a candidate tree outside this checkout also supplies tests.score_gateway
    tests.__path__.append(str(Path(SRC) / "tests"))

from reviewer.benchmark import allpairs as A                                          # noqa: E402
from reviewer.benchmark import score_prompts as P                                     # noqa: E402
from reviewer.benchmark.model import Golden, RawComment, ScorerCase, ToolReview       # noqa: E402
from reviewer.score_config import load_score_config                                   # noqa: E402

assert Path(A.__file__).resolve().is_relative_to(Path(SRC).resolve()), "producer imported from outside the candidate tree"
ROOT = Path(SRC)
CONFIG = ROOT / "pullo-score.toml"
CFG = load_score_config(CONFIG)
REF = "pullo-score@1"
URL = "https://example.invalid/case/9"
LONG = "Independent invented comment long enough to extract: "
# bench.extract@v3 answers segment ranges, so every invented comment carries one line (= one segment) per fragment the
# tests select by reference.
VOCAB_LINES = ("same", "same one", "alpha", "alpha one", "beta", "beta two", "gamma", "only one", "t0", "t1", "t2", " lead", "trail ")
JUDGE = {"model": "anthropic/claude-opus-5.5", "extractionPrompt": P.VERSIONS["extract"], "dedupPrompt": P.VERSIONS["dedup"],
         "matchPrompt": P.VERSIONS["pair"], "schemaSha256": "0" * 64, "runRef": "evr_1111111111111111"}


def case(tools=("zeta-tool", "alpha-tool"), ngold=2, ncomments=3):
    gold = tuple(Golden(f"REALGOLD-{n}", f"gold finding number {n}", "high", "bug") for n in range(1, ngold + 1))
    reviews = tuple(ToolReview(t, "repo", None, tuple(RawComment(f"REALCID-{t}-{n}", f"src/private/path{n}.py", 10 + n, f"{LONG}item {n} of {chr(96 + len(t) % 26)}\n" + "\n".join(VOCAB_LINES), "2026-01-01T00:00:00Z")
                                                       for n in range(1, ncomments + 1))) for t in tools)
    return ScorerCase(URL, "repo", None, 1, gold, reviews)


@dataclass
class Res:
    output: object = None
    error: object = None

    @property
    def ok(self):
        return self.error is None


class Fake:
    def __init__(self, extract=None, dedup=None, pair=None):
        self.extract, self.dedup, self.pair, self.log = extract, dedup, pair, []

    def __call__(self, stage, role, agent, ordinal, request):
        self.log.append((stage, role, agent, ordinal, request))
        out = {"extractor": self.extract, "deduper": self.dedup, "matcher": self.pair}[role]
        out = out(request, ordinal) if callable(out) else out
        return out if isinstance(out, Res) else Res(out)


def cands(*texts):
    """A fake bench.extract@v3 extractor: candidate i references (as a one-segment range) the first segment of comment
    c00{(i % 3) + 1} in the REQUEST it answers that contains texts[i]. Numbers only, never text."""
    def answer(request, ordinal):
        comments = {c["id"]: c["segments"] for c in json.loads(request["messages"][-1]["content"])["comments"]}
        out = []
        for i, t in enumerate(texts):
            cid = f"c{(i % 3) + 1:03d}"
            hit = [s["n"] for s in comments[cid] if t in s["text"]]
            assert t and hit, "test fixture: fragment absent from the invented comment"
            out.append(rng(cid, hit[0], hit[0]))
        return {"candidates": out}
    return answer


def rng(cid, start, end):
    return {"sourceCommentId": cid, "startSegment": start, "endSegment": end}


def segment_with(text, fragment):
    """The exact segment (P.segments) of `text` that cands() selects for `fragment`."""
    return next(s for s in P.segments(text) if fragment in s)


def units(tools=("zeta-tool", "alpha-tool"), texts=("alpha", " ", "alpha"), **kw):
    c = case(tools, **kw)
    out = []
    for n, t in enumerate(tools, 1):
        m = A.build_mapping(c, t, f"u001-t{n:02d}")
        e = A.run_extract(Fake(extract=cands(*texts)), CFG, REF, m)
        d = A.run_dedup(Fake(dedup={"groups": [[i] for i in range(len(e.candidates))]}), CFG, REF, m, e)
        out.append((m, e, d))
    return c, out
