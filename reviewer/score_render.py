"""Pullo comment renderer for scoring inputs (SCORE-HOST-05). Pure. The emitted Pullo title + blank line + body is rendered
ONCE here, before adaptation into RawComment.body. Competitor bodies are preserved byte-for-byte (whitespace included);
no title is invented, no evidence trailer is appended."""

from __future__ import annotations

from .benchmark.model import RawComment


def render_pullo(title: str, body: str) -> str:
    if not isinstance(title, str) or not isinstance(body, str) or not title.strip():
        raise ValueError("a Pullo comment needs a non-blank title and a string body")
    return title + "\n\n" + body


def adapt(origin: str, cid: str, path: str, line, title, body: str, ts: str) -> RawComment:
    """origin 'pullo' renders title+blank+body once; 'competitor' keeps the raw body unchanged (a title is not allowed)."""
    if origin == "pullo":
        return RawComment(cid, path, line, render_pullo(title, body), ts)
    if origin == "competitor":
        if title is not None:
            raise ValueError("competitor comments carry no separate title; the raw body is preserved as is")
        if not isinstance(body, str):
            raise ValueError("competitor body must be a string")
        return RawComment(cid, path, line, body, ts)
    raise ValueError("origin must be pullo or competitor")
