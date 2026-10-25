"""Protected-secret redaction (single source for tools, gateway, traces, reports).

Apply `redact` to (1) tool output before it reaches a model, (2) model requests
before hashing/sending, (3) anything persisted: traces, artifacts, reports.
Persisted contract entities reject text that still matches (`contains_protected`).
Ordinary source text is otherwise left as-is. Citation checks compare redacted
excerpts against redacted snapshot text.

Guarantees: newline count is preserved (Evidence line numbers stay valid);
redact runs to a bounded fixpoint, so output is idempotent and passes
`contains_protected`; matching is linear-time per pass on adversarial input.
redact@3 (vs @2): fixpoint iteration; a marker prefix no longer hides a trailing
secret. Corpus fixtures recorded under earlier versions need a refresh.
Patterns with a `secret` group replace only that group, keeping the key name.

Adding a pattern is a contract change: it alters request hashes and therefore
invalidates recorded traces. Coverage is a known-format list plus a generic
quoted-assignment rule; unlisted formats can still leak.
"""

from __future__ import annotations

import re
from typing import Any

REDACTION_VERSION = "redact@3"
MAX_PASSES = 8

_NB = r"(?<![A-Za-z0-9])"          # not glued to a preceding letter/digit ('_' allowed)
_MARKER = r"\[REDACTED:[a-z0-9-]+\]"
# Skip a value only when it is exactly one complete marker; a marker prefix glued to more
# text does not hide the rest (RR10).
_NOT_MARKER = r"(?!" + _MARKER + r"[\"'])"

PROTECTED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Test canary for exfiltration/acceptance suites; never legitimate content.
    ("canary", re.compile(r"RVWCANARY_[A-Za-z0-9]{16,}")),
    ("private-key", re.compile(
        r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|\Z)",
        re.S)),
    ("aws-access-key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("aws-secret-key", re.compile(
        r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{40})")),
    ("github-token", re.compile(_NB + r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("gitlab-token", re.compile(_NB + r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("anthropic-key", re.compile(_NB + r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(_NB + r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("stripe-key", re.compile(_NB + r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack-token", re.compile(_NB + r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(_NB + r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("url-credentials", re.compile(
        r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,30}://(?P<secret>[^\s:/@\[]{1,256}:[^\s@/]{1,256})@")),
    ("bearer-token", re.compile(
        r"(?i)\bbearer\s+(?P<secret>(?:" + _MARKER + r")?[A-Za-z0-9._~+/\-]{16,}=*)")),
    ("assigned-secret", re.compile(
        r"(?i)" + _NB + r"[A-Za-z0-9_.\-]{0,64}(?:password|passwd|pwd|secret|token|api[_-]?key|"
        r"access[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_.\-]{0,64}[\"']?\s*[:=]\s*"
        r"([\"'])" + _NOT_MARKER + r"(?P<secret>[^\"'\s]{8,512})\1")),
)


def _sub(pid: str, pat: re.Pattern[str], text: str) -> tuple[str, int]:
    marker = f"[REDACTED:{pid}]"
    has_group = "secret" in pat.groupindex

    def repl(m: re.Match[str]) -> str:
        if has_group:
            s, e = m.span("secret")
            start = s - m.start()
            whole = m.group(0)
            hidden = whole[start:e - m.start()]
            return whole[:start] + marker + "\n" * hidden.count("\n") + whole[e - m.start():]
        return marker + "\n" * m.group(0).count("\n")

    return pat.subn(repl, text)


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Apply every pattern repeatedly until nothing changes (bounded by MAX_PASSES): removing
    one secret can expose an adjacent one (RR9). Raises ValueError if no fixpoint is reached,
    so callers never persist half-redacted text."""
    counts: dict[str, int] = {}
    for _ in range(MAX_PASSES):
        before = text
        for pid, pat in PROTECTED_PATTERNS:
            text, n = _sub(pid, pat, text)
            if n:
                counts[pid] = counts.get(pid, 0) + n
        if text == before:
            return text, counts
    if contains_protected(text):
        raise ValueError("redaction did not reach a fixpoint")
    return text, counts


def redact_json(obj: Any) -> tuple[Any, dict[str, int]]:
    """Redact every string (values and keys). Keys that collide after redaction get a
    '#<n>' suffix so no value is dropped."""
    total: dict[str, int] = {}

    def add(c: dict[str, int]) -> None:
        for k, n in c.items():
            total[k] = total.get(k, 0) + n

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            r, c = redact(v)
            add(c)
            return r
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            out: dict = {}
            for k, x in v.items():
                rk = walk(k) if isinstance(k, str) else k
                base, n = rk, 1
                while rk in out:
                    n += 1
                    rk = f"{base}#{n}"
                out[rk] = walk(x)
            return out
        return v

    return walk(obj), total


def contains_protected(text: str) -> bool:
    """True if any pattern still matches. Complete markers never match (redact is idempotent)."""
    return any(pat.search(text) for _, pat in PROTECTED_PATTERNS)


def json_contains_protected(obj: Any) -> bool:
    stack = [obj]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if contains_protected(v):
                return True
        elif isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            stack.extend(k for k in v if isinstance(k, str))
            stack.extend(v.values())
    return False
