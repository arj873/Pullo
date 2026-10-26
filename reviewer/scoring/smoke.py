"""Deterministic generator for fixtures/smoke (synthetic Stage 0A smoke suite).

Everything here is synthetic: code, PR text, labels and scripted model responses were written
for mechanics tests. Bug line numbers and citation excerpts are derived from the head files, so
labels, scripts and snapshots cannot drift apart. Regenerate with
`python3 -m reviewer.scoring build-smoke`; `--check` fails if the tree on disk differs.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from reviewer.contracts.canonical import hypothesis_id
from reviewer.contracts.redaction import REDACTION_VERSION
from reviewer.contracts.snapshot import build_manifest

SPECIALIST = "generalist"
MODEL = "synthetic-fixture"
NULL_USAGE = {k: None for k in ("uncachedInputTokens", "cachedInputTokens", "cacheWriteInputTokens",
                                "outputTokens", "reasoningTokens")}
TOLERANCE = 3

AUTH_BASE = '''"""Token checks for the admin API."""
import hmac

HEADER = "x-api-key"


def _clean(raw):
    return raw.strip() if raw else None


def load_expected():
    return EXPECTED_VALUE


def require_auth(raw):
    """Return True only when the caller presented a valid key."""
    value = _clean(raw)
    if value is None:
        return False
    return hmac.compare_digest(value, load_expected())
'''
AUTH_HEAD = AUTH_BASE.replace("    if value is None:\n        return False\n",
                              "    if value == None:\n        return True\n")
ROUTES = '''from auth import require_auth

app = make_app()


@app.get("/admin")
def admin():
    if not require_auth(request.key):
        return deny()
    return render_admin_panel()
'''
REPORT_BASE = '''"""Row formatting for the weekly report."""


def build_row(name, total):
    return f"{name:<20}{total:>10.2f}"


def build_report(items):
    return "\\n".join(build_row(n, t) for n, t in items)
'''
REPORT_HEAD = REPORT_BASE.replace("build_row", "format_row")
CACHE_BASE = '''"""A tiny bounded cache."""


class Cache:
    def __init__(self, limit):
        self.limit = limit
        self.items = {}

    def put(self, key, value):
        self.items[key] = value
        while len(self.items) > self.limit:
            self.items.pop(next(iter(self.items)))

    def get(self, key):
        return self.items.get(key)
'''
CACHE_HEAD = CACHE_BASE.replace("len(self.items) > self.limit:", "len(self.items) > self.limit + 1:")
SERVICE = '''from cache import Cache

recent = Cache(limit=2)


def remember(key, value):
    recent.put(key, value)
    assert len(recent.items) <= recent.limit
'''
PAGER_BASE = '''"""Pagination helpers."""


def page_slice(rows, page, size):
    offset = (page - 1) * size
    return rows[offset:offset + size]
'''
PAGER_HEAD = PAGER_BASE.replace("(page - 1) * size", "page * size")
VIEWS = '''from pager import page_slice


def first_page(rows):
    return page_slice(rows, 1, 25)
'''
MONEY_BASE = '''"""Money helpers."""


def to_cents(amount):
    return round(amount * 100)
'''
MONEY_HEAD = MONEY_BASE.replace("round(amount * 100)", "int(amount * 100)")
BILLING = '''from money import to_cents


def charge_cents(price):
    return to_cents(price)
'''
CONFIG_BASE = '''"""Runtime settings."""


def read_timeout(raw):
    return int(raw) if raw else 30
'''
CONFIG_HEAD = CONFIG_BASE.replace("else 30", "else 0")
SERVER = '''from config import read_timeout


def connect(host, raw_timeout):
    return open_socket(host, timeout=read_timeout(raw_timeout))
'''

# Case ids are neutral on purpose: an id such as "rename-only-silence" would tell the reviewer the
# answer (it appears in input.json). The descriptive `kind` stays here and in the handoff.
# bug: the buggy lines in the head file; caller: an independent citation the verifier makes.
CASES = [
    dict(id="smoke-c01", kind="auth-bypass-positive", repo="fixture-auth", mode="positive", title="Simplify key check",
         body="Refactor the auth helper.", expect="findings",
         base={"src/auth.py": AUTH_BASE, "src/routes.py": ROUTES},
         head={"src/auth.py": AUTH_HEAD, "src/routes.py": ROUTES},
         bug=dict(id="smoke-auth-bypass", path="src/auth.py", snippet="    if value == None:\n        return True\n",
                  category="security", severity="P0", impact="auth-bypass",
                  claim="require_auth returns True when no key is presented",
                  mechanism="The None branch now returns True instead of False.",
                  title="Requests without a key pass authentication",
                  body="`require_auth` returns True when the key is missing, so `/admin` is reachable unauthenticated."),
         caller=dict(path="src/routes.py", snippet="    if not require_auth(request.key):\n        return deny()\n")),
    dict(id="smoke-c02", kind="rename-only-silence", repo="fixture-report", mode="silence", title="Rename row helper",
         body="Rename build_row to format_row.", expect="silence",
         base={"src/report.py": REPORT_BASE}, head={"src/report.py": REPORT_HEAD}, bug=None, caller=None),
    dict(id="smoke-c03", kind="duplicate-hypotheses", repo="fixture-cache", mode="duplicate", title="Relax eviction check",
         body="Tune cache eviction.", expect="findings",
         base={"src/cache.py": CACHE_BASE, "src/service.py": SERVICE},
         head={"src/cache.py": CACHE_HEAD, "src/service.py": SERVICE},
         bug=dict(id="smoke-cache-off-by-one", path="src/cache.py",
                  snippet="        while len(self.items) > self.limit + 1:\n", category="bug", severity="P1",
                  impact="incorrect-result", claim="Cache holds limit+1 entries",
                  claim2="Eviction threshold admits one entry over the limit",
                  mechanism="The loop only evicts above limit+1.",
                  title="Cache can hold one entry more than its limit",
                  body="The eviction loop uses `limit + 1`, so `service.remember` can see `len(items) == limit + 1`."),
         caller=dict(path="src/service.py", snippet="    assert len(recent.items) <= recent.limit\n")),
    dict(id="smoke-c04", kind="malformed-output-repair", repo="fixture-pager", mode="repair", title="Simplify offset",
         body="Inline the offset arithmetic.", expect="findings",
         base={"src/pager.py": PAGER_BASE, "src/views.py": VIEWS},
         head={"src/pager.py": PAGER_HEAD, "src/views.py": VIEWS},
         bug=dict(id="smoke-pager-offset", path="src/pager.py", snippet="    offset = page * size\n",
                  category="bug", severity="P1", impact="incorrect-result",
                  claim="page_slice skips the first page", mechanism="offset is page*size instead of (page-1)*size.",
                  title="First page is skipped",
                  body="`offset = page * size` makes page 1 start at row `size`, so `first_page` never returns row 0."),
         caller=dict(path="src/views.py", snippet="    return page_slice(rows, 1, 25)\n")),
    dict(id="smoke-c05", kind="verifier-failure", repo="fixture-money", mode="verifier-failure", title="Use int conversion",
         body="Avoid float rounding helper.", expect="partial", expectReason="verifier-failure",
         base={"src/money.py": MONEY_BASE, "src/billing.py": BILLING},
         head={"src/money.py": MONEY_HEAD, "src/billing.py": BILLING},
         bug=dict(id="smoke-money-truncation", path="src/money.py", snippet="    return int(amount * 100)\n",
                  category="bug", severity="P1", impact="incorrect-result",
                  claim="to_cents truncates instead of rounding", mechanism="int() drops the fraction of amount*100.",
                  title="Amounts are truncated to cents", body="`int(amount * 100)` turns 0.29 into 28 cents."),
         caller=dict(path="src/billing.py", snippet="    return to_cents(price)\n")),
    dict(id="smoke-c06", kind="provider-timeout", repo="fixture-config", mode="timeout", title="Change default timeout",
         body="Default to no timeout.", expect="failed", expectReason="provider-timeout",
         base={"src/config.py": CONFIG_BASE, "src/server.py": SERVER},
         head={"src/config.py": CONFIG_HEAD, "src/server.py": SERVER},
         bug=dict(id="smoke-config-no-timeout", path="src/config.py", snippet="    return int(raw) if raw else 0\n",
                  category="bug", severity="P1", impact="incorrect-result",
                  claim="Default timeout becomes 0", mechanism="A missing setting now means timeout 0.",
                  title="Default timeout is 0", body="`else 0` replaces the 30 second default."),
         caller=dict(path="src/server.py", snippet="    return open_socket(host, timeout=read_timeout(raw_timeout))\n")),
]


def lines_of(text: str, snippet: str) -> list[int]:
    start = text.index(snippet)
    first = text.count("\n", 0, start) + 1
    return [first, first + snippet.count("\n") - 1]


def _excerpt(text: str, lines: list[int]) -> str:
    return "\n".join(text.split("\n")[lines[0] - 1:lines[1]])


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def dumps(doc) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _resp(output) -> dict:
    return {"status": "ok", "resolvedModel": MODEL, "output": output, "rawText": None, "usage": dict(NULL_USAGE)}


def _entry(stage, role, agent, ordinal, attempt, **body) -> dict:
    return {"stage": stage, "role": role, "agentId": agent, "ordinal": ordinal, "attempt": attempt, **body}


def _error(code, stage, message) -> dict:
    return {"code": code, "message": message, "retryable": True, "stage": stage}


def _citation(commit, path, text, snippet) -> dict:
    lines = lines_of(text, snippet)
    return {"kind": "code", "path": path, "lines": lines, "commit": commit, "excerpt": _excerpt(text, lines)}


def build_script(case: dict, head_id: str) -> dict:
    """Scripted responses for one case, keyed (stage, role, agentId, ordinal, attempt)."""
    bug, caller, mode = case["bug"], case["caller"], case["mode"]
    entries: list[dict] = []
    if mode == "silence":
        entries.append(_entry("INVESTIGATE", "investigator", "generalist", 0, 0,
                              response=_resp({"hypotheses": []})))
        return {"schemaVersion": 1, "entries": entries}
    text = case["head"][bug["path"]]
    ctext = case["head"][caller["path"]]
    lines = lines_of(text, bug["snippet"])
    cite = _citation(head_id, bug["path"], text, bug["snippet"])
    caller_cite = _citation(head_id, caller["path"], ctext, caller["snippet"])

    def hyp(claim, end_line):
        return {"claim": claim, "category": bug["category"], "suspectedSeverity": bug["severity"],
                "impact": bug["impact"], "mechanism": bug["mechanism"],
                "location": {"path": bug["path"], "line": lines[0], "endLine": end_line},
                "evidence": [dict(cite)]}

    def verdict():
        return {"verdict": "confirmed", "reachable": True, "impact": bug["impact"],
                "evidence": [dict(cite), dict(caller_cite)], "notes": "The caller exercises the changed lines."}

    if mode == "timeout":
        for a in range(3):
            entries.append(_entry("INVESTIGATE", "investigator", "generalist", 0, a,
                                  error=_error("provider-timeout", "INVESTIGATE",
                                               "scripted provider timeout (no real request was made)")))
        return {"schemaVersion": 1, "entries": entries}

    hyps = [hyp(bug["claim"], lines[1])]
    if mode == "duplicate":
        hyps.append(hyp(bug["claim2"], lines[0]))
    good = _resp({"hypotheses": hyps})
    if mode == "repair":
        entries.append(_entry("INVESTIGATE", "investigator", "generalist", 0, 0, response={
            "status": "invalid-output", "resolvedModel": MODEL, "output": None, "usage": dict(NULL_USAGE),
            "rawText": '{"hypotheses": [{"claim": "truncated scripted output'}))
        entries.append(_entry("INVESTIGATE", "investigator", "generalist", 0, 1, response=good))
    else:
        entries.append(_entry("INVESTIGATE", "investigator", "generalist", 0, 0, response=good))
    if mode == "verifier-failure":
        for a in range(3):
            entries.append(_entry("VERIFY", "verifier", "verifier", 0, a,
                                  error=_error("provider-error", "VERIFY", "scripted verifier provider error")))
        return {"schemaVersion": 1, "entries": entries}
    for n in range(len(hyps)):
        entries.append(_entry("VERIFY", "verifier", "verifier", n, 0, response=_resp(verdict())))
    fids = [hypothesis_id(SPECIALIST, i, h["claim"], h["location"]["path"], h["location"]["line"])
            for i, h in enumerate(hyps)]
    entries.append(_entry("JUDGE", "judge", "judge", 0, 0, response=_resp(
        {"comments": [{"findingIds": fids, "title": bug["title"], "body": bug["body"]}]})))
    return {"schemaVersion": 1, "entries": entries}


def build_files() -> dict[str, str]:
    """Every file of fixtures/smoke as {relative path: text}. Needs a scratch tree for snapshot ids."""
    import tempfile
    out: dict[str, str] = {}
    suite_cases = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in CASES:
            ids = {}
            for side in ("base", "head"):
                root = Path(tmp) / case["id"] / side
                root.mkdir(parents=True)
                _write_tree(root, case[side])
                ids[side] = build_manifest(root)["snapshotId"]
                for rel, text in case[side].items():
                    out[f"cases/{case['id']}/{side}/{rel}"] = text
            out[f"cases/{case['id']}/input.json"] = dumps({
                "schema": "case-input@1", "id": case["id"], "repo": case["repo"], "synthetic": True,
                "base": {"root": f"cases/{case['id']}/base", "snapshotId": ids["base"]},
                "head": {"root": f"cases/{case['id']}/head", "snapshotId": ids["head"]},
                "pr": {"title": case["title"], "body": case["body"]}})
            bug = case["bug"]
            labels = {"schema": "case-labels@1", "caseId": case["id"], "expect": case["expect"],
                      "bugs": []}
            if bug and case["expect"] != "silence":
                labels["bugs"] = [{"id": bug["id"], "path": bug["path"],
                                   "lines": lines_of(case["head"][bug["path"]], bug["snippet"]),
                                   "category": bug["category"], "severity": bug["severity"]}]
            if "expectReason" in case:
                labels["expectReason"] = case["expectReason"]
            out[f"labels/{case['id']}.json"] = dumps(labels)
            out[f"scripts/{case['id']}.json"] = dumps(build_script(case, ids["head"]))
            suite_cases.append({"id": case["id"], "input": f"cases/{case['id']}/input.json",
                                "labels": f"labels/{case['id']}.json"})
    out["suite.json"] = dumps({
        "schema": "suite@1", "id": "smoke", "version": 1, "synthetic": True,
        "description": "Synthetic Stage 0A smoke suite: positive, bug-free, duplicate, malformed-output "
                       "repair, verifier-failure and timeout cases. Mechanics only; not a quality "
                       "benchmark, and never used for real PRs. Fixture excerpts were validated under "
                       f"{REDACTION_VERSION}.",
        "matching": {"rule": "path-line-overlap@1", "lineTolerance": TOLERANCE}, "cases": suite_cases})
    return out


def write_smoke(out_dir) -> None:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    for rel, text in build_files().items():
        p = out_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def diff_smoke(out_dir) -> list[str]:
    """Differences between the tree on disk and the generator output (empty = identical)."""
    out_dir = Path(out_dir)
    want = build_files()
    have = {p.relative_to(out_dir).as_posix(): p for p in out_dir.rglob("*") if p.is_file()} if out_dir.exists() else {}
    problems = [f"missing {r}" for r in sorted(set(want) - set(have))]
    problems += [f"unexpected {r}" for r in sorted(set(have) - set(want))]
    problems += [f"changed {r}" for r in sorted(set(want) & set(have))
                 if have[r].read_text(encoding="utf-8") != want[r]]
    return problems
