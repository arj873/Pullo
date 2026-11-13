#!/usr/bin/env python3
"""pullo-review: review a GitHub PR or a branch with Pullo v26 (K6 consensus).

The method is Pullo v26 (impact@v26, k6-plain-witness@1), the version that matched CodeRabbit and beat Greptile on the
sealed HELDOUT-PREP-06 benchmark batch (all-gold F1 .624 vs .614 / .507; core .706 vs .687 / .525):
  1. ONE plain Opus 5.5 answer (the candidate) and TWO plain Sonnet 5.5 answers (the witnesses), each a single `claude -p`
     call on the same fixed prompt plus the PR diff (no tools, no system prompt of ours, no repo access), run in parallel.
  2. A candidate comment is kept when BOTH witnesses raised the same defect (the deterministic matcher below, vendored byte
     for byte from Pullo's reviewer/pipeline/consensus.py: same file, line distance, word / code-token overlap, one-to-one
     per witness).
  3. Kept comments in a file the PR does not change, or on a line the head file does not have, are dropped. Comments on a
     file the PR deletes are kept (on the base side): a deliberate change from v26 (res2's deleted-file finding).
Each kept comment is the Opus text verbatim: no rewrite, no extra model call.

Usage:
  pullo_review.py review <target> [--base REF] [--repo DIR] [--out DIR] [--show-unconfirmed]
  pullo_review.py post <review-dir> [--yes]          # GitHub PR targets only; dry run unless --yes
<target>: https://github.com/O/R/pull/N | O/R#N | https://github.com/O/R/tree/BRANCH | https://github.com/O/R/compare/B...H
          | a local branch or ref (in --repo, default the current directory; base = --base or the remote default branch).
Read-only: `review` never writes to GitHub or to the reviewed repository. The three calls use the Claude Code subscription.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------- the fixed v26 inputs (rereview_ccbaseline.py)
PROMPT = ('You are reviewing a pull request. The PR diff (the output of `git diff <base>...HEAD`) is below. Find the bugs and problems this '
          'PR introduces. For each one, give the file, the line, and a short explanation. Output only a JSON array of {"file", "line", '
          '"body"} objects.')
PROMPT_SHA256 = '4d63d991cc7828a85f3e017c5b82f2e64607c1da7079bacdfdbe113408e4a860'
SEP = '\n\n'
REPAIR_HEAD = ('\n\nYour previous reply (below) is not a valid answer: {why}. Reply again with only the JSON array of {{"file", "line", '
               '"body"}} objects and nothing else.\n<previous-reply>\n')
REPAIR_TAIL = '\n</previous-reply>\n'
CANDIDATE_MODEL, WITNESS_MODEL = 'claude-opus-5-5', 'claude-sonnet-5-5'
N_WITNESSES, K_VOTES = 2, 2
CLI_ARGS = ['-p', '--output-format', 'json', '--input-format', 'text', '--model', '<model>', '--tools', '',
            '--strict-mcp-config', '--setting-sources', '', '--disable-slash-commands', '--no-session-persistence']
ENV_FLAGS = {'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
             'DISABLE_AUTOUPDATER': '1', 'CLAUDE_CODE_MAX_TURNS': '1', 'CLAUDE_CODE_DISABLE_THINKING': '1',
             'CLAUDE_CODE_DISABLE_FILE_MENTIONS': '1', 'CLAUDE_CODE_DISABLE_CLAUDE_MDS': '1',
             'CLAUDE_CODE_DISABLE_AUTO_MEMORY': '1', 'CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY': '1',
             'CLAUDE_CODE_DISABLE_TERMINAL_TITLE': '1', 'CLAUDE_CODE_DISABLE_BUNDLED_SKILLS': '1',
             'CLAUDE_CODE_DISABLE_ATTACHMENTS': '1', 'CLAUDE_CODE_MAX_OUTPUT_TOKENS': '32000'}
ENV_PASS = ('PATH', 'LANG', 'LC_ALL', 'HOME', 'USER', 'LOGNAME', 'CLAUDE_CONFIG_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
            'XDG_CACHE_HOME', 'XDG_STATE_HOME')          # never ANTHROPIC_API_KEY: the calls run on the subscription
CALL_TIMEOUT_SEC = 1800
MAX_DIFF_BYTES = 1_500_000
VENDORED_SHA256 = '3061579621b806d2e3aeabfa41828f56df5585424e0feadd91474d0548ccfa5e'
_BEGIN, _END = '# --- vendored from res2 proto/support.py (byte for byte) ---\n', '# --- end vendored ---\n'

if hashlib.sha256(PROMPT.encode()).hexdigest() != PROMPT_SHA256:
    raise SystemExit('pullo-review: the fixed prompt was edited (sha256 mismatch)')

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


def _check_vendored() -> None:
    src = Path(__file__).read_text()
    a = src.index(_BEGIN) + len(_BEGIN)
    if hashlib.sha256(src[a:src.index(_END, a)].encode()).hexdigest() != VENDORED_SHA256:
        raise SystemExit('pullo-review: the vendored matcher differs from Pullo v26 (sha256 mismatch)')


def assign_pairs(targets, others):
    """assign(), returning the matched (target, other) index pairs."""
    cand = sorted(((score(t, o), i, j) for i, t in enumerate(targets) for j, o in enumerate(others) if same_defect(t, o)),
                  reverse=True)
    used_t, used_o, out = set(), set(), []
    for _, i, j in cand:
        if i not in used_t and j not in used_o:
            used_t.add(i); used_o.add(j); out.append((i, j))
    return out


# ---------------------------------------------------------------- small helpers
def fail(msg: str, code: int = 2):
    print(json.dumps({'status': 'error', 'error': msg}))
    sys.exit(code)


def run(argv, cwd=None, inp=None, timeout=300, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=cwd, input=inp, capture_output=True, text=True, timeout=timeout, env=env)


def gh(*args, accept=None, timeout=300) -> str:
    argv = ['gh', *args] if accept is None else ['gh', 'api', '-H', f'Accept: {accept}', *args]
    p = run(argv, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)[:120]}: {p.stderr.strip()[:300]}")
    return p.stdout


# ---------------------------------------------------------------- target -> diff
PR_URL = re.compile(r'^https?://github\.com/([^/\s]+)/([^/\s]+)/pull/(\d+)')
PR_SHORT = re.compile(r'^([^/\s#]+)/([^/\s#]+)#(\d+)$')
TREE_URL = re.compile(r'^https?://github\.com/([^/\s]+)/([^/\s]+)/tree/(.+?)/?$')
COMPARE_URL = re.compile(r'^https?://github\.com/([^/\s]+)/([^/\s]+)/compare/(.+?)\.\.\.(.+?)/?$')


def resolve(target: str, base: str | None, repo_dir: str | None) -> dict:
    """{kind, title, url, owner, repo, number, base, head, headSha, diff, label}."""
    m = PR_URL.match(target) or PR_SHORT.match(target)
    if m:
        o, r, n = m.group(1), m.group(2), int(m.group(3))
        meta = json.loads(gh('pr', 'view', str(n), '-R', f'{o}/{r}', '--json',
                             'number,title,url,headRefOid,baseRefName,headRefName,state,isDraft'))
        try:
            diff = gh('pr', 'diff', str(n), '-R', f'{o}/{r}', '--color', 'never')
        except RuntimeError:                                       # very large PRs: the compare API instead
            b = json.loads(gh('api', f'repos/{o}/{r}/pulls/{n}'))['base']['sha']
            diff = gh(f'repos/{o}/{r}/compare/{b}...{meta["headRefOid"]}', accept='application/vnd.github.diff')
        return {'kind': 'pr', 'title': meta['title'], 'url': meta['url'], 'owner': o, 'repo': r, 'number': n,
                'base': meta['baseRefName'], 'head': meta['headRefName'], 'headSha': meta['headRefOid'], 'diff': diff,
                'state': meta['state'], 'label': f'{o}-{r}-pr{n}'}
    m = COMPARE_URL.match(target) or TREE_URL.match(target)
    if m:
        o, r = m.group(1), m.group(2)
        if m.re is COMPARE_URL:
            b, h = m.group(3), m.group(4)
        else:
            h = m.group(3)
            b = base or json.loads(gh('api', f'repos/{o}/{r}'))['default_branch']
        sha = json.loads(gh('api', f'repos/{o}/{r}/commits/{h}'))['sha']
        diff = gh(f'repos/{o}/{r}/compare/{b}...{sha}', accept='application/vnd.github.diff')
        return {'kind': 'github-branch', 'title': f'{h} vs {b}', 'url': f'https://github.com/{o}/{r}/compare/{b}...{h}',
                'owner': o, 'repo': r, 'number': None, 'base': b, 'head': h, 'headSha': sha, 'diff': diff,
                'label': f'{o}-{r}-' + re.sub(r'[^A-Za-z0-9._-]+', '_', h)[:60]}
    if target.startswith('-') or (base or '').startswith('-'):
        fail('a target or --base that starts with "-" is refused (it would reach git as an option)')
    d = Path(repo_dir or '.').resolve()
    g = lambda *a: run(['git', '-C', str(d), *a])                  # noqa: E731
    if g('rev-parse', '--git-dir').returncode != 0:
        fail(f'not a PR/branch URL and {d} is not a git repository: {target!r}')
    p = g('rev-parse', '--verify', '--quiet', target + '^{commit}')
    if p.returncode != 0:
        fail(f'unknown local ref {target!r} in {d}')
    sha = p.stdout.strip()
    if base is None:
        p = g('symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD')
        base = p.stdout.strip() if p.returncode == 0 else next(
            (b for b in ('main', 'master', 'origin/main', 'origin/master')
             if g('rev-parse', '--verify', '--quiet', b).returncode == 0), None)
        if base is None:
            fail('no --base given and no main/master/origin HEAD found')
    p = g('diff', '--no-color', '--no-ext-diff', f'{base}...{sha}')
    if p.returncode != 0:
        fail(f'git diff {base}...{target} failed: {p.stderr.strip()[:300]}')
    return {'kind': 'local-branch', 'title': f'{target} vs {base}', 'url': str(d), 'owner': None, 'repo': d.name,
            'number': None, 'base': base, 'head': target, 'headSha': sha, 'diff': p.stdout, 'repoDir': str(d),
            'label': f'{d.name}-' + re.sub(r'[^A-Za-z0-9._-]+', '_', target)[:60]}


# ---------------------------------------------------------------- diff structure (for the location check)
HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')


def git_path(raw: str) -> str:
    """A path as git prints it in a diff header: drop the trailing TAB git adds after a name with a space, and undo
    core.quotePath's C-style quoting (\"caf\\303\\251.py\" -> café.py)."""
    raw = raw.rstrip('\t')
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        out, i, body = bytearray(), 0, raw[1:-1]
        esc = {'n': 10, 't': 9, 'r': 13, '"': 34, '\\': 92, 'a': 7, 'b': 8, 'f': 12, 'v': 11}
        while i < len(body):
            c = body[i]
            if c == '\\' and i + 1 < len(body):
                if len(body[i + 1:i + 4]) == 3 and all(x in '01234567' for x in body[i + 1:i + 4]):
                    out.append(int(body[i + 1:i + 4], 8)); i += 4; continue
                if body[i + 1] in esc:
                    out.append(esc[body[i + 1]]); i += 2; continue
            out += c.encode(); i += 1
        raw = out.decode('utf-8', 'replace')
    return raw


def parse_diff(diff: str) -> dict:
    """{path: {status, old, new, newLines:set, oldLines:set}} keyed by both the new and the old path.
    Inside a hunk, lines are counted against the header's lengths, so content that starts with '--- ' or '+++ ' (an SQL
    comment, say) is never read as a file header."""
    files, cur, o, n, left_o, left_n = {}, None, 0, 0, 0, 0

    def register():
        if cur is not None:
            for p in {cur['old'], cur['new']} - {None}:
                files[p] = cur

    for line in diff.splitlines():
        if left_o > 0 or left_n > 0:                                # hunk body
            if line.startswith('+'):
                cur['newLines'].add(n); n += 1; left_n -= 1
            elif line.startswith('-'):
                cur['oldLines'].add(o); o += 1; left_o -= 1
            elif line.startswith('\\'):                            # "\ No newline at end of file"
                pass
            else:                                                   # context (' ' or an empty line)
                cur['newLines'].add(n); n += 1; o += 1; left_n -= 1; left_o -= 1
            continue
        if line.startswith('diff --git '):
            register()
            cur = {'status': 'modified', 'old': None, 'new': None, 'newLines': set(), 'oldLines': set()}
            # a fallback for entries with no ---/+++ lines (binary, mode-only); the ---/+++ lines win when present.
            # Forms: a/X b/Y, and "a/X" "b/Y" when core.quotePath quotes a name.
            m = re.match(r'^diff --git ("a/.*?(?<!\\)"|a/.+?) ("b/.*(?<!\\)"|b/.+)$', line)
            if m:
                cur['old'], cur['new'] = (git_path(x).removeprefix('a/').removeprefix('b/') for x in m.groups())
            continue
        if cur is None:
            continue
        if line.startswith('new file mode'):
            cur['status'] = 'added'
        elif line.startswith('deleted file mode'):
            cur['status'] = 'deleted'
        elif line.startswith('rename from '):
            cur['status'], cur['old'] = 'renamed', git_path(line[len('rename from '):])
        elif line.startswith('rename to '):
            cur['new'] = git_path(line[len('rename to '):])
        elif line.startswith('--- '):
            v = git_path(line[4:])
            cur['old'] = None if v == '/dev/null' else v.removeprefix('a/')
        elif line.startswith('+++ '):
            v = git_path(line[4:])
            cur['new'] = None if v == '/dev/null' else v.removeprefix('b/')
        elif (m := HUNK.match(line)):
            o, n = int(m.group(1)), int(m.group(3))
            left_o = 1 if m.group(2) is None else int(m.group(2))
            left_n = 1 if m.group(4) is None else int(m.group(4))
    register()
    return files


def head_line_count(t: dict, path: str, cache: dict):
    if path in cache:
        return cache[path]
    try:
        if t['kind'] == 'local-branch':
            p = run(['git', '-C', t['repoDir'], 'show', f"{t['headSha']}:{path}"])
            cache[path] = len(p.stdout.splitlines()) if p.returncode == 0 else None
        else:
            raw = gh(f"repos/{t['owner']}/{t['repo']}/contents/{path}?ref={t['headSha']}", accept='application/vnd.github.raw')
            cache[path] = len(raw.splitlines())
    except Exception:                                              # noqa: BLE001 - unknown, keep the comment
        cache[path] = None
    return cache[path]


# ---------------------------------------------------------------- one plain answer
WHY = {'not-json': 'it is not JSON', 'not-an-array': 'it is not a JSON array',
       'item-keys': 'an item is not an object with "file", "line" and "body"', 'item-file': 'a "file" is not a non-empty string',
       'item-line': 'a "line" is not an integer >= 1', 'item-body': 'a "body" is not a non-empty string'}


def parse_items(text: str):
    """-> (items, None) or (None, why-key). Lenient about a code fence or prose around ONE array; strict about the items."""
    s = text.strip()
    if s.startswith('```'):
        s = re.sub(r'^```[a-zA-Z]*\n?', '', s)
        s = re.sub(r'\n?```$', '', s).strip()
    try:
        doc = json.loads(s)
    except json.JSONDecodeError:
        a, b = s.find('['), s.rfind(']')
        if a < 0 or b <= a:
            return None, 'not-json'
        try:
            doc = json.loads(s[a:b + 1])
        except json.JSONDecodeError:
            return None, 'not-json'
    if not isinstance(doc, list):
        return None, 'not-an-array'
    out = []
    for x in doc:
        if not isinstance(x, dict) or not {'file', 'line', 'body'} <= set(x):
            return None, 'item-keys'
        if not isinstance(x['file'], str) or not x['file'].strip():
            return None, 'item-file'
        line = x['line']
        if isinstance(line, str) and line.strip().isdigit():
            line = int(line.strip())
        if type(line) is not int or line < 1:
            return None, 'item-line'
        if not isinstance(x['body'], str) or not x['body'].strip():
            return None, 'item-body'
        out.append({'file': x['file'].strip().removeprefix('./').removeprefix('b/'), 'line': line, 'body': x['body']})
    return out, None


def call_claude(model: str, prompt: str, workdir: Path) -> dict:
    claude = os.environ.get('PULLO_CLAUDE') or shutil.which('claude')
    if not claude:
        raise RuntimeError('the claude CLI is not on PATH')
    env = {k: os.environ[k] for k in ENV_PASS if k in os.environ}
    env.update(ENV_FLAGS)
    env['TMPDIR'] = str(workdir)
    argv = [claude] + [model if a == '<model>' else a for a in CLI_ARGS]
    t0 = time.time()
    p = run(argv, cwd=str(workdir), inp=prompt, timeout=CALL_TIMEOUT_SEC, env=env)
    out = {'model': model, 'rc': p.returncode, 'sec': round(time.time() - t0, 1)}
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f'{model}: rc {p.returncode}, no JSON result: {(p.stderr or p.stdout).strip()[:300]}')
    # --output-format json is one result object on some CLI versions and a list of events (last: type "result") on others
    events = doc if isinstance(doc, list) else [doc]
    res = next((e for e in reversed(events) if isinstance(e, dict) and e.get('type') == 'result'), None)
    if res is None:
        raise RuntimeError(f'{model}: rc {p.returncode}, no result event in the CLI output')
    if p.returncode != 0 or res.get('is_error'):
        raise RuntimeError(f"{model}: rc {p.returncode}, {res.get('subtype')}: {str(res.get('result'))[:300]}")
    out.update(text=res.get('result') or '', usage=res.get('usage'), sessionId=res.get('session_id'))
    return out


def plain_answer(role: str, model: str, diff: str, workdir: Path) -> dict:
    """One plain answer: one call, at most ONE repair (as v26), and ONE retry after a CLI failure."""
    workdir.mkdir(parents=True, exist_ok=True)
    prompt = PROMPT + SEP + diff
    calls, last_err = [], None
    for attempt in range(2):
        try:
            c = call_claude(model, prompt, workdir)
            break
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            last_err = str(e)
            calls.append({'error': last_err})
            if attempt == 0:
                time.sleep(20)
    else:
        return {'role': role, 'model': model, 'status': 'failed', 'error': last_err, 'calls': calls, 'items': []}
    calls.append({k: c[k] for k in ('rc', 'sec', 'usage')})
    items, why = parse_items(c['text'])
    if why:
        try:
            c2 = call_claude(model, prompt + REPAIR_HEAD.format(why=WHY[why]) + c['text'] + REPAIR_TAIL, workdir)
            calls.append({k: c2[k] for k in ('rc', 'sec', 'usage')})
            items, why2 = parse_items(c2['text'])
            if why2:
                return {'role': role, 'model': model, 'status': 'invalid', 'error': WHY[why2], 'calls': calls, 'items': [],
                        'raw': c2['text'][:20000]}
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            return {'role': role, 'model': model, 'status': 'invalid', 'error': str(e), 'calls': calls, 'items': []}
    for i, x in enumerate(items):
        x['id'] = f'{role}-{i + 1}'
    return {'role': role, 'model': model, 'status': 'completed', 'calls': calls, 'items': items}


# ---------------------------------------------------------------- review
def review(args) -> None:
    _check_vendored()
    try:
        t = resolve(args.target, args.base, args.repo)
    except (RuntimeError, FileNotFoundError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        fail(f'could not get the diff: {e}')
    diff = t['diff']
    if not diff.strip():
        fail('the diff is empty (nothing to review)')
    if len(diff.encode()) > args.max_diff_bytes:
        fail(f"the diff is {len(diff.encode())} bytes, over the {args.max_diff_bytes} limit (--max-diff-bytes)")
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    root = Path(args.out or os.environ.get('PULLO_REVIEW_DIR') or Path.home() / '.cache' / 'pullo-review')
    out, n = root / f"{t['label']}-{stamp}", 1
    while True:
        try:
            out.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            n += 1
            out = root / f"{t['label']}-{stamp}-{n}"
    (out / 'diff.patch').write_text(diff)
    roles = [('candidate', CANDIDATE_MODEL)] + [(f'witness{j + 1}', WITNESS_MODEL) for j in range(N_WITNESSES)]
    with cf.ThreadPoolExecutor(max_workers=len(roles)) as ex:
        futs = {r: ex.submit(plain_answer, r, m, diff, out / 'work' / r) for r, m in roles}
        answers = {r: f.result() for r, f in futs.items()}
    cand = answers['candidate']
    if cand['status'] != 'completed':
        (out / 'review.json').write_text(json.dumps({'target': {k: v for k, v in t.items() if k != 'diff'},
                                                     'answers': answers}, indent=1))
        fail(f"the Opus candidate answer {cand['status']}: {cand.get('error')} (details: {out}/review.json)", 3)
    wits = [answers[f'witness{j + 1}'] for j in range(N_WITNESSES)]
    live = [w for w in wits if w['status'] == 'completed']
    k = K_VOTES if len(live) == N_WITNESSES else len(live)
    degraded = len(live) < N_WITNESSES
    if not live:
        fail(f'no witness answer completed ({", ".join(str(w.get("error")) for w in wits)}); nothing can be confirmed', 3)
    items = cand['items']
    rows = [{'id': c['id'], 'votes': 0, 'support': []} for c in items]
    for w in live:
        pairs = assign_pairs(items, w['items'])
        if {i for i, _ in pairs} != assign(items, w['items']):      # the pinned matcher is the authority
            fail('internal: assign_pairs disagrees with the pinned assign()', 4)
        for i, j in pairs:
            rows[i]['votes'] += 1
            rows[i]['support'].append(w['items'][j]['id'])
    files, cache, kept, dropped = parse_diff(diff), {}, [], []
    for c, r in zip(items, rows):
        if r['votes'] < k:
            dropped.append({**c, 'votes': r['votes'], 'reason': 'unconfirmed'})
            continue
        f = files.get(c['file'])
        if f is None or c['file'].startswith('/') or '..' in Path(c['file']).parts:
            dropped.append({**c, 'votes': r['votes'], 'reason': 'not-a-changed-file'})
            continue
        if f['status'] == 'deleted':
            kept.append({**c, 'votes': r['votes'], 'support': r['support'], 'side': 'LEFT', 'inDiff': c['line'] in f['oldLines'],
                         'note': 'file deleted by this PR'})
            continue
        in_diff = c['line'] in f['newLines']
        if not in_diff:
            nlines = head_line_count(t, f['new'], cache)
            if nlines is not None and c['line'] > nlines:
                dropped.append({**c, 'votes': r['votes'], 'reason': 'no-such-line'})
                continue
        extra = {'file': f['new'], 'note': f"renamed from {f['old']}"} if f['status'] == 'renamed' and c['file'] != f['new'] else {}
        kept.append({**c, **extra, 'votes': r['votes'], 'support': r['support'], 'side': 'RIGHT', 'inDiff': in_diff})
    kept.sort(key=lambda x: (x['file'], x['line']))
    rec = {'schema': 'pullo-review@1', 'method': 'Pullo v26 K6 consensus (k6-plain-witness@1, matcher res2-lexical-1to1@1)',
           'at': stamp, 'target': {k2: v for k2, v in t.items() if k2 != 'diff'},
           'rule': {'n': len(live), 'k': k, 'degraded': degraded}, 'promptSha256': PROMPT_SHA256,
           'matcherSha256': VENDORED_SHA256, 'answers': answers, 'kept': kept, 'dropped': dropped}
    (out / 'review.json').write_text(json.dumps(rec, indent=1))
    (out / 'review.md').write_text(render(rec, args.show_unconfirmed))
    print(json.dumps({'status': 'ok', 'reviewDir': str(out), 'reviewMd': str(out / 'review.md'), 'comments': len(kept),
                      'candidates': len(items), 'unconfirmed': sum(d['reason'] == 'unconfirmed' for d in dropped),
                      'offDiff': sum(d['reason'] != 'unconfirmed' for d in dropped), 'degraded': degraded,
                      'witnessComments': [len(w['items']) for w in live]}))


def render(rec: dict, show_unconfirmed: bool) -> str:
    t, kept, dropped = rec['target'], rec['kept'], rec['dropped']
    head = (f"# Pullo review: {t['title']}\n\n{t['url']}  \nHead `{t['headSha'][:12]}` vs base `{t['base']}`. "
            f"Method: Pullo v26 consensus. One plain Opus 5.5 review; each comment is kept only when "
            f"{rec['rule']['k']} of {rec['rule']['n']} independent plain Sonnet 5.5 reviews raised the same defect. "
            "Comment text is Opus's, verbatim.\n")
    if rec['rule']['degraded']:
        head += ("\n> **Degraded:** a witness answer failed, so comments were confirmed by 1 witness instead of 2. "
                 "Expect more false positives than usual.\n")
    unc = [d for d in dropped if d['reason'] == 'unconfirmed']
    off = [d for d in dropped if d['reason'] != 'unconfirmed']
    lines = [head, f"\n**{len(kept)} comment(s)** from {len(kept) + len(dropped)} Opus candidate(s): "
                   f"{len(unc)} not confirmed by the witnesses, {len(off)} not on a line this PR has.\n"]
    for i, c in enumerate(kept, 1):
        where = f"{c['file']}:{c['line']}" + (' (deleted file, base side)' if c['side'] == 'LEFT' else '') + (
            '' if c['inDiff'] else ' (outside the changed lines)')
        lines.append(f"\n## {i}. `{where}`\n\n{c['body'].strip()}\n")
    if not kept:
        lines.append('\nNo confirmed problems.\n')
    if show_unconfirmed and unc:
        lines.append('\n---\n\n### Not confirmed (raised by Opus; fewer witnesses agreed)\n')
        for c in unc:
            lines.append(f"\n- `{c['file']}:{c['line']}` ({c['votes']} of {rec['rule']['n']}): {c['body'].strip()[:600]}\n")
    return ''.join(lines)


# ---------------------------------------------------------------- post (explicit, PR targets only)
def post(args) -> None:
    d = Path(args.review_dir)
    rec = json.loads((d / 'review.json').read_text())
    t = rec['target']
    if t['kind'] != 'pr':
        fail('post: only a GitHub PR review can be posted')
    inline = [c for c in rec['kept'] if c['inDiff']]
    rest = [c for c in rec['kept'] if not c['inDiff']]
    body = (f"Pullo review (v26 consensus): {len(rec['kept'])} comment(s), each raised by Opus 5.5 and confirmed by "
            f"{rec['rule']['k']} of {rec['rule']['n']} independent Sonnet 5.5 reviews.")
    if rest:
        body += '\n\nOutside the changed lines:\n' + '\n'.join(f"- `{c['file']}:{c['line']}`: {c['body'].strip()}" for c in rest)
    payload = {'commit_id': t['headSha'], 'event': 'COMMENT', 'body': body,
               'comments': [{'path': c['file'], 'line': c['line'], 'side': c['side'], 'body': c['body'].strip()} for c in inline]}
    (d / 'post-payload.json').write_text(json.dumps(payload, indent=1))
    if not args.yes:
        print(json.dumps({'status': 'dry-run', 'pr': t['url'], 'inline': len(inline), 'inBody': len(rest),
                          'payload': str(d / 'post-payload.json'), 'post': f'pullo_review.py post {d} --yes'}))
        return
    p = run(['gh', 'api', '--method', 'POST', f"repos/{t['owner']}/{t['repo']}/pulls/{t['number']}/reviews",
             '--input', str(d / 'post-payload.json')])
    if p.returncode != 0:
        fail(f'post failed: {p.stderr.strip()[:400]}')
    print(json.dumps({'status': 'posted', 'pr': t['url'], 'review': json.loads(p.stdout).get('html_url')}))


def main() -> None:
    ap = argparse.ArgumentParser(prog='pullo_review.py', description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('review', help='review a PR or branch (read-only)')
    r.add_argument('target')
    r.add_argument('--base', help='base ref for a branch target (default: the default branch)')
    r.add_argument('--repo', help='local repository for a local branch target (default: cwd)')
    r.add_argument('--out', help='output root (default: $PULLO_REVIEW_DIR or ~/.cache/pullo-review)')
    r.add_argument('--max-diff-bytes', type=int, default=MAX_DIFF_BYTES)
    r.add_argument('--show-unconfirmed', action='store_true', help='also list the Opus comments the witnesses did not confirm')
    p = sub.add_parser('post', help='post a finished PR review to GitHub (dry run unless --yes)')
    p.add_argument('review_dir')
    p.add_argument('--yes', action='store_true')
    a = ap.parse_args()
    review(a) if a.cmd == 'review' else post(a)


if __name__ == '__main__':
    main()
