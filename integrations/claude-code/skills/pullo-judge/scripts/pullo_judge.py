#!/usr/bin/env python3
"""pullo-judge: Pullo's v6e scoring judge run over the Claude Code CLI on the user's subscription (judge v6ecc).

The judge is the frozen v6e scoring code, unchanged: the same model (Opus 5.5), the same prompts (bench.extract@v3,
bench.dedup@v2, bench.pair@v2), the same request bodies, parsing, matching, caps and budgets. This script loads that code from a
pinned judge export (every file re-hashed against its manifest before import) and runs its ScoreHost pipeline. The ONLY change is
the transport: each judge request body the frozen OpenRouterProvider builds is answered by ONE `claude -p` call instead of an HTTPS
call to OpenRouter.

How one request body becomes one CLI call (project_body):
  * --system-prompt = the judge's own system message, then the response schema that the API path sends as response_format.
    The CLI has no constrained decoding without a tool (`--json-schema` is a tool), so the schema is quoted, not enforced.
  * stdin = the judge's user message, byte for byte (the JSON data blob).
  * --model claude-opus-5-5, --effort high (what the API path gets: it sends no effort key, and the API default is high),
    CLAUDE_CODE_MAX_OUTPUT_TOKENS = the body's max_tokens (8000 / 4000 / 1024), the per-stage timeout from the frozen score config.
  * no tools (--tools ""), --strict-mcp-config, no settings, no slash commands, no session persistence, no retries, no thinking
    key, no CLAUDE.md / memory / attachments / file mentions. PATH=/usr/bin:/bin. Never ANTHROPIC_API_KEY or any other key.
The CLI's answer text is handed to the frozen provider as the message content (one whole-answer ```json fence is removed and
counted); the frozen code parses and validates it exactly as it parses an OpenRouter answer.

Safety: calls are serial (one call at a time inside a run, and a per-user lock so two runs never overlap unless --parallel).
A usage limit, rate limit, overload, auth or billing error, a missing/odd model, an isolation problem (a tool, an extra turn, a
retry) or EXTRA USAGE latches: the call's answer is discarded and every later call is refused before anything is spawned, so the
run ends incomplete (never a partial score). The latch is written to a per-user file and blocks every later run until
`unlatch`. This process opens no socket (it is denied): it never calls OpenRouter or any other service; only the CLI child talks
to Anthropic. The CLI version must be exactly 2.1.322.

Seal: stdout carries counts, statuses and paths only - never gold, review, prompt or answer text. The trace and documents (which
hold the judged text, as on the v6e path) are 0600 files in the job's output dir.

Each job runs under its own run lock (<outDir>.lock, taken before outDir exists). Anything after outDir exists ends in the job's
v6ecc-result.json (SIGTERM and Ctrl-C too); only a SIGKILL or a power loss leaves none, and then the free run lock tells the
scoring tools that the run was interrupted. The latch is written before the result. The batch summary is always written: a job
that is refused or fails is recorded with its reason and ends the batch (exit codes: done 0, refused / error 2, latched 3,
interrupted 4). Any rate_limit_event of a call showing extra usage stops that call at once.

Usage:
  python3 -I pullo_judge.py judge <job.json> [<job.json> ...]   run jobs in order; stop at the first latch, refusal or error
  python3 -I pullo_judge.py check <job.json>                     verify a job and its judge export; no CLI call
  python3 -I pullo_judge.py unlatch                              clear the per-user latch (after the limit resets)
A job (pullo-v6ecc-job@1) is written by Pullo's scoring tools (score_v5 rescore-v6ecc / campaign-plan under judge v6ecc)."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from decimal import Decimal
from pathlib import Path

SCRIPT_REL = 'integrations/claude-code/skills/pullo-judge/scripts/pullo_judge.py'   # this file's path inside a judge export
JOB_SCHEMA = 'pullo-v6ecc-job@1'
RESULT_SCHEMA = 'pullo-v6ecc-result@1'
TRANSPORT = 'pullo-v6ecc-cli@1'
JUDGE_LABEL = 'v6ecc'
CLI_VERSION = '2.1.322'
CLI_MODEL = 'claude-opus-5-5'
ROUTE_MODEL = 'anthropic/claude-opus-5.5'          # the frozen judge's model id; the CLI's model is its 1:1 first-party id
EFFORT = 'high'
BILLING_KIND = 'claude-subscription'
CLI_PATH = '/usr/bin:/bin'
CLI_ARGS = ('-p', '--output-format', 'stream-json', '--verbose', '--input-format', 'text', '--model', CLI_MODEL, '--tools', '',
            '--strict-mcp-config', '--setting-sources', '', '--disable-slash-commands', '--no-session-persistence',
            '--effort', EFFORT, '--system-prompt')                          # + the per-call system prompt (last argv item)
ENV_FLAGS = (('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', '1'), ('DISABLE_TELEMETRY', '1'), ('DISABLE_ERROR_REPORTING', '1'),
             ('DISABLE_AUTOUPDATER', '1'), ('DISABLE_UPDATES', '1'), ('DISABLE_INSTALLATION_CHECKS', '1'),
             ('CLAUDE_CODE_MAX_RETRIES', '0'), ('CLAUDE_CODE_MAX_TURNS', '1'), ('CLAUDE_CODE_DISABLE_THINKING', '1'),
             ('CLAUDE_CODE_DISABLE_FILE_MENTIONS', '1'), ('CLAUDE_CODE_DISABLE_CLAUDE_MDS', '1'),
             ('CLAUDE_CODE_DISABLE_AUTO_MEMORY', '1'), ('CLAUDE_CODE_DISABLE_REFUSAL_RETRY', '1'),
             ('CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK', '1'), ('CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK', '1'),
             ('CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY', '1'), ('CLAUDE_CODE_DISABLE_TERMINAL_TITLE', '1'),
             ('CLAUDE_CODE_DISABLE_BUNDLED_SKILLS', '1'), ('CLAUDE_CODE_DISABLE_ATTACHMENTS', '1'))
OUTPUT_CAP_ENV = 'CLAUDE_CODE_MAX_OUTPUT_TOKENS'
ENV_PASS = ('HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'CLAUDE_CONFIG_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
            'XDG_STATE_HOME')                                               # the user's own Claude Code login; never a key
SCHEMA_NOTE = '\n\nThe schema ({name}, JSON Schema):\n'
FENCE_NOTE = 'fenced-json'
CONTINUATION_PREFIX = 'Output token limit hit'
LATCH_TYPES = ('usage-limit', 'rate-limit', 'overloaded', 'auth', 'billing', 'extra-usage', 'model-unavailable', 'isolation',
               'cli-missing')
STAGE_OF_SCHEMA = {'ScoreExtractionSegments': 'extract', 'ScoreDedup': 'dedup', 'ScorePair': 'pair'}
BODY_KEYS = {'model', 'messages', 'max_tokens', 'stream', 'response_format', 'provider'}
PROVIDER_PIN = {'order': ['anthropic'], 'only': ['anthropic'], 'allow_fallbacks': False, 'require_parameters': True}
MAX_STDOUT = 8 << 20
MAX_STDERR = 256 << 10
KILL_GRACE_SEC = 2.0


class Refused(Exception):
    """A fixed refusal before or outside the judge pipeline; the message is a short code (no content)."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def state_dir() -> Path:
    return Path(os.environ.get('PULLO_JUDGE_STATE') or (Path.home() / '.cache/pullo-judge'))


def write_new(path: Path, data: bytes) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    return sha(data)


def dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode()


def script_sha() -> str:
    return sha(Path(__file__).read_bytes())


def args_sha() -> str:
    return sha(json.dumps([list(CLI_ARGS), list(ENV_FLAGS), CLI_PATH, OUTPUT_CAP_ENV, SCHEMA_NOTE]).encode())


# ---------------------------------------------------------------- latch (per user) and serial lock
def read_latch() -> dict | None:
    p = state_dir() / 'latch.json'
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {'type': 'unreadable-latch-file'}


def set_latch(latch: dict) -> None:
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = d / 'latch.json'
    if not p.exists():
        write_new(p, dump(latch))


def serial_lock(parallel: bool):
    if parallel:
        return None
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(d / 'serial.lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise Refused('another-judge-run-active') from None
    return fd


# ---------------------------------------------------------------- the CLI
def cli_binary() -> str:
    path = os.environ.get('PULLO_JUDGE_CLAUDE') or shutil.which('claude', path=CLI_PATH)
    if not path:
        raise Refused('cli-missing')
    return path


def cli_env(workdir: Path, max_tokens: int | None) -> dict:
    env = {k: os.environ[k] for k in ENV_PASS if k in os.environ}
    env.update(ENV_FLAGS)
    env.update(PATH=CLI_PATH, TMPDIR=str(workdir))
    if max_tokens is not None:
        env[OUTPUT_CAP_ENV] = str(max_tokens)
    for k in [k for k in env if 'API_KEY' in k or 'BASE_URL' in k or 'OPENROUTER' in k or 'AUTH_TOKEN' in k]:
        del env[k]                                                          # belt and braces: the env is built from a fixed list
    return env


def cli_version(claude: str, tmp_root: Path) -> str:
    work = Path(tempfile.mkdtemp(prefix='pj-ver-', dir=tmp_root))
    try:
        p = subprocess.run([claude, '--version'], cwd=work, env=cli_env(work, None), capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return (p.stdout or '').strip().split(' ')[0] if p.returncode == 0 else ''


def extra_usage(info: dict | None) -> bool:
    """An answer served from paid EXTRA USAGE (overage), as the CLI's rate_limit_info shows it."""
    i = info or {}
    return bool(i.get('isUsingOverage') is True or i.get('overageInUse') is True
                or (i.get('status') == 'rejected' and i.get('overageStatus') == 'allowed'))


def overage_event(rates: list) -> dict | None:
    """Gate F1: the first rate_limit_info of a call that shows extra usage (any event of the call, not only the last one)."""
    return next((x for x in rates if extra_usage(x)), None)


def classify(status, code, rate: dict | None, text: str) -> str:
    """-> error class from the HTTP status, the CLI's error code, the last rate-limit info and the CLI's own words."""
    text = text or ''
    window = isinstance(rate, dict) and rate.get('status') == 'rejected' and bool(rate.get('rateLimitType'))
    if 'not your usage limit' not in text and (window or 'hit your limit' in text):
        return 'usage-limit'
    if status == 429 or code == 'rate_limit':
        return 'rate-limit'
    if status == 529 or code == 'overloaded':
        return 'overloaded'
    if status in (401, 403) or code in ('authentication_failed', 'oauth_org_not_allowed') or 'Not logged in' in text:
        return 'auth'
    if status == 402 or code == 'billing_error':
        return 'billing'
    if status == 404 or code in ('not_found_error', 'model_not_found'):
        return 'model-unavailable'
    if 'Prompt is too long' in text:
        return 'prompt-too-long'
    if status == 400 or code == 'invalid_request':
        return 'invalid-request'
    if type(status) is int and status >= 500:
        return 'server-error'
    return 'cli-error'


STATUS_OF = {'usage-limit': 429, 'rate-limit': 429, 'overloaded': 529, 'auth': 401, 'billing': 402, 'model-unavailable': 404,
             'prompt-too-long': 413, 'invalid-request': 400, 'server-error': 500}


class Stream:
    """Line-by-line audit of `claude -p --output-format stream-json --verbose`. `feed` returns a kill reason or None."""

    def __init__(self):
        self.init = None
        self.result = None
        self.rate = []
        self.api_error = None
        self.kill = None
        self.continuation = False
        self.unknown = []
        self.bad = 0
        self.thinking_blocks = 0

    def feed(self, line: bytes):
        try:
            ev = json.loads(line)
        except ValueError:
            self.bad += 1
            return None
        if not isinstance(ev, dict):
            self.bad += 1
            return None
        t = ev.get('type')
        if t == 'system':
            if ev.get('subtype') == 'init':
                self.init = ev
            elif ev.get('subtype') == 'api_retry':
                return self._stop('retry')                                    # no retries: one request per call
            elif 'hook' in str(ev.get('subtype')):
                return self._stop('hook')                                     # a user hook could add text to the judge's prompt
        elif t == 'assistant':
            if ev.get('is_api_error_message'):
                self.api_error = {'code': str(ev.get('error'))[:60] if ev.get('error') is not None else None,
                                  'status': ev.get('api_error_status') if type(ev.get('api_error_status')) is int else None}
            msg = ev.get('message') if isinstance(ev.get('message'), dict) else {}
            for c in msg.get('content') or []:
                ct = c.get('type') if isinstance(c, dict) else None
                if ct in ('tool_use', 'server_tool_use'):
                    return self._stop('tool-attempt')
                if ct in ('thinking', 'redacted_thinking'):
                    self.thinking_blocks += 1
                elif ct != 'text':
                    self.unknown.append(f'content/{str(ct)[:30]}')
        elif t == 'user':
            content = (ev.get('message') or {}).get('content') if isinstance(ev.get('message'), dict) else None
            texts = [c.get('text') for c in content if isinstance(c, dict) and c.get('type') == 'text'] \
                if isinstance(content, list) else [content] if isinstance(content, str) else []
            if len(texts) == 1 and isinstance(texts[0], str) and texts[0].startswith(CONTINUATION_PREFIX):
                self.continuation = True                                    # the CLI's own max_tokens continuation turn
            return self._stop('extra-turn')
        elif t == 'rate_limit_event':
            if isinstance(ev.get('rate_limit_info'), dict):
                self.rate.append(ev['rate_limit_info'])
                if extra_usage(ev['rate_limit_info']):
                    return self._stop('extra-usage')                        # gate F1: ANY overage event of the call; stop at once
        elif t == 'result':
            self.result = ev
        else:
            self.unknown.append(str(t)[:30])
        return None

    def _stop(self, reason):
        self.kill = self.kill or reason
        return self.kill


def run_cli(argv, stdin: bytes, env: dict, cwd: Path, timeout: float, stream: Stream) -> dict:
    """One CLI run with a hard deadline, byte caps and a live audit; the whole process group is killed on deadline, overflow or a
    kill reason from the audit."""
    t0 = time.monotonic()
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True)
    out, err, buf = bytearray(), bytearray(), bytearray()
    timed_out = overflow = False
    def feed_stdin():                                                       # a thread: the deadline also covers a CLI that never reads
        try:
            p.stdin.write(stdin)
            p.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass
    writer = threading.Thread(target=feed_stdin, name='pullo-judge-stdin', daemon=True)
    try:
        writer.start()
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ, 'out')
        sel.register(p.stderr, selectors.EVENT_READ, 'err')
        open_ = 2
        while open_:
            left = timeout - (time.monotonic() - t0)
            if left <= 0:
                timed_out = True
                break
            for key, _ in sel.select(min(left, 1.0)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    open_ -= 1
                    continue
                if key.data == 'err':
                    err.extend(chunk[:max(0, MAX_STDERR - len(err))])
                    continue
                out.extend(chunk)
                buf.extend(chunk)
                if len(out) > MAX_STDOUT:
                    overflow = True
                    break
                while b'\n' in buf:
                    line, _, rest = bytes(buf).partition(b'\n')
                    buf[:] = rest
                    if line.strip() and stream.feed(line):
                        break
            if overflow or stream.kill:
                break
        if buf.strip() and not stream.kill:
            stream.feed(bytes(buf))
    finally:
        if p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            p.wait(KILL_GRACE_SEC + 5)
        except subprocess.TimeoutExpired:
            pass
    return {'rc': p.returncode, 'sec': round(time.monotonic() - t0, 2), 'timedOut': timed_out, 'overflow': overflow,
            'stderrBytes': len(err), 'stderrTail': bytes(err[-600:]).decode('utf-8', 'replace')}   # for classify() only, never stored


# ---------------------------------------------------------------- body -> CLI call -> OpenRouter-shaped answer
def project_body(body: dict):
    """The frozen provider's OpenRouter body -> (system prompt, stdin bytes, max_tokens, schema name), or None for any body that
    is not exactly the v6e score request shape."""
    if not isinstance(body, dict) or set(body) != BODY_KEYS or body['model'] != ROUTE_MODEL or body['stream'] is not False:
        return None
    if body['provider'] != PROVIDER_PIN:
        return None
    rf, msgs, mt = body['response_format'], body['messages'], body['max_tokens']
    if not (isinstance(rf, dict) and rf.get('type') == 'json_schema' and isinstance(rf.get('json_schema'), dict)):
        return None
    js = rf['json_schema']
    if set(js) != {'name', 'strict', 'schema'} or js['strict'] is not True or js['name'] not in STAGE_OF_SCHEMA:
        return None
    if not (isinstance(msgs, list) and len(msgs) == 2 and [m.get('role') for m in msgs] == ['system', 'user']
            and all(set(m) == {'role', 'content'} and isinstance(m['content'], str) for m in msgs)):
        return None
    if type(mt) is not int or mt < 1:
        return None
    system = msgs[0]['content'] + SCHEMA_NOTE.format(name=js['name']) + json.dumps(js['schema'], ensure_ascii=False,
                                                                                  separators=(',', ':'))
    return system, msgs[1]['content'].encode('utf-8'), mt, js['name']


def unfence(text: str):
    """One Markdown code fence around the WHOLE answer is removed (note 'fenced-json'); nothing else is touched."""
    s = text.strip()
    if s.startswith('```') and s.endswith('```') and s.count('```') == 2:
        first_nl = s.find('\n')
        if first_nl != -1 and s[3:first_nl].strip() in ('', 'json', 'JSON'):
            return s[first_nl + 1:-3].strip(), FENCE_NOTE
    return text, None


class CliJudge:
    """The CaptureTransport `respond` callback of the frozen ScoreHost: one CLI call per request body, serial."""

    def __init__(self, claude: str, tmp_root: Path, timeouts: dict, calls_path: Path, H, catalog):
        self.claude, self.tmp_root, self.timeouts, self.calls_path = claude, tmp_root, timeouts, calls_path
        self.H, self.catalog = H, catalog
        self.n = 0
        self.latch = None
        self.stopped = None                                                 # run-level stop: the first call that cannot complete
        self.extra_usage = False
        self.rows = []
        self.cli_versions = set()

    # the frozen provider maps these exactly as it maps an HTTPS transport's failures
    def _not_sent(self):
        from reviewer.runtime.openrouter import TransportError
        return TransportError(False)

    def _unknown(self):
        from reviewer.runtime.openrouter import TransportError
        return TransportError(True)

    def _row(self, row):
        if self.stopped is None and not row['outcome'].startswith('refused-') and (row['outcome'] != 'processed' or row.get('finish') != 'stop'):
            self.stopped = row['outcome'] if row['outcome'] != 'processed' else 'finish-' + str(row.get('finish'))
        self.rows.append(row)
        with open(self.calls_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(row, sort_keys=True) + '\n')

    def _latch(self, kind, words, row):
        if self.latch is None:
            self.latch = {'type': kind, 'words': (words or '')[:300], 'at': now_iso(), 'call': row['n']}
        row['latch'] = kind

    def __call__(self, body):
        self.n += 1
        raw = json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode('utf-8')   # the bytes the v6e provider sends
        row = {'n': self.n, 'at': now_iso(), 'requestSha256': sha(raw), 'requestBytes': len(raw), 'model': CLI_MODEL,
               'effort': EFFORT, 'billingKind': BILLING_KIND, 'transport': TRANSPORT}
        proj = project_body(body)
        if proj is None:
            row.update(outcome='refused-body-shape')
            self._row(row)
            return self._not_sent()
        system, stdin, max_tokens, name = proj
        stage = STAGE_OF_SCHEMA[name]
        timeout = self.timeouts[stage]
        row.update(stage=stage, schemaName=name, maxTokens=max_tokens, timeoutSec=timeout,
                   systemPromptSha256=sha(system.encode()), userSha256=sha(stdin))
        if self.latch is not None or self.stopped is not None:
            # after a latch or any call that cannot complete, the campaign is incomplete either way: nothing more is spawned
            row.update(outcome='refused-latched' if self.latch is not None else 'refused-run-stopped',
                       stoppedBy=(self.latch or {}).get('type') or self.stopped)
            self._row(row)
            return self._not_sent()
        work = Path(tempfile.mkdtemp(prefix='pj-call-', dir=self.tmp_root))
        argv = [self.claude, *CLI_ARGS, system]
        stream = Stream()
        try:
            run = run_cli(argv, stdin, cli_env(work, max_tokens), work, timeout, stream)
        except OSError:
            row.update(outcome='cli-missing')
            self._latch('cli-missing', '', row)
            self._row(row)
            return self._not_sent()
        finally:
            shutil.rmtree(work, ignore_errors=True)
        row.update(rc=run['rc'], sec=run['sec'])
        r, init = stream.result, stream.init or {}
        over = overage_event(stream.rate)                                   # gate F1: any event of the call, not only the last one
        limit = next((x for x in stream.rate if x.get('status') == 'rejected'), None)
        rate = over or limit or (stream.rate[-1] if stream.rate else None)  # the event that decides; recorded in the row
        if init.get('claude_code_version'):
            self.cli_versions.add(str(init['claude_code_version'])[:20])
        row['cliVersion'] = init.get('claude_code_version')
        if rate is not None:
            row['rateLimit'] = {k: rate.get(k) for k in ('status', 'rateLimitType', 'resetsAt', 'isUsingOverage', 'overageInUse',
                                                         'overageStatus') if rate.get(k) is not None}
            row['rateLimitEvents'] = len(stream.rate)
        if isinstance(r, dict) and isinstance(r.get('usage'), dict):
            u = r['usage']
            row['usage'] = {k: u.get(k) for k in ('input_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens',
                                                  'output_tokens') if type(u.get(k)) is int}
        if over is not None or stream.kill == 'extra-usage':              # served from paid overage: never $0, never used
            self.extra_usage = True
            row.update(outcome='extra-usage', billingKind='claude-extra-usage')
            self._latch('extra-usage', 'served from extra usage (overage); output discarded', row)
            self._row(row)
            return self._unknown()
        if run['timedOut'] or run['overflow']:
            row.update(outcome='timeout' if run['timedOut'] else 'oversize-output')
            self._row(row)
            from reviewer.runtime.openrouter import TransportTimeout
            return TransportTimeout(True) if run['timedOut'] else self._unknown()
        problems = self._isolation(init, r, stream) if (stream.init is not None or r is not None or stream.kill) else []
        if problems:
            row.update(outcome='isolation', problems=problems[:5])
            self._latch('isolation', ','.join(problems)[:200], row)
            self._row(row)
            return self._unknown()
        if stream.kill == 'extra-turn' and stream.continuation and (r is None or not r.get('is_error')):
            return self._answer(row, r, stream, finish='length')        # the answer hit max_tokens; the CLI's continuation was killed
        if not isinstance(r, dict) or r.get('is_error') or r.get('subtype') != 'success' or not isinstance(r.get('result'), str):
            text = str((r or {}).get('result') or '') or run.get('stderrTail', '')
            err = stream.api_error or {}
            status = err.get('status') or ((r or {}).get('api_error_status') if type((r or {}).get('api_error_status')) is int else None)
            kind = classify(status, err.get('code'), rate, text)
            row.update(outcome='cli-error', errorClass=kind, httpStatus=status)
            if kind in LATCH_TYPES:
                self._latch(kind, text, row)
            self._row(row)
            st = STATUS_OF.get(kind)
            if st is None:
                return self._unknown()
            return self.H_response(st, {'error': {'code': kind}})
        return self._answer(row, r, stream, finish='length' if r.get('stop_reason') == 'max_tokens' else 'stop')

    def _isolation(self, init, r, stream):
        p = []
        if stream.init is None:
            p.append('no-init-event')
        else:
            for k in ('tools', 'mcp_servers'):
                if init.get(k) != []:
                    p.append(f'init-{k}')
            if init.get('model') != CLI_MODEL:
                p.append('init-model')
            if init.get('claude_code_version') != CLI_VERSION:
                p.append('init-version')
            plugins = init.get('plugins') or []
            if not isinstance(plugins, list) or any(not isinstance(x, dict) or not str(x.get('source', '')).endswith('@builtin')
                                                    for x in plugins):
                p.append('init-plugins')                                     # only the CLI's builtin plugins (no user plugin or hook)
        if stream.kill in ('tool-attempt', 'retry', 'hook') or (stream.kill == 'extra-turn' and not stream.continuation):
            p.append(f'killed-{stream.kill}')
        if isinstance(r, dict):
            used = r.get('modelUsage') if isinstance(r.get('modelUsage'), dict) else {}
            if set(used) - {CLI_MODEL}:
                p.append('extra-model')
            if not r.get('is_error') and r.get('num_turns') not in (None, 1):
                p.append('num-turns')
        return p

    def H_response(self, status, doc):
        return self.H.HttpResponse(status, {}, json.dumps(doc).encode())

    def _answer(self, row, r, stream, finish):
        text = (r or {}).get('result') if isinstance(r, dict) else None
        if not isinstance(text, str):
            text = ''
        text, note = unfence(text)
        u = (r or {}).get('usage') if isinstance((r or {}).get('usage'), dict) else {}
        inp, cw, cr, out = (u.get(k) if type(u.get(k)) is int and u.get(k) >= 0 else 0 for k in
                            ('input_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens', 'output_tokens'))
        prompt = inp + cw + cr
        micros = self.catalog.token_priced_micros(ROUTE_MODEL, inp, cr, cw, out, prompt)    # API-equivalent pacing, not money
        usage = {'prompt_tokens': prompt, 'completion_tokens': out, 'total_tokens': prompt + out,
                 'cost': str(Decimal(micros) / Decimal(1_000_000)),
                 'prompt_tokens_details': {'cached_tokens': cr, 'cache_write_tokens': cw}}
        gid = 'v6ecc-' + sha(f"{(r or {}).get('session_id')}|{row['n']}|{row['requestSha256']}".encode())[:24]
        doc = {'id': gid, 'model': ROUTE_MODEL, 'provider': 'Anthropic',
               'choices': [{'index': 0, 'finish_reason': finish, 'message': {'role': 'assistant', 'content': text}}], 'usage': usage}
        row.update(outcome='processed', finish=finish, stopReason=(r or {}).get('stop_reason'), apiEquivalentUsdMicros=micros,
                   answerSha256=sha(text.encode()), notes=[n for n in (note, 'continuation-killed' if stream.continuation else None,
                                                                     'adaptive-thinking' if stream.thinking_blocks else None) if n],
                   numTurns=(r or {}).get('num_turns'), modelUsage=sorted(((r or {}).get('modelUsage') or {}).keys()))
        self._row(row)
        return self.H.HttpResponse(200, {}, json.dumps(doc).encode())


# ---------------------------------------------------------------- job -> frozen ScoreHost run
def load_job(job_path: Path) -> tuple[dict, bytes]:
    raw = job_path.read_bytes()
    job = json.loads(raw)
    need = {'schema', 'name', 'kind', 'judge', 'judgeRoot', 'judgeManifestSha256', 'transportSha256', 'baseline', 'baselineSha256',
            'casesSha256', 'evalRunId', 'outDir', 'stateDir', 'tmpDir', 'cli'}
    if not isinstance(job, dict) or set(job) != need or job['schema'] != JOB_SCHEMA or job['judge'] != JUDGE_LABEL:
        raise Refused('job-shape')
    if job['cli'] != {'version': CLI_VERSION, 'model': CLI_MODEL, 'effort': EFFORT, 'transport': TRANSPORT, 'argsSha256': args_sha()}:
        raise Refused('job-cli-pins-differ')
    return job, raw


def verify_export(job: dict) -> Path:
    """The judge export: its manifest sha is the job's pin and every file is re-hashed (no extra file, no symlink); this script's
    own bytes must be the export's transport file (the frozen v6ecc transport)."""
    root = Path(job['judgeRoot'])
    mraw = (root / 'source-baseline.json').read_bytes()
    if sha(mraw) != job['judgeManifestSha256']:
        raise Refused('judge-manifest-pin')
    man, ex = json.loads(mraw), root / 'export'
    actual = {str(p.relative_to(ex)): p for p in ex.rglob('*') if p.is_file() or p.is_symlink()}
    if set(actual) != set(man['files']):
        raise Refused('judge-export-fileset')
    for n, h in man['files'].items():
        if actual[n].is_symlink() or sha(actual[n].read_bytes()) != h:
            raise Refused('judge-export-drift')
    if man['files'].get(SCRIPT_REL) != job['transportSha256'] or script_sha() != job['transportSha256']:
        raise Refused('transport-script-differs-from-the-frozen-v6ecc-transport')
    return ex


def deny_sockets():
    def denied(*a, **k):
        raise PermissionError('pullo-judge: this process opens no socket (no OpenRouter, no network)')
    socket.socket = socket.create_connection = socket.getaddrinfo = denied   # type: ignore[assignment]


def run_lock_path(out: Path) -> Path:
    """<outDir>.lock: the job's run lock (a sibling of outDir, in the campaign dir)."""
    return out.with_name(out.name + '.lock')


def job_lock(out: Path) -> int:
    """Gate F2: the job's run lock, taken BEFORE outDir exists and held until the result is written. flock is released when the
    process dies (even on SIGKILL), so 'outDir present, no result, run lock free' means an interrupted run (score_v5 v6ecc-settle
    settles it unscorable, and v6ecc-replan can then supersede it)."""
    fd = os.open(run_lock_path(out), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise Refused('job-run-in-progress') from None
    return fd


def run_job(job_path: Path, claude: str) -> dict:
    job, jraw = load_job(job_path)
    ex = verify_export(job)
    out, state, tmp = Path(job['outDir']), Path(job['stateDir']), Path(job['tmpDir'])
    if os.path.lexists(out) or os.path.lexists(state):
        raise Refused('job-already-run')
    if not tmp.is_dir():
        raise Refused('job-tmp-dir-missing')
    sys.path.insert(0, str(ex))
    from reviewer import score_host as H, score_host_cli as C
    from reviewer.gateway import SpendBook, trusted_authorization
    from reviewer.runtime import RuntimeLedger, Secret
    from reviewer.runtime import catalog
    from reviewer.score_baseline import load_baseline, read_regular, sha256_hex, verify
    from reviewer.score_config import load_score_config
    for m in (H, C, catalog):
        if not Path(m.__file__).resolve().is_relative_to(ex.resolve()):
            raise Refused('judge-import-not-from-export')
    deny_sockets()
    bpath = Path(job['baseline'])
    if sha(bpath.read_bytes()) != job['baselineSha256']:
        raise Refused('baseline-pin')
    b = load_baseline(bpath)
    d = b.doc
    if (d['mode'], d['liveAuthorized'], d['envFile'], d['stateDir'], Path(d['sourceRoot']).resolve()) != ('campaign', False, None, str(state), ex.resolve()):
        raise Refused('baseline-not-a-v6ecc-baseline')
    if [f['sha256'] for f in d['inputs'] if f['path'] == 'cases.json'] != [job['casesSha256']]:
        raise Refused('cases-pin')
    cfg = load_score_config(ex / 'pullo-score.toml')
    a = d['auth']
    if sha256_hex(read_regular(a['path'], root=None, owner_only=True)) != a['sha256']:
        raise Refused('pacing-auth-drift')
    handle = trusted_authorization(a['path'], forbidden_roots=(d['inputRoot'], d['sourceRoot']))
    v = verify(b, now=now_iso(), auth_handle=handle, require_proofs=False, **C._pins(cfg))
    cases = C._cases(b, v)
    units = C._units(b.declared, cases)
    launch = C._launch(d, b.declared, cfg)
    version = cli_version(claude, tmp)
    if version != CLI_VERSION:
        raise Refused('cli-version')
    lock = job_lock(out)
    try:
        if os.path.lexists(out) or os.path.lexists(state):
            raise Refused('job-already-run')                                # checked again under the run lock
        out.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        return _run_host(job_path, job, jraw, claude, tmp, out, state, cfg, launch, units, handle, version, H, C, catalog,
                         SpendBook, RuntimeLedger, Secret)
    finally:
        os.close(lock)


def _run_host(job_path, job, jraw, claude, tmp, out, state, cfg, launch, units, handle, version, H, C, catalog,
              SpendBook, RuntimeLedger, Secret) -> dict:
    """The frozen ScoreHost run of one job, under its run lock. Gate F2: anything after outDir exists ends in a result file (an
    exception while building the host too; SIGTERM / Ctrl-C write it, then stop the batch). Only a SIGKILL or a power loss leaves
    no result, and the free run lock tells v6ecc-settle so."""
    calls_path = out / 'v6ecc-calls.jsonl'
    judge = host = stop = None
    started = now_iso()
    err = None
    rep = {}
    try:
        judge = CliJudge(claude, tmp, dict(cfg.timeout_sec), calls_path, H, catalog)
        host = H.ScoreHost(cfg, launch, units, profile_ref=C.PROFILE_REF, price=catalog.gateway_price(ROUTE_MODEL), auth=handle,
                           book=SpendBook(handle, state / 'spend-book.jsonl'), ledger=RuntimeLedger(state / 'runtime-ledger.jsonl', 150_000_000),
                           key=Secret(H.PLACEHOLDER_KEY), transport=H.CaptureTransport(respond=judge), store_dir=out,
                           eval_run_id=job['evalRunId'])
        rep = host.execute_offline()
    except H.ScoreHostError as e:
        err = 'score-host:' + e.reason
    except Exception as e:  # noqa: BLE001 - type name only
        err = 'exception:' + type(e).__name__
    except BaseException as e:  # noqa: BLE001 - SIGTERM (main makes it SystemExit) or Ctrl-C: write the result, then stop
        err, stop = 'interrupted:' + type(e).__name__, e
    rep = dict(rep or {})
    rep.pop('documents', None)
    rows = judge.rows if judge is not None else []
    latch = judge.latch if judge is not None else None
    extra = judge.extra_usage if judge is not None else False
    run_id = getattr(host, 'run_id', None)
    trace = out / f'{run_id}.trace.jsonl' if run_id else None
    docs = out / f'{run_id}.documents.json' if run_id else None
    processed = [r for r in rows if r.get('outcome') == 'processed']
    by_stage = {s: sum(1 for r in rows if r.get('stage') == s) for s in ('extract', 'dedup', 'pair')}
    complete = err is None and rep.get('complete') is True and latch is None and not extra
    status = 'completed' if complete else 'latched' if latch else 'incomplete'
    result = {'schema': RESULT_SCHEMA, 'status': status, 'name': job['name'], 'kind': job['kind'], 'judge': JUDGE_LABEL,
              'jobSha256': sha(jraw), 'scriptSha256': script_sha(), 'judgeManifestSha256': job['judgeManifestSha256'],
              'baselineSha256': job['baselineSha256'], 'casesSha256': job['casesSha256'], 'evalRunId': job['evalRunId'], 'runId': run_id,
              'transport': {'name': TRANSPORT, 'cliVersion': version, 'cliVersionsSeen': sorted(judge.cli_versions if judge else ()), 'model': CLI_MODEL,
                            'route': ROUTE_MODEL, 'effort': EFFORT, 'argsSha256': args_sha(), 'serial': True},
              'calls': {'total': len(rows), 'processed': len(processed), 'byStage': by_stage,
                        'outcomes': {o: sum(1 for r in rows if r.get('outcome') == o) for o in sorted({r.get('outcome') for r in rows})},
                        'fencedJson': sum(1 for r in processed if FENCE_NOTE in r.get('notes', [])),
                        'finishLength': sum(1 for r in processed if r.get('finish') == 'length')},
              'callsSha256': sha(calls_path.read_bytes()) if calls_path.exists() else None,
              'latch': latch, 'extraUsage': extra, 'error': err,
              'report': {k: rep.get(k) for k in ('mode', 'complete', 'gate', 'admission', 'fitRefusal', 'fitTotals', 'attemptSet',
                                                 'baselineDigest', 'configDigest', 'declaredUnits', 'scoringLedger', 'realScoring')},
              'trace': {'path': str(trace), 'sha256': 'sha256:' + sha(trace.read_bytes())} if trace and trace.exists() else None,
              'documents': {'path': str(docs), 'sha256': sha(docs.read_bytes())} if docs and docs.exists() else None,
              'billingKind': BILLING_KIND, 'actualChargeUsdMicros': 0,
              'apiEquivalentEstimateUsdMicros': sum(r.get('apiEquivalentUsdMicros', 0) for r in processed),
              'estimateBasis': 'v6e catalog Opus 5.5 list rates x CLI-reported tokens (pacing, never money)',
              'socketsOpenedByThisProcess': 0, 'startedAt': started, 'endedAt': now_iso()}
    if latch is not None:
        set_latch({**latch, 'job': str(job_path)})                          # gate I-2: persisted before the result write
    write_new(out / 'v6ecc-result.json', dump(result))
    if stop is not None:
        raise stop
    return {'job': str(job_path), 'name': job['name'], 'status': status, 'complete': complete, 'calls': result['calls']['total'],
            'processed': result['calls']['processed'], 'byStage': by_stage, 'latch': (latch or {}).get('type'),
            'latchWords': (latch or {}).get('words') if (latch or {}).get('type') in ('usage-limit', 'rate-limit') else None,
            'extraUsage': extra, 'error': err, 'result': str(out / 'v6ecc-result.json')}


PACING_AUTH_ID = 'pullo-v6ecc-pacing'
PACING_PER_RUN, PACING_TOTAL = 4_000_000, 150_000_000     # = the v6e ScoreHost PER_RUN_MAX and the frozen ledger cap: same fit arithmetic


def make_pacing_auth(path: Path, expires_at: str) -> dict:
    """The operator-issued SpendAuthorization the frozen ScoreHost needs for its scratch (pacing) book and ledger. It authorizes no
    money: nothing on the v6ecc path is paid, and no OpenRouter key exists on it. Per-run bound = the v6e run ceiling (4M)."""
    doc = {'schema': 'spend-authorization@1', 'id': PACING_AUTH_ID, 'issuedBy': 'operator', 'providers': ['anthropic'],
           'models': [ROUTE_MODEL], 'maxUsdMicrosPerRun': PACING_PER_RUN, 'maxUsdMicrosTotal': PACING_TOTAL, 'expiresAt': expires_at,
           'purpose': 'Pullo judge v6ecc pacing only: the v6e scoring fit arithmetic over a scratch ledger; the judge calls run on the '
                      'Claude Code subscription (claude-subscription, $0); no OpenRouter key, no money.'}
    write_new(path, dump(doc))
    return doc


def build_job(*, name: str, kind: str, judge_root: Path, judge_manifest_sha: str, campaign_dir: Path, declared: list,
              cases_sha: str, pacing_auth: Path, eval_run_id: str, evidence_root: Path) -> dict:
    """Write <campaign>/operator/v6ecc-baseline.json and v6ecc-job.json for a campaign whose sealed inputs/cases.json exists.
    Call it in a process whose `reviewer` package IS <judge_root>/export (the frozen judge). No CLI call, no network."""
    from reviewer import score_host_cli as C
    from reviewer.gateway import trusted_authorization
    from reviewer.score_config import load_score_config
    ex, M = Path(judge_root) / 'export', Path(campaign_dir)
    if not Path(C.__file__).resolve().is_relative_to(ex.resolve()):
        raise Refused('build-job-needs-the-judge-export-on-sys.path')
    mraw = (Path(judge_root) / 'source-baseline.json').read_bytes()
    if sha(mraw) != judge_manifest_sha:
        raise Refused('judge-manifest-pin')
    man = json.loads(mraw)
    if sha((M / 'inputs/cases.json').read_bytes()) != cases_sha:
        raise Refused('cases-pin')
    cfg = load_score_config(ex / 'pullo-score.toml')
    pins = C._pins(cfg)
    araw = Path(pacing_auth).read_bytes()
    handle = trusted_authorization(pacing_auth, forbidden_roots=(M / 'inputs', ex))
    if handle.auth['id'] != PACING_AUTH_ID or handle.auth['maxUsdMicrosPerRun'] != PACING_PER_RUN:
        raise Refused('not-the-pacing-authorization')
    doc = {'schema': 'pullo-score-launch-baseline@1', 'mode': 'campaign', 'declared': [list(x) for x in declared],
           'scoreConfig': {'path': 'pullo-score.toml', 'sha256': man['files']['pullo-score.toml'], 'digest': cfg.digest},
           'promptSha256': pins['prompt_sha256'], 'schemaSha256': pins['schema_sha256'], 'policySha256': pins['policy_sha256'],
           'rendererSha256': pins['renderer_sha256'], 'sourceRoot': str(ex),
           'sourceFiles': [{'path': n, 'sha256': h} for n, h in sorted(man['files'].items())],
           'inputRoot': str(M / 'inputs'), 'inputs': [{'path': 'cases.json', 'sha256': cases_sha}], 'stateDir': str(M / 'v6ecc-state'),
           'auth': {'path': str(pacing_auth), 'sha256': sha(araw), 'digest': handle.digest, 'expiresAt': handle.auth['expiresAt']},
           'initial': {'scoring': 0, 'all': 0, 'bookCommitted': 0, 'bookInflight': 0}, 'catalogProof': None, 'canaryProof': None,
           'tracePins': [], 'liveAuthorized': False, 'envFile': None, 'evidenceRoot': str(evidence_root)}
    bpath = M / 'operator/v6ecc-baseline.json'
    bsha = write_new(bpath, dump(doc))
    (M / 'v6ecc-tmp').mkdir(mode=0o700)
    job = {'schema': JOB_SCHEMA, 'name': name, 'kind': kind, 'judge': JUDGE_LABEL, 'judgeRoot': str(judge_root),
           'judgeManifestSha256': judge_manifest_sha, 'transportSha256': man['files'][SCRIPT_REL], 'baseline': str(bpath),
           'baselineSha256': bsha, 'casesSha256': cases_sha, 'evalRunId': eval_run_id, 'outDir': str(M / 'v6ecc-output'),
           'stateDir': str(M / 'v6ecc-state'), 'tmpDir': str(M / 'v6ecc-tmp'),
           'cli': {'version': CLI_VERSION, 'model': CLI_MODEL, 'effort': EFFORT, 'transport': TRANSPORT, 'argsSha256': args_sha()}}
    jsha = write_new(M / 'operator/v6ecc-job.json', dump(job))
    return {'job': str(M / 'operator/v6ecc-job.json'), 'jobSha256': jsha, 'baselineSha256': bsha}


def check_job(job_path: Path) -> dict:
    job, jraw = load_job(job_path)
    verify_export(job)
    return {'job': str(job_path), 'name': job['name'], 'status': 'ok', 'jobSha256': sha(jraw),
            'alreadyRun': os.path.lexists(job['outDir'])}


STOP_STATUSES = ('refused', 'error', 'interrupted')
EXIT_OF = {'done': 0, 'refused': 2, 'error': 2, 'latched': 3, 'interrupted': 4}


def _sigterm(signum, frame):
    raise SystemExit(128 + signum)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog='pullo_judge.py')
    sub = ap.add_subparsers(dest='cmd', required=True)
    j = sub.add_parser('judge')
    j.add_argument('jobs', nargs='+')
    j.add_argument('--parallel', action='store_true', help='skip the per-user serial lock (only when root allows it)')
    c = sub.add_parser('check')
    c.add_argument('job')
    sub.add_parser('unlatch')
    a = ap.parse_args(argv)
    try:
        if a.cmd == 'unlatch':
            p = state_dir() / 'latch.json'
            old = read_latch()
            if old is not None:
                p.unlink()
            print(json.dumps({'status': 'unlatched' if old else 'no-latch', 'was': (old or {}).get('type')}))
            return 0
        if a.cmd == 'check':
            print(json.dumps(check_job(Path(a.job))))
            return 0
        latch = read_latch()
        if latch is not None:
            raise Refused(f"latched:{latch.get('type')}")
        lock = serial_lock(a.parallel)
        try:
            claude = cli_binary()
            runs = state_dir() / 'runs'
            runs.mkdir(parents=True, exist_ok=True, mode=0o700)
            summary_path = runs / f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{os.getpid()}.json"
            print(json.dumps({'status': 'started', 'jobs': len(a.jobs), 'summary': str(summary_path)}), flush=True)
            signal.signal(signal.SIGTERM, _sigterm)                         # gate F2: a TERM still writes the job result + summary
            results = []
            for jp in a.jobs:
                try:
                    r = run_job(Path(jp), claude)
                except Refused as e:                                        # gate F4: recorded per job; the summary is always written
                    r = {'job': jp, 'status': 'refused', 'reason': str(e)}
                except Exception as e:  # noqa: BLE001 - type name only
                    r = {'job': jp, 'status': 'error', 'reason': type(e).__name__}
                except BaseException as e:  # noqa: BLE001 - SIGTERM / Ctrl-C
                    r = {'job': jp, 'status': 'interrupted', 'reason': type(e).__name__}
                results.append(r)
                if r.get('latch') is not None or r['status'] in STOP_STATUSES:
                    break                                                   # a latch or a stop ends the batch: later jobs are not started
            stopped = next((r for r in results if r['status'] in STOP_STATUSES), None)
            summary = {'status': 'latched' if any(r.get('latch') for r in results) else stopped['status'] if stopped else 'done',
                       'jobs': results, 'notStarted': a.jobs[len(results):], 'completed': sum(1 for r in results if r.get('complete')),
                       **({'reason': stopped['reason'], 'stoppedAt': stopped['job']} if stopped else {})}
            write_new(summary_path, dump(summary))
            print(json.dumps(summary))
            return EXIT_OF[summary['status']]
        finally:
            if lock is not None:
                os.close(lock)
    except Refused as e:
        print(json.dumps({'status': 'refused', 'reason': str(e)}))
        return 2
    except Exception as e:  # noqa: BLE001 - type name only; never content
        print(json.dumps({'status': 'error', 'reason': type(e).__name__}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
