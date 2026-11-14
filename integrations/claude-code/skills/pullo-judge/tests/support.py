"""Test support for pullo-judge: a scratch judge export of a reviewer tree, invented cases, job building and the v6e comparison run,
each in an isolated child interpreter (its own `reviewer` package). Invented text only; no network, no model."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TESTS = Path(__file__).resolve().parent
SKILL = TESTS.parent
SCRIPT = SKILL / 'scripts/pullo_judge.py'
SCRIPT_REL = 'integrations/claude-code/skills/pullo-judge/scripts/pullo_judge.py'
REPO = Path(os.environ.get('PULLO_JUDGE_REVIEWER_ROOT') or SKILL.parents[3])     # the checkout holding reviewer/ + pullo-score.toml

GOLD_TEXT = ['INVENTED-GOLD the cursor pagination skips records', 'INVENTED-GOLD the retry counter overflows silently']
COMMENT_TEXT = ['INVENTED-COMMENT pagination cursor skips the final records. Please fix.',
                'INVENTED-COMMENT unrelated naming nit in the helper.',
                'INVENTED-COMMENT the counter overflows when retries exceed the limit. It wraps silently.']


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build_export(dst: Path, reviewer_root: Path = REPO, script: Path = SCRIPT) -> tuple[Path, str]:
    """A judge root like freeze_v6ecc_exports.py writes: <dst>/export/{reviewer/**, pullo-score.toml, the skill script} and
    <dst>/source-baseline.json. -> (root, manifest sha256)."""
    ex = dst / 'export'
    shutil.copytree(reviewer_root / 'reviewer', ex / 'reviewer', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(reviewer_root / 'pullo-score.toml', ex / 'pullo-score.toml')
    (ex / SCRIPT_REL).parent.mkdir(parents=True)
    shutil.copy2(script, ex / SCRIPT_REL)
    files = {str(p.relative_to(ex)): sha(p.read_bytes()) for p in sorted(ex.rglob('*')) if p.is_file()}
    raw = (json.dumps({'schema': 'v6ecc-test-export@1', 'commit': 'test', 'files': files}, indent=2, sort_keys=True) + '\n').encode()
    (dst / 'source-baseline.json').write_bytes(raw)
    return dst, sha(raw)


def cases_doc() -> dict:
    """Two invented cases, two tools: a competitor (raw bodies) and pullo (title + body)."""
    def comments(prefix, items, origin):
        return [{'id': f'{prefix}-{i}', 'path': 'src/a.py', 'line': 10 + i, 'origin': origin, 'title': ('Title ' + str(i)) if origin == 'pullo' else None,
                 'body': t, 'ts': '2026-01-01T00:00:00Z'} for i, t in enumerate(items)]
    return {'cases': [
        {'url': 'https://github.com/invented-owner/invented-repo/pull/1', 'repo': 'o/r',
         'golden': [{'id': 'G1', 'comment': GOLD_TEXT[0], 'severity': 'high', 'category': 'bug'},
                    {'id': 'G2', 'comment': GOLD_TEXT[1], 'severity': 'medium', 'category': 'bug'}],
         'reviews': [{'tool': 'coderabbit', 'comments': comments('cr1', COMMENT_TEXT, 'competitor')},
                     {'tool': 'pullo', 'comments': comments('p1', COMMENT_TEXT[:2], 'pullo')}]},
        {'url': 'https://github.com/invented-owner/invented-repo/pull/2', 'repo': 'o/r',
         'golden': [{'id': 'G3', 'comment': GOLD_TEXT[1], 'severity': 'high', 'category': 'bug'}],
         'reviews': [{'tool': 'coderabbit', 'comments': comments('cr2', COMMENT_TEXT[2:], 'competitor')},
                     {'tool': 'pullo', 'comments': comments('p2', COMMENT_TEXT[1:], 'pullo')}]}]}


def child(export: Path, code: str, *args, env=None, timeout=600) -> dict:
    """Run `code` in `python3 -I` with the export's reviewer first on sys.path and the skill script importable; JSON on the last line."""
    pre = (f'import sys, json; sys.path.insert(0, {str(export)!r}); sys.path.insert(1, {str(SCRIPT.parent)!r}); '
           f'sys.path.insert(2, {str(TESTS)!r})\n')
    p = subprocess.run([sys.executable, '-I', '-B', '-c', pre + code, *args], capture_output=True, text=True, timeout=timeout,
                       env=env or child_env())
    if p.returncode != 0:
        raise AssertionError(f'child failed rc={p.returncode}: {p.stderr[-2000:]}')
    return json.loads(p.stdout.strip().splitlines()[-1])


def child_env(home: Path | None = None) -> dict:
    tmp = tempfile.gettempdir()
    return {'PATH': '/usr/bin:/bin', 'HOME': str(home or Path(tmp) / 'no-home'), 'TMPDIR': tmp, 'LANG': 'C.UTF-8'}


BUILD = r'''
import pullo_judge as PJ
from pathlib import Path
a = json.loads(sys.argv[1])
M = Path(a["campaign"]); (M / "inputs").mkdir(parents=True); (M / "operator").mkdir()
raw = (json.dumps(a["cases"], indent=2, ensure_ascii=False) + "\n").encode()
csha = PJ.write_new(M / "inputs/cases.json", raw)
auth = Path(a["auth"])
if not auth.exists():
    PJ.make_pacing_auth(auth, "2030-01-01T00:00:00Z")
declared = [[c["url"], r["tool"]] for c in a["cases"]["cases"] for r in c["reviews"]]
out = PJ.build_job(name=a["name"], kind="test", judge_root=Path(a["root"]), judge_manifest_sha=a["pin"], campaign_dir=M,
                   declared=declared, cases_sha=csha, pacing_auth=auth, eval_run_id=a["evr"], evidence_root=Path(a["evidence"]))
print(json.dumps(out))
'''


def build_job(root: Path, pin: str, world: Path, name='c1', evr='evr_00000000000000a1', cases=None) -> Path:
    (world / 'operator').mkdir(parents=True, exist_ok=True)
    (world / 'evidence').mkdir(exist_ok=True)
    arg = {'campaign': str(world / f'campaign-{name}'), 'cases': cases or cases_doc(), 'auth': str(world / 'operator/pacing-auth.json'),
           'root': str(root), 'pin': pin, 'name': name, 'evr': evr, 'evidence': str(world / 'evidence')}
    return Path(child(root / 'export', BUILD, json.dumps(arg))['job'])


# The v6e path for the same job: the frozen ScoreHost's live-shaped pipeline (OpenRouterProvider.call -> the transport) over a
# RECORDING fake OpenRouter transport that answers with fake_answers.answer. Records each HttpRequest.body (the exact bytes the
# v6e provider would send to openrouter.ai) and returns the documents.
V6E = r'''
import hashlib
from pathlib import Path
from fake_answers import answer
from reviewer import score_host as H, score_host_cli as C
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.runtime import RuntimeLedger, Secret, catalog
from reviewer.runtime.openrouter import HttpResponse
from reviewer.score_baseline import load_baseline, verify
from reviewer.score_config import load_score_config
a = json.loads(sys.argv[1]); job = json.loads(Path(a["job"]).read_text())
b = load_baseline(job["baseline"]); d = b.doc
cfg = load_score_config(Path(d["sourceRoot"]) / "pullo-score.toml")
handle = trusted_authorization(d["auth"]["path"], forbidden_roots=(d["inputRoot"], d["sourceRoot"]))
v = verify(b, now="2026-11-13T00:00:00Z", auth_handle=handle, require_proofs=False, **C._pins(cfg))
units = C._units(b.declared, C._cases(b, v)); launch = C._launch(d, b.declared, cfg)
sent = []
class Recording:                                            # a stand-in for HttpsTransport: same HttpRequest in, HttpResponse out
    def __call__(self, req):
        sent.append(req.body)
        body = json.loads(req.body)
        out = answer(body["response_format"]["json_schema"]["name"], body["messages"][1]["content"])
        doc = {"id": "gen-%04d" % len(sent), "model": body["model"], "provider": "Anthropic",
               "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(out)}}],
               "usage": {"prompt_tokens": 300, "completion_tokens": 20, "total_tokens": 320, "cost": "0.0020",
                         "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0}}}
        return HttpResponse(200, {}, json.dumps(doc).encode())
st = Path(a["state"]); st.mkdir(parents=True)
tr = Recording()
key = Secret("sk-or-v1-" + "0123456789abcdef" * 4)
host = H.ScoreHost(cfg, launch, units, profile_ref=C.PROFILE_REF, price=catalog.gateway_price("anthropic/claude-opus-5.5"), auth=handle,
                   book=SpendBook(handle, st / "book.jsonl"), ledger=RuntimeLedger(st / "ledger.jsonl", 150_000_000), key=key,
                   transport=tr, store_dir=Path(a["store"]), eval_run_id=job["evalRunId"])
rep = host._execute("live-synthetic-transport", pre_send=lambda: None)   # the live-shaped pipeline; pins re-checked inside
docs = json.loads((Path(a["store"]) / (host.run_id + ".documents.json")).read_text())
print(json.dumps({"complete": rep["complete"], "requestSha256": [hashlib.sha256(x).hexdigest() for x in sent],
                  "bodies": [x.decode() for x in sent], "documents": docs}))
'''


def v6e_run(root: Path, job: Path, scratch: Path) -> dict:
    return child(root / 'export', V6E, json.dumps({'job': str(job), 'state': str(scratch / 'v6e-state'), 'store': str(scratch / 'v6e-store')}))


def skill_env(home: Path, claude: Path, state: Path | None = None) -> dict:
    env = child_env(home)
    env['PULLO_JUDGE_CLAUDE'] = str(claude)
    if state is not None:
        env['PULLO_JUDGE_STATE'] = str(state)
    return env


def run_skill(args, home: Path, claude: Path, state: Path | None = None, timeout=600, script: Path = SCRIPT):
    env = skill_env(home, claude, state)
    p = subprocess.run([sys.executable, '-I', '-B', str(script), *args], capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout, json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else None, p.stderr
