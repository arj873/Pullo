"""Offline tests of the pullo-judge skill (judge v6ecc): a fake claude CLI, a scratch judge export of this checkout's reviewer tree,
invented cases. No network, no model, no real CLI. Every run uses a scratch HOME and a scratch per-user state dir.

  * the CLI call: exact argv flags, the judge's own system prompt (+ the schema), the user message on stdin byte for byte,
    max_tokens = the body's, effort high, PATH=/usr/bin:/bin, no key in the env, a fresh empty cwd per call;
  * parity: the request bodies (bytes) and the judgments equal the v6e path's (the frozen live-shaped pipeline over a recording
    fake OpenRouter transport) for the same job;
  * the latch: a usage limit stops the run (later calls never spawned, no documents) and every later run until `unlatch`;
    extra usage is refused (never used, never $0) and latches, on any rate_limit_event of a call; tool/extra-turn/version/model
    problems refuse; the script must be the job's frozen transport; no socket opens inside the run;
  * a refusal mid-batch keeps the summary; the run lock; SIGTERM still writes the result and summary; SIGKILL leaves the lock free;
  * the seal: stdout and the calls log carry no gold or review text.
Run: TMPDIR=<scratch> nice -n 19 python3 -I -m unittest discover -s integrations/claude-code/skills/pullo-judge/tests -v"""
import json
import os
import shutil
import sys

sys.dont_write_bytecode = True
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_claude  # noqa: E402
import support as T  # noqa: E402

sys.path.insert(0, str(T.SCRIPT.parent))
import pullo_judge as PJ  # noqa: E402


class World:
    def __init__(self, mode='ok', **cfg):
        self.dir = Path(tempfile.mkdtemp(prefix='pj-test-'))
        self.home = self.dir / 'home'
        self.home.mkdir()
        self.state = self.dir / 'pj-state'
        self.root, self.pin = T.build_export(self.dir / 'judge')
        self.fake = self.dir / 'fakebin'
        self.claude = fake_claude.install(self.fake, mode=mode, **cfg)

    def job(self, name='c1', **kw):
        return T.build_job(self.root, self.pin, self.dir / 'world', name=name, **kw)

    def judge(self, *jobs, extra=()):
        return T.run_skill(['judge', *map(str, jobs), *extra], self.home, self.claude, self.state)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class TestCliCall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = World()
        cls.jobp = cls.w.job()
        cls.rc, cls.stdout, cls.out, cls.err = cls.w.judge(cls.jobp)
        cls.calls = fake_claude.calls(cls.w.fake)
        cls.job = json.loads(cls.jobp.read_text())
        cls.result = json.loads(Path(cls.out['jobs'][0]['result']).read_text())

    @classmethod
    def tearDownClass(cls):
        cls.w.close()

    def test_completed(self):
        self.assertEqual(self.rc, 0, self.err[-800:])
        self.assertEqual(self.out['status'], 'done')
        self.assertEqual(self.result['status'], 'completed')
        self.assertTrue(self.result['report']['complete'])
        self.assertIsNotNone(self.result['documents'])
        self.assertEqual(self.result['calls']['total'], len(self.calls))
        self.assertEqual(self.result['calls']['processed'], len(self.calls))
        self.assertEqual(self.result['billingKind'], 'claude-subscription')
        self.assertEqual(self.result['actualChargeUsdMicros'], 0)
        self.assertEqual(self.result['transport']['cliVersion'], '2.1.322')
        self.assertEqual(self.result['transport']['effort'], 'high')
        self.assertEqual(self.result['latch'], None)
        self.assertFalse(self.result['extraUsage'])

    def test_argv_env_cwd(self):
        for c in self.calls:
            self.assertEqual(c['argv'], [*PJ.CLI_ARGS])                          # the system prompt is the last argv item (removed)
            env = c['env']
            self.assertEqual(env['PATH'], '/usr/bin:/bin')
            for k, v in PJ.ENV_FLAGS:
                self.assertEqual(env[k], v)
            self.assertFalse([k for k in env if 'KEY' in k or 'OPENROUTER' in k or 'BASE_URL' in k or 'TOKEN' in k and k != PJ.OUTPUT_CAP_ENV])
            self.assertEqual(env['HOME'], str(self.w.home))
            self.assertTrue(c['cwd'].startswith(self.job['tmpDir']))
        self.assertEqual(os.listdir(self.job['tmpDir']), [])                     # every per-call work dir was removed

    def test_system_prompt_stdin_max_tokens(self):
        bodies = [json.loads(b) for b in T.v6e_run(self.w.root, self.jobp, self.w.dir / 'v6e-a')['bodies']]
        self.assertEqual(len(bodies), len(self.calls))
        for body, c in zip(bodies, self.calls):
            js = body['response_format']['json_schema']
            want = body['messages'][0]['content'] + PJ.SCHEMA_NOTE.format(name=js['name']) + json.dumps(js['schema'], ensure_ascii=False, separators=(',', ':'))
            self.assertEqual(c['system'], want)
            self.assertEqual(c['stdin'], body['messages'][1]['content'])
            self.assertEqual(c['env'][PJ.OUTPUT_CAP_ENV], str(body['max_tokens']))
        self.assertEqual({b['max_tokens'] for b in bodies}, {8000, 4000, 1024})

    def test_parity_with_v6e_path(self):
        v6e = T.v6e_run(self.w.root, self.jobp, self.w.dir / 'v6e-b')
        self.assertTrue(v6e['complete'])
        rows = [json.loads(x) for x in Path(self.job['outDir'], 'v6ecc-calls.jsonl').read_text().splitlines()]
        self.assertEqual([r['requestSha256'] for r in rows], v6e['requestSha256'])            # byte-identical judge inputs
        docs = json.loads(Path(self.result['documents']['path']).read_text())
        norm = lambda ds: sorted(({**d, 'judge': {**d['judge'], 'runRef': None}} for d in ds), key=lambda d: (d['caseUrl'], d['tool']))
        self.assertEqual(norm(docs), norm(v6e['documents']))                                 # the same judgments for the same answers

    def test_seal(self):
        logtext = Path(self.job['outDir'], 'v6ecc-calls.jsonl').read_text() + Path(self.out['jobs'][0]['result']).read_text()
        for t in T.GOLD_TEXT + T.COMMENT_TEXT:
            for piece in (t, t.split(' ', 1)[1][:24]):
                self.assertNotIn(piece, self.stdout)
                self.assertNotIn(piece, logtext)
        self.assertNotIn('INVENTED', self.stdout + logtext)

    def test_rerun_refused(self):
        rc, _, out, _ = self.w.judge(self.jobp)
        self.assertEqual((rc, out['reason']), (2, 'job-already-run'))

    def test_check(self):
        rc, _, out, _ = T.run_skill(['check', str(self.jobp)], self.w.home, self.w.claude, self.w.state)
        self.assertEqual((rc, out['status'], out['alreadyRun']), (0, 'ok', True))


class TestLatchAndRefusals(unittest.TestCase):
    def setUp(self):
        self.w = World()

    def tearDown(self):
        self.w.close()

    def test_usage_limit_latches_the_run_and_later_runs(self):
        fake_claude.set_config(self.w.fake, mode='ok', modes={'2': 'usage-limit'})
        j1, j2 = self.w.job('c1'), self.w.job('c2', evr='evr_00000000000000a2')
        rc, _, out, _ = self.w.judge(j1, j2)
        self.assertEqual((rc, out['status'], out['notStarted']), (3, 'latched', [str(j2)]))
        r = json.loads(Path(out['jobs'][0]['result']).read_text())
        self.assertEqual((r['status'], r['latch']['type'], r['documents']), ('latched', 'usage-limit', None))
        self.assertIn('resets', out['jobs'][0]['latchWords'])
        self.assertEqual(len(fake_claude.calls(self.w.fake)), 2)                             # nothing spawned after the latch
        self.assertTrue(r['calls']['outcomes']['refused-latched'] >= 1)
        rc, _, out, _ = self.w.judge(j2)
        self.assertEqual((rc, out['reason']), (2, 'latched:usage-limit'))
        rc, _, out, _ = T.run_skill(['unlatch'], self.w.home, self.w.claude, self.w.state)
        self.assertEqual(out['was'], 'usage-limit')
        fake_claude.set_config(self.w.fake, mode='ok')
        rc, _, out, _ = self.w.judge(j2)
        self.assertEqual((rc, out['completed']), (0, 1))

    def test_extra_usage_refused(self):
        fake_claude.set_config(self.w.fake, mode='overage')
        rc, _, out, _ = self.w.judge(self.w.job())
        r = json.loads(Path(out['jobs'][0]['result']).read_text())
        self.assertEqual((rc, r['latch']['type'], r['extraUsage'], r['documents']), (3, 'extra-usage', True, None))
        self.assertEqual(len(fake_claude.calls(self.w.fake)), 1)

    def test_version_refused_before_any_call(self):
        fake_claude.set_config(self.w.fake, mode='ok', version='2.1.323')
        rc, _, out, _ = self.w.judge(self.w.job())
        self.assertEqual((rc, out['reason']), (2, 'cli-version'))
        self.assertEqual(fake_claude.calls(self.w.fake), [])

    def test_isolation_problems_latch(self):
        for mode in ('tool-use', 'wrong-model', 'retry', 'tool-use-init', 'hook', 'user-plugin'):
            with self.subTest(mode=mode):
                fake_claude.set_config(self.w.fake, mode=mode)
                shutil.rmtree(self.w.state, ignore_errors=True)
                rc, _, out, _ = self.w.judge(self.w.job(mode, evr='evr_0000000000000' + str(abs(hash(mode)) % 900 + 100)))
                r = json.loads(Path(out['jobs'][0]['result']).read_text())
                self.assertEqual((rc, r['status'], r['latch']['type'], r['documents']), (3, 'latched', 'isolation', None))

    def test_max_tokens_continuation_is_cut_not_continued(self):
        fake_claude.set_config(self.w.fake, mode='max-tokens')
        rc, _, out, _ = self.w.judge(self.w.job())
        r = json.loads(Path(out['jobs'][0]['result']).read_text())
        self.assertEqual((rc, r['status'], r['calls']['finishLength']), (0, 'incomplete', 1))
        self.assertEqual(len(fake_claude.calls(self.w.fake)), 1)                             # the run stops: incomplete either way

    def test_fenced_answer_tolerated_and_counted(self):
        fake_claude.set_config(self.w.fake, mode='fenced')
        rc, _, out, _ = self.w.judge(self.w.job())
        r = json.loads(Path(out['jobs'][0]['result']).read_text())
        self.assertEqual((rc, r['status']), (0, 'completed'))
        self.assertEqual(r['calls']['fencedJson'], r['calls']['processed'])

    def test_prose_answer_is_invalid_output(self):
        fake_claude.set_config(self.w.fake, mode='prose')
        rc, _, out, _ = self.w.judge(self.w.job())
        r = json.loads(Path(out['jobs'][0]['result']).read_text())
        self.assertEqual((rc, r['status'], r['documents']), (0, 'incomplete', None))          # the frozen strict parser refuses it

    def test_auth_latches(self):
        fake_claude.set_config(self.w.fake, mode='auth')
        rc, _, out, _ = self.w.judge(self.w.job())
        self.assertEqual((rc, out['jobs'][0]['latch']), (3, 'auth'))

    def test_export_drift_and_script_pin(self):
        j = self.w.job()
        f = self.w.root / 'export/reviewer/benchmark/score_prompts.py'
        f.chmod(0o644)
        f.write_text(f.read_text() + '\n# drift\n')
        rc, _, out, _ = self.w.judge(j)
        self.assertEqual((rc, out['reason']), (2, 'judge-export-drift'))
        self.assertEqual(fake_claude.calls(self.w.fake), [])

    def test_serial_lock(self):
        import fcntl
        self.w.state.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.w.state / 'serial.lock', os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            rc, _, out, _ = self.w.judge(self.w.job())
            self.assertEqual((rc, out['reason']), (2, 'another-judge-run-active'))
        finally:
            os.close(fd)

    def test_job_cli_pins(self):
        j = self.w.job()
        doc = json.loads(j.read_text())
        doc['cli']['effort'] = 'medium'
        j.chmod(0o600)
        j.write_text(json.dumps(doc))
        rc, _, out, _ = self.w.judge(j)
        self.assertEqual((rc, out['reason']), (2, 'job-cli-pins-differ'))

    # ---- gate-v6ecc-r2 F1: extra usage on ANY rate_limit_event of a call, not only the last
    def test_extra_usage_on_an_earlier_rate_event(self):
        fake_claude.set_config(self.w.fake, mode='overage-two')            # overage first, then an allowed seven_day event
        rc, _, out, _ = self.w.judge(self.w.job())
        self.assertEqual((rc, out['status'], out['jobs'][0]['latch'], out['jobs'][0]['extraUsage']), (3, 'latched', 'extra-usage', True))
        r = json.loads(Path(out['jobs'][0]['result']).read_text())
        self.assertEqual((r['status'], r['latch']['type'], r['extraUsage'], r['documents']), ('latched', 'extra-usage', True, None))
        rows = [json.loads(x) for x in (Path(out['jobs'][0]['result']).parent / 'v6ecc-calls.jsonl').read_text().splitlines()]
        self.assertEqual((rows[0]['outcome'], rows[0]['billingKind'], rows[0]['rateLimit'].get('isUsingOverage')),
                         ('extra-usage', 'claude-extra-usage', True))
        self.assertEqual(r['calls']['processed'], 0)                            # the overage-served answer is never used
        self.assertEqual(len(fake_claude.calls(self.w.fake)), 1)                 # and the run latched: nothing more was spawned
        self.assertEqual(PJ.extra_usage({'status': 'allowed', 'isUsingOverage': False}), False)

    # ---- F3 (gate mutant K5): the script must be the job's frozen transport
    def test_script_differs_from_the_frozen_transport(self):
        j = self.w.job()
        other = self.w.dir / 'other' / 'pullo_judge.py'
        other.parent.mkdir()
        other.write_bytes(T.SCRIPT.read_bytes() + b'\n# not the frozen copy\n')
        rc, _, out, _ = T.run_skill(['judge', str(j)], self.w.home, self.w.claude, self.w.state, script=other)
        self.assertEqual((rc, out['status'], out['reason']), (2, 'refused', 'transport-script-differs-from-the-frozen-v6ecc-transport'))
        doc = json.loads(j.read_text())
        doc['transportSha256'] = '0' * 64
        j.chmod(0o600)
        j.write_text(json.dumps(doc))
        rc, _, out, _ = self.w.judge(j)
        self.assertEqual((rc, out['reason']), (2, 'transport-script-differs-from-the-frozen-v6ecc-transport'))
        self.assertEqual(fake_claude.calls(self.w.fake), [])
        self.assertFalse(Path(doc['outDir']).exists())

    # ---- F3 (gate mutant K9): no socket can be opened inside run_job
    def test_sockets_denied_inside_the_run(self):
        j = self.w.job()
        code = (
            'import socket, pullo_judge as PJ\n'
            'seen = []\n'
            'orig = PJ.CliJudge.__call__\n'
            'def probe(self, body):\n'
            '    for f in (lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM), lambda: socket.create_connection(("127.0.0.1", 9)),\n'
            '              lambda: socket.getaddrinfo("localhost", 80)):\n'
            '        try:\n'
            '            f(); seen.append("opened")\n'
            '        except PermissionError:\n'
            '            seen.append("denied")\n'
            '    return orig(self, body)\n'
            'PJ.CliJudge.__call__ = probe\n'
            'rc = PJ.main(["judge", sys.argv[1]])\n'
            'print(json.dumps({"rc": rc, "seen": sorted(set(seen)), "n": len(seen)}))\n')
        res = T.child(self.w.root / 'export', code, str(j), env=T.skill_env(self.w.home, self.w.claude, self.w.state))
        self.assertEqual((res['rc'], res['seen']), (0, ['denied']))
        self.assertTrue(res['n'] >= 3)

    # ---- F4: a mid-batch refusal or error keeps the batch summary
    def test_mid_batch_refusal_keeps_the_summary(self):
        j1, j3 = self.w.job('c1'), self.w.job('c3', evr='evr_00000000000000a3')
        rc, stdout, out, _ = self.w.judge(j1, j1, j3)                          # the 2nd job is the 1st again: job-already-run
        first = json.loads(stdout.strip().splitlines()[0])
        self.assertEqual((rc, out['status'], out['reason'], out['stoppedAt'], out['completed']), (2, 'refused', 'job-already-run', str(j1), 1))
        self.assertEqual([x['status'] for x in out['jobs']], ['completed', 'refused'])
        self.assertEqual(out['notStarted'], [str(j3)])
        self.assertEqual(json.loads(Path(first['summary']).read_text()), out)  # the announced summary file = the last stdout line
        self.assertFalse(Path(json.loads(j3.read_text())['outDir']).exists())

    # ---- F2 (skill side): the run lock; SIGTERM still writes the result and the summary; SIGKILL leaves the lock free
    def test_run_lock_refuses_a_concurrent_run(self):
        import fcntl
        j = self.w.job()
        lockp = PJ.run_lock_path(Path(json.loads(j.read_text())['outDir']))
        fd = os.open(lockp, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            rc, _, out, _ = self.w.judge(j, extra=('--parallel',))
        finally:
            os.close(fd)
        self.assertEqual((rc, out['status'], out['reason']), (2, 'refused', 'job-run-in-progress'))
        self.assertEqual(fake_claude.calls(self.w.fake), [])
        self.assertFalse(Path(json.loads(j.read_text())['outDir']).exists())

    def test_sigterm_writes_the_result_and_the_summary(self):
        import fcntl
        fake_claude.set_config(self.w.fake, mode='ok', modes={'2': 'term-parent'})
        j1, j2 = self.w.job('c1'), self.w.job('c2', evr='evr_00000000000000a2')
        rc, stdout, out, _ = self.w.judge(j1, j2)
        self.assertEqual((rc, out['status'], out['reason'], out['notStarted']), (4, 'interrupted', 'SystemExit', [str(j2)]))
        first = json.loads(stdout.strip().splitlines()[0])
        self.assertEqual(json.loads(Path(first['summary']).read_text()), out)
        outdir = Path(json.loads(j1.read_text())['outDir'])
        r = json.loads((outdir / 'v6ecc-result.json').read_text())
        self.assertEqual((r['status'], r['error'], r['documents']), ('incomplete', 'interrupted:SystemExit', None))
        self.assertEqual(len(fake_claude.calls(self.w.fake)), 2)
        fd = os.open(PJ.run_lock_path(outdir), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)                     # released
        finally:
            os.close(fd)

    def test_sigkill_leaves_no_result_and_a_free_run_lock(self):
        import fcntl
        fake_claude.set_config(self.w.fake, mode='ok', modes={'2': 'kill-parent'})
        j = self.w.job()
        rc, _, _, _ = self.w.judge(j)
        self.assertEqual(rc, -9)
        outdir = Path(json.loads(j.read_text())['outDir'])
        self.assertTrue(outdir.is_dir())
        self.assertFalse((outdir / 'v6ecc-result.json').exists())               # what score_v5 v6ecc-settle reads as interrupted
        fd = os.open(PJ.run_lock_path(outdir), os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)                     # the kernel released it with the process
        finally:
            os.close(fd)
        fake_claude.set_config(self.w.fake, mode='ok')
        rc, _, out, _ = self.w.judge(j)
        self.assertEqual((rc, out['reason']), (2, 'job-already-run'))           # never re-run: score_v5 settles it, then replans


class TestPure(unittest.TestCase):
    def test_project_body_refuses_other_shapes(self):
        body = {'model': PJ.ROUTE_MODEL, 'messages': [{'role': 'system', 'content': 's'}, {'role': 'user', 'content': '{}'}],
                'max_tokens': 1024, 'stream': False, 'provider': PJ.PROVIDER_PIN,
                'response_format': {'type': 'json_schema', 'json_schema': {'name': 'ScorePair', 'strict': True, 'schema': {}}}}
        self.assertIsNotNone(PJ.project_body(body))
        for k, v in (('model', 'anthropic/claude-sonnet-5.5'), ('stream', True), ('max_tokens', 0), ('tools', []),
                     ('provider', {'order': ['x']})):
            self.assertIsNone(PJ.project_body({**body, k: v}), k)
        self.assertIsNone(PJ.project_body({**body, 'messages': body['messages'] + [{'role': 'assistant', 'content': 'x'}]}))

    def test_unfence_only_whole_answer(self):
        self.assertEqual(PJ.unfence('```json\n{"a":1}\n```'), ('{"a":1}', 'fenced-json'))
        self.assertEqual(PJ.unfence('x ```json\n{}\n```')[1], None)
        self.assertEqual(PJ.unfence('```json\n{}\n``` ```')[1], None)

    def test_classify(self):
        self.assertEqual(PJ.classify(429, 'rate_limit', {'status': 'rejected', 'rateLimitType': 'five_hour'}, ''), 'usage-limit')
        self.assertEqual(PJ.classify(None, None, None, "You've hit your limit · resets 3pm"), 'usage-limit')
        self.assertEqual(PJ.classify(429, 'rate_limit', None, 'Rate limited (not your usage limit)'), 'rate-limit')
        self.assertEqual(PJ.classify(None, None, None, 'Not logged in'), 'auth')

    def test_overage_event_is_any_event_of_the_call(self):                 # gate F1
        over = {'status': 'allowed_warning', 'rateLimitType': 'five_hour', 'isUsingOverage': True}
        ok = {'status': 'allowed', 'rateLimitType': 'seven_day', 'isUsingOverage': False}
        self.assertIs(PJ.overage_event([over, ok]), over)
        self.assertIs(PJ.overage_event([ok, over]), over)
        self.assertIsNone(PJ.overage_event([ok, ok]))
        self.assertIsNone(PJ.overage_event([]))

    def test_stream_stops_at_an_overage_event(self):                       # gate F1: the CLI is killed before any answer
        st = PJ.Stream()
        self.assertIsNone(st.feed(json.dumps({'type': 'rate_limit_event', 'rate_limit_info': {'status': 'allowed'}}).encode()))
        self.assertEqual(st.feed(json.dumps({'type': 'rate_limit_event', 'rate_limit_info': {'status': 'allowed', 'isUsingOverage': True}}).encode()),
                         'extra-usage')
        self.assertEqual((st.kill, len(st.rate)), ('extra-usage', 2))

    def test_extra_usage_rule(self):
        self.assertTrue(PJ.extra_usage({'isUsingOverage': True}))
        self.assertTrue(PJ.extra_usage({'status': 'rejected', 'overageStatus': 'allowed'}))
        self.assertFalse(PJ.extra_usage({'status': 'allowed', 'isUsingOverage': False}))


if __name__ == '__main__':
    unittest.main()
