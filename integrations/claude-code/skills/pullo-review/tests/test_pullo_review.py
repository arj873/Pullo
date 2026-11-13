"""Offline tests for pullo_review.py: no network, no model call (a fake `claude` CLI answers), no GitHub.

Run: python3 -B -m unittest discover -s integrations/claude-code/skills/pullo-review/tests -v
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / 'scripts' / 'pullo_review.py'
spec = importlib.util.spec_from_file_location('pullo_review', SCRIPT)
PR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PR)

FAKE_CLI = textwrap.dedent('''\
    #!/usr/bin/env python3
    """Fake `claude -p`: prints a list of stream events whose result is answers.json[<model>] (next to this file;
    the script passes the CLI only an allow-listed environment)."""
    import json, os, sys
    sys.stdin.read()
    model = sys.argv[sys.argv.index('--model') + 1]
    answers = json.loads(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'answers.json')).read())
    print(json.dumps([{'type': 'system'}, {'type': 'result', 'subtype': 'success', 'is_error': False,
                       'result': json.dumps(answers[model]), 'usage': {'output_tokens': 1}}]))
''')


def git(repo, *args):
    env = {'PATH': os.environ['PATH'], 'HOME': str(repo), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t'}
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


class ParseDiff(unittest.TestCase):
    def test_content_lines_that_look_like_headers(self):
        d = ('diff --git a/q.sql b/q.sql\n--- a/q.sql\n+++ b/q.sql\n@@ -1,3 +1,3 @@\n select 1;\n'
             '--- old comment\n+++ new comment\n select 2;\n')
        f = PR.parse_diff(d)['q.sql']
        self.assertEqual(sorted(f['newLines']), [1, 2, 3])
        self.assertEqual(sorted(f['oldLines']), [2])

    def test_git_path_unquotes(self):
        self.assertEqual(PR.git_path('"b/caf\\303\\251.py"'), 'b/café.py')
        self.assertEqual(PR.git_path('b/with space.py\t'), 'b/with space.py')
        self.assertEqual(PR.git_path('"a/tab\\there.py"'), 'a/tab\there.py')

    def test_parse_items(self):
        self.assertEqual(PR.parse_items('```json\n[{"file":"./a.py","line":"3","body":"x"}]\n```'),
                         ([{'file': 'a.py', 'line': 3, 'body': 'x'}], None))
        self.assertEqual(PR.parse_items('[]'), ([], None))
        self.assertEqual(PR.parse_items('no issues')[1], 'not-json')
        self.assertEqual(PR.parse_items('[{"file":"a","line":0,"body":"x"}]')[1], 'item-line')

    def test_pinned_matcher(self):
        PR._check_vendored()
        a = {'file': 'a.py', 'line': 10, 'body': '`foo` can be None here and `bar()` crashes'}
        b = {'file': 'a.py', 'line': 11, 'body': '`foo` may be None; calling `bar()` raises'}
        self.assertTrue(PR.same_defect(a, b))
        self.assertEqual({i for i, _ in PR.assign_pairs([a], [b, b])}, PR.assign([a], [b, b]))


class EndToEnd(unittest.TestCase):
    """A real git repo with the three paths ccb-gate found (non-ASCII, a space, a rename) and a fake CLI."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='pullo-review-test-', dir=os.environ.get('TMPDIR')))
        self.repo = self.tmp / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'main')
        (self.repo / 'café.py').write_text('a = 1\n')
        (self.repo / 'with space.py').write_text('b = 1\n')
        (self.repo / 'old_name.py').write_text('c = 1\nd = 2\n')
        git(self.repo, 'add', '-A'); git(self.repo, 'commit', '-qm', 'base')
        git(self.repo, 'checkout', '-qb', 'feature')
        (self.repo / 'café.py').write_text('a = 1\nx = None.y\n')
        (self.repo / 'with space.py').write_text('b = 2\n')
        git(self.repo, 'mv', 'old_name.py', 'new_name.py')
        (self.repo / 'new_name.py').write_text('c = 1\nd = 3\n')
        git(self.repo, 'commit', '-qam', 'change')
        cli = self.tmp / 'claude'
        cli.write_text(FAKE_CLI); cli.chmod(0o755)
        comments = [{'file': 'café.py', 'line': 2, 'body': '`None.y` raises `AttributeError` at import'},
                    {'file': 'with space.py', 'line': 1, 'body': 'changing `b` from 1 to 2 breaks `b` callers'},
                    {'file': 'old_name.py', 'line': 2, 'body': '`d` changed from 2 to 3 without a migration'},
                    {'file': 'nowhere.py', 'line': 1, 'body': '`ghost` file is not part of this PR'}]
        answers = {'claude-opus-5-5': comments, 'claude-sonnet-5-5': comments}
        (self.tmp / 'answers.json').write_text(json.dumps(answers))
        self.env = {'PATH': os.environ['PATH'], 'HOME': str(self.tmp), 'TMPDIR': str(self.tmp), 'LANG': 'C.UTF-8',
                    'PULLO_CLAUDE': str(cli)}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_review(self, *extra):
        p = subprocess.run([sys.executable, '-I', str(SCRIPT), 'review', 'feature', '--repo', str(self.repo), '--base', 'main',
                            '--out', str(self.tmp / 'out'), *extra], capture_output=True, text=True, env=self.env, timeout=120)
        return p, json.loads(p.stdout.strip().splitlines()[-1])

    def test_locations(self):
        p, res = self.run_review()
        self.assertEqual(res['status'], 'ok', p.stderr)
        rec = json.loads((Path(res['reviewDir']) / 'review.json').read_text())
        kept = {c['file']: c for c in rec['kept']}
        self.assertIn('café.py', kept)                         # C-quoted by git, unquoted here
        self.assertIn('with space.py', kept)                   # trailing TAB stripped
        self.assertIn('new_name.py', kept)                     # renamed: anchored on the new path
        self.assertNotIn('old_name.py', kept)
        self.assertEqual(kept['new_name.py']['note'], 'renamed from old_name.py')
        self.assertEqual([d['reason'] for d in rec['dropped']], ['not-a-changed-file'])
        self.assertFalse(rec['rule']['degraded'])

    def test_option_like_target_is_refused(self):
        p = subprocess.run([sys.executable, '-I', str(SCRIPT), 'review', '--output=/tmp/x', '--repo', str(self.repo)],
                           capture_output=True, text=True, env=self.env, timeout=60)
        self.assertNotEqual(p.returncode, 0)

    def test_same_second_reviews_get_distinct_dirs(self):
        _, a = self.run_review()
        _, b = self.run_review()
        self.assertNotEqual(a['reviewDir'], b['reviewDir'])


if __name__ == '__main__':
    unittest.main()
