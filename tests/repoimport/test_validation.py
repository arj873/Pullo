import os
import sys
import time
from unittest import mock

from reviewer.repoimport import ImportPolicy, RepoImportError, github_remote, gitrun
from reviewer.repoimport.remote import check_commit

from .helpers import Tmp


class Urls(Tmp):
    def test_accepts_only_plain_github_https(self):
        r = github_remote("https://github.com/boykopovar/AnyPS5")
        self.assertEqual((r.owner, r.name, r.slug), ("boykopovar", "AnyPS5", "boykopovar--anyps5"))
        self.assertEqual(github_remote("https://github.com/o/r.git/").url, "https://github.com/o/r")
        for bad in ("http://github.com/o/r", "https://github.com.evil/o/r", "https://user@github.com/o/r",
                    "https://user:pw@github.com/o/r", "https://github.com:443/o/r", "git@github.com:o/r.git",
                    "ssh://git@github.com/o/r", "file:///tmp/x", "https://github.com/o/r?x=1", "https://github.com/o/r#f",
                    "https://github.com/o/r/tree/main", "https://github.com/o", "https://github.com/../r",
                    "https://github.com/o/..", "https://github.com/-o/r", "https://github.com/o/-r",
                    "https://github.com/o/r\n", "https://github.com/o/r evil", "https://GITHUB.com/o/r",
                    "https://github.com/o/r.git.git", "https://github.com/o\\x/r", "--upload-pack=x", "", None, 5):
            with self.subTest(bad=bad), self.assertRaises(RepoImportError) as c:
                github_remote(bad)
            self.assertEqual(c.exception.code, "bad-url")

    def test_commit_must_be_exact_lowercase_sha(self):
        self.assertEqual(check_commit("a" * 40), "a" * 40)
        for bad in ("main", "HEAD", "a" * 39, "a" * 41, "A" * 40, "g" * 40, "a" * 40 + "\n", "-" + "a" * 39, None, b"a" * 40):
            with self.subTest(bad=bad), self.assertRaises(RepoImportError) as c:
                check_commit(bad)
            self.assertEqual(c.exception.code, "bad-commit")

    def test_policy_rejects_nonpositive_or_non_int(self):
        for kw in ({"max_files": 0}, {"max_file_bytes": -1}, {"fetch_timeout_s": 1.5}, {"max_depth": True and "x"}):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                ImportPolicy(**kw)
        self.assertEqual(ImportPolicy().doc()["digest"], ImportPolicy().doc()["digest"])


class Isolation(Tmp):
    def test_env_preserves_home_and_codex_home_and_drops_git_state(self):
        src = {"PATH": "/usr/bin", "HOME": "/h/me", "CODEX_HOME": "/h/codex", "GIT_DIR": "/x", "GIT_SSH_COMMAND": "evil",
               "GIT_EXEC_PATH": "/evil", "GIT_CONFIG_COUNT": "1", "GIT_SSL_NO_VERIFY": "1", "XDG_CONFIG_HOME": "/x",
               "OPENROUTER_KEY": "sk-" + "a" * 30, "HTTPS_PROXY": "http://p"}
        env = gitrun.git_env(src)
        self.assertEqual((env["HOME"], env["CODEX_HOME"], env["PATH"], env["HTTPS_PROXY"]), ("/h/me", "/h/codex", "/usr/bin", "http://p"))
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual((env["GIT_CONFIG_NOSYSTEM"], env["GIT_ATTR_NOSYSTEM"], env["GIT_TERMINAL_PROMPT"]), ("1", "1", "0"))
        for k in ("GIT_DIR", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_COUNT", "GIT_SSL_NO_VERIFY", "XDG_CONFIG_HOME", "OPENROUTER_KEY"):
            self.assertNotIn(k, env)

    def test_argv_hardening_and_no_shell(self):
        argv = gitrun.git_argv("/g", ["fetch"])
        joined = " ".join(argv)
        for want in ("core.hooksPath=/dev/null", "protocol.allow=never", "protocol.https.allow=always",
                     "transfer.fsckObjects=true", "credential.helper=", "fetch.recurseSubmodules=false"):
            self.assertIn(want, joined)
        self.assertNotIn("protocol.file.allow", joined)
        self.assertIn("protocol.file.allow=always", " ".join(gitrun.git_argv("/g", ["fetch"], local_fixture=True)))
        with mock.patch("subprocess.Popen", wraps=__import__("subprocess").Popen) as p:
            gitrun.run([sys.executable, "-c", "print(1)"], env=gitrun.git_env(), timeout=20, max_stdout=100)
        self.assertIs(p.call_args.kwargs["shell"], False)
        self.assertIsInstance(p.call_args.args[0], list)

    def test_run_bounds_time_and_output(self):
        env = gitrun.git_env()
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            gitrun.run([sys.executable, "-c", "import time; time.sleep(30)"], env=env, timeout=0.5, max_stdout=100)
        self.assertEqual(c.exception.code, "timeout")
        self.assertLess(time.monotonic() - t, 10)
        with self.assertRaises(RepoImportError) as c:
            gitrun.run([sys.executable, "-c", "import sys; sys.stdout.write('x'*100000); sys.stdout.flush(); import time; time.sleep(30)"],
                       env=env, timeout=20, max_stdout=1000)
        self.assertEqual(c.exception.code, "too-large")
        r = gitrun.run([sys.executable, "-c", "import sys; sys.stderr.write('e'*100000)"], env=env, timeout=20, max_stdout=10, max_stderr=500)
        self.assertEqual(len(r.stderr), 500)

    def test_run_watch_can_abort(self):
        def watch():
            raise RepoImportError("too-large", "watch")
        with self.assertRaises(RepoImportError):
            gitrun.run([sys.executable, "-c", "import time; time.sleep(30)"], env=gitrun.git_env(), timeout=20, max_stdout=10, watch=watch)
