"""S1-03 independent review: Git isolation (with positive decoy controls), what is actually sent to Git, hostile
transports, pack/time/output bounds with killed process groups, DAG/redaction CPU bounds, failure cleanup.

Conventions: `test_CONTROL_*` pass and pin intended behaviour; `test_LIMIT_*` pin a documented limit.
Run: nice -n 19 python3 -W error::ResourceWarning -m unittest discover -s tests/repoimport_review -v
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _support import Base, CLEAN, GIT, ShimMixin, alive, g  # noqa: E402

from reviewer.repoimport import ImportPolicy, Remote, RepoImportError, github_remote, import_repository  # noqa: E402
from reviewer.repoimport import fsio  # noqa: E402

SECRETS = {"OPENROUTER_API_KEY": "sk-or-v1-" + "a" * 40, "ANTHROPIC_API_KEY": "sk-ant-" + "b" * 40,
           "OPENAI_API_KEY": "sk-" + "c" * 40, "GITHUB_TOKEN": "ghp_" + "d" * 36, "openrouter_key": "e" * 30}
GIT_STATE = {"GIT_DIR": "/nonexistent/gd", "GIT_WORK_TREE": "/nonexistent/wt", "GIT_OBJECT_DIRECTORY": "/nonexistent/o",
             "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/nonexistent/alt", "GIT_INDEX_FILE": "/nonexistent/i",
             "GIT_EXEC_PATH": "/nonexistent/exec", "GIT_SSH_COMMAND": "false", "GIT_PROXY_COMMAND": "false",
             "GIT_EXTERNAL_DIFF": "false", "GIT_PAGER": "false", "PAGER": "false", "GIT_TRACE": "/nonexistent/t",
             "GIT_TRACE2_EVENT": "/nonexistent/t2", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath",
             "GIT_CONFIG_VALUE_0": "/nonexistent/hooks", "GIT_CONFIG_PARAMETERS": "'core.hooksPath'='/nonexistent'",
             "GIT_NAMESPACE": "x", "GIT_REPLACE_REF_BASE": "refs/x/", "GIT_CONFIG_SYSTEM": "/nonexistent/sys",
             "GIT_ASKPASS": "/nonexistent/askpass", "GIT_CURL_VERBOSE": "1", "XDG_CONFIG_HOME": "/nonexistent/xdg",
             "GIT_SSL_NO_VERIFY": "1", "GIT_SSL_CAINFO": "/nonexistent/ca", "GIT_CEILING_DIRECTORIES": "/",
             "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1", "GIT_AUTHOR_NAME": "leak"}
ALLOWED_NON_GIT = {"PATH", "HOME", "CODEX_HOME", "LANG", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY",
                   "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "LC_ALL", "SSH_ASKPASS",
                   "LC_CTYPE", "PYTHONCOERCECLOCALE"}      # last two: possible interpreter artefacts of the shim


class WhatReachesGit(Base, ShimMixin):
    def test_CONTROL_every_git_call_is_isolated_and_requests_exactly_the_pinned_sha(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim()
        home = self.tmp / "home"
        home.mkdir()
        env = {**SECRETS, **GIT_STATE, "HOME": str(home), "CODEX_HOME": str(home / "codex-sentinel")}
        with mock.patch.dict(os.environ, env):
            imp = import_repository(self.remote(w), sha, self.store)
        self.assert_matches_git(imp, w, sha)
        calls = self.shim_calls()
        self.assertEqual({c["verb"] for c in calls} - {"--version"}, {"init", "fetch", "cat-file"})
        for c in calls:
            e, a = c["env"], c["argv"]
            stray = {k for k in e if k not in ALLOWED_NON_GIT and not (k.startswith("GIT_") and k in
                     {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_ATTR_NOSYSTEM", "GIT_TERMINAL_PROMPT", "GIT_ASKPASS",
                      "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS", "GIT_LFS_SKIP_SMUDGE"})}
            self.assertEqual(stray, set(), f"{c['verb']}: unexpected env keys")
            for k in list(SECRETS) + [k for k in GIT_STATE if k not in ("GIT_ASKPASS",)]:
                self.assertNotIn(k, e)
            self.assertEqual(e["HOME"], str(home))                                  # HOME / CODEX_HOME preserved
            self.assertEqual(e["CODEX_HOME"], str(home / "codex-sentinel"))
            self.assertEqual((e["GIT_CONFIG_GLOBAL"], e["GIT_CONFIG_NOSYSTEM"], e["GIT_TERMINAL_PROMPT"]), ("/dev/null", "1", "0"))
            self.assertEqual(e["GIT_ASKPASS"], "/bin/false")
            for banned in ("checkout", "clone", "ls-remote", "switch", "worktree", "submodule", "archive", "pull", "merge",
                           "branch", "reset", "restore", "lfs", "gc"):
                self.assertNotIn(banned, a)
            if c["verb"] in ("fetch", "cat-file"):
                opts = [a[i + 1] for i, x in enumerate(a) if x == "-c"]
                for want in ("core.hooksPath=/dev/null", "protocol.allow=never", "credential.helper=", "core.fsmonitor=false",
                             "transfer.fsckObjects=true", "fetch.recurseSubmodules=false"):
                    self.assertIn(want, opts)
        fetch = [c for c in calls if c["verb"] == "fetch"]
        self.assertEqual(len(fetch), 1)                                              # one fetch, no retries/fallbacks
        a = fetch[0]["argv"]
        self.assertEqual(a[-3], "--")
        self.assertEqual(a[-1], sha)                                                 # the bare sha is the only refspec
        self.assertEqual(sum(sha in x for x in a), 1)
        self.assertNotIn("HEAD", a)
        self.assertFalse(any(x.startswith(("refs/", "+", "main")) for x in a[a.index("fetch"):]))
        self.assertIn("--depth=1", a)
        self.assertIn("--no-tags", a)

    def test_CONTROL_invalid_pins_never_reach_git(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim()
        r = self.remote(w)
        for bad in ("main", "HEAD", "refs/heads/main", sha[:7], sha[:39], sha.upper(), sha + "0", " " + sha, sha + "\n",
                    "", None, 123, "origin/main", sha[:-1] + "g"):
            with self.subTest(bad=bad), self.assertRaises(RepoImportError) as c:
                import_repository(r, bad, self.store)
            self.assertEqual(c.exception.code, "bad-commit")
        self.assertEqual(self.shim_calls(), [])
        self.assertFalse(self.store.exists())

    def test_CONTROL_url_validation_bypass_is_still_blocked_by_protocol_allow_never(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        canary = self.tmp / "EXT-CANARY"
        for url in (f"ext::sh -c 'touch {canary}'", "file://" + str(w), str(w), f"fd::{canary}"):
            with self.subTest(url=url), self.assertRaises(RepoImportError) as c:
                import_repository(Remote(url, "o", "r"), sha, self.store)         # kind='github': no local-fixture opt-in
            self.assertIn(c.exception.code, ("fetch-failed", "unreproducible"))
            self.assertFalse(canary.exists())
        self.assertEqual(sorted(os.listdir(self.store / "o--r")), [])

    def test_CONTROL_github_url_table(self):
        ok = {"https://github.com/boykopovar/AnyPS5": "https://github.com/boykopovar/AnyPS5",
              "https://github.com/boykopovar/AnyPS5.git": "https://github.com/boykopovar/AnyPS5",
              "https://github.com/boykopovar/AnyPS5/": "https://github.com/boykopovar/AnyPS5"}
        for u, canon in ok.items():
            with self.subTest(u=u):
                r = github_remote(u)
                self.assertEqual((r.url, r.kind, r.repo), (canon, "github", "boykopovar/AnyPS5"))
        for u in ("http://github.com/o/r", "https://github.com.evil.example/o/r", "https://evil.example/github.com/o/r",
                  "https://user:pw@github.com/o/r", "https://github.com:443/o/r", "https://GITHUB.com/o/r",
                  "https://github.com/o/r/extra", "https://github.com/o/r?x=1", "https://github.com/o/r#f",
                  "https://github.com/o/../r", "https://github.com/o/%2e%2e", "https://github.com/-o/r",
                  "https://github.com/o/-r", "https://github.com/o/r.git.git", "https://github.com//r",
                  "https://github.com/o/r with space", "https://github.com/o\\r", "https://gıthub.com/o/r",
                  "ssh://git@github.com/o/r", "git@github.com:o/r.git", "https://github.com/o/r\n", "https://github.com/o/.."):
            with self.subTest(u=u), self.assertRaises(RepoImportError) as c:
                github_remote(u)
            self.assertEqual(c.exception.code, "bad-url")


class DecoyControls(Base):
    """Independent decoys: a vector is only credited when an UNISOLATED fetch demonstrably triggers it."""

    def write_hook(self, name):
        canary = self.tmp / f"canary-{name}"
        hook = self.tmp / f"hook-{name}.sh"
        hook.write_text(f'#!/bin/sh\necho fired >> "{canary}"\nexec "$@"\n')
        hook.chmod(0o755)
        return hook, canary

    def vectors(self, src: Path):
        out = {}
        hook, canary = self.write_hook("xdg")
        h = self.tmp / "h-xdg"
        (h / ".config/git").mkdir(parents=True)
        (h / ".config/git/config").write_text(f"[uploadpack]\n\tpackObjectsHook = {hook}\n")
        out["xdg-config"] = ({"HOME": str(h)}, canary, False)

        hook, canary = self.write_hook("include")
        h = self.tmp / "h-inc"
        h.mkdir()
        (h / "inc.cfg").write_text(f"[uploadpack]\n\tpackObjectsHook = {hook}\n")
        (h / ".gitconfig").write_text("[include]\n\tpath = inc.cfg\n")
        out["gitconfig-include"] = ({"HOME": str(h)}, canary, False)

        out["_placeholder"] = None
        decoy = self.tmp / "decoy-remote"
        decoy.mkdir()
        g(decoy, "init", "-q")
        h = self.tmp / "h-rewrite"
        h.mkdir()
        (h / ".gitconfig").write_text(f'[url "file://{decoy}"]\n\tinsteadOf = file://{src}\n')
        out["url.insteadOf-redirect"] = ({"HOME": str(h)}, None, True)
        h2 = self.tmp / "h-env"
        h2.mkdir()
        rewrite = (f"url.file://{decoy}.insteadOf", f"file://{src}")      # env vars are not forwarded to a local upload-pack,
        out["GIT_CONFIG_COUNT-redirect"] = ({"HOME": str(h2), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": rewrite[0],
                                             "GIT_CONFIG_VALUE_0": rewrite[1]}, None, True)   # so use a client-side effect
        out["GIT_CONFIG_PARAMETERS-redirect"] = ({"HOME": str(h2), "GIT_CONFIG_PARAMETERS": f"'{rewrite[0].lower()}'='{rewrite[1]}'"},
                                                 None, True)
        out.pop("_placeholder")
        return out

    def test_CONTROL_decoys_fire_when_unisolated_and_never_under_the_importer(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        url = "file://" + str(w)
        for name, (env, canary, redirect) in self.vectors(w).items():
            with self.subTest(vector=name):
                # positive control: plain git with the same HOME/env DOES honour the decoy
                bare = self.tmp / f"ctl-{name}"
                subprocess.run([GIT, "init", "-q", "--bare", str(bare)], env={**CLEAN, "HOME": env["HOME"]}, check=True)
                unisolated = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", **env}
                r = subprocess.run([GIT, "--git-dir", str(bare), "-c", "protocol.file.allow=always", "fetch", "-q", "--depth=1",
                                    "--no-tags", "--", url, sha], env=unisolated, capture_output=True)
                if redirect:
                    self.assertNotEqual(r.returncode, 0, "the insteadOf decoy did not redirect the unisolated fetch")
                else:
                    self.assertTrue(canary.exists(), f"decoy {name} never fired unisolated: {r.stderr[-300:]!r}")
                    canary.unlink()
                # under the importer, with the very same environment
                with mock.patch.dict(os.environ, env):
                    imp = import_repository(self.remote(w), sha, self.tmp / f"store-{name}")
                self.assertEqual(imp.record["commitSha"], sha)
                self.assertEqual((Path(imp.root) / "a.txt").read_bytes(), b"a\n")
                if canary is not None:
                    self.assertFalse(canary.exists(), f"decoy {name} fired under the importer")


class Bounds(Base, ShimMixin):
    def residue(self):
        root = self.store / "fix--repo"
        return sorted(os.listdir(root)) if root.exists() else []

    def test_CONTROL_hung_fetch_times_out_kills_the_process_group_and_leaves_nothing(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim("hang-fetch")
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(fetch_timeout_s=1))
        self.assertEqual(c.exception.code, "timeout")
        self.assertLess(time.monotonic() - t, 8)
        pids = self.shim_pids()
        self.assertEqual(len(pids), 2)
        time.sleep(0.3)
        self.assertEqual([p for p in pids if alive(p)], [], "a process (incl. the grandchild) survived the timeout")
        self.assertEqual(self.residue(), [])

    def test_CONTROL_stdout_flood_is_cut_off(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim("flood-stdout")
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(fetch_timeout_s=60))
        self.assertEqual(c.exception.code, "too-large")
        self.assertLess(time.monotonic() - t, 10)
        time.sleep(0.3)
        self.assertEqual([p for p in self.shim_pids() if alive(p)], [])
        self.assertEqual(self.residue(), [])

    def test_CONTROL_stderr_flood_is_bounded_and_the_message_is_short(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim("flood-stderr")
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store)
        self.assertEqual(c.exception.code, "fetch-failed")
        self.assertLess(len(str(c.exception)), 700)
        self.assertLess(time.monotonic() - t, 20)
        self.assertEqual(self.residue(), [])

    def test_CONTROL_pack_growth_is_cut_off_while_the_fetch_is_still_running(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim("grow")
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(max_pack_bytes=1 << 20, fetch_timeout_s=60))
        self.assertEqual(c.exception.code, "too-large")
        self.assertLess(time.monotonic() - t, 10)
        time.sleep(0.3)
        self.assertEqual([p for p in self.shim_pids() if alive(p)], [])
        self.assertEqual(self.residue(), [])

    def test_CONTROL_hung_object_reader_times_out(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        self.install_shim("hang-catfile")
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(read_timeout_s=1))
        self.assertEqual(c.exception.code, "timeout")
        self.assertLess(time.monotonic() - t, 10)
        time.sleep(0.3)
        self.assertEqual([p for p in self.shim_pids() if alive(p)], [])
        self.assertEqual(self.residue(), [])

    def test_CONTROL_shared_subtree_dag_bomb_is_refused_quickly(self):
        w, _ = self.repo([{"seed": "x\n"}])
        leaf = self.raw_tree(w, [("100644", b"f", self.blob(w, b"leaf\n"))])
        cur = leaf
        for _ in range(18):                         # 2**18 = 262,144 leaves from 19 tree objects
            cur = self.raw_tree(w, [("40000", b"a", cur), ("40000", b"b", cur)])
        sha = g(w, "commit-tree", cur, "-m", "bomb")
        t = time.monotonic()
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store)
        self.assertEqual(c.exception.code, "too-large")
        self.assertLess(time.monotonic() - t, 60)
        self.assertEqual(self.residue(), [])

    def test_CONTROL_adversarial_megabyte_files_do_not_stall_the_redaction_probe(self):
        M = 1 << 20
        hostile = {
            "key-no-end.txt": "-----BEGIN PRIVATE KEY-----\n" * (M // 28),
            "begin-spam.txt": "-----BEGIN " * (M // 11),
            "password-spam.txt": 'password="' * (M // 10),
            "scheme-spam.txt": "a://" * (M // 4),
            "ghp-spam.txt": "ghp_" * (M // 4),
            "bearer-spaces.txt": "bearer" + " " * (M - 6),
        }
        w, (sha,) = self.repo([{k: v[:M] for k, v in hostile.items()}])
        t = time.monotonic()
        imp = import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(max_file_bytes=M))
        took = time.monotonic() - t
        self.assertLess(took, 30, f"importing 6 adversarial 1 MiB files took {took:.1f}s")
        self.assertEqual(imp.record["omissions"]["counts"].get("redaction", 0) + imp.record["counts"]["included"], 6)


class Cleanup(Base):
    def test_CONTROL_interrupt_mid_materialization_leaves_nothing_and_publishes_late(self):
        w, (sha,) = self.repo([{"a.txt": "a\n", "d/b.txt": "b\n"}])
        remote = self.remote(w)
        final = self.store / "fix--repo" / sha
        seen = {}
        from reviewer.repoimport import importer as imod
        real = imod.materialize

        def interrupt(*a, **k):
            seen["final_exists_mid_run"] = os.path.lexists(final)
            real(*a, **k)                                                     # tree fully written and sealed (0555 dirs)
            raise KeyboardInterrupt

        with mock.patch.object(imod, "materialize", interrupt), self.assertRaises(KeyboardInterrupt):
            import_repository(remote, sha, self.store)
        self.assertFalse(seen["final_exists_mid_run"])
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])           # sealed read-only staging was removed
        imp = import_repository(remote, sha, self.store)                      # and a retry is not blocked
        self.assertEqual(imp.dir, final)

    def test_CONTROL_stale_staging_residue_neither_blocks_nor_is_mistaken_for_an_import(self):
        w, (sha,) = self.repo([{"a.txt": "a\n"}])
        stale = self.store / "fix--repo" / ".staging-1-deadbeef"
        (stale / "tree").mkdir(parents=True)
        (stale / "import-record.json").write_text("{}")
        imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual(sorted(os.listdir(self.store / "fix--repo")), sorted([".staging-1-deadbeef", sha]))
        self.assertTrue(stale.exists())
        self.assertEqual(stat.S_IMODE(os.stat(imp.dir).st_mode), 0o555)


if __name__ == "__main__":
    unittest.main()
