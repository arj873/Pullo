import os
import stat
import subprocess
from pathlib import Path
from unittest import mock

from reviewer.repoimport import ImportPolicy, RepoImportError, gitrun, import_repository, verify_import
from reviewer.repoimport.materialize import materialize

from .helpers import ENV, Tmp, git


class Hostile(Tmp):
    def raw_tree(self, w, entries) -> str:
        body = b"".join(m.encode() + b" " + n + b"\0" + bytes.fromhex(o) for m, n, o in entries)
        return subprocess.run(["git", "hash-object", "-t", "tree", "-w", "--literally", "--stdin"], cwd=w,
                              env={**ENV, "HOME": str(w)}, input=body, capture_output=True, check=True).stdout.decode().strip()

    def hostile_repo(self):
        w = self.tmp / "evil"
        w.mkdir()
        git(w, "init", "-q")
        good, cfg = self.blob(w, b"ok\n"), self.blob(w, b"[core]\n\thooksPath=/tmp/x\n")
        gitdir = self.raw_tree(w, [("100644", b"config", cfg)])
        inner = self.raw_tree(w, [("100644", b"leaf.txt", good)])
        link = self.blob(w, b"../../../../etc/passwd")
        badlink = self.blob(w, b"\xff\xfe")
        entries = [("100644", b"ok.txt", good), ("100644", b"..", good), ("100644", b".", good), ("40000", b".git", gitdir),
                   ("100644", b".GIT", good), ("100644", b".git ", good), ("100644", b"a\\b", good),
                   ("100644", b"ctl\x01x", good), ("100644", b"\xff\xfebad", good), ("100644", b"git~1", good),
                   ("100644", b".g\xe2\x80\x8cit", good), ("40000", b"nested", inner), ("120000", b"lnk", link),
                   ("120000", b"badlink", badlink), ("100664", b"oddmode", good), ("100644", b"n" * 300, good)]
        return w, entries

    def test_fetch_refuses_hostile_trees_via_fsck(self):
        w, entries = self.hostile_repo()
        commit = self.raw_commit(w, entries[:4])         # '..', '.', '.git' in the root tree
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), commit, self.store)
        self.assertEqual(c.exception.code, "fetch-failed")
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])

    def test_materializer_omits_unsafe_names_and_writes_nothing_outside(self):
        w, entries = self.hostile_repo()
        commit = self.raw_commit(w, entries)
        tree = git(w, "rev-parse", commit + "^{tree}")
        before = sorted(str(p) for p in self.tmp.rglob("*"))
        out = self.tmp / "outdir"
        out.mkdir()
        with gitrun.ObjectReader(w / ".git", env=gitrun.git_env(), timeout=30) as rd:
            res = materialize(rd, tree, out / "tree", ImportPolicy())
        written = sorted(p.relative_to(out / "tree").as_posix() for p in (out / "tree").rglob("*"))
        self.assertEqual(written, ["lnk", "nested", "nested/leaf.txt", "ok.txt"])
        kinds = {l.pb: (l.kind, l.reason) for l in res["leaves"] if l.kind}
        self.assertEqual(kinds[b".."], ("unsafe", "dot-segment"))
        self.assertEqual(kinds[b"."], ("unsafe", "dot-segment"))
        self.assertEqual(kinds[b".git"], ("unsafe", "dot-git"))
        self.assertEqual(kinds[b".GIT"][1], "dot-git")
        self.assertEqual(kinds[b".git "][1], "dot-git")
        self.assertEqual(kinds[b"git~1"][1], "dot-git")
        self.assertEqual(kinds[b".g\xe2\x80\x8cit"][1], "dot-git")
        self.assertEqual(kinds[b"a\\b"][0], "unsafe")
        self.assertEqual(kinds[b"ctl\x01x"][0], "unsafe")
        self.assertEqual(kinds[b"\xff\xfebad"], ("unsafe", "non-utf8"))
        self.assertEqual(kinds[b"badlink"], ("unsafe", "symlink-target"))
        self.assertEqual(kinds[b"oddmode"][0], "unsupported")
        self.assertEqual(kinds[b"n" * 300], ("unsafe", "name-too-long"))
        self.assertEqual(os.readlink(out / "tree" / "lnk"), "../../../../etc/passwd")
        after = sorted(str(p) for p in self.tmp.rglob("*"))
        self.assertEqual([p for p in after if p not in before and "/outdir" not in p], [])

    def test_malformed_and_duplicate_trees_refuse_the_import(self):
        w = self.tmp / "m"
        w.mkdir()
        git(w, "init", "-q")
        good = self.blob(w, b"ok\n")
        for entries in ([("100644", b"a", good), ("100644", b"a", good)], [("100644", b"x/y", good)]):
            tree = self.raw_tree(w, entries)
            with self.subTest(entries=entries), gitrun.ObjectReader(w / ".git", env=gitrun.git_env(), timeout=30) as rd:
                with self.assertRaises(RepoImportError) as c:
                    materialize(rd, tree, self.tmp / f"o{len(entries)}{entries[0][1].decode()}" , ImportPolicy())
                self.assertEqual(c.exception.code, "malformed-object")

    def test_missing_blob_is_incomplete_store(self):
        w = self.tmp / "inc"
        w.mkdir()
        git(w, "init", "-q")
        tree = self.raw_tree(w, [("100644", b"gone", "e" * 40)])
        with gitrun.ObjectReader(w / ".git", env=gitrun.git_env(), timeout=30) as rd:
            with self.assertRaises(RepoImportError) as c:
                materialize(rd, tree, self.tmp / "o", ImportPolicy())
        self.assertEqual(c.exception.code, "incomplete-store")

    def test_corrupt_object_fails_identity(self):
        w, sha = self.fixture({"f.txt": "hello\n"})
        loose = w / ".git" / "objects" / git(w, "rev-parse", "HEAD:f.txt")[:2]
        tree = git(w, "rev-parse", "HEAD^{tree}")
        import zlib
        blob = git(w, "rev-parse", "HEAD:f.txt")
        path = w / ".git" / "objects" / blob[:2] / blob[2:]
        path.chmod(0o644)
        path.write_bytes(zlib.compress(b"blob 6\0HELLO\n"))      # right size, wrong content for its name
        with gitrun.ObjectReader(w / ".git", env=gitrun.git_env(), timeout=30) as rd:
            with self.assertRaises(RepoImportError) as c:
                materialize(rd, tree, self.tmp / "o2", ImportPolicy())
        self.assertIn(c.exception.code, ("identity-mismatch", "git-failed", "malformed-object"))


class NoExecution(Tmp):
    def decoy(self, name, *, rewrite=None):
        home = self.tmp / name
        home.mkdir()
        for s in ("pack", "clean", "fsm", "cred", "hook"):
            f = home / f"{s}.sh"
            body = f'#!/bin/sh\ntouch "{home}/CANARY-{s}"\n'
            if s == "pack":
                body += 'exec "$@"\n'
            if s == "fsm":
                body += 'printf "\\0"\n'
            f.write_text(body)
            f.chmod(0o755)
        (home / "hooks").mkdir()
        (home / "hooks" / "post-checkout").write_text(f'#!/bin/sh\ntouch "{home}/CANARY-hooksdir"\n')
        (home / "hooks" / "post-checkout").chmod(0o755)
        cfg = (f'[core]\n\thooksPath = {home}/hooks\n\tfsmonitor = {home}/fsm.sh\n[uploadpack]\n\tpackObjectsHook = {home}/pack.sh\n'
               f'[filter "evil"]\n\tclean = {home}/clean.sh\n\tsmudge = {home}/clean.sh\n\trequired = true\n'
               f'[credential]\n\thelper = !{home}/cred.sh\n')
        if rewrite:
            cfg += f'[url "file:///nonexistent/"]\n\tinsteadOf = {rewrite}\n'
        (home / ".gitconfig").write_text(cfg)
        return home

    def test_decoy_config_filters_hooks_and_helpers_never_run(self):
        w, sha = self.fixture({"a.txt": "x\n", ".gitattributes": "* filter=evil\n", "hooks/post-checkout": ("x", "#!/bin/sh\nexit 1\n"),
                               ".gitmodules": '[submodule "s"]\n\tpath = s\n\turl = file:///nonexistent\n'})
        # control: the decoy really fires when Git is NOT isolated
        ctl = self.decoy("ctl")
        c = self.tmp / "ctlrepo"
        c.mkdir()
        subprocess.run(["git", "init", "-q", "--bare", str(c)], env={"PATH": os.environ["PATH"], "HOME": str(ctl)}, check=True)
        subprocess.run(["git", "--git-dir", str(c), "-c", "protocol.file.allow=always", "fetch", "-q", "--depth=1", "file://" + str(w), sha],
                       env={"PATH": os.environ["PATH"], "HOME": str(ctl)}, check=True, capture_output=True)
        self.assertTrue((ctl / "CANARY-pack").exists(), "decoy control must be able to fire")
        # isolated import with HOME pointing at the decoy
        home = self.decoy("evilhome", rewrite="file://" + str(w))
        with mock.patch.dict(os.environ, {"HOME": str(home), "CODEX_HOME": str(home / "codex")}):
            imp = import_repository(self.remote(w), sha, self.store)
            self.assertEqual((os.environ["HOME"], os.environ["CODEX_HOME"]), (str(home), str(home / "codex")))
        self.assertEqual(sorted(p.name for p in home.iterdir() if p.name.startswith("CANARY")), [])
        self.assertEqual(sorted(e["path"] for e in imp.manifest["entries"]), [".gitattributes", ".gitmodules", "a.txt", "hooks/post-checkout"])
        self.assertEqual((Path(imp.root) / "a.txt").read_bytes(), b"x\n")
        self.assertEqual(stat.S_IMODE(os.stat(Path(imp.root) / "hooks/post-checkout").st_mode), 0o555)
        self.assertFalse((Path(imp.root) / ".git").exists())
        self.assertEqual(verify_import(imp.dir), [])

    def test_bare_store_has_no_template_hooks(self):
        seen = {}
        orig = gitrun.run

        def spy(argv, **kw):
            r = orig(argv, **kw)
            if "init" in argv:
                g = Path(argv[-1])
                seen["hooks"] = sorted(p.name for p in (g / "hooks").glob("*")) if (g / "hooks").exists() else []
            return r
        w, sha = self.fixture({"a": "x\n"})
        with mock.patch.object(gitrun, "run", spy):
            import_repository(self.remote(w), sha, self.store)
        self.assertEqual(seen["hooks"], [])
