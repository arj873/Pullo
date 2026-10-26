import json
import os
import stat
import subprocess
from pathlib import Path
from unittest import mock

from reviewer.contracts import require
from reviewer.contracts.snapshot import build_manifest, read_verified
from reviewer.repoimport import ImportPolicy, RepoImportError, coverage_of, import_repository, verify_import
from reviewer.repoimport import discard

from .helpers import ENV, Tmp, git

FILES = {"README.md": "# hi\n", "src/a.py": "print(1)\n", "src/run.sh": ("x", "#!/bin/sh\necho\n"), "empty": ""}


class Basic(Tmp):
    def test_clean_repo_is_full_coverage_and_exact(self):
        w, sha = self.fixture(FILES, links={"src/link": "a.py"})
        imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual(imp.dir, self.store / "fix--repo" / sha)
        self.assertEqual(imp.record["coverage"], {"scope": "full-repository", "fullRepositoryCoverage": True})
        self.assertEqual(imp.coverage["scope"], "full-repository")
        self.assertEqual(imp.record["omissions"]["items"], [])
        self.assertEqual(imp.record["counts"]["symlinks"], 1)
        m = imp.manifest
        require("SnapshotManifest", m)
        self.assertEqual(m["gitCommit"], sha)
        self.assertEqual({e["path"]: e["type"] for e in m["entries"]},
                         {"README.md": "file", "empty": "file", "src/a.py": "file", "src/run.sh": "executable", "src/link": "symlink"})
        self.assertEqual(build_manifest(imp.root)["snapshotId"], imp.snapshot_id)
        self.assertEqual(read_verified(imp.root, m, "src/a.py"), b"print(1)\n")
        self.assertEqual(os.readlink(Path(imp.root) / "src/link"), "a.py")
        self.assertEqual(git(w, "rev-parse", "HEAD^{tree}"), imp.record["treeOid"])
        self.assertEqual(verify_import(imp.dir), [])
        self.assertEqual(sorted(os.listdir(imp.dir)), sorted(["tree", "manifest.json", "import-record.json", "git-entries.json",
                                                              "commit-object", "line-anchors.json"]))
        self.assertEqual(stat.S_IMODE(os.stat(imp.dir).st_mode), 0o555)
        self.assertEqual(sorted(os.listdir(imp.dir.parent)), [sha])           # staging and bare store are gone

    def test_deterministic_manifest_and_record_across_stores(self):
        w, sha = self.fixture(FILES, links={"l": "x"})
        a = import_repository(self.remote(w), sha, self.tmp / "s1")
        b = import_repository(self.remote(w), sha, self.tmp / "s2")
        self.assertEqual(a.manifest, b.manifest)
        for n in ("manifest.json", "import-record.json", "git-entries.json", "line-anchors.json", "commit-object"):
            self.assertEqual((a.dir / n).read_bytes(), (b.dir / n).read_bytes(), n)

    def test_refuses_existing_target_and_cleans_up_on_failure(self):
        w, sha = self.fixture(FILES)
        import_repository(self.remote(w), sha, self.store)
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store)
        self.assertEqual(c.exception.code, "store-exists")
        other = "1" * 40
        with self.assertRaises(RepoImportError):
            import_repository(self.remote(w), other, self.store)
        self.assertEqual(sorted(os.listdir(self.store / "fix--repo")), [sha])

    def test_missing_sha_never_falls_back_to_a_branch(self):
        w, sha = self.fixture(FILES)
        for missing in ("0" * 40, "a" * 40):
            with self.assertRaises(RepoImportError) as c:
                import_repository(self.remote(w), missing, self.store)
            self.assertIn(c.exception.code, ("unreproducible", "fetch-failed"))
        self.assertFalse((self.store / "fix--repo" / ("0" * 40)).exists())
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), "main", self.store)
        self.assertEqual(c.exception.code, "bad-commit")

    def test_store_inside_a_git_worktree_is_refused(self):
        w, sha = self.fixture(FILES)
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, w / "inside")
        self.assertEqual(c.exception.code, "bad-store")

    def test_snapshot_input_and_views(self):
        w, sha = self.fixture(FILES)
        imp = import_repository(self.remote(w), sha, self.store)
        si = imp.snapshot
        self.assertEqual((si.root, si.manifest), (imp.root, imp.manifest))
        from reviewer.repoimport import full_view_of
        v = full_view_of(imp, imp)
        self.assertTrue(v.coverage()["fullRepositoryCoverage"])

    def test_discard_removes_only_an_import_dir(self):
        w, sha = self.fixture(FILES)
        imp = import_repository(self.remote(w), sha, self.store)
        with self.assertRaises(RepoImportError):
            discard(self.tmp)
        discard(imp.dir)
        self.assertFalse(imp.dir.exists())


class Omissions(Tmp):
    def test_every_omission_kind_is_recorded_honestly(self):
        lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 123\n"
        files = {"ok.txt": "fine\n", "bin.dat": b"\x00\x01\x02", "latin1.txt": b"caf\xe9\n", "big.txt": "x" * 3000,
                 "model.bin": lfs, "A.txt": "upper\n", "a.txt": "lower\n", "é.txt": "nfd\n", "é.txt": "nfc\n",
                 ".gitmodules": '[submodule "m"]\n\tpath = m\n\turl = https://example.invalid/m\n',
                 ".gitattributes": "* filter=evil\n*.bin filter=lfs diff=lfs merge=lfs -text\n"}
        sub = {}

        def extra(w):
            git(w, "update-index", "--add", "--cacheinfo", "160000,%s,vendor/m" % ("c" * 40))
        w, sha = self.fixture(files, extra=extra)
        imp = import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(max_file_bytes=2000))
        counts = imp.record["omissions"]["counts"]
        self.assertEqual(counts, {"submodule": 1, "lfs": 1, "binary": 2, "oversize": 1, "colliding": 4})
        kinds = {i["path"]: i["kind"] for i in imp.record["omissions"]["items"]}
        self.assertEqual(kinds["vendor/m"], "submodule")
        self.assertEqual(kinds["bin.dat"], "binary")
        self.assertEqual(kinds["latin1.txt"], "binary")
        self.assertEqual(kinds["big.txt"], "oversize")
        self.assertEqual(kinds["model.bin"], "lfs")
        self.assertEqual({kinds[k] for k in ("A.txt", "a.txt", "é.txt", "é.txt")}, {"colliding"})
        paths = {e["path"] for e in imp.manifest["entries"]}
        self.assertEqual(paths, {"ok.txt", ".gitmodules", ".gitattributes"})
        self.assertEqual(imp.record["coverage"], {"scope": "repository-with-omissions", "fullRepositoryCoverage": False})
        self.assertEqual(coverage_of(imp.record)["scope"], "repository-with-omissions")
        self.assertEqual(imp.record["counts"]["omitted"], 9)
        self.assertFalse((Path(imp.root) / "vendor").exists())
        self.assertEqual(verify_import(imp.dir), [])

    def test_symlinks_are_recorded_not_followed(self):
        secret = self.tmp / "outside.txt"
        secret.write_text("TOPSECRET\n")
        w, sha = self.fixture({"a": "x\n"}, links={"abs": str(secret), "up": "../../outside.txt", "dir": "/etc"})
        imp = import_repository(self.remote(w), sha, self.store)
        ent = {e["path"]: e for e in imp.manifest["entries"]}
        self.assertEqual({k: ent[k]["type"] for k in ("abs", "up", "dir")}, {"abs": "symlink", "up": "symlink", "dir": "symlink"})
        self.assertEqual(ent["abs"]["size"], len(str(secret).encode()))
        self.assertNotIn(b"TOPSECRET", b"".join(p.read_bytes() for p in Path(imp.root).rglob("*") if p.is_file() and not p.is_symlink()))
        with self.assertRaises(Exception):
            read_verified(imp.root, imp.manifest, "abs")
        self.assertEqual(verify_import(imp.dir), [])

    def test_executable_and_text_bytes_are_exact(self):
        data = b"line1\r\nline2\r\n\xef\xbb\xbfbom\n\ttab  \nno newline"
        w, sha = self.fixture({"crlf.txt": data, "x.sh": ("x", b"#!/bin/sh\n")})
        imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual((Path(imp.root) / "crlf.txt").read_bytes(), data)
        self.assertEqual(stat.S_IMODE(os.stat(Path(imp.root) / "x.sh").st_mode), 0o555)


class Caps(Tmp):
    def test_aggregate_caps_refuse_with_too_large_and_leave_nothing(self):
        w, sha = self.fixture({f"f{i}.txt": "x\n" * 50 for i in range(8)})
        for pol in (ImportPolicy(max_files=5), ImportPolicy(max_total_bytes=300), ImportPolicy(max_tree_entries=4),
                    ImportPolicy(max_pack_bytes=100)):
            with self.subTest(pol=pol), self.assertRaises(RepoImportError) as c:
                import_repository(self.remote(w), sha, self.store, policy=pol)
            self.assertEqual(c.exception.code, "too-large")
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])

    def test_depth_cap_omits_the_directory_as_unsafe(self):
        w, sha = self.fixture({"a/b/c/d/e.txt": "deep\n", "top.txt": "t\n"})
        imp = import_repository(self.remote(w), sha, self.store, policy=ImportPolicy(max_depth=2))
        self.assertEqual([(i["path"], i["kind"], i["reason"]) for i in imp.record["omissions"]["items"]],
                         [("a/b/c", "unsafe", "depth")])
        self.assertEqual({e["path"] for e in imp.manifest["entries"]}, {"top.txt"})
        self.assertEqual(verify_import(imp.dir), [])

    def test_truncated_source_pack_is_a_typed_failure_without_residue(self):
        w, sha = self.fixture({"f.txt": "x" * 5000})
        git(w, "gc", "-q", "--aggressive")
        pack = next((w / ".git/objects/pack").glob("*.pack"))
        pack.chmod(0o644)
        pack.write_bytes(pack.read_bytes()[:-60])
        with self.assertRaises(RepoImportError) as c:
            import_repository(self.remote(w), sha, self.store)
        self.assertIn(c.exception.code, ("fetch-failed", "git-failed", "unreproducible"))
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])
