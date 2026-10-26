"""S1-03 independent review: exact commit/tree/blob identity (against an independent `git ls-tree` oracle), non-commit
and non-tip pins, forged-import ladder (what internal consistency can and cannot prove), pin capture/open separation,
on-disk tampering classes, hostile-but-fsck-legal names end to end, raw bytes and line anchors vs what the tools show.

Run: nice -n 19 python3 -W error::ResourceWarning -m unittest discover -s tests/repoimport_review -v
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _support import Base, g  # noqa: E402

from reviewer.contracts.canonical import canonical_json, digest  # noqa: E402
from reviewer.contracts.redaction import redact  # noqa: E402
from reviewer.contracts.schema import is_safe_relpath  # noqa: E402
from reviewer.contracts.snapshot import snapshot_id  # noqa: E402
from reviewer.pipeline.snaps import head_lines  # noqa: E402
from reviewer.repoimport import (ImportPolicy, RepoImportError, capture_import_pins, full_view_of, import_repository,  # noqa: E402
                                 load_import_pins, open_import, verify_import, write_import_pins)
from reviewer.tools import ToolSession  # noqa: E402

CAPTURED = "2026-10-25T12:00:00Z"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class Identity(Base):
    def test_CONTROL_older_non_tip_commit_imports_exactly_that_commit(self):
        w, (c1, c2, c3) = self.repo([{"v.txt": "one\n", "only1.txt": "x\n"}, {"v.txt": "two\n"}, {"v.txt": "three\n"}],
                                    configure=lambda w: g(w, "config", "uploadpack.allowAnySHA1InWant", "true"))
        imp = import_repository(self.remote(w), c1, self.store)
        self.assertEqual(imp.record["commitSha"], c1)
        self.assertEqual((Path(imp.root) / "v.txt").read_bytes(), b"one\n")          # not the branch tip
        self.assertTrue((Path(imp.root) / "only1.txt").exists())
        self.assertEqual(imp.record["parents"], [])
        self.assert_matches_git(imp, w, c1)
        imp3 = import_repository(self.remote(w), c3, self.store)
        self.assertEqual(imp3.record["parents"], [c2])                               # recorded, not fetched
        self.assertEqual((Path(imp3.root) / "v.txt").read_bytes(), b"three\n")
        self.assertNotEqual(imp.snapshot_id, imp3.snapshot_id)

    def test_CONTROL_non_commit_pins_are_refused_not_peeled(self):
        w, (c1,) = self.repo([{"a.txt": "a\n"}], configure=lambda w: g(w, "config", "uploadpack.allowAnySHA1InWant", "true"))
        g(w, "tag", "-a", "v1", "-m", "annotated", c1)
        tag_obj = g(w, "rev-parse", "v1")
        tree, blob = g(w, "rev-parse", c1 + "^{tree}"), g(w, "rev-parse", c1 + ":a.txt")
        self.assertNotEqual(tag_obj, c1)
        for what, oid in (("annotated tag object", tag_obj), ("tree", tree), ("blob", blob)):
            with self.subTest(what=what), self.assertRaises(RepoImportError) as c:
                import_repository(self.remote(w), oid, self.store)
            self.assertIn(c.exception.code, ("malformed-object", "fetch-failed", "unreproducible"))
        self.assertEqual(os.listdir(self.store / "fix--repo"), [])

    def test_CONTROL_independent_oracle_agrees_on_a_mixed_repo(self):
        lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 9\n"
        files = {"README.md": "# r\n", "src/a.py": "x=1\n", "src/b/c.txt": "c\n", "bin": b"\x00\x01", "lfs.bin": lfs,
                 "run.sh": "#!/bin/sh\n", "empty": ""}

        def extra(w):
            os.chmod(w / "run.sh", 0o755)
            g(w, "update-index", "--chmod=+x", "run.sh")
            g(w, "update-index", "--add", "--cacheinfo", "160000,%s,vendor/sub" % ("d" * 40))
        w, (sha,) = self.repo([(files, {"src/ln": "a.py"}, extra)])
        imp = import_repository(self.remote(w), sha, self.store)
        self.assert_matches_git(imp, w, sha)
        self.assertEqual(verify_import(imp.dir), [])
        om = {i["path"]: i["kind"] for i in imp.record["omissions"]["items"]}
        self.assertEqual(om, {"bin": "binary", "lfs.bin": "lfs", "vendor/sub": "submodule"})
        for e in imp.manifest["entries"]:                                              # raw bytes, hashed independently
            p = Path(imp.root) / e["path"]
            if e["type"] == "symlink":
                self.assertEqual(sha256(os.readlink(p).encode()), e["sha256"])
            else:
                self.assertEqual(sha256(p.read_bytes()), e["sha256"])
                self.assertEqual(g(w, "rev-parse", f"{sha}:{e['path']}"), g(w, "hash-object", "--", str(p)))


class Forgeries(Base):
    """What each layer of verification proves. Ladder L1-L3 must be caught WITHOUT pins; L4 needs the pins."""

    def setUp(self):
        super().setUp()
        self.w, (self.sha,) = self.repo([{"a.txt": "alpha\n", "b.txt": "beta\n", "bin": b"\x00\x00"}])
        self.imp = import_repository(self.remote(self.w), self.sha, self.store)
        self.pins = capture_import_pins(self.imp.dir, captured_at=CAPTURED)

    def forge(self, name, *, new=b"ALPHA\n", manifest=False, record=False, entries=False):
        d = self.writable_copy(self.imp.dir, name)
        (d / "tree/a.txt").write_bytes(new)
        mf, rc = json.loads((d / "manifest.json").read_bytes()), json.loads((d / "import-record.json").read_bytes())
        if manifest:
            for e in mf["entries"]:
                if e["path"] == "a.txt":
                    e["sha256"], e["size"] = sha256(new), len(new)
            mf["snapshotId"] = snapshot_id(mf["entries"])
            (d / "manifest.json").write_bytes(canonical_json(mf))
            rc["snapshotId"] = mf["snapshotId"]
        if entries:
            ge = json.loads((d / "git-entries.json").read_bytes())
            for row in ge:
                if row[2] == "a.txt":
                    row[1] = g(self.w, "hash-object", "--stdin", input=new)
            (d / "git-entries.json").write_bytes(canonical_json(ge))
            rc["gitEntries"]["sha256"] = digest(ge)
        if record or manifest or entries:
            (d / "import-record.json").write_bytes(canonical_json(rc))
        return d

    def test_CONTROL_L0_clean_import_verifies_internally_and_against_pins(self):
        self.assertEqual(verify_import(self.imp.dir), [])
        self.assertEqual(open_import(self.imp.dir, pins=self.pins).snapshot_id, self.imp.snapshot_id)

    def test_CONTROL_L1_bytes_changed_alone(self):
        bad = verify_import(self.forge("l1"))
        self.assertTrue(bad and any("differs from the manifest" in b or "tree" in b for b in bad), bad)

    def test_CONTROL_L2_bytes_and_manifest_and_snapshot_id_rewritten_consistently(self):
        bad = verify_import(self.forge("l2", manifest=True))
        self.assertTrue(any("Git blob id" in b for b in bad), bad)

    def test_CONTROL_L3_plus_git_entries_rewritten_cannot_rebuild_the_commit_tree(self):
        bad = verify_import(self.forge("l3", manifest=True, entries=True))
        self.assertTrue(any("rebuild the pinned tree id" in b for b in bad), bad)

    def test_LIMIT_L4_a_genuine_import_of_other_content_passes_internal_checks_and_only_pins_refuse_it(self):
        """A different commit imported honestly, then moved into the original slot, is internally consistent: verify without
        pins (and anything that does not compare the pins' commit/files) cannot tell. open_import with the pins must."""
        w2, (sha2,) = self.repo([{"a.txt": "ALPHA\n", "b.txt": "beta\n", "bin": b"\x00\x00"}], name="other")
        other = import_repository(self.remote(w2), sha2, self.tmp / "store2")
        self.assertNotEqual(other.record["commitSha"], self.sha)
        self.assertEqual(verify_import(other.dir), [])                                # consistent: NOT evidence of authenticity
        with self.assertRaises(RepoImportError) as c:
            open_import(other.dir, pins=self.pins)
        self.assertEqual(c.exception.code, "tamper")
        self.assertIn("commit", str(c.exception).lower() + " ".join(verify_import(other.dir, pins=self.pins)).lower())
        self.assertNotEqual(other.dir.name, self.imp.dir.name)                        # directory name is not itself checked

    def test_CONTROL_consistent_omission_forgery_is_caught_by_git_entry_accounting_without_pins(self):
        d = self.writable_copy(self.imp.dir, "omit")
        rc = json.loads((d / "import-record.json").read_bytes())
        self.assertEqual(rc["omissions"]["counts"], {"binary": 1})
        rc["omissions"] = {"counts": {}, "items": [], "sha256": digest([])}
        rc["counts"]["omitted"] = 0
        rc["coverage"] = {"scope": "full-repository", "fullRepositoryCoverage": True}
        (d / "import-record.json").write_bytes(canonical_json(rc))
        bad = verify_import(d)
        self.assertTrue(any("account for exactly the Git leaves" in b for b in bad), bad)


class Pins(Base):
    def setUp(self):
        super().setUp()
        self.w, (self.sha,) = self.repo([{"a.txt": "alpha\n", "d/b.txt": "beta\n"}])
        self.imp = import_repository(self.remote(self.w), self.sha, self.store)

    def test_CONTROL_import_verify_and_open_never_create_pins(self):
        pins = capture_import_pins(self.imp.dir, captured_at=CAPTURED)
        before = sorted(str(p) for p in self.tmp.rglob("*"))
        verify_import(self.imp.dir)
        verify_import(self.imp.dir, pins=pins)
        open_import(self.imp.dir, pins=pins)
        self.assertEqual(sorted(str(p) for p in self.tmp.rglob("*")), before)
        self.assertFalse([p for p in self.tmp.rglob("*") if "pin" in p.name.lower()])
        with self.assertRaises(RepoImportError) as c:
            open_import(self.imp.dir, pins=None)
        self.assertEqual(c.exception.code, "bad-pins")

    def test_CONTROL_pin_file_conventions_and_hostile_pin_paths(self):
        pins = capture_import_pins(self.imp.dir, captured_at=CAPTURED)
        out = self.tmp / "pins" / "p.json"
        out.parent.mkdir()
        write_import_pins(out, pins)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o444)
        first = out.read_bytes()
        with self.assertRaises(RepoImportError):
            write_import_pins(out, pins)                                           # exclusive create: no overwrite
        self.assertEqual(out.read_bytes(), first)
        victim = self.tmp / "victim.txt"
        victim.write_text("do not touch\n")
        planted = self.tmp / "pins" / "planted.json"
        os.symlink(victim, planted)
        with self.assertRaises(RepoImportError) as c:
            write_import_pins(planted, pins)                                       # a pre-planted symlink is not followed
        self.assertEqual(c.exception.code, "bad-pins")
        self.assertEqual(victim.read_text(), "do not touch\n")
        self.assertEqual(load_import_pins(out, import_dir=self.imp.dir), pins)
        alias = self.tmp / "alias.json"                                              # outside the dir, but a link INTO it
        os.symlink(self.imp.dir / "manifest.json", alias)
        for inside in (self.imp.dir / "manifest.json", alias):
            with self.subTest(inside=str(inside)), self.assertRaises(RepoImportError) as c:
                load_import_pins(inside, import_dir=self.imp.dir)
            self.assertEqual(c.exception.code, "bad-pins")
        for mutate in (lambda p: p.update(extra=1), lambda p: p.update(schema="x"), lambda p: p.update(commitSha=p["commitSha"].upper()),
                       lambda p: p["files"].pop("manifest.json"), lambda p: p.update(capturedAt="yesterday")):
            bad = json.loads(json.dumps(pins))
            mutate(bad)
            with self.assertRaises(RepoImportError) as c:
                open_import(self.imp.dir, pins=bad)
            self.assertIn(c.exception.code, ("bad-pins", "tamper"))      # LOW: malformed pins surface as 'tamper' (verify_import swallows bad-pins)
        with self.assertRaises(RepoImportError):
            capture_import_pins(self.imp.dir, captured_at="2026-10-25 12:00")

    def tamper_cases(self):
        def extra_git_hook(d):
            (d / "tree/.git/hooks").mkdir(parents=True)
            (d / "tree/.git/hooks/post-checkout").write_text("#!/bin/sh\ntouch pwned\n")

        def fifo(d):
            os.mkfifo(d / "tree/fifo")

        def exec_bit(d):
            os.chmod(d / "tree/a.txt", 0o555)

        def dir_to_symlink(d):
            os.rename(d / "tree/d", d / "tree/d.real")
            os.symlink("d.real", d / "tree/d")

        def manifest_symlink(d):
            os.rename(d / "manifest.json", d / "manifest.real")
            os.symlink("manifest.real", d / "manifest.json")

        def extra_top_file(d):
            (d / "notes.txt").write_text("hi")

        def omission_reason(d):
            rc = json.loads((d / "import-record.json").read_bytes())
            rc["policy"]["max_file_bytes"] = 1                       # a metadata edit the tree cannot reveal
            (d / "import-record.json").write_bytes(canonical_json(rc))
        return {"extra .git/hooks file": extra_git_hook, "fifo in tree": fifo, "exec bit flip": exec_bit,
                "dir replaced by symlink": dir_to_symlink, "manifest.json symlink": manifest_symlink,
                "extra top-level file": extra_top_file, "policy edit in record": omission_reason}

    def test_CONTROL_on_disk_tampering_is_refused_with_pins_and_never_hangs(self):
        pins = capture_import_pins(self.imp.dir, captured_at=CAPTURED)
        for name, fn in self.tamper_cases().items():
            with self.subTest(tamper=name):
                d = self.writable_copy(self.imp.dir, "t-" + name.replace(" ", "_").replace(".", "_").replace("/", "_"))
                fn(d)
                out = {}

                def run():
                    try:
                        out["r"] = open_import(d, pins=pins)
                    except RepoImportError as e:
                        out["e"] = e
                t = threading.Thread(target=run, daemon=True)
                t.start()
                t.join(30)
                self.assertFalse(t.is_alive(), "verification hung")
                self.assertIn("e", out, f"{name} was accepted")
                self.assertEqual(out["e"].code, "tamper")

    def test_LIMIT_an_extra_empty_directory_is_not_content_and_is_not_detected(self):
        """Characterization: empty dirs carry no content in Git or in the manifest model, so adding one is invisible."""
        pins = capture_import_pins(self.imp.dir, captured_at=CAPTURED)
        d = self.writable_copy(self.imp.dir, "emptydir")
        (d / "tree/empty-dir").mkdir()
        outcome = verify_import(d, pins=pins)
        self.assertEqual(outcome, [], "behaviour changed: an empty directory is now detected (good) - update this LIMIT")


class HostileNames(Base):
    NAMES = ["-rf", "--help", " lead", "trail ", "tab\there", "new\nline", "‮evil", "zero​width", "$(touch CANARY)",
             "`touch CANARY`", ";touch CANARY", "a b", "*", "?", "[x]", "{a,b}", "%s", "CON", "aux.txt", "é.txt", "\U0001F600.txt",
             "ctl\x01x", "back\\slash", "n" * 255, "quote'\"", "~", "#hash", "a:b", "ok.txt"]

    def test_CONTROL_fsck_legal_hostile_names_end_to_end(self):
        files = {}
        for n in self.NAMES:
            files[n] = f"content of {len(n)}\n"
        files["dir/-rf/$(touch CANARY)"] = "nested\n"
        w, (sha,) = self.repo([files])
        cwd_before = sorted(os.listdir("."))
        imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual(sorted(os.listdir(".")), cwd_before)
        self.assert_matches_git(imp, w, sha)                                          # every leaf accounted for by the oracle
        self.assertEqual(verify_import(imp.dir), [])
        tree = Path(imp.root)
        on_disk = set()
        for dp, dn, fn in os.walk(tree, followlinks=False):
            for n in dn + fn:
                self.assertFalse(os.path.islink(os.path.join(dp, n)) and n != "x", n)
            on_disk |= {os.path.relpath(os.path.join(dp, f), tree) for f in fn}
        manifest = {e["path"] for e in imp.manifest["entries"]}
        self.assertEqual(on_disk, manifest)
        self.assertTrue(all(is_safe_relpath(p) for p in manifest))
        omitted = imp.record["omissions"]["items"]                                    # unsafe names record path=None
        self.assertEqual(len(manifest) + len(omitted), len(files))
        self.assertEqual(imp.record["coverage"]["fullRepositoryCoverage"], not omitted)
        self.assertTrue(omitted and all(i["pathSha256"] for i in omitted))
        for p in manifest:
            self.assertTrue(".git" not in p.lower().split("/"))
        self.assertEqual([p for p in self.tmp.rglob("*") if p.name == "CANARY"], [])    # no name was ever executed/expanded


class AnchorsAndRaw(Base):
    SEP = "a\rb\x0bc\x0cd\x1ce\x1df\x1eg\x85h i j\nsecond\n"

    def files(self):
        canary = "RVWCANARY_" + "A" * 20
        key = "-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"
        return {"sep.txt": self.SEP, "crlf.txt": "a\r\nb\r\n", "nofinal.txt": "x\ny", "blank.txt": "\n\n\n", "empty.txt": "",
                "key.txt": "head\n" + key + "tail1\ntail2\n", "multi.txt": f"t = '{canary}'\npassword = \"hunter2hunter2\"\n" + key,
                "bom.txt": b"\xef\xbb\xbfbom\n", "lonely-cr.txt": "a\rb\rc\r"}, canary

    def test_CONTROL_anchors_equal_the_lines_the_tools_show_and_secrets_stay_out(self):
        files, canary = self.files()
        w, (sha,) = self.repo([files])
        imp = import_repository(self.remote(w), sha, self.store)
        self.assertEqual(verify_import(imp.dir), [])
        anchors = json.loads((imp.dir / "line-anchors.json").read_bytes())
        view = full_view_of(imp, imp)
        sess = ToolSession(view)
        for path, content in files.items():
            raw = content.encode() if isinstance(content, str) else content
            self.assertEqual((Path(imp.root) / path).read_bytes(), raw)               # RAW bytes stored
            text = raw.decode("utf-8")
            expect = 0 if text == "" else len(text.split("\n")) - (1 if text.endswith("\n") else 0)
            self.assertEqual(anchors.get(path), expect, path)                          # independent line count
            self.assertEqual(len(head_lines(imp.root, imp.manifest, path)), expect, path)
            if expect:
                call = sess.call("read_file", {"side": "head", "path": path, "start_line": 1, "end_line": expect})
                self.assertEqual(call.result["status"], "ok", (path, call.result["notice"]))
                red = redact(text)[0].split("\n")
                if red and red[-1] == "":
                    red.pop()
                self.assertEqual(call.result["evidence"][0]["excerpt"], "\n".join(red), path)
                self.assertEqual(call.result["evidence"][0]["lines"], [1, expect])
                self.assertNotIn(canary, json.dumps(call.result))
                self.assertNotIn("hunter2hunter2", json.dumps(call.result))
                self.assertNotIn("AAAA", json.dumps(call.result)) if path in ("key.txt", "multi.txt") else None
        self.assertEqual(imp.record["omissions"]["items"], [])


class RawBytesDownstream(Base):
    def test_CONTROL_no_tool_returns_a_raw_secret_from_an_import(self):
        """Raw bytes are stored, so every read path must redact. Sweep all four tools with probing queries."""
        from reviewer.tools import TOOLS
        canary, tok = "RVWCANARY_" + "Z" * 20, "ghp_" + "q" * 36
        key = "-----BEGIN PRIVATE KEY-----\nKEYBODYLINE\n-----END PRIVATE KEY-----\n"
        wb, (sb,) = self.repo([{"a.txt": "x\n", "s.txt": "old\n"}], name="b")
        wh, (sh,) = self.repo([{"a.txt": "x\n", "s.txt": f"old\nc={canary}\nt={tok}\n" + key + 'password = "hunter2hunter2"\n'}], name="h")
        b = import_repository(self.remote(wb), sb, self.store)
        h = import_repository(self.remote(wh), sh, self.tmp / "s2")
        sess = ToolSession(full_view_of(b, h))
        n = 0
        for tool in TOOLS:
            for args in ({"side": "head"}, {"side": "head", "path": "s.txt"}, {"side": "head", "query": "hunter2"},
                         {"side": "head", "query": "KEYBODYLINE"}, {"side": "head", "query": "ghp_"}, {"path": "s.txt"},
                         {"query": "RVWCANARY_"}, {}):
                out = json.dumps(sess.call(tool, args).result)
                n += 1
                for secret in (canary, tok, "KEYBODYLINE", "hunter2hunter2"):
                    self.assertNotIn(secret, out, (tool, args))
        self.assertEqual(n, 32)
        self.assertEqual(sess.call("read_file", {"side": "head", "path": "s.txt"}).result["status"], "ok")


if __name__ == "__main__":
    unittest.main()
