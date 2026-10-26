import contextlib
import io
import json
import os

from reviewer.repoimport import cli

from .helpers import Tmp


class Cli(Tmp):
    def run_cli(self, *argv, remote=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(list(argv), _remote=remote)
        return rc, (json.loads(out.getvalue()) if out.getvalue() else None)

    def test_fetch_capture_verify_roundtrip(self):
        w, sha = self.fixture({"a.txt": "x\n", "b/c.txt": "y\n"})
        r = self.remote(w)
        rc, doc = self.run_cli("fetch", "--repo", "https://github.com/fix/repo", "--commit", sha, "--store", str(self.store), remote=r)
        self.assertEqual((rc, doc["status"], doc["coverage"]["fullRepositoryCoverage"]), (0, "imported", True))
        pins = str(self.tmp / "pins.json")
        rc, doc2 = self.run_cli("capture-pins", "--repo", "https://github.com/fix/repo", "--commit", sha, "--store", str(self.store),
                                "--out", pins, "--captured-at", "2026-10-25T22:00:00Z", remote=r)
        self.assertEqual((rc, doc2["snapshotId"]), (0, doc["snapshotId"]))
        rc, doc3 = self.run_cli("verify", "--repo", "https://github.com/fix/repo", "--commit", sha, "--store", str(self.store),
                                "--pins", pins, remote=r)
        self.assertEqual((rc, doc3["status"]), (0, "verified"))
        (self.store / "fix--repo" / sha / "tree").chmod(0o755)
        (self.store / "fix--repo" / sha / "tree" / "zzz").write_text("x")
        rc, doc4 = self.run_cli("verify", "--repo", "https://github.com/fix/repo", "--commit", sha, "--store", str(self.store),
                                "--pins", pins, remote=r)
        self.assertEqual((rc, doc4["code"]), (1, "tamper"))

    def test_refusals_are_json_with_exit_1_and_usage_is_2(self):
        rc, doc = self.run_cli("fetch", "--repo", "http://github.com/o/r", "--commit", "a" * 40, "--store", str(self.store))
        self.assertEqual((rc, doc["code"]), (1, "bad-url"))
        rc, doc = self.run_cli("fetch", "--repo", "https://github.com/o/r", "--commit", "main", "--store", str(self.store))
        self.assertEqual((rc, doc["code"]), (1, "bad-commit"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["fetch"]), 2)
            self.assertEqual(cli.main(["nonsense"]), 2)

    def test_policy_flags_reach_the_importer(self):
        w, sha = self.fixture({f"f{i}": "x\n" for i in range(4)})
        rc, doc = self.run_cli("fetch", "--repo", "https://github.com/fix/repo", "--commit", sha, "--store", str(self.store),
                               "--max-files", "2", remote=self.remote(w))
        self.assertEqual((rc, doc["code"]), (1, "too-large"))

    def test_default_store_expands_home(self):
        self.assertTrue(os.path.expanduser(cli.DEFAULT_STORE).startswith(os.path.expanduser("~")))
