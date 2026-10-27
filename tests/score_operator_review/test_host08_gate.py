"""SCORE-HOST-08 independent regressions (fake files/keys/state only). Real CLI bootstrap in a subprocess; plan and reconcile only
(never live/canary in a subprocess: that would load the real HttpsTransport)."""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

from tests.score_host_operator.test_operator import EVR, NOW, SENT, Fixture

ROOT = Path(__file__).resolve().parents[2]
BOOT = "import sys; sys.path.insert(0, %r); from reviewer.score_host_cli import main; sys.exit(main())" % str(ROOT)


def run_cli(*args, cwd):
    return subprocess.run([sys.executable, "-I", "-B", "-c", BOOT, *args], cwd=cwd, env={}, capture_output=True, text=True, timeout=60)


class Cli(Fixture):
    def test_documented_module_form_cannot_import_from_uninstalled_cwd_but_pinned_bootstrap_plans(self):
        p = subprocess.run([sys.executable, "-I", "-B", "-m", "reviewer.score_host_cli", "plan"], cwd=self.tmp, env={}, capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)                                   # honest limit: -I -m needs an installed package
        base = self.write_baseline()
        p = run_cli("plan", "--config", str(self.config), "--baseline", str(base), "--store", str(self.tmp / "out"), cwd=self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        rep = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertTrue(rep["synthetic"] and rep["plan"] and not rep["realScoring"] and rep["complete"])
        self.assertNotIn(SENT, p.stdout + p.stderr)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_cli_errors_are_fixed_json_with_no_path_or_content(self):
        base = self.write_baseline(declared=[["https://x.invalid/9", "t"]])
        p = run_cli("plan", "--config", str(self.config), "--baseline", str(base), "--store", str(self.tmp / "out"), cwd=self.tmp)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(set(json.loads(p.stdout)), {"ok", "reason"})
        self.assertNotIn(str(self.tmp), p.stdout + p.stderr)

    def test_reconcile_in_another_process_is_blocked_by_the_canonical_lock_and_leaves_state(self):
        base = self.write_baseline()
        self.state.mkdir(exist_ok=True)
        fd = os.open(self.state / "scorer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            before = sorted(p.name for p in self.state.iterdir())
            p = run_cli("reconcile", "--baseline", str(base), "--evidence", str(self.tmp / "none.json"), cwd=self.tmp)
        finally:
            os.close(fd)
        self.assertEqual((p.returncode, json.loads(p.stdout)["reason"]), (2, "scorer-lock-held"))
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), before)

    def test_live_in_same_process_with_distinct_store_is_blocked_by_the_same_lock(self):
        base = self.write_baseline()
        fd = os.open(self.state / "scorer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            rc, rep, _ = self.live(base=base, store="other-store")
        finally:
            os.close(fd)
        self.assertEqual((rc, rep["reason"]), (2, "scorer-lock-held"))


class CanaryTime(Fixture):
    def _with_canary_times(self, observed, expires):
        base = self.write_baseline()                                   # default writes valid evidence; then re-bind it with new times
        doc = json.loads(base.read_text())
        ev_path = self.tmp / "evidence" / "canary.json"
        ev = json.loads(ev_path.read_text())
        ev.update(observedAt=observed, expiresAt=expires)
        ev_path.unlink()
        sha = self.evidence("canary.json", ev)
        doc["canaryProof"].update(sha256=sha, observedAt=observed, expiresAt=expires)
        base.unlink()
        base.write_text(json.dumps(doc))
        os.chmod(base, 0o600)
        return base

    def test_future_dated_canary_receipt_refused(self):                     # also kills the observedAt<=now mutant
        base = self._with_canary_times("2026-10-27T17:00:00Z", "2026-10-28T17:00:00Z")      # NOW is 16:00
        rc, rep, _ = self.live(base=base)
        self.assertEqual(rc, 2, rep)

    def test_red_canary_receipt_ttl_beyond_24h_is_admitted(self):
        # root policy: canary receipt TTL at most 24h. observed 15:30Z, expires 30 days later, evidence and proof agree.
        base = self._with_canary_times("2026-10-27T15:30:00Z", "2026-11-26T15:30:00Z")
        rc, rep, _ = self.live(base=base)
        self.assertEqual(rc, 2, "baseline admitted a canary receipt valid for 30 days (policy: <=24h)")
