"""HOLD-ACK-01 S3: `score_host_cli acknowledge` runs the append-only acknowledge tool on the baseline's ORIGINAL ledger under
the canonical shared scorer lock; preview by default. FAKE baseline/auth/state only; no network, key or provider."""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import shutil

from reviewer import score_host_cli as C
from reviewer.runtime import RuntimeLedger
from tests.score_host_operator.test_operator import NOW, Fixture

OPUS = "anthropic/claude-opus-5.5"
S = dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=20_000_000)
EV = {"reasonCode": "generation-not-found", "keyRemainingBeforeMicros": 48_000_000,
      "keyRemainingAfterMicros": 47_900_000, "sumOtherOfficialMicros": 100_000}


class AcknowledgeCmd(Fixture):
    def setUp(self):
        super().setUp()
        self.ledger = self.state / "runtime-ledger.jsonl"
        lg = RuntimeLedger(self.ledger, 50_000_000)
        lg.admit("cf", 121_032, model=OPUS, **S)
        lg.finish("cf", outcome="processed", httpStatus=200, generationId="gen-cf", finishReason="content_filter")
        self.ev = self.tmp / "op" / "ack.json"
        self.ev.write_text(json.dumps({"generationId": "gen-cf", "callKey": "cf", "evidence": EV}))

    def sha(self):
        return hashlib.sha256(self.ledger.read_bytes()).hexdigest()

    def run_cmd(self, *extra):
        out = io.StringIO()
        rc = C.main(["acknowledge", "--baseline", str(self.write_baseline()), "--evidence", str(self.ev), *extra],
                    out=out, now=NOW)
        return rc, json.loads(out.getvalue())

    def test_preview_default_then_apply_on_the_baseline_ledger(self):
        before = self.sha()
        rc, rep = self.run_cmd()
        self.assertEqual((rc, rep["ok"], rep["applied"], rep["holdAfter"]), (0, True, False, None))
        self.assertEqual(self.sha(), before)
        lg = RuntimeLedger(self.ledger, 50_000_000)
        self.assertIsNotNone(lg.scoring_startup_hold())
        totals = lg.totals()
        rc, rep = self.run_cmd("--apply")
        self.assertEqual((rc, rep["applied"]), (0, True))
        self.assertEqual(json.loads(self.ledger.read_text().splitlines()[-1])["type"], "acknowledge")
        self.assertIsNone(lg.scoring_startup_hold())
        self.assertEqual(lg.totals(), totals)

    def test_refusal_writes_nothing(self):
        self.ev.write_text(json.dumps({"generationId": "gen-cf", "evidence": {**EV, "reasonCode": "usage-zero"}}))
        before = self.sha()
        rc, rep = self.run_cmd("--apply")
        self.assertEqual((rc, rep["ok"]), (1, False))
        self.assertEqual(self.sha(), before)

    def test_blocked_by_the_canonical_lock_without_touching_state(self):
        fd = os.open(self.state / "scorer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = {p.name: p.read_bytes() for p in self.state.iterdir()}
        try:
            rc, rep = self.run_cmd("--apply")
            self.assertEqual((rc, rep["reason"]), (2, "scorer-lock-held"))
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.state.iterdir()})
        finally:
            os.close(fd)

    def test_holds_the_lock_while_running(self):
        from reviewer.runtime import acknowledge
        seen, real = {}, acknowledge.main

        def spy(argv, out=None):
            fd = os.open(self.state / "scorer.lock", os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen["held"] = False
            except OSError:
                seen["held"] = True
            finally:
                os.close(fd)
            raise SystemExit(2)
        acknowledge.main = spy
        try:
            rc, rep = self.run_cmd()
        finally:
            acknowledge.main = real
        self.assertEqual((seen["held"], rc, rep["reason"]), (True, 2, "acknowledge-refused"))

    def test_never_creates_the_original_state_dir_or_ledger(self):
        b = self.write_baseline()
        shutil.rmtree(self.state)
        out = io.StringIO()
        rc = C.main(["acknowledge", "--baseline", str(b), "--evidence", str(self.ev), "--apply"], out=out, now=NOW)
        self.assertEqual((rc, json.loads(out.getvalue())["reason"], self.state.exists()), (2, "state-dir-missing", False))
        self.state.mkdir()
        rc = C.main(["acknowledge", "--baseline", str(b), "--evidence", str(self.ev), "--apply"], out=io.StringIO(), now=NOW)
        self.assertEqual(rc, 2)                                       # argparse refusal inside the tool: no ledger created
        self.assertFalse(self.ledger.exists())
