"""SCORE-HOST-09: canary = EXACTLY three role/schema probes through the real Gateway/runtime provider over a fake transport;
reconcile holds the canonical shared scorer lock. FAKE evidence/auth/state/transport only; no actual canary or reconcile."""
from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import json
import os
import stat

from reviewer import score_host as H
from reviewer import score_host_cli as C
from tests.score_host_operator.test_operator import EVR, NOW, Fixture, sha256_hex


@contextlib.contextmanager
def fixed_clock(iso=NOW):
    """Scoped deterministic clock: datetime.datetime.now() returns the fixture instant (fake catalog is valid at NOW) and is
    restored on exit. The subclass keeps every other datetime method/type intact; only now() is pinned."""
    fixed = _dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    real = _dt.datetime

    class FixedDatetime(real):
        @classmethod
        def now(cls, tz=None):
            return fixed if tz is None else fixed.astimezone(tz)
    _dt.datetime = FixedDatetime
    try:
        yield
    finally:
        _dt.datetime = real


class Canary(Fixture):
    def canary(self, respond=None):
        b = self.write_baseline(mode="canary", declared=[list(x) for x in H.CANARY_DECLARED], canaryProof=None,
                                inputs=[{"path": "cases.json", "sha256": sha256_hex((self.inp / "cases.json").read_bytes())}])
        if respond is not None:
            self.transport = lambda: (setattr(self, "cap", H.CaptureTransport(respond)) or self.cap)
        return self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=b)

    def test_exactly_three_probes_one_per_role_same_caps_and_no_sampling(self):
        rc, rep, _ = self.canary()
        self.assertEqual(rc, 0, rep)
        names = [x["response_format"]["json_schema"]["name"] for x in self.cap.bodies]
        self.assertEqual(names, ["ScoreExtractionSpans", "ScoreDedup", "ScorePair"])                    # 3 calls, never the old 4-call all-pairs loop
        self.assertEqual((rep["probeCalls"], rep["probes"], rep["canaryOk"]), ({"extractor": 1, "deduper": 1, "matcher": 1}, {"extractor": "ok", "deduper": "ok", "matcher": "ok"}, True))
        self.assertEqual((rep["realScoring"], rep["headline"]), (False, None))
        self.assertEqual({b["model"] for b in self.cap.bodies}, {"anthropic/claude-opus-5.5"})
        self.assertEqual([b["max_tokens"] for b in self.cap.bodies], [8000, 4000, 256])           # same per-role caps as the campaign
        for b in self.cap.bodies:
            for k in ("temperature", "top_p", "top_k", "reasoning", "effort", "route", "fallbacks", "tools"):
                self.assertNotIn(k, b)
        ik = [json.loads(x)["callKey"] for x in self.ledger_lines() if '"intent"' in x]
        self.assertEqual((len(ik), len(set(ik))), (3, 3))                                          # one intent per probe, no retry

    def ledger_lines(self):
        return (self.state / "runtime-ledger.jsonl").read_text().splitlines()

    def test_evidence_is_derived_from_actual_calls_and_admits_a_campaign(self):
        with fixed_clock():                                            # receipt observedAt/expiresAt come from the fixture clock, not wallclock
            rc, rep, _ = self.canary()
        ev = next((self.tmp / "out").glob("*.canary-evidence.json"))
        self.assertEqual(stat.S_IMODE(ev.stat().st_mode), 0o600)
        doc = json.loads(ev.read_text())
        self.assertEqual(doc["probes"], {"extractor": 1, "deduper": 1, "matcher": 1})
        self.assertEqual((doc["outcome"], doc["authDigest"], doc["route"]), ("ok", self.handle.digest, "anthropic/claude-opus-5.5"))
        # the derived file is exactly what the campaign baseline verifier accepts as the canary receipt
        self.setUp_campaign(doc, ev)

    def setUp_campaign(self, doc, ev):
        base = self.baseline_doc()
        shutil_target = self.tmp / "evidence" / "canary.json"
        shutil_target.write_bytes(ev.read_bytes())
        os.chmod(shutil_target, 0o600)
        base["canaryProof"].update(sha256=sha256_hex(shutil_target.read_bytes()), observedAt=doc["observedAt"], expiresAt=doc["expiresAt"])
        from reviewer.gateway import SpendBook
        from reviewer.runtime import RuntimeLedger
        led = RuntimeLedger(self.state / "runtime-ledger.jsonl", 50_000_000)
        bt = SpendBook(self.handle, self.state / "spend-book.jsonl").totals()
        base["initial"] = {"scoring": led.totals("scoring")["committedUsdMicros"], "all": led.totals()["committedUsdMicros"],
                           "bookCommitted": bt["committed"], "bookInflight": bt["inflight"]}      # the canary's actual spend is the campaign's start
        p = self.tmp / "op" / "campaign.json"
        p.write_text(json.dumps(base))
        os.chmod(p, 0o600)
        with fixed_clock():
            rc, rep, _ = self.op("live", "--confirm-live", "--eval-run-id", "evr_5555555555555555", base=p, now=NOW)
        self.assertEqual(rc, 0, rep)

    def test_failed_or_invalid_probe_stops_and_writes_no_evidence(self):
        for stage_fail, want_bodies, want in (("ScoreExtractionSpans", 1, {"extractor": "failed", "deduper": "unsent", "matcher": "unsent"}),
                                              ("ScoreDedup", 2, {"extractor": "ok", "deduper": "failed", "matcher": "unsent"}),
                                              ("ScorePair", 3, {"extractor": "ok", "deduper": "ok", "matcher": "failed"})):
            self.setUp()
            base = H.CaptureTransport._default

            def respond(body, f=stage_fail):
                n = body["response_format"]["json_schema"]["name"]
                if n == f:
                    return {"groups": [[0], [0]]} if n == "ScoreDedup" else {"candidates": "bad"} if n == "ScoreExtractionSpans" else {"match": "yes"}
                return base(body)
            rc, rep, _ = self.canary(respond)
            self.assertEqual(rc, 0, rep)
            self.assertEqual((len(self.cap.bodies), rep["probes"], rep["canaryOk"], rep["evidenceFile"]), (want_bodies, want, False, None), stage_fail)
            self.assertEqual(list((self.tmp / "out").glob("*.canary-evidence.json")), [], stage_fail)

    def test_provider_error_is_a_failed_probe_not_evidence_and_not_retried(self):
        calls = []

        def respond(body):
            calls.append(1)
            return RuntimeError("down")
        rc, rep, _ = self.canary(respond)
        self.assertEqual((len(calls), rep["canaryOk"], rep["evidenceFile"]), (1, False, None))

    def test_canary_still_refuses_unconfirmed_wrong_mode_and_other_sets(self):
        rc, rep, _ = self.op("canary", "--eval-run-id", EVR, base=self.write_baseline(mode="canary", declared=[list(x) for x in H.CANARY_DECLARED], canaryProof=None))
        self.assertEqual((rc, rep["reason"]), (2, "live-needs-confirm"))
        rc, rep, _ = self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=self.write_baseline())
        self.assertEqual((rc, rep["reason"]), (2, "mode-mismatch"))


class ReconcileLock(Fixture):
    def test_reconcile_is_blocked_by_the_canonical_lock_without_touching_state(self):
        b = self.write_baseline()
        lock = self.state / "scorer.lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = {p.name: p.read_bytes() for p in self.state.iterdir()}
        try:
            import io
            out = io.StringIO()
            rc = C.main(["reconcile", "--baseline", str(b), "--evidence", str(self.tmp / "none.json"), "--apply"], out=out, now=NOW)
            self.assertEqual((rc, json.loads(out.getvalue())["reason"]), (2, "scorer-lock-held"))
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.state.iterdir()})        # no ledger/book mutation, no new file
        finally:
            os.close(fd)

    def test_reconcile_holds_the_lock_while_running_and_releases_it(self):
        import io
        from reviewer.runtime import reconcile
        b = self.write_baseline()
        seen = {}
        real = reconcile.main

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
        reconcile.main = spy
        try:
            out = io.StringIO()
            rc = C.main(["reconcile", "--baseline", str(b), "--evidence", str(self.tmp / "none.json")], out=out, now=NOW)
        finally:
            reconcile.main = real
        self.assertEqual((seen["held"], rc), (True, 2))
        fd = os.open(self.state / "scorer.lock", os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)                                              # released after return
        os.close(fd)

    def test_reconcile_never_creates_the_original_state_dir(self):
        import io, shutil
        b = self.write_baseline()
        shutil.rmtree(self.state)
        out = io.StringIO()
        rc = C.main(["reconcile", "--baseline", str(b), "--evidence", "x"], out=out, now=NOW)
        self.assertEqual((rc, json.loads(out.getvalue())["reason"], self.state.exists()), (2, "state-dir-missing", False))
