"""SCORE-HOST-04 independent re-gate of the HOST-03 corrections H1/H2 plus the HOST-02 survivor guards
(campaign call budget, pre-first-send hold recheck, fresh replay id). Offline; invented data; fake capture transport."""
import json
import unittest

from tests.score_host_review.common import CFG, EVR, EVR2, KEY, S, Env
from reviewer.gateway.trace import bytes_digest
from reviewer.runtime import Secret
from reviewer.score_config import parse_score_config

NAMES = lambda t: [b["response_format"]["json_schema"]["name"] for b in t.bodies]  # noqa: E731


class Trip:
    """Any touch fails the test: replay must not read auth/book/ledger/key/transport."""
    def __getattr__(self, n):
        raise AssertionError(f"replay touched {n}")

    def __call__(self, *a, **k):
        raise AssertionError("replay called a tripwire")


class SubCT(S.CaptureTransport):
    pass


class SubCall(S.CaptureTransport):
    def __call__(self, req):
        raise AssertionError("must never be reached")


class Extra(S.CaptureTransport):
    pass


class H1(Env):
    def refused(self, reason, **kw):
        with self.assertRaises(S.ScoreHostError) as c:
            h = self.host(**kw)
            self.assertFalse(self.store.exists())
            h.execute_offline()
        self.assertEqual(c.exception.reason, reason)
        self.assertFalse((self.store / "scorer.lock").exists())                      # refused BEFORE the lock
        self.assertFalse(self.ledger_path.exists() and self.intents())               # no intent/state change
        self.assertFalse(self.store.exists() and list(self.store.glob("*.trace.jsonl")))

    def test_exact_capture_transport_and_placeholder_key_pass(self):
        self.assertTrue(self.host().execute_offline()["complete"])
        self.setUp()
        self.assertTrue(self.host(transport=S.CaptureTransport(None)).execute_offline()["complete"])

    def test_every_non_exact_transport_is_refused_before_lock_and_state(self):
        sent = []
        ex = S.CaptureTransport()
        ex.sneaky = 1
        for name, t in (("function", lambda req: sent.append(req)), ("subclass", SubCT()), ("subclass-call", SubCall()), ("extra-attr", ex),
                        ("object", object()), ("class-itself", S.CaptureTransport)):
            with self.subTest(name):
                self.setUp()
                self.refused("offline-needs-capture-transport", transport=t)
        self.setUp()
        h = self.host()
        h.transport = None
        with self.assertRaises(S.ScoreHostError) as c:
            h.execute_offline()
        self.assertEqual(c.exception.reason, "offline-needs-capture-transport")
        self.assertFalse((self.store / "scorer.lock").exists())
        self.assertEqual(sent, [])

    def test_non_placeholder_or_wrong_type_key_refused(self):
        import reviewer.score_host as M
        for name, k in (("other-secret", Secret("sk-or-v1-" + "r34l" * 12)), ("off-by-one", Secret(M.PLACEHOLDER_KEY[:-1] + "x")),
                        ("plain-str", M.PLACEHOLDER_KEY), ("none", None)):
            with self.subTest(name):
                self.setUp()
                h = self.host()
                h.key = k
                with self.assertRaises(S.ScoreHostError) as c:
                    h.execute_offline()
                self.assertEqual(c.exception.reason, "offline-needs-placeholder-key")
                self.assertEqual((self.transport.bodies, self.intents()), ([], []))
                self.assertFalse((self.store / "scorer.lock").exists())


class H2Replay(Env):
    def recorded(self):
        h = self.host()
        h.execute_offline()
        return h, self.store / f"{h.run_id}.trace.jsonl"

    def test_static_pin_drifts_refuse_before_trace_read(self):
        h, trace = self.recorded()
        missing = self.tmp / "nope.jsonl"
        import reviewer.score_host as M
        for name, bl in (("declared", dict(declared=[("https://example.invalid/case/7", "zeta-tool")])),):
            hh = self.host(**bl)
            with self.assertRaises(S.ScoreHostError) as c:
                hh.replay(missing, "sha256:" + "0" * 64, EVR2)
            self.assertEqual(c.exception.reason, "declared-set-drift")
        cfg2 = parse_score_config(CFG_TEXT.replace("max_calls_per_score_run = 2002", "max_calls_per_score_run = 2001"))   # tighter is allowed, so only the digest pin drifts
        hh = self.host(cfg=cfg2)
        hh.baseline = h.baseline                                                       # launch baseline from the original run, config now drifted
        with self.assertRaises(S.ScoreHostError) as c:
            hh.replay(missing, "sha256:" + "0" * 64, EVR2)
        self.assertEqual(c.exception.reason, "config-or-prompt-drift")
        hh = self.host()
        hh.units = hh.units + hh.units[:1]
        with self.assertRaises(S.ScoreHostError) as c:
            hh.replay(missing, "sha256:" + "0" * 64, EVR2)
        self.assertEqual(c.exception.reason, "duplicate-unit")
        hh = self.host()
        hh.units = ()
        with self.assertRaises(S.ScoreHostError) as c:
            hh.replay(missing, "sha256:" + "0" * 64, EVR2)
        self.assertEqual(c.exception.reason, "no-declared-units")

    def test_replay_touches_no_auth_book_ledger_key_or_transport(self):
        h, trace = self.recorded()
        docs = json.loads((self.store / f"{h.run_id}.documents.json").read_text())
        pin = bytes_digest(trace.read_bytes())
        before = (self.ledger_path.read_bytes(), self.book_path.read_bytes(), len(self.transport.bodies))
        h.auth = h.book = h.ledger = h.key = h.transport = Trip()
        rep = h.replay(trace, pin, EVR2)
        self.assertEqual(rep["liveCalls"], 0)
        self.assertTrue(rep["complete"])
        self.assertIsNone(rep["scoringLedger"])                                         # no ledger tally in replay
        norm = lambda ds: [{k: v for k, v in json.loads(json.dumps(d)).items() if k != "judge"} for d in ds]  # noqa: E731
        self.assertEqual(norm(rep["documents"]), norm(docs))
        self.assertEqual(before[:2], (self.ledger_path.read_bytes(), self.book_path.read_bytes()))

    def test_fresh_id_checked_before_any_trace_read(self):
        h, trace = self.recorded()
        with self.assertRaises(S.ScoreHostError) as c:
            h.replay(self.tmp / "nope.jsonl", "sha256:" + "0" * 64, EVR)
        self.assertEqual(c.exception.reason, "replay-needs-fresh-run-id")
        with self.assertRaises(S.ScoreHostError) as c:
            h.replay(self.tmp / "nope.jsonl", "sha256:" + "0" * 64, EVR2)
        self.assertEqual(c.exception.reason, "replay-trace-refused")


from tests.score_host_review.common import ROOT  # noqa: E402
CFG_TEXT = (ROOT / "pullo-score.toml").read_text()


class SurvivorGuards(Env):
    def with_calls(self, n):
        return parse_score_config(CFG_TEXT.replace("max_calls_per_score_run = 2002", f"max_calls_per_score_run = {n}"))

    def test_whole_campaign_call_budget_counts_extraction_dedup_and_pairs(self):
        cfg = self.with_calls(16)                                                       # 2 extract + 2 dedup + 12 pairs exactly
        r = self.host(cfg=cfg).execute_offline()
        self.assertTrue(r["complete"], r["fitRefusal"])
        self.assertEqual(NAMES(self.transport).count("ScorePair"), 12)
        self.setUp()
        r = self.host(cfg=self.with_calls(15)).execute_offline()                        # one call short: per-unit fine, whole sum not
        self.assertEqual((r["fitRefusal"], r["admission"]["reason"], r["complete"]), ("call-budget", "does-not-fit", False))
        self.assertNotIn("ScorePair", NAMES(self.transport))
        self.assertEqual({u["status"] for u in r["attemptSet"]["units"] if u["phase"] == "pair"}, {"unsent"})

    def test_startup_hold_appearing_after_pins_stops_before_first_send(self):
        import sys
        h = self.host()
        callers = []

        def hold():                                                   # a hold that appears only for the host's own pre-first-send recheck
            who = sys._getframe(1).f_code.co_name
            callers.append(who)
            return {"reason": "orphan"} if who == "execute_offline" else None
        h.ledger.scoring_startup_hold = hold
        with self.assertRaises(S.ScoreHostError) as c:
            h.execute_offline()
        self.assertEqual(c.exception.reason, "scoring-startup-hold")
        self.assertIn("_check_pins", callers)
        self.assertEqual((self.transport.bodies, self.intents()), ([], []))


if __name__ == "__main__":
    unittest.main()
