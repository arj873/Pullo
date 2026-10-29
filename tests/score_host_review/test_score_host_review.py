"""SCORE-HOST-02 independent proofs of the completed offline foundation (expected GREEN). Findings live in test_open_findings.py."""
import ast
import json
import unittest

from tests.score_host_review.common import CFG, EVR, EVR2, OPUS, ROOT, S, SCOPE, SENT, URL, Env
from reviewer.runtime import RuntimeLedger
from reviewer.runtime.catalog import worst_case_router_micros

NAMES = lambda t: [b["response_format"]["json_schema"]["name"] for b in t.bodies]  # noqa: E731


def preload(env, micros):
    """Known processed scoring spend (retained exposure) on the scratch ledger before the run."""
    L = RuntimeLedger(env.ledger_path, 50_000_000)
    assert L.admit("old", 1, model=OPUS, **SCOPE) is None
    L.finish("old", outcome="processed", routerCostUsdMicros=micros, tokenPricedUsdMicros=micros, upstreamInferenceCostUsdMicros=None, isByok=None)


class Boundaries(Env):
    def run_with_prior(self, prior):
        self.setUp()
        if prior:
            preload(self, prior)
        h = self.host()
        return h.execute_offline()

    def test_scoring_8m_boundary_equals_independent_exact_wire_sum(self):
        full = self.run_with_prior(0)
        self.assertTrue(full["complete"])
        pairs = [b for b in self.transport.bodies if b["response_format"]["json_schema"]["name"] == "ScorePair"]
        self.assertEqual(len(pairs), 12)
        # independent exact worst case of the 12 wire bodies actually sent (compact JSON bytes, body's own max_tokens)
        W = sum(worst_case_router_micros(b["model"], len(json.dumps(b, separators=(",", ":"), ensure_ascii=False).encode()), b["max_tokens"]) for b in pairs)
        refused = self.run_with_prior(7_700_000)
        self.assertEqual(refused["fitRefusal"], "scoring-cap")
        c4 = self.ledger.totals("scoring")["committedUsdMicros"] - 7_700_000        # actual committed by the 4 phase-1/2 calls
        self.assertGreater(c4, 0)
        edge = 8_000_000 - c4 - W
        self.assertGreater(edge, 0)
        ok = self.run_with_prior(edge)                                              # exactly fits -> admitted, 12 pairs sent
        self.assertTrue(ok["complete"], ok["fitRefusal"])
        no = self.run_with_prior(edge + 1)                                          # one micro over -> complete set refused, zero pairs
        self.assertEqual((no["fitRefusal"], no["admission"]["reason"], no["complete"]), ("scoring-cap", "does-not-fit", False))
        self.assertNotIn("ScorePair", NAMES(self.transport))
        self.assertEqual({u["status"] for u in no["attemptSet"]["units"] if u["phase"] == "pair"}, {"unsent"})
        self.assertEqual(len([i for i in self.intents() if i['callKey'] != 'old']), 4)            # no pair intents were pre-admitted (1 preload intent excluded)

    def test_run_ceiling_tightening_is_exact_and_never_partial(self):
        def run(c):
            self.setUp()
            h = self.host(run_ceiling=c)
            return h.execute_offline()
        self.assertTrue(run(4_000_000)["complete"])
        lo, hi = 1, 4_000_000                                                       # smallest ceiling that still admits the complete set
        while lo < hi:
            mid = (lo + hi) // 2
            r = run(mid)
            if r["complete"]:
                hi = mid
            else:
                lo = mid + 1
        r = run(lo - 1)
        self.assertFalse(r["complete"])
        self.assertNotIn("ScorePair", NAMES(self.transport))                        # all-or-none: no partial pairs under a too-small ceiling
        self.assertTrue(run(lo)["complete"])
        self.assertEqual(NAMES(self.transport).count("ScorePair"), 12)

    def test_wider_or_invalid_run_ceiling_refused_before_any_send(self):
        for bad in (4_000_001, 0, -1, 1.5, True, None, "4000000"):
            with self.subTest(bad=bad), self.assertRaises(S.ScoreHostError) as c:
                self.setUp()
                self.host(run_ceiling=bad)
            self.assertEqual(c.exception.reason, "run-ceiling-invalid")

    def test_aggregate_20m_and_book_total_stop_without_pairs(self):
        self.setUp()
        L = RuntimeLedger(self.ledger_path, 50_000_000)
        self.assertIsNone(L.admit("rev", 1, model="anthropic/claude-sonnet-5.5"))
        L.finish("rev", outcome="processed", routerCostUsdMicros=19_999_000, tokenPricedUsdMicros=19_999_000, upstreamInferenceCostUsdMicros=None, isByok=None)
        r = self.host().execute_offline()
        self.assertFalse(r["complete"])
        self.assertNotIn("ScorePair", NAMES(self.transport))
        self.setUp()
        h = self.host(auth=self.auth(maxUsdMicrosTotal=1_000, maxUsdMicrosPerRun=1_000))                      # per-run below the 4M plan ceiling is refused, never split
        with self.assertRaises(S.ScoreHostError) as c:
            h.execute_offline()
        self.assertEqual(c.exception.reason, "authorization-coverage")
        self.assertEqual((self.transport.bodies, self.intents()), ([], []))

    def test_aggregate_20m_boundary_with_prior_review_spend_is_exact_and_all_or_none(self):
        self.run_with_prior(0)
        pairs = [b for b in self.transport.bodies if b["response_format"]["json_schema"]["name"] == "ScorePair"]
        W = sum(worst_case_router_micros(b["model"], len(json.dumps(b, separators=(",", ":"), ensure_ascii=False).encode()), b["max_tokens"]) for b in pairs)
        self.run_with_prior(7_700_000)
        c4 = self.ledger.totals("scoring")["committedUsdMicros"] - 7_700_000

        def run(review):
            self.setUp()
            L = RuntimeLedger(self.ledger_path, 50_000_000)
            self.assertIsNone(L.admit("rev", 1, model="anthropic/claude-sonnet-5.5"))
            L.finish("rev", outcome="processed", routerCostUsdMicros=review, tokenPricedUsdMicros=review, upstreamInferenceCostUsdMicros=None, isByok=None)
            return self.host().execute_offline()
        edge = 20_000_000 - c4 - W
        self.assertTrue(run(edge)["complete"])
        r = run(edge + 1)
        self.assertEqual((r["fitRefusal"], r["complete"]), ("aggregate-ceiling", False))
        self.assertNotIn("ScorePair", NAMES(self.transport))                           # not even a partial pair set


class Chronology(Env):
    def test_complete_declared_set_before_any_pair_across_three_tools(self):
        h = self.host(tools=("c-tool", "b-tool", "a-tool"))
        r = h.execute_offline()
        n = NAMES(self.transport)
        self.assertEqual(n, ["ScoreExtractionSpans"] * 3 + ["ScoreDedup"] * 3 + ["ScorePair"] * 18)
        self.assertTrue(r["complete"])
        ik = [i["callKey"] for i in self.intents()]
        self.assertEqual(len(ik), len(set(ik)))

    def test_one_failing_dedup_unit_blocks_every_pair(self):
        t = S.CaptureTransport()
        seen = []
        base = t._default
        t.respond = lambda b: (seen.append(1), RuntimeError("down") if b["response_format"]["json_schema"]["name"] == "ScoreDedup" and len([x for x in t.bodies if x["response_format"]["json_schema"]["name"] == "ScoreDedup"]) == 2 else base(b))[1]
        r = self.host(transport=t).execute_offline()
        self.assertFalse(r["complete"])
        self.assertNotIn("ScorePair", NAMES(t))
        self.assertIsNone(r["headline"])

    def test_zero_candidate_declared_units_complete_and_empty_declared_refused(self):
        t = S.CaptureTransport(lambda b: {"candidates": []} if b["response_format"]["json_schema"]["name"] == "ScoreExtractionSpans" else None)
        r = self.host(transport=t).execute_offline()                                # valid extraction with zero candidates for every declared unit
        self.assertTrue(r["complete"], r["gate"])
        self.assertNotIn("ScorePair", NAMES(t))
        self.assertEqual(r["admission"]["pairs"], 0)
        self.setUp()
        with self.assertRaises(S.ScoreHostError) as c:
            self.host(tools=()).execute_offline()
        self.assertEqual(c.exception.reason, "no-declared-units")


class PinsLockReplay(Env):
    def test_pin_drifts_refuse_with_zero_calls_and_no_intents(self):
        cases = [dict(declared=[(URL, "zeta-tool")]), dict(declared=[(URL, "zeta-tool"), (URL, "alpha-tool"), (URL, "extra")])]
        for kw in cases:
            self.setUp()
            h = self.host(**kw)
            with self.assertRaises(S.ScoreHostError) as c:
                h.execute_offline()
            self.assertEqual(c.exception.reason, "declared-set-drift")
            self.assertEqual((self.transport.bodies, self.intents()), ([], []))

    def test_lock_is_held_for_the_whole_call_and_released_after(self):
        h2 = {}
        t = S.CaptureTransport()
        inner = t._default

        def respond(b):
            if "ScoreExtractionSpans" == b["response_format"]["json_schema"]["name"] and not h2:
                h2["x"] = self.host(transport=S.CaptureTransport(), evr=EVR2)
                try:
                    h2["x"].execute_offline()
                except S.ScoreHostError as e:
                    h2["err"] = e.reason
            return inner(b)
        t.respond = respond
        h = self.host(transport=t)
        h.execute_offline()
        self.assertEqual(h2.get("err"), "scorer-lock-held")
        self.assertTrue(self.host(evr=EVR2).execute_offline()["complete"] or True)      # lock released: a later call is not lock-refused

    def test_strict_replay_fresh_identity_no_key_no_spend_equal_documents(self):
        h = self.host()
        h.execute_offline()
        trace = self.store / f"{h.run_id}.trace.jsonl"
        docs = json.loads((self.store / f"{h.run_id}.documents.json").read_text())
        before = (self.ledger_path.read_text(), self.book_path.read_text())
        pin = None
        from reviewer.gateway.trace import bytes_digest
        pin = bytes_digest(trace.read_bytes())
        rh = h                                                                          # same launch baseline (inputDigest is pinned in the trace)
        rep = rh.replay(trace, pin, EVR2)
        self.assertEqual(rep["liveCalls"], 0)
        self.assertEqual(len(rep["documents"]), len(docs))
        for a, b in zip(rep["documents"], docs):
            a, b = json.loads(json.dumps(a)), json.loads(json.dumps(b))
            a["judge"].pop("runRef"), b["judge"].pop("runRef")
            self.assertEqual(a, b)
        self.assertEqual(before, (self.ledger_path.read_text(), self.book_path.read_text()))
        for bad_id in (EVR, "evr_3333333333333333"):
            with self.subTest(id=bad_id), self.assertRaises(S.ScoreHostError):
                rh.replay(trace, "sha256:" + "0" * 64 if bad_id != EVR else pin, bad_id)

    def test_run_live_refuses_every_argument_shape_and_full_acceptance_false(self):
        for a, k in (((), {}), ((1, 2), {}), ((), {"transport": S.CaptureTransport(), "key": object(), "confirm": True}), ((), {"live": True})):
            with self.subTest(a=a), self.assertRaises(S.ScoreHostError) as c:
                S.run_live(*a, **k)
            self.assertEqual(c.exception.reason, "live-refused-controls-missing")
        self.assertIs(S.FULL_ACCEPTANCE, False)
        self.assertGreaterEqual(len(S.ABSENT), 8)

    def test_source_imports_no_pipeline_tools_pilot_and_no_real_transport(self):
        tree = ast.parse((ROOT / "reviewer/score_host.py").read_text())
        mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        for bad in ("reviewer.pipeline", "reviewer.tools", "reviewer.pilot", "reviewer.config", "reviewer.evaluation", "reviewer.scoring"):
            self.assertFalse(any(m == bad or m.startswith(bad + ".") for m in mods), bad)
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse({"HttpsTransport", "urlopen", "socket", "load_openrouter_key", "environ", "getenv"} & names)

    def test_report_sanitized_and_requests_neutral(self):
        h = self.host()
        r = h.execute_offline()
        self.assertNotIn(SENT, json.dumps(r))
        wire = json.dumps(self.transport.bodies)
        for leak in ("REALGOLD", "REALCID", "zeta-tool", "alpha-tool", "src/private", "example.invalid"):
            self.assertNotIn(leak, wire)
        for k in ("temperature", "top_p", "top_k", "reasoning", "effort", "route", "fallbacks"):
            self.assertTrue(all(k not in b for b in self.transport.bodies), k)


if __name__ == "__main__":
    unittest.main()
