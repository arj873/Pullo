"""SCORE-HOST-01 first offline milestone. Real score-family Gateway + real OpenRouterProvider(category=scoring) over a
fake capture transport with scratch book/ledger/fake authorization. Invented data only; no key, env, network, Git."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from reviewer.benchmark.model import Golden, RawComment, ScorerCase, ToolReview
from reviewer.contracts.budget import authorization_digest
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer import score_host as S
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS
from reviewer.score_config import load_score_config
from tests.score_gateway import helpers as H

ROOT = Path(__file__).resolve().parents[2]
CFG = load_score_config(ROOT / "pullo-score.toml")
PRICE = H.PROFILE["roles"]["extractor"]["price"]
OPUS = "anthropic/claude-opus-5.5"
SENT = "RAWSENTINEL_5d1e"
URL = "https://example.invalid/case/7"
KEY = Secret("sk-or-v1-" + "f4k3" * 12)
EVR, EVR2 = "evr_1111111111111111", "evr_2222222222222222"
SCOPE = dict(category="scoring", category_cap=8_000_000, aggregate_ceiling=20_000_000)
NOW = lambda: "2026-10-27T00:00:00Z"  # noqa: E731


def make_case(tools=("zeta-tool", "alpha-tool"), ngold=2, ncomments=3):
    gold = tuple(Golden(f"REALGOLD-{n}", f"gold finding {n} {SENT}", "high", "bug") for n in range(1, ngold + 1))
    revs = tuple(ToolReview(t, "repo", None, tuple(RawComment(f"REALCID-{t}-{n}", f"src/private{n}.py", n,
                 f"Invented comment body long enough to extract, item {n} {SENT}", "2026-01-01T00:00:00Z")
                 for n in range(1, ncomments + 1))) for t in tools)
    return ScorerCase(URL, "repo", None, 1, gold, revs)


class Env(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        (self.tmp / "op").mkdir()
        self.store = self.tmp / "store"
        self.ledger_path, self.book_path = self.tmp / "op/ledger.jsonl", self.tmp / "op/book.jsonl"

    def auth(self, **over):
        doc = {**H.AUTH_DOC, "id": "fake-auth", "maxUsdMicrosPerRun": 4_000_000, "maxUsdMicrosTotal": 50_000_000, **over}
        p = self.tmp / "op" / f"auth{len(list((self.tmp / 'op').iterdir()))}.json"
        p.write_text(json.dumps(doc))
        return trusted_authorization(p)

    def host(self, *, tools=("zeta-tool", "alpha-tool"), transport=None, auth=None, case=None, declared=None, baseline=None,
             cfg=CFG, evr=EVR, ledger_cap=50_000_000, run_ceiling=4_000_000, **case_kw):
        case = case or make_case(tools, **case_kw)
        units = [S.ScoreUnit(case, t, f"u001-t{n:02d}") for n, t in enumerate(tools, 1)]
        self.ledger = RuntimeLedger(self.ledger_path, ledger_cap)
        h = auth or self.auth()
        self.book = SpendBook(h, self.book_path)
        sc, al = self.ledger.totals("scoring")["committedUsdMicros"], self.ledger.totals()["committedUsdMicros"]
        b = baseline or S.LaunchBaseline(tuple(declared if declared is not None else [(case.url, t) for t in tools]),
                                         cfg.digest, tuple(sorted(cfg.prompt_sha256.items())), sc, al)
        self.transport = transport or S.CaptureTransport()
        return S.ScoreHost(cfg, b, units, profile_ref="pullo-score@1", price=PRICE, auth=h, book=self.book, ledger=self.ledger,
                           key=KEY, transport=self.transport, store_dir=self.store, eval_run_id=evr, clock=NOW, run_ceiling=run_ceiling)

    def intents(self):
        return [json.loads(x) for x in self.ledger_path.read_text().splitlines() if '"intent"' in x] if self.ledger_path.exists() else []


class Composition(Env):
    def test_two_tool_all_phase_chronology_complete_and_sanitized(self):
        h = self.host()
        rep = h.execute_offline()
        names = [b["response_format"]["json_schema"]["name"] for b in self.transport.bodies]
        self.assertEqual(names, ["ScoreExtractionSegments"] * 2 + ["ScoreDedup"] * 2 + ["ScorePair"] * 12)      # ALL extraction, ALL dedup, then pairs
        self.assertTrue(rep["complete"])
        self.assertEqual((rep["admission"]["reason"], rep["admission"]["pairs"], rep["gate"]["ok"]), ("admitted", 12, True))
        ik = [i["callKey"] for i in self.intents()]
        self.assertEqual((len(ik), len(set(ik))), (16, 16))                                             # no duplicate intents
        self.assertTrue(all(i["category"] == "scoring" for i in self.intents()))
        wire = json.dumps(self.transport.bodies)
        for leak in ("REALGOLD", "REALCID", "zeta-tool", "alpha-tool", "src/private", "example.invalid"):
            self.assertNotIn(leak, wire)                                                                # neutral ids only
        blob = json.dumps(rep)
        self.assertNotIn(SENT, blob)                                                                    # report is sanitized
        for k in ("temperature", "top_p", "top_k", "reasoning", "effort"):
            self.assertNotIn(k, self.transport.bodies[0])
        docs = self.store / f"{h.run_id}.documents.json"
        self.assertEqual(stat.S_IMODE(docs.stat().st_mode), 0o600)
        d = json.loads(docs.read_text())
        self.assertEqual(sorted(x["tool"] for x in d), ["alpha-tool", "zeta-tool"])
        self.assertIn(SENT, docs.read_text())                                                           # raw text only in the 0600 store
        self.assertEqual(d[0]["judge"]["runRef"], EVR)
        self.assertEqual(stat.S_IMODE((self.store / f"{h.run_id}.trace.jsonl").stat().st_mode), 0o600)

    def test_missing_extraction_failure_stops_all_pairs_and_marks_everything_unsent(self):
        def respond(body):
            n = body["response_format"]["json_schema"]["name"]
            return RuntimeError("boom") if (n == "ScoreExtractionSegments" and len(self_t.bodies) == 2) else None
        self_t = S.CaptureTransport()
        calls = []
        base = self_t._default
        self_t.respond = lambda b: (calls.append(1), RuntimeError("down") if len(calls) == 2 else base(b))[1]
        h = self.host(transport=self_t)
        rep = h.execute_offline()
        names = [b["response_format"]["json_schema"]["name"] for b in self_t.bodies]
        self.assertNotIn("ScorePair", names)
        self.assertFalse(rep["complete"])
        self.assertIsNone(rep["admission"])
        self.assertIsNone(rep["headline"])
        pair_units = [u for u in rep["attemptSet"]["units"] if u["phase"] == "pair"]
        self.assertEqual({u["status"] for u in pair_units}, {"unsent"})
        self.assertFalse((self.store / f"{h.run_id}.documents.json").exists())

    def test_complete_set_does_not_fit_sends_zero_pairs(self):
        # known scoring spend 7.7M: extraction+dedup fit, the exact worst-case 12-pair set exceeds the 8M scoring sub-cap
        L = RuntimeLedger(self.ledger_path, 50_000_000)
        self.assertIsNone(L.admit("old", 1, model=OPUS, **SCOPE))
        L.finish("old", outcome="processed", routerCostUsdMicros=7_700_000, tokenPricedUsdMicros=7_700_000,
                 upstreamInferenceCostUsdMicros=None, isByok=None)
        h = self.host()
        rep = h.execute_offline()
        names = [b["response_format"]["json_schema"]["name"] for b in self.transport.bodies]
        self.assertEqual(names, ["ScoreExtractionSegments"] * 2 + ["ScoreDedup"] * 2)
        self.assertEqual((rep["admission"]["reason"], rep["fitRefusal"]), ("does-not-fit", "scoring-cap"))
        self.assertFalse(rep["complete"])
        self.assertEqual({u["status"] for u in rep["attemptSet"]["units"] if u["phase"] == "pair"}, {"unsent"})

    def test_aggregate_ceiling_blocks_with_prior_review_spend(self):
        L = RuntimeLedger(self.ledger_path, 50_000_000)
        self.assertIsNone(L.admit("rev", 1, model="anthropic/claude-sonnet-5.5"))
        L.finish("rev", outcome="processed", routerCostUsdMicros=19_950_000, tokenPricedUsdMicros=19_950_000,
                 upstreamInferenceCostUsdMicros=None, isByok=None)
        rep = self.host().execute_offline()
        self.assertFalse(rep["complete"])
        self.assertFalse(any(b["response_format"]["json_schema"]["name"] == "ScorePair" for b in self.transport.bodies))

    def test_run_ceiling_does_not_fit_after_extraction_and_dedup(self):
        # per-run 4M ceiling cannot hold 2 tools x 60 candidates x 2 gold pairs after two 8000-token extractions: refuse whole set
        h = self.host(ngold=3, ncomments=60, run_ceiling=900_000)
        rep = h.execute_offline()
        names = [b["response_format"]["json_schema"]["name"] for b in self.transport.bodies]
        self.assertEqual(rep["admission"]["reason"], "does-not-fit", rep["gate"])
        self.assertEqual(rep["fitRefusal"], "run-ceiling")
        self.assertNotIn("ScorePair", names)
        self.assertEqual({u["status"] for u in rep["attemptSet"]["units"] if u["phase"] == "pair"}, {"unsent"})
        self.assertFalse(rep["complete"])

    def test_zero_candidate_declared_units_are_complete_but_empty_declared_set_is_refused(self):
        t = S.CaptureTransport(respond=lambda b: {"candidates": []})
        h = self.host(transport=t)
        rep = h.execute_offline()
        self.assertTrue(rep["complete"])
        self.assertEqual(rep["admission"]["pairs"], 0)
        self.assertFalse(any(b["response_format"]["json_schema"]["name"] == "ScorePair" for b in t.bodies))
        with self.assertRaises(S.ScoreHostError) as cm:
            self.host(tools=(), declared=[]).execute_offline()
        self.assertEqual(cm.exception.reason, "no-declared-units")


class ExtractV3(Env):
    """bench.extract@v3 through the real Gateway/OpenRouterProvider: the extractor is asked for ScoreExtractionSegments, the fake
    transport answers segment ranges only, and every stored candidate text is the exact joined segments (no model-copied text)."""

    def test_wire_asks_for_segment_ranges_and_documents_hold_the_exact_comments(self):
        from reviewer.benchmark import score_prompts as P
        from reviewer.contracts import validate
        from reviewer.runtime import schemas
        h = self.host()
        rep = h.execute_offline()
        self.assertTrue(rep["complete"])
        ext = [b for b in self.transport.bodies if b["response_format"]["json_schema"]["name"] == "ScoreExtractionSegments"]
        self.assertEqual(len(ext), 2)
        for b in ext:
            self.assertEqual(b["response_format"]["json_schema"]["schema"], schemas.provider_schema("ScoreExtractionSegments", "anthropic"))
            self.assertEqual(b["messages"][0]["content"], P.SYSTEM["extract"])
            data = json.loads(b["messages"][-1]["content"])
            self.assertTrue(all(set(c) == {"id", "segments"} for c in data["comments"]))                   # no separate full text
            out = S.CaptureTransport._default(b)
            self.assertEqual(validate("ScoreExtractionSegments", out), [])
            self.assertEqual(out["candidates"], [{"sourceCommentId": c["id"], "startSegment": 1, "endSegment": len(c["segments"])}
                                                 for c in data["comments"]])
        case = make_case()
        bodies = {c.id: c.body for r in case.reviews for c in r.comments}
        for d in json.loads((self.store / f"{h.run_id}.documents.json").read_text()):
            self.assertEqual(d["judge"]["extractionPrompt"], "bench.extract@v3")
            self.assertEqual([c["text"] for c in d["extraction"]["candidates"]], [bodies[c["sourceCommentId"]] for c in d["extraction"]["candidates"]])

    def _bad_range(self, make):
        def respond(b):
            if b["response_format"]["json_schema"]["name"] == "ScoreExtractionSegments":
                c = json.loads(b["messages"][-1]["content"])["comments"][0]
                return {"candidates": [make(c)]}
            return None
        t = S.CaptureTransport(respond=respond)
        return self.host(transport=t).execute_offline(), t

    def test_reversed_or_out_of_range_segments_through_the_gateway_are_extraction_invalid_and_block_pairs(self):
        """Gateway path: a reversed or past-the-end range is schema-VALID (order and bound are local), so the real Gateway
        returns it and the producer classifies the unit extraction-invalid; nothing reaches the pair phase."""
        for name, make in (("reversed", lambda c: {"sourceCommentId": c["id"], "startSegment": 2, "endSegment": 1}),
                           ("past last", lambda c: {"sourceCommentId": c["id"], "startSegment": 1, "endSegment": len(c["segments"]) + 1})):
            with self.subTest(name):
                self.setUp()
                rep, t = self._bad_range(make)
                self.assertFalse(rep["complete"])
                self.assertIn(["zeta-tool", URL, "extract", "extraction-invalid"], rep["gate"]["failures"])
                self.assertNotIn("ScorePair", [b["response_format"]["json_schema"]["name"] for b in t.bodies])

    def test_type_errors_through_the_gateway_are_schema_invalid_provider_failures(self):
        """A bool, zero or float number fails the contract at the Gateway: the unit is provider-failure / schema-invalid."""
        for name, v in (("bool", True), ("zero", 0), ("float", 1.0)):
            with self.subTest(name):
                self.setUp()
                rep, t = self._bad_range(lambda c, v=v: {"sourceCommentId": c["id"], "startSegment": v, "endSegment": 1})
                self.assertFalse(rep["complete"])
                self.assertIn(["zeta-tool", URL, "extract", "provider-failure"], rep["gate"]["failures"])
                ext = [u for u in rep["attemptSet"]["units"] if u["phase"] == "extract" and u["tool"] == "zeta-tool"]
                self.assertEqual(ext[0]["error"], "schema-invalid")

    def test_schema_digest_covers_the_segments_projection(self):
        import hashlib
        from reviewer.benchmark.jsonio import canonical
        from reviewer.runtime import schemas
        want = hashlib.sha256(canonical({n: schemas.provider_schema(n, "anthropic")
                                         for n in ("ScoreExtractionSegments", "ScoreDedup", "ScorePair")})).hexdigest()
        self.assertEqual(S.schema_sha256(), want)
        self.assertEqual(CFG.canonical()["promptVersions"]["extract"], "bench.extract@v3")


class Refusals(Env):
    def refused(self, h, reason):
        with self.assertRaises(S.ScoreHostError) as cm:
            h.execute_offline()
        self.assertEqual(cm.exception.reason, reason)
        self.assertEqual(self.transport.bodies, [])                                                    # zero provider calls
        self.assertEqual(self.intents(), [])

    def test_live_entry_is_refused_whatever_the_arguments(self):
        for args in ((), (True,), ({"confirm": True},)):
            with self.assertRaises(S.ScoreHostError) as cm:
                S.run_live(*args, confirm=True)
            self.assertEqual(cm.exception.reason, "live-refused-controls-missing")
        self.assertFalse(S.FULL_ACCEPTANCE)
        self.assertGreaterEqual(len(S.ABSENT), 5)

    def test_declared_set_and_pin_drift_refused_before_any_send(self):
        self.refused(self.host(declared=[(URL, "zeta-tool")]), "declared-set-drift")              # tool missing from the baseline
        self.refused(self.host(declared=[(URL, "zeta-tool"), (URL, "alpha-tool"), (URL, "extra")]), "declared-set-drift")
        self.refused(self.host(declared=[(URL, "zeta-tool"), ("https://example.invalid/other", "alpha-tool")]), "declared-set-drift")
        h = self.host()
        h.baseline = S.LaunchBaseline(h.baseline.declared, "sha256:" + "0" * 64, h.baseline.prompt_sha256, 0, 0)
        self.refused(h, "config-or-prompt-drift")
        h = self.host()
        h.baseline = S.LaunchBaseline(h.baseline.declared, h.baseline.config_digest, (("extract", "0" * 64),), 0, 0)
        self.refused(h, "config-or-prompt-drift")
        h = self.host()
        h.baseline = S.LaunchBaseline(h.baseline.declared, h.baseline.config_digest, h.baseline.prompt_sha256, 5, 0)
        self.refused(h, "ledger-state-drift")

    def test_prior_unresolved_scoring_exposure_holds_and_is_retained(self):
        L = RuntimeLedger(self.ledger_path, 50_000_000)
        self.assertIsNone(L.admit("orphan", 5000, model=OPUS, **SCOPE))                           # intent with no result
        h = self.host()
        with self.assertRaises(S.ScoreHostError) as cm:
            h.execute_offline()
        self.assertEqual(cm.exception.reason, "scoring-startup-hold")
        self.assertEqual(self.transport.bodies, [])
        self.assertEqual(len(self.intents()), 1)                                                   # orphan retained, nothing released
        self.assertEqual(RuntimeLedger(self.ledger_path, 50_000_000).totals("scoring")["unknownBoundUsdMicros"], 5000)

    def test_lock_contention_refuses_without_calls(self):
        self.store.mkdir(mode=0o700)
        fd = os.open(self.store / "scorer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.refused(self.host(), "scorer-lock-held")

    def test_authorization_that_does_not_cover_the_profile_refuses_without_aliasing(self):
        sonnet = "anthropic/claude-sonnet-5.5"
        self.refused(self.host(auth=self.auth(models=[sonnet])), "authorization-coverage")
        self.refused(self.host(auth=self.auth(providers=["openai"])), "authorization-coverage")
        self.refused(self.host(auth=self.auth(expiresAt="2020-01-01T00:00:00Z")), "authorization-coverage")

    def test_per_run_authorization_below_the_plan_ceiling_is_refused_not_split_or_widened(self):
        self.refused(self.host(auth=self.auth(maxUsdMicrosPerRun=1_000_000)), "authorization-coverage")
        with self.assertRaises(S.ScoreHostError):
            self.host(run_ceiling=4_000_001)                                                       # a host ceiling can only tighten

    def test_whole_book_total_exhausted_by_prior_spend_stops_without_pairs(self):
        a = self.auth(maxUsdMicrosTotal=4_000_000)
        h = self.host(auth=a)
        h.book.reserve("prior", 1)
        h.book.settle("prior", 3_999_000)
        rep = h.execute_offline()
        self.assertFalse(rep["complete"])
        self.assertIsNone(rep["headline"])
        self.assertFalse(any(b["response_format"]["json_schema"]["name"] == "ScorePair" for b in self.transport.bodies))

    def test_oversize_candidate_config_cannot_be_widened_by_a_looser_baseline(self):
        from reviewer.score_config import ScoreConfigError, parse_score_config
        text = (ROOT / "pullo-score.toml").read_text().replace("max_pairs_per_tool_case = 2000", "max_pairs_per_tool_case = 2001")
        with self.assertRaises(ScoreConfigError):
            parse_score_config(text)


class Replay(Env):
    def test_fresh_id_strict_replay_makes_no_live_call_and_returns_equal_documents(self):
        h = self.host()
        rep = h.execute_offline()
        trace = self.store / f"{h.run_id}.trace.jsonl"
        from reviewer.gateway.trace import bytes_digest
        pin = bytes_digest(trace.read_bytes())
        docs = json.loads((self.store / f"{h.run_id}.documents.json").read_text())
        before = (len(self.transport.bodies), self.ledger_path.read_bytes(), self.book_path.read_bytes())
        out = h.replay(trace, pin, EVR2)
        self.assertEqual(out["liveCalls"], 0)
        self.assertTrue(out["complete"])
        norm = lambda ds: [{k: v for k, v in d.items() if k != "judge"} for d in ds]  # noqa: E731 judge.runRef is the fresh id
        self.assertEqual(norm(out["documents"]), norm(docs))
        self.assertEqual(out["documents"][0]["judge"]["runRef"], EVR2)
        self.assertEqual(before, (len(self.transport.bodies), self.ledger_path.read_bytes(), self.book_path.read_bytes()))   # zero new spend
        with self.assertRaises(S.ScoreHostError):
            h.replay(trace, pin, EVR)                                                              # same id refused
        with self.assertRaises(S.ScoreHostError):
            h.replay(trace, "sha256:" + "0" * 64, EVR2)                                            # wrong external pin
        self.assertTrue(rep["complete"])


class Corrections(Env):
    """SCORE-HOST-03: H1 (offline entry accepts only the exact fake transport + placeholder key) and H2 (replay pins)."""

    def no_effects(self):
        self.assertFalse(self.ledger_path.exists() and self.ledger_path.read_bytes())
        self.assertFalse(self.book_path.exists() and self.book_path.read_bytes())
        self.assertFalse((self.store / "scorer.lock").exists() if self.store.exists() else False)
        self.assertEqual(list(self.store.glob("*.jsonl")) if self.store.exists() else [], [])

    def test_h1_non_capture_transports_are_refused_before_lock_intent_or_request(self):
        sent = []

        class Sub(S.CaptureTransport):                         # subclass override must not pass an isinstance-style check
            def __call__(self, req):
                sent.append(req)
                return super().__call__(req)

        class Weird(S.CaptureTransport):
            pass
        inst = S.CaptureTransport()
        inst.extra = 1                                          # extra instance state
        for name, t in (("plain function", lambda req: sent.append(req)), ("subclass override", Sub()), ("empty subclass", Weird()),
                        ("extra attribute", inst), ("None (would default to a real HTTPS transport)", None), ("object", object())):
            h = self.host(transport=t)
            if t is None:
                h.transport = None
            with self.assertRaises(S.ScoreHostError, msg=name) as cm:
                h.execute_offline()
            self.assertEqual(cm.exception.reason, "offline-needs-capture-transport", name)
        self.assertEqual(sent, [])
        self.no_effects()

    def test_h1_non_placeholder_key_is_refused_before_any_effect(self):
        for v in ("sk-or-v1-" + "a1b2" * 12, "sk-or-v1-" + "f4k3" * 12 + "x"):
            h = self.host()
            h.key = Secret(v)
            with self.assertRaises(S.ScoreHostError) as cm:
                h.execute_offline()
            self.assertEqual(cm.exception.reason, "offline-needs-placeholder-key")
        h = self.host()
        h.key = "sk-or-v1-" + "f4k3" * 12                          # a bare string is not a Secret
        with self.assertRaises(S.ScoreHostError):
            h.execute_offline()
        self.assertEqual(self.transport.bodies, [])
        self.no_effects()

    def test_h1_positive_exact_capture_transport_and_trusted_callback_still_work(self):
        t = S.CaptureTransport(respond=lambda b: S.CaptureTransport._default(b))       # trusted test callback is allowed, honest scope
        rep = self.host(transport=t).execute_offline()
        self.assertTrue(rep["complete"])
        self.assertGreater(len(t.bodies), 0)

    def test_h2_replay_checks_declared_config_and_prompt_pins_before_processing(self):
        h = self.host()
        h.execute_offline()
        from reviewer.gateway.trace import bytes_digest
        trace = self.store / f"{h.run_id}.trace.jsonl"
        pin = bytes_digest(trace.read_bytes())
        good = h.baseline
        for name, b, reason in (
                ("tool dropped", S.LaunchBaseline(((URL, "zeta-tool"),), good.config_digest, good.prompt_sha256, 0, 0), "declared-set-drift"),
                ("tool added", S.LaunchBaseline(good.declared + ((URL, "extra"),), good.config_digest, good.prompt_sha256, 0, 0), "declared-set-drift"),
                ("config digest", S.LaunchBaseline(good.declared, "sha256:" + "0" * 64, good.prompt_sha256, 0, 0), "config-or-prompt-drift"),
                ("prompt digest", S.LaunchBaseline(good.declared, good.config_digest, (("extract", "0" * 64),), 0, 0), "config-or-prompt-drift")):
            h2 = self.host()
            h2.baseline = b
            with self.assertRaises(S.ScoreHostError, msg=name) as cm:
                h2.replay(trace, pin, EVR2)
            self.assertEqual(cm.exception.reason, reason, name)

    def test_h2_replay_touches_no_auth_book_ledger_key_transport_or_state_totals(self):
        h = self.host()
        h.execute_offline()
        from reviewer.gateway.trace import bytes_digest
        trace = self.store / f"{h.run_id}.trace.jsonl"
        pin = bytes_digest(trace.read_bytes())
        docs = json.loads((self.store / f"{h.run_id}.documents.json").read_text())

        class Tripwire:
            def __getattr__(self, n):
                raise AssertionError("replay touched " + n)
        r = self.host()
        r.baseline = h.baseline                                    # the recorded launch baseline (inputDigest is pinned in the trace)
        r.auth = r.book = r.ledger = r.key = r.transport = Tripwire()
        out = r.replay(trace, pin, EVR2)
        self.assertEqual((out["liveCalls"], out["complete"]), (0, True))
        norm = lambda ds: [{k: v for k, v in d.items() if k != "judge"} for d in ds]  # noqa: E731
        self.assertEqual(norm(out["documents"]), norm(docs))
        # initial ledger totals in the baseline are NOT applied by replay (they are a live-admission pin only)
        r2 = self.host()
        r2.baseline = S.LaunchBaseline(h.baseline.declared, h.baseline.config_digest, h.baseline.prompt_sha256, 123, 456)
        r2.auth = r2.book = r2.ledger = r2.key = r2.transport = Tripwire()
        out2 = r2.replay(trace, pin, EVR2)                          # no ledger-state-drift refusal: totals are not applied by replay
        self.assertFalse(out2["complete"])                          # but the changed baseline no longer matches the recorded inputDigest
        self.assertEqual(out2["liveCalls"], 0)


class Imports(unittest.TestCase):
    BAD = ("reviewer.pipeline", "reviewer.tools", "reviewer.config", "reviewer.scoring", "reviewer.evaluation", "reviewer.pilot")

    def test_host_source_imports_no_review_pipeline_gold_or_env_modules(self):
        import ast
        tree = ast.parse((ROOT / "reviewer/score_host.py").read_text())
        mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | \
               {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse([m for m in mods if m.startswith(self.BAD)], mods)
        self.assertFalse([m for m in mods if "gold" in m or "corpus" in m])

    def test_importing_the_host_loads_no_pipeline_tools_config_or_pilot(self):
        import subprocess
        import sys
        code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); import reviewer.score_host;"
                f"print([m for m in sys.modules if m.startswith({self.BAD!r})])")
        out = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "[]", out.stderr[-300:])


if __name__ == "__main__":
    unittest.main()
