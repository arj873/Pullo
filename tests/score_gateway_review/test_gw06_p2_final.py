"""SCORE-GW-06 final P2 gate (independent). The GW-04 P2 repro stays UNCHANGED in test_gw04_probes.py and passes
(its try/except accepts construction refusal). These tests tighten it: when the trusted profile is refused at
construction the refusal must be typed (GatewayConfigError), echo nothing, write no event, admit nothing and never
contact a provider; request-side keys are refused before provider in live and in strict replay."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reviewer.contracts.budget import STANDARD_S0A_BUDGET  # noqa: E402
from reviewer.contracts.canonical import score_run_id  # noqa: E402
from reviewer.gateway import Gateway, GatewayConfigError, Recorder, SpendBook  # noqa: E402
from tests.score_gateway_review import support as S  # noqa: E402
from tests.score_gateway_review.support import Fake  # noqa: E402

TEN = ("provider_order", "providerOptions", "extra_headers", "api_base", "endpoint", "max_price", "mcp",
       "tool_resources", "openrouter", "base_url_override")
MORE = ("provider_preferences", "Temperature", "TOP_P", "topP", "top_k", "stop", "tools", "provider", "route", "fallbacks",
        "temperature ", "seed\n", "response_format", "reasoning", "user", S.SENT)


def prof(role, **extra):
    p = copy.deepcopy(S.PROFILE)
    p["roles"][role]["params"] = {**p["roles"][role]["params"], **extra}
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = self._t.name


class ConstructionRefusal(Base):
    def test_every_unsafe_key_in_every_role_is_refused_typed_before_anything_happens(self):
        for role in S.ROLES:
            for k in TEN + MORE:
                p = Fake()
                h = S.auth_handle(self.tmp)
                book = SpendBook(h)
                rid = score_run_id(S.EVR, S.CASE, 0)
                rec = Recorder(rid, family="score")
                with self.assertRaises(GatewayConfigError, msg=(role, k)) as cm:
                    Gateway(mode="live", profile=prof(role, **{k: ["x"]}), budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                            family="score", providers={"anthropic": p}, authorization=h, book=book, recorder=rec,
                            eval_run_id=S.EVR, eval_case_id=S.CASE, repeat=0, clock=S.NOW)
                self.assertNotIn(S.SENT, str(cm.exception))                     # the key name is not echoed
                self.assertEqual((p.calls, rec.events), (0, []), (role, k))     # nothing recorded, no provider contact
                self.assertEqual(book.totals()["committed"] if "committed" in book.totals() else 0, 0)

    def test_same_refusal_in_strict_replay_and_disabled_modes(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        for k in TEN:
            rid = score_run_id(S.EVR2, S.CASE, 0)
            with self.assertRaises(GatewayConfigError, msg=k):
                Gateway(mode="strict-replay", profile=prof("matcher", **{k: 1}), budget=dict(STANDARD_S0A_BUDGET),
                        run_id=rid, family="score", replay=tr, eval_run_id=S.EVR2, eval_case_id=S.CASE, repeat=0,
                        expected_trace_digest=tr.byte_digest)
            with self.assertRaises(GatewayConfigError, msg=k):
                Gateway(mode="disabled", profile=prof("matcher", **{k: 1}), budget=dict(STANDARD_S0A_BUDGET),
                        run_id=score_run_id(S.EVR, S.CASE, 0), family="score", eval_run_id=S.EVR, eval_case_id=S.CASE,
                        repeat=0)

    def test_fixed_sampling_values_must_be_finite_plain_numbers(self):
        for bad in (True, False, "0", None, [0], {"a": 1}, float("nan"), float("inf"), float("-inf")):
            for k in ("temperature", "top_p", "seed"):
                try:
                    Gateway(mode="disabled", profile=prof("matcher", **{k: bad}), budget=dict(STANDARD_S0A_BUDGET),
                            run_id=score_run_id(S.EVR, S.CASE, 0), family="score", eval_run_id=S.EVR,
                            eval_case_id=S.CASE, repeat=0)
                except Exception as e:      # noqa: BLE001  (contract-level or gateway refusal; never constructs)
                    self.assertIsInstance(e, (GatewayConfigError, ValueError), (k, bad))
                else:
                    self.fail(f"{k}={bad!r} constructed")
        for good in (0, 0.0, 1, 0.5, 7):
            Gateway(mode="disabled", profile=prof("matcher", temperature=good, top_p=0.9, seed=7),
                    budget=dict(STANDARD_S0A_BUDGET), run_id=score_run_id(S.EVR, S.CASE, 0), family="score",
                    eval_run_id=S.EVR, eval_case_id=S.CASE, repeat=0)

    def test_review_family_profiles_are_not_narrowed(self):
        rp = json.loads((S.EX / "ModelProfile.smoke-synthetic.json").read_text())
        rp["roles"]["investigator"]["params"]["provider_order"] = ["x"]
        Gateway(mode="disabled", profile=rp, budget=dict(STANDARD_S0A_BUDGET), run_id="run_" + "1" * 16)


class SafeParamsStillWork(Base):
    def test_safe_profile_end_to_end_live_provider_copy_and_replay(self):
        pf = copy.deepcopy(S.PROFILE)
        for r in S.ROLES:
            pf["roles"][r]["params"] = {"temperature": 0, "top_p": 0.9, "seed": 7}
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p, profile=pf)
        for r in S.ROLES:
            req = S.request(r, params={"temperature": 0, "top_p": 0.9, "seed": 7})
            self.assertTrue(gw.call(S.STAGE[r], r, "s1", 0, req).ok, r)
        for (sent, _k), r in zip(p.seen, S.ROLES):
            self.assertEqual(sent["params"], {"temperature": 0, "top_p": 0.9, "seed": 7,
                                              "timeoutSec": pf["roles"][r]["caps"]["timeoutSec"]})
        tr = S.finish(rec)
        rid = score_run_id(S.EVR2, S.CASE, 0)
        rr = Recorder(rid, family="score")
        rg = Gateway(mode="strict-replay", profile=pf, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                     replay=tr, recorder=rr, eval_run_id=S.EVR2, eval_case_id=S.CASE, repeat=0,
                     expected_trace_digest=tr.byte_digest)
        rr.start(S.run_doc("strict-replay", S.EVR2, S.CASE, 0, replay_of=tr.run_id))
        for r in S.ROLES:
            req = S.request(r, params={"temperature": 0, "top_p": 0.9, "seed": 7})
            self.assertTrue(rg.call(S.STAGE[r], r, "s1", 0, req).ok, r)
        self.assertEqual((rg.report()["liveCalls"], rg.report()["newSpendUsdMicros"]), (0, 0))

    def test_default_profile_and_cap_lowering_overrides_still_work(self):
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p)
        self.assertTrue(gw.call("MATCH", "matcher", "s1", 0, S.request()).ok)
        for i, extra in enumerate(({"timeoutSec": 5}, {"maxOutputTokens": 10}, {"max_tokens": 10}), 1):
            self.assertTrue(gw.call("MATCH", "matcher", "s1", i, S.request(params=S.params(**extra))).ok, extra)


class RequestSideAllowlist(Base):
    def test_unsafe_request_keys_refused_before_provider_live(self):
        for k in TEN + MORE:
            p = Fake()
            gw, rec, _ = S.live(self.tmp, p)
            r = gw.call("MATCH", "matcher", "s1", 0, S.request(params=S.params(**{k: "x"})))
            self.assertEqual((p.calls, r.error["code"]), (0, "contract-violation"), k)
            self.assertNotIn("stage", r.error)
            self.assertNotIn(S.SENT, json.dumps(r.error))

    def test_unsafe_request_keys_refused_in_strict_replay_without_consuming(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        rg, rrec = S.replay(tr)
        for k in TEN + MORE:
            before = (len(rrec.events), rg.unconsumed())
            r = rg.call("MATCH", "matcher", "s1", 0, S.request(params=S.params(**{k: "x"})))
            self.assertEqual(r.error["code"], "contract-violation", k)
            self.assertEqual(before[1], rg.unconsumed(), k)
            self.assertFalse(any(e["type"] == "score.model.call" for e in rrec.events), k)
        self.assertEqual((rg.report()["liveCalls"], rg.report()["replayedCalls"]), (0, 0))
        self.assertTrue(rg.call("MATCH", "matcher", "s1", 0, S.request()).ok)      # a clean call still replays
