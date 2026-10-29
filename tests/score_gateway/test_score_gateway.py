"""SCORE-GW-01: score family inside the existing Gateway. Offline, invented fixtures, no provider/network/Git."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import validate_score_trace  # noqa: E402
from reviewer.contracts.budget import STANDARD_S0A_BUDGET  # noqa: E402
from reviewer.contracts.canonical import score_request_hash, score_run_id  # noqa: E402
from reviewer.gateway import (Gateway, GatewayConfigError, Recorder, ScriptError, TraceError,  # noqa: E402
                              bytes_digest, events_to_bytes, load_trace, parse_script)
from tests.score_gateway import helpers as H  # noqa: E402
from tests.score_gateway.review_equiv import record_and_replay, review_report_keys, review_trace  # noqa: E402

# Pinned from the unmodified gateway at public main f1c62ec (same fixture, same fixed clock).
REVIEW_LIVE_DIGEST = "sha256:d49fef0892e772153ef094485584d765a112b550de5368ab45e01504941acae4"
REVIEW_REPLAY_DIGEST = "sha256:5daf844aa326d6fc48bf424e69c5c581971bec39aca256afc20102afafb38e10"
ROLES = ("extractor", "deduper", "matcher")


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = self._t.name

    def all_roles(self, **kw):
        sc = H.script([(r, 0, "response", H.response(r)) for r in ROLES])
        gw, rec, prov, h = H.live(self.tmp, sc, **kw)
        for r in ROLES:
            self.assertTrue(gw.call(H.ROLE_STAGE[r], r, "s1", 0, H.request(r)).ok)
        return gw, rec, prov, H.finish(gw, rec)


class LiveAndReplay(Base):
    def test_three_roles_live_then_strict_replay(self):
        gw, rec, prov, tr = self.all_roles()
        self.assertEqual(prov.calls, 3)
        self.assertEqual(validate_score_trace(rec.events), [])
        costs = [e["record"] for e in rec.events if e["type"] == "cost"]
        self.assertEqual({c["kind"] for c in costs}, {"score"})
        self.assertTrue(all("stage" not in c for c in costs))
        self.assertEqual(gw.report()["family"], "score")
        rg, rrec = H.replay(tr)
        for r in ROLES:
            self.assertTrue(rg.call(H.ROLE_STAGE[r], r, "s1", 0, H.request(r)).ok)
        rep = rg.report()
        self.assertEqual((rep["liveCalls"], rep["newSpendUsdMicros"], rep["replayedCalls"]), (0, 0, 3))
        self.assertEqual({e["record"]["basis"] for e in rrec.events if e["type"] == "cost"}, {"replayed"})
        self.assertEqual(rg.unconsumed(), 0)

    def test_replay_has_no_provider_and_refuses_one(self):
        _, _, _, tr = self.all_roles()

        class FailOnCall:
            def call(self, *a):
                raise AssertionError("provider called in replay")
        with self.assertRaises(GatewayConfigError):
            H.replay(tr, providers={"anthropic": FailOnCall()})

    def test_replay_needs_fresh_eval_run_and_pinned_digest(self):
        _, _, _, tr = self.all_roles()
        with self.assertRaises(GatewayConfigError):
            H.replay(tr, evr=H.EVR)
        rid = score_run_id(H.EVR2, H.CASE, 0)
        with self.assertRaises(GatewayConfigError):      # unpinned
            Gateway(mode="strict-replay", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                    family="score", replay=tr, eval_run_id=H.EVR2, eval_case_id=H.CASE, repeat=0)

    def test_replay_binding_wrong_replayof(self):
        _, _, _, tr = self.all_roles()
        rid = score_run_id(H.EVR2, H.CASE, 0)
        rec = Recorder(rid, family="score")
        gw = Gateway(mode="strict-replay", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                     family="score", replay=tr, recorder=rec, eval_run_id=H.EVR2, eval_case_id=H.CASE, repeat=0,
                     expected_trace_digest=tr.byte_digest)
        bad = H.run_doc("strict-replay", evr=H.EVR2, replay_of="run_" + "0" * 16)
        rec.start(bad)
        res = gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        self.assertEqual(res.error["code"], "contract-violation")
        self.assertEqual(gw.report()["replayedCalls"], 0)

    def test_request_hash_changes_with_exact_text_and_replay_miss(self):
        a, b = H.request("matcher", "x"), H.request("matcher", "x ")
        self.assertNotEqual(score_request_hash(a), score_request_hash(b))
        _, _, _, tr = self.all_roles()
        rg, _ = H.replay(tr)
        res = rg.call("MATCH", "matcher", "s1", 0, b)
        self.assertEqual(res.error["code"], "replay-miss")
        self.assertNotIn("stage", res.error)

    def test_loaded_trace_mutation_refused(self):
        _, _, _, tr = self.all_roles()
        tr.events[1]["response"]["output"] = {"match": False, "confidence": 0}
        rid = score_run_id(H.EVR2, H.CASE, 0)
        with self.assertRaises(TraceError):
            Gateway(mode="strict-replay", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                    family="score", replay=tr, eval_run_id=H.EVR2, eval_case_id=H.CASE, repeat=0,
                    expected_trace_digest=tr.byte_digest)

    def test_file_roundtrip_and_tampered_cost_refused(self):
        p = Path(self.tmp) / "t.jsonl"
        sc = H.script([("matcher", 0, "response", H.response("matcher"))])
        gw, rec, _, _ = H.live(self.tmp, sc, path=p)
        gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        rec.end("completed")
        tr = load_trace(p)
        self.assertEqual(tr.family, "score")
        lines = p.read_text().splitlines()
        evs = [json.loads(x) for x in lines]
        evs[2]["record"]["usage"]["outputTokens"] += 1
        with self.assertRaises(TraceError):
            load_trace(evs)


class Failures(Base):
    def one(self, doc_kind, doc, **kw):
        sc = H.script([("matcher", 0, doc_kind, doc)])
        gw, rec, prov, _ = H.live(self.tmp, sc, **kw)
        return gw, rec, prov, gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))

    def test_unknown_provider_error_is_retained_and_replayed_retained(self):
        err = {"code": "provider-timeout", "message": "scripted", "retryable": True}
        gw, rec, prov, res = self.one("error", err)
        self.assertEqual(res.error["code"], "provider-timeout")
        self.assertEqual(prov.calls, 1)                      # zero retries
        self.assertEqual(len(gw.retained), 1)
        self.assertNotIn("stage", res.error)
        tr = H.finish(gw, rec)
        rg, rrec = H.replay(tr)
        r2 = rg.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        self.assertEqual(r2.error["code"], "provider-timeout")
        self.assertEqual(rg.report()["newSpendUsdMicros"], 0)
        self.assertEqual(len(rg.retained), 1)
        c = [e["record"] for e in rrec.events if e["type"] == "cost"][0]
        self.assertEqual(c["basis"], "replayed")

    def test_released_provider_error_costs_zero(self):
        err = {"code": "provider-error", "message": "m", "retryable": False, "detail": {"outcome": "not-sent"}}
        gw, _, _, res = self.one("error", err)
        self.assertEqual(gw.report()["newSpendUsdMicros"], 0)
        self.assertEqual(gw.retained, [])

    def test_malformed_output_is_typed_without_exception_or_text(self):
        bad = H.response("matcher", output={"match": "yes", "confidence": H.SENTINEL})
        gw, rec, _, res = self.one("response", bad)
        self.assertEqual(res.error["code"], "schema-invalid")
        self.assertNotIn("stage", res.error)
        self.assertNotIn(H.SENTINEL, json.dumps(res.error))
        self.assertEqual(validate_score_trace(rec.events), [])

    def test_wrong_model_response_is_billed_error(self):
        gw, _, _, res = self.one("response", H.response("matcher", resolvedModel="other/model"))
        self.assertEqual(res.error["code"], "contract-violation")
        self.assertGreater(gw.report()["newSpendUsdMicros"], 0)

    def test_budget_refusal_omits_stage_and_never_calls_provider(self):
        gw, rec, prov, res = self.one("response", H.response("matcher"), ceiling=1)
        self.assertEqual(res.error["code"], "budget-exhausted")
        self.assertNotIn("stage", res.error)
        self.assertEqual(prov.calls, 0)
        self.assertEqual(validate_score_trace(rec.events), [])

    def test_missing_script_entry_never_falls_back(self):
        sc = H.script([("matcher", 1, "response", H.response("matcher"))])
        gw, _, prov, _ = H.live(self.tmp, sc)
        res = gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        self.assertEqual(res.error["code"], "provider-error")

    def test_guard_refusal_is_stageless_and_free(self):
        from reviewer.gateway import GuardRefusal
        sc = H.script([("matcher", 0, "response", H.response("matcher"))])
        gw, _, prov, _ = H.live(self.tmp, sc, guard=lambda ctx: GuardRefusal("cancelled"))
        res = gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        self.assertEqual((res.error["code"], prov.calls, gw.report()["newSpendUsdMicros"]), ("cancelled", 0, 0))
        self.assertNotIn("stage", res.error)


class Refusals(Base):
    def gw(self):
        sc = H.script([(r, 0, "response", H.response(r)) for r in ROLES])
        return H.live(self.tmp, sc)

    def test_bad_coordinates_raise_before_anything(self):
        gw, _, prov, _ = self.gw()
        for st, ro in (("INVESTIGATE", "matcher"), ("EXTRACT", "matcher"), ("MATCH", "judge"), ("MATCH", "investigator")):
            with self.assertRaises(ValueError):
                gw.call(st, ro, "s1", 0, H.request("matcher"))
        with self.assertRaises(ValueError):
            gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"), repair=lambda r: r)
        self.assertEqual(prov.calls, 0)

    def test_request_mismatches_refused_before_provider(self):
        gw, _, prov, _ = self.gw()
        cases = [{**H.request("matcher"), "role": "deduper"}, H.request("matcher", profile="other@1"),
                 H.request("matcher", outputSchema="ScoreDedup"), H.request("matcher", promptVersion="x@v9"),
                 H.request("matcher", tools=[{"name": "t"}]), "not a dict",
                 H.request("matcher", messages=[{"role": "tool", "content": "x"}]),
                 H.request("matcher", params={"max_tokens": 10**6}),
                 {**H.request("matcher"), "hop": 0}]
        for i, req in enumerate(cases):
            res = gw.call("MATCH", "matcher", f"s{i}", 0, req)
            self.assertEqual(res.error["code"], "contract-violation", i)
            self.assertNotIn("stage", res.error)
        self.assertEqual(prov.calls, 0)

    def test_hidden_routing_tools_fallback_in_params_refused(self):
        gw, _, prov, _ = self.gw()
        for i, p in enumerate(({"provider": {"order": ["x"]}}, {"extra_body": {"models": ["a", "b"]}},
                               {"nested": [{"Tool-Choice": "auto"}]}, {"fallbacks": []}, {"route": "fallback"},
                               {"a": {"b": {"c": {"allow_fallbacks": True}}}})):
            res = gw.call("MATCH", "matcher", f"s{i}", 0, H.request("matcher", params={"temperature": 0, **p}))
            self.assertEqual(res.error["code"], "contract-violation", p)
        self.assertEqual(prov.calls, 0)
        self.assertTrue(gw.call("MATCH", "matcher", "s1", 0, H.request("matcher", params={"temperature": 0})).ok)

    def test_duplicate_call_identity_refused(self):
        gw, _, prov, _ = self.gw()
        self.assertTrue(gw.call("MATCH", "matcher", "s1", 0, H.request("matcher")).ok)
        self.assertEqual(gw.call("MATCH", "matcher", "s1", 0, H.request("matcher")).error["code"], "contract-violation")

    def test_wrong_family_documents_and_cost_kinds(self):
        sc = H.script([("matcher", 0, "response", H.response("matcher"))])
        rid = score_run_id(H.EVR, H.CASE, 0)
        h = H.handle(self.tmp)
        # score profile in the review path, review profile in the score path
        with self.assertRaises(Exception):
            Gateway(mode="disabled", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid)
        review_prof = json.loads((H.EX / "ModelProfile.smoke-synthetic.json").read_text())
        with self.assertRaises(Exception):
            Gateway(mode="disabled", profile=review_prof, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                    family="score", eval_run_id=H.EVR, eval_case_id=H.CASE, repeat=0)
        # D1: cost-family crossing
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="disabled", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                    family="score", cost_kind="eval", eval_run_id=H.EVR, eval_case_id=H.CASE, repeat=0)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="disabled", profile=review_prof, budget=dict(STANDARD_S0A_BUDGET),
                    run_id="run_" + "1" * 16, cost_kind="score")
        # run id must be the derived score id; recorder family must match
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="disabled", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id="run_" + "1" * 16,
                    family="score", eval_run_id=H.EVR, eval_case_id=H.CASE, repeat=0)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="disabled", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid, family="score",
                    recorder=Recorder(rid), eval_run_id=H.EVR, eval_case_id=H.CASE, repeat=0)

    def test_recorders_refuse_the_other_cost_family(self):
        gw, rec, _, _ = self.gw()
        gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        score_cost = [e["record"] for e in rec.events if e["type"] == "cost"][0]
        review = Recorder("run_" + "1" * 16)
        with self.assertRaises(TraceError):
            review.append("cost", record=score_cost)
        review_cost = {**score_cost, "kind": "review"}
        with self.assertRaises(TraceError):
            rec.append("cost", record=review_cost)

    def test_review_recording_refused_by_score_gateway_and_back(self):
        review = review_trace()
        rid = score_run_id(H.EVR2, H.CASE, 0)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=H.PROFILE, budget=dict(STANDARD_S0A_BUDGET), run_id=rid,
                    family="score", replay=review, eval_run_id=H.EVR2, eval_case_id=H.CASE, repeat=0,
                    expected_trace_digest=review.byte_digest)
        _, _, _, tr = self.all_roles()
        review_prof = json.loads((H.EX / "ModelProfile.smoke-synthetic.json").read_text())
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=review_prof, budget=dict(STANDARD_S0A_BUDGET),
                    run_id="run_" + "2" * 16, replay=tr, expected_trace_digest=tr.byte_digest)


class ParamPolicy(Base):
    def seen(self, **params):
        seen = []

        class P:
            def call(self, req, key):
                from reviewer.gateway.providers import ProviderResult
                seen.append(req["params"])
                return ProviderResult(H.response("matcher"), None, "processed")
        gw, _, _, _ = H.live(self.tmp, None, providers={"anthropic": P()})
        res = gw.call("MATCH", "matcher", "s1", 0, H.request("matcher", params={**H.PROFILE["roles"]["matcher"]["params"],
                                                                           **params}))
        return res, seen

    def test_timeout_cap_default_and_lowering(self):
        cap = H.PROFILE["roles"]["matcher"]["caps"]["timeoutSec"]
        res, seen = self.seen()
        self.assertTrue(res.ok)
        self.assertEqual(seen[0]["timeoutSec"], cap)                 # default is the trusted cap, sent to the adapter
        res, seen = self.seen(timeoutSec=30, max_tokens=64)
        self.assertEqual((res.ok, seen[0]["timeoutSec"]), (True, 30))
        for bad in (cap + 1, 0, True, "30", 1.5, 10**6):
            res, seen = self.seen(timeoutSec=bad)
            self.assertEqual((res.error["code"], seen), ("contract-violation", []), bad)

    def test_unlisted_or_changed_params_refused(self):
        for p in ({"temperature": 1}, {"top_p": 0.5}, {"provider_order": ["x"]}, {"endpoint": "u"}, {"api_base": "u"},
                  {"extra_headers": {"a": "b"}}, {"max_price": 1}, {"mcp": 1}, {"openrouter": {}}):
            res, seen = self.seen(**p)
            self.assertEqual((res.error["code"], seen), ("contract-violation", []), p)

    def test_adapter_error_with_review_stage_is_retained_and_recorded(self):
        class P:
            def call(self, req, key):
                from reviewer.gateway.providers import ProviderResult
                return ProviderResult(None, {"code": "provider-timeout", "message": "m", "retryable": True,
                                             "stage": "JUDGE"}, "unknown")
        gw, rec, _, _ = H.live(self.tmp, None, providers={"anthropic": P()})
        res = gw.call("MATCH", "matcher", "s1", 0, H.request("matcher"))
        self.assertNotIn("stage", res.error)
        self.assertEqual(len(gw.retained), 1)
        self.assertEqual(validate_score_trace(rec.events), [])

    def test_report_keysets(self):
        gw, _, _, _ = H.live(self.tmp, H.script([]))
        self.assertIn("family", gw.report())
        from tests.score_gateway.review_equiv import review_report_keys
        self.assertEqual(review_report_keys(), sorted(REVIEW_REPORT_KEYS))


class ProfileParamAllowlist(Base):
    UNSAFE = ("provider_order", "providerOptions", "extra_headers", "api_base", "endpoint", "max_price", "mcp",
              "tool_resources", "openrouter", "base_url_override", "stop", "top_k")

    def build(self, params):
        prof = copy.deepcopy(H.PROFILE)
        prof["roles"]["matcher"]["params"] = params
        return Gateway(mode="disabled", profile=prof, budget=dict(STANDARD_S0A_BUDGET),
                       run_id=score_run_id(H.EVR, H.CASE, 0), family="score", eval_run_id=H.EVR,
                       eval_case_id=H.CASE, repeat=0)

    def test_unsafe_profile_keys_refused_at_construction(self):
        for k in self.UNSAFE:
            with self.assertRaises(GatewayConfigError, msg=k):
                self.build({"temperature": 0, k: "x"})
        for bad in ({"temperature": True}, {"temperature": "0"}, {"seed": {"a": 1}}):
            with self.assertRaises(GatewayConfigError, msg=bad):
                self.build(bad)

    def test_safe_profile_keys_accepted(self):
        self.build({"temperature": 0, "top_p": 0.9, "seed": 7, "max_tokens": 100, "timeoutSec": 60})

    def test_review_gateway_params_not_narrowed(self):
        prof = json.loads((H.EX / "ModelProfile.smoke-synthetic.json").read_text())
        prof["roles"]["investigator"]["params"] = {**prof["roles"]["investigator"]["params"], "provider_order": ["x"]}
        Gateway(mode="disabled", profile=prof, budget=dict(STANDARD_S0A_BUDGET), run_id="run_" + "1" * 16)


REVIEW_REPORT_KEYS = ("mode", "liveCalls", "replayedCalls", "newSpendUsdMicros", "replayedUsdMicros", "retainedCalls",
                      "overruns", "spend", "total", "unconsumedRecordedCalls")


class Script(unittest.TestCase):
    def test_score_script_rules(self):
        ok = {"stage": "MATCH", "role": "matcher", "agentId": "s1", "ordinal": 0, "attempt": 0,
              "response": H.response("matcher")}
        wrap = lambda e: json.dumps({"schemaVersion": 1, "entries": [e]})  # noqa: E731
        parse_script(wrap(ok), family="score")
        for bad in ({**ok, "stage": "EXTRACT"}, {**ok, "stage": "VERIFY", "role": "verifier"},
                    {**ok, "role": "judge"}):
            with self.assertRaises(ScriptError):
                parse_script(wrap(bad), family="score")
        with self.assertRaises(ScriptError):        # review script in the score path
            parse_script(wrap({**ok, "stage": "JUDGE", "role": "judge"}), family="score")
        with self.assertRaises(ScriptError):        # score error with a review stage
            e = {k: v for k, v in ok.items() if k != "response"}
            parse_script(wrap({**e, "error": {"code": "provider-error", "message": "m", "retryable": False,
                                              "stage": "JUDGE"}}), family="score")
        with self.assertRaises(ScriptError):        # score entry in the review parser
            parse_script(wrap(ok))


class Diagnostics(Base):
    def test_sentinel_stays_in_trusted_trace_only(self):
        out = {"candidates": [{"sourceCommentId": H.SENTINEL, "startSegment": 1, "endSegment": 1}]}      # v3: the id is the only model-written string
        sc = H.script([("extractor", 0, "response", H.response("extractor", output=out))])
        gw, rec, _, _ = H.live(self.tmp, sc)
        res = gw.call("EXTRACT", "extractor", "s1", 0, H.request("extractor"))
        self.assertTrue(res.ok)
        rep = json.dumps(gw.report())
        self.assertNotIn(H.SENTINEL, rep)
        self.assertEqual(res.output, out)
        # a damaged trace reports codes, not model text
        evs = copy.deepcopy(rec.events)
        evs[1]["response"]["output"]["candidates"][0]["sourceCommentId"] = H.SENTINEL + "x"
        evs[1]["requestHash"] = "sha256:" + "0" * 64
        with self.assertRaises(TraceError) as cm:
            load_trace(evs)
        self.assertNotIn(H.SENTINEL, str(cm.exception))


class ReviewUnchanged(unittest.TestCase):
    def test_review_record_and_replay_bytes_equal_pre_score_gateway(self):
        self.assertEqual(record_and_replay(), (REVIEW_LIVE_DIGEST, REVIEW_REPLAY_DIGEST))


if __name__ == "__main__":
    unittest.main()
