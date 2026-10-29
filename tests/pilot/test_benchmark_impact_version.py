"""BENCH-IMPACT-VERSION: BenchmarkOptions.impact_version selects the investigator impact version on a benchmark run
without monkeypatching. Invented fixtures, fake transport only: no network, key, state or live call.

Unset (None) and the profile default (2) build the same bytes (profile, Plan, policy, config identity, first request and
whole plan report); 3 selects the specialist investigators (impact@v3 pins); 1 the IMPACT-01 arm; anything else is a
fixed refusal before ingestion, key, state or output."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from unittest import mock

from reviewer.config import resolve_config
from reviewer.contracts.canonical import canonical_json, digest
from reviewer.pilot import benchmark as B
from reviewer.pilot.profile import MODEL
from reviewer.pilot.repository_profile import repository_policy, repository_profile
from reviewer.pipeline import PipelineError, prompts

import tests.pilot.test_benchmark_host as TBH
from tests.verification_context.test_context_check import GOLD, IMPACT_GOLD, IMPACT_V2_GOLD, IMPACT_V3_GOLD


class ImpactVersionOption(TBH.Base):
    def parts(self, **over):
        cfg = resolve_config()
        o = self.w.options(**over)
        profile, plan, policy = B._profile_parts(o, cfg)
        ing = B.ingest(o, cfg)
        return profile, plan, policy, B.config_identity(ing, profile, plan, policy, o.retrieval, cfg, o.experiment)

    def test_unset_and_2_are_byte_identical_to_the_pinned_default(self):
        reps = [self.plan(), self.plan(impact_version=2)]
        self.assertEqual(canonical_json(reps[0]), canonical_json(reps[1]))          # the whole plan report
        for rep in reps:
            p = rep["plan"]
            self.assertEqual((rep["status"], rep["ok"]), ("planned", True))
            self.assertEqual(p["firstRequest"]["bodySha256"], IMPACT_V2_GOLD["benchFirst"])
            self.assertEqual(p["profileDigest"], IMPACT_V2_GOLD["profileOn"])
            self.assertEqual(digest(p["retrievalPolicy"]), IMPACT_V2_GOLD["policy"])
            self.assertEqual(p["investigator"], {"impactVersion": 2, "promptVersion": "investigator.impact@v2",
                                                 "specialists": ["generalist"]})
        unset, two = self.parts(), self.parts(impact_version=2)
        self.assertEqual(canonical_json(unset[0]), canonical_json(two[0]))
        self.assertEqual(canonical_json(unset[1]), canonical_json(two[1]))
        self.assertEqual(unset[2].to_doc(), two[2].to_doc())
        self.assertEqual(digest(unset[1]), GOLD["plan"])
        self.assertEqual(unset[2].digest, IMPACT_V2_GOLD["policy"])
        self.assertEqual(unset[3], two[3])                                           # config identity, key for key
        self.assertNotIn("impactVersion", unset[3])                                  # bound only via the profile
        # the CLI default leaves it unset
        self.assertIsNone(B._parser().parse_args(self.cli_base()).impact_version)

    def test_retrieval_off_default_is_unchanged(self):
        self.assertEqual(self.plan(retrieval=False)["plan"]["firstRequest"]["bodySha256"], GOLD["benchRetrievalOff"])
        self.assertIsNone(self.plan(retrieval=False)["plan"]["investigator"]["impactVersion"])

    def test_3_selects_the_specialist_investigators(self):
        rep = self.plan(impact_version=3)
        p = rep["plan"]
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True))
        self.assertEqual(p["profileDigest"], IMPACT_V3_GOLD["profileOn"])
        self.assertEqual(digest(p["retrievalPolicy"]), IMPACT_V3_GOLD["policy"])
        self.assertEqual(p["firstRequest"]["bodySha256"], IMPACT_V3_GOLD["benchFirst"])
        self.assertEqual(p["capturedCount"], 3)                                      # one first request per specialist
        self.assertEqual(p["investigator"], {"impactVersion": 3, "promptVersion": "investigator.impact@v3",
                                             "specialists": list(prompts.SPECIALIST_AGENTS)})
        profile, plan, policy, ident = self.parts(impact_version=3)
        self.assertEqual(digest(plan), IMPACT_V3_GOLD["plan"])
        self.assertEqual(policy.digest, IMPACT_V3_GOLD["policy"])
        self.assertNotEqual(ident, self.parts()[3])
        self.assertNotEqual(p["configIdentityDigest"], self.plan()["plan"]["configIdentityDigest"])
        self.assertIn("investigator: investigator.impact@v3", B.render(rep))
        # the option equals the earlier monkeypatched route, byte for byte
        prof = lambda *a, **k: repository_profile(*a, **{**k, "impact_version": 3})   # noqa: E731
        pol = lambda *a, **k: repository_policy(*a, **{**k, "impact_version": 3})     # noqa: E731
        with mock.patch.object(B, "repository_profile", prof), mock.patch.object(B, "repository_policy", pol):
            patched = self.plan()
        self.assertEqual(canonical_json(patched), canonical_json(rep))

    def test_4_selects_the_diff_shard_sweeps_and_keeps_the_v3_specialist_bytes(self):
        rep = self.plan(impact_version=4)
        p = rep["plan"]
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True))
        self.assertEqual(p["investigator"], {"impactVersion": 4, "promptVersion": "investigator.impact@v4",
                                             "specialists": list(prompts.SPECIALIST_AGENTS) + ["diff-sweep"]})
        # the fixture's change is tiny (no diff shards): the provider sees exactly the v3 specialist requests
        self.assertEqual(p["firstRequest"]["bodySha256"], IMPACT_V3_GOLD["benchFirst"])
        self.assertEqual(p["capturedCount"], 3)
        profile, plan, policy, ident = self.parts(impact_version=4)
        v3 = self.parts(impact_version=3)
        for a, b in ((digest(profile), IMPACT_V3_GOLD["profileOn"]), (digest(plan), IMPACT_V3_GOLD["plan"]),
                     (policy.digest, IMPACT_V3_GOLD["policy"])):
            self.assertNotEqual(a, b)
        self.assertNotEqual(ident, v3[3])
        self.assertEqual(plan["budget"]["maxToolCalls"], 400)
        self.assertIn("investigator: investigator.impact@v4", B.render(rep))

    def test_1_selects_the_impact01_arm(self):
        p = self.plan(impact_version=1)["plan"]
        self.assertEqual(p["firstRequest"]["bodySha256"], IMPACT_GOLD["benchFirst"])
        self.assertEqual(p["profileDigest"], IMPACT_GOLD["profileOn"])
        self.assertEqual(digest(p["retrievalPolicy"]), IMPACT_GOLD["policy"])

    def test_live_3_and_strict_replay_need_the_same_selection(self):
        from tests.specialist_lanes import lanes

        from tests.pilot.test_repository import Model

        class LaneModel(Model):
            def __call__(self, http_req):
                from reviewer.runtime.openrouter import HttpResponse
                from tests.pilot.test_repository import USAGE
                self.requests.append(http_req)
                body = json.loads(http_req.body)
                self.bodies.append(body)
                d = {"id": f"gen-{len(self.requests)}", "model": MODEL,
                     "provider": "Anthropic", "usage": USAGE,
                     "choices": [{"index": 0, "finish_reason": "stop",
                                  "message": {"role": "assistant", "content": json.dumps(lanes(self).next(body))}}]}
                return HttpResponse(200, {}, json.dumps(d).encode())

        model = LaneModel(self.w.imports["head"].snapshot_id)
        rep, _ = self.live(model, impact_version=3)
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 9))
        tasks = [json.loads(b["messages"][1]["content"])["task"] for b in model.bodies]
        self.assertEqual(tasks[0:6:2], [prompts.investigator_v3_task(a) for a in prompts.SPECIALIST_AGENTS])
        trace, pin = rep["paths"]["trace"], rep["traceDigest"]["value"]
        rr = B.run_benchmark(self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "rp3"), replay_trace=trace,
                                            trace_digest=pin, impact_version=3), key_loader=self.boom)
        self.assertEqual((rr["status"], rr["replay"]["liveCalls"], rr["replay"]["replayedCalls"]), ("completed", 0, 9))
        for over in ({}, {"impact_version": 2}):
            with self.subTest(**over), self.assertRaises(PipelineError):
                B.run_benchmark(self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / f"rpx{len(over)}"),
                                               replay_trace=trace, trace_digest=pin, **over), key_loader=self.boom)

    def test_invalid_versions_are_refused_before_ingestion_key_state_or_output(self):
        before = self.w.state_bytes()
        bad = (0, 5, -1, 99, True, False, 2.0, "2", "v3", [3], 4.0)
        msgs = set()
        for v in bad:
            with self.subTest(v=v):
                msgs.add(self.refused(impact_version=v))
                # refused even when every input path is missing: nothing was read
                with self.assertRaises(B.BenchmarkLaunchError):
                    B.run_benchmark(self.w.options(impact_version=v, store=str(self.tmp / "missing"),
                                                   cutoff_proof=str(self.tmp / "missing.json")), key_loader=self.boom)
        self.assertEqual(msgs, {"impact_version must be one of [1, 2, 3, 4] (or unset for the profile default)"})
        self.assertEqual(self.refused(impact_version=3, retrieval=False),
                         "impact_version needs the retrieval profile (--retrieval on)")
        self.assertEqual(self.w.state_bytes(), before)
        self.w.seed()
        seeded = self.w.state_bytes()
        for over in ({"impact_version": 5}, {"impact_version": True}, {"impact_version": 2, "retrieval": False}):
            with self.subTest(live=over):
                with self.assertRaises(B.BenchmarkLaunchError):
                    B.run_benchmark(self.w.live_options(**over), transport=self.model(), key_loader=self.boom)
                self.assertFalse(self.w.out.exists())
                self.assertEqual(self.w.state_bytes(), seeded)
        self.assertEqual(self.loads, [])

    def cli_base(self):
        return ["--case-url", TBH.URL, "--cutoff-proof", "a", "--admission", "b", "--decision", "c",
                "--launch-baseline", "d", "--store", "e", "--base-import-pins", "f", "--head-import-pins", "g",
                "--out", "h"]

    def test_cli_flag_parses_the_known_versions_and_passes_them_through(self):
        ap = B._parser()
        for v in (1, 2, 3, 4):
            self.assertEqual(ap.parse_args(self.cli_base() + ["--impact-version", str(v)]).impact_version, v)
        for v in ("0", "5", "v3", "two"):
            with self.subTest(v=v), self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                ap.parse_args(self.cli_base() + ["--impact-version", v])
        seen = []

        def capture(o, **_):
            seen.append(o)
            raise B.BenchmarkLaunchError("stop")
        with mock.patch.object(B, "run_benchmark", capture):
            err = io.StringIO()
            self.assertEqual(B.main(self.cli_base(), err=err), 2)
            self.assertEqual(B.main(self.cli_base() + ["--impact-version", "3"], err=err), 2)
        self.assertEqual([o.impact_version for o in seen], [None, 3])
        rep = io.StringIO()
        self.assertIn(B.main(["--case-url", TBH.URL, "--cutoff-proof", str(self.w.proof_path), "--admission",
                              str(self.w.admission_path), "--decision", str(self.w.decision_path), "--launch-baseline",
                              str(self.w.baseline_path), "--store", str(self.w.store), "--base-import-pins",
                              str(self.w.pins["base"]), "--head-import-pins", str(self.w.pins["head"]), "--out",
                              str(self.w.out), "--auth", str(self.w.auth), "--impact-version", "3", "--json"],
                             out=rep, err=io.StringIO(), key_loader=self.boom), (0, 1))
        self.assertEqual(json.loads(rep.getvalue())["plan"]["profileDigest"], IMPACT_V3_GOLD["profileOn"])


if __name__ == "__main__":
    unittest.main()
