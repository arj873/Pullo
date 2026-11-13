"""TOURNAMENT-V10: BenchmarkOptions(impact_version=10) on the benchmark host. Invented fixtures, fake transport only.

v10 needs `[review.investigator_alt]`: without it the run is refused before ingestion, key, state or output (never a
silent v3); with it the plan captures one first request per lane, the three `.alt` lanes naming the alternate model, and
the report, profile digest and config identity bind the alternate. The authorization must cover the alternate model."""

from __future__ import annotations

from reviewer.config import resolve_config
from reviewer.contracts.canonical import digest
from reviewer.pilot import benchmark as B
from reviewer.pipeline import prompts

import tests.pilot.test_benchmark_host as TBH
import tests.pilot.test_benchmark_v7 as T7
from tests.pilot.helpers import SONNET

ALT_CFG, CFG, HAIKU = T7.ALT_CFG, T7.CFG, T7.HAIKU


class V10Benchmark(TBH.Base):
    config = T7.V7Benchmark.config          # the v7 helpers only (its tests stay in their own module)
    auth = T7.V7Benchmark.auth

    def test_v10_without_an_alternate_is_refused_before_ingestion(self):
        before = self.w.state_bytes()
        for cfg in (None, self.config(CFG, "plain.toml")):
            with self.subTest(cfg=cfg):
                msg = self.refused(impact_version=10, config=cfg)
                self.assertIn("[review.investigator_alt]", msg)
                self.assertIn("v10 never runs as the v3 specialists alone", msg)
                with self.assertRaises(B.BenchmarkLaunchError):    # nothing was read: missing inputs are not reached
                    B.run_benchmark(self.w.options(impact_version=10, config=cfg, store=str(self.tmp / "missing"),
                                                   cutoff_proof=str(self.tmp / "missing.json")), key_loader=self.boom)
        self.assertEqual(self.w.state_bytes(), before)
        self.assertEqual(self.loads, [])

    def test_v10_plan_runs_six_lanes_and_binds_the_alternate(self):
        cfg = self.config(ALT_CFG)
        rep = self.plan(impact_version=10, config=cfg, auth=self.auth([SONNET, HAIKU]))
        p = rep["plan"]
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("unmetGates"))
        self.assertEqual(p["investigator"], {"impactVersion": 10, "promptVersion": "investigator.impact@v10",
                                             "specialists": list(prompts.V10_AGENTS),
                                             "alternateInvestigator": {"provider": "anthropic", "model": HAIKU,
                                                                       "lanes": list(prompts.V10_ALT_AGENTS)}})
        self.assertEqual(p["capturedCount"], 6)                                # one first request per lane
        self.assertEqual([r["model"] for r in p["capturedRequests"]], [SONNET] * 3 + [HAIKU] * 3)
        self.assertEqual(rep["reviewModels"]["alternates"]["investigator"]["model"], HAIKU)
        o = self.w.options(impact_version=10, config=cfg)
        c = resolve_config(cfg)
        profile, plan, policy = B._profile_parts(o, c)
        self.assertEqual(profile["alternates"]["investigator"]["model"], HAIKU)
        self.assertEqual(p["profileDigest"], digest(profile))
        ident = B.config_identity(B.ingest(o, c), profile, plan, policy, True, c)
        self.assertEqual(ident["reviewModelsAlternates"], {"investigator": {"provider": "anthropic", "model": HAIKU}})
        # the v3 identity of the same config carries no alternate
        p3, pl3, pol3 = B._profile_parts(self.w.options(impact_version=3, config=cfg), c)
        self.assertNotIn("alternates", p3)
        self.assertNotIn("reviewModelsAlternates", B.config_identity(B.ingest(o, c), p3, pl3, pol3, True, c))
        self.assertIn("investigator: investigator.impact@v10", B.render(rep))

    def test_a_v10_authorization_without_the_alternate_model_is_plan_failed(self):
        rep = self.plan(impact_version=10, config=self.config(ALT_CFG), auth=self.auth([SONNET]))
        self.assertEqual((rep["status"], rep["ok"], rep["plan"]["capturedCount"]), ("plan-failed", False, 0))
        self.assertIn(f"alternates.investigator: model {HAIKU} not authorized", rep["plan"]["authorization"])
