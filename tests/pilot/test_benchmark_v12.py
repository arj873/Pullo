"""TOURNAMENT-V12: BenchmarkOptions(impact_version=12) on the benchmark host. Invented fixtures, fake transport only.

v12 runs on the primary investigator model only: even with `[review.investigator_alt]` configured, its profile, report
and config identity carry no alternate, and an authorization for the primary models alone is enough."""

from __future__ import annotations

from reviewer.config import resolve_config
from reviewer.contracts.canonical import digest
from reviewer.pilot import benchmark as B
from reviewer.pipeline import deepcov

import tests.pilot.test_benchmark_host as TBH
import tests.pilot.test_benchmark_v7 as T7
from tests.pilot.helpers import SONNET

ALT_CFG = T7.ALT_CFG


class V12Benchmark(TBH.Base):
    config = T7.V7Benchmark.config
    auth = T7.V7Benchmark.auth

    def test_v12_plan_is_primary_only_and_binds_the_v12_investigator(self):
        cfg = self.config(ALT_CFG)
        rep = self.plan(impact_version=12, config=cfg, auth=self.auth([SONNET]))
        p = rep["plan"]
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("unmetGates"))
        self.assertEqual(p["investigator"]["impactVersion"], 12)
        self.assertEqual(p["investigator"]["promptVersion"], "investigator.impact@v12")
        self.assertEqual(p["investigator"]["specialists"], deepcov.plan_specialists())
        self.assertNotIn("alternateInvestigator", p["investigator"])
        self.assertTrue(p["capturedCount"] >= 1)
        self.assertEqual({r["model"] for r in p["capturedRequests"]}, {SONNET})
        o = self.w.options(impact_version=12, config=cfg)
        c = resolve_config(cfg)
        profile, plan, policy = B._profile_parts(o, c)
        self.assertNotIn("alternates", profile)
        self.assertEqual(p["profileDigest"], digest(profile))
        self.assertTrue(policy.coverage_forced)
        self.assertEqual(plan["specialists"], deepcov.plan_specialists())
        self.assertNotIn("reviewModelsAlternates", B.config_identity(B.ingest(o, c), profile, plan, policy, True, c))
        self.assertIn("investigator: investigator.impact@v12", B.render(rep))
