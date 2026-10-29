"""TOURNAMENT-V7: BenchmarkOptions(impact_version=7) on the benchmark host. Invented fixtures, fake transport only.

v7 needs `[review.investigator_alt]`: without it the run is refused before ingestion, key, state or output (never a
silent v5); with it the plan captures one first request per lane, the three `.alt` lanes naming the alternate model, and
the report, profile digest and config identity bind the alternate. The authorization must cover the alternate model."""

from __future__ import annotations

import hashlib
import json
import os

from reviewer.config import resolve_config
from reviewer.contracts.canonical import digest
from reviewer.pilot import benchmark as B
from reviewer.pipeline import prompts

import tests.pilot.test_benchmark_host as TBH
from tests.pilot.helpers import AUTH, SONNET

HAIKU = "anthropic/claude-haiku-5.5"
CFG = ('schema = "pullo-config@1"\n' + "".join(f'[review.{r}]\nprovider = "anthropic"\nmodel = "{SONNET}"\n'
                                              for r in ("investigator", "verifier", "judge")))
ALT_CFG = CFG + f'[review.investigator_alt]\nprovider = "anthropic"\nmodel = "{HAIKU}"\n'


class V7Benchmark(TBH.Base):
    def config(self, text, name="v7.toml"):
        d = self.tmp / "cfg"
        d.mkdir(exist_ok=True)
        p = d / name
        p.write_text(text)
        return str(p)

    def auth(self, models):
        p = self.tmp / f"auth-{len(models)}.json"
        p.write_text(json.dumps({**AUTH, "models": models}))
        os.chmod(p, 0o600)
        self.rewrite(baseline={**self.w.baseline_doc,
                               "authorizationSha256": "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()})
        return str(p)

    def test_v7_without_an_alternate_is_refused_before_ingestion(self):
        before = self.w.state_bytes()
        for cfg in (None, self.config(CFG, "plain.toml")):
            with self.subTest(cfg=cfg):
                msg = self.refused(impact_version=7, config=cfg)
                self.assertIn("[review.investigator_alt]", msg)
                with self.assertRaises(B.BenchmarkLaunchError):    # nothing was read: missing inputs are not reached
                    B.run_benchmark(self.w.options(impact_version=7, config=cfg, store=str(self.tmp / "missing"),
                                                   cutoff_proof=str(self.tmp / "missing.json")), key_loader=self.boom)
        self.assertEqual(self.w.state_bytes(), before)
        self.assertEqual(self.loads, [])

    def test_v7_plan_runs_eight_lanes_and_binds_the_alternate(self):
        cfg = self.config(ALT_CFG)
        self.assertEqual(resolve_config(cfg).models.digest, resolve_config().models.digest)   # the baseline still binds
        rep = self.plan(impact_version=7, config=cfg, auth=self.auth([SONNET, HAIKU]))
        p = rep["plan"]
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("unmetGates"))
        self.assertEqual(p["investigator"], {"impactVersion": 7, "promptVersion": "investigator.impact@v7",
                                             "specialists": list(prompts.V7_AGENTS),
                                             "alternateInvestigator": {"provider": "anthropic", "model": HAIKU,
                                                                       "lanes": list(prompts.V7_ALT_AGENTS)}})
        self.assertEqual(p["capturedCount"], 8)                                # one first request per lane
        self.assertEqual([r["model"] for r in p["capturedRequests"]], [SONNET] * 5 + [HAIKU] * 3)
        self.assertEqual(rep["reviewModels"]["alternates"]["investigator"]["model"], HAIKU)
        o = self.w.options(impact_version=7, config=cfg)
        c = resolve_config(cfg)
        profile, plan, policy = B._profile_parts(o, c)
        self.assertEqual(profile["alternates"]["investigator"]["model"], HAIKU)
        self.assertEqual(p["profileDigest"], digest(profile))
        ident = B.config_identity(B.ingest(o, c), profile, plan, policy, True, c)
        self.assertEqual(ident["reviewModelsAlternates"], {"investigator": {"provider": "anthropic", "model": HAIKU}})
        # the v5 identity of the same config carries no alternate
        p5, pl5, pol5 = B._profile_parts(self.w.options(impact_version=5, config=cfg), c)
        self.assertNotIn("alternates", p5)
        self.assertNotIn("reviewModelsAlternates", B.config_identity(B.ingest(o, c), p5, pl5, pol5, True, c))
        self.assertIn("investigator: investigator.impact@v7", B.render(rep))

    def test_an_authorization_without_the_alternate_model_is_plan_failed(self):
        rep = self.plan(impact_version=7, config=self.config(ALT_CFG), auth=self.auth([SONNET]))
        self.assertEqual((rep["status"], rep["ok"], rep["plan"]["capturedCount"]), ("plan-failed", False, 0))
        self.assertIn(f"alternates.investigator: model {HAIKU} not authorized", rep["plan"]["authorization"])
