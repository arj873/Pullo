"""V19 on the benchmark host (the cc tool's path): BenchmarkOptions(impact_version=19) with a claude-cli config plans at the
$10 v19 ceiling; a live launch passes every launch check (the per-Plan ceiling check included), exports the run's PR
snapshot (head and base from the pinned imports, privately, outside home and the repository), hands it to live_terra so
the claude-cli adapter opens agentic, reaches the runner, and removes the snapshot afterwards. Invented fixtures; the
adapter and the runner are stand-ins, so no CLI and no pipeline runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest import mock

from reviewer.config import resolve_config
from reviewer.pilot import benchmark as B
from reviewer.pilot import providers as P
from reviewer.pilot.repository_profile import V19_RUN_CEILING_USD_MICROS
from reviewer.pipeline import PipelineError, agentic

import tests.pilot.test_benchmark_host as TBH
from tests.config.test_claude_cli_integration import SJ_VARIANT, cli_live
from tests.pilot.helpers import AUTH

STOP = "stopped by the test after every launch check"


class V19BenchmarkHost(TBH.Base):
    def setUp(self):
        super().setUp()
        models = resolve_config(SJ_VARIANT).models
        self.w.auth.write_text(json.dumps({**AUTH, "providers": ["claude-cli"],
                                           "models": sorted({models.model(r) for r in ("investigator", "verifier", "judge")}),
                                           "maxUsdMicrosPerRun": V19_RUN_CEILING_USD_MICROS}))
        self.rewrite(baseline={**self.w.baseline_doc, "reviewConfigDigest": models.digest,
                               "authorizationSha256": "sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest()})
        self.seen = []

    def terra(self, profile, ledger, scope, snapshot=None):
        """live_terra stand-in: records what the host hands the adapter while the snapshot exists."""
        info = {"agentic": agentic.is_agentic_profile(profile), "snapshot": snapshot}
        if snapshot is not None:
            info.update(problems=snapshot.problems(), head=Path(snapshot.head), base=Path(snapshot.base),
                        files=sorted(str(p.relative_to(snapshot.head)) for p in Path(snapshot.head).rglob("*")
                                     if p.is_file()))
        self.seen.append(info)
        return P.CliProviders(P.DisabledProvider("openai"), P.DisabledProvider("opencode"), P.DisabledProvider("claude-cli"))

    def launch(self, version):
        specs = []

        def stop(spec):
            specs.append(spec)
            raise PipelineError("config", STOP)
        d, opts = cli_live(self.w, self.tmp, config=str(SJ_VARIANT), impact_version=version)
        with mock.patch.object(B, "live_terra", self.terra):
            rep = B.run_benchmark(opts, key_loader=self.boom, runner=stop)
        return rep, specs

    def test_plan_mode_names_v19_at_its_ten_dollar_ceiling(self):
        rep = B.run_benchmark(self.w.options(config=str(SJ_VARIANT), impact_version=19), key_loader=self.boom)
        self.assertEqual(rep["status"], "planned", rep)
        self.assertEqual(rep["plan"]["runCeilingUsdMicros"], V19_RUN_CEILING_USD_MICROS)
        first = rep["plan"]["firstRequest"]
        self.assertEqual((first["provider"], first["isolationVersion"]), ("claude-cli", "claude-cli-isolated@7"))

    def test_a_v19_live_launch_exports_the_snapshot_opens_agentic_and_cleans_up(self):
        rep, specs = self.launch(19)
        self.assertEqual((rep["status"], rep["error"]["message"], rep["providerCalls"]),
                         ("pipeline-refused", "config: " + STOP, 0), rep)
        (seen,) = self.seen
        self.assertTrue(seen["agentic"])
        self.assertEqual(seen["problems"], [])                                   # a snapshot the adapter accepts
        self.assertIn("src/b.py", seen["files"])                                 # the head files were there
        self.assertFalse(seen["head"].parent.exists())                           # and the private export is gone
        (spec,) = specs
        self.assertTrue(agentic.is_v19_plan(spec.plan))
        self.assertEqual(spec.plan["budget"]["maxUsdMicros"], V19_RUN_CEILING_USD_MICROS)
        self.assertEqual(spec.profile["roles"]["investigator"]["params"]["agentic"], agentic.spec())

    def test_a_v20_launch_is_the_v19_launch_with_the_v20_investigator(self):
        from reviewer.pipeline import prompts
        rep = B.run_benchmark(self.w.options(config=str(SJ_VARIANT), impact_version=20), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["plan"]["runCeilingUsdMicros"]), ("planned", V19_RUN_CEILING_USD_MICROS), rep)
        rep, specs = self.launch(20)
        self.assertEqual((rep["status"], rep["error"]["message"]), ("pipeline-refused", "config: " + STOP), rep)
        (seen,) = self.seen
        self.assertTrue(seen["agentic"])
        self.assertEqual(seen["problems"], [])
        self.assertFalse(seen["head"].parent.exists())
        (spec,) = specs
        self.assertTrue(agentic.is_v19_plan(spec.plan))
        self.assertEqual(spec.plan["budget"]["maxUsdMicros"], V19_RUN_CEILING_USD_MICROS)
        inv = spec.profile["roles"]["investigator"]
        self.assertEqual((inv["promptVersion"], inv["params"]["agentic"]),
                         (prompts.INVESTIGATOR_IMPACT_V20_PROMPT, agentic.spec()))

    def test_a_v21_launch_opens_agentic_with_an_agentic_verifier_at_ten_dollars(self):
        from reviewer.pipeline import dual, prompts
        rep = B.run_benchmark(self.w.options(config=str(SJ_VARIANT), impact_version=21), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["plan"]["runCeilingUsdMicros"]), ("planned", V19_RUN_CEILING_USD_MICROS), rep)
        rep, specs = self.launch(21)
        self.assertEqual((rep["status"], rep["error"]["message"]), ("pipeline-refused", "config: " + STOP), rep)
        (seen,) = self.seen
        self.assertTrue(seen["agentic"])
        self.assertEqual(seen["problems"], [])
        self.assertFalse(seen["head"].parent.exists())
        (spec,) = specs
        self.assertTrue(dual.is_v21_plan(spec.plan))
        self.assertEqual(spec.plan["budget"]["maxUsdMicros"], V19_RUN_CEILING_USD_MICROS)
        roles = spec.profile["roles"]
        self.assertEqual((roles["investigator"]["promptVersion"], roles["investigator"]["params"]["agentic"],
                          roles["verifier"]["params"]["agentic"]),
                         (prompts.INVESTIGATOR_IMPACT_V21_PROMPT, agentic.spec(), dual.verifier_spec()))

    def test_a_v16_launch_opens_the_adapter_exactly_as_before(self):
        rep, specs = self.launch(16)                          # the v16 Plan is 4M, inside the 10M authorization
        self.assertEqual(rep["status"], "pipeline-refused", rep)
        self.assertEqual([(s["agentic"], s["snapshot"]) for s in self.seen], [(False, None)])
