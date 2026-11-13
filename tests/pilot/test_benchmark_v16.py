"""V16 on the benchmark host (the cc tool's path): BenchmarkOptions(impact_version=16) plans the one-reviewer Plan at the
pilot's $4 ceiling and a live launch passes every launch check (the run-ceiling check included) to the runner.
Invented fixtures, fake transport and key only; the live run uses a stub runner, so no pipeline runs."""

from __future__ import annotations

from reviewer.pilot import benchmark as B
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.pipeline import PipelineError, whole

import tests.pilot.test_benchmark_host as TBH

STOP = "stopped by the test after every launch check"


class V16BenchmarkHost(TBH.Base):
    def test_plan_mode_names_the_one_reviewer_at_the_pilot_ceiling(self):
        rep = self.plan(impact_version=16)
        self.assertEqual(rep["status"], "planned")
        self.assertFalse(self.w.out.exists())
        text = repr(rep)
        self.assertIn("investigator.impact@v16", text)
        self.assertEqual(RUN_CEILING_USD_MICROS, 4_000_000)

    def test_a_v16_live_launch_reaches_the_runner(self):
        specs = []

        def stop(spec):
            specs.append(spec)
            raise PipelineError("config", STOP)

        self.w.seed()
        rep = B.run_benchmark(self.w.live_options(impact_version=16), transport=self.model(), key_loader=self.loader,
                              runner=stop)
        self.assertEqual((rep["status"], rep["error"]["message"], rep["providerCalls"]),
                         ("pipeline-refused", "config: " + STOP, 0))
        (spec,) = specs
        self.assertTrue(whole.is_v16_plan(spec.plan))
        self.assertEqual(spec.plan["budget"]["maxUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual(spec.profile["roles"]["investigator"]["promptVersion"], "investigator.impact@v16")
