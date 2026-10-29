"""TERRA-ARM-01 end to end: real config, profile, pipeline and gateway, fake Codex runner - never a live call.

Covers the historical pilot, the repository pilot and the benchmark host (root's review path), with a mixed
authorization and with a Terra-only authorization (providers ["openai"], the realistic separate operator file)."""

import hashlib
import json
from pathlib import Path
from unittest import mock

from reviewer.config import resolve_config
from reviewer.pilot import benchmark as B
from reviewer.pilot import repository as R
from reviewer.pilot.providers import TERRA_LEDGER_NAME
from reviewer.runtime import codex_cli as C
from reviewer.runtime.catalog import TERRA_6_MODEL
from tests.pilot import helpers as H
from tests.pilot import test_benchmark_host as BT
from tests.pilot import test_repository as RT
from tests.runtime.test_codex import events

VARIANT = Path(__file__).resolve().parents[2] / "pullo-terra.toml"
TERRA_ONLY = dict(H.AUTH, id="terra-subscription-test", providers=["openai"], models=[TERRA_6_MODEL])


def scripted_terra(script, seen, *, check=None):
    """A live_terra stand-in: the REAL CodexTerraProvider over a fake runner that answers `script` in order."""
    it = iter(script)

    def factory(profile, ledger, scope):
        def runner(argv, stdin, env, cwd, timeout):
            assert C.check_isolated_home(env["CODEX_HOME"])["supported"]
            if check:
                check(argv, stdin, env)
            seen.append({"argv": argv, "stdin": stdin, "timeout": timeout})
            return C.RunResult(0, events(json.dumps(next(it))), b"")
        return C.CodexTerraProvider(enabled=True, ledger=ledger, run_scope=scope, runner=runner,
                                    preflight={"supported": True})
    return factory


def no_cli(*a, **k):
    raise AssertionError("the Codex CLI must not run in plan mode")


def terra_state(root: Path) -> Path:
    """An operator-created Terra state dir: an empty subscription ledger file, nothing else."""
    d = root / "terra-state"
    d.mkdir()
    (d / TERRA_LEDGER_NAME).write_bytes(b"")
    return d


def terra_live(w, root, **over):
    d = terra_state(root)
    return d, w.live_options(state_dir=str(d), env_file=None, baseline_micros=0, **over)


class HistoricalTerra(H.Rig):
    def setUp(self):
        super().setUp()
        self.auth.write_text(json.dumps(dict(H.AUTH, providers=["anthropic", "openai"], models=[H.SONNET, TERRA_6_MODEL])))

    def test_plan_pins_investigator_without_cli_or_key(self):
        with mock.patch.object(C, "run_bounded", side_effect=no_cli):
            code, rep, err = self.run_json(self.argv("--config", str(VARIANT), live=False), key_loader=H.boom_key_loader)
        self.assertEqual((code, err), (0, ""))
        pin = rep["cases"][0]["plan"]["firstRequests"][0]
        self.assertEqual((pin["provider"], pin["model"], pin["role"]), ("openai", TERRA_6_MODEL, "investigator"))
        self.assertRegex(pin["bodySha256"], "^[0-9a-f]{64}$")

    def test_live_terra_is_refused_here_and_never_touches_the_cli_or_trial_ledger(self):
        """Gate S1: this host's state is the OpenRouter trial state, so it only plans Terra arms."""
        before = (self.state / "runtime-ledger.jsonl").read_bytes() if (self.state / "runtime-ledger.jsonl").exists() else None
        with mock.patch("reviewer.pilot.launcher.live_terra", side_effect=AssertionError("no Terra adapter")):
            code, rep, err = self.run_json(self.argv("--config", str(VARIANT)), key_loader=H.boom_key_loader,
                                           transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertIn("repository/benchmark hosts", json.dumps(rep) + err)
        after = (self.state / "runtime-ledger.jsonl").read_bytes() if (self.state / "runtime-ledger.jsonl").exists() else None
        self.assertEqual(before, after)


class RepositoryTerra(RT.Base):
    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(dict(RT.AUTH, providers=["anthropic", "openai"], models=[RT.SONNET, TERRA_6_MODEL])))

    def test_repository_plan_pins_actual_investigator_turn(self):
        before = self.w.state_bytes()
        with mock.patch.object(C, "run_bounded", side_effect=no_cli):
            rep = R.run_repository(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual(rep["status"], "planned", rep)
        first = rep["plan"]["firstRequest"]
        self.assertEqual((first["provider"], first["model"], first["schemaName"]),
                         ("openai", TERRA_6_MODEL, "InvestigatorTurn"))
        self.assertEqual(first["isolationVersion"], "codex-isolated-home@2")
        self.assertGreater(first["worstCaseApiEquivalentUsdMicros"], 0)
        self.assertEqual(rep["plan"]["worstCaseAdmissionUsdMicros"], first["worstCaseApiEquivalentUsdMicros"])
        self.assertEqual({v["provider"] for v in rep["plan"]["models"].values()}, {"openai"})
        self.assertEqual(self.w.state_bytes(), before)
        self.assertFalse(self.w.out.exists())

    def test_repository_live_uses_its_own_terra_state_and_never_the_trial_state(self):
        self.w.seed()
        trial_before = self.w.state_bytes()
        seen = []
        d, opts = terra_live(self.w, self.tmp, config=str(VARIANT), retrieval=False)
        with mock.patch.object(R, "live_terra", side_effect=scripted_terra([{"hypotheses": []}], seen)):
            rep = R.run_repository(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 1), rep)
        self.assertEqual(self.w.state_bytes(), trial_before)                     # trial ledger/book untouched
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        self.assertEqual([r["type"] for r in rows], ["intent", "result"])
        self.assertEqual(rows[-1]["billingKind"], "subscription-consumption")
        self.assertFalse((d / "terra-spend-book.jsonl").exists() and (d / "terra-spend-book.jsonl").read_bytes())

    def test_terra_live_refuses_the_trial_state_dir_and_a_missing_ledger(self):
        self.w.seed()
        empty = self.tmp / "terra-empty"
        empty.mkdir()
        for state, why in ((str(self.w.state), "OpenRouter trial state"), (str(empty), "lacks the operator-created")):
            with self.subTest(why), mock.patch.object(R, "live_terra", side_effect=AssertionError("no CLI")):
                with self.assertRaisesRegex(R.RepositoryError, why):
                    R.run_repository(self.w.live_options(config=str(VARIANT), state_dir=state, env_file=None,
                                                         baseline_micros=0), key_loader=self.boom)
        self.assertFalse(self.w.out.exists())

    def test_live_mixed_arm_is_refused_before_state_key_or_cli(self):
        mixed = self.tmp / "mixed.toml"
        mixed.write_text('schema = "pullo-config@1"\n[review.judge]\nprovider = "openai"\nmodel = "gpt-6.1-terra"\n')
        self.w.seed()
        before = self.w.state_bytes()
        with mock.patch.object(R, "live_terra", side_effect=AssertionError("no CLI")):
            with self.assertRaisesRegex(R.RepositoryError, "mixed"):
                R.run_repository(self.w.live_options(config=str(mixed)), key_loader=self.boom)
        self.assertEqual(self.w.state_bytes(), before)
        rep = R.run_repository(self.w.options(config=str(mixed)), key_loader=self.boom)   # plan still shows it
        self.assertEqual({v["provider"] for v in rep["plan"]["models"].values()}, {"anthropic", "openai"})


class RepositoryTerraOnlyAuthorization(RT.Base):
    """The realistic operator setup: a separate authorization that names only openai + gpt-6.1-terra."""

    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(TERRA_ONLY))

    def test_plan_needs_no_anthropic_authorization_and_builds_no_openrouter_provider(self):
        with mock.patch.object(C, "run_bounded", side_effect=no_cli), \
                mock.patch.object(R, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = R.run_repository(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual(rep["status"], "planned", rep)
        self.assertEqual(rep["plan"]["firstRequest"]["provider"], "openai")

    def test_live_reads_no_key_and_records_only_in_the_terra_ledger(self):
        seen = []
        model = self.model()
        d, opts = terra_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(R, "live_terra", side_effect=scripted_terra(model.script, seen)), \
                mock.patch.object(R, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = R.run_repository(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 5), rep)
        self.assertEqual(rep["costs"]["runtime"]["ledgerCalls"]["thisCase"], 5)
        self.assertEqual(rep["costs"]["runtime"]["thisCase"]["accountable"]["usdMicros"], 0)
        self.assertEqual(list(self.w.state.iterdir()), [])                       # no trial state was ever created


class BenchmarkTerra(BT.Base):
    """Root's review path (reviewer.pilot.benchmark) with pullo-terra.toml and a Terra-only authorization."""

    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(TERRA_ONLY))
        base = dict(self.w.baseline_doc, reviewConfigDigest=resolve_config(VARIANT).models.digest,
                    authorizationSha256="sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest())
        self.w.write_roots(baseline=base)

    def test_plan_pins_the_terra_investigator_first_request_and_shows_role_providers(self):
        before = self.w.state_bytes()
        with mock.patch.object(C, "run_bounded", side_effect=no_cli):
            rep = B.run_benchmark(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("plan"))
        p = rep["plan"]
        first = p["firstRequest"]
        self.assertEqual((first["provider"], first["model"], first["role"], first["schemaName"]),
                         ("openai", TERRA_6_MODEL, "investigator", "InvestigatorTurn"))
        for k in ("bodySha256", "schemaSha256"):
            self.assertRegex(first[k], "^[0-9a-f]{64}$")
        for k in ("argvSha256", "configSha256", "instructionsSha256"):
            self.assertRegex(first[k], "^sha256:[0-9a-f]{64}$")
        self.assertEqual({r: v["provider"] for r, v in p["models"].items()},
                         {"investigator": "openai", "verifier": "openai", "judge": "openai"})
        self.assertTrue(all(v["isolation"] == "codex-isolated-home@2" for v in p["models"].values()))
        self.assertIn("Terra arm", p["firstRequestNote"])
        self.assertEqual(self.w.state_bytes(), before)

    def test_live_runs_every_role_on_terra_and_the_plan_pin_is_the_actual_stdin(self):
        plan = B.run_benchmark(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertIn("Terra state dir", " ".join(plan["unmetGates"]))
        model, seen = self.model(), []
        d, opts = terra_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_terra(model.script, seen)), \
                mock.patch.object(B, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 5), rep.get("error"))
        self.assertEqual(plan["plan"]["firstRequest"]["bodySha256"], hashlib.sha256(seen[0]["stdin"]).hexdigest())
        self.assertEqual([s["argv"][s["argv"].index("--model") + 1] for s in seen], [TERRA_6_MODEL] * 5)
        self.assertEqual(list(self.w.state.iterdir()), [])
        self.assertEqual(len((d / TERRA_LEDGER_NAME).read_text().splitlines()), 10)
        self.assertEqual(self.loads, [])
        self.assertEqual(rep["reviewModels"]["roles"]["judge"]["provider"], "openai")

    def test_isolation_preflight_failure_refuses_before_any_output(self):
        def unsupported(profile, ledger, scope):
            raise R.PipelineError("config", "Terra isolation preflight failed: test")
        d, opts = terra_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=unsupported):
            with self.assertRaises(R.PipelineError):
                B.run_benchmark(opts, key_loader=self.boom)
        self.assertFalse(self.w.out.exists())
