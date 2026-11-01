"""OPENCODE-FREE-PROVIDER end to end: real config, profile, pipeline and gateway, the REAL OpenCodeFreeProvider over the
in-process fake opencode (tests/runtime/opencode_fake.py) - never the real CLI, never a live call, never a key.

Covers config parsing/report, the profile, the historical pilot refusal, the repository pilot and the benchmark host (root's
review path) with an opencode-only authorization (providers ["opencode"])."""

import hashlib
import json
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from reviewer.config import ConfigError, ReviewModels, parse, resolve_config
from reviewer.contracts import validate
from reviewer.pilot import benchmark as B
from reviewer.pilot import providers as P
from reviewer.pilot import repository as R
from reviewer.pilot.profile import live_profile
from reviewer.pilot.providers import TERRA_LEDGER_NAME
from reviewer.runtime import opencode_cli as O
from reviewer.runtime.catalog import OPENCODE_DEFAULT_MODEL, OPENCODE_PACING_PRICE_VERSION, TERRA_6_MODEL
from tests.pilot import helpers as H
from tests.pilot import test_benchmark_host as BT
from tests.pilot import test_repository as RT
from tests.runtime.opencode_fake import ScriptedRunner

VARIANT = Path(__file__).resolve().parents[2] / "pullo-opencode.toml"
FREE_ONLY = dict(H.AUTH, id="opencode-free-test", providers=["opencode"], models=[OPENCODE_DEFAULT_MODEL])


def scripted_opencode(answers, runners, scenarios=()):
    """A live_terra stand-in: CliProviders with the REAL OpenCodeFreeProvider over the scripted fake CLI."""
    def factory(profile, ledger, scope):
        runner = ScriptedRunner(*scenarios, answers=answers)
        runners.append(runner)
        return P.CliProviders(P.DisabledProvider("openai"), O.OpenCodeFreeProvider(
            enabled=True, ledger=ledger, run_scope=scope, runner=runner, preflight={"supported": True}))
    return factory


def no_cli(*a, **k):
    raise AssertionError("the opencode CLI must not run in plan mode")


def cli_state(root: Path) -> Path:
    """An operator-created CLI-arm state dir: an empty ledger file, nothing else."""
    d = root / "opencode-state"
    d.mkdir()
    (d / TERRA_LEDGER_NAME).write_bytes(b"")
    return d


def cli_live(w, root, **over):
    d = cli_state(root)
    return d, w.live_options(state_dir=str(d), env_file=None, baseline_micros=0, **over)


class ConfigAndProfile(unittest.TestCase):
    def test_variant_binds_every_role_to_the_free_model_and_discloses_billing(self):
        cfg = resolve_config(VARIANT)
        rep = cfg.report()
        self.assertEqual({r: (v["provider"], v["model"]) for r, v in rep["roles"].items()},
                         {r: ("opencode", OPENCODE_DEFAULT_MODEL) for r in ("investigator", "verifier", "judge")})
        self.assertTrue(all(v["isolation"] == "opencode-isolated-home@1" and v["billing"].startswith("free-model")
                            for v in rep["roles"].values()))
        self.assertEqual(cfg.models.providers(), frozenset({"opencode"}))
        self.assertNotIn("investigator_alt", tomllib.loads(VARIANT.read_text())["review"])

    def test_unknown_or_crossed_models_are_refused_without_fallback(self):
        base = 'schema = "pullo-config@1"\n[review.investigator]\nprovider = "%s"\nmodel = "%s"\n'
        for prov, model in (("opencode", "opencode/big-pickle"), ("opencode", TERRA_6_MODEL),
                            ("openai", OPENCODE_DEFAULT_MODEL), ("anthropic", OPENCODE_DEFAULT_MODEL),
                            ("opencode", "openrouter/deepseek/deepseek-v4.1-flash")):
            with self.subTest(prov=prov, model=model), self.assertRaisesRegex(ConfigError, "allowlist"):
                parse(base % (prov, model))
        with self.assertRaisesRegex(ConfigError, "allowlists"):
            ReviewModels.uniform("opencode/beam-free")

    def test_existing_variants_and_digests_are_unchanged(self):
        terra = resolve_config(Path(__file__).resolve().parents[2] / "pullo-terra.toml")
        self.assertEqual(terra.models.provider("investigator"), "openai")
        self.assertEqual(ReviewModels().provider("judge"), "anthropic")
        self.assertNotIn("billing", resolve_config(Path(__file__).resolve().parents[2] / "pullo.toml").report()["roles"]["judge"])

    def test_profile_roles_carry_family_and_the_pacing_price_and_validate(self):
        p = live_profile(models=resolve_config(VARIANT).models)
        self.assertEqual(validate("ModelProfile", p), [])
        for r in p["roles"].values():
            self.assertEqual((r["provider"], r["family"], r["price"]["priceVersion"]),
                             ("opencode", "deepseek", OPENCODE_PACING_PRICE_VERSION))
            self.assertGreater(r["price"]["outputPerMTokUsdMicros"], 0)       # pacing, never $0 reservations


class Routing(unittest.TestCase):
    def profile(self, **over):
        return live_profile(models=ReviewModels(**{"investigator": OPENCODE_DEFAULT_MODEL, "verifier": OPENCODE_DEFAULT_MODEL,
                                                   "judge": OPENCODE_DEFAULT_MODEL, **over}))

    def test_live_arm_and_mixed_refusals(self):
        self.assertEqual(P.live_arm(self.profile()), "terra")                # the CLI-arm state layout
        for judge in (H.SONNET, TERRA_6_MODEL):
            with self.subTest(judge), self.assertRaisesRegex(P.TerraStateError, "mixed"):
                P.live_arm(self.profile(judge=judge))

    def test_live_terra_builds_the_opencode_adapter_and_router_arms_are_unchanged(self):
        built = []

        def factory(**kw):
            built.append(kw)
            return "ADAPTER"
        got = P.live_terra(self.profile(), "LEDGER", "scope", factory=lambda **k: self.fail("no Codex"),
                           opencode_factory=factory)
        self.assertIsInstance(got, P.CliProviders)
        self.assertEqual((got.opencode, got.openai.name), ("ADAPTER", "openai"))
        self.assertEqual(built, [{"enabled": True, "ledger": "LEDGER", "run_scope": "scope",
                                  "models": [OPENCODE_DEFAULT_MODEL]}])
        m = P.ReviewProviders("ROUTER", got).mapping
        self.assertEqual((m["opencode"], m["anthropic"], m["openai"].name), ("ADAPTER", "ROUTER", "openai"))
        router = live_profile(models=ReviewModels())
        self.assertEqual(P.live_terra(router, None, "s").name, "openai")      # still a DisabledProvider
        self.assertEqual(set(P.ReviewProviders("R", P.live_terra(router, None, "s")).mapping),
                         {"anthropic", "openai", "synthetic"})                # mapping exactly as before

    def test_preflight_failure_is_a_typed_config_refusal(self):
        def unsupported(**kw):
            raise O.OpenCodeUnsupported("opencode version is not the pinned 2.1.4")
        with self.assertRaisesRegex(P.PipelineError, "opencode isolation preflight failed"):
            P.live_terra(self.profile(), None, "s", opencode_factory=unsupported)

    def test_plan_capture_records_opencode_facts_in_call_order(self):
        providers, capture = P.plan_providers(self.profile(), None, lambda: self.fail("no OpenRouter"))
        req = {"provider": "opencode", "model": OPENCODE_DEFAULT_MODEL, "role": "verifier", "outputSchema": "VerifierOutput",
               "params": {"maxOutputTokens": 6000}, "messages": [{"role": "user", "content": "x"}]}
        res = providers.mapping["opencode"].call(req, ("VERIFY", "verifier", "v", 0, 0))
        self.assertEqual(res.outcome, "not-sent")
        facts = capture.facts([], lambda r: self.fail("no router facts"))
        self.assertEqual([(f["provider"], f["billingKind"], f["schemaName"]) for f in facts],
                         [("opencode", "free-model", "VerifierOutput")])
        self.assertEqual(P.planned_request(req)["bodySha256"], facts[0]["bodySha256"])
        self.assertEqual(P.worst_case(facts), facts[0]["worstCaseApiEquivalentUsdMicros"])


class HistoricalOpenCode(H.Rig):
    def setUp(self):
        super().setUp()
        self.auth.write_text(json.dumps(dict(H.AUTH, providers=["opencode"], models=[OPENCODE_DEFAULT_MODEL])))

    def test_live_opencode_is_refused_here_and_never_touches_the_cli_or_trial_ledger(self):
        before = (self.state / "runtime-ledger.jsonl").read_bytes() if (self.state / "runtime-ledger.jsonl").exists() else None
        with mock.patch("reviewer.pilot.launcher.live_terra", side_effect=AssertionError("no CLI adapter")):
            code, rep, err = self.run_json(self.argv("--config", str(VARIANT)), key_loader=H.boom_key_loader,
                                           transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertIn("repository/benchmark hosts", json.dumps(rep) + err)
        after = (self.state / "runtime-ledger.jsonl").read_bytes() if (self.state / "runtime-ledger.jsonl").exists() else None
        self.assertEqual(before, after)


class RepositoryOpenCode(RT.Base):
    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(FREE_ONLY))

    def test_plan_pins_the_actual_investigator_turn_without_cli_key_or_openrouter(self):
        before = self.w.state_bytes()
        with mock.patch.object(O, "run_bounded_stream", side_effect=no_cli), \
                mock.patch.object(R, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = R.run_repository(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual(rep["status"], "planned", rep)
        first = rep["plan"]["firstRequest"]
        self.assertEqual((first["provider"], first["model"], first["schemaName"], first["billingKind"]),
                         ("opencode", OPENCODE_DEFAULT_MODEL, "InvestigatorTurn", "free-model"))
        self.assertEqual((first["isolationVersion"], first["cliVersion"]), ("opencode-isolated-home@1", "2.1.4"))
        self.assertRegex(first["configSha256"], "^sha256:[0-9a-f]{64}$")
        self.assertGreater(first["worstCaseApiEquivalentUsdMicros"], 0)
        self.assertEqual(rep["plan"]["worstCaseAdmissionUsdMicros"], first["worstCaseApiEquivalentUsdMicros"])
        self.assertEqual(self.w.state_bytes(), before)
        self.assertFalse(self.w.out.exists())

    def test_live_uses_its_own_cli_state_records_free_rows_and_never_the_trial_state(self):
        runners = []
        model = self.model()
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(R, "live_terra", side_effect=scripted_opencode(model.script, runners)), \
                mock.patch.object(R, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = R.run_repository(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 5), rep)
        self.assertEqual(list(self.w.state.iterdir()), [])                       # no trial state was ever created
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        self.assertEqual([r["type"] for r in rows], ["intent", "result"] * 5)
        res = [r for r in rows if r["type"] == "result"]
        self.assertTrue(all(r["kind"] == "opencode-cli" and r["billingKind"] == "free-model" and r["outcome"] == "processed"
                            and r["costBasis"] == "free-model-zero" and r["model"] == OPENCODE_DEFAULT_MODEL for r in res))
        self.assertTrue(all(r["worstCaseUsdMicros"] == 0 for r in rows if r["type"] == "intent"))
        self.assertEqual(rep["costs"]["runtime"]["thisCase"]["accountable"]["usdMicros"], 0)
        self.assertFalse((d / "terra-spend-book.jsonl").exists() and (d / "terra-spend-book.jsonl").read_bytes())
        seen = runners[0].seen
        self.assertTrue(all(s["argv"][1:4] == ["run", "--standalone", "--format"] and "--auto" not in s["argv"] for s in seen))
        self.assertTrue(all(not any(k.startswith(("OPENROUTER", "OPENAI", "ANTHROPIC")) for k in s["env"]) for s in seen))

    def test_live_mixed_opencode_arm_is_refused_before_state_key_or_cli(self):
        mixed = self.tmp / "mixed.toml"
        mixed.write_text('schema = "pullo-config@1"\n[review.judge]\nprovider = "opencode"\n'
                         f'model = "{OPENCODE_DEFAULT_MODEL}"\n')
        self.w.auth.write_text(json.dumps(dict(RT.AUTH, providers=["anthropic", "opencode"],
                                               models=[RT.SONNET, OPENCODE_DEFAULT_MODEL])))
        self.w.seed()
        before = self.w.state_bytes()
        with mock.patch.object(R, "live_terra", side_effect=AssertionError("no CLI")):
            with self.assertRaisesRegex(R.RepositoryError, "mixed"):
                R.run_repository(self.w.live_options(config=str(mixed)), key_loader=self.boom)
        self.assertEqual(self.w.state_bytes(), before)
        rep = R.run_repository(self.w.options(config=str(mixed)), key_loader=self.boom)   # plan still shows it
        self.assertEqual({v["provider"] for v in rep["plan"]["models"].values()}, {"anthropic", "opencode"})

    def test_an_authorization_without_opencode_refuses_before_any_cli(self):
        self.w.auth.write_text(json.dumps(dict(H.AUTH, providers=["openai"], models=[TERRA_6_MODEL])))
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(R, "live_terra", side_effect=AssertionError("no CLI")):
            with self.assertRaisesRegex(R.RepositoryError, "not authorized"):
                R.run_repository(opts, key_loader=self.boom)
        self.assertEqual((d / TERRA_LEDGER_NAME).read_bytes(), b"")


class BenchmarkOpenCode(BT.Base):
    """Root's review path (reviewer.pilot.benchmark, GATED bytes unchanged) with pullo-opencode.toml."""

    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(FREE_ONLY))
        base = dict(self.w.baseline_doc, reviewConfigDigest=resolve_config(VARIANT).models.digest,
                    authorizationSha256="sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest())
        self.w.write_roots(baseline=base)

    def test_plan_pins_the_free_investigator_first_request(self):
        before = self.w.state_bytes()
        with mock.patch.object(O, "run_bounded_stream", side_effect=no_cli):
            rep = B.run_benchmark(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("plan"))
        p = rep["plan"]
        first = p["firstRequest"]
        self.assertEqual((first["provider"], first["model"], first["role"], first["schemaName"]),
                         ("opencode", OPENCODE_DEFAULT_MODEL, "investigator", "InvestigatorTurn"))
        for k in ("argvSha256", "configSha256", "configTemplateSha256", "instructionsSha256", "envSha256"):
            self.assertRegex(first[k], "^sha256:[0-9a-f]{64}$")
        self.assertTrue(all(f["provider"] == "opencode" for f in p["capturedRequests"]))
        self.assertTrue(all(v["isolation"] == "opencode-isolated-home@1" for v in p["models"].values()))
        self.assertEqual(self.w.state_bytes(), before)

    def test_live_runs_every_role_free_and_the_plan_pin_is_the_actual_stdin_and_config(self):
        plan = B.run_benchmark(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        model, runners = self.model(), []
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_opencode(model.script, runners)), \
                mock.patch.object(B, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 5), rep.get("error"))
        seen = runners[0].seen
        first = plan["plan"]["firstRequest"]
        self.assertEqual(first["bodySha256"], hashlib.sha256(seen[0]["stdin"]).hexdigest())
        self.assertEqual(first["configSha256"],
                         "sha256:" + hashlib.sha256(seen[0]["env"]["OPENCODE_CONFIG_CONTENT"].encode()).hexdigest())
        self.assertEqual(first["argvSha256"], O.argv_digest(seen[0]["argv"]))
        self.assertEqual([s["argv"][s["argv"].index("--model") + 1] for s in seen], [OPENCODE_DEFAULT_MODEL] * 5)
        self.assertEqual(list(self.w.state.iterdir()), [])
        self.assertEqual(len((d / TERRA_LEDGER_NAME).read_text().splitlines()), 10)
        self.assertEqual(self.loads, [])
        self.assertEqual(rep["reviewModels"]["roles"]["judge"]["provider"], "opencode")
        events = [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]
        costs = [e["record"] for e in events if e.get("type") == "cost"]
        self.assertEqual(len(costs), 5)
        self.assertTrue(all(c["provider"] == "opencode" and c["basis"] == "estimated"
                            and c["priceVersion"] == OPENCODE_PACING_PRICE_VERSION for c in costs))

    def test_free_limit_surfaces_the_cli_words_in_the_report_and_ledger(self):
        runners = []
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_opencode([], runners, ["freelimit"])):
            rep = B.run_benchmark(opts, key_loader=self.boom)
        self.assertNotEqual(rep["status"], "completed")
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        res = [r for r in rows if r["type"] == "result"]
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["outcome"], "rejected-before-processing")
        self.assertIn("Free usage limit reached", res[0]["note"])
        trace = Path(rep["paths"]["trace"]).read_text() if rep.get("paths", {}).get("trace") else ""
        self.assertIn("provider.free-limit", trace)
        self.assertIn("FreeUsageLimitError", trace)


if __name__ == "__main__":
    unittest.main()
