"""CLAUDE-CLI-PROVIDER end to end: real config, profile, pipeline and gateway, the REAL ClaudeCliProvider over the in-process
fake claude (tests/runtime/claude_fake.py) - never the real CLI, never a live call, never a credential (a dummy token).

Covers config parsing/report, the profile, the historical pilot refusal, the repository pilot and the benchmark host (root's
review path) with a claude-cli-only authorization (providers ["claude-cli"])."""

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
from reviewer.runtime import claude_cli as O
from reviewer.runtime.catalog import (CLAUDE_CLI_DEFAULT_MODEL, CLAUDE_CLI_PRICE_VERSION, OPENCODE_DEFAULT_MODEL,
                                      TERRA_6_MODEL)
from tests.pilot import helpers as H
from tests.pilot import test_benchmark_host as BT
from tests.pilot import test_repository as RT
from tests.runtime.claude_fake import DUMMY_TOKEN, OPUS, ScriptedRunner, dummy_token

VARIANT = Path(__file__).resolve().parents[2] / "pullo-claude-cli.toml"
OPUS_VARIANT = Path(__file__).resolve().parents[2] / "pullo-claude-cli-opus.toml"
SJ_VARIANT = Path(__file__).resolve().parents[2] / "pullo-claude-cli-sj.toml"      # the PRIMARY arm: Sonnet roles + Opus judge
SJ_ROLES = {"investigator": CLAUDE_CLI_DEFAULT_MODEL, "verifier": CLAUDE_CLI_DEFAULT_MODEL, "judge": OPUS}
MODEL = CLAUDE_CLI_DEFAULT_MODEL
SUB_ONLY = dict(H.AUTH, id="claude-cli-test", providers=["claude-cli"], models=[MODEL])


def scripted_claude(answers, runners, scenarios=()):
    """A live_terra stand-in: CliProviders with the REAL ClaudeCliProvider over the scripted fake CLI."""
    def factory(profile, ledger, scope):
        runner = ScriptedRunner(*scenarios, answers=answers)
        runners.append(runner)
        return P.CliProviders(P.DisabledProvider("openai"), P.DisabledProvider("opencode"), O.ClaudeCliProvider(
            enabled=True, ledger=ledger, run_scope=scope, runner=runner, preflight={"supported": True},
            token_loader=dummy_token))
    return factory


def no_cli(*a, **k):
    raise AssertionError("the claude CLI must not run in plan mode")


def cli_state(root: Path) -> Path:
    """An operator-created CLI-arm state dir: an empty ledger file, nothing else."""
    d = root / "claude-cli-state"
    d.mkdir()
    (d / TERRA_LEDGER_NAME).write_bytes(b"")
    return d


def cli_live(w, root, **over):
    d = cli_state(root)
    return d, w.live_options(state_dir=str(d), env_file=None, baseline_micros=0, **over)


class ConfigAndProfile(unittest.TestCase):
    def test_variants_bind_every_role_to_one_claude_cli_model_and_disclose_billing(self):
        for path, model in ((VARIANT, MODEL), (OPUS_VARIANT, OPUS)):
            cfg = resolve_config(path)
            rep = cfg.report()
            self.assertEqual({r: (v["provider"], v["model"]) for r, v in rep["roles"].items()},
                             {r: ("claude-cli", model) for r in ("investigator", "verifier", "judge")})
            self.assertTrue(all(v["isolation"] == "claude-cli-isolated@1"
                                and v["billing"] == "claude-subscription ($0; pacing estimate at Terra-6 list rates, not money)"
                                for v in rep["roles"].values()))
            self.assertEqual(cfg.models.providers(), frozenset({"claude-cli"}))
            self.assertNotIn("investigator_alt", tomllib.loads(path.read_text())["review"])
        self.assertNotEqual(resolve_config(VARIANT).models.digest, resolve_config(OPUS_VARIANT).models.digest)

    def test_primary_variant_binds_sonnet_roles_and_an_opus_judge_and_no_haiku(self):
        cfg = resolve_config(SJ_VARIANT)
        rep = cfg.report()
        self.assertEqual({r: (v["provider"], v["model"]) for r, v in rep["roles"].items()},
                         {r: ("claude-cli", m) for r, m in SJ_ROLES.items()})
        self.assertEqual(cfg.models.providers(), frozenset({"claude-cli"}))
        self.assertEqual(len({resolve_config(v).models.digest for v in (VARIANT, OPUS_VARIANT, SJ_VARIANT)}), 3)
        p = live_profile(models=cfg.models)
        self.assertEqual(validate("ModelProfile", p), [])
        self.assertEqual({r: v["model"] for r, v in p["roles"].items()}, SJ_ROLES)
        root = Path(__file__).resolve().parents[2]
        for f in ("pullo-claude-cli.toml", "pullo-claude-cli-opus.toml", "pullo-claude-cli-sj.toml"):
            self.assertNotIn("haiku", (root / f).read_text().split("schema =", 1)[1].lower())
        self.assertFalse(any("haiku" in m for m in O.CLAUDE_CLI_MODELS))
        self.assertEqual(P.live_arm(p), "terra")
        built = []
        got = P.live_terra(p, "LEDGER", "scope", claude_factory=lambda **kw: built.append(kw) or "ADAPTER")
        self.assertEqual((got.claude, built[0]["models"]), ("ADAPTER", sorted({CLAUDE_CLI_DEFAULT_MODEL, OPUS})))

    def test_unknown_or_crossed_models_are_refused_without_fallback(self):
        base = 'schema = "pullo-config@1"\n[review.investigator]\nprovider = "%s"\nmodel = "%s"\n'
        for prov, model in (("claude-cli", "claude-opus-5-5"), ("claude-cli", "claude-cli/claude-haiku-5-5"),
                            ("claude-cli", "anthropic/claude-sonnet-5.5"), ("anthropic", MODEL), ("openai", MODEL),
                            ("opencode", MODEL), ("claude-cli", OPENCODE_DEFAULT_MODEL), ("claude-cli", TERRA_6_MODEL)):
            with self.subTest(prov=prov, model=model), self.assertRaisesRegex(ConfigError, "allowlist"):
                parse(base % (prov, model))
        with self.assertRaisesRegex(ConfigError, "allowlists"):
            ReviewModels.uniform("claude-sonnet-5-5")

    def test_existing_variants_and_digests_are_unchanged(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(resolve_config(root / "pullo-terra.toml").models.provider("investigator"), "openai")
        self.assertEqual(resolve_config(root / "pullo-opencode.toml").models.provider("judge"), "opencode")
        self.assertEqual(ReviewModels().provider("judge"), "anthropic")
        self.assertNotIn("billing", resolve_config(root / "pullo.toml").report()["roles"]["judge"])

    def test_profile_roles_carry_the_claude_family_and_the_list_price_and_validate(self):
        for path in (VARIANT, OPUS_VARIANT):
            p = live_profile(models=resolve_config(path).models)
            self.assertEqual(validate("ModelProfile", p), [])
            for r in p["roles"].values():
                self.assertEqual((r["provider"], r["family"], r["price"]["priceVersion"]),
                                 ("claude-cli", "claude", CLAUDE_CLI_PRICE_VERSION))
                self.assertGreater(r["price"]["outputPerMTokUsdMicros"], 0)    # pacing, never $0 reservations
            terra = live_profile(models=resolve_config(Path(__file__).resolve().parents[2] / "pullo-terra.toml").models)
            oc = live_profile(models=resolve_config(Path(__file__).resolve().parents[2] / "pullo-opencode.toml").models)
            strip = lambda pr: {k: v for k, v in pr.items() if k != "priceVersion"}            # noqa: E731
            self.assertEqual({strip(r["price"]) == strip(oc["roles"][n]["price"]) == strip(terra["roles"][n]["price"])
                              for n, r in p["roles"].items()}, {True})               # the same pacing as Terra-6 and opencode


class Routing(unittest.TestCase):
    def profile(self, **over):
        return live_profile(models=ReviewModels(**{"investigator": MODEL, "verifier": MODEL, "judge": MODEL, **over}))

    def test_live_arm_and_mixed_refusals(self):
        self.assertEqual(P.live_arm(self.profile()), "terra")                # the CLI-arm state layout
        for judge in (H.SONNET, TERRA_6_MODEL, OPENCODE_DEFAULT_MODEL):
            with self.subTest(judge), self.assertRaisesRegex(P.TerraStateError, "mixed"):
                P.live_arm(self.profile(judge=judge))
        with self.assertRaisesRegex(P.PipelineError, "mixed"):
            P.live_terra(self.profile(judge=OPENCODE_DEFAULT_MODEL), None, "s", claude_factory=lambda **k: self.fail("x"))

    def test_live_terra_builds_the_claude_cli_adapter_and_other_arms_are_unchanged(self):
        built = []

        def factory(**kw):
            built.append(kw)
            return "ADAPTER"
        got = P.live_terra(self.profile(investigator=OPUS), "LEDGER", "scope", factory=lambda **k: self.fail("no Codex"),
                           opencode_factory=lambda **k: self.fail("no opencode"), claude_factory=factory)
        self.assertIsInstance(got, P.CliProviders)
        self.assertEqual((got.claude, got.openai.name, got.opencode.name), ("ADAPTER", "openai", "opencode"))
        self.assertEqual(built, [{"enabled": True, "ledger": "LEDGER", "run_scope": "scope", "models": sorted([MODEL, OPUS])}])
        m = P.ReviewProviders("ROUTER", got).mapping
        self.assertEqual((m["claude-cli"], m["anthropic"], m["openai"].name, m["opencode"].name),
                         ("ADAPTER", "ROUTER", "openai", "opencode"))
        router = live_profile(models=ReviewModels())
        self.assertEqual(set(P.ReviewProviders("R", P.live_terra(router, None, "s")).mapping),
                         {"anthropic", "openai", "synthetic"})                # mapping exactly as before
        oc = live_profile(models=ReviewModels.uniform(OPENCODE_DEFAULT_MODEL))
        got = P.live_terra(oc, None, "s", opencode_factory=lambda **k: "OC", claude_factory=lambda **k: self.fail("x"))
        self.assertEqual(set(P.ReviewProviders("R", got).mapping), {"anthropic", "openai", "synthetic", "opencode"})

    def test_preflight_failure_is_a_typed_config_refusal(self):
        def unsupported(**kw):
            raise O.ClaudeCliUnsupported("claude version is not the pinned 2.1.309")
        with self.assertRaisesRegex(P.PipelineError, "claude-cli isolation preflight failed"):
            P.live_terra(self.profile(), None, "s", claude_factory=unsupported)

    def test_plan_capture_records_claude_cli_facts_in_call_order(self):
        providers, capture = P.plan_providers(self.profile(), None, lambda: self.fail("no OpenRouter"))
        req = {"provider": "claude-cli", "model": MODEL, "role": "verifier", "outputSchema": "VerifierOutput",
               "params": {"maxOutputTokens": 6000}, "messages": [{"role": "user", "content": "x"}]}
        res = providers.mapping["claude-cli"].call(req, ("VERIFY", "verifier", "v", 0, 0))
        self.assertEqual(res.outcome, "not-sent")
        self.assertEqual(providers.mapping["opencode"].name, "opencode")         # disabled
        facts = capture.facts([], lambda r: self.fail("no router facts"))
        self.assertEqual([(f["provider"], f["billingKind"], f["schemaName"]) for f in facts],
                         [("claude-cli", "claude-subscription", "VerifierOutput")])
        self.assertEqual(P.planned_request(req)["bodySha256"], facts[0]["bodySha256"])
        self.assertEqual(P.worst_case(facts), facts[0]["worstCaseApiEquivalentUsdMicros"])


class HistoricalClaudeCli(H.Rig):
    def setUp(self):
        super().setUp()
        self.auth.write_text(json.dumps(dict(H.AUTH, providers=["claude-cli"], models=[MODEL])))

    def test_live_claude_cli_is_refused_here_and_never_touches_the_cli_or_trial_ledger(self):
        before = (self.state / "runtime-ledger.jsonl").read_bytes() if (self.state / "runtime-ledger.jsonl").exists() else None
        with mock.patch("reviewer.pilot.launcher.live_terra", side_effect=AssertionError("no CLI adapter")):
            code, rep, err = self.run_json(self.argv("--config", str(VARIANT)), key_loader=H.boom_key_loader,
                                           transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertIn("repository/benchmark hosts", json.dumps(rep) + err)
        after = (self.state / "runtime-ledger.jsonl").read_bytes() if (self.state / "runtime-ledger.jsonl").exists() else None
        self.assertEqual(before, after)


class RepositoryClaudeCli(RT.Base):
    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(SUB_ONLY))

    def test_plan_pins_the_actual_investigator_turn_without_cli_key_or_openrouter(self):
        before = self.w.state_bytes()
        with mock.patch.object(O, "run_bounded_stream", side_effect=no_cli), \
                mock.patch.object(R, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = R.run_repository(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual(rep["status"], "planned", rep)
        first = rep["plan"]["firstRequest"]
        self.assertEqual((first["provider"], first["model"], first["schemaName"], first["billingKind"]),
                         ("claude-cli", MODEL, "InvestigatorTurn", "claude-subscription"))
        self.assertEqual((first["isolationVersion"], first["cliVersion"]), ("claude-cli-isolated@1", "2.1.309"))
        self.assertGreater(first["worstCaseApiEquivalentUsdMicros"], 0)
        self.assertEqual(rep["plan"]["worstCaseAdmissionUsdMicros"], first["worstCaseApiEquivalentUsdMicros"])
        self.assertEqual(self.w.state_bytes(), before)
        self.assertFalse(self.w.out.exists())

    def test_live_uses_its_own_cli_state_records_subscription_rows_and_never_the_trial_state(self):
        runners = []
        model = self.model()
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(R, "live_terra", side_effect=scripted_claude(model.script, runners)), \
                mock.patch.object(R, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = R.run_repository(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 5), rep)
        self.assertEqual(list(self.w.state.iterdir()), [])                       # no trial state was ever created
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        self.assertEqual([r["type"] for r in rows], ["intent", "result"] * 5)
        res = [r for r in rows if r["type"] == "result"]
        self.assertTrue(all(r["kind"] == "claude-cli" and r["billingKind"] == "claude-subscription"
                            and r["outcome"] == "processed" and r["costBasis"] == "claude-subscription-zero"
                            and r["model"] == MODEL for r in res))
        self.assertTrue(all(r["worstCaseUsdMicros"] == 0 for r in rows if r["type"] == "intent"))
        self.assertEqual(rep["costs"]["runtime"]["thisCase"]["accountable"]["usdMicros"], 0)
        seen = runners[0].seen
        self.assertTrue(all(O.split_sandbox(s["argv"])[1] == O.build_argv("claude", MODEL)
                            and O.split_sandbox(s["argv"])[0] is not None for s in seen))
        self.assertTrue(all(not any(k.startswith(("OPENROUTER", "OPENAI", "ANTHROPIC")) for k in s["env"]) for s in seen))
        self.assertNotIn(DUMMY_TOKEN, (d / TERRA_LEDGER_NAME).read_text())

    def test_live_mixed_claude_cli_arm_is_refused_before_state_key_or_cli(self):
        mixed = self.tmp / "mixed.toml"
        mixed.write_text(f'schema = "pullo-config@1"\n[review.judge]\nprovider = "claude-cli"\nmodel = "{MODEL}"\n')
        self.w.auth.write_text(json.dumps(dict(RT.AUTH, providers=["anthropic", "claude-cli"], models=[RT.SONNET, MODEL])))
        self.w.seed()
        before = self.w.state_bytes()
        with mock.patch.object(R, "live_terra", side_effect=AssertionError("no CLI")):
            with self.assertRaisesRegex(R.RepositoryError, "mixed"):
                R.run_repository(self.w.live_options(config=str(mixed)), key_loader=self.boom)
        self.assertEqual(self.w.state_bytes(), before)
        rep = R.run_repository(self.w.options(config=str(mixed)), key_loader=self.boom)   # plan still shows it
        self.assertEqual({v["provider"] for v in rep["plan"]["models"].values()}, {"anthropic", "claude-cli"})

    def test_an_authorization_without_claude_cli_refuses_before_any_cli(self):
        self.w.auth.write_text(json.dumps(dict(H.AUTH, providers=["opencode"], models=[OPENCODE_DEFAULT_MODEL])))
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(R, "live_terra", side_effect=AssertionError("no CLI")):
            with self.assertRaisesRegex(R.RepositoryError, "not authorized"):
                R.run_repository(opts, key_loader=self.boom)
        self.assertEqual((d / TERRA_LEDGER_NAME).read_bytes(), b"")


class BenchmarkClaudeCli(BT.Base):
    """Root's review path (reviewer.pilot.benchmark, GATED bytes unchanged) with pullo-claude-cli.toml."""

    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(SUB_ONLY))
        base = dict(self.w.baseline_doc, reviewConfigDigest=resolve_config(VARIANT).models.digest,
                    authorizationSha256="sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest())
        self.w.write_roots(baseline=base)

    def test_plan_pins_the_subscription_investigator_first_request(self):
        before = self.w.state_bytes()
        with mock.patch.object(O, "run_bounded_stream", side_effect=no_cli):
            rep = B.run_benchmark(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("plan"))
        p = rep["plan"]
        first = p["firstRequest"]
        self.assertEqual((first["provider"], first["model"], first["role"], first["schemaName"]),
                         ("claude-cli", MODEL, "investigator", "InvestigatorTurn"))
        for k in ("argvSha256", "instructionsSha256", "envSha256", "sandboxSha256"):
            self.assertRegex(first[k], "^sha256:[0-9a-f]{64}$")
        self.assertTrue(all(f["provider"] == "claude-cli" for f in p["capturedRequests"]))
        self.assertTrue(all(v["isolation"] == "claude-cli-isolated@1" for v in p["models"].values()))
        self.assertEqual(self.w.state_bytes(), before)

    def test_live_runs_every_role_on_the_subscription_and_the_plan_pin_is_the_actual_stdin(self):
        plan = B.run_benchmark(self.w.options(config=str(VARIANT)), key_loader=self.boom)
        model, runners = self.model(), []
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_claude(model.script, runners)), \
                mock.patch.object(B, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 5), rep.get("error"))
        seen = runners[0].seen
        first = plan["plan"]["firstRequest"]
        self.assertEqual(first["bodySha256"], hashlib.sha256(seen[0]["stdin"]).hexdigest())
        self.assertEqual(first["argvSha256"], O.argv_digest(O.split_sandbox(seen[0]["argv"])[1]))
        self.assertEqual([s["argv"][s["argv"].index("--model") + 1] for s in seen], ["claude-sonnet-5-5"] * 5)
        self.assertEqual(list(self.w.state.iterdir()), [])
        self.assertEqual(len((d / TERRA_LEDGER_NAME).read_text().splitlines()), 10)
        self.assertEqual(self.loads, [])
        self.assertEqual(rep["reviewModels"]["roles"]["judge"]["provider"], "claude-cli")
        events = [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]
        costs = [e["record"] for e in events if e.get("type") == "cost"]
        self.assertEqual(len(costs), 5)
        self.assertTrue(all(c["provider"] == "claude-cli" and c["basis"] == "estimated"
                            and c["priceVersion"] == CLAUDE_CLI_PRICE_VERSION for c in costs))

    def test_primary_sonnet_opus_judge_arm_plans_and_runs_each_role_on_its_model(self):
        self.w.auth.write_text(json.dumps(dict(SUB_ONLY, models=sorted(set(SJ_ROLES.values())))))
        base = dict(self.w.baseline_doc, reviewConfigDigest=resolve_config(SJ_VARIANT).models.digest,
                    authorizationSha256="sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest())
        self.w.write_roots(baseline=base)
        with mock.patch.object(O, "run_bounded_stream", side_effect=no_cli):
            plan = B.run_benchmark(self.w.options(config=str(SJ_VARIANT)), key_loader=self.boom)
        self.assertEqual((plan["status"], plan["ok"]), ("planned", True), plan.get("plan"))
        self.assertEqual({r: v["model"] for r, v in plan["plan"]["models"].items()}, SJ_ROLES)
        self.assertTrue(all(f["model"] == SJ_ROLES[f["role"]] for f in plan["plan"]["capturedRequests"]))
        model, runners = self.model(), []
        d, opts = cli_live(self.w, self.tmp, config=str(SJ_VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_claude(model.script, runners)):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"]), ("completed", True), rep.get("error"))
        self.assertEqual({r: v["model"] for r, v in rep["reviewModels"]["roles"].items()}, SJ_ROLES)
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        roles = {(r["callKey"].rsplit("|", 5)[2], r["model"]) for r in rows if r["type"] == "intent"}
        self.assertTrue(roles and all(m == SJ_ROLES[role] for role, m in roles), roles)
        cli = {"claude-sonnet-5-5": CLAUDE_CLI_DEFAULT_MODEL, "claude-opus-5-5": OPUS}
        self.assertTrue(all(cli[s["argv"][s["argv"].index("--model") + 1]] in SJ_ROLES.values() for s in runners[0].seen))

    def test_a_usage_limit_surfaces_the_cli_words_and_latches_the_rest_of_the_run(self):
        runners = []
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_claude([], runners, ["usage-limit"])):
            rep = B.run_benchmark(opts, key_loader=self.boom)
        self.assertNotEqual(rep["status"], "completed")
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        res = [r for r in rows if r["type"] == "result"]
        self.assertEqual(len(res), 1)                                            # every later call refused unsent
        self.assertEqual(len(runners[0].seen), 1)
        self.assertEqual(res[0]["outcome"], "rejected-before-processing")
        self.assertIn("hit your limit", res[0]["note"])
        trace = Path(rep["paths"]["trace"]).read_text() if rep.get("paths", {}).get("trace") else ""
        self.assertIn("claude.usage-limit", trace)


if __name__ == "__main__":
    unittest.main()
