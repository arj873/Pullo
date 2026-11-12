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
from reviewer.contracts.canonical import digest
from reviewer.pilot import benchmark as B
from reviewer.pilot import providers as P
from reviewer.pilot import repository as R
from reviewer.pilot.profile import REPAIR_REASON, ProfileError, live_plan, live_profile, profile_repairs
from reviewer.pilot.repository_profile import ALT_IMPACT_VERSIONS, IMPACT_VERSIONS, repository_plan, repository_profile
from reviewer.pipeline import prompts
from reviewer.pilot.providers import TERRA_LEDGER_NAME
from reviewer.runtime import claude_cli as O
from reviewer.runtime.catalog import (CLAUDE_CLI_DEFAULT_MODEL, CLAUDE_CLI_PRICE_VERSION, OPENCODE_DEFAULT_MODEL,
                                      TERRA_6_MODEL)
from tests.pilot import helpers as H
from tests.pilot import test_benchmark_host as BT
from tests.pilot import test_repository as RT
from tests.runtime.claude_fake import DUMMY_TOKEN, OPUS, Raw, ScriptedRunner, dummy_token

VARIANT = Path(__file__).resolve().parents[2] / "pullo-claude-cli.toml"
OPUS_VARIANT = Path(__file__).resolve().parents[2] / "pullo-claude-cli-opus.toml"
SJ_VARIANT = Path(__file__).resolve().parents[2] / "pullo-claude-cli-sj.toml"      # the PRIMARY arm: Sonnet roles + Opus judge
SJ_ROLES = {"investigator": CLAUDE_CLI_DEFAULT_MODEL, "verifier": CLAUDE_CLI_DEFAULT_MODEL, "judge": OPUS}
MODEL = CLAUDE_CLI_DEFAULT_MODEL
SUB_ONLY = dict(H.AUTH, id="claude-cli-test", providers=["claude-cli"], models=[MODEL])
ROOT = Path(__file__).resolve().parents[2]
BAD_TURN = {"contextRequests": [], "output": {"hypotheses": [{"bogus": 1}]}}     # valid JSON, schema-invalid (REPAIR1)


def scripted_claude(answers, runners, scenarios=()):
    """A live_terra stand-in: CliProviders with the REAL ClaudeCliProvider over the scripted fake CLI."""
    def factory(profile, ledger, scope):
        runner = ScriptedRunner(*scenarios, answers=answers)
        runners.append(runner)
        return P.CliProviders(P.DisabledProvider("openai"), P.DisabledProvider("opencode"), O.ClaudeCliProvider(
            enabled=True, ledger=ledger, run_scope=scope, runner=runner, preflight={"supported": True},
            token_loader=dummy_token, forwarder=runner.forwarder))
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
            self.assertTrue(all(v["isolation"] == "claude-cli-isolated@5"
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


class Repair1(unittest.TestCase):
    """CLAUDE-CLI-REPAIR1: claude-cli roles get maxRepairs 1 (Pullo's own gateway repair); nothing else changes."""

    def test_claude_cli_roles_get_one_gateway_repair_and_every_other_provider_none(self):
        for path in (VARIANT, OPUS_VARIANT, SJ_VARIANT):
            prof = live_profile(models=resolve_config(path).models)
            self.assertEqual(validate("ModelProfile", prof), [])
            self.assertEqual({r: s["caps"]["maxRepairs"] for r, s in prof["roles"].items()},
                             {"investigator": 1, "verifier": 1, "judge": 1}, path.name)
            self.assertEqual({s["caps"]["maxRetries"] for s in prof["roles"].values()}, {0})
            self.assertEqual(profile_repairs(prof), 1)
            for v in sorted(set(IMPACT_VERSIONS) - set(ALT_IMPACT_VERSIONS)):       # v7/v10 need an alternate
                rp = repository_profile(True, resolve_config(path).models, impact_version=v)
                for plan in (live_plan(rp), repository_plan(rp), repository_plan(rp, live_stage_timing=True)):
                    self.assertEqual(plan["reasons"].count(REPAIR_REASON), 1, (path.name, v))
                    self.assertFalse(any("repairs off" in r for r in plan["reasons"]), plan["reasons"])
        for name in ("pullo.toml", "pullo-terra.toml", "pullo-opencode.toml"):
            prof = live_profile(models=resolve_config(ROOT / name).models)
            self.assertEqual({s["caps"]["maxRepairs"] for s in prof["roles"].values()}, {0}, name)
            self.assertEqual(profile_repairs(prof), 0)
            self.assertNotIn(REPAIR_REASON, live_plan(prof)["reasons"])
        self.assertEqual({s["caps"]["maxRepairs"] for s in live_profile()["roles"].values()}, {0})

    def test_a_mixed_provider_alternate_is_refused_and_same_provider_pairs_keep_alternate_pinning(self):
        haiku, terra = "anthropic/claude-haiku-5.5", ROOT / "pullo-terra.toml"
        for v in (7, 10):                                                       # gate L1: refused up front, both ways
            with self.subTest(v=v, mix="claude-cli + other"), self.assertRaises(ProfileError) as c:
                repository_profile(True, ReviewModels(MODEL, MODEL, MODEL, investigator_alt=haiku), impact_version=v)
            self.assertEqual(str(c.exception), "a claude-cli investigator needs a claude-cli alternate (gateway repairs must match)")
            with self.subTest(v=v, mix="other + claude-cli"), self.assertRaises(ProfileError) as c:
                repository_profile(True, ReviewModels(haiku, haiku, haiku, investigator_alt=MODEL), impact_version=v)
            self.assertEqual(str(c.exception), "a claude-cli alternate needs a claude-cli investigator (gateway repairs must match)")
            for models, repairs in ((ReviewModels(MODEL, MODEL, MODEL, investigator_alt=OPUS), 1),
                                    (resolve_config(terra).models, 0)):
                p = repository_profile(True, models, impact_version=v)
                self.assertEqual(validate("ModelProfile", p), [], models)       # alternate-pinning holds (not relaxed)
                self.assertEqual({k: x for k, x in p["alternates"]["investigator"].items() if k not in ("provider", "model", "family", "price")},
                                 {k: x for k, x in p["roles"]["investigator"].items() if k not in ("provider", "model", "family", "price")})
                self.assertEqual(p["alternates"]["investigator"]["caps"]["maxRepairs"], repairs)

    def test_local_schema_issues_name_the_exact_failure(self):
        cases = {'{"hypotheses": [{"bogus": 1}]}': ["$.hypotheses[0].claim: required: missing"],
                 "```json\n{\"hypotheses\": [{\"bogus\": 1}]}\n```": ["$.hypotheses[0].claim: required: missing"],
                 '{"hypotheses": [], "note": 1}': ["$.note: unknown-field: not allowed"],             # pilot: unknown field
                 '{"hypotheses": [], "hypotheses": []}': ["invalid JSON: duplicate key 'hypotheses'"],  # pilot: duplicate key
                 '{"hypotheses": [{"claim": "x}]}': ["invalid JSON: Unterminated string starting at: line 1 column 27 (char 26)"],
                 '{"hypotheses": []} trailing': ["invalid JSON (text after the JSON object): Extra data: line 1 column 20"],
                 '{"hypotheses": NaN}': ["invalid JSON: NaN is not JSON"],
                 'I found no issues.': ['the answer is not the JSON object alone: it starts with text, not with "{"',
                                        "invalid JSON: Expecting value: line 1 column 1 (char 0)"],
                 '{"hypotheses": []}': ["the answer must be exactly one JSON object and nothing else"]}
        for raw, want in cases.items():
            got = prompts.local_schema_issues("InvestigatorOutput", raw)
            self.assertTrue(len(got) >= len(want) and all(g.startswith(w) for g, w in zip(got, want)), (raw, got))

    def test_the_repair_request_quotes_bounded_redacted_issues_and_the_previous_answer(self):
        prof = live_profile(models=resolve_config(VARIANT).models)
        req = prompts._request(prof, "pilot-live@1", "investigator", {"task": "t", "answerFormat": prompts.INVESTIGATOR_FORMAT})
        build = prompts.repair_issues_builder(req, "InvestigatorOutput")
        raw = 'api_key = "abcd1234efgh5678ijkl" ' + "x" * 70000
        rep = build({"status": "invalid-output", "output": None, "rawText": raw}, [])           # adapter refusal: local issues
        self.assertEqual(rep["messages"][:-1], req["messages"])
        self.assertEqual({k: rep[k] for k in rep if k != "messages"}, {k: req[k] for k in req if k != "messages"})
        doc = json.loads(rep["messages"][-1]["content"])
        self.assertEqual((rep["messages"][-1]["role"], sorted(doc)), ("user", ["previousAnswerUntrusted", "repair", "schemaIssues"]))
        self.assertEqual(doc["repair"], prompts.REPAIR_TASK.format(schema="InvestigatorOutput"))
        self.assertIn("ONLY the corrected whole JSON object", doc["repair"])
        self.assertEqual(len(doc["previousAnswerUntrusted"]), prompts.REPAIR_RAW_CHARS)
        self.assertIn("[REDACTED:assigned-secret]", doc["previousAnswerUntrusted"])
        self.assertIn("starts with text", doc["schemaIssues"][0])
        gw = ["$.a: " + "y" * 900] * 20                                                        # the gateway's own (D3) issues win
        doc = json.loads(build({"status": "ok", "output": {}, "rawText": "{}"}, gw)["messages"][-1]["content"])
        self.assertEqual((len(doc["schemaIssues"]), {len(i) for i in doc["schemaIssues"]}),
                         (prompts.REPAIR_MAX_ISSUES, {prompts.REPAIR_ISSUE_CHARS}))

    def test_the_plan_bound_covers_every_repair_the_builder_can_send(self):
        prof = live_profile(models=resolve_config(OPUS_VARIANT).models)
        req = prompts._request(prof, "pilot-live@1", "investigator", {"task": "t", "answerFormat": prompts.INVESTIGATOR_FORMAT})
        facts = O.request_facts(req)
        bound = P.claude_repair_worst_case(facts)
        build = prompts.repair_issues_builder(req, "InvestigatorOutput")
        extra = P.claude_repair_extra_bytes("InvestigatorOutput")
        for ch in ("\x00", '"', "\\", "\u2028", "\U0001F600", "a"):
            rep = build({"status": "invalid-output", "output": None, "rawText": ch * 70000}, [ch * 999] * 30)
            f = O.request_facts(rep)
            self.assertLessEqual(f["bodyBytes"], facts["bodyBytes"] + extra, repr(ch))
            self.assertLessEqual(f["worstCaseApiEquivalentUsdMicros"], bound, repr(ch))
        worst = build({"status": "invalid-output", "output": None, "rawText": "\x01" * 70000}, ["\x01" * 999] * 30)
        self.assertEqual(O.request_facts(worst)["bodyBytes"], facts["bodyBytes"] + extra)      # exact at the worst message
        self.assertGreater(bound, facts["worstCaseApiEquivalentUsdMicros"])


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
            raise O.ClaudeCliUnsupported("claude version is not the pinned 2.1.322")
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
        self.assertEqual((first["isolationVersion"], first["cliVersion"]), ("claude-cli-isolated@5", "2.1.322"))
        self.assertGreater(first["worstCaseApiEquivalentUsdMicros"], 0)
        self.assertEqual(rep["plan"]["worstCaseAdmissionUsdMicros"], first["worstCaseApiEquivalentUsdMicros"])
        p = rep["plan"]                                                     # REPAIR1: one repair, bounded with each first call
        pairs = [(x["worstCaseApiEquivalentUsdMicros"], P.claude_repair_worst_case(x)) for x in p["capturedRequests"]]
        self.assertEqual((p["retries"], p["repairs"], p["worstCaseRepairAdmissionUsdMicros"], p["worstCaseCallUsdMicros"]),
                         (0, 1, max(r for _, r in pairs), max(w + r for w, r in pairs)))
        self.assertLessEqual(p["worstCaseCallUsdMicros"], p["runCeilingUsdMicros"])
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
        self.assertTrue(all(not any(k.startswith(("OPENROUTER", "OPENAI", "ANTHROPIC")) for k in s["env"] if k != "ANTHROPIC_BASE_URL")
                            and O.BASE_URL_RE.fullmatch(s["env"]["ANTHROPIC_BASE_URL"]) for s in seen))   # the forwarder slot only
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
        self.assertTrue(all(v["isolation"] == "claude-cli-isolated@5" for v in p["models"].values()))
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

    # ------------------------------------------------------------------ CLAUDE-CLI-REPAIR1
    def test_plan_digests_the_repairing_profile_and_its_first_call_fits_with_its_repair(self):
        o = self.w.options(config=str(VARIANT))
        with mock.patch.object(O, "run_bounded_stream", side_effect=no_cli):
            rep = B.run_benchmark(o, key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("plan"))
        p = rep["plan"]                                       # benchmark.py is GATED: its "repairs": 0 is fixed text, unchanged
        prof = repository_profile(o.retrieval, resolve_config(VARIANT).models, o.experiment,
                                  impact_version=B.selected_impact_version(o))
        self.assertEqual(digest(prof), p["profileDigest"])                  # the profile the plan binds has the repair
        self.assertEqual(profile_repairs(prof), 1)
        calls = [x["worstCaseApiEquivalentUsdMicros"] + P.claude_repair_worst_case(x) for x in p["capturedRequests"]]
        self.assertLessEqual(max(calls), p["runCeilingUsdMicros"])

    def live_events(self, answers):
        runners = []
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_claude(answers, runners)):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        events = [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]
        return rep, runners[0].seen, [r for r in rows if r["type"] == "result"], events

    def test_a_schema_invalid_answer_gets_exactly_one_visible_repair_call_and_the_run_completes(self):
        rep, seen, res, events = self.live_events([BAD_TURN] + self.model().script)
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 6), rep.get("error"))
        tail = seen[0]["stdin"].index(b'<output-schema name="')
        self.assertTrue(seen[1]["stdin"].startswith(seen[0]["stdin"][:tail]))          # the same request + one repair message
        self.assertEqual(seen[1]["stdin"][-len(seen[0]["stdin"]) + tail:], seen[0]["stdin"][tail:])
        self.assertNotIn(b'"schemaIssues"', seen[0]["stdin"])
        self.assertIn(b'"schemaIssues":["$.output.hypotheses[0].claim: required: missing"', seen[1]["stdin"])
        self.assertEqual({s["argv"][s["argv"].index("--model") + 1] for s in seen[:2]}, {"claude-sonnet-5-5"})
        keys = [r["callKey"].rsplit("|", 1) for r in res[:2]]
        self.assertEqual((keys[0][0] == keys[1][0], keys[0][1], keys[1][1]), (True, "0", "1"))   # one logical call, attempt 0 + 1
        self.assertEqual(res[0]["note"], "invalid-output")
        calls = [e for e in events if e.get("type") == "model.call"]
        self.assertEqual((calls[1]["attempt"], calls[1]["repairOf"]), (1, calls[0]["callId"]))
        self.assertEqual(len([e for e in events if e.get("type") == "cost"]), 6)          # each attempt admitted and charged apart

    def test_verifier_and_judge_repairs_run_on_their_own_roles_model_in_the_primary_arm(self):
        self.w.auth.write_text(json.dumps(dict(SUB_ONLY, models=sorted(set(SJ_ROLES.values())))))
        base = dict(self.w.baseline_doc, reviewConfigDigest=resolve_config(SJ_VARIANT).models.digest,
                    authorizationSha256="sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest())
        self.w.write_roots(baseline=base)
        s = self.model().script
        bad_ver, bad_judge = {"contextRequests": [], "output": {"verdict": "maybe"}}, {"comments": [{"bogus": 1}]}
        runners = []
        d, opts = cli_live(self.w, self.tmp, config=str(SJ_VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_claude(s[:2] + [bad_ver] + s[2:4] + [bad_judge] + s[4:], runners)):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 7), rep.get("error"))
        seen = runners[0].seen
        self.assertEqual([x["argv"][x["argv"].index("--model") + 1] for x in seen],
                         ["claude-sonnet-5-5"] * 5 + ["claude-opus-5-5"] * 2)            # each repair on its role's model
        self.assertEqual([b'"schemaIssues"' in x["stdin"] for x in seen], [False, False, False, True, False, False, True])
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines() if '"result"' in x]
        self.assertEqual([(r["callKey"].rsplit("|", 5)[2], r["callKey"].rsplit("|", 1)[1]) for r in rows if r["type"] == "result"],
                         [("investigator", "0"), ("investigator", "0"), ("verifier", "0"), ("verifier", "1"), ("verifier", "0"),
                          ("judge", "0"), ("judge", "1")])

    def test_a_cut_answer_at_the_role_cap_gets_one_repair_that_says_so(self):     # TIMEOUT-FIX
        runners = []
        d, opts = cli_live(self.w, self.tmp, config=str(VARIANT))
        with mock.patch.object(B, "live_terra", side_effect=scripted_claude([BAD_TURN] + self.model().script, runners,
                                                                            ["max-tokens-cut"])):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 6), rep.get("error"))
        seen = runners[0].seen
        self.assertEqual([s["env"][O.OUTPUT_CAP_ENV] for s in seen], ["16000"] * 3 + ["6000"] * 2 + ["8000"])   # each role's cap
        self.assertIn(b"reached the output limit (16000 tokens, thinking included) and was cut off", seen[1]["stdin"])
        rows = [json.loads(x) for x in (d / TERRA_LEDGER_NAME).read_text().splitlines()]
        res = [r for r in rows if r["type"] == "result"]
        self.assertEqual((res[0]["outcome"], res[0]["finishReason"], res[0]["usage"]["outputTokens"], res[0]["isolation"]["requestsSent"]),
                         ("processed", "max_tokens", 16000, 1))
        self.assertIn("max-output-tokens", res[0]["note"])

    def whole_text_repair(self, raw, issue):
        rep, seen, res, events = self.live_events([Raw(raw)] + self.model().script)
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 6), rep.get("error"))
        self.assertEqual((res[0]["note"], [r["callKey"].rsplit("|", 1)[1] for r in res[:2]]), ("invalid-output", ["0", "1"]))
        fix = seen[1]["stdin"]
        self.assertIn(json.dumps(issue)[1:-1].encode(), fix)                      # the exact failure, as the model will read it
        self.assertLess(fix.rindex(b'"schemaIssues"'), fix.rindex(b'<output-schema name="InvestigatorTurn">'))   # schema again
        self.assertIn(b"ONLY the corrected whole JSON object", fix)

    def test_a_prose_answer_is_repaired_once(self):
        self.whole_text_repair("I looked at the diff and found nothing.", 'it starts with text, not with \"{\"')

    def test_a_duplicate_key_answer_is_repaired_once_naming_the_key(self):
        self.whole_text_repair('{"contextRequests": [], "output": {"hypotheses": []}, "output": null}', "duplicate key 'output'")

    def test_an_unterminated_string_is_repaired_once(self):
        self.whole_text_repair('{"contextRequests": [], "output": {"hypotheses": [{"claim": "x}]}}',
                               "invalid JSON: Unterminated string starting at")

    def test_a_still_invalid_repair_fails_the_call_without_a_third_attempt(self):
        rep, seen, res, events = self.live_events([BAD_TURN, BAD_TURN] + self.model().script)
        self.assertNotEqual(rep["status"], "completed")
        first = res[0]["callKey"].rsplit("|", 1)[0]
        self.assertEqual([r["callKey"].rsplit("|", 1)[1] for r in res if r["callKey"].startswith(first + "|")], ["0", "1"])
        self.assertIn(b'"schemaIssues"', seen[1]["stdin"])
        errs = [e["error"] for e in events if e.get("type") == "error" and e["error"]["code"] == "repair-exhausted"]
        self.assertEqual([(e["detail"]["repairsUsed"], e["detail"].get("localValidation")) for e in errs], [(1, None)])


if __name__ == "__main__":
    unittest.main()
