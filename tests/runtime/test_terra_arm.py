"""TERRA-ARM-01: isolated per-call CODEX_HOME, prompt-isolation proof, routing, estimates, score-family readiness and
the root-only canary - entirely offline (fake runners; the Codex CLI is never executed here)."""

import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest import mock

from reviewer.config import ConfigError, ReviewModels, parse, resolve_config
from reviewer.contracts import validate
from reviewer.pilot.profile import live_profile
from reviewer.runtime import codex_cli as C
from reviewer.runtime import terra_canary as TC
from reviewer.runtime.catalog import (TERRA_MODEL, TERRA_6_MODEL, TERRA_6_PRICE_VERSION, TERRA_MODELS,
                                      terra_api_equivalent_micros, terra_worst_case_micros)
from reviewer.runtime.receipts import RuntimeLedger
from tests.runtime.common import req
from tests.runtime.test_codex import events

ROOT = Path(__file__).resolve().parents[2]
USER = {"HOME": "/invented-user", "OPENAI_API_KEY": "fake", "OPENROUTER_KEY": "fake", "TMPDIR": os.environ.get("TMPDIR", "")}


def score_req(**over):
    r = {"provider": "openai", "model": TERRA_6_MODEL, "profile": "score-test@1", "role": "matcher",
         "promptVersion": "pair@2", "outputSchema": "ScorePair", "params": {"maxOutputTokens": 256},
         "messages": [{"role": "user", "content": "Do these two comments describe the same issue? A: x. B: x."}],
         "tools": []}
    r.update(over)
    return r


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger = RuntimeLedger(self.root / "ledger.jsonl", 50_000_000)
        self.seen = []
        self.during = None             # optional callback(codex_home: Path) run inside the fake CLI

    def runner(self, argv, stdin, env, cwd, timeout):
        home = Path(env["CODEX_HOME"])
        snap = {"argv": list(argv), "stdin": stdin, "env": dict(env), "cwd": cwd, "timeout": timeout,
                "home": sorted(p.name for p in home.iterdir()), "link": os.readlink(home / "auth.json"),
                "config": (home / "config.toml").read_text(), "cwdList": os.listdir(cwd),
                "precheck": C.check_isolated_home(str(home))}
        i = argv.index("model_instructions_file=" + json.dumps(str(Path(cwd).parent / "instructions.md")))
        snap["instructions"] = (Path(cwd).parent / "instructions.md").read_text()
        self.assertEqual(argv[i - 1], "-c")
        self.seen.append(snap)
        if self.during:
            self.during(home)
        return C.RunResult(0, self.out if hasattr(self, "out") else events(), b"")

    def provider(self, environ=None, **over):
        return C.CodexTerraProvider(enabled=True, ledger=self.ledger, runner=self.runner, preflight={"supported": True},
                                    workdir_parent=self.root, environ=USER if environ is None else environ, **over)

    def results(self):
        return [json.loads(x) for x in self.ledger.path.read_text().splitlines() if json.loads(x)["type"] == "result"]


class IsolatedHome(Base):
    def test_every_call_gets_a_fresh_minimal_home_and_the_settings_are_mirrored(self):
        p = self.provider()
        for model in (TERRA_MODEL, TERRA_6_MODEL):
            r = p.call(req("verifier", model=model), ("VERIFY", model, 0))
            self.assertEqual(r.response["resolvedModel"], model)
        a, b = self.seen
        self.assertNotEqual(a["env"]["CODEX_HOME"], b["env"]["CODEX_HOME"])
        for s in self.seen:
            self.assertEqual(s["home"], ["auth.json", "config.toml"])
            self.assertTrue(s["precheck"]["supported"], s["precheck"])
            self.assertEqual(s["link"], "/invented-user/.codex/auth.json")
            self.assertEqual(s["cwdList"], [])
            self.assertFalse(Path(s["env"]["CODEX_HOME"]).exists())          # deleted after the call
            self.assertNotIn("OPENAI_API_KEY", s["env"])
            self.assertNotIn("OPENROUTER_KEY", s["env"])
            self.assertNotEqual(s["env"]["HOME"], "/invented-user")
            for k in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
                self.assertTrue(Path(s["env"][k]).is_relative_to(s["env"]["HOME"]))
            self.assertEqual(s["instructions"], C.BASE_INSTRUCTIONS)
            cfg = tomllib.loads(s["config"])                                    # valid TOML
            self.assertEqual(cfg["approval_policy"], "never")
            self.assertTrue(all(v is False for k, v in cfg["features"].items() if k != "multi_agent_v2"))
            self.assertNotIn("AGENTS", s["config"])
            argv = s["argv"]
            overrides = [argv[i + 1] for i, x in enumerate(argv) if x == "-c"]
            lines = [ln.replace(" = ", "=", 1) for ln in s["config"].splitlines() if ln and not ln.startswith("#")]
            self.assertEqual(overrides, [ln for ln in lines if not ln.startswith("features.")
                                         or ln.startswith("features.multi_agent_v2.")])   # same settings, same order
            self.assertEqual([argv[i + 1] for i, x in enumerate(argv) if x == "--disable"], list(C.DISABLED_FEATURES))

    def test_operator_codex_home_is_the_link_target_when_set(self):
        self.provider(environ=dict(USER, CODEX_HOME="/srv/codex-login")).call(req("verifier", model=TERRA_6_MODEL), ("k",))
        self.assertEqual(self.seen[0]["link"], "/srv/codex-login/auth.json")
        self.provider(environ=dict(USER, CODEX_HOME="relative/dir")).call(req("verifier", model=TERRA_6_MODEL), ("k2",))
        self.assertEqual(self.seen[1]["link"], "/invented-user/.codex/auth.json")    # relative value ignored

    def test_pullo_never_opens_stats_or_resolves_the_login_file(self):
        target = self.root / "login" / ".codex" / "auth.json"
        target.parent.mkdir(parents=True)
        target.write_text("SECRET-NOT-FOR-PULLO")
        real_open, real_os_open, real_stat = builtins.open, os.open, os.stat

        def guard(path):
            if "login" in str(path) and str(path).endswith("auth.json"):
                raise AssertionError(f"Pullo touched the login file: {path}")

        def g_open(path, *a, **k):
            guard(path)
            return real_open(path, *a, **k)

        def g_os_open(path, *a, **k):
            guard(path)
            return real_os_open(path, *a, **k)

        def g_stat(path, *a, follow_symlinks=True, **k):
            if follow_symlinks:
                guard(path)
            return real_stat(path, *a, follow_symlinks=follow_symlinks, **k)
        p = self.provider(environ=dict(USER, HOME=str(self.root / "login")))
        with mock.patch("builtins.open", g_open), mock.patch("os.open", g_os_open), mock.patch("os.stat", g_stat):
            r = p.call(req("verifier", model=TERRA_6_MODEL), ("k",))
        self.assertEqual(r.response["status"], "ok")
        self.assertEqual(target.read_text(), "SECRET-NOT-FOR-PULLO")            # untouched and still in place
        led = self.ledger.path.read_text()
        self.assertNotIn("SECRET-NOT-FOR-PULLO", led)

    def test_argv_is_isolated_strict_and_never_bypasses(self):
        for model in TERRA_MODELS:
            a = C.build_argv("codex", "/w/schema.json", "/w/cwd", model, instructions_file="/w/instructions.md")
            for flag in ("--ephemeral", "--ignore-user-config", "--strict-config", "--ignore-rules", "--json"):
                self.assertIn(flag, a)
            self.assertEqual(a[a.index("--sandbox") + 1], "read-only")
            for kv in ('approval_policy="never"', "include_permissions_instructions=false",
                       "include_environment_context=false", "skills.include_instructions=false",
                       "skills.bundled.enabled=false", "project_doc_max_bytes=0", "mcp_servers={}",
                       'model_instructions_file="/w/instructions.md"', "features.multi_agent_v2.enabled=false",
                       f'model_reasoning_effort="medium"'):
                self.assertEqual(a[a.index(kv) - 1], "-c", kv)
            self.assertFalse(C.FORBIDDEN_FLAGS & set(a))
            # the built-in provider cannot be overridden (the CLI refuses to start): never emit model_providers.*
            self.assertFalse([x for x in a if x.startswith("model_providers")])
            self.assertEqual(a[-1], "-")

    def test_offline_home_check_refuses_instruction_and_extension_carriers(self):
        for forbidden in ("AGENTS.md", "skills", "plugins", "prompt.md", "mcp.json", "rules"):
            with tempfile.TemporaryDirectory(dir=self.root) as work:
                home = Path(C.isolated_home(work, USER)["codexHome"])
                (home / forbidden).write_text("untrusted")
                self.assertFalse(C.check_isolated_home(str(home))["supported"], forbidden)
        with tempfile.TemporaryDirectory(dir=self.root) as work:
            home = Path(C.isolated_home(work, USER)["codexHome"])
            (home / "auth.json").unlink()
            (home / "auth.json").write_text("{}")                                # a copy, not a link
            self.assertFalse(C.check_isolated_home(str(home))["supported"])


class PostCallAudit(Base):
    def test_cli_state_files_are_allowed_and_listed(self):
        self.during = lambda h: [(h / n).write_text("") for n in ("installation_id", "state_5.sqlite", ".sandbox_migration")]
        r = self.provider().call(req("verifier", model=TERRA_6_MODEL), ("k",))
        self.assertEqual(r.response["status"], "ok")
        after = self.results()[-1]["isolation"]["homeAfter"]
        self.assertTrue(after["ok"])
        self.assertEqual(after["newEntries"], [".sandbox_migration", "installation_id", "state_5.sqlite"])

    def test_instruction_carrier_created_during_the_call_discards_output_and_disables_the_adapter(self):
        for name in ("AGENTS.md", "skills"):
            with self.subTest(name):
                self.seen.clear()
                self.during = lambda h, n=name: (h / n).mkdir()
                p = self.provider()
                r = p.call(req("verifier", model=TERRA_6_MODEL), ("k", name))
                self.assertIsNone(r.response)
                self.assertEqual(r.error["detail"]["reason"], "isolation-violation")
                self.assertEqual(p.disabled_reason, "forbidden-home-entry")
                r2 = p.call(req("verifier", model=TERRA_6_MODEL), ("k2", name))
                self.assertEqual((r2.outcome, r2.error["detail"]["reason"]), ("not-sent", "adapter-disabled"))
                self.assertEqual(len(self.seen), 1)

    def test_login_rewritten_inside_the_throwaway_home_is_detected_never_read(self):
        def replace(h):
            (h / "auth.json").unlink()
            (h / "auth.json").write_text("refreshed-token-would-be-lost")
        self.during = replace
        p = self.provider()
        r = p.call(req("verifier", model=TERRA_6_MODEL), ("k",))
        self.assertEqual(r.error["detail"]["itemType"], "auth-replaced")
        self.assertEqual(p.disabled_reason, "auth-replaced")
        self.assertNotIn("refreshed-token", self.ledger.path.read_text())


class Bounds(Base):
    def test_cap_and_timeout_cannot_be_widened(self):
        p = self.provider(max_calls=1, timeout_sec=20)
        p.call(req("verifier", model=TERRA_6_MODEL, params={"timeoutSec": 999}), ("first",))
        self.assertEqual(self.seen[0]["timeout"], 20)
        self.assertEqual(p.call(req("verifier", model=TERRA_6_MODEL), ("next",)).error["detail"]["reason"], "call-cap")
        self.assertEqual(len(self.seen), 1)
        for bad in (dict(max_calls=0), dict(max_calls=129), dict(timeout_sec=301), dict(timeout_sec=True)):
            with self.assertRaises(ValueError):
                self.provider(**bad)

    def test_receipts_are_subscription_estimates_and_never_commit_dollars(self):
        self.provider().call(req("verifier", model=TERRA_6_MODEL), ("VERIFY", 0))
        row = self.results()[-1]
        self.assertEqual((row["billingKind"], row["estimateBasis"], row["priceVersion"]),
                         ("subscription-consumption", "api-equivalent-standard", TERRA_6_PRICE_VERSION))
        self.assertEqual(row["apiEquivalentEstimateUsdMicros"], 800 + 10 + 250)    # 800 uncached, 200 cached, 50 out
        self.assertEqual(row["isolation"]["toolItems"], 0)
        self.assertEqual(row["isolation"]["version"], "codex-isolated-home@1")
        self.assertEqual(self.ledger.totals()["committedUsdMicros"], 0)

    def test_cli_reconnect_error_events_abort_as_unknown_outcome(self):
        self.out = events(extra=[{"type": "error", "message": "Reconnecting... 2/5"}])
        r = self.provider().call(req("verifier", model=TERRA_6_MODEL), ("k",))
        self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("unknown", "cli-failure"))
        self.out = events(extra=[{"type": "item.completed", "item": {"type": "error", "message": "Model metadata ..."}}])
        r = self.provider().call(req("verifier", model=TERRA_6_MODEL), ("k2",))
        self.assertEqual(r.error["detail"]["reason"], "isolation-violation")


class PlanPin(Base):
    def test_plan_pin_is_the_actual_stdin_schema_and_cli_settings(self):
        r = req("verifier", model=TERRA_6_MODEL)
        facts = C.request_facts(r)
        self.provider().call(r, ("pin",))
        s = self.seen[0]
        self.assertEqual(facts["bodySha256"], hashlib.sha256(s["stdin"]).hexdigest())
        self.assertEqual(facts["argvSha256"], self.results()[-1]["isolation"]["argvSha256"])
        self.assertEqual(facts["configSha256"], "sha256:" + hashlib.sha256(
            s["config"].replace(str(Path(s["cwd"]).parent), "<work>").encode()).hexdigest())
        self.assertEqual(facts["worstCaseRouterUsdMicros"], 0)
        self.assertEqual(facts["worstCaseApiEquivalentUsdMicros"],
                         terra_worst_case_micros(TERRA_6_MODEL, facts["bodyBytes"], facts["maxTokens"]))
        self.assertEqual((facts["billingKind"], facts["reasoningEffort"]), ("subscription-consumption", "medium"))


class PromptIsolationProof(unittest.TestCase):
    def fake(self, items, rc=0, create=()):
        calls = []

        def run(argv, env, cwd):
            home = Path(env["CODEX_HOME"])
            calls.append({"argv": argv, "home": sorted(os.listdir(home))})
            for n in create:
                (home / n).mkdir()
            return C.RunResult(rc, json.dumps(items).encode(), b"")
        return run, calls

    def test_only_the_probe_reaches_the_model(self):
        run, calls = self.fake([{"type": "message", "role": "user", "content": [{"type": "input_text", "text": C.PROBE}]}])
        rep = C.check_prompt_isolation(runner=run, environ=USER, model=TERRA_6_MODEL)
        self.assertTrue(rep["supported"], rep)
        argv = calls[0]["argv"]
        self.assertEqual(argv[1:3], ["debug", "prompt-input"])
        self.assertEqual(calls[0]["home"], ["config.toml"])                    # auth-less: no credential at all
        self.assertIn("skills.bundled.enabled=false", argv)
        self.assertEqual(argv[-1], C.PROBE)

    def test_developer_text_skills_or_agents_fail_the_proof(self):
        dev = {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "<skills_instructions>"}]}
        user = {"type": "message", "role": "user", "content": [{"type": "input_text", "text": C.PROBE}]}
        for items, rc, create in (([dev, user], 0, ()), ([user], 1, ()), ("not a list", 0, ()), ([user], 0, ("skills",))):
            run, _ = self.fake(items, rc, create)
            self.assertFalse(C.check_prompt_isolation(runner=run, environ=USER)["supported"], (items, rc, create))

    def test_preflight_runs_the_proof_for_every_terra_model(self):
        def cli(argv):
            out = {"--version": b"codex-cli 0.163.0", "exec": " ".join(C.REQUIRED_HELP_FLAGS).encode(),
                   "features": "".join(f"{f} stable true\n" for f in C.DISABLED_FEATURES).encode(),
                   "login": b"Logged in using ChatGPT"}[argv[1]]
            return C.RunResult(0, out, b"")
        run, calls = self.fake([{"type": "message", "role": "user", "content": [{"type": "input_text", "text": C.PROBE}]}])
        rep = C.check_cli_isolation(runner=cli, environ=USER, prompt_check=True, prompt_runner=run)
        self.assertTrue(rep["supported"], rep)
        self.assertEqual(set(rep["promptIsolation"]), set(TERRA_MODELS))
        self.assertEqual(len(calls), len(TERRA_MODELS))
        bad, _ = self.fake([])
        self.assertFalse(C.check_cli_isolation(runner=cli, environ=USER, prompt_check=True, prompt_runner=bad)["supported"])


class ScoreFamilyReadiness(Base):
    """The same adapter serves the score family's schemas when the HOST constructs it so (no score host uses it yet)."""

    def score_provider(self, **over):
        return self.provider(family="score", category_cap=8_000_000, aggregate_ceiling=20_000_000, **over)

    def test_score_pair_is_served_validated_and_admitted_in_the_scoring_category(self):
        self.out = events(json.dumps({"match": True, "confidence": 0.75}))
        r = self.score_provider().call(score_req(), ("PAIR", 0))
        self.assertEqual((r.response["status"], r.response["output"]), ("ok", {"match": True, "confidence": 0.75}))
        self.assertTrue(self.seen[0]["stdin"].startswith(b"You are a review-scoring role."))
        intents = [json.loads(x) for x in self.ledger.path.read_text().splitlines() if json.loads(x)["type"] == "intent"]
        self.assertEqual(intents[-1]["category"], "scoring")

    def test_families_never_cross_and_score_params_are_refused(self):
        self.assertEqual(self.provider().call(score_req(), ("a",)).error["detail"]["reason"], "request-refused")
        self.assertEqual(self.score_provider().call(req("verifier", model=TERRA_6_MODEL), ("b",)).error["detail"]["reason"],
                         "request-refused")
        r = self.score_provider().call(score_req(params={"maxOutputTokens": 256, "temperature": 0}), ("c",))
        self.assertEqual(r.error["detail"]["reason"], "request-refused")
        self.assertEqual(self.seen, [])
        with self.assertRaises(ValueError):
            self.provider(family="judge")
        with self.assertRaises(ValueError):
            C.CodexTerraProvider(enabled=True, preflight={"supported": True}, family="score")    # needs a ledger


class Catalog(unittest.TestCase):
    def test_terra6_is_the_published_standard_estimate_with_long_context_tier(self):
        self.assertEqual(terra_api_equivalent_micros(300_000, 0, 1000, 300_000, TERRA_6_MODEL), 607_500)
        self.assertEqual(terra_api_equivalent_micros(1_000_000, 0, 1_000_000, 1000, TERRA_6_MODEL), 6_000_000)
        self.assertGreater(terra_worst_case_micros(TERRA_6_MODEL, 10_000, 16_000), 0)


class ConfigAndProfile(unittest.TestCase):
    def test_variant_is_all_terra_and_default_config_is_unchanged(self):
        cfg = resolve_config(ROOT / "pullo-terra.toml")
        roles = cfg.report()["roles"]
        self.assertEqual({v["provider"] for v in roles.values()}, {"openai"})
        self.assertEqual({v["model"] for v in roles.values()}, {TERRA_6_MODEL})
        self.assertTrue(all(v["isolation"] == "codex-isolated-home@1" for v in roles.values()))
        default = resolve_config(ROOT / "pullo.toml")
        self.assertEqual(default.models, ReviewModels())
        self.assertTrue(all(set(v) == {"provider", "model"} for v in default.report()["roles"].values()))

    def test_profiles_use_pinned_terra_prices_no_retries_no_fallbacks(self):
        for model in (TERRA_MODEL, TERRA_6_MODEL):
            profile = live_profile(models=ReviewModels(verifier=model))
            self.assertEqual(validate("ModelProfile", profile), [])
            v = profile["roles"]["verifier"]
            self.assertEqual((v["provider"], v["family"], v["fallbacks"], v["caps"]["maxRetries"]), ("openai", "gpt", [], 0))
            self.assertEqual(profile["roles"]["investigator"]["provider"], "anthropic")

    def test_wrong_pairs_and_held_provider_refuse_without_fallback(self):
        bad = ('[review.verifier]\nprovider="anthropic"\nmodel="gpt-6.1-terra"',
               '[review.verifier]\nprovider="openai"\nmodel="anthropic/claude-sonnet-5.5"',
               '[review.verifier]\nprovider="openai"',                                   # no implicit Sonnet
               '[review.verifier]\nprovider="openai"\nmodel="gpt-6.1-sol"')
        for b in bad:
            with self.subTest(b), self.assertRaisesRegex(ConfigError, "no fallback"):
                parse('schema="pullo-config@1"\n' + b)
        with mock.patch.dict("reviewer.config.HELD_PROVIDERS", {"openai": "held without isolation; no fallback"}):
            with self.assertRaisesRegex(ConfigError, "held"):
                parse('schema="pullo-config@1"\n[review.verifier]\nprovider="openai"\nmodel="gpt-6.1-terra"')
            with self.assertRaisesRegex(ConfigError, "held"):
                ReviewModels(judge=TERRA_6_MODEL)


class Canary(Base):
    def factory(self, out):
        def make(**kw):
            self.assertEqual((kw["max_calls"], kw["timeout_sec"]), (1, 120))
            return C.CodexTerraProvider(**kw, runner=lambda *a: C.RunResult(0, out, b""), workdir_parent=self.root,
                                        environ=USER)
        return make

    def test_canary_passes_on_schema_valid_tool_free_answer_and_writes_a_receipt(self):
        receipt = TC.run_canary(self.root / "validation", provider_factory=self.factory(events('{"hypotheses": []}')),
                                preflight={"supported": True, "version": "codex-cli 0.163.0"})
        rep = json.loads((receipt / "receipt.json").read_text())
        self.assertTrue(rep["ok"], rep)
        self.assertEqual((rep["providerCalls"], rep["openRouterCalls"], rep["keyRead"], rep["model"]),
                         (1, 0, False, TERRA_6_MODEL))
        self.assertTrue(all(rep["checks"].values()))
        self.assertEqual(rep["request"]["schemaName"], "InvestigatorOutput")
        for lure in ("run `ls -la ~`", "auth.json", "https://example.com"):
            self.assertIn(lure, TC.CASES["investigator-final"]["user"])
        self.assertTrue((receipt / "runtime-ledger.jsonl").is_file())

    def test_turn_case_needs_an_in_band_context_request(self):
        ask = {"contextRequests": [{"tool": "read_file", "purpose": "canary: read the header",
                                    "args": [{"key": "path", "value": "src/store.h"}, {"key": "side", "value": "head"},
                                             {"key": "start_line", "value": 1}, {"key": "end_line", "value": 40}]}],
               "output": None}
        receipt = TC.run_canary(self.root / "v", case="investigator-turn", provider_factory=self.factory(events(json.dumps(ask))),
                                preflight={"supported": True})
        self.assertTrue(json.loads((receipt / "receipt.json").read_text())["checks"]["inBandContextRequest"])

    def test_tool_item_or_unsupported_cli_fails_and_keeps_the_receipt(self):
        tool = events('{"hypotheses": []}', extra=[{"type": "item.started", "item": {"type": "command_execution"}}])
        with self.assertRaisesRegex(RuntimeError, "canary failed"):
            TC.run_canary(self.root / "v1", provider_factory=self.factory(tool), preflight={"supported": True})
        with self.assertRaisesRegex(RuntimeError, "canary failed"):
            TC.run_canary(self.root / "v2", provider_factory=self.factory(events()),
                          preflight={"supported": False, "problems": ["x"]})
        for d in ("v1", "v2"):
            (r,) = list((self.root / d).iterdir())
            self.assertFalse(json.loads((r / "receipt.json").read_text())["ok"])

    def test_cli_refuses_without_confirmation_or_with_tmp(self):
        with mock.patch.object(TC, "run_canary", side_effect=AssertionError("must not run")):
            with self.assertRaises(SystemExit):
                TC.main(["--out-dir", str(self.root)], out=io.StringIO())
            with mock.patch.dict(os.environ, {"TMPDIR": "/tmp"}), self.assertRaises(SystemExit):
                TC.main(["--out-dir", str(self.root), "--confirm-live"], out=io.StringIO())
