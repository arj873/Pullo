"""CFG-01: review models come from a trusted config file. Fake provider only: invented configs, no key, no network."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from reviewer import config as C
from reviewer.config import ConfigError, ReviewModels, resolve_config
from reviewer.contracts import validate
from reviewer.pilot.profile import ProfileError, live_profile
from reviewer.pilot.repository_profile import repository_profile
from tests.pilot import helpers as H

SONNET, HAIKU, OPUS = ("anthropic/claude-sonnet-5.5", "anthropic/claude-haiku-5.5", "anthropic/claude-opus-5.5")
ROLE_OF = {"InvestigatorOutput": "investigator", "VerifierOutput": "verifier", "JudgeOutput": "judge"}


def toml(inv=SONNET, ver=SONNET, jdg=SONNET, extra=""):
    return ('schema = "pullo-config@1"\n' + "".join(
        f'[review.{r}]\nprovider = "anthropic"\nmodel = "{m}"\n' for r, m in
        (("investigator", inv), ("verifier", ver), ("judge", jdg))) + extra)


class Parse(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.d = Path(os.path.realpath(self._t.name))

    def write(self, text, name="c.toml", mode="w"):
        p = self.d / name
        with open(p, mode) as f:
            f.write(text)
        return p

    def test_shipped_pullo_toml_is_exact_sonnet_everywhere_and_matches_builtin(self):
        cfg = resolve_config()
        self.assertEqual((cfg.source, cfg.models), ("app-default", ReviewModels.uniform(SONNET)))
        self.assertEqual(cfg.models, ReviewModels())
        self.assertEqual(C.DEFAULT_CONFIG_PATH, Path(C.__file__).resolve().parents[1] / "pullo.toml")

    def test_default_is_anchored_to_app_root_not_cwd(self):
        (self.d / "pullo.toml").write_text(toml(HAIKU, HAIKU, HAIKU))
        old = os.getcwd()
        os.chdir(self.d)
        self.addCleanup(os.chdir, old)
        self.assertEqual(resolve_config().models, ReviewModels.uniform(SONNET))

    def test_mixed_allowed_models_and_omitted_roles_default_to_sonnet(self):
        m = resolve_config(self.write(toml(HAIKU, OPUS, SONNET))).models
        self.assertEqual((m.investigator, m.verifier, m.judge), (HAIKU, OPUS, SONNET))
        m = resolve_config(self.write('schema = "pullo-config@1"\n[review.judge]\nmodel = "%s"\n' % OPUS)).models
        self.assertEqual((m.investigator, m.verifier, m.judge), (SONNET, SONNET, OPUS))

    def test_refusals(self):
        bad = {
            "unknown top field": toml(extra='retries = 3\n'),
            "unknown role field": toml().replace('provider = "anthropic"', 'provider = "anthropic"\nkey = "x"', 1),
            "unknown role": toml(extra='[review.extra]\nmodel = "x"\n'),
            "budget section": toml(extra='[budget]\nmaxUsd = 99\n'),
            "secret field": toml(extra='[review]\n'.replace('[review]\n', '') + 'openrouter_key = "sk-or-v1-abc"\n'),
            "no schema": toml().replace('schema = "pullo-config@1"\n', ""),
            "wrong schema": toml().replace("@1", "@2"),
            "unknown model": toml(inv="anthropic/claude-sonnet-9"),
            "foreign model": toml(jdg="openai/gpt-5"),
            "bare model name": toml(ver="claude-sonnet-5-5"),
            "unsupported provider": toml().replace('"anthropic"', '"gemini"', 1),
            "non-string model": toml().replace('"%s"' % SONNET, "5", 1),
            "bad toml": "schema = ",
            "nul": toml() + "\x00",
            "huge": toml() + "# " + "x" * 9000 + "\n",
        }
        for name, text in bad.items():
            with self.subTest(name), self.assertRaises(ConfigError):
                resolve_config(self.write(text))

    def test_held_openai_refuses_clearly_and_has_no_fallback(self):
        t = toml().replace('provider = "anthropic"\nmodel = "%s"' % SONNET, 'provider = "openai"\nmodel = "gpt-5.6-terra"', 1)
        with self.assertRaisesRegex(ConfigError, "held.*no fallback"):
            resolve_config(self.write(t))

    def test_non_regular_missing_symlink_and_not_utf8_refuse(self):
        real = self.write(toml())
        link = self.d / "link.toml"
        link.symlink_to(real)
        for p in (self.d, self.d / "absent.toml", link, self.write(b"\xff\xfe", "bin.toml", "wb")):
            with self.subTest(str(p.name)), self.assertRaises(ConfigError):
                resolve_config(p)

    def test_explicit_config_inside_a_forbidden_root_refuses(self):
        p = self.write(toml(), "inside.toml")
        with self.assertRaises(ConfigError):
            resolve_config(p, forbidden_roots=(self.d,))
        self.assertEqual(resolve_config(p, forbidden_roots=(self.d / "other",)).source, "explicit")

    def test_report_has_no_path_and_digest_ignores_path_comments_and_whitespace(self):
        a = resolve_config(self.write("# one\n" + toml(HAIKU), "a.toml"))
        sub = self.d / "x"
        sub.mkdir()
        b = resolve_config(self.write(toml(HAIKU).replace("\n", "\n\n"), "x/b.toml"))
        self.assertEqual(a.report(), b.report())
        self.assertNotIn(str(self.d), json.dumps(a.report()))
        self.assertNotEqual(a.models.digest, ReviewModels().digest)

    def test_legacy_model_is_a_noop_or_a_conflict_never_an_override(self):
        d = resolve_config()
        self.assertIs(C.reconcile_legacy_model(d, None), d)
        self.assertIs(C.reconcile_legacy_model(d, SONNET), d)
        with self.assertRaises(ConfigError):
            C.reconcile_legacy_model(d, HAIKU)
        ex = resolve_config(self.write(toml()))
        with self.assertRaises(ConfigError):
            C.reconcile_legacy_model(ex, SONNET)          # even an agreeing --model conflicts with --config


class Profile(unittest.TestCase):
    def test_default_profile_is_unchanged_and_roles_follow_models(self):
        self.assertEqual(live_profile(), live_profile(SONNET))
        self.assertEqual(live_profile(models=ReviewModels()), live_profile())
        p = live_profile(models=ReviewModels(HAIKU, OPUS, SONNET))
        self.assertEqual(validate("ModelProfile", p), [])
        self.assertEqual({r: s["model"] for r, s in p["roles"].items()},
                         {"investigator": HAIKU, "verifier": OPUS, "judge": SONNET})
        base = live_profile()
        for r in p["roles"]:
            same = p["roles"][r]["model"] == SONNET
            self.assertEqual(p["roles"][r] == base["roles"][r], same)
            self.assertEqual(p["roles"][r]["caps"], base["roles"][r]["caps"])
            self.assertEqual((p["roles"][r]["fallbacks"], p["roles"][r]["caps"]["maxRetries"]), ([], 0))

    def test_model_and_models_conflict_and_allowlist_holds(self):
        with self.assertRaises(ProfileError):
            live_profile(SONNET, models=ReviewModels())
        with self.assertRaises(ProfileError):
            live_profile("anthropic/claude-sonnet-9")
        self.assertEqual(repository_profile(True, ReviewModels(judge=HAIKU))["roles"]["judge"]["model"], HAIKU)


AUTH3 = dict(H.AUTH, models=[SONNET, HAIKU, OPUS])


class Rig(H.Rig):
    def setUp(self):
        super().setUp()
        self.auth.write_text(json.dumps(AUTH3))
        self.cfgdir = self.tmp / "cfg"
        self.cfgdir.mkdir()

    def cfg(self, text, name="pullo.toml"):
        p = self.cfgdir / name
        p.write_text(text)
        return str(p)

    def models_by_role(self, m):
        out = {}
        for r in m.requests:
            b = json.loads(r.body)
            out.setdefault(ROLE_OF[b["response_format"]["json_schema"]["name"]], set()).add(b["model"])
        return out


class Live(Rig):
    def test_default_run_uses_sonnet_for_every_role_and_reports_it(self):
        m = self.model()
        code, rep, _ = self.run_json(self.argv(), transport=m)
        self.assertEqual(code, 0)
        self.assertEqual(self.models_by_role(m), {r: {SONNET} for r in ROLE_OF.values()})
        c = rep["cases"][0]
        self.assertEqual(c["reviewModels"]["source"], "app-default")
        self.assertEqual({r: v["model"] for r, v in c["reviewModels"]["roles"].items()},
                         {r: SONNET for r in ROLE_OF.values()})

    def test_each_role_follows_its_config_and_only_that_role_changes(self):
        seen = {}
        for i, (inv, ver, jdg) in enumerate([(HAIKU, SONNET, SONNET), (SONNET, OPUS, SONNET),
                                             (SONNET, SONNET, HAIKU), (HAIKU, OPUS, SONNET)]):
            self.out = self.tmp / f"out{i}"
            m = self.model()
            code, rep, err = self.run_json(self.argv("--config", self.cfg(toml(inv, ver, jdg), f"c{i}.toml")), transport=m)
            self.assertEqual((code, err), (0, ""), rep)
            self.assertEqual(self.models_by_role(m), {"investigator": {inv}, "verifier": {ver}, "judge": {jdg}})
            seen[i] = rep["cases"][0]["runId"]
            self.assertEqual(rep["cases"][0]["reviewModels"]["source"], "explicit")
            self.assertNotIn(str(self.cfgdir), json.dumps(rep))
            for r in m.requests:
                self.assertNotIn(str(self.cfgdir).encode(), r.body)
        self.assertEqual(len(set(seen.values())), 4)                      # changed model => changed identity

    def test_budgets_retries_and_fallbacks_are_not_config_reachable(self):
        p = live_profile(models=ReviewModels(HAIKU, OPUS, SONNET))
        q = live_profile()
        for r in p["roles"]:
            self.assertEqual((p["roles"][r]["caps"], p["roles"][r]["fallbacks"]), (q["roles"][r]["caps"], []))
        for extra in ("[budget]\nmaxUsdMicros = 99\n", "[review.judge.caps]\nmaxRetries = 2\n",
                      '[review.judge]\nfallbacks = ["x"]\n'):
            code, _, err = self.run_main(self.argv("--config", self.cfg(toml() + extra)), key_loader=H.boom_key_loader)
            self.assertEqual(code, 2, extra)

    def test_authorization_not_widened_by_config(self):
        self.auth.write_text(json.dumps(H.AUTH))                          # Sonnet only
        m = self.model()
        code, rep, err = self.run_json(self.argv("--config", self.cfg(toml(HAIKU))), transport=m,
                                       key_loader=H.boom_key_loader)
        self.assertNotEqual(code, 0)
        self.assertEqual(m.requests, [])
        self.assertFalse(self.out.exists() and any((self.out / "runs").iterdir()))

    def test_bad_held_and_overlapping_configs_refuse_before_key_network_or_output(self):
        held = toml().replace('provider = "anthropic"\nmodel = "%s"' % SONNET,
                              'provider = "openai"\nmodel = "gpt-5.6-terra"', 1)
        inside = self.corpus / "pullo.toml"
        inside.write_text(toml())
        inout = self.cfgdir / "x.toml"
        for name, path in (("unknown model", self.cfg(toml(inv="anthropic/nope"))), ("held", self.cfg(held)),
                           ("unknown field", self.cfg(toml(extra="x = 1\n"))), ("in corpus", str(inside)),
                           ("missing", str(self.cfgdir / "absent.toml"))):
            m = self.model()
            with self.subTest(name):
                code, out, err = self.run_main(self.argv("--config", path), transport=m, key_loader=H.boom_key_loader)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("ConfigError", err)
                self.assertEqual(m.requests, [])
                self.assertFalse(self.out.exists())
        self.assertIn("held", err if name == "held" else self.run_main(
            self.argv("--config", self.cfg(held)), key_loader=H.boom_key_loader)[2])

    def test_legacy_model_flag_conflicts_instead_of_overriding(self):
        for extra in (["--model", HAIKU], ["--model", SONNET, "--config", self.cfg(toml())]):
            m = self.model()
            code, _, err = self.run_main(self.argv(*extra), transport=m, key_loader=H.boom_key_loader)
            self.assertEqual(code, 2)
            self.assertIn("conflicts", err)
            self.assertEqual(m.requests, [])
        m = self.model()
        self.assertEqual(self.run_main(self.argv("--model", SONNET), transport=m)[0], 0)   # agreeing no-op

    def test_replay_refuses_changed_models_and_accepts_the_recorded_config(self):
        cfg = self.cfg(toml(HAIKU, SONNET, OPUS))
        code, rep, _ = self.run_json(self.argv("--config", cfg), transport=self.model())
        c = rep["cases"][0]
        self.assertEqual(code, 0)
        base = ["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--case", "o--r--1",
                "--replay-trace", c["paths"]["trace"], "--trace-digest", c["traceDigest"]["value"]]
        with mock.patch("reviewer.runtime.openrouter.HttpsTransport.__call__", side_effect=AssertionError("network")):
            for i, extra in enumerate(([], ["--config", self.cfg(toml(SONNET, SONNET, OPUS), "other.toml")],
                                       ["--config", self.cfg(toml(HAIKU, OPUS, OPUS), "other2.toml")])):
                code, r, _ = self.run_json(base + ["--out", str(self.tmp / f"rp{i}")] + extra,
                                           key_loader=H.boom_key_loader)
                self.assertEqual(code, 1, extra)                         # current default / changed models: refused
                self.assertTrue(r["cases"][0]["refused"])
            copy = self.cfg(toml(HAIKU, SONNET, OPUS), "copy.toml")      # same effective config, another path
            code, r, _ = self.run_json(base + ["--out", str(self.tmp / "rpok"), "--config", copy],
                                       key_loader=H.boom_key_loader)
            self.assertEqual((code, r["cases"][0]["status"], r["cases"][0]["providerCalls"]), (0, "completed", 0))

    def test_plan_exposes_per_role_models_and_two_trusted_paths_give_identical_requests(self):
        text = toml(HAIKU, OPUS, SONNET)
        reps = []
        for name in ("a/one.toml", "b/deeper/two.toml"):
            p = self.cfgdir / name
            p.parent.mkdir(parents=True)
            p.write_text(text)
            code, rep, err = self.run_json(self.argv("--config", str(p), live=False))
            self.assertEqual((code, err), (0, ""))
            reps.append(rep["cases"][0])
        a, b = reps
        self.assertEqual(a["plan"]["models"], {"investigator": {"provider": "anthropic", "model": HAIKU},
                                               "verifier": {"provider": "anthropic", "model": OPUS},
                                               "judge": {"provider": "anthropic", "model": SONNET}})
        self.assertEqual(a["plan"]["model"], "mixed")
        self.assertEqual(a["plan"]["firstRequests"], b["plan"]["firstRequests"])
        self.assertEqual(a["reviewModels"], b["reviewModels"])


class OtherEntrypoints(unittest.TestCase):
    """repository and positive resolve and validate the config before reading any case, fixture, output or key."""

    setUp, write = Parse.setUp, Parse.write

    def test_bad_config_refuses_before_ingest_prepare_or_output(self):
        from reviewer.pilot import positive as P, repository as R
        bad = self.write(toml(inv="anthropic/nope"))
        out = self.d / "out"
        ro = R.RepositoryOptions(mode="plan", case_dir=str(self.d / "nocase"), case_pins="p", case_baseline="b",
                                 store="s", base_import_pins="bp", head_import_pins="hp", out_dir=str(out),
                                 auth="a", config=str(bad))
        po = P.PositiveOptions(mode="plan", source_baseline=str(self.d / "nobaseline"), out_dir=str(out), auth="a",
                               config=str(bad))
        with self.assertRaises(ConfigError):
            R.run_repository(ro)
        with self.assertRaises(ConfigError):
            P.run_positive(po)
        self.assertFalse(out.exists())

    def test_config_flag_exists_and_config_inside_target_or_output_refuses(self):
        from reviewer.pilot import positive as P, repository as R
        for parser in (R._parser(), P._parser()):
            self.assertIn("--config", {s for a in parser._actions for s in a.option_strings})
        good = self.write(toml())
        ro = R.RepositoryOptions(mode="plan", case_dir=str(self.d / "case"), case_pins="p", case_baseline="b",
                                 store="s", base_import_pins="bp", head_import_pins="hp", out_dir=str(self.d / "o"),
                                 auth="a", config=str(good))
        with self.assertRaises(ConfigError):
            R.effective_config(ro)                      # the config lies beside the case: inside the corpus
        po = P.PositiveOptions(mode="plan", source_baseline="b", out_dir=str(self.d), auth="a", config=str(good))
        with self.assertRaises(ConfigError):
            P.effective_config(po)                      # inside the output root


if __name__ == "__main__":
    unittest.main()
