"""CFG-01-review: independent gate for review-model configuration (pullo.toml / --config).

Fake OpenRouter transport and fake key loader only: invented configs, no key, no network, no model call. The
historical, repository and positive entry points are driven through their public `run_*`/`main` functions with the real
pipeline, gateway, ledger and adapter, and the model that answers is whatever the request actually names."""

from __future__ import annotations

import io
import json
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer import config as C
from reviewer.config import ConfigError, ReviewModels, resolve_config
from reviewer.pilot import positive as P, repository as R
from reviewer.pilot.profile import live_plan, live_profile
from reviewer.pilot.repository_profile import repository_plan, repository_profile
from reviewer.runtime import Secret
from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS, gateway_price
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot import helpers as H
from tests.pilot import test_positive as PT
from tests.pilot import test_repository as RT

SONNET, HAIKU, OPUS = "anthropic/claude-sonnet-5.5", "anthropic/claude-haiku-5.5", "anthropic/claude-opus-5.5"
AUTH3 = dict(H.AUTH, models=[SONNET, HAIKU, OPUS])
MIX = (HAIKU, OPUS, SONNET)                                  # investigator, verifier, judge
ROLES = ("investigator", "verifier", "judge")
ROLE_OF = {"InvestigatorOutput": "investigator", "InvestigatorTurn": "investigator", "VerifierOutput": "verifier",
           "VerifierTurn": "verifier", "JudgeOutput": "judge"}
HELD = 'provider = "openai"\nmodel = "gpt-unallowlisted-terra"'


def toml(inv=SONNET, ver=SONNET, jdg=SONNET, extra=""):
    return 'schema = "pullo-config@1"\n' + "".join(
        f'[review.{r}]\nprovider = "anthropic"\nmodel = "{m}"\n' for r, m in zip(ROLES, (inv, ver, jdg))) + extra


def held_toml(role):
    return 'schema = "pullo-config@1"\n' + "".join(
        f"[review.{r}]\n" + (HELD if r == role else f'provider = "anthropic"\nmodel = "{SONNET}"') + "\n" for r in ROLES)


def by_role(requests):
    out = {}
    for r in requests:
        b = json.loads(r.body)
        out.setdefault(ROLE_OF[b["response_format"]["json_schema"]["name"]], set()).add(b["model"])
    return out


def echo(inner):
    """Wrap a fake OpenRouter so the response names the model that was requested (a router that does what it is told)."""
    def call(http_req):
        resp = inner(http_req)
        if resp.status != 200:
            return resp
        d = json.loads(resp.body)
        d["model"] = json.loads(http_req.body)["model"]
        return HttpResponse(200, {}, json.dumps(d).encode())
    return call


def substitute(inner, served=SONNET):
    """A router that quietly serves another model than the one requested."""
    def call(http_req):
        resp = inner(http_req)
        d = json.loads(resp.body)
        d["model"] = served
        return HttpResponse(200, {}, json.dumps(d).encode())
    return call


def all_bytes(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(Path(root).rglob("*")) if p.is_file())


def trace_models(trace_path):
    """{role: {model}} from the recorded model.call events: what was actually asked of the provider."""
    out = {}
    for line in Path(trace_path).read_text().splitlines():
        d = json.loads(line)
        if d.get("type") == "model.call":
            out.setdefault(d["role"], set()).add(d["request"]["model"])
    return out


def receipt_profile_digest(receipt_path):
    return json.loads(Path(receipt_path).read_text())["profile"]["digest"]


def find(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find(v, key)
            if r is not None:
                return r
    return None


class Files(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.d = Path(os.path.realpath(self._t.name))

    def write(self, text, name="c.toml", mode="w"):
        p = self.d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, mode) as f:
            f.write(text)
        return p

    def default_file(self, text, name="app/pullo.toml"):
        """Point Pullo's application-default config at an invented trusted file."""
        p = self.write(text, name)
        patcher = mock.patch.object(C, "DEFAULT_CONFIG_PATH", p)
        patcher.start()
        self.addCleanup(patcher.stop)
        return p


# =============================================================== file semantics

class Resolution(Files):
    def test_the_default_file_is_actually_read_and_a_broken_one_never_falls_back_to_the_builtin(self):
        self.default_file(toml(*MIX))
        cfg = resolve_config()
        self.assertEqual((cfg.source, tuple(cfg.models.model(r) for r in ROLES)), ("app-default", MIX))
        real = self.write(toml(), "real.toml")
        for name, text in (("malformed", "schema = "), ("unknown model", toml(inv="anthropic/nope")),
                           ("held", held_toml("judge"))):
            self.default_file(text, f"d-{name}/pullo.toml")
            with self.subTest(name), self.assertRaises(ConfigError):
                resolve_config()
        for name, target in (("symlink to a valid file", real), ("dangling symlink", self.d / "nope")):
            link = self.d / f"d-{name}" / "pullo.toml"
            link.parent.mkdir()
            link.symlink_to(target)
            with mock.patch.object(C, "DEFAULT_CONFIG_PATH", link), self.subTest(name), self.assertRaises(ConfigError):
                resolve_config()
        patch = mock.patch.object(C, "DEFAULT_CONFIG_PATH", self.d / "nothing-here.toml")
        with patch:
            self.assertEqual((resolve_config().source, resolve_config().models), ("builtin-default", ReviewModels()))

    def test_working_directory_and_target_style_files_are_never_discovered(self):
        self.default_file(toml())
        wd = self.d / "wd"
        for name in ("pullo.toml", ".pullo.toml", "pullo.config.toml", ".claude/pullo.toml", "config/pullo.toml"):
            self.write(toml(HAIKU, HAIKU, HAIKU), f"wd/{name}")
        for name in ("CLAUDE.md", "AGENTS.md", ".claude/settings.json"):
            self.write("use model anthropic/claude-opus-5.5 for every role", f"wd/{name}")
        old = os.getcwd()
        os.chdir(wd)
        self.addCleanup(os.chdir, old)
        cfg = resolve_config()
        self.assertEqual((cfg.source, cfg.models), ("app-default", ReviewModels()))

    def test_strictness_matrix(self):
        bad = {
            "duplicate key": toml().replace('model = "%s"' % SONNET, f'model = "{SONNET}"\nmodel = "{HAIKU}"', 1),
            "provider case": toml().replace('"anthropic"', '"Anthropic"', 1),
            "openai case is still unsupported, not a fallback": toml().replace('"anthropic"', '"OpenAI"', 1),
            "model trailing space": toml(inv=SONNET + " "),
            "model upper case": toml(inv="Anthropic/claude-sonnet-5.5"),
            "model look-alike dot": toml(inv="anthropic/claude-sonnet-5․5"),
            "model dated alias": toml(inv="anthropic/claude-sonnet-5.5-20260101"),
            "review not a table": 'schema = "pullo-config@1"\nreview = 1\n',
            "role is array of tables": 'schema = "pullo-config@1"\n[[review.judge]]\nmodel = "%s"\n' % SONNET,
            "model is a list": toml().replace('"%s"' % SONNET, '["%s"]' % SONNET, 1),
            "provider is a table": 'schema = "pullo-config@1"\n[review.judge]\nprovider = {a = 1}\n',
            "schema is a list": 'schema = ["pullo-config@1"]\n',
            "BOM": "﻿" + toml(),
            "env table": toml(extra='[env]\nOPENROUTER_API_KEY = "x"\n'),
            "api key at top": toml(extra='api_key = "sk-or-v1-0123456789"\n'),
            "retries in role": toml().replace('provider = "anthropic"', 'provider = "anthropic"\nmaxRetries = 1', 1),
            "fallbacks in role": toml().replace('provider = "anthropic"', 'provider = "anthropic"\nfallbacks = []', 1),
            "price in role": toml().replace('provider = "anthropic"', 'provider = "anthropic"\nprice = 0', 1),
            "empty file": "",
            "ESC char": toml() + "\x1b",
            "DEL char": toml() + "#\x7f\n",
            "secret as model value": toml(inv="sk-or-v1-" + "a1b2" * 14),
        }
        for name, text in bad.items():
            with self.subTest(name), self.assertRaises(ConfigError):
                resolve_config(self.write(text, "m.toml"))

    def test_held_provider_refuses_for_every_role_and_names_no_fallback(self):
        for role in ROLES:
            with self.subTest(role), self.assertRaisesRegex(ConfigError, "allowlist.*no\\s+fallback"):
                resolve_config(self.write(held_toml(role), f"h-{role}.toml"))

    def test_size_boundary_is_exact(self):
        base = toml()
        ok = base + "#" * (C.MAX_BYTES - len(base.encode()) - 1) + "\n"
        self.assertEqual(len(ok.encode()), C.MAX_BYTES)
        self.assertEqual(resolve_config(self.write(ok, "ok.toml")).source, "explicit")
        with self.assertRaises(ConfigError):
            resolve_config(self.write(ok + "#", "over.toml"))

    def test_fifo_and_directory_and_symlink_refuse_without_blocking(self):
        fifo = self.d / "fifo.toml"
        os.mkfifo(fifo)
        link = self.d / "link.toml"
        link.symlink_to(self.write(toml(), "real.toml"))
        def timeout(*a):
            raise TimeoutError("config read blocked")
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(10)
        self.addCleanup(signal.alarm, 0)
        for p in (fifo, self.d, link):
            with self.subTest(p.name), self.assertRaises(ConfigError):
                resolve_config(p)

    def test_forbidden_roots_hold_through_dotdot_and_symlinked_directories(self):
        target = self.d / "target"
        inside = self.write(toml(), "target/sub/pullo.toml")
        alias = self.d / "alias"
        alias.symlink_to(target)
        for p in (inside, alias / "sub" / "pullo.toml", self.d / "elsewhere" / ".." / "target" / "sub" / "pullo.toml",
                  str(inside.parent) + "/./pullo.toml"):
            with self.subTest(str(p)), self.assertRaises(ConfigError):
                resolve_config(p, forbidden_roots=(target,))
        elsewhere = self.write(toml(), "other/pullo.toml")
        self.assertEqual(resolve_config(elsewhere, forbidden_roots=(target,)).source, "explicit")

    def test_the_documented_models_are_exactly_the_catalog_allowlist(self):
        import re
        shipped = (C.APP_ROOT / "pullo.toml").read_text()
        self.assertEqual(set(re.findall(r"anthropic/claude-[a-z]+-5\.5", shipped)), set(ALLOWED_ROUTER_MODELS))
        for needle in ("HELD", "no fallback", "--config", "never discovered"):
            self.assertIn(needle.lower(), shipped.lower())
        cfg = resolve_config(C.APP_ROOT / "pullo.toml")
        self.assertEqual(cfg.models, ReviewModels())

    def test_deeply_nested_toml_fails_in_process_before_any_effect(self):
        # ~1 KB of brackets: tomllib raises RecursionError. It must not reach the model stage; see the typed check below.
        with self.assertRaises(Exception):
            resolve_config(self.write("x = " + "[" * 600 + "]" * 600, "deep.toml"))

    def test_deeply_nested_toml_is_a_typed_refusal(self):
        """B1 (fixed in CFG-02): a ~1 KB deeply nested config is refused as ConfigError, not an escaping RecursionError,
        so the CLI entry points (which catch ConfigError) print `error: ConfigError` instead of a traceback."""
        with self.assertRaises(ConfigError):
            resolve_config(self.write("x = " + "[" * 600 + "]" * 600, "deep.toml"))


class Identity(Files):
    def test_profile_roles_follow_the_config_and_nothing_else_widens(self):
        base = live_profile()
        for models in (ReviewModels(*MIX), ReviewModels(judge=OPUS), ReviewModels.uniform(HAIKU)):
            p, rp = live_profile(models=models), repository_profile(True, models)
            for r in ROLES:
                m = models.model(r)
                for prof in (p, rp):
                    s = prof["roles"][r]
                    self.assertEqual((s["provider"], s["model"], s["price"], s["fallbacks"]),
                                     ("anthropic", m, gateway_price(m), []))
                    self.assertEqual((s["caps"], s["params"]), (base["roles"][r]["caps"], base["roles"][r]["params"]))
                    self.assertEqual((s["caps"]["maxRetries"], s["caps"]["maxRepairs"]), (0, 0))
            self.assertEqual(live_plan(p), live_plan(base))
            self.assertEqual(repository_plan(rp), repository_plan(repository_profile(True)))
            self.assertEqual(live_plan(p)["budget"]["maxUsdMicros"], 4_000_000)

    def test_default_profile_is_pinned_literally_as_sonnet_everywhere(self):
        """A literal (not derived from live_profile): any drift in the default identity shows here. The pre-CFG code is
        untracked, so this cannot be diffed against the old bytes; see the handoff limit."""
        def role(r, out, pv, cap):
            return {"provider": "anthropic", "model": SONNET, "family": "claude", "resolved": True,
                    "promptVersion": pv, "outputSchema": out, "params": {"maxOutputTokens": cap},
                    "caps": {"maxOutputTokens": cap, "timeoutSec": {"investigator": 300, "verifier": 150, "judge": 200}[r],
                             "maxRetries": 0, "maxRepairs": 0},
                    "price": gateway_price(SONNET), "fallbacks": []}
        want = {"id": "pilot-live", "version": 1, "tier": "standard", "triage": "fixed-rule@1", "roles": {
            "investigator": role("investigator", "InvestigatorOutput", "investigator.generalist@v1", 16_000),
            "verifier": role("verifier", "VerifierOutput", "verifier.refute@v1", 6_000),
            "judge": role("judge", "JudgeOutput", "judge.wording@v1", 8_000)}}
        self.assertEqual(live_profile(), want)
        self.assertEqual(live_profile(SONNET), want)
        self.assertEqual(live_profile(models=resolve_config(C.APP_ROOT / "pullo.toml").models), want)

    def test_changing_one_role_changes_the_profile_digest_and_two_paths_do_not(self):
        from reviewer.contracts.canonical import digest
        d = {}
        for name, m in (("base", ReviewModels()), ("inv", ReviewModels(investigator=HAIKU)),
                        ("ver", ReviewModels(verifier=HAIKU)), ("jdg", ReviewModels(judge=HAIKU))):
            d[name] = digest(live_profile(models=m))
        self.assertEqual(len(set(d.values())), 4)
        a = resolve_config(self.write(toml(*MIX), "one/a.toml"))
        b = resolve_config(self.write("# same, other path and bytes\n" + toml(*MIX), "two/deeper/b.toml"))
        self.assertEqual(digest(live_profile(models=a.models)), digest(live_profile(models=b.models)))
        self.assertEqual(a.report(), b.report())
        self.assertNotIn(str(self.d), json.dumps(a.report()))


# =============================================================== historical pilot (public CLI)

class Historical(H.Rig):
    def setUp(self):
        super().setUp()
        self.auth.write_text(json.dumps(AUTH3))
        self.cfgdir = self.tmp / "cfg"
        self.cfgdir.mkdir()
        self.n = 0

    def cfg(self, text, name=None):
        self.n += 1
        p = self.cfgdir / (name or f"c{self.n}.toml")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return str(p)

    def default_file(self, text):
        p = self.cfgdir / "app" / "pullo.toml"
        p.parent.mkdir(exist_ok=True)
        p.write_text(text)
        m = mock.patch.object(C, "DEFAULT_CONFIG_PATH", p)
        m.start()
        self.addCleanup(m.stop)
        return p

    def fresh(self):
        """A new output dir and empty durable state so identical identities can be run twice."""
        self.n += 1
        self.out = self.tmp / f"out{self.n}"
        for n in ("spend-book.jsonl", "runtime-ledger.jsonl"):
            (self.state / n).write_bytes(b"")

    def live(self, *extra, text=None):
        self.fresh()
        m = self.model()
        argv = list(extra)
        if text is not None:
            argv = ["--config", self.cfg(text)] + argv
        code, rep, err = self.run_json(self.argv(*argv), transport=echo(m))
        return code, rep, err, m

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def assert_no_effect(self, code, out, err, m, state_before, *, out_dir=None):
        self.assertEqual((code, out), (2, ""))
        self.assertIn("ConfigError", err)
        self.assertEqual(m.requests, [])
        self.assertFalse((out_dir or self.out).exists())
        self.assertEqual(self.state_bytes(), state_before)

    def test_default_file_control_is_read_and_each_role_request_names_its_model(self):
        self.default_file(toml(*MIX))
        code, rep, err, m = self.live()
        self.assertEqual((code, err), (0, ""), rep)
        self.assertEqual(by_role(m.requests), {"investigator": {HAIKU}, "verifier": {OPUS}, "judge": {SONNET}})
        c = rep["cases"][0]
        self.assertEqual(c["reviewModels"]["source"], "app-default")
        self.assertEqual({r: v["model"] for r, v in c["reviewModels"]["roles"].items()},
                         dict(zip(ROLES, MIX)))
        self.assertEqual((c["providerCalls"], len(m.requests)), (3, 3))

    def test_explicit_config_overrides_the_default_file_and_two_trusted_paths_agree_byte_for_byte(self):
        self.default_file(toml(HAIKU, HAIKU, HAIKU))
        bodies, run_ids = [], []
        for name in ("x/first.toml", "y/z/second.toml"):
            self.fresh()
            m = self.model()
            code, rep, err = self.run_json(self.argv("--config", self.cfg(toml(OPUS, SONNET, HAIKU), name)),
                                           transport=echo(m))
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(by_role(m.requests), {"investigator": {OPUS}, "verifier": {SONNET}, "judge": {HAIKU}})
            self.assertEqual(rep["cases"][0]["reviewModels"]["source"], "explicit")
            bodies.append([r.body for r in m.requests])
            run_ids.append(rep["cases"][0]["runId"])
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(run_ids[0], run_ids[1])
        code, rep, err, m = self.live()                       # the patched default (all Haiku) is a different identity
        self.assertEqual(by_role(m.requests), {r: {HAIKU} for r in ROLES})
        self.assertNotEqual(rep["cases"][0]["runId"], run_ids[0])

    def test_single_role_changes_move_only_that_roles_model_and_each_changes_identity(self):
        _, base, _, mb = self.live()
        ids = {"base": base["cases"][0]["runId"]}
        base_body = {ROLE_OF[json.loads(r.body)["response_format"]["json_schema"]["name"]]: json.loads(r.body)
                     for r in mb.requests}
        for i, role in enumerate(ROLES):
            models = {r: SONNET for r in ROLES}
            models[role] = HAIKU
            code, rep, err, m = self.live(text=toml(**{k: v for k, v in zip(("inv", "ver", "jdg"), models.values())}))
            self.assertEqual((code, err), (0, ""), rep)
            self.assertEqual(by_role(m.requests), {r: {models[r]} for r in ROLES})
            ids[role] = rep["cases"][0]["runId"]
            got = {ROLE_OF[json.loads(r.body)["response_format"]["json_schema"]["name"]]: json.loads(r.body)
                   for r in m.requests}
            for r in ROLES:                                  # everything but the changed role's model is untouched
                a, b = dict(base_body[r]), dict(got[r])
                self.assertEqual(a.pop("model"), SONNET)
                b.pop("model")
                self.assertEqual(a, b, f"{role} change altered the {r} request beyond its model")
        self.assertEqual(len(set(ids.values())), 4)

    def test_receipts_trace_and_summary_carry_per_role_models_and_never_a_host_config_path(self):
        code, rep, err, m = self.live(text=toml(*MIX))
        c = rep["cases"][0]
        self.assertEqual(trace_models(c["paths"]["trace"]), {r: {x} for r, x in zip(ROLES, MIX)})
        from reviewer.contracts.canonical import digest
        self.assertEqual(receipt_profile_digest(c["paths"]["receipt"]), digest(live_profile(models=ReviewModels(*MIX))))
        blob = all_bytes(self.out)
        self.assertNotIn(str(self.cfgdir).encode(), blob)
        for r in m.requests:
            self.assertNotIn(str(self.cfgdir).encode(), r.body)
            self.assertNotIn(str(self.tmp).encode(), r.body)
        self.assertNotIn(str(self.cfgdir), json.dumps(rep))

    def test_budget_ceiling_aggregate_and_request_caps_are_independent_of_the_config(self):
        _, base, _, mb = self.live()
        caps = lambda m: sorted((json.loads(r.body)["response_format"]["json_schema"]["name"],
                                 json.loads(r.body)["max_tokens"]) for r in m.requests)
        _, mixed, _, mm = self.live(text=toml(*MIX))
        self.assertEqual(caps(mb), caps(mm))
        for rep in (base, mixed):
            sb = rep["cases"][0]["costs"]["spendBook"]
            self.assertEqual((sb["limit"], sb["inflight"]), (50_000_000, 0))
        self.assertEqual(live_plan(live_profile(models=ReviewModels(*MIX))), live_plan(live_profile()))

    def test_a_router_that_serves_another_model_is_refused_not_accepted_as_a_fallback(self):
        self.fresh()
        m = self.model()
        code, rep, err = self.run_json(self.argv("--config", self.cfg(toml(HAIKU))), transport=substitute(m, SONNET))
        self.assertNotEqual(code, 0)
        self.assertNotEqual(rep["cases"][0].get("status"), "completed")
        self.assertEqual(by_role(m.requests), {"investigator": {HAIKU}})
        self.assertEqual(len(m.requests), 1)                 # no retry, no second model

    def test_authorization_that_lacks_a_role_model_refuses_live_before_the_key_and_plan_does_not_claim_coverage(self):
        self.auth.write_text(json.dumps(dict(H.AUTH, models=[SONNET, HAIKU])))            # no Opus
        st = self.state_bytes()
        m = self.model()
        code, out, err = self.run_main(self.argv("--config", self.cfg(toml(ver=OPUS))), transport=m,
                                       key_loader=H.boom_key_loader)
        self.assertEqual(m.requests, [])
        self.assertFalse(self.out.exists() and any((self.out / "runs").iterdir()))
        self.assertEqual(self.state_bytes(), st)
        self.assertNotEqual(code, 0)
        code, rep, err = self.run_json(self.argv("--config", self.cfg(toml(ver=OPUS)), live=False))
        self.assertNotEqual(code, 0)
        self.assertNotEqual(rep["cases"][0]["status"], "planned")
        self.assertTrue(rep["cases"][0].get("refused"))

    def test_bad_configs_refuse_in_every_mode_before_output_state_key_or_contact(self):
        case = self.corpus / "o--r--1"
        alias = self.tmp / "alias"
        alias.symlink_to(self.corpus)
        inside = {"corpus root": self.corpus / "pullo.toml", "case dir": case / "pullo.toml",
                  "case source": case / "source" / "pullo.toml"}
        for p in inside.values():
            p.write_text(toml())
        (self.corpus / "pullo.toml").write_text(toml())
        fifo, link = self.cfgdir / "fifo.toml", self.cfgdir / "link.toml"
        os.mkfifo(fifo)
        link.symlink_to(self.cfg(toml()))
        cases = {k: str(v) for k, v in inside.items()}
        cases["via symlinked dir into corpus"] = str(alias / "pullo.toml")
        cases |= {"unknown model": self.cfg(toml(inv="anthropic/nope")), "malformed": self.cfg("schema = "),
                  "oversized": self.cfg(toml() + "#" * 9000), "unknown field": self.cfg(toml(extra="x = 1\n")),
                  "secret field": self.cfg(toml(extra='openrouter_key = "sk-or-v1-abc"\n')),
                  "directory": str(self.cfgdir), "fifo": str(fifo), "symlink": str(link),
                  "missing": str(self.cfgdir / "absent.toml")}
        for role in ROLES:
            cases[f"held {role}"] = self.cfg(held_toml(role))
        for name, path in cases.items():                      # the config is refused first in all three modes
            for mode in ("live", "plan", "replay"):
                before, m = self.state_bytes(), self.model()
                if mode == "replay":
                    argv = ["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--case", "o--r--1",
                            "--out", str(self.out), "--replay-trace", str(self.tmp / "no-trace.jsonl"),
                            "--trace-digest", "sha256:" + "0" * 64, "--config", path]
                else:
                    argv = self.argv("--config", path, live=mode == "live")
                with self.subTest(name=name, mode=mode):
                    code, out, err = self.run_main(argv, transport=m, key_loader=H.boom_key_loader)
                    self.assert_no_effect(code, out, err, m, before)

    def test_config_inside_the_output_directory_is_refused_and_leaves_it_untouched(self):
        self.out.mkdir()
        p = self.out / "pullo.toml"
        p.write_text(toml())
        before, m = self.state_bytes(), self.model()
        code, out, err = self.run_main(self.argv("--config", str(p)), transport=m, key_loader=H.boom_key_loader)
        self.assertEqual((code, out, m.requests), (2, "", []))
        self.assertIn("ConfigError", err)
        self.assertEqual(sorted(x.name for x in self.out.iterdir()), ["pullo.toml"])
        self.assertEqual(self.state_bytes(), before)

    def test_deeply_nested_config_still_fails_before_any_effect(self):
        p = self.cfg("x = " + "[" * 600 + "]" * 600)
        before, m = self.state_bytes(), self.model()
        code, out, err = self.run_main(self.argv("--config", p), transport=m, key_loader=H.boom_key_loader)
        self.assert_no_effect(code, out, err, m, before)
        self.assertNotIn("Traceback", err)
        self.assertEqual((m.requests, self.out.exists(), self.state_bytes()), ([], False, before))

    def test_cli_errors_never_echo_any_part_of_a_secret_like_value(self):
        """B3 (fixed in CFG-02): on the operator's stderr, not just in the exception text; no 8-char window either."""
        secret = "sk-or-v1-" + "q7Zx" * 8
        windows = {secret[i:i + 8] for i in range(len(secret) - 7)}
        bad = {"model": toml(inv=secret), "provider": toml().replace('"anthropic"', f'"{secret}"', 1),
               "unknown field": toml(extra=f"{secret} = 1\n"), "unknown role": toml(extra=f"[review.{secret}]\n"),
               "unknown role field": toml().replace('provider = "anthropic"', f'{secret} = "x"', 1),
               "malformed": toml() + f"model = {secret}\n"}
        before = self.state_bytes()
        for name, text in bad.items():
            with self.subTest(name=name):
                m = self.model()
                code, out, err = self.run_main(self.argv("--config", self.cfg(text)), transport=m,
                                               key_loader=H.boom_key_loader)
                self.assert_no_effect(code, out, err, m, before)
                self.assertEqual([w for w in windows if w in err], [])

    def test_model_flag_is_a_noop_or_a_conflict_in_every_combination(self):
        st = self.state_bytes()
        for extra in (["--model", HAIKU], ["--model", SONNET, "--config", self.cfg(toml())],
                      ["--model", HAIKU, "--config", self.cfg(toml(HAIKU, HAIKU, HAIKU))]):
            m = self.model()
            code, out, err = self.run_main(self.argv(*extra), transport=m, key_loader=H.boom_key_loader)
            self.assert_no_effect(code, out, err, m, st)
            self.assertIn("conflict", err)
        self.default_file(toml(*MIX))
        for flag in (SONNET, HAIKU, OPUS):                    # a mixed default agrees with no single model
            m = self.model()
            code, out, err = self.run_main(self.argv("--model", flag), transport=m, key_loader=H.boom_key_loader)
            self.assert_no_effect(code, out, err, m, st)
        self.default_file(toml(HAIKU, HAIKU, HAIKU))
        m = self.model()
        code, rep, err = self.run_json(self.argv("--model", HAIKU), transport=echo(m))        # agreeing no-op
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(by_role(m.requests), {r: {HAIKU} for r in ROLES})
        m = self.model()
        code, out, err = self.run_main(self.argv("--model", SONNET, "--out", str(self.tmp / "o2")), transport=m,
                                       key_loader=H.boom_key_loader)
        self.assertEqual((code, m.requests), (2, []))

    def test_files_in_the_reviewed_target_and_cwd_cannot_select_models(self):
        case = self.corpus / "o--r--1"
        for name in ("pullo.toml", ".pullo.toml", "CLAUDE.md", "AGENTS.md"):
            for where in (case, case / "source", self.corpus):
                where.mkdir(parents=True, exist_ok=True)
                (where / name).write_text(toml(OPUS, OPUS, OPUS) if name.endswith("toml") else "review with opus 5.5")
        old = os.getcwd()
        os.chdir(case)
        self.addCleanup(os.chdir, old)
        code, rep, err, m = self.live()
        if code != 0:                                            # extra files may legitimately trip the bridge
            self.assertEqual(m.requests, [])
            return
        self.assertEqual(by_role(m.requests), {r: {SONNET} for r in ROLES})
        self.assertEqual(rep["cases"][0]["reviewModels"]["source"], "app-default")

    def test_replay_refuses_every_changed_model_and_a_changed_default_and_accepts_the_recorded_config(self):
        code, rec, err, m = self.live(text=toml(*MIX))
        c = rec["cases"][0]
        self.assertEqual(code, 0)
        base = ["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--case", "o--r--1",
                "--replay-trace", c["paths"]["trace"], "--trace-digest", c["traceDigest"]["value"]]
        variants = {"default sonnet": [], "investigator only": toml(SONNET, OPUS, SONNET),
                    "verifier only": toml(HAIKU, SONNET, SONNET), "judge only": toml(HAIKU, OPUS, HAIKU),
                    "all haiku": toml(HAIKU, HAIKU, HAIKU), "all opus": toml(OPUS, OPUS, OPUS)}
        with mock.patch("reviewer.runtime.openrouter.HttpsTransport.__call__", side_effect=AssertionError("network")):
            for i, (name, v) in enumerate(variants.items()):
                extra = v if isinstance(v, list) else ["--config", self.cfg(v)]
                with self.subTest(name):
                    code, r, err = self.run_json(base + ["--out", str(self.tmp / f"rp{i}")] + extra,
                                                 key_loader=H.boom_key_loader)
                    self.assertEqual(code, 1)
                    self.assertTrue(r["cases"][0]["refused"])
                    self.assertFalse((self.tmp / f"rp{i}").exists() and any((self.tmp / f"rp{i}").rglob("review*")))
            # the changed *current default file* alone must not be replayed under either
            self.default_file(toml(HAIKU, OPUS, OPUS))
            code, r, err = self.run_json(base + ["--out", str(self.tmp / "rpd")], key_loader=H.boom_key_loader)
            self.assertEqual((code, r["cases"][0]["refused"]), (1, True))
            # the recorded effective config at a different trusted path, and as the default file, replays cleanly
            for i, extra in enumerate((["--config", self.cfg(toml(*MIX), "z/q/copy.toml")], [])):
                if not extra:
                    self.default_file(toml(*MIX))
                code, r, err = self.run_json(base + ["--out", str(self.tmp / f"rpok{i}")] + extra,
                                             key_loader=H.boom_key_loader)
                self.assertEqual((code, r["cases"][0]["status"], r["cases"][0]["providerCalls"]), (0, "completed", 0))
                self.assertEqual({k: v["model"] for k, v in r["cases"][0]["reviewModels"]["roles"].items()},
                                 dict(zip(ROLES, MIX)))

    def test_help_documents_config_and_deprecates_model(self):
        from reviewer.pilot import cli
        text = cli._parser().format_help()
        self.assertIn("--config", text)
        self.assertIn("pullo.toml", text)
        self.assertRegex(text.replace("\n", " "), r"--model.*DEPRECATED")


# =============================================================== repository entry point

class Repository(RT.Base):
    def setUp(self):
        super().setUp()
        self.w.auth.write_text(json.dumps(AUTH3))
        self.cfgdir = self.tmp / "cfg"
        self.cfgdir.mkdir()
        self.n = 0

    def cfg(self, text, name=None):
        self.n += 1
        p = self.cfgdir / (name or f"c{self.n}.toml")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return str(p)

    def default_file(self, text):
        p = self.cfgdir / "app" / "pullo.toml"
        p.parent.mkdir(exist_ok=True)
        p.write_text(text)
        m = mock.patch.object(C, "DEFAULT_CONFIG_PATH", p)
        m.start()
        self.addCleanup(m.stop)

    def live(self, text=None, *, path=None, retrieval=True, out=None, model=None, **over):
        for n in ("spend-book.jsonl", "runtime-ledger.jsonl"):
            (self.w.state / n).unlink(missing_ok=True)
        self.w.seed()
        m = model or self.model()
        cfgp = path or (self.cfg(text) if text is not None else None)
        rep = R.run_repository(self.w.live_options(config=cfgp, retrieval=retrieval,
                                                   out_dir=str(out or self.tmp / f"out{self.n}"), **over),
                               transport=echo(m), key_loader=self.loader)
        return rep, m

    def test_live_default_file_control_and_explicit_override_follow_per_role_models(self):
        self.default_file(toml(OPUS, HAIKU, SONNET))
        rep, m = self.live()
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 5))
        self.assertEqual(by_role(m.requests), {"investigator": {OPUS}, "verifier": {HAIKU}, "judge": {SONNET}})
        self.assertEqual(rep["reviewModels"]["source"], "app-default")
        rep2, m2 = self.live(toml(*MIX))
        self.assertEqual(by_role(m2.requests), dict(zip(ROLES, ({x} for x in MIX))))
        self.assertEqual(rep2["reviewModels"]["source"], "explicit")
        self.assertNotEqual(rep["runId"], rep2["runId"])

    def test_retrieval_off_also_follows_the_config(self):
        rep, m = self.live(toml(*MIX), retrieval=False, model=H.Model(self.head_id()))
        self.assertEqual(rep["status"], "completed")
        self.assertEqual(by_role(m.requests), dict(zip(ROLES, ({x} for x in MIX))))

    def test_two_trusted_paths_give_identical_requests_and_run_identity_and_no_path_leaks(self):
        runs = []
        for name in ("p/one.toml", "q/r/s/two.toml"):
            rep, m = self.live(path=self.cfg(toml(*MIX), name))
            runs.append((rep, [r.body for r in m.requests]))
            blob = all_bytes(Path(rep["paths"]["runDir"]).parent) + Path(rep["reportPath"]).read_bytes()
            self.assertNotIn(str(self.cfgdir).encode(), blob)
            self.assertNotIn(str(self.cfgdir), json.dumps(rep))
            for b in runs[-1][1]:
                self.assertNotIn(str(self.cfgdir).encode(), b)
        self.assertEqual(runs[0][1], runs[1][1])
        self.assertEqual(runs[0][0]["runId"], runs[1][0]["runId"])

    def test_receipt_carries_per_role_models_and_fixed_caps(self):
        rep, _ = self.live(toml(*MIX))
        self.assertEqual(trace_models(rep["paths"]["trace"]), {r: {x} for r, x in zip(ROLES, MIX)})
        from reviewer.contracts.canonical import digest
        self.assertEqual(receipt_profile_digest(rep["paths"]["receipt"]),
                         digest(repository_profile(True, ReviewModels(*MIX))))

    def test_plan_exposes_models_and_the_first_request_names_the_investigator_model(self):
        for text, want in ((None, SONNET), (toml(HAIKU, OPUS, SONNET), HAIKU)):
            rep = R.run_repository(self.w.options(config=self.cfg(text) if text else None,
                                                  out_dir=str(self.tmp / f"plan{self.n}")))
            self.assertEqual(rep["plan"]["firstRequest"]["model"], want)
            self.assertEqual(rep["status"], "planned")
            if text:
                self.assertEqual(rep["plan"]["model"], "mixed")
                self.assertEqual(rep["plan"]["models"]["verifier"]["model"], OPUS)

    def test_a_substituting_router_is_refused_without_a_second_model(self):
        m = self.model()
        for n in ("spend-book.jsonl", "runtime-ledger.jsonl"):
            (self.w.state / n).unlink(missing_ok=True)
        self.w.seed()
        rep = R.run_repository(self.w.live_options(config=self.cfg(toml(HAIKU)), out_dir=str(self.tmp / "sub")),
                               transport=substitute(m), key_loader=self.loader)
        self.assertFalse(rep["ok"])
        self.assertEqual(len(m.requests), 1)
        self.assertEqual({json.loads(r.body)["model"] for r in m.requests}, {HAIKU})

    def test_replay_refuses_changed_models_and_accepts_the_recorded_config(self):
        rep, _ = self.live(toml(*MIX))
        base = dict(mode="replay", auth=None, replay_trace=rep["paths"]["trace"], trace_digest=rep["traceDigest"]["value"])
        for i, text in enumerate((None, toml(SONNET, OPUS, SONNET), toml(HAIKU, SONNET, SONNET), toml(HAIKU, OPUS, HAIKU))):
            out = self.tmp / f"rp{i}"
            with self.subTest(i), self.assertRaises(Exception) as c:
                R.run_repository(self.w.options(**base, out_dir=str(out), config=self.cfg(text) if text else None),
                                 key_loader=self.boom)
            self.assertEqual(type(c.exception).__name__, "PipelineError")
            self.assertFalse(out.exists())
        ok = R.run_repository(self.w.options(**base, out_dir=str(self.tmp / "rpok"),
                                             config=self.cfg(toml(*MIX), "elsewhere/copy.toml")), key_loader=self.boom)
        self.assertEqual((ok["status"], ok["providerCalls"], ok["replay"]["liveCalls"]), ("completed", 0, 0))

    def test_bad_target_and_malformed_configs_refuse_before_ingest_output_state_key_or_contact(self):
        w = self.w
        inside = {"case dir": w.case_dir / "pullo.toml", "corpus": w.corpus / "pullo.toml",
                  "store": w.store / "pullo.toml", "output": w.out / "pullo.toml"}
        for p in inside.values():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(toml())
        alias = self.tmp / "alias"
        alias.symlink_to(w.store)
        cases = {k: str(v) for k, v in inside.items()}
        cases["via symlinked dir into store"] = str(alias / "pullo.toml")
        cases["unknown model"] = self.cfg(toml(jdg="anthropic/nope"))
        cases["held verifier"] = self.cfg(held_toml("verifier"))
        cases["malformed"] = self.cfg("schema = ")
        cases["oversized"] = self.cfg(toml() + "#" * 9000)
        cases["directory"] = str(self.cfgdir)
        w.seed()
        before = w.state_bytes()
        for name, path in cases.items():
            for mode, extra in (("plan", {}), ("live", dict(state_dir=str(w.state), env_file=str(w.env),
                                                          baseline_micros=RT.BASELINE, confirm_live=True)),
                                ("replay", dict(auth=None, replay_trace=str(self.tmp / "nt"),
                                                trace_digest="sha256:" + "0" * 64))):
                out = w.out if name == "output" else self.tmp / f"never-{self.n}"
                self.n += 1
                m = self.model()
                with self.subTest(name=name, mode=mode), self.assertRaises(C.ConfigError):
                    R.run_repository(w.options(mode=mode, config=path, out_dir=str(out), **extra), transport=m,
                                     key_loader=self.boom)
                self.assertEqual(m.requests, [])
                self.assertEqual(sorted(x.name for x in out.iterdir()) if name == "output" else out.exists(),
                                 ["pullo.toml"] if name == "output" else False)
                self.assertEqual(w.state_bytes(), before)

    def test_cli_wiring_exit_codes_flags_and_messages(self):
        w = self.w
        argv = ["--case-dir", str(w.case_dir), "--case-pins", str(w.case_pins), "--case-baseline", str(w.baseline),
                "--store", str(w.store), "--base-import-pins", str(w.import_pins["base"]),
                "--head-import-pins", str(w.import_pins["head"]), "--auth", str(w.auth), "--json"]
        code, out, err = self.run_main(argv + ["--out", str(self.tmp / "cli1"), "--config", self.cfg(toml(*MIX))],
                                       key_loader=self.boom)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["reviewModels"]["roles"]["verifier"]["model"], OPUS)
        code, out, err = self.run_main(argv + ["--out", str(self.tmp / "cli2"), "--config", self.cfg("schema = ")],
                                       key_loader=self.boom)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("ConfigError", err)
        self.assertFalse((self.tmp / "cli2").exists())
        with self.assertRaises(SystemExit):                  # no ambiguous --model on this entry point
            R._parser().parse_args(argv + ["--out", "x", "--model", SONNET])
        text = R._parser().format_help()
        self.assertIn("--config", text)
        self.assertIn("pullo.toml", text)


# =============================================================== positive entry point

class Positive(PT.Rig):
    def setUp(self):
        super().setUp()
        self.auth.write_text(json.dumps(AUTH3))
        self.cfgdir = self.tmp / "cfg"
        self.cfgdir.mkdir()
        self.n = 0

    cfg = Repository.cfg
    default_file = Repository.default_file

    def live_cfg(self, text=None, *, path=None, model=None, **over):
        for n in ("spend-book.jsonl", "runtime-ledger.jsonl"):
            (self.state / n).unlink(missing_ok=True)
        m = model or self.model()
        cfgp = path or (self.cfg(text) if text is not None else None)
        self.seed()
        self.n += 1
        rep = P.run_positive(self.live_options(config=cfgp, out_dir=str(self.tmp / f"out{self.n}"), **over),
                             transport=echo(m), key_loader=self.loader)
        return rep, m

    def test_default_file_control_and_explicit_override_follow_per_role_models(self):
        self.default_file(toml(OPUS, HAIKU, SONNET))
        rep, m = self.live_cfg()
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 5))
        self.assertEqual(by_role(m.requests), {"investigator": {OPUS}, "verifier": {HAIKU}, "judge": {SONNET}})
        self.assertEqual(rep["reviewModels"]["source"], "app-default")
        rep2, m2 = self.live_cfg(toml(*MIX))
        self.assertEqual(by_role(m2.requests), dict(zip(ROLES, ({x} for x in MIX))))
        self.assertNotEqual(rep["runId"], rep2["runId"])

    def test_two_trusted_paths_give_identical_requests_and_identity_and_no_path_leaks(self):
        runs = []
        for name in ("p/one.toml", "q/r/two.toml"):
            rep, m = self.live_cfg(path=self.cfg(toml(*MIX), name))
            runs.append((rep["runId"], [r.body for r in m.requests]))
            self.assertNotIn(str(self.cfgdir).encode(), all_bytes(Path(rep["paths"]["runDir"]).parent))
            self.assertNotIn(str(self.cfgdir), json.dumps(rep))
            self.assertTrue(all(str(self.cfgdir).encode() not in b for b in runs[-1][1]))
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(trace_models(rep["paths"]["trace"]), {r: {x} for r, x in zip(ROLES, MIX)})

    def test_plan_first_request_and_report_show_the_configured_models(self):
        for text, want in ((None, SONNET), (toml(OPUS, SONNET, HAIKU), OPUS)):
            self.n += 1
            rep = P.run_positive(self.options(config=self.cfg(text) if text else None,
                                              out_dir=str(self.tmp / f"plan{self.n}")))
            self.assertEqual((rep["status"], rep["plan"]["firstRequest"]["model"]), ("planned", want))
            self.assertEqual({r: v["model"] for r, v in rep["plan"]["models"].items()},
                             {r: SONNET for r in ROLES} if text is None else dict(zip(ROLES, (OPUS, SONNET, HAIKU))))

    def test_a_substituting_router_is_refused_without_a_second_model(self):
        for n in ("spend-book.jsonl", "runtime-ledger.jsonl"):
            (self.state / n).unlink(missing_ok=True)
        self.seed()
        m = self.model()
        rep = P.run_positive(self.live_options(config=self.cfg(toml(HAIKU)), out_dir=str(self.tmp / "sub")),
                             transport=substitute(m), key_loader=self.loader)
        self.assertFalse(rep["ok"])
        self.assertEqual({json.loads(r.body)["model"] for r in m.requests}, {HAIKU})
        self.assertEqual(len(m.requests), 1)

    def test_replay_refuses_changed_models_and_a_changed_default_and_accepts_the_recorded_config(self):
        rep, _ = self.live_cfg(toml(*MIX))
        ro = lambda **kw: self.options(mode="replay", auth=None, replay_trace=rep["paths"]["trace"],
                                       trace_digest=rep["traceDigest"]["value"], **kw)
        for i, text in enumerate((None, toml(SONNET, OPUS, SONNET), toml(HAIKU, SONNET, SONNET), toml(HAIKU, OPUS, HAIKU))):
            out = self.tmp / f"rp{i}"
            with self.subTest(i), self.assertRaises(Exception) as c:
                P.run_positive(ro(out_dir=str(out), config=self.cfg(text) if text else None), key_loader=self.boom)
            self.assertEqual(type(c.exception).__name__, "PipelineError")
            self.assertFalse(out.exists())
        self.default_file(toml(HAIKU, OPUS, OPUS))                       # pullo.toml is outside the source baseline scope:
        with self.assertRaises(Exception) as c:                          # its effect is caught by identity, not by hashes
            P.run_positive(ro(out_dir=str(self.tmp / "rpd")), key_loader=self.boom)
        self.assertEqual(type(c.exception).__name__, "PipelineError")
        ok = P.run_positive(ro(out_dir=str(self.tmp / "rpok"), config=self.cfg(toml(*MIX), "k/copy.toml")),
                            key_loader=self.boom)
        self.assertEqual((ok["status"], ok["providerCalls"], ok["replay"]["liveCalls"]), ("completed", 0, 0))

    def test_bad_configs_refuse_before_baseline_fixture_output_state_key_or_contact(self):
        self.out.mkdir()
        (self.out / "pullo.toml").write_text(toml())
        cases = {"inside output": self.out / "pullo.toml", "the source baseline file": self.baseline,
                 "unknown model": self.cfg(toml(inv="anthropic/nope")), "held judge": self.cfg(held_toml("judge")),
                 "malformed": self.cfg("schema = "), "oversized": self.cfg(toml() + "#" * 9000),
                 "directory": self.cfgdir}
        self.seed()
        before = self.state_bytes()
        for name, path in cases.items():
            for mode, extra in (("plan", {}), ("live", dict(state_dir=str(self.state), env_file=str(self.env),
                                                          baseline_micros=PT.BASELINE, confirm_live=True)),
                                ("replay", dict(auth=None, replay_trace=str(self.tmp / "nt"),
                                                trace_digest="sha256:" + "0" * 64))):
                m = self.model()
                with self.subTest(name=name, mode=mode), self.assertRaises(C.ConfigError):
                    P.run_positive(self.options(mode=mode, config=str(path), **extra), transport=m, key_loader=self.boom)
                self.assertEqual(m.requests, [])
                self.assertEqual(self.state_bytes(), before)
        self.assertEqual(sorted(x.name for x in self.out.iterdir()), ["pullo.toml"])

    def test_a_config_inside_the_fixture_is_refused_by_root_not_only_by_missing_file(self):
        inside = str(P.FIXTURE / "base" / "pullo.toml")
        with mock.patch.object(C, "_read", return_value=toml()):            # the bytes would be valid
            with self.assertRaises(C.ConfigError):
                P.effective_config(self.options(config=inside))
            self.assertEqual(P.effective_config(self.options(config=str(self.tmp / "ok.toml"))).source, "explicit")

    def test_cli_wiring_exit_codes_flags_and_messages(self):
        argv = ["--source-baseline", str(self.baseline), "--auth", str(self.auth), "--json"]
        code, out, err = self.run_main(argv + ["--out", str(self.tmp / "c1"), "--config", self.cfg(toml(*MIX))],
                                       key_loader=self.boom)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["reviewModels"]["roles"]["investigator"]["model"], HAIKU)
        code, out, err = self.run_main(argv + ["--out", str(self.tmp / "c2"), "--config", self.cfg(toml(ver="x/y"))],
                                       key_loader=self.boom)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("ConfigError", err)
        self.assertFalse((self.tmp / "c2").exists())
        with self.assertRaises(SystemExit):
            P._parser().parse_args(argv + ["--out", "x", "--model", SONNET])
        text = P._parser().format_help()
        self.assertIn("--config", text)
        self.assertIn("pullo.toml", text)


if __name__ == "__main__":
    unittest.main()
