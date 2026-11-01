"""OPENCODE-FREE-PROVIDER: the opencode free-model adapter, offline. The fake CLI (opencode_fake) writes the per-call
session DB and the JSON event stream the real opencode 2.1.4 produces; no network, no key, no real CLI."""

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from reviewer.runtime import RuntimeLedger
from reviewer.runtime import opencode_capture as CAP
from reviewer.runtime import opencode_cli as O
from reviewer.runtime import schemas
from reviewer.runtime.catalog import OPENCODE_DEFAULT_MODEL, OPENCODE_MODELS, opencode_pacing_micros
from tests.runtime import opencode_fake as F

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)
GOOD = {"supported": True, "problems": []}
HOSTILE_ENV = {"PATH": os.environ["PATH"], "HOME": "/home/operator", "OPENROUTER_API_KEY": "sk-or-v1-" + "f4k3" * 12,
               "OPENAI_API_KEY": "sk-proj-" + "x" * 30, "OPENCODE_API_KEY": "zen-key", "ANTHROPIC_API_KEY": "sk-ant-x",
               "HTTPS_PROXY": "http://proxy", "XDG_DATA_HOME": "/home/operator/.local/share", "LANG": "C.UTF-8"}
ALLOWED_ENV = {"PATH", "LANG", "LC_ALL", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
               "TMPDIR", "OPENCODE_CONFIG_CONTENT", *dict(O.ENV_FLAGS)}


def _bwrap_works() -> bool:
    bw = shutil.which("bwrap")
    if not bw:
        return False
    try:
        return subprocess.run([bw, "--ro-bind", "/", "/", "--dev", "/dev", "--", "true"], capture_output=True,
                              timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


BWRAP = _bwrap_works()


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.dir = self._t.name

    def prov(self, *scenarios, answer=None, **kw):
        self.runner = F.ScriptedRunner(*scenarios, answer=answer)
        self.led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)
        kw.setdefault("environ", HOSTILE_ENV)
        return O.OpenCodeFreeProvider(enabled=True, ledger=self.led, runner=self.runner, preflight=GOOD,
                                      workdir_parent=self.dir, **kw)

    def rows(self):
        p = os.path.join(self.dir, "led.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(x) for x in f]

    def leftovers(self):
        return [n for n in os.listdir(self.dir) if n.startswith("rvw-opencode-")]


class Settings(unittest.TestCase):
    def test_argv_is_pinned_prompt_free_and_never_auto(self):
        argv = O.build_argv("opencode", OPENCODE_DEFAULT_MODEL)
        self.assertEqual(argv, ["opencode", "run", "--standalone", "--format", "json", "--agent", "pullo", "--model",
                                OPENCODE_DEFAULT_MODEL])
        self.assertFalse(O.FORBIDDEN_FLAGS & set(argv))
        self.assertIn("--auto", O.FORBIDDEN_FLAGS)

    def test_config_denies_every_tool_restricts_providers_and_disables_hidden_calls(self):
        c = json.loads(O.config_text(OPENCODE_DEFAULT_MODEL, "VerifierOutput"))
        deny = [{"action": "*", "resource": "*", "effect": "deny"}]
        self.assertEqual(c["permissions"], deny)
        a = c["agents"]["pullo"]
        self.assertEqual((a["permissions"], a["system"], a["mode"], a["steps"]), (deny, O.BASE_INSTRUCTIONS, "primary", 2))
        self.assertEqual(c["agents"]["title"], {"disabled": True})
        self.assertEqual(c["policies"], [{"action": "provider.use", "resource": "*", "effect": "deny"},
                                         {"action": "provider.use", "resource": "opencode", "effect": "allow"},
                                         {"action": "tool.use", "resource": "*", "effect": "deny"},
                                         {"action": "integration.use", "resource": "*", "effect": "deny"}])
        self.assertEqual((c["share"], c["update"], c["snapshots"], c["lsp"], c["formatter"], c["websearch"], c["warming"]),
                         ("disabled", "disable", False, False, False, False, False))
        self.assertEqual((c["mcp"], c["plugins"], c["skills"], c["instructions"], c["compaction"]),
                         ({}, [], [], [], {"auto": False}))
        self.assertEqual(c["default_agent"], "pullo")
        body = c["providers"]["opencode"]["models"]["deepseek-v4.1-flash-free"]["body"]
        self.assertEqual(body["response_format"]["json_schema"]["schema"],
                         schemas.provider_schema("VerifierOutput", "openai-strict"))
        self.assertTrue(body["response_format"]["json_schema"]["strict"])
        self.assertNotIn("settings", c["providers"]["opencode"])            # no baseURL override outside the proof
        self.assertNotIn("providers", json.loads(O.config_text(OPENCODE_DEFAULT_MODEL)))
        self.assertEqual(json.loads(O.config_text(OPENCODE_DEFAULT_MODEL, "VerifierOutput", base_url="http://127.0.0.1:1/v1"))
                         ["providers"]["opencode"]["settings"], {"baseURL": "http://127.0.0.1:1/v1"})

    def test_prompt_wraps_messages_and_quotes_the_same_schema_codex_gets(self):
        r = F.opencode_request("verifier")
        p = O._prompt(r)
        self.assertIn("<user>\nDiff:\n+x = 1\n\n</user>", p)
        self.assertIn(schemas.schema_bytes("VerifierOutput", "openai-strict").decode(), p)
        f = O.request_facts(r)
        self.assertEqual(f["bodySha256"], hashlib.sha256(p.encode()).hexdigest())
        self.assertEqual(f["schemaSha256"], hashlib.sha256(schemas.schema_bytes("VerifierOutput", "openai-strict")).hexdigest())
        self.assertEqual((f["billingKind"], f["worstCaseRouterUsdMicros"], f["provider"]), ("free-model", 0, "opencode"))
        self.assertGreater(f["worstCaseApiEquivalentUsdMicros"], 0)
        self.assertEqual(f, O.request_facts(F.opencode_request("verifier")))          # deterministic
        self.assertEqual(f["configSha256"], "sha256:" + hashlib.sha256(O.config_text(OPENCODE_DEFAULT_MODEL, "VerifierOutput")
                                                                      .encode()).hexdigest())

    def test_prompt_mode_drops_the_response_format_but_keeps_the_schema_in_the_prompt(self):
        from unittest import mock
        entry = dict(OPENCODE_MODELS[OPENCODE_DEFAULT_MODEL], structured="prompt")
        with mock.patch.dict(OPENCODE_MODELS, {OPENCODE_DEFAULT_MODEL: entry}):
            c = json.loads(O.config_text(OPENCODE_DEFAULT_MODEL, "VerifierOutput"))
            self.assertNotIn("providers", c)
            self.assertIn("<output-schema", O._prompt(F.opencode_request("verifier")))
            self.assertEqual(O.isolation_identity(OPENCODE_DEFAULT_MODEL)["structuredMode"], "prompt")

    def test_identity_differs_per_model_and_is_stable(self):
        a, b = (O.isolation_identity(m) for m in sorted(OPENCODE_MODELS))
        self.assertNotEqual(a["argvSha256"], b["argvSha256"])
        self.assertEqual(a, O.isolation_identity(sorted(OPENCODE_MODELS)[0]))
        self.assertEqual(a["isolationVersion"], "opencode-isolated-home@2")
        self.assertEqual(a["cliRetries"], O.RETRY_POLICY)
        self.assertIn("killed-when-scheduled", a["cliRetries"])
        self.assertEqual((a["agentSteps"], a["maxRequestsPerCall"]), (2, 2))
        self.assertEqual((a["sandbox"], a["sandboxSha256"]), (O.SANDBOX_VERSION, O.sandbox_identity()["sandboxSha256"]))

    def test_gateway_free_model_skip_needs_a_pinned_free_model(self):
        from reviewer.gateway import gateway as G
        self.assertTrue(all(G._opencode_free_model(m) for m in OPENCODE_MODELS))
        for m in ("opencode/big-pickle", "anthropic/claude-sonnet-5.5", None):
            self.assertFalse(G._opencode_free_model(m))

    def test_sandbox_prefix_masks_credentials_and_state_and_keeps_only_the_work_dir_writable(self):
        masks = [("dir", "/h/.aws"), ("dir", "/h/.config/opencode"), ("file", "/r/.env")]
        pre = O.sandbox_prefix("/usr/bin/bwrap", "/w/rvw-opencode-x", masks, "/h", "/run/user/7")
        self.assertEqual(pre, ["/usr/bin/bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/h",
                               "--unshare-pid", "--proc", "/proc", "--unshare-ipc", "--tmpfs", "/run/user/7", "--tmpfs", "/tmp",
                               "--tmpfs", "/var/tmp", "--tmpfs", "/h/.aws", "--tmpfs", "/h/.config/opencode", "--ro-bind", "/dev/null", "/r/.env",
                               "--bind", "/w/rvw-opencode-x", "/w/rvw-opencode-x", "--chdir", "/w/rvw-opencode-x/cwd", "--"])
        self.assertNotIn("--unshare-net", pre)                                     # the free endpoint needs the network
        argv = pre + O.build_argv("opencode", OPENCODE_DEFAULT_MODEL)
        self.assertEqual(O.split_sandbox(argv), (pre, O.build_argv("opencode", OPENCODE_DEFAULT_MODEL)))
        self.assertEqual(O.split_sandbox(["opencode", "--version"]), (None, ["opencode", "--version"]))
        self.assertTrue(O.is_review_call(argv) and O.is_review_call(argv[len(pre):]))
        self.assertEqual(O.sandbox_identity()["sandbox"], "opencode-bwrap-masked@3")
        self.assertNotIn("/run/user/7", O.sandbox_prefix("/usr/bin/bwrap", "/w/x", masks, "/h", None))   # no runtime dir, no mask
        self.assertTrue(O.under("/h/x/y", "/h") and O.under("/h", "/h") and not O.under("/hx/y", "/h"))

    def test_the_whole_passwd_home_is_masked_and_a_binary_under_it_is_refused(self):
        from unittest import mock
        import pwd
        self.assertEqual(O.real_home(), os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))
        with mock.patch.dict(os.environ, {"HOME": "/nonexistent-home"}):
            self.assertEqual(O.real_home(), os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))   # passwd, never $HOME
        with tempfile.TemporaryDirectory() as h:
            binp = Path(h, ".opencode", "bin", "opencode")
            binp.parent.mkdir(parents=True)
            binp.write_text("#!/bin/sh\n")
            binp.chmod(0o755)
            with mock.patch.object(O, "real_home", return_value=os.path.realpath(h)):
                with self.assertRaisesRegex(O.OpenCodeUnsupported, "under the user home"):
                    O.OpenCodeFreeProvider(enabled=True, preflight=GOOD, opencode=str(binp))
                r = O.check_cli_isolation(str(binp), lambda a, e, c: O.RunResult(0, b"", b""), capture=False)
                self.assertIn("the opencode binary resolves under the user home, which the sandbox masks", r["problems"])
        with mock.patch.object(O, "real_home", return_value=None), self.assertRaisesRegex(O.OpenCodeUnsupported, "home"):
            O.OpenCodeFreeProvider(enabled=True, preflight=GOOD)

    def test_sandbox_masks_cover_existing_home_dirs_and_env_files_only(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as h, tempfile.TemporaryDirectory() as c:
            for rel in (".config/opencode", ".aws", ".local/state/pullo/x"):
                os.makedirs(os.path.join(h, rel))
            Path(c, ".env").write_text("OPENROUTER=not-a-key\n")
            os.symlink(os.path.join(h, ".aws"), os.path.join(h, ".cache-link"))
            Path(h, "checkout.env").write_text("KEY=x\n")
            old = os.getcwd()
            os.chdir(c)
            try:
                with mock.patch.object(O, "_user_homes", return_value=[h]):
                    got = O.sandbox_masks()
                    with mock.patch.object(O, "HOST_MASKS", [os.path.join(h, "checkout.env"), "relative/.env",
                                                             os.path.join(h, "missing.env")]):
                        hosted = O.sandbox_masks()
            finally:
                os.chdir(old)
            real = lambda *x: os.path.realpath(os.path.join(*x))              # noqa: E731
            want = [("dir", real(h, ".aws")), ("dir", real(h, ".config/opencode")), ("dir", real(h, ".local/state/pullo")),
                    ("file", real(c, ".env"))]
            self.assertEqual(got, sorted(want, key=lambda x: x[1]))
            self.assertEqual(hosted, sorted(want + [("file", real(h, "checkout.env"))], key=lambda x: x[1]))


class Calls(Base):
    def test_success_is_isolated_keyless_free_and_paced(self):
        p = self.prov()
        r = F.opencode_request()
        res = p.call(r, KEY)
        self.assertEqual((res.outcome, res.response["status"], res.response["output"]), ("processed", "ok", F.OK_INV))
        self.assertEqual(res.response["usage"], {"uncachedInputTokens": 1000, "cachedInputTokens": 200,
                                                 "cacheWriteInputTokens": 0, "outputTokens": 50, "reasoningTokens": 10})
        self.assertEqual(res.response["providerRequestId"], F.SID)
        s = self.runner.seen[0]
        work = os.path.dirname(s["cwd"])
        self.assertEqual(O.split_sandbox(s["argv"]),                                # every live call is sandboxed
                         (O.sandbox_prefix(p._bwrap, work, O.sandbox_masks(), O.real_home(), O.runtime_dir()),
                          O.build_argv("opencode", OPENCODE_DEFAULT_MODEL)))
        self.assertTrue(s["polled"])                                               # with the session-DB retry watch
        self.assertEqual(set(s["env"]) - ALLOWED_ENV, set())                       # no key, no proxy, no operator dirs
        self.assertTrue(s["env"]["HOME"].startswith(self.dir) and "/home/operator" not in json.dumps(s["env"]))
        self.assertEqual(s["cwd_listing"], [])
        self.assertEqual(s["stdin"], O._prompt(r).encode())
        self.assertNotIn(O._prompt(r), " ".join(s["argv"]))
        self.assertEqual(self.leftovers(), [])                                    # the per-call dir is removed
        intent, result = self.rows()
        self.assertEqual((intent["type"], intent["worstCaseUsdMicros"]), ("intent", 0))
        self.assertEqual((result["kind"], result["billingKind"], result["costBasis"], result["outcome"]),
                         ("opencode-cli", "free-model", "free-model-zero", "processed"))
        self.assertEqual(result["apiEquivalentEstimateUsdMicros"], opencode_pacing_micros(1000, 200, 0, 50))
        self.assertEqual(result["isolation"]["toolItems"], 0)
        self.assertEqual((result["isolation"]["requestsSeen"], result["isolation"]["sandbox"]), (1, O.SANDBOX_VERSION))
        self.assertEqual(self.led.totals()["committedUsdMicros"], 0)

    def test_fenced_answer_is_accepted_and_noted_prose_is_invalid_output(self):
        p = self.prov("fenced", "prose", "length")
        ok = p.call(F.opencode_request(), KEY)
        self.assertEqual(ok.response["status"], "ok")
        bad = p.call(F.opencode_request(), ("INVESTIGATE", "investigator", "g", 1, 0))
        self.assertEqual((bad.outcome, bad.response["status"]), ("processed", "invalid-output"))
        self.assertIn("Here is the JSON", bad.response["rawText"])
        cut = p.call(F.opencode_request(), ("INVESTIGATE", "investigator", "g", 2, 0))
        self.assertEqual(cut.response["status"], "invalid-output")
        notes = [r.get("note") for r in self.rows() if r["type"] == "result"]
        self.assertEqual(notes, ["fenced-json", "invalid-output", "invalid-output,finish-length"])

    def test_tool_attempt_is_discarded_and_an_executed_tool_disables_the_adapter(self):
        p = self.prov("toolcall", "executed", "ok")
        res = p.call(F.opencode_request(), KEY)
        self.assertEqual((res.outcome, res.error["detail"]["reason"], res.error["detail"]["itemType"],
                          res.error["detail"]["requestsSeen"]), ("unknown", "isolation-violation", "tool-attempt", 1))
        self.assertIsNone(p.disabled_reason)                                       # attempted, not executed
        res = p.call(F.opencode_request(), ("INVESTIGATE", "investigator", "g", 1, 0))
        self.assertEqual(res.error["detail"]["itemType"], "tool-executed")
        self.assertEqual(p.disabled_reason, "tool-executed")
        res = p.call(F.opencode_request(), ("INVESTIGATE", "investigator", "g", 2, 0))
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "adapter-disabled"))
        self.assertEqual(len(self.runner.seen), 2)

    def test_credentials_config_or_a_second_session_in_the_home_disable_the_adapter(self):
        for sc, cause in (("authfile", "forbidden-home-entry"), ("config-written", "forbidden-home-entry"),
                          ("second-session", "extra-session")):
            with self.subTest(sc):
                p = self.prov(sc)
                res = p.call(F.opencode_request(), KEY)
                self.assertIsNone(res.response)
                self.assertEqual((res.error["detail"]["reason"], p.disabled_reason), ("isolation-violation", cause))

    def test_free_usage_limit_keeps_the_cli_words(self):
        p = self.prov("freelimit")
        res = p.call(F.opencode_request(), KEY)
        e = res.error
        self.assertEqual((res.outcome, e["code"]), ("rejected-before-processing", "provider-error"))
        for s in ("provider.free-limit", "HTTP 429", "Free usage limit reached", "FreeUsageLimitError"):
            self.assertIn(s, e["message"])
        d = e["detail"]
        self.assertEqual((d["reason"], d["errorType"], d["httpStatus"], d["exitCode"]),
                         ("cli-failure", "provider.free-limit", 429, 1))
        self.assertIn("Free usage limit reached for today", d["responseBody"])
        row = self.rows()[-1]
        self.assertIn("provider.free-limit 429: Free usage limit reached", row["note"])
        self.assertEqual(row["errorKind"], "cli-failure")

    def test_a_hidden_cli_retry_is_killed_when_scheduled_before_it_is_sent(self):
        p = self.prov("retry")
        res = p.call(F.opencode_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["reason"], d["errorType"], d["httpStatus"]),
                         ("rejected-before-processing", "cli-retry", "provider.rate-limit", 429))
        self.assertEqual((d["requestsSeen"], d["retryRequestSeen"], d["cliScheduledAttempt"]), (1, False, 2))
        self.assertNotIn("attempts", d)
        self.assertIn("Rate limit exceeded: free tier", res.error["message"])
        self.assertIn("hidden retry", res.error["message"])
        self.assertIn("killed when it was scheduled; provider requests seen: 1 (at least; at most 2)", res.error["message"])
        self.assertEqual(self.rows()[-1]["isolation"]["requestsSeen"], 1)

    def test_a_retry_request_that_left_is_killed_and_counted_never_claimed_prevented(self):
        p = self.prov("retry-fast")
        res = p.call(F.opencode_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["reason"], d["requestsSeen"], d["retryRequestSeen"], d["cliScheduledAttempt"]),
                         ("unknown", "cli-retry", 2, True, 2))
        self.assertIn("killed at its request; provider requests seen: 2 (at least; at most 2)", res.error["message"])
        self.assertEqual(self.rows()[-1]["isolation"]["requestsSeen"], 2)

    def test_a_retry_the_stream_missed_is_recorded_not_hidden(self):
        p = self.prov("retried-ok")
        res = p.call(F.opencode_request(), KEY)
        self.assertEqual(res.response["status"], "ok")
        row = self.rows()[-1]
        self.assertEqual((row["note"], row["isolation"]["cliScheduledAttempt"], row["isolation"]["requestsSeen"]),
                         ("hidden-cli-retry:attempt-2:requests-seen-1", 2, 1))

    def test_timeout_reports_the_last_scheduled_retry_error(self):
        p = self.prov("timeout", timeout_sec=10)
        res = p.call(F.opencode_request(), KEY)
        self.assertEqual((res.outcome, res.error["code"], res.error["detail"]["reason"]),
                         ("unknown", "provider-timeout", "timeout"))
        self.assertIn("provider.rate-limit", res.error["message"])

    def test_stderr_tail_is_kept_when_the_cli_gives_no_structured_error(self):
        res = self.prov("stderr-only").call(F.opencode_request(), KEY)
        self.assertEqual(res.error["detail"]["reason"], "cli-failure")
        self.assertIn("Server process exited with code 1", res.error["detail"]["stderrTail"])
        self.assertNotIn("\x1b", res.error["detail"]["stderrTail"])

    def test_audit_failures_discard_output(self):
        for sc, item in (("unknown-event", "unknown-event:session.weird"), ("synthetic-message", "db-message:synthetic"),
                         ("wrong-model", "session-agent-or-model"), ("no-db", "session-db-missing")):
            with self.subTest(sc):
                res = self.prov(sc).call(F.opencode_request(), KEY)
                self.assertIsNone(res.response)
                self.assertEqual((res.error["detail"]["reason"], res.error["detail"]["itemType"]),
                                 ("isolation-violation", item))
        res = self.prov("no-text").call(F.opencode_request(), KEY)
        self.assertEqual(res.error["detail"]["reason"], "no-final-message")

    def test_refusals_happen_before_any_spawn_or_ledger_row(self):
        p = self.prov()
        bad = [F.opencode_request(provider="openai"), F.opencode_request(model="opencode/big-pickle"),
               F.opencode_request(model="openrouter/deepseek/deepseek-v4.1-flash"),
               F.opencode_request(tools=[{"type": "function"}]),
               F.opencode_request(messages=[{"role": "tool", "content": "x"}]),
               dict(F.opencode_request(), role="extractor"), F.opencode_request(outputSchema="JudgeOutput")]
        for n, r in enumerate(bad):
            with self.subTest(n):
                res = p.call(r, ("INVESTIGATE", "investigator", "g", n, 0))
                self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "request-refused"))
        big = F.opencode_request(text="x" * (OPENCODE_MODELS[OPENCODE_DEFAULT_MODEL]["contextTokens"] * 4 + 1))
        res = p.call(big, ("INVESTIGATE", "investigator", "g", 99, 0))
        self.assertEqual(res.error["detail"]["reason"], "request-too-large")
        self.assertEqual((self.runner.seen, self.rows()), ([], []))

    def test_call_cap_timeout_cap_and_opt_in(self):
        p = self.prov(max_calls=1)
        p.call(F.opencode_request(), KEY)
        res = p.call(F.opencode_request(), ("INVESTIGATE", "investigator", "g", 1, 0))
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "call-cap"))
        p = self.prov(timeout_sec=20)
        p.call(F.opencode_request(params={"maxOutputTokens": 10, "timeoutSec": 999}), KEY)
        self.assertEqual(self.runner.seen[0]["timeout"], 20.0)
        for kw in ({"enabled": False}, {"enabled": True, "family": "score"}, {"enabled": True, "max_calls": 129},
                   {"enabled": True, "timeout_sec": 1201}, {"enabled": True, "models": ["opencode/big-pickle"]}):
            with self.subTest(kw), self.assertRaises(ValueError):
                O.OpenCodeFreeProvider(preflight=GOOD, **kw)
        with self.assertRaises(O.OpenCodeUnsupported):
            O.OpenCodeFreeProvider(enabled=True, preflight={"supported": False, "problems": ["x"]})
        from unittest import mock
        with mock.patch.object(O.shutil, "which", return_value=None), self.assertRaisesRegex(O.OpenCodeUnsupported, "bwrap"):
            O.OpenCodeFreeProvider(enabled=True, preflight=GOOD)                # no sandbox, no live call

    def test_runner_crash_and_missing_binary(self):
        led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)
        for exc, outcome, reason in ((FileNotFoundError(), "not-sent", "opencode-missing"),
                                     (RuntimeError("boom"), "unknown", "runner-crash")):
            def runner(*a, **k):
                raise exc
            p = O.OpenCodeFreeProvider(enabled=True, ledger=led, runner=runner, preflight=GOOD, workdir_parent=self.dir)
            res = p.call(F.opencode_request(), (reason, "investigator", "g", 0, 0))
            self.assertEqual((res.outcome, res.error["detail"]["reason"]), (outcome, reason))
        self.assertEqual(self.leftovers(), [])


@unittest.skipUnless(shutil.which("bwrap"), "the guard pins the system bwrap")
class Guard(Base):
    def test_review_call_guard_accepts_the_real_call_and_refuses_drift(self):
        p = self.prov()
        r = F.opencode_request()
        p.call(r, KEY)
        s = self.runner.seen[0]
        first = O.request_facts(r)
        self.assertTrue(O.is_review_call(s["argv"]))
        self.assertFalse(O.is_review_call(["opencode", "--version"]))
        ok = lambda **o: O.review_call_problems(o.get("argv", s["argv"]), o.get("stdin", s["stdin"]), o.get("env", s["env"]),
                                                s["cwd"], o.get("model", OPENCODE_DEFAULT_MODEL), o.get("first", first))
        self.assertEqual(ok(), [])
        cfg = json.loads(s["env"]["OPENCODE_CONFIG_CONTENT"])
        evil = dict(cfg, providers={"opencode": {"settings": {"baseURL": "http://evil"}}})
        pre, inner = O.split_sandbox(s["argv"])
        loose = [x for x in pre if x != "--die-with-parent"]
        cases = {"argv differs from the pinned review argv for this model": dict(argv=s["argv"] + ["--auto"]),
                 "review call is not inside the bwrap sandbox": dict(argv=inner),
                 "sandbox argv differs from the pinned bwrap sandbox for this call": dict(argv=loose + inner),
                 "child environment is not the scratch-built allowlist": dict(env=dict(s["env"], OPENROUTER_API_KEY="x")),
                 "first call stdin differs from the plan": dict(stdin=s["stdin"] + b" "),
                 "config is not the pinned deny-all config (or overrides the provider endpoint)":
                     dict(env=dict(s["env"], OPENCODE_CONFIG_CONTENT=json.dumps(evil))),
                 "first call config differs from the plan": dict(first=dict(first, configSha256="sha256:0"))}
        for want, over in cases.items():
            with self.subTest(want):
                self.assertIn(want, ok(**over))
        self.assertIn("argv differs from the pinned review argv for this model", ok(model="opencode/glm-5.3-flash-free"))
        self.assertEqual(pre[7:9], ["--tmpfs", O.real_home()])                    # the whole home, right after the root
        fixed = O.sandbox_prefix(pre[0], os.path.dirname(s["cwd"]), [], O.real_home(), O.runtime_dir())[:-6]
        self.assertEqual(pre[:len(fixed)], fixed)
        hardening = [i for i, x in enumerate(pre) if x in ("--unshare-pid", "--unshare-ipc")]
        for drifted in (fixed + pre[-6:], pre[:7] + pre[9:],                      # the per-path masks or the home tmpfs dropped
                        [x for i, x in enumerate(pre) if i not in hardening]):    # the PID/IPC namespaces dropped
            if drifted != pre:
                self.assertIn("sandbox argv differs from the pinned bwrap sandbox for this call", ok(argv=drifted + inner))


class Audits(unittest.TestCase):
    def feed(self, *lines):
        a = O.StreamAudit()
        return [a.feed(x.encode()) for x in lines][-1]

    def test_stream_audit(self):
        self.assertEqual(self.feed(F.step_start(), F.tool_ev()), "tool-attempt")
        self.assertEqual(self.feed(F.step_start(), F.step_start()), "cli-retry")
        self.assertEqual(self.feed(F.step_start("m1"), F.step_start("m2")), "extra-step")
        self.assertIsNone(self.feed("garbage", "[1]", F.step_start(), F.text_ev("{}"), F.ev("step_finish")))

    def test_json_extraction_tolerates_one_whole_fence_only(self):
        self.assertEqual(O.extract_json_text(' {"a": 1} '), ('{"a": 1}', False))
        self.assertEqual(O.extract_json_text('```json\n{"a": 1}\n```'), ('{"a": 1}', True))
        self.assertEqual(O.extract_json_text('```\n{"a": 1}\n```\n'), ('{"a": 1}', True))
        self.assertEqual(O.extract_json_text('x ```json\n{}\n```')[1], False)
        self.assertEqual(O.extract_json_text('```json\n{}\n```\nmore')[1], False)

    def test_session_db_audit(self):
        with tempfile.TemporaryDirectory() as d:
            F.write_db(os.path.join(d, "data"), messages=[F.SWITCH, F.USER, F.assistant(text="{}"), F.idle()])
            a = O.audit_session_db(d, OPENCODE_DEFAULT_MODEL)
            self.assertTrue(a["ok"], a)
            self.assertEqual((a["text"], a["finish"], a["assistants"], a["sessionId"]), ("{}", "stop", 1, F.SID))
            self.assertEqual(a["tokens"], {"input": 1000, "output": 40, "reasoning": 10, "read": 200, "write": 0})
        with tempfile.TemporaryDirectory() as d:
            F.write_db(os.path.join(d, "data"), messages=[F.USER, F.USER, F.assistant(text="{}")])
            self.assertIn("user-message-count", O.audit_session_db(d, OPENCODE_DEFAULT_MODEL)["problems"])
        with tempfile.TemporaryDirectory() as d:
            F.write_db(os.path.join(d, "data"), agent="build", messages=[F.USER, F.assistant(text="{}")])
            self.assertIn("session-agent-or-model", O.audit_session_db(d, OPENCODE_DEFAULT_MODEL)["problems"])
        with tempfile.TemporaryDirectory() as d:
            db = Path(d, "data", "opencode")
            db.mkdir(parents=True)
            con = sqlite3.connect(db / "opencode.db")
            con.execute("create table other (x)")
            con.commit()
            con.close()
            self.assertTrue(O.audit_session_db(d, OPENCODE_DEFAULT_MODEL)["problems"][0].startswith("session-db-unreadable"))

    def test_retry_watch_reads_the_scheduled_retry_and_never_raises(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(O.retry_scheduled(d))                                   # no DB yet
            F.write_db(os.path.join(d, "data"), messages=[F.SWITCH, F.USER, F.assistant(tokens=None)])
            self.assertFalse(O.retry_scheduled(d))
        with tempfile.TemporaryDirectory() as d:
            F.write_db(os.path.join(d, "data"), messages=[F.SWITCH, F.USER, F.assistant(
                tokens=None, retry={"attempt": 2, "at": 9, "error": F.RATE})])
            self.assertTrue(O.retry_scheduled(d))
        with tempfile.TemporaryDirectory() as d:
            db = Path(d, "data", "opencode")
            db.mkdir(parents=True)
            (db / "opencode.db").write_bytes(b"not a database")
            self.assertFalse(O.retry_scheduled(d))

    def test_home_audit(self):
        with tempfile.TemporaryDirectory() as d:
            for sub in ("config/opencode", "data/opencode/log", "cache/opencode/bin", "state/opencode"):
                os.makedirs(os.path.join(d, sub))
            self.assertTrue(O.audit_home_after(d)["ok"])
            Path(d, "data/opencode/auth.json").write_text("{}")
            self.assertEqual(O.audit_home_after(d)["forbidden"], ["data/opencode/auth.json"])


def capture_out(**over):
    prompt = "P"
    body = {"model": "deepseek-v4.1-flash-free", "stream": True, "response_format": O.response_format("InvestigatorOutput"),
            "messages": [{"role": "system", "contentSha256": "s", "startsWithBase": True, "extraChars": 600, "markers": []},
                         {"role": "user", "contentSha256": "u", "isPrompt": True}]}
    out = {"mode": "answer", "model": OPENCODE_DEFAULT_MODEL, "posts": 1, "gets": [], "paths": ["/v1/chat/completions"],
           "sandbox": {"bwrap": True, "roRoot": True, "homeTmpfs": True, "hardened": True, "masks": 6, "unshareNet": False},
           "bodies": [body], "verdict": {"outcome": "processed", "status": "ok", "outputOk": True}, "disabled": None,
           "expectedResponseFormat": O.response_format("InvestigatorOutput")}
    for k, v in over.items():
        if k == "body":
            body.update(v)
        else:
            out[k] = v
    return out


class Preflight(unittest.TestCase):
    def runner(self, version="opencode v2.1.4", help_text="--standalone --format --agent --model", seen=None):
        def run(argv, env, cwd):
            if seen is not None:
                seen.append({"argv": argv, "env": dict(env), "cwd": cwd, "workExists": os.path.isdir(os.path.dirname(cwd))})
            out = version if argv[1:] == ["--version"] else help_text
            return O.RunResult(0, out.encode(), b"")
        return run

    def test_version_and_help_probes_run_in_their_own_isolated_home(self):
        seen = []
        O.check_cli_isolation("oc", self.runner(seen=seen), environ=HOSTILE_ENV, capture=False)
        self.assertEqual([s["argv"] for s in seen], [["oc", "--version"], ["oc", "run", "--help"]])
        for s in seen:
            work = os.path.dirname(s["cwd"])
            self.assertTrue(os.path.basename(work).startswith("rvw-opencode-probe-") and s["workExists"])
            self.assertEqual(os.path.basename(s["cwd"]), "cwd")
            for k in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TMPDIR"):
                self.assertTrue(s["env"][k].startswith(work + os.sep), k)
            self.assertEqual(set(s["env"]) - ALLOWED_ENV, set())
            self.assertNotIn("/home/operator", json.dumps(s["env"]))
            self.assertEqual(json.loads(s["env"]["OPENCODE_CONFIG_CONTENT"]), {})
            self.assertFalse(os.path.exists(work))                                 # removed after the probe
        self.assertNotEqual(seen[0]["cwd"], seen[1]["cwd"])                        # a fresh home per probe

    def test_real_probes_are_wrapped_in_a_network_less_bwrap(self):
        from unittest import mock
        seen = []

        def plain(argv, env, cwd, timeout=60, max_stdout=1 << 20):
            seen.append(argv)
            return O.RunResult(0, b"opencode v2.1.4" if "--version" in argv else b"--standalone --format --agent --model",
                               b"")
        with mock.patch.object(O.shutil, "which", return_value="/usr/bin/bwrap"), mock.patch.object(O, "_plain_run", plain):
            r = O.check_cli_isolation("oc", capture=False, models_runner=self.models_runner(
                [O.cli_model(m) for m in OPENCODE_MODELS]))
        self.assertTrue(r["supported"], r)
        for argv in seen:
            self.assertEqual(argv[:6], ["/usr/bin/bwrap", "--unshare-net", "--die-with-parent", "--dev-bind", "/", "/"])
            self.assertEqual(argv[-3:-1] if argv[-1] == "--version" else argv[-4:-2], ["--", "oc"])
        with mock.patch.object(O.shutil, "which", return_value=None):
            r = O.check_cli_isolation("oc", capture=False, models_runner=self.models_runner([]))
        self.assertIn("bwrap is required: every live opencode call runs in the masked bwrap sandbox", r["problems"])

    def models_runner(self, listed):
        return lambda argv, env, cwd, *a, **k: O.RunResult(0, "\n".join(listed).encode(), b"")

    def test_supported_and_each_refusal(self):
        good = [O.cli_model(m) for m in OPENCODE_MODELS] + ["opencode/big-pickle"]
        r = O.check_cli_isolation("oc", self.runner(), models_runner=self.models_runner(good), capture=False)
        self.assertTrue(r["supported"], r)
        r = O.check_cli_isolation("oc", self.runner(version="opencode v2.1.5"), capture=False)
        self.assertIn("opencode version is not the pinned 2.1.4", r["problems"])
        r = O.check_cli_isolation("oc", self.runner(help_text="--format --agent --model"), capture=False)
        self.assertIn("opencode run lacks --standalone", r["problems"])
        r = O.check_cli_isolation("oc", self.runner(), capture=False,
                                  models_runner=self.models_runner(good + ["openrouter/anthropic/claude-sonnet-5.5"]))
        self.assertIn("the credential-less catalog lists a non-opencode (paid) provider", r["problems"])
        r = O.check_cli_isolation("oc", self.runner(), capture=False, models_runner=self.models_runner(good[1:]))
        self.assertFalse(r["supported"])

    def test_capture_analysis(self):
        self.assertTrue(CAP.analyse(capture_out(), OPENCODE_DEFAULT_MODEL, "answer")["supported"])
        cases = {"a request offered tools": dict(body={"tools": [{"type": "function"}]}),
                 "a request carried tool-choice fields": dict(body={"tool_choice": "auto"}),
                 "the request named a different model": dict(body={"model": "big-pickle"}),
                 "the request lacks the pinned json_schema response_format": dict(body={"response_format": None}),
                 "expected exactly one request, saw 2": dict(posts=2),
                 "the scripted answer did not come back through the adapter as status ok":
                     dict(verdict={"status": "invalid-output"}),
                 "the CLI made GET requests to the provider endpoint": dict(gets=["/v1/models"])}
        for want, over in cases.items():
            with self.subTest(want):
                self.assertIn(want, CAP.analyse(capture_out(**over), OPENCODE_DEFAULT_MODEL, "answer")["problems"])
        roles = capture_out(body={"messages": [{"role": "system"}, {"role": "system"}, {"role": "user"}]})
        self.assertTrue(any("exactly [system, user]" in x for x in CAP.analyse(roles, OPENCODE_DEFAULT_MODEL, "answer")["problems"]))
        tc = capture_out(mode="toolcall", posts=2, verdict={"reason": "isolation-violation", "itemType": "tool-attempt"})
        self.assertTrue(CAP.analyse(tc, OPENCODE_DEFAULT_MODEL, "toolcall")["supported"])
        tc["disabled"] = "tool-executed"
        self.assertFalse(CAP.analyse(tc, OPENCODE_DEFAULT_MODEL, "toolcall")["supported"])
        ok_box = {"bwrap": True, "roRoot": True, "homeTmpfs": True, "hardened": True, "masks": 6}
        for box in ({}, dict(ok_box, roRoot=False), dict(ok_box, homeTmpfs=False), dict(ok_box, hardened=False),
                    dict(ok_box, unshareNet=True)):
            self.assertIn("the CLI did not run through the live bwrap sandbox",
                          CAP.analyse(capture_out(sandbox=box), OPENCODE_DEFAULT_MODEL, "answer")["problems"])
        v = {"reason": "cli-retry", "requestsSeen": 1, "retryRequestSeen": False, "httpStatus": 429, "wordsKept": True}
        st = capture_out(mode="status:429", verdict=v)
        self.assertTrue(CAP.analyse(st, OPENCODE_DEFAULT_MODEL, "status:429")["supported"])
        bad = {"the CLI re-sent the request (hidden retry not prevented): 2 requests": dict(posts=2),
               "the scheduled retry was not killed before it was sent, or the request count is wrong":
                   dict(verdict=dict(v, requestsSeen=2, retryRequestSeen=True)),
               "the provider's HTTP status / error words were not kept": dict(verdict=dict(v, wordsKept=False))}
        for want, over in bad.items():
            with self.subTest(want):
                self.assertIn(want, CAP.analyse(capture_out(mode="status:429", **dict({"verdict": v}, **over)),
                                                OPENCODE_DEFAULT_MODEL, "status:429")["problems"])


class _Exposed(O.OpenCodeFreeProvider):
    """Test seam: the live sandbox plus read-only re-binds of what an EXECUTABLE fake needs (its own dir and this repo, which
    live under the masked /var/tmp) and, optionally, ONE writable bind for its call log."""
    log_dir = None

    def _sandbox(self, work):
        pre = super()._sandbox(work)
        extra = [x for d in sorted({self.fake_dir, str(F.ROOT)}) for x in ("--ro-bind", d, d)]
        if self.log_dir:
            extra += ["--bind", self.log_dir, self.log_dir]
        return pre[:-6] + extra + pre[-6:]                                          # before the work-dir --bind (kept last)


def fake_bin(base, scenario, **kw):
    """An executable fake in its OWN dir (<base>/bin): re-binding it never re-exposes a work dir, home or cwd."""
    d = os.path.join(base, "bin")
    os.makedirs(d, exist_ok=True)
    return F.write_fake_binary(d, scenario, **kw)


def exposed(binp, **kw):
    p = _Exposed(enabled=True, opencode=binp, preflight=GOOD, **kw)
    p.fake_dir = os.path.dirname(binp)
    return p


@unittest.skipUnless(BWRAP, "needs a working bwrap (the live sandbox)")
class Subprocess(Base):
    """The real bounded runner, the real bwrap sandbox and the adapter against an EXECUTABLE fake opencode (python),
    never the real CLI."""

    def test_end_to_end_with_an_executable_fake(self):
        logs = os.path.join(self.dir, "logs")
        os.mkdir(logs)
        binp, log = F.write_fake_binary(logs, "ok")
        led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)
        p = exposed(binp, ledger=led, workdir_parent=self.dir, environ=HOSTILE_ENV)
        p.log_dir = logs
        r = F.opencode_request("judge")
        res = p.call(r, ("JUDGE", "judge", "judge", 0, 0))
        self.assertEqual((res.outcome, res.response["status"]), ("processed", "invalid-output"))   # {} is no JudgeOutput
        call = json.loads(Path(log).read_text().splitlines()[0])
        self.assertEqual(call["argv"][1:], O.build_argv("x", OPENCODE_DEFAULT_MODEL)[1:])
        self.assertEqual(call["stdin"], O._prompt(r))
        self.assertEqual(call["cwdListing"], [])
        self.assertEqual(set(call["env"]) - ALLOWED_ENV - {"PWD", "SHLVL", "_", "LC_CTYPE"}, set())
        self.assertNotIn("sk-or-v1", json.dumps(call["env"]))
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(json.loads(Path(self.dir, "led.jsonl").read_text().splitlines()[-1])["isolation"]["requestsSeen"], 1)

    def test_the_live_call_runs_in_the_masked_read_only_sandbox(self):
        from unittest import mock
        binp, _ = fake_bin(self.dir, "sandbox-probe")
        home, cwd = os.path.join(self.dir, "realhome"), os.path.join(self.dir, "runner-cwd")
        hidden, absent = [], []
        for rel in O.SANDBOX_HOME_MASKS:
            os.makedirs(os.path.join(home, rel))
            Path(home, rel, "auth.json").write_text("CANARY-SECRET")
            hidden.append(os.path.join(home, rel))
        for rel in (".codex/auth.json", ".ssh/id_ed25519", ".claude/.credentials.json", ".config/gh/hosts.yml", "projects/x/.env"):
            Path(home, rel).parent.mkdir(parents=True, exist_ok=True)
            Path(home, rel).write_text("CANARY-SECRET")
            absent += [os.path.join(home, rel), os.path.join(home, rel.split("/")[0])]
        os.mkdir(cwd)
        Path(cwd, ".env").write_text("OPENROUTER_KEY=CANARY-SECRET\n")
        hidden.append(os.path.join(cwd, ".env"))
        outside = os.path.join(str(F.ROOT), "outside-write-probe")             # host bytes, read-only inside the sandbox
        spec = json.dumps({"hidden": hidden + absent, "outside": outside})
        old = os.getcwd()
        os.chdir(cwd)
        try:
            with mock.patch.object(O, "_user_homes", return_value=[home]), \
                    mock.patch.object(O, "real_home", return_value=os.path.realpath(home)):
                p = exposed(binp, workdir_parent=self.dir)
                res = p.call(F.opencode_request(text=F.PROBE_MARK + spec + "\n"), KEY)
        finally:
            os.chdir(old)
        seen = json.loads(res.response["rawText"])
        self.assertEqual(seen["hidden"][os.path.join(cwd, ".env")], {"error": "PermissionError"})   # /dev/null, nodev: unreadable
        for rel in O.SANDBOX_HOME_MASKS:
            self.assertEqual(seen["hidden"][os.path.join(home, rel)], {"entries": 0}, rel)
        for path in absent:                                                        # ~/.codex, ~/.ssh, ~/.claude, ~/.config/gh, ...
            if not path.endswith("/.config"):                                      # ~/.config holds the masked ~/.config/opencode
                self.assertEqual(seen["hidden"][path], {"absent": True}, path)
        self.assertEqual(seen["hidden"][os.path.join(home, ".config/gh/hosts.yml")], {"absent": True})
        self.assertEqual((seen["outside"], seen["inside"]), ("OSError", "written"))   # read-only root, writable work dir
        self.assertFalse(os.path.exists(outside))
        self.assertNotIn("CANARY-SECRET", res.response["rawText"])
        # R1: no session bus / keyring sockets, a private PID namespace, /tmp empty, /var/tmp only the re-bound paths' first parts
        if O.runtime_dir():
            self.assertEqual(seen["runUser"], [], seen["runUser"])
        self.assertLessEqual(seen["procPids"], 8)
        self.assertEqual(seen["tmp"], [])
        want = {Path(x).relative_to("/var/tmp").parts[0] for x in (self.dir, os.path.dirname(binp), str(F.ROOT))
                if str(x).startswith("/var/tmp/")}
        self.assertEqual(set(seen["varTmp"]), want)

    def test_a_hidden_retry_is_killed_when_scheduled_before_the_retry_request(self):
        binp, _ = fake_bin(self.dir, "retry")
        p = exposed(binp, workdir_parent=self.dir)
        t = time.monotonic()
        res = p.call(F.opencode_request(), KEY)
        self.assertLess(time.monotonic() - t, 1.5)                                # the fake re-sends only after 1.6 s
        d = res.error["detail"]
        self.assertEqual((d["reason"], d["requestsSeen"], d["retryRequestSeen"]), ("cli-retry", 1, False))

    def test_a_retry_request_that_left_is_killed_at_once_and_counted(self):
        binp, _ = fake_bin(self.dir, "retry-fast")
        p = exposed(binp, workdir_parent=self.dir)
        t = time.monotonic()
        res = p.call(F.opencode_request(), KEY)
        self.assertLess(time.monotonic() - t, 4)                                  # the fake would sleep 5 s more
        d = res.error["detail"]
        self.assertEqual((d["reason"], d["requestsSeen"], d["retryRequestSeen"]), ("cli-retry", 2, True))

    def test_preflight_against_the_fake_binary(self):
        binp, _ = F.write_fake_binary(self.dir, "ok")
        r = O.check_cli_isolation(binp, capture=False, models_runner=lambda argv, env, cwd, *a, **k: O._plain_run(
            [binp, "models", "--standalone"], env, cwd))
        self.assertTrue(r["supported"], r)
        self.assertEqual(r["version"], "opencode v" + O.OPENCODE_CLI_VERSION)    # through the isolated bwrap probe
        old, _ = F.write_fake_binary(os.path.join(self.dir), "ok", version="2.1.3")
        self.assertFalse(O.check_cli_isolation(old, capture=False)["supported"])


def _pinned_cli():
    if not (shutil.which("opencode") and BWRAP):
        return False
    try:
        r, _ = O._probe(["opencode", "--version"], timeout=30)                   # isolated home, never the user's dirs
    except (OSError, subprocess.SubprocessError):
        return False
    return r.stdout.decode().strip() == "opencode v" + O.OPENCODE_CLI_VERSION


@unittest.skipUnless(_pinned_cli(), "needs the installed opencode 2.1.4 and bwrap")
class RealCliCaptureProof(unittest.TestCase):
    """The REAL opencode binary, offline: private network namespace, credential-less home, loopback fake endpoint, the
    exact live argv/env/config, run through the live bwrap sandbox. No inference."""

    def test_full_offline_preflight_for_every_pinned_model(self):
        rep = O.check_cli_isolation("opencode")
        self.assertTrue(rep["supported"], rep)
        self.assertTrue(rep["offlineCatalog"]["networkIsolated"])
        self.assertTrue(all(x.startswith("opencode/") for x in rep["offlineCatalog"]["listed"]))
        self.assertEqual(sorted(rep["requestIsolation"]), sorted(f"{m}:{k}" for m in OPENCODE_MODELS
                                                                 for k in O.PREFLIGHT_CAPTURE_MODES))
        for k, v in rep["requestIsolation"].items():
            self.assertEqual((v["supported"], v["tools"]), (True, []), k)
            if k.endswith(":status:429"):
                self.assertEqual(v["posts"], 1, k)

    def test_a_429_500_or_503_reaches_the_endpoint_exactly_once(self):
        for mode in ("status:429", "status:500", "status:503"):
            with self.subTest(mode):
                cap = O.check_request_isolation("opencode", OPENCODE_DEFAULT_MODEL, mode=mode)
                self.assertTrue(cap["supported"], cap)
                v = cap["verdict"]
                self.assertEqual((cap["posts"], v["reason"], v["requestsSeen"], v["retryRequestSeen"], v["httpStatus"]),
                                 (1, "cli-retry", 1, False, int(mode.split(":")[1])))
                self.assertTrue(v["wordsKept"])


class Canary(Base):
    def test_requires_confirm_live_and_an_approved_tmpdir(self):
        from reviewer.runtime import opencode_canary as K
        with self.assertRaises(SystemExit):
            K.main(["--out-dir", self.dir])
        from unittest import mock
        with mock.patch.dict(os.environ, {"TMPDIR": "/tmp/x"}), self.assertRaises(SystemExit):
            K.main(["--out-dir", self.dir, "--confirm-live"])

    def test_canary_passes_on_a_clean_answer_and_keeps_the_cli_words_on_failure(self):
        from reviewer.runtime import opencode_canary as K
        rec = K.run_canary(self.dir, preflight=GOOD, runner=F.ScriptedRunner("ok"))
        doc = json.loads((rec / "receipt.json").read_text())
        self.assertTrue(doc["ok"], doc)
        self.assertEqual((doc["billingKind"], doc["actualUsdMicros"], doc["providerCalls"]), ("free-model", 0, 1))
        self.assertTrue(all(doc["checks"].values()))
        for sc, word in (("freelimit", "Free usage limit reached"), ("toolcall", "tool-attempt")):
            with self.subTest(sc), self.assertRaises(RuntimeError) as c:
                K.run_canary(self.dir, preflight=GOOD, runner=F.ScriptedRunner(sc))
            doc = json.loads((Path(str(c.exception).split("receipt: ")[1]) / "receipt.json").read_text())
            self.assertFalse(doc["ok"])
            self.assertIn(word, json.dumps(doc))


class Bounded(unittest.TestCase):
    py = [sys.executable, "-I", "-c"]

    def run_it(self, code, stdin=b"", timeout=10, **kw):
        return O.run_bounded_stream(self.py + [code], stdin, {"PATH": os.environ["PATH"]}, tempfile.gettempdir(), timeout,
                                    **kw)

    def test_stdin_roundtrip_deadline_and_cap(self):
        r = self.run_it("import sys; sys.stdout.write(sys.stdin.read().upper()); sys.exit(3)", b"abc")
        self.assertEqual((r.stdout, r.returncode, r.timed_out, r.truncated, r.aborted), (b"ABC", 3, False, False, None))
        t = time.monotonic()
        r = self.run_it("import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)", timeout=1)
        self.assertTrue(r.timed_out)
        self.assertLess(time.monotonic() - t, 8)
        r = self.run_it("import sys\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush()", max_stdout=100_000)
        self.assertTrue(r.truncated)

    def test_drain_after_the_kill_reads_what_is_left_and_never_blocks(self):
        r, w = os.pipe()
        os.write(w, b"left-1\nleft-2\n")
        os.close(w)
        buf = bytearray(b"seen\n")
        with os.fdopen(r, "rb", buffering=0) as f:
            O._drain(f, buf, 1 << 20)
        self.assertEqual(bytes(buf), b"seen\nleft-1\nleft-2\n")
        r, w = os.pipe()                                                           # a writer that never closes: bounded wait
        try:
            buf, t = bytearray(), time.monotonic()
            with os.fdopen(r, "rb", buffering=0) as f:
                os.set_blocking(f.fileno(), False)
                O._drain(f, buf, 1 << 20, limit=0.3)
            self.assertLess(time.monotonic() - t, 2)
            self.assertEqual(bytes(buf), b"")
        finally:
            os.close(w)

    def test_poll_aborts_the_run_and_a_failing_poll_is_ignored(self):
        calls = []

        def poll():
            calls.append(time.monotonic())
            if len(calls) == 1:
                raise sqlite3.OperationalError("database is locked")
            return "cli-retry-scheduled" if len(calls) >= 3 else None
        t = time.monotonic()
        r = self.run_it("import time; time.sleep(20)", timeout=30, poll=poll, poll_every=0.05)
        self.assertEqual((r.aborted, len(calls)), ("cli-retry-scheduled", 3))
        self.assertLess(time.monotonic() - t, 8)

    def test_audit_aborts_on_the_first_tool_event(self):
        code = ("import sys,time\nprint(%r, flush=True)\ntime.sleep(0.2)\nprint(%r, flush=True)\ntime.sleep(20)"
                % (F.step_start(), F.tool_ev()))
        t = time.monotonic()
        r = self.run_it(code, timeout=30, audit=O.StreamAudit())
        self.assertEqual(r.aborted, "tool-attempt")
        self.assertLess(time.monotonic() - t, 8)


if __name__ == "__main__":
    unittest.main()
