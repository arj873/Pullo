"""CLAUDE-CLI-PROVIDER: the Claude Code CLI subscription adapter, offline. The fake CLI (claude_fake) prints the stream-json
events the real claude 2.1.309 produces; no network, no credential, no live call. RealCliCaptureProof runs the REAL CLI
against a loopback fake Anthropic endpoint inside a network-less namespace (a dummy token; no inference)."""

import functools
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from reviewer.gateway import gateway as G
from reviewer.runtime import RuntimeLedger
from reviewer.runtime import claude_canary as CAN
from reviewer.runtime import claude_capture as CAP
from reviewer.runtime import claude_cli as C
from reviewer.runtime import schemas
from reviewer.runtime.catalog import (CLAUDE_CLI_MODELS, CLAUDE_CLI_PRICE_VERSION, OPENCODE_PACING_PRICE, TERRA_6_PRICE,
                                      claude_cli_gateway_price, claude_cli_pacing_micros, opencode_gateway_price)
from reviewer.runtime.envfile import Secret
from tests.runtime import claude_fake as F

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)
GOOD = {"supported": True, "problems": []}
HOSTILE_ENV = {"PATH": os.environ["PATH"], "HOME": "/home/operator", "OPENROUTER_API_KEY": "sk-or-v1-" + "f4k3" * 12,
               "ANTHROPIC_API_KEY": "sk-ant-api03-x", "ANTHROPIC_BASE_URL": "http://evil", "CLAUDE_CODE_OAUTH_TOKEN": "t",
               "CLAUDE_CONFIG_DIR": "/home/operator/.claude", "HTTPS_PROXY": "http://proxy", "LANG": "C.UTF-8",
               "CLAUDE_CODE_USE_BEDROCK": "1", "XDG_CONFIG_HOME": "/home/operator/.config"}
ALLOWED_ENV = {*C.ENV_PASS, *C.ENV_HOME_KEYS, *dict(C.ENV_FLAGS), "ANTHROPIC_BASE_URL"}   # the base URL: the forwarder slot only


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
        kw.setdefault("token_loader", F.dummy_token)
        kw.setdefault("forwarder", self.runner.forwarder)
        return C.ClaudeCliProvider(enabled=True, ledger=self.led, runner=self.runner, preflight=GOOD,
                                   workdir_parent=self.dir, **kw)

    def rows(self):
        p = os.path.join(self.dir, "led.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(x) for x in f]

    def leftovers(self):
        return [n for n in os.listdir(self.dir) if n.startswith("rvw-claude-")]


class Settings(unittest.TestCase):
    def test_argv_is_pinned_prompt_free_tool_free_and_never_bypasses(self):
        for m in CLAUDE_CLI_MODELS:
            a = C.build_argv("claude", m)
            self.assertEqual(a[a.index("--model") + 1], CLAUDE_CLI_MODELS[m]["cliModel"])
            self.assertEqual(a[a.index("--tools") + 1], "")
            self.assertEqual(a[a.index("--setting-sources") + 1], "")
            self.assertEqual(a[a.index("--output-format") + 1], "stream-json")
            self.assertEqual(a[a.index("--system-prompt") + 1], C.BASE_INSTRUCTIONS)
            for f in ("--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence", "-p", "--verbose"):
                self.assertIn(f, a)
            self.assertFalse(C.FORBIDDEN_FLAGS & set(a))
            for bad in ("--bare", "--json-schema", "--dangerously-skip-permissions", "--permission-mode", "--fallback-model",
                        "--mcp-config", "--resume", "--continue"):
                self.assertNotIn(bad, a)
            self.assertNotIn(C.PROBE, " ".join(a))                               # the prompt never travels in argv

    def test_env_is_built_from_scratch_with_the_pinned_switches_and_no_credential(self):
        with tempfile.TemporaryDirectory() as d:
            env = C.isolated_home(d, HOSTILE_ENV)["env"]
        self.assertEqual(set(env), ALLOWED_ENV - {"LC_ALL", "ANTHROPIC_BASE_URL"})   # the adapter adds the forwarder slot per call
        for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "OPENROUTER_API_KEY", "HTTPS_PROXY",
                  "CLAUDE_CODE_USE_BEDROCK", C.TOKEN_FD_ENV):
            self.assertNotIn(k, env)
        self.assertTrue(all(env[k].startswith(d + os.sep) for k in C.ENV_HOME_KEYS))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], os.path.join(d, "home", ".claude"))
        f = dict(C.ENV_FLAGS)
        self.assertEqual((f["CLAUDE_CODE_MAX_RETRIES"], f["CLAUDE_CODE_MAX_TURNS"], f["CLAUDE_CODE_DISABLE_FILE_MENTIONS"],
                          f["CLAUDE_CODE_DISABLE_THINKING"], f["CLAUDE_CODE_MAX_OUTPUT_TOKENS"]),
                         ("0", "1", "1", "1", str(C.OUTPUT_TOKENS)))

    def test_prompt_wraps_messages_and_quotes_the_anthropic_projection(self):
        r = F.claude_request("verifier", text="a <b> & c")
        p = C._prompt(r)
        self.assertTrue(p.startswith(C._PREFIX))                                 # never a leading "/" (slash command)
        self.assertIn("<user>\na <b> & c\n</user>", p)
        self.assertIn(schemas.schema_bytes("VerifierOutput", "anthropic").decode(), p)
        f = C.request_facts(r)
        self.assertEqual((f["bodySha256"], f["schemaSha256"]), (hashlib.sha256(p.encode()).hexdigest(),
                         hashlib.sha256(schemas.schema_bytes("VerifierOutput", "anthropic")).hexdigest()))
        self.assertEqual((f["billingKind"], f["worstCaseRouterUsdMicros"], f["provider"]),
                         ("claude-subscription", 0, "claude-cli"))
        self.assertGreater(f["worstCaseApiEquivalentUsdMicros"], 0)

    def test_identity_differs_per_model_and_is_stable(self):
        a, b = C.isolation_identity(F.MODEL), C.isolation_identity(F.OPUS)
        self.assertNotEqual(a["argvSha256"], b["argvSha256"])
        self.assertEqual(a, C.isolation_identity(F.MODEL))
        self.assertEqual({k for k in a if a[k] != b[k]}, {"argvSha256"})
        self.assertEqual((a["isolationVersion"], a["cliVersion"], a["sandbox"]),
                         ("claude-cli-isolated@2", "2.1.309", "claude-bwrap-masked@2"))

    def test_pacing_is_the_terra6_list_rates_of_the_opencode_arm_for_every_model(self):
        oc = opencode_gateway_price("opencode/deepseek-v4.1-flash-free")
        for m in CLAUDE_CLI_MODELS:
            p = claude_cli_gateway_price(m)
            self.assertEqual({k: v for k, v in p.items() if k != "priceVersion"}, {k: v for k, v in oc.items() if k != "priceVersion"})
            self.assertEqual((p["inputPerMTokUsdMicros"], p["cachedInputPerMTokUsdMicros"], p["cacheWriteInputPerMTokUsdMicros"],
                              p["outputPerMTokUsdMicros"]), (TERRA_6_PRICE["input"], TERRA_6_PRICE["cached"], TERRA_6_PRICE["write"],
                                                             TERRA_6_PRICE["output"]))
            self.assertEqual(p["priceVersion"], CLAUDE_CLI_PRICE_VERSION)
        self.assertEqual(CLAUDE_CLI_PRICE_VERSION, "claude-cli-pacing@terra6-list-2026-10-29")
        self.assertEqual(claude_cli_pacing_micros(F.OPUS, 1_000_000, 0, 0, 0), OPENCODE_PACING_PRICE["input"])
        self.assertEqual(claude_cli_pacing_micros(F.OPUS, 1, 2, 3, 4), claude_cli_pacing_micros(F.MODEL, 1, 2, 3, 4))
        self.assertEqual(C.ESTIMATE_BASIS, "pacing-terra6-list-rates")
        with self.assertRaises(ValueError):
            claude_cli_gateway_price("claude-opus-5-5")                         # the bare id is development-only

    def test_gateway_subscription_path_needs_a_pinned_claude_cli_model(self):
        self.assertTrue(G._claude_cli_model(F.MODEL))
        self.assertFalse(G._claude_cli_model("claude-sonnet-5-5"))
        self.assertFalse(G._claude_cli_model("anthropic/claude-sonnet-5.5"))

    def test_sandbox_prefix_masks_the_home_tmp_and_env_and_keeps_only_the_work_dir_writable(self):
        masks = [("file", "/srv/repo/.env"), ("dir", "/opt/state")]
        pre = C.sandbox_prefix("/usr/bin/bwrap", "/w/rvw-claude-x", masks, "/home/u", "/run/user/7")
        self.assertEqual(pre[:13], ["/usr/bin/bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev",
                                    "--tmpfs", "/home/u", "--unshare-pid", "--proc", "/proc", "--unshare-ipc"])
        self.assertEqual(pre[13:19], ["--tmpfs", "/run/user/7", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp"])
        self.assertIn(["--ro-bind", "/dev/null", "/srv/repo/.env"], [pre[i:i + 3] for i in range(len(pre))])
        self.assertEqual(pre[-6:], ["--bind", "/w/rvw-claude-x", "/w/rvw-claude-x", "--chdir", "/w/rvw-claude-x/cwd", "--"])
        self.assertNotIn("--unshare-net", pre)                                  # the API must be reachable
        self.assertEqual([x for x in pre if x == "--bind"], ["--bind"])           # the only writable bind

    def test_masks_skip_paths_under_the_home_tmpfs_and_cover_host_masks(self):
        with tempfile.TemporaryDirectory() as d:
            home, other = os.path.join(d, "home"), os.path.join(d, "other")
            os.makedirs(os.path.join(home, ".claude"))
            os.makedirs(os.path.join(other, ".claude"))
            Path(d, "x.env").write_text("k=v")
            with mock.patch.object(C, "real_home", return_value=home), \
                    mock.patch.object(C, "_user_homes", return_value=[home, other]), \
                    mock.patch.object(C, "HOST_MASKS", [os.path.join(d, "x.env"), "relative/ignored"]):
                masks = C.sandbox_masks()
        self.assertIn(("file", os.path.realpath(os.path.join(d, "x.env"))), masks)
        self.assertIn(("dir", os.path.realpath(os.path.join(other, ".claude"))), masks)     # a $HOME outside the passwd home
        self.assertFalse(any(C.under(p, home) for _, p in masks))

    def test_binary_under_home_or_no_home_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            binp, _ = F.write_fake_binary(d, "ok")
            with mock.patch.object(C, "real_home", return_value=os.path.realpath(d)):
                with self.assertRaisesRegex(C.ClaudeCliUnsupported, "under the user home"):
                    C.ClaudeCliProvider(enabled=True, claude=binp, preflight=GOOD, runner=F.ScriptedRunner())
                self.assertIn("the claude binary resolves under the user home, which the sandbox masks",
                              C.check_cli_isolation(binp, runner=lambda *a: C.RunResult(0, b"", b""), capture=False)["problems"])
            with mock.patch.object(C, "real_home", return_value=None):
                with self.assertRaisesRegex(C.ClaudeCliUnsupported, "passwd"):
                    C.ClaudeCliProvider(enabled=True, preflight=GOOD, runner=F.ScriptedRunner())


class Auth(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.path = os.path.join(self._t.name, ".credentials.json")
        self.now = 1_800_000_000_000

    def write(self, doc, mode=0o600):
        Path(self.path).write_text(json.dumps(doc) if not isinstance(doc, str) else doc)
        os.chmod(self.path, mode)

    def cred(self, **over):
        o = {"accessToken": F.DUMMY_TOKEN, "refreshToken": "sk-ant-ort01-REFRESH-NEVER-PASSED-00000000000000",
             "expiresAt": self.now + 3_600_000, "scopes": ["user:inference"], "subscriptionType": "max"}
        o.update(over)
        return {"claudeAiOauth": o}

    def test_the_access_token_only_is_loaded_and_the_refresh_token_is_dropped(self):
        self.write(self.cred())
        t = C.load_access_token(self.path, now_ms=self.now)
        self.assertEqual((t.secret.reveal(), t.expires_at_ms, t.source),
                         (F.DUMMY_TOKEN, self.now + 3_600_000, "claude-credentials-access-token"))
        self.assertNotIn("REFRESH", repr(t))
        self.assertEqual(repr(t.secret), "Secret(***)")
        self.assertNotIn("REFRESH", json.dumps({k: str(v) for k, v in vars(t).items()}))

    def test_an_expiring_token_is_refused_before_any_call(self):
        self.write(self.cred(expiresAt=self.now + 60_000))
        with self.assertRaisesRegex(C.ClaudeAuthUnavailable, "expires within"):
            C.load_access_token(self.path, now_ms=self.now)

    def test_unsafe_or_malformed_files_are_refused_without_their_content(self):
        cases = [(self.cred(), 0o644, "private"), ('{"claudeAiOauth": {"accessToken": 1, "expiresAt": 1}}', 0o600, "shape"),
                 (self.cred(accessToken="not-a-token"), 0o600, "shape"), ('{"a": 1, "a": 2}', 0o600, "strict JSON"),
                 (self.cred(expiresAt="soon"), 0o600, "shape")]
        for doc, mode, why in cases:
            with self.subTest(why):
                self.write(doc, mode)
                with self.assertRaisesRegex(C.ClaudeAuthUnavailable, why) as cm:
                    C.load_access_token(self.path, now_ms=self.now)
                self.assertNotIn(F.DUMMY_TOKEN, str(cm.exception))
        os.remove(self.path)
        with self.assertRaisesRegex(C.ClaudeAuthUnavailable, "missing"):
            C.load_access_token(self.path, now_ms=self.now)
        real = os.path.join(self._t.name, "real.json")
        Path(real).write_text(json.dumps(self.cred()))
        os.chmod(real, 0o600)
        os.symlink(real, self.path)
        with self.assertRaisesRegex(C.ClaudeAuthUnavailable, "symlink"):
            C.load_access_token(self.path, now_ms=self.now)

    def test_operator_token_file_and_the_host_switch(self):
        p = os.path.join(self._t.name, "tok")
        Path(p).write_text(F.DUMMY_TOKEN + "\n")
        os.chmod(p, 0o600)
        t = C.load_token_file(p)
        self.assertEqual((t.secret.reveal(), t.expires_at_ms, t.source), (F.DUMMY_TOKEN, None, "operator-token-file"))
        with mock.patch.object(C, "TOKEN_FILE", p):
            self.assertEqual(C.default_token_loader().source, "operator-token-file")
        Path(p).write_text(F.DUMMY_TOKEN + "\n" + F.DUMMY_TOKEN)
        with self.assertRaisesRegex(C.ClaudeAuthUnavailable, "one OAuth token"):
            C.load_token_file(p)


class Calls(Base):
    def test_success_is_isolated_keyless_subscription_and_paced(self):
        p = self.prov("ok")
        r = F.claude_request()
        res = p.call(r, KEY)
        self.assertEqual((res.outcome, res.response["status"], res.response["output"]), ("processed", "ok", F.OK_INV))
        s = self.runner.seen[0]
        box, inner = C.split_sandbox(s["argv"])
        self.assertIsNotNone(box)
        self.assertEqual(inner, C.build_argv("claude", F.MODEL))
        self.assertEqual(s["stdin"], C._prompt(r).encode())
        self.assertEqual(s["cwd_listing"], [])
        self.assertEqual(set(s["env"]) - ALLOWED_ENV, set())
        self.assertRegex(s["env"]["ANTHROPIC_BASE_URL"], C.BASE_URL_RE)            # the only endpoint: the host forwarder
        self.assertNotIn(C.TOKEN_FD_ENV, s["env"])                               # added by the runner, never the caller
        self.assertEqual(s["tokenSha256"], hashlib.sha256(F.DUMMY_TOKEN.encode()).hexdigest())
        self.assertNotIn(F.DUMMY_TOKEN, json.dumps(s["env"]) + " ".join(s["argv"]) + s["stdin"].decode())
        rows = self.rows()
        self.assertEqual([x["type"] for x in rows], ["intent", "result"])
        self.assertEqual(rows[0]["worstCaseUsdMicros"], 0)
        res_row = rows[1]
        self.assertEqual((res_row["kind"], res_row["billingKind"], res_row["costBasis"], res_row["outcome"]),
                         ("claude-cli", "claude-subscription", "claude-subscription-zero", "processed"))
        u = F.USAGE
        self.assertEqual(res_row["apiEquivalentEstimateUsdMicros"], claude_cli_pacing_micros(
            F.MODEL, u["input_tokens"], u["cache_read_input_tokens"], u["cache_creation_input_tokens"], u["output_tokens"]))
        self.assertEqual((res_row["estimateBasis"], res_row["priceVersion"]), ("pacing-terra6-list-rates", CLAUDE_CLI_PRICE_VERSION))
        self.assertEqual(res_row["usage"], {"uncachedInputTokens": 1000, "cachedInputTokens": 200,
                                            "cacheWriteInputTokens": 300, "outputTokens": 40, "reasoningTokens": 0})
        self.assertEqual((res_row["generationId"], res_row["isolation"]["requestsSeen"], res_row["isolation"]["toolItems"],
                          res_row["isolation"]["requestsSent"], res_row["isolation"]["forwarder"]["version"]),
                         ("req_fake_1", 1, 0, 1, "claude-loopback-forwarder@1"))
        self.assertEqual(self.led.totals()["committedUsdMicros"], 0)
        self.assertNotIn(F.DUMMY_TOKEN, Path(self.dir, "led.jsonl").read_text())
        self.assertEqual(self.leftovers(), [])

    def test_fenced_answer_is_accepted_and_noted_prose_is_invalid_output(self):
        p = self.prov("fenced", "prose", "over-cap")
        a, b, c = (p.call(F.claude_request(), (*KEY[:3], i, 0)) for i in range(3))
        self.assertEqual((a.response["status"], b.response["status"], c.response["status"]), ("ok", "invalid-output", "ok"))
        notes = [x.get("note") for x in self.rows() if x["type"] == "result"]
        self.assertEqual(notes, ["fenced-json", "invalid-output", "output-over-cap"])

    def test_a_tool_attempt_is_killed_and_discarded(self):
        p = self.prov("toolcall", "ok")
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["reason"], d["itemType"]), ("unknown", "isolation-violation", "tool-attempt"))
        self.assertIsNone(p.disabled_reason)                                     # nothing could run: no tool exists
        self.assertEqual(p.call(F.claude_request(), (*KEY[:3], 1, 0)).outcome, "processed")

    def test_isolation_audit_failures_discard_output(self):
        for sc, item in (("init-tools", "init-surface:init-tools"), ("init-mcp", "init-surface:init-mcp_servers"),
                         ("init-plugin", "init-surface:init-plugins"), ("wrong-model", "init-surface:init-model"),
                         ("two-requests", "extra-request"), ("max_tokens", "extra-turn"),
                         ("extra-model", "extra-model:claude-haiku-5-5"), ("unknown-event", "unknown-event:system/hook_response"),
                         ("thinking", "unknown-event:content/thinking"), ("multi-turn", "num-turns:2"),
                         ("nonstream", "nonstreaming-fallback"), ("unrelayed", "answer-not-relayed:0")):
            with self.subTest(sc):
                p = self.prov(sc)
                res = p.call(F.claude_request(), KEY)
                d = res.error["detail"]
                sent = F.SENT.get(sc, 1)                                            # exact, from the forwarder
                self.assertEqual((res.outcome, d["reason"], d["itemType"], d.get("requestsSent")),
                                 ("not-sent" if sent == 0 else "unknown", "isolation-violation", item, sent))
        p = self.prov("unrelayed", "ok")
        p.call(F.claude_request(), KEY)
        self.assertEqual(p.disabled_reason, "answer-not-relayed")                  # an answer from anywhere but the forwarder

    def test_extra_usage_is_never_zero_and_latches(self):
        p = self.prov("overage", "ok")
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["reason"], d["errorType"], d["latched"], res.response), ("unknown", "extra-usage",
                                                                                                    "claude.extra-usage", True, None))
        self.assertEqual(d["rateLimit"]["isUsingOverage"], True)
        row = self.rows()[-1]
        self.assertEqual((row["billingKind"], row["costBasis"]), ("claude-extra-usage", "extra-usage-charge-unknown"))
        self.assertIn("may have been billed as extra usage", row["note"])
        self.assertEqual(p.call(F.claude_request(), (*KEY[:3], 1, 0)).error["detail"]["reason"], "limit-latched")
        self.assertTrue(C.extra_usage(None, {"anthropic-ratelimit-unified-overage-in-use": "true"}))      # host-side headers alone
        self.assertTrue(C.extra_usage({"status": "rejected", "overageStatus": "allowed"}, None))
        self.assertFalse(C.extra_usage({"status": "allowed", "isUsingOverage": False}, {"anthropic-ratelimit-unified-status": "allowed"}))

    def test_a_404_model_unavailable_latches_with_the_upstream_status(self):
        p = self.prov("model404", "ok")
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["errorType"], d["httpStatus"], d["requestsSent"], d["latched"]),
                         ("rejected-before-processing", "claude.model-unavailable", 404, 1, True))

    def test_a_written_cwd_or_a_persisted_credential_disables_the_adapter(self):
        for sc in ("write-cwd", "write-cred", "persist-token"):
            with self.subTest(sc):
                p = self.prov(sc, "ok")
                res = p.call(F.claude_request(), KEY)
                self.assertEqual((res.error["detail"]["reason"], p.disabled_reason),
                                 ("isolation-violation", "forbidden-work-entry"))
                again = p.call(F.claude_request(), (*KEY[:3], 1, 0))
                self.assertEqual((again.outcome, again.error["detail"]["reason"]), ("not-sent", "adapter-disabled"))

    def test_a_usage_limit_keeps_the_cli_words_and_latches_the_run(self):
        p = self.prov("usage-limit", "ok")
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["errorType"], d["httpStatus"], d["cliError"], d["latched"]),
                         ("rejected-before-processing", "claude.usage-limit", 429, "rate_limit", True))
        self.assertIn(F.LIMIT_TEXT, res.error["message"])
        self.assertEqual(d["rateLimit"], {"status": "rejected", "rateLimitType": "five_hour", "resetsAt": 1793568634,
                                          "overageStatus": "rejected"})
        self.assertIn("hit your limit", self.rows()[-1]["note"])
        again = p.call(F.claude_request(), (*KEY[:3], 1, 0))
        self.assertEqual((again.outcome, again.error["detail"]["reason"], again.error["detail"]["errorType"]),
                         ("not-sent", "limit-latched", "claude.usage-limit"))
        self.assertIn(F.LIMIT_TEXT, again.error["message"])
        self.assertEqual(len(self.runner.seen), 1)                               # nothing was spawned for the latched call
        self.assertEqual(len([x for x in self.rows() if x["type"] == "intent"]), 1)

    def test_error_types_and_which_ones_latch(self):
        for sc, etype, latched, outcome in (("throttle", "claude.rate-limit", True, "rejected-before-processing"),
                                            ("overloaded", "claude.overloaded", True, "unknown"),
                                            ("server500", "claude.server-error", False, "unknown"),
                                            ("refusal", "claude.refusal", False, "unknown"),
                                            ("not-logged-in", "claude.auth", True, "not-sent")):
            with self.subTest(sc):
                p = self.prov(sc, "ok")
                res = p.call(F.claude_request(), KEY)
                d = res.error["detail"]
                self.assertEqual((d["errorType"], res.outcome, bool(p.latched)), (etype, outcome, latched))
                again = p.call(F.claude_request(), (*KEY[:3], 1, 0))
                self.assertEqual(again.outcome, "not-sent" if latched else "processed")

    def test_a_scheduled_401_retry_is_killed_before_it_is_sent(self):
        p = self.prov("retry401", "ok")
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((d["reason"], d["errorType"], d["httpStatus"], d["cliError"], d["requestsSent"], d["retryRequestSent"]),
                         ("cli-retry", "claude.auth", 401, "authentication_failed", 1, False))
        self.assertEqual(res.outcome, "rejected-before-processing")
        self.assertIn("hidden retry", res.error["message"])
        self.assertEqual(p.call(F.claude_request(), (*KEY[:3], 1, 0)).error["detail"]["reason"], "limit-latched")

    def test_an_unavailable_token_refuses_before_any_spawn_or_ledger_row_and_latches(self):
        def none():
            raise C.ClaudeAuthUnavailable("the OAuth access token expires within 300 s")
        p = self.prov(token_loader=none)
        res = p.call(F.claude_request(), KEY)
        self.assertEqual((res.outcome, res.error["detail"]["reason"], res.error["detail"]["errorType"]),
                         ("not-sent", "auth-unavailable", "claude.auth"))
        self.assertEqual((self.runner.seen, self.rows()), ([], []))
        self.assertEqual(p.call(F.claude_request(), (*KEY[:3], 1, 0)).error["detail"]["reason"], "limit-latched")

    def test_timeout_and_stderr_and_no_result(self):
        p = self.prov("timeout", "stderr-only", "no-result", timeout_sec=5)
        a = p.call(F.claude_request(params={"maxOutputTokens": 100, "timeoutSec": 5}), KEY)
        self.assertEqual((a.error["code"], a.outcome), ("provider-timeout", "unknown"))
        self.assertEqual(self.runner.seen[0]["timeout"], 5.0)
        b = p.call(F.claude_request(), (*KEY[:3], 1, 0))
        self.assertIn("crashed before any request", b.error["message"])
        c = p.call(F.claude_request(), (*KEY[:3], 2, 0))
        self.assertEqual(c.error["detail"]["reason"], "no-final-message")

    def test_refusals_happen_before_any_spawn_or_ledger_row(self):
        p = self.prov()
        bad = [F.claude_request(provider="anthropic"), F.claude_request(model="claude-opus-5-5"),
               F.claude_request(model="anthropic/claude-opus-5.5"), F.claude_request(tools=[{"name": "Bash"}]),
               F.claude_request(messages=[]), F.claude_request(messages=[{"role": "tool", "content": "x"}]),
               F.claude_request(outputSchema="JudgeOutput"), F.claude_request(text="x" * (7 << 20))]
        for i, r in enumerate(bad):
            with self.subTest(i):
                res = p.call(r, (*KEY[:3], i, 0))
                self.assertEqual(res.outcome, "not-sent")
        self.assertEqual((self.runner.seen, self.rows()), ([], []))

    def test_call_cap_timeout_cap_models_and_opt_in(self):
        with self.assertRaises(ValueError):
            C.ClaudeCliProvider(enabled=False, preflight=GOOD, runner=F.ScriptedRunner())
        with self.assertRaises(ValueError):
            C.ClaudeCliProvider(enabled=True, preflight=GOOD, runner=F.ScriptedRunner(), timeout_sec=C.MAX_TIMEOUT_SEC + 1)
        with self.assertRaises(ValueError):
            C.ClaudeCliProvider(enabled=True, preflight=GOOD, runner=F.ScriptedRunner(), models=["anthropic/claude-opus-5.5"])
        with self.assertRaises(ValueError):
            C.ClaudeCliProvider(enabled=True, preflight=GOOD, runner=F.ScriptedRunner(), family="score")
        with self.assertRaisesRegex(C.ClaudeCliUnsupported, "version"):
            C.ClaudeCliProvider(enabled=True, preflight={"supported": False, "problems": ["claude version is not"]},
                                runner=F.ScriptedRunner())
        p = self.prov(max_calls=1)
        self.assertEqual(p.call(F.claude_request(), KEY).outcome, "processed")
        self.assertEqual(p.call(F.claude_request(), (*KEY[:3], 1, 0)).error["detail"]["reason"], "call-cap")
        q = self.prov(models=[F.OPUS])
        self.assertEqual(q.call(F.claude_request(), KEY).outcome, "not-sent")    # Sonnet is outside this run's models

    def test_runner_crash_and_missing_binary(self):
        led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)
        for exc, outcome, reason in ((FileNotFoundError(), "not-sent", "claude-missing"),
                                     (RuntimeError("x"), "not-sent", "runner-crash")):     # the forwarder relayed nothing
            def boom(*a, _e=exc, **k):
                raise _e
            p = C.ClaudeCliProvider(enabled=True, ledger=led, runner=boom, preflight=GOOD, workdir_parent=self.dir,
                                    token_loader=F.dummy_token, run_scope=reason, forwarder=F.FakeForwarder())
            res = p.call(F.claude_request(), KEY)
            self.assertEqual((res.outcome, res.error["detail"]["reason"]), (outcome, reason))
        self.assertEqual(self.leftovers(), [])


class Guard(Base):
    def test_review_call_guard_accepts_the_real_call_and_refuses_drift(self):
        p = self.prov("ok")
        r = F.claude_request()
        p.call(r, KEY)
        s = self.runner.seen[0]
        first = C.request_facts(r)
        if shutil.which("bwrap"):
            self.assertEqual(C.review_call_problems(s["argv"], s["stdin"], s["env"], s["cwd"], F.MODEL, first), [])
        _, inner = C.split_sandbox(s["argv"])
        self.assertIn("review call is not inside the bwrap sandbox",
                      C.review_call_problems(inner, s["stdin"], s["env"], s["cwd"], F.MODEL))
        drift = {
            "argv": (s["argv"][:-1] + ["other prompt"], s["env"], s["cwd"], s["stdin"]),
            "env-base-url": (s["argv"], dict(s["env"], ANTHROPIC_BASE_URL="http://x"), s["cwd"], s["stdin"]),
            "env-token": (s["argv"], dict(s["env"], CLAUDE_CODE_OAUTH_TOKEN="t"), s["cwd"], s["stdin"]),
            "env-fd": (s["argv"], dict(s["env"], **{C.TOKEN_FD_ENV: "3"}), s["cwd"], s["stdin"]),
            "env-flag": (s["argv"], dict(s["env"], CLAUDE_CODE_MAX_RETRIES="3"), s["cwd"], s["stdin"]),
            "home": (s["argv"], dict(s["env"], HOME="/home/blop"), s["cwd"], s["stdin"]),
            "cwd": (s["argv"], s["env"], "/var/tmp/x/cwd", s["stdin"]),
            "stdin": (s["argv"], s["env"], s["cwd"], s["stdin"] + b"x"),
        }
        for name, (argv, env, cwd, stdin) in drift.items():
            with self.subTest(name):
                self.assertTrue(C.review_call_problems(argv, stdin, env, cwd, F.MODEL, first))
        self.assertTrue(C.review_call_problems(s["argv"], s["stdin"], s["env"], s["cwd"], F.OPUS))
        self.assertTrue(C.is_review_call(s["argv"]) and not C.is_review_call(["claude", "--version"]))
        if shutil.which("bwrap"):                                              # a dropped mask or namespace is refused
            for cut in (("--tmpfs", C.real_home()), ("--unshare-pid",), ("--tmpfs", "/var/tmp")):
                a = list(s["argv"])
                i = next(j for j in range(len(a)) if tuple(a[j:j + len(cut)]) == cut)
                del a[i:i + len(cut)]
                self.assertIn("sandbox argv differs from the pinned bwrap sandbox for this call",
                              C.review_call_problems(a, s["stdin"], s["env"], s["cwd"], F.MODEL))


class Audits(unittest.TestCase):
    def feed(self, *lines, model=F.MODEL):
        a = C.StreamAudit(model=model)
        for ln in lines:
            a.feed(ln.encode())
        return a

    def test_stream_audit(self):
        m = "claude-sonnet-5-5"
        self.assertIsNone(self.feed(F.init(m), F.text(m, "{}"), F.rate(), F.result(m, "{}")).reason)
        self.assertEqual(self.feed(F.init(m), F.ev("system", subtype="api_retry", error_status=401)).reason, "cli-retry")
        self.assertEqual(self.feed(F.init(m), F.ev("user", message={"content": "x"})).reason, "extra-turn")
        self.assertEqual(self.feed(F.init(m), F.assistant(m, [{"type": "server_tool_use", "name": "web_search"}])).reason,
                         "tool-attempt")
        self.assertEqual(self.feed(F.init(m, slash_commands=["init"])).reason, "init-surface")
        a = self.feed(F.init(m), "not json", F.ev("weird"))
        self.assertEqual((a.bad, a.unknown, a.reason), (1, ["weird"], None))

    def test_classify(self):
        self.assertEqual(C.classify(429, "rate_limit", {"status": "rejected", "rateLimitType": "seven_day"}, ""),
                         "claude.usage-limit")
        self.assertEqual(C.classify(429, "rate_limit", {"status": "rejected"}, F.THROTTLE_TEXT), "claude.rate-limit")
        self.assertEqual(C.classify(429, None, {"status": "rejected", "rateLimitType": "five_hour"},
                                    "Server is temporarily limiting requests (not your usage limit)"), "claude.rate-limit")
        self.assertEqual(C.classify(529, None, None, ""), "claude.overloaded")
        self.assertEqual(C.classify(None, None, None, "Not logged in · Please run /login"), "claude.auth")
        self.assertEqual(C.classify(402, None, None, ""), "claude.billing")
        self.assertEqual(C.classify(400, None, None, ""), "claude.invalid-request")
        self.assertEqual(C.classify(400, "invalid_request", None, "API Error: Opus 5.5's safeguards flagged this message"),
                         "claude.refusal")                                           # N1: refusal before invalid-request
        self.assertEqual(C.classify(404, None, None, ""), "claude.model-unavailable")
        self.assertEqual(C.classify(None, None, None, "Prompt is too long"), "claude.prompt-too-long")
        self.assertEqual(C.classify(503, None, None, ""), "claude.server-error")

    def test_json_extraction_tolerates_one_whole_fence_only(self):
        self.assertEqual(C.extract_json_text('```json\n{"a": 1}\n```'), ('{"a": 1}', True))
        self.assertEqual(C.extract_json_text('x\n```json\n{"a": 1}\n```')[1], False)

    def test_work_audit(self):
        with tempfile.TemporaryDirectory() as d:
            C.isolated_home(d, {})
            os.mkdir(os.path.join(d, "cwd"))
            Path(d, "home", ".claude.json").write_text("{}")                      # what the real CLI leaves: fine
            self.assertTrue(C.audit_work_after(d)["ok"])
            Path(d, "home", ".claude", "settings.json").write_text("{}")
            self.assertEqual(C.audit_work_after(d)["forbidden"], ["home/.claude/settings.json"])
            Path(d, "tmp", "x.log").write_text("..." + F.DUMMY_TOKEN + "...")
            self.assertIn("token-persisted:tmp/x.log", C.audit_work_after(d, F.dummy_token().secret)["forbidden"])
            self.assertNotIn("token-persisted:tmp/x.log", C.audit_work_after(d)["forbidden"])


def capture_out(**over):
    m = F.MODEL
    body = {"model": "claude-sonnet-5-5", "max_tokens": C.OUTPUT_TOKENS, "stream": True, "tools": [],
            "metadataKeys": ["user_id"],
            "system": [{"kind": "billing"}, {"kind": "identity"}, {"kind": "base"}],
            "messages": [{"role": "user", "isPrompt": True, "markers": []},
                         {"role": "system", "envBlock": True, "envExact": True, "head": "# Environment", "chars": 900, "markers": []}]}
    out = {"mode": "answer", "model": m, "posts": 1, "paths": ["/v1/messages?beta=true"], "others": [], "bodies": [body],
           "bearerIsDummy": [True], "apiKeyHeader": [False], "betas": ["claude-code-20250219,oauth-2025-04-20"],
           "verdict": {"outcome": "processed", "status": "ok", "outputOk": True}, "disabled": None, "executed": [],
           "leaks": {"hostname": False, "osRelease": False, "tokenInBody": False}, "baseUrlIsForwarder": True,
           "forwarder": {"version": C.FORWARDER_VERSION, "requestsSent": 1, "requestsAttempted": 1, "refused": [], "upstreamStatus": 200},
           "sandbox": {"bwrap": True, "roRoot": True, "homeTmpfs": True, "hardened": True, "masks": 6, "unshareNet": False}}
    out.update(over)
    return out


class CaptureAnalysis(unittest.TestCase):
    def test_capture_analysis(self):
        self.assertTrue(CAP.analyse(capture_out(), F.MODEL, "answer")["supported"])
        b = capture_out()["bodies"][0]
        bad = {
            "tools": capture_out(bodies=[dict(b, tools=[{"name": "StructuredOutput"}])]),
            "thinking": capture_out(bodies=[dict(b, thinking={"type": "adaptive"})]),
            "model": capture_out(bodies=[dict(b, model="claude-haiku-5-5")]),
            "system": capture_out(bodies=[dict(b, system=[{"kind": "identity"}, {"kind": "other"}])]),
            "prompt": capture_out(bodies=[dict(b, messages=[dict(b["messages"][0], isPrompt=False), b["messages"][1]])]),
            "markers": capture_out(bodies=[dict(b, messages=[b["messages"][0], dict(b["messages"][1], markers=["PULLO-PLANT-AGENTS"])])]),
            "apikey": capture_out(apiKeyHeader=[True]),
            "two-posts": capture_out(posts=2),
            "get": capture_out(others=["HEAD /api/hello"]),
            "no-sandbox": capture_out(sandbox={"bwrap": False}),
            "leak": capture_out(leaks={"hostname": True}),
            "ran": capture_out(executed=["cwd/pullo-mark-bang"]),
            "not-exact-env": capture_out(bodies=[dict(b, messages=[b["messages"][0], dict(b["messages"][1], envExact=False)])]),
            "no-forwarder": capture_out(baseUrlIsForwarder=False),
            "a-get": capture_out(forwarder=dict(capture_out()["forwarder"], refused=[{"method": "GET", "path": "/api/claude_code/settings",
                                                                                     "verdict": "method-or-path"}])),
            "count-mismatch": capture_out(forwarder=dict(capture_out()["forwarder"], requestsSent=2)),
        }
        for name, out in bad.items():
            with self.subTest(name):
                self.assertFalse(CAP.analyse(out, F.MODEL, "answer")["supported"])
        ul = capture_out(mode="usage-limit", verdict={"httpStatus": 429, "wordsKept": True, "errorType": "claude.usage-limit",
                                                      "rateLimitStatus": "rejected", "requestsSent": 1}, latched="claude.usage-limit",
                         second={"outcome": "not-sent", "reason": "limit-latched", "newRequests": 0})
        self.assertTrue(CAP.analyse(ul, F.MODEL, "usage-limit")["supported"])
        self.assertFalse(CAP.analyse(dict(ul, second={"outcome": "processed", "newRequests": 1}), F.MODEL,
                                     "usage-limit")["supported"])


class _Exposed(C.ClaudeCliProvider):
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
    d = os.path.join(base, "bin")
    os.makedirs(d, exist_ok=True)
    return F.write_fake_binary(d, scenario, **kw)


UPSTREAM_URL, _UP_SRV, UPSTREAM_LOG = None, None, []


def local_upstream():
    """ONE loopback stand-in for api.anthropic.com shared by the tests that run the REAL Forwarder: it must never relay off-host."""
    global UPSTREAM_URL, _UP_SRV
    if UPSTREAM_URL is None:
        UPSTREAM_URL, _UP_SRV, log = F.start_upstream()
        UPSTREAM_LOG.append(log)
    return UPSTREAM_URL


def exposed(binp, **kw):
    kw.setdefault("token_loader", F.dummy_token)
    kw.setdefault("upstream", local_upstream())                                  # NEVER the production upstream in a test
    p = _Exposed(enabled=True, claude=binp, preflight=GOOD, **kw)
    p.fake_dir = os.path.dirname(binp)
    return p


@unittest.skipUnless(BWRAP, "needs a working bwrap (the live sandbox)")
class Subprocess(Base):
    """The real bounded runner (token pipe included), the real bwrap sandbox and the adapter against an EXECUTABLE fake
    claude (python), never the real CLI."""

    def test_end_to_end_with_an_executable_fake(self):
        logs = os.path.join(self.dir, "logs")
        os.mkdir(logs)
        binp, log = F.write_fake_binary(logs, "ok")
        led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)
        p = exposed(binp, ledger=led, workdir_parent=self.dir, environ=HOSTILE_ENV)
        p.log_dir = logs
        r = F.claude_request("judge")
        res = p.call(r, ("JUDGE", "judge", "judge", 0, 0))
        self.assertEqual((res.outcome, res.response["status"]), ("processed", "invalid-output"))   # {} is no JudgeOutput
        call = json.loads(Path(log).read_text().splitlines()[0])
        self.assertEqual(call["argv"][1:], C.build_argv("x", F.MODEL)[1:])
        self.assertEqual(call["stdin"], C._prompt(r))
        self.assertEqual(call["cwdListing"], [])
        self.assertEqual(set(call["env"]) - ALLOWED_ENV - {C.TOKEN_FD_ENV, "PWD", "SHLVL", "_", "LC_CTYPE"}, set())
        self.assertTrue(call["env"][C.TOKEN_FD_ENV].isdigit())
        self.assertNotIn(F.DUMMY_TOKEN, json.dumps(call))
        self.assertEqual(self.leftovers(), [])

    def test_the_live_call_runs_in_the_masked_sandbox_and_gets_only_the_token_fd(self):
        binp, _ = fake_bin(self.dir, "sandbox-probe")
        home, cwd = os.path.join(self.dir, "realhome"), os.path.join(self.dir, "runner-cwd")
        absent = []
        for rel in (".claude/.credentials.json", ".claude.json", ".claude/settings.json", ".codex/auth.json",
                    ".ssh/id_ed25519", ".config/gh/hosts.yml", ".local/state/pullo/x", "projects/x/.env"):
            Path(home, rel).parent.mkdir(parents=True, exist_ok=True)
            Path(home, rel).write_text("CANARY-SECRET")
            absent += [os.path.join(home, rel), os.path.join(home, rel.split("/")[0])]
        os.mkdir(cwd)
        Path(cwd, ".env").write_text("OPENROUTER_KEY=CANARY-SECRET\n")
        outside = os.path.join(str(F.ROOT), "outside-write-probe")
        spec = json.dumps({"hidden": [os.path.join(cwd, ".env"), *absent], "outside": outside})
        old = os.getcwd()
        os.chdir(cwd)
        try:
            with mock.patch.object(C, "_user_homes", return_value=[home]), \
                    mock.patch.object(C, "real_home", return_value=os.path.realpath(home)):
                p = exposed(binp, workdir_parent=self.dir)
                res = p.call(F.claude_request(text=F.PROBE_MARK + spec + "\n"), KEY)
        finally:
            os.chdir(old)
        seen = json.loads(res.response["rawText"])
        self.assertEqual(seen["hidden"][os.path.join(cwd, ".env")], {"error": "PermissionError"})
        for path in absent:
            self.assertEqual(seen["hidden"][path], {"absent": True}, path)            # the whole home is an empty tmpfs
        self.assertEqual(seen["outside"], "OSError")
        self.assertFalse(os.path.exists(outside))
        self.assertNotIn("CANARY-SECRET", res.response["rawText"])
        self.assertEqual(seen["fdHolds"], "dummy")                                 # the token arrives via the fd only
        self.assertFalse(seen["tokenInEnv"])
        if C.runtime_dir():
            self.assertEqual(seen["runUser"], [])
        self.assertLessEqual(seen["procPids"], 8)
        self.assertEqual(seen["tmp"], [])
        want = {Path(x).relative_to("/var/tmp").parts[0] for x in (self.dir, os.path.dirname(binp), str(F.ROOT))
                if str(x).startswith("/var/tmp/")}
        self.assertEqual(set(seen["varTmp"]), want)

    def test_a_scheduled_retry_is_killed_at_once(self):
        binp, _ = fake_bin(self.dir, "retry401")
        p = exposed(binp, workdir_parent=self.dir)
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((d["reason"], d["requestsSeen"], d["errorType"]), ("cli-retry", 1, "claude.auth"))

    def test_preflight_against_the_fake_binary(self):
        binp, _ = F.write_fake_binary(self.dir, "ok")
        r = C.check_cli_isolation(binp, capture=False)
        self.assertTrue(r["supported"], r)
        self.assertEqual(r["version"], C.CLAUDE_CLI_VERSION + " (Claude Code)")    # through the isolated bwrap probe
        old, _ = F.write_fake_binary(os.path.join(self.dir), "old", version="2.1.308")
        self.assertFalse(C.check_cli_isolation(old, capture=False)["supported"])
        nof, _ = F.write_fake_binary(os.path.join(self.dir), "noflag", flags=C.REQUIRED_HELP_FLAGS[:-1])
        self.assertIn("claude lacks --effort", C.check_cli_isolation(nof, capture=False)["problems"])
        with mock.patch.object(C, "MANAGED_SETTINGS_DIR", self.dir):
            self.assertIn(f"managed (policy) settings exist at {self.dir}: they would apply to every call",
                          C.check_cli_isolation(binp, capture=False)["problems"])


class Bounded(unittest.TestCase):
    def test_token_pipe_stdin_roundtrip_deadline_and_cap(self):
        code = ("import os,sys; fd=int(os.environ['" + C.TOKEN_FD_ENV + "']); t=os.read(fd,99).decode(); "
                "sys.stdout.write(t+'|'+sys.stdin.read())")
        r = C.run_bounded_stream(["python3", "-I", "-c", code], b"hello", {"PATH": os.environ["PATH"]}, "/",
                                 10, token=Secret(F.DUMMY_TOKEN))
        self.assertEqual((r.returncode, r.stdout), (0, (F.DUMMY_TOKEN + "|hello").encode()))
        r = C.run_bounded_stream(["python3", "-I", "-c", "import os; print(sorted(os.environ))"], b"",
                                 {"PATH": os.environ["PATH"]}, "/", 10)
        self.assertNotIn(C.TOKEN_FD_ENV, r.stdout.decode())
        t = time.monotonic()
        r = C.run_bounded_stream(["sleep", "5"], b"", {"PATH": os.environ["PATH"]}, "/", 0.5)
        self.assertTrue(r.timed_out and time.monotonic() - t < 3)
        r = C.run_bounded_stream(["python3", "-I", "-c", "print('x'*100000)"], b"", {"PATH": os.environ["PATH"]}, "/", 10,
                                 max_stdout=1000)
        self.assertTrue(r.truncated)

    def test_audit_kills_the_run_at_the_first_retry_event(self):
        m = "claude-sonnet-5-5"
        lines = [F.init(m), F.ev("system", subtype="api_retry", error_status=401, retry_delay_ms=261)]
        code = ("import sys,time; [print(x, flush=True) for x in " + repr(lines) + "]; time.sleep(5); print('late')")
        t = time.monotonic()
        a = C.StreamAudit(model=F.MODEL)
        r = C.run_bounded_stream(["python3", "-I", "-c", code], b"", {"PATH": os.environ["PATH"]}, "/", 10, audit=a)
        self.assertEqual(r.aborted, "cli-retry")
        self.assertLess(time.monotonic() - t, 3)
        self.assertNotIn(b"late", r.stdout)


def _pinned_cli():
    if not (shutil.which("claude") and BWRAP):
        return False
    try:
        r, _ = C._probe(["claude", "--version"], timeout=30)                     # isolated home, never the user's dirs
    except (OSError, subprocess.SubprocessError):
        return False
    return r.stdout.decode().strip() == C.CLAUDE_CLI_VERSION + " (Claude Code)"


@unittest.skipUnless(_pinned_cli(), "needs the installed claude 2.1.309 and bwrap")
class RealCliCaptureProof(unittest.TestCase):
    """The REAL claude binary, offline: private network namespace, a dummy OAuth token on the live fd path, loopback fake
    Anthropic endpoint, the exact live argv/env, run through the live bwrap sandbox. No inference, no real credential."""

    def test_full_offline_preflight_for_every_pinned_model(self):
        rep = C.check_cli_isolation("claude")
        self.assertTrue(rep["supported"], rep)
        self.assertEqual(sorted(rep["requestIsolation"]), sorted(f"{m}:{k}" for m in CLAUDE_CLI_MODELS
                                                                 for k in C.PREFLIGHT_CAPTURE_MODES))
        for k, v in rep["requestIsolation"].items():
            self.assertEqual((v["supported"], v["tools"], v["posts"]), (True, [], 1), k)

    def test_every_other_mode_on_the_real_cli_through_the_forwarder(self):
        for mode in [m for m in C.CAPTURE_MODES if m not in C.PREFLIGHT_CAPTURE_MODES]:   # 404-then-ok, remote-settings, ...
            with self.subTest(mode):
                cap = C.check_request_isolation("claude", F.MODEL, mode=mode)
                self.assertTrue(cap["supported"], cap)
                self.assertEqual(cap["posts"], 1)                                   # exact: the forwarder relays at most one


class Canary(Base):
    def test_requires_confirm_live_and_an_approved_tmpdir(self):
        with self.assertRaises(SystemExit):
            CAN.main(["--out-dir", self.dir])
        with mock.patch.dict(os.environ, {"TMPDIR": "/tmp/x"}), self.assertRaises(SystemExit):
            CAN.main(["--out-dir", self.dir, "--confirm-live"])

    def test_canary_passes_on_a_clean_answer_and_keeps_the_cli_words_on_failure(self):
        ok = F.ScriptedRunner("ok")
        rec = CAN.run_canary(self.dir, runner=ok, preflight=GOOD, token_loader=F.dummy_token,
                             provider_factory=functools.partial(C.ClaudeCliProvider, forwarder=ok.forwarder))
        doc = json.loads(Path(rec, "receipt.json").read_text())
        self.assertTrue(doc["ok"] and all(doc["checks"].values()), doc["checks"])
        self.assertEqual((doc["billingKind"], doc["actualUsdMicros"], doc["openRouterCalls"]), ("claude-subscription", 0, 0))
        self.assertNotIn(F.DUMMY_TOKEN, Path(rec, "receipt.json").read_text() + Path(rec, "runtime-ledger.jsonl").read_text())
        with self.assertRaisesRegex(RuntimeError, "canary failed"):
            lim = F.ScriptedRunner("usage-limit")
            CAN.run_canary(self.dir, runner=lim, preflight=GOOD, token_loader=F.dummy_token,
                           provider_factory=functools.partial(C.ClaudeCliProvider, forwarder=lim.forwarder),
                           now=__import__("datetime").datetime(2026, 11, 1, tzinfo=__import__("datetime").timezone.utc))
        bad = Path(self.dir, "claude-cli-canary-20261101T000000000000Z")
        self.assertIn("hit your limit", Path(bad, "receipt.json").read_text())


if __name__ == "__main__":
    unittest.main()


class ForwarderUnit(unittest.TestCase):
    """The REAL Forwarder against a loopback upstream (no CLI, no sandbox): what it relays, refuses, counts and records."""

    def setUp(self):
        self.url, self.srv, self.log = F.start_upstream(headers=[("anthropic-ratelimit-unified-status", "allowed"),
                                                                 ("anthropic-ratelimit-unified-overage-in-use", "false")])
        self.addCleanup(self.srv.shutdown)
        self.fwd = C.Forwarder(self.url)
        self.addCleanup(self.fwd._srv.shutdown)

    def req(self, base, method="POST", path=C.FORWARD_PATH, body=None, headers=None):
        import http.client
        import urllib.parse
        u = urllib.parse.urlsplit(base)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        raw = json.dumps(body).encode() if body is not None else None
        c.request(method, u.path + path, body=raw, headers={"content-type": "application/json", "authorization": "Bearer DUMMY",
                                                            **(headers or {})})
        r = c.getresponse()
        out = (r.status, r.read())
        c.close()
        return out

    def test_relays_one_streamed_post_and_refuses_everything_else(self):
        slot = self.fwd.open("claude-sonnet-5-5", 10)
        base = self.fwd.base_url(slot)
        self.assertRegex(base, C.BASE_URL_RE)
        good = {"model": "claude-sonnet-5-5", "stream": True, "tools": [], "messages": [{"role": "user", "content": "x"}]}
        self.assertEqual(self.req(base, "GET", "/api/claude_code/settings")[0], 404)       # remote settings: never relayed
        self.assertEqual(self.req(base, "HEAD", "/api/hello")[0], 404)
        for bad, why in ((dict(good, stream=False), "not-streaming"), (dict(good, model="claude-haiku-5-5"), "model"),
                         (dict(good, tools=[{"name": "Bash"}]), "tools"), (dict(good, tool_choice={"type": "any"}), "tools")):
            self.assertEqual(self.req(base, body=bad)[0], 404, why)
        self.assertEqual(self.req(base, path="/v1/messages/count_tokens?beta=true", body=good)[0], 404)
        status, body = self.req(base, body=good)
        self.assertEqual((status, body), (200, b"event: message_stop\ndata: {}\n\n"))
        self.assertEqual(self.req(base, body=good)[0], 404)                                  # a second request: refused
        self.assertEqual(self.req("http://127.0.0.1:%d/c/%s" % (self.fwd.port, "x" * 40), body=good)[0], 404)   # unknown token
        facts = self.fwd.close(slot)
        self.assertEqual((facts["requestsSent"], facts["requestsAttempted"], facts["upstreamStatus"]), (1, 9, 200))
        self.assertEqual([a["verdict"] for a in facts["refused"]],
                         ["method-or-path", "method-or-path", "not-streaming", "model", "tools", "tools", "method-or-path",
                          "second-request"])
        self.assertEqual(facts["rateLimitHeaders"], {"anthropic-ratelimit-unified-status": "allowed",
                                                     "anthropic-ratelimit-unified-overage-in-use": "false"})
        self.assertEqual(self.fwd.stray, 1)
        self.assertEqual([(x["method"], x["path"], x["auth"], x["acceptEncoding"]) for x in self.log],
                         [("POST", C.FORWARD_PATH, "Bearer DUMMY", "identity")])             # exactly one, headers relayed
        self.assertNotIn("DUMMY", json.dumps(facts))                                         # no header value is recorded
        self.assertEqual(self.req(base, body=good)[0], 404)                                  # a closed slot relays nothing

    def test_upstream_errors_keep_status_and_words(self):
        url, srv, log = F.start_upstream(status=429, headers=[("anthropic-ratelimit-unified-status", "rejected")])
        self.addCleanup(srv.shutdown)
        fwd = C.Forwarder(url)
        self.addCleanup(fwd._srv.shutdown)
        slot = fwd.open("claude-opus-5-5", 10)
        status, body = self.req(fwd.base_url(slot), body={"model": "claude-opus-5-5", "stream": True, "messages": []})
        f = fwd.close(slot)
        self.assertEqual((status, f["upstreamStatus"], f["requestsSent"], f["rateLimitHeaders"]),
                         (429, 429, 1, {"anthropic-ratelimit-unified-status": "rejected"}))
        self.assertIn('"message":"up"', f["upstreamError"])
        with self.assertRaises(ValueError):
            C.Forwarder("ftp://x")
