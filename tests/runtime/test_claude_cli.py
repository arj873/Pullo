"""CLAUDE-CLI-PROVIDER: the Claude Code CLI subscription adapter, offline. The fake CLI (claude_fake) prints the stream-json
events the real claude 2.1.317 produces (CLI317; as 2.1.309 but for the deltas in claude_cli); no network, no credential, no live call. RealCliCaptureProof runs the REAL CLI
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
from tests.runtime import claude_repair_proof as RP

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)
GOOD = {"supported": True, "problems": []}
HOSTILE_ENV = {"PATH": os.environ["PATH"], "HOME": "/home/operator", "OPENROUTER_API_KEY": "sk-or-v1-" + "f4k3" * 12,
               "ANTHROPIC_API_KEY": "sk-ant-api03-x", "ANTHROPIC_BASE_URL": "http://evil", "CLAUDE_CODE_OAUTH_TOKEN": "t",
               "CLAUDE_CONFIG_DIR": "/home/operator/.claude", "HTTPS_PROXY": "http://proxy", "LANG": "C.UTF-8",
               "CLAUDE_CODE_USE_BEDROCK": "1", "XDG_CONFIG_HOME": "/home/operator/.config"}
ALLOWED_ENV = {*C.ENV_PASS, *C.ENV_HOME_KEYS, *dict(C.ENV_FLAGS), "ANTHROPIC_BASE_URL",   # the base URL: the forwarder slot only
               C.OUTPUT_CAP_ENV}                                                          # TIMEOUT-FIX: the per-call output cap


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
        self.assertEqual(set(env), ALLOWED_ENV - {"LC_ALL", "ANTHROPIC_BASE_URL", C.OUTPUT_CAP_ENV})   # both added per call
        for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "OPENROUTER_API_KEY", "HTTPS_PROXY",
                  "CLAUDE_CODE_USE_BEDROCK", C.TOKEN_FD_ENV):
            self.assertNotIn(k, env)
        self.assertTrue(all(env[k].startswith(d + os.sep) for k in C.ENV_HOME_KEYS))
        self.assertEqual(env["CLAUDE_CONFIG_DIR"], os.path.join(d, "home", ".claude"))
        f = dict(C.ENV_FLAGS)
        self.assertEqual((f["CLAUDE_CODE_MAX_RETRIES"], f["CLAUDE_CODE_MAX_TURNS"], f["CLAUDE_CODE_DISABLE_FILE_MENTIONS"],
                          f["CLAUDE_CODE_DISABLE_THINKING"]), ("0", "1", "1", "1"))
        self.assertNotIn(C.OUTPUT_CAP_ENV, f)                                   # TIMEOUT-FIX: set per call to the role cap

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
                         ("claude-cli-isolated@5", "2.1.317", "claude-bwrap-masked@2"))

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
            self.assertEqual(C.LIVE_DEFAULT_TOKEN_LOADER().source, "operator-token-file")   # the real loader (R2: tests use a stub)
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
                         ("req_fake_1", 1, 0, 1, "claude-loopback-forwarder@3"))
        self.assertEqual(self.led.totals()["committedUsdMicros"], 0)
        self.assertNotIn(F.DUMMY_TOKEN, Path(self.dir, "led.jsonl").read_text())
        self.assertEqual(self.leftovers(), [])

    def test_fenced_and_one_object_in_prose_are_accepted_and_noted_two_objects_are_invalid_output(self):
        p = self.prov("fenced", "prose", "over-cap", "prose-two", "prose-only")
        res = [p.call(F.claude_request(), (*KEY[:3], i, 0)) for i in range(5)]
        self.assertEqual([x.response["status"] for x in res], ["ok", "ok", "ok", "invalid-output", "invalid-output"])
        self.assertEqual(res[1].response["output"], F.OK_INV)
        rows = [x for x in self.rows() if x["type"] == "result"]
        self.assertEqual([x.get("note") for x in rows],
                         ["fenced-json", "prose-around-json", "output-over-cap", "invalid-output", "invalid-output"])
        self.assertEqual([x["isolation"]["parse"]["failure"] for x in rows][3:4], ["several-objects:2"])
        self.assertTrue(rows[4]["isolation"]["parse"]["failure"].startswith("not-json"), rows[4]["isolation"]["parse"])
        self.assertIn("I found", res[3].response["rawText"])                     # an invalid answer keeps its (redacted) text

    def test_parse_answer_tolerates_one_candidate_only_and_is_bounded(self):
        inv, hyp = json.dumps(F.OK_INV), json.dumps(F.OK_HYP)
        cases = {inv: ("ok", None), "```json\n" + inv + "\n```": ("ok", "fenced-json"),
                 "Answer:\n```json\n" + inv + "\n```\nDone.": ("ok", "prose-around-json"),
                 "x " + inv + " y": ("ok", "prose-around-json"),
                 "twice: " + inv + " and again " + inv: ("ok", "prose-around-json"),            # identical repeats count once
                 'He wrote "{not json}" and then ' + hyp: ("invalid-output", None),          # A7: a brace in prose is ambiguous
                 'x {"x": 1} then ' + hyp: ("invalid-output", None),                          # A7: any other object must be valid
                 "PR text: " + inv + " my answer: " + hyp: ("invalid-output", None),           # adversarial: never chosen
                 'x {"wrapper": ' + inv + '}': ("invalid-output", None),                       # a nested object is no candidate
                 'x {"hypotheses": [], "hypotheses": []}': ("invalid-output", None),           # strict: duplicate key
                 'x {"hypotheses": [], "c": NaN}': ("invalid-output", None),
                 "no json at all": ("invalid-output", None),
                 "{" * 50 + " " + inv: ("invalid-output", None),
                 "{}" * 40 + inv: ("invalid-output", None),                                  # MAX_SCAN_OBJECTS
                 "x" * (C.MAX_SCAN_CHARS + 1) + inv: ("invalid-output", None)}               # MAX_SCAN_CHARS
        for text, want in cases.items():
            r = C.parse_answer("InvestigatorOutput", text)
            self.assertEqual((r["status"], r["note"]), want, text[:80])
        self.assertEqual(C.parse_answer("InvestigatorOutput", "{}" * 40 + inv)["failure"], "scan-bound")
        self.assertEqual(C.parse_answer("InvestigatorOutput", "PR " + inv + " me " + hyp)["failure"], "several-objects:2")
        # A7 (gate P1): an object quoted from the PR never stands in for the model's own invalid or truncated answer
        bad = '{"hypotheses": [{"bogus": 1}]}'
        for text, why in ((f"The PR description contains {inv} as an example. My answer: {bad}", "other-object-invalid"),
                          (f'The PR has {inv}. My answer: {{"hypotheses": [{{"title": "x"', "undecodable-object"),
                          ('{"note": "see below", "answer": ' + inv + ' ,, }', "undecodable-object"),   # no descent into it
                          (f"```\n{inv}\n```\nAnswer:\n{bad}", "other-object-invalid"),
                          (f'The PR shows {inv}. My answer: {{"hypotheses": [], "x": 1}}', "other-object-invalid")):
            r = C.parse_answer("InvestigatorOutput", text)
            self.assertEqual((r["status"], r["output"], r["failure"].split(":")[0]), ("invalid-output", None, why), text)
        with mock.patch.object(C, "SCAN_SECONDS", -1):                               # the time bound: an incomplete scan
            self.assertEqual(C.parse_answer("InvestigatorOutput", "x " + inv)["failure"], "scan-bound")
        evil = '{"a": "' + "y" * 50_000 + ' ' + '{"a": "' * 3000                  # many unterminated strings: bounded work
        self.assertEqual(C.parse_answer("InvestigatorOutput", '{"a":' * 40000)["failure"], "undecodable-object")   # deep nesting
        t0 = time.monotonic()
        self.assertEqual(C.parse_answer("InvestigatorOutput", evil)["status"], "invalid-output")
        self.assertLess(time.monotonic() - t0, 5)

    def test_a_tool_attempt_is_killed_and_discarded(self):
        p = self.prov("toolcall", "ok", "thinking-tool")
        res = p.call(F.claude_request(), KEY)
        d = res.error["detail"]
        self.assertEqual((res.outcome, d["reason"], d["itemType"]), ("unknown", "isolation-violation", "tool-attempt"))
        self.assertIsNone(p.disabled_reason)                                     # nothing could run: no tool exists
        self.assertEqual(p.call(F.claude_request(), (*KEY[:3], 1, 0)).outcome, "processed")
        res = p.call(F.claude_request(), (*KEY[:3], 2, 0))                       # A5: thinking first changes nothing
        self.assertEqual((res.outcome, res.error["detail"]["itemType"]), ("unknown", "tool-attempt"))

    def test_adaptive_thinking_is_admitted_counted_paced_and_never_kept(self):
        p = self.prov("thinking", "thinking-heavy", "thinking-mismatch")
        a, b, c = (p.call(F.claude_request(), (*KEY[:3], i, 0)) for i in range(3))
        self.assertEqual([x.response["status"] for x in (a, b, c)], ["ok", "ok", "ok"])
        self.assertEqual(a.response["output"], F.OK_INV)                         # A6: the decoy in thinking is never a candidate
        self.assertEqual(a.response["output"], F.OK_INV)                         # the text answer, never the thinking decoy
        rows = [x for x in self.rows() if x["type"] == "result"]
        t = rows[0]["isolation"]["thinking"]
        self.assertEqual((t["blocks"], t["redactedBlocks"], t["events"], t["estimatedTokens"], t["sseBlocks"], t["sseRedactedBlocks"],
                          t["crossCheck"]), (2, 1, 2, 18, 2, 1, "match"))
        self.assertEqual((rows[0]["usage"]["reasoningTokens"], rows[0]["usage"]["outputTokens"], rows[0]["note"]),
                         (18, 40, "adaptive-thinking"))
        u = F.USAGE                                   # output_tokens (40) already includes the 18 thinking tokens: paced on 40
        self.assertEqual(rows[0]["apiEquivalentEstimateUsdMicros"], claude_cli_pacing_micros(
            F.MODEL, u["input_tokens"], u["cache_read_input_tokens"], u["cache_creation_input_tokens"], 40))
        self.assertEqual((rows[1]["usage"]["reasoningTokens"], rows[1]["note"]), (5014, "output-over-cap,adaptive-thinking"))
        self.assertEqual(rows[1]["apiEquivalentEstimateUsdMicros"], claude_cli_pacing_micros(          # never below the estimate
            F.MODEL, u["input_tokens"], u["cache_read_input_tokens"], u["cache_creation_input_tokens"], 5014))
        self.assertEqual((rows[2]["isolation"]["thinking"]["crossCheck"], rows[2]["note"]),
                         ("mismatch", "adaptive-thinking,thinking-count-mismatch"))
        kept = Path(self.dir, "led.jsonl").read_text() + json.dumps([x.response for x in (a, b, c)])
        self.assertNotIn("PULLO-FAKE-THINKING", kept)
        self.assertNotIn("PULLO-DECOY", kept)
        self.assertNotIn("opaque-redacted", kept)
        self.assertNotIn("sig-1", kept)

    def test_a_max_tokens_stop_is_a_cut_answer_its_continuation_killed_and_never_relayed(self):
        req = F.claude_request()
        cap = req["params"]["maxOutputTokens"]
        for sc, raw in (("max-tokens-cut", F.CUT_TEXT), ("max-tokens-cut-thinking", "")):
            with self.subTest(sc):
                p = self.prov(sc)
                res = p.call(req, KEY)
                self.assertEqual((res.outcome, res.error), ("processed", None))
                r = res.response
                self.assertEqual((r["status"], r["output"], r["rawText"], r["usage"]["outputTokens"]), ("invalid-output", None, raw, cap))
                row = [x for x in self.rows() if x["type"] == "result"][-1]
                self.assertEqual((row["outcome"], row["finishReason"], row["isolation"]["requestsSent"],
                                  row["isolation"]["parse"]["failure"]), ("processed", "max_tokens", 1, "max-output-tokens"))
                self.assertTrue({"invalid-output", "max-output-tokens", "finish-max_tokens"} <= set(row["note"].split(",")), row["note"])
                self.assertNotIn("PULLO-DECOY", json.dumps(self.rows()) + json.dumps(r))
                self.assertEqual(self.runner.seen[0]["env"][C.OUTPUT_CAP_ENV], str(cap))   # max_tokens = the role cap, per call

    def test_the_output_cap_is_per_call_required_and_bound_on_both_sides(self):
        p = self.prov("ok")
        req = F.claude_request()
        p.call(req, KEY)
        s = self.runner.seen[0]
        self.assertEqual(s["env"][C.OUTPUT_CAP_ENV], str(req["params"]["maxOutputTokens"]))
        self.assertEqual(self.runner.forwarder.closed[-1]["requestsSent"], 1)
        prob = lambda env, mt: C.review_call_problems(s["argv"], s["stdin"], env, s["cwd"], F.MODEL, max_tokens=mt)  # noqa: E731
        self.assertFalse([x for x in prob(s["env"], req["params"]["maxOutputTokens"]) if "output cap" in x])
        self.assertTrue([x for x in prob(s["env"], 16000) if "output cap" in x])           # another role's cap
        self.assertTrue([x for x in prob(dict(s["env"], **{C.OUTPUT_CAP_ENV: "128001"}), None) if "output cap" in x])
        self.assertTrue([x for x in prob({k: v for k, v in s["env"].items() if k != C.OUTPUT_CAP_ENV}, None) if "output cap" in x])
        for bad in (None, 0, C.OUTPUT_TOKENS + 1, "4000", True):
            with self.subTest(bad=bad):
                r = dict(req, params={k: v for k, v in req["params"].items() if k != "maxOutputTokens"}
                         | ({} if bad is None else {"maxOutputTokens": bad}))
                res = self.prov("ok").call(r, KEY)
                self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "request-refused"))

    def test_isolation_audit_failures_discard_output(self):
        for sc, item in (("init-tools", "init-surface:init-tools"), ("init-mcp", "init-surface:init-mcp_servers"),
                         ("init-plugin", "init-surface:init-plugins"), ("wrong-model", "init-surface:init-model"),
                         ("two-requests", "extra-request"), ("max_tokens", "extra-turn"),
                         ("max-tokens-other-turn", "extra-turn"),            # max_tokens upstream, but not the CLI's own turn
                         ("extra-model", "extra-model:claude-haiku-5-5"), ("unknown-event", "unknown-event:system/hook_response"),
                         ("thinking-badshape", "unknown-event:content/thinking-shape"),
                         ("thinking-event-badshape", "unknown-event:system/thinking_tokens-shape"),
                         ("sse-tool", "upstream-block:tool_use"), ("multi-turn", "num-turns:2"),
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

    def test_extra_usage_on_a_non_clean_call_is_booked_and_latches_too(self):
        for sc, reason in (("overage-tool", "isolation-violation"), ("overage-timeout", "timeout")):
            with self.subTest(sc):
                p = self.prov(sc, "ok", timeout_sec=5)
                res = p.call(F.claude_request(params={"maxOutputTokens": 100, "timeoutSec": 5}), KEY)
                d = res.error["detail"]
                self.assertEqual((d["reason"], d["extraUsage"], p.latched["errorType"]), (reason, True, "claude.extra-usage"))
                row = self.rows()[-1]
                self.assertEqual((row["billingKind"], row["costBasis"]), ("claude-extra-usage", "extra-usage-charge-unknown"))
                self.assertTrue(row["note"].startswith("claude.extra-usage: may have been billed"), row["note"])
                again = p.call(F.claude_request(), (*KEY[:3], 1, 0))
                self.assertEqual((again.outcome, again.error["detail"]["reason"]), ("not-sent", "limit-latched"))

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
        a = self.feed(F.init(m), F.think_event(10, 10), F.think_event(12, 2), F.assistant(m, [{"type": "thinking", "thinking": "t",
                                                                                         "signature": "s"}]))
        self.assertEqual((a.thinking, a.unknown, a.reason), ({"thinking": 1, "redacted_thinking": 0, "events": 2, "estimatedTokens": 12},
                                                             [], None))
        for bad in (F.ev("system", subtype="thinking_tokens", estimated_tokens=-1, estimated_tokens_delta=1),
                    F.ev("system", subtype="thinking_tokens", estimated_tokens=1, estimated_tokens_delta=True),
                    F.ev("system", subtype="thinking_tokens", estimated_tokens=1)):
            self.assertEqual(self.feed(F.init(m), bad).unknown, ["system/thinking_tokens-shape"], bad)
        for blk, want in (({"type": "redacted_thinking", "data": 1}, "content/redacted_thinking-shape"),
                          ({"type": "thinking", "thinking": "t", "signature": "s", "citations": []}, "content/thinking-shape")):
            self.assertEqual(self.feed(F.init(m), F.assistant(m, [blk])).unknown, [want])

    def test_sse_tally_counts_blocks_across_chunk_boundaries_and_keeps_no_text(self):
        evs = [{"type": "message_start", "message": {"usage": {"input_tokens": 5}}},
               {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}},
               {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta",
                                                                     "thinking": "SECRET content_block_start message_delta"}},
               {"type": "content_block_start", "index": 1, "content_block": {"type": "redacted_thinking", "data": "x"}},
               {"type": "content_block_start", "index": 2, "content_block": {"type": "text", "text": ""}},
               {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 77}}]
        raw = b"".join(f"event: {e['type']}\ndata: {json.dumps(e, separators=(',', ':'))}\n\n".encode() for e in evs)
        t = C._SseTally()
        for i in range(0, len(raw), 7):                                            # 7-byte chunks: lines split anywhere
            t.feed(raw[i:i + 7])
        self.assertEqual(t.facts, {"blocks": {"thinking": 1, "redacted_thinking": 1, "text": 1}, "outputTokens": 77,
                                   "stopReason": "end_turn", "unparsed": 0})
        self.assertNotIn("SECRET", json.dumps(t.facts))

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

    def test_work_audit_admits_only_the_builtin_plugin_store_layout(self):
        """CLI317: 2.1.317's builtin plugins keep state in <config>/plugins/store/: the store file, its atomic-write temp and
        its empty mkdir lock are admitted for the BUILTIN_PLUGINS only; any other `plugins` content still fails."""
        name = "cc-plugin-agents-md_builtin-" + hashlib.sha256(b"cc-plugin-agents-md@builtin").hexdigest()[:12] + ".json"
        self.assertEqual(name, "cc-plugin-agents-md_builtin-b049b47b3618.json")             # what the real 2.1.317 writes
        self.assertEqual(len(C.PLUGIN_STORE_FILES), len(C.BUILTIN_PLUGINS))

        def audit(make):
            with tempfile.TemporaryDirectory() as d:
                C.isolated_home(d, {})
                os.mkdir(os.path.join(d, "cwd"))
                store = Path(d, "home", ".claude", "plugins", "store")
                store.mkdir(parents=True)
                make(store)
                return C.audit_work_after(d, F.dummy_token().secret)

        good = (lambda s: None, lambda s: Path(s, name).write_text('{"usage-rows-queued": "x ok"}\n'),
                lambda s: (Path(s, name + ".lock").mkdir(), Path(s, name + ".tmp.9efb39f4").write_text("{")),   # killed mid-write
                lambda s: s.rmdir())                                                      # plugins/ without store/
        for i, make in enumerate(good):
            with self.subTest(good=i):
                self.assertTrue(audit(make)["ok"])
        other = "evil_market-" + "0" * 12 + ".json"
        bad = {"another plugin's store": lambda s: Path(s, other).write_text("{}"),
               "a carry temp": lambda s: Path(s, name + ".carry-1").write_text("{}"),
               "a lock with content": lambda s: (Path(s, name + ".lock").mkdir(), Path(s, name + ".lock", "x").write_text("")),
               "a lock that is a file": lambda s: Path(s, name + ".lock").write_text(""),
               "a symlink": lambda s: Path(s, name).symlink_to("/etc/hostname"),
               "an oversize store": lambda s: Path(s, name).write_text("x" * (C.PLUGIN_STORE_MAX_BYTES + 1)),
               "an installed plugin": lambda s: Path(s.parent, "installed_plugins.json").write_text("{}"),
               "a marketplace": lambda s: Path(s.parent, "marketplaces").mkdir(),
               "the token in the store": lambda s: Path(s, name).write_text(F.DUMMY_TOKEN)}
        for why, make in bad.items():
            with self.subTest(bad=why):
                r = audit(make)
                self.assertFalse(r["ok"], r)
        with tempfile.TemporaryDirectory() as d:                                          # `plugins` anywhere else: still forbidden
            C.isolated_home(d, {})
            os.mkdir(os.path.join(d, "cwd"))
            Path(d, "home", "xdg", "config", "plugins").mkdir(parents=True)
            self.assertEqual(C.audit_work_after(d)["forbidden"], ["home/xdg/config/plugins"])

    def test_init_admits_the_2_1_317_builtin_plugins_only(self):
        """CLI317: init lists cc-plugin-agents-md, cc-plugin-privacy and cc-plugin-plugin-authoring (all builtin); any other
        plugin, a builtin name from another path, or the 2.1.309 version still fails the init surface."""
        ev = json.loads(F.init(C.CLAUDE_CLI_MODELS[F.MODEL]["cliModel"]))
        self.assertEqual(sorted(p["source"] for p in ev["plugins"]), sorted(C.BUILTIN_PLUGINS))
        self.assertEqual(C.init_problems(ev, F.MODEL), [])
        for over, why in (({"plugins": ev["plugins"] + [{"name": "x", "path": "builtin", "source": "cc-plugin-x@builtin"}]}, "init-plugins"),
                          ({"plugins": [dict(ev["plugins"][1], path="/x")]}, "init-plugins"),
                          ({"claude_code_version": "2.1.309"}, "init-version")):
            with self.subTest(why=why, over=over):
                self.assertEqual(C.init_problems(dict(ev, **over), F.MODEL), [why])


def capture_out(**over):
    m = F.MODEL
    body = {"model": "claude-sonnet-5-5", "max_tokens": CAP.PROBE_CAP, "stream": True, "tools": [],
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


@unittest.skipUnless(_pinned_cli(), "needs the installed claude 2.1.317 and bwrap")
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


@unittest.skipUnless(_pinned_cli(), "needs the installed claude 2.1.317 and bwrap")
class RealCliRepairProof(unittest.TestCase):
    """CLAUDE-CLI-REPAIR1 on the REAL claude binary, offline (tests/runtime/claude_repair_proof: private network namespace,
    loopback fake Anthropic endpoint, dummy token, the live sandbox and forwarder) under Pullo's real Gateway: a schema-invalid
    first answer gets exactly ONE repair call - admitted, traced (repairOf) and booked on its own, on the same model, its stdin
    quoting the local schema issue - and a still-invalid repair fails the call (repair-exhausted) with nothing sent after it."""

    def proof(self, model, answers, expect=()):
        r = subprocess.run(RP.argv(shutil.which("bwrap"), str(Path(__file__).resolve().parents[2])),
                           input=json.dumps({"model": model, "answers": answers, "expect": list(expect)}).encode(),
                           capture_output=True, timeout=300,
                           env={k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "TMPDIR")})
        return json.loads(r.stdout)

    def test_one_repair_call_fixes_a_schema_invalid_answer_and_a_still_invalid_one_fails(self):
        for model in sorted(CLAUDE_CLI_MODELS):
            cli = CLAUDE_CLI_MODELS[model]["cliModel"]
            with self.subTest(model=model, case="invalid-then-valid"):
                out = self.proof(model, [RP.INVALID, RP.VALID])
                self.assertEqual((out["maxRepairs"], out["result"]), (1, {"ok": True, "status": "ok", "error": None,
                                                                         "repairsUsed": None}), out)
                self.assertEqual(out["attempts"], [{"attempt": 0, "outcome": "invalid-output"}, {"attempt": 1, "outcome": "ok"}])
                self.assertEqual([(c["model"], c["repairMessage"], c["issueShown"]) for c in out["cli"]],
                                 [(cli, False, False), (cli, True, True)])
                self.assertEqual((out["posts"], out["others"]), (2, []))                  # exactly two requests, nothing else
                self.assertEqual([(r["attempt"], r["outcome"], r["note"], r["requestsSent"]) for r in out["rows"]],
                                 [(0, "processed", "invalid-output", 1), (1, "processed", None, 1)])
                self.assertEqual(out["trace"][1]["repairOf"], out["trace"][0]["callId"])
            with self.subTest(model=model, case="invalid-twice"):
                out = self.proof(model, [RP.INVALID, RP.INVALID])
                self.assertEqual(out["result"], {"ok": False, "status": None, "error": "repair-exhausted", "repairsUsed": 1}, out)
                self.assertEqual([a["outcome"] for a in out["attempts"]], ["invalid-output", "invalid-output"])
                self.assertEqual([(c["model"], c["repairMessage"]) for c in out["cli"]], [(cli, False), (cli, True)])
                self.assertEqual((out["posts"], len(out["rows"])), (2, 2))               # no third attempt

    def test_an_answer_cut_at_the_role_cap_is_repaired_once_and_told_why(self):   # TIMEOUT-FIX
        for model in sorted(CLAUDE_CLI_MODELS):
            with self.subTest(model=model):
                out = self.proof(model, [{"cut": '{"hypotheses": [{"claim": "cut her'}, RP.VALID],
                                 expect=["reached the output limit (16000 tokens, thinking included) and was cut off"])
                self.assertEqual((out["result"]["ok"], [a["outcome"] for a in out["attempts"]], out["posts"], out["others"]),
                                 (True, ["invalid-output", "ok"], 2, []), out)        # the CLI's continuation never reached upstream
                self.assertEqual(["max-output-tokens" in (r["note"] or "") for r in out["rows"]], [True, False])
                self.assertEqual((out["cli"][1]["repairMessage"], out["cli"][1]["expectShown"]), (True, [True]), out)

    def test_whole_text_failures_are_repaired_once_and_shown_exactly(self):
        model = sorted(CLAUDE_CLI_MODELS)[0]
        for name, (bad, issue) in RP.WHOLE_TEXT.items():                          # pilot data 2026-11-02: verifier slips
            with self.subTest(name):
                out = self.proof(model, [bad, RP.VALID], expect=[issue])
                self.assertEqual((out["result"]["ok"], [a["outcome"] for a in out["attempts"]], out["posts"]),
                                 (True, ["invalid-output", "ok"], 2), out)
                first, fix = out["cli"]
                self.assertEqual((first["repairMessage"], fix["repairMessage"], fix["expectShown"], fix["schemaAfterRepair"]),
                                 (False, True, [True], True), out)


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

    def test_an_invalid_answer_keeps_its_redacted_text_and_the_parse_failure(self):
        r = F.ScriptedRunner("prose-two")
        with self.assertRaisesRegex(RuntimeError, "canary failed"):
            CAN.run_canary(self.dir, runner=r, preflight=GOOD, token_loader=F.dummy_token,
                           provider_factory=functools.partial(C.ClaudeCliProvider, forwarder=r.forwarder),
                           now=__import__("datetime").datetime(2026, 11, 1, 0, 1, tzinfo=__import__("datetime").timezone.utc))
        doc = json.loads(Path(self.dir, "claude-cli-canary-20261101T000100000000Z", "receipt.json").read_text())
        self.assertEqual(([k for k, v in doc["checks"].items() if not v], doc["status"]), (["schemaValid"], "invalid-output"))
        self.assertEqual(doc["parse"]["failure"], "several-objects:2")
        self.assertIn("but I found", doc["rawText"])
        self.assertLessEqual(len(doc["rawText"]), CAN.RAW_CAP)
        ok = F.ScriptedRunner("ok")
        rec = CAN.run_canary(self.dir, runner=ok, preflight=GOOD, token_loader=F.dummy_token,
                             provider_factory=functools.partial(C.ClaudeCliProvider, forwarder=ok.forwarder))
        self.assertIsNone(json.loads(Path(rec, "receipt.json").read_text())["rawText"])     # a valid answer keeps no raw text

    def test_the_real_size_thinking_case_requires_observed_and_agreeing_thinking(self):
        req = CAN.canary_request("investigator-thinking")
        self.assertGreater(len(C._prompt(req).encode()), 50_000)                   # the size of the first live request that thought
        th = F.ScriptedRunner("thinking")
        rec = CAN.run_canary(self.dir, case="investigator-thinking", runner=th, preflight=GOOD, token_loader=F.dummy_token,
                             provider_factory=functools.partial(C.ClaudeCliProvider, forwarder=th.forwarder))
        doc = json.loads(Path(rec, "receipt.json").read_text())
        self.assertTrue(doc["ok"] and doc["checks"]["thinkingObserved"] and doc["checks"]["thinkingCrossCheck"], doc["checks"])
        self.assertEqual((doc["thinkingPolicy"], doc["thinking"]["blocks"], doc["reasoningTokens"]),
                         ("adaptive thinking (effort high)", 2, 18))
        self.assertNotIn("PULLO-FAKE-THINKING", Path(rec, "receipt.json").read_text() + Path(rec, "runtime-ledger.jsonl").read_text())
        for sc, check in (("ok", "thinkingObserved"), ("thinking-mismatch", "thinkingCrossCheck")):
            r = F.ScriptedRunner(sc)
            with self.assertRaisesRegex(RuntimeError, "canary failed"):
                CAN.run_canary(self.dir, case="investigator-thinking", runner=r, preflight=GOOD, token_loader=F.dummy_token,
                               provider_factory=functools.partial(C.ClaudeCliProvider, forwarder=r.forwarder),
                               now=__import__("datetime").datetime(2026, 11, 1, 0, 0, len(sc), tzinfo=__import__("datetime").timezone.utc))
            failed = json.loads(Path(self.dir, f"claude-cli-canary-20261101T0000{len(sc):02d}000000Z", "receipt.json").read_text())
            self.assertEqual([k for k, v in failed["checks"].items() if not v], [check], sc)


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

    def req(self, base, method="POST", path=C.FORWARD_PATH, body=None, headers=None, raw=None):
        import http.client
        import urllib.parse
        u = urllib.parse.urlsplit(base)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        raw = raw if raw is not None else json.dumps(body).encode() if body is not None else None
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
        good = {"model": "claude-sonnet-5-5", "stream": True, "tools": [], "max_tokens": C.OUTPUT_TOKENS,
                "messages": [{"role": "user", "content": "x"}]}
        self.assertEqual(self.req(base, "GET", "/api/claude_code/settings")[0], 404)       # remote settings: never relayed
        self.assertEqual(self.req(base, "HEAD", "/api/hello")[0], 404)
        for bad, why in ((dict(good, stream=False), "not-streaming"), (dict(good, model="claude-haiku-5-5"), "model"),
                         (dict(good, tools=[{"name": "Bash"}]), "tools"), (dict(good, tool_choice={"type": "any"}), "tools"),
                         (dict(good, mcp_servers=[{"type": "url", "url": "https://x"}]), "keys"), (dict(good, container="c"), "keys"),
                         (dict(good, thinking={"type": "enabled", "budget_tokens": 1024}), "keys"),
                         (dict(good, max_tokens=64000), "max-tokens")):
            self.assertEqual(self.req(base, body=bad)[0], 404, why)
        dup = json.dumps(good).replace('"tools": []', '"tools": [{"name": "Bash"}], "tools": []').encode()   # last-wins would pass
        self.assertEqual(self.req(base, raw=dup)[0], 404)
        self.assertEqual(self.req(base, path="/v1/messages/count_tokens?beta=true", body=good)[0], 404)
        status, body = self.req(base, body=good)
        self.assertEqual((status, body), (200, b"event: message_stop\ndata: {}\n\n"))
        self.assertEqual(self.req(base, body=good)[0], 404)                                  # a second request: refused
        self.assertEqual(self.req("http://127.0.0.1:%d/c/%s" % (self.fwd.port, "x" * 40), body=good)[0], 404)   # unknown token
        facts = self.fwd.close(slot)
        self.assertEqual((facts["requestsSent"], facts["requestsAttempted"], facts["upstreamStatus"]), (1, 14, 200))
        self.assertEqual([a["verdict"] for a in facts["refused"]],
                         ["method-or-path", "method-or-path", "not-streaming", "model", "tools", "tools", "keys", "keys", "keys",
                          "max-tokens", "not-json", "method-or-path", "second-request"])
        self.assertEqual(facts["rateLimitHeaders"], {"anthropic-ratelimit-unified-status": "allowed",
                                                     "anthropic-ratelimit-unified-overage-in-use": "false"})
        self.assertEqual(self.fwd.stray, 1)
        self.assertEqual([(x["method"], x["path"], x["auth"], x["acceptEncoding"]) for x in self.log],
                         [("POST", C.FORWARD_PATH, "Bearer DUMMY", "identity")])             # exactly one, headers relayed
        self.assertNotIn("DUMMY", json.dumps(facts))                                         # no header value is recorded
        self.assertEqual(self.req(base, body=good)[0], 404)                                  # a closed slot relays nothing

    def test_a_slot_relays_only_its_own_output_cap(self):                    # TIMEOUT-FIX: max_tokens = the call's role cap
        slot = self.fwd.open("claude-sonnet-5-5", 10, 16000)
        base = self.fwd.base_url(slot)
        good = {"model": "claude-sonnet-5-5", "stream": True, "tools": [], "max_tokens": 16000,
                "messages": [{"role": "user", "content": "x"}]}
        for mt in (C.OUTPUT_TOKENS, 15999, 16001):
            self.assertEqual(self.req(base, body=dict(good, max_tokens=mt))[0], 404, mt)
        self.assertEqual(self.req(base, body=good)[0], 200)
        facts = self.fwd.close(slot)
        self.assertEqual((facts["requestsSent"], [a["verdict"] for a in facts["refused"]]), (1, ["max-tokens"] * 3))

    def test_the_relay_tallies_the_upstream_sse_blocks(self):
        evs = [{"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}},
               {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "PULLO-SECRET"}},
               {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}},
               {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 9}},
               {"type": "message_stop"}]
        sse = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in evs)
        url, srv, log = F.start_upstream(sse=sse)
        self.addCleanup(srv.shutdown)
        fwd = C.Forwarder(url)
        self.addCleanup(fwd._srv.shutdown)
        slot = fwd.open("claude-sonnet-5-5", 10)
        status, body = self.req(fwd.base_url(slot), body={"model": "claude-sonnet-5-5", "stream": True, "tools": [],
                                                          "max_tokens": C.OUTPUT_TOKENS, "messages": []})
        f = fwd.close(slot)
        self.assertEqual((status, body), (200, sse))                                      # relayed byte for byte
        self.assertEqual(f["sse"], {"blocks": {"thinking": 1, "text": 1}, "outputTokens": 9, "stopReason": "end_turn", "unparsed": 0})
        self.assertNotIn("PULLO-SECRET", json.dumps(f))

    def test_upstream_errors_keep_status_and_words(self):
        url, srv, log = F.start_upstream(status=429, headers=[("anthropic-ratelimit-unified-status", "rejected")])
        self.addCleanup(srv.shutdown)
        fwd = C.Forwarder(url)
        self.addCleanup(fwd._srv.shutdown)
        slot = fwd.open("claude-opus-5-5", 10)
        status, body = self.req(fwd.base_url(slot), body={"model": "claude-opus-5-5", "stream": True, "max_tokens": C.OUTPUT_TOKENS,
                                                          "messages": []})
        f = fwd.close(slot)
        self.assertEqual((status, f["upstreamStatus"], f["requestsSent"], f["rateLimitHeaders"]),
                         (429, 429, 1, {"anthropic-ratelimit-unified-status": "rejected"}))
        self.assertIn('"message":"up"', f["upstreamError"])
        with self.assertRaises(ValueError):
            C.Forwarder("ftp://x")


class FailClosedUnderTests(unittest.TestCase):
    """Re-gate R2: the production defaults are disabled for the whole test package (tests/__init__.py)."""

    def test_defaults_point_nowhere_and_read_no_credential(self):
        import tests
        self.assertEqual(C.UPSTREAM, tests.CLOSED_UPSTREAM)
        with self.assertRaisesRegex(C.ClaudeAuthUnavailable, "disabled"):
            C.default_token_loader()
        with tempfile.TemporaryDirectory() as d:                                   # an adapter built with every default
            runner = F.ScriptedRunner("ok")
            p = C.ClaudeCliProvider(enabled=True, preflight=GOOD, runner=runner, workdir_parent=d)
            self.assertEqual(p._upstream, tests.CLOSED_UPSTREAM)
            res = p.call(F.claude_request(), KEY)
            self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "auth-unavailable"))
            self.assertEqual(runner.seen, [])                                        # nothing was spawned
            f = C.Forwarder(C.UPSTREAM)                                              # a relay can only fail, on-host
            self.addCleanup(f._srv.shutdown)
            self.assertEqual(urllib_parse(f._up), ("127.0.0.1", 9))
            g = C.Forwarder()                                                        # N5: the default is resolved at call time
            self.addCleanup(g._srv.shutdown)
            self.assertEqual(urllib_parse(g._up), ("127.0.0.1", 9))


def urllib_parse(u):
    return (u.hostname, u.port)
