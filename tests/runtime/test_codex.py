import json
import os
import sys
import tempfile
import time
import unittest

from reviewer.runtime import CodexTerraProvider, RuntimeLedger, check_cli_isolation
from reviewer.runtime import codex_cli as cc
from reviewer.runtime.codex_cli import CodexUnsupported, RunResult, build_argv, clean_env, run_bounded
from reviewer.runtime.catalog import TERRA_MODEL
from tests.runtime.common import FAKE_KEY, OK_VERIFY, req

KEY = ("VERIFY", "verifier", "verifier", 0, 0)
GOOD_PREFLIGHT = {"supported": True, "problems": []}
VERIFY_TERRA = lambda **o: req("verifier", **o)


def events(final=None, *, usage=None, extra=()):
    final = json.dumps(OK_VERIFY) if final is None else final
    ev = [{"type": "thread.started", "thread_id": "thr-123"}, {"type": "turn.started"},
          *extra,
          {"type": "item.completed", "item": {"id": "i1", "type": "agent_message", "text": final}},
          {"type": "turn.completed", "usage": usage if usage is not None else {"input_tokens": 1000, "cached_input_tokens": 200,
                                                         "output_tokens": 50, "reasoning_output_tokens": 10}}]
    return "".join(json.dumps(e) + "\n" for e in ev).encode()


class Runner:
    def __init__(self, *results):
        self.results, self.seen = list(results), []

    def __call__(self, argv, stdin, env, cwd, timeout):
        snap = {"argv": list(argv), "stdin": stdin, "env": dict(env), "cwd": cwd, "timeout": timeout,
                "cwd_listing": os.listdir(cwd) if os.path.isdir(cwd) else None}
        i = argv.index("--output-schema")
        snap["schema_exists"] = os.path.exists(argv[i + 1])
        if snap["schema_exists"]:
            with open(argv[i + 1]) as f:
                snap["schema"] = json.load(f)
        self.seen.append(snap)
        r = self.results.pop(0) if self.results else RunResult(0, events(), b"")
        if isinstance(r, Exception):
            raise r
        return r


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.dir = self._t.name

    def prov(self, *results, **kw):
        self.runner = Runner(*results)
        self.led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)
        return CodexTerraProvider(enabled=True, ledger=self.led, runner=self.runner, preflight=GOOD_PREFLIGHT,
                                  workdir_parent=self.dir, **kw)

    def receipts(self):
        p = os.path.join(self.dir, "led.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(x) for x in f]


class Argv(Base):
    def test_isolation_flags_present_and_bypass_flags_absent(self):
        a = build_argv("codex", "/s.json", "/c")
        for flag in ("--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--json", "--output-schema"):
            self.assertIn(flag, a)
        self.assertEqual(a[a.index("--sandbox") + 1], "read-only")
        self.assertEqual(a[a.index("--model") + 1], TERRA_MODEL)
        self.assertFalse(cc.FORBIDDEN_FLAGS & set(a))
        for f in ("shell_tool", "unified_exec", "apps", "plugins", "hooks", "multi_agent", "browser_use", "computer_use"):
            self.assertEqual(a[a.index(f) - 1], "--disable")
        self.assertEqual(a[-1], "-")
        self.assertIn('web_search="disabled"', a)

    def test_default_model_is_terra_not_the_configured_sol(self):
        self.assertNotIn("gpt-6.1-sol", " ".join(build_argv("codex", "/s", "/c")))

    def test_environment_is_minimal_and_keyless(self):
        env = clean_env({"PATH": "/bin", "HOME": "/h", "OPENROUTER_API_KEY": FAKE_KEY, "openrouter_key": FAKE_KEY,
                         "OPENAI_API_KEY": "sk-x" * 10, "HTTPS_PROXY": "http://p"})
        self.assertEqual(set(env), {"PATH", "HOME"})


class Calls(Base):
    def test_success_runs_isolated_and_reports_subscription_not_dollars(self):
        p = self.prov()
        res = p.call(VERIFY_TERRA(), KEY)
        self.assertEqual(res.outcome, "processed")
        r = res.response
        self.assertEqual((r["status"], r["output"], r["resolvedModel"], r["providerRequestId"]), ("ok", OK_VERIFY, TERRA_MODEL, "thr-123"))
        self.assertEqual(r["usage"], {"uncachedInputTokens": 800, "cachedInputTokens": 200, "cacheWriteInputTokens": None,
                                      "outputTokens": 50, "reasoningTokens": 10})
        seen = self.runner.seen[0]
        self.assertEqual(seen["cwd_listing"], [])                        # an EMPTY cwd
        self.assertTrue(seen["schema_exists"])
        self.assertIn(b"Diff:", seen["stdin"])                           # prompt on stdin, never argv
        self.assertFalse(any("Diff:" in a for a in seen["argv"]))
        self.assertFalse(os.path.exists(seen["argv"][seen["argv"].index("--output-schema") + 1]))   # temp dir removed
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual(rec["billingKind"], "subscription-consumption")
        self.assertEqual(rec["costBasis"], "unknown")
        self.assertNotIn("routerCostUsdMicros", rec)
        # 800*2 + 200*0.2 + 50*12 per Mtok = 1600+40+600 = 2240 micros: an API-equivalent ESTIMATE only
        self.assertEqual(rec["apiEquivalentEstimateUsdMicros"], 2240)
        self.assertEqual(rec["resolvedModelSource"], "requested-not-reported-by-cli")

    def test_cache_write_policy_zero_is_an_explicit_operator_choice(self):
        p = self.prov(cache_write_policy="zero")
        self.assertEqual(p.call(VERIFY_TERRA(), KEY).response["usage"]["cacheWriteInputTokens"], 0)
        with self.assertRaises(ValueError):
            self.prov(cache_write_policy="free")

    def test_strict_projection_is_what_the_cli_gets_and_nulls_are_normalised(self):
        out = {"verdict": "uncertain", "reachable": False, "impact": "none", "evidence": [], "notes": "n"}
        p = self.prov(RunResult(0, events(json.dumps(out)), b""))
        self.assertEqual(p.call(VERIFY_TERRA(), KEY).response["status"], "ok")
        sch = self.runner.seen[0]["schema"]
        self.assertEqual(set(sch["required"]), set(sch["properties"]))

    def test_invalid_output_is_processed_and_repairable(self):
        for text in ("not json", json.dumps({"verdict": "maybe"}), json.dumps({"verdict": "confirmed", "reachable": True,
                     "impact": "none", "evidence": [], "notes": "n"})):
            with self.subTest(text[:12]):
                self.setUp()
                res = self.prov(RunResult(0, events(text), b"")).call(VERIFY_TERRA(), KEY)
                self.assertEqual((res.outcome, res.response["status"], res.response["output"]), ("processed", "invalid-output", None))

    def test_refusals_before_spawn(self):
        p = self.prov()
        for why, r in {"model": VERIFY_TERRA(model="gpt-6.1-sol"), "provider": VERIFY_TERRA(provider="anthropic"),
                       "tools": VERIFY_TERRA(tools=[{"x": 1}]), "schema": VERIFY_TERRA(outputSchema="JudgeOutput")}.items():
            with self.subTest(why):
                res = p.call(r, KEY + (why,))
                self.assertEqual((res.outcome, res.error["code"]), ("not-sent", "provider-error"))
        self.assertEqual(self.runner.seen, [])

    def test_tool_use_is_an_isolation_violation_and_output_is_discarded(self):
        for item in ({"type": "command_execution", "command": "ls"}, {"type": "mcp_tool_call"}, {"type": "web_search"},
                     {"type": "file_change"}, {"type": "collab_tool_call"}):
            with self.subTest(item["type"]):
                self.setUp()
                ev = events(extra=[{"type": "item.started", "item": {"id": "x", **item}}])
                res = self.prov(RunResult(0, ev, b"")).call(VERIFY_TERRA(), KEY)
                self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("unknown", "isolation-violation"))
                self.assertIsNone(res.response)

    def test_failure_modes(self):
        cases = {"timeout": (RunResult(None, b"", b"", timed_out=True), "unknown", "provider-timeout"),
                 "oversize": (RunResult(0, b"x", b"", truncated=True), "unknown", "provider-error"),
                 "nonzero": (RunResult(2, b"", b"boom"), "unknown", "provider-error"),
                 "turn failed": (RunResult(1, b'{"type":"turn.failed","error":{"message":"x"}}\n', b""), "unknown", "provider-error"),
                 "no message": (RunResult(0, b'{"type":"turn.started"}\n', b""), "unknown", "provider-error"),
                 "missing binary": (FileNotFoundError("codex"), "not-sent", "provider-error"),
                 "runner crash": (RuntimeError(FAKE_KEY), "unknown", "provider-error")}
        for name, (r, outcome, code) in cases.items():
            with self.subTest(name):
                self.setUp()
                res = self.prov(r).call(VERIFY_TERRA(), KEY)
                self.assertEqual((res.outcome, res.error["code"]), (outcome, code))
                self.assertNotIn(FAKE_KEY, json.dumps(res.error))

    def test_stderr_and_garbage_lines_never_surface(self):
        res = self.prov(RunResult(0, b"garbage\n" + events(), b"secret stderr " + FAKE_KEY.encode())).call(VERIFY_TERRA(), KEY)
        self.assertEqual(res.response["status"], "ok")
        with open(os.path.join(self.dir, "led.jsonl")) as f:
            self.assertNotIn(FAKE_KEY, f.read())

    def test_unknown_usage_stays_unknown(self):
        res = self.prov(RunResult(0, events(usage={}), b"")).call(VERIFY_TERRA(), KEY)
        self.assertTrue(all(v is None for v in res.response["usage"].values()))
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertIsNone(rec["apiEquivalentEstimateUsdMicros"])

    def test_long_context_tier_estimate(self):
        from reviewer.runtime.catalog import terra_api_equivalent_micros
        self.assertEqual(terra_api_equivalent_micros(300_000, 0, 1000, 300_000), 1_200_000 + 18_000)


class Preflight(Base):
    def fake(self, help_text="--sandbox --ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check --json "
                             "--output-schema --cd --model --disable --config --color", login=0, feats=None):
        feats = feats if feats is not None else "".join(f"{f}   stable   true\n" for f in cc.DISABLED_FEATURES)

        def run(argv):
            if argv[1:] == ["--version"]:
                return RunResult(0, b"codex-cli 9.9.9\n", b"")
            if argv[1:] == ["exec", "--help"]:
                return RunResult(0, help_text.encode(), b"")
            if argv[1:] == ["features", "list"]:
                return RunResult(0, feats.encode(), b"")
            if argv[1:] == ["login", "status"]:
                return RunResult(login, b"", b"")
            raise AssertionError(argv)
        return run

    def test_supported(self):
        r = check_cli_isolation(runner=self.fake())
        self.assertTrue(r["supported"], r)

    def test_missing_flag_is_typed_unsupported(self):
        r = check_cli_isolation(runner=self.fake(help_text="--json"))
        self.assertFalse(r["supported"])
        with self.assertRaises(CodexUnsupported):
            CodexTerraProvider(enabled=True, runner=Runner(), preflight=r)

    def test_not_logged_in_is_unsupported(self):
        self.assertFalse(check_cli_isolation(runner=self.fake(login=1))["supported"])

    def test_not_runnable_is_unsupported(self):
        def run(argv):
            raise FileNotFoundError("codex")
        self.assertFalse(check_cli_isolation(runner=run)["supported"])

    def test_opt_in_required(self):
        with self.assertRaises(ValueError):
            CodexTerraProvider(enabled=False, preflight=GOOD_PREFLIGHT)


class Bounded(unittest.TestCase):
    """The real subprocess bounder, exercised with python itself (no codex, no network)."""
    py = [sys.executable, "-I", "-c"]

    def run_it(self, code, stdin=b"", timeout=10, **kw):
        return run_bounded(self.py + [code], stdin, {"PATH": os.environ["PATH"]}, tempfile.gettempdir(), timeout, **kw)

    def test_stdin_roundtrip_and_exit_code(self):
        r = self.run_it("import sys; sys.stdout.write(sys.stdin.read().upper()); sys.exit(3)", b"abc")
        self.assertEqual((r.stdout, r.returncode, r.timed_out, r.truncated), (b"ABC", 3, False, False))

    def test_deadline_kills_the_process_group(self):
        t = time.monotonic()
        r = self.run_it("import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)", timeout=1)
        self.assertTrue(r.timed_out)
        self.assertLess(time.monotonic() - t, 8)

    def test_output_cap_truncates_and_kills(self):
        r = self.run_it("import sys\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush()", max_stdout=100_000)
        self.assertTrue(r.truncated)
        self.assertLessEqual(len(r.stdout), 100_000)

    def test_environment_is_exactly_what_was_given(self):
        r = self.run_it("import os; print(sorted(os.environ))")
        self.assertNotIn(b"OPENROUTER", r.stdout)


if __name__ == "__main__":
    unittest.main()
