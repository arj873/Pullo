"""Independent S0B-01a review: Codex Terra adapter. No model call, no auth read: fake runners, `codex --version/features`
metadata, one `codex sandbox -P :read-only` run of `cat` on a sentinel file this test creates (no model, no credentials).
`expectedFailure` = CONFIRMED defect or unproven safety property (assertion states the safe behaviour)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from reviewer.runtime import codex_cli as C
from reviewer.runtime.catalog import TERRA_MODEL
from reviewer.runtime.receipts import RuntimeLedger
from tests.runtime.common import RT, req

KEY = ("VERIFY", "verifier", "v", 0, 1)
GOOD = {"verdict": "uncertain", "reachable": False, "impact": "none", "evidence": [], "notes": "n"}


def ev(*events):
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


def stream(*extra, text=None, usage=True):
    msg = {"type": "item.completed", "item": {"id": "i", "type": "agent_message", "text": json.dumps(GOOD) if text is None else text}}
    evs = [{"type": "thread.started", "thread_id": "t-1"}, *extra, msg]
    if usage:
        evs.append({"type": "turn.completed", "usage": {"input_tokens": 100, "cached_input_tokens": 10, "output_tokens": 20,
                                                          "reasoning_output_tokens": 5}})
    return ev(*evs)


class Fake:
    def __init__(self, out, rc=0, **kw):
        self.out, self.rc, self.kw, self.argvs = out, rc, kw, []

    def __call__(self, argv, stdin, env, cwd, timeout):
        self.argvs.append((argv, env, cwd))
        return C.RunResult(self.rc, self.out, b"", **self.kw)


OK_PREFLIGHT = {"supported": True, "problems": []}


class CodexReview(RT):
    def prov(self, runner, **kw):
        led = RuntimeLedger(self.ledger_path, 50_000_000)
        self.led = led
        return C.CodexTerraProvider(enabled=True, ledger=led, runner=runner, preflight=OK_PREFLIGHT, **kw)

    def r(self):
        return req("verifier", model=TERRA_MODEL, provider="openai")

    # ---- argv / env -----------------------------------------------------------------------------------------------
    def test_argv_has_no_bypass_flags_and_prompt_is_stdin(self):
        a = C.build_argv("codex", "/s.json", "/w")
        self.assertEqual(a[-1], "-")
        self.assertFalse(C.FORBIDDEN_FLAGS & set(a))
        self.assertEqual(a[a.index("--sandbox") + 1], "read-only")
        self.assertIn("--ignore-user-config", a)
        self.assertNotIn("--full-auto", a)

    def test_env_whitelist_has_no_secrets_but_exposes_home_and_codex_home(self):
        env = C.clean_env({"PATH": "/bin", "HOME": "/h", "CODEX_HOME": "/h/.codex", "OPENROUTER_KEY": "x", "openrouter_key": "x",
                           "OPENAI_API_KEY": "y", "HTTPS_PROXY": "p", "SSL_CERT_FILE": "/c", "LD_PRELOAD": "z"})
        self.assertEqual(set(env), {"PATH", "HOME", "CODEX_HOME"})

    def test_wrong_model_provider_tools_refused(self):
        p = self.prov(Fake(stream()))
        for over in ({"model": "gpt-6.1-sol"}, {"model": "gpt-5.6-terra "}, {"provider": "anthropic"}, {"tools": [{"x": 1}]}):
            with self.subTest(over=over):
                self.assertEqual(p.call({**self.r(), **over}, KEY + (str(over),)).outcome, "not-sent")

    # ---- event audit ------------------------------------------------------------------------------------------------
    def test_known_tool_item_types_are_violations(self):
        for t in ("command_execution", "mcp_tool_call", "web_search", "file_change", "collab_tool_call", "todo_list", "error", "custom_tool_call", None):
            with self.subTest(t=t):
                p = self.prov(Fake(stream({"type": "item.started", "item": {"id": "x", "type": t}})))
                res = p.call(self.r(), KEY + (str(t),))
                self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("unknown", "isolation-violation"))

    def test_violation_on_started_only_still_rejects_even_with_valid_final_message(self):
        p = self.prov(Fake(stream({"type": "item.started", "item": {"type": "command_execution", "command": "cat ~/.codex/auth.json"}})))
        self.assertEqual(p.call(self.r(), KEY).error["detail"]["reason"], "isolation-violation")

    def test_command_text_is_not_persisted_in_receipts(self):
        p = self.prov(Fake(stream({"type": "item.started", "item": {"type": "command_execution", "command": "cat ~/.codex/auth.json SECRET"}})))
        p.call(self.r(), KEY)
        self.assertNotIn("SECRET", self.ledger_path.read_text())

    def test_F6_unrecognised_event_types_must_fail_closed(self):
        """CONFIRMED fail-open: only item.started/completed/updated are inspected. Any tool activity reported under another
        event type (the JSONL schema was never observed - handoff limit 3) is ignored and the call returns status ok."""
        for e in ({"type": "exec_command_begin", "command": ["cat", "/etc/passwd"]}, {"type": "mcp_tool_call.started", "tool": "x"},
                  {"type": "tool.started", "name": "exec"}, {"type": "response_item", "payload": {"type": "function_call"}},
                  {"type": "item.completed", "details": {"type": "command_execution"}}):
            with self.subTest(e=e):
                self.setUp()
                p = self.prov(Fake(stream(e)))
                res = p.call(self.r(), KEY)
                self.assertIsNone(res.response, f"ok result despite unrecognised event {e['type']}")

    test_F6_unrecognised_event_types_must_fail_closed = unittest.expectedFailure(test_F6_unrecognised_event_types_must_fail_closed)

    def test_nonjson_lines_do_not_fail_the_audit(self):
        """Observation: unparsable stdout lines are counted but ignored; a tool event printed in a non-JSON form is invisible."""
        out = b"exec: cat /etc/passwd\n" + stream()
        res = self.prov(Fake(out)).call(self.r(), KEY)
        self.assertEqual(res.response["status"], "ok")

    def test_turn_failed_and_error_events(self):
        for e in ({"type": "turn.failed", "error": {"message": "x"}}, {"type": "error", "message": "m"}):
            self.setUp()
            res = self.prov(Fake(stream(e))).call(self.r(), KEY)
            self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("unknown", "cli-failure"))

    def test_nonzero_exit_without_message_and_timeout_and_overflow(self):
        for runner, reason in ((Fake(b"", rc=1), "no-final-message"), (Fake(b"", rc=None, timed_out=True), "timeout"),
                               (Fake(b"x", truncated=True), "oversize-output")):
            self.setUp()
            res = self.prov(runner).call(self.r(), KEY)
            self.assertEqual(res.error["detail"]["reason"], reason)

    def test_usage_missing_or_malformed_is_null_not_zero(self):
        for usage in (False,):
            res = self.prov(Fake(stream(usage=usage))).call(self.r(), KEY)
            u = res.response["usage"]
            self.assertIsNone(u["outputTokens"])
            self.assertIsNone(u["uncachedInputTokens"])
        self.setUp()
        bad = ev({"type": "thread.started", "thread_id": "t"}, {"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(GOOD)}},
                 {"type": "turn.completed", "usage": {"input_tokens": -5, "output_tokens": "x", "cached_input_tokens": 99}})
        u = self.prov(Fake(bad)).call(self.r(), KEY).response["usage"]
        self.assertTrue(all(v is None for k, v in u.items() if k != "cacheWriteInputTokens"))

    def test_receipts_never_claim_dollars(self):
        self.prov(Fake(stream())).call(self.r(), KEY)
        row = [r for r in map(json.loads, self.ledger_path.read_text().splitlines()) if r["type"] == "result"][0]
        self.assertEqual((row["billingKind"], row["costBasis"], row["resolvedModelSource"]),
                         ("subscription-consumption", "unknown", "requested-not-reported-by-cli"))
        self.assertNotIn("routerCostUsdMicros", row)
        self.assertEqual(self.led.totals()["committedUsdMicros"], 0)       # subscription tokens are not in the $50 ledger

    def test_F3c_same_call_tuple_in_a_second_run_is_refused_for_codex_too(self):
        p = self.prov(Fake(stream()))
        self.assertIsNotNone(p.call(self.r(), KEY).response)
        res = p.call(self.r(), KEY)
        self.assertEqual((res.outcome, res.error["detail"]["reason"]), ("not-sent", "duplicate-call-key"))

    def test_temp_dir_removed_and_cwd_empty_at_call_time(self):
        seen = {}
        def runner(argv, stdin, env, cwd, timeout):
            seen["listing"] = os.listdir(cwd); seen["cwd"] = cwd
            return C.RunResult(0, stream())
        before = set(Path(tempfile.gettempdir()).glob("rvw-codex-*"))
        self.prov(runner).call(self.r(), KEY)
        self.assertEqual(seen["listing"], [])
        self.assertFalse(Path(seen["cwd"]).exists())
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("rvw-codex-*")), before)

    def test_untrusted_preflight_dict_is_accepted_without_verification(self):
        """Observation: `preflight=` is caller-supplied truth; passing {'supported': True} skips every CLI check."""
        C.CodexTerraProvider(enabled=True, ledger=None, runner=Fake(b""), preflight={"supported": True})


class IsolationBoundary(unittest.TestCase):
    """Facts about the INSTALLED CLI (metadata only). Environment dependent; skipped if codex is absent."""

    @classmethod
    def setUpClass(cls):
        cls.codex = shutil.which("codex")
        if not cls.codex:
            raise unittest.SkipTest("codex not installed")
        cls.features = {}
        for line in subprocess.run([cls.codex, "features", "list"], capture_output=True, text=True, timeout=30).stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                cls.features[parts[0]] = parts[-1]

    def test_adapter_disables_only_features_that_exist(self):
        self.assertEqual([f for f in C.DISABLED_FEATURES if f not in self.features], [])

    def test_F1_tool_exposure_features_still_enabled_after_the_adapters_disable_list(self):
        """Documents the gap: features that are default-on, tool/exec/plugin related, and NOT in the adapter's --disable list.
        Nothing here proves any of them adds a tool; it proves the disable list is not a closed set and the effective tool list
        is unobservable offline."""
        suspects = [f for f in self.features if self.features[f] == "true" and f not in C.DISABLED_FEATURES and
                    any(w in f for w in ("code_mode", "tool", "exec", "browser", "plugin", "mcp", "shell", "sleep", "stdin", "skill"))]
        self.assertEqual(suspects, [], "default-on, tool-related, not disabled: " + ", ".join(sorted(suspects)))

    test_F1_tool_exposure_features_still_enabled_after_the_adapters_disable_list = unittest.expectedFailure(
        test_F1_tool_exposure_features_still_enabled_after_the_adapters_disable_list)

    def test_F1b_terra_model_metadata_declares_code_mode_only_tooling(self):
        """models_cache.json (CLI metadata, no credentials) lists tool_mode for gpt-5.6-terra. The adapter's --disable list
        names no code_mode feature, so the model's declared tool surface is not shown to be removed."""
        mc = Path.home() / ".codex" / "models_cache.json"
        if not mc.exists():
            self.skipTest("no models cache")
        doc = json.loads(mc.read_text())
        m = next((m for m in doc.get("models", []) if m.get("slug") == TERRA_MODEL), None)
        if m is None:
            self.skipTest("terra not in cache")
        mode = m.get("tool_mode")
        self.assertIn(mode, (None, "code_mode_only", "standard"), mode)
        if mode == "code_mode_only":
            self.assertFalse([f for f in C.DISABLED_FEATURES if f.startswith("code_mode")],
                             "adapter does not disable any code_mode feature (documenting)")
        self.assertEqual(m.get("shell_type"), "unified_exec")

    def test_F1c_readonly_sandbox_still_reads_host_files_outside_cwd(self):
        """The read-only policy protects WRITES. With `codex sandbox -P :read-only` (no model, no credentials) a command in an
        empty cwd reads a file elsewhere on the host. A tool-using Terra turn can therefore read anything the user can read,
        including $CODEX_HOME/auth.json, because the adapter passes HOME/CODEX_HOME through."""
        with tempfile.TemporaryDirectory(prefix="rvw-iso-") as d:
            (Path(d) / "cwd").mkdir()
            sentinel = Path(d) / "outside.txt"
            sentinel.write_text("HOSTFILE-SENTINEL")
            r = subprocess.run([self.codex, "sandbox", "-P", ":read-only", "-C", str(Path(d) / "cwd"), "--", "cat", str(sentinel)],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "HOSTFILE-SENTINEL"))
            w = subprocess.run([self.codex, "sandbox", "-P", ":read-only", "-C", str(Path(d) / "cwd"), "--", "sh", "-c", f"echo x > {d}/w"],
                               capture_output=True, text=True, timeout=60)
            self.assertNotEqual(w.returncode, 0)         # writes ARE blocked
            self.assertFalse((Path(d) / "w").exists())

    def test_F1d_a_namespace_wrapper_can_hide_host_files_but_not_the_cli_credential(self):
        """Preventive isolation exists only at the OS layer (bubblewrap). It hides the home tree, but the CLI needs its own
        credential inside the namespace, so a tool running as the same process would still reach THAT file."""
        bw = shutil.which("bwrap")
        if not bw:
            self.skipTest("bwrap missing")
        with tempfile.TemporaryDirectory(prefix="rvw-iso-") as d:
            home = Path(d) / "home"; (home / ".codex").mkdir(parents=True)
            decoy = home / ".codex" / "auth.json"; decoy.write_text("DECOY")
            base = [bw, "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
                    "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
            hidden = subprocess.run(base + ["--tmpfs", str(Path(d).parent), "cat", str(decoy)], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(hidden.returncode, 0)
            exposed = subprocess.run(base + ["--ro-bind", str(home / ".codex"), "/codexhome", "cat", "/codexhome/auth.json"],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(exposed.stdout, "DECOY")          # the credential must be mounted for the CLI -> reachable by its tools


class RunBounded(unittest.TestCase):
    def _run_isolated(self, code, deadline):
        t0 = time.monotonic()
        p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=deadline + 30, cwd=str(Path(__file__).resolve().parents[2]))
        return p, time.monotonic() - t0

    def test_deadline_kills_group_and_returns(self):
        code = ("from reviewer.runtime.codex_cli import run_bounded\nimport sys\n"
                "r=run_bounded([sys.executable,'-c','import time;time.sleep(60)'],b'',{},'/tmp',1)\nprint(r.timed_out)")
        p, dt = self._run_isolated(code, 5)
        self.assertEqual(p.stdout.strip(), "True")
        self.assertLess(dt, 10)

    def test_output_cap_kills(self):
        code = ("from reviewer.runtime.codex_cli import run_bounded\nimport sys\n"
                "r=run_bounded([sys.executable,'-c','import sys\\nwhile True: sys.stdout.write(\"x\"*100000)'],b'',{},'/tmp',20,max_stdout=1000)\n"
                "print(r.truncated,len(r.stdout))")
        p, dt = self._run_isolated(code, 20)
        self.assertEqual(p.stdout.split(), ["True", "1000"])
        self.assertLess(dt, 15)

    @unittest.expectedFailure
    def test_F8_detached_grandchild_holding_the_pipes_must_not_hang_run_bounded(self):
        """A descendant that leaves the process group (setsid) and keeps stdout open survives killpg. run_bounded then joins its
        pump threads for 5 s each and calls stdout.close() while a pump thread is blocked in read(): close() waits on the buffer
        lock held by that read, so the call can hang until the grandchild exits."""
        code = ("from reviewer.runtime.codex_cli import run_bounded\nimport sys\n"
                "child=\"import os,time,subprocess,sys\\nsubprocess.Popen([sys.executable,'-c','import time;time.sleep(45)'],start_new_session=True)\\ntime.sleep(60)\"\n"
                "r=run_bounded([sys.executable,'-c',child],b'',{},'/tmp',1)\nprint('returned',r.timed_out)")
        p, dt = self._run_isolated(code, 40)
        self.assertEqual(p.stdout.strip(), "returned True")
        self.assertLess(dt, 12, f"run_bounded took {dt:.1f}s with a 1 s deadline")


if __name__ == "__main__":
    unittest.main()
