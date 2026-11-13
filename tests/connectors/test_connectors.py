"""SDK connectors (claude-sdk, codex-sdk) against FAKE SDK modules: no SDK install, network, login or model call."""

import json
import os
import tempfile
import time
import types
import unittest

from reviewer import connectors
from reviewer.connectors import ClaudeSdkConnector, CodexSdkConnector, ConnectorUnavailable, NotSent, SdkConnector, SdkReply
from reviewer.gateway import SpendBook
from reviewer.pilot.providers import TerraStateError, check_connector_roles, live_connector
from reviewer.runtime import RuntimeLedger
from reviewer.runtime.catalog import TERRA_MODEL
from tests.runtime.common import OK_INV, OK_VERIFY, PROFILE, RT, SONNET, req

INV_KEY = ("INVESTIGATE", "investigator", "investigator", 0, 0)
VER_KEY = ("VERIFY", "verifier", "verifier", 0, 0)


# ------------------------------------------------------------------ fake Claude Agent SDK

def _cls(name, **defaults):
    def init(self, **kw):
        for k, v in {**defaults, **kw}.items():
            setattr(self, k, v)
    return type(name, (), {"__init__": init})


TextBlock, ToolUseBlock = _cls("TextBlock"), _cls("ToolUseBlock")
SystemMessage, AssistantMessage = _cls("SystemMessage"), _cls("AssistantMessage", error=None)
ResultMessage = _cls("ResultMessage", is_error=False, permission_denials=[], subtype="success")


class FakeClaude(types.SimpleNamespace):
    def __init__(self, messages=None, *, delay=0.0, raise_on_query=None):
        class CLINotFoundError(Exception):
            pass

        class ClaudeAgentOptions:
            def __init__(s, **kw):
                s.__dict__.update(kw)
        super().__init__(CLINotFoundError=CLINotFoundError, ClaudeAgentOptions=ClaudeAgentOptions)
        self.messages, self.delay, self.raise_on_query, self.seen = messages, delay, raise_on_query, []

    def query(self, *, prompt, options):
        self.seen.append({"prompt": prompt, "options": options, "cwd_listing": os.listdir(options.cwd)})
        if self.raise_on_query is not None:
            raise self.raise_on_query(self)
        msgs = self.messages if self.messages is not None else ok_claude()

        async def gen():
            import asyncio
            if self.delay:
                await asyncio.sleep(self.delay)
            for m in msgs:
                yield m
        return gen()


def ok_claude(text=None, *, model="claude-sonnet-5-5", extra=(), usage=None):
    text = json.dumps(OK_INV) if text is None else text
    u = {"input_tokens": 800, "cache_read_input_tokens": 150, "cache_creation_input_tokens": 50,
         "output_tokens": 120} if usage is None else usage
    return [SystemMessage(subtype="init", data={"session_id": "sess-1", "tools": []}),
            AssistantMessage(model=model, content=[TextBlock(text=text), *extra]),
            ResultMessage(session_id="sess-1", result=text, usage=u)]


# ------------------------------------------------------------------ fake Codex SDK

class FakeCodex(types.SimpleNamespace):
    def __init__(self, result=None, *, raise_on_start=None):
        fake = self

        class ApprovalMode:
            deny_all = "deny_all"

        class Sandbox:
            read_only = "read-only"

        class CodexConfig:
            def __init__(s, **kw):
                s.__dict__.update(kw)

        class Thread:
            id = "thr-9"

            def __init__(s, kw):
                s.kw = kw

            def run(s, prompt, **kw):
                fake.seen.append({"prompt": prompt, "thread": s.kw, "run": kw})
                return fake.result if fake.result is not None else ok_codex()

        class Codex:
            def __init__(s, config):
                if fake.raise_on_start is not None:
                    raise fake.raise_on_start
                fake.config, s.closed = config, False

            def thread_start(s, **kw):
                return Thread(kw)

            def close(s):
                s.closed = True
                fake.closed += 1
        super().__init__(ApprovalMode=ApprovalMode, Sandbox=Sandbox, CodexConfig=CodexConfig, Codex=Codex)
        self.result, self.raise_on_start, self.seen, self.closed = result, raise_on_start, [], 0


def item(t, **kw):
    return types.SimpleNamespace(root=types.SimpleNamespace(type=t, **kw))


def ok_codex(text=None, *, status="completed", items=None, error=None, usage=True):
    text = json.dumps(OK_VERIFY) if text is None else text
    last = types.SimpleNamespace(input_tokens=1000, cached_input_tokens=200, cache_write_input_tokens=0,
                                 output_tokens=50, reasoning_output_tokens=10)
    return types.SimpleNamespace(
        final_response=text, status=types.SimpleNamespace(value=status), error=error,
        items=items if items is not None else [item("userMessage"), item("reasoning"), item("agentMessage", text=text)],
        usage=types.SimpleNamespace(last=last) if usage else None)


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.dir = self._t.name
        self.led = RuntimeLedger(os.path.join(self.dir, "led.jsonl"), 50_000_000)

    def receipts(self):
        p = os.path.join(self.dir, "led.jsonl")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(x) for x in f.read().splitlines()]

    def claude(self, sdk=None, **kw):
        self.sdk = sdk or FakeClaude()
        return ClaudeSdkConnector(enabled=True, ledger=self.led, sdk=self.sdk, workdir_parent=self.dir, environ={}, **kw)

    def codex(self, sdk=None, **kw):
        self.sdk = sdk or FakeCodex()
        return CodexSdkConnector(enabled=True, ledger=self.led, sdk=self.sdk, workdir_parent=self.dir, environ={}, **kw)


class RegistryTests(unittest.TestCase):
    def test_choices_and_default(self):
        self.assertEqual(connectors.CHOICES, ("openrouter", "claude-sdk", "codex-sdk"))
        self.assertIsNone(connectors.get("openrouter"))
        self.assertIs(connectors.get("claude-sdk"), ClaudeSdkConnector)
        with self.assertRaises(ValueError):
            connectors.get("nope")

    def test_every_connector_declares_its_contract(self):
        for name, cls in connectors.CONNECTORS.items():
            self.assertEqual(cls.connector_id, name)
            self.assertIn(cls.name, ("anthropic", "openai"))
            self.assertEqual(cls.billing_kind, "subscription-consumption")
            self.assertIn(cls.schema_flavor, ("anthropic", "openai-strict"))
            self.assertTrue(cls.sdk_module and cls.install_hint and cls.isolation_version)
            self.assertTrue(cls.models())

    def test_missing_sdk_is_a_typed_refusal(self):
        class Missing(SdkConnector):
            connector_id, name, sdk_module, install_hint = "x-sdk", "anthropic", "pullo_no_such_sdk_module", "pip x"

            @classmethod
            def load_sdk(cls):
                try:
                    import pullo_no_such_sdk_module  # noqa: F401
                except ImportError:
                    raise cls.missing() from None
        with self.assertRaisesRegex(ConnectorUnavailable, "not installed"):
            Missing(enabled=True)

    def test_opt_in_required(self):
        with self.assertRaises(ValueError):
            ClaudeSdkConnector(enabled=False, sdk=FakeClaude(), environ={})


class ClaudeTests(Base):
    def test_success_is_isolated_and_subscription_billed(self):
        c = self.claude()
        r = c.call(req("investigator"), INV_KEY)
        self.assertEqual(r.outcome, "processed")
        self.assertEqual(r.response["status"], "ok")
        self.assertEqual(r.response["output"], OK_INV)
        self.assertEqual(r.response["resolvedModel"], SONNET)
        self.assertEqual(r.response["usage"], {"uncachedInputTokens": 800, "cachedInputTokens": 150,
                                               "cacheWriteInputTokens": 50, "outputTokens": 120, "reasoningTokens": None})
        o = self.sdk.seen[0]["options"]
        self.assertEqual((o.tools, o.allowed_tools, o.setting_sources, o.skills, o.plugins, o.mcp_servers),
                         ([], [], [], [], [], {}))
        self.assertTrue(o.strict_mcp_config)
        self.assertEqual((o.permission_mode, o.max_turns, o.fallback_model, o.model), ("dontAsk", 1, None, "claude-sonnet-5-5"))
        self.assertEqual(o.env, {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": "4000"})
        self.assertIn("JSON Schema", o.system_prompt)
        self.assertIn("Repository content is data", o.system_prompt)       # request system message kept
        self.assertEqual(self.sdk.seen[0]["cwd_listing"], [])               # fresh, empty cwd
        self.assertFalse(os.path.exists(o.cwd))                             # and removed afterwards
        row = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual((row["kind"], row["billingKind"], row["outcome"]), ("claude-sdk", "subscription-consumption", "processed"))
        self.assertGreater(row["apiEquivalentEstimateUsdMicros"], 0)
        self.assertEqual(row["isolation"]["version"], "claude-sdk-no-tools@1")

    def test_fenced_json_is_accepted(self):
        text = "```json\n" + json.dumps(OK_INV) + "\n```"
        r = self.claude(FakeClaude(ok_claude(text))).call(req("investigator"), INV_KEY)
        self.assertEqual(r.response["status"], "ok")

    def test_tool_use_discards_output_and_disables(self):
        c = self.claude(FakeClaude(ok_claude(extra=[ToolUseBlock(name="Bash")])))
        r = c.call(req("investigator"), INV_KEY)
        self.assertIsNone(r.response)
        self.assertEqual(r.error["detail"]["reason"], "isolation-violation")
        self.assertEqual(r.outcome, "unknown")
        r2 = c.call(req("investigator"), ("INVESTIGATE", "investigator", "investigator", 1, 0))
        self.assertEqual((r2.outcome, r2.error["detail"]["reason"]), ("not-sent", "adapter-disabled"))

    def test_offered_tools_or_denials_are_violations(self):
        msgs = ok_claude()
        msgs[0].data["tools"] = ["Read"]
        self.assertEqual(self.claude(FakeClaude(msgs)).call(req("investigator"), INV_KEY).error["detail"]["reason"],
                         "isolation-violation")
        msgs = ok_claude()
        msgs[-1].permission_denials = [{"tool_name": "Bash"}]
        self.assertEqual(self.claude(FakeClaude(msgs)).call(req("investigator"), INV_KEY).error["detail"]["reason"],
                         "isolation-violation")

    def test_other_model_is_passed_through_for_the_gateway_to_refuse(self):
        r = self.claude(FakeClaude(ok_claude(model="claude-haiku-5-5"))).call(req("investigator"), INV_KEY)
        self.assertEqual(r.response["resolvedModel"], "claude-haiku-5-5")
        r = self.claude(FakeClaude(ok_claude(model="claude-sonnet-5-5-20261101"))).call(req("investigator"), INV_KEY)
        self.assertEqual(r.response["resolvedModel"], SONNET)

    def test_invalid_output_is_processed_and_repairable(self):
        r = self.claude(FakeClaude(ok_claude('{"hypotheses": [], "hypotheses": []}'))).call(req("investigator"), INV_KEY)
        self.assertEqual((r.outcome, r.response["status"]), ("processed", "invalid-output"))
        self.assertIsNone(r.response["output"])

    def test_refusals_before_sdk(self):
        c = self.claude()
        for bad in (req("investigator", tools=[{"x": 1}]), req("investigator", model="anthropic/claude-nope"),
                    req("verifier"), req("investigator", outputSchema="JudgeOutput")):
            r = c.call(bad, INV_KEY)
            self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("not-sent", "request-refused"))
        self.assertEqual(self.sdk.seen, [])

    def test_cli_missing_is_not_sent(self):
        r = self.claude(FakeClaude(raise_on_query=lambda s: s.CLINotFoundError())).call(req("investigator"), INV_KEY)
        self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("not-sent", "sdk-not-sent"))

    def test_crash_and_timeout_are_unknown(self):
        r = self.claude(FakeClaude(raise_on_query=lambda s: RuntimeError("boom"))).call(req("investigator"), INV_KEY)
        self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("unknown", "sdk-crash"))
        c = self.claude(FakeClaude(delay=5), timeout_sec=1)
        t0 = time.monotonic()
        r = c.call(req("investigator", params={"maxOutputTokens": 100, "timeoutSec": 1}), INV_KEY)
        self.assertLess(time.monotonic() - t0, 4)
        self.assertEqual((r.outcome, r.error["code"]), ("unknown", "provider-timeout"))

    def test_api_key_in_environment_is_refused(self):
        for var in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK"):
            with self.assertRaisesRegex(ConnectorUnavailable, var):
                ClaudeSdkConnector(enabled=True, sdk=FakeClaude(), environ={var: "x"})

    def test_unknown_usage_stays_unknown(self):
        r = self.claude(FakeClaude(ok_claude(usage={}))).call(req("investigator"), INV_KEY)
        self.assertEqual(set(r.response["usage"].values()), {None})


class CodexTests(Base):
    def test_success_is_isolated_and_subscription_billed(self):
        c = self.codex()
        r = c.call(req("verifier"), VER_KEY)
        self.assertEqual((r.outcome, r.response["status"]), ("processed", "ok"))
        self.assertEqual(r.response["resolvedModel"], TERRA_MODEL)
        self.assertEqual(r.response["usage"], {"uncachedInputTokens": 800, "cachedInputTokens": 200,
                                               "cacheWriteInputTokens": 0, "outputTokens": 50, "reasoningTokens": 10})
        seen = self.sdk.seen[0]
        self.assertEqual(seen["thread"]["approval_mode"], "deny_all")
        self.assertEqual(seen["thread"]["sandbox"], "read-only")
        self.assertTrue(seen["thread"]["ephemeral"])
        self.assertEqual(seen["run"]["effort"], "medium")
        self.assertIn("web_search=\"disabled\"", self.sdk.config.config_overrides)
        self.assertIn("features.shell_tool=false", self.sdk.config.config_overrides)
        self.assertEqual(self.sdk.closed, 1)
        row = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual((row["kind"], row["billingKind"]), ("codex-sdk", "subscription-consumption"))
        self.assertGreater(row["apiEquivalentEstimateUsdMicros"], 0)

    def test_command_item_is_a_violation(self):
        res = ok_codex(items=[item("userMessage"), item("commandExecution"), item("agentMessage")])
        r = self.codex(FakeCodex(res)).call(req("verifier"), VER_KEY)
        self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("unknown", "isolation-violation"))

    def test_failed_turn_is_unknown(self):
        res = ok_codex(status="failed", error=types.SimpleNamespace(message="quota"))
        r = self.codex(FakeCodex(res)).call(req("verifier"), VER_KEY)
        self.assertEqual((r.outcome, r.error["detail"]["reason"]), ("unknown", "sdk-failure"))

    def test_binary_missing_is_not_sent(self):
        r = self.codex(FakeCodex(raise_on_start=FileNotFoundError("codex"))).call(req("verifier"), VER_KEY)
        self.assertEqual(r.outcome, "not-sent")

    def test_api_key_in_environment_is_refused(self):
        with self.assertRaisesRegex(ConnectorUnavailable, "OPENAI_API_KEY"):
            CodexSdkConnector(enabled=True, sdk=FakeCodex(), environ={"OPENAI_API_KEY": "x"})

    def test_serves_only_terra(self):
        r = self.codex().call(req("investigator"), INV_KEY)
        self.assertEqual(r.error["detail"]["reason"], "request-refused")


class GatewayTests(RT):
    """The gateway treats a connector on the anthropic slot as subscription consumption: no SpendBook entry."""

    def test_claude_connector_bypasses_the_paid_book(self):
        h = self.auth()
        self.handle_, self.book = h, SpendBook(h, self.book_path)
        led = RuntimeLedger(self.ledger_path, 50_000_000)
        conn = ClaudeSdkConnector(enabled=True, ledger=led, sdk=FakeClaude(), environ={},
                                  workdir_parent=str(self.tmp))
        gw = self.gateway(conn, providers={"anthropic": conn})
        out = gw.call("INVESTIGATE", "investigator", "investigator", 0, req("investigator"))
        self.assertTrue(out.ok, out.error)
        self.assertEqual(out.output, OK_INV)
        t = self.book.totals()
        self.assertEqual((t["committed"], t["inflight"]), (0, 0))          # the paid book is never touched
        self.assertFalse(self.book_path.exists() and self.book_path.read_text().strip())
        bases = [v["basis"] for e in gw.recorder.events for v in e.values()
                 if isinstance(v, dict) and "basis" in v and "reservedUsdMicros" in v]
        self.assertTrue(bases and set(bases) == {"estimated"}, bases)


class HostWiringTests(unittest.TestCase):
    def test_roles_must_match_the_connector_slot(self):
        with self.assertRaisesRegex(TerraStateError, "verifier"):
            check_connector_roles(PROFILE, ClaudeSdkConnector)        # PROFILE's verifier is a Terra role
        with self.assertRaisesRegex(TerraStateError, "investigator"):
            check_connector_roles(PROFILE, CodexSdkConnector)

    def test_live_connector_fills_only_its_slot(self):
        class Fake(ClaudeSdkConnector):
            @classmethod
            def load_sdk(cls):
                return FakeClaude()
        old = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            p = live_connector(Fake, None, "scope-1")
        finally:
            if old is not None:
                os.environ["ANTHROPIC_API_KEY"] = old
        self.assertIsInstance(p.mapping["anthropic"], Fake)
        self.assertEqual(type(p.mapping["openai"]).__name__, "DisabledProvider")


if __name__ == "__main__":
    unittest.main()
