"""Connector `claude-sdk`: Claude review roles through the Claude Agent SDK (`pip install claude-agent-sdk`).

The SDK drives the locally installed Claude Code under the operator's own login, so calls consume the operator's
Claude subscription instead of the OpenRouter trial key. It serves provider slot `anthropic`, i.e. the same
pullo.toml models (`anthropic/claude-sonnet-5.5`, ...), mapped to Claude's own ids (`claude-sonnet-5-5`, ...).

Isolation `claude-sdk-no-tools@1` (configured per call, NOT proven offline):
  tools=[] and allowed_tools=[] (no built-in tools), setting_sources=[] (no user/project/local settings, CLAUDE.md,
  hooks or permissions), skills=[] and plugins=[] (none loaded), mcp_servers={} with strict_mcp_config (no MCP),
  permission_mode "dontAsk" (anything not pre-approved is denied), max_turns=1, no fallback model, a custom system
  prompt (not the Claude Code preset), and a fresh empty cwd. The message stream is audited: a tool-use block, a
  non-empty tool list in the init message, or a permission denial discards the output and disables the connector.
Billing: refuses to start while ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN or a Bedrock/Vertex/Foundry switch is set,
because Claude Code would then bill that account instead of the subscription. Receipts carry an API-equivalent
ESTIMATE at the pinned OpenRouter catalog rates only. Output tokens are capped through CLAUDE_CODE_MAX_OUTPUT_TOKENS.
The JSON schema travels in the system prompt (the SDK's structured-output mode works through a tool, which this
connector does not allow); the reply is parsed strictly and re-validated locally."""

from __future__ import annotations

import asyncio
import json
import os

from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS, PRICE_VERSION, token_priced_micros

from .base import ConnectorUnavailable, NotSent, SdkConnector, SdkReply

BILLING_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
               "CLAUDE_CODE_USE_FOUNDRY")
TOOL_BLOCKS = ("ToolUseBlock", "ServerToolUseBlock", "ToolResultBlock", "ServerToolResultBlock")


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```") and t.endswith("```"):
        t = t[3:-3]
        t = t[t.index("\n") + 1:] if "\n" in t else t
    return t.strip()


class ClaudeSdkConnector(SdkConnector):
    connector_id = "claude-sdk"
    name = "anthropic"
    sdk_module = "claude_agent_sdk"
    install_hint = "pip install claude-agent-sdk, and log in to Claude Code once with `claude` then /login"
    schema_flavor = "anthropic"
    isolation_version = "claude-sdk-no-tools@1"

    def __init__(self, **kw):
        super().__init__(**kw)
        env = os.environ if self._environ is None else self._environ
        billed = [k for k in BILLING_ENV if env.get(k)]
        if billed:
            raise ConnectorUnavailable(f"claude-sdk: unset {', '.join(billed)} for this run - Claude Code would "
                                       "bill that account instead of your Claude subscription")

    @classmethod
    def load_sdk(cls):
        try:
            import claude_agent_sdk
        except ImportError:
            raise cls.missing() from None
        return claude_agent_sdk

    @classmethod
    def models(cls) -> frozenset:
        return frozenset(ALLOWED_ROUTER_MODELS)

    def sdk_model(self, model: str) -> str:
        return model.split("/", 1)[1].replace(".", "-")       # anthropic/claude-sonnet-5.5 -> claude-sonnet-5-5

    def invoke(self, *, prompt, system, schema, model, max_output_tokens, timeout, cwd) -> SdkReply:
        sdk = self.sdk
        system = (system + "\n\nThe JSON object must validate against this JSON Schema:\n"
                  + json.dumps(schema, separators=(",", ":"), sort_keys=True))
        env = {"CLAUDE_CODE_MAX_OUTPUT_TOKENS": str(max_output_tokens)} if max_output_tokens else {}
        options = sdk.ClaudeAgentOptions(
            tools=[], allowed_tools=[], setting_sources=[], skills=[], plugins=[], mcp_servers={},
            strict_mcp_config=True, permission_mode="dontAsk", max_turns=1, fallback_model=None,
            system_prompt=system, model=self.sdk_model(model), cwd=cwd, env=env)
        return asyncio.run(asyncio.wait_for(self._collect(prompt, options), timeout))

    async def _collect(self, prompt, options) -> SdkReply:
        sdk, reply, texts = self.sdk, SdkReply(), []
        try:
            stream = sdk.query(prompt=prompt, options=options)
        except getattr(sdk, "CLINotFoundError", ()) as e:
            raise NotSent(f"Claude Code CLI not found ({type(e).__name__})") from None
        try:
            async for msg in stream:
                kind = type(msg).__name__
                if kind == "SystemMessage" and getattr(msg, "subtype", None) == "init":
                    data = getattr(msg, "data", None) or {}
                    if data.get("tools"):
                        reply.violations.append("tools-offered")
                    reply.request_id = data.get("session_id") or reply.request_id
                elif kind == "AssistantMessage":
                    reply.resolved_model = getattr(msg, "model", None) or reply.resolved_model
                    for block in getattr(msg, "content", None) or []:
                        b = type(block).__name__
                        if b in TOOL_BLOCKS:
                            reply.violations.append(b)
                        elif b == "TextBlock":
                            texts.append(block.text)
                    if getattr(msg, "error", None):
                        reply.error = str(msg.error)
                elif kind == "ResultMessage":
                    reply.request_id = getattr(msg, "session_id", None) or reply.request_id
                    if getattr(msg, "permission_denials", None):
                        reply.violations.append("permission-denial")
                    if getattr(msg, "is_error", False):
                        reply.error = reply.error or str(getattr(msg, "subtype", "error"))
                    if isinstance(getattr(msg, "result", None), str):
                        texts = [msg.result]
                    u = getattr(msg, "usage", None) or {}
                    tok = lambda k: u.get(k) if type(u.get(k)) is int else None  # noqa: E731
                    base, read, write = tok("input_tokens"), tok("cache_read_input_tokens"), \
                        tok("cache_creation_input_tokens")
                    reply.cached_input_tokens = read if read is not None else (0 if base is not None else None)
                    reply.cache_write_tokens = write if write is not None else (0 if base is not None else None)
                    if None not in (base, reply.cached_input_tokens, reply.cache_write_tokens):
                        reply.input_tokens = base + reply.cached_input_tokens + reply.cache_write_tokens
                    reply.output_tokens = tok("output_tokens")
                elif kind not in ("UserMessage", "StreamEvent", "RateLimitEvent", "SystemMessage"):
                    reply.violations.append(kind)
        except getattr(sdk, "CLINotFoundError", ()) as e:
            raise NotSent(f"Claude Code CLI not found ({type(e).__name__})") from None
        reply.text = _strip_fence("".join(texts)) if texts else None
        return reply

    def estimate(self, model, r):
        u = self._usage(r)
        if None in (u["uncachedInputTokens"], u["cachedInputTokens"], u["outputTokens"]):
            return None, PRICE_VERSION
        return token_priced_micros(model, u["uncachedInputTokens"], u["cachedInputTokens"],
                                   u["cacheWriteInputTokens"] or 0, u["outputTokens"], r.input_tokens), PRICE_VERSION
