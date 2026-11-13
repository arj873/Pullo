"""Connector `codex-sdk`: GPT Terra review roles through the official Codex Python SDK (`pip install openai-codex`).

The SDK drives `codex app-server` under the operator's ChatGPT login (subscription consumption). It serves provider
slot `openai`: the pullo.toml Terra models (`gpt-5.6-terra`, `gpt-6.1-terra`), whose SDK ids are the same.
This is an alternative to the hardened `codex exec` adapter (reviewer/runtime/codex_cli.py, codex-isolated-home@2),
which stays the default for Terra roles; choose this connector explicitly with `--connector codex-sdk`.

Isolation `codex-sdk-no-tools@1` (configured per call, NOT proven offline - weaker than codex-isolated-home@2):
  an ephemeral thread with approval mode deny_all, sandbox read-only, a fresh empty cwd, Pullo's base instructions,
  and the same `--config` isolation overrides and disabled features as the CLI adapter (no web search, MCP, apps,
  skills, plugins, hooks, shell or multi-agent). The turn's items are audited: anything other than the echoed user
  message, reasoning or agent messages discards the output and disables the connector for the run.
Billing: refuses to start while OPENAI_API_KEY / CODEX_API_KEY is set (so the SDK cannot fall back to API billing).
Receipts carry an API-equivalent ESTIMATE at the pinned Terra list rates only. The SDK cannot cap output tokens."""

from __future__ import annotations

import os
import threading

from reviewer.runtime.catalog import (TERRA_MODELS, TERRA_REASONING_EFFORT, terra_api_equivalent_micros,
                                      terra_price_version)
from reviewer.runtime.codex_cli import DISABLED_FEATURES, ISOLATION_OVERRIDES

from .base import ConnectorUnavailable, NotSent, SdkConnector, SdkReply

BILLING_ENV = ("OPENAI_API_KEY", "CODEX_API_KEY")
ALLOWED_ITEMS = frozenset({"userMessage", "agentMessage", "reasoning"})


def config_overrides() -> tuple[str, ...]:
    return tuple(f"{k}={v}" for k, v in ISOLATION_OVERRIDES) + tuple(f"features.{f}=false" for f in DISABLED_FEATURES)


class CodexSdkConnector(SdkConnector):
    connector_id = "codex-sdk"
    name = "openai"
    sdk_module = "openai_codex"
    install_hint = "pip install openai-codex, and log in once with `codex login` (ChatGPT)"
    schema_flavor = "openai-strict"
    isolation_version = "codex-sdk-no-tools@1"

    def __init__(self, **kw):
        super().__init__(**kw)
        env = os.environ if self._environ is None else self._environ
        billed = [k for k in BILLING_ENV if env.get(k)]
        if billed:
            raise ConnectorUnavailable(f"codex-sdk: unset {', '.join(billed)} for this run - the SDK could bill that "
                                       "API key instead of your ChatGPT subscription")
        self._active = None
        self._active_lock = threading.Lock()

    @classmethod
    def load_sdk(cls):
        try:
            import openai_codex
        except ImportError:
            raise cls.missing() from None
        return openai_codex

    @classmethod
    def models(cls) -> frozenset:
        return frozenset(TERRA_MODELS)

    def sdk_model(self, model: str) -> str:
        return model

    def abort(self) -> None:
        with self._active_lock:
            client, self._active = self._active, None
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001 - best effort on a deadline overrun
                pass

    def invoke(self, *, prompt, system, schema, model, max_output_tokens, timeout, cwd) -> SdkReply:
        sdk = self.sdk
        try:
            client = sdk.Codex(sdk.CodexConfig(cwd=cwd, config_overrides=config_overrides()))
        except FileNotFoundError as e:
            raise NotSent(f"codex binary not found ({type(e).__name__})") from None
        with self._active_lock:
            self._active = client
        try:
            thread = client.thread_start(approval_mode=sdk.ApprovalMode.deny_all, sandbox=sdk.Sandbox.read_only,
                                         ephemeral=True, base_instructions=system, cwd=cwd, model=model)
            result = thread.run(prompt, output_schema=schema, effort=TERRA_REASONING_EFFORT.get(model))
        finally:
            self.abort()
        reply = SdkReply(text=getattr(result, "final_response", None), resolved_model=None,
                         request_id=getattr(thread, "id", None))
        for item in getattr(result, "items", None) or []:
            it = getattr(getattr(item, "root", item), "type", None)
            if it not in ALLOWED_ITEMS:
                reply.violations.append(str(it))
        status = getattr(getattr(result, "status", None), "value", getattr(result, "status", None))
        if status != "completed" or getattr(result, "error", None) is not None:
            err = getattr(result, "error", None)
            reply.error = getattr(err, "message", None) or f"turn {status}"
        usage = getattr(getattr(result, "usage", None), "last", None)
        if usage is not None:
            reply.input_tokens = usage.input_tokens
            reply.cached_input_tokens = usage.cached_input_tokens
            reply.cache_write_tokens = usage.cache_write_input_tokens
            reply.output_tokens = usage.output_tokens
            reply.reasoning_tokens = usage.reasoning_output_tokens
        return reply

    def _usage(self, r):
        # Codex reports cached tokens inside input_tokens and cache writes separately; uncached = input - cached.
        u = super()._usage(SdkReply(input_tokens=r.input_tokens, cached_input_tokens=r.cached_input_tokens,
                                    output_tokens=r.output_tokens, reasoning_tokens=r.reasoning_tokens))
        u["cacheWriteInputTokens"] = r.cache_write_tokens if type(r.cache_write_tokens) is int else None
        return u

    def estimate(self, model, r):
        u = self._usage(r)
        if None in (u["uncachedInputTokens"], u["cachedInputTokens"], u["outputTokens"]):
            return None, terra_price_version(model)
        return terra_api_equivalent_micros(u["uncachedInputTokens"], u["cachedInputTokens"], u["outputTokens"],
                                           r.input_tokens, model), terra_price_version(model)
