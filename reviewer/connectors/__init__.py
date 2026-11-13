"""SDK connectors: answer review roles through an agent SDK under the operator's own login (subscription) instead of
the paid OpenRouter key. Select one with `--connector` on the repository / ordinary review hosts.

    openrouter  (default) provider anthropic through OpenRouter, paid trial key; provider openai through `codex exec`
    claude-sdk  provider anthropic through the Claude Agent SDK (your Claude subscription)
    codex-sdk   provider openai (GPT Terra) through the Codex Python SDK (your ChatGPT subscription)

To add a connector for another SDK, follow `.claude/skills/add-sdk-connector/SKILL.md`: subclass
`base.SdkConnector`, implement `invoke()`, and add the class to CONNECTORS below. Nothing here imports an SDK at import
time; a connector loads its SDK only when a live run constructs it."""

from __future__ import annotations

from .base import ConnectorUnavailable, NotSent, SdkConnector, SdkReply
from .claude_sdk import ClaudeSdkConnector
from .codex_sdk import CodexSdkConnector

DEFAULT = "openrouter"
CONNECTORS: dict[str, type[SdkConnector]] = {
    ClaudeSdkConnector.connector_id: ClaudeSdkConnector,
    CodexSdkConnector.connector_id: CodexSdkConnector,
}
CHOICES = (DEFAULT, *CONNECTORS)


def get(name: str) -> type[SdkConnector] | None:
    """The connector class for `name`, or None for the default (built-in OpenRouter / Codex CLI adapters)."""
    if name == DEFAULT:
        return None
    if name not in CONNECTORS:
        raise ValueError(f"unknown connector {name!r}; choose one of {', '.join(CHOICES)}")
    return CONNECTORS[name]


__all__ = ["CHOICES", "CONNECTORS", "ClaudeSdkConnector", "CodexSdkConnector", "ConnectorUnavailable", "DEFAULT",
           "NotSent", "SdkConnector", "SdkReply", "get"]
