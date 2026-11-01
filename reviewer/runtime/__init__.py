"""Live runtime adapters (owner: S0B-01a). Opt-in, offline-tested. See orchestration/handoffs/S0B-01a.md.

OpenRouterProvider  - provider=anthropic, exact OpenRouter model IDs, bounded HTTPS, no fallback.
CodexTerraProvider  - provider=openai, GPT Terra (gpt-6.1-terra, gpt-5.6-terra) through the installed `codex exec`
                      in a fresh isolated CODEX_HOME per call (codex-isolated-home@2), no model tools.
OpenCodeFreeProvider - provider=opencode, OpenCode Zen FREE models through the installed `opencode run` in a fresh
                      credential-less home per call (opencode-isolated-home@2), every tool denied, $0 (free-model).
ClaudeCliProvider   - provider=claude-cli, Claude Opus/Sonnet 5.5 through the installed `claude -p` on the user's subscription
                      (claude-cli-isolated@3): no tools, OAuth access token on an inherited fd, masked bwrap sandbox, $0.

Nothing here runs at import time: no key is read, no socket is opened, no subprocess is started."""

from .catalog import (ALLOWED_ROUTER_MODELS, TERRA_MODEL, TRIAL_TOTAL_USD_MICROS, PRICE_VERSION)
from .codex_cli import CodexTerraProvider, check_cli_isolation
from .opencode_cli import OpenCodeFreeProvider
from .claude_cli import ClaudeCliProvider
from .envfile import EnvFileError, Secret, load_openrouter_key
from .openrouter import OpenRouterProvider
from .receipts import RuntimeLedger, accountable_cost
from .scoring_budget import SCORING_AGGREGATE_CEILING_MAX, SCORING_CATEGORY_CAP_MAX, validate_admission

__all__ = ["ALLOWED_ROUTER_MODELS", "ClaudeCliProvider", "CodexTerraProvider", "EnvFileError", "OpenCodeFreeProvider", "OpenRouterProvider",
           "PRICE_VERSION",
           "RuntimeLedger", "SCORING_AGGREGATE_CEILING_MAX", "SCORING_CATEGORY_CAP_MAX", "Secret", "accountable_cost", "TERRA_MODEL", "TRIAL_TOTAL_USD_MICROS", "check_cli_isolation",
           "load_openrouter_key", "validate_admission"]
