"""Pinned runtime model allowlist and price snapshots (USD micros per million tokens).

Source: orchestration/RUNTIME-ACCESS.md catalog observation 2026-10-25T19:52Z and PROVIDER-ADAPTERS.md (Terra).
These are catalog observations, not a bill. Refresh and re-pin before live admission."""

from __future__ import annotations

import math

PRICE_VERSION = "openrouter-catalog@2026-10-25T1952Z"
TERRA_PRICE_VERSION = "openai-terra-list@2026-10-25"
TRIAL_TOTAL_USD_MICROS = 50_000_000
TERRA_MODEL = "gpt-5.6-terra"
# GPT Terra 6 ("you can use gpt terra 6", user 2026-10-29). Id from the installed codex-cli 0.163.0 model catalog:
# `codex debug models` (server-refreshed, metadata only, no inference) lists slug gpt-6.1-terra, display "GPT-6.1 Terra",
# context 500000, default reasoning low; it is the only Terra-6 slug and is NOT in the `--bundled` catalog. No
# gpt-6-terra exists. gpt-5.6-terra stays supported (older arm, replay of earlier work).
TERRA_6_MODEL = "gpt-6.1-terra"
TERRA_6_PRICE_VERSION = "openai-gpt-6.1-terra-standard@2026-10-29"
TERRA_MODELS = frozenset({TERRA_MODEL, TERRA_6_MODEL})
# Pinned reasoning effort per Terra model (explicit, so an arm never silently follows a CLI/catalog default change).
TERRA_REASONING_EFFORT = {TERRA_MODEL: "medium", TERRA_6_MODEL: "medium"}
# Every Terra call runs in a fresh per-call CODEX_HOME (codex_cli.isolated_home); there is no shared-home path.
TERRA_ISOLATION_VERSION = "codex-isolated-home@2"

# model -> {input, cached, write, write1h, output}; `override` applies when prompt tokens >= threshold
ALLOWED_ROUTER_MODELS: dict[str, dict] = {
    "anthropic/claude-sonnet-5.5": {"input": 2_000_000, "cached": 100_000, "write": 2_500_000,
                                    "write1h": 4_000_000, "output": 10_000_000},
    "anthropic/claude-opus-5.5": {"input": 4_000_000, "cached": 200_000, "write": 5_000_000,
                                  "write1h": 8_000_000, "output": 20_000_000},
    "anthropic/claude-haiku-5.5": {"input": 100_000, "cached": 10_000, "write": 125_000, "write1h": 200_000,
                                   "output": 500_000,
                                   "override": {"promptTokensAtLeast": 100_000, "input": 500_000, "cached": 50_000,
                                                "write": 625_000, "write1h": 1_000_000, "output": 2_500_000}},
}
TERRA_PRICE = {"input": 2_000_000, "cached": 200_000, "write": 2_500_000, "output": 12_000_000,
               "tierAbovePromptTokens": 272_000, "tierInputX": 2.0, "tierOutputX": 1.5}
# Official model page https://developers.openai.com/api/docs/models/gpt-6.1-terra, read 2026-10-29: input $1, cached
# input $0.05, cache write $1.25 (30-minute retention; 12-hour $2.50 is not used), output $5 per 1M tokens; above 272K
# input tokens the whole request is 2x input/cache and 1.5x output. API-equivalent ESTIMATE basis only: Codex CLI
# calls are ChatGPT-subscription consumption, never a paid-API or OpenRouter charge.
TERRA_6_PRICE = {**TERRA_PRICE, "input": 1_000_000, "cached": 50_000, "write": 1_250_000,
                 "output": 5_000_000}


def terra_price_version(model: str) -> str:
    return TERRA_6_PRICE_VERSION if model == TERRA_6_MODEL else TERRA_PRICE_VERSION


def terra_price(model: str) -> dict:
    if model not in TERRA_MODELS:
        raise ValueError("unknown Terra model")
    return TERRA_6_PRICE if model == TERRA_6_MODEL else TERRA_PRICE


def _ceil_cost(tokens: int, per_mtok: int) -> int:
    return -(-tokens * per_mtok // 1_000_000)


def router_price(model: str, prompt_tokens: int | None = None) -> dict:
    p = ALLOWED_ROUTER_MODELS[model]
    o = p.get("override")
    if o and prompt_tokens is not None and prompt_tokens >= o["promptTokensAtLeast"]:
        return {**p, **{k: v for k, v in o.items() if k != "promptTokensAtLeast"}}
    return p


def gateway_price(model: str) -> dict:
    """The contract `Price` block for a ModelProfile role (base tier; see handoff: tier overrides are NOT
    expressible in the contract, so Haiku >=100k-prompt calls can be under-priced by the gateway)."""
    p = ALLOWED_ROUTER_MODELS[model]
    return {"priceVersion": PRICE_VERSION, "inputPerMTokUsdMicros": p["input"],
            "cachedInputPerMTokUsdMicros": p["cached"], "cacheWriteInputPerMTokUsdMicros": p["write"],
            "outputPerMTokUsdMicros": p["output"]}


def terra_gateway_price(model: str = TERRA_MODEL) -> dict:
    p = terra_price(model)
    return {"priceVersion": terra_price_version(model), "inputPerMTokUsdMicros": p["input"],
            "cachedInputPerMTokUsdMicros": p["cached"],
            "cacheWriteInputPerMTokUsdMicros": p["write"],
            "outputPerMTokUsdMicros": p["output"]}


# Pre-send input-token bound. The first live canary measured 1347 input tokens for a 2356-byte request body
# (~0.57 token/byte, schema + framing included), which already exceeds the earlier bytes/2 assumption. Dense
# numeric, symbol-heavy, base64-like or non-Latin text can approach one token per UTF-8 byte, so the bound is
# one token per byte plus a fixed allowance for provider-side framing, capped at the listed 1M context (a
# larger request is rejected before processing, not billed).
INPUT_TOKENS_PER_BYTE = 1
INPUT_TOKEN_OVERHEAD = 2048
MAX_CONTEXT_TOKENS = 1_000_000


def worst_case_input_tokens(request_bytes: int) -> int:
    return min(request_bytes * INPUT_TOKENS_PER_BYTE + INPUT_TOKEN_OVERHEAD, MAX_CONTEXT_TOKENS)


def worst_case_router_micros(model: str, request_bytes: int, max_output_tokens: int) -> int:
    """Upper bound used by the runtime ledger before sending: `worst_case_input_tokens` at the dearest input
    rate of any tier, plus the full output cap at the dearest output rate."""
    p = ALLOWED_ROUTER_MODELS[model]
    o = p.get("override", {})
    in_rate = max(p["input"], p["write"], p["write1h"], o.get("input", 0), o.get("write", 0), o.get("write1h", 0))
    out_rate = max(p["output"], o.get("output", 0))
    return _ceil_cost(worst_case_input_tokens(request_bytes), in_rate) + _ceil_cost(max_output_tokens, out_rate)


def terra_worst_case_micros(model: str, request_bytes: int, max_output_tokens: int) -> int:
    """Pre-send API-equivalent upper bound for a Terra call (plan disclosure): `worst_case_input_tokens` at the dearer
    of the uncached/cache-write input rates and the full output cap, both at the long-context multiplier. The CLI cannot
    cap output tokens, so actual usage can exceed this; the gateway then records an overrun, never hides it."""
    t = terra_price(model)
    return math.ceil(_ceil_cost(worst_case_input_tokens(request_bytes), max(t["input"], t["write"])) * t["tierInputX"]
                     + _ceil_cost(max_output_tokens, t["output"]) * t["tierOutputX"])


def token_priced_micros(model: str, uncached: int, cached: int, write: int, output: int,
                        prompt_tokens: int | None = None) -> int:
    """Catalog token-price computation (NOT the provider bill). Cache writes use the 5-minute rate."""
    p = router_price(model, prompt_tokens)
    return (_ceil_cost(uncached, p["input"]) + _ceil_cost(cached, p["cached"]) + _ceil_cost(write, p["write"])
            + _ceil_cost(output, p["output"]))


def terra_api_equivalent_micros(uncached: int, cached: int, output: int, prompt_tokens: int,
                                model: str = TERRA_MODEL) -> int:
    """API-equivalent ESTIMATE for subscription CLI usage. Never a paid-API charge."""
    t = terra_price(model)
    ix = t["tierInputX"] if prompt_tokens > t["tierAbovePromptTokens"] else 1.0
    ox = t["tierOutputX"] if prompt_tokens > t["tierAbovePromptTokens"] else 1.0
    return math.ceil(_ceil_cost(uncached, t["input"]) * ix + _ceil_cost(cached, t["cached"]) * ix
                     + _ceil_cost(output, t["output"]) * ox)
