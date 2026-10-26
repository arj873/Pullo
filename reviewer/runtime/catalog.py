"""Pinned runtime model allowlist and price snapshots (USD micros per million tokens).

Source: orchestration/RUNTIME-ACCESS.md catalog observation 2026-10-25T19:52Z and PROVIDER-ADAPTERS.md (Terra).
These are catalog observations, not a bill. Refresh and re-pin before live admission."""

from __future__ import annotations

import math

PRICE_VERSION = "openrouter-catalog@2026-10-25T1952Z"
TERRA_PRICE_VERSION = "openai-terra-list@2026-10-25"
TRIAL_TOTAL_USD_MICROS = 50_000_000
TERRA_MODEL = "gpt-5.6-terra"

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


def terra_gateway_price() -> dict:
    return {"priceVersion": TERRA_PRICE_VERSION, "inputPerMTokUsdMicros": TERRA_PRICE["input"],
            "cachedInputPerMTokUsdMicros": TERRA_PRICE["cached"],
            "cacheWriteInputPerMTokUsdMicros": TERRA_PRICE["write"],
            "outputPerMTokUsdMicros": TERRA_PRICE["output"]}


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


def token_priced_micros(model: str, uncached: int, cached: int, write: int, output: int,
                        prompt_tokens: int | None = None) -> int:
    """Catalog token-price computation (NOT the provider bill). Cache writes use the 5-minute rate."""
    p = router_price(model, prompt_tokens)
    return (_ceil_cost(uncached, p["input"]) + _ceil_cost(cached, p["cached"]) + _ceil_cost(write, p["write"])
            + _ceil_cost(output, p["output"]))


def terra_api_equivalent_micros(uncached: int, cached: int, output: int, prompt_tokens: int) -> int:
    """API-equivalent ESTIMATE for subscription CLI usage. Never a paid-API charge."""
    t = TERRA_PRICE
    ix = t["tierInputX"] if prompt_tokens > t["tierAbovePromptTokens"] else 1.0
    ox = t["tierOutputX"] if prompt_tokens > t["tierAbovePromptTokens"] else 1.0
    return math.ceil(_ceil_cost(uncached, t["input"]) * ix + _ceil_cost(cached, t["cached"]) * ix
                     + _ceil_cost(output, t["output"]) * ox)
