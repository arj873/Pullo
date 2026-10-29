"""Explicit routing of review roles to provider adapters (review family only; scoring has its own host).

Each role's provider comes from its ModelProfile entry (pullo.toml model -> provider; the allowlists are disjoint):
  anthropic -> OpenRouterProvider (paid, the operator's $50 trial key/book)
  openai    -> CodexTerraProvider (ChatGPT subscription through the installed Codex CLI, codex-isolated-home@1)
A provider no role uses is a DisabledProvider, so an arm that needs no OpenRouter role never loads the key, and an
arm with no Terra role never runs the Codex CLI preflight. Plan mode captures both kinds in call order without
sending anything; the Terra capture declares the same billing kind as the live adapter, so the gateway takes the
same (no SpendBook) path in plan as in live."""

from __future__ import annotations

from reviewer.gateway import DisabledProvider
from reviewer.gateway.errors import typed_error
from reviewer.gateway.providers import ProviderResult
from reviewer.pipeline.errors import PipelineError
from reviewer.runtime.codex_cli import CodexTerraProvider, CodexUnsupported, request_facts


class ReviewProviders:
    def __init__(self, router, terra):
        self.mapping = {"anthropic": router, "openai": terra, "synthetic": DisabledProvider("synthetic")}

    @property
    def calls(self):
        return sum(getattr(p, "calls", 0) for p in self.mapping.values())


def needs(profile, provider) -> bool:
    return any(s["provider"] == provider for s in profile["roles"].values())


def live_terra(profile, ledger, scope, *, factory=CodexTerraProvider):
    """The live Terra adapter for this run (its offline CLI/prompt-isolation preflight runs here, before any output
    exists), or a DisabledProvider when no role uses openai. An unsupported CLI is a typed config refusal."""
    if not needs(profile, "openai"):
        return DisabledProvider("openai")
    try:
        return factory(enabled=True, ledger=ledger, run_scope=scope)
    except CodexUnsupported as e:
        raise PipelineError("config", f"Terra isolation preflight failed: {str(e)[:300]}") from e


class PlanCapture:
    """Ordered record of what plan mode WOULD send: ('anthropic', index into the capturing transport) or
    ('openai', request)."""

    def __init__(self):
        self.order: list[tuple[str, object]] = []

    def facts(self, transport_requests, router_facts) -> list[dict]:
        out = []
        for kind, item in self.order:
            if kind == "openai":
                out.append(request_facts(item))
            elif item < len(transport_requests):
                out.append(router_facts(transport_requests[item]))
        seen = {i for k, i in self.order if k == "anthropic"}
        out += [router_facts(r) for i, r in enumerate(transport_requests) if i not in seen]
        return out


class TerraPlanProvider:
    """Plan-only stand-in for CodexTerraProvider: records the request, never runs the CLI."""
    name = "openai"
    billing_kind = "subscription-consumption"

    def __init__(self, capture: PlanCapture):
        self.capture, self.calls = capture, 0

    def call(self, request, key):
        self.calls += 1
        self.capture.order.append(("openai", request))
        return ProviderResult(None, typed_error("provider-error", "plan mode: nothing is sent", retryable=False),
                              "not-sent")


class _RouterPlanTap:
    """Marks where in the call order an OpenRouter plan request was captured, then delegates unchanged."""

    def __init__(self, inner, capture: PlanCapture, transport):
        self.inner, self.capture, self.transport = inner, capture, transport
        self.name = getattr(inner, "name", "anthropic")

    @property
    def calls(self):
        return self.inner.calls

    def call(self, request, key):
        self.capture.order.append(("anthropic", len(self.transport.requests)))
        return self.inner.call(request, key)


def plan_providers(profile, transport, router_factory) -> tuple[ReviewProviders, PlanCapture]:
    """Plan-mode providers. `router_factory()` builds the placeholder-key OpenRouterProvider over the capturing
    `transport`; it is called only when a role uses anthropic (a Terra-only authorization need not cover anthropic)."""
    capture = PlanCapture()
    router = (_RouterPlanTap(router_factory(), capture, transport) if needs(profile, "anthropic")
              else DisabledProvider("anthropic"))
    terra = TerraPlanProvider(capture) if needs(profile, "openai") else DisabledProvider("openai")
    return ReviewProviders(router, terra), capture


def worst_case(facts: list[dict]) -> int | None:
    """Largest per-request admission bound across arms: router dollars or the Terra API-equivalent estimate."""
    vals = [max(f.get("worstCaseRouterUsdMicros") or 0, f.get("worstCaseApiEquivalentUsdMicros") or 0) for f in facts]
    return max(vals, default=None)


def planned_request(request):
    if request["provider"] == "openai":
        return request_facts(request)
    return None


def scrub_of(key):
    return key.scrub if key is not None else (lambda text: text)
