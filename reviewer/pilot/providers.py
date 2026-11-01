"""Explicit routing of review roles to provider adapters (review family only; scoring has its own host).

Each role's provider comes from its ModelProfile entry (pullo.toml model -> provider; the allowlists are disjoint):
  anthropic -> OpenRouterProvider (paid, the operator's $50 trial key/book)
  openai    -> CodexTerraProvider (ChatGPT subscription through the installed Codex CLI, codex-isolated-home@2)
  opencode  -> OpenCodeFreeProvider (OpenCode Zen free models through the installed opencode CLI, opencode-isolated-home@2;
               OPENCODE-FREE-PROVIDER). It is a CLI arm like Terra: live_arm() calls it "terra" (its own operator-created
               CLI-arm state dir, never the OpenRouter trial state, never the key) and live_terra() returns CliProviders.
A provider no role uses is a DisabledProvider, so an arm that needs no OpenRouter role never loads the key, and an
arm with no Terra role never runs the Codex CLI preflight. Plan mode captures both kinds in call order without
sending anything; the Terra capture declares the same billing kind as the live adapter, so the gateway takes the
same (no SpendBook) path in plan as in live."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from reviewer.gateway import DisabledProvider, SpendBook
from reviewer.gateway.errors import typed_error
from reviewer.gateway.providers import ProviderResult
from reviewer.pipeline.errors import PipelineError
from reviewer.runtime.catalog import TRIAL_TOTAL_USD_MICROS
from reviewer.runtime.codex_cli import CodexTerraProvider, CodexUnsupported, request_facts
from reviewer.runtime.opencode_cli import OpenCodeFreeProvider, OpenCodeUnsupported
from reviewer.runtime.opencode_cli import request_facts as opencode_request_facts
from reviewer.runtime.receipts import RuntimeLedger

# A Terra arm's live state is its OWN operator-created directory (gate S1): the subscription ledger and an (unused,
# never-written) spend book bound to the Terra authorization. It may never be, or hold, the OpenRouter trial state.
TERRA_LEDGER_NAME = "terra-subscription-ledger.jsonl"
TERRA_BOOK_NAME = "terra-spend-book.jsonl"
TRIAL_STATE_NAMES = ("runtime-ledger.jsonl", "spend-book.jsonl")
TERRA_STATE_NOTE = ("live: a Terra arm uses --state-dir as its own operator-created Terra state dir holding "
                    f"{TERRA_LEDGER_NAME} (subscription ledger; may start empty) - never the OpenRouter trial state; "
                    "--env is not read; --baseline-micros is that ledger's committed total (0 for subscription calls)")


class TerraStateError(ValueError):
    pass


class CliProviders:
    """The CLI adapters of an opencode arm (what live_terra/plan_providers return when a role uses opencode): `openai` and
    `opencode`, each a live/plan adapter or a DisabledProvider. A Terra-only arm keeps receiving the bare Codex adapter."""

    def __init__(self, openai, opencode):
        self.openai, self.opencode = openai, opencode

    @property
    def calls(self):
        return getattr(self.openai, "calls", 0) + getattr(self.opencode, "calls", 0)


class ReviewProviders:
    def __init__(self, router, terra):
        if isinstance(terra, CliProviders):       # an opencode arm: route provider=opencode requests to its adapter
            self.mapping = {"anthropic": router, "openai": terra.openai, "synthetic": DisabledProvider("synthetic"),
                            "opencode": terra.opencode}
        else:                                     # every other arm: the mapping exactly as before
            self.mapping = {"anthropic": router, "openai": terra, "synthetic": DisabledProvider("synthetic")}

    @property
    def calls(self):
        return sum(getattr(p, "calls", 0) for p in self.mapping.values())


def needs(profile, provider) -> bool:
    """Any role, or a role's impact@v7 alternate (ModelProfile.alternates), runs on `provider`."""
    return any(s["provider"] == provider for s in [*profile["roles"].values(), *profile.get("alternates", {}).values()])


def live_arm(profile) -> str:
    """'router' (OpenRouter roles only) or 'terra' (Terra roles only, or opencode roles only: the same CLI-arm state
    layout). A live mixed arm is refused: it would need the trial state and a subscription ledger in one run, and the trial
    ledger must never carry subscription or free-model rows."""
    router, terra, free = needs(profile, "anthropic"), needs(profile, "openai"), needs(profile, "opencode")
    if router and terra:
        raise TerraStateError("live mixed OpenRouter+Terra arms are not supported: run all roles on one provider "
                              "(plan mode still shows a mixed arm's requests)")
    if free and (router or terra):            # OPENCODE-FREE-PROVIDER: an opencode arm runs every role on opencode
        raise TerraStateError("live mixed opencode arms are not supported: run all roles on opencode free models "
                              "(plan mode still shows a mixed arm's requests)")
    return "terra" if terra or free else "router"


def open_terra_state(state_dir, handle, baseline: int) -> tuple:
    """-> (SpendBook, RuntimeLedger) of a Terra state dir. Refuses a symlink, a missing dir or ledger file (the operator
    creates both), a directory holding OpenRouter trial state, and a ledger whose committed total differs from
    `baseline`."""
    state = Path(state_dir)
    if os.path.islink(state) or not state.is_dir():
        raise TerraStateError("--state-dir must be an existing directory (not a symlink)")
    if any(os.path.lexists(state / n) for n in TRIAL_STATE_NAMES):
        raise TerraStateError("--state-dir holds OpenRouter trial state; a Terra arm needs its own Terra state dir")
    led = state / TERRA_LEDGER_NAME
    try:
        st = os.lstat(led)
    except OSError:
        raise TerraStateError(f"Terra state dir lacks the operator-created {TERRA_LEDGER_NAME}") from None
    if not stat.S_ISREG(st.st_mode):
        raise TerraStateError(f"{TERRA_LEDGER_NAME} is not a regular file")
    ledger = RuntimeLedger(led, TRIAL_TOTAL_USD_MICROS)
    try:
        t = ledger.totals()
    except (ValueError, KeyError, TypeError, OSError):
        raise TerraStateError("Terra subscription ledger is unreadable") from None
    if t["committedUsdMicros"] != baseline:
        raise TerraStateError(f"Terra ledger committed {t['committedUsdMicros']} != --baseline-micros {baseline}")
    if os.path.lexists(state / TERRA_BOOK_NAME) and not os.path.isfile(state / TERRA_BOOK_NAME):
        raise TerraStateError(f"{TERRA_BOOK_NAME} is not a regular file")
    return SpendBook(handle, state / TERRA_BOOK_NAME), ledger


def live_terra(profile, ledger, scope, *, factory=CodexTerraProvider, opencode_factory=OpenCodeFreeProvider):
    """The live Terra adapter for this run (its offline CLI/prompt-isolation preflight runs here, before any output
    exists), or a DisabledProvider when no role uses openai. An unsupported CLI is a typed config refusal.
    An opencode arm gets CliProviders(DisabledProvider("openai"), OpenCodeFreeProvider) (its offline preflight - exact CLI
    version, credential-less offline catalog, loopback capture proofs - runs here too)."""
    if needs(profile, "opencode"):
        if needs(profile, "openai") or needs(profile, "anthropic"):
            raise PipelineError("config", "live mixed opencode arms are not supported")
        models = sorted({s["model"] for s in [*profile["roles"].values(), *profile.get("alternates", {}).values()]})
        try:
            return CliProviders(DisabledProvider("openai"),
                                opencode_factory(enabled=True, ledger=ledger, run_scope=scope, models=models))
        except OpenCodeUnsupported as e:
            raise PipelineError("config", f"opencode isolation preflight failed: {str(e)[:300]}") from e
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
            elif kind == "opencode":
                out.append(opencode_request_facts(item))
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


class OpenCodePlanProvider:
    """Plan-only stand-in for OpenCodeFreeProvider: records the request, never runs the CLI."""
    name = "opencode"
    billing_kind = "free-model"

    def __init__(self, capture: PlanCapture):
        self.capture, self.calls = capture, 0

    def call(self, request, key):
        self.calls += 1
        self.capture.order.append(("opencode", request))
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
    if needs(profile, "opencode"):                # OPENCODE-FREE-PROVIDER: same order capture, opencode request facts
        return ReviewProviders(router, CliProviders(terra, OpenCodePlanProvider(capture))), capture
    return ReviewProviders(router, terra), capture


def worst_case(facts: list[dict]) -> int | None:
    """Largest per-request admission bound across arms: router dollars or the Terra API-equivalent estimate."""
    vals = [max(f.get("worstCaseRouterUsdMicros") or 0, f.get("worstCaseApiEquivalentUsdMicros") or 0) for f in facts]
    return max(vals, default=None)


def planned_request(request):
    if request["provider"] == "openai":
        return request_facts(request)
    if request["provider"] == "opencode":
        return opencode_request_facts(request)
    return None


def scrub_of(key):
    return key.scrub if key is not None else (lambda text: text)
