"""Explicit routing of review roles to provider adapters (review family only; scoring has its own host).

Each role's provider comes from its ModelProfile entry (pullo.toml model -> provider; the allowlists are disjoint):
  anthropic -> OpenRouterProvider (paid, the operator's $50 trial key/book)
  openai    -> CodexTerraProvider (ChatGPT subscription through the installed Codex CLI, codex-isolated-home@2)
  opencode  -> OpenCodeFreeProvider (OpenCode Zen free models through the installed opencode CLI, opencode-isolated-home@2;
               OPENCODE-FREE-PROVIDER). It is a CLI arm like Terra: live_arm() calls it "terra" (its own operator-created
               CLI-arm state dir, never the OpenRouter trial state, never the key) and live_terra() returns CliProviders.
  claude-cli -> ClaudeCliProvider (Claude Opus/Sonnet 5.5 through the installed Claude Code CLI on the user's subscription,
               no tools, claude-cli-isolated@4; CLAUDE-CLI-PROVIDER). A CLI arm like opencode: "terra" state layout,
               CliProviders(..., claude=adapter).
A provider no role uses is a DisabledProvider, so an arm that needs no OpenRouter role never loads the key, and an
arm with no Terra role never runs the Codex CLI preflight. Plan mode captures both kinds in call order without
sending anything; the Terra capture declares the same billing kind as the live adapter, so the gateway takes the
same (no SpendBook) path in plan as in live."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

from reviewer.gateway import DisabledProvider, SpendBook
from reviewer.gateway.errors import typed_error
from reviewer.gateway.providers import ProviderResult
from reviewer.contracts.snapshot import read_verified
from reviewer.pipeline import agentic, prompts
from reviewer.pipeline.errors import PipelineError
from reviewer.runtime.catalog import TRIAL_TOTAL_USD_MICROS, claude_cli_worst_case_micros
from reviewer.runtime.claude_cli import ClaudeCliProvider, ClaudeCliUnsupported
from reviewer.runtime.claude_cli import request_facts as claude_request_facts
from reviewer.runtime.codex_cli import CodexTerraProvider, CodexUnsupported, request_facts
from reviewer.runtime.opencode_cli import OpenCodeFreeProvider, OpenCodeUnsupported
from reviewer.runtime.opencode_cli import request_facts as opencode_request_facts
from reviewer.runtime.receipts import RuntimeLedger

from .profile import profile_repairs

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
    """The CLI adapters of an opencode or claude-cli arm (what live_terra/plan_providers return when a role uses one):
    `openai`, `opencode` and (claude-cli arms only) `claude`, each a live/plan adapter or a DisabledProvider. A Terra-only
    arm keeps receiving the bare Codex adapter."""

    def __init__(self, openai, opencode, claude=None):
        self.openai, self.opencode, self.claude = openai, opencode, claude

    @property
    def calls(self):
        return getattr(self.openai, "calls", 0) + getattr(self.opencode, "calls", 0) + getattr(self.claude, "calls", 0)


class ReviewProviders:
    def __init__(self, router, terra):
        if isinstance(terra, CliProviders):       # an opencode arm: route provider=opencode requests to its adapter
            self.mapping = {"anthropic": router, "openai": terra.openai, "synthetic": DisabledProvider("synthetic"),
                            "opencode": terra.opencode}
            if terra.claude is not None:          # a claude-cli arm (CLAUDE-CLI-PROVIDER)
                self.mapping["claude-cli"] = terra.claude
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
    claude = needs(profile, "claude-cli")
    if claude and (router or terra or free):  # CLAUDE-CLI-PROVIDER: a claude-cli arm runs every role on claude-cli
        raise TerraStateError("live mixed claude-cli arms are not supported: run all roles on claude-cli models "
                              "(plan mode still shows a mixed arm's requests)")
    return "terra" if terra or free or claude else "router"


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


AGENTIC_SNAPSHOT_SKIPPED_TOP = (".git", ".env")    # claude_agentic.Snapshot refuses either at a snapshot's top


def export_snapshot(base, head) -> tuple:
    """impact@v19 (reviewer.pipeline.agentic): the run's PR snapshot for an agentic claude-cli session, exported from the
    pinned imports (`base`, `head`: SnapshotInput-like, root + manifest; every byte read through read_verified) into a
    private 0700 directory under TMPDIR, outside home and the repository: regular and executable entries only (links are
    left out; so are a top-level .git or .env). -> (claude_agentic.Snapshot(head, base), the directory to remove after
    the run). Every file is written FRESH (one hard link: gate-agentic-p1 F3, claude_agentic.Snapshot refuses a hard link,
    which would be the host file itself); the benchmark host has no git repository to `git archive` at review time (the
    importer removes its bare store after materializing), so the pinned, hash-verified tree is the source. A snapshot the
    adapter would refuse is a typed config refusal (the directory is removed first)."""
    from reviewer.runtime.claude_agentic import Snapshot
    parent = os.path.realpath(tempfile.mkdtemp(prefix="pullo-agentic-snapshot-"))
    os.chmod(parent, 0o700)
    try:
        dirs = {}
        for name, snap in (("head", head), ("base", base)):
            d = dirs[name] = os.path.join(parent, name)
            os.mkdir(d, 0o755)
            for e in snap.manifest["entries"]:
                if e["type"] not in ("file", "executable") or e["path"].split("/")[0] in AGENTIC_SNAPSHOT_SKIPPED_TOP:
                    continue
                data = read_verified(snap.root, snap.manifest, e["path"])
                dest = os.path.join(d, *e["path"].split("/"))
                os.makedirs(os.path.dirname(dest), mode=0o755, exist_ok=True)
                with open(dest, "xb") as f:
                    f.write(data)
                os.chmod(dest, 0o755 if e["type"] == "executable" else 0o644)
        out = Snapshot(head=dirs["head"], base=dirs["base"])
        problems = out.problems()
        if problems:
            raise PipelineError("config", "agentic PR snapshot refused: " + "; ".join(problems)[:300])
        return out, parent
    except BaseException:
        shutil.rmtree(parent, ignore_errors=True)
        raise


def live_terra(profile, ledger, scope, *, factory=CodexTerraProvider, opencode_factory=OpenCodeFreeProvider,
               claude_factory=ClaudeCliProvider, snapshot=None):
    """The live Terra adapter for this run (its offline CLI/prompt-isolation preflight runs here, before any output
    exists), or a DisabledProvider when no role uses openai. An unsupported CLI is a typed config refusal.
    An opencode arm gets CliProviders(DisabledProvider("openai"), OpenCodeFreeProvider) (its offline preflight - exact CLI
    version, credential-less offline catalog, loopback capture proofs - runs here too)."""
    if needs(profile, "claude-cli"):                  # CLAUDE-CLI-PROVIDER: offline preflight + capture proofs run here
        if needs(profile, "openai") or needs(profile, "anthropic") or needs(profile, "opencode"):
            raise PipelineError("config", "live mixed claude-cli arms are not supported")
        models = sorted({s["model"] for s in [*profile["roles"].values(), *profile.get("alternates", {}).values()]})
        # impact@v19: a role in agentic mode needs the adapter opened agentic, with the run's PR snapshot (export_snapshot)
        kw = {"agentic": True, "agentic_snapshot": snapshot} if agentic.is_agentic_profile(profile) else {}
        if kw and snapshot is None:
            raise PipelineError("config", "an agentic claude-cli review needs the run's PR snapshot (benchmark host only)")
        try:
            return CliProviders(DisabledProvider("openai"), DisabledProvider("opencode"),
                                claude_factory(enabled=True, ledger=ledger, run_scope=scope, models=models, **kw))
        except ClaudeCliUnsupported as e:
            raise PipelineError("config", f"claude-cli isolation preflight failed: {str(e)[:300]}") from e
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
            elif kind == "claude-cli":
                out.append(claude_request_facts(item))
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


class ClaudeCliPlanProvider:
    """Plan-only stand-in for ClaudeCliProvider: records the request, never runs the CLI."""
    name = "claude-cli"
    billing_kind = "claude-subscription"

    def __init__(self, capture: PlanCapture):
        self.capture, self.calls = capture, 0

    def call(self, request, key):
        self.calls += 1
        self.capture.order.append(("claude-cli", request))
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
    if needs(profile, "claude-cli"):              # CLAUDE-CLI-PROVIDER: same order capture, claude-cli request facts
        oc = OpenCodePlanProvider(capture) if needs(profile, "opencode") else DisabledProvider("opencode")
        return ReviewProviders(router, CliProviders(terra, oc, ClaudeCliPlanProvider(capture))), capture
    if needs(profile, "opencode"):                # OPENCODE-FREE-PROVIDER: same order capture, opencode request facts
        return ReviewProviders(router, CliProviders(terra, OpenCodePlanProvider(capture))), capture
    return ReviewProviders(router, terra), capture


def claude_repair_extra_bytes(schema: str) -> int:
    """CLAUDE-CLI-REPAIR1: the most bytes the ONE gateway repair adds to a claude-cli prompt (claude_cli._prompt joins one more
    message block): prompts.repair_issues_builder's message at its largest - the most issues and previous-answer characters it
    shows, each at its largest JSON-escaped size (a control character: 6 bytes)."""
    worst = "\x01" * (prompts.REPAIR_RAW_CHARS + 1)
    issues = ["\x01" * (prompts.REPAIR_ISSUE_CHARS + 1)] * (prompts.REPAIR_MAX_ISSUES + 1)
    m = prompts.repair_issues_builder({"messages": []}, schema)({"status": "invalid-output", "output": None, "rawText": worst},
                                                               issues)["messages"][-1]
    return len(f"\n<{m['role']}>\n{m['content']}\n</{m['role']}>".encode("utf-8"))


def claude_repair_worst_case(facts: dict) -> int | None:
    """The admission bound (PACING micros) of the one repair of the claude-cli call whose plan facts are `facts`
    (claude_cli.request_facts: model, bodyBytes, maxTokens, schemaName)."""
    if type(facts.get("maxTokens")) is not int:
        return None
    return claude_cli_worst_case_micros(facts["model"], facts["bodyBytes"] + claude_repair_extra_bytes(facts["schemaName"]),
                                        facts["maxTokens"])


def repair_bound(profile: dict, first: list[dict], worst: int | None, ceiling: int) -> tuple[dict, str | None]:
    """(Plan fields, unmet gate or None) of a profile with gateway repairs (CLAUDE-CLI-REPAIR1): over every captured
    claude-cli first request, the largest repair bound and the largest logical call (that request + its one repair),
    against the run ceiling. A profile without repairs -> ({}, None), so its Plan report keeps its bytes."""
    if not profile_repairs(profile):
        return {}, None
    pairs = [(f.get("worstCaseApiEquivalentUsdMicros"), claude_repair_worst_case(f)) for f in first if f.get("provider") == "claude-cli"]
    ok = bool(pairs) and worst is not None and all(type(w) is int and type(r) is int for w, r in pairs)
    rep = max(r for _, r in pairs) if ok else None
    call = max(w + r for w, r in pairs) if ok else None
    fields = {"worstCaseRepairAdmissionUsdMicros": rep, "worstCaseCallUsdMicros": call}
    if call is None:
        return fields, "the first requests' gateway repairs could not be bounded (no bounded claude-cli first request captured)"
    if call > ceiling:
        return fields, f"worst-case call (first request + its one repair) {call} micros exceeds the {ceiling} run ceiling"
    return fields, None


def worst_case(facts: list[dict]) -> int | None:
    """Largest per-request admission bound across arms: router dollars or the Terra API-equivalent estimate."""
    vals = [max(f.get("worstCaseRouterUsdMicros") or 0, f.get("worstCaseApiEquivalentUsdMicros") or 0) for f in facts]
    return max(vals, default=None)


def planned_request(request):
    if request["provider"] == "openai":
        return request_facts(request)
    if request["provider"] == "opencode":
        return opencode_request_facts(request)
    if request["provider"] == "claude-cli":
        return claude_request_facts(request)
    return None


def scrub_of(key):
    return key.scrub if key is not None else (lambda text: text)
