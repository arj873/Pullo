"""Public data types of the pipeline: inputs the host supplies and the result it gets back.

The engine takes a CaseInput document, separately provided snapshot roots/manifests, a profile, a Plan,
host-owned configuration and an explicit gateway backend. It never takes a SuiteCase, labels, scripts or
expectations; the host (S0-08) keeps those and gives scripts only to the provider inside the backend.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from reviewer.tools import Limits


@dataclass(frozen=True)
class SnapshotInput:
    """A pinned full snapshot: an explicit root directory and its provided SnapshotManifest."""
    root: str | Path
    manifest: dict


@dataclass(frozen=True)
class EvalIdentity:
    eval_run_id: str          # evr_<16 hex>, unique per evaluation execution (a replay gets its own)
    case_id: str              # must equal CaseInput.id
    repeat: int = 0


@dataclass
class Hooks:
    """Optional seams. `after_checkpoint` runs after a stage artifact and its checkpoint event are durable;
    a test raises a BaseException from it to simulate a crash between stages."""
    after_checkpoint: Callable[[str, str], None] | None = None


@dataclass(frozen=True)
class HostConfig:
    out_root: str | Path
    eval: EvalIdentity | None = None
    attempt: int = 1
    config_identity: Any = None
    forbidden_roots: tuple = ()
    clock: Callable[[], float] = time.monotonic
    wall_clock: Callable[[], str] | None = None
    cancel: Callable[[], bool] | None = None
    tool_limits: Limits | None = None
    comment_cap: int = 5
    hooks: Hooks = field(default_factory=Hooks)


class GatewayBackend(Protocol):
    """Explicit gateway dependency. The engine owns the Recorder and run.start; the backend builds a
    Gateway bound to that recorder."""
    mode: str                          # "live" (recording) | "strict-replay"
    authorization_digest: str | None
    replay_of: str | None
    recording: Any                     # LoadedTrace for replay, else None
    pin_source: str | None

    def preflight(self, profile: dict, budget: dict) -> None: ...

    def make_gateway(self, *, run_id: str, profile: dict, budget: dict, recorder, cost_kind: str,
                     eval_run_id: str | None, eval_case_id: str | None): ...


@dataclass(frozen=True)
class ReviewSpec:
    case: dict
    base: SnapshotInput
    head: SnapshotInput
    profile: dict
    plan: dict
    host: HostConfig
    backend: Any


@dataclass
class RunResult:
    run_id: str
    run: dict
    status: str
    incomplete: list
    error: dict | None
    hypotheses: list
    findings: list
    verifications: list
    drops: list
    comments: list
    stages: dict
    cost: dict
    latency: dict
    run_dir: str
    trace_path: str
    trace_digest: str
    receipt: dict
    receipt_path: str
    comments_path: str
    review_path: str
    idempotent: bool = False
    resumed_from: str | None = None
    gateway_report: dict | None = None
