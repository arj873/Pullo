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

from .retrieval import RetrievalPolicy


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
    retrieval: RetrievalPolicy | None = None     # retrieval@1 limits; None = defaults when a profile role is a Turn role


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
                     eval_run_id: str | None, eval_case_id: str | None, guard: Any = None): ...


@dataclass(frozen=True)
class RepositoryImports:
    """The two host-verified `repo-import@1` records (base, head) behind complete-repository snapshots. The
    pipeline re-checks each against its manifest; coverage and omissions come from these records only."""
    base: dict
    head: dict


@dataclass(frozen=True)
class StageReplay:
    """Offline replay from a stage: stages before `from_stage` come from the pinned recording's checkpointed
    artifacts in `recording_dir`; the rest is re-executed against the gateway in strict replay."""
    from_stage: str
    recording_dir: str | Path


@dataclass(frozen=True)
class ForkFrom:
    """Zero-cost recorded prefix, live suffix: a different operation from StageReplay. `source` is the pinned
    ReplayBackend of the recording; the run backend is a RecordBackend sharing the evaluation's SpendBook."""
    source: Any
    from_stage: str
    recording_dir: str | Path


@dataclass(frozen=True)
class ReviewSpec:
    case: dict
    base: SnapshotInput
    head: SnapshotInput
    profile: dict
    plan: dict
    host: HostConfig
    backend: Any
    coverage: dict | None = None     # host-built historical-coverage@1 (partial view); None = two full snapshots
    imports: RepositoryImports | None = None     # complete pinned repositories (repo-import@1 records)
    stage_replay: StageReplay | None = None
    fork: ForkFrom | None = None


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
    retrieval: dict | None = None        # retrieval summary re-derived from the trace (None for legacy profiles)
    impact: dict | None = None           # impact-coverage@1 re-derived from the trace (None unless impact mode)
