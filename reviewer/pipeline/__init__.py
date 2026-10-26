"""Stage 0A synthetic pipeline (owner: S0-07): INGEST -> PREPARE -> TRIAGE -> INVESTIGATE -> VERIFY -> JUDGE ->
PUBLISH -> LEARN over two pinned full snapshots, with local draft outputs, recording and strict offline replay.

See orchestration/handoffs/S0-07-interface.md for the API and S0-07.md for results and limits.
"""

from .backends import RecordBackend, ReplayBackend, read_recording_receipt
from .errors import PipelineError
from .identity import PIPELINE_VERSION, engine_identity
from .runner import load_result, run_review, validate_spec
from .retrieval import RetrievalPolicy
from .spec import (EvalIdentity, ForkFrom, HostConfig, Hooks, RepositoryImports, ReviewSpec, RunResult, SnapshotInput,
                   StageReplay)

__all__ = ["EvalIdentity", "ForkFrom", "HostConfig", "Hooks", "PIPELINE_VERSION", "PipelineError", "RecordBackend",
           "ReplayBackend", "RepositoryImports", "RetrievalPolicy", "ReviewSpec", "RunResult", "SnapshotInput",
           "StageReplay", "engine_identity", "load_result",
           "read_recording_receipt", "run_review", "validate_spec"]
