"""Stage 0A synthetic pipeline (owner: S0-07): INGEST -> PREPARE -> TRIAGE -> INVESTIGATE -> VERIFY -> JUDGE ->
PUBLISH -> LEARN over two pinned full snapshots, with local draft outputs, recording and strict offline replay.

See orchestration/handoffs/S0-07-interface.md for the API and S0-07.md for results and limits.
"""

from .backends import RecordBackend, ReplayBackend, read_recording_receipt
from .errors import PipelineError
from .identity import PIPELINE_VERSION, engine_identity
from .runner import load_result, run_review, validate_spec
from .spec import EvalIdentity, HostConfig, Hooks, ReviewSpec, RunResult, SnapshotInput

__all__ = ["EvalIdentity", "HostConfig", "Hooks", "PIPELINE_VERSION", "PipelineError", "RecordBackend",
           "ReplayBackend", "ReviewSpec", "RunResult", "SnapshotInput", "engine_identity", "load_result",
           "read_recording_receipt", "run_review", "validate_spec"]
