"""Gateway backends: the explicit dependency the host injects.

RecordBackend  - live mode against the synthetic provider (Stage 0A allows nothing else). The host owns the
                 authorization handle, the ONE SpendBook for the whole evaluation and the providers dict
                 (scripts are given only to the provider, here, never to the engine).
ReplayBackend  - strict replay of a pinned recording. No authorization, book or providers exist in it.
"""

from __future__ import annotations

import hmac
import os
import re
from pathlib import Path

from reviewer.contracts import ContractInputError, loads_strict
from reviewer.contracts.budget import check_spend_authorization
from reviewer.gateway import (AuthorizationHandle, Gateway, GatewayConfigError, SpendBook, TraceError,
                              load_trace)

from .errors import PipelineError
from .store import MAX_READ_BYTES

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class RecordBackend:
    mode = "live"
    replay_of = None
    recording = None
    pin_source = None

    def __init__(self, authorization: AuthorizationHandle, book: SpendBook, providers: dict, clock):
        if not isinstance(authorization, AuthorizationHandle):
            raise PipelineError("config", "recording needs a trusted AuthorizationHandle")
        if not isinstance(book, SpendBook):
            raise PipelineError("config", "recording needs the evaluation's shared SpendBook")
        if book.handle.digest != authorization.digest:
            raise PipelineError("config", "spend book belongs to a different authorization")
        self.authorization, self.book, self.providers, self.clock = authorization, book, providers, clock

    @property
    def authorization_digest(self) -> str:
        return self.authorization.digest

    def preflight(self, profile: dict, budget: dict) -> None:
        problems = check_spend_authorization(self.authorization.auth, profile, budget, self.clock())
        if problems:
            raise PipelineError("config", "authorization does not cover this profile/Plan: " + "; ".join(problems))

    def make_gateway(self, *, run_id, profile, budget, recorder, cost_kind, eval_run_id, eval_case_id, guard=None):
        try:
            return Gateway(mode="live", profile=profile, budget=budget, run_id=run_id, providers=self.providers,
                           authorization=self.authorization, book=self.book, recorder=recorder, clock=self.clock,
                           cost_kind=cost_kind, eval_run_id=eval_run_id, eval_case_id=eval_case_id, guard=guard)
        except GatewayConfigError as e:
            raise PipelineError("config", str(e)) from e


class ReplayBackend:
    mode = "strict-replay"
    authorization_digest = None

    def __init__(self, trace_path, expected_trace_digest: str, pin_source: str = "operator-config"):
        if not isinstance(expected_trace_digest, str) or not _DIGEST.fullmatch(expected_trace_digest):
            raise PipelineError("replay-pin", "strict replay needs expected_trace_digest from a trusted source")
        self.trace_path = Path(trace_path)
        self.pin_source = pin_source
        self.expected_trace_digest = expected_trace_digest
        try:
            self.recording = load_trace(self.trace_path)
        except TraceError as e:
            raise PipelineError("replay-recording", f"recording is not a complete valid trace: {e}") from e
        if not hmac.compare_digest(self.recording.byte_digest, expected_trace_digest):
            raise PipelineError("replay-pin", "recording bytes do not match the pinned expected_trace_digest")
        self.replay_of = self.recording.run_id

    def preflight(self, profile: dict, budget: dict) -> None:
        return None

    def make_gateway(self, *, run_id, profile, budget, recorder, cost_kind, eval_run_id, eval_case_id, guard=None):
        try:
            return Gateway(mode="strict-replay", profile=profile, budget=budget, run_id=run_id,
                           replay=self.recording, recorder=recorder, cost_kind=cost_kind, eval_run_id=eval_run_id,
                           eval_case_id=eval_case_id, expected_trace_digest=self.expected_trace_digest, guard=guard)
        except (GatewayConfigError, TraceError) as e:
            raise PipelineError("replay-pin", str(e)) from e


def read_recording_receipt(receipt_path, recording_dir, *, allow_colocated: bool = False) -> tuple[str, str]:
    """-> (traceDigest, pin_source) from a recording receipt. A receipt stored inside the recording directory
    is the same trust domain as the trace it pins (an attacker who rewrites one can rewrite both), so it is
    refused unless the caller opts in; the replay receipt then records `colocated-receipt`."""
    rp, rd = Path(os.path.realpath(receipt_path)), Path(os.path.realpath(recording_dir))
    colocated = rd == rp.parent or rd in rp.parents
    if colocated and not allow_colocated:
        raise PipelineError("replay-pin", "the receipt lies inside the recording directory it pins; supply the "
                            "digest from operator config or a separate location (or opt in to a colocated pin)")
    try:
        fd = os.open(rp, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f:
            data = f.read(MAX_READ_BYTES + 1)
        doc = loads_strict(data)
    except (OSError, ContractInputError):
        raise PipelineError("replay-pin", "recording receipt unreadable") from None
    d = doc.get("traceDigest") if isinstance(doc, dict) else None
    if not isinstance(d, str) or not _DIGEST.fullmatch(d):
        raise PipelineError("replay-pin", "recording receipt has no valid traceDigest")
    return d, ("colocated-receipt" if colocated else "receipt")
