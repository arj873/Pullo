"""Typed errors shared by the gateway. Config-time problems raise; call-time problems return TypedError documents."""

from __future__ import annotations

from reviewer.contracts import require
from reviewer.contracts.redaction import redact


class GatewayConfigError(ValueError):
    """The gateway was built with an unsafe or inconsistent configuration."""


class AuthorizationError(GatewayConfigError):
    """No acceptable trusted SpendAuthorization for this use."""


class ScriptError(ValueError):
    """A synthetic script violates the frozen interface."""


class SettlementError(RuntimeError):
    """The spend book failed after a provider call may have been billed. The call was recorded
    (model.call, cost and an error event) before this was raised; its book reservation stays open
    and needs operator reconciliation."""


class TraceError(ValueError):
    """A recorded trace is damaged, inconsistent or hand-edited."""


def typed_error(code: str, message: str, *, retryable: bool = False, stage: str | None = None,
                detail=None) -> dict:
    """Build a contract-valid TypedError; text is redacted so an error can always be persisted."""
    doc: dict = {"code": code, "message": redact(message[:1900])[0], "retryable": retryable}
    if stage is not None:
        doc["stage"] = stage
    if detail is not None:
        from reviewer.contracts.redaction import redact_json
        doc["detail"] = redact_json(detail)[0]
    return require("TypedError", doc)
