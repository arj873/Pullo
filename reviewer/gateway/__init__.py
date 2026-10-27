"""Stage 0A model gateway (owner: S0-05). See orchestration/handoffs/S0-05.md for API and limits."""

from .auth import AuthorizationHandle, SpendBook, parse_ts, trusted_authorization
from .errors import (AuthorizationError, GatewayConfigError, ScriptError, SettlementError, TraceError,
                     typed_error)
from .gateway import CallResult, Gateway
from .guard import (AttemptContext, AttemptGuard, GuardRefusal, cancel_guard, chain_guards,
                    deadline_guard)
from .providers import DisabledProvider, ProviderResult, SyntheticProvider, default_providers
from .script import Script, ScriptedScoreProvider, load_script, parse_script
from .trace import (LoadedTrace, Recorder, bytes_digest, error_charge_class, events_to_bytes, load_trace,
                    verify_events)

__all__ = ["AttemptContext", "AttemptGuard", "GuardRefusal", "cancel_guard", "chain_guards",
           "deadline_guard", "AuthorizationHandle", "AuthorizationError", "CallResult", "DisabledProvider", "Gateway",
           "GatewayConfigError", "LoadedTrace", "ProviderResult", "Recorder", "Script", "ScriptError", "ScriptedScoreProvider",
           "SettlementError", "SpendBook", "SyntheticProvider", "TraceError", "bytes_digest",
           "error_charge_class", "events_to_bytes", "default_providers", "load_script",
           "load_trace", "parse_script", "parse_ts", "trusted_authorization", "typed_error",
           "verify_events"]
