"""Stage 0A executable contracts (owner: S0-03). Changes require a contract-change request.

Usage:
    from reviewer.contracts import loads_strict, require, validate
    doc = loads_strict(untrusted_text)    # duplicate keys / NaN / unsafe JSON -> ContractInputError
    require("CostRecord", doc)            # raises ContractViolation
    issues = validate("Finding", doc)     # list[Issue]; never raises on document content
"""

from . import entities as _entities
from .entities import (HOST_CONTEXT_STAGES, MAX_HOP, MAX_TURN_REQUESTS, ROLE_OUTPUT, ROLE_SCHEMAS,
                       ROLE_TURN, TURN_PAYLOAD, check_finding_provenance, check_turn_trace,
                       citable_tool_calls, is_turn_schema, serves_request, terminal_payload,
                       turn_chain, turn_requests, usable_output, validate_trace)
from .scoring_family import (SCORE_MODELS, SCORE_OUTPUT_SCHEMAS, SCORE_ROLE_SCHEMA, SCORE_ROLE_STAGE,
                             SCORE_ROLES, SCORE_STAGES, check_score_replay, validate_score_trace)
from .schema import (REGISTRY, ContractInputError, ContractViolation, Issue, export_bundle,
                     loads_strict, require, validate)

CONTRACTS_VERSION = "s0a-contracts@7"
ENTITY_NAMES = _entities.ENTITY_NAMES

__all__ = ["CONTRACTS_VERSION", "ENTITY_NAMES", "REGISTRY", "ContractInputError",
           "ContractViolation", "Issue", "export_bundle", "loads_strict", "require", "validate",
           "validate_trace", "check_finding_provenance", "check_turn_trace", "citable_tool_calls",
           "is_turn_schema", "serves_request", "terminal_payload", "turn_chain", "turn_requests",
           "usable_output", "HOST_CONTEXT_STAGES", "MAX_HOP", "MAX_TURN_REQUESTS", "ROLE_OUTPUT",
           "ROLE_SCHEMAS", "ROLE_TURN", "TURN_PAYLOAD", "SCORE_MODELS", "SCORE_OUTPUT_SCHEMAS",
           "SCORE_ROLE_SCHEMA", "SCORE_ROLE_STAGE", "SCORE_ROLES", "SCORE_STAGES", "check_score_replay",
           "validate_score_trace"]
