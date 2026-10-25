"""Smoke evaluation runner (owner: S0-08). See orchestration/handoffs/S0-08-interface.md.

The evaluator alone loads labels and scripts; the pipeline engine receives only CaseInput, pinned snapshots,
profile, Plan, host configuration and a gateway backend.
"""

from .errors import EvalError
from .runner import (DEFAULT_SUITE, CaseOutcome, EvalOutcome, compare_outcomes, eval_config, expected_run_id,
                     record_smoke, replay_smoke)

__all__ = ["DEFAULT_SUITE", "CaseOutcome", "EvalError", "EvalOutcome", "compare_outcomes", "eval_config",
           "expected_run_id", "record_smoke", "replay_smoke"]
