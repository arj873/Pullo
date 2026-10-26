"""Host PR trial launcher (owner: S0B-01c). Standalone `python -m reviewer.pilot`; no root CLI edit.

Plan mode (default) reads corpus, pins and authorization only: no .env, no key, no network, no real spend files.
`--live` is for the trusted host after independent gates. See orchestration/handoffs/S0B-01c-api.md."""

from .launcher import PilotError, PilotOptions, run_cases
from .cli import main
from .profile import live_plan, live_profile

__all__ = ["PilotError", "PilotOptions", "live_plan", "live_profile", "main", "run_cases"]
