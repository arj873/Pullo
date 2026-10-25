"""Stage 0A smoke scorer and synthetic smoke fixtures (owner: S0-04).

Smoke-only: path/line overlap matching exists to check mechanics on SYNTHETIC cases whose
labels were planted by us. It must never be applied to real historical PRs; those stay
unscored (null metrics with a reason). See matching.py and report.py.
"""

from .cases import CaseScore, score_case, score_loaded_case, scored_case_result, unscored_case_result
from .errors import ScoringError, UnscoredSuiteError
from .matching import MatchResult, match_comments
from .metrics import f1_value, ratio
from .report import build_report

__all__ = ["CaseScore", "MatchResult", "ScoringError", "UnscoredSuiteError", "build_report",
           "f1_value", "match_comments", "ratio", "score_case", "score_loaded_case", "scored_case_result",
           "unscored_case_result"]
