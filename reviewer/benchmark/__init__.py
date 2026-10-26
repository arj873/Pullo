"""Offline benchmark data and scoring boundary (S1-07a). Scorer-side only: never imported by the review pipeline."""

from .cutoff import resolve_cutoff, select_cases
from .errors import BenchmarkError
from .loader import Source, load_proposal, load_source
from .pins import load_pins, verify_file
from .projection import project_metadata, resolve_versions
from .reference_graph import score_reference_case, score_reference_suite
from .scoring import score_case, score_suite

__all__ = ["BenchmarkError", "Source", "load_pins", "load_proposal", "load_source", "project_metadata",
           "resolve_cutoff", "resolve_versions", "score_case", "score_reference_case", "score_reference_suite", "score_suite", "select_cases", "verify_file"]
