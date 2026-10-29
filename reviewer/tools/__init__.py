"""Bounded read-only snapshot tools for the investigator (owner: S0-06).

list_files / read_file / search_literal / diff over explicit pinned base and head views; in impact mode also
find_references (model) and impact_scan (host-only PREPARE pre-pass); heuristics in reviewer.impactmap.
See orchestration/handoffs/S0-06.md for the API, limits and what a partial view means.
"""

from .ops import Limits
from .session import ALL_TOOLS, HOST_IMPACT_TOOLS, IMPACT_TOOLS, SWEEP_TOOLS, TOOLS, ArgError, ToolCall, ToolSession, normalize
from .view import (PARTIAL_NOTE, Layer, View, ViewError, capture_historical_pins, full_view, import_view, omissions_from_records,
                   historical_input_view, make_layer, partial_union_view)

__all__ = ["ALL_TOOLS", "HOST_IMPACT_TOOLS", "IMPACT_TOOLS", "ArgError", "Layer", "Limits", "PARTIAL_NOTE", "SWEEP_TOOLS", "TOOLS", "ToolCall", "ToolSession", "View",
           "ViewError", "capture_historical_pins", "full_view", "import_view", "omissions_from_records", "historical_input_view", "make_layer", "normalize",
           "partial_union_view"]
