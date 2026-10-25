"""Bounded read-only snapshot tools for the investigator (owner: S0-06).

list_files / read_file / search_literal / diff over explicit pinned base and head views.
See orchestration/handoffs/S0-06.md for the API, limits and what a partial view means.
"""

from .ops import Limits
from .session import TOOLS, ArgError, ToolCall, ToolSession, normalize
from .view import (PARTIAL_NOTE, Layer, View, ViewError, capture_historical_pins, full_view,
                   historical_input_view, make_layer)

__all__ = ["ArgError", "Layer", "Limits", "PARTIAL_NOTE", "TOOLS", "ToolCall", "ToolSession", "View",
           "ViewError", "capture_historical_pins", "full_view", "historical_input_view", "make_layer", "normalize"]
