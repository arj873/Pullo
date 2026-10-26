"""Host-only bridge from a trusted historical corpus case to pipeline inputs (owner: S0B-02a).

Pins are captured once at trusted import time and stored outside the corpus; `materialize` validates the
case against them and writes two read-only side union snapshots. The output is partial coverage, never a
full repository. It is not wired into the pipeline: see orchestration/handoffs/S0B-02a-interface.md.
"""

from .bridge import BridgeLimits, HistoricalBridge, discard, materialize, union_entries
from .pins import BridgeError, capture_bridge_pins, check_pins, load_pins, write_pins

__all__ = ["BridgeError", "BridgeLimits", "HistoricalBridge", "capture_bridge_pins", "check_pins", "discard",
           "load_pins", "materialize", "union_entries", "write_pins"]
