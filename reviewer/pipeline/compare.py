"""Entity-aware comparison of a replay against its pinned recording, stage by stage.

The recording is split into the stage segments the engine always writes: run.start, then for each of the eight
stages [stage.start .. checkpoint], then run.end. A replay recomputes every event itself (requests are rebuilt
and matched by the gateway, tools are re-executed on the pinned snapshots, Findings/Comments rebuilt) and each
stage's events must equal the recorded stage's events after `canonical.comparable` strips only the fields
that legitimately differ (run id, timestamps, latency, replayed cost basis). Nothing is copied from the recording.
"""

from __future__ import annotations

from reviewer.contracts.canonical import comparable
from reviewer.contracts.stages import STAGES

from .errors import PipelineError


def segment(events: list, stage: str) -> list:
    start = next((i for i, e in enumerate(events) if e["type"] == "stage.start" and e["stage"] == stage), None)
    if start is None:
        return []
    for j in range(start, len(events)):
        if events[j]["type"] == "checkpoint" and events[j]["stage"] == stage:
            return events[start:j + 1]
    return events[start:]


def split_recording(events: list) -> dict[str, list]:
    """-> {stage: events}. PipelineError('replay-recording') unless the recording is exactly
    run.start + eight contiguous complete stage segments + run.end (no stray or missing events)."""
    if not events or events[0]["type"] != "run.start" or events[-1]["type"] != "run.end":
        raise PipelineError("replay-recording", "recording is not run.start ... run.end")
    out, pos = {}, 1
    for st in STAGES:
        seg = segment(events[pos:], st)
        if not seg or seg[0]["type"] != "stage.start" or seg[-1]["type"] != "checkpoint" or seg[0] is not events[pos]:
            raise PipelineError("replay-recording", f"recording has no contiguous complete {st} segment")
        if any(e["type"] in ("stage.start", "run.start", "run.end") for e in seg[1:]) \
                or sum(1 for e in seg if e["type"] == "stage.end") != 1:
            raise PipelineError("replay-recording", f"{st} segment is malformed")
        out[st] = seg
        pos += len(seg)
    if pos != len(events) - 1:
        raise PipelineError("replay-recording", "recording has events outside the stage segments")
    return out


def first_difference(recorded: list, replayed: list) -> str | None:
    """None when both event lists are equal under entity-aware comparison, else a short reason."""
    for i in range(max(len(recorded), len(replayed))):
        if i >= len(replayed):
            return f"recorded {recorded[i]['type']} event #{i} was never reproduced (unconsumed)"
        if i >= len(recorded):
            return f"replay produced an extra {replayed[i]['type']} event #{i} not in the recording"
        if comparable(recorded[i], "TraceEvent") != comparable(replayed[i], "TraceEvent"):
            ev = replayed[i]
            what = ev.get("callId") or ev.get("toolCallId") or ev.get("stage") or ev["type"]
            return f"{ev['type']} event #{i} ({what}) differs from the recording"
    return None
