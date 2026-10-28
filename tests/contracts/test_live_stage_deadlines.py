"""LIVE-DEADLINE-02: Plan budget stageCeilingsSec / hostStopRecording validation and the legacy-preserving lookup."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from reviewer.contracts import validate
from reviewer.contracts.budget import (HOST_STOP_RECORDING, HOST_STOP_RECORDING_V1, HOST_STOP_RECORDING_V2,
                                       stage_ceiling, stage_deadline_exceeded)
from reviewer.contracts.canonical import digest
from reviewer.contracts.stages import STAGE_CEILING_SEC

EX = Path(__file__).resolve().parents[2] / "reviewer/contracts/examples"
PLAN = json.loads((EX / "Plan.json").read_text())


def budget(**kw):
    b = copy.deepcopy(PLAN["budget"])
    b.update(kw)
    return b


class Ceilings(unittest.TestCase):
    def test_absent_key_is_exactly_the_legacy_table(self):
        for st, sec in STAGE_CEILING_SEC.items():
            self.assertEqual(stage_ceiling(st, budget()), sec)
            self.assertEqual(stage_ceiling(st), sec)
        self.assertTrue(stage_deadline_exceeded("VERIFY", 45.0, budget()))
        self.assertFalse(stage_deadline_exceeded("VERIFY", 44.9))

    def test_listed_stage_replaces_and_unlisted_keeps_the_table(self):
        b = budget(stageCeilingsSec={"VERIFY": 300, "JUDGE": 200})
        self.assertEqual((stage_ceiling("VERIFY", b), stage_ceiling("JUDGE", b), stage_ceiling("INVESTIGATE", b)),
                         (300, 200, 120))
        self.assertFalse(stage_deadline_exceeded("VERIFY", 299.9, b))
        self.assertTrue(stage_deadline_exceeded("VERIFY", 300.0, b))

    def test_valid_configs_pass(self):
        self.assertEqual(validate("Budget", budget(stageCeilingsSec={"VERIFY": 300})), [])
        self.assertEqual(validate("Budget", budget(stageCeilingsSec={"VERIFY": 360})), [])         # == wallClockSec
        self.assertEqual(validate("Budget", budget(hostStopRecording=HOST_STOP_RECORDING)), [])
        for v in (HOST_STOP_RECORDING_V1, HOST_STOP_RECORDING_V2):                       # both known versions load explicitly
            self.assertEqual(validate("Budget", budget(hostStopRecording=v)), [])
        self.assertEqual(HOST_STOP_RECORDING, HOST_STOP_RECORDING_V2)                    # latest recording policy is @2

    def test_host_stop_gate_ordinal_shape(self):
        from reviewer.contracts import validate as v
        ev = {"schema": "trace-event@1", "runId": "run_" + "0" * 16, "seq": 5, "type": "host.stop", "stage": "VERIFY",
              "scope": "tool", "code": "stage-deadline", "afterSeq": 4}
        self.assertEqual(v("TraceEvent", ev), [])                                        # v1 shape: no ordinal
        self.assertEqual(v("TraceEvent", {**ev, "gateOrdinal": 2}), [])
        for bad in (0, -1, True, 1.5, "2", None, 10**9 + 1):
            self.assertTrue(v("TraceEvent", {**ev, "gateOrdinal": bad}), bad)

    def test_invalid_configs_are_refused(self):
        for bad in ({}, {"LEARN": 10}, {"NOPE": 10}, {"VERIFY": True}, {"VERIFY": 1.5}, {"VERIFY": "300"},
                    {"VERIFY": 0}, {"VERIFY": -1}, {"VERIFY": 361}, {"VERIFY": 10**12}, [], "VERIFY", None):
            self.assertTrue(validate("Budget", budget(stageCeilingsSec=bad)), bad)
        for bad in ("host-stop@3", "host-stop@0", True, 1, None):
            self.assertTrue(validate("Budget", budget(hostStopRecording=bad)), bad)

    def test_explicit_fields_change_the_plan_digest_and_absence_does_not(self):
        base = copy.deepcopy(PLAN)
        with_key = copy.deepcopy(PLAN)
        with_key["budget"]["stageCeilingsSec"] = {"VERIFY": 300}
        rec = copy.deepcopy(PLAN)
        rec["budget"]["hostStopRecording"] = HOST_STOP_RECORDING
        self.assertEqual(len({digest(base), digest(with_key), digest(rec)}), 3)
        self.assertEqual(validate("Plan", base), [])
        self.assertEqual(validate("Plan", with_key), [])
