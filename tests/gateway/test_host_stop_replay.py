"""LIVE-DEADLINE-02: the host.stop trace event validates strictly; legacy traces without it load unchanged."""

from __future__ import annotations

import unittest

from reviewer.contracts import validate


def stop(**kw):
    ev = {"schema": "trace-event@1", "runId": "run_" + "0" * 16, "seq": 5, "type": "host.stop", "stage": "VERIFY",
          "scope": "model", "code": "stage-deadline", "afterSeq": 4}
    ev.update(kw)
    return ev


class HostStopEvent(unittest.TestCase):
    def test_well_formed_stop_validates(self):
        self.assertEqual(validate("TraceEvent", stop()), [])
        for code in ("cancelled", "hard-deadline", "stage-deadline", "soft-deadline"):
            self.assertEqual(validate("TraceEvent", stop(code=code)), [], code)

    def test_position_must_be_the_immediately_preceding_event(self):
        for after in (3, 5, 6):
            self.assertTrue(validate("TraceEvent", stop(afterSeq=after)), after)

    def test_unknown_scope_code_stage_and_extra_keys_are_rejected(self):
        for bad in ({"scope": "everywhere"}, {"code": "deadline-exceeded"}, {"stage": "LEARNX"}, {"extra": 1},
                    {"afterSeq": True}, {"afterSeq": -1}):
            self.assertTrue(validate("TraceEvent", stop(**bad)), bad)
