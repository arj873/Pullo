"""LIVE-DEADLINE-02: trusted pilot/repository controls for stage ceilings and host-stop recording."""

from __future__ import annotations

import unittest

from reviewer.contracts.budget import HOST_STOP_RECORDING
from reviewer.pilot import live_plan, live_profile
from reviewer.pilot.profile import LIVE_STAGE_CEILINGS_SEC, MODEL, ProfileError
from reviewer.pilot.repository_profile import repository_plan, repository_profile


class LivePlan(unittest.TestCase):
    def setUp(self):
        self.profile = live_profile(MODEL)

    def test_default_plan_has_no_new_keys(self):
        b = live_plan(self.profile)["budget"]
        self.assertNotIn("stageCeilingsSec", b)
        self.assertNotIn("hostStopRecording", b)
        self.assertEqual((b["wallClockSec"], b["softDeadlineSec"], b["maxUsdMicros"]), (1200, 900, 4_000_000))

    def test_explicit_options_are_validated_and_leave_money_models_and_deadlines_alone(self):
        base = live_plan(self.profile)
        p = live_plan(self.profile, stage_ceilings_sec={"VERIFY": 300}, host_stop_recording=True)
        self.assertEqual(p["budget"]["stageCeilingsSec"], {"VERIFY": 300})
        self.assertEqual(p["budget"]["hostStopRecording"], HOST_STOP_RECORDING)
        for k in ("maxUsdMicros", "wallClockSec", "softDeadlineSec", "maxRetriesPerCall", "verifyReserveBp"):
            self.assertEqual(p["budget"][k], base["budget"][k])
        self.assertEqual(p["modelProfile"], base["modelProfile"])
        for bad in ({}, {"LEARN": 5}, {"VERIFY": 1201}, {"VERIFY": True}):
            with self.assertRaises(ProfileError):
                live_plan(self.profile, stage_ceilings_sec=bad)

    def test_repository_live_stage_timing_is_opt_in_and_pins_both_controls(self):
        prof = repository_profile(True)
        legacy = repository_plan(prof)
        self.assertEqual(legacy, repository_plan(prof, live_stage_timing=False))
        self.assertNotIn("stageCeilingsSec", legacy["budget"])
        live = repository_plan(prof, live_stage_timing=True)
        self.assertEqual(live["budget"]["stageCeilingsSec"], {"INVESTIGATE": 300, "VERIFY": 300, "JUDGE": 200})
        self.assertEqual(live["budget"]["stageCeilingsSec"], LIVE_STAGE_CEILINGS_SEC)
        self.assertEqual(live["budget"]["hostStopRecording"], HOST_STOP_RECORDING)
        self.assertEqual({k: v for k, v in live["budget"].items() if k not in ("stageCeilingsSec", "hostStopRecording")},
                         legacy["budget"])
        self.assertEqual((live["budget"]["wallClockSec"], live["budget"]["softDeadlineSec"]), (1200, 900))
