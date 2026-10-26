"""GW-02: recorder/run binding (profile, replayOf), single run.start, post-load mutation, effect-free refusals."""

from __future__ import annotations

import copy
import unittest

from reviewer.gateway import (Gateway, GatewayConfigError, Recorder, TraceError, bytes_digest, events_to_bytes,
                              load_trace)
from tests.gateway.helpers import (BUDGET, PROFILE, Env, entry, replay_run_doc, request, response, run_doc, script,
                                   verifier_out)

INV = ("INVESTIGATE", "investigator", "generalist")
FORGED = {"hypotheses": [{"claim": "forged", "category": "bug", "suspectedSeverity": "P1", "impact": "crash",
                          "location": {"path": "src/f7.py", "line": 8},
                          "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16}]}]}


class Binding(Env):
    def sealed(self):
        gw = self.live(script(entry(response=response())))
        gw.call(*INV, 0, request())
        return self.finish(gw)

    def test_profile_in_run_start_must_be_the_gateways_profile(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        rd["profile"] = "someone-else@9"
        rec = Recorder(rd["id"])
        rec.start(rd)
        with self.assertRaises(GatewayConfigError):
            self.live_with(rec, rd, h)

    def live_with(self, rec, rd, h):
        from reviewer.gateway import SpendBook, default_providers
        return Gateway(mode="live", profile=PROFILE, budget=BUDGET, run_id=rd["id"],
                       providers=default_providers(script(entry(response=response()))), authorization=h,
                       book=SpendBook(h), recorder=rec, clock=lambda: "2026-10-25T12:00:00Z")

    def test_late_run_start_with_another_profile_admits_nothing_and_writes_nothing(self):
        h = self.handle()
        rd = run_doc("live", auth_digest=h.digest)
        rec = Recorder(rd["id"])
        gw = self.live_with(rec, rd, h)
        rec.start({**rd, "profile": "someone-else@9"})
        r = gw.call(*INV, 0, request())
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual([e["type"] for e in rec.events], ["run.start"])

    def test_strict_replay_run_start_must_name_the_recorded_run(self):
        events = self.sealed()
        tr = load_trace(events)
        for replay_of in ("run_" + "e" * 16, None):
            rd, evr = replay_run_doc(tr.run_id)
            rd["replayOf"] = replay_of
            if replay_of is None:
                del rd["replayOf"]
            rec = Recorder(rd["id"])
            try:
                rec.start(rd)
            except Exception:
                continue                          # the contract itself refuses it: nothing to bind
            with self.subTest(replay_of=replay_of), self.assertRaises(GatewayConfigError):
                Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id=rd["id"], replay=tr, recorder=rec,
                        expected_trace_digest=bytes_digest(events_to_bytes(events)))

    def test_strict_replay_with_the_right_replayOf_still_serves(self):
        events = self.sealed()
        self.assertTrue(self.replayer(events).call(*INV, 0, request()).ok)

    def test_a_second_run_start_makes_the_trace_unloadable(self):
        events = self.sealed()
        ev = copy.deepcopy(events)
        extra = copy.deepcopy(ev[0])
        extra["seq"] = len(ev) - 1
        extra["run"] = {**extra["run"], "spendAuthorization": "sha256:" + "9" * 64}
        ev.insert(len(ev) - 1, extra)
        ev[-1]["seq"] = len(ev) - 1
        with self.assertRaisesRegex(TraceError, "duplicate run.start"):
            load_trace(ev)

    def test_mutating_a_loaded_trace_to_a_schema_valid_answer_is_refused_under_the_original_pin(self):
        events = self.sealed()
        pin = bytes_digest(events_to_bytes(events))
        tr = load_trace(events)
        for lst in tr.calls.values():
            lst[0]["response"]["output"] = copy.deepcopy(FORGED)
        with self.assertRaisesRegex(TraceError, "changed after load"):
            self._replay_loaded(tr, pin)

    def _replay_loaded(self, tr, pin):
        rd, evr = replay_run_doc(tr.run_id)
        rec = Recorder(rd["id"])
        rec.start(rd)
        return Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id=rd["id"], replay=tr, recorder=rec,
                       expected_trace_digest=pin)

    def test_mutation_after_construction_does_not_reach_the_running_gateway(self):
        events = self.sealed()
        tr = load_trace(events)
        rp = self._replay_loaded(tr, bytes_digest(events_to_bytes(events)))
        for lst in tr.calls.values():
            lst[0]["response"]["output"] = copy.deepcopy(FORGED)
        r = rp.call(*INV, 0, request())
        self.assertTrue(r.ok)
        self.assertEqual(r.output, response()["output"])

    def test_trusted_explicit_repin_of_an_edited_trace_still_serves_the_edit(self):
        events = self.sealed()
        edited = copy.deepcopy(events)
        for e in edited:
            if e["type"] == "model.call":
                e["response"]["output"] = copy.deepcopy(FORGED)
        repin = bytes_digest(events_to_bytes(edited))
        self.assertNotEqual(repin, bytes_digest(events_to_bytes(events)))
        tr = load_trace(edited)
        r = self._replay_loaded(tr, repin).call(*INV, 0, request())
        self.assertEqual(r.output, FORGED)
        with self.assertRaises(TraceError):                           # the old pin does not cover the edit
            self._replay_loaded(load_trace(edited), bytes_digest(events_to_bytes(events)))

    def test_refusals_never_append_into_a_misbound_recorder(self):
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = run_doc("live", auth_digest=other.digest)
        rec = Recorder(rd["id"])
        from reviewer.gateway import SpendBook, default_providers
        gw = Gateway(mode="live", profile=PROFILE, budget=BUDGET, run_id=rd["id"],
                     providers=default_providers(script(entry(response=response()))), authorization=h,
                     book=SpendBook(h), recorder=rec, clock=lambda: "2026-10-25T12:00:00Z")
        rec.start(rd)
        bad = request()
        bad["profile"] = "someone-else@1"
        for req in (bad, [], request()):
            self.assertFalse(gw.call(*INV, 0, req).ok)
        self.assertEqual([e["type"] for e in rec.events], ["run.start"])
        self.assertEqual(gw.report()["liveCalls"], 0)


if __name__ == "__main__":
    unittest.main()
