"""Independent acceptance controls for GW-02 (NEW2 profile binding, NEW3 replayOf, NEW4 single run.start, NEW5 post-load
mutation, NEW6 effect-free refusals). Reviewer-owned, offline, stdlib only, no provider/network.

Narrow additions only: the NEWn repros themselves live in test_gateway_rereview.NewDefects and
test_gateway_s102_review.Forgery. Conventions as in test_gateway_s102_review.py (`test_OPEN_*` = still-open defect,
expectedFailure, asserts the CORRECT behaviour). Builders: tests/gateway/helpers.py (read-only data builders) and
test_gateway_rereview.Direct (explicit book, independently computed pin; no author Env).

Run: nice -n 19 python3 -m unittest discover -s tests/gateway_review -p 'test_gateway_gw02_review.py' -v
"""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.gateway_review import test_gateway_rereview as R  # noqa: E402  (module import: its tests are not re-collected)
from tests.gateway_review import test_gateway_s102_review as S  # noqa: E402
from reviewer.gateway import (Gateway, GatewayConfigError, Recorder, SpendBook, TraceError, load_trace,  # noqa: E402
                              verify_events)
from tests.gateway import helpers as H  # noqa: E402

INV = R.INV
LATER = "2099-01-01T00:00:00Z"


class Gw(S.Rv):
    def sealed(self, n=1):
        gw = self.live(H.entry(response=S.good(n)))
        S.rcall(gw)
        events, pin = self.seal(gw)
        return gw, events, pin

    def replayer(self, tr, pin, *, run=None, **kw):
        rd = run or R.rundoc(9100, mode="strict-replay", replay_of=tr.run_id)
        rec = Recorder(rd["id"])
        rec.start(rd)
        gw = Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                     recorder=rec, expected_trace_digest=pin, **kw)
        gw.rd = rd
        return gw


# ============================================================================================ NEW2 / NEW3
class RunBinding(Gw):
    PROFILES = {"other id": "someone-else@{v}", "same id, other version": "{id}@999", "absent": None}

    def _profile(self, form):
        p = self.PROFILES[form]
        return None if p is None else p.format(id=H.PROFILE["id"], v=H.PROFILE["version"])

    def test_NEW2_every_wrong_profile_is_refused_in_live_replay_and_disabled_and_the_true_one_is_admitted(self):
        h = self.handle()
        _, events, pin = self.sealed()
        tr = load_trace(events)
        builds = {
            "live": lambda rd: Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"],
                                       providers=self.synth(H.entry(response=S.good(1))), authorization=h,
                                       book=SpendBook(h), recorder=rec, clock=lambda: R.NOW),
            "strict-replay": lambda rd: Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET,
                                                run_id=rd["id"], replay=tr, recorder=rec, expected_trace_digest=pin),
            "disabled": lambda rd: Gateway(mode="disabled", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"],
                                           recorder=rec),
        }
        for mode, build in builds.items():
            for form in self.PROFILES:
                with self.subTest(mode=mode, profile=form):
                    rd = R.rundoc(31, mode="live" if mode == "disabled" else mode, auth_digest=h.digest,
                                  replay_of=tr.run_id)
                    if self.PROFILES[form] is None:
                        rd.pop("profile")
                    else:
                        rd["profile"] = self._profile(form)
                    rec = Recorder(rd["id"])
                    try:
                        rec.start(rd)
                    except Exception:      # noqa: BLE001 - the contract refusing the run.start is equally acceptable
                        continue
                    with self.assertRaises(GatewayConfigError):
                        build(rd)
            with self.subTest(mode=mode, profile="trusted"):
                rd = R.rundoc(32, mode="live" if mode == "disabled" else mode, auth_digest=h.digest,
                              replay_of=tr.run_id)
                self.assertEqual(rd["profile"], f"{H.PROFILE['id']}@{H.PROFILE['version']}")
                rec = Recorder(rd["id"])
                rec.start(rd)
                gw = build(rd)
                r = S.rcall(gw)
                if mode == "disabled":
                    self.assertEqual(r.error["code"], "live-calls-disabled")
                else:
                    self.assertEqual(r.output, S.inv_out(1))

    def test_NEW3_replay_of_another_genuine_recording_or_missing_is_refused_and_no_recording_is_consumed(self):
        _, events_a, pin_a = self.sealed(1)
        _, events_b, _ = self.sealed(2)
        tr = load_trace(events_a)
        other = load_trace(events_b).run_id
        self.assertNotEqual(other, tr.run_id)
        for name, replay_of in (("another genuine recording", other), ("missing", None)):
            with self.subTest(replayOf=name):
                rd = R.rundoc(33, mode="strict-replay", replay_of=replay_of)
                if replay_of is None:
                    rd.pop("replayOf")
                try:
                    self.replayer(tr, pin_a, run=rd)
                except GatewayConfigError:
                    continue
                except Exception:          # noqa: BLE001 - the contract refusing the run.start is equally acceptable
                    continue
                self.fail("strict replay constructed under a run.start naming another recording")
        # late-written wrong replayOf: refused per attempt, nothing appended, recording stays unconsumed
        rd = R.rundoc(34, mode="strict-replay", replay_of=other)
        rec = Recorder(rd["id"])
        gw = Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                     recorder=rec, expected_trace_digest=pin_a)
        rec.start(rd)
        r = S.rcall(gw)
        self.assertEqual((r.error["code"], gw.unconsumed(), [e["type"] for e in rec.events]),
                         ("contract-violation", 1, ["run.start"]))
        rec.events[0]["run"]["replayOf"] = tr.run_id                  # binding repaired in memory
        self.assertEqual(S.rcall(gw).output, S.inv_out(1))
        self.assertEqual(gw.unconsumed(), 0)


# ============================================================================================ NEW4
class SingleRunStart(Gw):
    def test_NEW4_an_identical_second_run_start_is_refused_from_every_source_and_partial_loads(self):
        gw = self.live(H.entry(response=S.good(1)))
        S.rcall(gw)
        gw.recorder.start(copy.deepcopy(gw.rd))      # byte-identical run document, not a conflicting one
        partial = copy.deepcopy(gw.recorder.events)
        gw.recorder.end("completed")
        for name, src, kw in (("path", gw.path, {}), ("bytes", gw.path.read_bytes(), {}),
                              ("events", gw.recorder.events, {}), ("partial", partial, {"allow_partial": True})):
            with self.subTest(source=name), self.assertRaises(TraceError) as cm:
                load_trace(src, **kw)
            self.assertIn("run.start", str(cm.exception))

    def test_CONTROL_single_run_start_loads_and_replays(self):
        gw, events, pin = self.sealed()
        self.assertEqual([e["type"] for e in events].count("run.start"), 1)
        self.assertEqual(S.rcall(self.replayer(load_trace(gw.path), pin)).output, S.inv_out(1))


# ============================================================================================ NEW5
class PostLoadMutation(Gw):
    def test_NEW5_mutation_after_gateway_construction_never_reaches_the_running_gateway(self):
        gw, events, pin = self.sealed()
        tr = load_trace(gw.path)
        rp = self.replayer(tr, pin)
        for ev in tr.events:                                          # schema-valid answer AND a matching cost edit
            if ev["type"] == "model.call":
                ev["response"]["output"] = S.inv_out(7)
            elif ev["type"] == "cost":
                ev["record"]["usdMicros"] = 1
        r = S.rcall(rp)
        self.assertEqual(r.output, S.inv_out(1))
        self.assertEqual(rp.report()["replayedUsdMicros"], gw.report()["newSpendUsdMicros"])
        self.assertEqual((rp.report()["liveCalls"], rp.unconsumed()), (0, 0))
        with self.assertRaises(TraceError):                           # and the mutated object cannot start another
            self.replayer(tr, pin, run=R.rundoc(9101, mode="strict-replay", replay_of=tr.run_id))

    def test_NEW5_mutating_a_non_call_event_or_only_the_calls_index(self):
        gw, events, pin = self.sealed()
        tr = load_trace(gw.path)
        next(e for e in tr.events if e["type"] == "run.end")["status"] = "failed"
        with self.assertRaises(TraceError):
            self.replayer(tr, pin)
        tr = load_trace(gw.path)                                      # index-only swap: the gateway rebuilds from events
        for lst in tr.calls.values():
            forged = copy.deepcopy(lst[0])
            forged["response"]["output"] = S.inv_out(7)
            lst[0] = forged
        self.assertEqual(S.rcall(self.replayer(tr, pin)).output, S.inv_out(1))

    def test_CONTROL_reverted_mutation_and_trusted_reload_with_explicit_repin(self):
        gw, events, pin = self.sealed()
        tr = load_trace(gw.path)
        ev = next(iter(tr.calls.values()))[0]
        kept = copy.deepcopy(ev["response"]["output"])
        ev["response"]["output"] = S.inv_out(7)
        ev["response"]["output"] = kept
        self.assertEqual(S.rcall(self.replayer(tr, pin)).output, S.inv_out(1))
        edited = copy.deepcopy(events)                                # trusted edit = new bytes, re-loaded, re-pinned
        for e in edited:
            if e["type"] == "model.call":
                e["response"]["output"] = S.inv_out(9)
        p = self.tampered_file("gw02-trusted.jsonl", edited)
        with self.assertRaises(TraceError):
            self.replayer(load_trace(p), pin)
        self.assertEqual(S.rcall(self.replayer(load_trace(p), R.sha(p.read_bytes()))).output, S.inv_out(9))

    @unittest.expectedFailure
    def test_OPEN_NEW7_verify_events_with_the_genuine_bytes_binds_the_pin_to_other_events(self):
        """OPEN (Low, found by GW-02-review). The public, exported verify_events(events, data) takes the byte digest from
        `data` without checking that `events` are those bytes, so a schema-valid forged event list passes the
        original pin. Product code reaches strict replay only via load_trace(path|bytes), which parses `events`
        from `data`; LoadedTrace(...) construction and byte_digest reassignment are the same class (not tested)."""
        gw, events, pin = self.sealed()
        forged = copy.deepcopy(events)
        for e in forged:
            if e["type"] == "model.call":
                e["response"]["output"] = S.inv_out(7)
        try:
            rp = self.replayer(verify_events(forged, gw.path.read_bytes()), pin)
        except TraceError:
            return
        self.assertNotEqual(S.rcall(rp).output, S.inv_out(7), "forged events served under the genuine pin")


# ============================================================================================ NEW6
class EffectFreeRefusals(Gw):
    """Every refusal reached before provider contact, against a recorder whose run.start (written after construction)
    names another authorization: nothing appended, no contact, no reservation, no guard call, coordinate reusable."""

    NAMES = ("non-object request", "schema-invalid request", "request profile differs", "params over the role cap",
             "authorization expired", "no adapter")

    def _case(self, bound: bool):
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = R.rundoc(41, auth_digest=h.digest if bound else other.digest)
        rec = Recorder(rd["id"])
        provs = self.synth(H.entry(response=S.good(1)))
        clock = [R.NOW]
        guarded = []
        gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                     authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: clock[0],
                     guard=lambda ctx: guarded.append(ctx))
        rec.start(rd)
        return gw, rec, provs["synthetic"], clock, guarded, h

    def _refusals(self, gw, clock):
        """name -> (setup, request, restore). Each produces a refusal before provider contact."""
        over_cap = H.request()
        over_cap["params"] = {**(over_cap.get("params") or {}),
                              "maxOutputTokens": H.PROFILE["roles"]["investigator"]["caps"]["maxOutputTokens"] + 1}
        wrong_profile = H.request()
        wrong_profile["profile"] = "someone-else@1"
        not_schema = H.request()
        not_schema["unexpectedField"] = 1
        saved = {}

        def expire():
            clock[0] = LATER

        def unexpire():
            clock[0] = R.NOW

        def drop_adapter():
            saved["p"] = gw.providers.pop("synthetic")

        def restore_adapter():
            gw.providers["synthetic"] = saved["p"]
        nop = lambda: None                                            # noqa: E731
        return {"non-object request": (nop, ["not", "a", "dict"], nop),
                "schema-invalid request": (nop, not_schema, nop),
                "request profile differs": (nop, wrong_profile, nop),
                "params over the role cap": (nop, over_cap, nop),
                "authorization expired": (expire, H.request(), unexpire),
                "no adapter": (drop_adapter, H.request(), restore_adapter)}

    def test_NEW6_every_early_refusal_into_a_misbound_recorder_is_effect_free(self):
        for name in self.NAMES:
            with self.subTest(refusal=name):
                gw, rec, prov, clock, guarded, h = self._case(bound=False)
                setup, req, restore = self._refusals(gw, clock)[name]
                setup()
                r = gw.call(*INV, 0, req)
                restore()
                self.assertFalse(r.ok)
                self.assertEqual([e["type"] for e in rec.events], ["run.start"])
                self.assertEqual((prov.calls, guarded, gw.report()["liveCalls"]), (0, [], 0))
                t = gw.book.totals()
                self.assertEqual(t["committed"] + t["inflight"], 0)
                rec.events[0]["run"]["spendAuthorization"] = h.digest  # binding repaired in memory
                self.assertEqual(gw.call(*INV, 0, H.request()).output, S.inv_out(1),
                                 "the refused attempt consumed the coordinate or the scripted answer")
                self.assertEqual((prov.calls, len(guarded)), (1, 1))

    def test_CONTROL_the_same_refusals_into_a_bound_recorder_are_still_recorded_errors(self):
        for name in self.NAMES:
            with self.subTest(refusal=name):
                gw, rec, prov, clock, guarded, _ = self._case(bound=True)
                setup, req, restore = self._refusals(gw, clock)[name]
                setup()
                r = gw.call(*INV, 0, req)
                restore()
                self.assertEqual([e["type"] for e in rec.events], ["run.start", "error"])
                self.assertEqual(rec.events[1]["error"]["code"], r.error["code"])
                self.assertEqual((prov.calls, guarded), (0, []))

    def test_NEW6_misbound_replay_recorder_consults_no_guard_and_consumes_nothing(self):
        gw, events, pin = self.sealed()
        tr = load_trace(gw.path)
        rd = R.rundoc(9102, mode="strict-replay", replay_of=tr.run_id)
        rec = Recorder(rd["id"])
        guarded = []
        rp = Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                     recorder=rec, expected_trace_digest=pin, guard=lambda ctx: guarded.append(ctx))
        rec.start({**rd, "profile": "someone-else@9"})
        r = S.rcall(rp)
        self.assertEqual((r.error["code"], [e["type"] for e in rec.events], guarded, rp.unconsumed()),
                         ("contract-violation", ["run.start"], [], 1))
        rec.events[0]["run"]["profile"] = rd["profile"]
        self.assertEqual(S.rcall(rp).output, S.inv_out(1))
        self.assertEqual((len(guarded), rp.unconsumed()), (1, 0))


if __name__ == "__main__":
    unittest.main()
