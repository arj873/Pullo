"""Strict replay must fail closed: pin, recording structure, request/tool/response tamper, missing, duplicated and
unconsumed events, and any drift of inputs or configuration. Edited recordings are re-pinned on purpose (a caller who
trusts the edited bytes), so the failure must come from the replay logic, not from the pin."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from reviewer.contracts.canonical import call_id, cost_id, digest, request_hash
from reviewer.gateway import bytes_digest, events_to_bytes, load_trace
from reviewer.pipeline import PipelineError, ReplayBackend, read_recording_receipt

from .helpers import (EVR2, PLAN, PROFILE, Rig, events_of, hid, hyp, inv, judge, model_calls, script, ver)


def renumber(events):
    for i, e in enumerate(events):
        e["seq"] = i
    return events


class Base(Rig):
    def setUp(self):
        super().setUp()
        self.m = self.mini()
        self.h0, self.h1 = hyp(self.m, "src/a.py", 2, claim="first"), hyp(self.m, "src/a.py", 5, claim="second")
        self.scr = script(inv(self.h0, self.h1), ver(0, self.m, path="src/a.py", line=2),
                          ver(1, self.m, path="src/a.py", line=5),
                          judge({"findingIds": [hid(0, self.h0)], "title": "A", "body": "b"},
                                {"findingIds": [hid(1, self.h1)], "title": "B", "body": "b"}))
        self.rec, self.spy = self.record(self.m, self.scr)
        self.assertEqual((self.rec.status, len(self.rec.comments)), ("completed", 2))

    def tampered_replay(self, fn, name="edited.jsonl"):
        path, dig = self.edited_copy(self.rec, name, fn)
        return self.replay(self.m, self.rec, trace_path=path, digest=dig)

    def assert_failed_closed(self, res, code, stage):
        self.assertEqual(res.status, "failed")
        self.assertEqual(res.error["code"], code)
        self.assertEqual(res.error["stage"], stage)
        self.assertEqual(res.stages[stage]["status"], "failed")
        self.assertEqual(res.comments, [])
        self.assertEqual(json.loads(Path(res.comments_path).read_text())["comments"], [])
        self.assertEqual(self.spy.calls, 4)                         # replay never called the provider
        self.assertEqual(events_of(res)[-1]["status"], "failed")
        self.assertIn("did not finish", Path(res.review_path).read_text())
        later = [s for s in ("TRIAGE", "INVESTIGATE", "VERIFY", "JUDGE") if list(res.stages).index(s) > list(res.stages).index(stage)]
        self.assertTrue(all(res.stages[s]["status"] == "skipped" for s in later), res.stages)


class Pin(Base):
    def test_wrong_or_missing_pin_is_refused_before_a_run_directory_exists(self):
        before = sorted(p.name for p in self.out.iterdir())
        for bad in ("sha256:" + "0" * 64, bytes_digest(b"other"), None, "nope"):
            with self.assertRaises(PipelineError) as cm:
                ReplayBackend(self.rec.trace_path, bad)
            self.assertEqual(cm.exception.code, "replay-pin")
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), before)

    def test_editing_the_recording_without_repinning_is_refused(self):
        path, _ = self.edited_copy(self.rec, "e.jsonl", lambda ev: ev[0].update(seq=0))
        data = Path(path).read_bytes().replace(b'"claim": "first"', b'"claim": "frist"')
        Path(path).write_bytes(data)
        with self.assertRaises(PipelineError) as cm:
            ReplayBackend(path, self.rec.receipt["traceDigest"])
        self.assertEqual(cm.exception.code, "replay-pin")

    def test_a_pin_computed_from_the_untrusted_trace_inside_its_own_directory_is_refused_unless_opted_in(self):
        with self.assertRaises(PipelineError) as cm:
            read_recording_receipt(self.rec.receipt_path, self.rec.run_dir)
        self.assertEqual(cm.exception.code, "replay-pin")
        dig, src = read_recording_receipt(self.rec.receipt_path, self.rec.run_dir, allow_colocated=True)
        self.assertEqual((dig, src), (self.rec.receipt["traceDigest"], "colocated-receipt"))
        elsewhere = self.tmp / "operator" / "pins.json"
        elsewhere.write_text(json.dumps({"traceDigest": self.rec.receipt["traceDigest"]}))
        dig2, src2 = read_recording_receipt(elsewhere, self.rec.run_dir)
        self.assertEqual((dig2, src2), (dig, "receipt"))
        rep = self.replay(self.m, self.rec)
        self.assertEqual(rep.status, "completed")
        backend = ReplayBackend(self.rec.trace_path, dig2, src2)
        self.assertEqual(backend.pin_source, "receipt")

    def test_incomplete_or_structurally_damaged_recordings_are_not_replayable(self):
        events = copy.deepcopy(load_trace(self.rec.trace_path).events)
        call_at = next(n for n, e in enumerate(events) if e["type"] == "model.call")
        stray = {"schema": "trace-event@1", "runId": events[0]["runId"], "seq": 0, "type": "error",
                 "error": {"code": "internal", "message": "x", "retryable": False}}
        end_at = next(n for n, e in enumerate(events) if e["type"] == "stage.end" and e["stage"] == "TRIAGE")
        cases = {"no-run-end": events[:-1],
                 "two-stage-ends": events[:end_at + 1] + [copy.deepcopy(events[end_at])] + events[end_at + 1:],
                 "duplicate-call": events[:call_at + 1] + [copy.deepcopy(events[call_at])] + events[call_at + 1:],
                 "stray-event-between-stages": events[:4] + [stray] + events[4:]}
        for name, evs in cases.items():
            data = events_to_bytes(renumber(copy.deepcopy(evs)))
            p = self.tmp / f"{name}.jsonl"
            p.write_bytes(data)
            before = sorted(x.name for x in self.out.iterdir())
            with self.assertRaises(PipelineError, msg=name) as cm:
                self.replay(self.m, self.rec, trace_path=str(p), digest=bytes_digest(data))
            self.assertEqual(cm.exception.code, "replay-recording", name)
            self.assertEqual(sorted(x.name for x in self.out.iterdir()), before, f"{name} left a run directory")


class Tamper(Base):
    def test_edited_request_in_the_recording_is_a_replay_miss_on_that_stage(self):
        def edit(ev):
            for e in ev:
                if e["type"] == "model.call" and e["stage"] == "INVESTIGATE":
                    e["request"]["messages"][1]["content"] += " "
                    e["requestHash"] = request_hash(e["request"])
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-miss", "INVESTIGATE")

    def test_edited_tool_result_in_the_recording_is_a_replay_mismatch(self):
        def edit(ev):
            e = next(e for e in ev if e["type"] == "tool.call" and e["stage"] == "PREPARE")
            e["result"]["evidence"][0]["excerpt"] += "x"
            e["resultHash"] = digest(e["result"])
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-mismatch", "PREPARE")
        self.assertIn("differs from the recording", res.error["message"])

    def test_edited_recorded_response_cannot_pass_its_checkpoint_digest(self):
        def edit(ev):
            e = next(e for e in ev if e["type"] == "model.call" and e["stage"] == "INVESTIGATE")
            e["response"]["output"]["hypotheses"][0]["claim"] = "an entirely different claim"
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-mismatch", "INVESTIGATE")

    def test_edited_verifier_verdict_in_the_recording_is_detected(self):
        def edit(ev):
            e = next(e for e in ev if e["type"] == "model.call" and e["stage"] == "VERIFY")
            e["response"]["output"]["verdict"] = "refuted"
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-mismatch", "VERIFY")

    def test_a_missing_recorded_model_call_is_a_replay_miss(self):
        def edit(ev):
            i = next(n for n, e in enumerate(ev) if e["type"] == "model.call" and e["stage"] == "JUDGE")
            del ev[i:i + 2]                                    # the call and its cost record
            renumber(ev)
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-miss", "JUDGE")

    def test_an_unconsumed_recorded_model_call_fails_the_replay(self):
        def edit(ev):
            i = max(n for n, e in enumerate(ev) if e["type"] == "model.call" and e["stage"] == "VERIFY")
            call, cost = copy.deepcopy(ev[i]), copy.deepcopy(ev[i + 1])
            call["ordinal"] = 7
            call["callId"] = call_id("VERIFY", "verifier", "verifier", 7, 0)
            call["costRecordId"] = cost_id(call["callId"])
            cost["record"]["id"], cost["record"]["callId"] = call["costRecordId"], call["callId"]
            ev[i + 2:i + 2] = [call, cost]
            renumber(ev)
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-mismatch", "VERIFY")
        self.assertIn("never reproduced", res.error["message"])

    def test_a_recorded_tool_event_the_replay_does_not_find_makes_the_replay_produce_an_extra_event(self):
        def edit(ev):
            i = next(n for n, e in enumerate(ev) if e["type"] == "tool.call" and e["stage"] == "PREPARE")
            del ev[i]
            renumber(ev)
        res = self.tampered_replay(edit)
        self.assert_failed_closed(res, "replay-mismatch", "PREPARE")
        self.assertIn("differs from the recording", res.error["message"])

    def test_a_changed_recorded_error_or_cost_is_detected(self):
        def edit(ev):
            e = next(e for e in ev if e["type"] == "cost" and e["record"]["stage"] == "VERIFY")
            e["record"]["usdMicros"] += 1
        res = self.tampered_replay(edit)
        self.assertEqual(res.status, "failed")
        self.assertIn(res.error["code"], ("replay-mismatch", "replay-miss"))
        self.assertEqual(res.comments, [])

    def test_untouched_recording_still_replays_completed_after_all_these_tampers(self):
        res = self.replay(self.m, self.rec)
        self.assertEqual((res.status, len(res.comments)), ("completed", 2))


class Drift(Base):
    def test_changed_inputs_config_profile_or_plan_cannot_replay_a_recording(self):
        head2 = dict(self.m.head_files)
        head2["src/b.py"] = "def g(x):\n    return x * 3\n"
        m2 = self.mini("mini-1b", head=head2)
        m2.case["id"] = self.m.case["id"]                        # same case id, different pinned head
        m2.case["base"], m2.case["head"] = dict(m2.case["base"]), dict(m2.case["head"])
        cases = {
            "head snapshot": lambda: self.replay_spec_run(m2),
            "config identity": lambda: self.replay(self.m, self.rec, config_identity={"test": "other"}),
            "profile price": lambda: self.replay(self.m, self.rec, profile=self.price_changed()),
            "plan budget": lambda: self.replay(self.m, self.rec, plan=self.budget_changed()),
            "comment cap": lambda: self.replay(self.m, self.rec, comment_cap=3),
        }
        for name, fn in cases.items():
            with self.assertRaises(PipelineError, msg=name) as cm:
                fn()
            self.assertEqual(cm.exception.code, "identity-mismatch", name)
        self.assertEqual(self.spy.calls, 4)

    def replay_spec_run(self, m2):
        from reviewer.pipeline import run_review
        return run_review(self.spec(m2, self.replay_backend(self.rec), eval_id=EVR2))

    def price_changed(self):
        p = json.loads(json.dumps(PROFILE))
        p["roles"]["judge"]["price"]["outputPerMTokUsdMicros"] += 1
        return p

    def budget_changed(self):
        p = json.loads(json.dumps(PLAN))
        p["budget"]["maxUsdMicros"] -= 1
        return p

    def test_replay_of_a_different_case_is_refused(self):
        other = self.mini("mini-2")
        with self.assertRaises(PipelineError) as cm:
            self.replay(other, self.rec)
        self.assertEqual(cm.exception.code, "identity-mismatch")


if __name__ == "__main__":
    unittest.main()
