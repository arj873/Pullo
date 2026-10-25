"""Checkpoints, crash recovery and idempotency. Crashes are simulated with Hooks.after_checkpoint raising a
BaseException (nothing in the engine can catch or finish it), leaving exactly what a killed process leaves."""

from __future__ import annotations

import copy
import json
import shutil
import unittest
from pathlib import Path

from reviewer.contracts.stages import STAGES, artifact_name
from reviewer.gateway import bytes_digest, events_to_bytes
from reviewer.pipeline import Hooks, PipelineError, load_result

from .helpers import EVR2, PLAN, Crash, Rig, events_of, hid, hyp, inv, judge, script, ver
from .test_replay_failures import Base


def crash_after(stage):
    def hook(st, digest):
        if st == stage:
            raise Crash(stage)
    return Hooks(after_checkpoint=hook)


class ResumeBase(Base):
    def setUp(self):
        super().setUp()
        self.out2 = self.tmp / "out-reference"
        self.out2.mkdir()
        self.reference = self.replay(self.m, self.rec, out=self.out2)          # same run id, uninterrupted
        self.assertEqual(self.reference.status, "completed")

    def interrupted_dir(self):
        return Path(self.out) / self.reference.run_id

    def crash(self, stage, **kw):
        with self.assertRaises(Crash):
            self.replay(self.m, self.rec, hooks=crash_after(stage), **kw)
        d = self.interrupted_dir()
        self.assertTrue(d.is_dir())
        self.assertFalse((d / "receipt.json").exists())
        self.assertFalse((d / "run.json").exists())
        return d


class Resume(ResumeBase):
    def test_resume_after_every_checkpoint_equals_an_uninterrupted_replay_byte_for_byte(self):
        for i, stage in enumerate(STAGES):
            with self.subTest(stage=stage):
                shutil.rmtree(self.interrupted_dir(), ignore_errors=True)
                d = self.crash(stage)
                trace_before = (d / "trace.jsonl").read_bytes()
                res = self.replay(self.m, self.rec)
                nxt = STAGES[i + 1] if i + 1 < len(STAGES) else "run.end"
                self.assertEqual((res.resumed_from, res.status, res.run_id), (nxt, "completed", self.reference.run_id))
                self.assertFalse(res.idempotent)
                self.assertEqual((d / "trace.interrupted-1.jsonl").read_bytes(), trace_before)
                self.assertEqual(Path(res.trace_path).read_bytes(), Path(self.reference.trace_path).read_bytes())
                self.assertEqual(res.trace_digest, self.reference.trace_digest)
                self.assertEqual({s: v["artifactDigest"] for s, v in res.stages.items()},
                                 {s: v["artifactDigest"] for s, v in self.reference.stages.items()})
                for name in ("comments.json", "review.md", "run.json"):
                    self.assertEqual((d / name).read_bytes(), Path(self.reference.run_dir, name).read_bytes(), name)
                self.assertEqual(res.comments, self.reference.comments)
                self.assertEqual(len(res.cost["records"]), len(self.reference.cost["records"]))
                self.assertEqual(res.gateway_report["unconsumedRecordedCalls"], 0)
                self.assertEqual(res.receipt["resumedFrom"], nxt)
                self.assertEqual(self.spy.calls, 4)                       # no provider call, ever
                events = events_of(res)
                self.assertEqual([e["seq"] for e in events], list(range(len(events))))
                self.assertEqual(sum(1 for e in events if e["type"] == "model.call"), 4)   # not replayed twice

    def test_prior_stage_model_calls_are_accounted_explicitly_not_silently_ignored(self):
        self.crash("VERIFY")
        res = self.replay(self.m, self.rec)
        self.assertEqual(res.gateway_report["priorStageModelCalls"], 3)           # investigator + two verifiers
        self.assertEqual(res.gateway_report["replayedCalls"], 1)                  # only the judge ran in this process
        self.assertEqual(res.receipt["gateway"]["priorStageModelCalls"], 3)

    def test_resume_ignores_uncheckpointed_tail_torn_lines_and_half_finished_stages(self):
        d = self.crash("TRIAGE")
        events = events_of(self.reference)
        half = next(e for e in events if e["type"] == "stage.start" and e["stage"] == "INVESTIGATE")
        half = dict(half, seq=len(events_of(self.reference)) and 13)
        with open(d / "trace.jsonl", "ab") as f:
            f.write((json.dumps(half, sort_keys=True) + "\n").encode())           # started, never checkpointed
            f.write(b'{"schema": "trace-event@1", "runId": "run_00')              # torn mid-write
        res = self.replay(self.m, self.rec)
        self.assertEqual((res.resumed_from, res.status), ("INVESTIGATE", "completed"))
        self.assertEqual(Path(res.trace_path).read_bytes(), Path(self.reference.trace_path).read_bytes())

    def test_an_interrupted_dir_with_no_checkpoint_restarts_cleanly(self):
        d = self.crash("INGEST")
        events = [json.loads(x) for x in (d / "trace.jsonl").read_text().splitlines()]
        (d / "trace.jsonl").write_bytes(events_to_bytes(events[:2]))              # run.start + stage.start only
        res = self.replay(self.m, self.rec)
        self.assertEqual((res.resumed_from, res.status), (None, "completed"))
        self.assertEqual(res.trace_digest, self.reference.trace_digest)

    def test_completed_replay_is_idempotent_and_leaves_resumed_receipt_alone(self):
        self.crash("JUDGE")
        res = self.replay(self.m, self.rec)
        again = self.replay(self.m, self.rec)
        self.assertTrue(again.idempotent)
        self.assertEqual(again.receipt, res.receipt)
        self.assertEqual(again.resumed_from, "PUBLISH")
        loaded = load_result(self.out, res.run_id)
        self.assertEqual(loaded.comments, res.comments)
        self.assertEqual(loaded.cost["byBasis"], res.cost["byBasis"])


class CorruptCheckpoints(ResumeBase):
    def attempt(self, expect="checkpoint-invalid"):
        d = self.interrupted_dir()
        before = (d / "trace.jsonl").read_bytes()
        with self.assertRaises(PipelineError) as cm:
            self.replay(self.m, self.rec)
        self.assertEqual(cm.exception.code, expect)
        self.assertEqual((d / "trace.jsonl").read_bytes(), before, "a refused resume must not touch the trace")
        self.assertFalse(list(d.glob("trace.interrupted-*")))
        self.assertFalse((d / "receipt.json").exists())
        return cm.exception.message

    def art(self, d, stage):
        return d / "artifacts" / artifact_name(stage, 1)

    def test_tampered_artifact_content_is_refused(self):
        d = self.crash("INVESTIGATE")
        p = self.art(d, "PREPARE")
        doc = json.loads(p.read_text())
        doc["payload"]["files"][0]["additions"] += 5
        p.write_text(json.dumps(doc, sort_keys=True))
        self.assertIn("checkpoint digest", self.attempt())

    def test_missing_invalid_duplicate_key_and_oversized_artifacts_are_refused(self):
        d = self.crash("INVESTIGATE")
        p = self.art(d, "TRIAGE")
        good = p.read_bytes()
        p.unlink()
        self.assertIn("missing", self.attempt())
        p.write_bytes(b"{not json")
        self.attempt()
        p.write_bytes(b'{"a": 1, "a": 2}')
        self.attempt()
        p.write_bytes(b" " * (17 << 20))
        self.assertIn("read limit", self.attempt())
        p.write_bytes(good)
        res = self.replay(self.m, self.rec)
        self.assertEqual(res.status, "completed")

    def test_artifact_from_another_stage_or_run_or_chain_break_is_refused(self):
        d = self.crash("INVESTIGATE")
        a, b = self.art(d, "PREPARE"), self.art(d, "TRIAGE")
        pa, pb = a.read_bytes(), b.read_bytes()
        a.write_bytes(pb)                                  # TRIAGE content under PREPARE's name
        self.attempt()
        a.write_bytes(pa)
        doc = json.loads(b.read_text())
        doc["runId"] = "run_" + "9" * 16
        b.write_text(json.dumps(doc))
        self.attempt()
        b.write_bytes(pb)
        doc = json.loads(pb)
        doc["inputDigest"] = "sha256:" + "0" * 64
        b.write_text(json.dumps(doc))
        self.attempt()

    def edit_trace(self, d, fn):
        events = [json.loads(x) for x in (d / "trace.jsonl").read_text().splitlines()]
        fn(events)
        (d / "trace.jsonl").write_bytes(events_to_bytes(events))

    def test_tampered_trace_prefix_is_refused(self):
        d = self.crash("INVESTIGATE")
        orig = (d / "trace.jsonl").read_bytes()

        def tool_result(ev):
            e = next(e for e in ev if e["type"] == "tool.call")
            e["result"]["evidence"][0]["excerpt"] += "x"                       # resultHash no longer matches

        def response(ev):
            e = next(e for e in ev if e["type"] == "model.call")
            e["response"]["output"]["hypotheses"][0]["claim"] = "edited"        # not hash-covered: caught vs recording

        def run_start(ev):
            ev[0]["run"]["configSnapshotId"] = "sha256:" + "1" * 64

        def checkpoint(ev):
            e = next(e for e in ev if e["type"] == "checkpoint" and e["stage"] == "PREPARE")
            e["artifactDigest"] = "sha256:" + "2" * 64

        def reorder(ev):
            i = next(n for n, e in enumerate(ev) if e["type"] == "stage.start" and e["stage"] == "TRIAGE")
            ev[i], ev[i + 1] = ev[i + 1], ev[i]
            for n, e in enumerate(ev):
                e["seq"] = n

        for name, fn in (("tool result", tool_result), ("response", response), ("run.start", run_start),
                         ("checkpoint digest", checkpoint), ("stage order", reorder)):
            (d / "trace.jsonl").write_bytes(orig)
            self.edit_trace(d, fn)
            with self.subTest(name):
                self.attempt()
        (d / "trace.jsonl").write_bytes(orig)
        self.assertEqual(self.replay(self.m, self.rec).status, "completed")

    def test_a_trace_from_a_different_run_or_a_symlinked_artifact_is_refused(self):
        d = self.crash("INVESTIGATE")
        self.edit_trace(d, lambda ev: [e.update(runId="run_" + "7" * 16) for e in ev])
        self.attempt()
        other = self.tmp / "elsewhere.json"
        other.write_bytes(self.art(d, "PREPARE").read_bytes())
        self.art(d, "PREPARE").unlink()
        self.art(d, "PREPARE").symlink_to(other)
        self.attempt()

    def test_resume_is_refused_when_the_recording_holds_a_budget_refusal_it_could_not_reproduce(self):
        plan = json.loads(json.dumps(PLAN))
        plan["budget"]["maxUsdMicros"] = 180_000
        rec2, spy2 = self.record(self.m, self.scr, plan=plan, eval_id="evr_" + "6" * 16)
        self.assertEqual(rec2.status, "partial")
        full = self.replay(self.m, rec2, plan=plan, out=self.tmp / "o3") if (self.tmp / "o3").mkdir() is None else None
        self.assertEqual((full.status, [d["reason"] for d in full.drops]), ("partial", ["budget"]))   # replays it exactly
        with self.assertRaises(Crash):
            self.replay(self.m, rec2, plan=plan, hooks=crash_after("INVESTIGATE"))
        with self.assertRaises(PipelineError) as cm:
            self.replay(self.m, rec2, plan=plan)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")
        self.assertIn("budget refusal", cm.exception.message)


class RecordingRecovery(Base):
    def test_interrupted_recording_is_never_reissued_and_spend_stays_reserved(self):
        m2 = self.mini("mini-9")
        with self.assertRaises(Crash):
            self.record(m2, self.scr, hooks=crash_after("INVESTIGATE"))
        spy = self.spies[-1]
        calls, spent = spy.calls, self.book.totals()
        self.assertEqual(calls, 1)
        for _ in range(2):
            with self.assertRaises(PipelineError) as cm:
                self.record(m2, self.scr)
            self.assertEqual(cm.exception.code, "recovery-required")
            self.assertIn("nothing is re-issued", cm.exception.message)
        self.assertEqual(self.spies[-1].calls, 0)
        self.assertEqual(spy.calls, calls)
        self.assertEqual(self.book.totals(), spent)
        self.assertGreater(spent["committed"] + spent["inflight"], 0)
        # a replay of that interrupted recording is impossible: it has no run.end
        d = next(p for p in Path(self.out).iterdir() if p.name != self.rec.run_id and not (p / "receipt.json").exists())
        with self.assertRaises(PipelineError):
            from reviewer.pipeline import ReplayBackend
            ReplayBackend(d / "trace.jsonl", bytes_digest((d / "trace.jsonl").read_bytes()))

    def test_a_directory_with_no_trace_events_is_safe_to_start_again(self):
        shutil.rmtree(self.rec.run_dir)
        Path(self.rec.run_dir).mkdir()
        (Path(self.rec.run_dir) / "trace.jsonl").write_bytes(b"")
        res, spy = self.record(self.m, self.scr)
        self.assertEqual((res.status, spy.calls), ("completed", 4))

    def test_recorded_run_directory_cannot_be_reused_for_a_different_recording_identity(self):
        with self.assertRaises(PipelineError) as cm:
            self.record(self.m, self.scr, config_identity={"test": "different"})
        self.assertEqual(cm.exception.code, "identity-mismatch")
        self.assertEqual(self.spies[-1].calls, 0)


if __name__ == "__main__":
    unittest.main()
