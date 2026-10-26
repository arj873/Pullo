"""S1-05: offline replay from a stage (stage-replay) and the honest status of fork."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from reviewer.contracts.canonical import artifact_digest
from reviewer.gateway import load_trace
from reviewer.pipeline import ForkFrom, PipelineError, ReviewSpec, StageReplay, load_result, run_review

from .helpers import (EVR2, Rig, events_of, hid, hyp, ifinal, inv, judge, model_calls, script, ver, vfinal, vturn, iturn,
                      treq, TURN_PLAN, TURN_PROFILE, PLAN, PROFILE)


def w(ids):
    return {"findingIds": list(ids), "title": "T", "body": "B"}


class StageReplayRuns(Rig):
    def recorded(self, turn=False):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        if turn:
            scr = script(iturn(0, [treq("read_file", side="head", path="src/b.py")]), ifinal(1, h),
                         vfinal(0, m, path="src/a.py", line=2), judge(w([hid(0, h)])))
            res, spy = self.record_turn(m, scr)
        else:
            res, spy = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual(len(res.comments), 1)
        return m, res, spy

    def stage_replay(self, m, res, stage, *, turn=False, digest=None, recording_dir=None, out="out2"):
        o = self.tmp / out
        o.mkdir(exist_ok=True)
        backend = self.replay_backend(res, digest=digest)
        spec = ReviewSpec(case=m.case, base=m.base, head=m.head, profile=TURN_PROFILE if turn else PROFILE,
                          plan=TURN_PLAN if turn else PLAN, host=self.host(m.id, eval_id=EVR2, out_root=o),
                          backend=backend, stage_replay=StageReplay(stage, recording_dir or res.run_dir))
        return run_review(spec)

    def test_replay_from_verify_adopts_the_prefix_and_reproduces_the_suffix_with_everything_consumed(self):
        m, res, spy = self.recorded()
        n = spy.calls
        rep = self.stage_replay(m, res, "VERIFY")
        self.assertEqual((rep.status, rep.run["mode"], rep.receipt["stageReplay"]["fromStage"]),
                         ("completed", "strict-replay", "VERIFY"))
        self.assertEqual(rep.run["replayOf"], res.run_id)
        g = rep.gateway_report
        self.assertEqual((g["liveCalls"], g["newSpendUsdMicros"], g["unconsumedRecordedCalls"]), (0, 0, 0))
        self.assertEqual(g["replayedCalls"], n - 1)                          # only the suffix calls hit the gateway
        sr = rep.receipt["stageReplay"]
        self.assertEqual(sr["adoptedStages"], ["INGEST", "PREPARE", "TRIAGE", "INVESTIGATE"])
        self.assertEqual(sr["consumedPrefixCallIds"], [c["callId"] for c in model_calls(res, "INVESTIGATE")])
        self.assertTrue(sr["consumptionComplete"])
        for st in ("INVESTIGATE", "VERIFY", "JUDGE"):                          # artifact digests equal the recording's
            self.assertEqual(rep.stages[st]["artifactDigest"], res.stages[st]["artifactDigest"])
        self.assertEqual([c["id"] for c in rep.comments], [c["id"] for c in res.comments])
        load_trace(rep.trace_path)                                           # the finished trace is internally valid
        costs = [e["record"]["basis"] for e in events_of(rep) if e["type"] == "cost"]
        self.assertEqual(set(costs), {"replayed"})
        self.assertEqual(load_result(self.tmp / "out2", rep.run_id).status, "completed")
        self.assertEqual(spy.calls, n)

    def test_replay_of_a_retrieval_run_from_judge_and_from_publish(self):
        m, res, _ = self.recorded(turn=True)
        for stage in ("JUDGE", "PUBLISH", "INVESTIGATE"):
            rep = self.stage_replay(m, res, stage, turn=True, out=f"o-{stage}")
            self.assertEqual((rep.status, rep.gateway_report["unconsumedRecordedCalls"]), ("completed", 0), stage)
            self.assertEqual(rep.retrieval["summary"], res.retrieval["summary"], stage)

    def test_tampered_stored_artifact_is_refused_against_the_pinned_trace_before_any_work(self):
        m, res, _ = self.recorded()
        p = Path(res.run_dir) / "artifacts" / "04-INVESTIGATE.v1.json"
        names = sorted(x.name for x in (Path(res.run_dir) / "artifacts").iterdir())
        p = Path(res.run_dir) / "artifacts" / next(n for n in names if "INVESTIGATE" in n)
        doc = json.loads(p.read_text())
        doc["payload"]["hypotheses"][0]["claim"] = "edited after the fact"
        p.chmod(0o600)
        p.write_text(json.dumps(doc))
        with self.assertRaises(PipelineError) as e:
            self.stage_replay(m, res, "VERIFY")
        self.assertEqual(e.exception.code, "checkpoint-invalid")
        self.assertIn("checkpoint digest", e.exception.message)
        self.assertFalse((self.tmp / "out2").exists() and any((self.tmp / "out2").iterdir()))   # nothing left behind

    def test_wrong_pin_and_wrong_directory_and_bad_stage_are_refused(self):
        m, res, _ = self.recorded()
        with self.assertRaises(PipelineError) as e:
            self.stage_replay(m, res, "VERIFY", digest="sha256:" + "0" * 64)
        self.assertEqual(e.exception.code, "replay-pin")
        with self.assertRaises(PipelineError) as e:
            self.stage_replay(m, res, "VERIFY", recording_dir=str(self.tmp))
        self.assertEqual(e.exception.code, "checkpoint-invalid")
        with self.assertRaises(PipelineError) as e:
            self.stage_replay(m, res, "INGEST")
        self.assertEqual(e.exception.code, "invalid-input")

    def test_changed_inputs_are_an_identity_mismatch_not_a_silent_replay(self):
        m, res, _ = self.recorded()
        m2 = self.mini(cid="mini-1", title="A different title")
        with self.assertRaises(PipelineError) as e:
            self.stage_replay(m2, res, "VERIFY")
        self.assertEqual(e.exception.code, "identity-mismatch")


class ForkIsNotClaimed(Rig):
    def test_fork_is_refused_with_the_reason_instead_of_pretending(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        backend, spy = self.record_backend(script())
        spec = ReviewSpec(case=m.case, base=m.base, head=m.head, profile=PROFILE, plan=PLAN,
                          host=self.host(m.id, eval_id=EVR2), backend=backend,
                          fork=ForkFrom(self.replay_backend(res), "VERIFY", res.run_dir))
        with self.assertRaises(PipelineError) as e:
            run_review(spec)
        self.assertEqual(e.exception.code, "config")
        self.assertIn("not implemented", e.exception.message)
        self.assertEqual(spy.calls, 0)


if __name__ == "__main__":
    unittest.main()


class NoIdentityOverride(Rig):
    def test_engine_identity_always_names_the_running_contracts_and_has_no_baseline_switch(self):
        import inspect
        from reviewer.contracts import CONTRACTS_VERSION
        from reviewer.pipeline import HostConfig, engine_identity
        self.assertEqual(engine_identity()["contracts"], CONTRACTS_VERSION)
        self.assertEqual(list(inspect.signature(engine_identity).parameters), [])
        self.assertNotIn("legacy_baseline", inspect.signature(HostConfig).parameters)
