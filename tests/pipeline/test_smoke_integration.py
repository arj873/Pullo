"""All six synthetic smoke cases through the real gateway, tools, contracts and engine; then strict replay.

The host side of this test (the only place that touches SuiteCase, labels and scripts) mirrors what S0-08 will do:
load the suite, give each case's script only to the provider, hand the engine a CaseInput + roots/manifests,
and score afterwards with score_loaded_case. Expectations live in the scorer's labels, never in the engine.
"""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from reviewer.contracts import require, validate, validate_trace
from reviewer.contracts.canonical import artifact_digest, comparable_digest, run_id
from reviewer.contracts.stages import STAGES, artifact_name
from reviewer.gateway import DisabledProvider, load_script, load_trace
from reviewer.pipeline import (EvalIdentity, HostConfig, PipelineError, RecordBackend, ReviewSpec, SnapshotInput,
                               engine_identity, load_result, run_review)
from reviewer.scoring import score_loaded_case
from reviewer.scoring.suite import load_suite, redaction_fingerprint, synthetic_config_digest

from .helpers import (EVR1, EVR2, NOW, PLAN, PROFILE, ROOT, SMOKE, Rig, SpyProvider, all_bytes, events_of, model_calls,
                      tool_calls)

CASES = ["smoke-c01", "smoke-c02", "smoke-c03", "smoke-c04", "smoke-c05", "smoke-c06"]
EXPECT = {"smoke-c01": ("completed", 1), "smoke-c02": ("completed", 0), "smoke-c03": ("completed", 1),
          "smoke-c04": ("completed", 1), "smoke-c05": ("partial", 0), "smoke-c06": ("failed", 0)}


class SmokeRig(Rig):
    suite_dir = SMOKE

    def setUp(self):
        super().setUp()
        self.suite = load_suite(self.suite_dir)
        self.cfg = synthetic_config_digest(self.suite, config={"engine": engine_identity()})

    def spec_for(self, cid, backend, eval_id=EVR1, **kw):
        c = self.suite.cases[cid]
        host = dict(out_root=self.out, eval=EvalIdentity(eval_id, cid, 0), config_identity=self.cfg,
                    forbidden_roots=(self.suite.root,), clock=self.clock)
        host.update(kw)
        return ReviewSpec(case=c.input, base=SnapshotInput(self.suite.root / c.input["base"]["root"], c.base_manifest),
                          head=SnapshotInput(self.suite.root / c.input["head"]["root"], c.head_manifest),
                          profile=PROFILE, plan=PLAN, host=HostConfig(**host), backend=backend)

    def record_case(self, cid, **kw):
        backend, spy = self.record_backend(load_script(self.suite.root / self.suite.cases[cid].script_path))
        return run_review(self.spec_for(cid, backend, **kw)), spy

    def replay_case(self, cid, res, **kw):
        kw.setdefault("eval_id", EVR2)
        return run_review(self.spec_for(cid, self.replay_backend(res), **kw))

    def score(self, cid, res):
        return score_loaded_case(self.suite, cid, res.comments, run_id=res.run_id, status=res.status,
                                 incomplete=res.incomplete, error=res.error)


class SixCases(SmokeRig):
    @classmethod
    def setUpClass(cls):
        cls._results = {}

    def recorded(self):
        return {cid: self.record_case(cid, **({} if cid == CASES[0] else {})) for cid in CASES}

    def test_record_all_six_with_expected_outcomes_scored_afterwards(self):
        got = self.recorded()
        for cid in CASES:
            res, spy = got[cid]
            self.assertEqual((res.status, len(res.comments)), EXPECT[cid], cid)
            s = self.score(cid, res)
            self.assertTrue(s.expectation_met, f"{cid}: scorer expectation not met")
        self.assertEqual(got["smoke-c01"][0].comments[0]["severity"], "P0")
        self.assertEqual(got["smoke-c03"][0].comments[0]["severity"], "P1")
        self.assertEqual(self.score("smoke-c03", got["smoke-c03"][0]).duplicates, 0)

    def test_engine_source_has_no_case_id_label_or_scorer_dependency(self):
        for p in sorted((ROOT / "reviewer/pipeline").glob("*.py")):
            src = p.read_text()
            for needle in ("smoke-", "reviewer.scoring", "from reviewer import scoring", "load_suite", ".labels",
                           "[\"labels\"]", "expectReason", "synthetic_config_digest("):
                self.assertNotIn(needle, src, f"{p.name}: {needle}")

    def test_c04_used_exactly_one_bounded_repair_and_c06_exhausted_retries(self):
        got = self.recorded()
        c04 = [(e["attempt"], e.get("repairOf") is not None) for e in model_calls(got["smoke-c04"][0], "INVESTIGATE")]
        self.assertEqual(c04, [(0, False), (1, True)])
        c06 = model_calls(got["smoke-c06"][0], "INVESTIGATE")
        self.assertEqual([e["attempt"] for e in c06], [0, 1, 2])
        self.assertTrue(all(e["error"]["code"] == "provider-timeout" for e in c06))
        res = got["smoke-c06"][0]
        self.assertEqual(res.error["code"], "provider-timeout")
        self.assertEqual(res.stages["INVESTIGATE"]["status"], "failed")
        self.assertEqual([res.stages[s]["status"] for s in ("VERIFY", "JUDGE", "PUBLISH", "LEARN")],
                         ["skipped", "skipped", "completed", "skipped"])
        # timeouts keep their reservation (outcome unknown): charged, never released
        retained = [r for r in res.cost["records"] if r["usdMicros"] == r["reservedUsdMicros"] and r["usdMicros"]]
        self.assertEqual(len(retained), 3)

    def test_c05_other_candidates_would_survive_a_failed_verifier(self):
        res, _ = self.record_case("smoke-c05")
        self.assertEqual(res.status, "partial")
        self.assertEqual([i["reason"] for i in res.incomplete], ["verifier-failure"])
        self.assertEqual(res.findings, [])
        self.assertEqual([v["verdict"] for v in res.verifications], ["failed"])
        self.assertEqual([d["reason"] for d in res.drops], ["verifier-failed"])
        self.assertEqual(res.stages["VERIFY"]["status"], "partial")
        self.assertEqual(res.comments, [])

    def test_state_agrees_across_run_artifacts_trace_receipt_and_outputs(self):
        for cid, (res, _) in self.recorded().items():
            events = events_of(res)
            self.assertEqual(validate_trace(events), [], cid)
            self.assertEqual(events[-1]["type"], "run.end")
            self.assertEqual((events[-1]["status"], events[-1]["incomplete"]), (res.status, res.incomplete), cid)
            self.assertEqual(res.receipt["status"], res.status)
            self.assertEqual(json.loads(Path(res.run_dir, "run.json").read_text())["status"], res.status)
            self.assertEqual(json.loads(Path(res.comments_path).read_text())["status"], res.status)
            self.assertEqual([e["stage"] for e in events if e["type"] == "checkpoint"], list(STAGES))
            prev = None
            for st in STAGES:
                art = require("StageArtifact", json.loads(Path(res.run_dir, "artifacts",
                                                               artifact_name(st, 1)).read_text()))
                cp = next(e for e in events if e["type"] == "checkpoint" and e["stage"] == st)
                end = next(e for e in events if e["type"] == "stage.end" and e["stage"] == st)
                self.assertEqual(artifact_digest(art), cp["artifactDigest"])
                self.assertEqual(end["artifactDigest"], cp["artifactDigest"])
                self.assertEqual(end["status"], art["status"])
                self.assertEqual(art["inputDigest"], None if prev is None else artifact_digest(prev))
                prev = art
                ids = [e["record"]["id"] for e in events if e["type"] == "cost"]
                self.assertTrue(set(art["costRecordIds"]) <= set(ids))
            cost_ids = [i for st in STAGES for i in res.stages[st]["costRecordIds"]]
            self.assertEqual(sorted(cost_ids), sorted(r["id"] for r in res.cost["records"]), cid)
            self.assertEqual(res.stages["LEARN"]["status"], "skipped")

    def test_outputs_are_local_draft_files_only(self):
        res, _ = self.record_case("smoke-c01")
        names = sorted(p.name for p in Path(res.run_dir).iterdir())
        self.assertEqual(names, ["artifacts", "comments.json", "receipt.json", "review.md", "run.json", "trace.jsonl"])
        self.assertFalse([p for p in Path(res.run_dir).rglob("*") if p.name.startswith(".")], "temp file left behind")
        doc = json.loads(Path(res.comments_path).read_text())
        self.assertEqual(doc["state"], "draft")
        c = doc["comments"][0]
        self.assertEqual(require("Comment", c)["state"], "draft")
        self.assertEqual(c["anchor"]["snapshotId"], self.suite.cases["smoke-c01"].input["head"]["snapshotId"])
        md = Path(res.review_path).read_text()
        self.assertIn("DRAFT", md)
        self.assertIn("src/auth.py", md)
        res2, _ = self.record_case("smoke-c02")
        self.assertIn("not a certificate", Path(res2.review_path).read_text())
        self.assertIn("Changed paths found by the diff tool: 1", Path(res2.review_path).read_text())
        self.assertEqual(json.loads(Path(res2.comments_path).read_text())["comments"], [])

    def test_strict_replay_reproduces_all_six_with_no_provider_and_no_new_spend(self):
        got = self.recorded()
        spent_before = self.book.totals()
        for cid in CASES:
            orig = got[cid][0]
            rep = self.replay_case(cid, orig)
            self.assertEqual((rep.status, len(rep.comments)), EXPECT[cid], cid)
            self.assertEqual([comparable_digest(c) for c in rep.comments],
                             [comparable_digest(c) for c in orig.comments], cid)
            self.assertEqual([comparable_digest(f) for f in rep.findings],
                             [comparable_digest(f) for f in orig.findings], cid)
            self.assertEqual([comparable_digest(h) for h in rep.hypotheses],
                             [comparable_digest(h) for h in orig.hypotheses], cid)
            self.assertEqual({s: v["artifactDigest"] for s, v in rep.stages.items()},
                             {s: v["artifactDigest"] for s, v in orig.stages.items()}, cid)
            self.assertEqual(rep.error, orig.error)
            self.assertEqual(rep.incomplete, orig.incomplete)
            self.assertEqual(rep.cost["liveCalls"], 0)
            self.assertEqual(rep.gateway_report["liveCalls"], 0)
            self.assertEqual(rep.gateway_report["unconsumedRecordedCalls"], 0)
            self.assertEqual({b: v["records"] for b, v in rep.cost["byBasis"].items() if v["records"]},
                             {"replayed": len(orig.cost["records"])})
            self.assertEqual(rep.cost["actualProviderUsdMicros"], 0)
            self.assertEqual(rep.receipt["mode"], "strict-replay")
            self.assertEqual(rep.receipt["replayOf"], orig.run_id)
            self.assertEqual(rep.receipt["pin"], {"traceDigest": orig.receipt["traceDigest"], "source": "test-pin"})
            self.assertNotEqual(rep.run_id, orig.run_id)
            self.assertTrue(self.score(cid, rep).expectation_met)
        self.assertEqual(self.book.totals(), spent_before, "replay moved the spend book")
        for spy in self.spies:                                       # scripted provider answered record calls only
            self.assertEqual(spy.calls, len(spy.requests))

    def test_replay_recomputes_tool_results_and_requests_instead_of_copying(self):
        res, _ = self.record_case("smoke-c01")
        rep = self.replay_case("smoke-c01", res)
        t1 = [(e["toolCallId"], e["resultHash"]) for e in tool_calls(res)]
        t2 = [(e["toolCallId"], e["resultHash"]) for e in tool_calls(rep)]
        self.assertEqual(t1, t2)
        self.assertGreaterEqual(len(t1), 5)
        # the replay trace has its own run id and was written by this process
        self.assertTrue(all(e["runId"] == rep.run_id for e in events_of(rep)))
        self.assertNotEqual(rep.trace_digest, res.trace_digest)

    def test_repeated_invocation_is_idempotent_and_makes_no_calls_or_rewrites(self):
        res, spy = self.record_case("smoke-c01")
        calls, requests = spy.calls, len(spy.requests)
        before = {p: p.read_bytes() for p in Path(res.run_dir).rglob("*") if p.is_file()}
        mtimes = {p: p.stat().st_mtime_ns for p in before}
        spent = self.book.totals()
        again, spy2 = self.record_case("smoke-c01")
        self.assertTrue(again.idempotent)
        self.assertEqual((again.run_id, again.status, again.trace_digest), (res.run_id, res.status, res.trace_digest))
        self.assertEqual([c["id"] for c in again.comments], [c["id"] for c in res.comments])
        self.assertEqual(spy2.calls, 0)
        self.assertEqual(spy.calls, calls)
        self.assertEqual(len(spy.requests), requests)
        self.assertEqual(self.book.totals(), spent)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual({p: p.stat().st_mtime_ns for p in before}, mtimes)
        self.assertEqual(len(again.comments), 1)
        self.assertEqual(len(json.loads(Path(res.comments_path).read_text())["comments"]), 1)
        loaded = load_result(self.out, res.run_id)
        self.assertEqual(loaded.status, res.status)

    def test_replay_repeated_invocation_is_idempotent_too(self):
        res, _ = self.record_case("smoke-c03")
        rep = self.replay_case("smoke-c03", res)
        again = self.replay_case("smoke-c03", res)
        self.assertTrue(again.idempotent)
        self.assertEqual(again.trace_digest, rep.trace_digest)

    def test_manual_rerun_is_a_new_attempt_with_its_own_run_and_receipt(self):
        res, _ = self.record_case("smoke-c01")
        c = self.suite.cases["smoke-c01"]
        backend, spy = self.record_backend(load_script(self.suite.root / c.script_path))
        spec = self.spec_for("smoke-c01", backend, eval=None, attempt=2)
        # an eval execution is attempt 1 only: a repeat of an eval is a new eval run id, not attempt 2
        with self.assertRaises(PipelineError):
            run_review(self.spec_for("smoke-c01", backend, attempt=2))
        r2 = run_review(spec)
        self.assertEqual(r2.run["attempt"], 2)
        self.assertEqual(r2.run["trigger"], "manual-rerun")
        self.assertNotEqual(r2.run_id, res.run_id)
        self.assertEqual(r2.run["rerunOf"], run_id(r2.run["idempotencyKey"], 1))
        self.assertEqual(r2.status, "completed")
        self.assertEqual(spy.calls, 3)


class BoundaryAndCanary(SmokeRig):
    def make_suite_copy(self):
        dst = self.tmp / "suite-copy"
        shutil.copytree(SMOKE, dst)
        p = dst / "labels/smoke-c01.json"
        doc = json.loads(p.read_text())
        doc["bugs"][0]["note"] = "LABELCANARY-9d41c0e7 planted note"
        p.write_text(json.dumps(doc, indent=2, sort_keys=True))
        self.suite_dir = dst
        self.suite = load_suite(dst)
        self.cfg = synthetic_config_digest(self.suite, config={"engine": engine_identity()})

    def test_labels_never_reach_a_provider_request_the_trace_or_any_output(self):
        self.make_suite_copy()
        self.assertEqual(self.suite.cases["smoke-c01"].labels["bugs"][0]["note"][:11], "LABELCANARY")
        res, spy = self.record_case("smoke-c01")
        self.assertGreaterEqual(len(spy.requests), 3)
        blob = json.dumps(spy.requests) + all_bytes(res.run_dir).decode("utf-8", "replace")
        for needle in ("LABELCANARY", "smoke-auth-bypass", "case-labels", "expectReason", "labels/smoke-c01"):
            self.assertNotIn(needle, blob, needle)
        for rq in spy.requests:
            for k in ("labels", "expect", "expectation", "bugs", "script"):
                self.assertNotIn(k, rq)
        self.assertEqual(self.suite.cases["smoke-c01"].labels["expect"], "findings")      # labels exist host-side

    def test_a_suite_case_or_labels_cannot_be_handed_to_the_engine(self):
        c = self.suite.cases["smoke-c01"]
        backend, spy = self.record_backend(load_script(self.suite.root / c.script_path))
        for bad in (c, {**c.input, "labels": c.labels}, {**c.input, "expect": "findings"}):
            spec = ReviewSpec(case=bad, base=SnapshotInput(self.suite.root / c.input["base"]["root"], c.base_manifest),
                              head=SnapshotInput(self.suite.root / c.input["head"]["root"], c.head_manifest),
                              profile=PROFILE, plan=PLAN,
                              host=HostConfig(out_root=self.out, eval=EvalIdentity(EVR1, "smoke-c01", 0),
                                              forbidden_roots=(self.suite.root,)), backend=backend)
            with self.assertRaises(PipelineError) as cm:
                run_review(spec)
            self.assertEqual(cm.exception.code, "invalid-input")
        self.assertEqual(spy.calls, 0)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_engine_identity_matches_the_scorers_redaction_fingerprint(self):
        self.assertEqual(engine_identity()["redaction"]["fingerprint"], redaction_fingerprint())

    def test_changed_script_identity_cannot_reuse_an_output_directory_or_replay_a_recording(self):
        self.make_suite_copy()
        res, spy = self.record_case("smoke-c01")
        self.assertEqual(res.run["configSnapshotId"], res.receipt["configSnapshotId"])
        sp = self.suite.root / "scripts/smoke-c01.json"
        sp.write_text(sp.read_text() + "\n")                    # one byte of script drift, same dataset digest
        drifted = load_suite(self.suite_dir)
        self.assertEqual(drifted.digest, self.suite.digest)
        self.suite = drifted
        self.cfg = synthetic_config_digest(drifted, config={"engine": engine_identity()})
        calls = spy.calls
        with self.assertRaises(PipelineError) as cm:
            self.record_case("smoke-c01")                          # same output root, same run id
        self.assertEqual(cm.exception.code, "identity-mismatch")
        self.assertIn("configSnapshotId", cm.exception.message)
        with self.assertRaises(PipelineError) as cm2:
            self.replay_case("smoke-c01", res)                     # recording was made under the old identity
        self.assertEqual(cm2.exception.code, "identity-mismatch")
        self.assertEqual(spy.calls, calls)


if __name__ == "__main__":
    unittest.main()
