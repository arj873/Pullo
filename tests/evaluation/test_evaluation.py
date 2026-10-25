"""S0-08 author tests: smoke record/replay through the real pipeline, label isolation, pins and refusals.

Run: nice -n 19 python3 -m unittest discover -s tests/evaluation -t .
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import loads_strict, require
from reviewer.contracts.canonical import canonical_json
from reviewer.gateway.providers import SyntheticProvider
from reviewer.pipeline import PipelineError, RecordBackend, ReplayBackend
from reviewer.scoring.suite import SuiteCase, load_suite, synthetic_config_digest
import reviewer.evaluation.runner as runner
from reviewer.evaluation import EvalError, compare_outcomes, eval_config, record_smoke, replay_smoke
from reviewer.__main__ import main as cli

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "fixtures" / "smoke"
CANARY = "CANARY-LABEL-9d41c7"
EXPECT = {"smoke-c01": ("completed", 1), "smoke-c02": ("completed", 0), "smoke-c03": ("completed", 1),
          "smoke-c04": ("completed", 1), "smoke-c05": ("partial", 0), "smoke-c06": ("failed", 0)}


def copy_suite(dest: Path, *, canary=False) -> Path:
    shutil.copytree(SMOKE, dest)
    if canary:
        p = dest / "labels" / "smoke-c01.json"
        doc = json.loads(p.read_text())
        doc["bugs"][0]["note"] = f"planted {CANARY} note"
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return dest


def files_under(root: Path):
    for dp, _, fns in os.walk(root):
        for fn in fns:
            yield Path(dp) / fn


class Recorded(unittest.TestCase):
    """One real recording and one strict replay shared by the read-only tests."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="s008-"))
        cls.suite = copy_suite(cls.tmp / "suite-src", canary=True)
        cls.specs, cls.requests = [], []
        real_run, real_call = runner.run_review, SyntheticProvider.call

        def spy_run(spec):
            cls.specs.append(spec)
            return real_run(spec)

        def spy_call(self, request, key):
            cls.requests.append(copy.deepcopy(request))
            return real_call(self, request, key)

        with mock.patch.object(runner, "run_review", spy_run), mock.patch.object(SyntheticProvider, "call", spy_call):
            cls.rec = record_smoke(cls.tmp / "rec", suite_dir=cls.suite)
            cls.n_record_requests = len(cls.requests)
            cls.rep = replay_smoke(cls.tmp / "rec", cls.tmp / "rep", suite_dir=cls.suite,
                                   manifest_digest=cls.rec.manifest_digest)
        cls.manifest = json.loads((cls.tmp / "rec" / "eval.json").read_text())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---------------------------------------------------------------- record
    def test_record_all_six_cases_meet_scorer_expectations(self):
        self.assertEqual(self.rec.exit_code, 0, self.rec.summary)
        got = {c.case_id: (c.status, c.case_result["comments"]) for c in self.rec.cases}
        self.assertEqual(got, EXPECT)
        self.assertTrue(all(c.case_result["expectationMet"] for c in self.rec.cases))
        c06 = next(c for c in self.rec.cases if c.case_id == "smoke-c06")
        self.assertEqual(c06.case_result["error"]["code"], "provider-timeout")
        c05 = next(c for c in self.rec.cases if c.case_id == "smoke-c05")
        self.assertIn("verifier-failure", [i["reason"] for i in c05.case_result["incomplete"]])
        rep = require("EvalReport", loads_strict((self.tmp / "rec" / "report.json").read_bytes()))
        self.assertEqual(rep["mode"], "live")
        self.assertEqual(len(rep["cases"]), 6)
        self.assertEqual(rep["coverage"]["expectationMet"], 6)

    def test_config_digest_is_synthetic_config_digest_with_engine_plan_profile(self):
        frozen = load_suite(self.tmp / "rec" / "suite")
        profile, plan = runner.default_profile_plan()
        want = synthetic_config_digest(frozen, eval_config(profile, plan))
        self.assertEqual(self.rec.report["configDigest"], want)
        self.assertEqual(self.manifest["configDigest"], want)
        for spec in self.specs[:6]:
            self.assertEqual(spec.host.config_identity, want)
        self.assertIn("engine", self.manifest["config"])
        self.assertIn("plan", self.manifest["config"])
        self.assertIn("profile", self.manifest["config"])

    def test_engine_gets_caseinput_and_pinned_snapshots_only(self):
        frozen = (self.tmp / "rec" / "suite").resolve()
        self.assertEqual(len(self.specs), 12)       # six record + six replay
        for spec in self.specs:
            self.assertIsInstance(spec.case, dict)
            self.assertNotIsInstance(spec.case, SuiteCase)
            self.assertNotIn("labels", spec.case)
            self.assertNotIn(CANARY, canonical_json([spec.case, spec.profile, spec.plan]).decode())
            for snap in (spec.base, spec.head):
                root = Path(snap.root).resolve()
                self.assertTrue(frozen in root.parents or (self.tmp / "rep" / "suite").resolve() in root.parents)
                self.assertNotIn("labels", root.parts)
        self.assertIsInstance(self.specs[0].backend, RecordBackend)
        self.assertIsInstance(self.specs[-1].backend, ReplayBackend)

    def test_label_canary_never_reaches_provider_or_outputs(self):
        self.assertGreater(len(self.requests), 0)
        for req in self.requests:
            text = canonical_json(req).decode()
            self.assertNotIn(CANARY, text)
            self.assertNotIn("smoke-auth-bypass", text)
            self.assertNotIn("case-labels@1", text)
        for d in ("rec", "rep"):
            for p in files_under(self.tmp / d / "runs"):
                data = p.read_bytes()
                self.assertNotIn(CANARY.encode(), data, p)
                self.assertNotIn(b"smoke-auth-bypass", data, p)

    def test_one_shared_durable_spend_book(self):
        books = {id(s.backend.book) for s in self.specs[:6]}
        self.assertEqual(len(books), 1)
        lines = [json.loads(x) for x in (self.tmp / "rec" / "operator" / "spend-book.jsonl").read_text().splitlines()]
        self.assertEqual({op["auth"] for op in lines}, {self.manifest["authorization"]["digest"]})
        reserves = sum(1 for op in lines if op["op"] == "reserve")
        closes = sum(1 for op in lines if op["op"] == "close")
        self.assertEqual(reserves, closes)
        self.assertEqual(reserves, self.rec.report["cost"]["liveCalls"])
        self.assertEqual(self.manifest["authorization"]["providers"], ["synthetic"])
        self.assertEqual(self.manifest["spendBook"]["totals"]["inflight"], 0)

    def test_frozen_scripts_hashed_and_read_only(self):
        frozen = self.tmp / "rec" / "suite"
        for rel, sha in self.manifest["suite"]["scripts"]:
            data = (frozen / rel).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
            self.assertEqual((frozen / rel).stat().st_mode & 0o222, 0)

    def test_pin_lives_outside_run_directories(self):
        for e in self.manifest["cases"]:
            run_dir = self.tmp / "rec" / e["runDir"]
            trace = (run_dir / "trace.jsonl").read_bytes()
            self.assertEqual(e["traceDigest"], "sha256:" + hashlib.sha256(trace).hexdigest())
            self.assertNotIn(run_dir, (self.tmp / "rec" / "eval.json").parents)

    # ---------------------------------------------------------------- replay
    def test_replay_recomputes_equal_outputs_with_zero_provider_calls(self):
        self.assertEqual(self.rep.exit_code, 0, self.rep.summary)
        self.assertEqual(len(self.requests), self.n_record_requests)   # no provider call during replay
        rep = self.rep.report
        self.assertEqual(rep["mode"], "strict-replay")
        self.assertEqual(rep["replayOf"], self.rec.eval_run_id)
        self.assertEqual(rep["cost"]["liveCalls"], 0)
        self.assertEqual(rep["cost"]["byBasis"]["replayed"]["records"],
                         self.rec.report["cost"]["byBasis"]["synthetic"]["records"])
        for c in self.rep.cases:
            self.assertTrue(c.comparison["equal"], c.comparison)
            self.assertEqual(c.outcome["cost"]["gateway"]["unconsumedRecordedCalls"], 0)
            self.assertEqual(c.outcome["cost"]["gateway"]["liveCalls"], 0)
            self.assertIsNotNone(c.case_result["latencyMs"]["original"])
            self.assertIsNotNone(c.case_result["latencyMs"]["replay"])
        rec_ids = {c.case_id: c.run_id for c in self.rec.cases}
        for c in self.rep.cases:
            self.assertNotEqual(c.run_id, rec_ids[c.case_id])
            self.assertEqual(c.result.run["replayOf"], rec_ids[c.case_id])
            pin = c.result.receipt["pin"]
            self.assertEqual(pin["source"], "recording-manifest")
            want = next(e["traceDigest"] for e in self.manifest["cases"] if e["caseId"] == c.case_id)
            self.assertEqual(pin["traceDigest"], want)

    def test_replay_comparison_is_not_vacuous(self):
        c01 = next(c for c in self.rep.cases if c.case_id == "smoke-c01")
        self.assertEqual(len(c01.outcome["comments"]), 1)
        self.assertEqual(len(c01.outcome["findings"]), 1)
        rec01 = json.loads((self.tmp / "rec" / "outcomes" / "smoke-c01.json").read_text())
        broken = copy.deepcopy(rec01)
        broken["comments"][0]["body"] += " (edited)"
        self.assertFalse(compare_outcomes(broken, c01.outcome)["equal"])
        broken = copy.deepcopy(rec01)
        broken["findings"] = []
        self.assertFalse(compare_outcomes(broken, c01.outcome)["equal"])
        for k, v in (("unconsumedRecordedCalls", 1), ("unconsumedRecordedCalls", None), ("liveCalls", 2)):
            out = copy.deepcopy(c01.outcome)
            out["cost"]["gateway"][k] = v
            self.assertFalse(compare_outcomes(rec01, out)["equal"], k)
        out = copy.deepcopy(c01.outcome)
        out["cost"]["replayedCalls"] -= 1
        self.assertFalse(compare_outcomes(rec01, out)["equal"])

    # ---------------------------------------------------------------- replay refusals and failures
    def _rec_copy(self, name) -> Path:
        dst = self.tmp / name
        shutil.copytree(self.tmp / "rec", dst)
        return dst

    def test_tampered_trace_fails_that_case_and_reports_all_six(self):
        rec = self._rec_copy("rec-tamper")
        e = next(x for x in self.manifest["cases"] if x["caseId"] == "smoke-c01")
        trace = rec / e["runDir"] / "trace.jsonl"
        data = trace.read_bytes()
        tampered = data.replace(b'"seq": 0', b'"seq":  0', 1)
        self.assertNotEqual(data, tampered)
        trace.write_bytes(tampered)
        out = replay_smoke(rec, self.tmp / "rep-tamper", suite_dir=self.suite)
        self.assertEqual(out.exit_code, 1)
        self.assertEqual(len(out.report["cases"]), 6)
        c01 = next(c for c in out.cases if c.case_id == "smoke-c01")
        self.assertEqual(c01.status, "failed")
        self.assertFalse(c01.ran)
        self.assertEqual(c01.case_result["error"]["code"], "replay-mismatch")
        self.assertFalse(c01.comparison["equal"])
        self.assertTrue(all(c.comparison["equal"] for c in out.cases if c.case_id != "smoke-c01"))

    def test_manifest_digest_mismatch_refused(self):
        with self.assertRaises(EvalError):
            replay_smoke(self.tmp / "rec", self.tmp / "rep-md", suite_dir=self.suite,
                         manifest_digest="sha256:" + "0" * 64)

    def test_tampered_outcome_pin_refused(self):
        rec = self._rec_copy("rec-outcome")
        p = rec / "outcomes" / "smoke-c02.json"
        p.write_bytes(p.read_bytes() + b"\n")
        with self.assertRaises(EvalError) as cm:
            replay_smoke(rec, self.tmp / "rep-outcome", suite_dir=self.suite)
        self.assertIn("pin", str(cm.exception))

    def test_changed_script_is_config_drift(self):
        suite2 = copy_suite(self.tmp / "suite-drift", canary=True)
        p = suite2 / "scripts" / "smoke-c02.json"
        p.write_bytes(p.read_bytes() + b"\n")
        with self.assertRaises(EvalError) as cm:
            replay_smoke(self.tmp / "rec", self.tmp / "rep-drift", suite_dir=suite2)
        self.assertEqual(cm.exception.code, "config-drift")

    def test_replay_output_inside_recording_refused(self):
        with self.assertRaises(EvalError):
            replay_smoke(self.tmp / "rec", self.tmp / "rec" / "nested", suite_dir=self.suite)


class Refusals(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="s008r-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dirty_symlink_and_inside_suite_outputs_refused(self):
        suite = copy_suite(self.tmp / "suite")
        dirty = self.tmp / "dirty"
        dirty.mkdir()
        (dirty / "x").write_text("x")
        with self.assertRaises(EvalError):
            record_smoke(dirty, suite_dir=suite)
        link = self.tmp / "link"
        (self.tmp / "target").mkdir()
        link.symlink_to(self.tmp / "target")
        with self.assertRaises(EvalError):
            record_smoke(link, suite_dir=suite)
        with self.assertRaises(EvalError):
            record_smoke(suite / "out", suite_dir=suite)
        self.assertFalse((suite / "out").exists())

    def test_stray_script_refused(self):
        suite = copy_suite(self.tmp / "suite")
        shutil.copy(suite / "scripts" / "smoke-c01.json", suite / "scripts" / "extra.json")
        with self.assertRaises(EvalError) as cm:
            record_smoke(self.tmp / "out", suite_dir=suite)
        self.assertIn("extra.json", str(cm.exception))

    def test_symlink_in_suite_refused(self):
        suite = copy_suite(self.tmp / "suite")
        (suite / "cases" / "smoke-c01" / "head" / "link").symlink_to("/etc/hostname")
        with self.assertRaises(EvalError):
            record_smoke(self.tmp / "out", suite_dir=suite)

    def test_real_provider_profile_refused(self):
        profile, plan = runner.default_profile_plan()
        profile["roles"]["judge"]["provider"] = "anthropic"
        with self.assertRaises(EvalError):
            record_smoke(self.tmp / "out", suite_dir=SMOKE, profile=profile, plan=plan)
        profile["roles"]["judge"].update(family="claude", model="claude-sonnet-5-5")   # contract-valid real role
        with self.assertRaises(EvalError) as cm:
            record_smoke(self.tmp / "out", suite_dir=SMOKE, profile=profile, plan=plan)
        self.assertIn("synthetic-only", str(cm.exception))
        self.assertFalse((self.tmp / "out").exists())

    def test_incomplete_script_under_real_caps_refused(self):
        _, plan = runner.default_profile_plan()
        plan["budget"]["maxRetriesPerCall"] = 1     # c05/c06 script three error attempts
        with self.assertRaises(EvalError) as cm:
            record_smoke(self.tmp / "out", suite_dir=SMOKE, plan=plan)
        self.assertIn("suite check failed", str(cm.exception))


class Faults(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="s008f-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rr1_bad_run_id_is_not_scored_as_that_run(self):
        real = runner.run_review

        def wrong_id(spec):
            r = real(spec)
            if spec.case["id"] == "smoke-c01":
                r.run_id = None
            return r
        with mock.patch.object(runner, "run_review", wrong_id):
            out = record_smoke(self.tmp / "out", suite_dir=SMOKE)
        c01 = next(c for c in out.cases if c.case_id == "smoke-c01")
        self.assertTrue(any("run id" in p for p in c01.problems))
        self.assertEqual(out.exit_code, 1)
        self.assertEqual(c01.case_result["truePositives"], 1)      # scored against the run actually requested

    def test_pipeline_refusal_becomes_failed_case_others_continue(self):
        real = runner.run_review

        def refuse(spec):
            if spec.case["id"] == "smoke-c02":
                raise PipelineError("identity-mismatch", "injected")
            return real(spec)
        with mock.patch.object(runner, "run_review", refuse):
            out = record_smoke(self.tmp / "out", suite_dir=SMOKE)
        self.assertEqual(out.exit_code, 1)
        self.assertEqual(len(out.report["cases"]), 6)
        c02 = next(c for c in out.cases if c.case_id == "smoke-c02")
        self.assertEqual((c02.status, c02.ran), ("failed", False))
        self.assertEqual(c02.case_result["error"]["code"], "contract-violation")
        self.assertFalse(c02.case_result["expectationMet"])
        self.assertEqual(sum(1 for c in out.cases if c.case_result["expectationMet"]), 5)
        # the case without a run is reported as not replayable, not skipped
        rep = replay_smoke(self.tmp / "out", self.tmp / "rep", suite_dir=SMOKE)
        r02 = next(c for c in rep.cases if c.case_id == "smoke-c02")
        self.assertEqual(r02.case_result["error"]["code"], "replay-miss")
        self.assertEqual(rep.exit_code, 1)
        self.assertEqual(len(rep.report["cases"]), 6)

    def test_cancelled_case_is_reported_not_hidden(self):
        out = record_smoke(self.tmp / "out", suite_dir=SMOKE,
                           host_extra=lambda cid: {"cancel": (lambda: True)} if cid == "smoke-c01" else {})
        c01 = next(c for c in out.cases if c.case_id == "smoke-c01")
        self.assertEqual(c01.status, "cancelled")
        self.assertEqual(out.report["coverage"]["cancelled"], 1)
        self.assertEqual(out.exit_code, 1)


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="s008c-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_documented_commands_end_to_end(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        r = subprocess.run([sys.executable, "-m", "reviewer", "smoke", "record", "--out", str(self.tmp / "rec")],
                           capture_output=True, text=True, cwd=self.tmp, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("smoke record: OK", r.stdout)
        r = subprocess.run([sys.executable, "-m", "reviewer", "smoke", "replay", "--recording", str(self.tmp / "rec"),
                            "--out", str(self.tmp / "rep")], capture_output=True, text=True, cwd=self.tmp, env=env,
                           timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("smoke replay: OK", r.stdout)
        self.assertEqual(r.stdout.count("replay equal"), 6)

    def test_refusal_exit_2_without_traceback(self):
        (self.tmp / "dirty").mkdir()
        (self.tmp / "dirty" / "f").write_text("x")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = cli(["smoke", "record", "--out", str(self.tmp / "dirty")])
            rc2 = cli(["smoke", "replay", "--recording", str(self.tmp / "missing"), "--out", str(self.tmp / "o")])
        self.assertEqual((rc, rc2), (2, 2))
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("not empty", err.getvalue())


if __name__ == "__main__":
    unittest.main()
