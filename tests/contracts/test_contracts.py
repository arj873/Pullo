"""S0-03 contract tests. Run: nice -n 19 python3 -m unittest discover -s tests -t ."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts import (ENTITY_NAMES, ContractViolation, check_finding_provenance,
                                require, validate, validate_trace)
from reviewer.contracts import budget as B
from reviewer.contracts import canonical as C
from reviewer.contracts import redaction as R
from reviewer.contracts import severity as S
from reviewer.contracts import stages as ST
from reviewer.contracts.snapshot import SnapshotError, build_manifest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "reviewer" / "contracts" / "examples"


def ex(name: str) -> dict:
    return json.loads((EXAMPLES / f"{name}.json").read_text())


class Base(unittest.TestCase):
    def assertInvalid(self, entity: str, doc, code: str | None = None):
        issues = validate(entity, doc)
        self.assertTrue(issues, f"{entity} unexpectedly valid")
        if code:
            self.assertIn(code, {i.code for i in issues}, [str(i) for i in issues])


class ExamplesAndBundle(Base):
    def test_every_example_is_valid(self):
        files = sorted(EXAMPLES.glob("*.json"))
        self.assertGreaterEqual(len(files), 10)
        for f in files:
            with self.subTest(f.name):
                self.assertEqual(validate(f.name.split(".")[0], json.loads(f.read_text())), [])

    def test_schema_bundle_is_current_and_complete(self):
        r = subprocess.run([sys.executable, "-m", "reviewer.contracts", "export", "--check"],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        bundle = json.loads((ROOT / "reviewer/contracts/schemas/contracts.schema.json").read_text())
        self.assertEqual(sorted(bundle["$defs"]), list(ENTITY_NAMES))

    def test_require_raises(self):
        with self.assertRaises(ContractViolation):
            require("Plan", {})


class LabelIsolation(Base):
    def test_case_input_rejects_label_fields(self):
        doc = ex("CaseInput")
        for leak in ("bugs", "expect", "fixCommit", "labels"):
            with self.subTest(leak):
                self.assertInvalid("CaseInput", {**doc, leak: []}, "unknown-field")

    def test_suite_requires_labels_directory(self):
        doc = ex("SuiteManifest")
        bad = copy.deepcopy(doc)
        bad["cases"][0]["labels"] = "cases/auth-bypass-001/labels.json"
        self.assertInvalid("SuiteManifest", bad, "suite-separation")
        bad = copy.deepcopy(doc)
        bad["cases"][0]["input"] = "labels/input.json"
        self.assertInvalid("SuiteManifest", bad, "suite-separation")

    def test_labels_expectation_consistency(self):
        doc = ex("CaseLabels")
        self.assertInvalid("CaseLabels", {**doc, "expect": "silence"}, "labels-consistent")
        self.assertInvalid("CaseLabels", {**doc, "expect": "partial"}, "labels-consistent")
        self.assertEqual(validate("CaseLabels", {**doc, "expect": "silence", "bugs": []}), [])


class EvidenceAndFindings(Base):
    def test_hostile_paths_rejected(self):
        ev = ex("Finding")["evidence"][0]
        for p in ("../etc/passwd", "/etc/passwd", "a/../b", "a//b", "a\\b", "./a", "a/", ""):
            with self.subTest(p):
                self.assertInvalid("Evidence", {**ev, "path": p}, "unsafe-path")

    def test_code_evidence_needs_pin_and_non_code_needs_tool_call(self):
        ev = ex("Finding")["evidence"][0]
        self.assertInvalid("Evidence", {k: v for k, v in ev.items() if k != "commit"},
                           "evidence-shape")
        self.assertInvalid("Evidence", {"kind": "tool-result", "excerpt": "", "source": "search"},
                           "evidence-shape")
        self.assertInvalid("Evidence", {**ev, "lines": [12, 10]}, "evidence-shape")

    def test_finding_needs_distinct_call_provenance(self):
        f = ex("Finding")
        self.assertInvalid("Finding", {k: v for k, v in f.items() if k != "sourceCallId"}, "required")
        f["verification"]["callIds"] = [f["sourceCallId"]]
        self.assertInvalid("Finding", f, "independent-confirm")

    def test_finding_verdict_is_confirmed_only(self):
        f = ex("Finding")
        f["verification"]["verdict"] = "uncertain"
        self.assertInvalid("Finding", f, "const")

    def test_comment_draft_vs_posted(self):
        c = ex("Comment")
        self.assertInvalid("Comment", {**c, "hostCommentId": "123"}, "comment-state")
        self.assertInvalid("Comment", {**c, "state": "posted"}, "comment-state")
        ok = {**c, "state": "posted", "hostCommentId": "1", "postedAt": "2026-10-25T10:00:00Z"}
        self.assertEqual(validate("Comment", ok), [])

    def test_verifier_output_confirm_needs_citation(self):
        doc = {"verdict": "confirmed", "reachable": True, "impact": "crash", "evidence": [],
               "notes": ""}
        self.assertInvalid("VerifierOutput", doc, "confirm-cited")


class RunIdentity(Base):
    def test_local_run_rejects_pr_fields(self):
        self.assertInvalid("ReviewRun", {**ex("ReviewRun"), "headSha": "a" * 40}, "run-rules")

    def test_rerun_identity(self):
        run = ex("ReviewRun")
        self.assertInvalid("ReviewRun", {**run, "attempt": 2}, "run-rules")
        rerun = {**run, "attempt": 2, "rerunOf": run["id"], "trigger": "manual-rerun"}
        self.assertInvalid("ReviewRun", rerun, "run-rules")  # eval fields with manual trigger

    def test_live_mode_needs_authorization(self):
        run = {k: v for k, v in ex("ReviewRun").items() if k != "replayOf"}
        self.assertInvalid("ReviewRun", {**run, "mode": "live"}, "run-rules")
        self.assertInvalid("ReviewRun", {**run, "mode": "live", "spendAuthorization": "auth-1"},
                           "pattern")
        auth = C.digest(ex("SpendAuthorization.synthetic-recording"))
        self.assertEqual(validate("ReviewRun", {**run, "mode": "live",
                                                "spendAuthorization": auth}), [])

    def test_status_explanations(self):
        run = ex("ReviewRun")
        self.assertInvalid("ReviewRun", {**run, "status": "partial"}, "run-rules")
        self.assertInvalid("ReviewRun", {**run, "status": "failed"}, "run-rules")
        failed = {**run, "status": "failed", "error": {"code": "replay-miss", "message": "m",
                                                       "retryable": False}}
        self.assertEqual(validate("ReviewRun", failed), [])

    def test_ids_are_deterministic_and_rerun_distinct(self):
        k = C.idempotency_key_local("repo", "snap:sha256:" + "0" * 64, "snap:sha256:" + "1" * 64)
        self.assertEqual(C.run_id(k, 1), C.run_id(k, 1))
        self.assertNotEqual(C.run_id(k, 1), C.run_id(k, 2))
        e1 = C.idempotency_key_eval("evr_" + "0" * 16, "c", 0, "b", "h")
        e2 = C.idempotency_key_eval("evr_" + "0" * 16, "c", 1, "b", "h")
        self.assertNotEqual(e1, e2)


class Costs(Base):
    def test_eval_cost_attribution(self):
        doc = ex("CostRecord.eval-synthetic")
        self.assertInvalid("CostRecord", {k: v for k, v in doc.items() if k != "evalRunId"},
                           "cost-attribution")
        self.assertInvalid("CostRecord", {**doc, "kind": "index"}, "cost-attribution")

    def test_unknown_is_never_zero(self):
        doc = ex("CostRecord.eval-synthetic")
        self.assertInvalid("CostRecord", {**doc, "basis": "unknown", "usdMicros": 0},
                           "cost-attribution")
        self.assertInvalid("CostRecord", {**doc, "basis": "measured", "usdMicros": 5,
                                          "provider": "anthropic", "priceVersion": None},
                           "cost-attribution")
        self.assertInvalid("CostRecord", {**doc, "basis": "replayed"}, "cost-attribution")


class Profiles(Base):
    def test_runtime_roles_pinned_and_not_dev_only(self):
        p = ex("ModelProfile.standard-candidate")
        for model in ("gpt-6.1-sol", "claude-opus-5-5", "claude-sonnet-latest"):
            bad = copy.deepcopy(p)
            bad["roles"]["verifier"]["model"] = model
            with self.subTest(model):
                self.assertInvalid("ModelProfile", bad, "role-pinning")

    def test_no_fallbacks_and_priced_when_resolved(self):
        p = ex("ModelProfile.standard-candidate")
        bad = copy.deepcopy(p)
        bad["roles"]["judge"]["fallbacks"] = ["other@1"]
        self.assertInvalid("ModelProfile", bad, "max-items")
        bad = copy.deepcopy(p)
        bad["roles"]["investigator"]["resolved"] = True
        self.assertInvalid("ModelProfile", bad, "role-pinning")


class TraceAndArtifacts(Base):
    def test_model_call_outcome(self):
        ev = ex("TraceEvent.model-call")
        self.assertInvalid("TraceEvent", {**ev, "response": None}, "call-outcome")
        self.assertInvalid("TraceEvent", {**ev, "type": "model.retry"}, "enum")

    def test_stage_names_fixed(self):
        self.assertEqual(ST.STAGES, ("INGEST", "PREPARE", "TRIAGE", "INVESTIGATE", "VERIFY",
                                     "JUDGE", "PUBLISH", "LEARN"))
        self.assertInvalid("TraceEvent", {"schema": "trace-event@1", "runId": "run_" + "0" * 16,
                                          "seq": 0, "type": "stage.start", "stage": "REVIEW"})
        self.assertTrue(ST.can_transition("running", "partial"))
        self.assertFalse(ST.can_transition("completed", "running"))
        self.assertEqual(ST.artifact_name("VERIFY", 1), "05-VERIFY.v1.json")

    def test_artifact_payload_must_match_stage(self):
        a = ex("StageArtifact.learn-skipped")
        self.assertInvalid("StageArtifact", {**a, "stage": "PUBLISH"}, "artifact-stage")
        self.assertInvalid("StageArtifact", {**a, "payload": {"stage": "LEARN", "enabled": True}},
                           "artifact-stage")

    def test_replay_comparison_ignores_run_scope_and_latency(self):
        f = ex("Finding")
        g = {**copy.deepcopy(f), "runId": "run_" + "f" * 16}
        self.assertEqual(C.comparable_digest(f), C.comparable_digest(g))
        g["claim"] = "different"
        self.assertNotEqual(C.comparable_digest(f), C.comparable_digest(g))

    def test_request_hash_detects_altered_request(self):
        req = ex("TraceEvent.model-call")["request"]
        self.assertEqual(C.request_hash(req), ex("TraceEvent.model-call")["requestHash"])
        alt = copy.deepcopy(req)
        alt["messages"][1]["content"] += " "
        self.assertNotEqual(C.request_hash(req), C.request_hash(alt))

    def test_fingerprint_ignores_line_moves_and_whitespace(self):
        a = C.comment_fingerprint("bug", "a.py", "x = y  / z", "Divide by zero", "f")
        self.assertEqual(a, C.comment_fingerprint("bug", "a.py", "x = y / z", "divide  by zero", "f"))
        self.assertNotEqual(a, C.comment_fingerprint("bug", "b.py", "x = y / z", "Divide by zero", "f"))


class Metrics(Base):
    def test_undefined_denominator(self):
        self.assertEqual(validate("Ratio", {"value": None, "numerator": 0, "denominator": 0,
                                            "undefinedReason": "no-comments"}), [])
        self.assertInvalid("Ratio", {"value": 0.0, "numerator": 0, "denominator": 0,
                                     "undefinedReason": None}, "ratio-defined")
        self.assertInvalid("Ratio", {"value": 0.9, "numerator": 1, "denominator": 2,
                                     "undefinedReason": None}, "ratio-defined")

    def test_strict_replay_report_has_zero_live_calls(self):
        r = ex("EvalReport.strict-replay")
        r["cost"]["liveCalls"] = 1
        self.assertInvalid("EvalReport", r, "report-honesty")
        r = ex("EvalReport.strict-replay")
        r["limitations"] = []
        self.assertInvalid("EvalReport", r, "min-items")


class Snapshots(Base):
    def test_manifest_identity_and_symlinks_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "head"
            (root / "src").mkdir(parents=True)
            (root / "src" / "a.py").write_text("print(1)\n")
            os.symlink("/etc/passwd", root / "escape")
            os.symlink("/etc", root / "dirlink")
            m = build_manifest(root)
            self.assertEqual(validate("SnapshotManifest", m), [])
            kinds = {e["path"]: e["type"] for e in m["entries"]}
            self.assertEqual(kinds["escape"], "symlink")
            self.assertEqual(kinds["dirlink"], "symlink")
            self.assertNotIn("dirlink/passwd", kinds)
            self.assertEqual(build_manifest(root)["snapshotId"], m["snapshotId"])
            (root / "src" / "a.py").write_text("print(2)\n")
            self.assertNotEqual(build_manifest(root)["snapshotId"], m["snapshotId"])
            tampered = {**m, "entries": m["entries"][::-1]}
            self.assertInvalid("SnapshotManifest", tampered, "snapshot-digest")

    def test_special_files_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(Path(d) / "pipe")
            with self.assertRaises(SnapshotError):
                build_manifest(d)


class Redaction(Base):
    def test_protected_patterns(self):
        secrets = ["RVWCANARY_abcdefghijklmnop12", "AKIAABCDEFGHIJKLMNOP",
                   "ghp_" + "a" * 36, "sk-ant-" + "b" * 30, "sk-proj-" + "c" * 30,
                   "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"]
        for s in secrets:
            with self.subTest(s[:12]):
                out, counts = R.redact(f"x = '{s}'")
                self.assertNotIn(s, out)
                self.assertFalse(R.contains_protected(out))
                self.assertEqual(sum(counts.values()), 1)

    def test_redact_json_and_ordinary_code_untouched(self):
        doc, counts = R.redact_json({"k": ["RVWCANARY_abcdefghijklmnop12", "def f(): pass"]})
        self.assertEqual(doc["k"][1], "def f(): pass")
        self.assertEqual(counts, {"canary": 1})


class Severity(Base):
    def _ev(self, *paths, kind="code"):
        return [{"kind": kind, "path": p, "lines": [1, 2], "commit": "a" * 40, "resolved": True}
                for p in paths]

    def test_p0_needs_trusted_evidence_not_file_count(self):
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, self._ev("a.py")), "P0")
        self.assertEqual(S.severity_ceiling("bug", "crash", False, self._ev("a.py", "b.py")), "P2")
        self.assertEqual(S.severity_ceiling("bug", "crash", True, []), "P2")
        fake = {"kind": "test-run", "toolCallId": "tool_" + "0" * 16, "excerpt": "", "source": "m"}
        self.assertEqual(S.severity_ceiling("bug", "crash", True, [fake]), "P2")
        self.assertFalse(S.has_strong_evidence([fake]))

    def test_category_ceilings(self):
        self.assertEqual(S.severity_ceiling("style", "crash", True, self._ev("a")), "P2")
        self.assertEqual(S.severity_ceiling("test-gap", "incorrect-result", True, self._ev("a")), "P2")
        self.assertEqual(S.severity_ceiling("performance", "performance", True, self._ev("a")), "P1")

    def test_judge_never_exceeds_ceiling_or_promotes_silently(self):
        self.assertEqual(S.judge_severity("P0", "P0", "P1"), "P1")
        self.assertEqual(S.judge_severity("P0", "P2", "P0"), "P2")
        self.assertEqual(S.judge_severity("P0", "P2", "P0", "trace shows reach"), "P0")
        self.assertEqual(S.finding_ceiling(ex("Finding")), "P0")
        with self.assertRaises(ValueError):
            S.judge_severity("P3", "P1", "P1")


class Budget(Base):
    b = B.STANDARD_S0A_BUDGET

    def test_valid_default(self):
        self.assertEqual(validate("Budget", self.b), [])
        self.assertInvalid("Budget", {**self.b, "softDeadlineSec": 999}, "budget-order")

    def test_admission_refuses_rather_than_overruns(self):
        self.assertIsNone(B.admit_model_call(self.b, B.Spend(committed=3_000_000), "VERIFY",
                                             1_000_000))
        err = B.admit_model_call(self.b, B.Spend(committed=3_000_000, inflight=1), "VERIFY",
                                 1_000_000)
        self.assertEqual(err["code"], "budget-exhausted")
        self.assertEqual(validate("TypedError", err), [])

    def test_verify_reserve_protected(self):
        limit = B.investigation_limit(self.b)
        self.assertEqual(limit, 2_800_000)
        self.assertIsNotNone(B.admit_model_call(
            self.b, B.Spend(committed=limit, committed_investigate=limit), "INVESTIGATE", 1))
        self.assertIsNone(B.admit_model_call(
            self.b, B.Spend(committed=limit, committed_investigate=limit), "VERIFY", 1))

    def test_tool_caps(self):
        self.assertIsNotNone(B.admit_tool_call(self.b, 60, 0, "INVESTIGATE"))
        self.assertIsNotNone(B.admit_tool_call(self.b, 0, 30, "VERIFY"))
        self.assertIsNone(B.admit_tool_call(self.b, 59, 29, "VERIFY"))

    def test_unknown_usage_keeps_reservation(self):
        price = ex("ModelProfile.smoke-synthetic")["roles"]["investigator"]["price"]
        res = B.reservation(price, 10_000, 4_000)
        self.assertEqual(res, 37_500 + 60_000)  # dearest input rate (cache write)
        unknown = {k: None for k in ("uncachedInputTokens", "cachedInputTokens",
                                     "cacheWriteInputTokens", "outputTokens", "reasoningTokens")}
        self.assertEqual(B.settle(res, unknown, price), (res, "estimated", False))
        known = {**unknown, "uncachedInputTokens": 1000, "cachedInputTokens": 0,
                 "cacheWriteInputTokens": 0, "outputTokens": 100}
        self.assertEqual(B.settle(res, known, price), (3_000 + 1_500, "measured", False))


class RootDecisions(Base):
    """S0-03-fix: root decisions D1-D9 and review items C1-C14."""

    def test_d8_github_repo_identity_case_preserved(self):
        run = ex("ReviewRun.github-pr")
        self.assertEqual(run["repo"], "Vencord/Vesktop")
        self.assertEqual(C.idempotency_key_pr("vencord/vesktop", 1234, "3" * 40), run["idempotencyKey"])
        for repo in ("AnyPS5/orca", "Vencord/Vesktop", "fixture-auth"):
            self.assertTrue(C.GITHUB_REPO.fullmatch(repo) or repo == "fixture-auth")
        for bad in ("-x/y", "a/..", "a/b/c", "a/", "Owner Name/x"):
            with self.subTest(bad):
                self.assertInvalid("CaseInput", {**ex("CaseInput"), "repo": bad}, "pattern")
        self.assertInvalid("ReviewRun", {**run, "repo": "vesktop"}, "run-rules")

    def test_d8_pr_key_recomputed(self):
        run = ex("ReviewRun.github-pr")
        self.assertInvalid("ReviewRun", {**run, "prNumber": 1235}, "run-identity")

    def test_read_only_access_and_local_sink(self):
        run = ex("ReviewRun")
        self.assertInvalid("ReviewRun", {**run, "access": "read-write"}, "const")
        art = {"schema": "stage-artifact@1", "runId": run["id"], "stage": "PUBLISH",
               "planVersion": 1, "status": "completed", "inputDigest": C.digest(1),
               "payload": {"stage": "PUBLISH", "sink": "github", "path": "comments.json",
                           "commentIds": [], "summary": ""}, "costRecordIds": []}
        self.assertInvalid("StageArtifact", art, "enum")

    def test_d5_offline_modes_never_authorized(self):
        run = ex("ReviewRun")
        auth = C.digest(ex("SpendAuthorization.synthetic-recording"))
        self.assertInvalid("ReviewRun", {**run, "spendAuthorization": auth}, "run-rules")
        self.assertInvalid("ReviewRun", {**run, "mode": "stage-replay", "fromStage": "VERIFY",
                                         "spendAuthorization": auth}, "run-rules")

    def test_d5_spend_authorization_binds_provider_and_ceiling(self):
        auth = ex("SpendAuthorization.synthetic-recording")
        plan = ex("Plan")
        now = "2026-10-25T00:00:00Z"
        self.assertEqual(B.check_spend_authorization(auth, ex("ModelProfile.smoke-synthetic"),
                                                     plan["budget"], now), [])
        problems = B.check_spend_authorization(auth, ex("ModelProfile.standard-candidate"),
                                               plan["budget"], now)
        self.assertTrue(any("not authorized" in p for p in problems))
        self.assertTrue(any("not resolved" in p for p in problems))
        tight = {**auth, "maxUsdMicrosPerRun": 1}
        self.assertIn("Plan ceiling exceeds the authorized per-run ceiling",
                      B.check_spend_authorization(tight, ex("ModelProfile.smoke-synthetic"),
                                                  plan["budget"], now))
        self.assertIn("authorization expired", B.check_spend_authorization(
            auth, ex("ModelProfile.smoke-synthetic"), plan["budget"], "2027-01-01T00:00:00Z"))

    def test_d2_ledger_release_retain_and_atomicity(self):
        import threading
        led = B.Ledger({**B.STANDARD_S0A_BUDGET, "maxUsdMicros": 100})
        results = []
        barrier = threading.Barrier(2)

        def go(k):
            barrier.wait()
            results.append(led.reserve(k, "VERIFY", 80))
        ts = [threading.Thread(target=go, args=(k,)) for k in ("a", "b")]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(r is None for r in results), [False, True])
        key = next(iter(led._open))
        with self.assertRaises(ValueError):
            led.release(key, "timeout")
        self.assertEqual(led.retain(key), 80)
        self.assertEqual(led.spend(), B.Spend(committed=80))
        self.assertIsNone(led.reserve("c", "VERIFY", 20))
        led.release("c", "not-sent")
        self.assertEqual(led.spend().committed, 80)
        self.assertIsNone(led.reserve("d", "VERIFY", 20))
        led.settle("d", 25)
        self.assertEqual(led.overruns, ["d"])
        self.assertIsNotNone(led.reserve("e", "VERIFY", 1))

    def test_d7_effective_retries(self):
        caps = {"maxOutputTokens": 1, "timeoutSec": 1, "maxRetries": 3, "maxRepairs": 1}
        self.assertEqual(B.effective_retry_limits({**B.STANDARD_S0A_BUDGET, "maxRetriesPerCall": 0},
                                                  caps), (0, 1))
        self.assertEqual(B.effective_retry_limits(B.STANDARD_S0A_BUDGET, {**caps, "maxRetries": 1}),
                         (1, 1))

    def test_deadlines(self):
        b = B.STANDARD_S0A_BUDGET
        self.assertEqual([B.deadline_state(b, t) for t in (0, 240, 360)], ["ok", "soft", "hard"])
        self.assertTrue(B.stage_deadline_exceeded("VERIFY", 45))
        self.assertFalse(B.stage_deadline_exceeded("LEARN", 10**6))

    def test_d9_bounded_integers(self):
        self.assertInvalid("Budget", {**B.STANDARD_S0A_BUDGET, "maxUsdMicros": 10**30}, "int-range")
        self.assertInvalid("Budget", {**B.STANDARD_S0A_BUDGET, "maxUsdMicros": 10**10}, "maximum")

    def test_d1_real_prs_unscored(self):
        r = ex("EvalReport.unscored-real")
        self.assertEqual(validate("EvalReport", r), [])
        bad = copy.deepcopy(r)
        bad["metrics"]["precision"] = {"value": 1.0, "numerator": 1, "denominator": 1,
                                       "undefinedReason": None}
        self.assertInvalid("EvalReport", bad, "report-honesty")
        suite = {**ex("SuiteManifest"), "synthetic": False}
        self.assertInvalid("SuiteManifest", suite, "suite-separation")
        self.assertEqual(validate("SuiteManifest", {**suite, "matching": {"rule": "unadjudicated@1"}}), [])

    def test_c1_model_cannot_mint_strong_evidence(self):
        hyp = {"claim": "c", "category": "bug", "suspectedSeverity": "P0", "impact": "crash",
               "location": {"path": "a.py", "line": 1},
               "evidence": [{"kind": "analyzer", "toolCallId": "tool_" + "0" * 16}]}
        self.assertInvalid("InvestigatorOutput", {"hypotheses": [hyp]})
        ref = {"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16}
        tool_ev = {"kind": "analyzer", "excerpt": "taint", "source": "run_analyzer",
                   "toolCallId": "tool_" + "1" * 16}
        tc = {"type": "tool.call", "result": {"status": "ok", "evidence": [tool_ev]}}
        ev, problems = S.materialize_evidence([ref], {"tool_" + "1" * 16: tc}, "investigator")
        self.assertEqual((ev, problems), ([tool_ev], []))
        self.assertTrue(S.has_strong_evidence(ev, {"tool_" + "1" * 16: tc}))
        self.assertFalse(S.has_strong_evidence(ev, {}))
        _, problems = S.materialize_evidence([ref], {}, "investigator")
        self.assertTrue(problems)

    def test_d4_rank_by_evidence_strength_then_stable(self):
        def c(path, strength):
            return {"severity": "P1", "evidenceStrength": strength, "fingerprint": "fp2:" + "0" * 32,
                    "anchor": {"path": path, "startLine": 1}}
        cs = [c("a.py", "cited"), c("z.py", "reproduced"), c("m.py", "cited")]
        self.assertEqual([x["anchor"]["path"] for x in sorted(cs, key=S.comment_sort_key)],
                         ["z.py", "a.py", "m.py"])

    def test_c3_comment_and_cost_ids(self):
        self.assertInvalid("Comment", {**ex("Comment"), "id": "cmt_" + "f" * 16}, "comment-state")
        self.assertInvalid("CostRecord", {**ex("CostRecord.eval-synthetic"), "id": "cost_" + "f" * 16},
                           "cost-attribution")
        self.assertInvalid("Comment", {**ex("Comment"), "severityCeiling": "P1"}, "comment-state")

    def test_c5_persisted_entities_reject_secrets_and_lines_kept(self):
        self.assertInvalid("Comment", {**ex("Comment"), "body": "key AKIAIOSFODNN7EXAMPLE"},
                           "no-secrets")
        pem = "a\n-----BEGIN PRIVATE KEY-----\nx\ny\n-----END PRIVATE KEY-----\nb"
        self.assertEqual(R.redact(pem)[0].count("\n"), pem.count("\n"))
        out, _ = R.redact('password = "hunter2hunter2"')
        self.assertEqual(out, 'password = "[REDACTED:assigned-secret]"')

    def test_c6_strict_loader_and_no_crash(self):
        from reviewer.contracts import ContractInputError, loads_strict
        for bad in ('{"a":1,"a":2}', '{"a":NaN}', "{nope", '"\\ud800"', "[" * 100 + "]" * 100):
            with self.subTest(bad[:12]):
                with self.assertRaises(ContractInputError):
                    loads_strict(bad)
        self.assertTrue(validate("TraceEvent", {"type": []}))
        with self.assertRaises(TypeError):
            C.canonical_json({1: "x"})
        self.assertEqual(C.digest({"n": 1}), C.digest({"n": 1.0}))

    def test_c2_entity_aware_comparison_and_recipes(self):
        self.assertNotEqual(C.comparable_digest({"args": {"at": "a"}}),
                            C.comparable_digest({"args": {"at": "b"}}))
        a = ex("StageArtifact.learn-skipped")
        self.assertEqual(C.artifact_digest(a), C.artifact_digest({**a, "runId": "run_" + "1" * 16}))
        tr = {"status": "empty", "evidence": [], "completeness": "exact", "truncated": None,
              "notice": "no hits"}
        self.assertEqual(C.result_hash(tr), C.digest(tr))
        with self.assertRaises(ValueError):
            C.suite_digest(ex("SuiteManifest"), {})

    def test_c10_request_hash_guards(self):
        req = ex("TraceEvent.model-call")["request"]
        for bad in ("AKIAIOSFODNN7EXAMPLE", "see run_0123456789abcdef"):
            alt = copy.deepcopy(req)
            alt["messages"][1]["content"] = bad
            with self.subTest(bad), self.assertRaises(ValueError):
                C.request_hash(alt)

    def test_trace_file_rules(self):
        run = ex("ReviewRun")
        start = {"schema": "trace-event@1", "runId": run["id"], "seq": 0, "type": "run.start",
                 "run": run}
        end = {"schema": "trace-event@1", "runId": run["id"], "seq": 1, "type": "run.end",
               "status": "completed", "incomplete": []}
        self.assertEqual(validate_trace([start, end]), [])
        self.assertTrue(validate_trace([start, {**end, "seq": 2}]))
        self.assertTrue(validate_trace([end]))

    def test_c8_verified_reads(self):
        from reviewer.contracts.snapshot import excerpt_matches, read_verified, verify_manifest
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "src").mkdir()
            (root / "src" / "a.py").write_text("one\nkey = 'AKIAIOSFODNN7EXAMPLE'\nthree\n")
            os.symlink("/etc/passwd", root / "link")
            m = build_manifest(root)
            data = read_verified(root, m, "src/a.py")
            self.assertTrue(excerpt_matches(data, [2, 3], "key = '[REDACTED:aws-access-key]'\nthree"))
            self.assertFalse(excerpt_matches(data, [2, 2], "key = 'AKIAIOSFODNN7EXAMPLE'"))
            with self.assertRaises(SnapshotError):
                read_verified(root, m, "link")
            (root / "src" / "a.py").write_text("tampered\n")
            with self.assertRaises(SnapshotError):
                read_verified(root, m, "src/a.py")
            self.assertTrue(verify_manifest(root, m))


class FinalFix(Base):
    """S0-03-finalfix: RR1, RR2, RR4, RR6, RR9, RR10, RR12 (+ RR7/RR8 gateway helpers)."""

    def test_rr1_unresolved_code_is_untrusted_and_resolver_gates_trust(self):
        cite = {"kind": "code", "path": "a.py", "lines": [1, 1], "commit": None, "excerpt": "x = 1"}
        raw = {**cite, "commit": "a" * 40, "source": "m"}
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, [raw]), "P2")
        self.assertEqual(S.evidence_strength([raw]), "unsupported")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("x = 1\n")
            m = build_manifest(root)
            from reviewer.contracts.snapshot import snapshot_resolver
            res = snapshot_resolver({m["snapshotId"]: (root, m)})
            good = {**cite, "commit": m["snapshotId"]}
            bad = {**good, "excerpt": "x = 2"}
            other = {**good, "commit": "snap:sha256:" + "0" * 64}
            ev, problems = S.materialize_evidence([good, bad, other], {}, "investigator", res)
            self.assertEqual(len(ev), 1)
            self.assertEqual(len(problems), 2)
            self.assertIs(ev[0]["resolved"], True)
            self.assertEqual(validate("Evidence", ev[0]), [])
            self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, ev), "P0")
            unresolved, _ = S.materialize_evidence([good], {}, "investigator")
            self.assertNotIn("resolved", unresolved[0])
        self.assertInvalid("ModelEvidence", {**good, "resolved": True}, "unknown-field")
        self.assertInvalid("Evidence", {**raw, "resolved": False}, "const")

    def test_rr2_trace_ids_and_hashes_tied_to_payload(self):
        ev = ex("TraceEvent.model-call")
        self.assertEqual(validate("TraceEvent", ev), [])
        self.assertInvalid("TraceEvent", {**ev, "requestHash": "sha256:" + "0" * 64}, "call-outcome")
        self.assertInvalid("TraceEvent", {**ev, "costRecordId": "cost_" + "f" * 16}, "call-outcome")
        self.assertInvalid("TraceEvent", {**ev, "ordinal": 1}, "call-outcome")
        result = {"status": "empty", "evidence": [], "completeness": "exact", "truncated": None,
                  "notice": ""}
        args = {"path": "a.py"}
        tid = C.tool_call_id("INVESTIGATE", "a1", 0, "read-file", args)
        tool = {"schema": "trace-event@1", "runId": ev["runId"], "seq": 1, "type": "tool.call",
                "toolCallId": tid, "stage": "INVESTIGATE", "agentId": "a1", "ordinal": 0,
                "tool": "read-file", "args": args, "resultHash": C.result_hash(result),
                "result": result, "redactions": {}}
        self.assertEqual(validate("TraceEvent", tool), [])
        self.assertInvalid("TraceEvent", {**tool, "args": {"path": "b.py"}}, "tool-identity")
        self.assertInvalid("TraceEvent", {**tool, "resultHash": "sha256:" + "0" * 64}, "tool-identity")
        run = ex("ReviewRun")
        start = {"schema": "trace-event@1", "runId": run["id"], "seq": 0, "type": "run.start", "run": run}
        dup = {**tool, "seq": 2}
        self.assertTrue(any(i.code == "trace-duplicate" for i in validate_trace([start, tool, dup])))

    def test_rr4_ledger_misuse_is_value_error(self):
        led = B.Ledger(B.STANDARD_S0A_BUDGET)
        for fn in (lambda: led.settle("x", 1), lambda: led.retain("x"),
                   lambda: led.release("x", "not-sent")):
            with self.assertRaises(ValueError):
                fn()

    def test_rr6_timestamps_parsed(self):
        auth = {**ex("SpendAuthorization.synthetic-recording"), "expiresAt": "2026-01-01T00:00:00.5Z"}
        prof, budget = ex("ModelProfile.smoke-synthetic"), ex("Plan")["budget"]
        self.assertEqual(B.check_spend_authorization(auth, prof, budget, "2026-01-01T00:00:00Z"), [])
        self.assertTrue(B.check_spend_authorization(auth, prof, budget, "2026-01-01T00:00:00.5Z"))
        for junk in ("", None, "2019-01-01T00:00:00Z extra"):
            with self.subTest(junk), self.assertRaises(ValueError):
                B.check_spend_authorization(auth, prof, budget, junk)

    def test_rr7_rr8_gateway_helpers(self):
        auth = ex("SpendAuthorization.synthetic-recording")
        req = ex("TraceEvent.model-call")["request"]
        self.assertEqual(B.check_request_authorized(auth, req), [])
        self.assertTrue(B.check_request_authorized(auth, {**req, "provider": "openai"}))
        self.assertIsNone(B.admit_total(auth, 0, 1, "VERIFY"))
        self.assertIsNotNone(B.admit_total(auth, auth["maxUsdMicrosTotal"], 1, "VERIFY"))

    def test_rr9_rr10_redaction_fixpoint_and_marker_prefix(self):
        t = "AIza" + "B" * 35 + "ghp_" + "A" * 36
        o, _ = R.redact(t)
        self.assertEqual(R.redact(o)[0], o)
        self.assertFalse(R.contains_protected(o))
        for t in ('password = "[REDACTED:x]hunter2hunter2"',
                  "Bearer [REDACTED:x]abcdefghijklmnopqrstuvwxyz0123"):
            o, _ = R.redact(t)
            self.assertNotIn("hunter2hunter2", o)
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123", o)
            self.assertEqual(R.redact(o)[0], o)
        self.assertEqual(R.REDACTION_VERSION, "redact@3")

    def test_rr12_empty_cost_buckets(self):
        r = ex("EvalReport.strict-replay")
        r["cost"]["byBasis"]["synthetic"] = {"records": 0, "usdMicros": 5}
        self.assertInvalid("EvalReport", r, "report-honesty")


def _call(run_id, stage, role, agent, ordinal, output, status="ok", repair_of=None, *, seq=0,
          attempt=0, hypothesis=None, req_role=None, schema=None, check=True):
    """A payload-consistent model.call event (ids and hashes recomputed). `hypothesis` is the
    verifier request subject; `req_role`/`schema` make the request disagree with the event."""
    schema = schema or {"investigator": "InvestigatorOutput", "verifier": "VerifierOutput"}[role]
    req = {**ex("TraceEvent.model-call")["request"], "role": req_role or role, "outputSchema": schema,
           "messages": [{"role": "user", "content": f"{stage} {role} {agent} {ordinal}"}]}
    if hypothesis:
        req["hypothesisId"] = hypothesis
    cid = C.call_id(stage, role, agent, ordinal, attempt)
    ev = {"schema": "trace-event@1", "runId": run_id, "seq": seq, "type": "model.call",
          "callId": cid, "stage": stage, "role": role, "agentId": agent, "ordinal": ordinal,
          "attempt": attempt, "requestHash": C.request_hash(req), "request": req,
          "response": {"status": status, "resolvedModel": "synthetic-fixture", "output": output,
                       "rawText": None, "usage": ex("CostRecord.eval-synthetic")["usage"]},
          "costRecordId": C.cost_id(cid), "redactions": {}}
    if repair_of:
        ev["repairOf"] = repair_of
    if check:
        assert validate("TraceEvent", ev) == [], validate("TraceEvent", ev)
    return ev


def _tool(run_id, *kinds, status="ok", agent="v-tool", ordinal=0, args=None, seq=0):
    """A payload-consistent tool.call whose result items (one per kind) name the call itself."""
    args = args or {"k": ordinal}
    tid = C.tool_call_id("VERIFY", agent, ordinal, "pytest", args)
    items = [] if status == "error" else [
        {"kind": k, "excerpt": "1 failed" if n == 0 else f"item {n}", "source": "pytest",
         "toolCallId": tid} for n, k in enumerate(kinds)]
    res = {"status": status, "evidence": items, "completeness": "exact", "truncated": None,
           "notice": ""}
    ev = {"schema": "trace-event@1", "runId": run_id, "seq": seq, "type": "tool.call",
          "toolCallId": tid, "stage": "VERIFY", "agentId": agent, "ordinal": ordinal,
          "tool": "pytest", "args": args, "resultHash": C.result_hash(res), "result": res,
          "redactions": {}}
    assert validate("TraceEvent", ev) == [], validate("TraceEvent", ev)
    return ev


CITE_KEYS = ("kind", "path", "lines", "commit", "excerpt")


class VerificationPolicy(Base):
    """S0-03-verification-policy.md: independence = a distinct actual verifier call. The source
    call honestly proposes the Finding's hypothesis (an empty proposal is not a source), and the
    verifier request names it (s0a-contracts@5)."""

    def setUp(self):
        f = ex("Finding")
        self.run = f["runId"]
        self.cite = {k: f["evidence"][0][k] for k in CITE_KEYS}
        self.draft = {k: copy.deepcopy(f[k]) for k in
                      ("claim", "category", "suspectedSeverity", "impact", "location")}
        self.draft["evidence"] = [self.cite]
        self.inv = _call(self.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                         {"hypotheses": [self.draft]}, seq=1)
        self.confirm = {"verdict": "confirmed", **f["severityBasis"], "evidence": [self.cite],
                        "notes": "ok"}
        self.ver = self.verifier()
        # Same pinned lines as the proposer: a genuine one-line bug confirmed in place.
        f["sourceCallId"] = self.inv["callId"]
        f["verification"]["evidence"] = copy.deepcopy(f["evidence"])
        f["verification"]["callIds"] = [self.ver["callId"]]
        self.f = f

    def verifier(self, agent=None, ordinal=0, seq=2, hypothesis="same", **output):
        return _call(self.run, "VERIFY", "verifier", agent or "v-" + ex("Finding")["id"], ordinal,
                     {**self.confirm, **output}, seq=seq,
                     hypothesis=ex("Finding")["id"] if hypothesis == "same" else hypothesis)

    def rejected(self, f, events, contains):
        msgs = [i.message for i in check_finding_provenance(f, events)]
        self.assertTrue(any(contains in m for m in msgs), msgs)

    def test_same_line_confirmation_by_distinct_verifier_is_accepted(self):
        self.assertEqual(validate("Finding", self.f), [])
        self.assertEqual(check_finding_provenance(self.f, [self.inv, self.ver]), [])

    def test_whitespace_change_proves_nothing_on_its_own(self):
        f = copy.deepcopy(self.f)
        f["verification"]["evidence"][0]["excerpt"] += " "
        self.assertTrue(check_finding_provenance(f, [self.inv]))  # no verifier call: rejected

    def test_self_verification_rejected(self):
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [self.inv["callId"]]
        self.assertTrue(check_finding_provenance(f, [self.inv]))
        f["verification"]["callIds"] = [self.inv["callId"], self.ver["callId"]]
        self.assertInvalid("Finding", f, "independent-confirm")

    def test_nonexistent_or_other_run_call_rejected(self):
        self.assertTrue(check_finding_provenance(self.f, [self.inv]))
        other = _call("run_" + "e" * 16, "VERIFY", "verifier", "v-" + self.f["id"], 0, self.confirm,
                      seq=2, hypothesis=self.f["id"])
        self.assertTrue(check_finding_provenance(self.f, [self.inv, other]))

    def test_wrong_stage_or_role_rejected(self):
        wrong = _call(self.run, "INVESTIGATE", "investigator", "generalist-1", 0,
                      {"hypotheses": [self.draft]}, seq=2)
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [wrong["callId"]]
        issues = check_finding_provenance(f, [self.inv, wrong])
        self.assertTrue(any("not VERIFY/verifier" in i.message for i in issues))
        forged = {**wrong, "stage": "VERIFY", "role": "verifier"}  # relabel keeps the old id
        self.assertTrue(check_finding_provenance(f, [self.inv, forged]))
        f = copy.deepcopy(self.f)
        f["sourceCallId"] = self.ver["callId"]
        self.assertTrue(check_finding_provenance(f, [self.ver]))

    def test_verifier_must_have_confirmed(self):
        self.assertTrue(check_finding_provenance(self.f, [self.inv, self.verifier(verdict="refuted")]))
        bad = _call(self.run, "VERIFY", "verifier", "v-" + self.f["id"], 0, None,
                    status="invalid-output", seq=2, hypothesis=self.f["id"])
        self.assertTrue(check_finding_provenance(self.f, [self.inv, bad]))

    def test_repair_of_source_call_rejected(self):
        rep = _call(self.run, "VERIFY", "verifier", "v-" + self.f["id"], 0, self.confirm,
                    repair_of=self.inv["callId"], seq=2, hypothesis=self.f["id"])
        self.rejected(self.f, [self.inv, rep], "repair of the source call")

    def test_citations_stay_resolved_and_tool_refs_logged(self):
        f = copy.deepcopy(self.f)
        del f["verification"]["evidence"][0]["resolved"]
        self.assertInvalid("Finding", f, "independent-confirm")
        f = copy.deepcopy(self.f)
        f["verification"]["evidence"] = [{"kind": "tool-result", "excerpt": "", "source": "grep",
                                          "toolCallId": "tool_" + "1" * 16}]
        self.rejected(f, [self.inv, self.ver], "tool call not logged")


class ProvenanceBinding(VerificationPolicy):
    """S0-03-frfix: FR1-FR6 from S0-03-finalreview.md (s0a-contracts@5). Inherits the honest
    fixture, so every accepted case above is re-run under the new binding."""

    # FR1a: the verifier request names the hypothesis it checked
    def test_fr1_verifier_request_must_name_this_hypothesis(self):
        for name, hyp in (("no subject", None), ("other hypothesis", "hyp_" + "f" * 16)):
            ver = self.verifier(hypothesis=hyp)
            self.assertEqual(ver["callId"], self.ver["callId"])
            with self.subTest(name):
                self.rejected(self.f, [self.inv, ver], "does not name this hypothesis")

    def test_fr1_request_subject_is_hashed_and_verifier_only(self):
        req = self.ver["request"]
        self.assertNotEqual(C.request_hash(req), C.request_hash({**req, "hypothesisId": "hyp_" + "f" * 16}))
        edited = copy.deepcopy(self.ver)
        edited["request"]["hypothesisId"] = "hyp_" + "f" * 16
        self.assertInvalid("TraceEvent", edited, "call-outcome")
        inv_req = {**self.inv["request"], "hypothesisId": self.f["id"]}
        self.assertInvalid("ModelRequest", inv_req, "request-subject")
        self.assertEqual(validate("ModelRequest", self.inv["request"]), [])  # optional elsewhere

    # FR1b: the Finding is the proposal its id recomputes from
    def test_fr1_source_call_must_have_proposed_this_hypothesis(self):
        other = {**self.draft, "claim": "A different claim"}
        for name, hyps in (("empty proposal", []), ("different claim", [other]),
                           ("proposed at another index", [other, self.draft])):
            inv = _call(self.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                        {"hypotheses": hyps}, seq=1)
            with self.subTest(name):
                self.rejected(self.f, [inv, self.ver], "proposed no hypothesis with this id")
        f = copy.deepcopy(self.f)
        f["specialist"] = "security"                       # the specialist is part of the id
        self.rejected(f, [self.inv, self.ver], "proposed no hypothesis with this id")

    def test_fr1_index_is_part_of_identity(self):
        other = {**self.draft, "claim": "A different claim"}
        inv = _call(self.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                    {"hypotheses": [other, self.draft]}, seq=1)
        hid = C.hypothesis_id("generalist", 1, self.draft["claim"], "src/auth.py", 10)
        f = copy.deepcopy(self.f)
        f["id"], f["sourceCallId"] = hid, inv["callId"]
        ver = self.verifier(agent="v-" + hid, hypothesis=hid)
        f["verification"]["callIds"] = [ver["callId"]]
        self.assertEqual(check_finding_provenance(f, [inv, ver]), [])

    def test_fr1_finding_fields_equal_the_proposal(self):
        for field, value in (("category", "bug"), ("suspectedSeverity", "P1"), ("impact", "crash"),
                             ("location", {"path": "src/auth.py", "line": 10, "endLine": 11})):
            f = copy.deepcopy(self.f)
            f[field] = value
            with self.subTest(field):
                self.rejected(f, [self.inv, self.ver], "differs from the proposal")
        f = copy.deepcopy(self.f)
        f["evidence"][0]["excerpt"] = "something the investigator never cited"
        self.rejected(f, [self.inv, self.ver], "was not cited by the proposal")

    # FR1c: severity comes from what the verifier returned
    def test_fr1_severity_basis_equals_every_confirming_output(self):
        for name, change in (("unreachable", {"reachable": False}),
                             ("other impact", {"impact": "maintainability"})):
            with self.subTest(name):
                self.rejected(self.f, [self.inv, self.verifier(**change)], "severityBasis differs")
        second = self.verifier(agent="v-second", seq=3, reachable=False)
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"].append(second["callId"])
        self.rejected(f, [self.inv, self.ver, second], "severityBasis differs")

    # FR1d: verification evidence is what the confirming calls cited
    def test_fr1_verification_evidence_comes_from_confirming_calls(self):
        for key, value in (("path", "never/cited.py"), ("excerpt", "never returned"),
                           ("lines", [10, 11])):
            f = copy.deepcopy(self.f)
            f["verification"]["evidence"][0][key] = value
            with self.subTest(key):
                self.rejected(f, [self.inv, self.ver], "not cited by a confirming verifier call")

    def test_two_distinct_verifiers_union_of_citations(self):
        routes = {"kind": "code", "path": "src/routes.py", "lines": [4, 6],
                  "commit": self.cite["commit"], "excerpt": "@app.get('/admin')"}
        second = self.verifier(agent="v-second", seq=3, evidence=[routes])
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"].append(second["callId"])
        f["verification"]["evidence"].append({**routes, "source": "verifier", "resolved": True})
        self.assertEqual(check_finding_provenance(f, [self.inv, self.ver, second]), [])
        self.rejected(f, [self.inv, self.ver], "not a logged model call")   # second missing

    # FR2: duplicates and order
    def test_fr2_duplicate_ids_rejected_in_either_order(self):
        refuted = self.verifier(verdict="refuted")
        for name, evs in (("refuted first", [self.inv, refuted, self.ver]),
                          ("refuted last", [self.inv, self.ver, refuted]),
                          ("invalid twin", [self.inv, self.ver, {**self.ver, "requestHash": "sha256:" + "0" * 64}]),
                          ("source twice", [self.inv, copy.deepcopy(self.inv), self.ver])):
            with self.subTest(name):
                self.rejected(self.f, evs, "logged more than once")

    def test_fr2_verifier_must_follow_the_source_call(self):
        for seq in (0, 1):
            with self.subTest(seq=seq):
                self.rejected(self.f, [self.inv, self.verifier(seq=seq)], "logged before the source call")

    # FR3: the event describes the request that was sent
    def test_fr3_request_role_and_schema_match_the_event(self):
        for name, kw in (("request role", dict(req_role="investigator", schema="InvestigatorOutput")),
                         ("request role only", dict(req_role="investigator")),
                         ("output schema", dict(schema="InvestigatorOutput")),
                         ("judge schema", dict(schema="JudgeOutput"))):
            ev = _call(self.run, "VERIFY", "verifier", "v-x", 0, self.confirm, check=False, **kw)
            with self.subTest(name):
                self.assertInvalid("TraceEvent", ev, "call-outcome")
        self.assertEqual(validate("TraceEvent", self.ver), [])

    # FR4: non-code evidence is an item of an ok, logged, cited tool result
    def test_fr4_tool_evidence_honest_path_is_accepted(self):
        tc = _tool(self.run, "test-run", seq=2)
        ver = self.verifier(seq=3, evidence=[self.cite, {"kind": "tool-ref", "toolCallId": tc["toolCallId"]}])
        items, problems = S.materialize_evidence(ver["response"]["output"]["evidence"][1:],
                                                 {tc["toolCallId"]: tc}, "verifier")
        self.assertEqual(problems, [])
        f = copy.deepcopy(self.f)
        f["verification"]["evidence"] += items
        self.assertEqual(check_finding_provenance(f, [self.inv, tc, ver]), [])
        self.assertEqual(S.evidence_strength(f["evidence"], {tc["toolCallId"]: tc},
                                             f["verification"]["evidence"]), "reproduced")
        self.rejected(f, [self.inv, tc, self.ver], "not cited by a confirming verifier call")

    def test_fr4_tool_ref_index_limits_what_is_cited(self):
        tc = _tool(self.run, "test-run", "analyzer", seq=2)
        ref = {"kind": "tool-ref", "toolCallId": tc["toolCallId"], "index": 1}
        ver = self.verifier(seq=3, evidence=[self.cite, ref])
        first, second = (copy.deepcopy(x) for x in tc["result"]["evidence"])
        for item, ok in ((second, True), (first, False)):
            f = copy.deepcopy(self.f)
            f["verification"]["evidence"].append(item)
            with self.subTest(item["kind"]):
                got = check_finding_provenance(f, [self.inv, tc, ver])
                self.assertEqual(got == [], ok, [i.message for i in got])

    def test_fr4_untrusted_tool_evidence_rejected(self):
        ok, err = _tool(self.run, "history", seq=2), _tool(self.run, "test-run", status="error", ordinal=1, seq=3)
        for name, tc, kind, msg in (("errored call", err, "test-run", "result is error"),
                                    ("kind not returned", ok, "test-run", "not an item"),
                                    ("excerpt not returned", ok, "history", "not an item")):
            f = copy.deepcopy(self.f)
            f["evidence"].append({"kind": kind, "excerpt": "edited", "source": "pytest",
                                  "toolCallId": tc["toolCallId"]})
            if name == "kind not returned":
                f["evidence"][-1]["excerpt"] = "1 failed"
            with self.subTest(name):
                self.assertEqual(validate("Finding", f), [])
                self.rejected(f, [self.inv, self.ver, tc], msg)
        f = copy.deepcopy(self.f)
        f["evidence"].append(copy.deepcopy(ok["result"]["evidence"][0]))
        self.rejected(f, [self.inv, self.ver, ok, copy.deepcopy(ok)], "logged more than once")
        self.rejected(f, [self.inv, self.ver, ok], "was not cited by the proposal")

    # FR5: no phantom lines past EOF, one trailing newline only
    def test_fr5_excerpt_lines_must_exist(self):
        from reviewer.contracts.snapshot import excerpt_matches as M
        three = b"one\ntwo\nthree\n"
        self.assertFalse(M(three, [4, 4], ""))
        self.assertFalse(M(three, [3, 4], "three"))
        self.assertFalse(M(three, [3, 4], "three\n"))
        self.assertTrue(M(three, [3, 3], "three"))
        self.assertTrue(M(three, [1, 3], "one\ntwo\nthree\n"))
        self.assertFalse(M(three, [1, 3], "one\ntwo\nthree\n\n"))
        self.assertTrue(M(b"a\n\nb\n", [2, 2], ""))                # a real blank line is citable
        self.assertTrue(M(b"a\n\n", [2, 2], ""))                   # including a final blank line
        self.assertFalse(M(b"a\n\n", [3, 3], ""))
        self.assertTrue(M(b"a\nb", [2, 2], "b"))                   # no final newline
        self.assertFalse(M(b"", [1, 1], ""))                       # an empty file has no lines
        self.assertTrue(M(b"x\r\ny\r\n", [1, 2], "x\r\ny\r"))       # CRLF limit C3 unchanged

    # FR6: one logical verification counts once
    def test_fr6_call_with_its_repair_or_retry_counts_once(self):
        rep = _call(self.run, "VERIFY", "verifier", "v-" + self.f["id"], 0, self.confirm, seq=3,
                    attempt=1, repair_of=self.ver["callId"], hypothesis=self.f["id"])
        retry = _call(self.run, "VERIFY", "verifier", "v-" + self.f["id"], 0, self.confirm, seq=3,
                      attempt=1, hypothesis=self.f["id"])
        for name, extra in (("repair", rep), ("retry", retry)):
            f = copy.deepcopy(self.f)
            f["verification"]["callIds"].append(extra["callId"])
            with self.subTest(name):
                self.rejected(f, [self.inv, self.ver, extra], "repeats a listed verification")
        f = copy.deepcopy(self.f)
        f["verification"]["callIds"] = [rep["callId"]]              # the repair alone is fine
        self.assertEqual(check_finding_provenance(f, [self.inv, self.ver, rep]), [])


class BoundedRead(Base):
    """TR5 (S0-06-review.md), contracts side: read_verified never reads more than its cap + 1."""

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.file = self.root / "a.py"
        self.file.write_bytes(b"x" * 1000)
        self.m = build_manifest(self.root)

    def reads(self, fn):
        """Run fn with os.read counted (bytes returned) and optionally hooked."""
        from reviewer.contracts import snapshot as SN
        real, seen = os.read, []

        def counting(fd, n):
            if self.hook and not seen:
                self.hook()
            data = real(fd, n)
            seen.append(len(data))
            return data
        from unittest import mock
        with mock.patch.object(SN.os, "read", counting):
            try:
                return fn(), sum(seen)
            except SnapshotError as e:
                return e, sum(seen)

    hook = None

    def test_default_cap_is_the_pinned_size(self):
        from reviewer.contracts.snapshot import read_verified
        self.assertEqual(self.reads(lambda: read_verified(self.root, self.m, "a.py")),
                         (b"x" * 1000, 1000))
        os.truncate(self.file, 64 * 2**20)                 # sparse 64 MiB growth after pinning
        got, n = self.reads(lambda: read_verified(self.root, self.m, "a.py"))
        self.assertIsInstance(got, SnapshotError)
        self.assertEqual(n, 0, "refused at fstat, before any read")

    def test_concurrent_growth_after_fstat_stops_at_cap_plus_one(self):
        from reviewer.contracts.snapshot import read_verified
        def grow():                                        # grows between fstat and first read
            with self.file.open("ab") as fh:
                fh.write(b"y" * 2**20)
        self.hook = grow
        got, n = self.reads(lambda: read_verified(self.root, self.m, "a.py"))
        self.assertIsInstance(got, SnapshotError)
        self.assertIn("grew", str(got))
        self.assertEqual(n, 1001)
        self.hook = None
        got, n = self.reads(lambda: read_verified(self.root, self.m, "a.py", max_bytes=10**9))
        self.assertIsInstance(got, SnapshotError, "a larger max_bytes never lifts the pinned size")
        self.assertEqual(n, 0)

    def test_explicit_max_bytes(self):
        from reviewer.contracts.snapshot import read_verified
        for cap in (1000, 4096):
            with self.subTest(cap=cap):
                self.assertEqual(read_verified(self.root, self.m, "a.py", max_bytes=cap), b"x" * 1000)
        got, n = self.reads(lambda: read_verified(self.root, self.m, "a.py", max_bytes=999))
        self.assertIsInstance(got, SnapshotError)
        self.assertEqual(n, 0, "pinned size above the cap is refused before reading")
        for bad in (-1, True, 1.5, "10"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                read_verified(self.root, self.m, "a.py", max_bytes=bad)

    def test_length_other_than_pinned_size_and_existing_checks(self):
        from reviewer.contracts.snapshot import read_verified
        os.truncate(self.file, 10)                         # shrink, same inode
        with self.assertRaisesRegex(SnapshotError, "pinned at 1000"):
            read_verified(self.root, self.m, "a.py")
        self.file.write_bytes(b"z" * 1000)                 # same size, other bytes: hash check
        with self.assertRaisesRegex(SnapshotError, "does not match"):
            read_verified(self.root, self.m, "a.py")
        self.file.unlink()
        os.symlink("/etc/hostname", self.file)             # swapped for a link: nofollow
        with self.assertRaises(SnapshotError):
            read_verified(self.root, self.m, "a.py")
        self.file.unlink()
        os.mkfifo(self.file)                               # special file: refused, no block
        with self.assertRaises(SnapshotError):
            read_verified(self.root, self.m, "a.py", max_bytes=4096)


if __name__ == "__main__":
    unittest.main()
