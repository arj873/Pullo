"""S0-09 independent adversarial review of reviewer/pipeline + reviewer/evaluation + the CLI.

Run (repo root; NOT collected by `discover -s tests -t .` because this directory has no __init__.py):

    nice -n 19 python3 -m unittest discover -s tests/integration_review

Conventions (same as tests/tools_review):
* A DEFECT is held by an `expectedFailure` test that states the DESIRED behaviour, plus a `*_symptom_*` test that pins what
  happens today (delete the symptom test and the decorator when the owner fixes it).
* Every defect has a control that must pass: the neighbouring case that already behaves correctly.
* Inherited = already listed in S0-07.md (D1..D7) or S0-08.md; NEW = found here.
* Only the real gateway (synthetic provider), tools, contracts, pipeline and evaluator run. No network, no target code.
  The pipeline test rig (tests/pipeline/helpers.py) is READ ONLY here and used as a rig; it holds no assertions.

S0-09b update (independent re-check of the S0-07b corrections): N1 N2 N3 N4 N5 N8 are fixed. Each former DEFECT test lost its
`expectedFailure` marker and each former `*_symptom_*` test became a `*_fixed_*` regression that keeps the original scenario and
asserts the REASON for the new behaviour (drop reason/detail, nothing written), because a marker that merely flips can hide a fix
that works for the wrong reason. The sharper attacks are in test_corrections_review.py. STILL OPEN and still held by
expectedFailure: N7 (unpinned CLI replay). N7 is tested against a recording that is proven to have succeeded (see Evaluator),
because an unpinned replay that fails earlier would also "not say pinned".
RELEASE-02-compat: D4 (no gateway attempt after the hard deadline / cancellation) and N6 (run-id-shaped token on a cited line) are
fixed on this ordinary legacy path as well (S1-05 proved them on Turn chains); their markers and `*_symptom_*` tests are retired.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import reviewer.evaluation.runner as runner
import reviewer.pipeline.engine as engine
from reviewer.__main__ import main as cli
from reviewer.contracts import check_finding_provenance
from reviewer.evaluation import EvalError, record_smoke, replay_smoke
from reviewer.gateway import DisabledProvider, bytes_digest, events_to_bytes, load_trace
from reviewer.pipeline import Hooks, PipelineError, RecordBackend, load_result, run_review

from tests.pipeline.helpers import (BASE, HEAD, NOW, Rig, SpyProvider, entry, events_of, hid, hyp, inv, judge, model_calls,
                                    script, terr, ver)

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "fixtures" / "smoke"


def w(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


class Crash(BaseException):
    """Simulated process death."""


class Hooked(SpyProvider):
    """A provider spy that runs `on_call(n)` AFTER answering call number n (to move the injected clock / cancel flag
    while a gateway attempt is in flight)."""

    def __init__(self, scr, on_call):
        super().__init__(scr)
        self.on_call = on_call

    def call(self, request, key):
        r = super().call(request, key)
        self.on_call(len(self.requests))
        return r


class Base(Rig):
    def hooked_record(self, mini, scr, on_call, **kw):
        spy = Hooked(scr, on_call)
        self.spies.append(spy)
        providers = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai"), "synthetic": spy}
        be = RecordBackend(self.handle, self.book, providers, lambda: NOW)
        return run_review(self.spec(mini, be, **kw)), spy


# ======================================================================================================================
# 1. Evidence / provenance: source <-> verifier linkage
# ======================================================================================================================

class Linkage(Base):
    def test_control_finding_is_linked_to_the_exact_logged_calls_and_survives_an_independent_trace_reload(self):
        m = self.mini()
        h0, h1 = hyp(m, "src/a.py", 2, claim="first"), hyp(m, "src/a.py", 5, claim="second")
        res, _ = self.record(m, script(inv(h0, h1), ver(0, m, path="src/a.py", line=2), ver(1, m, path="src/a.py", line=5),
                                       judge(w([hid(0, h0)]), w([hid(1, h1)]))))
        events = load_trace(res.trace_path).events            # re-read from disk, not the engine's memory
        calls = {e["callId"]: e for e in events if e["type"] == "model.call"}
        self.assertEqual(len(res.findings), 2)
        for f in res.findings:
            self.assertEqual(check_finding_provenance(f, events), [])
            self.assertEqual((calls[f["sourceCallId"]]["stage"], calls[f["sourceCallId"]]["role"]), ("INVESTIGATE", "investigator"))
            [vc] = f["verification"]["callIds"]
            self.assertEqual(calls[vc]["request"]["hypothesisId"], f["id"])
            self.assertEqual(f["id"], hid(calls[vc]["ordinal"], [h0, h1][calls[vc]["ordinal"]]))      # ordinal = candidate index
        # cross the links: finding 0 claims finding 1's verifier call -> the contract check must refuse it
        crossed = json.loads(json.dumps(res.findings[0]))
        crossed["verification"]["callIds"] = list(res.findings[1]["verification"]["callIds"])
        self.assertTrue(check_finding_provenance(crossed, events))
        # a Finding never lists the investigator call as its verifier
        self_verified = json.loads(json.dumps(res.findings[0]))
        self_verified["verification"]["callIds"] = [res.findings[0]["sourceCallId"]]
        self.assertTrue(check_finding_provenance(self_verified, events))

    def test_control_edited_trace_cannot_rename_the_hypothesis_a_verifier_was_asked_about(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))

        def edit(events):
            for e in events:
                if e["type"] == "model.call" and e["stage"] == "VERIFY":
                    e["request"]["hypothesisId"] = "hyp_" + "0" * 16
        path, dig = self.edited_copy(res, "renamed.jsonl", edit)
        # the edit is either unloadable (ids are payload bound) or fails provenance; it must never validate
        try:
            events = load_trace(path).events
        except Exception:                                       # noqa: BLE001 - refusal at load is a pass
            return
        self.assertTrue(check_finding_provenance(res.findings[0], events))

    def test_fixed_N2_a_confirmation_citing_unrelated_code_is_not_independent_verification(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2, impact="crash", claim="claim about src/a.py line 2")
        # verifier "confirms" but its only citation is src/b.py line 2: it never looks at the claimed code
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2, impact="crash"), judge(w([hid(0, h)]))))
        # was: ("completed", 1, 1) with findings[0]["verification"]["evidence"][0]["path"] == "src/b.py"
        self.assertEqual((res.status, len(res.findings), len(res.comments)), ("completed", 0, 0))
        [d] = res.drops
        self.assertEqual((d["stage"], d["reason"], d["subjectIds"]), ("VERIFY", "invalid-citation", [hid(0, h)]))
        self.assertIn("unrelated", d["detail"])
        [v] = res.verifications                                        # the confirmation was downgraded, not silently kept
        self.assertEqual((v["verdict"], v["evidence"]), ("uncertain", []))

    def test_DEFECT_N2_verifier_confirmation_must_cite_code_that_bears_on_the_claim(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2, impact="crash")
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2, impact="crash"), judge(w([hid(0, h)]))))
        self.assertEqual(res.findings, [])

    def test_control_a_confirmation_citing_the_claimed_location_is_a_finding(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual(len(res.findings), 1)

    def test_fixed_N5_a_comment_no_longer_anchors_on_a_file_the_pr_did_not_change(self):
        same = {"src/a.py": BASE["src/a.py"], "src/b.py": "def g(x):\n    return x\n"}
        m = self.mini(base=same, head=dict(same, **{"src/a.py": HEAD["src/a.py"]}))     # b.py identical in both
        h = hyp(m, "src/b.py", 2, claim="problem in code the PR did not touch")
        res, spy = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2), judge(w([hid(0, h)]))))
        self.assertNotIn("src/b.py", [f["path"] for f in load_changed(res)])           # unchanged premise (kept)
        # was: [c["anchor"]["path"] for c in res.comments] == ["src/b.py"]
        self.assertEqual((res.comments, res.hypotheses), ([], []))
        self.assertEqual([(d["stage"], d["reason"]) for d in res.drops], [("VERIFY", "invalid-citation")])
        self.assertIn("outside the files this change modified", res.drops[0]["detail"])
        self.assertEqual(spy.calls, 1)                    # no verifier or judge call was spent on a candidate that cannot stand

    def test_DEFECT_N5_comments_must_not_anchor_outside_the_pr_diff(self):
        same = {"src/a.py": BASE["src/a.py"], "src/b.py": "def g(x):\n    return x\n"}
        m = self.mini(base=same, head=dict(same, **{"src/a.py": HEAD["src/a.py"]}))
        h = hyp(m, "src/b.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual(res.comments, [])


def load_changed(res):
    return json.loads((Path(res.run_dir) / "artifacts" / "02-PREPARE.v1.json").read_text())["payload"]["files"]


# ======================================================================================================================
# 2. issue-key: distinct same-line bugs
# ======================================================================================================================

class IssueKey(Base):
    def two(self, a, b, **recordkw):
        m = self.m
        return self.record(m, script(inv(a, b), ver(0, m, path="src/a.py", line=2), ver(1, m, path="src/a.py", line=2),
                                     judge(w([hid(0, a)]), w([hid(1, b)]))), **recordkw)

    def setUp(self):
        super().setUp()
        self.m = self.mini()

    def test_fixed_N3_two_distinct_defects_on_one_line_are_no_longer_merged_and_the_second_is_not_lost(self):
        a = hyp(self.m, "src/a.py", 2, claim="The operator is flipped: x - 0 subtracts instead of adding")
        b = hyp(self.m, "src/a.py", 2, claim="The function now returns int where callers rely on a float result")
        res, _ = self.two(a, b)
        # was: [[hid(0, a)]] with one "merged ... same issue as" drop and "float" in no comment
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, a)], [hid(1, b)]])
        self.assertEqual([d for d in res.drops if d["reason"] == "merged"], [])
        # (the scripted judge wording is the placeholder "T"/"B"; the second claim now has its OWN verified finding + comment)
        self.assertIn("float", json.dumps([f["claim"] for f in res.findings if f["id"] == hid(1, b)]))

    def test_DEFECT_N3_distinct_defects_on_one_line_each_keep_a_comment(self):
        a = hyp(self.m, "src/a.py", 2, claim="The operator is flipped: x - 0 subtracts instead of adding")
        b = hyp(self.m, "src/a.py", 2, claim="The function now returns int where callers rely on a float result")
        res, _ = self.two(a, b)
        self.assertEqual(len(res.comments), 2)

    def test_controls_each_field_of_the_key_separates_findings(self):
        base = dict(claim="c")
        variants = {
            "category": hyp(self.m, "src/a.py", 2, claim="v category", category="security"),
            "impact": hyp(self.m, "src/a.py", 2, claim="v impact", impact="crash"),
            "line": hyp(self.m, "src/a.py", 5, claim="v line"),
            "endLine": hyp(self.m, "src/a.py", 2, end=3, claim="v endLine"),
            "cites": hyp(self.m, "src/a.py", 2, claim="v cites", evidence=[self.m.cite("src/a.py", 1, 2)]),
        }
        a = hyp(self.m, "src/a.py", 2, **base)
        for field, v in variants.items():
            with self.subTest(field=field):
                self.setUp()
                m = self.m
                vimpact = "crash" if field == "impact" else "incorrect-result"
                vline = 5 if field == "line" else 2
                res, _ = self.record(m, script(inv(a, v), ver(0, m, path="src/a.py", line=2),
                                               ver(1, m, path="src/a.py", line=vline, impact=vimpact),
                                               judge(w([hid(0, a)]), w([hid(1, v)]))), eval_id="evr_" + "c" * 16)
                self.assertEqual(len(res.comments), 2, res.drops)

    def test_characterisation_the_same_defect_described_with_different_cited_lines_is_not_merged(self):
        a = hyp(self.m, "src/a.py", 2, claim="first wording")
        b = hyp(self.m, "src/a.py", 2, claim="second wording", evidence=[self.m.cite("src/a.py", 1, 2)])
        res, _ = self.two(a, b)
        self.assertEqual(len(res.comments), 2)       # conservative side of issue-key@1: duplicates can leak (precision)


# ======================================================================================================================
# 3. Deadline / cancellation between gateway attempts
# ======================================================================================================================

class DeadlineCancel(Base):
    def retry_script(self, m, a):
        return script(entry("INVESTIGATE", "investigator", "generalist", 0, 0, error=terr("provider-timeout", "INVESTIGATE")),
                      inv(a, attempt=1), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, a)])))

    def test_fixed_D4_no_provider_attempt_starts_after_the_hard_deadline(self):
        m = self.mini()
        a = hyp(m, "src/a.py", 2)
        _, spy = self.hooked_record(m, self.retry_script(m, a),
                                    lambda n: self.clock_value.__setitem__(0, 1000.0) if n == 1 else None)
        self.assertEqual(spy.calls, 1)

    def test_fixed_D4_no_provider_attempt_starts_after_cancellation(self):
        m = self.mini()
        a = hyp(m, "src/a.py", 2)
        flag = [False]
        _, spy = self.hooked_record(m, self.retry_script(m, a), lambda n: flag.__setitem__(0, True) if n == 1 else None,
                                    cancel=lambda: flag[0])
        self.assertEqual(spy.calls, 1)

    def test_control_deadline_reached_between_stages_starts_no_verifier_call(self):
        m = self.mini()
        a = hyp(m, "src/a.py", 2)
        scr = script(inv(a), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, a)])))
        res, spy = self.record(m, scr, hooks=Hooks(after_checkpoint=lambda st, d: self.clock_value.__setitem__(
            0, 1000.0 if st == "INVESTIGATE" else self.clock_value[0])))
        self.assertEqual((spy.calls, res.status), (1, "partial"))

    def _expire_during_last_verify_tool(self):
        m = self.mini()
        a = hyp(m, "src/a.py", 2)
        scr = script(inv(a), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, a)])))
        clock, Orig = self.clock_value, engine.ToolSession

        class Session(Orig):
            def call(s, tool, args):
                r = super().call(tool, args)
                if s.agent_id == "verifier" and tool == "diff":      # the last tool call of the candidate
                    clock[0] = 1000.0
                return r
        with mock.patch.object(engine, "ToolSession", Session):
            return self.record(m, scr)

    def test_fixed_N4_no_verifier_call_starts_after_the_deadline_passed_during_the_last_tool_call(self):
        res, spy = self._expire_during_last_verify_tool()
        # was: spy.calls == 2 and len(res.findings) == 1
        self.assertEqual((spy.calls, len(res.findings), len(res.comments)), (1, 0, 0))
        self.assertEqual(res.status, "partial")                                      # honestly incomplete, not "completed"
        self.assertEqual(model_calls(res, "VERIFY"), [])                             # no verifier call was even logged
        self.assertEqual([d["reason"] for d in res.drops], ["deadline"])

    def test_DEFECT_N4_gate_is_checked_again_immediately_before_each_model_call(self):
        _, spy = self._expire_during_last_verify_tool()
        self.assertEqual(spy.calls, 1)


# ======================================================================================================================
# 4. Resume / idempotency / corrupt checkpoints / output-file integrity
# ======================================================================================================================

class Resume(Base):
    def setUp(self):
        super().setUp()
        self.m = self.mini()
        self.h = hyp(self.m, "src/a.py", 2)
        self.scr = script(inv(self.h), ver(0, self.m, path="src/a.py", line=2),
                          judge(w([hid(0, self.h)], "Real title", "Real body")))
        self.rec, _ = self.record(self.m, self.scr)

    def crash_replay_after(self, stage, out):
        def boom(st, d):
            if st == stage:
                raise Crash()
        with self.assertRaises(Crash):
            self.replay(self.m, self.rec, out=out, hooks=Hooks(after_checkpoint=boom))
        [rd] = [p for p in out.iterdir()]
        return rd

    def fresh_out(self, name):
        p = self.tmp / name
        p.mkdir()
        return p

    @staticmethod
    def norm(text, run_id):
        return text.replace(run_id, "RUN")

    def test_control_resume_after_publish_with_untouched_files_equals_an_uninterrupted_replay(self):
        ref = self.replay(self.m, self.rec, out=self.fresh_out("ref"), eval_id="evr_" + "3" * 16)
        out = self.fresh_out("o1")
        rd = self.crash_replay_after("PUBLISH", out)
        r2 = self.replay(self.m, self.rec, out=out)
        for name in ("comments.json", "review.md"):
            self.assertEqual(self.norm((rd / name).read_text(), r2.run_id), self.norm(Path(ref.run_dir, name).read_text(), ref.run_id))

    def test_fixed_N1_resume_after_publish_no_longer_receipts_whatever_is_on_disk(self):
        out = self.fresh_out("o2")
        rd = self.crash_replay_after("PUBLISH", out)
        doc = json.loads((rd / "comments.json").read_text())
        doc["comments"][0]["title"] = "TAMPERED"
        (rd / "comments.json").write_text(json.dumps(doc))
        (rd / "review.md").write_text("TAMPERED REVIEW\n")
        # was: the replay returned status "completed" and the receipt hashed the two tampered files
        with self.assertRaises(PipelineError) as cm:
            self.replay(self.m, self.rec, out=out)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")
        self.assertIn("edited after PUBLISH", cm.exception.message)
        self.assertFalse((rd / "receipt.json").exists())                               # no receipt was minted for the forgery
        self.assertEqual(json.loads((rd / "comments.json").read_text())["comments"][0]["title"], "TAMPERED")   # left as found
        self.assertEqual((rd / "review.md").read_text(), "TAMPERED REVIEW\n")

    def test_DEFECT_N1_resume_never_publishes_comments_that_differ_from_the_verified_judge_artifact(self):
        out = self.fresh_out("o3")
        rd = self.crash_replay_after("PUBLISH", out)
        doc = json.loads((rd / "comments.json").read_text())
        doc["comments"][0]["title"] = "TAMPERED"
        (rd / "comments.json").write_text(json.dumps(doc))
        try:
            self.replay(self.m, self.rec, out=out)
        except PipelineError:
            return                                                                     # refusing is acceptable
        self.assertEqual(json.loads((rd / "comments.json").read_text())["comments"][0]["title"], "Real title")

    def forge_completed(self, res):
        rd = Path(res.run_dir)
        doc = json.loads((rd / "comments.json").read_text())
        doc["comments"][0]["title"] = "EVIL"
        data = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode()
        (rd / "comments.json").write_bytes(data)
        return rd, data

    def test_control_editing_comments_json_of_a_completed_run_is_detected(self):
        rd, _ = self.forge_completed(self.rec)
        with self.assertRaises(PipelineError) as cm:
            load_result(self.out, self.rec.run_id)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")
        with self.assertRaises(PipelineError):
            self.record(self.m, self.scr)                            # idempotent re-invocation refuses too

    def test_fixed_N1_a_consistent_receipt_edit_no_longer_makes_the_forged_comments_json_the_accepted_output(self):
        import hashlib
        rd, data = self.forge_completed(self.rec)
        rc = json.loads((rd / "receipt.json").read_text())
        rc["outputs"]["comments.json"] = hashlib.sha256(data).hexdigest()
        (rd / "receipt.json").write_text(json.dumps(rc, sort_keys=True, indent=2) + "\n")
        # the receipt now agrees with the forged file; only the re-render from the JUDGE artifact can still refuse it
        # was: the idempotent re-invocation returned (idempotent True, 0 provider calls) with "EVIL" still on disk
        with self.assertRaises(PipelineError) as cm:
            self.record(self.m, self.scr)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")
        self.assertIn("render", cm.exception.message)
        with self.assertRaises(PipelineError) as cm:
            load_result(self.out, self.rec.run_id)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")
        self.assertEqual(self.spies[-1].calls, 0)                                      # refused before any provider contact
        self.assertEqual(json.loads((rd / "comments.json").read_text())["comments"][0]["title"], "EVIL")      # untouched

    def test_DEFECT_N1_comments_json_is_checked_against_the_judge_artifact_not_only_against_the_receipt(self):
        import hashlib
        rd, data = self.forge_completed(self.rec)
        rc = json.loads((rd / "receipt.json").read_text())
        rc["outputs"]["comments.json"] = hashlib.sha256(data).hexdigest()
        (rd / "receipt.json").write_text(json.dumps(rc, sort_keys=True, indent=2) + "\n")
        with self.assertRaises(PipelineError):
            load_result(self.out, self.rec.run_id)

    def test_control_torn_trace_tail_after_a_checkpoint_resumes_and_matches_an_uninterrupted_replay(self):
        out = self.fresh_out("o4")
        rd = self.crash_replay_after("VERIFY", out)
        with open(rd / "trace.jsonl", "ab") as f:
            f.write(b'{"schema": "trace-event@1", "type": "stage.sta')        # torn write, no newline
        r2 = self.replay(self.m, self.rec, out=out)
        ref = self.replay(self.m, self.rec, out=self.fresh_out("ref2"), eval_id="evr_" + "4" * 16)
        self.assertEqual((r2.status, [c["id"] for c in r2.comments]), (ref.status, [c["id"] for c in ref.comments]))
        self.assertEqual(r2.resumed_from, "JUDGE")

    def test_control_a_foreign_but_valid_trace_dropped_into_the_run_directory_is_refused(self):
        out = self.fresh_out("o5")
        rd = self.crash_replay_after("VERIFY", out)
        other = self.mini("mini-2")
        h2 = hyp(other, "src/a.py", 5, claim="other case")
        res2, _ = self.record(other, script(inv(h2), ver(0, other, path="src/a.py", line=5), judge(w([hid(0, h2)]))),
                              eval_id="evr_" + "6" * 16)
        shutil.copy(res2.trace_path, rd / "trace.jsonl")
        with self.assertRaises(PipelineError) as cm:
            self.replay(self.m, self.rec, out=out)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")

    def test_control_a_stale_tampered_artifact_of_a_stage_that_never_checkpointed_is_overwritten_not_trusted(self):
        out = self.fresh_out("o6")
        rd = self.crash_replay_after("VERIFY", out)
        stale = rd / "artifacts" / "06-JUDGE.v1.json"
        stale.write_text('{"tampered": true}')
        r2 = self.replay(self.m, self.rec, out=out)
        self.assertEqual((r2.status, len(r2.comments)), ("completed", 1))
        self.assertNotIn("tampered", stale.read_text())

    def test_control_partial_and_failed_runs_are_idempotent_with_no_provider_call_or_rewrite(self):
        m = self.mini("mini-3")
        h = hyp(m, "src/a.py", 2)
        scr = script(inv(h), entry("VERIFY", "verifier", "verifier", 0, 0, error=terr("provider-error", "VERIFY", retryable=False)))
        res, _ = self.record(m, scr, eval_id="evr_" + "7" * 16)
        self.assertEqual(res.status, "partial")
        before = {p: p.read_bytes() for p in Path(res.run_dir).rglob("*") if p.is_file()}
        again, spy = self.record(m, scr, eval_id="evr_" + "7" * 16)
        self.assertEqual((again.idempotent, spy.calls, again.status), (True, 0, "partial"))
        self.assertEqual(before, {p: p.read_bytes() for p in Path(res.run_dir).rglob("*") if p.is_file()})

    def test_control_D5_inherited_budget_refusal_after_the_resume_point_refuses_the_resume(self):
        # D5 (open): a replay ledger cannot be seeded with earlier spend, so resume is refused fail-closed (not guessed).
        from tests.pipeline.helpers import PLAN
        plan = json.loads(json.dumps(PLAN))
        plan["budget"]["maxUsdMicros"] = 1                           # every priced call is refused by the budget
        m = self.mini("mini-4")
        a = hyp(m, "src/a.py", 2)
        res, _ = self.record(m, script(inv(a)), plan=plan, eval_id="evr_" + "8" * 16)
        self.assertTrue(any(e.get("error", {}).get("code") == "budget-exhausted" for e in model_calls(res)))
        out = self.fresh_out("o7")

        def boom(st, d):
            if st == "TRIAGE":
                raise Crash()
        with self.assertRaises(Crash):
            self.replay(m, res, out=out, plan=plan, eval_id="evr_" + "9" * 16, hooks=Hooks(after_checkpoint=boom))
        with self.assertRaises(PipelineError) as cm:
            self.replay(m, res, out=out, plan=plan, eval_id="evr_" + "9" * 16)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")
        self.assertIn("budget refusal", cm.exception.message)


# ======================================================================================================================
# 5. Untrusted text that rewrites citations (D6 consequence)
# ======================================================================================================================

class RunIdToken(Base):
    def planted(self, token):
        head = dict(HEAD)
        head["src/b.py"] = f"def g(x):\n    return x * 2  # {token}\n"
        return self.mini(head=head)

    def run_with(self, m, shown):
        h = hyp(m, "src/b.py", 2, claim="g doubles its input", evidence=[m.cite("src/b.py", 2, excerpt=shown)])
        return self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2), judge(w([hid(0, h)]))))

    def test_control_without_the_token_the_same_defect_is_reported(self):
        m = self.planted("see ticket")
        res, _ = self.run_with(m, "    return x * 2  # see ticket")
        self.assertEqual(len(res.comments), 1)

    def test_fixed_N6_the_model_is_shown_the_preserved_source_string_and_the_line_stays_citable(self):
        shown = "    return x * 2  # run_0123456789abcdef"                  # the actual preserved source, not scrubbed text
        m = self.planted("run_0123456789abcdef")
        res, spy = self.run_with(m, shown)
        self.assertIn("run_0123456789abcdef", json.dumps(spy.requests[0]))
        self.assertNotIn("run_[id-removed]", json.dumps(spy.requests[0]))
        self.assertEqual(len(res.comments), 1)
        self.assertEqual(res.drops, [])


# ======================================================================================================================
# 6. Output path containment
# ======================================================================================================================

class Containment(Base):
    def test_fixed_N8_pipeline_alone_now_refuses_an_ancestor_of_a_snapshot_root_and_keeps_the_sibling_limit(self):
        m = self.mini()
        (m.root / "labels").mkdir()
        for tag, out_root in (("parent of base/ and head/", m.root), ("grandparent", m.root.parent),
                              ("inside head (control)", m.root / "head")):
            with self.subTest(out_root=tag), self.assertRaises(PipelineError) as cm:
                self.record(m, script(inv()), out_root=out_root, forbidden_roots=())
            self.assertEqual(cm.exception.code, "path-escape")
            self.assertEqual(list(m.root.glob("run_*")), [])                    # was: run_*/ created beside the snapshots
        # documented residual (the pipeline cannot know what a host keeps beside its snapshots): a sibling is accepted
        # unless the host lists it; the evaluator lists it (control below)
        sibling = self.record(m, script(inv()), out_root=m.root / "labels", forbidden_roots=(), eval_id="evr_" + "9" * 16)[0]
        self.assertEqual(Path(sibling.run_dir).parent, m.root / "labels")
        with self.assertRaises(PipelineError) as cm:
            self.record(m, script(inv()), out_root=m.root / "labels", forbidden_roots=(m.root / "labels",),
                        eval_id="evr_" + "a" * 16)
        self.assertEqual(cm.exception.code, "path-escape")

    def test_control_the_evaluator_guards_both_directions_and_symlinked_parents(self):
        src = Path(tempfile.mkdtemp(prefix="s009-src-"))
        self.addCleanup(shutil.rmtree, src, True)
        (src / "head").mkdir()
        for out in (src, src / "head", src / "new"):
            with self.subTest(out=str(out.relative_to(src)) or "."), self.assertRaises(EvalError):
                runner.prepare_out(out, [src])
        parent = self.tmp / "viasym"
        os.symlink(src, parent)
        with self.assertRaises(EvalError):
            runner.prepare_out(parent / "fresh", [src])                  # symlinked PARENT resolving into the suite
        leaf = self.tmp / "leaf"
        os.symlink(self.tmp, leaf)
        with self.assertRaises(EvalError):
            runner.prepare_out(leaf, [src])


# ======================================================================================================================
# 7. Evaluator: frozen identity, pins, partial/failed reporting
# ======================================================================================================================

class Evaluator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="s009-eval-"))
        cls.suite = cls.tmp / "suite"
        shutil.copytree(SMOKE, cls.suite)
        cls.rec = record_smoke(cls.tmp / "rec", suite_dir=cls.suite)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_control_recording_has_six_reported_cases_with_the_expected_statuses(self):
        got = {c.case_id: (c.status, len(c.result.comments)) for c in self.rec.cases}
        self.assertEqual(got, {"smoke-c01": ("completed", 1), "smoke-c02": ("completed", 0), "smoke-c03": ("completed", 1),
                               "smoke-c04": ("completed", 1), "smoke-c05": ("partial", 0), "smoke-c06": ("failed", 0)})
        cov = self.rec.report["coverage"]
        self.assertEqual((cov["completed"], cov["partial"], cov["failed"], cov["cancelled"]), (4, 1, 1, 0))
        self.assertEqual(self.rec.exit_code, 0)

    def test_frozen_copy_is_what_runs_even_if_the_source_suite_changes_mid_evaluation(self):
        suite = self.tmp / "suite2"
        shutil.copytree(SMOKE, suite)
        flipped = []

        def mutate_source(cid):
            if not flipped:                                       # during the FIRST case: rewrite labels, script, snapshot
                flipped.append(cid)
                (suite / "labels" / "smoke-c06.json").write_text(
                    (suite / "labels" / "smoke-c06.json").read_text().replace('"failed"', '"findings"'))
                s = suite / "scripts" / "smoke-c03.json"
                s.write_text(s.read_text().replace("Cache holds", "Cache SWAPPED"))
                head = next((suite / "cases" / "smoke-c01" / "head").rglob("*.py"))
                head.write_text(head.read_text() + "\n# appended after freeze\n")
            return {}
        out = record_smoke(self.tmp / "rec2", suite_dir=suite, host_extra=mutate_source)
        self.assertEqual({c.case_id: c.status for c in out.cases}["smoke-c06"], "failed")
        self.assertEqual(out.exit_code, 0)
        self.assertNotIn("SWAPPED", json.dumps([c.result.comments for c in out.cases if c.result]))
        self.assertNotIn("SWAPPED", "".join(p.read_text() for p in (self.tmp / "rec2" / "runs").rglob("trace.jsonl")))
        # a replay against the NOW-modified source refuses: identity drift, not a quiet pass
        with self.assertRaises(EvalError) as cm:
            replay_smoke(self.tmp / "rec2", self.tmp / "rep2", suite_dir=suite)
        self.assertIn(cm.exception.code, ("config-drift", "suite"), str(cm.exception))

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_symptom_N7_replay_without_manifest_digest_is_reported_ok_and_pinned_by_the_recording_itself(self):
        # S0-09b: the recording is PROVEN to have succeeded first (six cases, 4 completed / 1 partial / 1 failed, trace per case).
        # Otherwise "not reported as pinned" could be satisfied by a replay that merely failed earlier (stale smoke fixture).
        self.assertEqual({c.case_id: c.status for c in self.rec.cases}, {
            "smoke-c01": "completed", "smoke-c02": "completed", "smoke-c03": "completed", "smoke-c04": "completed",
            "smoke-c05": "partial", "smoke-c06": "failed"})
        self.assertEqual(self.rec.exit_code, 0)
        rc, out, _ = self.run_cli("smoke", "replay", "--recording", str(self.tmp / "rec"), "--out", str(self.tmp / "rep-nopin"),
                                  "--suite", str(self.suite))
        self.assertEqual(rc, 0)
        self.assertIn("smoke replay: OK", out)
        self.assertIn("pinned by recording-manifest", out)

    @unittest.expectedFailure
    def test_DEFECT_N7_replay_without_an_operator_supplied_digest_is_not_reported_as_pinned(self):
        # Strict positive form (S0-09b): the desired behaviour is either a refusal that NAMES the missing digest, or an OK that
        # explicitly says no pin exists. A replay that fails for any other reason satisfies neither, so it cannot masquerade as a fix.
        rc, out, err = self.run_cli("smoke", "replay", "--recording", str(self.tmp / "rec"), "--out",
                                    str(self.tmp / "rep-nopin2"), "--suite", str(self.suite))
        refused = rc == 2 and "manifest-digest" in err and "Traceback" not in err
        low = out.lower()
        labelled = rc == 0 and "pinned by recording-manifest" not in out and any(
            s in low for s in ("pin: none", "unpinned", "not pinned", "no pin"))
        self.assertTrue(refused or labelled, (rc, out[-300:], err[-300:]))

    def test_control_the_operator_digest_is_enforced_when_supplied(self):
        d = self.rec.manifest_digest
        rc, out, _ = self.run_cli("smoke", "replay", "--recording", str(self.tmp / "rec"), "--out", str(self.tmp / "rep-pin"),
                                  "--suite", str(self.suite), "--manifest-digest", d)
        self.assertEqual(rc, 0)
        rc, _, err = self.run_cli("smoke", "replay", "--recording", str(self.tmp / "rec"), "--out", str(self.tmp / "rep-bad"),
                                  "--suite", str(self.suite), "--manifest-digest", "sha256:" + "0" * 64)
        self.assertEqual(rc, 2)
        self.assertNotIn("Traceback", err)

    def test_control_missing_case_in_the_recording_is_a_refusal_not_a_smaller_report(self):
        rec = self.tmp / "rec-missing"
        shutil.copytree(self.tmp / "rec", rec)
        m = json.loads((rec / "eval.json").read_text())
        m["cases"] = m["cases"][:-1]
        (rec / "eval.json").write_text(json.dumps(m, sort_keys=True, indent=2) + "\n")
        with self.assertRaises(EvalError):
            replay_smoke(rec, self.tmp / "rep-missing", suite_dir=self.suite)

    def test_control_symlinked_runs_directory_in_a_recording_is_refused(self):
        rec = self.tmp / "rec-link"
        shutil.copytree(self.tmp / "rec", rec)
        shutil.move(rec / "runs", self.tmp / "elsewhere-runs")
        os.symlink(self.tmp / "elsewhere-runs", rec / "runs")
        out = replay_smoke(rec, self.tmp / "rep-link", suite_dir=self.suite)
        self.assertEqual(out.exit_code, 1)
        self.assertTrue(all(not c.ran or c.problems for c in out.cases))
        self.assertEqual(len(out.cases), 6)                              # reported, none dropped

    def test_control_a_case_crash_in_the_engine_is_a_failed_scored_case_and_the_report_keeps_six(self):
        real = runner.run_review

        def boom(spec):
            if spec.case["id"] == "smoke-c02":
                raise RuntimeError("engine blew up")
            return real(spec)
        with mock.patch.object(runner, "run_review", boom):
            out = record_smoke(self.tmp / "rec-boom", suite_dir=self.suite)
        self.assertEqual(len(out.report["cases"]), 6)
        c2 = next(c for c in out.cases if c.case_id == "smoke-c02")
        self.assertEqual((c2.ran, c2.status, out.exit_code), (False, "failed", 1))
        self.assertEqual(out.report["coverage"]["failed"], 2)


if __name__ == "__main__":
    unittest.main()
