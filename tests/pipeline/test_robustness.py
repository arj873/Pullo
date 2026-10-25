"""Hostile or unlucky inputs and internal faults must end as honest, typed terminal outcomes."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest import mock

from reviewer.gateway import SpendBook
from reviewer.pipeline import PipelineError, load_result

from .helpers import (HEAD, Rig, all_bytes, entry, events_of, hid, hyp, inv, judge, model_calls, resp, script, terr, ver)


def w(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


class RunIdShapedText(Rig):
    def test_run_id_shaped_text_in_a_diff_or_pr_cannot_suppress_the_review(self):
        head = dict(HEAD)
        head["src/a.py"] = HEAD["src/a.py"].replace("return x - 1", "return x - 1  # see run_0123456789abcdef", 1)
        m = self.mini(head=head, body="ticket evr_fedcba9876543210 and run_aaaaaaaaaaaaaaaa")
        h = hyp(m, "src/a.py", 2)                        # a line without the token stays citable
        res, spy = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual((res.status, len(res.comments)), ("completed", 1))
        req = json.dumps(spy.requests[0])
        for tok in ("run_0123456789abcdef", "evr_fedcba9876543210", "run_aaaaaaaaaaaaaaaa"):
            self.assertNotIn(tok, req)
        self.assertIn("run_[id-removed]", req)
        self.assertIn("rewritten", req)
        # the rewrite is disclosed to the reader of the review as well as to the model
        self.assertIn("rewritten to 'run_[id-removed]'", Path(res.review_path).read_text())

    def test_model_output_with_run_id_shapes_cannot_break_the_verifier_or_judge_requests(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2, claim="mentions run_0123456789abcdef in its claim", mechanism="and evr_0123456789abcdef")
        res, spy = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual((res.status, len(res.comments)), ("completed", 1))
        self.assertTrue(all("run_0123456789abcdef" not in json.dumps(r) for r in spy.requests))


class VerifierRepair(Rig):
    def test_verifier_gets_one_bounded_repair_and_the_finding_names_the_confirming_attempt(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        bad = entry("VERIFY", "verifier", "verifier", 0, 0, response=resp(None, status="invalid-output", raw="{half"))
        good = ver(0, m, path="src/a.py", line=2, attempt=1)
        res, spy = self.record(m, script(inv(h), bad, good, judge(w([hid(0, h)]))))
        calls = model_calls(res, "VERIFY")
        self.assertEqual([(c["attempt"], c.get("repairOf") is not None, c["request"]["hypothesisId"]) for c in calls],
                         [(0, False, hid(0, h)), (1, True, hid(0, h))])
        self.assertEqual(res.findings[0]["verification"]["callIds"], [calls[1]["callId"]])
        self.assertEqual(res.verifications[0]["callIds"], [calls[0]["callId"], calls[1]["callId"]])
        self.assertEqual((res.status, len(res.comments)), ("completed", 1))

    def test_verifier_repair_exhaustion_is_a_verifier_failure(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        bad = lambda a: entry("VERIFY", "verifier", "verifier", 0, a, response=resp(None, status="invalid-output", raw="x"))
        res, _ = self.record(m, script(inv(h), bad(0), bad(1)))
        self.assertEqual((res.status, [i["reason"] for i in res.incomplete]), ("partial", ["verifier-failure"]))
        self.assertEqual(res.verifications[0]["error"]["code"], "repair-exhausted")


class Revalidation(Rig):
    def test_findings_are_proven_again_against_the_run_trace_before_any_comment_is_made(self):
        from reviewer.contracts import Issue
        from reviewer.pipeline import engine
        real = engine.check_finding_provenance

        def later_tampered(finding, events):
            if any(e["type"] == "stage.start" and e["stage"] == "JUDGE" for e in events):
                return [Issue("$finding", "provenance", "trace no longer proves this finding")]
            return real(finding, events)
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        with mock.patch.object(engine, "check_finding_provenance", side_effect=later_tampered):
            res, spy = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual((res.status, res.error["code"], res.error["stage"]), ("failed", "contract-violation", "JUDGE"))
        self.assertIn("revalidation", res.error["message"])
        self.assertEqual((res.comments, spy.calls), ([], 2))              # no judge call, nothing published
        self.assertEqual(json.loads(Path(res.comments_path).read_text())["comments"], [])
        self.assertEqual(len(res.findings), 1)                            # the verified finding is still on record


class BackendFailure(Rig):
    def test_a_backend_that_cannot_build_its_gateway_leaves_nothing_behind(self):
        from reviewer.pipeline import RecordBackend, run_review

        class Refusing(RecordBackend):
            def make_gateway(self, **kw):
                raise PipelineError("config", "gateway unavailable")
        m = self.mini()
        spy_backend, spy = self.record_backend(script(inv()))
        backend = Refusing(self.handle, self.book, spy_backend.providers, spy_backend.clock)
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, backend))
        self.assertEqual(cm.exception.code, "config")
        self.assertEqual((list(self.out.iterdir()), spy.calls), ([], 0))


class InternalFaults(Rig):
    def test_an_unexpected_exception_inside_a_stage_is_a_typed_failure_with_a_complete_trace(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        with mock.patch("reviewer.pipeline.engine.snaps.location_ok", side_effect=RuntimeError("boom secret-detail")):
            res, spy = self.record(m, script(inv(h)))
        self.assertEqual((res.status, res.error["code"], res.error["stage"]), ("failed", "internal", "INVESTIGATE"))
        self.assertNotIn("secret-detail", json.dumps(res.error))
        self.assertEqual(events_of(res)[-1]["type"], "run.end")
        self.assertEqual(res.stages["INVESTIGATE"]["status"], "failed")
        self.assertEqual(len(res.stages), 8)
        self.assertEqual(load_result(self.out, res.run_id).status, "failed")

    def test_a_failing_spend_book_after_provider_contact_is_recorded_and_flagged_for_reconciliation(self):
        class BrokenBook(SpendBook):
            def settle(self, key, usd):
                raise OSError("disk full")
        self.book = BrokenBook(self.handle)
        m = self.mini()
        res, spy = self.record(m, script(inv()))
        self.assertEqual((res.status, res.error["code"]), ("failed", "internal"))
        self.assertIn("reconciliation", res.error["message"])
        self.assertTrue(res.receipt["needsReconciliation"])
        self.assertEqual(spy.calls, 1)
        errs = [e for e in events_of(res) if e["type"] == "error"]
        self.assertTrue(any("spend book failed" in e["error"]["message"] for e in errs))
        self.assertEqual(events_of(res)[-1]["type"], "run.end")
        self.assertEqual(model_calls(res)[0]["callId"], res.cost["records"][0]["callId"])

    def test_oversized_or_corrupt_receipt_files_are_refused_not_parsed(self):
        m = self.mini()
        res, _ = self.record(m, script(inv()))
        p = Path(res.run_dir, "receipt.json")
        good = p.read_bytes()
        for bad in (b" " * (17 << 20), b'{"a": 1, "a": 2}', b"[1,2", b'{"schema": "run-receipt@1"}'):
            p.write_bytes(bad)
            with self.assertRaises(PipelineError) as cm:
                self.record(m, script(inv()))
            self.assertEqual(cm.exception.code, "checkpoint-invalid")
        p.write_bytes(good)
        self.assertTrue(self.record(m, script(inv()))[0].idempotent)

    def test_tampered_completed_run_directory_is_detected_when_reloaded(self):
        m = self.mini()
        res, _ = self.record(m, script(inv()))
        for name, fn in (("comments.json", lambda b: b.replace(b"draft", b"posted")),
                         ("review.md", lambda b: b + b"x"),
                         ("trace.jsonl", lambda b: b.replace(b"INGEST", b"INGEZT", 1))):
            p = Path(res.run_dir, name)
            good = p.read_bytes()
            p.write_bytes(fn(good))
            with self.assertRaises(PipelineError, msg=name) as cm:
                load_result(self.out, res.run_id)
            self.assertEqual(cm.exception.code, "checkpoint-invalid")
            p.write_bytes(good)
        art = Path(res.run_dir, "artifacts/04-INVESTIGATE.v1.json")
        good = art.read_bytes()
        art.write_bytes(good.replace(b"completed", b"failed"))
        with self.assertRaises(PipelineError):
            load_result(self.out, res.run_id)
        art.write_bytes(good)
        self.assertEqual(load_result(self.out, res.run_id).status, "completed")


if __name__ == "__main__":
    unittest.main()
