"""S1-05: D4 attempt guard (live + replay), strict pinned replay of a retrieval run, repository imports coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from reviewer.contracts import ContractViolation
from reviewer.gateway import load_trace
from reviewer.pipeline import PipelineError, RepositoryImports

from .helpers import (BASE, HEAD, Rig, entry, events_of, hid, hyp, ifinal, inv, iturn, judge, model_calls, resp, script,
                      terr, treq, ver, vfinal, vturn)


def w(ids):
    return {"findingIds": list(ids), "title": "T", "body": "B"}


class GuardLive(Rig):
    def test_cancel_after_the_first_attempt_blocks_the_retry_with_no_late_provider_contact(self):
        m = self.mini()
        t = [entry("INVESTIGATE", "investigator", "generalist", 0, a, error=terr("provider-timeout", "INVESTIGATE"))
             for a in range(3)]
        backend, spy = self.record_backend(script(*t))
        from reviewer.pipeline import ReviewSpec, run_review
        spec = ReviewSpec(case=m.case, base=m.base, head=m.head, profile=__import__("tests.pipeline.helpers", fromlist=["PROFILE"]).PROFILE,
                          plan=__import__("tests.pipeline.helpers", fromlist=["PLAN"]).PLAN,
                          host=self.host(m.id, cancel=lambda: spy.calls >= 1), backend=backend)
        res = run_review(spec)
        self.assertEqual(spy.calls, 1)                                   # attempt 0 only: no late provider contact
        calls = model_calls(res, "INVESTIGATE")
        self.assertEqual([(c["attempt"], c["error"]["code"]) for c in calls], [(0, "provider-timeout"), (1, "cancelled")])
        self.assertEqual(calls[1]["error"]["detail"]["refusedBy"], "host-guard")
        costs = {e["record"]["callId"]: e["record"] for e in events_of(res) if e["type"] == "cost"}
        self.assertGreater(costs[calls[0]["callId"]]["usdMicros"], 0)    # the earlier attempt stays charged
        self.assertEqual((costs[calls[1]["callId"]]["usdMicros"], costs[calls[1]["callId"]]["reservedUsdMicros"]), (0, 0))
        self.assertEqual(res.status, "cancelled")
        self.assertEqual(res.receipt["retrieval"] if "retrieval" in res.receipt else None, None)

    def test_deadline_after_the_first_attempt_blocks_the_repair(self):
        m = self.mini()
        bad = entry("INVESTIGATE", "investigator", "generalist", 0, 0, response=resp(None, status="invalid-output", raw="{x"))
        backend, spy = self.record_backend(script(bad, inv(hyp(m, "src/a.py", 2), attempt=1)))
        from reviewer.pipeline import ReviewSpec, run_review
        from .helpers import PLAN, PROFILE
        host = self.host(m.id, clock=lambda: 10_000.0 if spy.calls >= 1 else 0.0)
        res = run_review(ReviewSpec(case=m.case, base=m.base, head=m.head, profile=PROFILE, plan=PLAN, host=host,
                                    backend=backend))
        self.assertEqual(spy.calls, 1)
        calls = model_calls(res, "INVESTIGATE")
        self.assertEqual([(c["attempt"], c["error"]["code"] if c.get("error") else "ok") for c in calls],
                         [(0, "ok"), (1, "deadline-exceeded")])
        self.assertEqual(res.status, "failed")
        self.assertEqual(res.hypotheses, [])


class StrictReplay(Rig):
    def recorded(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        scr = script(iturn(0, [treq("read_file", side="head", path="src/b.py")]), ifinal(1, h),
                     vturn(0, [treq("read_file", side="head", path="src/b.py")]),
                     vfinal(1, m, path="src/a.py", line=2), judge(w([hid(0, h)])))
        res, spy = self.record_turn(m, scr)
        return m, res, spy

    def replay_turn(self, m, res, **kw):
        from .helpers import TURN_PLAN, TURN_PROFILE
        out = self.tmp / "out2"
        out.mkdir(exist_ok=True)
        return self.replay(m, res, out=out, profile=TURN_PROFILE, plan=TURN_PLAN, **kw)

    def test_retrieval_run_replays_offline_under_an_external_pin_with_everything_consumed(self):
        m, res, spy = self.recorded()
        self.assertEqual((res.status, len(res.comments)), ("completed", 1))
        n = spy.calls
        rep = self.replay_turn(m, res)
        self.assertEqual((rep.status, len(rep.comments)), ("completed", 1))
        g = rep.gateway_report
        self.assertEqual((g["liveCalls"], g["replayedCalls"], g["unconsumedRecordedCalls"], g["newSpendUsdMicros"]),
                         (0, n, 0, 0))
        self.assertEqual(spy.calls, n)                                   # the recording provider was never touched again
        self.assertEqual(rep.receipt["retrieval"]["summary"], res.receipt["retrieval"]["summary"])
        load_trace(rep.trace_path)

    def test_replay_with_a_different_policy_is_refused_by_config_identity(self):
        from reviewer.pipeline import RetrievalPolicy
        m, res, _ = self.recorded()
        with self.assertRaises(PipelineError) as e:
            self.replay_turn(m, res, retrieval=RetrievalPolicy().tightened(verifier_turns=3))
        self.assertEqual(e.exception.code, "identity-mismatch")

    def test_guard_stops_a_replay_between_attempts_and_consumes_nothing_it_did_not_reproduce(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        scr = script(entry("INVESTIGATE", "investigator", "generalist", 0, 0, error=terr("provider-timeout", "INVESTIGATE")),
                     inv(h, attempt=1), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)])))
        res, _ = self.record(m, scr)
        self.assertEqual(len(res.comments), 1)
        out = self.tmp / "out3"
        out.mkdir()

        def cancel():                                              # true once the replay logged its first model call
            return any('"type": "model.call"' in p.read_text() for p in out.glob("*/trace.jsonl"))
        rep = self.replay(m, res, out=out, cancel=cancel)
        calls = model_calls(rep, "INVESTIGATE")
        self.assertEqual([(c["attempt"], c["error"]["code"]) for c in calls], [(0, "provider-timeout")])
        # a replay-time refusal is an error event, not a replayed call: the recorded repair stays unconsumed
        self.assertEqual([e["error"]["code"] for e in events_of(rep) if e["type"] == "error"], ["cancelled"])
        self.assertEqual((rep.status, rep.error["code"]), ("cancelled", "cancelled"))
        self.assertEqual(rep.gateway_report["newSpendUsdMicros"], 0)
        self.assertGreater(rep.gateway_report["unconsumedRecordedCalls"], 0)      # the blocked repair was not "consumed"


# ---------------------------------------------------------------- repository imports

def record(m, side, *, counts=None, rel=None):
    snap = m.base_manifest if side == "base" else m.head_manifest
    counts = counts or {}
    total = sum(counts.values())
    r = {"schema": "repo-import@1", "repo": "o/r", "commitSha": ("a" if side == "base" else "b") * 40,
         "snapshotId": snap["snapshotId"], "omissions": {"counts": counts, "items": [{"path": f"x{i}.bin", "kind": k}
                                                                                  for k, n in counts.items() for i in range(n)],
                                                         "sha256": "0" * 64},
         "coverage": {"scope": "repository-with-omissions" if total else "full-repository",
                      "fullRepositoryCoverage": total == 0}}   # shape of a genuine repo-import@1 record
    if rel:
        r["relatesTo"] = rel
    return r


class Imports(Rig):
    def run_with(self, imports, **kw):
        m = self.mini(title="", body="")
        h = hyp(m, "src/a.py", 2)
        scr = script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)])))
        res, spy = self.record(m, scr, imports=imports(m), **kw)
        return m, res, spy

    def test_complete_imports_are_repository_scope_and_disclose_pr_text_omission(self):
        rel = {"caseId": "c", "side": "head", "partialSnapshotId": "snap:sha256:" + "1" * 64, "idEqualsPartial": False,
               "changedPathsChecked": 2, "changedPathsByteEqual": 2, "unchecked": []}
        m, res, spy = self.run_with(lambda m: RepositoryImports(record(m, "base"), record(m, "head", rel=rel)))
        cov = json.loads(Path(res.comments_path).read_text())["coverage"]
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"], cov["partial"]), ("repository", True, False))
        self.assertEqual(cov["relatesTo"]["head"]["idEqualsPartial"], False)
        req = json.loads(spy.requests[0]["messages"][1]["content"])
        self.assertIn("REPOSITORY coverage", req["coverage"])
        self.assertIn("title and body were not supplied", req["coverage"])
        self.assertIn("REPOSITORY coverage", Path(res.review_path).read_text())
        self.assertEqual(res.receipt["coverageDigest"], __import__("reviewer.contracts.canonical", fromlist=["digest"]).digest(
            json.loads((Path(res.run_dir) / "coverage.json").read_text())))

    def test_omissions_in_either_record_end_the_full_claim_in_view_tools_and_outputs(self):
        m, res, spy = self.run_with(lambda m: RepositoryImports(record(m, "base"), record(m, "head", counts={"binary": 2, "lfs": 1})))
        doc = json.loads(Path(res.comments_path).read_text())["coverage"]
        self.assertEqual((doc["scope"], doc["fullRepositoryCoverage"], doc["gapKinds"]),
                         ("repository-with-omissions", False, ["binary", "lfs"]))
        for t in (e for e in events_of(res) if e["type"] == "tool.call"):
            self.assertEqual(t["result"]["completeness"] if t["tool"] != "read_file" else "approximate", "approximate")
        notices = " ".join(e["result"]["notice"] for e in events_of(res) if e["type"] == "tool.call")
        self.assertIn("WITH OMISSIONS", notices)
        self.assertIn("NOT every path is present", json.loads(spy.requests[0]["messages"][1]["content"])["coverage"])
        self.assertIn("binary", Path(res.review_path).read_text())

    def test_records_must_match_their_manifests_and_their_own_counts(self):
        with self.assertRaises(PipelineError):
            self.run_with(lambda m: RepositoryImports({**record(m, "base"), "snapshotId": "snap:sha256:" + "9" * 64}, record(m, "head")))
        with self.assertRaises(PipelineError):
            self.run_with(lambda m: RepositoryImports({**record(m, "base", counts={"binary": 1}), "coverage": {"scope": "full-repository", "fullRepositoryCoverage": True}},
                                                      record(m, "head")))

    def test_a_string_or_flag_lying_coverage_is_refused(self):
        with self.assertRaises(PipelineError):
            self.run_with(lambda m: RepositoryImports({**record(m, "base"), "coverage": "full-repository"}, record(m, "head")))
        lie = {"scope": "repository-with-omissions", "fullRepositoryCoverage": True}
        with self.assertRaises(PipelineError):
            self.run_with(lambda m: RepositoryImports(record(m, "base"), {**record(m, "head", counts={"lfs": 1}), "coverage": lie}))

    def test_imports_are_bound_into_config_identity(self):
        _, a, _ = self.run_with(lambda m: RepositoryImports(record(m, "base"), record(m, "head")))
        self.assertIn("coverageDigest", a.receipt)
        m = self.mini(body="")
        h = hyp(m, "src/a.py", 2)
        b, _ = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, h)]))), eval_id="evr_" + "5" * 16)
        self.assertNotEqual(a.run["configSnapshotId"], b.run["configSnapshotId"])


if __name__ == "__main__":
    unittest.main()


class RealImporterRecords(Rig):
    """F1/B1: GENUINE records from the real importer (local file:// fixture repository, no network) through run_review."""

    def real_imports(self, head_files):
        from reviewer.repoimport import import_repository
        from tests.repoimport.helpers import git
        from reviewer.repoimport.remote import local_fixture_remote
        w = self.tmp / "gitsrc"
        w.mkdir()
        git(w, "init", "-q", "--initial-branch=main")
        shas = []
        for files in (BASE, head_files):
            for p, t in files.items():
                (w / p).parent.mkdir(parents=True, exist_ok=True)
                (w / p).write_bytes(t if isinstance(t, bytes) else t.encode())
            git(w, "add", "-A", "-f")
            git(w, "commit", "-q", "-m", "c", "--no-verify")
            shas.append(git(w, "rev-parse", "HEAD"))
        store = self.tmp / "imports"
        return [import_repository(local_fixture_remote(w), sha, store) for sha in shas]

    def run_real(self, head_files):
        from reviewer.pipeline import SnapshotInput
        base, head = self.real_imports(head_files)
        case = {"schema": "case-input@1", "id": "real-1", "repo": "fixture-mini", "synthetic": True,
                "base": {"root": "cases/real/base", "snapshotId": base.snapshot_id},
                "head": {"root": "cases/real/head", "snapshotId": head.snapshot_id}, "pr": {"title": "t", "body": "b"}}
        line = Path(head.root).joinpath("src/a.py").read_text().split("\n")[1]
        cite = {"kind": "code", "path": "src/a.py", "lines": [2, 2], "commit": head.snapshot_id, "excerpt": line}
        h = {"claim": "x", "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
             "location": {"path": "src/a.py", "line": 2}, "mechanism": "m", "evidence": [cite]}
        from .helpers import PLAN, PROFILE
        from reviewer.pipeline import ReviewSpec, run_review
        backend, spy = self.record_backend(script(inv(h), ver(0, None, evidence=[cite]), judge(w([hid(0, h)]))))
        host = self.host("real-1", forbidden_roots=(self.tmp / "imports",))
        spec = ReviewSpec(case=case, base=SnapshotInput(base.root, base.manifest), head=SnapshotInput(head.root, head.manifest),
                          profile=PROFILE, plan=PLAN, host=host, backend=backend,
                          imports=RepositoryImports(base.record, head.record))
        return run_review(spec), spy

    def test_a_genuine_complete_import_reaches_run_review_as_repository_scope(self):
        res, spy = self.run_real(HEAD)
        self.assertEqual((res.status, len(res.comments)), ("completed", 1))
        cov = json.loads(Path(res.comments_path).read_text())["coverage"]
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"], cov["gapKinds"]), ("repository", True, []))

    def test_a_genuine_import_with_omissions_says_so_in_every_layer(self):
        res, spy = self.run_real({**HEAD, "blob.bin": b"\x00\x01\x02binary"})
        self.assertEqual(res.status, "completed")
        cov = json.loads(Path(res.comments_path).read_text())["coverage"]
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"]), ("repository-with-omissions", False))
        self.assertEqual(cov["gapKinds"], ["binary"])
        tools = [e for e in events_of(res) if e["type"] == "tool.call"]
        self.assertTrue(tools and all(t["result"]["notice"].count("WITH OMISSIONS") == 1 or t["result"]["status"] == "error"
                                      for t in tools))
        self.assertTrue(all(t["result"]["completeness"] == "approximate" for t in tools if t["tool"] != "read_file"))
