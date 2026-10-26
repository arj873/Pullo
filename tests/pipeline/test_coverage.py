"""S0B-02b: optional host-provided partial coverage, plus the S0-09 corrections (N1, N2, N5, N8) that need a rig.

Coverage is a host document; the pipeline binds its digest, validates it against the PINNED union manifests,
never infers changes from head-only context, and says out loud that the view is partial."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import unittest

from reviewer.contracts.canonical import digest
from reviewer.pipeline import PipelineError, load_result, run_review
from reviewer.pipeline import coverage as cov_mod

from .helpers import BASE, HEAD, EVR2, Rig, hid, hyp, inv, judge, model_calls, script, ver

CTX = "src/ctx.py"


def changed(path, status="modified", *, base=True, head=True, prev=None, gaps=()):
    return {"path": path, "previousPath": prev, "status": status, "base": base, "head": head, "gapKinds": list(gaps)}


def coverage_for(*, context_head=(CTX,), context_base=(), recorded=None, extra=None):
    cov = {"schema": "historical-coverage@1", "scope": "changed-files-and-selected-context",
           "fullRepositoryCoverage": False, "recorded": recorded or {"complete": True, "gapKinds": []},
           "unsafePathsOmitted": 0, "changedPaths": [changed("src/a.py"), changed("src/b.py")],
           "contextPaths": {"base": sorted(context_base), "head": sorted(context_head)},
           "note": "Partial view."}
    cov.update(extra or {})
    return cov


class Partial(Rig):
    def mini_partial(self, cid="part-1"):
        # CTX exists only in the head union, as context: a manifest delta would call it an ADDED file
        return self.mini(cid, base=BASE, head={**HEAD, CTX: "VALUE = 1\n"})

    def spec(self, mini, backend, *, coverage=None, **kw):
        s = super().spec(mini, backend, **kw)
        return dataclasses.replace(s, coverage=coverage)

    def record_cov(self, mini, scr, cov, **kw):
        backend, spy = self.record_backend(scr)
        return run_review(self.spec(mini, backend, coverage=cov, **kw)), spy

    def basic(self, m):
        return script(inv(hyp(m, "src/a.py", 2)), ver(0, m, path="src/a.py", line=2),
                      judge({"findingIds": [hid(0, hyp(m, "src/a.py", 2))], "title": "T", "body": "B"}))


class Seam(Partial):
    def test_partial_run_binds_the_digest_and_never_reads_head_only_context_as_a_change(self):
        m = self.mini_partial()
        cov = coverage_for()
        res, spy = self.record_cov(m, self.basic(m), cov)
        self.assertEqual((res.status, len(res.comments)), ("completed", 1))
        self.assertEqual(res.receipt["coverageDigest"], digest(cov))
        self.assertEqual(sorted(f["path"] for f in json.loads(
            (self.out / res.run_id / "artifacts" / "02-PREPARE.v1.json").read_text())["payload"]["files"]),
            ["src/a.py", "src/b.py"])
        self.assertTrue((self.out / res.run_id / "coverage.json").is_file())
        # prompts and review.md say PARTIAL; the full-snapshot sentence is gone
        req = json.dumps(spy.requests[0]["messages"][1]["content"])
        self.assertIn("PARTIAL coverage", req)
        self.assertNotIn("Two full pinned snapshots", req)
        self.assertIn("PARTIAL coverage", json.dumps(spy.requests[1]["messages"][1]["content"]))
        md = (self.out / res.run_id / "review.md").read_text()
        self.assertIn("## Coverage (partial)", md)
        self.assertIn("not a full-repository review", md)
        self.assertEqual(load_result(self.out, res.run_id).receipt["coverageDigest"], digest(cov))

    def test_coverage_changes_the_run_identity_and_a_replay_must_use_the_same_coverage(self):
        m = self.mini_partial()
        cov = coverage_for()
        res, _ = self.record_cov(m, self.basic(m), cov)
        rep = run_review(self.spec(m, self.replay_backend(res), coverage=cov, eval_id=EVR2))
        self.assertEqual((rep.status, rep.trace_digest == res.trace_digest, len(rep.comments)), ("completed", False, 1))
        self.assertEqual(rep.receipt["coverageDigest"], res.receipt["coverageDigest"])
        other = coverage_for(extra={"note": "different"})
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, self.replay_backend(res), coverage=other, eval_id="evr_" + "8" * 16))
        self.assertEqual(cm.exception.code, "identity-mismatch")
        with self.assertRaises(PipelineError) as cm:                       # dropping the coverage is also a different run
            run_review(self.spec(m, self.replay_backend(res), coverage=None, eval_id="evr_" + "9" * 16))
        self.assertEqual(cm.exception.code, "identity-mismatch")

    def test_full_view_receipt_and_outputs_carry_no_coverage(self):
        m = self.mini()
        res, _ = self.record(m, self.basic(m))
        self.assertNotIn("coverageDigest", res.receipt)
        self.assertFalse((self.out / res.run_id / "coverage.json").exists())
        self.assertNotIn("Coverage (partial)", (self.out / res.run_id / "review.md").read_text())

    def test_tampered_coverage_json_is_refused_on_load(self):
        m = self.mini_partial()
        res, _ = self.record_cov(m, self.basic(m), coverage_for())
        p = self.out / res.run_id / "coverage.json"
        p.write_text(p.read_text().replace("Partial view.", "Whole repo."))
        with self.assertRaises(PipelineError) as cm:
            load_result(self.out, res.run_id)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")

    def test_candidate_in_a_context_only_file_is_not_a_change(self):
        m = self.mini_partial()
        h = hyp(m, CTX, 1)
        keep = hyp(m, "src/a.py", 2)
        res, spy = self.record_cov(m, script(inv(h, keep), ver(1, m, path="src/a.py", line=2),
                                             judge({"findingIds": [hid(1, keep)], "title": "T", "body": "B"})), coverage_for())
        self.assertEqual(spy.calls, 3)                       # investigator, ONE verifier (not for the context file), judge
        self.assertEqual([c["anchor"]["path"] for c in res.comments], ["src/a.py"])
        self.assertEqual([d["reason"] for d in res.drops if d["subjectIds"] == [hid(0, h)]], ["invalid-citation"])


class Validation(Partial):
    def refused(self, cov, code="invalid-input", mini=None):
        m = mini or self.mini_partial()
        backend, spy = self.record_backend(self.basic(m))
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, backend, coverage=cov))
        self.assertEqual(cm.exception.code, code)
        self.assertEqual(spy.calls, 0)
        return str(cm.exception)

    def test_malformed_or_overclaiming_coverage_is_refused_before_any_provider_call(self):
        self.assertIn("fullRepositoryCoverage", self.refused(coverage_for(extra={"fullRepositoryCoverage": True})))
        self.assertIn("unknown key", self.refused(coverage_for(extra={"surprise": 1})))
        self.assertIn("schema/scope", self.refused(coverage_for(extra={"scope": "full-repository"})))
        bad = coverage_for()
        bad["changedPaths"][0]["path"] = "../escape"
        self.assertIn("relative POSIX path", self.refused(bad))
        dup = coverage_for()
        dup["changedPaths"].append(changed("src/a.py"))
        self.assertIn("twice", self.refused(dup))

    def test_coverage_must_classify_exactly_the_pinned_manifest_paths(self):
        self.assertIn("does not classify", self.refused(coverage_for(context_head=())))                # CTX unclassified
        self.assertIn("absent from the pinned", self.refused(coverage_for(context_head=(CTX, "src/ghost.py"))))
        both = coverage_for(extra={"changedPaths": [changed("src/a.py"), changed("src/b.py"), changed(CTX, "added", base=False)]})
        self.assertIn("both changed and context", self.refused(both))
        # a head-only file the host calls "modified with a base" must exist on the base side too
        wrong = coverage_for(extra={"changedPaths": [changed("src/a.py"), changed("src/b.py"), changed(CTX)]},
                             context_head=())
        self.assertIn("absent from the pinned base", self.refused(wrong))

    def test_rows_follow_the_recorded_status_and_one_sided_rows_are_gaps_not_adds_or_deletes(self):
        cov = coverage_for(extra={"changedPaths": [
            changed("n.py", "renamed", prev="o.py"), changed("new.py", "added", base=False),
            changed("gone.py", "removed", head=False), changed("cp.py", "copied", prev="src.py"),
            changed("m_head_only.py", "modified", base=False), changed("m_base_only.py", "modified", head=False),
            changed("x.py", "modified", base=False, head=False), changed("odd.py", "added"),        # added WITH a base side
            changed("same.py", "unchanged"), changed("rn_nobase.py", "renamed", base=False)]})
        rows, gaps = cov_mod.rows_of(cov)
        self.assertEqual(rows, sorted([("D", "gone.py"), ("A", "n.py"), ("A", "new.py"), ("D", "o.py"), ("A", "cp.py")],
                                      key=lambda r: (r[1], r[0])))
        self.assertEqual(sorted(g["path"] for g in gaps),
                         ["m_base_only.py", "m_head_only.py", "odd.py", "rn_nobase.py", "x.py"])
        self.assertNotIn("m_head_only.py", [p for _, p in rows])             # a missing side is not an addition
        self.assertIn("NOT known additions or deletions", cov_mod.statement(cov))

    def test_validate_accepts_executable_entries_and_refuses_symlinks(self):
        import os, tempfile
        from pathlib import Path
        from reviewer.contracts.snapshot import build_manifest
        with tempfile.TemporaryDirectory() as t:
            for side in ("base", "head"):
                (Path(t) / side).mkdir()
                (Path(t) / side / "run.sh").write_text("echo hi\n" if side == "base" else "echo ho\n")
                os.chmod(Path(t) / side / "run.sh", 0o755)
            bm, hm = (build_manifest(Path(t) / s) for s in ("base", "head"))
            self.assertEqual({e["type"] for e in hm["entries"]}, {"executable"})
            cov = coverage_for(context_head=(), extra={"changedPaths": [changed("run.sh")]})
            self.assertEqual(cov_mod.validate(cov, bm, hm), digest(cov))
            (Path(t) / "head" / "ln").symlink_to("run.sh")
            with self.assertRaises(PipelineError) as cm:
                cov_mod.validate(cov, bm, build_manifest(Path(t) / "head"))
            self.assertIn("not a regular file", str(cm.exception))

    def test_one_sided_modified_row_is_listed_unchanged_in_kind_and_disclosed_end_to_end(self):
        m = self.mini("gap-1", base={**BASE, "src/old.py": "x = 1\n"}, head=HEAD)
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/old.py", "modified", head=False)]})
        res, spy = self.record_cov(m, self.basic(m), cov)
        self.assertEqual(res.status, "completed")
        prep = json.loads((self.out / res.run_id / "artifacts" / "02-PREPARE.v1.json").read_text())["payload"]["files"]
        old = next(f for f in prep if f["path"] == "src/old.py")
        self.assertEqual((old["status"], old["additions"], old["deletions"]), ("modified", 0, 0))      # never "deleted"
        self.assertIn("NOT known additions or deletions", spy.requests[0]["messages"][1]["content"])
        self.assertIn("Recorded on one side only", (self.out / res.run_id / "review.md").read_text())


class Corrections(Partial):
    def test_n2_unrelated_verifier_citation_does_not_verify_but_extra_cross_file_proof_is_kept(self):
        m = self.mini()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2)))
        self.assertEqual((len(res.findings), len(res.comments)), (0, 0))
        d = next(d for d in res.drops if d["subjectIds"] == [hid(0, h)])
        self.assertEqual(d["reason"], "invalid-citation")
        self.assertIn("tied to the proposed location", d["detail"])
        both = ver(0, m, evidence=[m.cite("src/a.py", 2), m.cite("src/b.py", 2)])
        res2, _ = self.record(m, script(inv(h), both, judge({"findingIds": [hid(0, h)], "title": "T", "body": "B"})),
                              eval_id="evr_" + "6" * 16)
        self.assertEqual(len(res2.findings), 1)
        self.assertEqual({e["path"] for e in res2.findings[0]["verification"]["evidence"]}, {"src/a.py", "src/b.py"})

    def test_n5_candidate_in_an_unchanged_file_is_dropped(self):
        same = {"src/a.py": HEAD["src/a.py"], "src/b.py": BASE["src/b.py"]}
        m = self.mini("offdiff", base=BASE, head=same)                    # only a.py changed
        h = hyp(m, "src/b.py", 2)
        res, spy = self.record(m, script(inv(h)))
        self.assertEqual((len(res.hypotheses), len(res.comments)), (0, 0))
        self.assertEqual(spy.calls, 1)

    def test_n8_output_root_that_contains_the_snapshots_is_refused(self):
        m = self.mini()
        backend, spy = self.record_backend(self.basic(m))
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, backend, out_root=m.root))
        self.assertEqual(cm.exception.code, "path-escape")
        with self.assertRaises(PipelineError):
            run_review(self.spec(m, backend, out_root=m.root.parent))
        self.assertEqual(spy.calls, 0)

    def test_n1_a_consistently_forged_comments_file_is_refused_on_load_and_reinvocation(self):
        m = self.mini()
        res, _ = self.record(m, self.basic(m))
        d = self.out / res.run_id
        forged = (d / "comments.json").read_text().replace('"B"', '"TAMPERED"').replace("Something is wrong", "FORGED")
        (d / "comments.json").write_text(forged)
        rec = json.loads((d / "receipt.json").read_text())
        rec["outputs"]["comments.json"] = hashlib.sha256(forged.encode()).hexdigest()
        (d / "receipt.json").write_text(json.dumps(rec, sort_keys=True, indent=2) + "\n")
        with self.assertRaises(PipelineError) as cm:
            load_result(self.out, res.run_id)
        self.assertIn("render", str(cm.exception))
        backend, spy = self.record_backend(self.basic(m))
        with self.assertRaises(PipelineError):
            run_review(self.spec(m, backend))
        self.assertEqual(spy.calls, 0)


class FinalCorrections(Partial):
    """S0-07c: C1 absent-side flag vs manifest, C2 logical-path uniqueness, C3 context gaps, C4 judge/bundle disclosure,
    T1 cross-side kind conflict (refused here; the tools API itself still accepts it, see S0-07c-fix.md)."""

    def refused(self, tag, m, cov):
        backend, spy = self.record_backend(self.basic(m))
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, backend, coverage=cov, out_root=self.tmp / ("o-" + tag)))
        self.assertEqual((cm.exception.code, spy.calls), ("invalid-input", 0))
        return str(cm.exception)

    def both(self):
        return self.mini("both", base={**BASE, "src/p.py": "P=1\n"}, head={**HEAD, "src/p.py": "P=1\n"})

    def test_c1_a_side_flag_false_is_refused_when_the_pinned_manifest_holds_the_path_as_context(self):
        m = self.both()
        add = coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "added", base=False)]})
        rem = coverage_for(context_head=("src/p.py",), context_base=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "removed", head=False)]})
        one = coverage_for(context_head=("src/p.py",), context_base=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "modified", head=False)]})
        for tag, cov in (("add", add), ("rem", rem), ("one", one)):
            with self.subTest(tag):
                self.assertIn("contradicts itself", self.refused("c1" + tag, m, cov))

    def test_c1_controls_one_sided_context_real_adds_deletes_and_gap_rows_still_pass(self):
        m = self.mini("c1ok", base={**BASE, "src/gone.py": "G=1\n"}, head={**HEAD, "src/new.py": "N=1\n", CTX: "V=1\n"})
        cov = coverage_for(extra={"changedPaths": [changed("src/a.py"), changed("src/b.py"),
                                                   changed("src/new.py", "added", base=False),
                                                   changed("src/gone.py", "removed", head=False)]})
        res, _ = self.record_cov(m, self.basic(m), cov)
        self.assertEqual(res.status, "completed")

    def test_c2_overlapping_logical_paths_are_refused_for_every_shape(self):
        base = {"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n", "src/y.py": "Y=1\n"}
        head = {"src/a.py": HEAD["src/a.py"], "src/y.py": "X=1\n", "src/z.py": "Y=1\n"}
        m = self.mini("c2", base=base, head=head)
        shapes = {
            "source also modified": [changed("src/y.py", "renamed", prev="src/x.py"), changed("src/x.py", "modified", head=False)],
            "source also removed": [changed("src/y.py", "renamed", prev="src/x.py"), changed("src/x.py", "removed", head=False)],
            "chain": [changed("src/y.py", "renamed", prev="src/x.py"), changed("src/z.py", "renamed", prev="src/y.py")],
            "swap": [changed("src/y.py", "renamed", prev="src/x.py"), changed("src/x.py", "renamed", prev="src/y.py")],
        }
        for tag, rows in shapes.items():
            with self.subTest(tag):
                self.assertIn("more than one changedPaths entry", self.refused("c2" + tag, m, coverage_for(
                    context_head=(), extra={"changedPaths": [changed("src/a.py"), *rows]})))

    def test_c2_a_plain_rename_is_one_delete_plus_one_add(self):
        m = self.mini("c2ok", base={"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n"},
                      head={"src/a.py": HEAD["src/a.py"], "src/y.py": "X=1\n"})
        cov = coverage_for(context_head=(), extra={"changedPaths": [changed("src/a.py"), changed("src/y.py", "renamed", prev="src/x.py")]})
        self.assertEqual(cov_mod.rows_of(cov)[0], [("M", "src/a.py"), ("D", "src/x.py"), ("A", "src/y.py")])
        res, _ = self.record_cov(m, self.basic(m), cov)
        self.assertEqual(res.status, "completed")

    def test_t1_a_path_changed_on_one_side_and_context_on_the_other_is_refused_by_validate_and_build_view(self):
        m = self.both()
        cov = coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "added", base=False)]})   # head changed / base context
        self.assertIn("contradicts itself", self.refused("t1", m, cov))          # validate: reached through the flag check
        with self.assertRaises(PipelineError) as cm:
            cov_mod.build_view(cov, m.base, m.head)                # build_view alone (no validate): own guard
        self.assertIn("changed on one side and only context on the other", str(cm.exception))

    def test_c3_context_gaps_reach_statement_detail_review_and_bundle(self):
        rec = {"complete": False, "gapKinds": [], "contextGapKinds": ["text-not-found"], "contextGapCount": 2}
        cov = coverage_for(recorded=rec)
        st = cov_mod.statement(cov)
        self.assertIn("text-not-found", st)
        self.assertIn("2 file(s)", st)
        self.assertEqual(cov_mod.detail(cov)["gapKinds"], ["text-not-found"])
        self.assertEqual(cov_mod.detail(cov)["contextGap"], {"kinds": ["text-not-found"], "count": 2, "incomplete": True})
        m = self.mini_partial("c3")
        res, spy = self.record_cov(m, self.basic(m), cov)
        md = (self.out / res.run_id / "review.md").read_text()
        self.assertIn("- Recorded coverage gaps: text-not-found", md)
        self.assertIn("- Selected context not recorded: 2 file(s) (text-not-found)", md)
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertEqual(doc["coverage"]["contextGap"]["count"], 2)

    def test_c3_incomplete_without_a_reason_is_said_and_a_clean_record_says_none_without_inventing_gaps(self):
        self.assertIn("incomplete without naming a reason", cov_mod.statement(coverage_for(recorded={"complete": False})))
        clean = cov_mod.statement(coverage_for())
        self.assertNotIn("could NOT be recorded", clean)
        self.assertNotIn("incomplete", clean.replace("may be incomplete", ""))
        self.assertEqual(cov_mod.context_gap(coverage_for(recorded={})), {"kinds": [], "count": None, "incomplete": False})

    def test_c4_judge_request_and_comments_bundle_say_partial_and_full_view_is_unchanged(self):
        m = self.mini_partial("c4")
        cov = coverage_for()
        res, spy = self.record_cov(m, self.basic(m), cov)
        judge_doc = json.loads(spy.requests[-1]["messages"][1]["content"])
        self.assertIn("PARTIAL coverage", judge_doc["coverage"])
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertEqual(doc["schema"], "review-comments@2")
        self.assertEqual(doc["status"], "completed")
        c = doc["coverage"]
        self.assertEqual((c["fullRepositoryCoverage"], c["partial"], c["coverageDigest"], c["changedPathCount"]),
                         (False, True, digest(cov), 2))
        self.assertEqual(sorted(doc["comments"][0]), sorted(res.comments[0]))          # Comment entities untouched
        full = self.mini("c4full")
        res2, spy2 = self.record(full, self.basic(full))
        self.assertNotIn("coverage", json.loads(spy2.requests[-1]["messages"][1]["content"]))
        d2 = json.loads((self.out / res2.run_id / "comments.json").read_text())
        self.assertEqual((d2["schema"], "coverage" in d2), ("review-comments@1", False))

    def test_c4_partial_behavior_version_is_bound_only_when_coverage_is_present(self):
        from reviewer.pipeline import identity
        m = self.mini_partial("ver")
        s_full, s_part = self.spec(m, None), self.spec(m, None, coverage=coverage_for())
        base_id = identity.config_snapshot_id(s_full)
        self.assertEqual(base_id, identity.config_snapshot_id(s_full))
        orig = identity.PARTIAL_BEHAVIOR
        a = identity.config_snapshot_id(s_part)
        try:
            identity.PARTIAL_BEHAVIOR = "partial-disclosure@next"
            self.assertNotEqual(a, identity.config_snapshot_id(s_part))
            self.assertEqual(base_id, identity.config_snapshot_id(s_full))
        finally:
            identity.PARTIAL_BEHAVIOR = orig


if __name__ == "__main__":
    unittest.main()
