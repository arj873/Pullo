"""S0-09c focused re-check of the frozen S0-07c-fix patch (C1 C2 C3 C4, T1 pipeline side).

Run (repo root; not collected by `discover -s tests`, no __init__.py):

    nice -n 19 python3 -m unittest discover -s tests/partial_review

Scope is ONLY the S0-09b repros C1 C2 C3 C4 T1 and their positive controls. Each test checks the REASON a fix holds (refusal code,
the message that names the contradiction, zero provider calls, nothing written), not just that the old symptom is gone. No fuzz,
no mutation campaign, no general review. T1 on the direct tools API is NOT fixed and stays an expected failure in
test_partial_review.py; `TOOLS_API_T1` below pins that the pipeline closes it by its own guard, not by the tools.
"""

from __future__ import annotations

import copy
import json
import unittest

from reviewer.contracts.canonical import digest
from reviewer.pipeline import PipelineError, identity, load_result, run_review
from reviewer.pipeline import coverage as cov_mod

from tests.partial_review.test_partial_review import prepare_rows
from tests.pipeline.helpers import BASE, HEAD, EVR2, hid, hyp, inv, judge, script, ver
from tests.pipeline.test_coverage import CTX, Partial, changed, coverage_for

GAP_1347 = {"complete": False, "gapKinds": [], "contextGapKinds": ["text-not-found"], "contextGapCount": 1,
            "changedFilesExpected": 3, "changedFilesListed": 3, "changedFilesRecorded": 3}


class Refusal(Partial):
    """Run a coverage through the pipeline; returns (result, out_dir, spy, error)."""

    def go(self, tag, cov, m, scr=None):
        out = self.tmp / ("o-" + tag)
        out.mkdir()
        backend, spy = self.record_backend(scr or self.basic(m))
        try:
            res = run_review(self.spec(m, backend, coverage=cov, out_root=out))
        except PipelineError as e:
            return None, out, spy, e
        return res, out, spy, None

    def refused(self, tag, cov, m, *needles):
        res, out, spy, err = self.go(tag, cov, m)
        self.assertIsNotNone(err, f"{tag}: the contradictory record was accepted")
        self.assertEqual((err.code, spy.calls), ("invalid-input", 0), tag)           # before ANY provider call
        self.assertEqual(list(out.iterdir()), [], f"{tag}: a refused record must write nothing")
        for n in needles:
            self.assertIn(n, str(err), tag)                                          # ... and for the stated reason
        return str(err)

    def both_sides(self, tag="both"):
        return self.mini(tag, base={**BASE, "src/p.py": "P=1\n"}, head={**HEAD, "src/p.py": "P=1\n"})


# ======================================================================================================================
# C1  absent-side flag vs the side's pinned manifest
# ======================================================================================================================

class C1AbsentSide(Refusal):
    def test_added_with_the_path_in_base_context_is_refused_for_the_contradiction(self):
        cov = coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "added", base=False, head=True)]})
        msg = self.refused("add", cov, self.both_sides(), "records the base side as absent", "contradicts itself")
        self.assertIn("src/p.py", msg)

    def test_removed_with_the_path_in_head_context_is_refused_for_the_contradiction(self):
        cov = coverage_for(context_head=("src/p.py",), context_base=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "removed", base=True, head=False)]})
        self.refused("rem", cov, self.both_sides(), "records the head side as absent", "contradicts itself")

    def test_every_status_is_covered_not_only_added_and_removed(self):
        for st in ("modified", "changed"):
            with self.subTest(st, side="base"):
                cov = coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
                    changed("src/a.py"), changed("src/b.py"), changed("src/p.py", st, base=False, head=True)]})
                self.refused("m" + st, cov, self.both_sides("both-" + st), "records the base side as absent")
            with self.subTest(st, side="head"):
                cov = coverage_for(context_head=("src/p.py",), context_base=(), extra={"changedPaths": [
                    changed("src/a.py"), changed("src/b.py"), changed("src/p.py", st, base=True, head=False)]})
                self.refused("h" + st, cov, self.both_sides("both2-" + st), "records the head side as absent")

    def test_the_rename_halves_are_checked_too_source_on_head_and_target_on_base(self):
        # x -> y: x must not be on head, y must not be on base. Both contradictions are refused (by the kind rule, still
        # before any provider call); neither is quietly turned into D(x)+A(y).
        m = self.mini("r1", base={"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n"},
                      head={"src/a.py": HEAD["src/a.py"], "src/x.py": "X=1\n", "src/y.py": "X=1\n"})
        cov = coverage_for(context_head=("src/x.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/y.py", "renamed", prev="src/x.py")]})
        self.refused("r1", cov, m, "src/x.py", "contradictory record")
        m = self.mini("r2", base={"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n", "src/y.py": "X=1\n"},
                      head={"src/a.py": HEAD["src/a.py"], "src/y.py": "X=1\n"})
        cov = coverage_for(context_head=(), context_base=("src/y.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/y.py", "renamed", prev="src/x.py")]})
        self.refused("r2", cov, m, "src/y.py", "contradictory record")

    # ---- positive controls: nothing legitimate is refused
    def test_control_truthful_add_and_delete_and_one_sided_context_still_pass(self):
        m = self.mini("truth", base={**BASE, "src/gone.py": "G=1\n"}, head={**HEAD, "src/new.py": "N=1\n", CTX: "V=1\n"})
        cov = coverage_for(context_head=(CTX,), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/new.py", "added", base=False),
            changed("src/gone.py", "removed", head=False)]})
        res, out, spy, err = self.go("truth", cov, m)
        self.assertIsNone(err)
        self.assertEqual({p: s for p, s, _, _ in prepare_rows(out, res)}, {          # genuine head-only context is NOT a row
            "src/a.py": "modified", "src/b.py": "modified", "src/new.py": "added", "src/gone.py": "deleted"})
        self.assertEqual(res.status, "completed")

    def test_control_a_missing_side_modified_is_a_gap_row_not_a_refusal_and_not_an_add_or_delete(self):
        for tag, kw, ctxkw in (("head-omitted", dict(head=False), dict(base={"src/a.py": BASE["src/a.py"], "src/b.py": BASE["src/b.py"]},
                                                                         head={"src/a.py": HEAD["src/a.py"]})),
                               ("base-omitted", dict(base=False), dict(base={"src/a.py": BASE["src/a.py"]},
                                                                         head={"src/a.py": HEAD["src/a.py"], "src/b.py": HEAD["src/b.py"]}))):
            with self.subTest(tag):
                m = self.mini("gap-" + tag, **ctxkw)
                cov = coverage_for(context_head=(), extra={"changedPaths": [changed("src/a.py"), changed("src/b.py", "modified", **kw)]})
                res, out, spy, err = self.go("gap-" + tag, cov, m)
                self.assertIsNone(err)
                self.assertEqual({p: (s, a, d) for p, s, a, d in prepare_rows(out, res)}["src/b.py"], ("modified", 0, 0))
                md = (out / res.run_id / "review.md").read_text()
                self.assertIn("Recorded on one side only", md)
                self.assertIn("`src/b.py`", md)
                detail = json.loads(spy.requests[0]["messages"][1]["content"])["coverageDetail"]
                self.assertEqual([g["path"] for g in detail["oneSidedOrAmbiguous"]], ["src/b.py"])

    def test_control_executable_manifest_entries_validate(self):
        m = self.mini("exe", base=BASE, head={**HEAD, "run.sh": "#!/bin/sh\n"})
        # the Rig writes plain files; mark the head one executable in the pinned manifest through the real manifest builder
        from reviewer.contracts.snapshot import build_manifest
        import os
        p = m.head.root / "run.sh"
        os.chmod(p, 0o755)
        man = build_manifest(m.head.root)
        self.assertIn("executable", {e["type"] for e in man["entries"]})
        # coverage validation accepts file and executable types alike (the type check is the symlink guard)
        cov = coverage_for(context_head=(), extra={"changedPaths": [changed("src/a.py"), changed("src/b.py"), changed("run.sh", "added", base=False)]})
        self.assertEqual(cov_mod.validate(cov, m.base.manifest, man), digest(cov))


# ======================================================================================================================
# C2  one logical path, one entry
# ======================================================================================================================

class C2LogicalPath(Refusal):
    def trees(self, tag):
        return self.mini(tag, base={"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n"},
                         head={"src/a.py": HEAD["src/a.py"], "src/y.py": "X=1\n"})

    def test_rename_source_that_also_has_its_own_entry_is_refused_no_duplicate_rows(self):
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/y.py", "renamed", prev="src/x.py"), changed("src/x.py", "modified", head=False)]})
        self.refused("alias", cov, self.trees("alias"), "'src/x.py' is named by more than one changedPaths entry")

    def test_the_same_name_as_a_rename_target_and_a_rename_source_chain_and_swap_are_refused(self):
        shapes = {
            "chain": ([changed("src/y.py", "renamed", prev="src/x.py"), changed("src/z.py", "renamed", prev="src/y.py")], "src/y.py"),
            "swap": ([changed("src/x.py", "renamed", prev="src/y.py"), changed("src/y.py", "renamed", prev="src/x.py")], "src/x.py"),
            "target-also-listed": ([changed("src/y.py", "renamed", prev="src/x.py"), changed("src/x.py", "removed", head=False)], "src/x.py"),
        }
        m = self.mini("shapes", base={"src/x.py": "X=1\n", "src/y.py": "Y=1\n", "src/a.py": BASE["src/a.py"]},
                      head={"src/y.py": "X=1\n", "src/z.py": "Y=1\n", "src/a.py": HEAD["src/a.py"], "src/x.py": "Y=1\n"})
        for tag, (entries, _) in shapes.items():
            with self.subTest(tag):
                cov = coverage_for(context_head=(), extra={"changedPaths": [changed("src/a.py"), *entries]})
                res, out, spy, err = self.go("s-" + tag, cov, m)
                self.assertIsNotNone(err)
                self.assertEqual((err.code, spy.calls), ("invalid-input", 0))

    def test_control_a_plain_rename_is_one_delete_plus_one_add_and_nothing_else(self):
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/y.py", "renamed", prev="src/x.py")]})
        res, out, spy, err = self.go("plain", cov, self.trees("plain"))
        self.assertIsNone(err)
        rows = prepare_rows(out, res)
        self.assertEqual(sorted((p, s) for p, s, _, _ in rows), [("src/a.py", "modified"), ("src/x.py", "deleted"), ("src/y.py", "added")])
        self.assertEqual(len({p for p, *_ in rows}), len(rows))                       # one row per path

    def test_characterisation_a_copy_whose_source_is_also_modified_is_refused_as_ambiguous(self):
        # fail-closed, over-conservative for git copy detection; the real bridge does not emit `copied` (no occurrence in
        # reviewer/historical). Pinned so nobody reads it as an oversight and nobody loosens it silently.
        m = self.mini("copy", base={"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n"},
                      head={"src/a.py": HEAD["src/a.py"], "src/x.py": "X=2\n", "src/y.py": "X=1\n"})
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/x.py"), changed("src/y.py", "copied", prev="src/x.py", base=False)]})
        self.refused("copy", cov, m, "named by more than one changedPaths entry")


# ======================================================================================================================
# C3  recorded context gaps are disclosed truthfully
# ======================================================================================================================

class C3ContextGap(Refusal):
    def run_gap(self, rec, tag="gap"):
        m = self.mini_partial(tag)
        res, spy = self.record_cov(m, self.basic(m), coverage_for(recorded=rec))
        return res, spy

    def test_statement_review_md_prompt_and_bundle_carry_the_gap(self):
        res, spy = self.run_gap(GAP_1347)
        st = cov_mod.statement(coverage_for(recorded=GAP_1347))
        self.assertIn("Selected context that could NOT be recorded: 1 file(s) (text-not-found)", st)
        self.assertIn("text-not-found", st)
        md = (self.out / res.run_id / "review.md").read_text()
        self.assertIn("- Selected context not recorded: 1 file(s) (text-not-found)", md)
        self.assertIn("- Recorded coverage gaps: text-not-found", md)
        self.assertNotIn("Recorded coverage gaps: none recorded", md)
        inv_req = json.loads(spy.requests[0]["messages"][1]["content"])
        self.assertIn("text-not-found", inv_req["coverage"])
        self.assertEqual(inv_req["coverageDetail"]["gapKinds"], ["text-not-found"])
        self.assertEqual(inv_req["coverageDetail"]["contextGap"], {"kinds": ["text-not-found"], "count": 1, "incomplete": True})
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertEqual(doc["coverage"]["contextGap"], {"kinds": ["text-not-found"], "count": 1, "incomplete": True})
        self.assertEqual(doc["coverage"]["gapKinds"], ["text-not-found"])

    def test_truthful_in_both_directions_nothing_is_invented_and_nothing_is_swallowed(self):
        clean = cov_mod.statement(coverage_for(recorded={"complete": True, "gapKinds": []}))
        self.assertNotIn("could NOT be recorded", clean)
        self.assertNotIn("incomplete", clean)
        absent_keys = cov_mod.statement(coverage_for(recorded={}))
        self.assertNotIn("could NOT be recorded", absent_keys)                       # absent keys say nothing
        self.assertEqual(cov_mod.context_gap(coverage_for(recorded={})), {"kinds": [], "count": None, "incomplete": False})
        res, _ = self.run_gap({"complete": True, "gapKinds": []}, "clean")
        md = (self.out / res.run_id / "review.md").read_text()
        self.assertIn("- Recorded coverage gaps: none recorded", md)
        self.assertIn("- Selected context not recorded: none recorded", md)
        # complete:false with no reason is said out loud rather than read as clean
        silent = cov_mod.statement(coverage_for(recorded={"complete": False, "gapKinds": []}))
        self.assertIn("marked this coverage record incomplete without naming a reason", silent)
        # a count without kinds, and kinds without a count, are both disclosed
        self.assertIn("2 file(s)", cov_mod.statement(coverage_for(recorded={"contextGapCount": 2})))
        self.assertIn("(binary)", cov_mod.statement(coverage_for(recorded={"contextGapKinds": ["binary"]})))
        # a zero count is not a gap; a boolean is not a count
        self.assertNotIn("could NOT be recorded", cov_mod.statement(coverage_for(recorded={"contextGapCount": 0})))
        self.assertNotIn("could NOT be recorded", cov_mod.statement(coverage_for(recorded={"contextGapCount": True})))

    def test_the_per_entry_gap_kinds_union_with_recorded_kinds(self):
        cov = coverage_for(recorded={"gapKinds": ["x-gap"], "contextGapKinds": ["text-not-found"]},
                           extra={"changedPaths": [changed("src/a.py", gaps=("patch-missing",)), changed("src/b.py")]})
        self.assertEqual(cov_mod.gap_kinds(cov), ["patch-missing", "text-not-found", "x-gap"])


# ======================================================================================================================
# C4  comments.json bundle and judge carry the partial scope
# ======================================================================================================================

class C4BundleAndJudge(Refusal):
    def test_judge_request_and_comments_bundle_say_partial(self):
        m = self.mini_partial("c4")
        cov = coverage_for(recorded=GAP_1347)
        res, spy = self.record_cov(m, self.basic(m), cov)
        judge_req = json.loads(spy.requests[-1]["messages"][1]["content"])
        self.assertEqual(judge_req["coverage"], cov_mod.statement(cov))
        self.assertTrue(judge_req["coverage"].startswith("PARTIAL coverage, NOT the whole repository"))
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertEqual(doc["schema"], "review-comments@2")                         # a reader that only knows @1 cannot mistake it
        c = doc["coverage"]
        self.assertEqual((c["partial"], c["fullRepositoryCoverage"], c["scope"]), (True, False, "changed-files-and-selected-context"))
        self.assertEqual(c["coverageDigest"], digest(cov))
        self.assertEqual(c["statement"], cov_mod.statement(cov))
        self.assertEqual((c["changedPathCount"], c["contextPathCount"]), (2, {"base": 0, "head": 1}))
        self.assertEqual(doc["status"], "completed")                                 # status is still the run's own; coverage rides beside it
        self.assertEqual(sorted(doc["comments"][0]), sorted(res.comments[0]))        # Comment entities untouched

    def test_a_partial_run_that_is_not_completed_still_carries_the_scope(self):
        m = self.mini_partial("c4p")
        scr = script(inv(hyp(m, "src/a.py", 2)), ver(0, m, path="src/a.py", line=2))   # judge unavailable
        res, spy = self.record_cov(m, scr, coverage_for())
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertNotEqual(res.status, "completed")
        self.assertEqual((doc["schema"], doc["coverage"]["partial"]), ("review-comments@2", True))
        self.assertEqual(doc, json.loads((self.out / load_result(self.out, res.run_id).run_id / "comments.json").read_text()))

    def test_control_full_view_judge_request_and_bundle_are_unchanged(self):
        m = self.mini()
        res, spy = self.record(m, self.basic(m))
        self.assertNotIn("coverage", json.loads(spy.requests[-1]["messages"][1]["content"]))
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertEqual((doc["schema"], "coverage" in doc), ("review-comments@1", False))
        self.assertEqual(sorted(doc), ["comments", "headSnapshotId", "runId", "schema", "state", "status"])

    def test_the_partial_bundle_is_bound_to_the_receipt_edit_is_refused_on_load(self):
        m = self.mini_partial("c4t")
        res, _ = self.record_cov(m, self.basic(m), coverage_for())
        p = self.out / res.run_id / "comments.json"
        doc = json.loads(p.read_text())
        doc["coverage"]["fullRepositoryCoverage"] = True                             # someone launders the scope
        p.write_text(json.dumps(doc, sort_keys=True, separators=(",", ":")))
        with self.assertRaises(PipelineError) as cm:
            load_result(self.out, res.run_id)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")


# ======================================================================================================================
# T1 (pipeline side) and the tools API limit
# ======================================================================================================================

class T1CrossSideKind(Refusal):
    def test_pipeline_refuses_both_conflicting_shapes_before_a_provider_call(self):
        m = self.both_sides("t1")
        base_ctx_head_changed = coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "modified")]})
        base_changed_head_ctx = coverage_for(context_head=("src/p.py",), context_base=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "modified")]})
        for tag, cov in (("base-ctx", base_ctx_head_changed), ("head-ctx", base_changed_head_ctx)):
            with self.subTest(tag):
                res, out, spy, err = self.go(tag, cov, m)
                self.assertIsNotNone(err)
                self.assertEqual((err.code, spy.calls, list(out.iterdir())), ("invalid-input", 0, []))
                self.assertIn("src/p.py", str(err))

    def test_build_view_has_its_own_guard_for_a_direct_caller(self):
        m = self.both_sides("t1b")
        cov = coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py")]})           # p.py: base context, and head holds it too but unclassified as changed
        cov["changedPaths"].append(changed("src/p.py", "added", base=False))
        with self.assertRaises(PipelineError) as cm:
            cov_mod.build_view(cov, m.base, m.head)
        self.assertEqual(cm.exception.code, "invalid-input")
        self.assertIn("changed on one side and only context on the other", str(cm.exception))

    def test_the_tools_api_itself_now_refuses_the_conflict_and_still_builds_the_legitimate_shape(self):
        # S1-04 closed T1 in the tools layer (View.__init__); the pipeline guards above stay as defence in depth. Direct API, no pipeline.
        import tempfile
        from pathlib import Path

        from reviewer.contracts.snapshot import build_manifest
        from reviewer.tools import ToolSession, ViewError, partial_union_view
        from tests.tools.helpers import write_tree

        with tempfile.TemporaryDirectory() as t:
            def tree(name, files):
                root = Path(t) / name
                root.mkdir()
                write_tree(root, files)
                return root, build_manifest(root)

            def view(base_ctx, head_ctx, head_body):
                rb, mb = tree(f"b{len(base_ctx)}{len(head_ctx)}{head_body[2]}", {"a.py": "A=1\n", "p.py": "P=1\n"})
                rh, mh = tree(f"h{len(base_ctx)}{len(head_ctx)}{head_body[2]}", {"a.py": "A=2\n", "p.py": head_body})
                return partial_union_view((rb, mb, base_ctx, {"a.py"} | ({"p.py"} - base_ctx)),
                                          (rh, mh, head_ctx, {"a.py"} | ({"p.py"} - head_ctx)))

            for base_ctx, head_ctx, body in (({"p.py"}, set(), "P=2\n"), (set(), {"p.py"}, "P=2\n")):
                with self.assertRaisesRegex(ViewError, r"1 path\(s\) are classified differently"):
                    view(base_ctx, head_ctx, body)
            rows = ToolSession(view({"p.py"}, {"p.py"}, "P=1\n")).call("diff", {}).result["evidence"][0]["excerpt"].split("\n")[1:]
            self.assertEqual(rows, ["M a.py"])                          # context on both sides: built, and p.py is neither added nor deleted


# ======================================================================================================================
# identity
# ======================================================================================================================

class Identity(Refusal):
    def test_partial_behavior_is_bound_only_with_coverage_and_a_bump_moves_only_partial_ids(self):
        m = self.mini_partial("id")
        cov = coverage_for()
        res, _ = self.record_cov(m, self.basic(m), cov)
        full_m = self.mini("id-full")
        full, _ = self.record(full_m, self.basic(full_m))
        orig = identity.PARTIAL_BEHAVIOR
        self.addCleanup(setattr, identity, "PARTIAL_BEHAVIOR", orig)
        spec_p = self.spec(m, self.record_backend(self.basic(m))[0], coverage=cov)
        spec_f = self.spec(full_m, self.record_backend(self.basic(full_m))[0])
        before_p, before_f = identity.config_snapshot_id(spec_p), identity.config_snapshot_id(spec_f)
        identity.PARTIAL_BEHAVIOR = "partial-disclosure@next"
        self.assertNotEqual(identity.config_snapshot_id(spec_p), before_p)
        self.assertEqual(identity.config_snapshot_id(spec_f), before_f)
        self.assertIn(res.run["configSnapshotId"], (before_p,))
        self.assertNotIn("coverageDigest", full.receipt)

    def test_a_valid_coverage_digest_is_unchanged_by_the_new_validation(self):
        # the patch adds refusals, not a different digest for records that were already valid
        cov = coverage_for()
        m = self.mini_partial("dig")
        self.assertEqual(cov_mod.validate(cov, m.base.manifest, m.head.manifest), digest(cov))
        res, _ = self.record_cov(m, self.basic(m), cov)
        self.assertEqual(res.receipt["coverageDigest"], digest(cov))

    def test_replay_of_a_gap_carrying_record_reproduces_outputs_byte_for_byte(self):
        m = self.mini_partial("rp")
        cov = coverage_for(recorded=GAP_1347)
        res, _ = self.record_cov(m, self.basic(m), cov)
        rep = run_review(self.spec(m, self.replay_backend(res), coverage=cov, eval_id=EVR2))
        self.assertNotEqual(res.run_id, rep.run_id)                                  # a replay is its own run (other eval id)
        self.assertEqual((self.out / res.run_id / "coverage.json").read_bytes(), (self.out / rep.run_id / "coverage.json").read_bytes())
        def norm(run, name):                  # only the run id and the cost-basis line (synthetic vs replayed) may differ
            t = (self.out / run.run_id / name).read_text().replace(run.run_id, "RUN")
            return [l for l in t.splitlines() if "model-call cost record" not in l]
        for name in ("comments.json", "review.md"):
            self.assertEqual(norm(res, name), norm(rep, name), name)
        other = copy.deepcopy(cov)
        other["recorded"]["contextGapCount"] = 2                                    # gap disclosure is identity-bound
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, self.replay_backend(res), coverage=other, eval_id="evr_" + "7" * 16))
        self.assertEqual(cm.exception.code, "identity-mismatch")


if __name__ == "__main__":
    unittest.main()
