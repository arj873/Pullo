"""S0-09b independent review of the partial-coverage chain: tools `partial_union_view` (S0B-02c) -> pipeline coverage (S0B-02b).

Run (repo root; not collected by `discover -s tests -t .`, no __init__.py):

    nice -n 19 python3 -m unittest discover -s tests/partial_review

Scope (bounded, no fuzz and no mutation campaign; the authors' own 19 + 14 + original controls are the baseline and are not repeated):
  A. tools seam: partition of changed/context across the TWO sides, post-construction tamper kinds the author did not drive
     (deleted file, symlink swap), and how search/list_files label context.
  B. pipeline coverage: flags vs the pinned union manifests, colliding rename sources, disclosure of recorded gaps, partial-ness of the
     machine-readable output and the judge prompt, host fields that must never reach a model, digest / idempotence / replay identity.
  C. the real corpus case Vencord--Vesktop--1347 through temporary trusted test pins, the real bridge and a scripted (fake) provider.

S0-09c: C1 C2 C3 C4 were fixed by S0-07c-fix (frozen coverage 70427d312054, engine e5e21048a9b0, identity 8385f04e2e19, prompts a0b8aaf8761c,
render 0abb2dbf6136); their five DEFECT tests lost the marker and became test_fixed_*, the three obsolete symptom tests were removed; the reason
checks are in test_final_corrections_review.py. T1 on the direct tools API was fixed by S1-04 (View.__init__ refuses a cross-side classification
conflict); its xfail was retired by the S1-04 independent gate (tests/tools_review/test_s104_retrieval_gate.py holds the broader T1 matrix).

Conventions as S0-09: a DEFECT is held by an `expectedFailure` test stating the DESIRED behaviour plus a `*_symptom_*` test that pins what
happens today (delete both when the owner fixes it); `test_characterisation_*` pins a design choice a reader might mistake for a hole.
Everything runs the real contracts/tools/pipeline/gateway (synthetic provider). No network, key, private store, agent or target code.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.canonical import digest
from reviewer.contracts.snapshot import build_manifest
from reviewer.pipeline import PipelineError, ReviewSpec, load_result, run_review
from reviewer.pipeline import coverage as cov_mod
from reviewer.tools import ToolSession, ViewError, partial_union_view

from tests.pipeline.helpers import BASE, HEAD, EVR2, PLAN, PROFILE, hid, hyp, inv, judge, script, ver
from tests.pipeline.test_coverage import CTX, Partial, changed, coverage_for
from tests.tools.helpers import write_tree

ROOT = Path(__file__).resolve().parents[2]


def prepare_rows(out: Path, res):
    art = json.loads((out / res.run_id / "artifacts" / "02-PREPARE.v1.json").read_text())["payload"]["files"]
    return [(f["path"], f["status"], f["additions"], f["deletions"]) for f in art]


# ======================================================================================================================
# A. tools seam
# ======================================================================================================================

class UnionPartition(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.t = Path(self._t.name)

    def tree(self, name, files):
        self.n = getattr(self, "n", 0) + 1
        root = self.t / f"{name}{self.n}"
        root.mkdir(parents=True)
        write_tree(root, files)
        return root, build_manifest(root)

    def rows(self, view):
        r = ToolSession(view).call("diff", {}).result
        return r["evidence"][0]["excerpt"].split("\n")[1:]

    def conflict_view(self, *, base_ctx, head_ctx, base_body="P=1\n", head_body="P=1\n"):
        rb, mb = self.tree("b", {"a.py": "A=1\n", "p.py": base_body})
        rh, mh = self.tree("h", {"a.py": "A=2\n", "p.py": head_body})
        return partial_union_view((rb, mb, base_ctx, {"a.py"} | ({"p.py"} - base_ctx)),
                                  (rh, mh, head_ctx, {"a.py"} | ({"p.py"} - head_ctx)))

    def test_control_a_shared_path_with_the_same_kind_on_both_sides_is_never_a_false_add_or_delete(self):
        for ctx in (set(), {"p.py"}):
            with self.subTest(context_on_both_sides=bool(ctx)):
                v = self.conflict_view(base_ctx=ctx, head_ctx=ctx, head_body="P=2\n")
                rows = self.rows(v)
                self.assertNotIn("A p.py", rows)
                self.assertNotIn("D p.py", rows)
                self.assertEqual(("M p.py" in rows), not ctx)             # changed on both sides => M; context on both => absent

    def test_historical_symptom_t1_conflicting_context_and_changed_kinds_were_accepted_as_added_or_deleted_and_are_now_refused(self):
        # S0-09b T1 repro, kept as evidence: before S1-04 these two views BUILT and diff listed the shared path as "A p.py" / "D p.py"
        # (while `diff p.py` said "identical"). The tools layer now refuses them at construction, for the contradiction itself.
        for tag, kw in (("base ctx / head changed", dict(base_ctx={"p.py"}, head_ctx=set())),
                        ("base changed / head ctx", dict(base_ctx=set(), head_ctx={"p.py"}, head_body="P=2\n"))):
            with self.subTest(tag):
                with self.assertRaises(ViewError) as cm:
                    self.conflict_view(**kw)
                self.assertIn("classified differently on the two sides", str(cm.exception))
                self.assertNotIn("p.py", str(cm.exception))                     # a count and kinds only, never a path

    def test_fixed_a_path_present_on_both_sides_with_conflicting_kinds_is_refused_and_never_added_or_deleted(self):
        for tag, kw in (("base ctx / head changed", dict(base_ctx={"p.py"}, head_ctx=set())),
                        ("base changed / head ctx", dict(base_ctx=set(), head_ctx={"p.py"}, head_body="P=2\n"))):
            with self.subTest(tag):
                with self.assertRaisesRegex(ViewError, r"1 path\(s\) are classified differently"):
                    v = self.conflict_view(**kw)                                # refused at construction ...
                    self.rows(v)                                                # ... so no view exists to list A/D rows from
        # the neighbouring legitimate shapes still build, with the shared path never added/deleted (positive control for the refusal above)
        for ctx in (set(), {"p.py"}):
            self.assertFalse({"A p.py", "D p.py"} & set(self.rows(self.conflict_view(base_ctx=ctx, head_ctx=ctx, head_body="P=2\n" if not ctx else "P=1\n"))))

    def test_a_context_file_deleted_or_swapped_for_a_symlink_after_construction_is_tamper_for_read_and_search(self):
        rb, mb = self.tree("b", {"a.py": "A=1\n", "c.py": "NEEDLE=1\n"})
        rh, mh = self.tree("h", {"a.py": "A=2\n", "c.py": "NEEDLE=1\n", "d.py": "NEEDLE=2\n"})
        v = partial_union_view((rb, mb, {"c.py"}, {"a.py"}), (rh, mh, {"c.py", "d.py"}, {"a.py"}))
        os.remove(rh / "d.py")                                                  # deleted context file
        os.remove(rh / "c.py")
        os.symlink(rh / "a.py", rh / "c.py")                                    # swapped for a link to a (valid-looking) file
        for path in ("d.py", "c.py"):
            s = ToolSession(v)
            r = s.call("read_file", {"side": "head", "path": path}).result
            self.assertEqual((r["status"], r["evidence"], s.tampered), ("error", [], True), path)
            self.assertIn("no longer matches its pinned snapshot", r["notice"])
        s = ToolSession(v)
        r = s.call("search_literal", {"side": "head", "query": "NEEDLE"}).result
        self.assertTrue(s.tampered)
        self.assertEqual(r["evidence"], [])                                     # nothing from either damaged file is quoted
        self.assertIn("failed pinned-snapshot verification", r["notice"])

    def test_characterisation_search_and_list_files_do_not_mark_context_only_read_file_does(self):
        # LOW observation: the model can only tell context from change through diff / read_file / the coverage statement.
        rb, mb = self.tree("b", {"a.py": "NEEDLE\n"})
        rh, mh = self.tree("h", {"a.py": "NEEDLE 2\n", "ctx.py": "NEEDLE ctx\n"})
        v = partial_union_view((rb, mb, set(), {"a.py"}), (rh, mh, {"ctx.py"}, {"a.py"}))
        s = ToolSession(v)
        self.assertIn("[context]", s.call("read_file", {"side": "head", "path": "ctx.py"}).result["notice"])
        hit = s.call("search_literal", {"side": "head", "query": "NEEDLE"}).result
        self.assertEqual(sorted(e["path"] for e in hit["evidence"]), ["a.py", "ctx.py"])
        self.assertNotIn("context", json.dumps(hit["evidence"]).lower())
        listing = s.call("list_files", {"side": "head"}).result["evidence"][0]["excerpt"]
        self.assertIn("ctx.py", listing)
        self.assertNotIn("[context]", listing)


# ======================================================================================================================
# B. pipeline coverage
# ======================================================================================================================

class Contradictions(Partial):
    def go(self, tag, cov, m, **kw):
        out = self.tmp / ("o-" + tag)
        out.mkdir()
        backend, spy = self.record_backend(script(inv()))
        try:
            res = run_review(self.spec(m, backend, coverage=cov, out_root=out, **kw))
        except PipelineError as e:
            return None, out, spy, e
        return res, out, spy, None

    def both_sides(self):
        return self.mini("both", base={**BASE, "src/p.py": "P=1\n"}, head={**HEAD, "src/p.py": "P=1\n"})

    def added_but_in_base_context(self):
        return coverage_for(context_head=(), context_base=("src/p.py",), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "added", base=False, head=True)]})

    def removed_but_in_head_context(self):
        return coverage_for(context_head=("src/p.py",), context_base=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/p.py", "removed", base=True, head=False)]})

    def test_control_a_truthful_add_and_delete_are_reported_as_such(self):
        m = self.mini("truth", base={**BASE, "src/gone.py": "G=1\n"}, head={**HEAD, "src/new.py": "N=1\n"})
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/new.py", "added", base=False),
            changed("src/gone.py", "removed", head=False)]})
        res, out, _, err = self.go("truth", cov, m)
        self.assertIsNone(err)
        self.assertEqual({p: s for p, s, _, _ in prepare_rows(out, res)}, {
            "src/a.py": "modified", "src/b.py": "modified", "src/new.py": "added", "src/gone.py": "deleted"})

    def test_fixed_a_flag_that_says_a_side_is_absent_must_not_coexist_with_the_path_in_that_side_s_pinned_manifest(self):
        m = self.both_sides()
        for tag, cov in (("add", self.added_but_in_base_context()), ("rem", self.removed_but_in_head_context())):
            with self.subTest(tag):
                res, out, spy, err = self.go("d-" + tag, cov, m)
                self.assertIsNotNone(err, "a real add/delete was reported for a file the pinned union holds on both sides")
                self.assertEqual((err.code, spy.calls), ("invalid-input", 0))

    def test_fixed_one_path_must_not_get_two_PREPARE_rows_with_different_statuses(self):
        base = {"src/a.py": BASE["src/a.py"], "src/x.py": "X=1\n"}
        head = {"src/a.py": HEAD["src/a.py"], "src/y.py": "X=1\n"}
        m = self.mini("coll2", base=base, head=head)
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/y.py", "renamed", prev="src/x.py"), changed("src/x.py", "modified", head=False)]})
        res, out, _, err = self.go("coll2", cov, m)
        if err is not None:
            return                                                       # refusing the inconsistent record is acceptable
        self.assertEqual(len([p for p, *_ in prepare_rows(out, res) if p == "src/x.py"]), 1)

    def test_one_sided_modified_on_either_side_stays_modified_with_zero_counts_and_is_disclosed(self):
        # the pipeline owner's addendum, driven from the other direction: BASE omitted (head-only 'modified') and a
        # 'modified' entry that carries a previousPath. Neither may read as a real add; the base-omitted one must not
        # be adopted from the diff tool's own manifest-delta listing either.
        m = self.mini("gaps", base={"src/a.py": BASE["src/a.py"]}, head={**HEAD, "src/b.py": HEAD["src/b.py"]})
        cov = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py", "modified", base=False)]})
        res, out, spy, err = self.go("gaps", cov, m)
        self.assertIsNone(err)
        rows = {p: (s, a, d) for p, s, a, d in prepare_rows(out, res)}
        self.assertEqual(rows["src/b.py"], ("modified", 0, 0))
        md = (out / res.run_id / "review.md").read_text()
        self.assertIn("Recorded on one side only", md)
        self.assertIn("`src/b.py`", md)
        m2 = self.mini("gaps2", base={**BASE, "src/old.py": "O=1\n", "src/new.py": "N=1\n"}, head=HEAD)
        cov2 = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed("src/old.py", "modified", head=False, prev="src/new.py")]})
        res2, out2, _, err2 = self.go("gaps3", cov2, m2)                 # previousPath on a plain 'modified' is ambiguous => gap
        if err2 is None:
            self.assertEqual({p: s for p, s, _, _ in prepare_rows(out2, res2)}["src/old.py"], "modified")
        else:
            self.assertEqual(err2.code, "invalid-input")                  # refusing is equally honest; a real add/delete is not

    # ---- disclosure: what the models and the readers are told
    def test_control_prompts_and_review_are_explicitly_partial_in_investigator_and_verifier(self):
        m = self.mini_partial("disc")
        res, spy = self.record_cov(m, self.basic(m), coverage_for())
        text = [json.dumps(r["messages"][1]["content"]) for r in spy.requests]
        for i in (0, 1):
            self.assertIn("PARTIAL coverage", text[i])
            self.assertNotIn("Two full pinned snapshots", text[i])
        self.assertIn("not a full-repository review", (self.out / res.run_id / "review.md").read_text())

    def test_fixed_the_judge_prompt_and_comments_json_also_say_the_review_is_partial(self):
        m = self.mini_partial("disc2")
        res, spy = self.record_cov(m, self.basic(m), coverage_for())
        self.assertIn("PARTIAL", json.dumps(spy.requests[-1]["messages"][1]["content"]))       # judge writes the user-visible wording
        doc = json.loads((self.out / res.run_id / "comments.json").read_text())
        self.assertIs(doc.get("coverage", {}).get("fullRepositoryCoverage"), False)             # a sink that reads only this file

    def test_fixed_the_recorded_context_gap_of_the_real_vesktop_1347_record_is_not_dropped_from_the_statement(self):
        # recorded.complete is False and contextGapKinds names a selected context file that was NOT recorded. These are the
        # exact keys the real bridge emits for 1347.
        rec = {"complete": False, "gapKinds": [], "contextGapKinds": ["text-not-found"], "contextGapCount": 1,
               "changedFilesExpected": 3, "changedFilesListed": 3, "changedFilesRecorded": 3}
        text = cov_mod.statement(coverage_for(recorded=rec))
        self.assertIn("text-not-found", text)

    # ---- host fields must never reach a model
    def test_corpus_labels_source_and_host_paths_in_the_coverage_record_never_reach_a_model_request(self):
        marks = ("LABELMARK-7f3", "SOURCEMARK-7f3", "EXPECTMARK-7f3", "NOTEMARK-7f3", "PINSMARK-7f3")
        rec = {"complete": True, "gapKinds": [], "labels": marks[0], "source": marks[1], "expectedFindings": [marks[2]]}
        cov = coverage_for(recorded=rec, extra={"note": marks[3], "pinsDigest": "sha256:" + "ab" * 32})
        cov["recorded"]["origin"] = marks[4]
        m = self.mini_partial("leak")
        res, spy = self.record_cov(m, self.basic(m), cov)
        self.assertEqual(res.status, "completed")
        blob = json.dumps(spy.requests)
        for mark in marks:
            self.assertNotIn(mark, blob)
        self.assertNotIn(str(self.tmp), blob)                           # no host path
        self.assertNotIn("sha256:" + "ab" * 32, blob)
        # ... but the same fields are not silently discarded: they are digest-bound host data
        self.assertEqual(res.receipt["coverageDigest"], digest(cov))
        self.assertIn(marks[0], (self.out / res.run_id / "coverage.json").read_text())

    # ---- digest / idempotence / replay identity
    def test_a_partition_difference_over_identical_bytes_changes_run_identity_and_what_may_be_cited(self):
        m = self.mini_partial("ident")
        as_context = coverage_for()
        as_added = coverage_for(context_head=(), extra={"changedPaths": [
            changed("src/a.py"), changed("src/b.py"), changed(CTX, "added", base=False)]})
        r1, spy1 = self.record_cov(m, self.basic(m), as_context)
        keep = hyp(m, CTX, 1, claim="in the file that is now a change")
        other = self.tmp / "out2"
        other.mkdir()
        r2, spy2 = self.record_cov(m, script(inv(keep), ver(0, m, path=CTX, line=1),
                                             judge({"findingIds": [hid(0, keep)], "title": "T", "body": "B"})),
                                   as_added, out_root=other)                         # SAME eval id and snapshots: only coverage differs
        # the run id comes from the eval identity, the partition is bound through configSnapshotId and the output directory
        self.assertEqual(r1.run_id, r2.run_id)
        self.assertNotEqual(r1.run["configSnapshotId"], r2.run["configSnapshotId"])
        self.assertNotEqual(r1.receipt["coverageDigest"], r2.receipt["coverageDigest"])
        backend, _ = self.record_backend(self.basic(m))
        with self.assertRaises(PipelineError) as cm:                                  # same run directory, other partition
            run_review(self.spec(m, backend, coverage=as_added))
        self.assertEqual(cm.exception.code, "identity-mismatch")
        self.assertNotIn(CTX, [p for p, *_ in prepare_rows(self.out, r1)])
        self.assertIn((CTX, "added", 1, 0), prepare_rows(other, r2))
        self.assertEqual([c["anchor"]["path"] for c in r2.comments], [CTX])         # citable only because the host SAID it is changed

    def test_canonical_key_order_does_not_change_identity_but_list_order_does(self):
        m = self.mini_partial("order")
        cov = coverage_for()
        res, _ = self.record_cov(m, self.basic(m), cov)
        shuffled = json.loads(json.dumps(cov, sort_keys=True))               # same content, different key order
        again, spy = self.record_cov(m, self.basic(m), dict(reversed(list(shuffled.items()))))
        self.assertEqual((again.run_id, again.idempotent, spy.calls), (res.run_id, True, 0))
        reordered = copy.deepcopy(cov)
        reordered["changedPaths"].reverse()
        self.assertNotEqual(digest(reordered), digest(cov))                  # characterisation: order is identity, conservatively
        with self.assertRaises(PipelineError) as cm:
            run_review(self.spec(m, self.replay_backend(res), coverage=reordered, eval_id="evr_" + "9" * 16))
        self.assertEqual(cm.exception.code, "identity-mismatch")

    def test_a_recorded_partial_run_replays_to_the_same_outputs_and_the_coverage_file_is_byte_identical(self):
        m = self.mini_partial("replay")
        cov = coverage_for()
        res, _ = self.record_cov(m, self.basic(m), cov)
        rep = run_review(self.spec(m, self.replay_backend(res), coverage=cov, eval_id=EVR2))
        self.assertEqual((rep.status, [c["findingIds"] for c in rep.comments]), (res.status, [c["findingIds"] for c in res.comments]))
        self.assertEqual((self.out / res.run_id / "coverage.json").read_bytes(), (self.out / rep.run_id / "coverage.json").read_bytes())
        self.assertEqual(load_result(self.out, rep.run_id).receipt["coverageDigest"], digest(cov))


# ======================================================================================================================
# C. real corpus case Vencord--Vesktop--1347, temporary trusted pins, fake provider
# ======================================================================================================================

CASE_1347 = ROOT / "fixtures" / "historical" / "Vencord--Vesktop--1347"


@unittest.skipUnless(CASE_1347.is_dir(), "corpus case not present")
class Vesktop1347(Partial):
    """Gate: the bridge F1-F6 + D2 view() fix is handed off (S0B-02a-fix.md, status ready-for-review) but NOT independently accepted;
    tests/historical_review is not yet adapted. This exercises it as a consumer; it is not an acceptance of the bridge.
    Pins are TEMPORARY and trusted-by-the-test (captured here with a fixed time); they are not the operator's pin store."""

    def setUp(self):
        super().setUp()
        from reviewer.historical import capture_bridge_pins, materialize
        pins = capture_bridge_pins(CASE_1347, captured_at="2026-10-25T20:00:00Z")
        self.b = materialize(CASE_1347, pins=pins, out_dir=self.tmp / "bridge", forbidden_roots=(ROOT / "fixtures",))
        self.cov = self.b.record["coverage"]
        self.head_id = self.b.case["head"]["snapshotId"]

    def cite(self, path, a, b=None):
        lines = (Path(self.b.head.root) / path).read_text().split("\n")
        return {"kind": "code", "path": path, "lines": [a, b or a], "commit": self.head_id, "excerpt": "\n".join(lines[a - 1:b or a])}

    def line_of(self, path):
        for n, l in enumerate((Path(self.b.head.root) / path).read_text().split("\n"), 1):
            if len(l.strip()) > 12 and not l.strip().startswith(("//", "*", "/*", "import")):
                return n

    def hypothesis(self, path, claim):
        n = self.line_of(path)
        return {"claim": claim, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
                "location": {"path": path, "line": n}, "mechanism": "scripted", "evidence": [self.cite(path, n)]}

    def run_(self, scr, **kw):
        backend, spy = self.record_backend(scr)
        host = self.host(self.b.case["id"], **kw)
        spec = ReviewSpec(case=self.b.case, base=self.b.base, head=self.b.head, profile=PROFILE, plan=PLAN, host=host,
                          backend=backend, coverage=self.cov)
        return run_review(spec), spy

    def test_the_real_record_has_the_shape_the_review_depends_on(self):
        self.assertEqual(self.cov["fullRepositoryCoverage"], False)
        self.assertEqual([(e["path"], e["status"], e["base"], e["head"]) for e in self.cov["changedPaths"]], [
            ("src/main/mainWindow.ts", "modified", True, True), ("src/main/utils/popout.ts", "modified", True, True),
            ("src/renderer/patches/windowsTitleBar.tsx", "modified", True, True)])
        self.assertEqual(self.cov["contextPaths"], {"base": [], "head": ["src/main/settings.ts", "src/renderer/utils.ts"]})
        self.assertEqual(self.b.case["synthetic"], False)

    def test_head_only_context_is_never_a_change_a_context_candidate_is_dropped_and_a_changed_one_gets_a_comment(self):
        ch = self.hypothesis("src/main/mainWindow.ts", "claim in a changed file")
        cx = self.hypothesis("src/main/settings.ts", "claim in a head-only context file")
        res, spy = self.run_(script(inv(ch, cx), ver(0, evidence=[self.cite("src/main/mainWindow.ts", ch["location"]["line"]),
                                                                   self.cite("src/renderer/utils.ts", self.line_of("src/renderer/utils.ts"))]),
                                    judge({"findingIds": [hid(0, ch)], "title": "T", "body": "B"})))
        self.assertEqual(res.status, "completed")
        self.assertEqual([p for p, *_ in prepare_rows(self.out, res)],
                         ["src/main/mainWindow.ts", "src/main/utils/popout.ts", "src/renderer/patches/windowsTitleBar.tsx"])
        self.assertEqual({s for _, s, _, _ in prepare_rows(self.out, res)}, {"modified"})        # no A for the two context files
        self.assertEqual([c["anchor"]["path"] for c in res.comments], ["src/main/mainWindow.ts"])
        self.assertEqual([(d["reason"], d["subjectIds"]) for d in res.drops], [("invalid-citation", [hid(1, cx)])])
        self.assertEqual(spy.calls, 3)                                  # investigator, ONE verifier (not for the context file), judge
        self.assertEqual(len(res.findings[0]["verification"]["evidence"]), 2)       # the cross-file context proof survives

    def test_the_model_payload_is_partial_has_no_corpus_source_or_labels_and_no_host_path(self):
        ch = self.hypothesis("src/main/mainWindow.ts", "claim")
        res, spy = self.run_(script(inv(ch), ver(0, evidence=[self.cite("src/main/mainWindow.ts", ch["location"]["line"])]),
                                    judge({"findingIds": [hid(0, ch)], "title": "T", "body": "B"})))
        blob = json.dumps(spy.requests)
        self.assertIn("PARTIAL coverage", blob)
        self.assertNotIn("Two full pinned snapshots", blob)
        for forbidden in (str(self.tmp), str(ROOT), "fixtures/historical", "labels", "/source/", "caseInputDigest", "pinsDigest"):
            self.assertNotIn(forbidden, blob, forbidden)
        md = (self.out / res.run_id / "review.md").read_text()
        self.assertIn("## Coverage (partial)", md)
        self.assertIn("not a full-repository review", md)

    def test_the_run_is_idempotent_replays_and_binds_the_coverage_digest(self):
        ch = self.hypothesis("src/main/mainWindow.ts", "claim")
        scr = script(inv(ch), ver(0, evidence=[self.cite("src/main/mainWindow.ts", ch["location"]["line"])]),
                     judge({"findingIds": [hid(0, ch)], "title": "T", "body": "B"}))
        res, _ = self.run_(scr)
        self.assertEqual(res.receipt["coverageDigest"], digest(self.cov))
        again, spy = self.run_(scr)
        self.assertEqual((again.idempotent, spy.calls, again.run_id), (True, 0, res.run_id))
        backend = self.replay_backend(res)
        rep = run_review(ReviewSpec(case=self.b.case, base=self.b.base, head=self.b.head, profile=PROFILE, plan=PLAN,
                                    host=self.host(self.b.case["id"], eval_id=EVR2), backend=backend, coverage=self.cov))
        self.assertEqual((rep.status, [c["findingIds"] for c in rep.comments]), ("completed", [[hid(0, ch)]]))

    def test_fixed_the_recorded_context_gap_of_1347_is_disclosed_in_the_statement_and_review_md(self):
        ch = self.hypothesis("src/main/mainWindow.ts", "claim")
        res, spy = self.run_(script(inv(ch), ver(0, evidence=[self.cite("src/main/mainWindow.ts", ch["location"]["line"])]),
                                    judge({"findingIds": [hid(0, ch)], "title": "T", "body": "B"})))
        md = (self.out / res.run_id / "review.md").read_text()
        # The gap does reach readers and models through the tool notices ("1 selected context file(s) were not recorded
        # (text-not-found)", see the bullets under "What was inspected"), but the Coverage section's own gap line contradicts it.
        line = next(l for l in md.splitlines() if l.startswith("- Recorded coverage gaps:"))
        self.assertIn("text-not-found", line)                                   # reads "none recorded" today
        detail = json.loads(spy.requests[0]["messages"][1]["content"])["coverageDetail"]
        self.assertIn("text-not-found", json.dumps(detail["gapKinds"]))         # [] today


if __name__ == "__main__":
    unittest.main()
