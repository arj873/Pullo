"""S0-09b independent attacks on the S0-07b corrections (N1 N2 N3 N4 N5 N8) of reviewer/pipeline.

Run (repo root; not collected by `discover -s tests -t .` because this directory has no __init__.py):

    nice -n 19 python3 -m unittest discover -s tests/integration_review

Method. The original S0-09 tests only show that the OLD symptom is gone. These tests ask whether each fix works for the intended
reason and does not trade one loss for another: every test states the reason (drop reason/detail, nothing written, no provider
call) and almost every one has a neighbouring control that must still behave. Residual problems found here are held by
`expectedFailure` with the DESIRED behaviour and are listed LOW in S0-09b-review.md. A `test_characterisation_*` test pins a
documented design choice that a reader might mistake for a hole.

Same rig as S0-09: the pipeline test rig (tests/pipeline/helpers.py) is read only; real gateway (synthetic provider), tools,
contracts and pipeline; no network, no target code, no key.
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest import mock

import reviewer.pipeline.engine as engine
from reviewer.pipeline import Hooks, PipelineError, load_result
from reviewer.tools import Limits

from tests.integration_review.test_integration_review import Base, Crash, w
from tests.pipeline.helpers import BASE, HEAD, entry, hid, hyp, inv, judge, model_calls, script, terr, ver


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rewrite_receipt(rd: Path, **outputs):
    rc = json.loads((rd / "receipt.json").read_text())
    rc["outputs"].update(outputs)
    (rd / "receipt.json").write_text(json.dumps(rc, sort_keys=True, indent=2) + "\n")


# ======================================================================================================================
# N1: outputs are re-rendered from the judged artifacts
# ======================================================================================================================

class OutputBinding(Base):
    def setUp(self):
        super().setUp()
        self.m = self.mini()
        self.h = hyp(self.m, "src/a.py", 2)
        self.scr = script(inv(self.h), ver(0, self.m, path="src/a.py", line=2),
                          judge(w([hid(0, self.h)], "Real title", "Real body")))
        self.rec, _ = self.record(self.m, self.scr)
        self.rd = Path(self.rec.run_dir)

    def fresh_out(self, name):
        p = self.tmp / name
        p.mkdir()
        return p

    def crash_after_publish(self, out):
        def boom(stage, _):
            if stage == "PUBLISH":
                raise Crash()
        with self.assertRaises(Crash):
            self.replay(self.m, self.rec, out=out, hooks=Hooks(after_checkpoint=boom))
        [rd] = list(out.iterdir())
        return rd

    def test_control_a_completed_run_reloads_and_its_idempotent_reinvocation_makes_no_provider_call(self):
        self.assertEqual(load_result(self.out, self.rec.run_id).comments[0]["title"], "Real title")
        again, spy = self.record(self.m, self.scr)
        self.assertEqual((again.idempotent, spy.calls), (True, 0))

    def test_review_md_alone_edited_with_a_consistent_receipt_is_refused(self):
        # comments.json is the file the original N1 tests forged; review.md is bound the same way
        data = b"# FORGED REVIEW\n"
        (self.rd / "review.md").write_bytes(data)
        rewrite_receipt(self.rd, **{"review.md": sha(data)})
        for call in (lambda: load_result(self.out, self.rec.run_id), lambda: self.record(self.m, self.scr)):
            with self.assertRaises(PipelineError) as cm:
                call()
            self.assertEqual(cm.exception.code, "checkpoint-invalid")
            self.assertIn("review.md", cm.exception.message)

    def test_a_deleted_output_is_refused_on_load_not_re_adopted(self):
        os.remove(self.rd / "comments.json")
        with self.assertRaises(PipelineError) as cm:
            load_result(self.out, self.rec.run_id)
        self.assertEqual(cm.exception.code, "checkpoint-invalid")

    def test_resume_after_publish_refuses_a_deleted_or_review_md_only_edit(self):
        for tag, damage in (("deleted", lambda rd: os.remove(rd / "comments.json")),
                            ("review.md only", lambda rd: (rd / "review.md").write_text("only the markdown was edited\n"))):
            with self.subTest(tag):
                out = self.fresh_out("o-" + tag.replace(" ", "-").replace(".", ""))
                rd = self.crash_after_publish(out)
                damage(rd)
                with self.assertRaises(PipelineError) as cm:
                    self.replay(self.m, self.rec, out=out)
                self.assertEqual(cm.exception.code, "checkpoint-invalid")
                self.assertFalse((rd / "receipt.json").exists())

    def test_partial_and_failed_runs_are_bound_too(self):
        m = self.mini("mini-p")
        h = hyp(m, "src/a.py", 2)
        for tag, scr in (("partial", script(inv(h), entry("VERIFY", "verifier", "verifier", 0, 0,
                                                            error=terr("provider-error", "VERIFY", retryable=False)))),
                         ("failed", script(entry("INVESTIGATE", "investigator", "generalist", 0, 0,
                                                 error=terr("provider-error", "INVESTIGATE", retryable=False))))):
            with self.subTest(tag):
                ev = "evr_" + ("d" if tag == "partial" else "e") * 16
                res, _ = self.record(m, scr, eval_id=ev)
                self.assertEqual(res.status, tag)
                rd = Path(res.run_dir)
                data = b"# FORGED\n"
                (rd / "review.md").write_bytes(data)
                rewrite_receipt(rd, **{"review.md": sha(data)})
                with self.assertRaises(PipelineError) as cm:
                    load_result(self.out, res.run_id)
                self.assertEqual(cm.exception.code, "checkpoint-invalid")

    def test_the_re_render_is_not_a_blanket_refusal_a_clean_resume_still_matches_an_uninterrupted_replay(self):
        out = self.fresh_out("clean")
        rd = self.crash_after_publish(out)
        r2 = self.replay(self.m, self.rec, out=out)
        ref = self.replay(self.m, self.rec, out=self.fresh_out("ref"), eval_id="evr_" + "3" * 16)
        for name in ("comments.json", "review.md"):
            self.assertEqual((rd / name).read_text().replace(r2.run_id, "RUN"),
                             Path(ref.run_dir, name).read_text().replace(ref.run_id, "RUN"))
        self.assertEqual((r2.status, r2.resumed_from), ("completed", "LEARN"))      # resumed at the stage after PUBLISH


# ======================================================================================================================
# N2: a confirmation must be tied to the claim, and real cross-file proof survives
# ======================================================================================================================

class VerifierRelevance(Base):
    def setUp(self):
        super().setUp()
        self.m = self.mini()

    def run_one(self, h, ev, eval_id=None):
        m = self.m
        kw = {"eval_id": eval_id} if eval_id else {}
        return self.record(m, script(inv(h), ver(0, m, evidence=ev, impact=h["impact"]), judge(w([hid(0, h)]))), **kw)

    def test_the_unrelated_confirmation_is_dropped_for_that_reason_and_its_neighbour_survives(self):
        m = self.m
        a, b = hyp(m, "src/a.py", 2, claim="first"), hyp(m, "src/a.py", 8, claim="second")
        res, spy = self.record(m, script(inv(a, b), ver(0, m, path="src/b.py", line=2), ver(1, m, path="src/a.py", line=8),
                                         judge(w([hid(1, b)]))))
        self.assertEqual([f["id"] for f in res.findings], [hid(1, b)])
        [d] = res.drops
        self.assertEqual((d["reason"], d["subjectIds"]), ("invalid-citation", [hid(0, a)]))
        self.assertEqual(spy.calls, 4)        # investigator, two verifiers, judge: the rejected candidate cost a verifier call, no more

    def test_real_cross_file_evidence_is_kept_beside_the_location_citation_in_either_order(self):
        m = self.m
        h = hyp(m, "src/a.py", 2)
        loc, caller = m.cite("src/a.py", 2), m.cite("src/b.py", 2)
        for tag, ev, evr in (("location first", [loc, caller], "evr_" + "1" * 16), ("caller first", [caller, loc], "evr_" + "2" * 16)):
            with self.subTest(tag):
                res, _ = self.run_one(h, ev, eval_id=evr)
                [f] = res.findings
                self.assertEqual(sorted(e["path"] for e in f["verification"]["evidence"]), ["src/a.py", "src/b.py"])
                [c] = res.comments
                self.assertIn("src/b.py", [e["path"] for e in c["evidence"]])       # the caller proof reaches the comment

    def test_characterisation_relevance_is_a_path_plus_window_not_a_semantic_test(self):
        # Holds the documented rule so nobody mistakes it for semantic verification: same file within VERIFY_WINDOW lines
        # of the location (or overlapping a proposal citation) is "tied". Line 23 is outside a window of 20 around line 2.
        w_ = engine.VERIFY_WINDOW
        m = self.m
        h = hyp(m, "src/a.py", 2)
        inside, _ = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=2 + w_), judge(w([hid(0, h)]))))
        self.assertEqual(len(inside.findings), 1)
        outside, _ = self.record(m, script(inv(h), ver(0, m, path="src/a.py", line=3 + w_), judge(w([hid(0, h)]))),
                                 eval_id="evr_" + "5" * 16)
        self.assertEqual((len(outside.findings), [d["reason"] for d in outside.drops]), (0, ["invalid-citation"]))

    def test_characterisation_echoing_the_investigators_own_cross_file_citation_is_accepted(self):
        # The proposal cites ONLY src/b.py for a src/a.py location; the verifier echoes that same cite. Overlap with a proposal
        # citation counts as "tied". Residual (LOW): a lazy investigator plus a lazy verifier still agree on code that is not
        # at the location. The proposal's own citation is not independent evidence, so this is weaker than "independent".
        m = self.m
        h = hyp(m, "src/a.py", 2, evidence=[m.cite("src/b.py", 2)])
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual((len(res.findings), len(res.comments)), (1, 1))

    @unittest.expectedFailure
    def test_DEFECT_LOW_echoing_the_investigators_cross_file_citation_must_not_verify_a_location_nobody_looked_at(self):
        m = self.m
        h = hyp(m, "src/a.py", 2, evidence=[m.cite("src/b.py", 2)])
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2), judge(w([hid(0, h)]))))
        self.assertEqual(res.findings, [])

    def test_a_cross_file_refutation_is_untouched_by_the_relevance_rule(self):
        # the rule guards CONFIRMATIONS (what becomes a published finding); a cited refutation elsewhere still refutes
        m = self.m
        h = hyp(m, "src/a.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, verdict="refuted", evidence=[m.cite("src/b.py", 2)]), judge()))
        self.assertEqual((res.findings, res.comments), ([], []))
        self.assertEqual([v["verdict"] for v in res.verifications], ["refuted"])
        self.assertEqual([d["reason"] for d in res.drops], ["refuted"])


# ======================================================================================================================
# N3: key-candidates are never dropped on the key; judge grouping is host-validated and lossless
# ======================================================================================================================

class DuplicateHandling(Base):
    def setUp(self):
        super().setUp()
        self.m = self.mini()

    def pair(self, a, b, jdg, *, ev0=None, ev1=None, v1=None, eval_id=None, **kw):
        m = self.m
        scr = script(inv(a, b), ver(0, m, evidence=ev0 or [m.cite("src/a.py", 2)]),
                     v1 or ver(1, m, evidence=ev1 or [m.cite("src/a.py", 2)]), jdg)
        return self.record(m, scr, **({"eval_id": eval_id} if eval_id else {}), **kw)

    def same_key(self, ca="first claim: operator flipped", cb="second claim: result type changed", **bk):
        return hyp(self.m, "src/a.py", 2, claim=ca), hyp(self.m, "src/a.py", 2, claim=cb, **bk)

    def test_a_judge_merge_inside_one_candidate_group_keeps_every_id_claim_and_piece_of_evidence(self):
        m = self.m
        a, b = self.same_key()
        res, _ = self.pair(a, b, judge(w([hid(0, a), hid(1, b)], "One title", "One body")),
                           ev1=[m.cite("src/a.py", 2), m.cite("src/b.py", 2)])
        [c] = res.comments
        self.assertEqual(c["findingIds"], [hid(0, a), hid(1, b)])
        self.assertIn("second claim: result type changed", c["body"])        # the non-primary claim is written by the HOST
        self.assertIn("src/b.py", [e["path"] for e in c["evidence"]])        # the second finding's proof is not lost
        [d] = [d for d in res.drops if d["reason"] == "merged"]
        self.assertEqual(d["subjectIds"], [hid(1, b)])
        self.assertIn("claim and evidence kept", d["detail"])
        self.assertEqual(sorted(f["id"] for f in res.findings), sorted([hid(0, a), hid(1, b)]))   # both findings stay on record

    def test_the_primary_is_the_most_severe_member_and_severity_is_neither_promoted_nor_demoted(self):
        m = self.m
        a = hyp(m, "src/a.py", 2, claim="mild reading", severity="P2")
        b = hyp(m, "src/a.py", 2, claim="severe reading", severity="P0")
        merged, _ = self.pair(a, b, judge(w([hid(0, a), hid(1, b)], "T", "B")))
        [c] = merged.comments
        self.assertEqual(c["findingIds"][0], hid(1, b))                         # most severe first, not earliest
        alone_a, _ = self.record(m, script(inv(a), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, a)]))),
                                 eval_id="evr_" + "6" * 16)
        alone_b, _ = self.record(m, script(inv(b), ver(0, m, path="src/a.py", line=2), judge(w([hid(0, b)]))),
                                 eval_id="evr_" + "7" * 16)
        self.assertEqual((alone_a.comments[0]["severity"], alone_b.comments[0]["severity"]), ("P2", "P1"))
        self.assertEqual(c["severity"], "P1")                                   # = the severe one's own (ceiling-capped), not P0, not P2
        self.assertEqual((c["proposedSeverity"], c["severityCeiling"]),
                         (alone_b.comments[0]["proposedSeverity"], alone_b.comments[0]["severityCeiling"]))

    def test_a_group_that_crosses_issue_keys_rejects_the_whole_judge_output_and_every_claim_survives(self):
        m = self.m
        a = hyp(m, "src/a.py", 2, claim="alpha")
        b = hyp(m, "src/a.py", 2, claim="beta", impact="crash")                  # different impact => different key
        res, _ = self.pair(a, b, judge(w([hid(0, a), hid(1, b)], "T", "B")), v1=ver(1, m, impact="crash", path="src/a.py", line=2))
        self.assertEqual(sorted(c["findingIds"][0] for c in res.comments), sorted([hid(0, a), hid(1, b)]))
        self.assertEqual(res.status, "partial")
        self.assertTrue(any("judge output rejected" in i["detail"] and "duplicate-candidate group" in i["detail"]
                            for i in res.incomplete), res.incomplete)
        self.assertEqual([d for d in res.drops if d["reason"] == "merged"], [])

    def test_a_group_spanning_two_different_candidate_groups_is_rejected(self):
        # two real candidate groups (K1 at line 2, K2 at line 5); a judge comment that mixes one finding of each is regrouping
        # ACROSS keys. (The test above only reaches the "not in any group" clause because its findings are singletons.)
        m = self.m
        a1, a2 = hyp(m, "src/a.py", 2, claim="a one"), hyp(m, "src/a.py", 2, claim="a two")
        b1, b2 = hyp(m, "src/a.py", 5, claim="b one"), hyp(m, "src/a.py", 5, claim="b two")
        scr = script(inv(a1, a2, b1, b2), *[ver(i, m, path="src/a.py", line=2 if i < 2 else 5) for i in range(4)],
                     judge(w([hid(0, a1), hid(2, b1)], "T", "B"), w([hid(1, a2)], "T", "B"), w([hid(3, b2)], "T", "B")))
        res, _ = self.record(m, scr)
        self.assertEqual(sorted(c["findingIds"][0] for c in res.comments), sorted(hid(i, h) for i, h in enumerate((a1, a2, b1, b2))))
        self.assertTrue(any("only inside one host duplicate-candidate group" in i["detail"] for i in res.incomplete), res.incomplete)
        self.assertEqual([d for d in res.drops if d["reason"] == "merged"], [])

    def test_a_group_naming_an_unverified_finding_is_rejected(self):
        m = self.m
        a, b = self.same_key()
        res, _ = self.pair(a, b, judge(w([hid(0, a), hid(1, b)], "T", "B")),
                           v1=ver(1, m, verdict="refuted", evidence=[]))
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, a)]])
        self.assertTrue(any("not a verified survivor" in i["detail"] for i in res.incomplete), res.incomplete)

    def test_an_unavailable_judge_reports_every_candidate_duplicate_with_its_own_claim(self):
        m = self.m
        a, b = self.same_key()
        res, _ = self.pair(a, b, entry("JUDGE", "judge", "judge", 0, 0, error=terr("provider-error", "JUDGE", retryable=False)))
        self.assertEqual(sorted(c["findingIds"][0] for c in res.comments), sorted([hid(0, a), hid(1, b)]))
        text = {c["findingIds"][0]: c["title"] + c["body"] for c in res.comments}
        self.assertIn("first claim", text[hid(0, a)])
        self.assertIn("second claim", text[hid(1, b)])
        self.assertEqual(res.status, "partial")

    def test_identical_claims_collapse_to_one_comment_that_keeps_both_ids(self):
        m = self.m
        a = hyp(m, "src/a.py", 2, claim="Same words")
        b = hyp(m, "src/a.py", 2, claim="same   WORDS")                        # fingerprint is case/whitespace insensitive
        res, _ = self.pair(a, b, judge(w([hid(0, a)], "T", "B")))              # the judge only ever sees the keeper
        [c] = res.comments
        self.assertEqual(c["findingIds"], [hid(0, a), hid(1, b)])
        [d] = [d for d in res.drops if d["reason"] == "merged"]
        self.assertIn("identical claim and anchor", d["detail"])
        self.assertEqual(res.status, "completed")

    @unittest.expectedFailure
    def test_DEFECT_LOW_an_identical_claim_twin_must_not_lower_the_comment_severity(self):
        m = self.m
        a = hyp(m, "src/a.py", 2, claim="Same words", severity="P2")
        b = hyp(m, "src/a.py", 2, claim="same words", severity="P0")
        res, _ = self.pair(a, b, judge(w([hid(0, a)], "T", "B")))
        self.assertEqual(res.comments[0]["severity"], "P1")                    # the more severe twin's (ceiling-capped); got P2

    @unittest.expectedFailure
    def test_DEFECT_LOW_an_identical_claim_twin_must_keep_its_own_evidence_on_the_comment(self):
        m = self.m
        a = hyp(m, "src/a.py", 2, claim="Same words")
        b = hyp(m, "src/a.py", 2, claim="same words", evidence=[m.cite("src/a.py", 1, 2)])    # extra cited line only on the twin
        res, _ = self.pair(a, b, judge(w([hid(0, a)], "T", "B")))
        self.assertIn([1, 2], [e.get("lines") for e in res.comments[0]["evidence"]])      # only its id survives today

    @unittest.expectedFailure
    def test_DEFECT_LOW_a_merged_comment_never_silently_truncates_a_member_claim(self):
        m = self.m
        hs = [hyp(m, "src/a.py", 2, claim=f"member {i} " + "x" * 880 + f" END{i}") for i in range(6)]
        scr = script(inv(*hs), *[ver(i, m, path="src/a.py", line=2) for i in range(6)],
                     judge(w([hid(i, h) for i, h in enumerate(hs)], "T", "B" * 3000)))
        res, _ = self.record(m, scr)
        [c] = res.comments
        for i in range(1, 6):
            self.assertTrue(f"END{i}" in c["body"], f"member {i} was cut mid-claim at the 4000 char cap")


# ======================================================================================================================
# N4: the gate before every verifier model call
# ======================================================================================================================

class ModelCallGate(Base):
    def two_candidates(self):
        m = self.mini()
        a, b = hyp(m, "src/a.py", 2, claim="first"), hyp(m, "src/a.py", 5, claim="second")
        return m, a, b, script(inv(a, b), ver(0, m, path="src/a.py", line=2), ver(1, m, path="src/a.py", line=5),
                               judge(w([hid(0, a)]), w([hid(1, b)])))

    def patched(self, on_diff):
        Orig, calls = engine.ToolSession, []

        class Session(Orig):
            def call(s, tool, args):
                r = super().call(tool, args)
                if s.agent_id == "verifier" and tool == "diff":
                    calls.append(1)
                    on_diff(len(calls))
                return r
        return mock.patch.object(engine, "ToolSession", Session)

    def test_control_without_any_clock_movement_all_four_provider_calls_happen(self):
        m, a, b, scr = self.two_candidates()
        res, spy = self.record(m, scr)
        self.assertEqual((spy.calls, len(res.findings), res.status), (4, 2, "completed"))

    def test_cancellation_during_the_last_tool_call_starts_no_verifier_call(self):
        m, a, b, scr = self.two_candidates()
        flag = [False]
        with self.patched(lambda n: flag.__setitem__(0, True)):
            res, spy = self.record(m, scr, cancel=lambda: flag[0])
        self.assertEqual((res.status, spy.calls), ("cancelled", 1))
        self.assertEqual(model_calls(res, "VERIFY"), [])

    def test_the_second_candidate_crossing_the_deadline_keeps_the_first_finding_and_says_deadline(self):
        m, a, b, scr = self.two_candidates()
        with self.patched(lambda n: self.clock_value.__setitem__(0, 1000.0) if n == 2 else None):
            res, spy = self.record(m, scr)
        self.assertEqual(spy.calls, 2)                                         # investigator + the FIRST verifier only
        self.assertEqual([f["id"] for f in res.findings], [hid(0, a)])
        self.assertEqual([(d["subjectIds"], d["reason"]) for d in res.drops if d["stage"] == "VERIFY"], [([hid(1, b)], "deadline")])
        self.assertEqual(res.status, "partial")
        self.assertEqual([c["findingIds"] for c in res.comments], [[hid(0, a)]])   # the verified finding is still reported


# ======================================================================================================================
# N5: candidates must sit in a file the change modified
# ======================================================================================================================

class ChangedFileAnchoring(Base):
    SAME = {"src/a.py": BASE["src/a.py"], "src/b.py": "def g(x):\n    return x\n"}

    def test_evidence_in_a_changed_file_does_not_launder_a_location_in_an_unchanged_file(self):
        m = self.mini(base=self.SAME, head=dict(self.SAME, **{"src/a.py": HEAD["src/a.py"]}))
        h = hyp(m, "src/b.py", 2, evidence=[m.cite("src/a.py", 2)])             # cites the changed file, locates the unchanged one
        res, _ = self.record(m, script(inv(h), judge()))
        self.assertEqual((res.hypotheses, res.comments), ([], []))
        self.assertEqual([d["reason"] for d in res.drops], ["invalid-citation"])

    def test_added_and_renamed_files_are_changed_files(self):
        base = {"src/a.py": BASE["src/a.py"], "src/old.py": "def old(x):\n    return x\n"}
        head = {"src/a.py": BASE["src/a.py"], "src/new.py": "def fresh(x):\n    return x + 1\n",
                "src/renamed.py": "def old(x):\n    return x\n"}
        m = self.mini(base=base, head=head)
        added, renamed = hyp(m, "src/new.py", 2, claim="added"), hyp(m, "src/renamed.py", 2, claim="renamed")
        res, _ = self.record(m, script(inv(added, renamed), ver(0, m, path="src/new.py", line=2),
                                       ver(1, m, path="src/renamed.py", line=2), judge(w([hid(0, added)]), w([hid(1, renamed)]))))
        self.assertEqual(sorted(c["anchor"]["path"] for c in res.comments), ["src/new.py", "src/renamed.py"])

    def test_characterisation_when_the_change_list_cannot_be_collected_the_rule_is_off_and_the_run_is_partial(self):
        # fail-open by design (S0-07b-fix: "skipped only if a full-view PREPARE could not list changes at all"). The run is
        # honest about it (partial, PREPARE incomplete), so the unchanged-file comment is visible as unvetted rather than hidden.
        m = self.mini(base=self.SAME, head=dict(self.SAME, **{"src/a.py": HEAD["src/a.py"]}))
        h = hyp(m, "src/b.py", 2)
        res, _ = self.record(m, script(inv(h), ver(0, m, path="src/b.py", line=2), judge(w([hid(0, h)]))),
                             tool_limits=Limits(max_calls=0))
        self.assertEqual(res.status, "partial")
        self.assertIn("PREPARE", [i["stage"] for i in res.incomplete])
        self.assertEqual([c["anchor"]["path"] for c in res.comments], ["src/b.py"])


# ======================================================================================================================
# N8: output root containment
# ======================================================================================================================

class OutputAncestors(Base):
    def attempt(self, out_root, forbidden=()):
        m = self.mini()
        with self.assertRaises(PipelineError) as cm:
            self.record(m, script(inv()), out_root=out_root, forbidden_roots=forbidden)
        self.assertEqual(cm.exception.code, "path-escape")
        self.assertEqual(list(m.root.glob("run_*")) + list(m.root.parent.glob("run_*")), [])      # nothing was created
        return m

    def test_a_dotdot_path_and_a_symlink_that_resolve_to_an_ancestor_are_refused(self):
        m = self.mini()
        link = self.tmp / "toparent"
        os.symlink(m.root, link)
        for tag, p in (("dotdot", m.root / "head" / ".."), ("symlink", link)):
            with self.subTest(tag), self.assertRaises(PipelineError) as cm:
                self.record(m, script(inv()), out_root=p, forbidden_roots=(), eval_id="evr_" + ("b" if tag == "dotdot" else "c") * 16)
            self.assertEqual(cm.exception.code, "path-escape")

    def test_the_filesystem_root_is_an_ancestor_of_every_input_and_is_refused(self):
        self.attempt(Path("/"))

    def test_an_unrelated_output_root_still_works(self):
        res, _ = self.record(self.mini(), script(inv()))
        self.assertEqual(Path(res.run_dir).parent, self.out)


if __name__ == "__main__":
    unittest.main()
