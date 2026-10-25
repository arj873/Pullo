"""Independent RE-review tests for the S0-04 corrections (reviewer/scoring, fixtures/smoke). Reviewer-owned, offline.

Convention (same as test_scoring_review.py): `test_RRn_*` asserts the CORRECT behaviour, so FAIL/ERROR = a
reproduced defect (ids in handoffs/S0-04-rereview.md); `test_CONTROL_*` pass today. Fixtures are only read or
copied to a temp dir; mutation happens on the copy. No network, no model, no target execution.

Policy under test: root SD5 ruling (orchestration/NEXT-WAVE.md): the DATASET digest may stay unchanged when
only scripts change; `synthetic_config_digest` must change with script bytes, redaction version/fingerprint and
caller config, deterministically.

Low-level vs production: `score_case` / `match_comments` take OPTIONAL `head_snapshot_id` / `run_id` so unit
tests can score hand-built comments; without them there is NO snapshot/run provenance check. The production
entry point is `score_loaded_case`, which always supplies the case's pinned head snapshot id and the run.

Run: nice -n 19 python3 -m unittest discover -s tests/scoring_review -v
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_scoring_review as T  # noqa: E402  (comment()/bug() builders and RUN/SNAP constants)
from reviewer.contracts import redaction as R  # noqa: E402
from reviewer.contracts.snapshot import build_manifest  # noqa: E402
from reviewer.scoring import (ScoringError, UnscoredSuiteError, build_report, match_comments,  # noqa: E402
                              score_case, score_loaded_case)
from reviewer.scoring import checks as CH  # noqa: E402
from reviewer.scoring import suite as SU  # noqa: E402
from reviewer.scoring.matching import SCORED_STATES, _distance, _span  # noqa: E402
from reviewer.scoring.report import zero_cost  # noqa: E402
from reviewer.scoring.scripts import check_case_script, smoke_limits  # noqa: E402
from reviewer.scoring.suite import (load_suite, redaction_fingerprint, scripts_digest,  # noqa: E402
                                    synthetic_config_digest)

SMOKE = ROOT / "fixtures" / "smoke"
AWS = "AKIAIOSFODNN7EXAMPLE"
RUN2 = "run_" + "9" * 16


def fresh():
    tmp = Path(tempfile.mkdtemp())
    d = tmp / "smoke"
    shutil.copytree(SMOKE, d, symlinks=True)
    return tmp, d


def dump(p: Path, doc) -> None:
    p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def cli(*args, timeout=60):
    return subprocess.run([sys.executable, "-m", "reviewer.scoring", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp, self.d = fresh()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def edit_script(self, cid, fn):
        p = self.d / f"scripts/{cid}.json"
        doc = json.loads(p.read_text())
        fn(doc)
        dump(p, doc)

    def problems(self, cid, **kw):
        return check_case_script(load_suite(self.d), cid, **kw)


# ============================================================ SD5 policy: dataset digest vs synthetic_config_digest
class RI_Identity(Base):
    def test_CONTROL_dataset_digest_is_unchanged_by_script_edits_and_config_digest_moves(self):
        ds, cfg = load_suite(self.d).digest, synthetic_config_digest(load_suite(self.d))
        self.edit_script("smoke-c03", lambda doc: doc["entries"][0]["response"]["output"]["hypotheses"][0]
                         .__setitem__("mechanism", doc["entries"][0]["response"]["output"]["hypotheses"][0]["mechanism"] + " x"))
        s = load_suite(self.d)
        self.assertEqual(s.digest, ds)                       # root ruling: dataset recipe untouched
        self.assertNotEqual(synthetic_config_digest(s), cfg)

    def test_CONTROL_every_script_is_individually_bound_down_to_whitespace(self):
        base = synthetic_config_digest(load_suite(self.d))
        seen = {base}
        for cid in load_suite(self.d).cases:
            with self.subTest(cid):
                p = self.d / f"scripts/{cid}.json"
                orig = p.read_bytes()
                p.write_bytes(orig + b"\n")                  # JSON-equivalent, bytes differ
                d2 = synthetic_config_digest(load_suite(self.d))
                p.write_bytes(orig)
                self.assertNotIn(d2, seen)
                seen.add(d2)
                self.assertEqual(synthetic_config_digest(load_suite(self.d)), base)   # restored bytes => same identity

    def test_CONTROL_missing_script_is_an_error_not_a_silently_smaller_identity(self):
        for case in ("smoke-c01", "smoke-c06"):
            with self.subTest(case):
                shutil.rmtree(self.tmp)
                self.setUp()
                (self.d / f"scripts/{case}.json").unlink()
                s = load_suite(self.d)                       # loading does not touch scripts
                for fn in (scripts_digest, synthetic_config_digest):
                    with self.assertRaises(ScoringError):
                        fn(s)
                r = cli("check", str(self.d))
                self.assertEqual(r.returncode, 1)
                self.assertIn("no script", r.stdout)

    def test_CONTROL_symlinked_or_directory_script_cannot_be_hashed(self):
        os.rename(self.d / "scripts/smoke-c01.json", self.d / "real.json")
        os.symlink(self.d / "real.json", self.d / "scripts/smoke-c01.json")
        with self.assertRaises(ScoringError):
            synthetic_config_digest(load_suite(self.d))
        (self.d / "scripts/smoke-c01.json").unlink()
        (self.d / "scripts/smoke-c01.json").mkdir()
        with self.assertRaises(ScoringError):
            synthetic_config_digest(load_suite(self.d))

    def test_CONTROL_same_data_different_config_changes_identity_and_is_deterministic(self):
        s = load_suite(self.d)
        a, b = synthetic_config_digest(s, {"plan": "p1", "profile": "x"}), synthetic_config_digest(s, {"plan": "p2", "profile": "x"})
        self.assertNotEqual(a, b)
        self.assertEqual(a, synthetic_config_digest(s, {"profile": "x", "plan": "p1"}))      # key order irrelevant
        self.assertEqual(a, synthetic_config_digest(load_suite(SMOKE), {"plan": "p1", "profile": "x"}))   # location independent
        self.assertNotEqual(synthetic_config_digest(s), synthetic_config_digest(s, {}))      # None and {} are distinct configs
        # caller config is nested: it cannot overwrite bound fields
        sneaky = {"suiteDigest": "sha256:" + "0" * 64, "scripts": [], "redaction": {}}
        self.assertNotEqual(synthetic_config_digest(s, sneaky), synthetic_config_digest(s))
        for bad in ({1, 2}, float("nan"), b"x", {"k": float("inf")}):
            with self.subTest(type(bad).__name__), self.assertRaises((TypeError, ValueError)):
                synthetic_config_digest(s, bad)

    def test_CONTROL_dataset_changes_move_the_config_identity(self):
        base = synthetic_config_digest(load_suite(self.d))
        lab = self.d / "labels/smoke-c01.json"
        doc = json.loads(lab.read_text())
        doc["bugs"][0]["severity"] = "P0" if doc["bugs"][0]["severity"] != "P0" else "P1"
        dump(lab, doc)
        s = load_suite(self.d)
        self.assertNotEqual(s.digest, load_suite(SMOKE).digest)
        self.assertNotEqual(synthetic_config_digest(s), base)

    def test_CONTROL_redaction_policy_moves_the_identity(self):
        s = load_suite(self.d)
        base, fp = synthetic_config_digest(s), redaction_fingerprint()
        with mock.patch.object(SU, "REDACTION_VERSION", "redact@4"):
            self.assertNotEqual(synthetic_config_digest(s), base)
        with mock.patch.object(SU, "PROTECTED_PATTERNS", SU.PROTECTED_PATTERNS + (("extra", re.compile("zzz")),)):
            self.assertNotEqual(redaction_fingerprint(), fp)
            self.assertNotEqual(synthetic_config_digest(s), base)
        pid, pat = SU.PROTECTED_PATTERNS[0]
        with mock.patch.object(SU, "PROTECTED_PATTERNS", ((pid, re.compile(pat.pattern + "x", pat.flags)),) + SU.PROTECTED_PATTERNS[1:]):
            self.assertNotEqual(redaction_fingerprint(), fp)           # same ids, edited source => new fingerprint
        with mock.patch.object(SU, "PROTECTED_PATTERNS", ((pid, re.compile(pat.pattern, pat.flags | re.I)),) + SU.PROTECTED_PATTERNS[1:]):
            self.assertNotEqual(redaction_fingerprint(), fp)           # flags only
        with mock.patch.object(SU, "MAX_PASSES", 9):
            self.assertNotEqual(synthetic_config_digest(s), base)
        self.assertEqual(synthetic_config_digest(s), base)             # patches fully undone

    def test_CONTROL_stale_policy_fails_check_and_regeneration_check(self):
        """A redaction version bump with fixtures still stamped redact@3: `check` and the description gate fail."""
        s = load_suite(self.d)
        self.assertEqual(CH.check_redaction_version(s), [])
        with mock.patch.object(CH, "REDACTION_VERSION", "redact@4"):
            self.assertEqual(len(CH.check_redaction_version(s)), 1)
            self.assertTrue(any("redact@4" in p for p in CH.check_suite(s)))
        # description edited to drop the stamp (suite digest moves with it)
        man = json.loads((self.d / "suite.json").read_text())
        man["description"] = man["description"].replace("redact@3", "redact@2")
        dump(self.d / "suite.json", man)
        self.assertTrue(CH.check_redaction_version(load_suite(self.d)))
        r = cli("check", str(self.d))
        self.assertEqual(r.returncode, 1)
        d = cli("build-smoke", "--check", "--out", str(self.d))
        self.assertEqual(d.returncode, 1)
        self.assertIn("changed suite.json", d.stdout)

    def test_CONTROL_pattern_edit_without_a_version_bump_is_visible_only_in_the_identity(self):
        """Documented RF1 limit: `check` cannot see an unversioned pattern edit (only the config digest moves);
        it still rescans every fixture with the CURRENT patterns, which is what keeps fixtures safe."""
        s = load_suite(self.d)
        base = synthetic_config_digest(s)
        with mock.patch.object(SU, "PROTECTED_PATTERNS", SU.PROTECTED_PATTERNS + (("extra", re.compile("zzz")),)):
            self.assertNotEqual(synthetic_config_digest(s), base)
            self.assertEqual(CH.check_redaction_version(s), [])        # version string unchanged => no complaint
        with mock.patch.object(CH, "contains_protected", lambda t: "def " in t):
            self.assertTrue(CH.check_protected(s))                     # but rescans use the live patterns

    def test_CONTROL_fixture_regeneration_detects_script_and_label_drift(self):
        self.assertEqual(cli("build-smoke", "--check", "--out", str(self.d)).returncode, 0)
        p = self.d / "scripts/smoke-c02.json"
        p.write_text(p.read_text() + "\n")                                # a still-valid but different script
        r = cli("build-smoke", "--check", "--out", str(self.d))
        self.assertEqual(r.returncode, 1)
        self.assertIn("changed scripts/smoke-c02.json", r.stdout)

    def test_CONTROL_config_digest_is_valid_in_an_eval_report_and_stable_across_hash_seeds(self):
        s = load_suite(SMOKE)
        cfg = synthetic_config_digest(s, {"plan": "p"})
        results = [T.scored_case_result(score_case(s.manifest, c.labels, [], status="completed"), run_id=T.RUN, status="completed")
                   for c in s.cases.values() if c.labels["expect"] == "silence"]
        man = copy.deepcopy(s.manifest)
        man["cases"] = [c for c in man["cases"] if s.cases[c["id"]].labels["expect"] == "silence"]
        rep = build_report(man, s.digest, results, eval_run_id="evr_" + "1" * 16, mode="strict-replay", config_digest=cfg,
                           profiles=[{"ref": "smoke-synthetic@1", "digest": "sha256:" + "3" * 64}], prompt_versions=["p@v1"],
                           cost=zero_cost(), scored=True, replay_of="evr_" + "9" * 16)
        self.assertEqual(rep["configDigest"], cfg)
        outs = set()
        for seed in ("0", "1", "4242", "random"):
            code = ("import sys; sys.path.insert(0,'.');from reviewer.scoring.suite import *;"
                    "print(synthetic_config_digest(load_suite('fixtures/smoke'),{'plan':'p'}))")
            r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                               env={**os.environ, "PYTHONHASHSEED": seed})
            outs.add(r.stdout.strip())
        self.assertEqual(outs, {cfg})

    def test_CONTROL_stray_files_are_outside_the_identity_but_not_used(self):
        """Limit, not a defect: scripts are addressed per case id (`scripts/<id>.json`). A stray extra file is not
        bound in the identity and `check` does not complain, so the runner MUST load scripts by case id only
        (never glob scripts/) and must hash the bytes it actually feeds (identity is computed at call time)."""
        base = synthetic_config_digest(load_suite(self.d))
        (self.d / "scripts/extra.json").write_text('{"schemaVersion":1,"entries":[]}')
        self.assertEqual(synthetic_config_digest(load_suite(self.d)), base)
        self.assertEqual(cli("check", str(self.d)).returncode, 0)


# ============================================================ SD3: foreign / base snapshot and wrong-run accounting
class RP_Provenance(Base):
    def setUp(self):
        super().setUp()
        self.suite = load_suite(SMOKE)
        c = self.suite.cases["smoke-c01"]
        self.bug = c.labels["bugs"][0]
        self.head, self.base_ = c.input["head"]["snapshotId"], c.input["base"]["snapshotId"]

    def at(self, snap, n=0, state="draft", run=None):
        c = T.comment(self.bug["path"], self.bug["lines"][0], self.bug["lines"][1], snap=snap, n=n, state=state)
        if run:
            c["runId"] = run
        return c

    def score(self, comments, cid="smoke-c01", **kw):
        return score_loaded_case(self.suite, cid, comments, run_id=T.RUN, status="completed", **kw)

    def test_CONTROL_head_anchored_comment_of_this_run_is_the_only_hit(self):
        s = self.score([self.at(self.head)])
        self.assertEqual((s.true_positives, s.false_positives, s.false_negatives, s.foreign, s.expectation_met), (1, 0, 0, 0, True))

    def test_CONTROL_base_other_case_and_arbitrary_snapshot_never_hit(self):
        other_case = self.suite.cases["smoke-c03"].input["head"]["snapshotId"]
        for name, snap in (("base side", self.base_), ("other case head", other_case), ("arbitrary", "snap:sha256:" + "0" * 64)):
            with self.subTest(name):
                s = self.score([self.at(snap)])
                self.assertEqual((s.true_positives, s.false_positives, s.false_negatives, s.foreign, s.duplicates), (0, 1, 1, 1, 0))
                self.assertFalse(s.expectation_met)
                self.assertEqual(s.match.foreign, (s.match.false_positives[0],))

    def test_CONTROL_wrong_run_is_a_false_positive_and_foreign(self):
        s = self.score([self.at(self.head, run=RUN2)])
        self.assertEqual((s.true_positives, s.false_positives, s.foreign, s.duplicates), (0, 1, 1, 0))

    def test_CONTROL_foreign_never_displaces_a_valid_match_and_is_never_a_duplicate(self):
        good, f_base, f_run = self.at(self.head, n=0), self.at(self.base_, n=1), self.at(self.head, n=2, run=RUN2)
        for order in ([good, f_base, f_run], [f_run, f_base, good], [f_base, good, f_run]):
            s = self.score(order)
            self.assertEqual((s.true_positives, s.false_positives, s.duplicates, s.foreign), (1, 2, 0, 2))
            self.assertEqual(s.match.matches, ((good["id"], self.bug["id"]),))
        # a second HEAD comment on the same bug IS a duplicate; foreign ones are not
        dup = self.at(self.head, n=3)
        s = self.score([good, dup, f_base])
        self.assertEqual((s.true_positives, s.false_positives, s.duplicates, s.foreign), (1, 2, 1, 1))

    def test_CONTROL_non_scored_states_are_ignored_not_foreign(self):
        s = self.score([self.at(self.base_, state="retracted")])
        self.assertEqual((s.comments, s.false_positives, s.foreign), (0, 0, 0))
        self.assertEqual(s.match.ignored, (self.at(self.base_, state="retracted")["id"],))

    def test_CONTROL_silence_case_with_a_foreign_comment_fails_the_expectation(self):
        s = score_loaded_case(self.suite, "smoke-c02", [T.comment("src/report.py", 1, 1, snap=self.base_)], run_id=T.RUN, status="completed")
        self.assertEqual((s.false_positives, s.foreign, s.expectation_met), (1, 1, False))

    def test_CONTROL_wrapper_refuses_unlabelled_and_real_suites(self):
        real = copy.copy(self.suite)
        man = copy.deepcopy(self.suite.manifest)
        man["synthetic"], man["matching"] = False, {"rule": "unadjudicated@1"}
        object.__setattr__(real, "manifest", man)
        with self.assertRaises(UnscoredSuiteError):
            score_loaded_case(real, "smoke-c01", [], run_id=T.RUN, status="completed")
        cases = dict(self.suite.cases)
        cases["smoke-c01"] = type(cases["smoke-c01"])(**{**cases["smoke-c01"].__dict__, "labels": None})
        nolabels = type(self.suite)(self.suite.root, self.suite.manifest, self.suite.digest, cases)
        with self.assertRaises(UnscoredSuiteError):
            score_loaded_case(nolabels, "smoke-c01", [], run_id=T.RUN, status="completed")

    def test_CONTROL_low_level_options_are_test_only_and_default_to_no_provenance_check(self):
        """score_case/match_comments WITHOUT head_snapshot_id/run_id perform NO snapshot/run check: a base-anchored
        or wrong-run comment is a hit. Anything but unit tests must go through score_loaded_case."""
        fb = self.at(self.base_)
        low = score_case(self.suite.manifest, self.suite.cases["smoke-c01"].labels, [fb], status="completed")
        self.assertEqual((low.true_positives, low.foreign), (1, 0))                      # test-only behaviour
        only_head = score_case(self.suite.manifest, self.suite.cases["smoke-c01"].labels, [fb], status="completed", head_snapshot_id=self.head)
        self.assertEqual((only_head.true_positives, only_head.foreign), (0, 1))          # snapshot check works alone
        only_run = score_case(self.suite.manifest, self.suite.cases["smoke-c01"].labels, [self.at(self.head, run=RUN2)],
                              status="completed", run_id=T.RUN)
        self.assertEqual((only_run.true_positives, only_run.foreign), (0, 1))            # run check works alone
        prod = self.score([fb])
        self.assertEqual((prod.true_positives, prod.foreign), (0, 1))                    # production wrapper

    def test_CONTROL_production_code_reaches_score_case_only_through_the_wrapper(self):
        """Static: nothing under reviewer/ calls score_case/match_comments except cases.score_loaded_case
        (which passes both provenance arguments) and score_case's own call to match_comments."""
        callers = []
        for p in (ROOT / "reviewer").rglob("*.py"):
            tree = ast.parse(p.read_text())
            for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.Module))]:
                for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
                    name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")
                    if name in ("score_case", "match_comments") and isinstance(fn, ast.FunctionDef):
                        callers.append((p.relative_to(ROOT).as_posix(), fn.name, name, sorted(k.arg for k in call.keywords if k.arg)))
        self.assertEqual(sorted(callers), [("reviewer/scoring/cases.py", "score_case", "match_comments", ["head_snapshot_id", "run_id"]),
                                           ("reviewer/scoring/cases.py", "score_loaded_case", "score_case", ["error", "head_snapshot_id", "incomplete", "run_id", "status"])])

    def test_CONTROL_evidence_commit_is_not_part_of_the_provenance_check(self):
        """Observation: only anchor.snapshotId and runId are checked; a head-anchored comment whose evidence cites
        the base commit still scores. (Comment evidence is validated by the pipeline's provenance stage, not here.)"""
        c = self.at(self.head)
        c["evidence"][0]["commit"] = self.base_
        self.assertEqual(self.score([c]).true_positives, 1)

    def test_RR1_wrapper_must_not_let_run_id_be_disabled(self):
        """score_loaded_case(run_id: str) is the production wrapper, but run_id=None is forwarded to score_case where
        None means 'do not check the run': a comment from ANY run then scores as a true positive."""
        wrong_run = self.at(self.head, run=RUN2)
        try:
            s = score_loaded_case(self.suite, "smoke-c01", [wrong_run], run_id=None, status="completed")
        except (ScoringError, TypeError, ValueError):
            return
        self.assertEqual(s.true_positives, 0, "run_id=None silently disabled the wrong-run check in score_loaded_case")

    def test_RR6_unknown_case_id_is_a_scoring_error(self):
        with self.assertRaises(ScoringError):
            score_loaded_case(self.suite, "no-such-case", [], run_id=T.RUN, status="completed")


# ============================================================ SD10/SD11: completeness under actual limits
class RC_Completeness(Base):
    LIM = {"investigator": (2, 1), "verifier": (2, 1), "judge": (2, 1)}

    def flagged(self, cid, fn=None, limits=None):
        if fn:
            self.edit_script(cid, fn)
        return self.problems(cid, limits=limits)

    def test_CONTROL_clean_suite_complete_under_the_example_limits(self):
        self.assertEqual(smoke_limits(), self.LIM)
        for cid in load_suite(SMOKE).cases:
            self.assertEqual(self.problems(cid), [], cid)

    def test_CONTROL_scripts_are_checked_against_the_limits_actually_supplied(self):
        """The same bytes pass under the plan they were written for and fail under any other plan."""
        for lim, why in (({"investigator": (3, 1), "verifier": (2, 1), "judge": (2, 1)}, "needs a 4th attempt"),
                         ({"investigator": (1, 1), "verifier": (2, 1), "judge": (2, 1)}, "more attempts than allowed")):
            with self.subTest(why):
                self.assertTrue(self.problems("smoke-c06", limits=lim))
        self.assertTrue(self.problems("smoke-c05", limits={"investigator": (2, 1), "verifier": (3, 1), "judge": (2, 1)}))
        self.assertTrue(self.problems("smoke-c04", limits={"investigator": (2, 0), "verifier": (2, 1), "judge": (2, 1)}))   # repairs=0
        self.assertEqual(self.problems("smoke-c04", limits={"investigator": (0, 1), "verifier": (0, 1), "judge": (0, 1)}), [])  # retries irrelevant to a repair

    def test_CONTROL_terminal_failures_must_script_every_attempt(self):
        def drop_last(doc):
            doc["entries"].pop()
        for cid in ("smoke-c05", "smoke-c06"):
            with self.subTest(cid):
                shutil.rmtree(self.tmp)
                self.setUp()
                self.assertTrue(self.flagged(cid, drop_last))

    def test_CONTROL_attempt_numbering_gaps_extras_and_after_ok(self):
        for name, fn in (("extra attempt", lambda d: d["entries"].append({**copy.deepcopy(d["entries"][-1]), "attempt": 3})),
                         ("gap", lambda d: d["entries"][-1].__setitem__("attempt", 5)),
                         ("attempt after ok", lambda d: d["entries"].append({**copy.deepcopy(d["entries"][0]), "attempt": 1}))):
            for cid in ("smoke-c06", "smoke-c01"):
                with self.subTest((name, cid)):
                    shutil.rmtree(self.tmp)
                    self.setUp()
                    self.assertTrue(self.flagged(cid, fn))

    def test_CONTROL_every_candidate_needs_a_verifier_call_and_a_confirmed_one_needs_a_judge(self):
        cases = (("smoke-c03", "drop verifier ordinal 1", lambda d: d.__setitem__("entries", [e for e in d["entries"] if not (e["stage"] == "VERIFY" and e["ordinal"] == 1)])),
                 ("smoke-c01", "drop all verifier entries", lambda d: d.__setitem__("entries", [e for e in d["entries"] if e["stage"] != "VERIFY"])),
                 ("smoke-c01", "drop the judge", lambda d: d.__setitem__("entries", [e for e in d["entries"] if e["stage"] != "JUDGE"])),
                 ("smoke-c04", "drop the judge after a repaired investigator", lambda d: d.__setitem__("entries", [e for e in d["entries"] if e["stage"] != "JUDGE"])))
        for cid, name, fn in cases:
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                self.assertTrue(self.flagged(cid, fn))

    def test_CONTROL_unreachable_or_inconsistent_calls_are_rejected(self):
        def refute(doc):
            for e in doc["entries"]:
                if e["stage"] == "VERIFY":
                    e["response"]["output"]["verdict"] = "refuted"

        def second_investigator(doc):
            e = copy.deepcopy([x for x in doc["entries"] if x["stage"] == "INVESTIGATE"][0])
            e["ordinal"] = 1
            doc["entries"].append(e)

        def judge_ordinal_1(doc):
            for e in doc["entries"]:
                if e["stage"] == "JUDGE":
                    e["ordinal"] = 1

        def verify_after_investigator_failure(doc):
            doc["entries"].append({"stage": "VERIFY", "role": "verifier", "agentId": "verifier", "ordinal": 0, "attempt": 0,
                                   "error": {"code": "provider-error", "message": "x", "retryable": True, "stage": "VERIFY"}})

        for cid, name, fn in (("smoke-c01", "judge kept although nothing is confirmed", refute),
                              ("smoke-c01", "second investigator call", second_investigator),
                              ("smoke-c01", "judge ordinal 1", judge_ordinal_1),
                              ("smoke-c06", "verify scripted behind a failing investigator", verify_after_investigator_failure),
                              ("smoke-c02", "verify scripted with zero candidates", verify_after_investigator_failure)):
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                self.assertTrue(self.flagged(cid, fn))

    def test_CONTROL_judge_may_only_cite_confirmed_candidates(self):
        def cite_unconfirmed(doc):
            for e in doc["entries"]:
                if e["stage"] == "JUDGE":
                    e["response"]["output"]["comments"][0]["findingIds"] = ["hyp_" + "0" * 16]
        self.assertTrue(self.flagged("smoke-c01", cite_unconfirmed))

    def test_CONTROL_accounting_matches_the_gateway_for_invalid_output_and_error_sequences(self):
        """Cross-check of `_call_outcome` against reviewer/gateway/gateway.py:call() semantics: invalid output
        consumes repairs, retryable errors consume retries, indexes advance for both."""
        def seq(kinds):
            e = []
            for i, k in enumerate(kinds):
                base = {"stage": "INVESTIGATE", "role": "investigator", "agentId": "generalist", "ordinal": 0, "attempt": i}
                if k == "err":
                    base["error"] = {"code": "provider-error", "message": "m", "retryable": True, "stage": "INVESTIGATE"}
                elif k == "bad":
                    base["response"] = {"status": "invalid-output", "output": None, "rawText": "{", "usage": None, "finishReason": None}
                e.append((k, base))
            return e
        ok_entry = json.loads((SMOKE / "scripts/smoke-c01.json").read_text())["entries"][0]
        from reviewer.scoring.scripts import _call_outcome
        sample_bad = json.loads((SMOKE / "scripts/smoke-c04.json").read_text())["entries"][0]
        sample_err = json.loads((SMOKE / "scripts/smoke-c06.json").read_text())["entries"][0]
        mk = {"ok": lambda i: {**copy.deepcopy(ok_entry), "attempt": i}, "bad": lambda i: {**copy.deepcopy(sample_bad), "attempt": i},
              "err": lambda i: {**copy.deepcopy(sample_err), "attempt": i}}
        table = [(["err", "err", "err"], "failed"), (["bad", "bad"], "failed"), (["err", "bad", "ok"], "ok"),
                 (["bad", "err", "err", "err"], "failed"), (["err", "err", "bad", "ok"], "ok"),
                 (["err", "bad", "err"], None), (["err", "err", "err", "ok"], None), (["bad", "bad", "ok"], None),
                 (["err", "err"], None), (["bad"], None), (["ok"], "ok")]
        for kinds, want in table:
            with self.subTest(kinds):
                grp = [mk[k](i) for i, k in enumerate(kinds)]
                probs: list[str] = []
                self.assertEqual(_call_outcome(grp, 2, 1, "t", probs), want, probs)

    def test_RR2_scripted_errors_must_be_retryable_provider_errors_to_justify_extra_attempts(self):
        """gateway.call() retries only `err["retryable"] and err["code"] in RETRYABLE_CODES` (provider-error,
        provider-timeout; gateway.py:194). A scripted non-retryable error, or one with another code, ends the call
        at attempt 0: attempts 1..2 are unreachable and the outcome is a different error. The checker accepts it."""
        for name, patch in (("retryable false", {"retryable": False}), ("non-retryable code 'internal'", {"code": "internal"})):
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                self.edit_script("smoke-c06", lambda d: [e["error"].update(patch) for e in d["entries"]])
                self.assertTrue(self.problems("smoke-c06"), f"checker accepted three attempts of a {name} error")

    def test_RR2b_first_attempt_non_retryable_with_later_attempts_is_unreachable(self):
        self.edit_script("smoke-c06", lambda d: d["entries"][0]["error"].update({"retryable": False}))
        self.assertTrue(self.problems("smoke-c06"), "attempts 1-2 can never be consumed after a non-retryable attempt 0")

    def test_RR2c_scripted_terminal_error_code_must_match_the_label_the_case_expects(self):
        """labels.expectReason for the failed case is 'provider-timeout'; the script ends the call with
        'provider-error' and `check` is still green, so the expectation can only fail at run time."""
        self.edit_script("smoke-c06", lambda d: [e["error"].update({"code": "provider-error"}) for e in d["entries"]])
        self.assertEqual(load_suite(self.d).cases["smoke-c06"].labels["expectReason"], "provider-timeout")
        self.assertTrue(self.problems("smoke-c06"), "script/label mismatch on the terminal error code is not reported")


# ============================================================ SD7/SD8/isolation: CLI errors, protected text, label leaks
class RX_CliAndChecks(Base):
    def test_CONTROL_cli_failures_are_clean(self):
        p = self.d / "scripts/smoke-c01.json"
        cases = {"invalid json": lambda: p.write_text("{nope"),
                 "duplicate keys": lambda: p.write_text('{"schemaVersion":1,"schemaVersion":1,"entries":[]}'),
                 "non-utf8": lambda: p.write_bytes(b"\xff\xfe\x00bad"),
                 "directory": lambda: (p.unlink(), p.mkdir()),
                 "symlink": lambda: (p.unlink(), os.symlink(self.d / "scripts/smoke-c02.json", p)),
                 "empty file": lambda: p.write_text(""),
                 "wrong shape": lambda: p.write_text("[]"),
                 "missing script": lambda: p.unlink()}
        for name, make in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                p = self.d / "scripts/smoke-c01.json"
                make()
                r = cli("check", str(self.d))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertNotIn("Traceback", r.stderr + r.stdout)
                self.assertTrue(r.stdout.strip())

    def test_CONTROL_cli_failures_for_suite_level_errors(self):
        (self.d / "suite.json").write_text("not json")
        for args in (("check", str(self.d)), ("check", "/nonexistent/suite"), ("build-smoke", "--check", "--out", "/nonexistent/x")):
            with self.subTest(args):
                r = cli(*args)
                self.assertEqual(r.returncode, 1)
                self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(cli().returncode, 2)                      # argparse usage error, still no traceback
        self.assertNotIn("Traceback", cli().stderr)

    def test_CONTROL_check_reports_all_independent_problems_in_one_run(self):
        (self.d / "scripts/smoke-c02.json").write_text("{nope")
        f = self.d / "scripts/smoke-c05.json"
        f.write_text(f.read_text().replace("scripted", AWS, 1))
        out = cli("check", str(self.d)).stdout
        self.assertIn("script smoke-c02", out)
        self.assertIn("scripts/smoke-c05.json: contains protected text", out)

    def test_CONTROL_protected_text_is_found_in_every_file_class(self):
        def repin(cid, side):
            inp = self.d / f"cases/{cid}/input.json"
            doc = json.loads(inp.read_text())
            doc[side]["snapshotId"] = build_manifest(self.d / f"cases/{cid}/{side}")["snapshotId"]
            dump(inp, doc)

        def m_suite():
            p = self.d / "suite.json"
            doc = json.loads(p.read_text())
            doc["description"] += " " + AWS
            p.write_text(json.dumps(doc))

        def m_input():
            p = self.d / "cases/smoke-c01/input.json"
            doc = json.loads(p.read_text())
            doc["pr"]["body"] += " " + AWS
            dump(p, doc)

        def m_snapshot(side):
            def go():
                f = self.d / f"cases/smoke-c02/{side}/src/report.py"
                f.write_text(f.read_text() + f'\nK = "{AWS}"\n')
                repin("smoke-c02", side)
            return go

        def m_script():
            self.edit_script("smoke-c01", lambda d: d["entries"][0]["response"]["output"]["hypotheses"][0].__setitem__(
                "mechanism", d["entries"][0]["response"]["output"]["hypotheses"][0]["mechanism"] + " " + AWS))

        def m_label():
            p = self.d / "labels/smoke-c01.json"
            doc = json.loads(p.read_text())
            doc["bugs"][0]["note"] = (doc["bugs"][0].get("note") or "") + " " + AWS
            dump(p, doc)
        for name, mutate in (("suite.json", m_suite), ("input.json", m_input), ("head snapshot", m_snapshot("head")),
                             ("base snapshot", m_snapshot("base")), ("script", m_script), ("label", m_label)):
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                mutate()
                r = cli("check", str(self.d))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("contains protected text", r.stdout)

    def test_CONTROL_label_material_is_found_wherever_the_reviewer_or_its_provider_looks(self):
        s0 = load_suite(SMOKE)
        lab = s0.cases["smoke-c01"].labels
        bug_id, reason = lab["bugs"][0]["id"], s0.cases["smoke-c06"].labels["expectReason"]

        def into_snapshot(side, text):
            def go():
                f = self.d / f"cases/smoke-c01/{side}/src/routes.py"
                f.write_text(f.read_text() + f"\n# {text}\n")
                inp = self.d / "cases/smoke-c01/input.json"
                doc = json.loads(inp.read_text())
                doc[side]["snapshotId"] = build_manifest(self.d / f"cases/smoke-c01/{side}")["snapshotId"]
                dump(inp, doc)
            return go

        def into_script(text):
            return lambda: self.edit_script("smoke-c01", lambda d: d["entries"][0]["response"]["output"]["hypotheses"][0].__setitem__("mechanism", text))

        def into_input(text):
            def go():
                p = self.d / "cases/smoke-c01/input.json"
                doc = json.loads(p.read_text())
                doc["pr"]["title"] += " " + text
                dump(p, doc)
            return go
        for name, mk in (("bug id in head snapshot", into_snapshot("head", bug_id)), ("bug id in base snapshot", into_snapshot("base", bug_id)),
                         ("bug id in script", into_script(bug_id)), ("bug id in input", into_input(bug_id)),
                         ("labels path in script", into_script("see labels/smoke-c01.json")),
                         ("contract tag in snapshot", into_snapshot("head", "case-labels@1")),
                         ("labels path in input", into_input("labels/smoke-c01"))):
            with self.subTest(name):
                shutil.rmtree(self.tmp)
                self.setUp()
                mk()
                self.assertTrue(SU.check_isolation(load_suite(self.d)), name)
                self.assertEqual(cli("check", str(self.d)).returncode, 1)
        # the expected reason is allowed in a script (scripted error code) but not in reviewer-visible input
        shutil.rmtree(self.tmp)
        self.setUp()
        self.assertEqual(SU.check_isolation(load_suite(self.d)), [])
        p6 = self.d / "cases/smoke-c06/input.json"
        doc = json.loads(p6.read_text())
        doc["pr"]["title"] += " " + reason
        dump(p6, doc)
        self.assertTrue(any(reason in p and "smoke-c06" in p for p in SU.check_isolation(load_suite(self.d))))

    def test_CONTROL_clean_suite_inputs_do_not_reveal_case_types(self):
        s = load_suite(SMOKE)
        for cid, case in s.cases.items():
            raw = json.dumps(case.input)
            for needle in ("silence", "findings", "verifier-failure", "provider-timeout", "expectReason", *[b["id"] for b in case.labels["bugs"]]):
                self.assertNotIn(needle, raw, (cid, needle))

    def test_RR3_check_suite_never_raises_on_malformed_script_entries(self):
        """check_suite documents 'reported as problems (never a traceback)'. An entry whose key fields are not
        hashable (e.g. "stage": []) raises TypeError out of check_script/check_suite; the CLI masks it as
        'FAIL: TypeError: cannot use list as a dict key' and drops every other problem."""
        for field in ("stage", "ordinal", "attempt", "role", "agentId"):
            with self.subTest(field):
                shutil.rmtree(self.tmp)
                self.setUp()
                self.edit_script("smoke-c02", lambda d: d["entries"][0].__setitem__(field, []))
                try:
                    problems = CH.check_suite(load_suite(self.d))
                except Exception as e:  # noqa: BLE001
                    self.fail(f"check_suite raised {type(e).__name__}: {e}")
                self.assertTrue(problems)

    def test_RR4_cli_check_does_not_hang_on_a_non_regular_script(self):
        """A FIFO named scripts/<id>.json: check_isolation reads it with Path.read_bytes() after `.exists()` and blocks
        forever (scripts_identity uses is_file() and would have refused it)."""
        (self.d / "scripts/smoke-c01.json").unlink()
        os.mkfifo(self.d / "scripts/smoke-c01.json")
        try:
            r = cli("check", str(self.d), timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("`reviewer.scoring check` hung reading a FIFO script (no timeout, no type check)")
        self.assertEqual(r.returncode, 1)


# ============================================================ deterministic matching (with provenance arguments)
def reference_matches(comments, bugs, tol):
    """Independent RECURSIVE Kuhn's algorithm with the documented visiting order (path,start,end,id; (distance,bug id))."""
    scored = sorted((c for c in comments if c["state"] in SCORED_STATES), key=lambda c: (*_span(c), c["id"]))
    compat = {c["id"]: sorted((d, b["id"]) for b in bugs if (d := _distance(_span(c), b)) is not None and d <= tol) for c in scored}
    owner: dict[str, str] = {}

    def aug(c, seen):
        for _, b in compat[c]:
            if b in seen:
                continue
            seen.add(b)
            if b not in owner or aug(owner[b], seen):
                owner[b] = c
                return True
        return False
    for c in scored:
        aug(c["id"], set())
    return tuple(sorted((c, b) for b, c in owner.items()))


class RD_Determinism(unittest.TestCase):
    def test_CONTROL_iterative_matching_equals_an_independent_recursive_reference_exactly(self):
        rng = random.Random(20261025)
        for it in range(3000):
            tol = rng.randint(0, 4)
            paths = ["a.py", "b.py"][:rng.randint(1, 2)]
            bugs = [T.bug(i, rng.choice(paths), (lo := rng.randint(1, 25)), lo + rng.randint(0, 3)) for i in range(rng.randint(0, 7))]
            cs = [T.comment(rng.choice(paths), (s := rng.randint(1, 25)), s + rng.randint(0, 3), n=n,
                            state=rng.choice(["draft", "draft", "posted", "retracted"])) for n in range(rng.randint(0, 8))]
            self.assertEqual(match_comments(cs, bugs, tol).matches, reference_matches(cs, bugs, tol), (it, tol))

    def test_CONTROL_provenance_arguments_do_not_disturb_ordering_or_determinism(self):
        rng = random.Random(31)
        for _ in range(300):
            bugs = [T.bug(i, "a.py", (lo := rng.randint(1, 12)), lo + rng.randint(0, 2)) for i in range(4)]
            cs = [T.comment("a.py", (s := rng.randint(1, 14)), s + rng.randint(0, 2), n=n, snap=rng.choice([T.SNAP, "snap:sha256:" + "b" * 64])) for n in range(6)]
            ref = match_comments(cs, bugs, 2, head_snapshot_id=T.SNAP, run_id=T.RUN)
            for _k in range(4):
                a, b = cs[:], bugs[:]
                rng.shuffle(a)
                rng.shuffle(b)
                r = match_comments(a, b, 2, head_snapshot_id=T.SNAP, run_id=T.RUN)
                self.assertEqual(r, ref)
            self.assertEqual(ref.foreign, tuple(sorted(c["id"] for c in cs if c["anchor"]["snapshotId"] != T.SNAP)))
            self.assertTrue(set(ref.foreign) <= set(ref.false_positives) and not set(ref.foreign) & set(ref.duplicates))

    def test_CONTROL_results_are_identical_across_processes_and_hash_seeds(self):
        code = ("import sys,random,json,hashlib;sys.path.insert(0,'.');sys.path.insert(0,'tests/scoring_review');"
                "import test_scoring_review as T;from reviewer.scoring import match_comments;rng=random.Random(5);out=[]\n"
                "for _ in range(200):\n"
                "    bugs=[T.bug(i,'a.py',(lo:=rng.randint(1,12)),lo+rng.randint(0,2)) for i in range(4)]\n"
                "    cs=[T.comment('a.py',(s:=rng.randint(1,14)),s+rng.randint(0,2),n=n,state=rng.choice(['draft','posted','suppressed'])) for n in range(6)]\n"
                "    r=match_comments(cs,bugs,2,head_snapshot_id=T.SNAP,run_id=T.RUN);out.append([r.matches,r.false_positives,r.duplicates,r.false_negatives,r.ignored,r.foreign])\n"
                "print(hashlib.sha256(json.dumps(out).encode()).hexdigest())")
        outs = {subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONHASHSEED": s}).stdout.strip()
                for s in ("0", "1", "123", "random")}
        self.assertEqual(len(outs), 1, outs)
        self.assertEqual(len(next(iter(outs))), 64)

    def test_CONTROL_long_augmenting_chain_and_input_validation(self):
        n = 1500
        bugs = [T.bug(i, "a.py", 2 * i + 1, 2 * i + 1) for i in range(n + 1)]
        cs = [T.comment("a.py", 2 * i + 1, 2 * i + 1, n=i) for i in range(n)] + [T.comment("a.py", 1, 1, n=n)]
        self.assertEqual(match_comments(cs, bugs, 2).true_positives, n + 1)
        for tol in (-1, 21, True, 1.5, "2"):
            with self.subTest(tol), self.assertRaises(ScoringError):
                match_comments([], [], tol)
        with self.assertRaises(ScoringError):
            match_comments([T.comment(cid="dup"), T.comment(n=1, cid="dup")], [], 1)
        with self.assertRaises(ScoringError):
            match_comments([], [T.bug(0, "a.py", 1, 1), T.bug(0, "a.py", 2, 2)], 1)


if __name__ == "__main__":
    unittest.main()
