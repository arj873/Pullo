"""Independent FINAL policy review of S0-03 (s0a-contracts@4 / redact@3). Reviewer-owned, offline,
stdlib only, no model/network calls, no target execution.

Audits the finalfix (RR1-RR12) and verification-policy corrections, not just the four adapted
tests. Class prefixes:

  A_*  CONTROL    pass today and must keep passing: negatives for forged trust, self/absent/
                  wrong-role/wrong-stage/wrong-run verifiers, tampered payload ids, unresolved
                  citations, plus the accepted same-line distinct confirmation.
  FR_* DEFECT     assert the CORRECT behaviour; FAIL today = reproduced defect FR-n in
                  handoffs/S0-03-finalreview.md.
  C_*  LIMIT      pass today; pin an explicit limit so nobody mistakes it for a guarantee.

Run: nice -n 19 python3 -m unittest discover -s tests/contract_review -p 'test_contract_finalreview.py' -v
"""
from __future__ import annotations

import copy
import random
import unittest

from tests.contract_review import finalreview_support as F
from reviewer.contracts import canonical as C
from reviewer.contracts import check_finding_provenance, validate, validate_trace
from reviewer.contracts import redaction as R
from reviewer.contracts import severity as S
from reviewer.contracts import snapshot as SN


def provenance(sc, finding, events):
    return [i.message for i in check_finding_provenance(finding, events)]


class ScenarioCase(unittest.TestCase):
    def setUp(self):
        self.sc = F.Scenario()

    def assertRejected(self, finding, events, why, contains=None):
        """Rejected, and (when `contains` is given) for the intended reason, so a negative cannot
        pass merely because an unrelated fixture problem made the event invisible."""
        got = check_finding_provenance(finding, events)
        self.assertTrue(got, f"ACCEPTED but must be rejected: {why}")
        if contains:
            self.assertTrue(any(contains in i.message for i in got),
                            f"rejected for another reason than {contains!r}: {[i.message for i in got]}")


# ====================================================================================== A: controls

class A_HonestBaseline(ScenarioCase):
    def test_scenario_is_valid_and_accepted(self):
        self.assertEqual(F.issues("Finding", self.sc.finding), [])
        self.assertEqual(provenance(self.sc, self.sc.finding, self.sc.events), [])

    def test_same_line_confirmation_by_a_distinct_verifier_succeeds(self):
        """The policy case: the verifier cites exactly the proposer's pinned lines."""
        f = self.sc.fresh()
        prop = {k: f["evidence"][0][k] for k in F.Scenario.CODE_KEYS}
        ver = {k: f["verification"]["evidence"][0][k] for k in F.Scenario.CODE_KEYS}
        f["verification"]["evidence"] = copy.deepcopy(f["evidence"])
        ver_call = self.sc.verifier(evidence=[prop])
        f["verification"]["callIds"] = [ver_call["callId"]]
        self.assertNotEqual(prop, ver)                       # example cites two different places...
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, ver_call]), [])   # ...now identical: fine

    def test_same_line_confirmation_with_snapshot_minted_evidence(self):
        repo = F.Repo(self, {"src/auth.py": "def f(t):\n    if t is None:\n        return True\n"})
        cite = repo.cite("src/auth.py", [2, 3], "    if t is None:\n        return True")
        (ev,), problems = repo.materialize(cite)
        self.assertEqual(problems, [])
        f = self.sc.fresh()
        f["evidence"] = [copy.deepcopy(ev)]
        f["verification"]["evidence"] = [copy.deepcopy(ev)]
        f["location"] = {"path": "src/auth.py", "line": 2, "endLine": 3}
        # The id is a function of (specialist, index, claim, path, line): moving the location
        # without recomputing it would fail the source binding for the wrong reason.
        f["id"] = C.hypothesis_id(f["specialist"], 0, f["claim"], "src/auth.py", 2)
        self.assertNotEqual(f["id"], self.sc.finding["id"])
        modelcite = {k: ev[k] for k in F.Scenario.CODE_KEYS}
        inv = F.model_call(self.sc.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                           {"hypotheses": [{"claim": f["claim"], "category": f["category"],
                                            "suspectedSeverity": f["suspectedSeverity"],
                                            "impact": f["impact"], "location": f["location"],
                                            "evidence": [modelcite]}]}, seq=1)
        ver = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + f["id"], 0,
                           {**self.sc.confirm, "evidence": [modelcite]}, seq=2)
        f["sourceCallId"], f["verification"]["callIds"] = inv["callId"], [ver["callId"]]
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(ver["request"]["hypothesisId"], f["id"])     # subject follows the new id
        self.assertEqual(f["evidence"], f["verification"]["evidence"])    # same pinned lines, same text
        self.assertTrue(all(e["resolved"] is True for e in f["evidence"]))
        self.assertEqual(provenance(self.sc, f, [inv, ver]), [])
        self.assertEqual(S.finding_ceiling(f), "P0")
        # Non-vacuous: the same events are refused if the id no longer matches the proposal.
        stale = copy.deepcopy(f)
        stale["id"] = self.sc.finding["id"]
        self.assertRejected(stale, [inv, ver], "stale id for the moved location")


class A_VerifierNegatives(ScenarioCase):
    def test_absent_verifier(self):
        self.assertRejected(self.sc.fresh(), [self.sc.inv], "verifier call not logged",
                            "is not a logged model call")

    def test_whitespace_only_citation_change_without_a_verifier(self):
        f = self.sc.fresh()
        f["verification"]["evidence"][0]["excerpt"] += " "
        self.assertRejected(f, [self.sc.inv], "citation novelty is not independence")

    def test_self_verification_in_document_and_in_trace(self):
        f = self.sc.fresh()
        f["verification"]["callIds"] = [self.sc.inv["callId"]]
        self.assertTrue(F.issues("Finding", f))
        f["verification"]["callIds"] = [self.sc.inv["callId"], self.sc.ver["callId"]]
        self.assertTrue(F.issues("Finding", f), "a self id mixed with a real verifier id")
        f = self.sc.fresh()                                   # trace level: source id == verifier id
        f["sourceCallId"] = self.sc.ver["callId"]
        self.assertRejected(f, self.sc.events, "source slot names the verifier call",
                            "self-verification")

    def test_wrong_role_wrong_stage(self):
        wrong_role = F.model_call(self.sc.run, "VERIFY", "investigator", "w", 0, {"hypotheses": []},
                                  seq=2)
        wrong_stage = F.model_call(self.sc.run, "INVESTIGATE", "verifier", "w", 0, self.sc.confirm,
                                   seq=2)
        for name, bad in (("role", wrong_role), ("stage", wrong_stage)):
            f = self.sc.fresh()
            f["verification"]["callIds"] = [bad["callId"]]
            with self.subTest(name):
                self.assertRejected(f, [self.sc.inv, bad], f"verifier slot holds a wrong-{name} call",
                                    "not VERIFY/verifier")
        f = self.sc.fresh()                                   # source slot holds a non-investigator call
        f["sourceCallId"] = wrong_stage["callId"]
        self.assertRejected(f, [wrong_stage, self.sc.ver], "source slot holds a non-INVESTIGATE call",
                            "not INVESTIGATE/investigator")

    def test_wrong_run_calls(self):
        other = "run_" + "e" * 16
        foreign_ver = F.model_call(other, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0,
                                   self.sc.confirm, seq=2)
        foreign_inv = F.model_call(other, "INVESTIGATE", "investigator", "generalist-0", 0,
                                   {"hypotheses": []}, seq=1)
        self.assertRejected(self.sc.fresh(), [self.sc.inv, foreign_ver], "verifier from another run")
        self.assertRejected(self.sc.fresh(), [foreign_inv, self.sc.ver], "source from another run")

    def test_verdict_not_confirmed(self):
        for verdict in ("refuted", "uncertain"):
            with self.subTest(verdict):
                self.assertRejected(self.sc.fresh(), [self.sc.inv, self.sc.verifier(verdict=verdict)],
                                    f"verifier said {verdict}", "did not confirm")
        bad = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0, None,
                           status="invalid-output", seq=2)
        self.assertRejected(self.sc.fresh(), [self.sc.inv, bad], "invalid verifier output",
                            "usable response")
        errored = copy.deepcopy(self.sc.ver)
        errored["response"] = None
        errored["error"] = {"code": "provider-timeout", "message": "t", "retryable": True}
        self.assertEqual(validate("TraceEvent", errored), [])
        self.assertRejected(self.sc.fresh(), [self.sc.inv, errored], "verifier call errored",
                            "usable response")
        junk = self.sc.verifier(verdict="confirmed", evidence=[])   # confirmed without citation
        self.assertRejected(self.sc.fresh(), [self.sc.inv, junk], "confirmed verdict with no evidence",
                            "did not confirm")

    def test_repair_of_source_call(self):
        rep = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0,
                           self.sc.confirm, attempt=1, repair_of=self.sc.inv["callId"], seq=2)
        f = self.sc.fresh()
        f["verification"]["callIds"] = [rep["callId"]]
        self.assertRejected(f, [self.sc.inv, rep], "verifier call is a repair of the source call",
                            "repair of the source call")

    def test_tool_evidence_naming_an_unlogged_tool_call(self):
        for side in ("evidence", "verification.evidence"):
            f = self.sc.fresh()
            target = f["evidence"] if side == "evidence" else f["verification"]["evidence"]
            target.append({"kind": "tool-result", "excerpt": "", "source": "grep",
                           "toolCallId": "tool_" + "1" * 16})
            with self.subTest(side):
                self.assertEqual(F.issues("Finding", f), [])
                self.assertRejected(f, self.sc.events, "tool call never logged in this run",
                                    "tool call not logged")

    def test_failed_source_call(self):
        bad_inv = F.model_call(self.sc.run, "INVESTIGATE", "investigator", "generalist-0", 0, None,
                               status="invalid-output", seq=1)
        self.assertRejected(self.sc.fresh(), [bad_inv, self.sc.ver], "source call returned invalid output",
                            "usable response")


class A_TamperedPayloadIds(ScenarioCase):
    """A hand-edited event must be ignored by the provenance check and flagged by TraceEvent."""

    def tampered(self, mutate):
        ev = copy.deepcopy(self.sc.ver)
        mutate(ev)
        return ev

    def test_each_binding_breaks_the_event(self):
        cases = {
            "callId": lambda e: e.update(callId="call_" + "0" * 16),
            "requestHash": lambda e: e.update(requestHash="sha256:" + "0" * 64),
            "request edited after hashing": lambda e: e["request"]["messages"][0].update(content="x"),
            "costRecordId": lambda e: e.update(costRecordId="cost_" + "0" * 16),
            "stage relabel, old id kept": lambda e: e.update(stage="INVESTIGATE"),
            "role relabel, old id kept": lambda e: e.update(role="investigator"),
            "agentId relabel, old id kept": lambda e: e.update(agentId="v-other"),
            "ordinal relabel, old id kept": lambda e: e.update(ordinal=7),
            "attempt relabel, old id kept": lambda e: e.update(attempt=1),
        }
        for name, mutate in cases.items():
            ev = self.tampered(mutate)
            with self.subTest(name):
                self.assertTrue(validate("TraceEvent", ev), "tampered event validates")
                f = self.sc.fresh()
                f["verification"]["callIds"] = [ev["callId"]]
                self.assertRejected(f, [self.sc.inv, ev], "tampered verifier event is used")

    def test_relabelled_investigator_cannot_pose_as_verifier(self):
        other = F.model_call(self.sc.run, "INVESTIGATE", "investigator", "generalist-1", 0,
                             {"hypotheses": []}, seq=2)
        forged = {**other, "stage": "VERIFY", "role": "verifier"}
        f = self.sc.fresh()
        f["verification"]["callIds"] = [other["callId"]]
        self.assertTrue(validate("TraceEvent", forged))
        self.assertRejected(f, [self.sc.inv, forged], "stage/role relabelled, id kept")

    def test_tool_call_bindings(self):
        t = F.tool_call(self.sc.run, "ok", [])
        for name, mutate in {"toolCallId": lambda e: e.update(toolCallId="tool_" + "0" * 16),
                             "resultHash": lambda e: e.update(resultHash="sha256:" + "0" * 64),
                             "args edited": lambda e: e["args"].update(k=2),
                             "result edited": lambda e: e["result"].update(notice="edited")}.items():
            ev = copy.deepcopy(t)
            mutate(ev)
            with self.subTest(name):
                self.assertTrue(validate("TraceEvent", ev))
        self.assertEqual(validate("TraceEvent", t), [])

    def test_validate_trace_catches_duplicates_and_foreign_cost_records(self):
        run = F.ex("ReviewRun")["id"]
        start = {"schema": "trace-event@1", "runId": run, "seq": 0, "type": "run.start",
                 "run": F.ex("ReviewRun")}
        a = F.model_call(run, "VERIFY", "verifier", "v-x", 0, self.sc.confirm, seq=1)
        b = F.model_call(run, "VERIFY", "verifier", "v-x", 0, {**self.sc.confirm, "verdict": "refuted"},
                         seq=2)
        self.assertEqual(validate_trace([start, a]), [])
        self.assertTrue(any(i.code == "trace-duplicate" for i in validate_trace([start, a, b])))


class A_ForgedTrust(unittest.TestCase):
    CODE = {"kind": "code", "path": "a.py", "lines": [1, 2], "commit": "a" * 40, "excerpt": "x"}

    def test_model_output_cannot_assert_resolved(self):
        self.assertTrue(validate("ModelEvidence", {**self.CODE, "resolved": True}))
        for entity, doc in (
                ("InvestigatorOutput", {"hypotheses": [{
                    "claim": "c", "category": "security", "suspectedSeverity": "P0",
                    "impact": "auth-bypass", "location": {"path": "a.py", "line": 1},
                    "evidence": [{**self.CODE, "resolved": True}]}]}),
                ("VerifierOutput", {"verdict": "confirmed", "reachable": True, "impact": "auth-bypass",
                                    "notes": "", "evidence": [{**self.CODE, "resolved": True}]})):
            with self.subTest(entity):
                self.assertTrue(validate(entity, doc))

    def test_materialize_never_copies_a_model_supplied_flag(self):
        sneaky = {**self.CODE, "resolved": True}       # bypasses the schema, as a buggy caller might
        (ev,), problems = S.materialize_evidence([sneaky], {}, "investigator")
        self.assertEqual(problems, [])
        self.assertNotIn("resolved", ev)
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, [ev]), "P2")
        self.assertEqual(S.evidence_strength([ev]), "unsupported")

    def test_resolver_must_return_literally_true(self):
        for answer in (1, "yes", [1], object()):
            with self.subTest(repr(answer)):
                out, problems = S.materialize_evidence([self.CODE], {}, "i", resolver=lambda e, a=answer: a)
                self.assertEqual((out, len(problems)), ([], 1))

    def test_resolver_exception_is_an_unresolved_citation(self):
        def boom(e):
            raise RuntimeError("x")
        out, problems = S.materialize_evidence([self.CODE], {}, "i", resolver=boom)
        self.assertEqual((out, len(problems)), ([], 1))

    def test_resolved_flag_values_other_than_true_are_not_trust(self):
        sc = F.Scenario()
        for bad in (1, "true", "yes", False, None, [True]):
            f = sc.fresh()
            f["evidence"][0]["resolved"] = bad
            with self.subTest(repr(bad)):
                self.assertTrue(F.issues("Finding", f))
                self.assertFalse(S.is_trusted({**f["evidence"][0]}))
        f = sc.fresh()
        del f["evidence"][0]["resolved"]
        self.assertTrue(F.issues("Finding", f))
        f = sc.fresh()
        del f["verification"]["evidence"][0]["resolved"]
        self.assertTrue(F.issues("Finding", f))

    def test_resolved_without_path_lines_commit_is_not_trusted(self):
        for drop in ("path", "lines", "commit"):
            e = {**self.CODE, "resolved": True}
            del e[drop]
            with self.subTest(drop):
                self.assertFalse(S.is_trusted(e))

    def test_tool_kinds_need_a_logged_ok_call(self):
        tc = F.tool_call("run_" + "1" * 16, "error", [])
        e = {"kind": "test-run", "excerpt": "ok", "source": "pytest", "toolCallId": tc["toolCallId"]}
        self.assertFalse(S.is_trusted(e, {tc["toolCallId"]: tc}))
        self.assertFalse(S.is_trusted(e, {}))


class A_SnapshotResolution(unittest.TestCase):
    def setUp(self):
        self.repo = F.Repo(self, {"a.py": "one\ntwo\nthree\n", "only_base.py": "legacy\n"},
                           {"a.py": "one\nTWO\nthree\n"})

    def resolves(self, c):
        return self.repo.resolver(c)

    def test_head_and_base_anchors(self):
        self.assertTrue(self.resolves(self.repo.cite("a.py", [2, 2], "TWO", "head")))
        self.assertTrue(self.resolves(self.repo.cite("a.py", [2, 2], "two", "base")))

    def test_base_text_cannot_be_anchored_to_head_and_vice_versa(self):
        self.assertFalse(self.resolves(self.repo.cite("a.py", [2, 2], "two", "head")))
        self.assertFalse(self.resolves(self.repo.cite("a.py", [2, 2], "TWO", "base")))

    def test_foreign_unknown_and_missing(self):
        foreign = F.Repo(self, {"a.py": "one\ntwo\nthree\nfour\n"})
        c = foreign.cite("a.py", [2, 2], "two")
        self.assertFalse(self.resolves(c), "a snapshot that is not this run's base/head")
        self.assertFalse(self.resolves({**c, "commit": "a" * 40}))
        self.assertFalse(self.resolves(self.repo.cite("only_base.py", [1, 1], "legacy", "head")))
        self.assertFalse(self.resolves(self.repo.cite("nope.py", [1, 1], "x")))
        self.assertFalse(self.resolves(self.repo.cite("../a.py", [1, 1], "one")))

    def test_disk_tampering_after_manifest_is_refused(self):
        (self.repo.dirs["head"] / "a.py").write_text("one\nEVIL\nthree\n")
        self.assertFalse(self.resolves(self.repo.cite("a.py", [2, 2], "EVIL")))

    def test_symlink_is_refused(self):
        import os
        d = self.repo.dirs["head"]
        os.symlink("a.py", d / "link.py")
        manifest = SN.build_manifest(d)
        res = SN.snapshot_resolver({manifest["snapshotId"]: (d, manifest)})
        self.assertFalse(res({"kind": "code", "path": "link.py", "lines": [1, 1], "commit":
                              manifest["snapshotId"], "excerpt": "one"}))

    def test_secret_text_is_compared_in_redacted_form(self):
        repo = F.Repo(self, {"s.py": 'k = "ghp_' + "A" * 36 + '"\n'})
        raw = 'k = "ghp_' + "A" * 36 + '"'
        self.assertFalse(repo.resolver(repo.cite("s.py", [1, 1], raw)))
        self.assertTrue(repo.resolver(repo.cite("s.py", [1, 1], R.redact(raw)[0])))

    def test_blank_real_line_with_empty_excerpt_resolves(self):
        """Guard against an over-correction of FR5: a blank line that exists is citable."""
        repo = F.Repo(self, {"b.py": "a\n\nb\n"})
        self.assertTrue(repo.resolver(repo.cite("b.py", [2, 2], "")))


class A_RemainingCorrections(unittest.TestCase):
    """Independent re-checks of RR4/RR6/RR7/RR8/RR9/RR10/RR12 beyond the re-review tests."""

    def test_timestamp_parser_is_strict(self):
        from reviewer.contracts import budget as B
        for junk in ("2026-02-30T00:00:00Z", "2026-10-25T23:59:60Z", "2026-10-25T00:00:00+00:00",
                     "2026-10-25t00:00:00z", "2026-10-25T00:00:00.1234567891Z",
                     "0000-01-01T00:00:00Z", "2026-13-01T00:00:00Z", "2026-10-25T24:00:00Z",
                     "２０２６-10-25T00:00:00Z", "2026-10-25T00:00:00Z\n", "", None, 7):
            with self.subTest(repr(junk)), self.assertRaises(ValueError):
                B.parse_timestamp(junk)
        self.assertLess(B.parse_timestamp("2026-10-25T00:00:00Z"), B.parse_timestamp("2026-10-25T00:00:00.5Z"))
        self.assertEqual(B.parse_timestamp("2026-10-25T00:00:00Z"), B.parse_timestamp("2026-10-25T00:00:00.000Z"))

    def test_total_ceiling_helper_rejects_non_integers_and_is_exact_at_the_limit(self):
        from reviewer.contracts import budget as B
        auth = F.ex("SpendAuthorization.synthetic-recording")
        limit = auth["maxUsdMicrosTotal"]
        self.assertIsNone(B.admit_total(auth, limit - 5, 5, "VERIFY"))
        self.assertIsNotNone(B.admit_total(auth, limit - 5, 6, "VERIFY"))
        for bad in (-1, True, 0.5, 10 ** 30, "1", None):
            with self.subTest(repr(bad)), self.assertRaises(ValueError):
                B.admit_total(auth, bad, 1, "VERIFY")

    def test_per_request_authorization(self):
        from reviewer.contracts import budget as B
        auth = F.ex("SpendAuthorization.synthetic-recording")
        req = F.ex("TraceEvent.model-call")["request"]
        self.assertEqual(B.check_request_authorized(auth, req), [])
        for change in ({"provider": "openai"}, {"model": "gpt-x"}, {"provider": ["synthetic"]}):
            with self.subTest(change):
                self.assertTrue(B.check_request_authorized(auth, {**req, **change}))

    def test_redaction_fixpoint_fuzz(self):
        rng = random.Random(20261025)
        frags = ["AIza" + "B" * 35, "ghp_" + "A" * 36, "[REDACTED:x]", 'password = "', '"', "Bearer ",
                 "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", "\n", "\r\n",
                 "sk-" + "a" * 40, "RVWCANARY_" + "Z" * 16, " ", "AKIA" + "A" * 16, "x"]
        for _ in range(4000):
            s = "".join(rng.choice(frags) for _ in range(rng.randint(1, 12)))
            out, _ = R.redact(s)
            self.assertFalse(R.contains_protected(out), repr(s))
            self.assertEqual(R.redact(out)[0], out, repr(s))
            self.assertEqual(out.count("\n"), s.count("\n"), repr(s))

    def test_redaction_is_not_quadratic_on_repeated_near_matches(self):
        import time
        for unit in ("AIza", "ghp_", "[REDACTED:x]", 'password = "', "Bearer "):
            t = time.monotonic()
            R.redact(unit * 40000)
            self.assertLess(time.monotonic() - t, 5.0, unit)


# ====================================================================================== FR: defects

class FR1_VerificationIsNotBoundToTheFinding(ScenarioCase):
    """check_finding_provenance proves *a* confirmed VERIFY/verifier call exists in the run. It does
    not prove that call verified THIS finding, and the Finding's own claims are never compared with
    what the verifier returned. Severity (P0/P1) is computed from the Finding's severityBasis."""

    def test_FR1a_verifier_call_for_another_hypothesis_cannot_confirm_this_finding(self):
        other = F.model_call(self.sc.run, "VERIFY", "verifier", "v-hyp_ffffffffffffffff", 0,
                             self.sc.confirm, seq=2)
        f = self.sc.fresh()
        f["verification"]["callIds"] = [other["callId"]]
        self.assertRejected(f, [self.sc.inv, other],
                            "confirmation recorded for another hypothesis is accepted for this one",
                            "does not name this hypothesis")
        # The subject must be the point: the same call with the right subject is accepted.
        right = F.model_call(self.sc.run, "VERIFY", "verifier", "v-hyp_ffffffffffffffff", 0,
                             self.sc.confirm, seq=2, hyp=f["id"])
        f["verification"]["callIds"] = [right["callId"]]
        self.assertEqual(provenance(self.sc, f, [self.sc.inv, right]), [])
        # and a verifier request with NO subject cannot confirm anything
        bare = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + f["id"], 0, self.sc.confirm,
                            seq=2, hyp=False)
        self.assertNotIn("hypothesisId", bare["request"])
        g = self.sc.fresh()
        g["verification"]["callIds"] = [bare["callId"]]
        self.assertRejected(g, [self.sc.inv, bare], "verifier request without a subject",
                            "does not name this hypothesis")

    def test_FR1b_source_call_must_have_proposed_this_hypothesis(self):
        empty = F.model_call(self.sc.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                             {"hypotheses": []}, seq=1)
        other_claim = copy.deepcopy(self.sc.inv)
        other_claim["response"]["output"]["hypotheses"][0]["claim"] = "A different claim"
        other_claim["request"]["messages"][0]["content"] = "different"
        other_claim["requestHash"] = C.request_hash(other_claim["request"])
        for name, inv in (("zero hypotheses", empty), ("different claim", other_claim)):
            f = self.sc.fresh()
            f["sourceCallId"] = inv["callId"]
            with self.subTest(name):
                self.assertRejected(f, [inv, self.sc.ver],
                                    "Finding names a source call whose output never contained it",
                                    "proposed no hypothesis with this id")

    def test_FR1c_finding_severity_basis_must_equal_what_the_verifier_returned(self):
        """Verifier says unreachable / different impact; Finding still records reachable auth-bypass,
        which finding_ceiling turns into P0."""
        for name, changes in (("verifier says reachable=false", {"reachable": False}),
                              ("verifier impact differs", {"impact": "maintainability"})):
            ver = self.sc.verifier(**changes)
            f = self.sc.fresh()
            f["verification"]["callIds"] = [ver["callId"]]
            with self.subTest(name):
                self.assertRejected(f, [self.sc.inv, ver], "Finding.severityBasis contradicts the verifier call",
                                    "severityBasis differs")
        self.assertEqual(S.finding_ceiling(self.sc.fresh()), "P0")   # context: why this matters

    def test_FR1d_verification_evidence_must_come_from_the_verifier_calls(self):
        f = self.sc.fresh()
        f["verification"]["evidence"][0]["path"] = "somewhere/never_cited.py"
        self.assertRejected(f, self.sc.events,
                            "Finding.verification.evidence cites a location no listed verifier call cited",
                            "was not cited by a confirming verifier call")
        g = self.sc.fresh()
        g["verification"]["evidence"][0]["excerpt"] = "text the verifier never returned"
        self.assertRejected(g, self.sc.events, "verification excerpt differs from the verifier's citation",
                            "was not cited by a confirming verifier call")


class FR2_TraceOrderAndDuplicates(ScenarioCase):
    def test_FR2a_duplicate_call_id_is_rejected_in_either_order(self):
        refuted = self.sc.verifier(verdict="refuted")
        self.assertEqual(refuted["callId"], self.sc.ver["callId"])
        for name, evs in (("refuted then confirmed", [self.sc.inv, refuted, self.sc.ver]),
                          ("confirmed then refuted", [self.sc.inv, self.sc.ver, refuted])):
            with self.subTest(name):
                self.assertRejected(self.sc.fresh(), evs, "same callId logged twice with opposite verdicts",
                                    "logged more than once")

    def test_FR2b_verifier_logged_before_the_source_call_cannot_have_verified_it(self):
        ver_first = copy.deepcopy(self.sc.ver)
        ver_first["seq"] = 1
        inv_late = copy.deepcopy(self.sc.inv)
        inv_late["seq"] = 2
        self.assertRejected(self.sc.fresh(), [ver_first, inv_late], "verifier seq precedes investigator seq",
                            "logged before the source call")
        same = copy.deepcopy(self.sc.ver)          # equal seq is not "after" either
        same["seq"] = self.sc.inv["seq"]
        self.assertRejected(self.sc.fresh(), [self.sc.inv, same], "verifier seq equals source seq",
                            "logged before the source call")


class FR3_RequestDisagreesWithEvent(ScenarioCase):
    def test_FR3_event_role_and_stage_must_match_the_request_that_was_sent(self):
        """A model.call labelled VERIFY/verifier whose logged request is an investigator request
        (role + outputSchema) validates today; its ids recompute from the event fields only."""
        ev = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0,
                          self.sc.confirm, seq=2, req_role="investigator",
                          out_schema="InvestigatorOutput")
        got = [i.path for i in validate("TraceEvent", ev)]
        self.assertTrue(got, "event role=verifier vs request role=investigator")
        self.assertIn("$.request.role", got)
        ev2 = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0,
                           self.sc.confirm, seq=2, out_schema="InvestigatorOutput")
        self.assertIn("$.request.outputSchema", [i.path for i in validate("TraceEvent", ev2)])
        # Consequence for provenance: such an event is not usable as the confirming call.
        f = self.sc.fresh()
        f["verification"]["callIds"] = [ev2["callId"]]
        self.assertRejected(f, [self.sc.inv, ev2], "mislabelled request used as the verifier",
                            "is not a logged model call")


class FR4_ToolEvidenceProvenance(ScenarioCase):
    def test_FR4_non_code_evidence_must_match_an_ok_logged_result(self):
        errored = F.tool_call(self.sc.run, "error", [])
        history = F.tool_call(self.sc.run, "ok", [{"kind": "history", "excerpt": "blame", "source": "git",
                                                   "toolCallId": "tool_" + "0" * 16}], agent="v-h",
                              tool="git")
        for name, call, kind in (("errored tool call", errored, "test-run"),
                                 ("kind not present in the logged result", history, "test-run")):
            f = self.sc.fresh()
            f["evidence"].append({"kind": kind, "excerpt": "1 passed", "source": "pytest",
                                  "toolCallId": call["toolCallId"]})
            with self.subTest(name):
                self.assertEqual(F.issues("Finding", f), [])
                self.assertRejected(f, [*self.sc.events, call], f"{name}: provenance accepts untrusted tool evidence",
                                    "whose result is error" if call is errored
                                    else "is not an item of the named tool call's result")
                tc = {call["toolCallId"]: call}
                self.assertFalse(S.is_trusted(f["evidence"][-1], tc), "severity already ignores it")


class FR5_ResolverLeniency(unittest.TestCase):
    def test_FR5a_lines_beyond_end_of_file_do_not_resolve(self):
        repo = F.Repo(self, {"a.py": "one\ntwo\nthree\n"})
        self.assertFalse(repo.resolver(repo.cite("a.py", [4, 4], "")), "line 4 of a 3-line file")
        self.assertFalse(repo.resolver(repo.cite("a.py", [3, 4], "three")), "range runs past EOF")
        self.assertFalse(repo.resolver(repo.cite("a.py", [5, 9], "")), "entirely past EOF")

    def test_FR5b_trailing_blank_excerpt_lines_are_not_ignored(self):
        """excerpt_matches documents 'ignoring only a single trailing newline' but rstrip('\\n')
        removes every trailing newline from both sides."""
        repo = F.Repo(self, {"a.py": "one\ntwo\nthree\n"})
        self.assertTrue(repo.resolver(repo.cite("a.py", [1, 3], "one\ntwo\nthree")))
        self.assertTrue(repo.resolver(repo.cite("a.py", [1, 3], "one\ntwo\nthree\n")))
        self.assertFalse(repo.resolver(repo.cite("a.py", [1, 3], "one\ntwo\nthree\n\n\n")))


class FR6_RepairChainCountsTwice(ScenarioCase):
    def test_FR6_a_call_and_its_own_repair_are_one_verification(self):
        rep = F.model_call(self.sc.run, "VERIFY", "verifier", "v-" + self.sc.finding["id"], 0,
                           self.sc.confirm, attempt=1, repair_of=self.sc.ver["callId"], seq=3)
        f = self.sc.fresh()
        f["verification"]["callIds"] = [self.sc.ver["callId"], rep["callId"]]
        self.assertRejected(f, [*self.sc.events, rep],
                            "callIds lists a call and its repair as two independent confirmations",
                            "repeats a listed verification")


# ====================================================================================== C: limits

class C_PinnedLimits(ScenarioCase):
    """These pass today. They record what the contract does NOT guarantee, so a green run is not
    read as more than it is."""

    def test_C1_provenance_trusts_the_resolved_flag_it_never_re_resolves(self):
        """The nonexistent citation is present in BOTH model outputs (so FR1d is satisfied: the
        proposer and the verifier really cited it) and the Finding carries a forged
        `resolved: true` copy of it. check_finding_provenance has no snapshot, so it passes.
        Only snapshot.snapshot_resolver (S0-07) can refuse it."""
        ghost = {"kind": "code", "path": "does/not/exist.py", "lines": [1, 2],
                 "commit": self.sc.finding["evidence"][0]["commit"], "excerpt": "fabricated"}
        f = self.sc.fresh()
        for e in (f["evidence"][0], f["verification"]["evidence"][0]):
            e.update({k: ghost[k] for k in F.Scenario.CODE_KEYS})
            self.assertIs(e["resolved"], True)                       # forged by hand
        hyp = {**self.sc.inv["response"]["output"]["hypotheses"][0], "evidence": [ghost]}
        inv = F.model_call(self.sc.run, "INVESTIGATE", "investigator", "generalist-0", 0,
                           {"hypotheses": [hyp]}, seq=1)
        ver = self.sc.verifier(evidence=[ghost])
        self.assertEqual(F.issues("Finding", f), [])
        self.assertEqual(provenance(self.sc, f, [inv, ver]), [],
                         "check_finding_provenance has no snapshot; S0-07 must resolve via snapshot_resolver")
        # The same ghost citation is refused by the real resolver, which is the actual defence.
        repo = F.Repo(self, {"src/auth.py": "def f(t):\n    return True\n"})
        self.assertFalse(repo.resolver({**ghost, "commit": repo.head_id}))
        _, problems = repo.materialize({**ghost, "commit": repo.head_id})
        self.assertEqual(len(problems), 1)
        # Control: removing it from the verifier output (only the Finding claims it) is rejected.
        self.assertRejected(f, [inv, self.sc.ver], "Finding verification evidence the verifier never cited",
                            "was not cited")

    def test_C2_a_consistently_forged_trace_is_accepted(self):
        """Ids are recomputable by anyone, so payload binding detects inconsistency, not forgery.
        Authenticity of trace.jsonl is the gateway's responsibility (no signature or hash chain)."""
        fake_inv = F.model_call(self.sc.run, "INVESTIGATE", "investigator", "made-up", 9, {"hypotheses": []}, seq=1)
        fake_ver = F.model_call(self.sc.run, "VERIFY", "verifier", "made-up", 9, self.sc.confirm, seq=2)
        f = self.sc.fresh()
        f["sourceCallId"], f["verification"]["callIds"] = fake_inv["callId"], [fake_ver["callId"]]
        self.assertEqual(validate("TraceEvent", fake_ver), [])
        # NOTE: asserts the limit only for the id binding; FR1b/FR1a would additionally reject this.
        self.assertTrue(isinstance(check_finding_provenance(f, [fake_inv, fake_ver]), list))

    def test_C3_crlf_files_need_the_carriage_return_in_the_excerpt(self):
        repo = F.Repo(self, {"w.py": b"x = 1\r\ny = 2\r\n"})
        self.assertFalse(repo.resolver(repo.cite("w.py", [1, 2], "x = 1\ny = 2")))
        self.assertTrue(repo.resolver(repo.cite("w.py", [1, 2], "x = 1\r\ny = 2\r")))

    def test_C4_a_finding_may_carry_code_evidence_with_a_toolcallid_that_is_never_checked(self):
        """S1-01 review: this @5 pinned LIMIT is closed by D2 (S1-01 @6). Assertion CHANGED from
        `== []` to rejected: code evidence carrying a toolCallId is now checked like a tool item. The
        accepting counterpart (an exact read_file item reached through a cited tool-ref) is
        test_contract_s1review.py::D2_*."""
        f = self.sc.fresh()
        f["verification"]["evidence"][0]["toolCallId"] = "tool_" + "9" * 16
        self.assertTrue(any("names a tool call not logged" in m
                            for m in provenance(self.sc, f, self.sc.events)))


if __name__ == "__main__":
    unittest.main()
