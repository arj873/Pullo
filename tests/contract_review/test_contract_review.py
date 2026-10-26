"""Independent review tests for S0-03 contracts (reviewer-owned, offline, stdlib only).

Convention: a test named `test_*` asserts the CORRECT behaviour, so a FAIL/ERROR is a
reproduced defect (IDs match orchestration/handoffs/S0-03-review.md). Classes named
`Characterization_*` pin current behaviour for product-direction decisions and PASS today.
No __init__.py on purpose: the author's `discover -s tests -t .` must not collect these.

Run:  nice -n 19 python3 -m unittest discover -s tests/contract_review -v
"""
from __future__ import annotations

import copy
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import REGISTRY, export_bundle, validate  # noqa: E402
from reviewer.contracts import budget as B  # noqa: E402
from reviewer.contracts import canonical as C  # noqa: E402
from reviewer.contracts import redaction as R  # noqa: E402
from reviewer.contracts import severity as S  # noqa: E402
from reviewer.contracts import snapshot as SN  # noqa: E402

from tests.contract_review import finalreview_support as F  # noqa: E402  (tests/contract_review is on sys.path under discover)

EXAMPLES = ROOT / "reviewer" / "contracts" / "examples"


def ex(name):
    return json.loads((EXAMPLES / f"{name}.json").read_text())


def no_crash(test, fn, what):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        test.fail(f"{what} raised {type(e).__name__}: {str(e)[:120]}")


# ------------------------------------------------------------------ V: validator robustness
class V_ValidatorCrashes(unittest.TestCase):
    def test_V1_union_tag_unhashable(self):
        issues = no_crash(self, lambda: validate("TraceEvent", {"type": []}), "validate(TraceEvent, type=[])")
        self.assertTrue(issues)

    def test_V2_num_huge_int(self):
        doc = {"value": 10 ** 400, "numerator": 1, "denominator": 1, "undefinedReason": None}
        issues = no_crash(self, lambda: validate("Ratio", doc), "validate(Ratio, value=10**400)")
        self.assertTrue(issues)

    def test_V3_deep_nesting_is_an_issue_not_a_crash(self):
        deep = cur = []
        for _ in range(3000):
            nxt = []
            cur.append(nxt)
            cur = nxt
        doc = {"status": "ok", "resolvedModel": "m", "output": deep, "rawText": None,
               "usage": ex("CostRecord.eval-synthetic")["usage"]}
        issues = no_crash(self, lambda: validate("ModelResponse", doc), "validate(deeply nested output)")
        self.assertTrue(issues, "unbounded nesting accepted")

    def test_V4_lone_surrogate_rejected_by_validator(self):
        """json.loads('"\\ud800"') yields a str that cannot be UTF-8 encoded, so hashing crashes later."""
        doc = {"code": "internal", "message": "bad \ud800", "retryable": False}
        self.assertTrue(validate("TypedError", doc), "validator accepts a string canonical_json cannot encode")

    def test_V5_canonical_json_lone_surrogate(self):
        """Adjudicated rev2: canonicalising a non-UTF-8 string is a typed ValueError (never UnicodeEncodeError);
        validate() and loads_strict() reject it first (V4)."""
        for fn in (C.canonical_json, C.digest):
            with self.assertRaises(ValueError) as cm:
                fn({"a": "\ud800"})
            self.assertNotIsInstance(cm.exception, UnicodeError)


# ------------------------------------------------------------------ N: nonfinite / canonical / collisions
class N_Canonical(unittest.TestCase):
    def test_N1_int_and_str_keys_collide(self):
        a, b = None, None
        try:
            a = C.canonical_json({1: "x"})
        except (TypeError, ValueError):
            return  # rejected: correct
        b = C.canonical_json({"1": "x"})
        self.assertNotEqual(a, b, "non-string key silently collides with its string form")

    def test_N2_bool_key_collision(self):
        try:
            a = C.canonical_json({True: 1})
        except (TypeError, ValueError):
            return
        self.assertNotEqual(a, C.canonical_json({"true": 1}))

    def test_N3_tuple_and_list_same_hash(self):
        """Python-only types hash like JSON arrays; docs must be pure JSON before hashing."""
        with self.assertRaises((TypeError, ValueError)):
            C.canonical_json({"a": (1, 2)})

    def test_CONTROL_nan_rejected(self):
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                C.canonical_json({"a": bad})

    def test_N4_negative_zero_and_int_float_forms(self):
        """1 vs 1.0 vs -0.0 are one JSON value to other languages but three digests here."""
        self.assertEqual(C.digest({"n": 1}), C.digest({"n": 1.0}),
                         "canonical form is not stable across int/float spellings of one JSON number")

    def test_CONTROL_derive_id_prefix_validated(self):
        with self.assertRaises(ValueError):
            C.derive_id("Run", 1)

    def test_N5_request_hash_accepts_unredacted_secret(self):
        req = {"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]}
        with self.assertRaises(Exception):
            C.request_hash(req)

    def test_N6_request_hash_accepts_run_scoped_id(self):
        req = {"runId": "run_0123456789abcdef", "messages": []}
        with self.assertRaises(Exception):
            C.request_hash(req)

    def test_N7_fingerprint_case_collision(self):
        a = C.comment_fingerprint("bug", "a.py", "Foo = 1", "Foo is shadowed")
        b = C.comment_fingerprint("bug", "a.py", "foo = 1", "foo is shadowed")
        self.assertNotEqual(a, b, "case-sensitive identifiers fingerprint identically")


class Characterization_Identity(unittest.TestCase):
    def test_repo_identity_policy_D8(self):
        """D8: GitHub 'Owner/Name' keeps display case; identity folds case; PR runs need the GitHub form."""
        d = ex("ReviewRun.github-pr")
        self.assertEqual(validate("ReviewRun", d), [])
        self.assertEqual(C.idempotency_key_pr("Vencord/Vesktop", 1347, "a" * 40),
                         C.idempotency_key_pr("vencord/vesktop", 1347, "a" * 40))
        self.assertNotEqual(C.idempotency_key_pr("Vencord/Vesktop", 1347, "a" * 40),
                            C.idempotency_key_pr("Vencord/Vesktop", 1348, "a" * 40))
        pr = copy.deepcopy(d)
        pr["repo"] = "fixture-slug"                      # opaque slug is not a PR repo
        self.assertTrue(validate("ReviewRun", pr))

    def test_ids_are_unique_per_run_only(self):
        """DECISION D6: content ids exclude runId; stores key by (runId, id) via scoped_key."""
        c1 = C.call_id("INVESTIGATE", "investigator", "a1", 0, 0)
        self.assertEqual(C.cost_id(c1), C.cost_id(C.call_id("INVESTIGATE", "investigator", "a1", 0, 0)))
        self.assertNotEqual(C.scoped_key("run_" + "0" * 16, c1), C.scoped_key("run_" + "1" * 16, c1))


# ------------------------------------------------------------------ I: identity is documented but not enforced
class I_IdentityNotEnforced(unittest.TestCase):
    def test_I1_run_id_must_equal_run_id_fn(self):
        d = ex("ReviewRun")
        d["id"] = "run_ffffffffffffffff"
        self.assertTrue(validate("ReviewRun", d), "ReviewRun.id not checked against run_id(key, attempt)")

    def test_I2_eval_idempotency_key_must_match_fields(self):
        d = ex("ReviewRun")
        d["idempotencyKey"] = "idem:eval:" + "0" * 64
        self.assertTrue(validate("ReviewRun", d), "eval idempotencyKey not recomputed from its fields")

    def test_I3_local_run_may_not_use_pr_key(self):
        d = ex("ReviewRun")
        d.update(trigger="cli", source="local", idempotencyKey="idem:pr:" + "0" * 64)
        for k in ("evalRunId", "evalCaseId", "repeat"):
            d.pop(k)
        self.assertTrue(validate("ReviewRun", d), "key family not tied to source")

    def test_I4_comment_id_must_derive_from_fingerprint(self):
        d = ex("Comment")
        d["id"] = "cmt_ffffffffffffffff"
        self.assertTrue(validate("Comment", d), "Comment.id != comment_id(fingerprint) accepted")

    def test_I5_cost_id_must_derive_from_subject(self):
        d = ex("CostRecord.eval-synthetic")
        d["id"] = "cost_ffffffffffffffff"
        self.assertTrue(validate("CostRecord", d), "CostRecord.id != cost_id(callId) accepted")

    def test_I6_attempt2_rerunOf_must_be_attempt1_id(self):
        d = ex("ReviewRun")
        d.update(attempt=2, trigger="manual-rerun", rerunOf="run_ffffffffffffffff")
        for k in ("evalRunId", "evalCaseId", "repeat"):
            d.pop(k)
        d["idempotencyKey"] = "idem:local:" + "1" * 64
        d["id"] = C.run_id(d["idempotencyKey"], 2)
        self.assertTrue(validate("ReviewRun", d), "rerunOf not checked against run_id(key, attempt-1)")

    def test_I7_completed_run_cannot_carry_incomplete_or_error(self):
        d = ex("ReviewRun")
        d["incomplete"] = [{"stage": "VERIFY", "reason": "deadline"}]
        self.assertTrue(validate("ReviewRun", d), "status=completed with incomplete[] accepted")
        d = ex("ReviewRun")
        d["error"] = {"code": "internal", "message": "x", "retryable": False}
        self.assertTrue(validate("ReviewRun", d), "status=completed with error accepted")

    def test_I8_profile_id_with_underscore_cannot_be_referenced(self):
        d = ex("ModelProfile.smoke-synthetic")
        d["id"] = "smoke_synthetic"
        self.assertEqual(validate("ModelProfile", d), [])      # id is valid...
        ref = "smoke_synthetic@1"
        issues = validate("Plan", {**ex("Plan"), "modelProfile": ref})
        self.assertFalse(issues, f"...but its own reference is rejected: {issues[:1]}")



# ------------------------------------------------------------------ D: comparable_digest / replay identity
class D_ReplayIdentity(unittest.TestCase):
    def test_D1_content_keys_named_like_volatile_keys_are_not_stripped(self):
        a = {"tool": "grep", "args": {"at": "src/a.py", "pattern": "x"}}
        b = {"tool": "grep", "args": {"at": "src/b.py", "pattern": "x"}}
        self.assertNotEqual(C.comparable_digest(a), C.comparable_digest(b),
                            "strip_keys removes data keys by name at any depth (tool args, model output)")

    def test_D2_model_output_with_runId_key_is_content(self):
        a = {"output": {"runId": "A", "verdict": "confirmed"}}
        b = {"output": {"runId": "B", "verdict": "confirmed"}}
        self.assertNotEqual(C.comparable_digest(a), C.comparable_digest(b))

    def test_D3_recorded_and_replayed_ReviewRun_are_comparable(self):
        """The same case replayed under a new evalRun: only run-scoped fields differ, so the digest
        should match. id / idempotencyKey / mode / status are run-scoped but are not stripped."""
        rec = ex("ReviewRun")
        rep = copy.deepcopy(rec)
        rep["evalRunId"] = "evr_0000000000000001"
        rep["idempotencyKey"] = C.idempotency_key_eval(rep["evalRunId"], rep["evalCaseId"], rep["repeat"],
                                                       rep["baseSnapshotId"], rep["headSnapshotId"])
        rep["id"] = C.run_id(rep["idempotencyKey"], rep["attempt"])
        rep["replayOf"] = rec["id"]
        self.assertEqual(C.comparable_digest(rec), C.comparable_digest(rep))

    def test_D4_recorded_and_replayed_CostRecord_are_comparable(self):
        rec = ex("CostRecord.eval-synthetic")
        rep = copy.deepcopy(rec)
        rep.update(basis="replayed", replayOf=rec["id"], runId="run_0000000000000001",
                   evalRunId="evr_0000000000000001")
        self.assertEqual(C.comparable_digest(rec), C.comparable_digest(rep))

    def test_CONTROL_comment_comparable_across_runs(self):
        a = ex("Comment")
        b = copy.deepcopy(a)
        b["runId"] = "run_0000000000000001"
        self.assertEqual(C.comparable_digest(a), C.comparable_digest(b))

    def test_CONTROL_comparable_digest_sees_semantic_change(self):
        a = ex("Comment")
        b = copy.deepcopy(a)
        b["severity"] = "P1"
        self.assertNotEqual(C.comparable_digest(a), C.comparable_digest(b))

    def test_D5_no_helper_defines_resultHash_or_other_digests(self):
        """resultHash, inputDigest, configDigest, suiteDigest, profile digest: undefined recipes."""
        names = [n for n in dir(C) if "result" in n.lower() or "hash" in n.lower()]
        self.assertIn("result_hash", names, f"only {names}; strict replay needs one recipe for tool.resultHash")


# ------------------------------------------------------------------ X: redaction
class X_Redaction(unittest.TestCase):
    AWS = "AKIAIOSFODNN7EXAMPLE"

    def test_X1_secret_preceded_by_underscore_or_letter(self):
        for s in (f"AWS_KEY_{self.AWS}", f"x{self.AWS}", f"key_sk-{'a' * 24}", f"tok_ghp_{'a' * 36}"):
            with self.subTest(s):
                out, _ = R.redact(s)
                self.assertTrue(out.count("[REDACTED") >= 1, f"leaked: {out}")

    def test_X2_common_secret_formats_missing(self):
        samples = {
            "stripe": "sk_live_" + "a" * 24,
            "google-api": "AIza" + "B" * 35,
            "gitlab": "glpat-" + "c" * 20,
            "jwt": "eyJhbGciOiJIUzI1NiJ9." + "e" * 20 + "." + "f" * 20,
            "url-creds": "postgres://admin:hunter2hunter2@db.internal:5432/app",
            "bearer": "Authorization: Bearer " + "g" * 30,
            "aws-secret": 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            "generic-assign": 'password = "Tr0ub4dor&3xyz"',
        }
        for name, s in samples.items():
            with self.subTest(name):
                self.assertNotEqual(R.redact(s)[0], s, f"{name} not redacted")

    def test_X3_redact_json_key_collision_drops_values(self):
        k1, k2 = "AKIAIOSFODNN7EXAMPLA", "AKIAIOSFODNN7EXAMPLB"
        out, _ = R.redact_json({k1: "one", k2: "two"})
        self.assertEqual(len(out), 2, f"distinct keys collapsed into {out}")

    def test_X4_redaction_preserves_line_numbers(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\nBBBB\n-----END RSA PRIVATE KEY-----"
        text = "line1\n" + pem + "\nline6\n"
        out, _ = R.redact(text)
        self.assertEqual(out.count("\n"), text.count("\n"), "redaction shifts later line numbers (Evidence.lines)")

    def test_X5_persisted_entities_reject_protected_text(self):
        d = ex("Comment")
        d["body"] = f"leaked {self.AWS}"
        self.assertTrue(validate("Comment", d), "contract accepts un-redacted secret in persisted Comment")
        e = ex("Finding")
        e["evidence"][0]["excerpt"] = f"token = '{self.AWS}'"
        self.assertTrue(validate("Finding", e), "contract accepts un-redacted secret in Evidence.excerpt")

    def test_CONTROL_redact_idempotent_and_keys_redacted(self):
        t = f"a {self.AWS} b"
        once, _ = R.redact(t)
        self.assertEqual(R.redact(once)[0], once)
        out, _ = R.redact_json({self.AWS: 1})
        self.assertNotIn(self.AWS, json.dumps(out))

    def test_CONTROL_redaction_not_quadratic(self):
        import time
        for s in ("-----BEGIN " * 20000, "-----BEGIN " + "A " * 200000, "sk-" + "a" * 500000):
            t = time.monotonic()
            R.redact(s)
            self.assertLess(time.monotonic() - t, 3)


# ------------------------------------------------------------------ B: budget
BUDGET = dict(B.STANDARD_S0A_BUDGET)
PRICE = {"priceVersion": "t@1", "inputPerMTokUsdMicros": 3_000_000, "cachedInputPerMTokUsdMicros": 300_000,
         "cacheWriteInputPerMTokUsdMicros": 3_750_000, "outputPerMTokUsdMicros": 15_000_000}


class B_Budget(unittest.TestCase):
    def test_B1_negative_reservation_is_not_a_credit(self):
        full = B.Spend(committed=BUDGET["maxUsdMicros"])
        try:
            r = B.admit_model_call(BUDGET, full, "VERIFY", -1_000_000)
        except (ValueError, TypeError):
            return
        self.assertIsNotNone(r, "negative reserve admitted against an exhausted budget")

    def test_B2_nan_reservation_bypasses_ceiling(self):
        full = B.Spend(committed=BUDGET["maxUsdMicros"])
        try:
            r = B.admit_model_call(BUDGET, full, "VERIFY", float("nan"))
        except (ValueError, TypeError):
            return
        self.assertIsNotNone(r, "NaN reserve admitted: `nan > limit` is False")

    def test_B3_negative_or_nan_spend_state(self):
        try:
            r = B.admit_model_call(BUDGET, B.Spend(committed=-10 ** 9), "VERIFY", 5_000_000)
        except (ValueError, TypeError):
            return
        self.assertIsNotNone(r, "negative committed spend gives free headroom")

    def test_B4_reservation_covers_cache_write_pricing(self):
        """Handoff: 'worst-case reservation ... overrun allowance is 0%'. Reservation prices every input
        token at the plain input price; a cache-write-heavy response costs more."""
        tokens, out = 100_000, 4_000
        reserve = B.reservation(PRICE, tokens, out)
        usage = {"uncachedInputTokens": 0, "cachedInputTokens": 0, "cacheWriteInputTokens": tokens,
                 "outputTokens": out, "reasoningTokens": 0}
        usd, basis, overrun = B.settle(reserve, usage, PRICE)    # rev2: (usd, basis, overrun)
        self.assertLessEqual(usd, reserve, f"settled {usd} > reserved {reserve} (basis {basis})")
        self.assertFalse(overrun)

    def test_B5_unknown_cache_split_must_not_undercharge(self):
        reserve = B.reservation(PRICE, 100_000, 4_000)
        usage = {"uncachedInputTokens": 1_000, "cachedInputTokens": None, "cacheWriteInputTokens": None,
                 "outputTokens": 100, "reasoningTokens": None}
        usd, basis, _overrun = B.settle(reserve, usage, PRICE)   # rev2: 3-tuple
        self.assertEqual(basis, "estimated")
        self.assertGreaterEqual(usd, reserve, "unknown cache tokens priced at zero; 'unknown is never zero'")

    def test_B6_settle_does_not_flag_overrun(self):
        reserve = 1_000
        usage = {"uncachedInputTokens": 10_000_000, "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
                 "outputTokens": 0, "reasoningTokens": 0}
        out = B.settle(reserve, usage, PRICE)
        self.assertEqual(len(out), 3, "settle returns (usd, basis) only; actual>reserved is silent")

    def test_B7_no_atomic_reserve_api(self):
        """Admission is a pure function over a Spend snapshot: concurrent agents can both pass."""
        has = [n for n in dir(B) if n.lower() in ("ledger", "budgetledger", "reserve", "release")]
        self.assertTrue(has, "no Ledger/reserve/release: in-flight bookkeeping and atomicity are unspecified")

    def test_B8_no_release_rule_for_calls_known_not_billed(self):
        has = [n for n in dir(B) if "release" in n.lower() or "refund" in n.lower()]
        self.assertTrue(has, "rejected (4xx/pre-flight) calls keep full worst-case reservation charged")

    def test_B9_deadline_logic_exists_if_acceptance_map_cites_budget_py(self):
        has = [n for n in dir(B) if "deadline" in n.lower()]
        self.assertTrue(has, "acceptance map cites budget.py for deadlines; module has only a docstring")

    def test_CONTROL_inflight_counts_toward_ceiling(self):
        sp = B.Spend(committed=0, inflight=BUDGET["maxUsdMicros"] - 10)
        self.assertIsNotNone(B.admit_model_call(BUDGET, sp, "VERIFY", 11))
        self.assertIsNone(B.admit_model_call(BUDGET, sp, "VERIFY", 10))

    def test_CONTROL_investigate_share(self):
        lim = B.investigation_limit(BUDGET)
        self.assertEqual(lim, 2_800_000)
        sp = B.Spend(committed_investigate=lim - 1, committed=lim - 1)
        self.assertIsNotNone(B.admit_model_call(BUDGET, sp, "INVESTIGATE", 2))
        self.assertIsNone(B.admit_model_call(BUDGET, sp, "VERIFY", 2))



class Characterization_BudgetAuthorization(unittest.TestCase):
    def test_two_retry_limits_have_a_stated_precedence(self):
        """D7: effective retries = min(Budget.maxRetriesPerCall, caps.maxRetries); repairs <= 1."""
        self.assertEqual(B.effective_retry_limits({"maxRetriesPerCall": 0}, {"maxRetries": 3, "maxRepairs": 1}), (0, 1))
        self.assertEqual(B.effective_retry_limits({"maxRetriesPerCall": 3}, {"maxRetries": 2, "maxRepairs": 0}), (2, 0))

    def test_spend_authorization_must_be_a_digest_not_any_string(self):
        """D5 policy: 'x' is invalid; a digest of a trusted SpendAuthorization is valid for live modes."""
        d = ex("ReviewRun")
        for k in ("evalRunId", "evalCaseId", "repeat", "replayOf"):
            d.pop(k)
        d.update(mode="live", trigger="cli", idempotencyKey=C.idempotency_key_local(
            d["repo"], d["baseSnapshotId"], d["headSnapshotId"]))
        d["id"] = C.run_id(d["idempotencyKey"], 1)
        d["spendAuthorization"] = "x"
        self.assertTrue(validate("ReviewRun", d))
        d["spendAuthorization"] = B.authorization_digest(ex("SpendAuthorization.synthetic-recording"))
        self.assertEqual(validate("ReviewRun", d), [])

    def test_stage_replay_is_offline_and_may_not_carry_authorization(self):
        d = ex("ReviewRun")
        d.update(mode="stage-replay", fromStage="VERIFY")
        self.assertEqual(validate("ReviewRun", d), [])
        d["spendAuthorization"] = B.authorization_digest(ex("SpendAuthorization.synthetic-recording"))
        self.assertTrue(validate("ReviewRun", d))

    def test_budget_integer_policy(self):
        """D9: ceilings are bounded (<= $1000 per run); beyond 2**53 is never valid."""
        b = ex("Plan")["budget"]
        self.assertEqual(validate("Budget", {**b, "maxUsdMicros": 10 ** 9}), [])
        self.assertTrue(validate("Budget", {**b, "maxUsdMicros": 10 ** 9 + 1}))
        self.assertTrue(validate("Budget", {**b, "maxUsdMicros": 10 ** 30}))


# ------------------------------------------------------------------ S: severity / P0
class S_Severity(unittest.TestCase):
    def ev(self, path="src/auth.py", kind="code"):
        return {"kind": kind, "path": path, "lines": [1, 2], "commit": "a" * 40, "excerpt": "x",
                "source": "read_file"}

    def test_S1_model_authored_evidence_cannot_claim_strong_kinds(self):
        """InvestigatorOutput/VerifierOutput reuse Evidence, whose `kind` the MODEL writes. A model can
        label evidence `analyzer`/`test-run` + any well-formed toolCallId; severity.py then lifts the
        P0 ceiling (it only counts kinds). Strong kinds must be minted by the tool layer."""
        fake = {"kind": "analyzer", "excerpt": "tainted flow", "source": "model",
                "toolCallId": "tool_0123456789abcdef"}
        hyp = {"claim": "c", "category": "security", "suspectedSeverity": "P0", "impact": "auth-bypass",
               "location": {"path": "a.py", "line": 1}, "evidence": [fake]}
        self.assertTrue(validate("InvestigatorOutput", {"hypotheses": [hyp]}),
                        "model output schema lets the model mint analyzer/test-run Evidence")

    def test_S1b_fabricated_analyzer_evidence_reaches_P0(self):
        fake = {"kind": "analyzer", "excerpt": "x", "source": "model", "toolCallId": "tool_0123456789abcdef"}
        self.assertNotEqual(S.severity_ceiling("security", "auth-bypass", True, [fake]), "P0",
                            "one self-labelled analyzer citation (no resolvable tool call) yields P0")

    def test_S2_independence_comes_from_a_distinct_verifier_call_not_citation_novelty(self):
        """Adapted to the approved verification policy (S0-03-verification-policy.md; supersedes C12).
        S2 originally asserted that a whitespace-altered copy of the proposer citation must not
        count as independent evidence. Under the policy the citation is not the independence
        signal, so the assertion moves to the real guard, `check_finding_provenance`, against
        actual provenance: the same Finding is rejected with no distinct verifier call, rejected
        when the 'verifier' is the proposer, and accepted only when a different VERIFY/verifier
        call actually confirmed."""
        from reviewer.contracts import check_finding_provenance
        sc = F.Scenario()
        f = sc.fresh()
        f["verification"]["evidence"][0]["excerpt"] += " "          # whitespace only: proves nothing
        self.assertEqual(validate("Finding", f), [], "the document alone no longer encodes independence")
        self.assertTrue(check_finding_provenance(f, [sc.inv]), "no verifier call recorded: accepted")
        selfv = copy.deepcopy(f)
        selfv["verification"]["callIds"] = [sc.inv["callId"]]
        self.assertTrue(validate("Finding", selfv), "self-verification must fail at the Finding boundary")
        # the same-line, same-text citation IS fine when a distinct real call confirmed
        self.assertEqual(check_finding_provenance(sc.fresh(), sc.events), [])

    def test_S3_single_file_severe_bug_reaches_P0_when_the_citation_is_resolved(self):
        """Adapted to RR1/D-RR1: the citation is resolved through the real snapshot path
        (materialize_evidence + snapshot_resolver) instead of being hand-labelled. The identical
        shape without resolution must stay out of P0."""
        repo = F.Repo(self, {"src/auth.py": "def f(t):\n    if t is None:\n        return True\n"})
        cite = repo.cite("src/auth.py", [2, 3], "    if t is None:\n        return True")
        resolved, problems = repo.materialize(cite)
        self.assertEqual(problems, [])
        self.assertIs(resolved[0].get("resolved"), True)
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, resolved), "P0")
        unresolved, _ = S.materialize_evidence([cite], {}, "investigator")      # no resolver
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, unresolved), "P2")

    def test_S4_cap_is_recorded_somewhere(self):
        """A capped severe finding must be visible to eval/reports (not just silently lower)."""
        fields = set(REGISTRY["Comment"].required) | set(REGISTRY["Comment"].optional)
        self.assertTrue({"cappedFrom", "proposedSeverity", "severityCeiling"} & fields,
                        f"Comment has no field for 'proposed P0, capped to P1'; fields: {sorted(fields)}")

    def test_S5_unknown_severity_or_missing_keys_fail_closed(self):
        """Adjudicated rev2: an unknown severity is a typed ValueError (validated documents cannot hold one;
        the schema/CLI stay clean). Malformed evidence must not raise at all."""
        with self.assertRaises(ValueError):
            S.judge_severity("P3", "P1", "P1")
        no_crash(self, lambda: S.has_strong_evidence([{"kind": "code"}]), "has_strong_evidence(code without path)")
        no_crash(self, lambda: S.comment_sort_key({"severity": "P9"}), "comment_sort_key(unknown severity)")
        self.assertTrue(validate("Comment", {**ex("Comment"), "severity": "P3"}))     # boundary rejects it first

    def test_CONTROL_two_files_gives_P0_and_P1_otherwise(self):
        """Adapted to RR1: both citations are resolved against a real snapshot first."""
        repo = F.Repo(self, {"a.py": "alpha\nbeta\n", "b.py": "gamma\ndelta\n"})
        two, problems = repo.materialize(repo.cite("a.py", [1, 2], "alpha\nbeta"),
                                         repo.cite("b.py", [1, 2], "gamma\ndelta"))
        self.assertEqual(problems, [])
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, two), "P0")
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", False, two), "P2")
        self.assertEqual(S.severity_ceiling("style", "none", True, two), "P2")


class Characterization_Judge(unittest.TestCase):
    def test_cap_selection_is_alphabetical_by_path_within_severity(self):
        """DECISION: with cap 5, six equal-severity comments drop the one whose path sorts last."""
        cs = [{"severity": "P1", "anchor": {"path": p, "startLine": 1}, "fingerprint": "fp1:" + "0" * 32}
              for p in ("a.py", "b.py", "c.py", "d.py", "e.py", "z_payment.py")]
        kept = sorted(cs, key=S.comment_sort_key)[:S.DEFAULT_COMMENT_CAP]
        self.assertNotIn("z_payment.py", [c["anchor"]["path"] for c in kept])

    def test_merge_window_and_weights_are_unused_constants(self):
        self.assertEqual(S.MERGE_LINE_WINDOW, 3)
        self.assertTrue(hasattr(S, "SEVERITY_WEIGHT"))


# ------------------------------------------------------------------ P: snapshot
class P_Snapshot(unittest.TestCase):
    def tree(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        return Path(td.name)

    def test_P1_non_utf8_filename_is_typed_error(self):
        root = self.tree()
        (root / "ok.txt").write_text("x")
        try:
            fd = os.open(os.fsencode(root) + b"/bad\xff.txt", os.O_CREAT | os.O_WRONLY)
            os.close(fd)
        except OSError:
            self.skipTest("fs rejects non-UTF8 names")
        try:
            SN.build_manifest(root)
        except SN.SnapshotError:
            return
        except Exception as e:  # noqa: BLE001
            self.fail(f"build_manifest raised {type(e).__name__} instead of SnapshotError")
        self.fail("non-UTF8 path accepted into a manifest")

    def test_P2_file_swapped_for_symlink_after_lstat_is_not_followed(self):
        root = self.tree()
        outside = self.tree() / "secret.txt" if False else Path(tempfile.mkdtemp()) / "secret.txt"
        outside.write_text("OUTSIDE-SECRET")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        (root / "f").write_text("inside")
        orig = SN.Path.lstat

        def racy(self_, *a, **k):
            st = orig(self_, *a, **k)
            if self_.name == "f" and not os.path.islink(self_):
                os.unlink(self_)
                os.symlink(outside, self_)
            return st
        SN.Path.lstat = racy
        try:
            m = SN.build_manifest(root)
        except SN.SnapshotError:
            return
        finally:
            SN.Path.lstat = orig
        import hashlib
        leaked = hashlib.sha256(b"OUTSIDE-SECRET").hexdigest()
        self.assertNotIn(leaked, [e["sha256"] for e in m["entries"]],
                         "manifest hashed a file outside the root through a swapped symlink (open() follows links)")

    def test_P3_manifest_rejects_entry_under_symlink_or_file(self):
        sha = "0" * 64
        entries = [{"path": "a", "type": "symlink", "size": 3, "sha256": sha},
                   {"path": "a/b", "type": "file", "size": 1, "sha256": sha}]
        doc = {"schema": "snapshot-manifest@1", "snapshotId": SN.snapshot_id(entries), "entries": entries}
        self.assertTrue(validate("SnapshotManifest", doc), "a/b under symlink a accepted")
        entries = [{"path": "a", "type": "file", "size": 1, "sha256": sha},
                   {"path": "a/b", "type": "file", "size": 1, "sha256": sha}]
        doc = {"schema": "snapshot-manifest@1", "snapshotId": SN.snapshot_id(entries), "entries": entries}
        self.assertTrue(validate("SnapshotManifest", doc), "a/b under regular file a accepted")

    def test_P4_no_verify_against_disk_helper(self):
        names = [n for n in dir(SN) if "verify" in n.lower() or "check" in n.lower()]
        self.assertTrue(names, "no way to re-verify a manifest against content at read time (tools re-read paths)")

    def test_CONTROL_identity_rules(self):
        a, b = self.tree(), self.tree()
        for r in (a, b):
            (r / "d").mkdir()
            (r / "d" / "x.py").write_text("print(1)\n")
        self.assertEqual(SN.build_manifest(a)["snapshotId"], SN.build_manifest(b)["snapshotId"])
        os.chmod(b / "d" / "x.py", 0o755)
        self.assertNotEqual(SN.build_manifest(a)["snapshotId"], SN.build_manifest(b)["snapshotId"])
        os.chmod(b / "d" / "x.py", 0o644)
        os.symlink("/etc/passwd", b / "link")
        m = SN.build_manifest(b)
        self.assertEqual([e for e in m["entries"] if e["path"] == "link"][0]["type"], "symlink")
        self.assertEqual(validate("SnapshotManifest", m), [])


# ------------------------------------------------------------------ E: eval report honesty / scoring assumptions
class E_EvalReport(unittest.TestCase):
    def test_E1_metrics_must_equal_case_tallies(self):
        r = ex("EvalReport.strict-replay")
        r["metrics"]["precision"] = {"value": 1.0, "numerator": 999, "denominator": 999, "undefinedReason": None}
        self.assertTrue(validate("EvalReport", r), "report metrics need not match per-case TP/FP/FN")

    def test_E2_f1_must_equal_harmonic_mean(self):
        r = ex("EvalReport.strict-replay")
        r["metrics"]["precision"] = {"value": 0.5, "numerator": 1, "denominator": 2, "undefinedReason": None}
        r["metrics"]["recall"] = {"value": 0.5, "numerator": 1, "denominator": 2, "undefinedReason": None}
        r["metrics"]["f1"] = {"value": 0.99, "undefinedReason": None}
        self.assertTrue(validate("EvalReport", r), "F1 not checked against P and R")

    def test_E3_coverage_must_match_cases(self):
        r = ex("EvalReport.strict-replay")
        r["coverage"]["completed"] += 5
        self.assertTrue(validate("EvalReport", r), "coverage counts need not match case statuses")

    def test_E4_strict_replay_cannot_report_new_measured_spend(self):
        r = ex("EvalReport.strict-replay")
        r["cost"]["byBasis"]["measured"] = {"records": 3, "usdMicros": 12345}
        self.assertTrue(validate("EvalReport", r), "strict replay (0 live calls) reports measured spend")

    def test_E5_report_names_its_matching_rule(self):
        """Smoke-only scoring must be visible in the report itself, not only in the suite file."""
        ex_def = json.dumps(export_bundle("x")["$defs"]["EvalReport"])
        self.assertIn("path-line-overlap", ex_def,
                      "EvalReport has no field recording that P/R came from path/line overlap")

    def test_E6_precision_recall_not_marked_smoke_only(self):
        r = ex("EvalReport.strict-replay")
        r["dataset"]["synthetic"] = False
        r["limitations"] = ["none"]
        self.assertTrue(validate("EvalReport", r),
                        "non-synthetic report with overlap-based P/R and no scope caveat is valid")

    def test_CHAR_E7_labels_ignore_category_and_severity_in_matching(self):
        """Characterisation of the proposed rule via the contract: labels carry category+severity but the
        only matching rule is path+line overlap, so a wrong-category/wrong-severity comment is a TP."""
        s = json.dumps(export_bundle("x")["$defs"]["SuiteManifest"])
        self.assertIn("path-line-overlap@1", s)
        self.assertNotIn("category", s)


# ------------------------------------------------------------------ J: JSON schema export honesty
class J_SchemaExport(unittest.TestCase):
    def test_J1_relpath_newline_python_vs_export(self):
        import re
        from reviewer.contracts.schema import is_safe_relpath
        pat = export_bundle("x")["$defs"]["SnapshotEntry"]["properties"]["path"]["pattern"]
        s = "a\nb"
        self.assertEqual(bool(re.search(pat, s)), is_safe_relpath(s),
                         "Python accepts newline in RelPath; exported pattern rejects it")

    def test_J2_timestamp_unicode_digits(self):
        d = ex("ReviewRun")
        d["startedAt"] = "٢026-10-25T00:00:00Z"        # ARABIC-INDIC DIGIT TWO
        self.assertTrue(validate("ReviewRun", d), "Python \\d accepts non-ASCII digits; ECMA/JSON Schema does not")

    def test_CHAR_J3_integer_valued_float_differs(self):
        d = ex("Plan")
        d["version"] = 1.0
        self.assertTrue(validate("Plan", d))        # Python rejects 1.0 ...
        self.assertIn("integer", json.dumps(export_bundle("x")["$defs"]["Plan"]))  # ... JSON Schema accepts 1.0

    def test_J4_bundle_documents_divergences(self):
        desc = export_bundle("x")["description"].lower()
        for word in ("pattern", "duplicate", "float", "nesting"):
            with self.subTest(word):
                self.assertIn(word, desc, "bundle description only mentions x-invariants")


# ------------------------------------------------------------------ L: loader / CLI
class L_Cli(unittest.TestCase):
    def run_cli(self, entity, text, suffix=".json"):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ("doc" + suffix)
            p.write_text(text)
            return subprocess.run([sys.executable, "-m", "reviewer.contracts", "validate", entity, str(p)],
                                  cwd=ROOT, capture_output=True, text=True)

    def test_L1_duplicate_keys_rejected(self):
        good = {"verdict": "refuted", "reachable": False, "impact": "none",
                "evidence": [ex("Finding")["evidence"][0]], "notes": ""}
        text = json.dumps(good).replace('"verdict": "refuted"', '"verdict": "refuted", "verdict": "confirmed"')
        self.assertEqual(json.loads(text)["verdict"], "confirmed")      # last key wins
        r = self.run_cli("VerifierOutput", text)
        self.assertNotEqual(r.returncode, 0, "last-key-wins hides which verdict the model emitted: " + r.stdout)

    def test_L2_malformed_json_is_not_a_traceback(self):
        r = self.run_cli("Plan", "{nope")
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn(r.returncode, (1, 2))

    def test_L3_nan_literal_rejected(self):
        d = ex("Comment")
        text = json.dumps(d).replace('"qualityScore": null', '"qualityScore": NaN')
        r = self.run_cli("Comment", text)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)

    def test_L4_jsonl_trace_sequence_checked(self):
        ev = ex("TraceEvent.model-call")
        lines = []
        for seq, rid in ((0, ev["runId"]), (0, ev["runId"]), (7, "run_ffffffffffffffff")):
            e = copy.deepcopy(ev)
            e.update(seq=seq, runId=rid)
            lines.append(json.dumps(e))
        r = self.run_cli("TraceEvent", "\n".join(lines) + "\n", ".jsonl")
        self.assertNotEqual(r.returncode, 0, "trace.jsonl with repeated seq and mixed runIds reported ok")


if __name__ == "__main__":
    unittest.main()
