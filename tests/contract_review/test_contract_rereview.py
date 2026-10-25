"""Independent RE-review of S0-03 rev2 (contracts s0a-contracts@2). Reviewer-owned, offline, stdlib only.

`test_*` asserts the CORRECT behaviour: FAIL/ERROR = reproduced defect (RR-n in handoffs/S0-03-rereview.md).
`CONTROL_*` and `Policy_*` pass today and guard what the author fixed. No __init__.py on purpose.

Run: nice -n 19 python3 -m unittest discover -s tests/contract_review -p 'test_contract_rereview.py' -v
"""
from __future__ import annotations

import copy
import json
import random
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import REGISTRY, ContractInputError, loads_strict, validate  # noqa: E402
from reviewer.contracts import budget as B  # noqa: E402
from reviewer.contracts import canonical as C  # noqa: E402
from reviewer.contracts import redaction as R  # noqa: E402
from reviewer.contracts import severity as S  # noqa: E402
from reviewer.contracts import snapshot as SN  # noqa: E402

import finalreview_support as F  # noqa: E402  (tests/contract_review is on sys.path under discover)

EX = ROOT / "reviewer" / "contracts" / "examples"


def ex(n):
    return json.loads((EX / f"{n}.json").read_text())


NOW = "2026-10-25T00:00:00Z"
FAKE_CODE = {"kind": "code", "path": "does/not/exist.py", "lines": [1, 2], "commit": "a" * 40,
             "excerpt": "no such text", "source": "investigator"}


# ================================================================ trusted evidence materialization
class T_TrustedEvidence(unittest.TestCase):
    def test_RR1_fabricated_code_citation_cannot_lift_P0(self):
        """is_trusted() accepts any code citation with path/lines/commit by SHAPE. Nothing in the
        severity path resolves it against the snapshot, so a model that invents a path and excerpt
        gets the P0 ceiling."""
        self.assertNotEqual(S.severity_ceiling("security", "auth-bypass", True, [FAKE_CODE]), "P0",
                            "unresolved, fabricated code citation reaches P0")
        self.assertEqual(S.evidence_strength([FAKE_CODE]), "unsupported",
                         "unresolved citation is ranked 'cited'")

    def test_RR1b_materialize_evidence_can_verify_code_citations(self):
        """materialize_evidence copies code citations unresolved and returns no problem for a path
        that does not exist; there is no parameter to resolve them."""
        import inspect
        params = set(inspect.signature(S.materialize_evidence).parameters)
        self.assertTrue(params & {"resolve", "resolver", "snapshot", "read_file", "manifest"},
                        f"no way to resolve code citations during materialization: {sorted(params)}")

    def test_RR1c_trust_is_not_carried_on_the_document(self):
        """Evidence/Finding/Comment carry no 'resolved' marker, so is_trusted must re-derive trust from
        shape downstream, where the same fabricated citation passes."""
        fields = set(REGISTRY["Evidence"].required) | set(REGISTRY["Evidence"].optional)
        self.assertTrue({"resolved", "verified", "trust"} & fields,
                        f"Evidence cannot record that a citation was resolved: {sorted(fields)}")

    def test_CONTROL_model_cannot_assert_strong_kinds(self):
        fake = {"kind": "analyzer", "toolCallId": "tool_0123456789abcdef"}
        hyp = {"claim": "c", "category": "security", "suspectedSeverity": "P0", "impact": "auth-bypass",
               "location": {"path": "a.py", "line": 1}, "evidence": [fake]}
        self.assertTrue(validate("InvestigatorOutput", {"hypotheses": [hyp]}))

    def test_CONTROL_self_labelled_kind_without_logged_call_is_untrusted(self):
        e = {"kind": "analyzer", "excerpt": "x", "source": "m", "toolCallId": "tool_0123456789abcdef"}
        self.assertFalse(S.has_strong_evidence([e], {}))
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, [e], {}), "P2")

    def test_CONTROL_logged_tool_result_makes_evidence_trusted(self):
        tid = "tool_0123456789abcdef"
        tc = {tid: {"type": "tool.call", "result": {"status": "ok", "evidence": [
            {"kind": "test-run", "excerpt": "FAILED", "source": "pytest", "toolCallId": tid}]}}}
        out, problems = S.materialize_evidence([{"kind": "tool-ref", "toolCallId": tid}], tc, "verifier")
        self.assertEqual(problems, [])
        self.assertEqual(S.evidence_strength(out, tc), "reproduced")
        self.assertEqual(S.severity_ceiling("bug", "crash", True, out, tc), "P0")
        bad, problems = S.materialize_evidence(
            [{"kind": "tool-ref", "toolCallId": "tool_ffffffffffffffff"}], tc, "verifier")
        self.assertTrue(problems and not bad)
        err = {tid: {"type": "tool.call", "result": {"status": "error", "evidence": tc[tid]["result"]["evidence"]}}}
        self.assertFalse(S.has_strong_evidence(out, err))     # an errored tool call is not trusted

    def test_CONTROL_single_file_defect_can_reach_P0_D3(self):
        """Adapted to RR1/D-RR1: the single citation is resolved through the real snapshot path,
        not hand-labelled `resolved`. The same shape unresolved stays P2 (guard unchanged)."""
        repo = F.Repo(self, {"a.py": "x = 1\nreturn True\n"})
        cite = repo.cite("a.py", [1, 2], "x = 1\nreturn True")
        (e,), problems = repo.materialize(cite)
        self.assertEqual(problems, [])
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, [e]), "P0")
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", False, [e]), "P2")
        self.assertEqual(S.severity_ceiling("style", "none", True, [e]), "P2")
        (u,), _ = S.materialize_evidence([cite], {}, "d")
        self.assertNotIn("resolved", u)
        self.assertEqual(S.severity_ceiling("security", "auth-bypass", True, [u]), "P2")

    def test_CONTROL_ranking_uses_strength_not_confidence_D4(self):
        a = {"severity": "P1", "evidenceStrength": "reproduced", "anchor": {"path": "z", "startLine": 1},
             "fingerprint": "f", "confidence": 0.1}
        b = {"severity": "P1", "evidenceStrength": "cited", "anchor": {"path": "a", "startLine": 1},
             "fingerprint": "f", "confidence": 0.99}
        self.assertLess(S.comment_sort_key(a), S.comment_sort_key(b))

    def test_CONTROL_snapshot_citation_resolution_works(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.py").write_text("x = 1\nAKIAIOSFODNN7EXAMPLE\nz = 3\n")
            m = SN.build_manifest(root)
            data = SN.read_verified(root, m, "a.py")
            self.assertTrue(SN.excerpt_matches(data, [1, 1], "x = 1"))
            self.assertFalse(SN.excerpt_matches(data, [1, 1], "x = 2"))
            self.assertTrue(SN.excerpt_matches(data, [2, 2], "[REDACTED:aws-access-key]"))
            self.assertFalse(SN.excerpt_matches(data, [2, 2], "AKIAIOSFODNN7EXAMPLE"))
            (root / "a.py").write_text("tampered\n")
            with self.assertRaises(SN.SnapshotError):
                SN.read_verified(root, m, "a.py")


# ================================================================ opaque payload replay hashes
class H_ReplayHashes(unittest.TestCase):
    def test_RR2_requestHash_must_match_request(self):
        t = ex("TraceEvent.model-call")
        t["requestHash"] = "sha256:" + "0" * 64
        self.assertTrue(validate("TraceEvent", t), "model.call with requestHash != digest(request) validates")

    def test_RR2b_request_tamper_with_stale_hash(self):
        t = ex("TraceEvent.model-call")
        t["request"]["messages"][0]["content"] = "something else entirely"
        self.assertTrue(validate("TraceEvent", t), "edited request with the old requestHash validates")

    def test_RR2c_resultHash_and_costRecordId_must_match(self):
        t = ex("TraceEvent.model-call")
        t["costRecordId"] = "cost_ffffffffffffffff"
        self.assertTrue(validate("TraceEvent", t), "costRecordId != cost_id(callId) accepted")
        tool = {"schema": "trace-event@1", "runId": t["runId"], "seq": 3, "type": "tool.call",
                "toolCallId": "tool_0123456789abcdef", "stage": "INVESTIGATE", "agentId": "a1",
                "ordinal": 0, "tool": "read-file", "args": {"path": "a.py"},
                "resultHash": "sha256:" + "0" * 64,
                "result": {"status": "empty", "evidence": [], "completeness": "exact", "truncated": None,
                           "notice": ""}, "redactions": {}}
        self.assertTrue(validate("TraceEvent", tool), "tool.call with wrong resultHash validates")
        tool["resultHash"] = C.result_hash(tool["result"])
        self.assertTrue(validate("TraceEvent", tool),
                        "toolCallId is not tied to (stage, agentId, ordinal, tool, args)")

    def test_CONTROL_comparable_digest_across_replay(self):
        rec = ex("ReviewRun")
        rep = copy.deepcopy(rec)
        rep.update(evalRunId="evr_0000000000000001")
        rep["idempotencyKey"] = C.idempotency_key_eval(rep["evalRunId"], rep["evalCaseId"], rep["repeat"],
                                                       rep["baseSnapshotId"], rep["headSnapshotId"])
        rep["id"] = C.run_id(rep["idempotencyKey"], 1)
        rep["replayOf"] = rec["id"]
        self.assertEqual(C.comparable_digest(rec), C.comparable_digest(rep))
        rep["status"] = "failed"
        self.assertNotEqual(C.comparable_digest(rec), C.comparable_digest(rep))

    def test_CONTROL_opaque_payloads_are_never_stripped(self):
        a = {"schema": "trace-event@1", "runId": "run_" + "0" * 16, "seq": 1, "type": "tool.call",
             "args": {"runId": "A", "at": "x", "latencyMs": 1}}
        b = copy.deepcopy(a)
        b["args"]["runId"] = "B"
        self.assertNotEqual(C.comparable_digest(a), C.comparable_digest(b))
        c = copy.deepcopy(a)
        c["runId"], c["at"], c["latencyMs"] = "run_" + "1" * 16, "t", 99
        self.assertEqual(C.comparable_digest(a), C.comparable_digest(c))      # top-level volatile only

    def test_CONTROL_unknown_documents_compare_in_full(self):
        self.assertNotEqual(C.comparable_digest({"runId": "A", "z": 1}), C.comparable_digest({"runId": "B", "z": 1}))

    def test_RR2d_artifact_digest_chain(self):
        a = ex("StageArtifact.learn-skipped")
        b = copy.deepcopy(a)
        b["runId"] = "run_" + "9" * 16
        self.assertEqual(C.artifact_digest(a), C.artifact_digest(b))
        b["status"] = "completed"
        self.assertNotEqual(C.artifact_digest(a), C.artifact_digest(b))

    def test_CONTROL_request_hash_guards(self):
        req = ex("TraceEvent.model-call")["request"]
        C.request_hash(req)
        bad = copy.deepcopy(req)
        bad["messages"][0]["content"] += " run_0123456789abcdef"
        with self.assertRaises(ValueError):
            C.request_hash(bad)
        bad = copy.deepcopy(req)
        bad["messages"][0]["content"] += " AKIAIOSFODNN7EXAMPLE"
        with self.assertRaises(ValueError):
            C.request_hash(bad)

    def test_CONTROL_canonical_form(self):
        self.assertEqual(C.digest({"n": 1}), C.digest({"n": 1.0}))
        self.assertEqual(C.digest({"n": 0}), C.digest({"n": -0.0}))
        for bad in ({1: "x"}, {"a": (1,)}, {"a": {1}}, {"a": 2 ** 60}, {"a": float("nan")}):
            with self.subTest(bad), self.assertRaises((TypeError, ValueError)):
                C.canonical_json(bad)


# ================================================================ strict loader
class L_StrictLoader(unittest.TestCase):
    def test_CONTROL_rejects_hostile_json(self):
        cases = ['{"a":1,"a":2}', '{"a":NaN}', "[Infinity]", "[-Infinity]", '{"a":"\\ud800"}', '{"a":1e999}',
                 '{"a":12345678901234567890}', "﻿{}", '{"a":1} x', "[" * 5000 + "]" * 5000, "",
                 '{"a":"\\udfff\\ud800"}', b"\xff\xfe", '{"a":[1,2,}']
        for c in cases:
            with self.subTest(repr(c)[:30]), self.assertRaises(ContractInputError):
                loads_strict(c)

    def test_CONTROL_accepts_normal_json(self):
        self.assertEqual(loads_strict('{"a":[1,2.5,"x",null,true]}'), {"a": [1, 2.5, "x", None, True]})
        self.assertEqual(loads_strict(b'{"a":"\xc3\xa9"}'), {"a": "é"})

    def test_RR3_nested_duplicate_keys_and_escapes(self):
        for c in ('{"a":{"b":1,"b":2}}', '[{"k":1,"k":1}]', '{"a":1,"\\u0061":2}'):
            with self.subTest(c), self.assertRaises(ContractInputError):
                loads_strict(c)

    def test_CONTROL_cli_clean_exit_codes(self):
        def run(entity, text, suffix=".json"):
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / ("d" + suffix)
                p.write_bytes(text if isinstance(text, bytes) else text.encode())
                return subprocess.run([sys.executable, "-m", "reviewer.contracts", "validate", entity, str(p)],
                                      cwd=ROOT, capture_output=True, text=True)
        for text in ("{nope", '{"a":NaN}', '{"a":1,"a":2}', b"\xff\xfe\x00", "[" * 3000 + "]" * 3000):
            with self.subTest(repr(text)[:20]):
                r = run("Plan", text)
                self.assertEqual(r.returncode, 1)
                self.assertNotIn("Traceback", r.stderr)
        r = run("Plan", (EX / "Plan.json").read_bytes())
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(subprocess.run([sys.executable, "-m", "reviewer.contracts", "validate", "Plan", "/nonexistent"],
                                        cwd=ROOT, capture_output=True, text=True).returncode, 2)
        self.assertEqual(subprocess.run([sys.executable, "-m", "reviewer.contracts", "validate", "Nope", "x"],
                                        cwd=ROOT, capture_output=True, text=True).returncode, 2)

    def test_CONTROL_all_examples_validate_via_cli(self):
        for f in sorted(EX.glob("*.json")):
            with self.subTest(f.name):
                r = subprocess.run([sys.executable, "-m", "reviewer.contracts", "validate", f.name.split(".")[0], str(f)],
                                   cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stdout)

    def test_CONTROL_validator_never_raises_on_mutated_examples(self):
        rng = random.Random(11)
        weird = [None, True, 0, -1, 2 ** 70, 1.5, float("nan"), "", "x" * 3000, [], {}, [[]], {"a": None},
                 "\ud800", {"type": []}, "\x00", "sha256:", {"stage": []}, {"rule": {}}, {"kind": []}]
        docs = [(f.name.split(".")[0], json.loads(f.read_text())) for f in EX.glob("*.json")]
        crashes = {}
        for name, d in docs:
            for _ in range(600):
                m = copy.deepcopy(d)
                for _k in range(rng.randint(1, 3)):
                    nodes = []

                    def walk(x, p):
                        nodes.append(p)
                        if isinstance(x, dict):
                            for k, v in x.items():
                                walk(v, p + [k])
                        elif isinstance(x, list):
                            for i, v in enumerate(x):
                                walk(v, p + [i])
                    walk(m, [])
                    p = rng.choice(nodes)
                    if not p:
                        m = copy.deepcopy(rng.choice(weird))
                        continue
                    par = m
                    for k in p[:-1]:
                        par = par[k]
                    if rng.random() < .3 and isinstance(par, dict):
                        del par[p[-1]]
                    else:
                        par[p[-1]] = copy.deepcopy(rng.choice(weird))
                try:
                    validate(name, m)
                except Exception as e:  # noqa: BLE001
                    crashes[(name, type(e).__name__)] = crashes.get((name, type(e).__name__), 0) + 1
        self.assertEqual(crashes, {})


# ================================================================ budget / ledger
BUDGET = dict(B.STANDARD_S0A_BUDGET)
PRICE = {"priceVersion": "t@1", "inputPerMTokUsdMicros": 3_000_000, "cachedInputPerMTokUsdMicros": 300_000,
         "cacheWriteInputPerMTokUsdMicros": 3_750_000, "outputPerMTokUsdMicros": 15_000_000}


class G_Ledger(unittest.TestCase):
    def ledger(self, cap=1000, **kw):
        return B.Ledger({**BUDGET, "maxUsdMicros": cap, "verifyReserveBp": 0, **kw})

    def test_CONTROL_concurrent_reservations_never_exceed_ceiling(self):
        L = self.ledger(1000)
        admitted = []

        def worker(i):
            if L.reserve(f"call_{i:016x}", "VERIFY", 100) is None:
                admitted.append(i)
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(300)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(admitted), 10)
        self.assertEqual(L.spend().inflight, 1000)

    def test_CONTROL_lifecycle_and_release_rules(self):
        L = self.ledger(1000)
        for i, out in enumerate(("not-sent", "rejected-before-processing")):
            k = f"call_{i:016x}"
            self.assertIsNone(L.reserve(k, "VERIFY", 100))
            L.release(k, out)
        self.assertEqual(L.spend(), B.Spend())
        for out in ("timeout", "stream-cut", "5xx", "", "unknown", None):
            k = "call_" + "a" * 16
            self.assertIsNone(L.reserve(k, "VERIFY", 100))
            with self.assertRaises(ValueError):
                L.release(k, out)
            self.assertEqual(L.retain(k), 100)
        self.assertEqual(L.spend().committed, 600)

    def test_CONTROL_overrun_charged_and_blocks_further_calls(self):
        L = self.ledger(1000)
        self.assertIsNone(L.reserve("call_" + "1" * 16, "VERIFY", 900))
        L.settle("call_" + "1" * 16, 1500)
        self.assertEqual(L.overruns, ["call_" + "1" * 16])
        self.assertIsNotNone(L.reserve("call_" + "2" * 16, "VERIFY", 1))

    def test_CONTROL_investigation_share_and_double_open(self):
        L = B.Ledger({**BUDGET, "maxUsdMicros": 1000, "verifyReserveBp": 3000})
        self.assertIsNone(L.reserve("call_" + "1" * 16, "INVESTIGATE", 700))
        self.assertIsNotNone(L.reserve("call_" + "2" * 16, "INVESTIGATE", 1))
        self.assertIsNone(L.reserve("call_" + "3" * 16, "VERIFY", 300))
        with self.assertRaises(ValueError):
            L.reserve("call_" + "3" * 16, "VERIFY", 1)

    def test_RR4_unknown_or_double_close_is_a_typed_error(self):
        L = self.ledger()
        for fn in (lambda: L.settle("call_" + "f" * 16, 1), lambda: L.retain("call_" + "f" * 16),
                   lambda: L.release("call_" + "f" * 16, "not-sent")):
            with self.assertRaises(ValueError):          # KeyError is not a ValueError
                fn()

    def test_CONTROL_retry_is_new_admission_and_cap_binds(self):
        L = self.ledger(250)
        ks = [C.call_id("VERIFY", "verifier", "v1", 0, a) for a in range(3)]
        res = [L.reserve(k, "VERIFY", 100) for k in ks]
        self.assertEqual([r is None for r in res], [True, True, False])

    def test_CONTROL_settle_semantics(self):
        reserve = B.reservation(PRICE, 100_000, 4_000)
        w = {"uncachedInputTokens": 0, "cachedInputTokens": 0, "cacheWriteInputTokens": 100_000,
             "outputTokens": 4_000, "reasoningTokens": None}
        usd, basis, over = B.settle(reserve, w, PRICE)
        self.assertEqual((basis, over), ("measured", False))
        self.assertLessEqual(usd, reserve)
        usd, basis, over = B.settle(100, {**w, "cacheWriteInputTokens": None}, PRICE)
        self.assertEqual((usd >= 100, basis), (True, "estimated"))
        usd, basis, over = B.settle(1, {**w, "outputTokens": 10 ** 6}, PRICE)
        self.assertTrue(over)

    def test_RR5_unknown_usage_with_garbage_values(self):
        for bad in (-5, float("nan"), True, "7", 2 ** 70):
            with self.subTest(bad):
                try:
                    usd, basis, over = B.settle(
                        100, {"uncachedInputTokens": bad, "cachedInputTokens": None, "cacheWriteInputTokens": None,
                              "outputTokens": 1, "reasoningTokens": None}, PRICE)
                except (ValueError, TypeError):
                    continue
                self.assertEqual(basis, "estimated")
                self.assertGreaterEqual(usd, 100)
                self.assertIsInstance(usd, int)

    def test_CONTROL_deadlines(self):
        self.assertEqual(B.deadline_state(BUDGET, 0), "ok")
        self.assertEqual(B.deadline_state(BUDGET, BUDGET["softDeadlineSec"]), "soft")
        self.assertEqual(B.deadline_state(BUDGET, BUDGET["wallClockSec"]), "hard")
        for bad in (-1, float("nan"), True, "1"):
            with self.assertRaises(ValueError):
                B.deadline_state(BUDGET, bad)


class A_SpendAuthorization(unittest.TestCase):
    def setUp(self):
        self.auth = ex("SpendAuthorization.synthetic-recording")
        self.profile = ex("ModelProfile.smoke-synthetic")
        self.budget = ex("Plan")["budget"]

    def test_CONTROL_synthetic_recording_is_allowed_and_candidate_blocked(self):
        self.assertEqual(B.check_spend_authorization(self.auth, self.profile, self.budget, NOW), [])
        cand = B.check_spend_authorization(self.auth, ex("ModelProfile.standard-candidate"), self.budget, NOW)
        self.assertTrue(any("not authorized" in p for p in cand) and any("not resolved" in p for p in cand))

    def test_CONTROL_expiry_and_ceiling(self):
        expired = {**self.auth, "expiresAt": "2020-01-01T00:00:00Z"}
        self.assertIn("authorization expired", B.check_spend_authorization(expired, self.profile, self.budget, NOW))
        low = {**self.auth, "maxUsdMicrosPerRun": 1}
        self.assertTrue(B.check_spend_authorization(low, self.profile, self.budget, NOW))

    def test_RR6_now_iso_is_validated(self):
        """An expired authorization must not pass because the caller supplied a junk 'now'."""
        expired = {**self.auth, "expiresAt": "2020-01-01T00:00:00Z"}
        for junk in ("", "0", "yesterday", None, 0, "2019-01-01T00:00:00Z extra"):
            with self.subTest(junk):
                try:
                    problems = B.check_spend_authorization(expired, self.profile, self.budget, junk)
                except (ValueError, TypeError):
                    continue
                self.assertTrue(problems, f"now_iso={junk!r} lets an expired authorization pass")

    def test_RR6b_fraction_timestamps_compare_by_time_not_text(self):
        """'2026-01-01T00:00:00Z' >= '2026-01-01T00:00:00.5Z' is True as text ('Z' > '.')."""
        a = {**self.auth, "expiresAt": "2026-01-01T00:00:00.5Z"}
        self.assertEqual(B.check_spend_authorization(a, self.profile, self.budget, "2026-01-01T00:00:00Z"), [],
                         "authorization still valid 0.5 s before expiry reported expired")

    def test_GAP_RR7_total_ceiling_is_not_enforceable(self):
        """maxUsdMicrosTotal exists but nothing accumulates spend across runs against it."""
        names = [n for n in dir(B) if "total" in n.lower() or "cumulative" in n.lower()]
        self.assertTrue(names, "maxUsdMicrosTotal has no enforcing code")

    def test_GAP_RR8_request_level_authorization_check(self):
        """The gateway must check each ModelRequest provider/model against the authorization, not only the profile."""
        names = [n for n in dir(B) if "request" in n.lower() and "auth" in n.lower()]
        self.assertTrue(names, "no per-request authorization check (only profile-level)")

    def test_CONTROL_authorization_is_closed_and_runtime_only(self):
        bad = {**self.auth, "models": ["claude-opus-5-5"]}
        self.assertTrue(validate("SpendAuthorization", bad))
        self.assertTrue(validate("SpendAuthorization", {**self.auth, "issuedBy": "repo"}))
        self.assertTrue(validate("SpendAuthorization", {**self.auth, "extra": 1}))


# ================================================================ redaction
class X_Redaction(unittest.TestCase):
    def test_CONTROL_newlines_idempotence_fuzz(self):
        rng = random.Random(5)
        frags = ["AKIAIOSFODNN7EXAMPLE", "sk-ant-" + "a" * 30, "ghp_" + "A" * 36, "password = \"hunter2hunter2\"",
                 "Bearer " + "x" * 30, "postgres://u:p4ss@h/db", "-----BEGIN RSA PRIVATE KEY-----\nAAA\nBBB\n"
                 "-----END RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\nzzz", "\n", "\r\n", " ", "x = 1",
                 "token: 'abcdefgh12345'", "[REDACTED:foo]", "\t", "'", '"']
        for _ in range(8000):
            t = "".join(rng.choice(frags) for _ in range(rng.randint(1, 7)))
            o, _c = R.redact(t)
            self.assertEqual(o.count("\n"), t.count("\n"), repr(t))
            self.assertEqual(R.redact(o)[0], o, repr(t))
            self.assertFalse(R.contains_protected(o), repr(t))

    def test_RR9_adjacent_secrets_redact_to_a_fixpoint(self):
        """A secret glued to the end of another secret is skipped by the letter/digit lookbehind on the
        first pass and exposed (redactable) on the second: redact is not idempotent and the output still
        trips the no-secrets invariant."""
        t = "AIza" + "B" * 35 + "ghp_" + "A" * 36
        o, _ = R.redact(t)
        self.assertEqual(R.redact(o)[0], o)
        self.assertFalse(R.contains_protected(o))

    def test_RR10_redaction_marker_prefix_does_not_hide_a_secret(self):
        for t in ('password = "[REDACTED:x]hunter2hunter2"', "Bearer [REDACTED:x]abcdefghijklmnopqrstuvwxyz0123"):
            with self.subTest(t):
                o, _ = R.redact(t)
                self.assertNotIn("hunter2hunter2", o)
                self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123", o)

    def test_CONTROL_formats_and_boundaries(self):
        aws = "AKIAIOSFODNN7EXAMPLE"
        for s in (f"AWS_KEY_{aws}", f"x{aws}", "key_sk-" + "a" * 24, "tok_ghp_" + "a" * 36,
                  "sk_live_" + "a" * 24, "AIza" + "B" * 35, "glpat-" + "c" * 20,
                  "eyJhbGciOiJIUzI1NiJ9." + "e" * 20 + "." + "f" * 20,
                  "postgres://admin:hunter2hunter2@db:5432/app", "Authorization: Bearer " + "g" * 30,
                  'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 'password = "Tr0ub4dor&3xyz"'):
            with self.subTest(s[:25]):
                self.assertNotEqual(R.redact(s)[0], s)
        k1, k2 = "AKIAIOSFODNN7EXAMPLA", "AKIAIOSFODNN7EXAMPLB"
        out, _ = R.redact_json({k1: 1, k2: 2})
        self.assertEqual(len(out), 2)

    def test_CONTROL_no_secrets_invariant_on_persisted_entities(self):
        d = ex("Comment")
        d["body"] = "leak AKIAIOSFODNN7EXAMPLE"
        self.assertTrue(validate("Comment", d))
        t = ex("TraceEvent.model-call")
        t["request"]["messages"][0]["content"] = "ghp_" + "A" * 36
        self.assertTrue(validate("TraceEvent", t))
        r = ex("EvalReport.unscored-real")
        r["limitations"] = ["sk-ant-" + "a" * 30]
        self.assertTrue(validate("EvalReport", r))

    def test_RR11_secrets_in_json_keys_are_checked(self):
        t = ex("TraceEvent.model-call")
        t["redactions"] = {"AKIAIOSFODNN7EXAMPLE": 1}
        self.assertTrue(validate("TraceEvent", t), "secret in an object KEY of a persisted entity accepted")


# ================================================================ report honesty / policy
class E_Honesty(unittest.TestCase):
    def test_CONTROL_real_pr_reports_are_unscored(self):
        r = ex("EvalReport.unscored-real")
        self.assertEqual(validate("EvalReport", r), [])
        r2 = copy.deepcopy(r)
        r2["matching"] = {"rule": "path-line-overlap@1", "scope": "synthetic-smoke"}
        self.assertTrue(validate("EvalReport", r2))
        r3 = copy.deepcopy(r)
        r3["metrics"]["precision"] = {"value": 0.9, "numerator": 9, "denominator": 10, "undefinedReason": None}
        self.assertTrue(validate("EvalReport", r3))

    def test_CONTROL_smoke_suite_rules(self):
        s = ex("SuiteManifest")
        self.assertEqual(validate("SuiteManifest", s), [])
        s["synthetic"] = False
        self.assertTrue(validate("SuiteManifest", s))
        s["matching"] = {"rule": "unadjudicated@1"}
        self.assertEqual(validate("SuiteManifest", s), [])

    def test_CONTROL_strict_replay_report_cannot_book_measured_cost(self):
        r = ex("EvalReport.strict-replay")
        self.assertEqual(validate("EvalReport", r), [])
        r["cost"]["byBasis"]["measured"] = {"records": 1, "usdMicros": 5}
        self.assertTrue(validate("EvalReport", r))

    def test_CONTROL_report_arithmetic(self):
        r = ex("EvalReport.strict-replay")
        r["coverage"]["completed"] += 1
        self.assertTrue(validate("EvalReport", r))
        r = ex("EvalReport.strict-replay")
        r["metrics"]["f1"] = {"value": 0.123, "undefinedReason": None}
        self.assertTrue(validate("EvalReport", r))

    def test_RR12_cost_reconciliation_across_report(self):
        """cost.byBasis.records can say anything while liveCalls == 0; a replay report claims
        'replayed' records with no link to cases."""
        r = ex("EvalReport.strict-replay")
        r["cost"]["byBasis"]["replayed"] = {"records": 10 ** 6, "usdMicros": 7}
        r["cost"]["byBasis"]["synthetic"] = {"records": 0, "usdMicros": 999_999_999}
        self.assertTrue(validate("EvalReport", r), "byBasis usd not reconcilable with records (synthetic: 0 records, $999)")

    def test_CONTROL_run_read_only_access(self):
        d = ex("ReviewRun")
        d["access"] = "read-write"
        self.assertTrue(validate("ReviewRun", d))
        pub = ex("StageArtifact.learn-skipped")
        self.assertEqual(validate("StageArtifact", pub), [])
        self.assertEqual(list(REGISTRY["StagePayload"].variants["PUBLISH"].required["sink"].values), ["local-file"])


class Q_Policy(unittest.TestCase):
    def test_CONTROL_comment_cap_fields(self):
        c = ex("Comment")
        c["severity"], c["severityCeiling"] = "P0", "P1"
        self.assertTrue(validate("Comment", c))
        c = ex("Comment")
        c["proposedSeverity"], c["severity"], c["severityCeiling"] = "P2", "P1", "P1"
        c.pop("severityReason", None)
        self.assertTrue(validate("Comment", c))

    def test_CONTROL_trace_file_rules(self):
        from reviewer.contracts import validate_trace
        t = ex("TraceEvent.model-call")
        self.assertTrue(validate_trace([t]))
        self.assertTrue(validate_trace([]))

    def test_CONTROL_schema_export_current(self):
        r = subprocess.run([sys.executable, "-m", "reviewer.contracts", "export", "--check"], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
