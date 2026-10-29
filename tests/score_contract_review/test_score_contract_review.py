"""SCORE-CONTRACT-02-review: independent gate of the s0a-contracts@7 score family (non-author, invented data).

SCORE-CONTRACT-04-review (scoped re-gate of D1/N1): root chose D1 option (b), so exactly two legacy defs differ from
the baseline, CostRecord (kind gains "score") and TraceEvent (its cost variant gains the review-cost-kind invariant).
The D1 expectedFailure/symptom and the N1 symptom are now regression controls.

Self-contained and public-portable. Every fixture is invented and built inline. The baseline pins below were computed
independently by the reviewer from the frozen legacy contracts (commit 4dd7e788d912acf2b31891166c10d2144d0f63ec,
tree 326aca34fe28dde6b0ceb1dad404d5f05b3b5702) using that commit's own code. They are embedded here, so nothing at
execution reads /tmp, private receipts, Git history, target data, credentials or state, and nothing calls a provider.
The only repository files read are the committed public contract examples that existed at the baseline commit.

Conventions (as in tests/integration_review):
* `expectedFailure` asserts the DESIRED behaviour of a confirmed open defect. An unexpected success means a fix
  landed and needs regression review before the marker is removed.
* `test_SYMPTOM_*` pins today's behaviour of that defect or limit, so a silent change is visible.
* `test_LIMIT_*` records a property that the contract layer deliberately leaves to the later gateway/host
  (SCORE-GW / SCORE-RT / SCORE-HOST). It is not a contract defect, and passing it is not proof of enforcement.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import (CONTRACTS_VERSION, ENTITY_NAMES, REGISTRY, check_score_replay,  # noqa: E402
                                export_bundle, loads_strict, validate, validate_score_trace, validate_trace)
from reviewer.contracts import canonical as C  # noqa: E402
from reviewer.contracts.stages import STAGES  # noqa: E402

EXAMPLES = ROOT / "reviewer" / "contracts" / "examples"

# ---- independent baseline pins (reviewer-computed from the frozen export's own code) -----------------------------
# sha256 of canonical JSON of sorted [[defName, digest(def)]] over the 39 baseline defs other than the two declared
# changed defs, CostRecord and TraceEvent.
OLD_DEFS_COMBINED = "ffabe30194d300e04da9498caf50ac3f2492e371db8f809ca655ff22e81ba1ed"
CHANGED_DEFS = frozenset({"CostRecord", "TraceEvent"})
OLD_DEF_NAMES = frozenset({
    "Budget", "CaseInput", "CaseLabels", "Category", "Comment", "ContextRequest", "CostRecord", "DropRecord",
    "EvalReport", "Evidence", "EvidenceStrength", "Finding", "Hypothesis", "HypothesisDraft", "Impact",
    "InvestigatorOutput", "InvestigatorTurn", "JudgeOutput", "Location", "ModelEvidence", "ModelProfile",
    "ModelRequest", "ModelResponse", "Plan", "Ratio", "ReviewRun", "Severity", "SnapshotEntry", "SnapshotManifest",
    "SpendAuthorization", "StageArtifact", "StagePayload", "SuiteManifest", "Tier", "ToolResult", "TraceEvent",
    "TypedError", "Usage", "VerificationRecord", "VerifierOutput", "VerifierTurn"})
NEW_DEF_NAMES = frozenset({"ScoreStage", "ScoreRole", "ScoreExtraction", "ScoreDedup", "ScorePair", "ScoreProfile",
                           "ScoreRequest", "ScoreRun", "ScoreTraceEvent",
                           "ScoreExtractionSpans"})              # bench.extract@v3 by-reference extractor output (additive)
COSTRECORD_BASELINE = "sha256:60504efb585bf21ad183b01e1a197c8af10c969fe7a3e266f10c5c71b24eaef8"
TRACEEVENT_BASELINE = "sha256:317934ec2b8ec44866e9d7245ab6ffceeea8d6877bd117a1d20e84d6b3d15365"
# sha256 of canonical JSON of sorted [["<schema>/<flavour>", sha256(json.dumps(proj, sort_keys=True))]] (15 entries).
PROJECTIONS_COMBINED = "9ec0aa5de298ebf04eea26c152dde17dc92011ea2553b45e25110f1add895e94"
# sha256 of canonical JSON of sorted [[name, digest(doc), comparable_digest(doc), request_hash or None]] over the
# 21 contract examples present at the baseline commit (request_hash only for TraceEvent model.call examples).
BASELINE_EXAMPLES = (
    "CaseInput", "CaseLabels", "Comment", "ContextRequest", "CostRecord.eval-synthetic", "EvalReport.strict-replay",
    "EvalReport.unscored-real", "Finding", "InvestigatorTurn.requests", "ModelProfile.smoke-synthetic",
    "ModelProfile.standard-candidate", "Plan", "ReviewRun", "ReviewRun.github-pr",
    "SpendAuthorization.synthetic-recording", "StageArtifact.learn-skipped", "SuiteManifest", "TraceEvent.model-call",
    "TraceEvent.model-call-turn", "TraceEvent.tool-call-requested", "VerifierTurn.final")
EXAMPLES_COMBINED = "9f5b28f6a63f83c2dcae052562c2d635e325155b16b9b5c74eed83d203f799ee"
# Review comparison tables at the baseline (code tables, not bundle defs).
REVIEW_IGNORE_BASELINE = {
    "ReviewRun": {"id", "idempotencyKey", "attempt", "rerunOf", "trigger", "mode", "evalRunId", "replayOf",
                  "fromStage", "spendAuthorization", "startedAt", "endedAt"},
    "CostRecord": {"runId", "evalRunId", "basis", "replayOf"}, "Hypothesis": {"runId"}, "Finding": {"runId"},
    "Comment": {"runId"}, "TraceEvent": {"runId", "at", "latencyMs"}, "StageArtifact": {"runId"},
    "StagePayload": set(), "EvalReport": {"evalRunId", "replayOf", "createdAt", "mode", "cost", "latency",
                                          "limitations"}, "CaseResult": {"runId", "latencyMs"}}
REVIEW_NESTED_BASELINE = {
    "TraceEvent": {"run": "ReviewRun", "record": "CostRecord"}, "StageArtifact": {"payload": "StagePayload"},
    "StagePayload": {"run": "ReviewRun", "hypotheses": "Hypothesis[]", "findings": "Finding[]",
                     "comments": "Comment[]"}, "EvalReport": {"cases": "CaseResult[]"}}
REVIEW_TAGS_BASELINE = {"trace-event@1": "TraceEvent", "stage-artifact@1": "StageArtifact",
                        "eval-report@1": "EvalReport"}

SENTINEL = "SENTINEL_REVIEWER_TEXT_5d0c"
OPUS = "anthropic/claude-opus-5.5"


def cj(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def combined(pairs) -> str:
    return hashlib.sha256(cj(sorted(pairs))).hexdigest()


def ex(name):
    return loads_strict((EXAMPLES / f"{name}.json").read_bytes())


# ---- LIVE-DEADLINE-04 (+HOST-POSITION-01: host-stop@2 enum + optional gateOrdinal repinned below): root-declared deliberate shared-schema extension (NOT a claim the old defs are byte-identical).
# Exactly these deltas are subtracted before comparing Budget/TraceEvent with the ORIGINAL legacy pins below, which are
# kept unchanged: Budget optional stageCeilingsSec + hostStopRecording and their "stage-ceilings" invariant, and the
# TraceEvent "host.stop" variant. The NEW shapes/digests are asserted independently so no other addition is excused.
LIVE_BUDGET_DIGEST = "sha256:2ad15744528ea621da0e31fd9f363f0428fe95552ec766447824cda80ede9671"
LIVE_TRACEEVENT_DIGEST = "sha256:7cd136dbd446caa159a1b120798073ffae98e490c2c861ff5f39c724c5aeb80b"
LIVE_HOST_STOP_DIGEST = "sha256:f4b6bf08491c8f2fda91c1c075fb9d3ca1c9cb0e9228731106606a319f55965f"


def budget_minus_live(b):
    b = copy.deepcopy(b)
    for k in ("stageCeilingsSec", "hostStopRecording"):
        assert k in b["properties"] and k not in b["required"], k
        del b["properties"][k]
    inv = [i for i in b["x-invariants"] if i.startswith("stage-ceilings:")]
    assert len(inv) == 1, inv
    b["x-invariants"] = [i for i in b["x-invariants"] if i not in inv]
    return b


def traceevent_minus_live(te):
    te = copy.deepcopy(te)
    hits = [i for i, v in enumerate(te["oneOf"]) if v["properties"]["type"]["const"] == "host.stop"]
    assert len(hits) == 1, hits
    del te["oneOf"][hits[0]]
    return te


def host_stop_variant(te):
    return next(v for v in te["oneOf"] if v["properties"]["type"]["const"] == "host.stop")


def costrecord_minus_delta(cr):
    """CostRecord def with the one intended delta (kind's appended "score") removed."""
    cr = copy.deepcopy(cr)
    assert cr["properties"]["kind"]["enum"][-1] == "score"
    cr["properties"]["kind"]["enum"].pop()
    return cr


def traceevent_minus_delta(te):
    """TraceEvent def with the one intended delta (the cost variant's leading review-cost-kind invariant) removed;
    fails if the entry is missing, misplaced or appears in any other variant."""
    te = traceevent_minus_live(te)      # LIVE-DEADLINE-04 deliberate host.stop variant, subtracted first
    hits = [(i, j) for i, v in enumerate(te["oneOf"]) for j, s in enumerate(v.get("x-invariants", []))
            if s.startswith("review-cost-kind:")]
    assert len(hits) == 1, hits
    i, j = hits[0]
    assert te["oneOf"][i]["properties"]["type"]["const"] == "cost" and j == 0, hits
    del te["oneOf"][i]["x-invariants"][0]
    return te


# ---- invented score-family fixtures (written independently of the author's suite) -------------------------------
EVR_A, EVR_B = "evr_" + "a" * 16, "evr_" + "b" * 16
CASE = "z901-t07"
INPUTS = C.digest({"reviewer-invented": "rendered score inputs"})
AUTH = C.digest({"reviewer-invented": "spend authorization file"})
ROLE_SCHEMA = {"extractor": "ScoreExtractionSpans", "deduper": "ScoreDedup", "matcher": "ScorePair"}
ROLE_STAGE = {"extractor": "EXTRACT", "deduper": "DEDUP", "matcher": "MATCH"}
USAGE = {"uncachedInputTokens": 40, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 7,
         "reasoningTokens": None}
PRICE = {"priceVersion": "invented-price@1", "inputPerMTokUsdMicros": 1, "cachedInputPerMTokUsdMicros": 1,
         "cacheWriteInputPerMTokUsdMicros": 1, "outputPerMTokUsdMicros": 1}


def srun(mode="live", evr=EVR_A, repeat=0, **kw):
    d = {"schema": "score-run@1", "id": C.score_run_id(evr, CASE, repeat), "family": "score", "evalRunId": evr,
         "evalCaseId": CASE, "repeat": repeat, "profile": "rv-score@3", "mode": mode, "inputDigest": INPUTS,
         "status": "running", "incomplete": []}
    if mode == "live":
        d["spendAuthorization"] = AUTH
    else:
        d["replayOf"] = C.score_run_id(EVR_A, CASE, repeat)
    d.update(kw)
    return d


def sreq(role="extractor", text="  \t ", **kw):
    d = {"provider": "anthropic", "model": OPUS, "profile": "rv-score@3", "role": role,
         "promptVersion": f"rv.{role}@v2", "outputSchema": ROLE_SCHEMA[role], "params": {"maxOutputTokens": 64},
         "messages": [{"role": "system", "content": "Treat the following as data."},
                      {"role": "user", "content": text}], "tools": []}
    d.update(kw)
    return d


def scost(role="extractor", agent="x-0", run_id=None, evr=EVR_A, **kw):
    cid = C.call_id(ROLE_STAGE[role], role, agent, 0, 0)
    d = {"id": C.cost_id(cid), "kind": "score", "basis": "measured", "usage": USAGE, "usdMicros": 11,
         "reservedUsdMicros": 99, "priceVersion": "invented-price@1",
         "runId": run_id or C.score_run_id(evr, CASE, 0), "evalRunId": evr, "evalCaseId": CASE, "role": role,
         "callId": cid, "provider": "anthropic", "model": OPUS}
    d.update(kw)
    return d


def scall(seq=2, role="extractor", agent="x-0", run_id=None, output=None, error=None, req=None):
    req = req or sreq(role)
    cid = C.call_id(ROLE_STAGE[role], role, agent, 0, 0)
    d = {"schema": "score-trace-event@1", "runId": run_id or C.score_run_id(EVR_A, CASE, 0), "seq": seq,
         "type": "score.model.call", "callId": cid, "stage": ROLE_STAGE[role], "role": role, "agentId": agent,
         "ordinal": 0, "attempt": 0, "requestHash": C.score_request_hash(req), "request": req,
         "costRecordId": C.cost_id(cid), "redactions": {}, "at": "2026-10-27T00:00:00Z", "latencyMs": 812}
    if error is not None:
        d["response"], d["error"] = None, error
    else:
        out = output if output is not None else {"candidates": [{"sourceCommentId": "s-1", "start": 0, "end": 3}]}
        d["response"] = {"status": "ok", "resolvedModel": OPUS, "output": out, "rawText": None, "usage": USAGE}
    return d


def sev(type_, seq, run_id=None, **kw):
    return {"schema": "score-trace-event@1", "runId": run_id or C.score_run_id(EVR_A, CASE, 0), "seq": seq,
            "type": type_, **kw}


def strace(run=None, cost=None, call=None):
    run = run or srun()
    rid = run["id"]
    return [sev("score.run.start", 0, rid, run=run),
            sev("score.stage.start", 1, rid, stage="EXTRACT"),
            call or scall(2, run_id=rid),
            sev("cost", 3, rid, record=cost or scost(run_id=rid, evr=run["evalRunId"])),
            sev("score.stage.end", 4, rid, stage="EXTRACT", status="completed"),
            sev("score.run.end", 5, rid, status="completed", incomplete=[])]


def replay_of(trace, evr=EVR_B):
    run = srun("strict-replay", evr=evr)
    rid = run["id"]
    out = copy.deepcopy(trace)
    for e in out:
        e["runId"] = rid
        e.pop("at", None)
        e.pop("latencyMs", None)
    out[0]["run"] = run
    rec = out[3]["record"]
    rec.update(runId=rid, evalRunId=evr, basis="replayed", replayOf=rec["id"])
    return out


BUDGET_ERR = {"code": "budget-exhausted", "message": "invented: reservation refused", "retryable": False,
              "detail": {"class": "budget", "reservedUsdMicros": 99}}
PROVIDER_ERR = {"code": "provider-error", "message": "invented: upstream 502", "retryable": False}


class Base(unittest.TestCase):
    def ok(self, entity, doc):
        self.assertEqual([str(i) for i in validate(entity, doc)], [], entity)

    def bad(self, entity, doc, code=None):
        issues = validate(entity, doc)
        self.assertTrue(issues, f"{entity} unexpectedly valid")
        if code:
            self.assertIn(code, {i.code for i in issues}, [str(i) for i in issues])
        return issues


# ============================================================ L1 / L2: compatibility against the frozen baseline
class L1L2Compatibility(Base):
    def test_every_baseline_def_except_the_two_declared_changed_defs_is_byte_identical(self):
        got = [[n, C.digest(budget_minus_live(REGISTRY[n].to_json()) if n == "Budget" else REGISTRY[n].to_json())]
               for n in OLD_DEF_NAMES - CHANGED_DEFS]
        self.assertEqual(len(got), 39)
        self.assertEqual(combined(got), OLD_DEFS_COMBINED)

    def test_live_stage_budget_and_host_stop_shapes_are_pinned_independently(self):
        # LIVE-DEADLINE-04: the new shapes are asserted on their own, so the normalization excuses nothing else.
        self.assertEqual(C.digest(REGISTRY["Budget"].to_json()), LIVE_BUDGET_DIGEST)
        te = REGISTRY["TraceEvent"].to_json()
        self.assertEqual(C.digest(te), LIVE_TRACEEVENT_DIGEST)
        self.assertEqual(C.digest(host_stop_variant(te)), LIVE_HOST_STOP_DIGEST)

    def test_CostRecord_changes_only_by_appending_score_to_kind(self):
        cr = REGISTRY["CostRecord"].to_json()
        self.assertNotEqual(C.digest(cr), COSTRECORD_BASELINE)
        self.assertEqual(C.digest(costrecord_minus_delta(cr)), COSTRECORD_BASELINE)

    def test_TraceEvent_changes_only_by_the_review_cost_kind_invariant(self):
        te = REGISTRY["TraceEvent"].to_json()
        self.assertNotEqual(C.digest(te), TRACEEVENT_BASELINE)
        self.assertEqual(C.digest(traceevent_minus_delta(te)), TRACEEVENT_BASELINE)

    def test_registry_is_baseline_plus_exactly_the_nine_family_defs(self):
        self.assertEqual(set(ENTITY_NAMES), OLD_DEF_NAMES | NEW_DEF_NAMES)
        self.assertEqual(list(ENTITY_NAMES), sorted(ENTITY_NAMES))

    def test_public_bundle_is_version7_current_and_carries_identical_old_defs(self):
        self.assertEqual(CONTRACTS_VERSION, "s0a-contracts@7")
        r = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "export", "--check"], cwd=ROOT,
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        bundle = loads_strict((ROOT / "reviewer/contracts/schemas/contracts.schema.json").read_bytes())
        self.assertEqual(bundle["$id"], "reviewer-contracts-s0a-contracts@7")
        self.assertEqual(set(bundle["$defs"]), OLD_DEF_NAMES | NEW_DEF_NAMES)
        got = [[n, C.digest(budget_minus_live(bundle["$defs"][n]) if n == "Budget" else bundle["$defs"][n])]
               for n in OLD_DEF_NAMES - CHANGED_DEFS]
        self.assertEqual(combined(got), OLD_DEFS_COMBINED)
        for n in ("Budget", "TraceEvent", "CostRecord"):                    # and the current registry, exactly
            self.assertEqual(C.digest(bundle["$defs"][n]), C.digest(REGISTRY[n].to_json()), n)
        self.assertEqual(C.digest(costrecord_minus_delta(bundle["$defs"]["CostRecord"])), COSTRECORD_BASELINE)
        self.assertEqual(C.digest(traceevent_minus_delta(bundle["$defs"]["TraceEvent"])), TRACEEVENT_BASELINE)

    def test_review_provider_projections_are_unchanged(self):
        from reviewer.runtime import schemas as S
        got = []
        for n in S.SCHEMA_NAMES:
            for f in ("anthropic", "openai-strict"):
                got.append([f"{n}/{f}", hashlib.sha256(json.dumps(S.provider_schema(n, f), sort_keys=True)
                                                       .encode()).hexdigest()])
            got.append([f"{n}/original", hashlib.sha256(json.dumps(S.original(n), sort_keys=True)
                                                        .encode()).hexdigest()])
        self.assertEqual(len(got), 15)
        self.assertEqual(combined(got), PROJECTIONS_COMBINED)
        for n in S.SCHEMA_NAMES:                      # no score schema leaked into the review projection set
            self.assertNotIn("Score", n)

    def test_baseline_review_documents_validate_and_hash_identically(self):
        rows = []
        for n in BASELINE_EXAMPLES:
            d = ex(n)
            self.assertEqual(validate(n.split(".")[0], d), [], n)
            rh = C.request_hash(d["request"]) if n.startswith("TraceEvent") and d.get("type") == "model.call" \
                else None
            rows.append([n, C.digest(d), C.comparable_digest(d), rh])
        self.assertEqual(combined(rows), EXAMPLES_COMBINED)

    def test_review_comparison_tables_keep_their_baseline_entries(self):
        for k, v in REVIEW_IGNORE_BASELINE.items():
            self.assertEqual(set(C.COMPARE_IGNORE[k]), v, k)
        for k, v in REVIEW_NESTED_BASELINE.items():
            self.assertEqual(C._NESTED[k], v, k)
        for k, v in REVIEW_TAGS_BASELINE.items():
            self.assertEqual(C._SCHEMA_TAGS[k], v)
        self.assertEqual(set(C.COMPARE_IGNORE) - set(REVIEW_IGNORE_BASELINE), {"ScoreRun", "ScoreTraceEvent"})
        self.assertEqual(set(C._NESTED) - set(REVIEW_NESTED_BASELINE), {"ScoreTraceEvent"})
        self.assertEqual(set(C._SCHEMA_TAGS) - set(REVIEW_TAGS_BASELINE), {"score-trace-event@1", "score-run@1"})


# ============================================================ A7: score errors omit the review Stage
class A7Errors(Base):
    def test_TypedError_keeps_the_review_stage_enum(self):
        self.assertEqual(REGISTRY["TypedError"].to_json()["properties"]["stage"]["enum"], list(STAGES))

    def test_budget_and_provider_errors_are_valid_score_documents_without_exceptions(self):
        rid = srun()["id"]
        for err in (BUDGET_ERR, PROVIDER_ERR):
            with self.subTest(err["code"]):
                self.ok("ScoreTraceEvent", scall(error=err))
                self.ok("ScoreTraceEvent", sev("error", 3, rid, error=err))
                self.ok("ScoreTraceEvent", sev("score.stage.end", 4, rid, stage="EXTRACT", status="failed",
                                               error=err))
                self.ok("ScoreRun", srun(status="failed", error=err, endedAt="2026-10-27T00:00:09Z"))

    def test_any_stage_on_a_score_error_is_an_issue_never_an_exception(self):
        rid = srun()["id"]
        for stage in ("JUDGE", "INVESTIGATE", "EXTRACT", SENTINEL, 7, None):
            err = {**BUDGET_ERR, "stage": stage}
            with self.subTest(stage=stage):
                self.bad("ScoreTraceEvent", scall(error=err))
                self.bad("ScoreTraceEvent", sev("error", 3, rid, error=err))
                self.bad("ScoreTraceEvent", sev("score.stage.end", 4, rid, stage="EXTRACT", status="failed",
                                                error=err))
                self.bad("ScoreRun", srun(status="failed", error=err))

    def test_a_failed_score_trace_with_a_provider_error_call_validates_as_a_file(self):
        rid = srun()["id"]
        tr = strace(call=scall(2, run_id=rid, error=PROVIDER_ERR))
        tr[3]["record"].update(basis="unknown", usdMicros=None)
        tr[4].update(status="failed", error=PROVIDER_ERR)
        tr[5].update(status="partial", incomplete=[{"stage": "EXTRACT", "reason": "provider-failure"}])
        self.assertEqual(validate_score_trace(tr), [])


# ============================================================ A8: CostRecord kind=score
class A8Cost(Base):
    def test_live_and_replayed_score_costs_validate_and_round_trip_canonically(self):
        live = scost()
        rep = scost(run_id=C.score_run_id(EVR_B, CASE, 0), evr=EVR_B, basis="replayed", replayOf=live["id"])
        for d in (live, rep):
            self.ok("CostRecord", d)
            again = loads_strict(C.canonical_json(d))
            self.assertEqual(again, d)
            self.assertEqual(C.digest(again), C.digest(d))
        self.assertEqual(C.entity_of(live), "CostRecord")
        self.assertEqual(C.comparable_digest(live), C.comparable_digest(rep))

    def test_score_cost_attribution_refusals(self):
        base = scost()
        for k in ("runId", "evalRunId", "evalCaseId", "callId", "role"):
            d = dict(base)
            del d[k]
            with self.subTest(missing=k):
                self.bad("CostRecord", d, "cost-attribution")
        for k, v in {"stage": "JUDGE", "toolCallId": "tool_" + "1" * 16, "retryOf": base["callId"],
                     "role": "judge", "id": "cost_" + "0" * 16}.items():
            with self.subTest(field=k):
                self.bad("CostRecord", {**base, k: v}, "cost-attribution")
        self.bad("CostRecord", {**base, "stage": "EXTRACT"})                      # not even a review Stage value
        self.bad("CostRecord", {**base, "basis": "replayed"}, "cost-attribution")  # replayed needs replayOf

    def test_score_cost_primitive_and_bool_int_boundaries(self):
        base = scost()
        for k, v in {"usdMicros": True, "reservedUsdMicros": False, "usdMicros": 1.0,
                     "kind": "SCORE", "basis": None, "evalCaseId": "", "runId": "run_XYZ"}.items():
            d = {**base, k.strip(): v}
            with self.subTest(field=k, value=v):
                self.bad("CostRecord", d)
        self.bad("CostRecord", {**base, "usage": {**USAGE, "outputTokens": True}})
        self.bad("CostRecord", {**base, "usdMicros": -1})

    def test_old_cost_kinds_keep_their_semantics(self):
        ev = ex("CostRecord.eval-synthetic")
        self.ok("CostRecord", ev)
        d = dict(ev)
        d.pop("evalCaseId", None)
        self.bad("CostRecord", d, "cost-attribution")
        self.bad("CostRecord", {**ev, "callId": ev.get("callId", "call_" + "3" * 16),
                                "toolCallId": "tool_" + "3" * 16}, "cost-attribution")
        # a review/eval cost still may carry a review stage; a score cost may not
        if "stage" not in ev:
            self.ok("CostRecord", {**ev, "stage": "JUDGE"})

    def test_score_trace_refuses_non_score_costs(self):
        rid = srun()["id"]
        ev = ex("CostRecord.eval-synthetic")
        self.bad("ScoreTraceEvent", sev("cost", 3, rid, record=ev), "score-cost-kind")

    def test_score_trace_refuses_a_cost_from_another_eval_run_or_case(self):
        rid = srun()["id"]
        for k, v in (("evalRunId", EVR_B), ("evalCaseId", "z999-t99")):
            tr = strace(cost=scost(run_id=rid, **{k: v}) if k != "evalRunId" else scost(run_id=rid, evr=EVR_B))
            with self.subTest(k):
                self.assertIn("trace-cost", {i.code for i in validate_score_trace(tr)})

    # ---- D1 (closed by SCORE-CONTRACT-03, option b): a review trace refuses a score CostRecord -------------------
    @staticmethod
    def _review_trace(record):
        """run.start, the public model.call example and its cost event, renumbered into one valid review file."""
        run, call = ex("ReviewRun"), ex("TraceEvent.model-call")
        rid = run["id"]
        call = {**call, "seq": 1}
        return [{"schema": "trace-event@1", "runId": rid, "seq": 0, "type": "run.start", "run": run}, call,
                {"schema": "trace-event@1", "runId": rid, "seq": 2, "type": "cost", "record": record}]

    @staticmethod
    def _score_twin(record):
        """The same call's cost re-labelled as a valid score CostRecord (same id, callId and runId)."""
        d = {k: v for k, v in record.items() if k != "stage"}
        d.update(kind="score", role="extractor", evalRunId=EVR_A, evalCaseId=CASE)
        return d

    def test_D1_positive_control_review_and_eval_costs_stay_valid_in_a_review_trace(self):
        rec = ex("CostRecord.eval-synthetic")
        self.assertEqual(validate_trace(self._review_trace(rec)), [])
        review = {k: v for k, v in rec.items() if k not in ("evalRunId", "evalCaseId")}
        review.update(kind="review", basis="measured", usdMicros=7, provider="anthropic", model=OPUS)
        self.ok("CostRecord", review)
        self.assertEqual(validate_trace(self._review_trace(review)), [])
        for r in (rec, review):
            self.ok("TraceEvent", self._review_trace(r)[2])

    def test_D1_review_trace_event_and_file_refuse_a_score_cost(self):
        """ARCH-02 §2(iv) / A8: a score CostRecord outside the score family is refused, per event and per file."""
        score = self._score_twin(ex("CostRecord.eval-synthetic"))
        self.ok("CostRecord", score)                              # valid on its own: only the family boundary refuses
        tr = self._review_trace(score)
        issues = validate("TraceEvent", tr[2])
        self.assertEqual([(i.path, i.code) for i in issues], [("$.record.kind", "review-cost-kind")])
        self.assertEqual([(i.path, i.code) for i in validate_trace(tr)], [("[2].record.kind", "review-cost-kind")])
        self.ok("ScoreTraceEvent", sev("cost", 3, record=scost()))  # the score family still accepts its own cost
        self.assertEqual(validate_score_trace(strace()), [])

    def test_D1_malformed_review_cost_records_are_issues_never_exceptions(self):
        base = ex("CostRecord.eval-synthetic")
        for kind in (None, 0, True, "SCORE", "score ", [], {}, ["score"]):
            for rec in ({**base, "kind": kind}, {**self._score_twin(base), "kind": kind}):
                tr = self._review_trace(rec)
                with self.subTest(kind=kind):
                    self.assertTrue(validate("TraceEvent", tr[2]))
                    self.assertTrue(validate_trace(tr))
        for rec in (None, 0, "score", [], {}, {"kind": "score"}):
            with self.subTest(record=rec):
                self.assertTrue(validate("TraceEvent", self._review_trace(rec)[2]))
                self.assertTrue(validate_trace(self._review_trace(rec)))


# ============================================================ outputs: closed, strict-projectable, whitespace kept
class Outputs(Base):
    def test_whitespace_only_nonempty_text_is_valid_and_preserved_byte_for_byte(self):
        for text in (" ", "\t", "\n\n", "   ", "\r\n  x  \r\n"):
            doc = {"candidates": [{"sourceCommentId": " ", "text": text}]}
            with self.subTest(text=text):
                self.ok("ScoreExtraction", doc)
                self.assertEqual(loads_strict(C.canonical_json(doc))["candidates"][0]["text"], text)
        a, b = sreq(text=" "), sreq(text="  ")
        self.assertNotEqual(C.score_request_hash(a), C.score_request_hash(b))   # never normalised before hashing

    def test_output_refusals(self):
        cases = {
            "ScoreExtraction": [{"candidates": [{"sourceCommentId": "s", "text": ""}]},
                                {"candidates": [{"sourceCommentId": "", "text": "x"}]},
                                {"candidates": [{"sourceCommentId": "s", "text": None}]},
                                {"candidates": [{"sourceCommentId": "s"}]},
                                {"candidates": [{"sourceCommentId": "s", "text": "x", "why": "y"}]},
                                {"candidates": [], "notes": "x"}, {}, {"candidates": "x"}],
            "ScoreExtractionSpans": [{"candidates": [{"sourceCommentId": "s", "start": 0, "end": 0}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": 4, "end": 2}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": -1, "end": 2}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": True, "end": 2}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": 0, "end": 2.0}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": "0", "end": 2}]},
                                     {"candidates": [{"sourceCommentId": "", "start": 0, "end": 2}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": 0}]},
                                     {"candidates": [{"sourceCommentId": "s", "start": 0, "end": 2, "text": "x"}]},
                                     {"candidates": [], "notes": "x"}, {}, {"candidates": "x"}],
            "ScoreDedup": [{"groups": [[]]}, {"groups": [[-1]]}, {"groups": [[True]]}, {"groups": [[0.0]]},
                           {"groups": [0]}, {"groups": [[0]], "reasoning": "x"}, {}],
            "ScorePair": [{"match": 1, "confidence": 0.1}, {"match": True, "confidence": True},
                          {"match": True, "confidence": float("nan")}, {"match": True, "confidence": float("inf")},
                          {"match": True, "confidence": "0.9"}, {"match": True},
                          {"match": True, "confidence": 0.5, "explanation": "x"}, {"match": None, "confidence": 0}],
        }
        for ent, docs in cases.items():
            for d in docs:
                with self.subTest(ent=ent, doc=d):
                    self.bad(ent, d)

    def test_output_schemas_are_closed_and_have_no_free_text_besides_extraction_text(self):
        bundle = export_bundle("x")["$defs"]

        def walk(node, path):
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False, path)
                    self.assertEqual(sorted(node.get("required", [])), sorted(node.get("properties", {})), path)
                for bad in ("anyOf", "oneOf", "patternProperties"):
                    self.assertNotIn(bad, node, path)
                for k, v in node.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, f"{path}[{i}]")
        for n in ("ScoreExtraction", "ScoreExtractionSpans", "ScoreDedup", "ScorePair"):
            walk(bundle[n], n)
        self.assertEqual(sorted(bundle["ScoreExtractionSpans"]["properties"]["candidates"]["items"]["properties"]),
                         ["end", "sourceCommentId", "start"])                  # v3: no model-written text field
        self.assertEqual(sorted(bundle["ScorePair"]["properties"]), ["confidence", "match"])
        self.assertEqual(sorted(bundle["ScoreDedup"]["properties"]), ["groups"])


# ============================================================ profile / request: role, model, no tools/retry/fallback
class ProfileAndRequest(Base):
    def profile(self):
        def role(r):
            return {"provider": "anthropic", "model": OPUS, "family": "anthropic", "resolved": True,
                    "promptVersion": f"rv.{r}@v2", "outputSchema": ROLE_SCHEMA[r], "params": {},
                    "caps": {"maxOutputTokens": 512, "timeoutSec": 60, "maxRetries": 0, "maxRepairs": 0},
                    "price": PRICE, "fallbacks": []}
        return {"id": "rv-score", "version": 3, "roles": {r: role(r) for r in ROLE_SCHEMA}}

    def test_invented_profile_is_valid(self):
        self.ok("ScoreProfile", self.profile())

    def test_profile_refusals(self):
        muts = {
            "sonnet": ("model", "anthropic/claude-sonnet-5.5"), "dev alias": ("model", "claude-opus-5-5"),
            "latest": ("model", "anthropic/claude-opus-latest"), "openai": ("provider", "openai"),
            "unresolved": ("resolved", False), "wrong schema": ("outputSchema", "ScoreDedup"),
            "no price": ("price", None), "fallback": ("fallbacks", ["rv-score@2"]),
        }
        for name, (k, v) in muts.items():
            p = self.profile()
            p["roles"]["matcher"][k] = v
            with self.subTest(name):
                self.bad("ScoreProfile", p)
        for cap, v in (("maxRetries", 1), ("maxRetries", False), ("maxRepairs", 1), ("maxRepairs", 0.0)):
            p = self.profile()
            p["roles"]["deduper"]["caps"][cap] = v
            with self.subTest(cap=cap, v=v):
                self.bad("ScoreProfile", p, "const")
        p = self.profile()
        p["roles"]["judge"] = p["roles"]["matcher"]
        self.bad("ScoreProfile", p)
        p = self.profile()
        del p["roles"]["deduper"]
        self.bad("ScoreProfile", p)

    def test_profiles_do_not_cross_families(self):
        self.bad("ModelProfile", self.profile())
        self.bad("ScoreProfile", ex("ModelProfile.standard-candidate"))
        self.ok("ModelProfile", ex("ModelProfile.standard-candidate"))

    def test_request_rules(self):
        for r in ROLE_SCHEMA:
            self.ok("ScoreRequest", sreq(r))
        self.bad("ScoreRequest", sreq("matcher", outputSchema="ScoreExtractionSpans"), "score-role-schema")
        self.bad("ScoreRequest", sreq("extractor", outputSchema="ScoreExtraction"))    # legacy copy shape: no longer role-legal
        self.bad("ScoreRequest", sreq(tools=[{"type": "function", "name": "read_file"}]), "max-items")
        req = sreq()
        del req["tools"]
        self.bad("ScoreRequest", req)
        for k, v in {"hop": 0, "continuationOf": "call_" + "1" * 16, "runId": "run_" + "1" * 16,
                     "evalRunId": EVR_A, "model": "claude-opus-5-5", "provider": "openrouter", "role": "judge",
                     "messages": []}.items():
            with self.subTest(k):
                self.bad("ScoreRequest", {**sreq(), k: v})

    def test_requests_and_hashes_do_not_cross_families(self):
        review_req = ex("TraceEvent.model-call")["request"]
        self.bad("ScoreRequest", review_req)
        self.bad("ModelRequest", sreq())
        with self.assertRaises(ValueError):
            C.request_hash(sreq())
        with self.assertRaises(ValueError):
            C.score_request_hash(review_req)
        self.assertEqual(C.request_hash(review_req), ex("TraceEvent.model-call")["requestHash"])

    def test_score_request_hash_refuses_protected_text(self):
        from reviewer.contracts.redaction import contains_protected
        leaked = "sk-or-v1-" + "0" * 64
        if not contains_protected(leaked):
            self.skipTest("redaction patterns do not cover this invented shape")
        with self.assertRaises(ValueError):
            C.score_request_hash(sreq(text=leaked))

    def test_LIMIT_params_are_opaque_and_tool_role_messages_are_shape_valid(self):
        """Contract leaves params as opaque Json and reuses the shared Message (role 'tool' allowed). 'No tools'
        is enforced only on the top-level tools array; params/tool-message hygiene is SCORE-GW/RT work."""
        self.ok("ScoreRequest", sreq(params={"tools": [{"name": "x"}], "models": ["other/model"],
                                             "tool_choice": "auto"}))
        req = sreq()
        req["messages"].append({"role": "tool", "content": "x"})
        self.ok("ScoreRequest", req)


# ============================================================ A10: run identity and replay
class A10RunIdentity(Base):
    def test_run_documents_validate(self):
        self.ok("ScoreRun", srun())
        self.ok("ScoreRun", srun("strict-replay", evr=EVR_B))
        self.assertEqual(C.entity_of(srun()), "ScoreRun")

    def test_id_derivation_and_family_separation(self):
        rid = C.score_run_id(EVR_A, CASE, 0)
        self.assertRegex(rid, r"^run_[0-9a-f]{16}$")
        self.assertNotEqual(rid, C.score_run_id(EVR_B, CASE, 0))
        self.assertNotEqual(rid, C.score_run_id(EVR_A, CASE, 1))
        for key in ("score-run", EVR_A, f"idem:eval:{'0' * 64}"):
            self.assertNotEqual(rid, C.run_id(key, 0))
        self.bad("ScoreRun", srun(id=C.score_run_id(EVR_A, CASE, 1)), "score-run-identity")
        self.bad("ScoreRun", srun(id=C.run_id("idem:eval:" + "0" * 64, 0)))

    def test_replay_needs_a_fresh_eval_run_and_a_different_run_id(self):
        rec = srun()
        rep = srun("strict-replay", evr=EVR_B)
        self.assertNotEqual(rep["id"], rec["id"])
        self.assertEqual(check_score_replay(rec, rep), [])
        same = srun("strict-replay", evr=EVR_A)                # reusing the recorded coordinates
        self.bad("ScoreRun", same)                               # replayOf == own id is refused per document
        self.assertTrue(check_score_replay(rec, same))
        for k, v in (("inputDigest", C.digest("other")), ("profile", "rv-score@4"), ("repeat", 1)):
            other = srun("strict-replay", evr=EVR_B, **({k: v} if k != "repeat" else {}))
            if k == "repeat":
                other = srun("strict-replay", evr=EVR_B, repeat=1)
            with self.subTest(k):
                self.assertIn(f"$.{k}", {i.path for i in check_score_replay(rec, other)})

    def test_mode_and_authorization_rules(self):
        d = srun()
        del d["spendAuthorization"]
        self.bad("ScoreRun", d)
        self.bad("ScoreRun", srun("strict-replay", evr=EVR_B, spendAuthorization=AUTH))
        d = srun("strict-replay", evr=EVR_B)
        del d["replayOf"]
        self.bad("ScoreRun", d)
        self.bad("ScoreRun", srun(replayOf=C.score_run_id(EVR_B, CASE, 0)))
        self.bad("ScoreRun", srun(status="completed", incomplete=[{"stage": "MATCH", "reason": "budget"}]))
        self.bad("ScoreRun", srun(status="partial"))
        self.bad("ScoreRun", srun(incomplete=[{"stage": "MATCH", "reason": "budget", "note": "x"}]))
        self.bad("ScoreRun", srun(incomplete=[{"stage": "JUDGE", "reason": "budget"}]))
        self.bad("ScoreRun", srun(repeat=True))

    def test_review_and_score_runs_do_not_cross(self):
        self.bad("ReviewRun", srun())
        self.bad("ScoreRun", ex("ReviewRun"))


# ============================================================ A9: trace family, canonical comparison
class A9TraceAndComparison(Base):
    def test_invented_trace_is_valid_and_carries_its_own_tag(self):
        tr = strace()
        self.assertEqual(validate_score_trace(tr), [])
        self.assertTrue(all(e["schema"] == "score-trace-event@1" for e in tr))
        self.assertTrue(all(C.entity_of(e) == "ScoreTraceEvent" for e in tr))

    def test_cross_family_trace_refusals(self):
        tr = strace()
        self.assertTrue(validate_trace(tr))
        for e in tr:
            self.bad("TraceEvent", e)
        review = ex("TraceEvent.model-call")
        self.bad("ScoreTraceEvent", review)
        self.assertTrue(validate_score_trace([review]))
        relabel = [{**e, "schema": "trace-event@1"} for e in tr]
        self.assertTrue(validate_trace(relabel))
        self.assertTrue(validate_score_trace(relabel))
        bad = strace()
        bad[0]["run"] = ex("ReviewRun")
        self.assertTrue(validate_score_trace(bad))

    def test_file_rules(self):
        for name, mutate in {
            "seq gap": lambda t: t[2].update(seq=7),
            "second run": lambda t: t[1].update(runId=C.score_run_id(EVR_B, CASE, 0)),
            "end not last": lambda t: t.insert(2, sev("score.run.end", 2, status="completed", incomplete=[])),
            "dup call": lambda t: t.insert(3, copy.deepcopy(t[2])),
            "cost for other role": lambda t: t[3]["record"].update(role="matcher"),
            "no start": lambda t: t.pop(0),
        }.items():
            tr = strace()
            mutate(tr)
            with self.subTest(name):
                self.assertTrue(validate_score_trace(tr))
        self.assertTrue(validate_score_trace([]))
        self.assertTrue(validate_score_trace("not a list"))

    def test_call_event_recomputes_ids_and_hash_and_pins_role_stage(self):
        for k, v in {"requestHash": C.digest("x"), "callId": "call_" + "0" * 16, "costRecordId": "cost_" + "0" * 16,
                     "stage": "MATCH", "attempt": 1}.items():
            e = scall()
            e[k] = v
            with self.subTest(k):
                self.bad("ScoreTraceEvent", e)
        e = scall()
        e["request"] = sreq("matcher")
        e["requestHash"] = C.score_request_hash(e["request"])
        self.bad("ScoreTraceEvent", e)                           # request role differs from the event role
        e = scall()
        e["error"] = PROVIDER_ERR                                # response AND error
        self.bad("ScoreTraceEvent", e)

    def test_replay_compares_equal_only_up_to_the_intended_ignore_sets(self):
        live = strace()
        rep = replay_of(live)
        self.assertEqual(validate_score_trace(rep), [])
        self.assertEqual([C.comparable_digest(e) for e in live], [C.comparable_digest(e) for e in rep])
        meaningful = [
            (0, ("run", "inputDigest"), C.digest("other")), (0, ("run", "evalCaseId"), "z902-t07"),
            (0, ("run", "repeat"), 1), (0, ("run", "profile"), "rv-score@4"), (0, ("run", "status"), "failed"),
            (0, ("run", "incomplete"), [{"stage": "DEDUP", "reason": "unsent"}]),
            (2, ("response", "output"), {"candidates": []}), (2, ("request", "messages", 1, "content"), " "),
            (2, ("requestHash",), C.digest("x")), (2, ("agentId",), "x-1"), (2, ("redactions",), {"p": 1}),
            (2, ("response", "usage", "outputTokens"), 8),
            (3, ("record", "usdMicros"), 12), (3, ("record", "evalCaseId"), "z902-t07"),
            (3, ("record", "role"), "deduper"), (3, ("record", "model"), "other/model"),
            (4, ("status",), "failed"), (5, ("incomplete",), [{"stage": "MATCH", "reason": "budget"}]),
            (1, ("seq",), 9), (1, ("stage",), "DEDUP"),
        ]
        for i, path, v in meaningful:
            t = copy.deepcopy(rep)
            node = t[i]
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = v
            with self.subTest(event=i, path=path):
                self.assertNotEqual(C.comparable_digest(t[i]), C.comparable_digest(live[i]))

    def test_ignore_sets_apply_only_at_their_own_scope(self):
        # ScoreRun's ignore set must not mask same-named keys at the event envelope, and the event envelope set must
        # not mask same-named keys inside the nested run or record.
        e = sev("score.stage.start", 1, stage="EXTRACT")
        cmp = C.comparable(e)
        for k in ("schema", "seq", "type", "stage"):
            self.assertIn(k, cmp)
        self.assertNotIn("runId", cmp)
        nested = C.comparable(sev("score.run.start", 0, run=srun()))["run"]
        self.assertEqual(set(srun()) - set(nested), {"id", "mode", "evalRunId", "spendAuthorization"})
        rec = C.comparable(sev("cost", 3, record=scost()))["record"]
        self.assertEqual(set(scost()) - set(rec), {"runId", "evalRunId", "basis"})
        self.assertIn("evalCaseId", rec)
        self.assertEqual(C.COMPARE_IGNORE["ScoreRun"], frozenset({"id", "mode", "evalRunId", "replayOf",
                                                                  "spendAuthorization", "startedAt", "endedAt"}))
        self.assertEqual(C.COMPARE_IGNORE["ScoreTraceEvent"], frozenset({"runId", "at", "latencyMs"}))

    # ---- N1 (closed by SCORE-CONTRACT-03): a strict-replay score trace carries only replayed costs --------------
    def test_N1_strict_replay_trace_refuses_every_new_charge_basis(self):
        """The comparison ignores basis, so the trace validator is the contract-level guard: in a strict-replay run
        every cost has basis replayed. Each refused record is valid as a CostRecord on its own."""
        news = {"measured": {}, "estimated": {}, "unknown": {"usdMicros": None},
                "synthetic": {"provider": "synthetic", "model": "synthetic-fixture"}}
        for basis, extra in news.items():
            for keep_replay_of in (False, True):
                rep = replay_of(strace())
                rec = rep[3]["record"]
                rec.update(basis=basis, **extra)
                if not keep_replay_of:
                    rec.pop("replayOf")
                with self.subTest(basis=basis, replayOf=keep_replay_of):
                    self.ok("ScoreTraceEvent", rep[3])
                    self.assertEqual([(i.path, i.code) for i in validate_score_trace(rep)],
                                     [("[3].record.basis", "trace-cost")])
                    if basis in ("measured", "estimated"):    # the comparison alone cannot see the new charge
                        self.assertEqual(C.comparable_digest(rep[3]), C.comparable_digest(strace()[3]))

    def test_N1_live_traces_keep_their_new_charge_bases(self):
        for basis, extra in {"measured": {}, "estimated": {}, "unknown": {"usdMicros": None}}.items():
            tr = strace()
            tr[3]["record"].update(basis=basis, **extra)
            with self.subTest(basis=basis):
                self.assertEqual(validate_score_trace(tr), [])

    def test_N1_replayed_costs_keep_the_recorded_amount_or_null(self):
        for usd in (11, 0, 900, None):
            rep = replay_of(strace())
            rep[3]["record"]["usdMicros"] = usd
            with self.subTest(usd=usd):
                self.assertEqual(validate_score_trace(rep), [])
        rep = replay_of(strace())
        rep[3]["record"].pop("replayOf")                          # a replayed cost still names its recorded record
        self.assertIn("cost-attribution", {i.code for i in validate_score_trace(rep)})

    def test_N1_a_recorded_failure_replays_as_a_retained_failure_with_no_new_spend(self):
        """Live: provider-error call, unknown cost (usd null), failed stage, partial run. Its strict replay keeps the
        error, the failed stage and the partial outcome; its cost is basis replayed with the recorded null amount.
        This says nothing about releasing the original unknown exposure in a ledger (SCORE-GW/ledger)."""
        rid = srun()["id"]
        live = strace(call=scall(2, run_id=rid, error=PROVIDER_ERR))
        live[3]["record"].update(basis="unknown", usdMicros=None)
        live[4].update(status="failed", error=PROVIDER_ERR)
        live[5].update(status="partial", incomplete=[{"stage": "EXTRACT", "reason": "provider-failure"}])
        self.assertEqual(validate_score_trace(live), [])
        rep = replay_of(live)
        self.assertEqual(validate_score_trace(rep), [])
        self.assertEqual(rep[3]["record"]["basis"], "replayed")
        self.assertIsNone(rep[3]["record"]["usdMicros"])
        self.assertEqual(rep[2]["error"], PROVIDER_ERR)
        self.assertIsNone(rep[2]["response"])
        self.assertNotIn("spendAuthorization", rep[0]["run"])
        self.assertEqual([C.comparable_digest(e) for e in live], [C.comparable_digest(e) for e in rep])
        fresh = copy.deepcopy(rep)                                # re-booking the failure as fresh unknown spend
        fresh[3]["record"]["basis"] = "unknown"
        self.assertEqual([(i.path, i.code) for i in validate_score_trace(fresh)],
                         [("[3].record.basis", "trace-cost")])

    def test_LIMIT_SYMPTOM_ok_response_output_is_not_checked_against_the_role_schema(self):
        """ModelResponse.output is opaque Json (shared, unchanged). An ok score.model.call whose output violates
        ScorePair validates as a trace event; output conformance is the gateway's _output_issues (SCORE-GW)."""
        req = sreq("matcher")
        e = scall(role="matcher", agent="p-0", req=req, output={"match": "yes", "confidence": "high"})
        self.assertEqual(validate("ScoreTraceEvent", e), [])

    def test_cli_validates_the_score_family_and_keeps_review_dispatch(self):
        good, bad = strace(), strace()
        bad[2]["seq"] = 9
        with tempfile.TemporaryDirectory() as d:
            for name, tr, want in (("good", good, 0), ("bad", bad, 1)):
                p = Path(d) / f"{name}.jsonl"
                p.write_text("".join(json.dumps(e) + "\n" for e in tr))
                r = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "validate", "ScoreTraceEvent",
                                    str(p)], cwd=ROOT, capture_output=True, text=True, timeout=120)
                self.assertEqual(r.returncode, want, name + r.stdout + r.stderr)
            p = Path(d) / "good.jsonl"
            r = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "validate", "TraceEvent", str(p)],
                               cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 1)


# ============================================================ L3 / L4 and robustness
class L3L4AndRobustness(Base):
    def test_output_value_errors_do_not_echo_model_text(self):
        for ent, d in (("ScorePair", {"match": SENTINEL, "confidence": SENTINEL}),
                       ("ScoreDedup", {"groups": [[SENTINEL]]}),
                       ("ScoreExtraction", {"candidates": [{"sourceCommentId": SENTINEL * 30, "text": 0}]}),
                       ("ScoreExtraction", {"candidates": [{"sourceCommentId": "s", "text": SENTINEL * 20_000}]}),
                       ("ScoreExtractionSpans", {"candidates": [{"sourceCommentId": SENTINEL * 30, "start": SENTINEL, "end": 0}]})):
            with self.subTest(ent):
                issues = self.bad(ent, d)
                self.assertNotIn(SENTINEL, " ".join(str(i) for i in issues))

    def test_error_and_incomplete_records_have_no_model_text_channel(self):
        inc = REGISTRY["ScoreRun"].to_json()["properties"]["incomplete"]["items"]
        self.assertEqual(sorted(inc["properties"]), ["reason", "stage"])
        self.assertIn("enum", json.dumps(inc["properties"]["reason"]))
        props = REGISTRY["CostRecord"].to_json()["properties"]
        self.assertFalse({"message", "detail", "text", "reason"} & set(props))

    def test_LIMIT_SYMPTOM_enum_issues_echo_the_offending_host_value(self):
        """Shared schema.py behaviour (unchanged): enum/const issues quote the rejected value. No score OUTPUT schema
        has an enum, so model-written outputs are not echoed, but host-built fields are. Diagnostics stay in the
        trusted trace store and are mapped to fixed classes before any report/handoff (L3, SCORE-HOST)."""
        issues = validate("ScoreRun", srun(incomplete=[{"stage": "MATCH", "reason": SENTINEL}]))
        self.assertIn(SENTINEL, " ".join(str(i) for i in issues))

    def test_contract_allowlist_is_a_literal_with_no_runtime_or_secret_access(self):
        from reviewer.contracts import SCORE_MODELS
        from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS
        from reviewer.contracts.entities import DEV_ONLY_MODELS
        self.assertEqual(SCORE_MODELS, (OPUS,))
        self.assertTrue(set(SCORE_MODELS) <= set(ALLOWED_ROUTER_MODELS))
        self.assertFalse(set(SCORE_MODELS) & set(DEV_ONLY_MODELS))
        src = (ROOT / "reviewer/contracts/scoring_family.py").read_text()
        imports = [ln.strip() for ln in src.splitlines() if ln.startswith(("import ", "from "))]
        self.assertTrue(all(ln.startswith(("from __future__", "from .")) for ln in imports), imports)
        for needle in ("environ", "getenv", "open(", "subprocess", "urllib", "socket"):
            self.assertNotIn(needle, src, needle)
        sa = ex("SpendAuthorization.synthetic-recording")
        self.ok("SpendAuthorization", sa)                         # spend authorization def unchanged and separate

    def test_malformed_mutations_never_raise(self):
        bad_values = (None, True, 0, -1, 2.5, "", " ", SENTINEL, [], {}, [None], {"k": 1}, "JUDGE",
                      "run_" + "0" * 16)
        docs = {"ScoreRun": srun(), "ScoreRequest": sreq(), "CostRecord": scost(), "ScoreTraceEvent": scall(),
                "ScoreExtraction": {"candidates": [{"sourceCommentId": "s", "text": " "}]},
                "ScoreExtractionSpans": {"candidates": [{"sourceCommentId": "s", "start": 0, "end": 1}]},
                "ScoreDedup": {"groups": [[0, 1], [2]]}, "ScorePair": {"match": False, "confidence": -3.5}}

        def paths(node, pre=()):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield pre + (k,)
                    yield from paths(v, pre + (k,))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    yield pre + (i,)
                    yield from paths(v, pre + (i,))
        n = 0
        for ent, base in docs.items():
            for p in list(paths(base)):
                for v in bad_values + ("<delete>",):
                    d = copy.deepcopy(base)
                    node = d
                    for k in p[:-1]:
                        node = node[k]
                    if v == "<delete>":
                        if not isinstance(node, dict):
                            continue
                        del node[p[-1]]
                    else:
                        node[p[-1]] = v
                    n += 1
                    try:
                        validate(ent, d)
                    except Exception as e:  # noqa: BLE001
                        self.fail(f"{ent} {p} {v!r}: {type(e).__name__}")
        self.assertGreater(n, 1000)
        tr = strace()
        for i in range(len(tr)):
            for v in bad_values:
                t = copy.deepcopy(tr)
                t[i] = v
                validate_score_trace(t)                            # must return issues, not raise


if __name__ == "__main__":
    unittest.main()
