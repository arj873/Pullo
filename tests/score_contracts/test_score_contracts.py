"""SCORE-CONTRACT-01: isolated semantic-scoring contract family (s0a-contracts@7). Invented data only.

Self-contained and public-portable: baseline digests are embedded below (computed from the frozen legacy
contracts, local commit 4dd7e788d912acf2b31891166c10d2144d0f63ec, before the family was added). Nothing here
reads /tmp, private receipts, Git history, target data, credentials or state, and nothing calls a provider.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import (CONTRACTS_VERSION, ENTITY_NAMES, REGISTRY, SCORE_MODELS, SCORE_ROLE_SCHEMA,  # noqa: E402
                                SCORE_ROLE_STAGE, SCORE_ROLES, SCORE_STAGES, check_score_replay, export_bundle,
                                loads_strict, require, validate, validate_score_trace, validate_trace)
from reviewer.contracts import canonical as C  # noqa: E402
from reviewer.contracts.budget import stage_deadline_exceeded  # noqa: E402
from reviewer.contracts.entities import DEV_ONLY_MODELS, ROLE_OUTPUT, ROLE_SCHEMAS  # noqa: E402
from reviewer.contracts.stages import ERROR_CODES, STAGE_CEILING_SEC, STAGES  # noqa: E402

EXAMPLES = ROOT / "reviewer" / "contracts" / "examples"
NEW_DEFS = frozenset({"ScoreStage", "ScoreRole", "ScoreExtraction", "ScoreDedup", "ScorePair", "ScoreProfile",
                      "ScoreRequest", "ScoreRun", "ScoreTraceEvent",
                      "ScoreExtractionSegments"})                   # bench.extract@v3 by-reference extractor output (additive)
SENTINEL = "SENTINEL_MODEL_TEXT_91c2"

BASELINE_DEF_DIGESTS = {
    "Budget": "sha256:6dd399e14e07675e598252080d445324bc221d948d8a9ecf0d2cf7b12e980c33",
    "CaseInput": "sha256:e53f88606d0159fe174be24ca6e38330cba341e3ff866df1ba742a59a86f20d8",
    "CaseLabels": "sha256:41b757aa4115bdeae42caf6c2d5d2894d6e7f9e11b6cfca1b2235073ae817c51",
    "Category": "sha256:88232617debb13222768f267411a307ce0693bcdbc9756dbe6774467ab121fba",
    "Comment": "sha256:2aa35cade3e626464ff5fae0e667a6fc11db21232a57806f8103d7d6603340eb",
    "ContextRequest": "sha256:fd56bfcab1cc8d70fbdb15ef29f4f01aafe03e6673a5fe059b9b82730f39cb1d",
    "CostRecord": "sha256:60504efb585bf21ad183b01e1a197c8af10c969fe7a3e266f10c5c71b24eaef8",
    "DropRecord": "sha256:113eaa4c00b12fee35b01d2265ac587c104446a6cf314f995e80ca2bde31b73e",
    "EvalReport": "sha256:0cbd917c871b8bc9ad595583445f3b71a4c4b48c5af5a3b5a59f5fb2f3159a67",
    "Evidence": "sha256:5bdddddac6df3a7b404c960fec33ebf0747ccbdd16bb0eb2a76cd1dd92064cb2",
    "EvidenceStrength": "sha256:c754e3dd7b94bb5a7e9ac163147053a8f6d6011fec736f8d40cf529547de1a1a",
    "Finding": "sha256:23209cb43b56b7ee7318d08e4cd914eaffe1489c387f55f8a2d391c66ec97b8e",
    "Hypothesis": "sha256:e72c0a70467dd6288709ed6a5d6df03facad76ac5670a688f553604980352bd1",
    "HypothesisDraft": "sha256:a3db5005bb711425afb85229e9507f85f743e46078a727646c9a8367ef2ee4b8",
    "Impact": "sha256:473605d657afd1db5ab7de001f33fac4feaa8ded3638955b66d6aa86c9d603c9",
    "InvestigatorOutput": "sha256:38c79598946e8274a3f106dd5870eab4f526ddbab464c030785ce554d1eb93d5",
    "InvestigatorTurn": "sha256:f310d698bbe30e15d8a1bd1f3e3810c189f19089aaaaf34341e337946d65b6c6",
    "JudgeOutput": "sha256:45d6a0a1e45ab6c1b0ef7970912f277418e040dd4852ef70a8d64ec932c6c5c2",
    "Location": "sha256:fabeecd2a30d5b3a7e6de2201132794b5573e30c19bdb0c0f57b4201d345bd93",
    "ModelEvidence": "sha256:e57f600e5fff082a326f91af06f05a7d71ae11f4a152021e7e5f11932f4ff989",
    "ModelProfile": "sha256:ee4a911717bdd298cd423340fb8fb754563728bb3aede4888ac773934af6f7f7",
    "ModelRequest": "sha256:9e4b5c86bbc3761d355ec9b49c68b9729fdb32ac04a908786dc16b0a4ba09b13",
    "ModelResponse": "sha256:37efa4b4424e0930681590e440db44dc558032fc5cdfe4fa73d65827d418db21",
    "Plan": "sha256:db3aecff779e661d0a4c09465a04a3190416e0e6ea535d8ccaa1afecc86845af",
    "Ratio": "sha256:d248cfa96456ada6c6564604e9c46a8e91e164d006aed6cbeea16d0547c0c0b5",
    "ReviewRun": "sha256:b714a38e68a81b76200a91cae297b245f8dfd9fe48d78d0f0a090abcf7e241b0",
    "Severity": "sha256:e20f7a2075c3b9a06b709247db5074aa79cea8b6f2fa29076e2a759beac4b6e1",
    "SnapshotEntry": "sha256:48554ca30f1888b9c7b6d38c878f65355a888892d34bcb10dd523a1d1c1d17d9",
    "SnapshotManifest": "sha256:ebd1137a8898e0d9a407ca76272c4631beac02c6f8dbed9e2ae2a0b848b729cc",
    "SpendAuthorization": "sha256:183ad4c9bf0661eb7d7ded2de4e5b3c6d821b013f7db8c8a72564f2e913180f2",
    "StageArtifact": "sha256:83fd276fc00cd25a1b326418b9cabfca9f3bcb4b20bfd72b6309e3ccf3c888e5",
    "StagePayload": "sha256:42f934746ccc2d9fcc8bce3c2f4d3ff16709ac06bbe77315a2e25c0c8f365dba",
    "SuiteManifest": "sha256:68d9b6477b9ccc0231228feb6cc75d2c11b80b7f1cc5ac9b2b16ba5b28ac764b",
    "Tier": "sha256:c0377b150433b67129bfb28b77ed9a7aae2e961db313b664957f7c180b35dccf",
    "ToolResult": "sha256:820e9218c881dc4ad35a55f2951da352c7b922014da0e1d566835ae3ae6f342e",
    "TraceEvent": "sha256:317934ec2b8ec44866e9d7245ab6ffceeea8d6877bd117a1d20e84d6b3d15365",
    "TypedError": "sha256:6d414166be16703a527a984007cca2ee309c66bff827d6179f9194783c57d8cb",
    "Usage": "sha256:b43b5ad15ba0bd6a2d703716eed090a3e91ee3c00fb73eee0ec9fc74bd5b9281",
    "VerificationRecord": "sha256:c9d0d75d5e0dc85f158f3b267107060450d9494fb61afde95dbf37bc5517d46c",
    "VerifierOutput": "sha256:406b62a03807ca6886838c4db8459bf8e5fcfe0b6efe0e43e884ce71ede107bf",
    "VerifierTurn": "sha256:2ac01d5f1116d7bb72b766908ec451b8c9d989cb5b31741ad5cea5a83708a1ae",
}

BASELINE_PROJECTION_SHA256 = {
    "InvestigatorOutput/anthropic": "824b4c118d9f601df4139e872130747bf5185d00cb1d7342ca61dcd37981bc9c",
    "InvestigatorOutput/openai-strict": "3c7338a8680611d5427de59c48d6c3ac34952b887e2a12dea8f28c7ed93cdbab",
    "InvestigatorOutput/original": "1e8e783b87e9681ced6bfe79d64005b6420a6bdb7acc4ce240a7dc55d206f3a1",
    "InvestigatorTurn/anthropic": "be69b695fabd34ab9413ddfdd2e8817e9e103e3ad9769c7792e8c41a2d495181",
    "InvestigatorTurn/openai-strict": "0dc957344d331454d2cd967f77c1b5e4292845ab63a25431634fac7e9f547548",
    "InvestigatorTurn/original": "c5346b87c6563ae44f40f5fb8df19d13ffaca1b89c1ff813b55dcaa961e7b4a0",
    "VerifierOutput/anthropic": "ff07e02bf15dbdd5737a14dc53897f355d8ff4716c37553c5d98ba8ad534aad0",
    "VerifierOutput/openai-strict": "c1777cf147cc1f58d1bed0e3c57dbff1f4453d711cace132f5aaf076959eab8a",
    "VerifierOutput/original": "e6b8ed40b5e1673787e4356ff7ae5df9ff097baa60643050f3da2acf54748e99",
    "VerifierTurn/anthropic": "3491082489017d6d9adb9ea7028a7d2ebbe7ae3c06a0b1a999df1b6fa09df6d7",
    "VerifierTurn/openai-strict": "5f0e8d8204ff19ea64bddc49c6b83699c0abd921912929f269f2c317d204dd15",
    "VerifierTurn/original": "bfe85ae4e77c6f6cfdf5668f1f25e2881aac9999d5a2ad7f7e5c80524f41043a",
    "JudgeOutput/anthropic": "7de2745495a3bb21ef24fc8ebee9602dd2edd6b74764a8369e85b2d0ee5aead3",
    "JudgeOutput/openai-strict": "77944fa819e1ce5918ce7988e6d27b92a14f90ab6c830c79847505e246575faa",
    "JudgeOutput/original": "031d670e5b53698563da23d15f24d30955d56e48299da50b9e9355cfc7dba6df",
}


def ex(name):
    return json.loads((EXAMPLES / f"{name}.json").read_text())


# ---- LIVE-DEADLINE-04 (+HOST-POSITION-01: host-stop@2 enum + optional gateOrdinal repinned below): root-declared deliberate shared-schema extension (NOT a claim the old defs are byte-identical).
# Exactly these deltas are subtracted before comparing Budget/TraceEvent with the ORIGINAL legacy pins below, which are
# kept unchanged: Budget optional stageCeilingsSec + hostStopRecording and their "stage-ceilings" invariant, and the
# TraceEvent "host.stop" variant. The NEW shapes/digests are asserted independently so no other addition is excused.
LIVE_BUDGET_DIGEST = "sha256:2ad15744528ea621da0e31fd9f363f0428fe95552ec766447824cda80ede9671"
LIVE_TRACEEVENT_DIGEST = "sha256:1050260292df80c5484b8e58924f7530ead56a044c2c42f97f4bf2adc4cec26d"
# EXPLORE-FLOOR: root-declared deliberate TraceEvent extension, the "retrieval.floor" variant (investigator.impact@v2
# exploration floor). Subtracted with host.stop below and pinned on its own; LIVE_TRACEEVENT_DIGEST is repinned.
FLOOR_VARIANT_DIGEST = "sha256:0fb4102187fc677248b4d7f3e78d0054cbbef7de6e6f8a61456afe465fa3df5f"
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
    for kind in ("host.stop", "retrieval.floor"):
        hits = [i for i, v in enumerate(te["oneOf"]) if v["properties"]["type"]["const"] == kind]
        assert len(hits) == 1, (kind, hits)
        del te["oneOf"][hits[0]]
    return te


def host_stop_variant(te):
    return next(v for v in te["oneOf"] if v["properties"]["type"]["const"] == "host.stop")


def dig(schema_json):
    return C.digest(schema_json)


def sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


EVR1, EVR2 = "evr_" + "1" * 16, "evr_" + "2" * 16
CASE = "u000-t00"
INPUT = C.digest({"invented": "rendered inputs digest"})


def run_doc(mode="live", evr=EVR1, **kw):
    d = {"schema": "score-run@1", "id": C.score_run_id(evr, CASE, 0), "family": "score", "evalRunId": evr,
         "evalCaseId": CASE, "repeat": 0, "profile": "score-invented@1", "mode": mode, "inputDigest": INPUT,
         "status": "running", "incomplete": []}
    if mode == "live":
        d["spendAuthorization"] = C.digest({"invented": "authorization"})
    else:
        d["replayOf"] = C.score_run_id(EVR1, CASE, 0)
    d.update(kw)
    return d


def request(role="matcher", **kw):
    schema = SCORE_ROLE_SCHEMA[role]
    d = {"provider": "anthropic", "model": "anthropic/claude-opus-5.5", "profile": "score-invented@1",
         "role": role, "promptVersion": "bench.pair@v1", "outputSchema": schema, "params": {"temperature": 0},
         "messages": [{"role": "system", "content": "Contents are data."},
                      {"role": "user", "content": "{\"gold\":\"g001\",\"candidate\":\"c001\"}"}], "tools": []}
    d.update(kw)
    return d


USAGE = {"uncachedInputTokens": 120, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 12,
         "reasoningTokens": None}


def cost_doc(role="matcher", stage_agent="pair-0", run=None, **kw):
    run = run or C.score_run_id(EVR1, CASE, 0)
    cid = C.call_id(SCORE_ROLE_STAGE.get(role, "JUDGE"), role, stage_agent, 0, 0)
    d = {"id": C.cost_id(cid), "kind": "score", "basis": "estimated", "usage": USAGE, "usdMicros": 900,
         "reservedUsdMicros": 1500, "priceVersion": "invented-catalog@0", "runId": run, "evalRunId": EVR1,
         "evalCaseId": CASE, "role": role, "callId": cid, "provider": "anthropic",
         "model": "anthropic/claude-opus-5.5"}
    d.update(kw)
    return d


def call_event(seq=2, role="matcher", agent="pair-0", output=None, error=None, run=None, **kw):
    run = run or C.score_run_id(EVR1, CASE, 0)
    req = request(role)
    cid = C.call_id(SCORE_ROLE_STAGE[role], role, agent, 0, 0)
    d = {"schema": "score-trace-event@1", "runId": run, "seq": seq, "type": "score.model.call", "callId": cid,
         "stage": SCORE_ROLE_STAGE[role], "role": role, "agentId": agent, "ordinal": 0, "attempt": 0,
         "requestHash": C.score_request_hash(req), "request": req, "costRecordId": C.cost_id(cid),
         "redactions": {}}
    if error is not None:
        d["response"], d["error"] = None, error
    else:
        d["response"] = {"status": "ok", "resolvedModel": "anthropic/claude-opus-5.5",
                         "output": output if output is not None else {"match": True, "confidence": 0.5},
                         "rawText": None, "usage": USAGE}
    d.update(kw)
    return d


def ev(type_, seq, run=None, **kw):
    return {"schema": "score-trace-event@1", "runId": run or C.score_run_id(EVR1, CASE, 0), "seq": seq,
            "type": type_, **kw}


def good_trace(error=None):
    run = run_doc()
    rid = run["id"]
    return [{"schema": "score-trace-event@1", "runId": rid, "seq": 0, "type": "score.run.start", "run": run},
            ev("score.stage.start", 1, stage="MATCH"),
            call_event(2, error=error),
            ev("cost", 3, record=cost_doc()),
            ev("score.stage.end", 4, stage="MATCH", status="completed"),
            ev("score.run.end", 5, status="completed", incomplete=[])]


class Base(unittest.TestCase):
    def assertInvalid(self, entity, doc, code=None):
        issues = validate(entity, doc)
        self.assertTrue(issues, f"{entity} unexpectedly valid")
        if code:
            self.assertIn(code, {i.code for i in issues}, [str(i) for i in issues])

    def assertValid(self, entity, doc):
        self.assertEqual([str(i) for i in validate(entity, doc)], [])


# ============================================================ L1/L2: compatibility with the frozen legacy contracts
class Compatibility(Base):
    def test_version_and_family_registered(self):
        self.assertEqual(CONTRACTS_VERSION, "s0a-contracts@7")
        self.assertEqual(set(ENTITY_NAMES), set(BASELINE_DEF_DIGESTS) | NEW_DEFS)
        self.assertEqual(list(ENTITY_NAMES), sorted(ENTITY_NAMES))

    CHANGED_LEGACY_DEFS = ("CostRecord", "TraceEvent")      # root declaration (SCORE-CONTRACT-03): exactly these two

    def test_every_prior_definition_is_identical_except_the_two_declared(self):
        for name, want in BASELINE_DEF_DIGESTS.items():
            if name in self.CHANGED_LEGACY_DEFS:
                continue
            with self.subTest(name):
                cur = REGISTRY[name].to_json()
                self.assertEqual(dig(budget_minus_live(cur) if name == "Budget" else cur), want)
        changed = sorted(n for n, want in BASELINE_DEF_DIGESTS.items() if dig(REGISTRY[n].to_json()) != want)
        self.assertEqual(changed, sorted((*self.CHANGED_LEGACY_DEFS, "Budget")))   # + LIVE-DEADLINE-04 Budget delta

    def test_live_stage_budget_and_host_stop_shapes_are_pinned_independently(self):
        self.assertEqual(dig(REGISTRY["Budget"].to_json()), LIVE_BUDGET_DIGEST)
        te = REGISTRY["TraceEvent"].to_json()
        self.assertEqual(dig(te), LIVE_TRACEEVENT_DIGEST)
        self.assertEqual(dig(host_stop_variant(te)), LIVE_HOST_STOP_DIGEST)
        floor = next(v for v in te["oneOf"] if v["properties"]["type"]["const"] == "retrieval.floor")
        self.assertEqual(dig(floor), FLOOR_VARIANT_DIGEST)

    def test_TraceEvent_differs_only_by_the_cost_variant_invariant(self):
        te = copy.deepcopy(REGISTRY["TraceEvent"].to_json())
        variants = {v["properties"]["type"]["const"]: v for v in te["oneOf"]}
        inv = variants["cost"]["x-invariants"]
        self.assertEqual([i.split(":")[0] for i in inv], ["review-cost-kind", "no-secrets"])
        variants["cost"]["x-invariants"] = [i for i in inv if not i.startswith("review-cost-kind")]
        self.assertEqual(dig(traceevent_minus_live(te)), BASELINE_DEF_DIGESTS["TraceEvent"])       # field shapes and every other variant untouched

    def test_CostRecord_differs_only_by_the_score_kind(self):
        cr = copy.deepcopy(REGISTRY["CostRecord"].to_json())
        self.assertEqual(cr["properties"]["kind"]["enum"], ["review", "chat", "index", "eval", "score"])
        cr["properties"]["kind"]["enum"].remove("score")
        self.assertEqual(dig(cr), BASELINE_DEF_DIGESTS["CostRecord"])

    def test_TypedError_and_review_stage_tables_are_unchanged(self):
        te = REGISTRY["TypedError"].to_json()
        self.assertEqual(te["properties"]["stage"]["enum"], list(STAGES))
        self.assertEqual(STAGES, ("INGEST", "PREPARE", "TRIAGE", "INVESTIGATE", "VERIFY", "JUDGE", "PUBLISH", "LEARN"))
        self.assertEqual(sorted(ROLE_OUTPUT), ["investigator", "judge", "verifier"])
        self.assertEqual({r: tuple(v) for r, v in ROLE_SCHEMAS.items()},
                         {"investigator": ("InvestigatorOutput", "InvestigatorTurn"),
                          "verifier": ("VerifierOutput", "VerifierTurn"), "judge": ("JudgeOutput",)})
        self.assertEqual(sorted(STAGE_CEILING_SEC), sorted(STAGES))
        for s in SCORE_STAGES:                       # no fabricated ceilings: the review helper does not know score stages
            with self.assertRaises(KeyError):
                stage_deadline_exceeded(s, 1.0)

    def test_bundle_is_current_and_changes_only_by_the_family_the_two_declared_defs_and_id(self):
        r = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "export", "--check"], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        bundle = json.loads((ROOT / "reviewer/contracts/schemas/contracts.schema.json").read_text())
        self.assertEqual(bundle["$id"], "reviewer-contracts-s0a-contracts@7")
        self.assertEqual(sorted(bundle["$defs"]), list(ENTITY_NAMES))
        for name, want in BASELINE_DEF_DIGESTS.items():
            if name not in self.CHANGED_LEGACY_DEFS:
                got = bundle["$defs"][name]
                self.assertEqual(dig(budget_minus_live(got) if name == "Budget" else got), want, name)
                self.assertEqual(dig(got), dig(REGISTRY[name].to_json()), name)       # and the current registry
            else:
                self.assertEqual(dig(bundle["$defs"][name]), dig(REGISTRY[name].to_json()), name)
        self.assertEqual(export_bundle("x")["$defs"].keys(), bundle["$defs"].keys())

    def test_review_documents_validate_and_hash_identically(self):
        tr = ex("TraceEvent.model-call")
        self.assertEqual(C.digest(tr), "sha256:5746bcd49946a27d697a587bc839b0b994858059171ad8a6a1c490f827718103")
        self.assertEqual(C.request_hash(tr["request"]),
                         "sha256:57a13826c07c9b0705bdc4e8dec2364b19212087f3689b8c81552658e9855a3e")
        self.assertEqual((tr["callId"], tr["costRecordId"]), ("call_f97125f22eb2ec7e", "cost_3fc115986e05f321"))
        self.assertEqual(C.comparable_digest(tr, "TraceEvent"),
                         "sha256:a27068c8ee6268954f412df4c4d9497f316ca957e9b7721e706118ae719aa43d")
        self.assertEqual(C.comparable_digest(ex("ReviewRun"), "ReviewRun"),
                         "sha256:8940bdda87bab4a8ddf48a74b21e55c8f20af36946e82ce79574a8dcb5adc103")
        self.assertEqual(C.digest(ex("ReviewRun")),
                         "sha256:393229f2211d82da54700bbf40744045c6fba31c883aea6e5203bfee763db83e")
        self.assertEqual(C.comparable_digest(ex("CostRecord.eval-synthetic"), "CostRecord"),
                         "sha256:53790ffeaa6f588b038159ea037ff3da1bc53ad3da42bb74e83186b608208536")
        self.assertEqual(C.digest(ex("CostRecord.eval-synthetic")),
                         "sha256:1dfbb1893b3d70f534e2a108644abffd427b619c62d23ee8e4df1b7d36eef605")
        self.assertEqual(C.run_id("idem:eval:" + "0" * 64, 1), "run_59cca05d0f17230c")
        self.assertEqual(C.call_id("INVESTIGATE", "investigator", "a1", 0, 0), "call_96bc21636c429003")
        self.assertEqual(C.cost_id("call_" + "0" * 16), "cost_dc5c1fc80d6c3121")
        self.assertEqual(validate("TraceEvent", tr), [])

    def test_review_projection_schemas_are_unchanged(self):
        """L2: the provider projections of every review role schema keep their sha256 after the bundle re-pin
        (runtime/schemas.py is untouched and reads only the reachable $defs, never the bundle id)."""
        from reviewer.runtime import schemas as S
        got = {}
        for n in S.SCHEMA_NAMES:
            for f in ("anthropic", "openai-strict"):
                got[f"{n}/{f}"] = sha(S.provider_schema(n, f))
            got[f"{n}/original"] = sha(S.original(n))
        self.assertEqual(got, BASELINE_PROJECTION_SHA256)

    def test_score_model_allowlist_is_a_catalog_subset_and_not_a_review_model(self):
        from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS
        self.assertEqual(SCORE_MODELS, ("anthropic/claude-opus-5.5",))
        self.assertTrue(set(SCORE_MODELS) <= set(ALLOWED_ROUTER_MODELS))
        self.assertFalse(set(SCORE_MODELS) & DEV_ONLY_MODELS)

    def test_review_profile_and_score_profile_do_not_cross(self):
        mp = ex("ModelProfile.standard-candidate")
        sp = ex("ScoreProfile.opus-invented")
        self.assertValid("ModelProfile", mp)
        self.assertInvalid("ScoreProfile", mp)
        self.assertInvalid("ModelProfile", sp)

    def test_review_request_and_score_request_do_not_cross(self):
        rq = ex("TraceEvent.model-call")["request"]
        self.assertValid("ModelRequest", rq)
        self.assertInvalid("ScoreRequest", rq)
        self.assertInvalid("ModelRequest", ex("ScoreRequest.matcher"))
        with self.assertRaises(ValueError):
            C.request_hash(ex("ScoreRequest.matcher"))
        with self.assertRaises(Exception):
            C.score_request_hash(rq)
        for role in ("investigator", "verifier", "judge"):
            self.assertInvalid("ScoreRequest", request(role="matcher") | {"role": role}, "enum")
        for role in SCORE_ROLES:
            self.assertInvalid("ModelRequest", {**ex("TraceEvent.model-call")["request"], "role": role}, "enum")

    def test_review_trace_validation_ignores_the_score_family(self):
        trace = good_trace()
        self.assertEqual(validate_score_trace(trace), [])
        for e in trace:
            self.assertInvalid("TraceEvent", e)
        self.assertTrue(validate_trace(trace))
        review = ex("TraceEvent.model-call")
        self.assertInvalid("ScoreTraceEvent", review)
        self.assertTrue(validate_score_trace([review]))


# ============================================================ outputs, profile, request
class Outputs(Base):
    def test_examples_are_valid(self):
        for n, ent in (("ScoreExtraction.example", "ScoreExtraction"), ("ScoreExtractionSegments.example", "ScoreExtractionSegments"),
                       ("ScoreDedup.example", "ScoreDedup"),
                       ("ScorePair.example", "ScorePair")):
            self.assertValid(ent, ex(n))

    def test_outputs_are_closed_strict_projectable_objects_with_no_free_text_fields(self):
        bundle = export_bundle("t")["$defs"]
        for name in ("ScoreExtraction", "ScoreExtractionSegments", "ScoreDedup", "ScorePair"):
            node = bundle[name]
            self.assertEqual(node["additionalProperties"], False)
            self.assertEqual(sorted(node["required"]), sorted(node["properties"]))      # every key required
            self.assertFalse({"reasoning", "explanation", "error", "message", "notes"} & set(node["properties"]))
            text = json.dumps(node)
            self.assertNotIn("propertyNames", text)                                     # no open Map objects
            self.assertNotIn("anyOf", text)
            self.assertNotIn("oneOf", text)

    def test_extraction_keeps_every_nonempty_text_exactly(self):
        for text in ("   ", "\n", "\t x \n", "a", "é" * 5):
            self.assertValid("ScoreExtraction", {"candidates": [{"sourceCommentId": "c1", "text": text}]})
        self.assertValid("ScoreExtraction", {"candidates": []})                         # zero candidates is valid

    def test_extraction_refusals(self):
        c = {"sourceCommentId": "c1", "text": "x"}
        for name, doc in {"empty text": {"candidates": [{**c, "text": ""}]},
                          "missing id": {"candidates": [{"text": "x"}]},
                          "empty id": {"candidates": [{**c, "sourceCommentId": ""}]},
                          "extra field": {"candidates": [{**c, "reasoning": "x"}]},
                          "extra top": {"candidates": [], "notes": "x"},
                          "text not string": {"candidates": [{**c, "text": 5}]},
                          "text bool": {"candidates": [{**c, "text": True}]},
                          "candidates not list": {"candidates": {}},
                          "too many": {"candidates": [c] * 1001}}.items():
            with self.subTest(name):
                self.assertInvalid("ScoreExtraction", doc)

    def test_extraction_segments_v3_shape(self):
        """bench.extract@v3: references only (id + inclusive 1-based segment range); the extractor role asks for this shape.
        Order and the upper bound are local producer checks (extraction-invalid), not contract rules."""
        self.assertEqual(SCORE_ROLE_SCHEMA["extractor"], "ScoreExtractionSegments")
        self.assertEqual(sorted(export_bundle("t")["$defs"]["ScoreExtractionSegments"]["properties"]["candidates"]["items"]["properties"]),
                         ["endSegment", "sourceCommentId", "startSegment"])
        c = {"sourceCommentId": "c1", "startSegment": 1, "endSegment": 3}
        for doc in ({"candidates": []}, {"candidates": [c]}, {"candidates": [c, c]},
                    {"candidates": [{**c, "startSegment": 3, "endSegment": 2}]}):          # reversed: valid shape, refused locally
            self.assertValid("ScoreExtractionSegments", doc)
        for name, doc in {"zero start": {"candidates": [{**c, "startSegment": 0}]}, "zero end": {"candidates": [{**c, "endSegment": 0}]},
                          "negative": {"candidates": [{**c, "startSegment": -1}]}, "bool start": {"candidates": [{**c, "startSegment": True}]},
                          "bool end": {"candidates": [{**c, "endSegment": True}]}, "float end": {"candidates": [{**c, "endSegment": 3.0}]},
                          "string start": {"candidates": [{**c, "startSegment": "1"}]}, "null end": {"candidates": [{**c, "endSegment": None}]},
                          "text key": {"candidates": [{**c, "text": "x"}]}, "char offsets": {"candidates": [{"sourceCommentId": "c1", "start": 0, "end": 1}]},
                          "missing end": {"candidates": [{"sourceCommentId": "c1", "startSegment": 1}]},
                          "empty id": {"candidates": [{**c, "sourceCommentId": ""}]}, "extra top": {"candidates": [], "notes": "x"},
                          "too many": {"candidates": [c] * 1001}}.items():
            with self.subTest(name):
                self.assertInvalid("ScoreExtractionSegments", doc)

    def test_dedup_boundaries(self):
        self.assertValid("ScoreDedup", {"groups": []})
        self.assertValid("ScoreDedup", {"groups": [[0], [1, 2]]})
        for name, doc in {"bool index": {"groups": [[True]]}, "float index": {"groups": [[1.0]]},
                          "negative": {"groups": [[-1]]}, "empty group": {"groups": [[]]},
                          "string index": {"groups": [["0"]]}, "flat": {"groups": [0, 1]},
                          "extra": {"groups": [], "x": 1}, "missing": {}}.items():
            with self.subTest(name):
                self.assertInvalid("ScoreDedup", doc)

    def test_pair_boundaries(self):
        for conf in (0, 1, -3, 7.5, 1e300, 0.0):
            self.assertValid("ScorePair", {"match": False, "confidence": conf})         # unclamped, ints allowed
        for name, doc in {"string match": {"match": "false", "confidence": 1}, "null match": {"match": None, "confidence": 1},
                          "int match": {"match": 1, "confidence": 1}, "string confidence": {"match": True, "confidence": "1"},
                          "bool confidence": {"match": True, "confidence": True},
                          "null confidence": {"match": True, "confidence": None},
                          "nan": {"match": True, "confidence": math.nan}, "inf": {"match": True, "confidence": math.inf},
                          "ninf": {"match": True, "confidence": -math.inf},
                          "huge int": {"match": True, "confidence": 2 ** 60},
                          "missing confidence": {"match": True}, "missing match": {"confidence": 1},
                          "extra": {"match": True, "confidence": 1, "why": "x"}}.items():
            with self.subTest(name):
                self.assertInvalid("ScorePair", doc)
        with self.assertRaises(Exception):
            loads_strict('{"match": true, "confidence": 1e999}')                       # strict parse refuses it too

    def test_validator_messages_do_not_echo_offending_model_values(self):
        """L3: for value errors the diagnostics are fixed classes. (Unknown KEY names are echoed in an issue path;
        those issues live only in the trusted trace store, never in reports or handoffs.)"""
        bad = {"ScorePair": {"match": SENTINEL, "confidence": SENTINEL},
               "ScoreDedup": {"groups": [[SENTINEL]]},
               "ScoreExtraction": {"candidates": [{"sourceCommentId": SENTINEL * 100, "text": 5}]}}
        for ent, doc in bad.items():
            issues = validate(ent, doc)
            self.assertTrue(issues)
            self.assertNotIn("SENTINEL", " ".join(str(i) for i in issues))


class Profile(Base):
    def p(self):
        return copy.deepcopy(ex("ScoreProfile.opus-invented"))

    def test_valid(self):
        self.assertValid("ScoreProfile", self.p())

    def test_refusals(self):
        def mut(f):
            d = self.p()
            f(d)
            return d
        cases = {
            "latest alias": lambda d: d["roles"]["matcher"].update(model="anthropic/claude-opus-latest"),
            "dev alias": lambda d: d["roles"]["matcher"].update(model="claude-opus-5-5"),
            "gpt dev": lambda d: d["roles"]["matcher"].update(model="gpt-6.1-sol"),
            "sonnet": lambda d: d["roles"]["matcher"].update(model="anthropic/claude-sonnet-5.5"),
            "haiku": lambda d: d["roles"]["extractor"].update(model="anthropic/claude-haiku-5.5"),
            "other provider": lambda d: d["roles"]["matcher"].update(provider="openai"),
            "retries": lambda d: d["roles"]["matcher"]["caps"].update(maxRetries=1),
            "repairs": lambda d: d["roles"]["matcher"]["caps"].update(maxRepairs=1),
            "retries bool": lambda d: d["roles"]["matcher"]["caps"].update(maxRetries=False),
            "unresolved": lambda d: d["roles"]["matcher"].update(resolved=False),
            "no price": lambda d: d["roles"]["matcher"].update(price=None),
            "fallback": lambda d: d["roles"]["matcher"].update(fallbacks=["score-invented@2"]),
            "extra role": lambda d: d["roles"].update(judge=d["roles"]["matcher"]),
            "missing role": lambda d: d["roles"].pop("deduper"),
            "wrong schema": lambda d: d["roles"]["matcher"].update(outputSchema="ScoreDedup"),
            "review schema": lambda d: d["roles"]["matcher"].update(outputSchema="JudgeOutput"),
            "version bool": lambda d: d.update(version=True),
            "version 0": lambda d: d.update(version=0),
        }
        for name, f in cases.items():
            with self.subTest(name):
                self.assertInvalid("ScoreProfile", mut(f))


class Request(Base):
    def test_valid_per_role(self):
        for role in SCORE_ROLES:
            self.assertValid("ScoreRequest", request(role))

    def test_refusals(self):
        for name, d in {
            "tools": request(tools=[{"type": "function"}]), "hop": request() | {"hop": 0},
            "hypothesis": request() | {"hypothesisId": "hyp_" + "0" * 16},
            "contextResults": request() | {"contextResults": []},
            "schema/role mismatch": request(outputSchema="ScoreDedup"),
            "review schema": request(outputSchema="JudgeOutput"),
            "model": request(model="anthropic/claude-sonnet-5.5"), "provider": request(provider="openai"),
            "no messages": request(messages=[]), "run id field": request() | {"runId": "run_" + "0" * 16},
        }.items():
            with self.subTest(name):
                self.assertInvalid("ScoreRequest", d)

    def test_hash_is_separate_stable_and_refuses_protected_text(self):
        req = ex("ScoreRequest.matcher")
        self.assertEqual(C.score_request_hash(req), "sha256:474d9d5d21acaf55df555548014ffb0369a0ac708cad406fa1852fc5a4b222f7")
        self.assertEqual(C.score_request_hash(req), C.score_request_hash(copy.deepcopy(req)))
        leak = request()
        leak["messages"][1]["content"] = "RVWCANARY_" + "a" * 20
        with self.assertRaises(ValueError):
            C.score_request_hash(leak)
        self.assertInvalid("ScoreRequest", leak, "no-secrets")


# ============================================================ run identity, replay, cost, trace
class Run(Base):
    def test_examples_and_identity(self):
        live, rep = ex("ScoreRun.live"), ex("ScoreRun.strict-replay-partial")
        self.assertValid("ScoreRun", live)
        self.assertValid("ScoreRun", rep)
        self.assertEqual(live["id"], "run_11db08e69129356c")
        self.assertEqual(live["id"], C.score_run_id(EVR1, CASE, 0))
        self.assertEqual(C.score_run_id(EVR1, CASE, 0), C.score_run_id(EVR1, CASE, 0))
        for other in (C.score_run_id(EVR2, CASE, 0), C.score_run_id(EVR1, "u000-t01", 0), C.score_run_id(EVR1, CASE, 1)):
            self.assertNotEqual(other, live["id"])
        # never collides with the review derivation for look-alike inputs
        self.assertNotEqual(C.score_run_id(EVR1, CASE, 0), C.run_id("idem:eval:" + "0" * 64, 0))

    def test_rules(self):
        for name, d, code in [
            ("live needs authorization", {k: v for k, v in run_doc().items() if k != "spendAuthorization"}, "score-run-rules"),
            ("live with replayOf", run_doc(replayOf=C.score_run_id(EVR2, CASE, 0)), "score-run-rules"),
            ("replay needs replayOf", {k: v for k, v in run_doc("strict-replay", EVR2).items() if k != "replayOf"}, "score-run-rules"),
            ("replay with authorization", run_doc("strict-replay", EVR2, spendAuthorization=INPUT), "score-run-rules"),
            ("replay of itself", run_doc("strict-replay", EVR2, replayOf=C.score_run_id(EVR2, CASE, 0)), "score-run-rules"),
            ("wrong id", run_doc(id="run_" + "0" * 16), "score-run-identity"),
            ("partial without incomplete", run_doc(status="partial"), "score-run-rules"),
            ("failed without error", run_doc(status="failed"), "score-run-rules"),
            ("completed with incomplete", run_doc(status="completed", incomplete=[{"stage": "DEDUP", "reason": "guard"}]), "score-run-rules"),
            ("running with endedAt", run_doc(endedAt="2026-01-01T00:00:00Z"), "score-run-rules"),
            ("error with review stage", run_doc(status="failed", error={"code": "internal", "message": "m", "retryable": False, "stage": "JUDGE"}), "score-run-rules"),
            ("mode not allowed", run_doc(mode="fresh-repeat"), "enum"),
            ("review field", run_doc(repo="owner/name"), "unknown-field"),
            ("trigger field", run_doc(trigger="eval"), "unknown-field"),
            ("repeat bool", run_doc(repeat=True), "type"),
            ("family", run_doc(family="review"), "const"),
            ("review stage in incomplete", run_doc(status="partial", incomplete=[{"stage": "JUDGE", "reason": "budget"}]), "enum"),
            ("free text in incomplete", run_doc(status="partial", incomplete=[{"stage": "MATCH", "reason": "budget", "detail": "x"}]), "unknown-field"),
            ("unknown reason", run_doc(status="partial", incomplete=[{"stage": "MATCH", "reason": "because"}]), "enum"),
        ]:
            with self.subTest(name):
                self.assertInvalid("ScoreRun", d, code)
        self.assertValid("ScoreRun", run_doc(status="failed", error={"code": "budget-exhausted", "message": "m", "retryable": False}))
        self.assertValid("ScoreRun", run_doc(status="completed", endedAt="2026-01-01T00:00:01Z"))

    def test_replay_cross_document_rules(self):
        rec = run_doc()
        good = run_doc("strict-replay", EVR2)
        self.assertEqual(check_score_replay(rec, good), [])
        self.assertNotEqual(good["id"], rec["id"])                                      # A10: fresh evalRunId => different run id
        same_eval = run_doc("strict-replay", EVR1)                                       # same coordinates: same id, same evalRunId
        codes = {i.message for i in check_score_replay(rec, {**same_eval, "replayOf": rec["id"]})}
        self.assertTrue(any("different run id" in m for m in codes) and any("fresh evalRunId" in m for m in codes))
        for name, bad in {"replayOf": {**good, "replayOf": C.score_run_id(EVR2, CASE, 0)},
                          "case": {**good, "evalCaseId": "u000-t01", "id": C.score_run_id(EVR2, "u000-t01", 0)},
                          "inputs": {**good, "inputDigest": C.digest({"other": 1})},
                          "profile": {**good, "profile": "score-invented@2"}}.items():
            with self.subTest(name):
                self.assertTrue(check_score_replay(rec, bad))


class Cost(Base):
    def test_example_and_shape(self):
        self.assertValid("CostRecord", ex("CostRecord.score-invented"))
        self.assertEqual(ex("CostRecord.score-invented"), cost_doc())

    def test_required_and_forbidden(self):
        for k in ("runId", "evalRunId", "evalCaseId", "callId"):
            with self.subTest("missing " + k):
                self.assertInvalid("CostRecord", {x: v for x, v in cost_doc().items() if x != k})
        for name, d in {"stage": cost_doc(stage="MATCH"), "review stage": cost_doc(stage="JUDGE"),
                        "review role": cost_doc(role="judge", callId=cost_doc()["callId"]),
                        "no role": {k: v for k, v in cost_doc().items() if k != "role"},
                        "tool subject": cost_doc(toolCallId="tool_" + "0" * 16),
                        "retryOf": cost_doc(retryOf=cost_doc()["callId"]),
                        "wrong id": cost_doc(id="cost_" + "0" * 16),
                        "bad kind": cost_doc(kind="scoring"),
                        "overrun bool-int": cost_doc(usdMicros=True)}.items():
            with self.subTest(name):
                self.assertInvalid("CostRecord", d)
        self.assertValid("CostRecord", cost_doc(role="extractor", stage_agent="ex-0"))
        self.assertValid("CostRecord", cost_doc(role="deduper", stage_agent="dd-0", basis="unknown", usdMicros=None))
        self.assertValid("CostRecord", cost_doc(overrun=True))

    def test_other_kinds_keep_their_old_semantics(self):
        e = ex("CostRecord.eval-synthetic")
        self.assertValid("CostRecord", e)
        self.assertInvalid("CostRecord", {k: v for k, v in e.items() if k != "evalRunId"})
        self.assertValid("CostRecord", {**e, "stage": "JUDGE"})                         # review costs still carry a review Stage
        self.assertInvalid("CostRecord", {k: v for k, v in {**e, "kind": "review"}.items() if k != "runId"}, "cost-attribution")


class Trace(Base):
    def test_examples_and_good_trace(self):
        self.assertValid("ScoreTraceEvent", ex("ScoreTraceEvent.model-call"))
        self.assertEqual(validate_score_trace(good_trace()), [])
        for stage_error in (
                {"code": "provider-error", "message": "m", "retryable": False, "detail": {"providerOutcome": "processed"}},
                {"code": "budget-exhausted", "message": "m", "retryable": False},
                {"code": "schema-invalid", "message": "m", "retryable": False, "detail": {"issues": ["x"]}}):
            with self.subTest(stage_error["code"]):
                t = good_trace(error=stage_error)
                self.assertEqual(validate_score_trace(t), [])        # provider/budget errors validate without any exception

    def test_error_events_omit_the_review_stage(self):
        err = {"code": "budget-exhausted", "message": "m", "retryable": False}
        self.assertValid("ScoreTraceEvent", ev("error", 1, error=err))
        self.assertInvalid("ScoreTraceEvent", ev("error", 1, error={**err, "stage": "MATCH"}), "enum")     # not even a review Stage
        self.assertInvalid("ScoreTraceEvent", ev("error", 1, error={**err, "stage": "JUDGE"}), "score-error")
        self.assertInvalid("ScoreTraceEvent", call_event(error={**err, "stage": "JUDGE"}), "score-call-outcome")
        self.assertInvalid("ScoreTraceEvent", ev("score.stage.end", 4, stage="MATCH", status="failed",
                                                  error={**err, "stage": "JUDGE"}), "score-stage-error")
        self.assertTrue(set(ERROR_CODES) >= {err["code"]})

    def test_event_refusals(self):
        base = call_event()
        cases = {
            "stage not for role": {**base, "stage": "DEDUP"},
            "review stage": {**base, "stage": "JUDGE"},
            "review role": {**base, "role": "judge"},
            "callId tampered": {**base, "callId": "call_" + "0" * 16},
            "requestHash tampered": {**base, "requestHash": C.digest({"x": 1})},
            "costRecordId tampered": {**base, "costRecordId": "cost_" + "0" * 16},
            "attempt 1": {**base, "attempt": 1},
            "attempt bool": {**base, "attempt": False},
            "ordinal bool": {**base, "ordinal": True},
            "seq bool": {**base, "seq": True},
            "repairOf": {**base, "repairOf": base["callId"]},
            "both response and error": {**base, "error": {"code": "internal", "message": "m", "retryable": False}},
            "neither": {**base, "response": None},
            "request role mismatch": {**base, "request": request("extractor")},
            "wrong tag": {**base, "schema": "trace-event@1"},
            "cost of other kind": ev("cost", 3, record={**cost_doc(), "kind": "eval"}),
            "run.start with review run": ev("score.run.start", 0, run=ex("ReviewRun")),
        }
        for name, d in cases.items():
            with self.subTest(name):
                self.assertInvalid("ScoreTraceEvent", d)

    def test_file_rules(self):
        good = good_trace()
        bad = {
            "empty": [],
            "not first": good[1:],
            "seq gap": [good[0], {**good[1], "seq": 2}, *good[2:]],
            "two runs": [*good[:-1], {**good[-1], "runId": C.score_run_id(EVR2, CASE, 0)}],
            "end not last": [*good[:5], good[5], ev("score.stage.start", 6, stage="DEDUP")],
            "second run.start": [*good[:2], {**good[0], "seq": 2}, *[{**e, "seq": e["seq"] + 1} for e in good[2:]]],
            "duplicate call": [*good[:3], {**call_event(3), }, *[{**e, "seq": e["seq"] + 1} for e in good[3:]]],
            "cost of another run": [*good[:3], ev("cost", 3, record=cost_doc(run=C.score_run_id(EVR2, CASE, 0))), *good[4:]],
            "cost of another eval run": [*good[:3], ev("cost", 3, record=cost_doc(evalRunId=EVR2)), *good[4:]],
            "cost of another case": [*good[:3], ev("cost", 3, record=cost_doc(evalCaseId="u000-t01")), *good[4:]],
            "cost of another call": [*good[:3], ev("cost", 3, record=cost_doc(stage_agent="pair-9", id=good[2]["costRecordId"])), *good[4:]],
        }
        for name, events in bad.items():
            with self.subTest(name):
                self.assertTrue(validate_score_trace(events), name)

    def test_cli_validates_the_family(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.jsonl"
            p.write_text("\n".join(json.dumps(e, sort_keys=True) for e in good_trace()) + "\n")
            ok = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "validate", "ScoreTraceEvent", str(p)],
                                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual((ok.returncode, ok.stdout.strip().splitlines()[-1]), (0, "ok"), ok.stdout)
            events = good_trace()
            events[3]["seq"] = 9
            p.write_text("\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n")
            bad = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "validate", "ScoreTraceEvent", str(p)],
                                 cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1)
            self.assertIn("trace-seq", bad.stdout)
            # the review dispatch is untouched: the same file is invalid as a review trace
            rv = subprocess.run([sys.executable, "-B", "-m", "reviewer.contracts", "validate", "TraceEvent", str(p)],
                                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(rv.returncode, 1)


class CanonicalAndComparison(Base):
    def test_canonical_round_trip(self):
        for e in good_trace():
            again = loads_strict(C.canonical_json(e).decode())
            self.assertEqual(again, e)
            self.assertEqual(C.digest(again), C.digest(e))
        self.assertEqual(C.digest(ex("ScoreTraceEvent.model-call")),
                         "sha256:93b5b61d3e0927a76a1557c92587986759a200eafdb5a78ef2e815ae67aeb018")

    def test_entity_dispatch(self):
        self.assertEqual(C.entity_of(run_doc()), "ScoreRun")
        self.assertEqual(C.entity_of(call_event()), "ScoreTraceEvent")
        self.assertEqual(C.entity_of(ex("TraceEvent.model-call")), "TraceEvent")
        self.assertEqual(C.entity_of(ex("ReviewRun")), "ReviewRun")
        self.assertEqual(C.COMPARE_IGNORE["ScoreRun"], frozenset({"id", "mode", "evalRunId", "replayOf", "spendAuthorization",
                                                                  "startedAt", "endedAt"}))
        self.assertEqual(C.COMPARE_IGNORE["ScoreTraceEvent"], frozenset({"runId", "at", "latencyMs"}))
        self.assertEqual(C._NESTED["ScoreTraceEvent"], {"run": "ScoreRun", "record": "CostRecord"})

    def test_replay_compares_equal_only_up_to_the_ignore_set(self):
        live, rep = run_doc(), run_doc("strict-replay", EVR2)
        self.assertEqual(C.comparable_digest(live), C.comparable_digest(rep))
        self.assertEqual(C.comparable_digest(ex("ScoreRun.live")), "sha256:84d1474c59d6f1168869260bcdc0dc7f7cc49d9fab10dc49610dbc8f9b3960e4")
        for field, other in (("evalCaseId", "u000-t01"), ("repeat", 1), ("profile", "score-invented@2"),
                             ("inputDigest", C.digest({"x": 1})), ("status", "completed"),
                             ("incomplete", [{"stage": "MATCH", "reason": "budget"}]), ("family", "other")):
            with self.subTest(field):
                self.assertNotEqual(C.comparable_digest({**live, field: other}), C.comparable_digest(live))
        # the ignore set is not masking by accident: every ignored field really is ignored, nothing else is
        ignored = C.COMPARE_IGNORE["ScoreRun"]
        self.assertEqual(sorted(set(live) - set(C.comparable(live))), sorted(ignored & set(live)))

    def test_trace_events_compare_across_a_replay(self):
        rid2 = C.score_run_id(EVR2, CASE, 0)
        recorded = good_trace()
        replay = []
        for e in recorded:
            r = copy.deepcopy(e)
            r["runId"], r["at"] = rid2, "2026-01-02T00:00:00Z"
            if e["type"] == "score.run.start":
                r["run"] = run_doc("strict-replay", EVR2)
            if e["type"] == "cost":
                r["record"].update(runId=rid2, evalRunId=EVR2, basis="replayed", replayOf=e["record"]["id"])
            if e["type"] == "score.model.call":
                r["latencyMs"] = 7
            replay.append(r)
        for a, b in zip(recorded, replay):
            self.assertEqual(C.comparable_digest(a), C.comparable_digest(b), a["type"])
        # a changed request, response or stage still differs
        changed = copy.deepcopy(recorded[2])
        changed["response"]["output"]["confidence"] = 0.9
        self.assertNotEqual(C.comparable_digest(changed), C.comparable_digest(recorded[2]))
        changed = copy.deepcopy(recorded[2])
        changed["request"]["messages"][1]["content"] = "{}"
        self.assertNotEqual(C.comparable_digest(changed), C.comparable_digest(recorded[2]))
        self.assertNotEqual(C.comparable_digest({**recorded[1], "stage": "DEDUP"}), C.comparable_digest(recorded[1]))


def replay_trace(basis="replayed", usd=900, error=None, **cost_kw):
    """good_trace() re-recorded as a strict replay under a fresh evalRunId; the cost has the given basis."""
    rid2 = C.score_run_id(EVR2, CASE, 0)
    out = []
    for e in good_trace(error=error):
        r = copy.deepcopy(e)
        r["runId"] = rid2
        if e["type"] == "score.run.start":
            r["run"] = run_doc("strict-replay", EVR2)
        if e["type"] == "cost":
            r["record"].update(runId=rid2, evalRunId=EVR2, basis=basis, usdMicros=usd, **cost_kw)
            if basis == "replayed":
                r["record"]["replayOf"] = e["record"]["id"]
        out.append(r)
    return out


REVIEW_COSTS = {
    "eval": lambda: ex("CostRecord.eval-synthetic"),
    "review": lambda: {**ex("CostRecord.eval-synthetic"), "kind": "review"},
}


def review_cost_event(record, seq=1):
    return {"schema": "trace-event@1", "runId": ex("TraceEvent.model-call")["runId"], "seq": seq, "type": "cost",
            "record": record}


class CrossFamilyCosts(Base):
    """SCORE-CONTRACT-03 D1 option (b): the review cost variant refuses kind=score, per event and per trace."""

    def test_review_event_refuses_a_score_cost_individually_and_in_a_trace(self):
        e = review_cost_event(cost_doc())
        self.assertInvalid("TraceEvent", e, "review-cost-kind")
        issues = validate_trace([e])                                          # whole-trace path refuses it too
        self.assertIn("review-cost-kind", {i.code for i in issues}, [str(i) for i in issues])

    def test_valid_review_and_eval_costs_still_pass_in_a_review_event(self):
        for kind, mk in REVIEW_COSTS.items():
            with self.subTest(kind):
                self.assertValid("TraceEvent", review_cost_event(mk()))

    def test_the_score_cost_still_validates_standalone_and_in_a_score_trace(self):
        self.assertValid("CostRecord", cost_doc())
        self.assertEqual(validate_score_trace(good_trace()), [])

    def test_malformed_cost_records_are_refused_without_a_crash(self):
        for bad in (None, 5, True, "score", [], [cost_doc()], {}, {"kind": "score"}, {"kind": ["score"]},
                    {"kind": {"x": 1}}, {"kind": 5}, {"kind": None}, {**cost_doc(), "kind": ["score"]},
                    {**cost_doc(), "usage": None}, {**cost_doc(), "basis": {}}):
            with self.subTest(repr(bad)[:40]):
                self.assertTrue(validate("TraceEvent", review_cost_event(bad)))
                self.assertTrue(validate("ScoreTraceEvent", ev("cost", 3, record=bad)))
                self.assertTrue(validate_trace([review_cost_event(bad)]))
                self.assertTrue(validate_score_trace([*good_trace()[:3], ev("cost", 3, record=bad)]))

    def test_mixed_family_traces_are_refused_both_ways(self):
        score = good_trace()
        review = [ex("TraceEvent.model-call")]
        self.assertTrue(validate_trace(score))                                # score events are not review events
        self.assertTrue(validate_score_trace(review))                         # nor the reverse
        self.assertTrue(validate_score_trace([*score[:3], review_cost_event(cost_doc()), *score[4:]]))
        self.assertTrue(validate_score_trace([*score[:3], review_cost_event(REVIEW_COSTS["eval"]()), *score[4:]]))
        self.assertTrue(validate_score_trace([*score[:3], ev("cost", 3, record=REVIEW_COSTS["eval"]()), *score[4:]]))


class StrictReplayCosts(Base):
    """SCORE-CONTRACT-03 N1: a strict-replay score trace carries only replayed costs (never new spend)."""

    def test_a_replay_with_replayed_costs_validates(self):
        self.assertEqual(validate_score_trace(replay_trace()), [])
        for usd in (0, 900, None):                                   # zero new spend and a recorded unknown both repeat
            with self.subTest(usd=usd):
                self.assertEqual(validate_score_trace(replay_trace(usd=usd)), [])

    def test_every_new_spend_basis_is_refused_in_a_replay(self):
        for basis, usd in (("measured", 900), ("estimated", 900), ("unknown", None), ("synthetic", 0)):
            with self.subTest(basis):
                issues = validate_score_trace(replay_trace(basis=basis, usd=usd, priceVersion="invented-catalog@0")
                                              if basis == "measured" else replay_trace(basis=basis, usd=usd))
                # synthetic is already refused per event for a real provider (cost-attribution); the rest by the trace rule
                self.assertIn("cost-attribution" if basis == "synthetic" else "trace-cost",
                              {i.code for i in issues}, [str(i) for i in issues])

    def test_replayed_cost_still_names_what_it_replays(self):
        t = replay_trace()
        del t[3]["record"]["replayOf"]
        self.assertTrue(validate_score_trace(t))

    def test_recorded_failure_accounting_is_replayed_not_deleted(self):
        err = {"code": "provider-error", "message": "m", "retryable": False, "detail": {"providerOutcome": "processed"}}
        live = good_trace(error=err)
        live[3]["record"].update(basis="unknown", usdMicros=None)             # a live failure with unknown cost is valid
        self.assertEqual(validate_score_trace(live), [])
        t = replay_trace(basis="replayed", usd=None, error=err)               # replayed: same error, null cost, kept
        self.assertEqual(validate_score_trace(t), [])
        self.assertEqual(t[2]["error"], err)
        self.assertIsNone(t[3]["record"]["usdMicros"])
        t[3]["record"]["basis"] = "unknown"                                   # but a fresh unknown is not replayed
        self.assertIn("trace-cost", {i.code for i in validate_score_trace(t)})

    def test_live_runs_keep_measured_estimated_and_unknown_costs(self):
        for basis, kw in (("measured", {"priceVersion": "invented-catalog@0"}), ("estimated", {}),
                          ("unknown", {"usdMicros": None})):
            with self.subTest(basis):
                t = good_trace()
                t[3]["record"].update(basis=basis, **kw)
                self.assertEqual(validate_score_trace(t), [])

    def test_the_old_symptom_is_closed_and_comparison_is_untouched(self):
        t = replay_trace(basis="measured", priceVersion="invented-catalog@0")
        self.assertTrue(validate_score_trace(t))
        good = replay_trace()
        for a, b in zip(good_trace(), good):                                  # replay still compares equal to the recording
            if a["type"] != "score.run.start":
                self.assertEqual(C.comparable_digest(a), C.comparable_digest(b), a["type"])


class Sentinel(Base):
    def test_family_documents_carry_no_model_text_fields(self):
        """L3: model-written text can only enter through ScoreExtraction.text and the trace's response/rawText
        (trusted store). ScoreRun, ScoreIncomplete and score CostRecord have no free-text field."""
        props = REGISTRY["ScoreRun"].to_json()["properties"]
        for k, v in props.items():
            if v.get("type") == "string":
                self.assertTrue("pattern" in v or "enum" in v or "const" in v, f"ScoreRun.{k} is a free string")
        cost_free = {"message", "detail"} & set(REGISTRY["CostRecord"].to_json()["properties"])
        self.assertEqual(cost_free, set())
        inc = REGISTRY["ScoreRun"].to_json()["properties"]["incomplete"]["items"]
        self.assertEqual(sorted(inc["properties"]), ["reason", "stage"])


if __name__ == "__main__":
    unittest.main()
