"""S1-10: repository-backed pilot host path. Owned local Git fixture, REAL importer/loaders/pipeline/adapter, fake
OpenRouter transport and fake key loader. No network, no .env, no real auth/state, no target scripts."""

from __future__ import annotations

import inspect
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from reviewer import historical
from reviewer.contracts import validate
from reviewer.contracts.canonical import digest, hypothesis_id
from reviewer.gateway import SpendBook, load_trace, trusted_authorization
from reviewer.historical import capture_bridge_pins, write_pins
from reviewer.pilot import repository as R
from reviewer.pilot.profile import MODEL, OUTPUT_CAPS, RUN_CEILING_USD_MICROS
from reviewer.pilot.repository_profile import repository_plan, repository_policy, repository_profile
from reviewer.pipeline import RetrievalPolicy
from reviewer.repoimport import (RelatesSpec, capture_import_pins, import_repository, write_import_pins)
from reviewer.repoimport.fsio import force_remove
from reviewer.repoimport.remote import local_fixture_remote
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET
from tests.pipeline.helpers import tcid
from tests.repoimport.helpers import ENV as GIT_ENV, git
from tests.tools.helpers import make_case

AT = "2026-10-25T20:00:00Z"
CASE = "o--r--1"
BASELINE = 70_576
BASE_FILES = {"src/a.py": "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(6)),
              "src/b.py": "def g(x):\n    return x\n",
              "src/util.py": "def close_stream():\n    return None\n\ndef is_open():\n    return True\n"}
HEAD_FILES = {**BASE_FILES, "src/a.py": "".join(f"def f{i}(x):\n    return x - {i}\n\n" for i in range(6)),
              "src/b.py": "def g(x):\n    return x * 2\n"}
CHANGED = ("src/a.py", "src/b.py")
GITLINK = "ab" * 20
USAGE = {"prompt_tokens": 1000, "completion_tokens": 200, "total_tokens": 1200, "cost": 0, "is_byok": True,
         "cost_details": {"upstream_inference_cost": 0.0042},
         "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "completion_tokens_details": {"reasoning_tokens": 0}}


def entries(**args):
    return [{"key": k, "value": v} for k, v in args.items()]      # the wire form the adapter projects


class World:
    """Everything the host holds outside the reviewed inputs: Git fixture, case, REAL imports, external pins, auth, state."""

    def __init__(self, tmp: Path, *, relates=True, gitlink=True):
        self.tmp = tmp
        self.src = tmp / "gitsrc"
        self.corpus = tmp / "corpus"
        self.store = tmp / "store"
        self.op = tmp / "operator"
        self.state = self.op / "state"
        for d in (self.src, self.corpus, self.op, self.state):
            d.mkdir(parents=True)
        git(self.src, "init", "-q", "--initial-branch=main")
        self.sha = {}
        for side, files in (("base", BASE_FILES), ("head", HEAD_FILES)):
            for p, t in files.items():
                (self.src / p).parent.mkdir(parents=True, exist_ok=True)
                (self.src / p).write_text(t)
            git(self.src, "add", "-A", "-f")
            if gitlink:
                git(self.src, "update-index", "--add", "--cacheinfo", f"160000,{GITLINK},vendor/sub")
            git(self.src, "commit", "-q", "-m", side, "--no-verify")
            self.sha[side] = git(self.src, "rev-parse", "HEAD")
        base = {p: BASE_FILES[p] for p in CHANGED}
        head = {p: HEAD_FILES[p] for p in CHANGED}
        self.case_dir = make_case(self.corpus, base, head, name=CASE)
        doc = json.loads((self.case_dir / "input/case.json").read_text())
        doc["base"] = {"sha": self.sha["base"], "mergeBase": None, "textRef": self.sha["base"]}
        doc["head"] = {"sha": self.sha["head"]}
        (self.case_dir / "input/case.json").write_text(json.dumps(doc))
        self.pins = capture_bridge_pins(self.case_dir, captured_at=AT)
        self.case_pins = self.op / f"{CASE}.pins.json"
        write_pins(self.case_pins, self.pins)
        self.baseline = self.op / "baseline.json"
        self.baseline.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
            {"case": CASE, "action": "captured", "pinsDigest": digest(self.pins)}]}))
        remote = local_fixture_remote(self.src, "o", "r")
        self.imports, self.import_pins = {}, {}
        for side in ("base", "head"):
            imp = import_repository(remote, self.sha[side], self.store,
                                    relates=RelatesSpec(self.case_dir, side) if relates else None)
            self.imports[side] = imp
            path = self.op / f"{side}.import-pins.json"
            write_import_pins(path, capture_import_pins(imp.dir, captured_at=AT))
            self.import_pins[side] = path
        self.auth = self.op / "auth.json"
        self.auth.write_text(json.dumps(AUTH))
        os.chmod(self.auth, 0o600)
        self.env = self.op / "dot.env"
        self.env.write_text("openrouter_key=not-read-in-tests\n")
        self.out = tmp / "out"

    def seed(self, *, committed=BASELINE, book_committed=None, inflight=0):
        h = trusted_authorization(self.auth)
        led = RuntimeLedger(self.state / R.LEDGER_NAME, 50_000_000)
        key = "prior|INVESTIGATE|investigator|generalist|0|0"
        led.admit(key, 100_000, model=SONNET)
        led.finish(key, outcome="processed", generationId="gen-prior", routerCostUsdMicros=0,
                   upstreamInferenceCostUsdMicros=committed, isByok=True, tokenPricedUsdMicros=committed,
                   costBasis="router-reported")
        book = SpendBook(h, self.state / R.BOOK_NAME)
        book.reserve("prior", 100_000)
        book.settle("prior", committed if book_committed is None else book_committed)
        if inflight:
            book.reserve("open", inflight)

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def options(self, **over):
        d = dict(mode="plan", case_dir=str(self.case_dir), case_pins=str(self.case_pins),
                 case_baseline=str(self.baseline), store=str(self.store), base_import_pins=str(self.import_pins["base"]),
                 head_import_pins=str(self.import_pins["head"]), out_dir=str(self.out), auth=str(self.auth))
        d.update(over)
        return R.RepositoryOptions(**d)

    def live_options(self, **over):
        d = dict(mode="live", state_dir=str(self.state), env_file=str(self.env), baseline_micros=BASELINE,
                 confirm_live=True)
        d.update(over)
        return self.options(**d)


class Model:
    """Fake OpenRouter in the order the pipeline asks: investigator request hop, final, verifier request hop, final, judge."""

    def __init__(self, head_id, *, byok=True, fail_with=None, script=None):
        self.head_id, self.fail_with = head_id, fail_with
        self.requests, self.bodies = [], []
        self.claim = "a.py f0 now subtracts"
        self.read = dict(side="head", path="src/util.py", start_line=1, end_line=2)
        self.read_id = tcid("VERIFY", "verifier", 2, "read_file", **self.read)
        self.script = script if script is not None else self.default_script()

    def cite(self):
        return {"kind": "code", "path": "src/a.py", "lines": [2, 2], "commit": self.head_id, "excerpt": "    return x - 0"}

    def hypothesis(self):
        return {"claim": self.claim, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
                "location": {"path": "src/a.py", "line": 2}, "mechanism": "The sign flipped.", "evidence": [self.cite()]}

    def default_script(self):
        ask = lambda: {"contextRequests": [{"tool": "read_file", "purpose": "read the unchanged helper",
                                           "args": entries(**self.read)}], "output": None}
        hid = hypothesis_id("generalist", 0, self.claim, "src/a.py", 2)
        return [ask(), {"contextRequests": [], "output": {"hypotheses": [self.hypothesis()]}},
                ask(), {"contextRequests": [], "output": {
                    "verdict": "confirmed", "reachable": True, "impact": "incorrect-result",
                    "evidence": [self.cite(), {"kind": "tool-ref", "toolCallId": self.read_id, "index": 0}],
                    "notes": "checked"}},
                {"comments": [{"findingIds": [hid], "title": "Sign flip", "body": "f0 returns x - 0."}]}]

    def __call__(self, http_req):
        self.requests.append(http_req)
        if self.fail_with is not None:
            return self.fail_with
        body = json.loads(http_req.body)
        self.bodies.append(body)
        content = self.script[len(self.requests) - 1]
        d = {"id": f"gen-{len(self.requests)}", "model": SONNET, "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": json.dumps(content)}}], "usage": USAGE}
        return HttpResponse(200, {}, json.dumps(d).encode())


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._rm)
        self.tmp = Path(os.path.realpath(self._t.name))
        self.w = World(self.tmp / "w")
        self.loads = []

    def _rm(self):
        force_remove(Path(self._t.name))
        try:
            self._t.cleanup()
        except FileNotFoundError:
            pass

    def loader(self, path, *, forbidden_roots=()):
        self.loads.append(str(path))
        return Secret(FAKE_KEY)

    @staticmethod
    def boom(path, *, forbidden_roots=()):
        raise AssertionError("the key loader must not be called")

    def head_id(self):
        return self.w.imports["head"].snapshot_id

    def model(self, **kw):
        return Model(self.head_id(), **kw)

    def live(self, model=None, **over):
        model = model or self.model()
        self.w.seed()
        rep = R.run_repository(self.w.live_options(**over), transport=model, key_loader=self.loader)
        return rep, model

    def run_main(self, argv, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = R.main(argv, out=out, err=err, **kw)
        return code, out.getvalue(), err.getvalue()


# ======================================================================== profile and policy

class ProfileTests(unittest.TestCase):
    def test_profile_is_sonnet_only_reviewed_caps_no_retry_no_fallback_and_contract_valid(self):
        for retrieval in (True, False):
            p = repository_profile(retrieval)
            self.assertEqual(validate("ModelProfile", p), [])
            self.assertEqual(validate("Plan", repository_plan(p)), [])
            for role, spec in p["roles"].items():
                self.assertEqual((spec["provider"], spec["model"], spec["fallbacks"]), ("anthropic", MODEL, []))
                self.assertEqual((spec["caps"]["maxRetries"], spec["caps"]["maxRepairs"]), (0, 0))
                self.assertEqual(spec["caps"]["maxOutputTokens"], OUTPUT_CAPS[role])
            self.assertEqual(p["roles"]["judge"]["outputSchema"], "JudgeOutput")
        self.assertEqual(repository_plan(repository_profile())["budget"]["maxUsdMicros"], RUN_CEILING_USD_MICROS)

    def test_tool_budgets_are_fixed_160_and_60_and_everything_else_matches_the_static_plan(self):
        from reviewer.pilot.profile import live_plan, live_profile
        for retrieval in (True, False):
            b = repository_plan(repository_profile(retrieval))["budget"]
            self.assertEqual((b["maxToolCalls"], b["maxToolCallsPerAgent"]), (160, 60))
            static = live_plan(live_profile(MODEL))["budget"]
            self.assertEqual({k: v for k, v in b.items() if k not in ("maxToolCalls", "maxToolCallsPerAgent")},
                             {k: v for k, v in static.items() if k not in ("maxToolCalls", "maxToolCallsPerAgent")})
        self.assertEqual(live_plan(live_profile(MODEL))["budget"]["maxToolCalls"], 60)    # old static plan unchanged
        self.assertTrue({"--max-tool-calls", "--tool-budget"}.isdisjoint(
            {a.option_strings[0] for a in R._parser()._actions if a.option_strings}))

    def test_retrieval_on_uses_turn_schemas_and_prompts_off_is_plain_with_no_policy(self):
        on, off = repository_profile(True, impact=False)["roles"], repository_profile(False)["roles"]
        self.assertEqual((on["investigator"]["outputSchema"], on["investigator"]["promptVersion"]),
                         ("InvestigatorTurn", "investigator.retrieve@v2"))
        self.assertEqual((on["verifier"]["outputSchema"], on["verifier"]["promptVersion"]),
                         ("VerifierTurn", "verifier.refute@v4"))
        self.assertEqual((off["investigator"]["outputSchema"], off["verifier"]["outputSchema"]),
                         ("InvestigatorOutput", "VerifierOutput"))
        self.assertEqual(repository_policy(True, impact=False), RetrievalPolicy())
        # IMPACT-01: the default with retrieval is impact mode (same schemas, impact prompt ids)
        imp = repository_profile(True)["roles"]
        self.assertEqual((imp["investigator"]["outputSchema"], imp["investigator"]["promptVersion"]),
                         ("InvestigatorTurn", "investigator.impact@v1"))
        self.assertEqual((imp["verifier"]["outputSchema"], imp["verifier"]["promptVersion"]),
                         ("VerifierTurn", "verifier.impact@v1"))
        self.assertEqual(repository_policy(True), RetrievalPolicy(investigator_prompt="investigator.impact@v1",
                                                                  verifier_prompt="verifier.impact@v1"))
        self.assertIsNone(repository_policy(False))

    def test_the_reused_private_helpers_keep_their_shape(self):
        self.assertEqual(list(inspect.signature(historical.bridge._validated).parameters), ["case_dir", "pins"])
        self.assertEqual(list(inspect.signature(historical.bridge._check_out).parameters),
                         ["out_dir", "case_dir", "forbidden"])


# ======================================================================== options

class OptionTests(Base):
    def refused(self, msg, **over):
        with self.assertRaises(R.RepositoryError) as c:
            R.check_options(self.w.options(**over))
        self.assertIn(msg, str(c.exception))

    def test_mode_argument_consistency(self):
        R.check_options(self.w.options())
        R.check_options(self.w.live_options())
        self.refused("mode must be", mode="bogus")
        self.refused("--confirm-live", mode="live", state_dir="s", env_file="e", baseline_micros=1)
        self.refused("--auth, --state-dir and --env", mode="live", confirm_live=True)
        self.refused("explicit --baseline-micros", mode="live", confirm_live=True, state_dir="s", env_file="e")
        self.refused("live-only", state_dir="s")
        self.refused("live-only", confirm_live=True)
        self.refused("plan needs --auth", auth=None)
        self.refused("replay uses no authorization", mode="replay", replay_trace="t", trace_digest="sha256:" + "0" * 64)
        self.refused("replay needs --replay-trace", mode="replay", auth=None, replay_trace="t", trace_digest="nope")
        self.refused("only for replay", replay_trace="t")
        self.refused("repeat", repeat=-1)


# ======================================================================== ingestion

class IngestTests(Base):
    def test_case_input_uses_import_ids_omits_pr_text_and_keeps_partials_separate(self):
        ing = R.ingest(self.w.options())
        c = ing.case
        self.assertEqual(validate("CaseInput", c), [])
        self.assertEqual((c["id"], c["repo"], c["synthetic"], c["pr"]), (CASE, "o/r", False, {"title": "", "body": ""}))
        self.assertEqual((c["base"]["snapshotId"], c["head"]["snapshotId"]),
                         (ing.base.snapshot_id, ing.head.snapshot_id))
        self.assertNotEqual(ing.base.snapshot_id, ing.head.snapshot_id)
        partial = {l["snapshotId"] for s in ing.partial.values() for l in s}
        self.assertTrue(partial)
        self.assertFalse(partial & {ing.base.snapshot_id, ing.head.snapshot_id})
        cov = R.coverage_doc(ing)
        self.assertEqual((cov["scope"], cov["fullRepositoryCoverage"], cov["gapKinds"]),
                         ("repository-with-omissions", False, ["submodule"]))
        self.assertEqual(cov["base"]["omissionCounts"], {"submodule": 1})
        self.assertEqual(cov["originalPartial"], ing.partial)
        self.assertEqual(cov["relatesTo"]["head"]["changedPathsByteEqual"], True)
        self.assertIn("title and body were not supplied", cov["statement"])

    def test_pr_text_in_the_case_pins_is_never_supplied(self):
        pins = capture_bridge_pins(self.w.case_dir, captured_at=AT, pr_text={"title": "Secret title", "body": "Body"})
        p = self.tmp / "pins-with-text.json"
        write_pins(p, pins)
        b = self.tmp / "baseline2.json"
        b.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
            {"case": CASE, "action": "captured", "pinsDigest": digest(pins)}]}))
        ing = R.ingest(self.w.options(case_pins=str(p), case_baseline=str(b)))
        self.assertEqual(ing.case["pr"], {"title": "", "body": ""})

    def refused(self, w=None, **over):
        with self.assertRaises(R.RepositoryError) as c:
            R.ingest((w or self.w).options(**over))
        return str(c.exception)

    def test_case_pins_must_match_the_operator_baseline(self):
        other = self.tmp / "baseline-other.json"
        other.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
            {"case": CASE, "action": "captured", "pinsDigest": "sha256:" + "1" * 64}]}))
        self.assertIn("differ from the operator baseline", self.refused(case_baseline=str(other)))
        none = self.tmp / "baseline-none.json"
        none.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": []}))
        self.assertIn("differ from the operator baseline", self.refused(case_baseline=str(none)))
        self.assertIn("not operator-pin-baseline@1", self.refused(case_baseline=str(self.tmp / "missing.json")))

    def test_case_json_is_validated_against_pins_before_it_is_trusted(self):
        f = self.w.case_dir / "input/case.json"
        doc = json.loads(f.read_text())
        doc["head"]["sha"] = "0" * 40                      # an attacker moves the head after the pins were captured
        f.write_text(json.dumps(doc))
        self.assertIn("case refused", self.refused())

    def test_pins_inside_the_case_directory_are_refused(self):
        inside = self.w.case_dir / "pins.json"
        shutil.copy(self.w.case_pins, inside)
        self.assertIn("outside the case directory", self.refused(case_pins=str(inside)))

    def test_tampered_import_is_refused_by_the_external_pins(self):
        d = self.w.imports["head"].dir
        os.chmod(d, 0o755)
        os.chmod(d / "tree/src", 0o755)
        os.chmod(d / "tree/src/a.py", 0o644)
        (d / "tree/src/a.py").write_text("def f0(x):\n    return 0\n")
        self.assertIn("head import refused (tamper)", self.refused())

    def test_swapped_import_pins_are_refused(self):
        msg = self.refused(base_import_pins=str(self.w.import_pins["head"]))
        self.assertIn("base import pins are not for the case's base commit", msg)

    def test_missing_import_is_refused(self):
        force_remove(self.w.imports["base"].dir)
        self.assertIn("base import refused", self.refused())

    def test_import_without_relates_to_is_refused(self):
        w = World(self.tmp / "w2", relates=False)
        self.assertIn("carries no relatesTo", self.refused(w))

    def test_relates_to_rules(self):
        good = {"caseId": CASE, "side": "head", "commitSha": "a" * 40, "changedPathsChecked": 2,
                "changedPathsByteEqual": True, "unchecked": [], "partialSnapshotId": None, "idEqualsPartial": None}
        ok = lambda **kw: R._relates_ok("head", {"relatesTo": {**good, **kw}}, CASE, "a" * 40, 2)
        self.assertEqual(ok()["changedPathsChecked"], 2)
        for kw in ({"unchecked": [{"path": "x", "reason": "recorded-gap"}]}, {"side": "base"}, {"caseId": "z--z--9"},
                   {"commitSha": "b" * 40}, {"changedPathsByteEqual": False}, {"changedPathsChecked": 1}):
            with self.assertRaises(R.RepositoryError, msg=str(kw)):
                ok(**kw)

    def test_output_path_rules(self):
        ing = R.ingest(self.w.options())
        for bad in (self.w.case_dir / "out", self.w.store / "out", self.w.corpus / "out", self.w.state / "out",
                    self.w.env.parent / "dot.env" / "out", Path(R.REPO) / "reviewer" / "out"):
            with self.assertRaises(R.RepositoryError, msg=str(bad)):
                R.check_out(self.w.live_options(out_dir=str(bad)), ing)
        self.w.out.mkdir()
        with self.assertRaises(R.RepositoryError):
            R.check_out(self.w.options(), ing)
        link = self.tmp / "link"
        os.symlink(self.tmp, link)
        with self.assertRaises(R.RepositoryError):
            R.check_out(self.w.options(out_dir=str(link / "fresh")), ing)


# ======================================================================== plan

class PlanTests(Base):
    def plan(self, **over):
        return R.run_repository(self.w.options(**over), key_loader=self.boom)

    def test_plan_captures_the_actual_first_request_through_the_real_pipeline_and_adapter(self):
        before = self.w.state_bytes()
        rep = self.plan()
        self.assertEqual((rep["status"], rep["ok"], rep["mode"]), ("planned", True, "plan"))
        p = rep["plan"]
        f = p["firstRequest"]
        self.assertGreaterEqual(p["capturedCount"], 1)
        self.assertEqual((f["schemaName"], f["model"], f["toolsInBody"]), ("InvestigatorTurn", MODEL, False))
        self.assertGreater(f["bodyBytes"], f["messagesBytes"] > 0 and f["schemaBytes"])
        self.assertRegex(f["bodySha256"], r"^[0-9a-f]{64}$")
        self.assertLessEqual(p["worstCaseAdmissionUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual((p["runCeilingUsdMicros"], p["retries"], p["repairs"]), (4_000_000, 0, 0))
        self.assertEqual((p["providerCalls"], p["networkCalls"], p["keyRead"], p["scratchOnly"]), (0, 0, False, True))
        self.assertEqual(p["outputCaps"], OUTPUT_CAPS)
        self.assertEqual(p["retrievalPolicy"]["version"], "retrieval@2")
        self.assertEqual(rep["coverage"]["scope"], "repository-with-omissions")
        self.assertTrue(any("independent" in g for g in rep["unmetGates"]))
        self.assertTrue(any("fork is not implemented" in g for g in rep["unmetGates"]))
        self.assertFalse(self.w.out.exists())                      # plan touches no output
        self.assertEqual(self.w.state_bytes() if self.w.state.exists() else {}, before)
        self.assertEqual(self.loads, [])

    def test_the_request_carries_no_labels_diagnostics_or_pr_text_and_shows_the_omission_notice(self):
        rep = self.plan()
        raw = json.dumps(rep)
        for canary in ("OUTCOME_SECRET", "LABELS_SECRET", "LABELS_DEEP"):
            self.assertNotIn(canary, raw)
        self.assertIn("were not supplied", rep["coverage"]["statement"])

    def test_retrieval_off_changes_only_the_roles_schema(self):
        on, off = self.plan(), self.plan(retrieval=False)
        self.assertEqual(off["status"], "planned")
        self.assertEqual(off["plan"]["firstRequest"]["schemaName"], "InvestigatorOutput")
        self.assertIsNone(off["plan"]["retrievalPolicy"])
        self.assertEqual(off["coverage"]["scope"], on["coverage"]["scope"])
        self.assertNotEqual(on["plan"]["firstRequest"]["bodySha256"], off["plan"]["firstRequest"]["bodySha256"])

    def test_plan_that_captures_no_request_is_not_labelled_planned(self):
        class Stub:
            status, error = "completed", None

        rep = R.run_repository(self.w.options(), key_loader=self.boom, runner=lambda spec: Stub())
        self.assertEqual((rep["status"], rep["ok"]), ("plan-failed", False))
        self.assertEqual(rep["plan"]["capturedCount"], 0)
        self.assertIsNone(rep["plan"]["firstRequest"])
        self.assertTrue(any("no first request was captured" in g for g in rep["unmetGates"]))

    def test_authorization_that_does_not_cover_the_ceiling_is_plan_failed_with_no_request(self):
        small = self.tmp / "small-auth.json"
        small.write_text(json.dumps({**AUTH, "maxUsdMicrosPerRun": 1_000_000}))
        os.chmod(small, 0o600)
        rep = self.plan(auth=str(small))
        self.assertEqual((rep["status"], rep["ok"], rep["plan"]["capturedCount"]), ("plan-failed", False, 0))
        self.assertTrue(rep["plan"]["authorization"].startswith("NOT covered"))

    def test_plan_rejects_state_env_and_never_creates_them(self):
        with self.assertRaises(R.RepositoryError):
            R.check_options(self.w.options(env_file=str(self.w.env)))
        self.assertEqual(self.loads, [])

    def test_text_rendering_names_the_unmet_gates(self):
        text = R.render(self.plan())
        self.assertIn("status: planned", text)
        self.assertIn("unmet gate", text)
        self.assertIn("first request: InvestigatorTurn", text)


# ======================================================================== live

class LiveTests(Base):
    def test_context_request_then_final_and_verifier_retrieval_end_to_end(self):
        plan = R.run_repository(self.w.options(), key_loader=self.boom)
        rep, model = self.live()
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 5))
        self.assertEqual(rep["counts"], {"hypotheses": 1, "findings": 1, "verifications": 1, "drops": 0, "comments": 1})
        self.assertEqual([b["response_format"]["json_schema"]["name"] for b in model.bodies],
                         ["InvestigatorTurn", "InvestigatorTurn", "VerifierTurn", "VerifierTurn", "JudgeOutput"])
        self.assertTrue(all(b["model"] == MODEL and "tools" not in b and b["provider"]["allow_fallbacks"] is False
                            for b in model.bodies))
        self.assertTrue(all(b["max_tokens"] <= max(OUTPUT_CAPS.values()) for b in model.bodies))
        # the plan's first request is the live run's first request, byte for byte
        import hashlib
        self.assertEqual(plan["plan"]["firstRequest"]["bodySha256"], hashlib.sha256(model.requests[0].body).hexdigest())
        # the model-requested calls are in the trace, causally chained
        events = load_trace(rep["paths"]["trace"]).events
        req = [e for e in events if e["type"] == "tool.call" and "requestedBy" in e]
        self.assertEqual([(e["agentId"], e["tool"]) for e in req], [("generalist", "read_file"), ("verifier", "read_file")])
        self.assertEqual(rep["retrieval"]["summary"]["hops"], 4)
        self.assertEqual(rep["coverage"]["scope"], "repository-with-omissions")
        self.assertEqual(self.loads, [str(self.w.env)])

    def test_report_costs_separate_the_ledger_from_the_gateway_estimate_and_no_key_leaks(self):
        rep, _ = self.live()
        rt = rep["costs"]["runtime"]
        self.assertEqual(rt["ledgerCalls"]["thisCase"], 5)
        self.assertEqual(rt["thisCase"]["accountable"]["usdMicros"], 5 * 4200)
        self.assertEqual(rt["cumulative"]["accountable"]["usdMicros"], BASELINE + 5 * 4200)
        self.assertIn("NOT a provider bill", rep["costs"]["gateway"]["note"])
        self.assertIn("reconciliation is root's", rep["costs"]["note"])
        self.assertIn("fork is not implemented", rep["forkAndStageReplay"])
        out = Path(self.w.out)
        self.assertTrue((out / "report.json").is_file())
        self.assertTrue(all(FAKE_KEY not in p.read_text(errors="ignore") for p in out.rglob("*") if p.is_file()))
        for name in ("review", "comments", "receipt", "trace"):
            self.assertTrue(Path(rep["paths"][name]).is_file(), name)
            self.assertTrue(Path(rep["paths"][name]).resolve().is_relative_to(out.resolve()))
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)

    def test_live_refusals_happen_before_the_key_and_leave_state_untouched(self):
        cases = [("missing --confirm-live", dict(confirm_live=False), {}),
                 ("wrong baseline", dict(baseline_micros=BASELINE + 1), {}),
                 ("book mismatch", dict(), dict(book_committed=BASELINE - 5)),
                 ("in-flight", dict(), dict(inflight=500)),
                 ("cannot cover the ceiling", dict(baseline_micros=47_000_000), dict(committed=47_000_000))]
        for name, over, seed in cases:
            with self.subTest(name):
                w = World(self.tmp / ("w-" + name.replace(" ", "-")))
                w.seed(**seed)
                before = w.state_bytes()
                with self.assertRaises(R.RepositoryError):
                    R.run_repository(w.live_options(**over), transport=self.model(), key_loader=self.boom)
                self.assertEqual(w.state_bytes(), before)
                self.assertFalse(w.out.exists())

    def test_missing_or_empty_state_is_never_created(self):
        for prep in ("missing", "empty"):
            with self.subTest(prep):
                w = World(self.tmp / ("w-" + prep))
                if prep == "empty":
                    for n in (R.BOOK_NAME, R.LEDGER_NAME):
                        (w.state / n).touch(mode=0o600)
                with self.assertRaises(R.RepositoryError):
                    R.run_repository(w.live_options(), transport=self.model(), key_loader=self.boom)
                self.assertEqual(sorted(p.name for p in w.state.iterdir()),
                                 sorted([R.BOOK_NAME, R.LEDGER_NAME]) if prep == "empty" else [])
                self.assertFalse(w.out.exists())

    def test_a_provider_failure_stops_after_one_attempt_without_retry_or_other_provider(self):
        m = self.model(fail_with=HttpResponse(500, {}, b"{}"))
        rep, _ = self.live(model=m)
        self.assertEqual((rep["ok"], len(m.requests)), (False, 1))
        self.assertNotEqual(rep["status"], "completed")
        self.assertEqual(rep["providerCalls"], 1)
        self.assertTrue((Path(self.w.out) / "report.json").is_file())

    def test_a_typed_pipeline_stop_is_a_failed_result_with_a_report_not_a_launcher_refusal(self):
        from reviewer.pipeline import PipelineError

        def stop(spec):
            raise PipelineError("config", "stopped by the engine")

        self.w.seed()
        rep = R.run_repository(self.w.live_options(), transport=self.model(), key_loader=self.loader, runner=stop)
        self.assertEqual((rep["status"], rep["ok"], rep["error"]["code"]), ("pipeline-refused", False, "config"))
        self.assertTrue((Path(self.w.out) / "report.json").is_file())
        self.assertIsNotNone(rep["costs"]["runtime"])

    def test_fresh_output_only(self):
        self.w.out.mkdir()
        self.w.seed()
        with self.assertRaises(R.RepositoryError):
            R.run_repository(self.w.live_options(), transport=self.model(), key_loader=self.boom)

    def test_key_loader_failure_leaves_no_output_and_spends_nothing(self):
        from reviewer.runtime import EnvFileError

        def bad(path, *, forbidden_roots=()):
            raise EnvFileError("no key")

        self.w.seed()
        before = self.w.state_bytes()
        with self.assertRaises(EnvFileError):
            R.run_repository(self.w.live_options(), transport=self.model(), key_loader=bad)
        self.assertEqual(self.w.state_bytes(), before)
        self.assertFalse(self.w.out.exists())

    def test_retrieval_off_runs_the_plain_roles(self):
        m = self.model(script=[
            {"hypotheses": [Model(self.head_id()).hypothesis()]},
            {"verdict": "confirmed", "reachable": True, "impact": "incorrect-result",
             "evidence": [Model(self.head_id()).cite()], "notes": "checked"},
            Model(self.head_id()).default_script()[-1]])
        rep, _ = self.live(model=m, retrieval=False)
        self.assertEqual((rep["status"], rep["providerCalls"]), ("completed", 3))
        self.assertEqual([b["response_format"]["json_schema"]["name"] for b in m.bodies],
                         ["InvestigatorOutput", "VerifierOutput", "JudgeOutput"])


# ======================================================================== replay

class ReplayTests(Base):
    def test_strict_replay_uses_no_key_auth_book_or_network_and_keeps_outputs(self):
        rep, _ = self.live()
        trace, pin = rep["paths"]["trace"], rep["traceDigest"]["value"]
        self.assertEqual(self.loads, [str(self.w.env)])
        before = self.w.state_bytes()
        out2 = self.tmp / "replay-out"
        o = self.w.options(mode="replay", auth=None, out_dir=str(out2), replay_trace=trace, trace_digest=pin)
        rr = R.run_repository(o, key_loader=self.boom)
        self.assertEqual((rr["status"], rr["ok"]), ("completed", True))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["consumedZeroLive"]),
                         (0, 0, True))
        self.assertGreaterEqual(rr["replay"]["replayedCalls"], 5)
        self.assertEqual(rr["providerCalls"], 0)
        self.assertEqual(self.w.state_bytes(), before)
        self.assertEqual(self.loads, [str(self.w.env)])            # still only the live load
        self.assertTrue((out2 / "report.json").is_file() and Path(rr["paths"]["trace"]).is_file())
        self.assertIn("fork is not implemented", rr["forkAndStageReplay"])

    def test_wrong_digest_is_refused_with_exit_2(self):
        rep, _ = self.live()
        argv = ["--mode", "replay", "--case-dir", str(self.w.case_dir), "--case-pins", str(self.w.case_pins),
                "--case-baseline", str(self.w.baseline), "--store", str(self.w.store),
                "--base-import-pins", str(self.w.import_pins["base"]), "--head-import-pins",
                str(self.w.import_pins["head"]), "--out", str(self.tmp / "r2"), "--replay-trace", rep["paths"]["trace"],
                "--trace-digest", "sha256:" + "0" * 64]
        code, out, err = self.run_main(argv, key_loader=self.boom)
        self.assertEqual(code, 2)
        self.assertIn("PipelineError", err)

    def test_replay_of_a_different_configuration_is_an_identity_mismatch(self):
        rep, _ = self.live()
        o = self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "r3"), replay_trace=rep["paths"]["trace"],
                           trace_digest=rep["traceDigest"]["value"], retrieval=False)
        with self.assertRaises(Exception) as c:
            R.run_repository(o, key_loader=self.boom)
        self.assertEqual(type(c.exception).__name__, "PipelineError")
        self.assertFalse((self.tmp / "r3").exists())               # nothing left behind by a refused replay


# ======================================================================== CLI and identity

class CliTests(Base):
    def argv(self, *extra):
        w = self.w
        return ["--case-dir", str(w.case_dir), "--case-pins", str(w.case_pins), "--case-baseline", str(w.baseline),
                "--store", str(w.store), "--base-import-pins", str(w.import_pins["base"]),
                "--head-import-pins", str(w.import_pins["head"]), "--out", str(w.out), *extra]

    def test_plan_json_exit_0_and_text_exit_0(self):
        code, out, err = self.run_main(self.argv("--auth", str(self.w.auth), "--json"), key_loader=self.boom)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["status"], "planned")
        code, out, _ = self.run_main(self.argv("--auth", str(self.w.auth)), key_loader=self.boom)
        self.assertEqual(code, 0)
        self.assertIn("mode: plan", out)

    def test_refusals_exit_2_without_secrets(self):
        code, out, err = self.run_main(self.argv("--mode", "live", "--auth", str(self.w.auth)), key_loader=self.boom)
        self.assertEqual(code, 2)
        self.assertIn("RepositoryError", err)
        self.assertNotIn(FAKE_KEY, err)

    def test_no_flag_widens_models_caps_or_budget(self):
        flags = {a.option_strings[0] for a in R._parser()._actions if a.option_strings}
        for bad in ("--model", "--max-usd", "--ceiling", "--allow-model", "--retries", "--fallback", "--wall-clock-sec"):
            self.assertNotIn(bad, flags)

    def test_config_identity_binds_pins_records_profile_policy_and_retrieval(self):
        ing = R.ingest(self.w.options())
        prof, plan = repository_profile(True), repository_plan(repository_profile(True))
        on = R.config_identity(ing, prof, plan, RetrievalPolicy(), True)
        off_prof = repository_profile(False)
        off = R.config_identity(ing, off_prof, repository_plan(off_prof), None, False)
        self.assertEqual(on["importRecordDigest"], {"base": digest(ing.base.record), "head": digest(ing.head.record)})
        self.assertEqual(on["casePinsDigest"], digest(ing.pins))
        self.assertEqual((on["prTextSupplied"], on["retrievalPolicy"]), (False, RetrievalPolicy().digest))
        self.assertNotEqual(digest(on), digest(off))
        self.assertTrue(on["originalPartialIds"]["head"])
        # plan and live share the evaluation identity; replay does not
        o_plan, o_live = self.w.options(), self.w.live_options()
        self.assertEqual(R.eval_run_id(o_plan, on), R.eval_run_id(o_live, on))
        o_rep = self.w.options(mode="replay", auth=None, replay_trace="t", trace_digest="sha256:" + "0" * 64)
        self.assertNotEqual(R.eval_run_id(o_rep, on), R.eval_run_id(o_plan, on))


if __name__ == "__main__":
    unittest.main()
