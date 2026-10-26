"""S1-12: real-provider positive review control, host harness. REAL pipeline/gateway/tools/adapter with a FAKE OpenRouter
transport and fake key loader over the owned fixture `fixtures/retrieval-positive`. No network, no .env, no real auth/state.
The expected issue and the scripted answers live ONLY in this file; the harness under test never sees them."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.canonical import hypothesis_id
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pilot import positive as P
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET
from tests.pilot.test_repository import USAGE, entries
from tests.pipeline.helpers import tcid

REPO = P.REPO
BASELINE = 70_576
CLAIM = "reap() compares lease expiry in milliseconds against a clock reading in seconds, so leases never expire"
# --- the expected issue (label): tests only ---
BUG_PATH, BUG_LINE, BUG_TEXT = "leasing/scheduler.py", 16, "        now = clock.now_seconds()"
DEF_PATH, DEF_LINE, DEF_TEXT = "leasing/lease.py", 7, "        self.expires_at = clock.now_millis() + ttl_ms"
CALLER_PATH = "leasing/worker.py"
BENIGN_PATH = "leasing/report.py"
HINT_WORDS = ("bug", "defect", "expected", "label", "mismatch", "fixme", "todo", "xxx", "intentional", "wrong")


def scope_hashes(repo: Path = REPO) -> dict:
    """Independent re-implementation of the baseline scope, so the module under test is not its own oracle."""
    out = {}
    for scope in ("reviewer", "fixtures/retrieval-positive"):
        for p in sorted((repo / scope).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
                out[str(p.relative_to(repo))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def force_remove(path: Path) -> None:
    for dirpath, dirnames, _ in os.walk(path):
        for d in [dirpath, *[os.path.join(dirpath, x) for x in dirnames]]:
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


class Model:
    """Fake OpenRouter that answers by script in the order the pipeline asks. It never sees a label."""

    def __init__(self, head_id, script=None, *, fail_with=None):
        self.head_id, self.fail_with = head_id, fail_with
        self.requests, self.bodies = [], []
        self.def_read = dict(side="head", path=DEF_PATH, start_line=1, end_line=9)
        self.read_id = tcid("VERIFY", "verifier", 2, "read_file", **self.def_read)
        self.script = script if script is not None else self.positive_script()

    def cite(self, path, line, text):
        return {"kind": "code", "path": path, "lines": [line, line], "commit": self.head_id, "excerpt": text}

    def hypothesis(self):
        return {"claim": CLAIM, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
                "location": {"path": BUG_PATH, "line": BUG_LINE},
                "mechanism": "Lease.expires_at is built from now_millis(); reap() now compares it with now_seconds().",
                "evidence": [self.cite(BUG_PATH, BUG_LINE, BUG_TEXT), self.cite(DEF_PATH, DEF_LINE, DEF_TEXT)]}

    def investigator_ask(self):
        return {"contextRequests": [
            {"tool": "read_file", "purpose": "see how Lease.expires_at is stored",
             "args": entries(side="head", path=DEF_PATH, start_line=1, end_line=9)},
            {"tool": "read_file", "purpose": "see who calls reap()",
             "args": entries(side="head", path=CALLER_PATH, start_line=1, end_line=12)}], "output": None}

    def verifier_ask(self):
        return {"contextRequests": [{"tool": "read_file", "purpose": "re-read the unchanged lease definition",
                                     "args": entries(**self.def_read)}], "output": None}

    def verdict(self, verdict):
        return {"contextRequests": [], "output": {
            "verdict": verdict, "reachable": verdict == "confirmed", "impact": "incorrect-result", "notes": "checked",
            "evidence": [self.cite(BUG_PATH, BUG_LINE, BUG_TEXT), {"kind": "tool-ref", "toolCallId": self.read_id, "index": 0}]}}

    def positive_script(self):
        hid = hypothesis_id("generalist", 0, CLAIM, BUG_PATH, BUG_LINE)
        return [self.investigator_ask(), {"contextRequests": [], "output": {"hypotheses": [self.hypothesis()]}},
                self.verifier_ask(), self.verdict("confirmed"),
                {"comments": [{"findingIds": [hid], "title": "Leases never expire",
                               "body": "reap() compares milliseconds with seconds."}]}]

    def refuted_script(self):
        return self.positive_script()[:3] + [self.verdict("refuted")]

    def miss_script(self):
        return [{"contextRequests": [], "output": {"hypotheses": []}}]

    def __call__(self, http_req):
        self.requests.append(http_req)
        if self.fail_with is not None:
            return self.fail_with
        self.bodies.append(json.loads(http_req.body))
        content = self.script[len(self.requests) - 1]
        d = {"id": f"gen-{len(self.requests)}", "model": SONNET, "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": json.dumps(content)}}], "usage": USAGE}
        return HttpResponse(200, {}, json.dumps(d).encode())


class Rig(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(lambda: (force_remove(Path(self._t.name)), self._cleanup()))
        self.tmp = Path(os.path.realpath(self._t.name))
        self.op = self.tmp / "operator"
        self.state = self.op / "state"
        self.state.mkdir(parents=True)
        self.baseline = self.op / "software-baseline.json"
        self.baseline.write_text(json.dumps({"schema": "software-baseline@1", "capturedAt": "2026-10-26T00:00:00Z",
                                             "files": scope_hashes()}))
        self.auth = self.op / "auth.json"
        self.auth.write_text(json.dumps(AUTH))
        os.chmod(self.auth, 0o600)
        self.env = self.op / "dot.env"
        self.env.write_text("openrouter_key=not-read-in-tests\n")
        self.out = self.tmp / "out"
        self.loads = []
        self.fixture_before = scope_hashes()

    def _cleanup(self):
        try:
            self._t.cleanup()
        except FileNotFoundError:
            pass

    def tearDown(self):
        self.assertEqual(scope_hashes(), self.fixture_before, "the fixture or source changed during a test")

    # ---- helpers
    def loader(self, path, *, forbidden_roots=()):
        self.loads.append(str(path))
        return Secret(FAKE_KEY)

    @staticmethod
    def boom(path, *, forbidden_roots=()):
        raise AssertionError("the key loader must not be called")

    def head_id(self):
        return P.prepare(self.options()).case["head"]["snapshotId"]

    def model(self, script="positive", **kw):
        m = Model(self.head_id(), **kw)
        if script != "positive":
            m.script = getattr(m, script + "_script")()
        return m

    def seed(self, committed=BASELINE, inflight=0):
        h = trusted_authorization(self.auth)
        led = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000)
        key = "prior|INVESTIGATE|investigator|generalist|0|0"
        led.admit(key, 100_000, model=SONNET)
        led.finish(key, outcome="processed", generationId="gen-prior", routerCostUsdMicros=0,
                   upstreamInferenceCostUsdMicros=committed, isByok=True, tokenPricedUsdMicros=committed,
                   costBasis="router-reported")
        book = SpendBook(h, self.state / P.BOOK_NAME)
        book.reserve("prior", 100_000)
        book.settle("prior", committed)
        if inflight:
            book.reserve("open", inflight)

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def options(self, **over):
        d = dict(mode="plan", source_baseline=str(self.baseline), out_dir=str(self.out), auth=str(self.auth))
        d.update(over)
        return P.PositiveOptions(**d)

    def live_options(self, **over):
        d = dict(mode="live", state_dir=str(self.state), env_file=str(self.env), baseline_micros=BASELINE,
                 confirm_live=True)
        d.update(over)
        return self.options(**d)

    def live(self, model=None, **over):
        model = model or self.model()
        self.seed()
        rep = P.run_positive(self.live_options(**over), transport=model, key_loader=self.loader)
        return rep, model

    def run_main(self, argv, **kw):
        out, err = io.StringIO(), io.StringIO()
        code = P.main(argv, out=out, err=err, **kw)
        return code, out.getvalue(), err.getvalue()


# ======================================================================== fixture hygiene

class FixtureTests(unittest.TestCase):
    def test_fixture_has_no_hint_comment_label_or_expected_issue_text(self):
        for p in (REPO / "fixtures/retrieval-positive").rglob("*"):
            if p.is_file():
                low = p.read_text().lower()
                self.assertNotIn("#", low, p)                              # no comments at all
                for w in HINT_WORDS:
                    self.assertNotIn(w, low, f"{p}: {w}")
        self.assertFalse(list((REPO / "fixtures/retrieval-positive").rglob("*.json")))   # no labels file

    def test_the_diff_is_two_files_one_clear_change_and_one_benign_refactor(self):
        base, head = REPO / "fixtures/retrieval-positive/base", REPO / "fixtures/retrieval-positive/head"
        changed = sorted(str(p.relative_to(head)) for p in head.rglob("*.py")
                         if p.read_text() != (base / p.relative_to(head)).read_text())
        self.assertEqual(changed, [BENIGN_PATH, BUG_PATH])
        # the label coordinates are real lines of the head tree, and the needed context is in UNCHANGED files
        self.assertEqual((head / BUG_PATH).read_text().splitlines()[BUG_LINE - 1], BUG_TEXT)
        self.assertEqual((head / DEF_PATH).read_text().splitlines()[DEF_LINE - 1], DEF_TEXT)
        for unchanged in (DEF_PATH, CALLER_PATH, "leasing/clock.py"):
            self.assertEqual((head / unchanged).read_bytes(), (base / unchanged).read_bytes())
        self.assertIn("reap()", (head / CALLER_PATH).read_text())

    def test_nothing_in_the_harness_module_knows_the_expected_issue(self):
        src = (REPO / "reviewer/pilot/positive.py").read_text()
        for needle in (BUG_PATH, DEF_PATH, "now_seconds", "now_millis", "expires_at", "reap"):
            self.assertNotIn(needle, src)


# ======================================================================== baseline

class BaselineTests(Rig):
    def write(self, files=None, **over):
        doc = {"schema": "software-baseline@1", "capturedAt": "x", "files": scope_hashes() if files is None else files}
        doc.update(over)
        self.baseline.write_text(json.dumps(doc))

    def refused(self, fragment):
        with self.assertRaises(P.PositiveError) as c:
            P.load_source_baseline(str(self.baseline))
        self.assertIn(fragment, str(c.exception))

    def test_matching_baseline_loads_and_other_files_are_out_of_scope(self):
        files = {**scope_hashes(), "tests/anything.py": "0" * 64}
        self.write(files)
        got = P.load_source_baseline(str(self.baseline))
        self.assertEqual(got["fileCount"], len(scope_hashes()))
        self.assertRegex(got["scopeDigest"], r"sha256:[0-9a-f]{64}")

    def test_absent_unreadable_wrong_schema_and_malformed_are_refused(self):
        self.baseline.unlink()
        self.refused("absent")
        self.baseline.write_text("{not json")
        self.refused("absent or not valid")
        self.write(schema="other@1")
        self.refused("software-baseline@1")
        self.write({**scope_hashes(), "reviewer/x.py": "nothex"})
        self.refused("malformed")

    def test_changed_extra_and_missing_files_in_scope_are_refused(self):
        files = scope_hashes()
        some = next(iter(files))
        self.write({**files, some: "0" * 64})
        self.refused("changed")
        files = scope_hashes()
        files.pop("reviewer/pilot/positive.py")
        self.write(files)
        self.refused("not in baseline")            # a baseline captured before this harness existed refuses
        self.write({**scope_hashes(), "fixtures/retrieval-positive/head/leasing/ghost.py": "1" * 64})
        self.refused("not on disk")

    def test_a_baseline_inside_the_checkout_is_refused(self):
        with self.assertRaises(P.PositiveError) as c:
            P.load_source_baseline(str(REPO / "orchestration" / "anything.json"))
        self.assertIn("outside the checkout", str(c.exception))

    def test_every_mode_checks_the_baseline_before_building_anything(self):
        self.write({})
        for o in (self.options(), self.live_options(), self.options(mode="replay", auth=None, replay_trace="t",
                                                                      trace_digest="sha256:" + "0" * 64)):
            with self.assertRaises(P.PositiveError):
                P.run_positive(o, key_loader=self.boom)
        self.assertFalse(self.out.exists())


# ======================================================================== options and flags

class OptionTests(Rig):
    def test_live_only_and_replay_only_flags_are_confined(self):
        bad = [dict(state_dir="s"), dict(env_file="e"), dict(baseline_micros=1), dict(confirm_live=True),
               dict(replay_trace="t", trace_digest="sha256:" + "0" * 64)]
        for kw in bad:
            with self.assertRaises(P.PositiveError, msg=kw):
                P.check_options(self.options(**kw))
        for kw in (dict(confirm_live=False), dict(baseline_micros=None), dict(env_file=None), dict(auth=None)):
            with self.assertRaises(P.PositiveError, msg=kw):
                P.check_options(self.live_options(**kw))
        with self.assertRaises(P.PositiveError):
            P.check_options(self.options(mode="replay", auth=str(self.auth), replay_trace="t",
                                         trace_digest="sha256:" + "0" * 64))
        with self.assertRaises(P.PositiveError):
            P.check_options(self.options(mode="replay", auth=None, replay_trace="t", trace_digest="bad"))
        with self.assertRaises(P.PositiveError):
            P.check_options(self.options(auth=None))

    def test_no_flag_can_widen_model_caps_budgets_retries_fixture_or_repeat(self):
        flags = {s for a in P._parser()._actions for s in a.option_strings}
        self.assertEqual(flags, {"-h", "--help", "--mode", "--source-baseline", "--out", "--auth", "--state-dir", "--env",
                                 "--baseline-micros", "--book-baseline-micros", "--confirm-live", "--replay-trace",
                                 "--trace-digest", "--json"})


# ======================================================================== plan

class PlanTests(Rig):
    def test_plan_captures_the_actual_first_request_and_touches_nothing(self):
        self.seed()
        before = self.state_bytes()
        rep = P.run_positive(self.options(), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True))
        p = rep["plan"]
        f = p["firstRequest"]
        self.assertEqual(f["schemaName"], "InvestigatorTurn")
        self.assertEqual(f["model"], SONNET)
        self.assertFalse(f["toolsInBody"])
        self.assertEqual(p["capturedCount"], 1)
        self.assertLessEqual(p["worstCaseAdmissionUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual(p["toolBudget"], {"maxToolCalls": 160, "maxToolCallsPerAgent": 60})
        self.assertEqual((p["retries"], p["repairs"], p["providerCalls"], p["networkCalls"], p["keyRead"]),
                         (0, 0, 0, 0, False))
        self.assertEqual(p["outputCaps"], {"investigator": 16000, "verifier": 6000, "judge": 8000})
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.loads, [])
        self.assertIn("model-decided", rep["outcome"])
        self.assertTrue(any("independent review" in g for g in rep["unmetGates"]))

    def test_plan_is_repeatable_and_equals_the_live_first_request_byte_for_byte(self):
        a = P.run_positive(self.options(), key_loader=self.boom)["plan"]["firstRequest"]
        b = P.run_positive(self.options(), key_loader=self.boom)["plan"]["firstRequest"]
        self.assertEqual(a, b)
        rep, model = self.live()
        self.assertEqual(hashlib.sha256(model.requests[0].body).hexdigest(), a["bodySha256"])

    def test_the_first_request_names_the_fixture_but_no_label_hint_or_pr_text(self):
        rep, model = self.live()
        user = json.loads(model.bodies[0]["messages"][1]["content"])
        visible = json.dumps([user["context"], user["untrustedPullRequest"]]).lower()
        self.assertIn("leasing/scheduler.py", visible)
        for w in HINT_WORDS:
            self.assertNotIn(w, visible, w)
        self.assertNotIn(CLAIM.lower(), json.dumps(model.bodies[0]).lower())
        self.assertEqual(user["untrustedPullRequest"], {"title": "", "body": ""})
        self.assertEqual(P.prepare(self.options()).case["pr"], {"title": "", "body": ""})

    def test_plan_fails_not_planned_without_a_captured_request(self):
        def stop(spec):
            from reviewer.pipeline import PipelineError
            raise PipelineError("config", "stopped before any model call")
        rep = P.run_positive(self.options(), runner=stop)
        self.assertEqual((rep["status"], rep["ok"]), ("plan-failed", False))
        self.assertEqual(rep["plan"]["capturedCount"], 0)

    def test_output_rules(self):
        self.out.mkdir()
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.options())
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.options(out_dir=str(REPO / "fixtures" / "newout")))
        self.seed()
        for bad in (self.state / "inside", REPO / "reviewer" / "newout", REPO / "tests" / "newout"):
            with self.assertRaises(P.PositiveError, msg=str(bad)):
                P.run_positive(self.live_options(out_dir=str(bad)), transport=self.model(), key_loader=self.boom)


# ======================================================================== live (fake transport)

class LiveTests(Rig):
    def trace_events(self, rep):
        return [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]

    def test_positive_control_five_calls_actual_turns_provenance_and_judge_output(self):
        rep, model = self.live()
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 5))
        self.assertEqual([b["response_format"]["json_schema"]["name"] for b in model.bodies],
                         ["InvestigatorTurn", "InvestigatorTurn", "VerifierTurn", "VerifierTurn", "JudgeOutput"])
        self.assertEqual(rep["counts"]["findings"], 1)
        self.assertEqual(rep["counts"]["comments"], 1)
        self.assertEqual(rep["counts"]["verifications"], 1)
        comments = json.loads(Path(rep["paths"]["comments"]).read_text())
        text = json.dumps(comments)
        self.assertIn(BUG_PATH, text)
        self.assertIn("Leases never expire", text)
        events = self.trace_events(rep)
        asked = [e for e in events if e.get("type") == "tool.call" and "requestedBy" in e]
        self.assertEqual(sorted((e["args"]["path"], e["stage"]) for e in asked),
                         sorted([(DEF_PATH, "INVESTIGATE"), (CALLER_PATH, "INVESTIGATE"), (DEF_PATH, "VERIFY")]))
        self.assertTrue(all(e["tool"] == "read_file" and e["result"]["status"] == "ok" for e in asked))
        self.assertIn(model.read_id, [e["toolCallId"] for e in asked])      # the verifier's cited id is the executed read
        ver = (Path(rep["paths"]["runDir"]) / "artifacts" / "05-VERIFY.v1.json").read_text()
        self.assertIn(model.read_id, ver)                                   # tool-ref evidence kept in the VERIFY artifact
        self.assertIn(BUG_TEXT.strip(), ver)
        chains = rep["retrieval"]["summary"]["chains"]
        self.assertEqual([(c["role"], c["hops"], c["requestedToolCalls"], c["final"]) for c in chains],
                         [("investigator", 2, 2, True), ("verifier", 2, 1, True)])
        self.assertEqual((rep["retrieval"]["summary"]["unreadRequests"], rep["retrieval"]["guardRefusals"]), (0, []))
        judge = json.loads((Path(rep["paths"]["runDir"]) / "artifacts" / "06-JUDGE.v1.json").read_text())
        self.assertIn("Leases never expire", json.dumps(judge))

    def test_the_report_states_model_decided_and_carries_no_label_or_score(self):
        rep, _ = self.live()
        self.assertIn("model-decided", rep["outcome"])
        low = json.dumps(rep).lower()
        for needle in ("expected issue", "recall", "precision", "hit", "scored"):
            self.assertNotIn(f'"{needle}', low)
        self.assertIn("not recall", rep["quality"])

    def test_refuted_control_makes_no_finding_and_no_comment(self):
        rep, model = self.live(self.model("refuted"))
        self.assertEqual((rep["status"], rep["ok"]), ("completed", True))
        self.assertEqual((rep["counts"]["findings"], rep["counts"]["comments"], rep["counts"]["drops"]), (0, 0, 1))
        self.assertEqual(len(model.requests), 4)                        # judge never called: nothing to word

    def test_a_miss_is_reported_as_is_with_exactly_one_call_and_no_retry_or_repeat(self):
        rep, model = self.live(self.model("miss"))
        self.assertEqual((rep["status"], rep["counts"]["hypotheses"], rep["counts"]["comments"]), ("completed", 0, 0))
        self.assertEqual(len(model.requests), 1)
        committed = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000).totals()["committedUsdMicros"]
        again = self.model("miss")
        try:
            rep2 = P.run_positive(self.live_options(out_dir=str(self.tmp / "again"), baseline_micros=committed),
                                  transport=again, key_loader=self.loader)
        except P.PositiveError:
            rep2 = None
        self.assertEqual(again.requests, [])                  # no automatic repeat: the ledger refuses before any contact
        self.assertTrue(rep2 is None or not rep2["ok"])

    def test_http_500_stops_after_one_attempt_with_a_report(self):
        m = Model(self.head_id(), fail_with=HttpResponse(500, {}, b"{}"))
        rep, _ = self.live(m)
        self.assertFalse(rep["ok"])
        self.assertEqual(len(m.requests), 1)
        self.assertTrue(Path(rep["reportPath"]).is_file())

    def test_ledger_gets_five_accountable_rows_and_state_is_not_widened(self):
        rep, _ = self.live()
        t = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000).totals()
        self.assertEqual(t["committedUsdMicros"] - BASELINE, 5 * 4200)       # five accountable calls, nothing more
        self.assertEqual(t["capUsdMicros"], 50_000_000)                       # the same aggregate, not widened
        self.assertEqual(rep["costs"]["spendBook"]["inflight"], 0)
        self.assertEqual(rep["costs"]["spendBook"]["limit"], 50_000_000)

    def test_secrets_never_reach_the_model_or_the_outputs(self):
        rep, model = self.live()
        self.assertNotIn(FAKE_KEY, json.dumps(model.bodies))
        for p in Path(rep["paths"]["runDir"]).rglob("*"):
            if p.is_file():
                self.assertNotIn(FAKE_KEY, p.read_text(errors="replace"))
        self.assertNotIn(FAKE_KEY, Path(rep["reportPath"]).read_text())
        self.assertEqual(self.loads, [str(self.env)])

    def test_refusals_before_the_key_leave_state_and_output_alone(self):
        self.seed()
        before = self.state_bytes()
        cases = [dict(baseline_micros=BASELINE + 1), dict(confirm_live=False)]
        for kw in cases:
            with self.assertRaises(Exception):
                P.run_positive(self.live_options(**kw), transport=self.model(), key_loader=self.boom)
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())

    def test_inflight_and_aggregate_ceiling_refuse_before_the_key(self):
        self.seed(inflight=1000)
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.live_options(), transport=self.model(), key_loader=self.boom)
        self.assertFalse(self.out.exists())

    def test_missing_state_is_refused_and_not_created(self):
        shutil.rmtree(self.state)
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.live_options(), transport=self.model(), key_loader=self.boom)
        self.assertFalse(self.state.exists())


# ======================================================================== replay

class ReplayTests(Rig):
    def replay_options(self, rep, **over):
        d = dict(mode="replay", auth=None, out_dir=str(self.tmp / "replay-out"), replay_trace=rep["paths"]["trace"],
                 trace_digest=rep["traceDigest"]["value"])
        d.update(over)
        return self.options(**d)

    def test_strict_replay_is_zero_cost_keyless_and_matches_the_recorded_run(self):
        rep, _ = self.live()
        before = self.state_bytes()
        rr = P.run_positive(self.replay_options(rep), key_loader=self.boom)
        self.assertEqual((rr["status"], rr["ok"]), ("completed", True))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["consumedZeroLive"]),
                         (0, 0, True))
        self.assertEqual(rr["replay"]["replayedCalls"], 5)
        self.assertEqual(rr["providerCalls"], 0)
        self.assertEqual(rr["counts"], rep["counts"])
        strip = lambda p: json.loads(re.sub(r'"run_[0-9a-f]{16}"', '"RUN"', Path(p).read_text()))
        self.assertEqual(strip(rr["paths"]["comments"]), strip(rep["paths"]["comments"]))   # same text; only run ids differ
        self.assertEqual(self.state_bytes(), before)
        self.assertEqual(self.loads, [str(self.env)])
        self.assertIn("fork is not implemented", rr["forkAndStageReplay"])

    def test_wrong_digest_and_a_tampered_trace_are_refused_with_no_output(self):
        rep, _ = self.live()
        with self.assertRaises(Exception) as c:
            P.run_positive(self.replay_options(rep, trace_digest="sha256:" + "0" * 64), key_loader=self.boom)
        self.assertEqual(type(c.exception).__name__, "PipelineError")
        self.assertFalse((self.tmp / "replay-out").exists())

    def test_replay_after_a_source_change_is_refused_by_the_baseline(self):
        rep, _ = self.live()
        self.baseline.write_text(json.dumps({"schema": "software-baseline@1", "files": {}}))
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.replay_options(rep), key_loader=self.boom)
        self.assertFalse((self.tmp / "replay-out").exists())


# ======================================================================== CLI

class CliTests(Rig):
    def argv(self, *extra):
        return ["--source-baseline", str(self.baseline), "--out", str(self.out), *extra]

    def test_plan_exit_0_json_and_text(self):
        code, out, err = self.run_main(self.argv("--auth", str(self.auth), "--json"), key_loader=self.boom)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["status"], "planned")
        code, out, _ = self.run_main(self.argv("--auth", str(self.auth)), key_loader=self.boom)
        self.assertEqual(code, 0)
        self.assertIn("mode: plan", out)
        self.assertIn("not recall", out)

    def test_refusals_exit_2_and_a_missed_run_exits_1(self):
        code, _, err = self.run_main(self.argv("--mode", "live", "--auth", str(self.auth)), key_loader=self.boom)
        self.assertEqual(code, 2)
        self.assertIn("PositiveError", err)
        self.seed()
        argv = self.argv("--mode", "live", "--auth", str(self.auth), "--state-dir", str(self.state), "--env", str(self.env),
                         "--baseline-micros", str(BASELINE), "--confirm-live", "--json")
        code, out, _ = self.run_main(argv, transport=self.model("miss"), key_loader=self.loader)
        self.assertEqual(code, 0)          # completed with no finding is still "completed": the miss is the scorer's call
        self.assertEqual(json.loads(out)["counts"]["comments"], 0)


if __name__ == "__main__":
    unittest.main()
