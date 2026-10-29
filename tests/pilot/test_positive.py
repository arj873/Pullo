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
from unittest import mock

from reviewer.contracts.canonical import digest, hypothesis_id
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pilot import positive as P
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET
from tests.pilot.test_repository import USAGE, entries
from tests.pipeline.helpers import tcid
from tests.specialist_lanes import lanes

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
        # EXPLORE-FLOOR: under investigator.impact@v2 the hop-0 empty answer is a draft; the second answers the one
        # floor continuation (and is accepted as it stands).
        return [{"contextRequests": [], "output": {"hypotheses": []}}] * 2

    def __call__(self, http_req):
        self.requests.append(http_req)
        if self.fail_with is not None:
            return self.fail_with
        self.bodies.append(json.loads(http_req.body))
        content = lanes(self).next(self.bodies[-1])
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
                                 "--trace-digest", "--json", "--config", "--control-dir", "--control-id",
                                 "--control-repo", "--control-pins"})


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
        self.assertEqual(p["capturedCount"], 3)          # SPECIALISTS-01: each specialist's first request
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
        # SPECIALISTS-01: three specialists ask then answer (the same hypothesis; two are merged), verifier, judge
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 9))
        self.assertEqual([b["response_format"]["json_schema"]["name"] for b in model.bodies],
                         ["InvestigatorTurn"] * 6 + ["VerifierTurn", "VerifierTurn", "JudgeOutput"])
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
                         sorted([(DEF_PATH, "INVESTIGATE"), (CALLER_PATH, "INVESTIGATE")] * 3 + [(DEF_PATH, "VERIFY")]))
        self.assertTrue(all(e["tool"] == "read_file" and e["result"]["status"] == "ok" for e in asked))
        self.assertIn(model.read_id, [e["toolCallId"] for e in asked])      # the verifier's cited id is the executed read
        ver = (Path(rep["paths"]["runDir"]) / "artifacts" / "05-VERIFY.v1.json").read_text()
        self.assertIn(model.read_id, ver)                                   # tool-ref evidence kept in the VERIFY artifact
        self.assertIn(BUG_TEXT.strip(), ver)
        chains = rep["retrieval"]["summary"]["chains"]
        self.assertEqual([(c["role"], c["hops"], c["requestedToolCalls"], c["final"]) for c in chains],
                         [("investigator", 2, 2, True)] * 3 + [("verifier", 2, 1, True)])
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
        # SPECIALISTS-01: + the two merged duplicates of the later specialists
        self.assertEqual((rep["counts"]["findings"], rep["counts"]["comments"], rep["counts"]["drops"]), (0, 0, 3))
        self.assertEqual(len(model.requests), 8)                        # judge never called: nothing to word

    def test_a_miss_is_reported_as_is_with_exactly_one_call_and_no_retry_or_repeat(self):
        rep, model = self.live(self.model("miss"))
        self.assertEqual((rep["status"], rep["counts"]["hypotheses"], rep["counts"]["comments"]), ("completed", 0, 0))
        # per specialist: one draft call + the one exploration-floor continuation (EXPLORE-FLOOR, SPECIALISTS-01);
        # no retry, no repeat
        self.assertEqual(len(model.requests), 6)
        self.assertIn("explorationFloor", json.loads(json.loads(model.requests[1].body)["messages"][1]["content"]))
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
        self.assertEqual(t["committedUsdMicros"] - BASELINE, 9 * 4200)       # nine accountable calls, nothing more
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
        self.assertEqual(rr["replay"]["replayedCalls"], 9)
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


# ======================================================================== optional private control (DOGFOOD-CONTROL-HOST-01)

CTL_ID, CTL_REPO = "control-a1", "owned/control-a"
CTL_BASE = {"app/units.py": "UNIT = 1000\n", "app/store.py": "def total(xs):\n    return sum(xs)\n"}
CTL_HEAD = {"app/units.py": "UNIT = 1000\n", "app/store.py": "def total(xs):\n    return sum(xs) + 0\n"}
CTL_STORE = dict(side="head", path="app/store.py", start_line=1, end_line=2)
CASE_KEYS = {"schema", "id", "repo", "synthetic", "base", "head", "pr"}
IDENT_KEYS = {"schema", "caseId", "sourceScopeDigest", "snapshotIds", "profile", "plan", "retrievalPolicy", "prTextSupplied"}


def tree_hashes(root: Path) -> dict:
    """Independent of the module under test."""
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


class ControlRig(Rig):
    """Rig whose default options select an invented private control held outside the checkout."""

    def setUp(self):
        super().setUp()
        self.ctl = self.tmp / "ctl" / "control"
        self.pins_path = self.op / "control-pins.json"
        self.reset()

    def reset(self, base=None, head=None):
        force_remove(self.ctl.parent)
        for side, files in (("base", base or CTL_BASE), ("head", head or CTL_HEAD)):
            for rel, text in files.items():
                (self.ctl / side / rel).parent.mkdir(parents=True, exist_ok=True)
                (self.ctl / side / rel).write_text(text)
        self.write_pins()

    def pins_doc(self, **over):
        d = {"schema": "control-pins@1", "caseId": CTL_ID, "repo": CTL_REPO, "base": tree_hashes(self.ctl / "base"),
             "head": tree_hashes(self.ctl / "head")}
        d.update(over)
        return d

    def write_pins(self, doc=None):
        self.pins_path.write_text(json.dumps(self.pins_doc() if doc is None else doc))

    def options(self, **over):
        d = dict(control_dir=str(self.ctl), control_id=CTL_ID, control_repo=CTL_REPO, control_pins=str(self.pins_path))
        d.update(over)
        return super().options(**d)

    NO_CONTROL = dict(control_dir=None, control_id=None, control_repo=None, control_pins=None)

    def hop_model(self):
        """One real read_file hop into the control's head tree, then an empty answer: two accountable calls."""
        return Model(self.head_id(), [
            {"contextRequests": [{"tool": "read_file", "purpose": "read the store", "args": entries(**CTL_STORE)}],
             "output": None},
            {"contextRequests": [], "output": {"hypotheses": []}}])

    def identity(self, **over):
        o = self.options(**over)
        prep = P.prepare(o)
        evr = P.eval_run_id(o, P.config_identity(prep, *P._profile_parts()))
        return evr, P.provider_scope(evr, prep)

    def refuse(self, fragment, *, options=None, **over):
        """A refusal before any state, key, network or output access. The caller seeded the state once."""
        before, model = self.state_bytes(), Model("unused-head-id")
        o = options or self.live_options(**over)
        with self.assertRaises(P.PositiveError, msg=fragment) as c:
            P.run_positive(o, transport=model, key_loader=self.boom)
        self.assertIn(fragment, str(c.exception))
        self.assertEqual(model.requests, [])
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.loads, [])


class ControlDefaultTests(ControlRig):
    def test_default_path_has_no_control_and_the_same_identity_shape(self):
        o = self.options(**self.NO_CONTROL)
        prep = P.prepare(o)
        self.assertIsNone(prep.control)
        self.assertEqual((prep.case["id"], prep.case["repo"]), (P.CASE_ID, P.CASE_REPO))
        ident = P.config_identity(prep, *P._profile_parts())
        self.assertEqual(set(ident), IDENT_KEYS)
        self.assertEqual(ident["caseId"], "retrieval-positive-1")
        rep = P.run_positive(o, key_loader=self.boom)
        self.assertEqual((rep["status"], rep["case"], rep["repo"]), ("planned", "retrieval-positive-1", "owned/lease-scheduler"))
        self.assertNotIn("control", rep)
        self.assertEqual(rep["plan"]["firstRequest"]["schemaName"], "InvestigatorTurn")

    def test_an_old_baseline_without_the_control_still_works_and_the_control_is_not_in_its_scope(self):
        self.assertTrue(all(not k.startswith("app/") for k in scope_hashes()))
        self.assertEqual(P.run_positive(self.options(), key_loader=self.boom)["status"], "planned")


class ControlPlanLiveReplayTests(ControlRig):
    def test_valid_control_plan_is_synthetic_labelled_and_touches_nothing(self):
        self.seed()
        before = self.state_bytes()
        rep = P.run_positive(self.options(), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"], rep["case"], rep["repo"], rep["synthetic"]),
                         ("planned", True, CTL_ID, CTL_REPO, True))
        self.assertEqual(rep["control"]["pinsDigest"], digest(self.pins_doc()))
        self.assertEqual(rep["control"]["fileCounts"], {"base": 2, "head": 2})
        self.assertIn("not historical", rep["control"]["label"])
        self.assertIn("no recall or quality rate", rep["control"]["label"])
        p = rep["plan"]
        self.assertEqual((p["capturedCount"], p["firstRequest"]["schemaName"], p["firstRequest"]["model"]),
                         (3, "InvestigatorTurn", SONNET))         # SPECIALISTS-01: one per specialist
        self.assertEqual((p["retries"], p["repairs"], p["providerCalls"], p["networkCalls"], p["keyRead"]), (0, 0, 0, 0, False))
        self.assertEqual(p["toolBudget"], {"maxToolCalls": 160, "maxToolCallsPerAgent": 60})
        self.assertEqual(p["outputCaps"], {"investigator": 16000, "verifier": 6000, "judge": 8000})
        self.assertLessEqual(p["worstCaseAdmissionUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.loads, [])

    def test_the_case_input_and_every_request_carry_no_label_gold_pins_path_or_pr_text(self):
        prep = P.prepare(self.options())
        self.assertEqual(set(prep.case), CASE_KEYS)
        self.assertEqual((prep.case["synthetic"], prep.case["pr"]), (True, {"title": "", "body": ""}))
        rep, model = self.live(self.hop_model())
        wire = json.dumps(model.bodies).lower()
        for needle in (P.CONTROL_LABEL, str(self.ctl), str(self.pins_path), rep["control"]["pinsDigest"], "control-pins",
                       "ground", "gold", "seeded", CLAIM):
            self.assertNotIn(needle.lower(), wire, needle)
        user = json.loads(model.bodies[0]["messages"][1]["content"])
        self.assertEqual(user["untrustedPullRequest"], {"title": "", "body": ""})
        self.assertIn("app/store.py", json.dumps(user["context"]))

    def test_plan_equals_the_live_first_request_and_retrieval_reads_the_control_tree(self):
        a = P.run_positive(self.options(), key_loader=self.boom)["plan"]["firstRequest"]
        rep, model = self.live(self.hop_model())
        self.assertEqual(hashlib.sha256(model.requests[0].body).hexdigest(), a["bodySha256"])
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"], rep["case"], rep["repo"]),
                         ("completed", True, 6, CTL_ID, CTL_REPO))        # SPECIALISTS-01: 3 x (ask, final)
        events = [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]
        reads = [e for e in events if e.get("type") == "tool.call" and "requestedBy" in e]
        self.assertEqual([(e["args"]["path"], e["result"]["status"]) for e in reads], [("app/store.py", "ok")] * 3)
        self.assertEqual(rep["retrieval"]["summary"]["unreadRequests"], 0)

    def test_strict_replay_is_zero_cost_and_a_different_control_cannot_replay_the_trace(self):
        rep, _ = self.live(self.hop_model())
        before = self.state_bytes()
        d = dict(mode="replay", auth=None, out_dir=str(self.tmp / "replay-out"), replay_trace=rep["paths"]["trace"],
                 trace_digest=rep["traceDigest"]["value"])
        rr = P.run_positive(self.options(**d), key_loader=self.boom)
        self.assertEqual((rr["status"], rr["ok"], rr["providerCalls"], rr["case"]), ("completed", True, 0, CTL_ID))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["replayedCalls"], rr["replay"]["newSpendUsdMicros"]), (0, 6, 0))
        self.assertEqual(rr["control"], rep["control"])
        self.assertEqual(self.state_bytes(), before)
        self.reset(head={**CTL_HEAD, "app/store.py": "def total(xs):\n    return sum(xs) + 1\n"})
        d["out_dir"] = str(self.tmp / "replay-other")
        with self.assertRaises(Exception) as c:
            P.run_positive(self.options(**d), key_loader=self.boom)
        self.assertEqual(type(c.exception).__name__, "PipelineError")
        self.assertFalse((self.tmp / "replay-other").exists())

    def test_a_ledger_run_adds_only_the_control_calls_and_does_not_widen_state(self):
        rep, _ = self.live(self.hop_model())
        t = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000).totals()
        self.assertEqual((t["committedUsdMicros"] - BASELINE, t["capUsdMicros"]), (6 * 4200, 50_000_000))
        self.assertEqual(rep["costs"]["spendBook"]["limit"], 50_000_000)


class ControlPinTests(ControlRig):
    def setUp(self):
        super().setUp()
        self.seed()

    def raw(self, text):
        self.pins_path.write_text(text)

    def test_changed_extra_and_missing_files_in_either_tree_are_refused(self):
        cases = {
            "changed base": (lambda: (self.ctl / "base/app/store.py").write_text("x = 1\n"), "changed"),
            "changed head": (lambda: (self.ctl / "head/app/units.py").write_text("UNIT = 1\n"), "changed"),
            "extra base": (lambda: (self.ctl / "base/app/extra.py").write_text("y = 2\n"), "unpinned"),
            "extra nested head": (lambda: ((self.ctl / "head/deep").mkdir(), (self.ctl / "head/deep/x.py").write_text("")), "unpinned"),
            "missing base": (lambda: (self.ctl / "base/app/units.py").unlink(), "missing"),
            "missing head": (lambda: (self.ctl / "head/app/store.py").unlink(), "missing"),
            "unpinned top-level entry": (lambda: (self.ctl / "notes.json").write_text("{}"), "exactly base/ and head/"),
        }
        for name, (mutate, fragment) in cases.items():
            with self.subTest(name):
                mutate()
                self.refuse(fragment)
                self.reset()

    def test_malformed_wrong_or_mismatched_pins_are_refused(self):
        doc = self.pins_doc()
        good = json.dumps(doc)
        cases = {
            "pinned file not on disk": (lambda: self.write_pins({**doc, "head": {**doc["head"], "app/ghost.py": "1" * 64}}), "missing"),
            "disk file not pinned": (lambda: self.write_pins({**doc, "base": {"app/units.py": doc["base"]["app/units.py"]}}), "unpinned"),
            "wrong sha": (lambda: self.write_pins({**doc, "head": {**doc["head"], "app/units.py": "0" * 64}}), "changed"),
            "other case id": (lambda: self.write_pins({**doc, "caseId": "control-zz"}), "different case id or repo"),
            "other repo": (lambda: self.write_pins({**doc, "repo": "owned/other"}), "different case id or repo"),
            "duplicate key": (lambda: self.raw(good[:-1] + ', "caseId": "%s"}' % CTL_ID), "strict JSON"),
            "not json": (lambda: self.raw("{nope"), "strict JSON"),
            "wrong schema": (lambda: self.write_pins({**doc, "schema": "control-pins@2"}), "control-pins@1"),
            "extra key": (lambda: self.write_pins({**doc, "labels": {}}), "control-pins@1"),
            "missing key": (lambda: self.write_pins({k: v for k, v in doc.items() if k != "repo"}), "control-pins@1"),
            "list not object": (lambda: self.raw("[]"), "control-pins@1"),
            "short sha": (lambda: self.write_pins({**doc, "base": {"app/units.py": "ab"}}), "malformed"),
            "upper-case sha": (lambda: self.write_pins({**doc, "base": {**doc["base"], "app/units.py": "A" * 64}}), "malformed"),
            "unsafe path": (lambda: self.write_pins({**doc, "head": {**doc["head"], "../x": "1" * 64}}), "malformed"),
            "empty tree": (lambda: self.write_pins({**doc, "head": {}}), "malformed"),
            "tree is a list": (lambda: self.write_pins({**doc, "base": []}), "malformed"),
            "absent": (lambda: self.pins_path.unlink(), "absent"),
            "pins are a link": (lambda: (self.pins_path.rename(self.op / "real.json"), self.pins_path.symlink_to(self.op / "real.json")),
                                "link"),
        }
        for name, (mutate, fragment) in cases.items():
            with self.subTest(name):
                mutate()
                self.refuse(fragment)
                if self.pins_path.is_symlink():
                    self.pins_path.unlink()
                self.write_pins()

    def test_links_special_files_executables_and_non_plain_roots_are_refused(self):
        def link_dir_root():
            shutil.move(str(self.ctl / "base"), str(self.tmp / "elsewhere"))
            (self.ctl / "base").symlink_to(self.tmp / "elsewhere")

        cases = {
            "file symlink": (lambda: (self.ctl / "head/app/ln.py").symlink_to("units.py"), "symlink"),
            "dir symlink": (lambda: (self.ctl / "base/lnk").symlink_to(self.ctl / "head"), "symlink"),
            "root symlink": (link_dir_root, "not a plain directory"),
            "executable": (lambda: os.chmod(self.ctl / "head/app/store.py", 0o755), "non-executable"),
            "fifo": (lambda: os.mkfifo(self.ctl / "base/app/pipe"), "non-executable"),
        }
        for name, (mutate, fragment) in cases.items():
            with self.subTest(name):
                mutate()
                self.refuse(fragment)
                force_remove(self.tmp / "elsewhere")
                self.reset()

    def test_a_refusal_in_replay_leaves_nothing_behind(self):
        (self.ctl / "head/app/units.py").write_text("UNIT = 2\n")
        o = self.options(mode="replay", auth=None, replay_trace=str(self.tmp / "t.jsonl"), trace_digest="sha256:" + "0" * 64,
                         out_dir=str(self.tmp / "replay-out"))
        with self.assertRaises(P.PositiveError) as c:
            P.run_positive(o, key_loader=self.boom)
        self.assertIn("changed", str(c.exception))
        self.assertFalse((self.tmp / "replay-out").exists())


class ControlHost03Tests(ControlRig):
    """HOST-03: three refusals that used to escape or echo raw."""

    def setUp(self):
        super().setUp()
        self.seed()

    def test_a_pins_directory_is_a_typed_refusal_before_state_key_and_output(self):
        self.pins_path.unlink()
        self.pins_path.mkdir()
        self.refuse("not a regular file")

    def test_an_escape_in_an_untrusted_file_name_is_never_echoed_raw(self):
        bad = "a\x1b[31mred\x07"
        for name, make in {"unpinned file": lambda: (self.ctl / "head/app" / bad).write_text("x"),
                           "symlink": lambda: (self.ctl / "base/app" / bad).symlink_to("units.py"),
                           "special file": lambda: os.mkfifo(self.ctl / "head/app" / bad)}.items():
            with self.subTest(name):
                make()
                before = self.state_bytes()
                with self.assertRaises(P.PositiveError) as c:
                    P.run_positive(self.live_options(), transport=Model("unused"), key_loader=self.boom)
                self.assertNotIn("\x1b", str(c.exception))
                self.assertNotIn("\x07", str(c.exception))
                self.assertIn("\\x1b", str(c.exception))
                self.assertEqual(self.state_bytes(), before)
                self.reset()

    def test_repo_must_match_the_case_input_grammar_and_refuse_cleanly(self):
        from reviewer.contracts import ContractViolation
        for repo in ("a.b/c.d", "a_b/c", "-/c", "a/..", "a/.", "x" * 40 + "/c"):
            with self.subTest(repo):
                self.refuse("lowercase slugs", control_repo=repo)
        for repo in ("a-b/c.d_e", "o/n", "0/1"):
            with self.subTest(repo):
                self.write_pins(self.pins_doc(repo=repo))
                P.check_options(self.options(control_repo=repo))
                self.assertEqual(P.prepare(self.options(control_repo=repo)).case["repo"], repo)   # CaseInput accepts it


class ControlOptionTests(ControlRig):
    def setUp(self):
        super().setUp()
        self.seed()

    def test_partial_empty_or_malformed_control_options_are_refused(self):
        for name in ("control_dir", "control_id", "control_repo", "control_pins"):
            for bad in (None, ""):
                with self.subTest(name=name, bad=bad):
                    self.refuse("needed together", **{name: bad})
        for kw, fragment in ((dict(control_id="Bad Id"), "lowercase slugs"), (dict(control_id="UPPER"), "lowercase slugs"),
                             (dict(control_repo="noslash"), "lowercase slugs"), (dict(control_repo="A/b"), "lowercase slugs"),
                             (dict(control_id=P.CASE_ID), "may not reuse"), (dict(control_repo=P.CASE_REPO), "may not reuse"),
                             (dict(control_id=5), "needed together")):
            with self.subTest(kw):
                self.refuse(fragment, **kw)

    def test_plan_and_replay_also_refuse_partial_options(self):
        before = self.state_bytes()
        for o in (self.options(control_pins=None),
                  self.options(mode="replay", auth=None, replay_trace="t", trace_digest="sha256:" + "0" * 64, control_id=None)):
            with self.assertRaises(P.PositiveError):
                P.run_positive(o, key_loader=self.boom)
        self.assertEqual((self.state_bytes(), self.out.exists(), self.loads), (before, False, []))

    def test_path_overlaps_with_the_control_or_the_checkout_are_refused(self):
        ctl = self.ctl
        cases = {
            "control inside the checkout": (dict(control_dir=str(REPO / "no-such-control")), "outside the checkout"),
            "checkout inside the control": (dict(control_dir=str(REPO.parent)), "outside the checkout"),
            "pins inside the checkout": (dict(control_pins=str(REPO / "pins.json")), "held outside the checkout"),
            "pins inside the control": (dict(control_pins=str(ctl / "base" / "pins.json")), "overlaps the control"),
            "pins are the source baseline": (dict(control_pins=str(self.baseline)), "separate files"),
            "source baseline inside the control": (dict(source_baseline=str(ctl / "baseline.json")), "overlaps the control"),
            "output inside the control": (dict(out_dir=str(ctl / "out")), "overlaps the control"),
            "output is the control's parent": (dict(out_dir=str(ctl.parent)), "overlaps the control"),
            "output is an ancestor": (dict(out_dir=str(self.tmp)), "overlaps the control"),
            "authorization inside the control": (dict(auth=str(ctl / "auth.json")), "overlaps the control"),
            "state inside the control": (dict(state_dir=str(ctl / "state")), "overlaps the control"),
            "env inside the control": (dict(env_file=str(ctl / "dot.env")), "overlaps the control"),
            "config inside the control": (dict(config=str(ctl / "pullo.toml")), "overlaps the control"),
            "output beside the control (parent is forbidden)": (dict(out_dir=str(ctl.parent / "out")), "overlaps"),
        }
        for name, (kw, fragment) in cases.items():
            with self.subTest(name):
                self.refuse(fragment, **kw)
        with self.subTest("replay trace inside the control"):
            self.refuse("overlaps the control", options=self.options(
                mode="replay", auth=None, replay_trace=str(ctl / "t.jsonl"), trace_digest="sha256:" + "0" * 64))
        with self.subTest("control dir is a link"):
            (self.tmp / "ctl-link").symlink_to(ctl)
            self.refuse("may not be a link", control_dir=str(self.tmp / "ctl-link"))


class ControlBoundaryTests(ControlRig):
    """Second-layer trust boundaries, reached directly (run_positive refuses the same paths earlier)."""

    def test_config_authorization_and_key_loader_all_exclude_the_control(self):
        from reviewer.config import ConfigError
        from reviewer.gateway import AuthorizationError
        prep, model = P.prepare(self.options()), self.hop_model()      # before the extra files make the trees differ from the pins
        shutil.copy(REPO / "pullo.toml", self.ctl / "pullo.toml")      # valid files, so only the root check can refuse
        shutil.copy(self.auth, self.ctl / "auth.json")
        os.chmod(self.ctl / "auth.json", 0o600)
        with self.assertRaises(ConfigError) as c:
            P.effective_config(self.options(config=str(self.ctl / "pullo.toml")))
        self.assertIn("outside", str(c.exception))
        with self.assertRaises(AuthorizationError) as c:
            P.plan_mode(self.options(auth=str(self.ctl / "auth.json")), prep)
        self.assertIn("content root", str(c.exception))
        with self.assertRaises(AuthorizationError):
            P.live_mode(self.live_options(auth=str(self.ctl / "auth.json")), prep, transport=model, key_loader=self.boom)
        self.assertEqual((model.requests, self.out.exists()), ([], False))
        self.assertFalse(self.out.exists())
        seen = []

        def loader(path, *, forbidden_roots=()):
            seen.append([str(Path(os.path.realpath(r))) for r in forbidden_roots])
            return Secret(FAKE_KEY)

        self.reset()
        self.seed()
        P.run_positive(self.live_options(), transport=model, key_loader=loader)
        self.assertIn(str(Path(os.path.realpath(self.ctl))), seen[0])
        self.assertIn(str(Path(os.path.realpath(self.pins_path))), seen[0])

    def test_a_tree_changed_between_the_pin_check_and_the_snapshot_is_refused(self):
        real = P.build_manifest

        def racing(root):
            (self.ctl / "head/app/units.py").write_text("UNIT = 7\n")
            return real(root)

        with mock.patch.object(P, "build_manifest", racing):
            with self.assertRaises(P.PositiveError) as c:
                P.prepare(self.options())
        self.assertIn("while it was being pinned", str(c.exception))


class ControlIdentityTests(ControlRig):
    def test_distinct_controls_never_share_run_ids_and_the_same_control_always_does(self):
        base = self.identity()
        self.assertEqual(self.identity(), base)
        self.pins_path.write_text(json.dumps(self.pins_doc(), indent=4))                 # formatting is not identity
        self.assertEqual(self.identity(), base)
        seen = {base[0]: "base", self.identity(**self.NO_CONTROL)[0]: "default"}
        variants = {}
        self.write_pins(self.pins_doc(caseId="control-a2"))
        variants["id"] = self.identity(control_id="control-a2")
        self.write_pins(self.pins_doc(repo="owned/control-b"))
        variants["repo"] = self.identity(control_repo="owned/control-b")
        self.reset(head={**CTL_HEAD, "app/store.py": "def total(xs):\n    return sum(xs) + 1\n"})
        variants["file"] = self.identity()
        self.reset(base={**CTL_BASE, "app/extra.py": "z = 3\n"})
        variants["extra base file"] = self.identity()
        for name, (evr, scope) in variants.items():
            self.assertNotIn(evr, seen, name)
            seen[evr] = name
            self.assertNotEqual(scope, base[1], name)
        self.assertEqual(len(seen), 6)

    def test_the_identity_binds_pins_snapshots_id_and_repo_and_the_source_baseline_is_untouched(self):
        o = self.options()
        prep = P.prepare(o)
        ident = P.config_identity(prep, *P._profile_parts())
        self.assertEqual(set(ident), IDENT_KEYS | {"control"})
        self.assertEqual(ident["control"], {"pinsDigest": digest(self.pins_doc()), "caseId": CTL_ID, "repo": CTL_REPO})
        self.assertEqual(ident["caseId"], CTL_ID)
        self.assertEqual(prep.source["scopeDigest"], P.prepare(self.options(**self.NO_CONTROL)).source["scopeDigest"])
        self.assertEqual(prep.fixture, Path(os.path.realpath(self.ctl)))


class ControlCliTests(ControlRig):
    def argv(self, *extra):
        return ["--source-baseline", str(self.baseline), "--out", str(self.out), "--auth", str(self.auth), *extra]

    def control_argv(self):
        return ["--control-dir", str(self.ctl), "--control-id", CTL_ID, "--control-repo", CTL_REPO,
                "--control-pins", str(self.pins_path)]

    def test_plan_with_a_control_exits_0_and_prints_the_label(self):
        code, out, err = self.run_main(self.argv(*self.control_argv(), "--json"), key_loader=self.boom)
        self.assertEqual((code, err), (0, ""))
        rep = json.loads(out)
        self.assertEqual((rep["status"], rep["case"], rep["control"]["fileCounts"]), ("planned", CTL_ID, {"base": 2, "head": 2}))
        code, out, _ = self.run_main(self.argv(*self.control_argv()), key_loader=self.boom)
        self.assertEqual(code, 0)
        self.assertIn("control: private synthetic control", out)

    def test_a_partial_set_of_flags_exits_2_with_nothing_created(self):
        code, _, err = self.run_main(self.argv(*self.control_argv()[:6]), key_loader=self.boom)
        self.assertEqual(code, 2)
        self.assertIn("needed together", err)
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
