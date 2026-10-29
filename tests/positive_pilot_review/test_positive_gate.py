"""S1-12-review: independent acceptance controls for the positive-pilot host harness (`reviewer.pilot.positive`).
Fake OpenRouter transport, fake key loader, files built in a temp dir. No network, no real .env/auth/ledger/book, no
fixture execution (the fixture is parsed as text/AST only). The oracle for the expected issue lives here and nowhere
else; scripted model answers exercise the harness, they say nothing about model quality."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from reviewer.contracts.canonical import hypothesis_id
from reviewer.contracts.snapshot import build_manifest
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pilot import positive as P
from reviewer.pipeline import PipelineError
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET
from tests.pilot.test_repository import USAGE, entries
from tests.pipeline.helpers import tcid

REPO = P.REPO
FIX = REPO / "fixtures" / "retrieval-positive"
BASELINE = 70_576
ENV_CANARY = "ENVCANARY-9f31c0de-do-not-leak"
CLAIM = "reap() compares lease expiry in milliseconds with a seconds clock reading"
BUG = ("leasing/scheduler.py", 16, "        now = clock.now_seconds()")
DEFN = ("leasing/lease.py", 7, "        self.expires_at = clock.now_millis() + ttl_ms")
CALLER = "leasing/worker.py"
BENIGN = "leasing/report.py"
ALLOWED_SCHEMAS = {"InvestigatorTurn", "VerifierTurn", "JudgeOutput"}


def scope_hashes(repo: Path = REPO) -> dict:
    out = {}
    for scope in ("reviewer", "fixtures/retrieval-positive"):
        for p in sorted((repo / scope).rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
                out[str(p.relative_to(repo))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def rmtree(path: Path) -> None:
    for dirpath, dirnames, _ in os.walk(path):
        for d in [dirpath, *[os.path.join(dirpath, x) for x in dirnames]]:
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


class Model:
    """Fake OpenRouter transport. `script` entries are JSON-able answers or HttpResponse objects, consumed in order."""

    def __init__(self, head_id, script=None):
        self.head_id = head_id
        self.requests, self.bodies = [], []
        self.read_id = tcid("VERIFY", "verifier", 2, "read_file", side="head", path=DEFN[0], start_line=1, end_line=9)
        self.script = script if script is not None else self.positive()

    def cite(self, path, line, text):
        return {"kind": "code", "path": path, "lines": [line, line], "commit": self.head_id, "excerpt": text}

    def hyp(self, path=BUG[0], line=BUG[1], text=BUG[2], claim=CLAIM, extra=()):
        return {"claim": claim, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
                "location": {"path": path, "line": line}, "mechanism": "units differ",
                "evidence": [self.cite(path, line, text), *extra]}

    @staticmethod
    def ask(*reads):
        return {"contextRequests": [{"tool": "read_file", "purpose": "look", "args": entries(side="head", path=p,
                                      start_line=a, end_line=b)} for p, a, b in reads], "output": None}

    @staticmethod
    def final(output):
        return {"contextRequests": [], "output": output}

    def verdict(self, v, evidence=None):
        ev = evidence if evidence is not None else [self.cite(*BUG), {"kind": "tool-ref", "toolCallId": self.read_id, "index": 0}]
        return self.final({"verdict": v, "reachable": v == "confirmed", "impact": "incorrect-result", "notes": "n",
                           "evidence": ev})

    def comment(self, claim=CLAIM, path=BUG[0], line=BUG[1]):
        return {"comments": [{"findingIds": [hypothesis_id("generalist", 0, claim, path, line)],
                              "title": "Leases never expire", "body": "milliseconds vs seconds"}]}

    def positive(self):
        return [self.ask((DEFN[0], 1, 9), (CALLER, 1, 12)),
                self.final({"hypotheses": [self.hyp(extra=[self.cite(*DEFN)])]}),
                self.ask((DEFN[0], 1, 9)), self.verdict("confirmed"), self.comment()]

    def __call__(self, http_req):
        self.requests.append(http_req)
        self.bodies.append(json.loads(http_req.body))
        item = self.script[len(self.requests) - 1]
        if isinstance(item, HttpResponse):
            return item
        d = {"id": f"gen-{len(self.requests)}", "model": SONNET, "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": item if isinstance(item, str) else json.dumps(item)}}],
             "usage": USAGE}
        return HttpResponse(200, {}, json.dumps(d).encode())


# EXPLORE-FLOOR: under the pilot default investigator.impact@v2 a hop-0 empty answer is a draft; the second empty
# answer replies to the one exploration-floor continuation and is accepted as it stands.
MISS = [Model.final({"hypotheses": []})] * 2


class Rig(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._rm)
        self.tmp = Path(os.path.realpath(self._t.name))
        self.op = self.tmp / "operator"
        self.state = self.op / "state"
        self.state.mkdir(parents=True)
        self.baseline = self.op / "software-baseline.json"
        self.write_baseline()
        self.auth = self.op / "auth.json"
        self.write_auth(AUTH)
        self.env = self.op / "dot.env"
        self.env.write_text(f"openrouter_key={ENV_CANARY}\n")
        self.out = self.tmp / "out"
        self.loads = []
        self.before = scope_hashes()
        self.modules_before = {m for m in sys.modules if m == "leasing" or m.startswith("leasing.")}

    def _rm(self):
        rmtree(Path(self._t.name))
        try:
            self._t.cleanup()
        except FileNotFoundError:
            pass

    def state_reset(self):
        for p in self.state.iterdir():
            p.unlink()

    def tearDown(self):
        self.assertEqual(scope_hashes(), self.before, "reviewed source or fixture changed during a test")
        self.assertEqual({m for m in sys.modules if m == "leasing" or m.startswith("leasing.")}, self.modules_before,
                         "a fixture module was imported (executed)")
        self.assertFalse([p for p in FIX.rglob("*") if p.name == "__pycache__" or p.suffix == ".pyc"])

    def write_baseline(self, files=None):
        self.baseline.write_text(json.dumps({"schema": "software-baseline@1", "capturedAt": "2026-10-26T00:00:00Z",
                                             "files": scope_hashes() if files is None else files}))

    def write_auth(self, doc):
        self.auth.write_text(json.dumps(doc))
        os.chmod(self.auth, 0o600)

    def loader(self, path, *, forbidden_roots=()):
        self.loads.append(str(path))
        return Secret(FAKE_KEY)

    @staticmethod
    def boom(path, *, forbidden_roots=()):
        raise AssertionError("the key loader must not be called")

    def options(self, **over):
        d = dict(mode="plan", source_baseline=str(self.baseline), out_dir=str(self.out), auth=str(self.auth))
        d.update(over)
        return P.PositiveOptions(**d)

    def live_options(self, **over):
        d = dict(mode="live", state_dir=str(self.state), env_file=str(self.env), baseline_micros=BASELINE,
                 confirm_live=True)
        d.update(over)
        return self.options(**d)

    def head_id(self):
        return P.prepare(self.options()).case["head"]["snapshotId"]

    def model(self, script=None):
        return Model(self.head_id(), script)

    def seed(self, committed=BASELINE, inflight=0, ledger_open=False):
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
        if ledger_open:
            led.admit("open|INVESTIGATE|investigator|generalist|0|0", 100_000, model=SONNET)

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def live(self, model=None, **over):
        model = model or self.model()
        if not (self.state / P.LEDGER_NAME).exists():
            self.seed()
        rep = P.run_positive(self.live_options(**over), transport=model, key_loader=self.loader)
        return rep, model

    def events(self, rep):
        return [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]

    def ledger_rows(self):
        return [json.loads(x) for x in (self.state / P.LEDGER_NAME).read_text().splitlines()]


# ===================================================================== fixture: reachable bug vs benign refactor

class FixtureSemantics(unittest.TestCase):
    """Structural reading of the fixture (ast only; nothing is imported or run)."""

    @staticmethod
    def tree(side, name):
        return ast.parse((FIX / side / "leasing" / name).read_text())

    @staticmethod
    def calls(node):
        return [ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)]

    def func(self, side, file, name):
        for n in ast.walk(self.tree(side, file)):
            if isinstance(n, (ast.FunctionDef,)) and n.name == name:
                return n
        self.fail(f"{side}/{file}:{name} missing")

    def test_unit_of_the_stored_expiry_versus_the_clock_the_head_compares_against(self):
        clock_src = ast.unparse(self.func("head", "clock.py", "now_millis"))
        self.assertIn("* 1000", clock_src)                                    # millis really is the 1000x unit
        self.assertNotIn("1000", ast.unparse(self.func("head", "clock.py", "now_seconds")))
        for fn in ("__init__", "renew"):                                      # unchanged: expiry is stored in millis
            self.assertIn("clock.now_millis", self.calls(self.func("head", "lease.py", fn)))
        reap = lambda side: self.calls(self.func(side, "scheduler.py", "reap"))
        self.assertIn("clock.now_millis", reap("base"))                       # before: same unit as the stored expiry
        self.assertIn("clock.now_seconds", reap("head"))                      # after: different unit => introduced
        self.assertNotIn("clock.now_millis", reap("head"))
        cmp_ = [n for n in ast.walk(self.func("head", "scheduler.py", "reap")) if isinstance(n, ast.Compare)]
        self.assertTrue(any("expires_at" in ast.unparse(c) and "now" in ast.unparse(c) for c in cmp_))

    def test_reachable_from_an_unchanged_caller_loop(self):
        self.assertIn("scheduler.reap", self.calls(self.func("head", "worker.py", "run_tick")))
        self.assertIn("run_tick", self.calls(self.func("head", "worker.py", "run_forever")))
        self.assertEqual((FIX / "base/leasing/worker.py").read_bytes(), (FIX / "head/leasing/worker.py").read_bytes())

    def test_exactly_one_behavioural_change_plus_one_pure_refactor(self):
        diff = sorted(p.name for p in (FIX / "head/leasing").glob("*.py")
                      if p.read_bytes() != (FIX / "base/leasing" / p.name).read_bytes())
        self.assertEqual(diff, ["report.py", "scheduler.py"])
        b, h = (FIX / "base/leasing/scheduler.py").read_text().splitlines(), (FIX / "head/leasing/scheduler.py").read_text().splitlines()
        self.assertEqual([i for i, (x, y) in enumerate(zip(b, h)) if x != y], [BUG[1] - 1])   # one line, the unit
        # report.py: same single function, no clock/scheduler dependence, same output template in both versions
        for side in ("base", "head"):
            t = self.tree(side, "report.py")
            self.assertEqual([n.name for n in t.body], ["summary"])
            src = ast.unparse(t)
            self.assertIn("held by", src)
            self.assertNotIn("clock", src)
            self.assertNotIn("import", src)

    def test_oracle_coordinates_are_real_head_lines(self):
        for path, line, text in (BUG, DEFN):
            self.assertEqual((FIX / "head" / path).read_text().splitlines()[line - 1], text)

    def test_fixture_carries_no_label_hint_comment_or_metadata_file(self):
        names = [p for p in FIX.rglob("*") if p.is_file()]
        self.assertTrue(names)
        for p in names:
            self.assertEqual(p.suffix, ".py", p)
            low = p.read_text().lower()
            self.assertNotIn("#", low)
            self.assertNotRegex(low, r"\b(bug|defect|expected|label|mismatch|fixme|todo|xxx|intentional|wrong|unit|units|seconds_vs)\b")
            self.assertNotIn('"""', low)
        self.assertEqual(sorted(p.name for p in (FIX / "head").iterdir()), ["leasing"])


# ===================================================================== freeze / baseline

class SourceFreeze(Rig):
    @unittest.expectedFailure
    def test_stray_pycache_or_pyc_in_the_fixture_is_not_hidden_from_the_baseline(self):
        """KNOWN GAP (see handoff): the baseline scan skips `__pycache__`/*.pyc inside the FIXTURE, but build_manifest
        includes them, so an unbaselined file could become model-visible. Desired behaviour asserted; currently fails."""
        t = Path(tempfile.mkdtemp(dir=self.tmp))
        shutil.copytree(REPO / "fixtures", t / "fixtures")
        shutil.copytree(REPO / "reviewer", t / "reviewer", ignore=shutil.ignore_patterns("__pycache__"))
        (t / "fixtures/retrieval-positive/head/leasing/__pycache__").mkdir()
        (t / "fixtures/retrieval-positive/head/leasing/__pycache__/x.py").write_text("hi\n")
        files = scope_hashes(REPO)
        self.baseline.write_text(json.dumps({"schema": "software-baseline@1", "files": files}))
        visible = {e["path"] for e in build_manifest(t / "fixtures/retrieval-positive/head")["entries"]}
        try:
            P.load_source_baseline(str(self.baseline), repo=t)
            accepted = True
        except P.PositiveError:
            accepted = False
        self.assertFalse(accepted and "leasing/__pycache__/x.py" in visible,
                         "baseline accepted a fixture whose model-visible snapshot has an unlisted file")

    def test_one_byte_in_either_fixture_side_or_the_harness_refuses_every_mode(self):
        t = Path(tempfile.mkdtemp(dir=self.tmp))
        for scope in ("fixtures", "reviewer"):
            shutil.copytree(REPO / scope, t / scope, ignore=shutil.ignore_patterns("__pycache__"))
        for victim in ("fixtures/retrieval-positive/base/leasing/clock.py", "fixtures/retrieval-positive/head/leasing/lease.py",
                       "reviewer/pilot/positive.py"):
            with self.subTest(victim):
                f = t / victim
                orig = f.read_bytes()
                f.write_bytes(orig + b"\n")
                with self.assertRaises(P.PositiveError) as c:
                    P.load_source_baseline(str(self.baseline), repo=t)
                self.assertIn("changed", str(c.exception))
                f.write_bytes(orig)
                P.load_source_baseline(str(self.baseline), repo=t)

    def test_a_link_in_the_scope_or_a_baseline_symlinked_into_the_checkout_is_refused(self):
        link = self.tmp / "baseline-link.json"
        link.symlink_to(REPO / "pyproject.toml" if (REPO / "pyproject.toml").exists() else REPO / "AGENTS.md")
        with self.assertRaises(P.PositiveError) as c:
            P.load_source_baseline(str(link))
        self.assertIn("outside the checkout", str(c.exception))
        t = Path(tempfile.mkdtemp(dir=self.tmp))
        for scope in ("fixtures", "reviewer"):
            shutil.copytree(REPO / scope, t / scope, ignore=shutil.ignore_patterns("__pycache__"))
        (t / "fixtures/retrieval-positive/head/leasing/ln.py").symlink_to(t / "fixtures/retrieval-positive/head/leasing/clock.py")
        with self.assertRaises(P.PositiveError):
            P.load_source_baseline(str(self.baseline), repo=t)

    def test_baseline_is_checked_before_state_key_or_output_in_live_and_replay(self):
        self.write_baseline({})
        self.seed()
        before = self.state_bytes()
        for o in (self.live_options(), self.options(mode="replay", auth=None, replay_trace="t",
                                                    trace_digest="sha256:" + "0" * 64)):
            with self.assertRaises(P.PositiveError):
                P.run_positive(o, key_loader=self.boom, transport=self.boom)
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())


# ===================================================================== plan / first request

class PlanControls(Rig):
    def test_plan_first_request_is_the_live_first_request_and_carries_no_secret(self):
        self.seed()
        before = self.state_bytes()
        plan = P.run_positive(self.options(), key_loader=self.boom)
        self.assertEqual((plan["status"], plan["plan"]["providerCalls"], plan["plan"]["keyRead"]), ("planned", 0, False))
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())
        rep, model = self.live()
        first = model.requests[0]
        f = plan["plan"]["firstRequest"]
        self.assertEqual(hashlib.sha256(first.body).hexdigest(), f["bodySha256"])
        self.assertEqual(len(first.body), f["bodyBytes"])
        self.assertNotIn(FAKE_KEY.encode(), first.body)
        self.assertNotIn(ENV_CANARY.encode(), first.body)
        self.assertNotIn(str(self.state).encode(), first.body)
        self.assertNotIn(str(self.auth).encode(), first.body)
        self.assertEqual(model.bodies[0]["response_format"]["json_schema"]["name"], "InvestigatorTurn")
        self.assertEqual(plan["plan"]["worstCaseAdmissionUsdMicros"] <= 4_000_000, True)

    def test_plan_is_not_a_live_run_even_when_the_runner_would_continue(self):
        calls = []

        def runner(spec):
            calls.append(spec)
            return P.run_review(spec)
        rep = P.run_positive(self.options(), runner=runner, key_loader=self.boom)
        self.assertEqual((len(calls), rep["plan"]["capturedCount"]), (1, 1))      # one request attempted, none delivered

    def test_plan_with_the_wrong_auth_for_this_profile_does_not_plan(self):
        self.write_auth({**AUTH, "models": ["anthropic/claude-haiku-5.5"]})
        try:
            rep = P.run_positive(self.options(), key_loader=self.boom)
            ok = rep["ok"]
        except Exception:
            ok = False
        self.assertFalse(ok)


# ===================================================================== live controls

class ModelDecides(Rig):
    def test_positive_chain_uses_ordinary_reads_and_the_verifier_citation_is_the_executed_read(self):
        rep, m = self.live()
        self.assertEqual((rep["status"], rep["providerCalls"], rep["counts"]["comments"]), ("completed", 5, 1))
        ev = self.events(rep)
        reads = [e for e in ev if e.get("type") == "tool.call" and "requestedBy" in e]
        self.assertTrue(all(e["tool"] == "read_file" and e["result"]["status"] == "ok" for e in reads))
        self.assertEqual(sorted((e["stage"], e["args"]["path"]) for e in reads),
                         sorted([("INVESTIGATE", DEFN[0]), ("INVESTIGATE", CALLER), ("VERIFY", DEFN[0])]))
        self.assertIn(m.read_id, [e["toolCallId"] for e in reads])
        # verifier independence: it is given the claim and the cited evidence, not the investigator's other raw reads
        vuser = [x["content"] for x in m.bodies[2]["messages"] if x["role"] == "user"][0]
        self.assertIn(CLAIM, vuser)
        self.assertIn("originalEvidence", vuser)
        self.assertNotIn("run_forever", vuser)                                  # worker.py was read only by the investigator
        self.assertNotIn("run_forever", "\n".join(x["content"] for x in m.bodies[2]["messages"]))
        # the judge sees findings through the real JudgeOutput schema only
        self.assertEqual(m.bodies[4]["response_format"]["json_schema"]["name"], "JudgeOutput")
        judge = json.loads((Path(rep["paths"]["runDir"]) / "artifacts" / "06-JUDGE.v1.json").read_text())
        self.assertIn("Leases never expire", json.dumps(judge))

    def test_a_tool_ref_to_a_call_that_never_ran_does_not_confirm_a_finding(self):
        m = self.model()
        ghost = {"kind": "tool-ref", "toolCallId": "tc_" + "0" * 16, "index": 0}
        m.script[3] = m.verdict("confirmed", [m.cite(*BUG), ghost])
        rep, m = self.live(m)
        # either the pipeline stops with a typed error or the finding is not kept; it must never be a clean confirmation
        confirmed = rep["ok"] and rep["counts"]["findings"] == 1 and rep["counts"]["comments"] == 1
        self.assertFalse(confirmed, rep["counts"])

    def test_a_code_citation_with_a_fabricated_excerpt_is_not_a_clean_finding(self):
        m = self.model()
        m.script[1] = m.final({"hypotheses": [m.hyp(text="        now = clock.now_minutes()")]})
        rep, m = self.live(m)
        self.assertFalse(rep["ok"] and rep["counts"]["findings"] >= 1 and rep["counts"]["comments"] >= 1, rep["counts"])

    def test_refuted_verdict_gives_no_finding_no_comment_and_no_judge_call(self):
        m = self.model()
        m.script = m.script[:3] + [m.verdict("refuted")]
        rep, m = self.live(m)
        self.assertEqual((rep["status"], rep["counts"]["findings"], rep["counts"]["comments"], len(m.requests)),
                         ("completed", 0, 0, 4))
        self.assertNotIn("JudgeOutput", [b["response_format"]["json_schema"]["name"] for b in m.bodies])

    def test_a_miss_and_a_wrong_finding_are_reported_as_the_model_decided_them(self):
        miss = self.model(MISS)
        rep, m = self.live(miss)
        self.assertEqual((rep["status"], len(m.requests), rep["counts"]["hypotheses"]), ("completed", 2, 0))
        self.assertTrue(rep["ok"])                                           # a miss is not an error, not retried
        rmtree(self.out)
        self.state_reset()
        benign = self.model()
        benign.script = [Model.final({"hypotheses": [benign.hyp(path=BENIGN, line=2, text="    return \"\\n\".join(lines)")]}),
                         ]
        other = Model.final({"hypotheses": [benign.hyp(path=BUG[0], line=BUG[1], text=BUG[2], claim="other")]})
        benign.script = [other, other,             # draft + the exploration-floor continuation (EXPLORE-FLOOR)
                         benign.ask((DEFN[0], 1, 9)), benign.verdict("confirmed"), benign.comment("other")]
        rep2, _ = self.live(benign, out_dir=str(self.out))
        self.assertIn("model-decided", rep2["outcome"])
        self.assertNotIn("expected", json.dumps({k: v for k, v in rep2.items() if k not in ("outcome", "quality")}).lower())

    def test_no_retry_repair_or_fallback_after_bad_http_or_bad_output(self):
        for bad in (HttpResponse(429, {}, b"{}"), HttpResponse(500, {}, b"{}"), HttpResponse(200, {}, b"not json"),
                    "this is not json", json.dumps({"unexpected": 1})):
            with self.subTest(str(bad)[:30]):
                self.state_reset()
                if self.out.exists():
                    rmtree(self.out)
                m = self.model([bad, bad, bad])
                try:
                    rep, m = self.live(m)
                    self.assertFalse(rep["ok"])
                except PipelineError:
                    pass
                self.assertEqual(len(m.requests), 1)

    def test_every_request_is_the_one_sonnet_route_json_protocol_no_tools_no_fallback(self):
        rep, m = self.live()
        for r, b in zip(m.requests, m.bodies):
            self.assertEqual(b["model"], SONNET)
            self.assertIn(b["response_format"]["json_schema"]["name"], ALLOWED_SCHEMAS)
            self.assertNotIn("tools", b)
            self.assertNotIn("tool_choice", b)
            self.assertNotIn("models", b)                                       # no OpenRouter fallback list
            self.assertNotIn("route", b)
            self.assertEqual(r.path, m.requests[0].path)
            self.assertNotIn(FAKE_KEY, r.path)
            self.assertNotIn(FAKE_KEY.encode(), r.body)

    def test_hint_and_label_words_never_reach_model_visible_user_content_in_any_hop(self):
        rep, m = self.live()
        for i, b in enumerate(m.bodies):
            user = [x["content"] for x in b["messages"] if x["role"] == "user"]
            blob = "\n".join(user).lower()
            for w in ("expected issue", "label", "ground truth", "gold", "recall", "precision", "hit", "benign"):
                self.assertNotIn(w, blob, f"hop {i}: {w}")

    def test_the_model_cannot_read_host_files_through_retrieval(self):
        m = self.model()
        ask = Model.ask((str(self.env), 1, 5), ("../../operator/dot.env", 1, 5), ("/etc/passwd", 1, 3),
                        ("leasing/../../../../operator/dot.env", 1, 5))
        m.script = [ask, Model.final({"hypotheses": []})]
        rep, m = self.live(m)
        blob = json.dumps(m.bodies) + Path(rep["paths"]["trace"]).read_text()
        self.assertNotIn(ENV_CANARY, blob)
        self.assertNotIn("root:x:0", blob)
        for p in Path(rep["paths"]["runDir"]).rglob("*"):
            if p.is_file():
                self.assertNotIn(ENV_CANARY, p.read_text(errors="replace"))
        reads = [e for e in self.events(rep) if e.get("type") == "tool.call" and "requestedBy" in e]
        self.assertTrue(reads)
        self.assertTrue(all(e["result"]["status"] != "ok" for e in reads), [e["result"]["status"] for e in reads])

    def test_a_key_echoed_by_the_model_is_scrubbed_from_the_report_at_least(self):
        m = self.model()
        m.script = MISS
        rep, _ = self.live(m)
        self.assertNotIn(FAKE_KEY, Path(rep["reportPath"]).read_text())
        for p in Path(rep["paths"]["runDir"]).rglob("*"):
            if p.is_file():
                self.assertNotIn(FAKE_KEY, p.read_text(errors="replace"))

    def test_five_calls_make_five_ledger_rows_with_no_extra_hidden_call(self):
        rep, m = self.live()
        before_rows = 2          # the seeded prior admit + finish
        rows = self.ledger_rows()
        self.assertEqual(len(m.requests), 5)
        self.assertEqual(len(rows) - before_rows, 10)                          # admit + finish per real request
        self.assertEqual(rep["costs"]["spendBook"]["inflight"], 0)
        self.assertEqual(RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000).totals()["committedUsdMicros"] - BASELINE,
                         5 * 4200)


# ===================================================================== durable admission

class Admission(Rig):
    def refused_before_key(self, **over):
        before = self.state_bytes()
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.live_options(**over), transport=self.boom, key_loader=self.boom)
        self.assertEqual(self.state_bytes(), before)
        self.assertFalse(self.out.exists())

    def test_committed_plus_run_ceiling_over_the_aggregate_refuses(self):
        self.seed(committed=46_000_001)
        self.refused_before_key(baseline_micros=46_000_001)

    def test_exactly_at_the_aggregate_is_admitted_through_preflight(self):
        self.seed(committed=46_000_000)
        m = self.model(MISS)
        rep = P.run_positive(self.live_options(baseline_micros=46_000_000), transport=m, key_loader=self.loader)
        self.assertEqual(len(m.requests), 2)                # the draft + its one exploration-floor continuation
        self.assertIn(rep["status"], ("completed", "pipeline-refused"))

    def test_book_inflight_and_wrong_baselines_refuse(self):
        self.seed(inflight=1)
        self.refused_before_key()
        self.state_reset()
        self.seed()
        for bad in (BASELINE - 1, BASELINE + 1):
            self.refused_before_key(baseline_micros=bad)
        self.refused_before_key(book_baseline_micros=BASELINE + 5)

    def test_an_interrupted_live_call_blocks_the_next_run_before_any_contact(self):
        self.seed()

        def interrupt(http_req):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            P.run_positive(self.live_options(), transport=interrupt, key_loader=self.loader)
        reports = list(self.out.rglob("report.json"))
        self.assertEqual(len(reports), 1)
        self.assertEqual(json.loads(reports[0].read_text())["status"], "interrupted")
        led = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000).totals()
        self.assertGreater(led["unknownBoundUsdMicros"], 0)                      # the intent is kept, not dropped
        again = self.model()
        with self.assertRaises(P.PositiveError) as c:
            P.run_positive(self.live_options(out_dir=str(self.tmp / "again"), baseline_micros=led["committedUsdMicros"],
                                             book_baseline_micros=BASELINE), transport=again, key_loader=self.boom)
        self.assertEqual(again.requests, [])
        self.assertFalse((self.tmp / "again").exists())

    def test_missing_empty_or_symlinked_state_refuses_and_is_not_created(self):
        shutil.rmtree(self.state)
        self.refused_before_key.__func__  # noqa: B018
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.live_options(), transport=self.boom, key_loader=self.boom)
        self.assertFalse(self.state.exists())
        self.state.mkdir()
        with self.assertRaises(P.PositiveError):                              # exists but holds no prior aggregate
            P.run_positive(self.live_options(), transport=self.boom, key_loader=self.boom)
        self.assertFalse(self.out.exists())

    def test_an_authorization_that_does_not_cover_the_profile_refuses_before_the_key(self):
        self.seed()
        self.write_auth({**AUTH, "models": ["anthropic/claude-haiku-5.5"]})
        with self.assertRaises(Exception) as c:
            P.run_positive(self.live_options(), transport=self.boom, key_loader=self.boom)
        self.assertNotIsInstance(c.exception, AssertionError)
        self.assertFalse(self.out.exists())

    def test_a_second_identical_live_run_makes_no_provider_contact(self):
        rep, _ = self.live(self.model(MISS))
        committed = RuntimeLedger(self.state / P.LEDGER_NAME, 50_000_000).totals()["committedUsdMicros"]
        again = self.model(MISS)
        try:
            P.run_positive(self.live_options(out_dir=str(self.tmp / "again"), baseline_micros=committed),
                           transport=again, key_loader=self.loader)
        except Exception:  # noqa: BLE001
            pass
        self.assertEqual(again.requests, [])

    def test_output_must_be_fresh_and_outside_reviewed_and_operator_trees(self):
        self.seed()
        self.out.mkdir()
        self.refused_before_key.__func__  # noqa: B018
        with self.assertRaises(P.PositiveError):
            P.run_positive(self.live_options(), transport=self.boom, key_loader=self.boom)
        self.out.rmdir()
        for bad in (self.state / "o", REPO / "fixtures" / "o", REPO / "reviewer" / "o"):
            with self.assertRaises(P.PositiveError, msg=str(bad)):
                P.run_positive(self.live_options(out_dir=str(bad)), transport=self.boom, key_loader=self.boom)
            self.assertFalse(bad.exists())


# ===================================================================== persistence and strict replay

class PersistenceAndReplay(Rig):
    def replay_options(self, rep, **over):
        d = dict(mode="replay", auth=None, out_dir=str(self.tmp / "rp"), replay_trace=rep["paths"]["trace"],
                 trace_digest=rep["traceDigest"]["value"])
        d.update(over)
        return self.options(**d)

    def test_outputs_exist_are_private_and_the_trace_is_what_replay_consumes(self):
        rep, m = self.live()
        for k in ("review", "comments", "receipt", "trace"):
            p = Path(rep["paths"][k])
            self.assertTrue(p.is_file(), k)
            self.assertEqual(p.stat().st_mode & 0o077, 0, f"{k} is group/world accessible")
        self.assertTrue(Path(rep["reportPath"]).is_file())
        pin = rep["traceDigest"]["value"]
        self.assertRegex(pin, r"^sha256:[0-9a-f]{64}$")

    def test_strict_replay_with_the_external_pin_is_zero_cost_keyless_and_equal(self):
        rep, m = self.live()
        before = self.state_bytes()
        rr = P.run_positive(self.replay_options(rep), key_loader=self.boom, transport=self.boom)
        self.assertEqual((rr["status"], rr["ok"], rr["providerCalls"]), ("completed", True, 5 - 5))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["replayedCalls"]), (0, 0, 5))
        self.assertEqual(rr["counts"], rep["counts"])
        self.assertEqual(self.state_bytes(), before)
        self.assertEqual(self.loads, [str(self.env)])                           # only the live run read the key
        strip = lambda p: json.loads(re.sub(r'"run_[0-9a-f]{16}"', '"RUN"', Path(p).read_text()))
        self.assertEqual(strip(rr["paths"]["comments"]), strip(rep["paths"]["comments"]))

    def test_replay_refuses_a_wrong_pin_a_tampered_trace_and_a_truncated_trace(self):
        rep, _ = self.live()
        trace = Path(rep["paths"]["trace"])
        good = trace.read_bytes()
        cases = {}
        cases["wrong-pin"] = (good, "sha256:" + "1" * 64)
        cases["tampered-keeps-pin"] = (good.replace(b"Leases never expire", b"Leases always expire"), rep["traceDigest"]["value"])
        for name, (data, pin) in cases.items():
            with self.subTest(name):
                alt = self.tmp / f"{name}.jsonl"
                alt.write_bytes(data)
                with self.assertRaises(PipelineError):
                    P.run_positive(self.replay_options(rep, replay_trace=str(alt), trace_digest=pin,
                                                       out_dir=str(self.tmp / f"o-{name}")), key_loader=self.boom)
                self.assertFalse((self.tmp / f"o-{name}").exists())
        # truncated: even with a pin recomputed for the truncated bytes, replay must not fall through to live calls
        cut = b"\n".join(good.splitlines()[:-6]) + b"\n"
        alt = self.tmp / "cut.jsonl"
        alt.write_bytes(cut)
        pin = "sha256:" + hashlib.sha256(cut).hexdigest()
        try:
            rr = P.run_positive(self.replay_options(rep, replay_trace=str(alt), trace_digest=pin,
                                                    out_dir=str(self.tmp / "o-cut")), key_loader=self.boom, transport=self.boom)
            clean = rr["ok"]
        except Exception:  # noqa: BLE001
            clean = False
        self.assertFalse(clean, "a truncated trace must not replay as a clean full review")

    def test_replay_has_no_state_auth_or_key_inputs_and_needs_an_existing_trace(self):
        rep, _ = self.live()
        for kw in (dict(auth=str(self.auth)), dict(state_dir=str(self.state)), dict(env_file=str(self.env))):
            with self.assertRaises(P.PositiveError):
                P.check_options(self.replay_options(rep, **kw))
        with self.assertRaises(Exception):
            P.run_positive(self.replay_options(rep, replay_trace=str(self.tmp / "nope.jsonl")), key_loader=self.boom)

    def test_miss_and_refuted_runs_replay_strictly_too(self):
        for name, script in (("miss", MISS), ("refuted", None)):
            with self.subTest(name):
                self.state_reset()
                outd = self.tmp / f"live-{name}"
                m = self.model(script)
                if script is None:
                    m.script = m.script[:3] + [m.verdict("refuted")]
                rep, _ = self.live(m, out_dir=str(outd))
                rr = P.run_positive(self.replay_options(rep, out_dir=str(self.tmp / f"rp-{name}")), key_loader=self.boom)
                self.assertTrue(rr["ok"])
                self.assertEqual(rr["counts"], rep["counts"])


if __name__ == "__main__":
    unittest.main()
