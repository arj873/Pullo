"""ORDINARY-PR-02-review: independent gate of the ordinary current-PR adapter (ORDINARY-PR-01).

Owned temporary Git fixture with a REAL advanced-base history (merge base != base tip), REAL importer, import pins,
loaders, shared repository host functions and pipeline; an invented fake OpenRouter transport and fake key. No network,
.env, real auth/state, target code, private orchestration or project Git history is read. Mechanics only: nothing here
says the reviewer finds real defects."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import reviewer
from reviewer.contracts.canonical import digest, hypothesis_id
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pilot import ordinary as O
from reviewer.pilot import repository as R
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.pipeline import PipelineError
from reviewer.repoimport import capture_import_pins, import_repository, write_import_pins
from reviewer.repoimport.fsio import force_remove
from reviewer.repoimport.remote import local_fixture_remote
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.pilot.helpers import AUTH, SONNET
from tests.repoimport.helpers import git

ROOT = Path(__file__).resolve().parents[2]
CASE = "acme--widget--42"
CAPTURED = "2026-10-27T04:00:00Z"
AT = "2026-10-27T04:01:00Z"
KEY = "sk-or-v1-" + "0rd1" * 12
COMMITTED = 123_000
RATE_BASE = "def per_minute(n):\n    return n * 60\n"
RATE_HEAD = "def per_minute(n):\n    return n / 60\n"
USAGE = {"prompt_tokens": 900, "completion_tokens": 100, "total_tokens": 1000, "cost": 0, "is_byok": True,
         "cost_details": {"upstream_inference_cost": 0.003},
         "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
         "completion_tokens_details": {"reasoning_tokens": 0}}
PER_CALL = 3000


class TempRoot(unittest.TestCase):
    def test_CONTROL_effective_temporary_root_is_writable_and_outside_every_git_work_tree(self):
        real = Path(os.path.realpath(tempfile.gettempdir()))
        self.assertTrue(os.access(real, os.W_OK))
        self.assertEqual([str(a) for a in (real, *real.parents) if os.path.lexists(a / ".git")], [])


class World:
    """main: m0 (merge base) -> m1 (advanced base tip); feature from m0 -> h1 (PR head)."""

    def __init__(self, tmp: Path):
        self.tmp, self.src, self.store, self.op = tmp, tmp / "src", tmp / "store", tmp / "op"
        self.case_dir, self.state = tmp / "meta" / CASE, tmp / "op" / "state"
        for d in (self.src, self.op, self.state, self.case_dir):
            d.mkdir(parents=True)
        (self.src / "lib").mkdir()
        git(self.src, "init", "-q", "--initial-branch=main")
        self.sha = {}
        self.commit("m0", {"lib/rate.py": RATE_BASE, "lib/util.py": "UNIT = 60\n"})
        self.commit("m1", {"docs/notes.md": "advanced base only\n"})
        git(self.src, "checkout", "-q", "-b", "feature", self.sha["m0"])
        if (self.src / "docs/notes.md").exists():
            (self.src / "docs/notes.md").unlink()
        self.commit("h1", {"lib/rate.py": RATE_HEAD})
        self.remote = local_fixture_remote(self.src, "acme", "widget")
        self.imports, self.import_pins = {}, {}
        for name in ("m0", "m1", "h1"):
            imp = import_repository(self.remote, self.sha[name], self.store)
            self.imports[name] = imp
            self.import_pins[name] = self.op / f"{name}.import-pins.json"
            write_import_pins(self.import_pins[name], capture_import_pins(imp.dir, captured_at=AT))
        self.doc = {"schema": O.PINS_SCHEMA, "caseId": CASE, "repo": "acme/widget", "prNumber": 42,
                    "baseSha": self.sha["m1"], "mergeBase": self.sha["m0"], "textRef": self.sha["m0"],
                    "headSha": self.sha["h1"], "state": "open", "capturedAt": CAPTURED}
        self.pins, self.baseline = self.op / "pr.pins.json", self.op / "pr.baseline.json"
        self.write_pins(self.doc)
        self.auth = self.op / "auth.json"
        self.auth.write_text(json.dumps(AUTH))
        os.chmod(self.auth, 0o600)
        self.env = self.op / "env"
        self.env.write_text("openrouter_key=never-read\n")
        self.out = tmp / "out"

    def commit(self, name, files):
        for p, t in files.items():
            (self.src / p).parent.mkdir(parents=True, exist_ok=True)
            (self.src / p).write_text(t)
        git(self.src, "add", "-A")
        git(self.src, "commit", "-q", "-m", name, "--no-verify")
        self.sha[name] = git(self.src, "rev-parse", "HEAD")

    def write_pins(self, doc, *, raw=None, baseline_doc=None):
        self.pins.write_text(raw if raw is not None else json.dumps(doc))
        self.baseline.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
            {"case": (baseline_doc or doc).get("caseId", CASE), "action": "captured",
             "pinsDigest": digest(baseline_doc or doc)}]}))

    def seed(self, committed=COMMITTED):
        h = trusted_authorization(self.auth)
        led = RuntimeLedger(self.state / R.LEDGER_NAME, 50_000_000)
        led.admit("prior|x", 100_000, model=SONNET)
        led.finish("prior|x", outcome="processed", generationId="gen-prior", routerCostUsdMicros=0,
                   upstreamInferenceCostUsdMicros=committed, isByok=True, tokenPricedUsdMicros=committed,
                   costBasis="router-reported")
        book = SpendBook(h, self.state / R.BOOK_NAME)
        book.reserve("prior", 100_000)
        book.settle("prior", committed)

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in sorted(self.state.iterdir())}

    def options(self, **over):
        d = dict(mode="plan", case_dir=str(self.case_dir), case_pins=str(self.pins), case_baseline=str(self.baseline),
                 store=str(self.store), base_import_pins=str(self.import_pins["m0"]),
                 head_import_pins=str(self.import_pins["h1"]), out_dir=str(self.out), auth=str(self.auth))
        d.update(over)
        return R.RepositoryOptions(**d)

    def live(self, committed=COMMITTED, **over):
        return self.options(**{**dict(mode="live", state_dir=str(self.state), env_file=str(self.env),
                                      baseline_micros=committed, confirm_live=True), **over})


class Wire:
    """Fake OpenRouter: investigator, verifier and judge each answer at hop 0."""

    def __init__(self, head_snapshot, *, fail=None, interrupt_at=None):
        self.requests, self.bodies, self.fail, self.interrupt_at = [], [], fail, interrupt_at
        claim = "per_minute divides instead of multiplying"
        cite = {"kind": "code", "path": "lib/rate.py", "lines": [2, 2], "commit": head_snapshot,
                "excerpt": "    return n / 60"}
        h = {"claim": claim, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
             "location": {"path": "lib/rate.py", "line": 2}, "mechanism": "n / 60 replaces n * 60.", "evidence": [cite]}
        self.script = [{"contextRequests": [], "output": {"hypotheses": [h]}},
                       {"contextRequests": [], "output": {"verdict": "confirmed", "reachable": True,
                                                          "impact": "incorrect-result", "evidence": [cite],
                                                          "notes": "line 2 divides"}},
                       {"comments": [{"findingIds": [hypothesis_id("generalist", 0, claim, "lib/rate.py", 2)],
                                      "title": "Rate inverted", "body": "per_minute now divides by 60."}]}]

    def __call__(self, req):
        self.requests.append(req)
        if self.interrupt_at is not None and len(self.requests) - 1 == self.interrupt_at:
            raise KeyboardInterrupt
        if self.fail is not None:
            return self.fail
        self.bodies.append(json.loads(req.body))
        content = self.script[len(self.requests) - 1]
        d = {"id": f"gen-o{len(self.requests)}", "model": SONNET, "provider": "Anthropic",
             "choices": [{"index": 0, "finish_reason": "stop",
                          "message": {"role": "assistant", "content": json.dumps(content)}}], "usage": USAGE}
        return HttpResponse(200, {}, json.dumps(d).encode())


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._rm)
        self.tmp = Path(os.path.realpath(self._t.name))
        self.w = World(self.tmp / "w")
        self.keys = []

    def _rm(self):
        force_remove(Path(self._t.name))
        with contextlib.suppress(FileNotFoundError):
            self._t.cleanup()

    def key(self, path, *, forbidden_roots=()):
        self.keys.append(str(path))
        return Secret(KEY)

    @staticmethod
    def no_key(path, *, forbidden_roots=()):
        raise AssertionError("key loader reached")

    def wire(self, **kw):
        return Wire(self.w.imports["h1"].snapshot_id, **kw)

    def run_live(self, wire=None, committed=COMMITTED, **over):
        self.w.seed(committed)
        wire = wire or self.wire()
        return O.run_ordinary(self.w.live(committed, **over), transport=wire, key_loader=self.key), wire

    def refused_everywhere(self, mutate_world=None, **over):
        """Each mode refuses before key, state or output; no transport call."""
        self.w.seed()
        before = self.w.state_bytes()
        for mode, o in (("plan", self.w.options(**over)), ("live", self.w.live(**over))):
            with self.subTest(mode=mode):
                wire = self.wire()
                with self.assertRaises((R.RepositoryError, PipelineError)):
                    O.run_ordinary(o, transport=wire, key_loader=self.no_key)
                self.assertEqual((wire.requests, self.keys), ([], []))
                self.assertFalse(self.w.out.exists())
                self.assertEqual(self.w.state_bytes(), before)


# ======================================================================== 1. merge-base semantics and honest case

class MergeBase(Base):
    def test_base_side_is_the_merge_base_not_the_advanced_base_tip(self):
        ing = O.ingest_ordinary(self.w.options())
        self.assertEqual(ing.base.record["commitSha"], self.w.sha["m0"])
        self.assertEqual(ing.head.record["commitSha"], self.w.sha["h1"])
        self.assertNotIn("docs/notes.md", {e["path"] for e in ing.base.manifest["entries"]})
        self.assertEqual(ing.case["synthetic"], False)
        self.assertEqual(ing.case["pr"], {"title": "", "body": ""})
        self.assertEqual(ing.partial, {"base": [], "head": []})
        self.assertNotIn("relatesTo", ing.base.record)
        cov = R.coverage_doc(ing)
        self.assertEqual((cov["relatesTo"], cov["base"]["commitSha"]), ({}, self.w.sha["m0"]))
        og = O.origin_doc(ing)
        self.assertEqual((og["baseSha"], og["mergeBase"], og["textRef"]), (self.w.sha["m1"], self.w.sha["m0"],
                                                                           self.w.sha["m0"]))
        self.assertEqual((og["historicalClaim"], og["state"], og["capturedAt"]), ("none", "open", CAPTURED))
        self.assertIn("root", og["verification"])

    def test_text_ref_at_the_base_tip_when_a_merge_base_is_supplied_is_refused(self):
        self.w.write_pins({**self.w.doc, "textRef": self.w.sha["m1"]})
        self.refused_everywhere(base_import_pins=str(self.w.import_pins["m1"]))

    def test_importing_the_base_tip_under_merge_base_pins_is_refused(self):
        self.refused_everywhere(base_import_pins=str(self.w.import_pins["m1"]))

    def test_null_merge_base_means_the_base_sha_is_the_text_ref(self):
        doc = {**self.w.doc, "baseSha": self.w.sha["m1"], "mergeBase": None, "textRef": self.w.sha["m1"]}
        self.w.write_pins(doc)
        ing = O.ingest_ordinary(self.w.options(base_import_pins=str(self.w.import_pins["m1"])))
        self.assertEqual(ing.base.record["commitSha"], self.w.sha["m1"])
        self.w.write_pins({**doc, "textRef": self.w.sha["m0"]})
        self.refused_everywhere()


# ======================================================================== 2. refusals before key/state/output

class Refusals(Base):
    def test_metadata_variants(self):
        d, s = self.w.doc, self.w.sha
        cases = {
            "closed": {**d, "state": "closed"}, "merged": {**d, "state": "merged"},
            "merged field": {**d, "merged": False}, "mergedAt": {**d, "mergedAt": None},
            "repo dotdot": {**d, "repo": "acme/..", "caseId": "acme--..--42"},
            "repo git suffix": {**d, "repo": "acme/widget.git", "caseId": "acme--widget.git--42"},
            "other owner": {**d, "repo": "evil/widget", "caseId": "evil--widget--42"},
            "case id case": {**d, "caseId": "ACME--widget--42"}, "pr number str": {**d, "prNumber": "42"},
            "pr number true": {**d, "prNumber": True}, "pr number 0": {**d, "prNumber": 0},
            "pr number mismatch": {**d, "prNumber": 43},
            "head abbreviated": {**d, "headSha": s["h1"][:12]}, "base upper": {**d, "baseSha": s["m1"].upper()},
            "time offset": {**d, "capturedAt": "2026-10-27T04:00:00+00:00"},
            "time fraction": {**d, "capturedAt": "2026-10-27T04:00:00.5Z"},
            "time impossible": {**d, "capturedAt": "2026-02-30T04:00:00Z"},
            "time future": {**d, "capturedAt": "2999-01-01T00:00:00Z"},
            "schema": {**d, "schema": "historical-bridge-pins@1"}, "missing key": {k: v for k, v in d.items()
                                                                                 if k != "mergeBase"},
        }
        for name, doc in cases.items():
            with self.subTest(name):
                self.w.write_pins(doc)
                over = {}
                cid = doc.get("caseId")
                if cid != CASE and isinstance(cid, str) and R._CASE_RX.fullmatch(cid):   # reach the repo checks
                    (self.w.tmp / "meta" / cid).mkdir(exist_ok=True)
                    over["case_dir"] = str(self.w.tmp / "meta" / cid)
                self.refused_everywhere(**over)

    def test_raw_file_and_baseline_hazards(self):
        good = json.dumps(self.w.doc)
        for name, raw in (("bom", "﻿" + good), ("trailing data", good + "{}"), ("dup", good[:-1] + ', "state": "open"}'),
                          ("nan", good.replace('"prNumber": 42', '"prNumber": NaN'))):
            with self.subTest(name):
                self.w.write_pins(self.w.doc, raw=raw)
                self.refused_everywhere()
        self.w.write_pins(self.w.doc, baseline_doc={**self.w.doc, "capturedAt": "2026-10-27T03:59:59Z"})
        self.refused_everywhere()
        # a reformatted but equal pins file is accepted: the baseline binds the parsed document
        self.w.write_pins(self.w.doc, raw=json.dumps(self.w.doc, indent=3, sort_keys=True))
        self.assertEqual(O.ingest_ordinary(self.w.options()).pins, self.w.doc)

    def test_swapped_foreign_and_tampered_imports(self):
        self.refused_everywhere(base_import_pins=str(self.w.import_pins["h1"]),
                                head_import_pins=str(self.w.import_pins["m0"]))
        self.refused_everywhere(head_import_pins=str(self.w.import_pins["m0"]))
        rate = Path(self.w.imports["h1"].root) / "lib/rate.py"
        os.chmod(rate, 0o644)
        rate.write_text(RATE_HEAD.replace("60", "61"))
        self.refused_everywhere()

    def test_option_refusals_come_before_any_file_is_read(self):
        missing = str(self.tmp / "missing.json")
        for over, word in ((dict(mode="live", confirm_live=False, state_dir="s", env_file="e", baseline_micros=1),
                            "confirm"), (dict(mode="plan", auth=None), "auth"),
                           (dict(mode="replay", auth=None, replay_trace="t", trace_digest="sha256:x"), "trace-digest"),
                           (dict(mode="plan", state_dir="s"), "live-only"), (dict(mode="plan", repeat=-1), "repeat")):
            with self.subTest(word):
                o = self.w.options(case_pins=missing, case_baseline=missing, **over)
                with self.assertRaises(R.RepositoryError) as c:
                    O.run_ordinary(o, transport=self.wire(), key_loader=self.no_key)
                self.assertIn(word, str(c.exception))
        err = io.StringIO()
        for argv in (["--case-pins", "x"], ["--max-usd", "9"], ["--model", "x"], ["--merged"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as c, contextlib.redirect_stderr(err):
                O.main(argv + ["--case-dir", "d", "--pr-pins", "p", "--pr-baseline", "b", "--store", "s",
                               "--base-import-pins", "bp", "--head-import-pins", "hp", "--out", "o"], key_loader=self.no_key)
            self.assertEqual(c.exception.code, 2)


# ======================================================================== 3. composed host: plan, live, failure paths, replay

class Composed(Base):
    def test_plan_captures_the_first_wire_without_key_network_state_or_output(self):
        self.w.seed()
        before = self.w.state_bytes()
        rep = O.run_ordinary(self.w.options(), transport=self.no_key, key_loader=self.no_key)
        p = rep["plan"]
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True))
        self.assertEqual((p["keyRead"], p["networkCalls"], p["providerCalls"], p["retries"], p["repairs"]),
                         (False, 0, 0, 0, 0))
        self.assertGreaterEqual(p["capturedCount"], 1)
        self.assertFalse(p["firstRequest"]["toolsInBody"])
        self.assertEqual(p["runCeilingUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual(RUN_CEILING_USD_MICROS, 4_000_000)
        self.assertFalse(self.w.out.exists())
        self.assertEqual(self.w.state_bytes(), before)
        self.assertNotIn("originPath", rep)
        self.assertEqual(rep["origin"]["pinsDigest"], rep["casePinsDigest"])

    def test_live_uses_the_plan_first_wire_caps_no_fallback_and_binds_the_sidecar(self):
        plan = O.run_ordinary(self.w.options(), key_loader=self.no_key)
        rep, wire = self.run_live()
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 3))
        self.assertEqual(plan["plan"]["firstRequest"]["bodySha256"],
                         __import__("hashlib").sha256(wire.requests[0].body).hexdigest())
        models = {r: v["model"] for r, v in rep["reviewModels"]["roles"].items()}
        for b, role in zip(wire.bodies, ("investigator", "verifier", "judge")):
            self.assertEqual(b["model"], models[role])
            self.assertNotIn("tools", b)
            self.assertIs(b["provider"]["allow_fallbacks"], False)
        self.assertEqual(self.keys, [str(self.w.env)])
        rt = rep["costs"]["runtime"]
        self.assertEqual(rt["ledgerCalls"]["thisCase"], 3)
        self.assertEqual(rt["cumulative"]["accountable"]["usdMicros"], COMMITTED + 3 * PER_CALL)
        out = Path(self.w.out)
        on_disk = json.loads((out / "report.json").read_text())
        origin = json.loads((out / "origin.json").read_text())
        self.assertEqual(rep["originPath"], str(out / "origin.json"))
        self.assertEqual(origin, rep["origin"])
        self.assertEqual(on_disk["casePinsDigest"], origin["pinsDigest"])
        self.assertEqual(origin["pinsDigest"], digest(self.w.doc))
        blob = "\n".join(p.read_text(errors="ignore") for p in out.rglob("*") if p.is_file())
        self.assertNotIn(KEY, blob)
        for claim in ('"historicalOriginClaimed": true', '"state": "merged"', '"synthetic": true', '"mergedAt"'):
            self.assertNotIn(claim, blob)

    def test_aggregate_and_run_ceilings_refuse_before_the_key(self):
        self.w.seed(47_000_000)
        before = self.w.state_bytes()
        with self.assertRaises(R.RepositoryError):
            O.run_ordinary(self.w.live(47_000_000), transport=self.wire(), key_loader=self.no_key)
        self.assertEqual((self.w.state_bytes(), self.w.out.exists()), (before, False))

    def test_provider_failure_is_one_attempt_with_no_retry_or_fallback(self):
        rep, wire = self.run_live(self.wire(fail=HttpResponse(500, {}, b'{"error":"x"}')))
        self.assertEqual(len(wire.requests), 1)
        self.assertFalse(rep["ok"])
        self.assertTrue((self.w.out / "origin.json").is_file())

    def test_typed_stop_report_carries_the_origin_sidecar(self):
        self.w.seed()

        def stop(spec):
            raise PipelineError("invalid-input", "scripted stop")
        rep = O.run_ordinary(self.w.live(), transport=self.wire(), key_loader=self.key, runner=stop)
        self.assertEqual(rep["status"], "pipeline-refused")
        origin = json.loads((self.w.out / "origin.json").read_text())
        self.assertEqual(origin["pinsDigest"], json.loads((self.w.out / "report.json").read_text())["casePinsDigest"])

    def test_interrupted_run_keeps_the_bound_report_but_has_no_origin_sidecar(self):
        """Disclosed limit: origin.json is written only after the shared host returns."""
        self.w.seed()
        with self.assertRaises(KeyboardInterrupt):
            O.run_ordinary(self.w.live(), transport=self.wire(interrupt_at=1), key_loader=self.key)
        rep = json.loads((self.w.out / "report.json").read_text())
        self.assertEqual((rep["status"], rep["casePinsDigest"]), ("interrupted", digest(self.w.doc)))
        self.assertFalse((self.w.out / "origin.json").exists())

    def test_strict_replay_is_keyless_stateless_and_has_its_own_identity(self):
        rep, _ = self.run_live()
        before = self.w.state_bytes()
        trace, pin = rep["paths"]["trace"], rep["traceDigest"]["value"]
        out2 = self.tmp / "replay"
        rr = O.run_ordinary(self.w.options(mode="replay", auth=None, out_dir=str(out2), replay_trace=trace,
                                           trace_digest=pin), key_loader=self.no_key)
        self.assertEqual((rr["status"], rr["ok"], rr["providerCalls"]), ("completed", True, 0))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["keyRead"],
                          rr["replay"]["networkCalls"]), (0, 0, False, 0))
        self.assertNotEqual(rr["runId"], rep["runId"])
        self.assertEqual(self.w.state_bytes(), before)
        self.assertEqual(json.loads((out2 / "origin.json").read_text())["pinsDigest"], digest(self.w.doc))
        # re-pinned PR metadata (new capture) is a different identity: the old trace does not replay under it
        self.w.write_pins({**self.w.doc, "capturedAt": "2026-10-27T04:30:00Z"})
        out3 = self.tmp / "replay-repinned"
        with self.assertRaises(PipelineError):
            O.run_ordinary(self.w.options(mode="replay", auth=None, out_dir=str(out3), replay_trace=trace,
                                          trace_digest=pin), key_loader=self.no_key)
        self.assertFalse(out3.exists())


# ======================================================================== 4. source boundary

class Boundary(unittest.TestCase):
    SRC = ROOT / "reviewer/pilot/ordinary.py"

    def test_imports_are_stdlib_or_own_package_with_no_dynamic_loading_or_network(self):
        tree = ast.parse(self.SRC.read_text())
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name for a in n.names}
            elif isinstance(n, ast.ImportFrom):
                mods.add(("." * n.level) + (n.module or ""))
        std = {"__future__", "argparse", "copy", "datetime", "json", "os", "re", "sys", "pathlib"}
        self.assertEqual({m for m in mods if m.split(".")[0] not in std and not m.startswith(("reviewer.", "."))}, set())
        self.assertFalse({m for m in mods if "historical" in m})
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
                {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse(names & {"path_hooks", "meta_path", "__import__", "import_module", "exec", "eval", "system",
                                  "popen", "urlopen", "socket", "run_path", "chdir"})
        self.assertNotIn("sys.path", self.SRC.read_text())

    def test_the_running_package_is_the_runtime_not_an_imported_target(self):
        self.assertEqual(Path(reviewer.__file__).resolve().parent, ROOT / "reviewer")
        self.assertEqual(Path(O.__file__).resolve(), self.SRC)


if __name__ == "__main__":
    unittest.main()
