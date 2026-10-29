"""ORDINARY-PR-01: ordinary current-PR host path. Owned local Git fixtures, REAL importer/loaders/pipeline/adapter and
the REAL shared repository host functions; fake OpenRouter transport and fake key loader. No network, no .env, no
real auth/state, no target scripts, no historical case."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts.canonical import digest
from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.pilot import ordinary as O
from reviewer.pilot import repository as R
from reviewer.pilot.profile import MODEL, OUTPUT_CAPS, RUN_CEILING_USD_MICROS
from reviewer.pipeline import PipelineError
from reviewer.repoimport import capture_import_pins, import_repository, write_import_pins
from reviewer.repoimport.fsio import force_remove
from reviewer.repoimport.remote import local_fixture_remote
from reviewer.runtime import RuntimeLedger, Secret
from reviewer.runtime.openrouter import HttpResponse
from tests.historical_review.test_historical_review import bridge_violations
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET
from tests.pilot.test_repository import AT, BASE_FILES, BASELINE, GITLINK, HEAD_FILES, Model
from tests.repoimport.helpers import git

ROOT = Path(__file__).resolve().parents[2]
CASE = "o--r--7"
OLD = "2026-10-26T08:00:00Z"


def setUpModule():
    """The effective temp root must be writable and outside any unrelated Git ancestry (the store refuses one)."""
    root = Path(os.path.realpath(tempfile.gettempdir()))
    assert os.access(root, os.W_OK), f"temp root {root} is not writable"
    assert not any(os.path.lexists(a / ".git") for a in (root, *root.parents)), \
        f"temp root {root} lies inside a Git work tree: set TMPDIR to a non-Git directory"


class World:
    """What root holds outside the reviewed repository: Git fixture, REAL imports, external pins/baseline, auth, state."""

    def __init__(self, tmp: Path, *, same_tree=False, merge_base=False):
        self.tmp = tmp
        self.src, self.store, self.op = tmp / "gitsrc", tmp / "store", tmp / "operator"
        self.case_dir = tmp / "meta" / CASE
        self.state = self.op / "state"
        for d in (self.src, self.op, self.state, self.case_dir):
            d.mkdir(parents=True)
        git(self.src, "init", "-q", "--initial-branch=main")
        self.sha = {}
        for side, files in (("base", BASE_FILES), ("head", HEAD_FILES)):
            if not (same_tree and side == "head"):
                for p, t in files.items():
                    (self.src / p).parent.mkdir(parents=True, exist_ok=True)
                    (self.src / p).write_text(t)
            git(self.src, "add", "-A", "-f")
            git(self.src, "update-index", "--add", "--cacheinfo", f"160000,{GITLINK},vendor/sub")
            git(self.src, "commit", "-q", "-m", side, "--no-verify", "--allow-empty")
            self.sha[side] = git(self.src, "rev-parse", "HEAD")
        remote = local_fixture_remote(self.src, "o", "r")
        self.imports, self.import_pins = {}, {}
        for side in ("base", "head"):
            imp = import_repository(remote, self.sha[side], self.store)
            self.imports[side] = imp
            self.import_pins[side] = self.op / f"{side}.import-pins.json"
            write_import_pins(self.import_pins[side], capture_import_pins(imp.dir, captured_at=AT))
        self.doc = {"schema": O.PINS_SCHEMA, "caseId": CASE, "repo": "o/r", "prNumber": 7,
                    "baseSha": "cd" * 20 if merge_base else self.sha["base"],
                    "mergeBase": self.sha["base"] if merge_base else None, "textRef": self.sha["base"],
                    "headSha": self.sha["head"], "state": "open", "capturedAt": OLD}
        self.pins = self.op / "pr.pins.json"
        self.baseline = self.op / "baseline.json"
        self.write_pins(self.doc)
        self.auth = self.op / "auth.json"
        self.auth.write_text(json.dumps(AUTH))
        os.chmod(self.auth, 0o600)
        self.env = self.op / "dot.env"
        self.env.write_text("openrouter_key=not-read-in-tests\n")
        self.out = tmp / "out"

    def write_pins(self, doc, *, baseline=True, raw=None):
        if self.pins.exists():
            self.pins.unlink()
        self.pins.write_text(raw if raw is not None else json.dumps(doc))
        if baseline:
            self.baseline.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
                {"case": doc["caseId"], "action": "captured", "pinsDigest": digest(doc)}]}))

    def seed(self, *, committed=BASELINE):
        h = trusted_authorization(self.auth)
        led = RuntimeLedger(self.state / R.LEDGER_NAME, 50_000_000)
        key = "prior|INVESTIGATE|investigator|generalist|0|0"
        led.admit(key, 100_000, model=SONNET)
        led.finish(key, outcome="processed", generationId="gen-prior", routerCostUsdMicros=0,
                   upstreamInferenceCostUsdMicros=committed, isByok=True, tokenPricedUsdMicros=committed,
                   costBasis="router-reported")
        book = SpendBook(h, self.state / R.BOOK_NAME)
        book.reserve("prior", 100_000)
        book.settle("prior", committed)

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def options(self, **over):
        d = dict(mode="plan", case_dir=str(self.case_dir), case_pins=str(self.pins), case_baseline=str(self.baseline),
                 store=str(self.store), base_import_pins=str(self.import_pins["base"]),
                 head_import_pins=str(self.import_pins["head"]), out_dir=str(self.out), auth=str(self.auth))
        d.update(over)
        return R.RepositoryOptions(**d)

    def live_options(self, **over):
        return self.options(**dict(dict(mode="live", state_dir=str(self.state), env_file=str(self.env),
                                        baseline_micros=BASELINE, confirm_live=True), **over))


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

    def model(self, **kw):
        return Model(self.w.imports["head"].snapshot_id, **kw)

    def live(self, model=None, w=None, **over):
        w = w or self.w
        model = model or self.model()
        w.seed()
        return O.run_ordinary(w.live_options(**over), transport=model, key_loader=self.loader), model

    def refused(self, w=None, *, live=False, expect=O.OrdinaryError):
        """The refusal comes before any key, state change or output."""
        w = w or self.w
        if live:
            w.seed()
        before = w.state_bytes()
        opts = w.live_options() if live else w.options()
        with self.assertRaises(expect) as c:
            O.run_ordinary(opts, transport=self.model(), key_loader=self.boom)
        self.assertEqual(w.state_bytes(), before)
        self.assertFalse(w.out.exists())
        return str(c.exception)

    def refused_with(self, **over):
        with self.assertRaises(O.OrdinaryError) as c:
            O.run_ordinary(self.w.options(**over), key_loader=self.boom)
        return str(c.exception)

    def argv(self, *extra):
        w = self.w
        return ["--case-dir", str(w.case_dir), "--pr-pins", str(w.pins), "--pr-baseline", str(w.baseline),
                "--store", str(w.store), "--base-import-pins", str(w.import_pins["base"]),
                "--head-import-pins", str(w.import_pins["head"]), "--out", str(w.out), *extra]


# ======================================================================== pins

class PinTests(Base):
    def test_valid_pins_and_merge_base_form(self):
        self.assertEqual(O.check_pins(self.w.doc)["state"], "open")
        w = World(self.tmp / "mb", merge_base=True)
        self.assertEqual(O.ingest_ordinary(w.options()).pins["textRef"], w.sha["base"])      # imported at the merge base

    def test_each_malformed_pin_is_refused_before_key_state_or_output(self):
        d = self.w.doc
        sha = d["headSha"]
        bad = {"state closed": {**d, "state": "closed"}, "state merged": {**d, "state": "merged"},
               "merged field": {**d, "merged": False}, "mergedAt field": {**d, "mergedAt": OLD},
               "missing capturedAt": {k: v for k, v in d.items() if k != "capturedAt"},
               "schema": {**d, "schema": "historical-bridge-pins@1"}, "prNumber bool": {**d, "prNumber": True},
               "prNumber zero": {**d, "prNumber": 0}, "prNumber str": {**d, "prNumber": "7"},
               "prNumber float": {**d, "prNumber": 7.0}, "caseId vs number": {**d, "prNumber": 8},
               "caseId vs repo": {**d, "caseId": "o--x--7"}, "short sha": {**d, "headSha": sha[:39]},
               "upper sha": {**d, "headSha": sha.upper()}, "textRef != base": {**d, "textRef": sha},
               "textRef != mergeBase": {**d, "mergeBase": sha, "baseSha": "cd" * 20},
               "bad time": {**d, "capturedAt": "2026-10-26 08:00:00"}, "impossible date": {**d, "capturedAt": "2026-13-45T00:00:00Z"},
               "future": {**d, "capturedAt": "2999-01-01T00:00:00Z"}, "bad repo": {**d, "repo": "o/r/x"},
               "lone surrogate": {**d, "repo": "o/r\ud800"}, "not an object": [d]}
        for name, doc in bad.items():
            with self.subTest(name):
                w = World(self.tmp / ("p-" + name.replace(" ", "-").replace("!", "")))
                w.pins.unlink()
                w.pins.write_text(json.dumps(doc, ensure_ascii=True))
                w.baseline.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
                    {"case": CASE, "action": "captured", "pinsDigest": "sha256:" + "0" * 64}]}))
                self.refused(w)
                self.refused(w, live=True)

    def test_raw_file_hazards(self):
        raw = json.dumps(self.w.doc)
        cases = {"duplicate key": raw[:-1] + ', "state": "open"}', "NaN": raw[:-1] + ', "x": NaN}',
                 "not utf-8": b"\xff\xfe", "oversize": " " * (O.PINS_MAX_BYTES + 1) + raw,
                 "deep": "[" * 100_000, "empty": ""}
        for name, text in cases.items():
            with self.subTest(name):
                w = World(self.tmp / ("r-" + name.replace(" ", "-")))
                w.pins.unlink()
                (w.pins.write_bytes if isinstance(text, bytes) else w.pins.write_text)(text)
                self.refused(w)
        with self.subTest("symlink"):
            w = World(self.tmp / "r-link")
            real = w.op / "real.json"
            w.pins.rename(real)
            w.pins.symlink_to(real)
            self.refused(w)
        with self.subTest("missing"):
            w = World(self.tmp / "r-missing")
            w.pins.unlink()
            self.refused(w)

    def test_pins_inside_the_case_dir_or_store_are_refused(self):
        for name, inside in (("case", self.w.case_dir), ("store", self.w.store)):
            with self.subTest(name):
                moved = inside / "pr.pins.json"
                moved.write_bytes(self.w.pins.read_bytes())
                self.assertIn("outside", self.refused_with(case_pins=str(moved)))

    def test_baseline_is_the_only_authority_for_the_pins(self):
        w = self.w
        w.write_pins({**w.doc, "capturedAt": "2026-10-26T09:00:00Z"}, baseline=False)    # altered after the baseline
        self.assertIn("baseline", self.refused(w))
        w.baseline.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": []}))
        self.assertIn("baseline", self.refused(w))
        w.baseline.write_text("{}")
        self.assertIn("baseline", self.refused(w))

    def test_case_dir_name_must_match_the_pins(self):
        other = self.tmp / "meta2" / "o--r--8"
        other.mkdir(parents=True)
        self.assertIn("different case", self.refused_with(case_dir=str(other)))
        link = self.tmp / "meta3"
        link.mkdir()
        (link / CASE).symlink_to(self.w.case_dir)
        self.assertIn("real directory", self.refused_with(case_dir=str(link / CASE)))


# ======================================================================== imports

class ImportTests(Base):
    def test_case_input_is_ordinary_with_import_ids_omitted_pr_text_and_no_partial_layers(self):
        ing = O.ingest_ordinary(self.w.options())
        c = ing.case
        self.assertEqual((c["id"], c["repo"], c["synthetic"], c["pr"]), (CASE, "o/r", False, {"title": "", "body": ""}))
        self.assertEqual((c["base"]["snapshotId"], c["head"]["snapshotId"]),
                         (self.w.imports["base"].snapshot_id, self.w.imports["head"].snapshot_id))
        self.assertEqual(ing.partial, {"base": [], "head": []})
        self.assertEqual(ing.pins, self.w.doc)

    def test_wrong_swapped_missing_or_tampered_imports_are_refused(self):
        w = self.w
        swapped = self.refused_with(base_import_pins=str(w.import_pins["head"]), head_import_pins=str(w.import_pins["base"]))
        self.assertIn("import", swapped)
        w2 = World(self.tmp / "other-sha")
        w2.write_pins({**w2.doc, "headSha": "ab" * 20})
        self.assertIn("head import", self.refused(w2))
        w3 = World(self.tmp / "other-repo")
        w3.write_pins({**w3.doc, "repo": "o/q", "caseId": "o--q--7"})
        w3.case_dir.rename(w3.case_dir.parent / "o--q--7")
        w3.case_dir = w3.case_dir.parent / "o--q--7"
        self.assertIn("import", self.refused(w3))
        w4 = World(self.tmp / "tamper")
        git_entries = w4.imports["head"].dir / "git-entries.json"
        os.chmod(git_entries.parent, 0o755)
        os.chmod(git_entries, 0o644)
        git_entries.write_text("[]")
        self.assertIn("import refused", self.refused(w4))

    def test_same_snapshots_are_not_a_reviewable_change(self):
        w = World(self.tmp / "same", same_tree=True)
        self.assertEqual(w.imports["base"].snapshot_id, w.imports["head"].snapshot_id)
        self.assertIn("same content", self.refused(w))

    def test_an_import_that_claims_a_historical_relation_is_refused(self):
        real = O.open_import

        def claiming(d, pins):
            imp = real(d, pins=pins)
            return dataclasses.replace(imp, record={**imp.record, "relatesTo": {"caseId": "x"}})

        with mock.patch.object(O, "open_import", claiming):
            self.assertIn("historical", self.refused())


# ======================================================================== plan / live / replay through the shared host

class PlanTests(Base):
    def test_plan_captures_the_actual_first_request_with_no_key_network_state_or_output(self):
        before = self.w.state_bytes()
        rep = O.run_ordinary(self.w.options(), key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"], rep["mode"]), ("planned", True, "plan"))
        p = rep["plan"]
        f = p["firstRequest"]
        self.assertEqual((f["schemaName"], f["model"], f["toolsInBody"]), ("InvestigatorTurn", MODEL, False))
        self.assertRegex(f["bodySha256"], r"^[0-9a-f]{64}$")
        self.assertLessEqual(p["worstCaseAdmissionUsdMicros"], RUN_CEILING_USD_MICROS)
        self.assertEqual((p["runCeilingUsdMicros"], p["retries"], p["repairs"]), (4_000_000, 0, 0))
        self.assertEqual((p["providerCalls"], p["networkCalls"], p["keyRead"], p["scratchOnly"]), (0, 0, False, True))
        self.assertEqual(p["outputCaps"], OUTPUT_CAPS)
        self.assertEqual(rep["coverage"]["scope"], "repository-with-omissions")
        self.assertEqual(rep["coverage"]["relatesTo"], {})
        self.assertEqual(rep["coverage"]["originalPartial"], {"base": [], "head": []})
        self.assertIn("not supplied", rep["coverage"]["statement"])
        self.assertFalse(self.w.out.exists())
        self.assertEqual(self.w.state_bytes(), before)
        self.assertNotIn("originPath", rep)

    def test_origin_is_honest(self):
        og = O.run_ordinary(self.w.options(), key_loader=self.boom)["origin"]
        d = self.w.doc
        self.assertEqual((og["schema"], og["state"], og["capturedAt"], og["historicalClaim"]),
                         (O.ORIGIN_SCHEMA, "open", OLD, "none"))
        self.assertEqual((og["baseSha"], og["headSha"], og["textRef"], og["prNumber"]),
                         (d["baseSha"], d["headSha"], d["textRef"], 7))
        self.assertEqual(og["pinsDigest"], digest(d))
        self.assertIn("not a historical, merged or closed", og["kind"])
        self.assertIn("verified by root outside this module", og["verification"])
        blob = json.dumps(og).lower()
        for word in ("mergedat", "closedat", "cutoff"):
            self.assertNotIn(word, blob)

    def test_plan_needs_the_authorization_like_the_shared_host(self):
        with self.assertRaises(R.RepositoryError):
            O.run_ordinary(self.w.options(auth=None), key_loader=self.boom)


class LiveTests(Base):
    def test_live_matches_the_plan_and_writes_the_origin_beside_the_report(self):
        plan = O.run_ordinary(self.w.options(), key_loader=self.boom)
        rep, model = self.live()
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 9))   # SPECIALISTS-01
        self.assertEqual(plan["plan"]["firstRequest"]["bodySha256"], hashlib.sha256(model.requests[0].body).hexdigest())
        self.assertTrue(all(b["model"] == MODEL and "tools" not in b and b["provider"]["allow_fallbacks"] is False
                            for b in model.bodies))
        self.assertTrue(all(b["max_tokens"] <= max(OUTPUT_CAPS.values()) for b in model.bodies))
        self.assertEqual(self.loads, [str(self.w.env)])
        out = self.w.out
        self.assertEqual(json.loads((out / "origin.json").read_text()), rep["origin"])
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(report["casePinsDigest"], digest(self.w.doc))
        self.assertEqual(report["coverage"]["relatesTo"], {})
        self.assertNotIn(FAKE_KEY, (out / "report.json").read_text() + (out / "origin.json").read_text())
        self.assertEqual(rep["originPath"], str(out / "origin.json"))
        self.assertEqual(R.eval_run_id(self.w.options(), self._cfg()), R.eval_run_id(self.w.live_options(), self._cfg()))

    def _cfg(self):
        ing = O.ingest_ordinary(self.w.options())
        prof = R.repository_profile(True)
        return R.config_identity(ing, prof, R.repository_plan(prof), R.repository_policy(True), True)

    def test_live_refusals_come_before_the_key_and_leave_state_untouched(self):
        for name, over in (("no confirm", dict(confirm_live=False)), ("wrong baseline", dict(baseline_micros=BASELINE + 1))):
            with self.subTest(name):
                w = World(self.tmp / ("l-" + name.replace(" ", "-")))
                w.seed()
                before = w.state_bytes()
                with self.assertRaises(R.RepositoryError):
                    O.run_ordinary(w.live_options(**over), transport=self.model(), key_loader=self.boom)
                self.assertEqual(w.state_bytes(), before)
                self.assertFalse(w.out.exists())

    def test_ceiling_is_the_inherited_four_dollars_and_the_aggregate_fifty(self):
        w = World(self.tmp / "full")
        w.seed(committed=47_000_000)
        with self.assertRaises(R.RepositoryError):
            O.run_ordinary(w.live_options(baseline_micros=47_000_000), transport=self.model(), key_loader=self.boom)
        self.assertFalse(w.out.exists())

    def test_a_provider_failure_stops_after_one_attempt_without_retry(self):
        m = self.model(fail_with=HttpResponse(500, {}, b"{}"))
        rep, _ = self.live(model=m)
        self.assertEqual((rep["ok"], len(m.requests), rep["providerCalls"]), (False, 1, 1))
        self.assertTrue((self.w.out / "report.json").is_file() and (self.w.out / "origin.json").is_file())

    def test_a_typed_pipeline_stop_keeps_its_report_and_origin(self):
        def stop(spec):
            raise PipelineError("config", "stopped by the engine")

        self.w.seed()
        rep = O.run_ordinary(self.w.live_options(), transport=self.model(), key_loader=self.loader, runner=stop)
        self.assertEqual((rep["status"], rep["ok"]), ("pipeline-refused", False))
        self.assertTrue((self.w.out / "origin.json").is_file())

    def test_fresh_output_only(self):
        self.w.out.mkdir()
        self.w.seed()
        with self.assertRaises(R.RepositoryError):
            O.run_ordinary(self.w.live_options(), transport=self.model(), key_loader=self.boom)


class ReplayTests(Base):
    def test_strict_replay_uses_no_key_auth_book_or_network(self):
        rep, _ = self.live()
        before = self.w.state_bytes()
        out2 = self.tmp / "replay-out"
        o = self.w.options(mode="replay", auth=None, out_dir=str(out2), replay_trace=rep["paths"]["trace"],
                           trace_digest=rep["traceDigest"]["value"])
        rr = O.run_ordinary(o, key_loader=self.boom)
        self.assertEqual((rr["status"], rr["ok"], rr["providerCalls"]), ("completed", True, 0))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["consumedZeroLive"]),
                         (0, 0, True))
        self.assertEqual(self.w.state_bytes(), before)
        self.assertEqual(self.loads, [str(self.w.env)])
        self.assertTrue((out2 / "origin.json").is_file())

    def test_different_configuration_or_wrong_digest_is_refused(self):
        rep, _ = self.live()
        o = self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "r3"), replay_trace=rep["paths"]["trace"],
                           trace_digest=rep["traceDigest"]["value"], retrieval=False)
        with self.assertRaises(PipelineError):
            O.run_ordinary(o, key_loader=self.boom)
        self.assertFalse((self.tmp / "r3").exists())
        code, _, err = self.run_main(["--mode", "replay", *self.argv_out(self.tmp / "r4"),
                                      "--replay-trace", rep["paths"]["trace"], "--trace-digest", "sha256:" + "0" * 64])
        self.assertEqual(code, 2)
        self.assertIn("PipelineError", err)

    def test_replay_identity_differs_from_plan_and_live(self):
        o_plan, o_live = self.w.options(), self.w.live_options()
        cfg = LiveTests._cfg(self)
        o_rep = self.w.options(mode="replay", auth=None, replay_trace="t", trace_digest="sha256:" + "0" * 64)
        self.assertEqual(R.eval_run_id(o_plan, cfg), R.eval_run_id(o_live, cfg))
        self.assertNotEqual(R.eval_run_id(o_rep, cfg), R.eval_run_id(o_plan, cfg))

    def argv_out(self, out):
        a = self.argv()
        a[a.index("--out") + 1] = str(out)
        return a

    def run_main(self, argv, **kw):
        out, err = io.StringIO(), io.StringIO()
        return O.main(argv, out=out, err=err, key_loader=self.boom, **kw), out.getvalue(), err.getvalue()


# ======================================================================== CLI, boundary, portability

class CliTests(Base):
    def run_main(self, argv, **kw):
        out, err = io.StringIO(), io.StringIO()
        kw.setdefault("key_loader", self.boom)
        return O.main(argv, out=out, err=err, **kw), out.getvalue(), err.getvalue()

    def test_plan_json_and_text_exit_0_with_origin(self):
        code, out, err = self.run_main(self.argv("--auth", str(self.w.auth), "--json"))
        self.assertEqual((code, err), (0, ""))
        doc = json.loads(out)
        self.assertEqual((doc["status"], doc["origin"]["historicalClaim"]), ("planned", "none"))
        code, out, _ = self.run_main(self.argv("--auth", str(self.w.auth)))
        self.assertEqual(code, 0)
        self.assertIn("ordinary current-PR snapshot o/r#7 state=open", out)
        self.assertIn("mode: plan", out)

    def test_refusals_exit_2_without_secrets_and_unsupported_args_exit_2(self):
        code, _, err = self.run_main(self.argv("--mode", "live", "--auth", str(self.w.auth)))
        self.assertEqual(code, 2)
        self.assertNotIn(FAKE_KEY, err)
        for extra in (["--model", "x"], ["--max-usd", "9"], ["--case-pins", "x"], ["--merged"]):
            with self.subTest(extra), self.assertRaises(SystemExit) as c, mock.patch("sys.stderr", io.StringIO()):
                self.run_main(self.argv(*extra))
            self.assertEqual(c.exception.code, 2)
        self.assertFalse(self.w.out.exists())

    def test_no_flag_widens_models_caps_or_budget_and_help_says_ordinary(self):
        flags = {a.option_strings[0] for a in O._parser()._actions if a.option_strings}
        for bad in ("--model", "--max-usd", "--ceiling", "--allow-model", "--retries", "--fallback", "--wall-clock-sec",
                    "--state", "--merged", "--title", "--body"):
            self.assertNotIn(bad, flags)
        shared = {a.option_strings[0] for a in R._parser()._actions if a.option_strings}
        self.assertEqual(flags, (shared - {"--case-pins", "--case-baseline"}) | {"--pr-pins", "--pr-baseline"})
        self.assertIn("CURRENT", O._parser().description)


class BoundaryTests(unittest.TestCase):
    def test_no_historical_bridge_import_and_no_private_paths_or_secrets(self):
        src = (ROOT / "reviewer/pilot/ordinary.py").read_text()
        self.assertEqual(bridge_violations({"reviewer/pilot/ordinary.py": src}), [])
        for private in ("/home/", "/tmp/", "openrouter_key=", "importlib", "urllib", "subprocess", "socket"):
            self.assertNotIn(private, src)

    def test_the_boundary_gauge_still_lists_only_the_original_sites(self):
        from tests.historical_review.test_historical_review import HOST_BRIDGE_IMPORTS
        self.assertNotIn("reviewer/pilot/ordinary.py", HOST_BRIDGE_IMPORTS)


if __name__ == "__main__":
    unittest.main()
