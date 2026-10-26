"""Independent S1-10-review gate for the repository-backed pilot host path (reviewer/pilot/repository.py).

Reviewer-owned, offline, stdlib only. Own local Git fixture (real binary, oversize and submodule omissions, an added and a
removed file, optional 4476-file scale) imported by the REAL importer, REAL case/import pins, REAL run_review/gateway/book/ledger/
OpenRouterProvider with a fake HTTP wire and a fake key loader. No network, no real .env/auth/state, no model call, no target script.
The author's `Model` (a fake OpenRouter that answers the happy path) is the only reuse from tests/pilot.

Conventions as the other *_review suites: CONTROL = accepted behaviour; LIMIT = documented limit that must change when the seam does;
NEW *_symptom_* pins today's wrong behaviour, NEW *_DEFECT_* is expectedFailure and states the DESIRED behaviour.
Run: nice -n 19 python3 -W error::ResourceWarning -m unittest tests.pilot_review.test_repository_gate
"""
from __future__ import annotations

import glob
import hashlib
import io
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts.canonical import digest  # noqa: E402
from reviewer.gateway import SpendBook, load_trace, trusted_authorization  # noqa: E402
from reviewer.historical import capture_bridge_pins, write_pins  # noqa: E402
from reviewer.pilot import repository as R  # noqa: E402
from reviewer.pilot.profile import MODEL, RUN_CEILING_USD_MICROS  # noqa: E402
from reviewer.repoimport import ImportPolicy, RelatesSpec, capture_import_pins, import_repository, write_import_pins  # noqa: E402
from reviewer.repoimport.fsio import force_remove  # noqa: E402
from reviewer.repoimport.remote import local_fixture_remote  # noqa: E402
from reviewer.runtime import RuntimeLedger, Secret  # noqa: E402
from reviewer.runtime.openrouter import HttpResponse, TransportError  # noqa: E402
from tests.pilot.helpers import AUTH, FAKE_KEY, SONNET  # noqa: E402
from tests.pilot.test_repository import USAGE, Model  # noqa: E402  (author's fake OpenRouter, happy path only)
from tests.repoimport.helpers import git  # noqa: E402
from tests.tools.helpers import make_case  # noqa: E402

AT = "2026-10-25T20:00:00Z"
CASE = "o--r--1"
BASELINE = 80_020                   # root's real aggregate at dispatch; any non-zero value would do
BIG_NOTE = "Excerpts omitted: request context budget"
A = lambda k: "".join(f"def f{i}(x):\n    return x {k} {i}\n\n" for i in range(6))      # noqa: E731
UTIL = "def close_stream():\n    return None\n\ndef is_open():\n    return True\n"
BASE = {"src/a.py": A("+"), "src/b.py": "def g(x):\n    return x\n", "src/old.py": "def gone():\n    return 1\n"}
HEAD = {"src/a.py": A("-"), "src/b.py": "def g(x):\n    return x * 2\n", "src/c.py": "def fresh():\n    return 2\n"}
BINARY, OVERSIZE = b"\x00\x01\x02binary-logo", "x" * 3000


class Gate:
    """Own fixture: Git source repo -> case dir (changed text files only) -> REAL imports with relatesTo + external pins -> auth + state."""

    def __init__(self, tmp: Path, *, gitlinks=1, omissions=True, base=None, head=None, n_extra=0, pr_text=None,
                 distinct_base_sha=False, relates=True, max_file_bytes=2000):
        self.tmp, self.src, self.corpus = tmp, tmp / "gitsrc", tmp / "corpus"
        self.op, self.store = tmp / "operator", tmp / "store"
        self.state = self.op / "state"
        for d in (self.src, self.corpus, self.op, self.state):
            d.mkdir(parents=True)
        base, head = dict(base or BASE), dict(head or HEAD)
        common = {"src/util.py": UTIL}
        if omissions:
            common.update({"assets/logo.bin": BINARY, "data/big.txt": OVERSIZE})
        common.update({f"gen/d{i // 100:02d}/f{i:05d}.py": f"x = {i}\n" for i in range(n_extra)})
        git(self.src, "init", "-q", "--initial-branch=main")
        shas = []
        for files in ({}, base, head):                                   # commit 0 = empty history anchor for `distinct_base_sha`
            for p in self.src.iterdir():
                if p.name != ".git":
                    shutil.rmtree(p) if p.is_dir() else p.unlink()
            for p, data in ({**common, **files} if files else {}).items():
                f = self.src / p
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data.encode() if isinstance(data, str) else data)
            git(self.src, "add", "-A", "-f")
            if files:
                for i in range(gitlinks):
                    git(self.src, "update-index", "--add", "--cacheinfo", f"160000,{'ab' * 20},vendor/sub{i:02d}")
            git(self.src, "commit", "-q", "-m", "c", "--allow-empty", "--no-verify")
            shas.append(git(self.src, "rev-parse", "HEAD"))
        self.anchor, self.sha = shas[0], {"base": shas[1], "head": shas[2]}
        self.case_dir = make_case(self.corpus, base, head, name=CASE)
        doc = json.loads((self.case_dir / "input/case.json").read_text())
        doc["base"] = ({"sha": self.anchor, "mergeBase": self.sha["base"], "textRef": self.sha["base"]} if distinct_base_sha else
                       {"sha": self.sha["base"], "mergeBase": None, "textRef": self.sha["base"]})
        doc["head"] = {"sha": self.sha["head"]}
        (self.case_dir / "input/case.json").write_text(json.dumps(doc))
        self.pins = capture_bridge_pins(self.case_dir, captured_at=AT, **({"pr_text": pr_text} if pr_text else {}))
        self.case_pins, self.baseline = self.op / f"{CASE}.pins.json", self.op / "baseline.json"
        write_pins(self.case_pins, self.pins)
        self.baseline.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": [
            {"case": CASE, "action": "captured", "pinsDigest": digest(self.pins)}]}))
        remote, self.imports, self.import_pins = local_fixture_remote(self.src, "o", "r"), {}, {}
        for side in ("base", "head"):
            imp = import_repository(remote, self.sha[side], self.store, policy=ImportPolicy(max_file_bytes=max_file_bytes),
                                    relates=RelatesSpec(self.case_dir, side) if relates else None)
            self.imports[side] = imp
            self.import_pins[side] = self.op / f"{side}.import-pins.json"
            write_import_pins(self.import_pins[side], capture_import_pins(imp.dir, captured_at=AT))
        self.auth, self.env, self.out = self.op / "auth.json", self.op / "dot.env", tmp / "out"
        self.auth.write_text(json.dumps(AUTH))
        os.chmod(self.auth, 0o600)
        self.env.write_text("openrouter_key=not-read-in-tests\n")

    def seed(self, *, committed=BASELINE, book_committed=None, inflight=0, auth=None):
        h = trusted_authorization(auth or self.auth)
        led = RuntimeLedger(self.state / R.LEDGER_NAME, 50_000_000)
        led.admit("prior|INVESTIGATE|investigator|generalist|0|0", 100_000, model=SONNET)
        led.finish("prior|INVESTIGATE|investigator|generalist|0|0", outcome="processed", generationId="gen-prior",
                   routerCostUsdMicros=0, upstreamInferenceCostUsdMicros=committed, isByok=True,
                   tokenPricedUsdMicros=committed, costBasis="router-reported")
        book = SpendBook(h, self.state / R.BOOK_NAME)
        book.reserve("prior", 100_000)
        book.settle("prior", committed if book_committed is None else book_committed)
        if inflight:
            book.reserve("open", inflight)

    def options(self, **over):
        d = dict(mode="plan", case_dir=str(self.case_dir), case_pins=str(self.case_pins), case_baseline=str(self.baseline),
                 store=str(self.store), base_import_pins=str(self.import_pins["base"]),
                 head_import_pins=str(self.import_pins["head"]), out_dir=str(self.out), auth=str(self.auth))
        d.update(over)
        return R.RepositoryOptions(**d)

    def live_options(self, **over):
        return self.options(**{**dict(mode="live", state_dir=str(self.state), env_file=str(self.env),
                                      baseline_micros=BASELINE, confirm_live=True), **over})

    def state_bytes(self):
        return {p.name: p.read_bytes() for p in self.state.iterdir()}

    def ledger_rows(self):
        return [json.loads(x) for x in (self.state / R.LEDGER_NAME).read_text().splitlines() if x.strip()]

    def book_totals(self):
        return SpendBook(trusted_authorization(self.auth), self.state / R.BOOK_NAME).totals()


class Wire:
    """Fake OpenRouter with per-request steps: a content dict (answered 200), an HttpResponse, or an exception to raise."""

    def __init__(self, *steps):
        self.steps, self.requests, self.bodies = list(steps), [], []

    def __call__(self, req):
        self.requests.append(req)
        self.bodies.append(json.loads(req.body))
        step = self.steps[min(len(self.requests), len(self.steps)) - 1]
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, HttpResponse):
            return step
        d = {"id": f"gen-{len(self.requests)}", "model": SONNET, "provider": "Anthropic", "usage": USAGE,
             "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": step if isinstance(step, str) else json.dumps(step)}}]}
        return HttpResponse(200, {}, json.dumps(d).encode())


_ACTIVE: list = []


def _audit_hook(event, args):
    if _ACTIVE and event in ("open", "os.listdir", "os.scandir") and args and isinstance(args[0], (str, bytes, os.PathLike)):
        raw = os.fsdecode(args[0])
        for a in _ACTIVE:
            a.opened.append(os.path.realpath(raw) if os.path.isabs(raw) else raw)


sys.addaudithook(_audit_hook)


class Audit:
    """Records every path opened or enumerated (builtins.open, os.open incl. dir_fd-relative names, listdir, scandir) while active, through
    the interpreter audit hook, so no function is replaced (the snapshot code checks `os.open in os.supports_dir_fd`)."""

    def __init__(self):
        self.opened = []

    def __enter__(self):
        _ACTIVE.append(self)
        return self

    def __exit__(self, *exc):
        _ACTIVE.remove(self)

    def under(self, root) -> list:
        r = os.path.realpath(root)
        return [p for p in self.opened if p == r or p.startswith(r + os.sep)]

    def gold_named(self) -> list:
        """Any recorded path (absolute or dir_fd-relative) with a `labels` or `source` component."""
        return [p for p in self.opened if {"labels", "source"} & set(Path(p).parts)]


def no_network():
    def boom(*a, **k):
        raise AssertionError("network attempted")
    return [mock.patch.object(socket.socket, "connect", boom), mock.patch.object(socket, "create_connection", boom),
            mock.patch.object(socket, "getaddrinfo", boom)]


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._rm)
        self.tmp = Path(os.path.realpath(self._t.name))
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

    def world(self, name="w", **kw) -> Gate:
        return Gate(self.tmp / name, **kw)

    def model(self, w: Gate, **kw) -> Model:
        return Model(w.imports["head"].snapshot_id, **kw)

    def live(self, w: Gate, transport, **over):
        w.seed()
        return R.run_repository(w.live_options(**over), transport=transport, key_loader=self.loader)

    def plan_bodies(self, w: Gate, **over):
        seen = []

        class Cap(R.CapturingTransport):
            def __call__(self, req):
                if req.method == "POST":
                    seen.append(bytes(req.body))
                return super().__call__(req)
        with mock.patch.object(R, "CapturingTransport", Cap):
            rep = R.run_repository(w.options(**over), key_loader=self.boom)
        return rep, seen


# ======================================================================== 1. inputs: pins before trust, no gold, distinct ids

class Inputs(Base):
    def test_CONTROL_labels_source_env_and_state_are_never_opened_by_plan_and_live_opens_state_but_not_env_or_gold(self):
        w = self.world()
        gold = [w.case_dir / "labels", w.case_dir / "source"]
        with Audit() as plan_audit:
            rep = R.run_repository(w.options(), key_loader=self.boom)
        self.assertEqual(rep["status"], "planned")
        for g in (*gold, w.env, w.state):
            self.assertEqual(plan_audit.under(g), [], f"plan opened {g}")
        self.assertEqual(plan_audit.gold_named(), [])
        with Audit() as live_audit:
            self.live(w, self.model(w))
        for g in (*gold, w.env):
            self.assertEqual(live_audit.under(g), [], f"live opened {g} (the key loader is the only env reader and it is faked here)")
        self.assertEqual(live_audit.gold_named(), [])
        self.assertTrue(live_audit.under(w.state / R.LEDGER_NAME), "control: the audit does see state opens")

    def test_CONTROL_the_first_request_carries_import_ids_and_omission_counts_but_no_gold_pr_text_partial_ids_or_host_paths(self):
        w = self.world(pr_text={"title": "PR_TITLE_CANARY", "body": "PR_BODY_CANARY"})
        rep, seen = self.plan_bodies(w)
        self.assertEqual((rep["status"], len(seen) >= 1), ("planned", True))
        text = seen[0].decode()
        msgs = json.dumps(json.loads(seen[0])["messages"])
        for canary in ("OUTCOME_SECRET", "LABELS_SECRET", "LABELS_DEEP", "PR_TITLE_CANARY", "PR_BODY_CANARY", str(self.tmp), os.path.expanduser("~")):
            self.assertNotIn(canary, text, canary)
        ing = R.ingest(w.options())
        self.assertIn(ing.head.snapshot_id, msgs)                                  # the evidence `commit` is the IMPORT content id
        partial = [l["snapshotId"] for s in ing.partial.values() for l in s]
        self.assertTrue(partial)
        for pid in partial:
            self.assertNotIn(pid, text)
        self.assertIn("WITH OMISSIONS", msgs)
        for kind in ("binary=1", "oversize=1", f"submodule={1}"):                  # per-kind counts reach the model (S1-05 gate item)
            self.assertIn(kind, msgs, kind)
        self.assertEqual(rep["coverage"]["base"]["omissionCounts"], {"binary": 1, "oversize": 1, "submodule": 1})
        self.assertEqual(rep["coverage"]["head"]["omissionCounts"], {"binary": 1, "oversize": 1, "submodule": 1})
        self.assertFalse(rep["coverage"]["fullRepositoryCoverage"])

    def test_CONTROL_spec_binds_import_roots_records_and_ids_never_the_partial_union(self):
        w = self.world()
        ing = R.ingest(w.options())
        o = w.options()
        profile, plan, policy = R._profile_parts(o)
        spec = R.build_spec(o, ing, R._Unused(trusted_authorization(w.auth)), self.tmp, profile, plan, policy)
        self.assertEqual((spec.base.root, spec.head.root), (ing.base.root, ing.head.root))
        self.assertEqual(spec.case["base"]["snapshotId"], ing.base.snapshot_id)
        self.assertEqual(spec.case["head"]["snapshotId"], ing.head.snapshot_id)
        self.assertNotEqual(ing.base.snapshot_id, ing.head.snapshot_id)
        self.assertEqual((digest(spec.imports.base), digest(spec.imports.head)), (digest(ing.base.record), digest(ing.head.record)))
        self.assertIsNone(spec.coverage)
        self.assertEqual(spec.case["pr"], {"title": "", "body": ""})
        self.assertFalse(spec.case["synthetic"])
        self.assertEqual((spec.base.manifest["snapshotId"], spec.head.manifest["snapshotId"]), (ing.base.snapshot_id, ing.head.snapshot_id))

    def test_CONTROL_the_base_import_is_the_case_textRef_even_when_the_case_baseSha_is_another_commit(self):
        w = self.world(distinct_base_sha=True)
        ing = R.ingest(w.options())
        self.assertEqual(ing.base.record["commitSha"], w.sha["base"])
        self.assertNotEqual(w.anchor, ing.base.record["commitSha"])
        self.assertEqual(R.run_repository(w.options(), key_loader=self.boom)["status"], "planned")

    def test_CONTROL_edited_pins_import_record_or_case_are_refused_before_a_request(self):
        w = self.world()
        # (a) the case pins are edited after the operator baseline was written
        edited = self.tmp / "edited.pins.json"
        doc = json.loads(w.case_pins.read_text())
        doc["origin"] = {**doc["origin"], "headSha": "0" * 40}
        edited.write_text(json.dumps(doc))
        with self.assertRaises(R.RepositoryError):
            R.ingest(w.options(case_pins=str(edited)))
        # (b) the import record is rewritten to claim byte equality it never had
        d = w.imports["head"].dir
        rec = d / "import-record.json"
        os.chmod(d, 0o755)
        os.chmod(rec, 0o644)
        doc = json.loads(rec.read_text())
        doc["relatesTo"]["changedPathsByteEqual"] = True
        doc["relatesTo"]["unchecked"] = []
        doc["relatesTo"]["changedPathsChecked"] = 99
        rec.write_text(json.dumps(doc))
        with self.assertRaises(R.RepositoryError) as c:
            R.ingest(w.options())
        self.assertIn("head import refused", str(c.exception))
        # (c) nothing was planned or captured
        rep_calls = []
        with mock.patch.object(R, "plan_mode", lambda *a, **k: rep_calls.append(1)):
            with self.assertRaises(R.RepositoryError):
                R.run_repository(w.options(), key_loader=self.boom)
        self.assertEqual(rep_calls, [])

    def test_CONTROL_a_case_without_an_external_baseline_or_with_a_symlinked_case_dir_is_refused(self):
        w = self.world()
        link = self.tmp / "link-case"
        os.symlink(w.case_dir, link)
        with self.assertRaises(R.RepositoryError):
            R.ingest(w.options(case_dir=str(link)))
        with self.assertRaises(R.RepositoryError):
            R.ingest(w.options(case_baseline=str(self.tmp / "absent.json")))
        for name, records in (("stale digest", [{"case": CASE, "action": "captured", "pinsDigest": "sha256:" + "1" * 64}]),
                              ("no record for the case", []),
                              ("record for another case", [{"case": "z--z--9", "action": "captured", "pinsDigest": digest(w.pins)}])):
            with self.subTest(name):
                b = self.tmp / f"baseline-{abs(hash(name))}.json"
                b.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": records}))
                with self.assertRaises(R.RepositoryError) as c:
                    R.ingest(w.options(case_baseline=str(b)))
                self.assertIn("operator baseline", str(c.exception))
                with self.assertRaises(R.RepositoryError):                           # every mode: plan, live and replay share ingestion
                    R.run_repository(w.options(case_baseline=str(b)), key_loader=self.boom)


# ======================================================================== 2. plan

class Plan(Base):
    def test_CONTROL_plan_is_hermetic_no_socket_no_state_env_or_output_no_leftover_scratch_and_is_repeatable(self):
        w = self.world()
        scratch_root = self.tmp / "tmpx"
        scratch_root.mkdir()
        state_before = w.state_bytes()
        patches = no_network() + [mock.patch.object(tempfile, "tempdir", str(scratch_root))]
        with patches[0], patches[1], patches[2], patches[3]:
            r1, b1 = self.plan_bodies(w)
            r2, b2 = self.plan_bodies(w)
        self.assertEqual((r1["status"], r2["status"]), ("planned", "planned"))
        self.assertEqual(b1[0], b2[0])                                              # same inputs, same bytes
        self.assertEqual(r1["plan"]["firstRequest"]["bodySha256"], hashlib.sha256(b1[0]).hexdigest())
        self.assertEqual(list(scratch_root.iterdir()), [], "plan left its scratch directory behind")
        self.assertFalse(w.out.exists())
        self.assertEqual(w.state_bytes(), state_before)
        self.assertEqual((r1["plan"]["providerCalls"], r1["plan"]["networkCalls"], r1["plan"]["keyRead"]), (0, 0, False))
        self.assertEqual(self.loads, [])

    def test_CONTROL_plan_and_live_send_the_same_first_request_bytes_whatever_the_out_dir_state_or_key(self):
        w = self.world()
        _, planned = self.plan_bodies(w)
        wire = self.model(w)
        w.seed(committed=BASELINE)
        R.run_repository(w.live_options(out_dir=str(self.tmp / "elsewhere"), baseline_micros=BASELINE), transport=wire,
                         key_loader=self.loader)
        self.assertEqual(bytes(wire.requests[0].body), planned[0])                  # byte equality, not only a digest
        self.assertNotIn(FAKE_KEY, planned[0].decode())
        self.assertNotIn(FAKE_KEY, json.dumps({k: str(v) for k, v in wire.requests[0].headers.items()}).replace("Bearer " + FAKE_KEY, ""))

    def test_CONTROL_a_plan_that_reached_no_model_call_is_plan_failed_and_names_why(self):
        w = self.world()
        from reviewer.pipeline import PipelineError

        def stop(spec):
            raise PipelineError("invalid-input", "refused before any request")
        rep = R.run_repository(w.options(), key_loader=self.boom, runner=stop)
        self.assertEqual((rep["status"], rep["ok"], rep["plan"]["capturedCount"]), ("plan-failed", False, 0))
        self.assertEqual(rep["plan"]["pipeline"]["code"], "invalid-input")
        self.assertTrue(any("no first request was captured" in g for g in rep["unmetGates"]))

    def test_NEW_authorization_claim_symptom_plan_says_covered_when_the_pipeline_stopped_before_the_authorization_check(self):
        """validate_spec runs BEFORE backend.preflight in plan_mode; a typed non-config stop therefore leaves the authorization unproven, yet
        the report says it 'covers the profile and run ceiling'. The status is still plan-failed, so nothing is mislabelled planned."""
        w = self.world()
        from reviewer.pipeline import PipelineError

        def stop(spec):
            raise PipelineError("invalid-input", "stopped by the engine")
        rep = R.run_repository(w.options(), key_loader=self.boom, runner=stop)
        self.assertEqual(rep["plan"]["authorization"], "covers the profile and run ceiling")

    @unittest.expectedFailure
    def test_NEW_authorization_claim_DEFECT_an_unproven_authorization_must_not_be_reported_as_covering_the_ceiling(self):
        w = self.world()
        from reviewer.pipeline import PipelineError

        def stop(spec):
            raise PipelineError("invalid-input", "stopped by the engine")
        rep = R.run_repository(w.options(), key_loader=self.boom, runner=stop)
        self.assertNotEqual(rep["plan"]["authorization"], "covers the profile and run ceiling")

    def _big_world(self):
        # each diff is capped near 30k chars in PREPARE, so several large changed files are needed to pass the 100k request budget
        big_base, big_head = dict(BASE), dict(HEAD)
        for k in range(8):
            big_base[f"src/big{k}.txt"] = "".join(f"line {i} base value {k}\n" for i in range(4000))
            big_head[f"src/big{k}.txt"] = "".join(f"line {i} head value {k}\n" for i in range(4000))
        return self.world("wbig", base=big_base, head=big_head, omissions=False, max_file_bytes=1 << 20)

    def test_NEW_R1_plan_blind_spot_symptom_a_context_limited_first_request_is_still_reported_as_a_clean_plan(self):
        """S1-05-review R1 is unfixed: bounded_context drops excerpts past ~100k chars with 'Excerpts omitted: request context budget'.
        The plan has the exact bytes in hand but reports only digests, so root cannot learn before spending that the trial is context-limited."""
        w = self._big_world()
        rep, seen = self.plan_bodies(w)
        self.assertEqual(rep["status"], "planned")
        self.assertIn(BIG_NOTE, seen[0].decode())                                    # the exposure is real in the captured request
        self.assertNotIn("request context budget", json.dumps(rep))                  # ... and invisible in the plan report

    @unittest.expectedFailure
    def test_NEW_R1_plan_blind_spot_DEFECT_the_plan_must_warn_when_the_first_request_omits_excerpts_for_budget(self):
        w = self._big_world()
        rep, _ = self.plan_bodies(w)
        self.assertIn("request context budget", json.dumps(rep))

    def test_CONTROL_R1_is_greppable_after_a_live_run_from_the_persisted_first_investigator_request(self):
        w = self._big_world()
        rep = self.live(w, self.model(w))
        self.assertEqual(rep["status"], "completed")
        ev = load_trace(rep["paths"]["trace"]).events
        first = next(e for e in ev if e["type"] == "model.call" and e["role"] == "investigator")
        self.assertIn(BIG_NOTE, json.dumps(first["request"]["messages"]))            # GO condition 3 is checkable from the trace
        clean = self.world("wclean")
        rep2 = self.live(clean, self.model(clean), out_dir=str(self.tmp / "out2"))
        first2 = next(e for e in load_trace(rep2["paths"]["trace"]).events if e["type"] == "model.call")
        self.assertNotIn(BIG_NOTE, json.dumps(first2["request"]["messages"]))

    def test_CONTROL_at_the_observed_scale_4476_files_and_21_submodules_plan_counts_exactly_and_lists_no_omitted_path(self):
        t0 = time.monotonic()
        w = self.world("wscale", gitlinks=21, omissions=False, n_extra=4476 - 6, base=BASE, head=HEAD)
        built = time.monotonic() - t0
        t1 = time.monotonic()
        rep, seen = self.plan_bodies(w)
        took = time.monotonic() - t1
        self.assertEqual(rep["status"], "planned", rep["unmetGates"])
        for side in ("base", "head"):
            self.assertEqual(rep["coverage"][side]["omissionCounts"], {"submodule": 21})
            self.assertEqual(rep["coverage"][side]["omittedTotal"], 21)
        self.assertEqual(rep["coverage"]["gapKinds"], ["submodule"])
        body = seen[0].decode()
        self.assertIn("submodule=21", body)
        self.assertNotIn("vendor/sub00", body)                                       # omitted paths are never listed
        self.assertLess(rep["plan"]["worstCaseAdmissionUsdMicros"], RUN_CEILING_USD_MICROS)
        print(f"\n[scale] fixture {built:.1f}s, plan {took:.1f}s, first request {len(seen[0])} bytes, "
              f"worst-case admission {rep['plan']['worstCaseAdmissionUsdMicros']} micros", file=sys.stderr)


# ======================================================================== 3. live: gates, accounting, hops

class Live(Base):
    def test_CONTROL_every_gate_runs_before_the_key_and_the_key_before_the_first_request(self):
        w = self.world()
        order = []
        real = {"open_state": R.open_state, "validate_spec": R.validate_spec, "make_out": R.make_out}
        orig_pf = R.RecordBackend.preflight

        def spy(name):
            def f(*a, **k):
                order.append(name)
                return real[name](*a, **k)
            return f

        def pf(self_, *a, **k):
            order.append("preflight")
            return orig_pf(self_, *a, **k)

        def loader(path, *, forbidden_roots=()):
            order.append("key")
            return Secret(FAKE_KEY)
        wire = self.model(w)

        def transport(req):
            order.append("request")
            return wire(req)
        w.seed()
        with mock.patch.object(R, "open_state", spy("open_state")), mock.patch.object(R, "validate_spec", spy("validate_spec")), \
                mock.patch.object(R, "make_out", spy("make_out")), mock.patch.object(R.RecordBackend, "preflight", pf):
            rep = R.run_repository(w.live_options(), transport=transport, key_loader=loader)
        self.assertEqual(rep["status"], "completed")
        self.assertEqual(order[:5], ["open_state", "validate_spec", "preflight", "make_out", "key"])
        self.assertLess(order.index("key"), order.index("request"))                  # (run_review preflights again after the key: harmless)
        self.assertEqual(order.count("key"), 1)

    def test_CONTROL_refusals_before_the_key_for_auth_that_widens_nothing_and_a_dead_or_foreign_authorization(self):
        w = self.world()
        w.seed()
        before = w.state_bytes()
        cases = {"per-run below the 4 USD ceiling": {**AUTH, "maxUsdMicrosPerRun": 3_000_000},
                 "model list without Sonnet 5.5": {**AUTH, "models": ["anthropic/claude-haiku-4.5"]},
                 "provider list without anthropic": {**AUTH, "providers": ["openai"]},
                 "total above the aggregate ($60M != ledger cap)": {**AUTH, "maxUsdMicrosTotal": 60_000_000},
                 "expired": {**AUTH, "expiresAt": "2020-01-01T00:00:00Z"}}
        for name, doc in cases.items():
            with self.subTest(name):
                p = self.tmp / f"auth-{abs(hash(name))}.json"
                p.write_text(json.dumps(doc))
                os.chmod(p, 0o600)
                wire = self.model(w)
                with self.assertRaises(Exception) as c:
                    R.run_repository(w.live_options(auth=str(p)), transport=wire, key_loader=self.boom)
                self.assertIn(type(c.exception).__name__, ("RepositoryError", "AuthorizationError", "PipelineError"), str(c.exception))
                self.assertEqual((wire.requests, w.state_bytes(), w.out.exists()), ([], before, False))

    def test_CONTROL_aggregate_boundary_46_000_000_is_allowed_and_one_micro_more_is_refused(self):
        w = self.world("wa")
        w.seed(committed=46_000_000)
        rep = R.run_repository(w.live_options(baseline_micros=46_000_000), transport=self.model(w), key_loader=self.loader)
        self.assertIn(rep["status"], ("completed", "failed", "incomplete"))          # admitted; the engine may still stop on admission
        w2 = self.world("wb")
        w2.seed(committed=46_000_001)
        before = w2.state_bytes()
        with self.assertRaises(R.RepositoryError):
            R.run_repository(w2.live_options(baseline_micros=46_000_001), transport=self.model(w2), key_loader=self.boom)
        self.assertEqual(w2.state_bytes(), before)

    def test_CONTROL_every_hop_is_one_provider_contact_one_ledger_intent_and_result_one_trace_model_call_and_one_book_settlement(self):
        w = self.world()
        wire = self.model(w)
        w.seed()
        book0 = w.book_totals()
        rep = R.run_repository(w.live_options(), transport=wire, key_loader=self.loader)
        self.assertEqual(rep["status"], "completed")
        n = len(wire.requests)
        rows = w.ledger_rows()
        intents = [r for r in rows if r["type"] == "intent" and not r["callKey"].startswith("prior|")]
        results = [r for r in rows if r["type"] == "result" and not r["callKey"].startswith("prior|")]
        ev = load_trace(rep["paths"]["trace"]).events
        self.assertEqual((n, len(intents), len(results), rep["providerCalls"]), (5, 5, 5, 5))
        self.assertEqual(len([e for e in ev if e["type"] == "model.call"]), n)
        self.assertEqual(len([e for e in ev if e["type"] == "cost"]), n)
        self.assertEqual(rep["costs"]["gateway"]["liveCalls"], n)
        self.assertTrue(all(r["outcome"] == "processed" for r in results))
        self.assertEqual({r["model"] for r in intents}, {SONNET})
        book1 = w.book_totals()
        self.assertEqual((book1["inflight"], book1["committed"] > book0["committed"]), (0, True))
        self.assertEqual(w.ledger_rows()[-1]["type"], "result")                      # nothing left open

    def test_CONTROL_requests_pin_the_model_and_forbid_fallback_routing(self):
        w = self.world()
        wire = self.model(w)
        self.live(w, wire)
        for b in wire.bodies:
            self.assertEqual(b["model"], MODEL)
            self.assertIs(b["provider"]["allow_fallbacks"], False)
            for k in ("models", "route", "fallbacks", "transforms", "tools", "tool_choice"):
                self.assertNotIn(k, b, k)

    def test_CONTROL_the_receipt_records_the_effective_caps_160_60_and_the_pinned_profile(self):
        w = self.world()
        rep = self.live(w, self.model(w))
        receipt = json.loads(Path(rep["paths"]["receipt"]).read_text())
        eff = receipt["retrieval"]["effective"]
        self.assertEqual((eff["runToolCalls"], eff["agentToolCalls"]), (160, 60))
        self.assertEqual(receipt["profile"]["ref"], "pilot-repository@1")
        self.assertEqual(receipt["mode"], "live")
        self.assertEqual(receipt["cost"]["liveCalls"], 5)

    def test_CONTROL_a_second_live_run_of_the_same_inputs_is_refused_by_the_ledger_without_any_provider_contact(self):
        w = self.world()
        first = self.live(w, self.model(w))
        self.assertEqual(first["status"], "completed")
        t = w.book_totals()
        committed = RuntimeLedger(w.state / R.LEDGER_NAME, 50_000_000).totals()["committedUsdMicros"]
        wire = self.model(w)
        try:
            rep = R.run_repository(w.live_options(out_dir=str(self.tmp / "out-again"), baseline_micros=committed,
                                                  book_baseline_micros=t["committed"]), transport=wire, key_loader=self.loader)
            self.assertNotEqual(rep["status"], "completed")
        except Exception as e:  # noqa: BLE001
            self.assertIn(type(e).__name__, ("RepositoryError", "PipelineError", "AuthorizationError"))
        self.assertEqual(wire.requests, [], "a repeated run re-contacted the provider")

    def test_CONTROL_no_retry_no_repair_no_second_attempt_for_http_errors_and_unusable_answers(self):
        cases = {"500": HttpResponse(500, {}, b"{}"), "429": HttpResponse(429, {"retry-after": "1"}, b'{"error":{"message":"slow down"}}'),
                 "garbage text": "not json {", "valid json, wrong shape": {"unexpected": True}}
        for name, step in cases.items():
            with self.subTest(name):
                w = self.world("w-" + name.replace(" ", "-").replace(",", ""))
                wire = Wire(step)
                rep = self.live(w, wire)
                self.assertEqual(len(wire.requests), 1, name)
                self.assertFalse(rep["ok"])
                self.assertNotEqual(rep["status"], "completed")
                intents = [r for r in w.ledger_rows() if r["type"] == "intent" and not r["callKey"].startswith("prior|")]
                self.assertEqual(len(intents), 1, name)
                self.assertTrue((w.out / "report.json").is_file())
                self.assertEqual(w.book_totals()["inflight"], 0, name)

    def test_CONTROL_an_unknown_provider_contact_is_charged_worst_case_never_retried_and_blocks_the_next_run(self):
        w = self.world()
        wire = Wire(TransportError(True))                                           # request may have reached the provider
        rep = self.live(w, wire)
        self.assertEqual(len(wire.requests), 1)
        self.assertFalse(rep["ok"])
        led = RuntimeLedger(w.state / R.LEDGER_NAME, 50_000_000).totals()
        self.assertGreater(led["committedUsdMicros"], BASELINE, "an unknown contact must not be free")
        with self.assertRaises(R.RepositoryError):                                  # same --baseline-micros: root has not reconciled
            R.run_repository(w.live_options(out_dir=str(self.tmp / "out-b")), transport=Wire(TransportError(True)), key_loader=self.boom)

    def test_CONTROL_an_interrupt_keeps_the_ledger_intent_writes_an_interrupted_report_and_the_next_run_refuses(self):
        w = self.world()
        good = self.model(w)

        class Interrupt:
            n = 0

            def __call__(s, req):
                s.n += 1
                if s.n == 2:
                    raise KeyboardInterrupt()
                return good(req)
        itr = Interrupt()
        w.seed()
        with self.assertRaises(KeyboardInterrupt):
            R.run_repository(w.live_options(), transport=itr, key_loader=self.loader)
        rep = json.loads((w.out / "report.json").read_text())
        self.assertEqual((rep["status"], rep["ok"]), ("interrupted", False))
        rows = [r for r in w.ledger_rows() if not r.get("callKey", "").startswith("prior|")]
        self.assertEqual(len([r for r in rows if r["type"] == "intent"]), 2)
        self.assertEqual(len([r for r in rows if r["type"] == "result"]), 1)          # the interrupted call has an intent and no result
        with self.assertRaises(R.RepositoryError):
            R.run_repository(w.live_options(out_dir=str(self.tmp / "out-c")), transport=self.model(w), key_loader=self.boom)

    def test_CONTROL_a_key_echoed_by_the_provider_never_reaches_any_output_state_or_console(self):
        w = self.world()
        echo = HttpResponse(401, {}, json.dumps({"error": {"message": f"invalid key {FAKE_KEY}"}}).encode())
        out, err = io.StringIO(), io.StringIO()
        w.seed()
        argv = ["--mode", "live", "--confirm-live", "--case-dir", str(w.case_dir), "--case-pins", str(w.case_pins),
                "--case-baseline", str(w.baseline), "--store", str(w.store), "--base-import-pins", str(w.import_pins["base"]),
                "--head-import-pins", str(w.import_pins["head"]), "--out", str(w.out), "--auth", str(w.auth),
                "--state-dir", str(w.state), "--env", str(w.env), "--baseline-micros", str(BASELINE), "--json"]
        R.main(argv, transport=Wire(echo), key_loader=self.loader, out=out, err=err)
        self.assertNotIn(FAKE_KEY, out.getvalue() + err.getvalue())
        for root in (w.out, w.state):
            for p in root.rglob("*"):
                if p.is_file():
                    self.assertNotIn(FAKE_KEY, p.read_text(errors="ignore"), str(p))

    def test_CONTROL_full_outputs_are_persisted_under_a_fresh_0700_directory_and_the_trace_holds_every_raw_answer(self):
        w = self.world()
        wire = self.model(w)
        rep = self.live(w, wire)
        out = Path(rep["reportPath"]).parent
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
        runs = Path(rep["paths"]["runDir"])
        for name in ("review.md", "comments.json", "receipt.json", "trace.jsonl", "coverage.json", "run.json"):
            self.assertTrue((runs / name).is_file(), name)
        self.assertEqual(len(list((runs / "artifacts").glob("*.json"))), 8)
        ev = load_trace(rep["paths"]["trace"]).events
        calls = [e for e in ev if e["type"] == "model.call"]
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(c["response"] and c["requestHash"] for c in calls))
        for p in out.rglob("*"):
            self.assertTrue(os.path.realpath(p).startswith(os.path.realpath(out) + os.sep) or p == out)

    def test_CONTROL_output_containment_symlinked_parent_dangling_link_and_state_dir_are_refused_and_create_nothing(self):
        w = self.world()
        w.seed()
        before = w.state_bytes()
        link = self.tmp / "sl"
        os.symlink(w.state, link)
        dangling = self.tmp / "dangling"
        os.symlink(w.state / "later", dangling)
        for bad in (link / "fresh", dangling, w.state / "child", w.op / "dot.env" / "x"):
            with self.subTest(str(bad)), self.assertRaises(R.RepositoryError):
                R.run_repository(w.live_options(out_dir=str(bad)), transport=self.model(w), key_loader=self.boom)
        self.assertFalse((w.state / "later").exists() or (w.state / "fresh").exists() or (w.state / "child").exists())
        self.assertEqual(w.state_bytes(), before)


# ======================================================================== 4. replay

class Replay(Base):
    def recorded(self, w, steps=None):
        rep = self.live(w, steps or self.model(w))
        return rep, rep["paths"]["trace"], rep["traceDigest"]["value"]

    def ropts(self, w, trace, pin, out):
        return w.options(mode="replay", auth=None, out_dir=str(out), replay_trace=trace, trace_digest=pin)

    def test_CONTROL_replay_touches_no_socket_key_auth_book_or_state_consumes_every_call_and_keeps_its_outputs(self):
        w = self.world()
        rep, trace, pin = self.recorded(w)
        state_before = w.state_bytes()
        with Audit() as aud:
            ps = no_network()
            with ps[0], ps[1], ps[2], mock.patch.object(R, "open_state", side_effect=AssertionError("state opened")), \
                    mock.patch.object(R, "trusted_authorization", side_effect=AssertionError("auth opened")):
                rr = R.run_repository(self.ropts(w, trace, pin, self.tmp / "replay-out"), key_loader=self.boom)
        self.assertEqual((rr["status"], rr["ok"]), ("completed", True))
        self.assertEqual((rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"], rr["replay"]["replayedCalls"]), (0, 0, 5))
        receipt = json.loads(Path(rr["paths"]["receipt"]).read_text())
        self.assertEqual(receipt["gateway"]["unconsumedRecordedCalls"], 0)           # every recorded call was consumed
        self.assertEqual(w.state_bytes(), state_before)
        for g in (w.state, w.env, w.auth, w.case_dir / "labels", w.case_dir / "source"):
            self.assertEqual(aud.under(g), [], str(g))
        self.assertEqual(aud.gold_named(), [])
        self.assertTrue(Path(rr["paths"]["trace"]).is_file())                        # kept: not under any temporary cleanup
        self.assertEqual(json.loads((self.tmp / "replay-out" / "report.json").read_text())["replay"]["consumedZeroLive"], True)

    def test_CONTROL_a_one_byte_edit_of_the_trace_under_the_old_digest_is_refused_and_leaves_no_output(self):
        w = self.world()
        _, trace, pin = self.recorded(w)
        raw = Path(trace).read_bytes()
        bad = self.tmp / "edited-trace.jsonl"
        bad.write_bytes(raw.replace(b"Sign flip", b"Sign flap", 1))
        self.assertNotEqual(raw, bad.read_bytes())
        out = self.tmp / "replay-bad"
        with self.assertRaises(Exception) as c:
            R.run_repository(self.ropts(w, str(bad), pin, out), key_loader=self.boom)
        self.assertEqual(type(c.exception).__name__, "PipelineError")
        self.assertFalse(out.exists())

    def test_CONTROL_replaying_a_failed_recording_is_not_reported_ok(self):
        w = self.world()
        rep, trace, pin = self.recorded(w, Wire(HttpResponse(500, {}, b"{}")))
        self.assertFalse(rep["ok"])
        rr = R.run_repository(self.ropts(w, trace, pin, self.tmp / "replay-failed"), key_loader=self.boom)
        self.assertFalse(rr["ok"])
        self.assertEqual(rr["replay"]["liveCalls"], 0)

    def test_CONTROL_replay_flags_that_would_reach_state_or_the_network_are_refused(self):
        w = self.world()
        with self.assertRaises(R.RepositoryError):
            R.check_options(w.options(mode="replay", auth=None, env_file=str(w.env), replay_trace="t", trace_digest="sha256:" + "0" * 64))
        with self.assertRaises(R.RepositoryError):
            R.check_options(w.options(mode="replay", auth=None, state_dir=str(w.state), replay_trace="t", trace_digest="sha256:" + "0" * 64))

    def test_CONTROL_no_fork_or_stage_flag_exists_and_the_report_does_not_claim_one(self):
        flags = {a.option_strings[0] for a in R._parser()._actions if a.option_strings}
        for bad in ("--fork", "--from-stage", "--stage", "--stage-replay", "--resume"):
            self.assertNotIn(bad, flags)
        w = self.world()
        rep = self.live(w, self.model(w))
        self.assertIn("fork is not implemented", rep["forkAndStageReplay"])
        plan = R.run_repository(w.options(out_dir=str(self.tmp / "p")), key_loader=self.boom)
        self.assertTrue(any("fork is not implemented" in g for g in plan["unmetGates"]))


if __name__ == "__main__":
    unittest.main()
