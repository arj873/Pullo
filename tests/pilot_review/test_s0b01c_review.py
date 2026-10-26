"""S0B-01c independent review: pilot launcher (reviewer/pilot). Offline only.

Fake key, fake OpenRouter transport (into the REAL OpenRouterProvider/RuntimeLedger/SpendBook/gateway/pipeline/bridge),
tmp corpus/pins/auth/state. No .env, network, model call or private state. Reuses the author's rig read-only.

DEFECT_*   expectedFailure: the assertion states the correct behaviour; flips to unexpected success when fixed.
HARDEN_*   expectedFailure: recommended guard (not a correctness bug in the code as specified).
CONDITION_ expectedFailure: an open condition from another gate (S0B-01b-review condition 2).
Everything else is a control that must pass."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from reviewer.pilot import live_profile
from reviewer.pilot import launcher as L
from reviewer.pipeline import PipelineError
from reviewer.runtime.openrouter import HttpsTransport, OpenRouterProvider
from tests.pilot.helpers import (BASE, CTX, FAKE_KEY, HEAD, LABEL_CANARIES, Model, Rig, boom_key_loader,
                                 tree_listing)
from tests.tools.helpers import make_case

_SPAWN = []
_SPAWN_ON = [False]
_SPAWN_EVENTS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
                 "pty.spawn")


def _hook(event, args):
    if _SPAWN_ON[0] and event in _SPAWN_EVENTS:
        _SPAWN.append(event)


sys.addaudithook(_hook)


def _bytes_under(root: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink())


class BadVerifier(Model):
    """Investigator finds one issue; the verifier answers with schema-invalid JSON (repairs are 0)."""

    def content(self, role):
        if role == "VerifierOutput":
            return {"verdict": "probably", "notes": 7}
        return super().content(role)


# ---------------------------------------------------------------- credentials / argument gating

class GatingBeforeCredentials(Rig):
    def _no_side_effects(self, argv, *, expect_code=None):
        led = (self.state / "runtime-ledger.jsonl").read_bytes()
        book = (self.state / "spend-book.jsonl").read_bytes()
        with mock.patch.object(HttpsTransport, "__call__", side_effect=AssertionError("network")), \
                mock.patch("sys.stderr"):
            try:
                code, out, err = self.run_main(argv, transport=None, key_loader=boom_key_loader)
            except SystemExit as e:                                   # argparse usage error
                code, out, err = e.code, "", ""
        self.assertNotEqual(code, 0, argv)
        if expect_code is not None:
            self.assertEqual(code, expect_code, (argv, err, out))
        self.assertEqual((self.state / "runtime-ledger.jsonl").read_bytes(), led)
        self.assertEqual((self.state / "spend-book.jsonl").read_bytes(), book)
        self.assertNotIn(FAKE_KEY, out + err)
        return code, out, err

    def test_invalid_mode_and_args_fail_before_key_spend_or_network(self):
        bad = [
            ["--model", "anthropic/claude-sonnet-5"], ["--model", "openai/gpt-5"],
            ["--model", "anthropic/claude-sonnet-5.5:nitro"],
            ["--judge-max-output-tokens", "0"], ["--investigator-max-output-tokens", "100001"],
            ["--repeat", "-1"], ["--repeat", "1001"],
            ["--wall-clock-sec", "0"], ["--soft-deadline-sec", "99999"],
            ["--replay-trace", "x", "--trace-digest", "sha256:" + "0" * 64],     # live + replay
            ["--trace-digest", "sha256:" + "0" * 64],                              # stray replay arg in live
        ]
        for extra in bad:
            self._no_side_effects(self.argv(*extra))
        # live without auth / state / env
        self._no_side_effects(self.argv(auth=False), expect_code=2)
        self._no_side_effects(self.argv(state=False), expect_code=2)
        a = self.argv()
        i = a.index("--env")
        self._no_side_effects(a[:i] + a[i + 2:], expect_code=2)
        # plan given live-only state/env
        self._no_side_effects(self.argv(live=False) + ["--state-dir", str(self.state)], expect_code=2)

    def test_paths_traversal_symlinks_and_placement_refuse_before_key(self):
        case_input = self.corpus / "o--r--1" / "input"
        link_out = self.tmp / "out-link"
        link_out.symlink_to(self.corpus / "o--r--1")
        link_state = self.operator / "state-link"
        link_state.symlink_to(case_input)
        pins_in_corpus = case_input / "pinsx"
        pins_in_corpus.mkdir()
        (pins_in_corpus / "o--r--1.json").write_bytes((self.pins / "o--r--1.json").read_bytes())
        env_in_out = self.out / "dot.env"
        self.out.mkdir()
        env_in_out.write_text("x=1\n")
        state_under_pins = self.pins / "state"          # allowed placement, but corpus/out checks must still hold
        swap = {
            "--out": [str(link_out), str(self.corpus), str(self.corpus.parent / "corpus" / ".." / "corpus"),
                      str(L.REPO / "reviewer" / "pilot" / "x"), str(L.REPO / "fixtures" / "x"), str(self.tmp)],
            "--state-dir": [str(link_state), str(self.out / "s")],
            "--pins-dir": [str(pins_in_corpus)],
            "--env": [str(env_in_out), str(case_input / "x.env")],
            "--auth": [str(self.out / "auth.json"), str(case_input / "a.json")],
        }
        base = self.argv()
        for flag, values in swap.items():
            for v in values:
                a = list(base)
                a[a.index(flag) + 1] = v
                self._no_side_effects(a)
        self.assertFalse(state_under_pins.exists())
        for bad_case in ("..", "o--r--1/../o--r--1", "/etc", "o--r--1\x00"):
            self._no_side_effects(self.argv(cases=[bad_case]), expect_code=2)

    def test_wrong_baseline_digest_or_missing_case_refuses_before_key(self):
        bl = self.operator / "baseline.json"
        for recs in ([{"case": "o--r--1", "pinsDigest": "sha256:" + "a" * 64, "action": "captured"}],
                     [{"case": "other", "pinsDigest": "sha256:" + "a" * 64, "action": "captured"}],
                     [{"case": "o--r--1", "pinsDigest": "sha256:" + "a" * 64, "action": "skipped"}]):
            bl.write_text(json.dumps({"schema": "operator-pin-baseline@1", "records": recs}))
            self._no_side_effects(self.argv("--pins-baseline", str(bl)), expect_code=2)
        # baseline file inside the corpus, or a symlink to one
        inside = self.corpus / "o--r--1" / "input" / "bl.json"
        inside.write_text(bl.read_text())
        self._no_side_effects(self.argv("--pins-baseline", str(inside)), expect_code=2)
        ln = self.operator / "bl-link.json"
        ln.symlink_to(inside)
        self._no_side_effects(self.argv("--pins-baseline", str(ln)), expect_code=2)


# ---------------------------------------------------------------- shared state, scopes, idempotency, costs

class SharedState(Rig):
    cases = ("o--r--1", "o--r--2")

    def test_existing_state_is_continued_never_reset_and_deltas_add_up(self):
        m = self.model()
        code, r1, _ = self.run_json(self.argv(cases=["o--r--1"]), transport=m)
        self.assertEqual(code, 0)
        led1 = (self.state / "runtime-ledger.jsonl").read_bytes()
        book1 = (self.state / "spend-book.jsonl").read_bytes()
        cum1 = r1["cases"][0]["costs"]["runtime"]["cumulative"]
        self.assertGreater(cum1["accountable"]["usdMicros"], 0)
        # a NEW invocation (new SpendBook/RuntimeLedger objects) over two cases
        code, r2, _ = self.run_json(self.argv("--repeat", "1"), transport=m)
        self.assertEqual(code, 0)
        led2 = (self.state / "runtime-ledger.jsonl").read_bytes()
        self.assertTrue(led2.startswith(led1) and len(led2) > len(led1))          # append-only, nothing rewritten
        self.assertTrue((self.state / "spend-book.jsonl").read_bytes().startswith(book1))
        prev = cum1
        for c in r2["cases"]:
            rt = c["costs"]["runtime"]
            self.assertEqual(rt["capUsdMicros"], 50_000_000)
            for k in prev:
                self.assertEqual(rt["cumulative"][k]["usdMicros"],
                                 prev[k]["usdMicros"] + rt["thisCase"][k]["usdMicros"], (c["case"], k))
            self.assertEqual(rt["thisCase"]["routerBilled"]["usdMicros"], 0)             # BYOK router ~0
            self.assertGreater(rt["thisCase"]["upstreamReported"]["usdMicros"], 0)
            self.assertNotEqual(c["costs"]["gateway"]["note"], rt["note"])              # kept separate
            prev = rt["cumulative"]

    def test_constructor_run_scope_is_the_pipeline_run_id_one_provider_per_case(self):
        scopes = []

        class Spy(OpenRouterProvider):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                scopes.append((kw.get("run_scope"), self.scope, kw.get("enabled"), kw.get("ledger"), kw.get("book")))

        with mock.patch.object(L, "OpenRouterProvider", Spy):
            code, rep, _ = self.run_json(self.argv(), transport=self.model())
        self.assertEqual(code, 0)
        self.assertEqual([s[0] for s in scopes], [c["runId"] for c in rep["cases"]])
        self.assertEqual([s[1] for s in scopes], [c["runId"] for c in rep["cases"]])
        self.assertEqual(len({id(s[3]) for s in scopes}), 1)                             # one ledger object
        self.assertEqual(len({id(s[4]) for s in scopes}), 1)                             # one book object

    def test_completed_rerun_is_idempotent_but_interrupted_recording_never_reissues(self):
        m = self.model()
        self.run_json(self.argv(cases=["o--r--1"]), transport=m)
        n, rows = len(m.requests), len(self.ledger_rows())
        code, rep, _ = self.run_json(self.argv(cases=["o--r--1"]), transport=m)
        c = rep["cases"][0]
        self.assertEqual((code, c["idempotent"], c["providerCalls"], len(m.requests), len(self.ledger_rows())),
                         (0, True, 0, n, rows))
        self.assertEqual(c["costs"]["runtime"]["thisCase"]["accountable"]["usdMicros"], 0)

        class Crash(BaseException):
            pass

        sent = []

        def crash(req):
            sent.append(req)
            raise Crash()

        with self.assertRaises(Crash):
            self.run_main(self.argv(cases=["o--r--2"]), transport=crash)
        k = len(sent)
        for _ in range(2):
            code, rep, _ = self.run_json(self.argv(cases=["o--r--2"]), transport=self.model())
            self.assertEqual((code, rep["cases"][0]["error"]["code"], len(sent)), (1, "recovery-required", k))


# ---------------------------------------------------------------- leaks, labels, native code

class Leaks(Rig):
    def test_model_payload_carries_no_host_paths_labels_or_key_and_nothing_is_spawned(self):
        m = self.model()
        _SPAWN.clear()
        _SPAWN_ON[0] = True
        try:
            code, rep, _ = self.run_json(self.argv(), transport=m)
            self.run_main(self.argv(live=False))
            c = rep["cases"][0]
            self.run_json(["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--out",
                           str(self.tmp / "o2"), "--case", "o--r--1", "--replay-trace", c["paths"]["trace"],
                           "--trace-digest", c["traceDigest"]["value"]], key_loader=boom_key_loader)
        finally:
            _SPAWN_ON[0] = False
        self.assertEqual(code, 0)
        self.assertEqual(_SPAWN, [])
        self.assertTrue(m.requests)
        for r in m.requests:
            body = r.body.decode("utf-8")
            for bad in (str(self.tmp), FAKE_KEY, *LABEL_CANARIES, "labels/", "source/", "merged"):
                self.assertNotIn(bad, body)
        allout = _bytes_under(self.out)
        for bad in (FAKE_KEY, *LABEL_CANARIES):
            self.assertNotIn(bad.encode(), allout)

    def test_unlabelled_case_never_gets_a_quality_metric(self):
        code, rep, _ = self.run_json(self.argv(), transport=self.model())
        c = rep["cases"][0]
        summ = json.loads(Path(c["summary"]).read_text())
        for doc in (c, summ):
            self.assertTrue(doc["quality"].startswith("not scored"))
            keys, stack = [], [doc]
            while stack:
                x = stack.pop()
                if isinstance(x, dict):
                    keys += [k.lower() for k in x]
                    stack += list(x.values())
                elif isinstance(x, list):
                    stack += x
            for k in keys:
                for word in ("precision", "recall", "f1", "score", "accuracy"):
                    self.assertNotIn(word, k)
        self.assertFalse(summ["disclosure"]["fullRepositoryCoverage"])
        self.assertIn("PARTIAL", summ["disclosure"]["statement"])
        self.assertIn("OMITTED", summ["disclosure"]["prText"])


# ---------------------------------------------------------------- partial status honesty

class PartialStatus(Rig):
    def test_partial_verifier_failure_is_never_completed_or_no_issues(self):
        m = BadVerifier(self.head_id)
        code, rep, _ = self.run_json(self.argv(), transport=m)
        c = rep["cases"][0]
        self.assertIn("VerifierOutput", m.roles)
        self.assertEqual(code, 1)
        self.assertFalse(rep["ok"])
        self.assertNotEqual(c["status"], "completed")
        self.assertTrue(c["incomplete"] or c["error"])
        summ = json.loads(Path(c["summary"]).read_text())
        self.assertEqual(summ["status"], c["status"])
        md = Path(c["paths"]["review"]).read_text()
        self.assertNotIn("Status: **completed**", md)
        self.assertTrue("## Incomplete" in md or "did not finish" in md)
        self.assertIn("not a certificate", md) if c["counts"]["comments"] == 0 else None

    def test_normal_plan_dry_run_stops_at_the_first_provider_call(self):
        code, rep, _ = self.run_json(self.argv(live=False))
        p = rep["cases"][0]["plan"]
        self.assertEqual(code, 0)
        self.assertEqual(p["scratchPipelineRun"]["error"], "provider-error")
        self.assertEqual(len(p["firstRequests"]), 1)
        self.assertFalse(self.out.exists())

    @unittest.expectedFailure
    def test_DEFECT_plan_reports_planned_when_the_dry_pipeline_refused_before_any_request(self):
        # unit seam: the scratch run ends at PREPARE (the real shape of a coverage-mismatch) before any request
        failed = SimpleNamespace(status="failed", error={"code": "contract-violation", "kind": "coverage-mismatch"})
        for effect in ({"return_value": failed}, {"side_effect": PipelineError("invalid-input", "coverage")}):
            with mock.patch.object(L, "run_review", **effect):
                code, rep, _ = self.run_json(self.argv(live=False))
            c = rep["cases"][0]
            self.assertEqual(c["plan"]["firstRequests"], [])
            self.assertNotEqual((code, c["status"], rep["ok"]), (0, "planned", True), effect)


# ---------------------------------------------------------------- replay and output containment

class ReplayAndOutputs(Rig):
    cases = ("o--r--1", "o--r--2")

    def _record(self, case="o--r--1"):
        code, rep, _ = self.run_json(self.argv(cases=[case]), transport=self.model())
        self.assertEqual(code, 0)
        return rep["cases"][0]

    def _replay(self, c, case, out, digest=None):
        return self.run_json(["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--out", str(out),
                              "--case", case, "--replay-trace", c["paths"]["trace"],
                              "--trace-digest", digest or c["traceDigest"]["value"]], key_loader=boom_key_loader)

    def test_replay_of_another_cases_trace_is_refused(self):
        c = self._record("o--r--1")
        code, rep, _ = self._replay(c, "o--r--2", self.tmp / "o2")
        self.assertEqual(code, 1)
        self.assertNotEqual(rep["cases"][0]["status"], "completed")

    def test_replay_wrong_digest_refused_without_key(self):
        c = self._record()
        code, rep, _ = self._replay(c, "o--r--1", self.tmp / "o2", digest="sha256:" + "e" * 64)
        self.assertEqual((code, rep["cases"][0]["status"]), (1, "refused"))

    @unittest.expectedFailure
    def test_DEFECT_replay_outputs_survive_under_out(self):
        c = self._record()
        out2 = self.tmp / "o2"
        code, rep, _ = self._replay(c, "o--r--1", out2)
        self.assertEqual(code, 0)
        r = rep["cases"][0]
        for k, p in r["paths"].items():
            self.assertTrue(Path(p).exists(), (k, p))
            self.assertTrue(Path(p).resolve().is_relative_to(out2.resolve()), (k, p))

    @unittest.expectedFailure
    def test_DEFECT_summaries_symlink_cannot_write_outside_out(self):
        target = self.corpus / "o--r--1" / "input"
        before = tree_listing(self.corpus)
        self.out.mkdir()
        (self.out / "summaries").symlink_to(target)
        code, rep, _ = self.run_json(self.argv(cases=["o--r--1"]), transport=self.model())
        self.assertEqual(tree_listing(self.corpus), before)


# ---------------------------------------------------------------- hardening / open conditions

class Hardening(Rig):
    @unittest.expectedFailure
    def test_HARDEN_live_requires_a_pins_baseline(self):
        code, _, _ = self.run_main(self.argv(), transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 2)

    @unittest.expectedFailure
    def test_HARDEN_live_refuses_an_empty_ledger_as_existing_state(self):
        # the shared $50 total lives in a non-empty ledger (canary committed 2814); empty files are fresh state
        self.assertEqual((self.state / "runtime-ledger.jsonl").stat().st_size, 0)
        code, _, _ = self.run_main(self.argv(), transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 2)

    @unittest.expectedFailure
    def test_CONDITION_live_role_timeouts_within_s0b01b_condition_2(self):
        for r, spec in live_profile()["roles"].items():
            self.assertLessEqual(spec["caps"]["timeoutSec"], 120, r)


if __name__ == "__main__":
    unittest.main()
