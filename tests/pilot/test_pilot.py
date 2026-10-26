"""S0B-01c: host PR trial launcher, offline. Real launcher -> bridge -> pipeline -> gateway -> OpenRouter adapter,
with a FAKE transport and a fake key. Run: nice -n 19 python3 -m unittest discover -s tests/pilot -t ."""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from reviewer.pilot import PilotError, PilotOptions, live_plan, live_profile, run_cases
from reviewer.pilot.profile import ProfileError
from reviewer.runtime.openrouter import HttpResponse, HttpsTransport
from tests.pilot.helpers import (FAKE_KEY, LABEL_CANARIES, Rig, boom_key_loader, fake_key_loader, tree_listing)

OPENED: list = []
WATCH = [False]


def _hook(event, args):
    if WATCH[0] and event in ("open", "os.scandir", "os.listdir"):
        OPENED.append(str(args[0]))


sys.addaudithook(_hook)


def watching(fn, *a, **kw):
    OPENED.clear()
    WATCH[0] = True
    try:
        return fn(*a, **kw)
    finally:
        WATCH[0] = False


class Plan(Rig):
    def test_plan_reads_no_key_state_or_labels_and_writes_nothing(self):
        before = tree_listing(self.tmp)
        with mock.patch.object(HttpsTransport, "__call__", side_effect=AssertionError("network")):
            code, rep, err = watching(self.run_json, self.argv(live=False), key_loader=boom_key_loader)
        self.assertEqual((code, err), (0, ""))
        c = rep["cases"][0]
        self.assertEqual(c["status"], "planned")
        p = c["plan"]
        self.assertEqual((p["providerCalls"], p["networkCalls"], p["keyRead"], p["retries"], p["repairs"]), (0, 0, False, 0, 0))
        self.assertEqual([r["role"] for r in p["firstRequests"]], ["investigator"])
        self.assertFalse(c["disclosure"]["fullRepositoryCoverage"])
        self.assertIn("OMITTED", c["disclosure"]["prText"])
        self.assertFalse(self.out.exists())
        self.assertEqual(tree_listing(self.tmp), before)                     # nothing created anywhere (scratch is gone)
        bad = [p for p in OPENED if any(s in p for s in (str(self.state), str(self.env), "/labels", "/source"))]
        self.assertEqual(bad, [])
        self.assertEqual((self.state / "runtime-ledger.jsonl").stat().st_size, 0)

    def test_plan_rejects_live_only_args(self):
        code, _, err = self.run_main(self.argv("--state-dir", str(self.state), live=False), key_loader=boom_key_loader)
        self.assertEqual(code, 2)
        self.assertIn("only for --live", err)

    def test_plan_needs_covering_authorization(self):
        doc = json.loads(self.auth.read_text())
        doc["models"] = ["anthropic/claude-haiku-5.5"]
        self.auth.write_text(json.dumps(doc))
        code, rep, _ = self.run_json(self.argv(live=False))
        self.assertEqual(code, 1)
        self.assertTrue(rep["cases"][0]["refused"])
        self.assertIn("not authorized", rep["cases"][0]["error"]["message"])


class Live(Rig):
    def test_full_review_outputs_costs_and_disclosure(self):
        m = self.model()
        code, rep, err = watching(self.run_json, self.argv(), transport=m)
        self.assertEqual((code, err), (0, ""))
        c = rep["cases"][0]
        self.assertEqual(c["status"], "completed")
        self.assertEqual(m.roles, ["InvestigatorOutput", "VerifierOutput", "JudgeOutput"])
        self.assertEqual(c["providerCalls"], 3)
        self.assertEqual(c["counts"], {"hypotheses": 1, "findings": 1, "verifications": 1, "drops": 0, "comments": 1})
        for k in ("review", "comments", "receipt", "trace", "runDir"):
            self.assertTrue(Path(c["paths"][k]).exists(), k)
            self.assertTrue(Path(c["paths"][k]).resolve().is_relative_to(self.out.resolve()))
        review = Path(c["paths"]["review"]).read_text()
        self.assertIn("artial", review)                                       # coverage disclosed in the review itself
        r = c["costs"]["runtime"]
        self.assertEqual(r["thisCase"]["routerBilled"]["usdMicros"], 0)       # BYOK: router 0, upstream carries it
        self.assertEqual(r["thisCase"]["upstreamReported"]["usdMicros"], 3 * 4200)
        self.assertEqual(r["thisCase"]["accountable"]["usdMicros"], 12600)
        self.assertIsNotNone(c["costs"]["gateway"]["computedTokenPricedUsdMicros"])
        self.assertIn("NOT a provider bill", c["costs"]["gateway"]["note"])
        self.assertIn("not scored", c["quality"])
        self.assertIn("not a trusted pin", c["traceDigest"]["trust"])
        self.assertTrue(Path(c["summary"]).is_file())
        self.assertEqual(c["disclosure"]["contextPaths"], {"base": 1, "head": 1})
        # request profile
        body = json.loads(m.requests[0].body)
        self.assertEqual(body["model"], "anthropic/claude-sonnet-5.5")
        self.assertEqual(body["max_tokens"], 16000)
        self.assertEqual(body["provider"]["allow_fallbacks"], False)

    def test_no_label_outcome_or_key_leak(self):
        m = self.model()
        code, out, err = self.run_main(self.argv(), transport=m)
        self.assertEqual(code, 0)
        texts = [out, err] + [r.body.decode() for r in m.requests]
        for p in self.out.rglob("*"):
            if p.is_file():
                texts.append(p.read_text(errors="replace"))
        blob = "\n".join(texts)
        for canary in LABEL_CANARIES + (FAKE_KEY,):
            self.assertNotIn(canary, blob)
        self.assertNotIn("Bearer", blob)

    def test_label_and_source_dirs_are_never_opened(self):
        m = self.model()
        watching(self.run_main, self.argv(), transport=m)
        bad = [p for p in OPENED if "/labels" in p or "/source" in p]
        self.assertEqual(bad, [])

    def test_idempotent_rerun_does_not_call_the_provider(self):
        m = self.model()
        self.run_json(self.argv(), transport=m)
        n, rows = len(m.requests), len(self.ledger_rows())
        code, rep, _ = self.run_json(self.argv(), transport=m)
        c = rep["cases"][0]
        self.assertEqual((code, c["status"], c["idempotent"], c["providerCalls"]), (0, "completed", True, 0))
        self.assertEqual((len(m.requests), len(self.ledger_rows())), (n, rows))
        self.assertEqual(c["costs"]["runtime"]["thisCase"]["accountable"]["usdMicros"], 0)
        self.assertEqual(len(list((self.out / "summaries").iterdir())), 2)    # each invocation keeps its own summary

    def test_work_trees_are_discarded(self):
        self.run_main(self.argv(), transport=self.model())
        self.assertEqual(list((self.out / "work").iterdir()), [])


class SharedAccounting(Rig):
    cases = ("o--r--1", "o--r--2")

    def test_two_cases_one_book_one_ledger_distinct_scopes(self):
        m = self.model()
        # case 2 has the same content (same head id), so the same fake answers are valid for both
        code, rep, err = self.run_json(self.argv(), transport=m)
        self.assertEqual((code, err), (0, ""))
        a, b = rep["cases"]
        self.assertEqual((a["status"], b["status"]), ("completed", "completed"))
        self.assertNotEqual(a["runId"], b["runId"])
        rows = self.ledger_rows()
        scopes = {r["callKey"].split("|")[0] for r in rows if r["type"] == "intent"}
        self.assertEqual(scopes, {a["runId"], b["runId"]})
        self.assertEqual(b["costs"]["runtime"]["cumulative"]["accountable"]["usdMicros"], 2 * 12600)
        self.assertEqual(b["costs"]["runtime"]["thisCase"]["accountable"]["usdMicros"], 12600)
        self.assertEqual(b["costs"]["spendBook"]["committed"], 2 * 12000)
        self.assertEqual(sum(1 for _ in (self.state / "spend-book.jsonl").read_text().splitlines()) > 0, True)
        # a later invocation with a new eval identity reuses the same files without a call-key collision
        code, rep2, _ = self.run_json(self.argv("--repeat", "1", cases=["o--r--1"]), transport=m)
        self.assertEqual((code, rep2["cases"][0]["status"]), (0, "completed"))
        self.assertEqual(rep2["cases"][0]["costs"]["runtime"]["cumulative"]["accountable"]["usdMicros"], 3 * 12600)

    def test_stops_after_a_failed_case_unless_keep_going(self):
        m = self.model(fail_with=HttpResponse(500, {}, b"{}"))
        code, rep, _ = self.run_json(self.argv(), transport=m)
        self.assertEqual(code, 1)
        self.assertEqual(len(rep["cases"]), 1)
        self.assertEqual(rep["notRun"], ["o--r--2"])
        code, rep, _ = self.run_json(self.argv("--keep-going"), transport=self.model(fail_with=HttpResponse(500, {}, b"{}")))
        self.assertEqual(len(rep["cases"]), 2)


class Failures(Rig):
    def test_provider_failure_is_an_honest_failed_result_with_unknown_spend_kept(self):
        m = self.model(fail_with=HttpResponse(500, {}, b'{"error":{"message":"x"}}'))
        code, rep, _ = self.run_json(self.argv(), transport=m)
        c = rep["cases"][0]
        self.assertEqual(code, 1)
        self.assertNotEqual(c["status"], "completed")
        self.assertTrue(c["incomplete"] or c["error"])
        self.assertTrue(Path(c["paths"]["review"]).exists())
        self.assertEqual(c["counts"]["comments"], 0)
        n = len(m.requests)
        code, rep2, _ = self.run_json(self.argv(), transport=m)                # finished failed run: no new call
        self.assertEqual(len(m.requests), n)
        self.assertEqual(rep2["cases"][0]["status"], c["status"])

    def test_interrupted_recording_fails_closed(self):
        class Crash(BaseException):
            pass

        calls = []

        def crash(req):
            calls.append(req)
            raise Crash()

        with self.assertRaises(Crash):
            self.run_main(self.argv(), transport=crash)
        self.assertEqual(list((self.out / "work").iterdir()), [])              # work tree still discarded
        n = len(calls)
        code, rep, _ = self.run_json(self.argv(), transport=crash)
        self.assertEqual(code, 1)
        self.assertEqual(rep["cases"][0]["error"]["code"], "recovery-required")
        self.assertEqual(len(calls), n)
        self.assertGreater(len([r for r in self.ledger_rows() if r["type"] == "intent"]), 0)   # reservation kept
        # explicit new identity is allowed (operator decision), under a fresh scope
        code, rep, _ = self.run_json(self.argv("--repeat", "1"), transport=self.model())
        self.assertEqual(code, 0)

    def test_missing_state_files_refuse_before_the_key_is_read(self):
        (self.state / "runtime-ledger.jsonl").unlink()
        code, _, err = self.run_main(self.argv(), transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 2)
        self.assertIn("fresh aggregate", err)
        self.assertFalse((self.state / "runtime-ledger.jsonl").exists())

    def test_wrong_and_missing_pins_refuse_before_the_key_is_read(self):
        pf = self.pins / "o--r--1.json"
        pf.chmod(0o600)
        doc = json.loads(pf.read_text())
        doc["origin"]["headSha"] = "c" * 40
        pf.write_text(json.dumps(doc))
        code, rep, err = self.run_json(self.argv(), transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 1)
        self.assertTrue(rep["cases"][0]["refused"])
        pf.unlink()
        code, _, err = self.run_main(self.argv(), transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 2)
        self.assertFalse(self.out.exists() and any((self.out / "runs").iterdir()))

    def test_pins_of_another_case_are_refused(self):
        other = self.corpus / "o--r--2"
        os.rename(self.corpus / "o--r--1", other)
        (self.pins / "o--r--2.json").write_text((self.pins / "o--r--1.json").read_text())
        code, rep, _ = self.run_json(self.argv(cases=["o--r--2"]), transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 2 if rep is None else 1)

    def test_baseline_mismatch_refuses_and_match_passes(self):
        from reviewer.contracts.canonical import digest
        pins = json.loads((self.pins / "o--r--1.json").read_text())
        base = {"schema": "operator-pin-baseline@1", "records": [
            {"action": "captured", "case": "o--r--1", "pinsDigest": digest(pins), "pinsPath": "/nonexistent/x"}]}
        bf = self.tmp / "baseline.json"
        bf.write_text(json.dumps(base))
        code, rep, _ = self.run_json(self.argv("--pins-baseline", str(bf), live=False), key_loader=boom_key_loader)
        self.assertEqual(code, 0)
        base["records"][0]["pinsDigest"] = "sha256:" + "0" * 64
        bf.write_text(json.dumps(base))
        code, _, err = self.run_main(self.argv("--pins-baseline", str(bf), live=False), key_loader=boom_key_loader)
        self.assertEqual(code, 2)
        self.assertIn("baseline", err)


class Containment(Rig):
    def refused(self, argv, needle):
        code, _, err = self.run_main(argv, transport=self.model(), key_loader=boom_key_loader)
        self.assertEqual(code, 2, err)
        self.assertIn(needle, err)

    def swap(self, argv, flag, value):
        a = list(argv)
        a[a.index(flag) + 1] = str(value)
        return a

    def test_out_dir_placement(self):
        for bad in (self.corpus / "x", self.corpus, self.tmp, Path(__file__).resolve().parents[2] / "reviewer" / "x"):
            self.refused(self.swap(self.argv(), "--out", bad), "outside")

    def test_operator_paths_must_be_outside_corpus_and_out(self):
        inside = self.corpus / "o--r--1" / "pins"
        inside.mkdir()
        self.refused(self.swap(self.argv(), "--pins-dir", inside), "pins must lie outside the corpus")
        a = self.argv()
        self.refused(self.swap(a, "--state-dir", self.corpus), "state must lie outside the corpus")
        (self.out).mkdir()
        self.refused(self.swap(a, "--env", self.out / ".env"), "env must lie outside the output")
        self.refused(self.swap(a, "--auth", self.corpus / "a.json"), "auth must lie outside the corpus")

    def test_corpus_and_pins_are_unchanged_after_a_live_run(self):
        before = tree_listing(self.corpus), tree_listing(self.pins)
        digest = lambda root: {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        d0 = digest(self.corpus), digest(self.pins)
        self.run_main(self.argv(), transport=self.model())
        self.assertEqual((tree_listing(self.corpus), tree_listing(self.pins)), before)
        self.assertEqual((digest(self.corpus), digest(self.pins)), d0)

    def test_case_ids_cannot_traverse(self):
        for bad in ("../x", "a/b", ".hidden", ""):
            code, _, err = self.run_main(self.argv(cases=[bad]), key_loader=boom_key_loader)
            self.assertEqual(code, 2)


class Replay(Rig):
    def test_replay_with_operator_digest_uses_no_provider_key_or_auth(self):
        m = self.model()
        code, rep, _ = self.run_json(self.argv(), transport=m)
        c = rep["cases"][0]
        digest = c["traceDigest"]["value"]                                    # stands in for the operator-held pin
        out2 = self.tmp / "out2"
        a = ["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--out", str(out2), "--case", "o--r--1",
             "--replay-trace", c["paths"]["trace"], "--trace-digest", digest]
        n = len(m.requests)
        with mock.patch.object(HttpsTransport, "__call__", side_effect=AssertionError("network")):
            code, rep2, err = self.run_json(a, transport=None, key_loader=boom_key_loader)
        self.assertEqual((code, err), (0, ""))
        r = rep2["cases"][0]
        self.assertEqual((r["status"], r["mode"], r["providerCalls"]), ("completed", "replay", 0))
        self.assertEqual(r["counts"], c["counts"])
        self.assertEqual(len(m.requests), n)
        self.assertIsNone(r["costs"]["runtime"])
        # wrong digest -> refusal; missing digest -> usage error
        bad = a[:-1] + ["sha256:" + "1" * 64]
        code, rep3, _ = self.run_json(bad)
        self.assertEqual((code, rep3["cases"][0]["refused"]), (1, True))
        code, _, err = self.run_main(a[:-2])
        self.assertEqual(code, 2)

    def test_replay_rejects_auth_and_multiple_cases(self):
        a = ["--corpus-root", str(self.corpus), "--pins-dir", str(self.pins), "--out", str(self.out), "--case", "o--r--1",
             "--replay-trace", "t", "--trace-digest", "sha256:" + "1" * 64]
        self.assertEqual(self.run_main(a + ["--auth", str(self.auth)])[0], 2)


class Profile(unittest.TestCase):
    def test_live_profile_and_plan(self):
        p = live_profile()
        plan = live_plan(p)
        for r in p["roles"].values():
            self.assertEqual((r["provider"], r["model"]), ("anthropic", "anthropic/claude-sonnet-5.5"))
            self.assertGreater(r["caps"]["maxOutputTokens"], 0)
            self.assertEqual((r["caps"]["maxRetries"], r["caps"]["maxRepairs"]), (0, 0))
            self.assertEqual(r["fallbacks"], [])
        self.assertEqual(plan["budget"]["maxUsdMicros"], 4_000_000)
        self.assertEqual(plan["budget"]["maxRetriesPerCall"], 0)
        self.assertEqual((plan["budget"]["maxToolCalls"], plan["budget"]["maxToolCallsPerAgent"]), (60, 30))
        self.assertEqual(plan["modelProfile"], "pilot-live@1")

    def test_model_and_caps_are_validated(self):
        for kw in ({"model": "anthropic/claude-sonnet-5"}, {"model": "openai/gpt-5"},
                   {"output_caps": {"judge": 0}}, {"output_caps": {"judge": 10**7}}):
            with self.assertRaises(ProfileError):
                live_profile(**kw)

    def test_modes_are_exclusive(self):
        o = PilotOptions("c", "p", "o", ("x",), mode="live", auth="a")
        with self.assertRaises(PilotError):
            run_cases(o)


if __name__ == "__main__":
    unittest.main()
