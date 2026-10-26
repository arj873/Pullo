"""S0-05: verified trace loading, strict replay (fail closed), equivalence and source hygiene."""

from __future__ import annotations

import copy
import json
import re
import socket
import threading
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import validate_trace
from reviewer.contracts.canonical import (call_id, comparable_digest, cost_id, digest, request_hash,
                                          result_hash, tool_call_id)
from reviewer.gateway import (Gateway, GatewayConfigError, Recorder, SpendBook, TraceError, load_trace,
                              verify_events)
from tests.gateway.helpers import BUDGET, PROFILE, ZERO, Env, entry, profile, request, response, script, terr, verifier_out

TOOL_RESULT = {"status": "ok", "evidence": [], "completeness": "exact", "truncated": None, "notice": "ok"}
H = hash("x")


class Rec(Env):
    """Records a small run: investigate + two verifier calls + a tool call; returns the events."""

    def record(self, *, extra_entries=(), budget=None, with_tool=True, **kw):
        entries = [entry(response=response()),
                   entry(stage="VERIFY", role="verifier", agent="verifier", ordinal=0,
                         response=response(output=verifier_out("confirmed"))),
                   entry(stage="VERIFY", role="verifier", agent="verifier", ordinal=1, error=terr("provider-timeout")),
                   entry(stage="VERIFY", role="verifier", agent="verifier", ordinal=1, attempt=1,
                         response=response(output=verifier_out("refuted"))), *extra_entries]
        gw = self.live(script(*entries), budget=budget, **kw)
        gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        gw.call("VERIFY", "verifier", "verifier", 0, request("verifier", text="candidate 0"))
        gw.call("VERIFY", "verifier", "verifier", 1, request("verifier", text="candidate 1"))
        if with_tool:
            args = {"path": "src/a.py"}
            tid = tool_call_id("VERIFY", "verifier", 0, "read-file", args)
            gw.recorder.append("tool.call", toolCallId=tid, stage="VERIFY", agentId="verifier", ordinal=0,
                               tool="read-file", args=args, resultHash=result_hash(TOOL_RESULT), result=TOOL_RESULT,
                               redactions={})
        return self.finish(gw)


class TraceVerifyTests(Rec):
    def setUp(self):
        super().setUp()
        self.events = self.record()

    def tamper(self, fn, why):
        ev = copy.deepcopy(self.events)
        fn(ev)
        with self.assertRaises(TraceError, msg=why):
            load_trace(ev)

    def idx(self, type_, n=0):
        return [i for i, e in enumerate(self.events) if e["type"] == type_][n]

    def test_untouched_recording_loads_and_has_all_hashes_recomputable(self):
        tr = load_trace(self.events)
        self.assertEqual(tr.model_calls, 4)
        self.assertEqual(validate_trace(self.events), [])
        for e in self.events:
            if e["type"] == "model.call":
                self.assertEqual(e["requestHash"], request_hash(e["request"]))
                self.assertEqual(e["costRecordId"], cost_id(e["callId"]))

    def test_each_payload_edit_is_detected_even_though_it_is_schema_valid(self):
        m = self.idx("model.call")
        t = self.idx("tool.call")
        c = self.idx("cost")
        cases = {
            "request edited after hashing": lambda ev: ev[m]["request"]["messages"][1].__setitem__("content", "different diff"),
            "requestHash replaced": lambda ev: ev[m].__setitem__("requestHash", "sha256:" + "0" * 64),
            "requestHash swapped with another call's": lambda ev: ev[m].__setitem__("requestHash", ev[self.idx("model.call", 1)]["requestHash"]),
            "callId replaced": lambda ev: ev[m].__setitem__("callId", "call_" + "0" * 16),
            "ordinal changed": lambda ev: ev[m].__setitem__("ordinal", 7),
            "attempt changed": lambda ev: ev[m].__setitem__("attempt", 3),
            "costRecordId replaced": lambda ev: ev[m].__setitem__("costRecordId", "cost_" + "0" * 16),
            "tool args edited": lambda ev: ev[t]["args"].__setitem__("path", "src/b.py"),
            "toolCallId replaced": lambda ev: ev[t].__setitem__("toolCallId", "tool_" + "0" * 16),
            "tool result edited": lambda ev: ev[t]["result"].__setitem__("notice", "tampered"),
            "resultHash replaced": lambda ev: ev[t].__setitem__("resultHash", "sha256:" + "0" * 64),
            "cost usage differs from response": lambda ev: ev[c]["record"]["usage"].__setitem__("outputTokens", 5),
            "cost record names another call": lambda ev: ev[c]["record"].update(callId=ev[self.idx("model.call", 1)]["callId"],
                                                                                 id=cost_id(ev[self.idx("model.call", 1)]["callId"])),
            "cost provider differs": lambda ev: ev[c]["record"].__setitem__("provider", "openai"),
            "cost event removed": lambda ev: ev.pop(c),
            "request role differs": lambda ev: ev[m]["request"].__setitem__("role", "judge"),
            "unredacted secret": lambda ev: ev[m]["request"]["messages"][1].__setitem__("content", "k ghp_" + "A1b2C3d4" * 5),
            "errored call carrying usage": lambda ev: ev[self.idx("cost", 2)]["record"]["usage"].__setitem__("outputTokens", 9),
        }
        for why, fn in cases.items():
            with self.subTest(why):
                ev = copy.deepcopy(self.events)
                fn(ev)
                with self.assertRaises(TraceError):
                    load_trace(ev)

    def test_structural_damage_is_detected(self):
        ev = copy.deepcopy(self.events)
        dup = copy.deepcopy(ev[self.idx("model.call")])
        ev.insert(self.idx("model.call") + 1, dup)
        for i, e in enumerate(ev):
            e["seq"] = i
        with self.assertRaises(TraceError):
            load_trace(ev)
        for bad in (self.events[:-1][1:], [], self.events[::-1], [{"type": "x"}]):
            with self.assertRaises(TraceError):
                load_trace(bad)

    def test_file_loading_is_strict(self):
        p = self.tmp / "t.jsonl"
        good = "\n".join(json.dumps(e, sort_keys=True) for e in self.events) + "\n"
        p.write_text(good)
        self.assertEqual(load_trace(p).model_calls, 4)
        self.assertEqual(load_trace(good.encode()).model_calls, 4)
        for name, text in {"dup key": good.replace('"seq": 1,', '"seq": 1, "seq": 1,', 1), "blank line": good.replace("\n", "\n\n", 1),
                           "garbage": good + "{nope\n", "truncated": good[: len(good) // 2], "nan": good.replace('"seq": 2', '"seq": NaN', 1),
                           "empty": ""}.items():
            q = self.tmp / f"{name}.jsonl"
            q.write_text(text)
            with self.subTest(name), self.assertRaises(TraceError):
                load_trace(q)
        with self.assertRaises(TraceError):
            load_trace(self.tmp / "missing.jsonl")
        (self.tmp / "ln.jsonl").symlink_to(p)
        with self.assertRaises(TraceError):
            load_trace(self.tmp / "ln.jsonl")
        with self.assertRaises(TraceError):
            load_trace(b"\xff\xfe")


class ReplayTests(Rec):
    def setUp(self):
        super().setUp()
        self.events = self.record()

    def replay_all(self, gw):
        a = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        b = gw.call("VERIFY", "verifier", "verifier", 0, request("verifier", text="candidate 0"))
        c = gw.call("VERIFY", "verifier", "verifier", 1, request("verifier", text="candidate 1"))
        return a, b, c

    def test_exact_replay_zero_real_calls_identical_outputs(self):
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("network used")):
            gw = self.replayer(self.events)
            a, b, c = self.replay_all(gw)
        self.assertEqual((a.output, b.output["verdict"], c.output["verdict"]), (response()["output"], "confirmed", "refuted"))
        self.assertEqual([len(x.attempts) for x in (a, b, c)], [1, 1, 2])          # the recorded timeout is replayed too
        self.assertEqual(c.attempts[0].outcome, "provider-timeout")
        rep = gw.report()
        self.assertEqual((rep["liveCalls"], rep["replayedCalls"], rep["newSpendUsdMicros"], rep["unconsumedRecordedCalls"]),
                         (0, 4, 0, 0))
        self.assertEqual(gw.providers, {})                                          # no adapter exists to call
        self.assertGreater(rep["replayedUsdMicros"], 0)

    def test_replayed_trace_is_valid_and_comparable_to_the_recording(self):
        gw = self.replayer(self.events)
        self.replay_all(gw)
        new = gw.recorder.events
        self.assertEqual(validate_trace(new + [{"schema": "trace-event@1", "runId": gw.run_id, "seq": len(new),
                                                "type": "run.end", "status": "completed", "incomplete": []}]), [])
        rec_calls = [e for e in self.events if e["type"] in ("model.call", "cost")]
        new_calls = [e for e in new if e["type"] in ("model.call", "cost")]
        self.assertEqual([comparable_digest(e) for e in rec_calls], [comparable_digest(e) for e in new_calls])
        for e in new_calls:
            if e["type"] == "cost":
                r = e["record"]
                self.assertEqual(r["basis"], "replayed")
                self.assertEqual(r["replayOf"], r["id"])                              # names the recorded CostRecord
                self.assertEqual(r["runId"], gw.run_id)
                self.assertNotEqual(r["runId"], self.events[0]["runId"])
            else:
                self.assertNotIn("run_", json.dumps(e["request"]))

    def test_recording_provenance_is_preserved(self):
        costs = [e["record"] for e in self.events if e["type"] == "cost"]
        self.assertEqual({c["basis"] for c in costs}, {"synthetic"})
        self.assertEqual([c["usdMicros"] for c in costs], [c["reservedUsdMicros"] for c in costs])   # unknown usage

    def test_caller_cannot_alter_the_recording_through_returned_data(self):
        gw = self.live(script(entry(response=response())))
        r = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        r.response["output"]["hypotheses"].append("injected")
        r.response["usage"]["outputTokens"] = 99
        ev = self.finish(gw)
        self.assertEqual(next(e for e in ev if e["type"] == "model.call")["response"]["output"], {"hypotheses": []})
        load_trace(ev)

    def test_replay_misses_fail_closed(self):
        gw = self.replayer(self.events)
        miss = gw.call("INVESTIGATE", "investigator", "generalist", 0, request(text="never recorded"))
        self.assertEqual(miss.error["code"], "replay-miss")
        self.assertIsNone(miss.response)
        a = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        self.assertTrue(a.ok)
        again = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())     # occurrence exhausted
        self.assertEqual(again.error["code"], "replay-miss")
        self.assertEqual(gw.report()["liveCalls"], 0)

    def test_same_hash_under_another_call_identity_is_a_mismatch_not_a_guess(self):
        gw = self.replayer(self.events)
        r = gw.call("INVESTIGATE", "investigator", "someone-else", 0, request())
        self.assertEqual(r.error["code"], "replay-mismatch")
        r = gw.call("INVESTIGATE", "investigator", "generalist", 5, request())
        self.assertEqual(r.error["code"], "replay-mismatch")
        self.assertTrue(gw.call("INVESTIGATE", "investigator", "generalist", 0, request()).ok)

    def test_unconsumed_recorded_calls_are_reported(self):
        gw = self.replayer(self.events)
        gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        self.assertEqual(gw.unconsumed(), 3)

    def test_profile_or_price_drift_is_detected_not_silently_replayed(self):
        price = {**PROFILE["roles"]["investigator"]["price"], "outputPerMTokUsdMicros": 99_000_000}
        gw = self.replayer(self.events, prof=profile(investigator={"price": price}))
        r = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        self.assertEqual(r.error["code"], "replay-mismatch")
        caps = {"caps": {**PROFILE["roles"]["investigator"]["caps"], "maxOutputTokens": 3999}}
        gw = self.replayer(self.events, prof=profile(investigator=caps))
        self.assertEqual(gw.call("INVESTIGATE", "investigator", "generalist", 0, request()).error["code"], "replay-mismatch")

    def test_every_request_is_checked_in_replay_too(self):
        gw = self.replayer(self.events)
        for req in (request(model="gpt-elsewhere"), request(provider="openai"), request(profile="x@1")):
            self.assertEqual(gw.call("INVESTIGATE", "investigator", "generalist", 0, req).error["code"], "contract-violation")

    def test_budget_exhaustion_reproduces_exactly(self):
        small = {**BUDGET, "maxUsdMicros": 100_000, "verifyReserveBp": 0}
        ev = self.record(budget=small, with_tool=False)
        refused = [e for e in ev if e["type"] == "model.call" and e.get("error", {}).get("code") == "budget-exhausted"]
        self.assertTrue(refused)
        gw = self.replayer(ev, budget=small)
        a, b, c = self.replay_all(gw)
        self.assertTrue(a.ok)
        self.assertEqual(b.error["code"], "budget-exhausted")
        self.assertEqual(gw.report()["unconsumedRecordedCalls"], 0)
        gw = self.replayer(ev, budget=BUDGET)                    # more budget now: admission differs -> fail closed
        gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        self.assertEqual(gw.call("VERIFY", "verifier", "verifier", 0, request("verifier", text="candidate 0")).error["code"], "replay-mismatch")

    def test_replay_config_rules(self):
        tr = load_trace(self.events)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id="run_" + "1" * 16)       # no trace
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id="run_" + "1" * 16, replay=tr,
                    authorization=self.handle())
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id="run_" + "1" * 16, replay=tr,
                    providers={"synthetic": object()})
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id="run_" + "1" * 16, replay=self.events)

    def test_replay_of_a_replay_trace_round_trips(self):
        gw = self.replayer(self.events)
        self.replay_all(gw)
        gw.recorder.end("completed")
        tr2 = load_trace(gw.recorder.events)
        self.assertEqual(tr2.model_calls, 4)

    def test_concurrent_replay_is_deterministic_per_agent(self):
        n = 12
        entries = [entry(agent=f"agent-{i}", response=response(rawText=f"who-{i}")) for i in range(n)]
        gw = self.live(script(*entries), handle=self.handle(maxUsdMicrosPerRun=5_000_000, maxUsdMicrosTotal=50_000_000),
                       budget={**BUDGET, "maxUsdMicros": 5_000_000, "verifyReserveBp": 0})
        same = request()                                              # identical request from every agent
        for i in range(n):
            gw.call("INVESTIGATE", "investigator", f"agent-{i}", 0, same)
        ev = self.finish(gw)
        rp = self.replayer(ev, budget={**BUDGET, "maxUsdMicros": 5_000_000, "verifyReserveBp": 0})
        out = {}
        order = list(range(n))[::-1]
        def go(i):
            out[i] = rp.call("INVESTIGATE", "investigator", f"agent-{i}", 0, same)
        ts = [threading.Thread(target=go, args=(i,)) for i in order]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertTrue(all(out[i].ok and out[i].response["rawText"] == f"who-{i}" for i in range(n)))
        self.assertEqual(rp.report()["unconsumedRecordedCalls"], 0)


class HygieneTests(unittest.TestCase):
    def test_gateway_source_has_no_network_env_or_key_access(self):
        import io
        import tokenize
        root = Path(__file__).resolve().parents[2] / "reviewer/gateway"
        banned = {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "subprocess", "environ", "getenv",
                  "ssl", "anthropic", "openai"}
        for p in sorted(root.glob("*.py")):
            for tok in tokenize.generate_tokens(io.StringIO(p.read_text()).readline):
                if tok.type == tokenize.NAME and tok.string in banned:
                    self.fail(f"{p.name}:{tok.start[0]} uses {tok.string!r}")

    def test_public_api_surface(self):
        import reviewer.gateway as g
        for name in ("Gateway", "load_script", "parse_script", "load_trace", "trusted_authorization", "SpendBook",
                     "Recorder", "SyntheticProvider", "DisabledProvider", "typed_error", "verify_events"):
            self.assertTrue(hasattr(g, name), name)


if __name__ == "__main__":
    unittest.main()
