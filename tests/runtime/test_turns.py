"""S1-06a: Turn-schema selection, projection and normalization on the runtime adapters (fake HTTP / fake CLI only)."""
import copy
import hashlib
import json
import unittest

from reviewer.gateway import load_trace
from reviewer.runtime import schemas
from reviewer.runtime.openrouter import HttpResponse
from reviewer.runtime.codex_cli import RunResult
from tests.runtime.test_codex import Base as CodexBase, KEY as CKEY, events
from tests.runtime.common import OK_INV, OK_VERIFY, PROFILE, RT, FakeTransport, completion, req

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)
REQUESTING = {"contextRequests": [{"tool": "read_file", "args": {"path": "src/a.py", "start": 3, "deep": True, "tag": None},
                                   "purpose": "see the caller"}], "output": None}
FINAL_INV = {"contextRequests": [], "output": OK_INV}
FINAL_VER = {"contextRequests": [], "output": OK_VERIFY}
PLAIN_SHA = {   # pinned before S1-06a: plain projection bytes must not move
    "InvestigatorOutput/anthropic": "824b4c118d9f601df4139e872130747bf5185d00cb1d7342ca61dcd37981bc9c",
    "InvestigatorOutput/openai-strict": "3c7338a8680611d5427de59c48d6c3ac34952b887e2a12dea8f28c7ed93cdbab",
    "VerifierOutput/anthropic": "ff07e02bf15dbdd5737a14dc53897f355d8ff4716c37553c5d98ba8ad534aad0",
    "VerifierOutput/openai-strict": "c1777cf147cc1f58d1bed0e3c57dbff1f4453d711cace132f5aaf076959eab8a",
    "JudgeOutput/anthropic": "7de2745495a3bb21ef24fc8ebee9602dd2edd6b74764a8369e85b2d0ee5aead3",
    "JudgeOutput/openai-strict": "77944fa819e1ce5918ce7988e6d27b92a14f90ab6c830c79847505e246575faa"}


def turn_req(role="investigator", schema=None, **over):
    schema = schema or {"investigator": "InvestigatorTurn", "verifier": "VerifierTurn"}[role]
    return req(role, outputSchema=schema, **{"hop": 0, "contextResults": [], **over})


def to_wire(turn):
    """What a strict provider returns: args as key/value entries."""
    t = copy.deepcopy(turn)
    for c in t["contextRequests"]:
        if isinstance(c["args"], dict):
            c["args"] = [{"key": k, "value": v} for k, v in c["args"].items()]
    return t


class Selection(unittest.TestCase):
    def test_legal_pairs_follow_the_request_not_the_role(self):
        for role, name in [("investigator", "InvestigatorOutput"), ("investigator", "InvestigatorTurn"),
                           ("verifier", "VerifierOutput"), ("verifier", "VerifierTurn"), ("judge", "JudgeOutput")]:
            self.assertEqual(schemas.select_schema({"role": role, "outputSchema": name}), name)

    def test_off_diagonal_and_junk_are_refused_never_coerced(self):
        for role, name in [("investigator", "VerifierTurn"), ("verifier", "InvestigatorTurn"), ("judge", "InvestigatorTurn"),
                           ("judge", "VerifierTurn"), ("investigator", "JudgeOutput"), ("verifier", "InvestigatorOutput"),
                           ("planner", "InvestigatorTurn"), ("investigator", None), (None, "InvestigatorTurn")]:
            self.assertIsNone(schemas.select_schema({"role": role, "outputSchema": name}), (role, name))
        self.assertIsNone(schemas.select_schema(None))
        self.assertIsNone(schemas.select_schema({"role": ["investigator"], "outputSchema": "InvestigatorTurn"}))


class Projection(unittest.TestCase):
    def test_plain_projection_bytes_unchanged(self):
        snap = schemas.projection_snapshot()
        for k, sha in PLAIN_SHA.items():
            self.assertEqual(hashlib.sha256(json.dumps(snap[k], sort_keys=True).encode()).hexdigest(), sha, k)

    def test_turn_projection_has_no_open_objects_in_either_flavor(self):
        def walk(n):
            if isinstance(n, dict):
                self.assertNotIn("propertyNames", n)
                self.assertNotIn("maxProperties", n)
                if n.get("type") == "object":
                    self.assertIs(n.get("additionalProperties"), False)
                for v in n.values():
                    walk(v)
            elif isinstance(n, list):
                for v in n:
                    walk(v)
        for name in ("InvestigatorTurn", "VerifierTurn"):
            for flavor in ("anthropic", "openai-strict"):
                with self.subTest((name, flavor)):
                    walk(schemas.provider_schema(name, flavor))

    def test_args_projection_is_lossless_entries_and_tool_stays_free(self):
        for flavor in ("anthropic", "openai-strict"):
            item = schemas.provider_schema("InvestigatorTurn", flavor)["properties"]["contextRequests"]["items"]
            self.assertEqual(item["properties"]["tool"], {"type": "string"})      # not narrowed to the four tools
            args = item["properties"]["args"]
            self.assertEqual(args["type"], "array")
            self.assertEqual(args["items"]["required"], ["key", "value"])
            kinds = {a.get("type") for a in args["items"]["properties"]["value"]["anyOf"]}
            self.assertEqual(kinds, {"null", "boolean", "integer", "string"})

    def test_strict_flavor_requires_envelope_keys_and_keeps_output_nullable(self):
        s = schemas.provider_schema("InvestigatorTurn", "openai-strict")
        self.assertEqual(s["required"], ["contextRequests", "output"])
        self.assertEqual(s["properties"]["output"]["anyOf"][0], {"type": "null"})
        self.assertEqual(schemas.provider_schema("VerifierTurn", "anthropic")["required"], ["contextRequests", "output"])

    def test_snapshot_covers_turn_schemas(self):
        self.assertIn("VerifierTurn/openai-strict", schemas.projection_snapshot())
        self.assertEqual(schemas.PROJECTION_VERSION, "role-schema-projection@2")


class Normalization(unittest.TestCase):
    def norm(self, name, value, flavor="anthropic"):
        v = schemas.normalize_output(name, value, flavor)
        return v, schemas.local_issues(name, v)

    def test_requesting_and_final_round_trip_both_flavors(self):
        for flavor in ("anthropic", "openai-strict"):
            v, bad = self.norm("InvestigatorTurn", to_wire(REQUESTING), flavor)
            self.assertEqual((v, bad), (REQUESTING, []))
            self.assertIsNone(v["output"])
            self.assertEqual(v["contextRequests"][0]["args"]["tag"], None)      # null arg value is data, never stripped
            self.assertEqual(self.norm("InvestigatorTurn", FINAL_INV, flavor), (FINAL_INV, []))
            self.assertEqual(self.norm("VerifierTurn", FINAL_VER, flavor), (FINAL_VER, []))

    def test_strict_forced_nulls_inside_final_payload_are_removed(self):
        sample = {"contextRequests": [], "output": {"verdict": "uncertain", "reachable": False, "impact": "none",
                                                    "evidence": [], "notes": "n"}}
        forced = copy.deepcopy(sample)
        props = schemas.original("VerifierOutput")["properties"]
        optional = [k for k in props if k not in schemas.original("VerifierOutput").get("required", [])]
        for k in optional:
            forced["output"].setdefault(k, None)
        v, bad = self.norm("VerifierTurn", forced, "openai-strict")
        self.assertEqual((v, bad), (sample, []))

    def test_bad_envelopes_fail_locally(self):
        req0 = REQUESTING["contextRequests"]
        cases = {"both": {"contextRequests": req0, "output": OK_INV}, "neither": {"contextRequests": [], "output": None},
                 "missing output": {"contextRequests": []}, "extra key": {**FINAL_INV, "x": 1},
                 "requests not a list": {"contextRequests": "x", "output": None}, "seven requests": {"contextRequests": req0 * 7, "output": None},
                 "output not object": {"contextRequests": [], "output": "done"}, "bad payload": {"contextRequests": [], "output": {"hypotheses": "no"}},
                 "unwrapped payload": OK_INV}
        for why, doc in cases.items():
            with self.subTest(why):
                self.assertTrue(self.norm("InvestigatorTurn", to_wire(doc) if "contextRequests" in doc and isinstance(doc["contextRequests"], list) else doc)[1])

    def test_bad_args_are_left_for_local_rejection_never_dropped_or_merged(self):
        def with_args(args):
            d = to_wire(REQUESTING)
            d["contextRequests"][0]["args"] = args
            return d
        ent = lambda k, v: {"key": k, "value": v}
        for why, args in {"duplicate key": [ent("a", 1), ent("a", 2)], "nested value": [ent("a", {"b": 1})],
                          "list value": [ent("a", [1])], "float": [ent("a", 1.5)], "bad key": [ent("Bad-Key", 1)],
                          "extra entry field": [{"key": "a", "value": 1, "z": 1}], "missing value": [{"key": "a"}],
                          "scalar entry": ["a"], "int key": [ent(1, 1)]}.items():
            with self.subTest(why):
                v, bad = self.norm("InvestigatorTurn", with_args(args))
                self.assertTrue(bad)

    def test_contract_shaped_object_args_are_also_accepted(self):
        d = to_wire(REQUESTING)
        d["contextRequests"][0]["args"] = {"path": "x"}      # already the authoritative shape: valid, unchanged
        self.assertEqual(self.norm("InvestigatorTurn", d)[1], [])

    def test_unknown_tool_and_arg_names_are_grammatical_data(self):
        doc = {"contextRequests": [{"tool": "run-shell", "args": [{"key": "cmd", "value": "rm -rf /"}], "purpose": "p"}], "output": None}
        v, bad = self.norm("InvestigatorTurn", doc)
        self.assertEqual((bad, v["contextRequests"][0]["tool"], v["contextRequests"][0]["args"]), ([], "run-shell", {"cmd": "rm -rf /"}))

    def test_plain_outputs_unchanged(self):
        self.assertEqual(self.norm("InvestigatorOutput", OK_INV), (OK_INV, []))
        self.assertEqual(self.norm("VerifierOutput", OK_VERIFY, "openai-strict"), (OK_VERIFY, []))


class OpenRouterPayload(RT):
    def body(self, r):
        p = self.provider()
        b, info = p.build_body(r)
        self.assertIsNotNone(b, info)
        return b

    def test_schema_follows_request_for_every_legal_pair(self):
        for r, name in [(req(), "InvestigatorOutput"), (turn_req(), "InvestigatorTurn")]:
            rf = self.body(r)["response_format"]["json_schema"]
            self.assertEqual((rf["name"], rf["strict"]), (name, True))
            self.assertEqual(rf["schema"], schemas.provider_schema(name, "anthropic"))
        self.assertEqual(self.body(turn_req())["response_format"]["json_schema"]["schema"]["required"], ["contextRequests", "output"])

    def test_same_schema_every_hop_and_tools_never_sent(self):
        hop1 = turn_req(hop=1, continuationOf="call_" + "0" * 16, contextResults=["tool_" + "1" * 16])
        a, b = self.body(turn_req()), self.body(hop1)
        self.assertEqual(a["response_format"], b["response_format"])
        for body in (a, b):
            self.assertNotIn("tools", body)
            self.assertNotIn("tool_choice", body)

    def test_turn_request_with_tools_or_off_diagonal_pair_is_refused_unsent(self):
        p = self.provider()
        for why, r in {"tools": turn_req(tools=[{"name": "read_file"}]),
                       "investigator asks verifier turn": turn_req(schema="VerifierTurn"),
                       "judge asks turn": req("judge", outputSchema="InvestigatorTurn"),
                       "verifier plain->turn mix": req("investigator", outputSchema="VerifierOutput")}.items():
            with self.subTest(why):
                res = p.call(r, KEY)
                self.assertEqual((res.outcome, res.error["code"]), ("not-sent", "provider-error"))
        self.assertEqual(self.transport.requests, [])
        self.assertEqual(self.receipts(), [])

    def call(self, content, r=None):
        p = self.provider(FakeTransport(completion(json.dumps(content) if not isinstance(content, str) else content)))
        res = p.call(r or turn_req(), KEY)
        self.assertEqual(res.outcome, "processed")
        return res

    def test_requesting_turn_recorded_as_complete_envelope(self):
        res = self.call(to_wire(REQUESTING))
        self.assertEqual((res.response["status"], res.response["output"]), ("ok", REQUESTING))
        sent = json.loads(self.transport.requests[0].body)
        self.assertEqual(sent["response_format"]["json_schema"]["name"], "InvestigatorTurn")

    def test_receipt_carries_projection_digest_and_raw_content_digest(self):
        raw = json.dumps(to_wire(REQUESTING))
        self.call(raw)
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual((rec["schemaProjection"], rec["schemaName"]), ("role-schema-projection@2", "InvestigatorTurn"))
        want = hashlib.sha256(json.dumps(schemas.provider_schema("InvestigatorTurn", "anthropic"), sort_keys=True).encode()).hexdigest()
        self.assertEqual(rec["schemaSha256"], want)
        self.assertEqual(rec["contentSha256"], hashlib.sha256(raw.encode()).hexdigest())     # raw wire form (entries) auditable
        self.assertEqual(self.transport.requests and json.loads(self.transport.requests[0].body)["response_format"]["json_schema"]["schema"],
                         schemas.provider_schema("InvestigatorTurn", "anthropic"))

    def test_ok_turn_keeps_original_provider_json_beside_normalized_envelope(self):
        raw = json.dumps(to_wire(REQUESTING))
        res = self.call(raw)
        self.assertEqual(res.response["output"], REQUESTING)                      # normalized, complete, dict args
        self.assertEqual(res.response["rawText"], raw)                            # original entry-form JSON, bounded copy
        self.assertEqual(json.loads(res.response["rawText"])["contextRequests"][0]["args"][0], {"key": "path", "value": "src/a.py"})
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual(rec["contentSha256"], hashlib.sha256(raw.encode()).hexdigest())

    def test_plain_ok_answers_keep_rawtext_null(self):
        self.assertIsNone(self.call(OK_INV, req()).response["rawText"])

    def test_turn_rawtext_is_key_scrubbed_and_truncated_but_hash_covers_original(self):
        from tests.runtime.common import FAKE_KEY
        from reviewer.runtime import openrouter as orm
        doc = {"contextRequests": [{"tool": "search", "args": [{"key": "q", "value": FAKE_KEY}], "purpose": "p"}], "output": None}
        res = self.call(json.dumps(doc))
        self.assertEqual(res.response["status"], "ok")
        self.assertNotIn(FAKE_KEY, res.response["rawText"])
        self.assertNotIn(FAKE_KEY, self.ledger_path.read_text())
        self.setUp()
        pad = json.dumps({"contextRequests": [{"tool": "search", "args": [{"key": "q", "value": "x" * 4000}] * 400, "purpose": "p"}], "output": None})
        self.assertGreater(len(pad), orm.MAX_RAW_TEXT)
        res = self.call(pad)
        self.assertEqual(res.response["status"], "invalid-output")                # over-long args fail locally
        self.assertEqual(len(res.response["rawText"]), orm.MAX_RAW_TEXT)
        rec = [x for x in self.receipts() if x["type"] == "result"][0]
        self.assertEqual(rec["contentSha256"], hashlib.sha256(pad.encode()).hexdigest())   # full original, not the cut copy

    def test_final_turn_is_the_envelope_not_the_payload(self):
        res = self.call(FINAL_INV)
        self.assertEqual(res.response["output"], FINAL_INV)
        self.assertNotEqual(res.response["output"], OK_INV)

    def test_unknown_tool_request_is_accepted_for_the_host_to_deny(self):
        doc = {"contextRequests": [{"tool": "web_fetch", "args": [], "purpose": "p"}], "output": None}
        self.assertEqual(self.call(doc).response["status"], "ok")

    def test_legacy_plain_profile_still_works(self):
        res = self.call(OK_INV, req())
        self.assertEqual((res.response["status"], res.response["output"]), ("ok", OK_INV))

    def test_invalid_envelopes_are_charged_invalid_output_with_receipt(self):
        bad = {"requests+output": {"contextRequests": REQUESTING["contextRequests"], "output": OK_INV},
               "empty both": {"contextRequests": [], "output": None},
               "plain payload unwrapped": OK_INV, "string output": {"contextRequests": [], "output": "x"}}
        for why, doc in bad.items():
            with self.subTest(why):
                self.setUp()
                if "contextRequests" in doc and doc["contextRequests"]:
                    doc = to_wire(doc)
                res = self.call(doc)
                self.assertEqual((res.response["status"], res.response["output"]), ("invalid-output", None))
                self.assertIsNotNone(res.response["rawText"])
                rec = [x for x in self.receipts() if x["type"] == "result"]
                self.assertEqual(len(rec), 1)
                self.assertEqual(rec[0]["note"], "invalid-output")
                self.assertEqual(rec[0]["outcome"], "processed")
                self.assertGreater(self.ledger.totals()["knownUsdMicros"], 0)       # still charged

    def test_nonscalar_arg_value_fails_locally(self):
        doc = to_wire(REQUESTING)
        doc["contextRequests"][0]["args"][0]["value"] = {"nested": 1}
        self.assertEqual(self.call(doc).response["status"], "invalid-output")


class CodexMapping(CodexBase):
    """Mapping only (Terra stays held; fake runner, no process): Turn requests select the schema and project strict."""

    def run_turn(self, schema, final):
        p = self.prov(RunResult(0, events(json.dumps(final)), b""))
        return p.call(req("verifier", outputSchema=schema, hop=0, contextResults=[]), CKEY)

    def test_verifier_turn_requesting_and_final(self):
        res = self.run_turn("VerifierTurn", to_wire(REQUESTING))
        self.assertEqual((res.response["status"], res.response["output"]), ("ok", REQUESTING))
        sch = self.runner.seen[0]["schema"]
        self.assertEqual(sch["required"], ["contextRequests", "output"])
        self.assertEqual(self.run_turn("VerifierTurn", FINAL_VER).response["output"], FINAL_VER)

    def test_invalid_turn_is_charged_invalid_output_and_plain_still_works(self):
        res = self.run_turn("VerifierTurn", {"contextRequests": [], "output": None})
        self.assertEqual((res.response["status"], res.response["output"]), ("invalid-output", None))
        self.assertEqual(self.run_turn("VerifierOutput", OK_VERIFY).response["output"], OK_VERIFY)

    def test_off_diagonal_pair_refused_unsent(self):
        p = self.prov()
        res = p.call(req("verifier", outputSchema="InvestigatorTurn"), CKEY)
        self.assertEqual((res.outcome, res.error["code"]), ("not-sent", "provider-error"))
        self.assertEqual(self.runner.seen, [])


class ThroughGatewayTurns(RT):
    def turn_gateway(self, *items):
        p = self.provider(FakeTransport(*items))
        gw = self.gateway(p)
        prof = copy.deepcopy(PROFILE)
        prof["roles"]["investigator"]["outputSchema"] = "InvestigatorTurn"
        gw.profile = prof
        return gw

    def test_requesting_then_repair_both_charged_and_trace_keeps_envelopes(self):
        bad = {"contextRequests": REQUESTING["contextRequests"] and to_wire(REQUESTING)["contextRequests"], "output": OK_INV}
        gw = self.turn_gateway(completion(json.dumps(bad)), completion(json.dumps(to_wire(REQUESTING))))
        res = gw.call("INVESTIGATE", "investigator", "generalist", 0, turn_req(), repair=lambda resp: turn_req(text="repair"))
        self.assertTrue(res.ok, res.error)
        self.assertEqual(len(res.attempts), 2)
        self.assertEqual(len(self.transport.requests), 2)
        names = {json.loads(t.body)["response_format"]["json_schema"]["name"] for t in self.transport.requests}
        self.assertEqual(names, {"InvestigatorTurn"})                      # repair keeps the chain's schema
        self.assertEqual(len([r for r in self.receipts() if r["type"] == "result"]), 2)
        gw.recorder.end("completed")
        events = load_trace(gw.recorder.events)
        outs = [e["response"]["output"] for e in gw.recorder.events if e.get("type") == "model.call" and e.get("response")]
        self.assertIn(REQUESTING, outs)                                     # whole envelope, not unwrapped
        self.assertIsNotNone(events)

    def test_final_turn_through_gateway(self):
        gw = self.turn_gateway(completion(json.dumps(FINAL_INV)))
        res = gw.call("INVESTIGATE", "investigator", "generalist", 0, turn_req())
        self.assertTrue(res.ok, res.error)
        gw.recorder.end("completed")
        load_trace(gw.recorder.events)


if __name__ == "__main__":
    unittest.main()
