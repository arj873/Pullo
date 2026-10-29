"""Independent S1-06a review: Turn envelope selection, projection, normalization, charging and receipts.

Fake HTTP / fake key only. No network, no real key, no operator state. The author's fixtures are reused as builders;
the author's tests are not re-run from here."""
from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import is_turn_schema
from reviewer.gateway import load_trace
from reviewer.runtime import schemas
from reviewer.runtime.openrouter import HttpResponse, TransportTimeout
from reviewer.runtime.codex_cli import RunResult
from tests.runtime.test_codex import Base as CodexBase, KEY as CKEY, events
from tests.runtime.common import FAKE_KEY, OK_INV, OK_VERIFY, PROFILE, RT, FakeTransport, completion, req

KEY = ("INVESTIGATE", "investigator", "generalist", 0, 0)
EXAMPLES = Path(__file__).resolve().parents[2] / "reviewer" / "contracts" / "examples"
ARGS = {"path": "src/a.py", "start_line": 3, "deep": True, "tag": None, "end_line": 9}
REQUESTING = {"contextRequests": [{"tool": "read_file", "args": ARGS, "purpose": "see the caller"}], "output": None}
FINAL_INV = {"contextRequests": [], "output": OK_INV}
FINAL_VER = {"contextRequests": [], "output": OK_VERIFY}
HANDOFF_SHA = {   # published in orchestration/handoffs/S1-06a.md (role-schema-projection@2)
    "InvestigatorTurn/anthropic": "be69b695fabd34ab9413ddfdd2e8817e9e103e3ad9769c7792e8c41a2d495181",
    "InvestigatorTurn/openai-strict": "0dc957344d331454d2cd967f77c1b5e4292845ab63a25431634fac7e9f547548",
    "VerifierTurn/anthropic": "3491082489017d6d9adb9ea7028a7d2ebbe7ae3c06a0b1a999df1b6fa09df6d7",
    "VerifierTurn/openai-strict": "5f0e8d8204ff19ea64bddc49c6b83699c0abd921912929f269f2c317d204dd15"}
TURNS = ("InvestigatorTurn", "VerifierTurn")
PLAIN = ("InvestigatorOutput", "VerifierOutput", "JudgeOutput")
FLAVORS = ("anthropic", "openai-strict")
# Keywords the projection may emit; everything else (length/range/pattern/format/open objects) must be gone.
WIRE_KEYWORDS = {"type", "properties", "required", "additionalProperties", "items", "anyOf", "enum", "description"}


def wire(turn):
    """Entry-form args, exactly what a strict provider is told to emit."""
    t = copy.deepcopy(turn)
    for c in t.get("contextRequests") or []:
        if isinstance(c, dict) and isinstance(c.get("args"), dict):
            c["args"] = [{"key": k, "value": v} for k, v in c["args"].items()]
    return t


def conforms(value, node) -> bool:
    """Minimal checker for the projected keyword subset: does `value` satisfy what the provider enforces?"""
    if "anyOf" in node:
        return any(conforms(value, alt) for alt in node["anyOf"])
    if "enum" in node and value not in node["enum"]:
        return False
    t = node.get("type")
    ok_type = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
               "string": lambda v: isinstance(v, str), "boolean": lambda v: isinstance(v, bool),
               "integer": lambda v: isinstance(v, int) and not isinstance(v, bool), "null": lambda v: v is None}
    if t is not None and not ok_type[t](value):
        return False
    if t == "object":
        props = node.get("properties", {})
        if node.get("additionalProperties") is False and set(value) - set(props):
            return False
        if set(node.get("required", [])) - set(value):
            return False
        return all(conforms(v, props[k]) for k, v in value.items() if k in props)
    if t == "array" and "items" in node:
        return all(conforms(v, node["items"]) for v in value)
    return True


def walk(node, fn, path="$"):
    if isinstance(node, dict):
        fn(node, path)
        for k, v in node.items():
            walk(v, fn, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, fn, f"{path}/{i}")


def strict_forced(value, node):
    """Simulate an openai-strict answer: every optional key absent from `value` is emitted as null."""
    if isinstance(value, dict) and "properties" in node:
        out = {k: strict_forced(v, node["properties"].get(k, {})) for k, v in value.items()}
        for k in node["properties"]:
            out.setdefault(k, None)
        return out
    if isinstance(value, list) and "items" in node:
        return [strict_forced(v, node["items"]) for v in value]
    alts = node.get("oneOf") or node.get("anyOf") if isinstance(node, dict) else None
    if isinstance(value, dict) and alts:
        objs = [a for a in alts if "properties" in a]
        kind = [a for a in objs if a["properties"].get("kind", {}).get("const") == value.get("kind")]
        if kind or objs:
            return strict_forced(value, (kind or objs)[0])
    return value


class Selection(unittest.TestCase):
    def test_only_role_legal_names_select(self):
        for r in [{"role": "investigator", "outputSchema": "ContextRequest"}, {"role": "verifier", "outputSchema": "Finding"},
                  {"role": "investigator", "outputSchema": "InvestigatorTurn "}, {"role": "investigator", "outputSchema": "investigatorturn"},
                  {"role": "investigator", "outputSchema": {"$ref": "InvestigatorTurn"}}, {"role": "judge", "outputSchema": "JudgeTurn"},
                  {"role": "investigator"}, {"outputSchema": "InvestigatorTurn"}]:
            with self.subTest(r):
                self.assertIsNone(schemas.select_schema(r))

    def test_turn_names_are_exactly_the_contract_turn_schemas(self):
        self.assertEqual({n for n in schemas.SCHEMA_NAMES if is_turn_schema(n)}, set(TURNS))


class Projection(unittest.TestCase):
    def test_plain_schemas_contain_no_map_so_the_new_branch_is_inert(self):
        for name in PLAIN:
            found = []
            walk(schemas.original(name), lambda n, p: found.append(p) if schemas._is_map(n) else None)
            self.assertEqual(found, [], name)
            for flavor in FLAVORS:
                with mock.patch.object(schemas, "_is_map", lambda n: False):
                    without = schemas.provider_schema(name, flavor)
                self.assertEqual(schemas.provider_schema(name, flavor), without, (name, flavor))

    def test_the_map_branch_is_the_only_turn_change(self):
        """Disabling Map projection changes ONLY the args node; everything else in the Turn projection is the old projector."""
        for name in TURNS:
            for flavor in FLAVORS:
                new = schemas.provider_schema(name, flavor)
                with mock.patch.object(schemas, "_is_map", lambda n: False):
                    old = schemas.provider_schema(name, flavor)
                diff = []

                def cmp(a, b, path):
                    if isinstance(a, dict) and isinstance(b, dict):
                        for k in set(a) | set(b):
                            cmp(a.get(k), b.get(k), f"{path}/{k}")
                    elif a != b:
                        diff.append(path)
                cmp(new, old, "$")
                self.assertTrue(diff)
                self.assertTrue(all(p.endswith("/args") or "/args/" in p for p in diff), diff)

    def test_wire_keywords_closed_objects_and_handoff_digests(self):
        for name in TURNS:
            for flavor in FLAVORS:
                sch = schemas.provider_schema(name, flavor)
                bad = []
                walk(sch, lambda n, p: bad.extend(f"{p}:{k}" for k in n if k not in WIRE_KEYWORDS and not p.endswith("/properties")))
                walk(sch, lambda n, p: bad.append(f"{p}:open") if n.get("type") == "object" and n.get("additionalProperties") is not False else None)
                self.assertEqual(bad, [], (name, flavor))
                self.assertEqual(hashlib.sha256(schemas.schema_bytes(name, flavor)).hexdigest(), HANDOFF_SHA[f"{name}/{flavor}"])

    def test_anthropic_complexity_is_recorded_and_small(self):
        """Evidence for the canary record (counts, not a provider-limit proof)."""
        def counts(name):
            c = {"optional": 0, "unions": 0, "objects": 0}

            def f(n, p):
                if "anyOf" in n:
                    c["unions"] += 1
                if n.get("type") == "object":
                    c["objects"] += 1
                    c["optional"] += len(set(n.get("properties", {})) - set(n.get("required", [])))
            walk(schemas.provider_schema(name, "anthropic"), f)
            return c, len(schemas.schema_bytes(name, "anthropic"))
        self.assertEqual(counts("InvestigatorTurn"), ({"optional": 6, "unions": 3, "objects": 8}, 3206))
        self.assertEqual(counts("VerifierTurn"), ({"optional": 2, "unions": 3, "objects": 6}, 2530))

    def test_wire_form_examples_conform_to_the_projection_and_contract_form_does_not(self):
        """The shape the provider is forced to emit is the shape normalization reverses."""
        cases = [("InvestigatorTurn", REQUESTING), ("InvestigatorTurn", FINAL_INV), ("VerifierTurn", FINAL_VER),
                 ("InvestigatorTurn", json.loads((EXAMPLES / "InvestigatorTurn.requests.json").read_text())),
                 ("VerifierTurn", json.loads((EXAMPLES / "VerifierTurn.final.json").read_text()))]
        for name, doc in cases:
            sch = schemas.provider_schema(name, "anthropic")
            self.assertTrue(conforms(wire(doc), sch), name)
            if doc["contextRequests"] and doc["contextRequests"][0]["args"]:
                self.assertFalse(conforms(doc, sch), "dict-form args must not satisfy the wire schema")
            strict = schemas.provider_schema(name, "openai-strict")
            forced = strict_forced(wire(doc), schemas.original(name))
            self.assertTrue(conforms(forced, strict), name)


class Normalization(unittest.TestCase):
    def norm(self, name, value, flavor="anthropic"):
        v = schemas.normalize_output(name, value, flavor)
        return v, schemas.local_issues(name, v)

    def test_contract_examples_round_trip_in_both_flavors(self):
        for fname, name in [("InvestigatorTurn.requests.json", "InvestigatorTurn"), ("VerifierTurn.final.json", "VerifierTurn")]:
            doc = json.loads((EXAMPLES / fname).read_text())
            for flavor in FLAVORS:
                sent = strict_forced(wire(doc), schemas.original(name)) if flavor == "openai-strict" else wire(doc)
                self.assertEqual(self.norm(name, sent, flavor), (doc, []), (fname, flavor))

    def test_entry_order_types_and_nulls_are_preserved(self):
        v, bad = self.norm("InvestigatorTurn", wire(REQUESTING))
        self.assertEqual(bad, [])
        args = v["contextRequests"][0]["args"]
        self.assertEqual(list(args), list(ARGS))
        self.assertIs(args["deep"], True)
        self.assertIs(type(args["start_line"]), int)
        self.assertIn("tag", args)
        self.assertIsNone(args["tag"])

    def test_strict_flavor_strips_forced_nulls_through_anyof_but_never_arg_nulls_or_output(self):
        loc = {"path": "a.py", "line": 3}
        hyp = {"claim": "c", "category": "bug", "suspectedSeverity": "P1", "impact": "crash", "location": loc,
               "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "a" * 16}]}
        inv = {"hypotheses": [hyp]}
        if schemas.local_issues("InvestigatorOutput", inv):
            self.skipTest(f"sample hypothesis not contract-valid: {schemas.local_issues('InvestigatorOutput', inv)}")
        final = {"contextRequests": [], "output": inv}
        forced = strict_forced(final, schemas.original("InvestigatorTurn"))
        self.assertIsNone(forced["output"]["hypotheses"][0]["location"]["endLine"])      # the simulation did force it
        self.assertEqual(forced["output"]["hypotheses"][0]["evidence"][0], {"kind": "tool-ref", "toolCallId": "tool_" + "a" * 16,
                                                                             "index": None, "note": None})   # through oneOf
        self.assertEqual(self.norm("InvestigatorTurn", forced, "openai-strict"), (final, []))
        req_forced = strict_forced(wire(REQUESTING), schemas.original("InvestigatorTurn"))
        v, bad = self.norm("InvestigatorTurn", req_forced, "openai-strict")
        self.assertEqual((v, bad), (REQUESTING, []))
        self.assertIn("output", v)

    def test_entry_boundaries(self):
        ent = lambda k, v: {"key": k, "value": v}

        def doc(args):
            return {"contextRequests": [{"tool": "t", "args": args, "purpose": "p"}], "output": None}
        good = {"empty": [], "sixteen": [ent(f"k{i}", i) for i in range(16)], "literal key/value names": [ent("key", "value"), ent("value", "key")],
                "max string": [ent("s", "x" * 4096)], "max int": [ent("n", 2 ** 53 - 1)], "min int": [ent("n", -(2 ** 53 - 1))]}
        bad = {"seventeen": [ent(f"k{i}", i) for i in range(17)], "long string": [ent("s", "x" * 4097)], "big int": [ent("n", 2 ** 53)],
               "uppercase key": [ent("Path", 1)], "digit-first key": [ent("1a", 1)], "empty key": [ent("", 1)],
               "33-char key": [ent("a" * 33, 1)], "null key": [ent(None, 1)], "dup after others": [ent("a", 1), ent("b", 2), ent("a", 1)],
               "entries as object list mixed": [ent("a", 1), ["b", 2]], "nested entries": [ent("a", [ent("b", 1)])]}
        for why, args in good.items():
            with self.subTest(why):
                self.assertEqual(self.norm("InvestigatorTurn", doc(args))[1], [])
        for why, args in bad.items():
            with self.subTest(why):
                self.assertTrue(self.norm("InvestigatorTurn", doc(args))[1])

    def test_duplicate_is_never_merged_even_with_equal_values(self):
        args = [{"key": "a", "value": 1}, {"key": "a", "value": 1}]
        v, bad = self.norm("InvestigatorTurn", {"contextRequests": [{"tool": "t", "args": args, "purpose": "p"}], "output": None})
        self.assertTrue(bad)
        self.assertEqual(v["contextRequests"][0]["args"], args)            # left as the model sent it

    def test_dict_shaped_single_entry_is_kept_literally_not_reinterpreted(self):
        d = {"contextRequests": [{"tool": "t", "args": {"key": "path", "value": "x"}, "purpose": "p"}], "output": None}
        v, bad = self.norm("InvestigatorTurn", d)
        self.assertEqual((v["contextRequests"][0]["args"], bad), ({"key": "path", "value": "x"}, []))

    def test_normalization_does_not_mutate_its_input(self):
        sent = wire(REQUESTING)
        before = copy.deepcopy(sent)
        schemas.normalize_output("InvestigatorTurn", sent, "openai-strict")
        self.assertEqual(sent, before)

    def test_plain_outputs_are_an_identity_in_the_anthropic_flavor(self):
        for name, doc in [("InvestigatorOutput", OK_INV), ("VerifierOutput", OK_VERIFY), ("JudgeOutput", {"comments": []})]:
            self.assertEqual(schemas.normalize_output(name, copy.deepcopy(doc), "anthropic"), doc)


def turn_req(role="investigator", **over):
    return req(role, outputSchema={"investigator": "InvestigatorTurn", "verifier": "VerifierTurn"}[role],
               **{"hop": 0, "contextResults": [], **over})


class OpenRouterTurns(RT):
    def run_one(self, content, r=None, **kw):
        body = content if isinstance(content, (bytes, HttpResponse, Exception)) else \
            completion(content if isinstance(content, str) else json.dumps(content), **kw)
        p = self.provider(FakeTransport(body))
        return p.call(r or turn_req(), KEY)

    def results(self):
        return [x for x in self.receipts() if x["type"] == "result"]

    def assert_charged_invalid(self, res):
        self.assertEqual(res.outcome, "processed")
        self.assertEqual((res.response["status"], res.response["output"]), ("invalid-output", None))
        rec = self.results()
        self.assertEqual(len(rec), 1)
        self.assertEqual((rec[0]["note"], rec[0]["outcome"]), ("invalid-output", "processed"))
        self.assertGreater(self.ledger.totals()["knownUsdMicros"], 0)
        return rec[0]

    def test_sent_body_carries_selected_schema_and_no_hop_metadata(self):
        r = turn_req("verifier", model="anthropic/claude-sonnet-5.5", provider="anthropic", hop=2,
                     continuationOf="call_" + "1" * 16, contextResults=["tool_" + "2" * 16])
        self.run_one(FINAL_VER, r)
        sent = json.loads(self.transport.requests[0].body)
        self.assertEqual(set(sent), {"model", "messages", "max_tokens", "stream", "response_format", "provider"})
        js = sent["response_format"]["json_schema"]
        self.assertEqual((js["name"], js["strict"]), ("VerifierTurn", True))
        self.assertEqual(hashlib.sha256(json.dumps(js["schema"], sort_keys=True).encode()).hexdigest(), HANDOFF_SHA["VerifierTurn/anthropic"])
        self.assertEqual(sent["messages"], r["messages"])
        self.assertNotIn("tool_" + "2" * 16, self.transport.requests[0].body.decode())

    def test_ok_turn_receipt_and_response(self):
        raw = json.dumps(wire(REQUESTING))
        res = self.run_one(raw)
        self.assertEqual((res.response["status"], res.response["output"]), ("ok", REQUESTING))
        rec = self.results()[0]
        self.assertEqual((rec["schemaProjection"], rec["schemaName"], rec["schemaSha256"]),
                         ("role-schema-projection@2", "InvestigatorTurn", HANDOFF_SHA["InvestigatorTurn/anthropic"]))
        self.assertEqual(rec["contentSha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertIsNone(rec.get("note"))
        self.assertGreater(self.ledger.totals()["knownUsdMicros"], 0)

    def test_duplicate_json_keys_are_charged_invalid_never_last_wins(self):
        for why, text in {"envelope": '{"contextRequests":[],"output":null,"output":{"hypotheses":[]}}',
                          "entry": '{"contextRequests":[{"tool":"t","args":[{"key":"a","key":"b","value":1}],"purpose":"p"}],"output":null}'}.items():
            with self.subTest(why):
                self.setUp()
                rec = self.assert_charged_invalid(self.run_one(text))
                self.assertEqual(rec["contentSha256"], hashlib.sha256(text.encode()).hexdigest())

    def test_float_and_exponent_arg_values_are_charged_invalid(self):
        for lit in ("1.0", "1e2", "-0.0"):
            with self.subTest(lit):
                self.setUp()
                text = '{"contextRequests":[{"tool":"t","args":[{"key":"a","value":%s}],"purpose":"p"}],"output":null}' % lit
                self.assert_charged_invalid(self.run_one(text))

    def test_truncated_or_filtered_turn_is_charged_invalid_even_if_parseable(self):
        for finish in ("length", "content_filter"):
            with self.subTest(finish):
                self.setUp()
                self.assert_charged_invalid(self.run_one(wire(REQUESTING), finish=finish))

    def test_seventeen_args_charged_invalid(self):
        doc = {"contextRequests": [{"tool": "t", "args": [{"key": f"k{i}", "value": i} for i in range(17)], "purpose": "p"}], "output": None}
        self.assert_charged_invalid(self.run_one(doc))

    def test_error_rows_still_record_the_turn_projection(self):
        for why, resp in {"http-500": HttpResponse(500, {}, b"{}"), "http-400": HttpResponse(400, {}, b"{}"),
                          "timeout": TransportTimeout(True)}.items():
            with self.subTest(why):
                self.setUp()
                self.run_one(resp)
                rec = self.results()
                self.assertEqual(len(rec), 1)
                self.assertEqual((rec[0]["schemaName"], rec[0]["schemaSha256"], rec[0]["schemaProjection"]),
                                 ("InvestigatorTurn", HANDOFF_SHA["InvestigatorTurn/anthropic"], "role-schema-projection@2"))

    def test_refusals_are_unsent_and_uncharged(self):
        for why, r in {"tools": turn_req(tools=[{"name": "read_file"}]), "judge turn": req("judge", outputSchema="VerifierTurn"),
                       "non-role def": req("investigator", outputSchema="ContextRequest")}.items():
            with self.subTest(why):
                self.setUp()
                res = self.run_one(FINAL_INV, r)
                self.assertEqual(res.outcome, "not-sent")
                self.assertEqual((self.transport.requests, self.receipts()), ([], []))

    # ---- raw provider JSON (author amendment in progress at review time; gated against the updated handoff)
    def test_turn_ok_keeps_raw_entry_form_text(self):
        raw = json.dumps(wire(REQUESTING), indent=1)
        res = self.run_one(raw)
        self.assertEqual(res.response["status"], "ok")
        self.assertEqual(res.response["rawText"], raw)                     # entry form, exact bytes when nothing to redact
        self.assertIsInstance(json.loads(res.response["rawText"])["contextRequests"][0]["args"], list)

    def test_turn_raw_text_is_key_scrubbed_and_hash_is_of_the_original(self):
        doc = wire(REQUESTING)
        doc["contextRequests"][0]["args"][0]["value"] = FAKE_KEY
        raw = json.dumps(doc)
        res = self.run_one(raw)
        self.assertIn("[REDACTED", res.response["rawText"])               # output itself is model data, not scrubbed (as for plain)
        self.assertNotIn(FAKE_KEY, res.response["rawText"])
        self.assertNotIn(FAKE_KEY, self.ledger_path.read_text())
        self.assertEqual(self.results()[0]["contentSha256"], hashlib.sha256(raw.encode()).hexdigest())

    def test_plain_ok_raw_text_unchanged_none(self):
        res = self.run_one(OK_INV, req())
        self.assertEqual((res.response["status"], res.response["rawText"]), ("ok", None))


class GatewayTurns(RT):
    def test_trace_keeps_whole_envelope_and_raw_text_for_both_hops(self):
        p = self.provider(FakeTransport(completion(json.dumps(wire(REQUESTING))), completion(json.dumps(FINAL_INV))))
        gw = self.gateway(p)
        prof = copy.deepcopy(PROFILE)
        prof["roles"]["investigator"]["outputSchema"] = "InvestigatorTurn"
        gw.profile = prof
        a = gw.call("INVESTIGATE", "investigator", "generalist", 0, turn_req())
        b = gw.call("INVESTIGATE", "investigator", "generalist", 1, turn_req())     # hop>0 validation is gateway scope
        self.assertTrue(a.ok, a.error)
        self.assertTrue(b.ok, b.error)
        gw.recorder.end("completed")
        load_trace(gw.recorder.events)
        calls = [e for e in gw.recorder.events if e.get("type") == "model.call" and e.get("response")]
        self.assertEqual([c["response"]["output"] for c in calls], [REQUESTING, FINAL_INV])
        self.assertTrue(all(isinstance(c["response"]["rawText"], str) for c in calls))
        self.assertEqual({json.loads(t.body)["response_format"]["json_schema"]["name"] for t in self.transport.requests}, {"InvestigatorTurn"})


class CodexTurnsHeld(CodexBase):
    """Recorded pre-Terra gaps. TERRA-ARM-01 un-held Terra behind codex-isolated-home@2, so these are now live-path
    requirements: duplicate JSON keys refuse (strict parse), never last-key-wins."""

    def test_codex_duplicate_json_keys_are_invalid_not_last_wins(self):
        text = '{"contextRequests":[],"output":{"verdict":"x"},"output":%s}' % json.dumps(OK_VERIFY)
        p = self.prov(RunResult(0, events(text), b""))
        res = p.call(req("verifier", outputSchema="VerifierTurn", hop=0, contextResults=[]), CKEY)
        self.assertEqual(res.response["status"], "invalid-output")      # was "ok" (json.loads kept the last key)


if __name__ == "__main__":
    unittest.main()
