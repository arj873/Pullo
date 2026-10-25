import copy
import json
import unittest

from reviewer.contracts import validate
from reviewer.contracts.canonical import hypothesis_id
from reviewer.scoring.scripts import check_case_script, check_script
from .helpers import SMOKE, smoke_suite


def script(cid):
    return json.loads((SMOKE / f"scripts/{cid}.json").read_text())


def keys(doc):
    return [(e["stage"], e["role"], e["agentId"], e["ordinal"], e["attempt"]) for e in doc["entries"]]


class Shipped(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = smoke_suite()

    def test_every_script_obeys_the_fixed_interface_and_its_case(self):
        for cid in self.suite.cases:
            with self.subTest(cid):
                self.assertEqual(check_case_script(self.suite, cid), [])

    def test_no_hand_built_traces_or_run_scoped_fields(self):
        banned = {"requestHash", "resultHash", "seq", "runId", "callId", "costRecordId", "request",
                  "labels", "expect", "bugs", "fixCommit"}
        for cid in self.suite.cases:
            blob = json.dumps(script(cid))
            for k in banned:
                self.assertNotIn(f'"{k}"', blob, f"{cid}: {k}")

    def test_silence_case_has_only_an_empty_investigation(self):
        d = script("smoke-c02")
        self.assertEqual(keys(d), [("INVESTIGATE", "investigator", "generalist", 0, 0)])
        self.assertEqual(d["entries"][0]["response"]["output"], {"hypotheses": []})

    def test_positive_case_runs_all_three_agents(self):
        stages = [k[0] for k in keys(script("smoke-c01"))]
        self.assertEqual(stages, ["INVESTIGATE", "VERIFY", "JUDGE"])

    def test_duplicate_case_has_two_candidates_at_the_same_place_and_matching_verifier_ordinals(self):
        d = script("smoke-c03")
        hyps = d["entries"][0]["response"]["output"]["hypotheses"]
        self.assertEqual(len(hyps), 2)
        self.assertEqual(hyps[0]["location"]["path"], hyps[1]["location"]["path"])
        self.assertNotEqual(hyps[0]["claim"], hyps[1]["claim"])
        self.assertEqual([k[3] for k in keys(d) if k[0] == "VERIFY"], [0, 1])

    def test_repair_case_malformed_then_valid_on_attempt_one(self):
        d = script("smoke-c04")
        first, second = d["entries"][0], d["entries"][1]
        self.assertEqual((first["attempt"], first["response"]["status"], first["response"]["output"]), (0, "invalid-output", None))
        self.assertIsInstance(first["response"]["rawText"], str)
        self.assertEqual((second["attempt"], second["response"]["status"]), (1, "ok"))
        self.assertEqual(keys(d).count(("INVESTIGATE", "investigator", "generalist", 0, 2)), 0)   # one repair only

    def test_verifier_failure_case_errors_without_sleeping(self):
        d = script("smoke-c05")
        ver = [e for e in d["entries"] if e["stage"] == "VERIFY"]
        self.assertTrue(ver and all("error" in e and "response" not in e for e in ver))
        self.assertEqual({e["error"]["code"] for e in ver}, {"provider-error"})
        self.assertFalse(any(e["stage"] == "JUDGE" for e in d["entries"]))

    def test_timeout_case_is_a_scripted_typed_error(self):
        d = script("smoke-c06")
        self.assertTrue(all(e["error"]["code"] == "provider-timeout" and e["stage"] == "INVESTIGATE"
                            for e in d["entries"]))
        self.assertEqual([e["attempt"] for e in d["entries"]], [0, 1, 2])
        for e in d["entries"]:
            self.assertEqual(validate("TypedError", e["error"]), [])

    def test_judge_ids_are_the_derived_hypothesis_ids(self):
        d = script("smoke-c01")
        h = d["entries"][0]["response"]["output"]["hypotheses"][0]
        want = hypothesis_id("generalist", 0, h["claim"], h["location"]["path"], h["location"]["line"])
        self.assertEqual(d["entries"][-1]["response"]["output"]["comments"][0]["findingIds"], [want])

    def test_verifier_cites_a_different_target_than_the_proposer(self):
        d = script("smoke-c01")
        prop = d["entries"][0]["response"]["output"]["hypotheses"][0]["evidence"][0]
        ver = d["entries"][1]["response"]["output"]["evidence"][0]
        self.assertNotEqual((prop["path"], tuple(prop["lines"])), (ver["path"], tuple(ver["lines"])))


class Interface(unittest.TestCase):
    def good(self):
        return copy.deepcopy(script("smoke-c01"))

    def test_good_script_has_no_problems(self):
        self.assertEqual(check_script(self.good()), [])

    def test_rejections(self):
        def dup(d): d["entries"].append(copy.deepcopy(d["entries"][0]))
        def both(d): d["entries"][0]["error"] = {"code": "provider-error", "message": "x", "retryable": True}
        def neither(d): del d["entries"][0]["response"]
        def extra(d): d["entries"][0]["note"] = "x"
        def version(d): d["schemaVersion"] = 2
        def top(d): d["comment"] = "x"
        def wrong_role(d): d["entries"][0]["role"] = "verifier"
        def bad_ordinal(d): d["entries"][0]["ordinal"] = -1
        def bool_attempt(d): d["entries"][0]["attempt"] = True
        def bad_output(d): d["entries"][0]["response"]["output"] = {"hypotheses": [{}]}
        def ok_without_output(d): d["entries"][0]["response"]["output"] = None
        def invalid_with_output(d): d["entries"][0]["response"]["status"] = "invalid-output"
        def bad_error(d):
            del d["entries"][0]["response"]
            d["entries"][0]["error"] = {"code": "nope", "message": "x", "retryable": True}
        def empty(d): d["entries"] = []
        cases = [dup, both, neither, extra, version, top, wrong_role, bad_ordinal, bool_attempt, bad_output,
                 ok_without_output, invalid_with_output, bad_error, empty]
        for fn in cases:
            with self.subTest(fn.__name__):
                d = self.good()
                fn(d)
                self.assertTrue(check_script(d), "accepted")

    def test_non_object_inputs(self):
        for bad in (None, [], "x", {"schemaVersion": 1}, {"schemaVersion": 1, "entries": "x"}):
            self.assertTrue(check_script(bad))


class CaseLevel(unittest.TestCase):
    def test_citation_that_does_not_match_the_snapshot_is_caught(self):
        import shutil, tempfile
        from pathlib import Path
        from reviewer.scoring.suite import load_suite
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "s"
            shutil.copytree(SMOKE, d)
            p = d / "scripts/smoke-c01.json"
            doc = json.loads(p.read_text())
            doc["entries"][0]["response"]["output"]["hypotheses"][0]["evidence"][0]["excerpt"] = "something else"
            p.write_text(json.dumps(doc))
            probs = check_case_script(load_suite(d), "smoke-c01")
            self.assertTrue(any("excerpt does not match" in x for x in probs), probs)

    def test_unknown_judge_id_and_orphan_verifier_ordinal_caught(self):
        import shutil, tempfile
        from pathlib import Path
        from reviewer.scoring.suite import load_suite
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "s"
            shutil.copytree(SMOKE, d)
            p = d / "scripts/smoke-c01.json"
            doc = json.loads(p.read_text())
            doc["entries"][-1]["response"]["output"]["comments"][0]["findingIds"] = ["hyp_" + "f" * 16]
            doc["entries"].append(dict(doc["entries"][1], ordinal=5))
            p.write_text(json.dumps(doc))
            probs = check_case_script(load_suite(d), "smoke-c01")
            self.assertTrue(any("unknown finding id" in x for x in probs), probs)
            self.assertTrue(any("ordinal 5" in x for x in probs), probs)


if __name__ == "__main__":
    unittest.main()
