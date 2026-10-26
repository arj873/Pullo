import contextlib
import io
import json
import pathlib

from reviewer.benchmark import __main__ as cli
from reviewer.benchmark import phaseb
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.scoring import score_case

from .helpers import Fx

JUDGE = {"model": "fixture", "extractionPrompt": phaseb.EXTRACT_V, "dedupPrompt": phaseb.DEDUP_V,
         "matchPrompt": phaseb.MATCH_V, "schemaSha256": "x", "runRef": "none"}


class PhaseB(Fx):
    def setUp(self):
        super().setUp()
        self.src = self.source()
        self.case = next(iter(self.src.cases.values()))
        self.review = self.case.review("cubic-v2")

    def test_interface_pins_prompts_schemas_and_accounting(self):
        for v in (phaseb.EXTRACT_V, phaseb.DEDUP_V, phaseb.MATCH_V):
            self.assertIn(v, phaseb.PROMPTS)
            self.assertEqual(phaseb.SCHEMA_SHA256[v], phaseb.digest(phaseb.SCHEMAS[v]))
            self.assertFalse(phaseb.SCHEMAS[v]["additionalProperties"])
        req = phaseb.extraction_request(self.review)
        self.assertEqual(req["accounting"]["category"], "scoring")
        self.assertTrue(req["accounting"]["countsTowardAggregateCap"])
        self.assertFalse(req["accounting"]["reviewCost"])
        self.assertEqual(phaseb.SEAM["callsMade"], 0)
        self.assertIn("JudgeOutput", " ".join(phaseb.SEAM["needs"]))

    def test_no_network_or_provider_import(self):
        t = pathlib.Path("reviewer/benchmark").glob("*.py")
        text = "".join(p.read_text() for p in t)
        for bad in ("import socket", "urllib", "import http", "import requests", "reviewer.runtime", "reviewer.gateway",
                    "subprocess"):
            self.assertNotIn(bad, text)

    def test_pipeline_of_validators_feeds_scorer(self):
        rc = self.review.comments[0].id
        cands = phaseb.validate_extraction(self.review, {"candidates": [{"sourceCommentId": rc, "text": "a"},
                                                                         {"sourceCommentId": rc, "text": "b"}]})
        groups = phaseb.validate_dedup(cands, {"groups": [{"representative": cands[0]["id"],
                                                           "members": [c["id"] for c in cands]}]})
        gold = self.case.golden[0].id
        matches = phaseb.validate_match([cands[0]["id"]], self.case,
                                        {"matches": [{"candidate": cands[0]["id"], "golden": gold, "reason": "same"}]})
        row = score_case(self.case, phaseb.assemble(self.case, "cubic-v2", JUDGE, cands, groups, matches))
        self.assertEqual(row["views"]["all"]["counts"]["tp"], 1)
        self.assertEqual(row["duplicateMembersNotCounted"], 1)

    def test_validators_refuse_bad_replies(self):
        rc = self.review.comments[0].id
        with self.assertRaises(BenchmarkError):
            phaseb.validate_extraction(self.review, {"candidates": [{"sourceCommentId": "rc:x", "text": "a"}]})
        with self.assertRaises(BenchmarkError):
            phaseb.validate_extraction(self.review, {"candidates": [], "extra": 1})
        cands = phaseb.validate_extraction(self.review, {"candidates": [{"sourceCommentId": rc, "text": "a"}]})
        with self.assertRaises(BenchmarkError) as cm:
            phaseb.validate_dedup(cands, {"groups": []})
        self.assertEqual(cm.exception.code, "incomplete")
        with self.assertRaises(BenchmarkError):
            phaseb.validate_match([cands[0]["id"]], self.case, {"matches": [{"candidate": cands[0]["id"], "golden": "gold:9:9", "reason": ""}]})
        big = {"candidates": [{"sourceCommentId": rc, "text": "t"}] * 201}
        with self.assertRaises(BenchmarkError):
            phaseb.validate_extraction(self.review, big)


class Cli(Fx):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def common(self):
        return ["--pins", str(self.pins_path), "--data", str(self.dp), "--labels", str(self.lp)]

    def test_verify_inspect_project_and_o_excl(self):
        rc, out, _ = self.run_cli("verify-pins", *self.common())
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["status"], "verified")
        dest = self.tmp / "reports" / "inspect.json"
        dest.parent.mkdir()
        rc, out, _ = self.run_cli("inspect", *self.common(), "--proposal", str(self.pp), "--out", str(dest))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(dest.read_text())["excludedFixtures"], ["https://example/pr"])
        rc, _, err = self.run_cli("inspect", *self.common(), "--proposal", str(self.pp), "--out", str(dest))
        self.assertEqual(rc, 2)                                  # O_EXCL: never overwritten
        rc, out, _ = self.run_cli("project", *self.common(), "--proposal", str(self.pp))
        self.assertEqual(json.loads(out)["versions"]["status"], "unresolved")
        self.assertNotIn("GOLDTEXT", out)

    def test_refusals_exit_codes(self):
        self.dp.write_bytes(self.dp.read_bytes() + b" ")
        rc, _, err = self.run_cli("verify-pins", *self.common())
        self.assertEqual(rc, 1)
        self.assertIn("refused", err)
        rc, _, _ = self.run_cli("inspect", *self.common(), "--proposal", str(self.pp), "--out",
                                str(pathlib.Path(cli.REPO) / "tests" / "should-not-exist.json"))
        self.assertEqual(rc, 1)                                  # tamper is found before any output decision
        self.write_all()
        rc, _, _ = self.run_cli("inspect", *self.common(), "--proposal", str(self.pp), "--out",
                                str(pathlib.Path(cli.REPO) / "tests" / "should-not-exist.json"))
        self.assertEqual(rc, 2)
        self.assertFalse((pathlib.Path(cli.REPO) / "tests" / "should-not-exist.json").exists())

    def test_score_command(self):
        src = self.source()
        url = next(iter(src.cases))
        rc = src.cases[url].review("cubic-v2").comments[0].id
        doc = {"schema": "semantic-judgments@1", "caseUrl": url, "tool": "cubic-v2", "judge": JUDGE,
               "extraction": {"candidates": [{"id": "cand:1", "sourceCommentId": rc, "text": "t"}]},
               "duplicateGroups": [{"id": "g", "representative": "cand:1", "members": ["cand:1"]}],
               "matches": [{"candidate": "cand:1", "golden": src.cases[url].golden[0].id, "reason": "r"}]}
        jp = self.tmp / "j.json"
        jp.write_text(json.dumps([doc]))
        rc_, out, _ = self.run_cli("score", *self.common(), "--proposal", str(self.pp), "--judgments", str(jp),
                                   "--tools", "cubic-v2")
        self.assertEqual(rc_, 0)
        rep = json.loads(out)
        self.assertFalse(rep["complete"])                       # 1 of 6 cases judged
        self.assertEqual(rep["tools"]["cubic-v2"]["casesScored"], 1)
        self.assertEqual(len(rep["tools"]["cubic-v2"]["missing"]), 5)
