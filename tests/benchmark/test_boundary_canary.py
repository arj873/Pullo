"""Label-canary: real run_review with a spy provider on invented tiny cases; scorer side holds a random sentinel."""

import copy
import json
import pathlib

from reviewer.benchmark.boundary import assert_case_input, assert_reviewer_root, assert_report_location
from reviewer.benchmark.canary import Sentinel
from reviewer.benchmark.errors import BenchmarkError
from reviewer.contracts.schema import ContractViolation
from reviewer.pipeline import PipelineError
from tests.pipeline.helpers import (BASE, HEAD, Rig, hyp, ifinal, iturn, judge, script, treq, ver, vfinal, vturn,
                                    events_of, tcid)

from .helpers import GOLD

ROOT = pathlib.Path(__file__).resolve().parents[2]


class Canary(Rig):
    def setUp(self):
        super().setUp()
        self.store = self.tmp / "scorer-store"
        self.store.mkdir()
        self.sent = Sentinel.new(*[t for t, _, _ in GOLD[1]])
        # scorer side: gold + sentinel live only in the store
        (self.store / "benchmark_data.json").write_text(json.dumps({"gold": [t for t, _, _ in GOLD[1]],
                                                                    "canary": self.sent.token}))

    def run_checked(self, m, **kw):
        res, spy = self.record(m, script(__import__("tests.pipeline.helpers", fromlist=["inv"]).inv(hyp(m, "src/b.py", 2)),
                                         ver(0, m, path="src/b.py", line=2), judge()), **kw)
        return res, spy

    def test_sentinel_and_gold_absent_from_requests_tools_roots_and_outputs(self):
        m = self.mini()
        res, spy = self.run_checked(m, forbidden_roots=(self.store,))
        self.assertEqual(res.status, "completed")
        self.assertGreater(len(spy.requests), 0)
        found = (self.sent.scan_requests(spy.requests) + self.sent.scan_events(events_of(res), ("tool.call", "model.call"))
                 + self.sent.scan_tree(m.root) + self.sent.scan_tree(res.run_dir))
        self.assertEqual(found, [])

    def test_retrieval_tool_outputs_are_clean_too(self):
        from tests.pipeline.helpers import TURN_PLAN, TURN_PROFILE
        m = self.mini()
        h = hyp(m, "src/b.py", 2)
        scr = script(iturn(0, [treq("read_file", side="head", path="src/a.py", start_line=1, end_line=3)]), ifinal(1, h),
                     vturn(0, [treq("search_literal", side="head", query="return")]), vfinal(1, m, verdict="uncertain"),
                     judge())
        res, spy = self.record(m, scr, profile=TURN_PROFILE, plan=TURN_PLAN, forbidden_roots=(self.store,))
        self.assertEqual(res.status, "completed")
        self.assertTrue([e for e in events_of(res) if e["type"] == "tool.call"])
        self.assertEqual(self.sent.scan_requests(spy.requests) + self.sent.scan_events(events_of(res), ("tool.call",)), [])

    def test_positive_control_scanner_detects_a_planted_sentinel(self):
        head = dict(HEAD)
        head["src/b.py"] = f"# {self.sent.token}\n" + HEAD["src/b.py"]
        m = self.mini(cid="planted", head=head)
        res, spy = self.run_checked_planted(m)
        self.assertTrue(self.sent.scan_tree(m.root))                     # snapshot root carries it
        self.assertTrue(self.sent.scan_requests([{"messages": [{"content": "x " + self.sent.token}]}]))
        self.assertTrue(self.sent.scan_bytes(("gold " + GOLD[1][0][0]).encode(), "t"))
        for f in self.sent.scan_tree(m.root):
            self.assertNotIn(self.sent.token, json.dumps(f))             # findings never echo the needle

    def run_checked_planted(self, m):
        from tests.pipeline.helpers import inv
        return self.record(m, script(inv(), judge()))

    def test_source_store_cannot_be_a_snapshot_root(self):
        with self.assertRaises(BenchmarkError):
            assert_reviewer_root(self.store, [self.store])
        with self.assertRaises(BenchmarkError):
            assert_reviewer_root(self.store / "cases" / "x", [self.store])
        with self.assertRaises(BenchmarkError):
            assert_reviewer_root(self.tmp, [self.store])                 # containing it is refused too
        assert_reviewer_root(self.tmp / "cases" / "ok", [self.store])
        # run_review's forbidden_roots guards the OUTPUT root only (a snapshot root inside it is not refused by the
        # pipeline: reported to root as a host-side gate). The output root inside the store is refused for real.
        with self.assertRaises(PipelineError):
            self.run_checked(self.mini(), forbidden_roots=(self.store,), out_root=self.store / "out")

    def test_reports_never_land_in_reviewer_roots_or_store(self):
        roots = [ROOT / "reviewer", ROOT / "fixtures", ROOT / "tests"]
        with self.assertRaises(BenchmarkError):
            assert_report_location(ROOT / "tests" / "r.json", roots, [self.store])
        with self.assertRaises(BenchmarkError):
            assert_report_location(self.store / "r.json", roots, [self.store])
        assert_report_location(self.tmp / "ops" / "r.json", roots, [self.store])

    def test_case_input_is_closed_against_gold_and_labels(self):
        m = self.mini()
        assert_case_input(m.case)
        for extra in ({"golden_comments": []}, {"labels": {}}, {"review_comments": []}, {"canary": self.sent.token}):
            bad = copy.deepcopy(m.case)
            bad.update(extra)
            with self.assertRaises(ContractViolation):
                assert_case_input(bad)
        bad = copy.deepcopy(m.case)
        bad["pr"]["body"] = bad["pr"]["body"]
        assert_case_input(bad)

    def test_engine_has_no_benchmark_branch(self):
        for pkg in ("pipeline", "gateway", "tools", "runtime", "contracts"):
            for p in (ROOT / "reviewer" / pkg).rglob("*.py"):
                t = p.read_text()
                for needle in ("reviewer.benchmark", "from ..benchmark", "martian", "benchmark_data"):
                    self.assertNotIn(needle, t, f"{p.name}: {needle}")
