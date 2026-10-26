"""CI-04-review independent controls (offline, no model, no corpus). Run from repo root with a non-Git TMPDIR:
    TMPDIR=/var/tmp nice -n 19 python3 -B -m unittest tests.ci04_review.test_ci04_review"""
import ast
import json
import tempfile
import unittest
from pathlib import Path

from tests.historical_review.test_historical_review import bridge_violations

ROOT = Path(__file__).resolve().parents[2]
CORE = "reviewer/pipeline/x.py"


class BoundaryEvasion(unittest.TestCase):
    def test_literal_spellings_are_flagged(self):
        for src in ("from reviewer import historical", "from reviewer import (\n historical)",
                    "from ..historical.bridge import x", "import reviewer.historical.bridge as b",
                    "__import__('reviewer.historical')", "import importlib\nimportlib.import_module('reviewer.historical')"):
            with self.subTest(src=src):
                self.assertTrue(bridge_violations({CORE: src}))

    def test_LIMIT_static_scan_misses_these_dynamic_spellings(self):
        """Gauge of a known gap: the AST scan only sees literal module names. Fails if the scan is later widened
        (then move the spelling to the flagged list above)."""
        missed = ("import reviewer\nreviewer.historical.x", "import importlib\nn='reviewer.'+'historical'\nimportlib.import_module(n)",
                  "import importlib\nimportlib.import_module('.historical', 'reviewer')",
                  "__import__('reviewer', fromlist=['historical'])", "from reviewer import *",
                  "from importlib import import_module as im\nim('reviewer.historical')")
        for src in missed:
            with self.subTest(src=src):
                self.assertEqual(bridge_violations({CORE: src}), [])

    def test_real_tree_has_no_dynamic_import_outside_the_bridge(self):
        """Mitigates the gap above for today's tree: no reviewer module outside reviewer/historical uses importlib,
        __import__ or import_module, so the literal-only scan is sufficient now."""
        for p in (ROOT / "reviewer").rglob("*.py"):
            rel = p.relative_to(ROOT).as_posix()
            if rel.startswith("reviewer/historical/"):
                continue
            for n in ast.walk(ast.parse(p.read_text())):
                if isinstance(n, ast.Import):
                    self.assertFalse(any(a.name.split(".")[0] == "importlib" for a in n.names), rel)
                if isinstance(n, ast.ImportFrom):
                    self.assertNotEqual((n.module or "").split(".")[0], "importlib", rel)
                if isinstance(n, ast.Call):
                    f = n.func
                    nm = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
                    self.assertNotIn(nm, ("__import__", "import_module"), rel)


class DuplicateSmokeActualRun(unittest.TestCase):
    def test_smoke_c03_real_run_one_comment_with_both_real_merged_findings(self):
        from reviewer.evaluation import record_smoke
        with tempfile.TemporaryDirectory(prefix="ci04rev") as d:
            self.assertFalse((Path(d) / ".git").exists())
            record_smoke(Path(d) / "out", suite_dir=ROOT / "fixtures" / "smoke")
            o = json.loads((Path(d) / "out" / "outcomes" / "smoke-c03.json").read_text())
        self.assertEqual((o["status"], o["error"], o["incomplete"]), ("completed", None, []))
        self.assertEqual(len(o["comments"]), 1)
        fids = {f["id"] for f in o["findings"]}
        self.assertEqual(len(fids), 2)
        self.assertEqual(set(o["comments"][0]["findingIds"]), fids)
        ce = {json.dumps(e, sort_keys=True) for e in o["comments"][0]["evidence"]}
        for f in o["findings"]:
            self.assertLessEqual({json.dumps(e, sort_keys=True) for e in f["evidence"]}, ce)
        self.assertEqual([(x["reason"], x["subjectIds"]) for x in o["drops"] if x["reason"] == "merged"][0][0], "merged")
        self.assertIn("duplicate of", o["drops"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
