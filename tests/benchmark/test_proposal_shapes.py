"""BENCH-LOADER-02: malformed proposal shapes are typed refusals (BenchmarkError), never AttributeError/TypeError/KeyError,
including through the real CLI. Every shape here is invented; no real benchmark data, network or provider is used."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reviewer.benchmark import __main__ as cli
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.loader import load_proposal

from .helpers import make_proposal

REPO = Path(__file__).resolve().parents[2]
SENTINEL = "SENTINEL-do-not-echo"
BIG_REPOS = ("alpha-app", "beta-web", "gamma-api", "delta-cli", "epsilon-sdk")


def big_proposal() -> dict:
    """INVENTED full-size shape: 5 repositories x 10 ranked pull requests = 50 cases; the top-ranked PR of each repository
    is dev (5) and the other nine of each are frozen (45), listed repository by repository in rank order."""
    sha = lambda u: hashlib.sha256(u.encode()).hexdigest()   # noqa: E731
    ranked = {}
    for r in BIG_REPOS:
        urls = sorted((f"https://example.invalid/{r}/pull/{n}" for n in range(1, 11)), key=sha)
        ranked[r] = [{"url": u, "urlSha256": sha(u)} for u in urls]
    return {"schema": "benchmark-partition-proposal@1", "sourceRevision": "b" * 40, "rankedUniverse": ranked,
            "preImportDevCandidates": [{"repo": r, **ranked[r][0]} for r in BIG_REPOS],
            "preImportFrozenCandidates": [{"repo": r, **it} for r in BIG_REPOS for it in ranked[r][1:]]}


def _demo():
    spec = importlib.util.spec_from_file_location("benchmark_demo_for_tests", REPO / "examples" / "benchmark_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mutations():
    """(name, mutator) pairs; each mutator edits a fresh valid proposal in place."""
    def uni(f):
        def m(p):
            repo = next(iter(p["rankedUniverse"]))
            f(p, repo)
        return m

    def part(key, f):
        def m(p):
            f(p, key)
        return m

    out = [
        ("universe-is-list", lambda p: p.update(rankedUniverse=[1])),
        ("universe-is-int", lambda p: p.update(rankedUniverse=7)),
        ("universe-is-empty", lambda p: p.update(rankedUniverse={})),
        ("universe-is-missing", lambda p: p.pop("rankedUniverse")),
        ("universe-items-are-int", lambda p: p.update(rankedUniverse={"invented-repo": [1]})),
        ("universe-value-int", uni(lambda p, r: p["rankedUniverse"].update({r: 5}))),
        ("universe-value-null", uni(lambda p, r: p["rankedUniverse"].update({r: None}))),
        ("universe-value-string", uni(lambda p, r: p["rankedUniverse"].update({r: SENTINEL}))),
        ("universe-value-object", uni(lambda p, r: p["rankedUniverse"].update({r: {"url": SENTINEL}}))),
        ("universe-item-string", uni(lambda p, r: p["rankedUniverse"][r].__setitem__(0, SENTINEL))),
        ("universe-item-null", uni(lambda p, r: p["rankedUniverse"][r].__setitem__(0, None))),
        ("universe-item-list", uni(lambda p, r: p["rankedUniverse"][r].__setitem__(0, [SENTINEL]))),
        ("universe-item-bool", uni(lambda p, r: p["rankedUniverse"][r].__setitem__(0, True))),
        ("universe-item-no-url", uni(lambda p, r: p["rankedUniverse"][r][0].pop("url"))),
        ("universe-item-no-hash", uni(lambda p, r: p["rankedUniverse"][r][0].pop("urlSha256"))),
        ("universe-url-int", uni(lambda p, r: p["rankedUniverse"][r][0].update(url=3))),
        ("universe-url-null", uni(lambda p, r: p["rankedUniverse"][r][0].update(url=None))),
        ("universe-hash-int", uni(lambda p, r: p["rankedUniverse"][r][0].update(urlSha256=3))),
        ("universe-hash-null", uni(lambda p, r: p["rankedUniverse"][r][0].update(urlSha256=None))),
        ("universe-hash-list", uni(lambda p, r: p["rankedUniverse"][r][0].update(urlSha256=[SENTINEL]))),
        ("universe-hash-wrong", uni(lambda p, r: p["rankedUniverse"][r][0].update(urlSha256="0" * 64))),
    ]
    for key in ("preImportDevCandidates", "preImportFrozenCandidates"):
        tag = "dev" if "Dev" in key else "frozen"
        out += [
            (f"{tag}-not-list-null", part(key, lambda p, k: p.update({k: None}))),
            (f"{tag}-not-list-object", part(key, lambda p, k: p.update({k: {"repo": "x", "url": "y"}}))),
            (f"{tag}-not-list-string", part(key, lambda p, k: p.update({k: SENTINEL}))),
            (f"{tag}-not-list-int", part(key, lambda p, k: p.update({k: 4}))),
            (f"{tag}-item-int", part(key, lambda p, k: p[k].__setitem__(0, 1))),
            (f"{tag}-item-string", part(key, lambda p, k: p[k].__setitem__(0, SENTINEL))),
            (f"{tag}-item-null", part(key, lambda p, k: p[k].__setitem__(0, None))),
            (f"{tag}-item-list", part(key, lambda p, k: p[k].__setitem__(0, [SENTINEL, SENTINEL]))),
            (f"{tag}-item-no-repo", part(key, lambda p, k: p[k][0].pop("repo"))),
            (f"{tag}-item-no-url", part(key, lambda p, k: p[k][0].pop("url"))),
            (f"{tag}-repo-int", part(key, lambda p, k: p[k][0].update(repo=9))),
            (f"{tag}-repo-list", part(key, lambda p, k: p[k][0].update(repo=[SENTINEL]))),
            (f"{tag}-url-int", part(key, lambda p, k: p[k][0].update(url=9))),
            (f"{tag}-url-list", part(key, lambda p, k: p[k][0].update(url=[SENTINEL]))),
            (f"{tag}-url-null", part(key, lambda p, k: p[k][0].update(url=None))),
        ]
    return out


class ProposalShapes(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)

    def write(self, doc, name="proposal.json") -> Path:
        p = self.tmp / name
        p.write_text(json.dumps(doc))
        return p

    # ---- loader boundary
    def test_every_malformed_shape_is_a_typed_refusal_without_echo(self):
        names = set()
        for name, mutate in _mutations():
            with self.subTest(name):
                self.assertNotIn(name, names)
                names.add(name)
                doc = make_proposal()
                mutate(doc)
                with self.assertRaises(BenchmarkError) as cm:
                    load_proposal(self.write(doc))
                self.assertEqual(cm.exception.code, "proposal")
                self.assertNotIn(SENTINEL, str(cm.exception))
        self.assertGreaterEqual(len(names), 40)

    def test_arbitrary_repo_name_is_not_echoed(self):
        doc = make_proposal()
        repo = next(iter(doc["rankedUniverse"]))
        doc["rankedUniverse"][SENTINEL] = doc["rankedUniverse"].pop(repo)
        doc["rankedUniverse"][SENTINEL][0]["urlSha256"] = "0" * 64
        with self.assertRaises(BenchmarkError) as cm:
            load_proposal(self.write(doc))
        self.assertNotIn(SENTINEL, str(cm.exception))

    def test_valid_controls_are_unchanged(self):
        doc = make_proposal()
        prop = load_proposal(self.write(doc))
        self.assertEqual(prop.universe, {r: [i["url"] for i in items] for r, items in doc["rankedUniverse"].items()})
        self.assertEqual(prop.dev, tuple((i["repo"], i["url"]) for i in doc["preImportDevCandidates"]))
        self.assertEqual(prop.frozen, tuple((i["repo"], i["url"]) for i in doc["preImportFrozenCandidates"]))
        self.assertEqual(prop.roster, [u for us in prop.universe.values() for u in us])
        # unknown extra keys on items and an empty repository list stay accepted, as before
        extra = copy.deepcopy(doc)
        extra["rankedUniverse"]["gamma"][0]["note"] = "extra"
        extra["rankedUniverse"]["empty-repo"] = []
        self.assertEqual(load_proposal(self.write(extra, "extra.json")).universe["empty-repo"], [])
        # an absent partition key is still read as an empty list (everything declared in the other key)
        solo = copy.deepcopy(doc)
        solo["preImportDevCandidates"] += solo.pop("preImportFrozenCandidates")
        self.assertEqual(len(load_proposal(self.write(solo, "solo.json")).dev), len(prop.dev) + len(prop.frozen))

    def test_existing_roster_rules_still_refuse(self):
        reverse = make_proposal()
        reverse["rankedUniverse"][next(iter(reverse["rankedUniverse"]))].reverse()
        dup = make_proposal()
        first, second = list(dup["rankedUniverse"])[:2]
        dup["rankedUniverse"][second] = copy.deepcopy(dup["rankedUniverse"][first])
        short = make_proposal()
        short["preImportFrozenCandidates"].pop()
        wrong = make_proposal()
        a, b = wrong["preImportDevCandidates"][0], wrong["preImportDevCandidates"][1]
        a["repo"], b["repo"] = b["repo"], a["repo"]
        schema = make_proposal()
        schema["schema"] = "other@1"
        for name, doc, word in (("order", reverse, "rank"), ("dup", dup, "twice"), ("partition", short, "partition"),
                                ("wrong-repo", wrong, "wrong repository"), ("schema", schema, "schema")):
            with self.subTest(name), self.assertRaises(BenchmarkError) as cm:
                load_proposal(self.write(doc, f"{name}.json"))
            self.assertIn(word, cm.exception.message)

    def test_full_size_invented_proposal_loads_in_shape_and_order(self):
        doc = big_proposal()
        prop = load_proposal(self.write(doc, "big.json"))
        self.assertEqual(list(prop.universe), list(BIG_REPOS))
        self.assertEqual([len(v) for v in prop.universe.values()], [10] * 5)
        for repo, items in doc["rankedUniverse"].items():
            self.assertEqual(prop.universe[repo], [i["url"] for i in items])
        self.assertEqual(len(prop.roster), 50)
        self.assertEqual((len(prop.dev), len(prop.frozen)), (5, 45))
        self.assertEqual(prop.dev, tuple((i["repo"], i["url"]) for i in doc["preImportDevCandidates"]))
        self.assertEqual(prop.frozen, tuple((i["repo"], i["url"]) for i in doc["preImportFrozenCandidates"]))
        self.assertEqual(prop.revision, "b" * 40)

    def test_full_size_shape_still_refuses_rule_breaks(self):
        for name, mutate, word in (
                ("order", lambda p: p["rankedUniverse"]["gamma-api"].reverse(), "rank"),
                ("drop-frozen", lambda p: p["preImportFrozenCandidates"].pop(), "partition"),
                ("int-item", lambda p: p["rankedUniverse"]["delta-cli"].__setitem__(3, 1), "item"),
                ("null-frozen", lambda p: p.update(preImportFrozenCandidates=None), "list")):
            with self.subTest(name):
                doc = big_proposal()
                mutate(doc)
                with self.assertRaises(BenchmarkError) as cm:
                    load_proposal(self.write(doc, f"big-{name}.json"))
                self.assertEqual(cm.exception.code, "proposal")
                self.assertIn(word, cm.exception.message)

    # ---- the real CLI, with the public demo fixture
    def _demo_run(self):
        demo = _demo()
        store, ops, out = self.tmp / "store", self.tmp / "ops", self.tmp / "out"
        for d in (store, ops, out):
            d.mkdir()
        paths = demo.build_source(store, ops)
        docs = [demo.build_judgments(paths, t, u) for t in demo.TOOLS for u in demo.GOLD]
        judgments = ops / "judgments.json"
        demo.write_json(judgments, docs)
        return demo, paths, judgments, out

    @staticmethod
    def _args(demo, paths, judgments, out, proposal, cmd="reference-score"):
        return [cmd, "--pins", str(paths["pins"]), "--data", str(paths["data"]), "--labels", str(paths["labels"]),
                "--proposal", str(proposal), "--expect-revision", demo.REVISION, "--judgments", str(judgments),
                "--out", str(out), "--tools", *demo.TOOLS]

    def test_real_cli_valid_control_scores(self):
        demo, paths, judgments, out = self._demo_run()
        rc, rep, err = demo.score(paths, judgments, out / "ok.json", demo.TOOLS)
        self.assertEqual(rc, 0)
        self.assertIsNone(err)
        self.assertEqual(rep["schema"], "reference-score-report@1")
        self.assertTrue((out / "ok.json").is_file())

    def test_real_cli_refuses_malformed_proposals_in_process(self):
        demo, paths, judgments, out = self._demo_run()
        valid = json.loads(Path(paths["proposal"]).read_text())
        cases = [("r2-repro", {"rankedUniverse": {"invented-repo": [1]}}),
                 ("universe-list", {"rankedUniverse": []}),
                 ("dev-null", {"preImportDevCandidates": None}),
                 ("frozen-item-int", {"preImportFrozenCandidates": [4]}),
                 ("dev-item-no-url", {"preImportDevCandidates": [{"repo": "demo-repo"}]})]
        for cmd in ("reference-score", "score", "inspect"):
            for name, over in cases:
                with self.subTest(cmd=cmd, case=name):
                    bad = self.write({**valid, **over}, f"{cmd}-{name}.json")
                    report = out / f"{cmd}-{name}-report.json"
                    outb, errb = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(outb), contextlib.redirect_stderr(errb):
                        rc = cli.main(self._args(demo, paths, judgments, report, bad, cmd))
                    self.assertEqual(rc, 1)
                    self.assertEqual(outb.getvalue(), "")
                    refusal = json.loads(errb.getvalue())
                    self.assertEqual((refusal["status"], refusal["code"]), ("refused", "proposal"))
                    self.assertNotIn("Traceback", errb.getvalue())
                    self.assertFalse(report.exists())

    def test_real_cli_subprocess_has_no_traceback_and_no_stdout(self):
        demo, paths, judgments, out = self._demo_run()
        valid = json.loads(Path(paths["proposal"]).read_text())
        bad = self.write({**valid, "rankedUniverse": {"invented-repo": [1]}}, "r2.json")
        report = out / "sub-report.json"
        proc = subprocess.run([sys.executable, "-B", "-m", "reviewer.benchmark",
                               *self._args(demo, paths, judgments, report, bad)],
                              cwd=REPO, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        self.assertNotIn("Traceback", proc.stderr)
        self.assertNotIn("AttributeError", proc.stderr)
        self.assertEqual(json.loads(proc.stderr)["code"], "proposal")
        self.assertFalse(report.exists())

    def test_real_cli_select_refuses_malformed_proposal(self):
        demo, paths, judgments, out = self._demo_run()
        valid = json.loads(Path(paths["proposal"]).read_text())
        bad = self.write({**valid, "rankedUniverse": {"invented-repo": [1]}}, "sel.json")
        empty = self.write({}, "empty.json")
        outb, errb = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(outb), contextlib.redirect_stderr(errb):
            rc = cli.main(["select", "--proposal", str(bad), "--projection", str(empty), "--proofs", str(empty)])
        self.assertEqual(rc, 1)
        self.assertEqual(outb.getvalue(), "")
        self.assertEqual(json.loads(errb.getvalue())["code"], "proposal")


if __name__ == "__main__":
    unittest.main()
