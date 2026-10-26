"""S1-07a-review: independent Phase A benchmark gate. Invented tiny cases and metadata-shaped receipts only.

CONTROL = must pass now. NEW defects are held by an expectedFailure test (the required behaviour) plus a `*_symptom_*`
test (today's behaviour); a fix flips the first to an unexpected success and breaks the symptom. Tool ids mirror the
metadata receipt toolIds; every body/gold string here is made up.

S1-07a-inputs-recheck: B1 and N1-N6 were independently verified fixed; their expectedFailure markers are removed and each
obsolete `*_symptom_*` test is now a `*_fixed_*` regression check. N4 is re-aimed at `attested` + root admission. B2/B3
(S1/S2) stay on HOLD with their markers. Deeper rechecks live in test_s107a_recheck.py.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from reviewer.benchmark import phaseb
from reviewer.benchmark.__main__ import main
from reviewer.benchmark.boundary import assert_reviewer_root
from reviewer.benchmark.canary import Sentinel
from reviewer.benchmark.cutoff import resolve_cutoff, select_cases
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.jsonio import git_blob_sha, sha256_of
from reviewer.benchmark.loader import load_proposal, load_source
from reviewer.benchmark.model import build_case
from reviewer.benchmark.pins import load_pins
from reviewer.benchmark.projection import project_metadata, resolve_versions
from reviewer.benchmark.scoring import score_case, score_suite

REPO_ROOT = Path(__file__).resolve().parents[2]
REV = "c" * 40
RAW = "https://raw.githubusercontent.com/withmartian/code-review-benchmark/{}/{}"
SRC = {"benchmark_data.json": "offline/results/benchmark_data.json", "pr_labels.json": "offline/results/pr_labels.json"}
# Real-shaped ids (metadata receipt), invented everything else.
TOOLS = ("cubic-dev", "cubic-v2", "coderabbit", "greptile", "greptile-v4", "greptile-v4-1", "greptile-v5")
URLS = {"calx": ["https://github.com/calx/calx/pull/11", "https://github.com/calx/calx/pull/12"],
        "disc": ["https://github.com/ai-code-review-evaluation/disc-graphite/pull/1",
                 "https://github.com/ai-code-review-evaluation/disc-graphite/pull/2"]}
GOLD = [("INVENTED-GOLD null deref", "High", "bug"), ("INVENTED-GOLD quadratic scan", "Medium", "perf"),
        ("INVENTED-GOLD naming", "Low", "style"), ("INVENTED-GOLD token in log", "High", "security")]
STAMP = "2026-01-25T07:13:47Z"   # competitor reviews were produced on re-created forks in 2026 (receipt shape)


def ranked():
    return {r: sorted(us, key=lambda u: hashlib.sha256(u.encode()).hexdigest()) for r, us in URLS.items()}


def item(u):
    return {"url": u, "urlSha256": hashlib.sha256(u.encode()).hexdigest()}


def proposal_doc():
    uni = ranked()
    return {"schema": "benchmark-partition-proposal@1", "sourceRevision": REV,
            "rankedUniverse": {r: [item(u) for u in us] for r, us in uni.items()},
            "preImportDevCandidates": [{"repo": r, **item(us[0])} for r, us in uni.items()],
            "preImportFrozenCandidates": [{"repo": r, **item(us[1])} for r, us in uni.items()]}


def comment(body, path="src/a.py", line=3, at=STAMP):
    return {"path": path, "line": line, "body": body, "created_at": at}


def entry(url, tools=TOOLS, gold=GOLD, comments=None):
    revs = [{"tool": t, "repo_name": f"x__{t}__PR1__20260122", "pr_url": f"https://github.com/code-review-benchmark/x-{t}/pull/1",
             "review_comments": copy.deepcopy(comments) if comments is not None else [comment(f"INVENTED-BODY {t}")]}
            for t in tools]
    return {"pr_title": "INVENTED-TITLE", "original_url": None, "source_repo": "calx",
            "golden_comments": [{"comment": c, "severity": s, "category": k} for c, s, k in gold],
            "golden_source_file": "g.json", "az_comment": None, "reviews": revs}


def capture_pins(paths: dict, rev=REV) -> dict:
    files = []
    for name, p in paths.items():
        b = p.read_bytes()
        keys = list(json.loads(b))
        files.append({"path": f"/elsewhere/{name}", "sourcePath": SRC[name], "url": RAW.format(rev, SRC[name]),
                      "revision": rev, "bytes": len(b), "gitBlobSha": git_blob_sha(b), "sha256": sha256_of(b),
                      "capturedAt": "2026-10-25T23:13:20.999827+00:00", "topType": "dict", "topKeys": keys,
                      "topCount": len(keys)})
    return {"schema": "benchmark-source-pins@1", "revision": rev, "capturedBy": "invented host", "files": files}


class Rig(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)
        self.store, self.ops = self.tmp / "store", self.tmp / "ops"
        self.store.mkdir()
        self.ops.mkdir()
        self.prop = proposal_doc()
        self.data = {u: entry(u) for us in ranked().values() for u in us}
        self.labels = None
        self.write()

    def write(self, data=None, labels=None, pins_mut=None):
        data = self.data if data is None else data
        labels = labels if labels is not None else (
            self.labels or {**{u: {"derived": {"num_golden_comments": len(e["golden_comments"])}} for u, e in data.items()},
                            "https://example/pr": {"derived": {"num_golden_comments": 0}}})
        self.dp, self.lp = self.store / "benchmark_data.json", self.store / "pr_labels.json"
        self.dp.write_text(json.dumps(data))
        self.lp.write_text(json.dumps(labels))
        self.pp = self.ops / "proposal.json"
        self.pp.write_text(json.dumps(self.prop))
        pins = capture_pins({"benchmark_data.json": self.dp, "pr_labels.json": self.lp})
        if pins_mut:
            pins_mut(pins)
        self.pins = self.ops / "pins.json"
        self.pins.write_text(json.dumps(pins))

    def source(self):
        return load_source(self.pins, self.dp, self.lp, self.pp, expect_revision=REV)

    def refused(self, code, fn, *a, **kw):
        with self.assertRaises(BenchmarkError) as cm:
            fn(*a, **kw)
        self.assertEqual(cm.exception.code, code, cm.exception.message)
        return cm.exception

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(list(argv))
        return rc, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------- pins / strict source verification
class Pins(Rig):
    def test_control_capture_format_loads_and_verifies(self):
        self.assertEqual(len(self.source().cases), 4)

    def test_same_length_byte_flip_is_tamper(self):
        b = bytearray(self.dp.read_bytes())
        i = b.index(b"INVENTED-BODY")
        b[i] = ord("J")
        self.dp.write_bytes(bytes(b))
        self.refused("tamper", self.source)

    def test_git_blob_is_checked_independently_of_sha256(self):
        def mut(p):
            p["files"][0]["gitBlobSha"] = "0" * 40
        self.write(pins_mut=mut)
        e = self.refused("tamper", self.source)
        self.assertIn("Git blob", e.message)

    def test_pins_inside_store_refused(self):
        inside = self.store / "pins.json"
        inside.write_bytes(self.pins.read_bytes())
        self.refused("pins", load_source, inside, self.dp, self.lp, self.pp)

    def test_unknown_authority_field_or_foreign_revision_refused(self):
        self.write(pins_mut=lambda p: p["files"][1].update(trusted=True))
        self.refused("pins", self.source)
        self.write(pins_mut=lambda p: p["files"][1].update(revision="d" * 40))
        self.refused("pins", self.source)
        self.write(pins_mut=lambda p: p["files"][1].update(url=RAW.format("d" * 40, SRC["pr_labels.json"])))
        self.refused("pins", self.source)

    def test_expect_revision_mismatch_refused(self):
        self.refused("pins", load_source, self.pins, self.dp, self.lp, self.pp, expect_revision="d" * 40)

    def test_symlinked_data_refused(self):
        real = self.tmp / "elsewhere.json"
        real.write_bytes(self.dp.read_bytes())
        self.dp.unlink()
        self.dp.symlink_to(real)
        self.refused("io", self.source)

    def test_cli_verify_pins_does_not_learn_from_store(self):
        rc, out, _ = self.cli("verify-pins", "--pins", str(self.pins), "--data", str(self.dp), "--labels", str(self.lp),
                              "--expect-revision", REV)
        self.assertEqual((rc, json.loads(out)["status"]), (0, "verified"))
        (self.store / "pins.json").write_bytes(self.pins.read_bytes())
        rc, _, err = self.cli("verify-pins", "--pins", str(self.store / "pins.json"), "--data", str(self.dp),
                              "--labels", str(self.lp))
        self.assertEqual((rc, json.loads(err)["code"]), (1, "pins"))


# ---------------------------------------------------------------- real-shaped nullable data
class RealShape(Rig):
    """Root census (validation/benchmark-real-shape-refusal.json): 9574 comments, 3616 path=null AND line=null
    (summary comments), 5958 str path/int line; actual inspect refuses `case 0: comment types`."""

    def with_comments(self, comments):
        u = ranked()["calx"][0]
        self.data[u] = entry(u, comments=comments)
        self.write()
        return u

    def summary_and_inline(self):
        return [comment("INVENTED-BODY summary one", path=None, line=None),
                comment("INVENTED-BODY summary two", path=None, line=None),
                comment("INVENTED-BODY inline", path="src/a.py", line=7)]

    def test_B1_summary_comment_null_path_null_line_is_loaded_not_discarded(self):
        u = self.with_comments(self.summary_and_inline())
        src = self.source()
        rev = src.cases[u].review("coderabbit")
        self.assertEqual(len(rev.comments), 3)                               # kept, not dropped
        self.assertEqual(sum(c.path is None and c.line is None for c in rev.comments), 2)
        self.assertEqual(len({c.id for c in rev.comments}), 3)               # distinct, stable ids
        again = load_source(self.pins, self.dp, self.lp, self.pp)
        self.assertEqual([c.id for c in rev.comments], [c.id for c in again.cases[u].review("coderabbit").comments])
        proj = project_metadata(src)
        counts = {r["tool"]: r["commentCount"] for c in proj["cases"] if c["url"] == u for r in c["reviews"]}
        self.assertEqual(counts["coderabbit"], 3)                            # census count preserved
        # a summary comment is citable by a candidate and scores like any other comment
        summ = next(c for c in rev.comments if c.path is None)
        doc = judgments(src.cases[u], "coderabbit", [(summ.id, "issue", "gold:0:1")], groups=None)
        self.assertEqual(score_case(src.cases[u], doc)["views"]["core"]["counts"]["tp"], 1)

    def test_B1_fixed_summary_comment_no_longer_refuses_import_but_null_path_int_line_does(self):
        self.with_comments(self.summary_and_inline())
        self.source()                                                        # was: shape "comment types"
        self.with_comments([comment("INVENTED-BODY s", path=None, line=4)])
        e = self.refused("shape", self.source)
        self.assertIn("line but no path", e.message)

    def test_B1_fixed_id_recipe_is_typed_so_null_and_the_string_None_differ(self):
        """The old recipe called len() on the path and str() on the line; ids now hash canonical typed JSON."""
        u = ranked()["calx"][0]
        ids = [build_case(u, 0, entry(u, comments=[comment("INVENTED-BODY s", path=p, line=None)])).reviews[0].comments[0].id
               for p in (None, "None")]
        self.assertTrue(all(i.startswith("rc2:") for i in ids))
        self.assertNotEqual(*ids)

    def test_control_str_path_null_line_and_nullable_metadata_load(self):
        u = self.with_comments([comment("INVENTED-BODY outdated", line=None)])
        self.data[u]["original_url"] = "https://github.com/calx/upstream/commit/" + "e" * 40
        self.data[u]["az_comment"] = None
        self.write()
        c = self.source().cases[u]
        self.assertIsNone(c.review("cubic-v2").comments[0].line)
        self.assertTrue(c.original_url.endswith("e" * 40))

    def test_control_review_with_zero_comments_is_kept(self):
        u = self.with_comments([])
        proj = project_metadata(self.source())
        row = next(c for c in proj["cases"] if c["url"] == u)
        self.assertEqual({r["commentCount"] for r in row["reviews"]}, {0})
        self.assertEqual(len(row["reviews"]), len(TOOLS))

    def test_control_unknown_category_refused_not_inferred(self):
        u = ranked()["calx"][0]
        self.data[u] = entry(u, gold=[("INVENTED-GOLD x", "High", "logic")])
        self.write()
        self.refused("category", self.source)

    def test_N1_unknown_severity_refused_as_interface_states(self):
        u = ranked()["calx"][0]
        self.data[u] = entry(u, gold=[("INVENTED-GOLD x", "Banana", "bug")])
        self.write()
        self.refused("severity", self.source)

    def test_N1_fixed_severity_is_exact_not_case_folded(self):
        u = ranked()["calx"][0]
        for s in ("high", " High", "HIGH"):
            self.data[u] = entry(u, gold=[("INVENTED-GOLD x", s, "bug")])
            self.write()
            self.refused("severity", self.source)

    def test_N2_duplicate_tool_review_in_one_case_refused(self):
        u = ranked()["calx"][0]
        self.data[u]["reviews"].append(copy.deepcopy(self.data[u]["reviews"][0]))
        self.data[u]["reviews"][-1]["review_comments"] = [comment("INVENTED-BODY second run")]
        self.write()
        self.refused("shape", self.source)

    def test_N2_fixed_identical_duplicate_review_is_refused_too(self):
        u = ranked()["calx"][0]
        self.data[u]["reviews"].append(copy.deepcopy(self.data[u]["reviews"][0]))   # byte-identical second run
        self.write()
        e = self.refused("shape", self.source)
        self.assertIn("more than one review", e.message)


# ---------------------------------------------------------------- roster / fixture exclusion
class Roster(Rig):
    def test_label_fixture_reported_and_never_a_case(self):
        src = self.source()
        rep = src.report()
        self.assertEqual((rep["labelEntries"], rep["scoredCaseCount"], rep["excludedFixtures"]), (5, 4, ["https://example/pr"]))
        self.assertNotIn("https://example/pr", src.cases)
        self.refused("roster", score_suite, src.cases, [], tools=["coderabbit"], urls=["https://example/pr"])

    def test_only_the_exact_fixture_is_excluded(self):
        lab = {**{u: {"derived": {"num_golden_comments": 4}} for u in self.data}, "https://example/pr/": {}}
        self.write(labels=lab)
        self.refused("roster", self.source)
        lab = {**{u: {"derived": {"num_golden_comments": 4}} for u in self.data}, "https://example/pr": {},
               "https://example/pr2": {}}
        self.write(labels=lab)
        self.refused("roster", self.source)

    def test_data_roster_must_equal_proposal(self):
        extra = {**self.data, "https://github.com/calx/calx/pull/99": entry("https://github.com/calx/calx/pull/99")}
        self.write(data=extra)
        self.refused("roster", self.source)
        missing = dict(list(self.data.items())[1:])
        self.write(data=missing)
        self.refused("roster", self.source)

    def test_proposal_rank_and_partition_checked(self):
        uni = self.prop["rankedUniverse"]["calx"]
        uni.reverse()
        self.write()
        self.refused("proposal", self.source)
        self.prop = proposal_doc()
        self.prop["preImportDevCandidates"] = self.prop["preImportDevCandidates"][:1]
        self.write()
        self.refused("proposal", self.source)


# ---------------------------------------------------------------- no-leak boundary
class Boundary(Rig):
    def test_projection_inspect_and_score_reports_carry_no_scorer_text(self):
        s = Sentinel.new(*[g[0] for g in GOLD])
        u = ranked()["calx"][0]
        self.data[u] = entry(u, comments=[comment(f"INVENTED-BODY {s.token}")])
        self.data[u]["pr_title"] = s.token
        self.write()
        self.assertTrue(s.scan_bytes(self.dp.read_bytes(), "store"))         # positive control: the store holds it
        src = self.source()
        proj = project_metadata(src)
        proj["versions"] = resolve_versions(proj, RULES)
        case = src.cases[u]
        doc = judgments(case, "coderabbit", [(case.review("coderabbit").comments[0].id, "issue text", "gold:0:1")])
        rep = score_suite(src.cases, [doc], tools=["coderabbit"])
        for name, obj in (("projection", proj), ("inspect", src.report()), ("score", rep)):
            blob = json.dumps(obj, ensure_ascii=False).encode()
            self.assertEqual(s.scan_bytes(blob, name), [], name)
            self.assertNotIn(b"INVENTED-BODY", blob, name)
            self.assertNotIn(b"INVENTED-TITLE", blob, name)
            self.assertNotIn(b"src/a.py", blob, name)

    def test_report_outputs_refused_inside_store_and_reviewer_roots(self):
        base = ["inspect", "--pins", str(self.pins), "--data", str(self.dp), "--labels", str(self.lp), "--proposal", str(self.pp)]
        rc, _, err = self.cli(*base, "--out", str(self.store / "r.json"))
        self.assertEqual((rc, json.loads(err)["code"]), (2, "boundary"))
        rc, _, err = self.cli(*base, "--out", str(REPO_ROOT / "tests" / "benchmark_review" / "never.json"))
        self.assertEqual((rc, json.loads(err)["code"]), (2, "boundary"))
        self.assertFalse((REPO_ROOT / "tests" / "benchmark_review" / "never.json").exists())
        rc, _, _ = self.cli(*base, "--out", str(self.ops / "r.json"))
        self.assertEqual(rc, 0)
        rc, _, err = self.cli(*base, "--out", str(self.ops / "r.json"))   # O_EXCL: never overwritten
        self.assertEqual(rc, 2)

    def test_store_is_never_a_snapshot_root(self):
        for p in (self.store, self.store / "sub", self.tmp):
            self.refused("boundary", assert_reviewer_root, p, [self.store])
        assert_reviewer_root(self.ops, [self.store])

    def test_package_has_no_network_provider_or_pipeline_import(self):
        banned = ("urllib", "http", "socket", "requests", "httpx", "ssl", "subprocess",
                  "reviewer.gateway", "reviewer.runtime", "reviewer.pipeline")
        for f in sorted((REPO_ROOT / "reviewer" / "benchmark").glob("*.py")):
            for node in ast.walk(ast.parse(f.read_text())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                        [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
                for n in names:
                    self.assertFalse(any(n == b or n.startswith(b + ".") for b in banned), f"{f.name} imports {n}")
        for pkg in ("pipeline", "gateway", "tools", "runtime", "contracts"):
            for f in (REPO_ROOT / "reviewer" / pkg).rglob("*.py"):
                self.assertNotIn("reviewer.benchmark", f.read_text(), f"{pkg}/{f.name}")


# ---------------------------------------------------------------- exact-version policy
FAM = lambda prefix, sup=(), skipped=(): {"prefix": prefix, "superseded": list(sup), "skipped": list(skipped),
                                          "source": {"blob": "fa3f38ce", "quote": "invented"}}
RULES = {"schema": "benchmark-version-rules@1", "families": {
    "cubic": FAM("cubic", ["cubic-dev"]), "coderabbit": FAM("coderabbit"),
    "greptile": FAM("greptile", ["greptile", "greptile-v4", "greptile-v4-1"])}}


class Versions(Rig):
    def proj(self):
        return project_metadata(self.source())

    def test_unresolved_without_rules_chooses_nothing(self):
        v = resolve_versions(self.proj(), None)
        self.assertEqual((v["status"], v["commonEligibleSet"]), ("unresolved", None))
        self.assertNotIn("chosen", v)
        self.assertEqual(len(v["attempted"]), 4)

    def test_control_exact_ids_from_real_shaped_tool_list(self):
        v = resolve_versions(self.proj(), RULES)
        self.assertEqual(v["chosen"], {"cubic": "cubic-v2", "coderabbit": "coderabbit", "greptile": "greptile-v5"})
        self.assertEqual(len(v["commonEligibleSet"]), 4)

    def test_upstream_hidden_list_alone_leaves_greptile_unresolved(self):
        """martian-score-semantics receipt / score_profiles.py lines 29-39: hidden cubic-dev, cubic-v3, greptile,
        greptile-v4 (exact ids). greptile-v4-1 and greptile-v5 both survive, so nothing may be chosen."""
        r = copy.deepcopy(RULES)
        r["families"]["cubic"] = FAM("cubic", ["cubic-dev", "cubic-v3"])
        r["families"]["greptile"] = FAM("greptile", ["greptile", "greptile-v4"])
        v = resolve_versions(self.proj(), r)
        self.assertEqual(v["status"], "unresolved")
        self.assertEqual(v["families"]["cubic"]["chosen"], "cubic-v2")
        self.assertEqual(v["families"]["coderabbit"]["chosen"], "coderabbit")
        self.assertEqual((v["families"]["greptile"]["chosen"], v["families"]["greptile"]["candidates"]),
                         (None, ["greptile-v4-1", "greptile-v5"]))
        self.assertIsNone(v["commonEligibleSet"])
        self.assertNotIn("chosen", v)

    def test_one_missing_superseded_entry_leaves_family_unresolved(self):
        r = copy.deepcopy(RULES)
        r["families"]["greptile"]["superseded"].remove("greptile-v4-1")
        v = resolve_versions(self.proj(), r)
        self.assertEqual(v["status"], "unresolved")
        self.assertEqual(v["families"]["greptile"]["candidates"], ["greptile-v4-1", "greptile-v5"])
        self.assertIsNone(v["commonEligibleSet"])

    def test_skipped_and_missing_tool_cases_are_omitted_but_retained(self):
        u1, u2 = ranked()["calx"]
        self.data[u2]["reviews"] = [r for r in self.data[u2]["reviews"] if r["tool"] != "greptile-v5"]
        self.write()
        r = copy.deepcopy(RULES)
        r["families"]["cubic"]["skipped"] = [{"tool": "cubic-v2", "prUrl": u1}]
        v = resolve_versions(self.proj(), r)
        self.assertEqual(set(v["omitted"]), {u1, u2})
        self.assertEqual(len(v["commonEligibleSet"]), 2)
        self.assertEqual(len(v["attempted"]), 4)

    def test_N3_ids_hidden_by_prefix_or_superseded_are_listed_for_audit(self):
        r = copy.deepcopy(RULES)
        r["families"]["cubic"] = FAM("cubic-v")                 # hides cubic-dev without naming it superseded
        v = resolve_versions(self.proj(), r)
        self.assertIn("cubic-dev", json.dumps(v["families"]["cubic"]))

    def test_N3_fixed_prefix_and_superseded_exclusions_carry_reasons(self):
        r = copy.deepcopy(RULES)
        r["families"]["cubic"] = FAM("cubic-v")
        v = resolve_versions(self.proj(), r)
        self.assertEqual((v["status"], v["chosen"]["cubic"]), ("resolved", "cubic-v2"))
        audit = {a["id"]: (a["status"], a["reason"]) for a in v["families"]["cubic"]["audit"]}
        self.assertEqual(audit["cubic-dev"][0], "excluded")
        self.assertIn("prefix", audit["cubic-dev"][1])
        g = {a["id"]: a["status"] for a in v["families"]["greptile"]["audit"]}
        self.assertEqual(g, {"greptile": "excluded", "greptile-v4": "excluded", "greptile-v4-1": "excluded",
                             "greptile-v5": "survives"})


# ---------------------------------------------------------------- cutoff admission
CALX_OBS = {"mergeCommitSha": "9" * 40, "mergedAt": "2024-08-20T09:26:20Z"}   # invented, eligibility-observation shaped


def proof(url, repo, **over):
    d = {"schema": "benchmark-cutoff-proof@1", "originalUrl": url, "resolvedRepo": repo, "asOfBase": "1" * 40,
         "asOfHead": "2" * 40, "mergeBase": "1" * 40, "headCommittedAt": "2024-04-25T00:03:43Z",
         "evidence": [{"kind": "commit-time", "source": "git-object-metadata", "observedAt": "t", "value": "2" * 40},
                      {"kind": "review-time", "source": "benchmark-comments", "observedAt": "t", "value": STAMP}]}
    d.update(over)
    return d


def ev(kind, source, value="v"):
    return {"kind": kind, "source": source, "observedAt": "t", "value": value}


def admit(url, p, **over):
    """Invented root admission, built from the fields written out here rather than from cutoff.attestation_binding,
    so the binding recipe is checked independently (sorted digests of every evidence item)."""
    from reviewer.benchmark.jsonio import digest
    d = {"schema": "benchmark-cutoff-admission@1", "originalUrl": url, "resolvedRepo": p["resolvedRepo"].lower(),
         "asOfBase": p["asOfBase"], "asOfHead": p["asOfHead"], "mergeBase": p["mergeBase"],
         "evidenceDigests": sorted({digest(e) for e in p["evidence"]}), "admittedBy": "root",
         "admittedAt": "2026-10-26T04:00:00Z", "decisionRef": "invented-decision"}
    d.update(over)
    return d


class Cutoff(Rig):
    def setUp(self):
        super().setUp()
        self.projection = project_metadata(self.source())
        self.by = {c["url"]: c for c in self.projection["cases"]}
        self.u = ranked()["calx"][0]
        self.f = ranked()["disc"][0]

    def test_control_well_formed_proof_is_attested_and_proven_only_with_root_admission(self):
        p = proof(self.u, "calx/calx")
        self.assertEqual(resolve_cutoff(self.u, p, self.by[self.u])["status"], "attested")
        self.assertEqual(resolve_cutoff(self.u, p, self.by[self.u], admit(self.u, p))["status"], "proven")

    def test_negative_controls_unproven(self):
        cases = {
            "none": None,
            "current-head": proof(self.u, "calx/calx", evidence=proof(self.u, "x")["evidence"] + [ev("upstream-pin", "merged-head")]),
            "late-head": proof(self.u, "calx/calx", headCommittedAt="2026-02-01T00:00:00Z"),
            "no-review-time": proof(self.u, "calx/calx", evidence=[ev("commit-time", "git")]),
            "short-sha": proof(self.u, "calx/calx", asOfHead="2" * 39),
            "other-url": proof(self.f, "calx/calx"),
            "redirect-without-evidence": proof(self.u, "calx/calx.diy"),
            "eval-fork-without-mapping": proof(self.f, "ai-code-review-evaluation/disc-graphite"),
        }
        for name, p in cases.items():
            url = self.f if name == "eval-fork-without-mapping" else self.u
            self.assertEqual(resolve_cutoff(url, p, self.by[url])["status"], "unproven", name)
            if p is not None:                                  # an admission never rescues a structural failure
                self.assertEqual(resolve_cutoff(url, p, self.by[url], admit(url, p))["status"], "unproven", name)
        p = proof(self.f, "ai-code-review-evaluation/disc-graphite")
        p["evidence"].append(ev("fork-mapping", "original-url-commit"))
        self.assertEqual(resolve_cutoff(self.f, p, self.by[self.f])["status"], "attested")
        self.assertEqual(resolve_cutoff(self.f, p, self.by[self.f], admit(self.f, p))["status"], "proven")
        p = proof(self.u, "calx/calx.diy")
        p["evidence"].append(ev("redirect", "api-canonical-url"))
        self.assertEqual(resolve_cutoff(self.u, p, self.by[self.u])["status"], "attested")
        self.assertEqual(resolve_cutoff(self.u, p, self.by[self.u], admit(self.u, p))["status"], "proven")

    def merge_head_proof(self):
        """The observed merge commit (post-review fixes) relabelled with an innocent source name."""
        return proof(self.u, "calx/calx", asOfHead=CALX_OBS["mergeCommitSha"], headCommittedAt=CALX_OBS["mergedAt"],
                     evidence=[ev("commit-time", "github-api", "whatever"), ev("review-time", "github-api", "whatever")])

    def test_N4_relabelled_merge_head_is_only_attested_and_never_selected(self):
        """Re-aimed per the ticket design: a self-attestation is `attested`, never auto-selectable; binding the exact
        SHAs is root's separate admission (not a mechanical merge-commit check)."""
        p = self.merge_head_proof()
        r = resolve_cutoff(self.u, p, self.by[self.u])
        self.assertEqual(r["status"], "attested")
        self.assertEqual(r["binding"]["asOfHead"], CALX_OBS["mergeCommitSha"])   # what root would have to admit
        sel = select_cases(load_proposal(self.pp), self.projection, {self.u: p})
        self.assertNotIn(self.u, sel["dev"] + sel["frozen"])
        self.assertEqual(sel["attested"], [self.u])

    def test_N4_fixed_admission_for_the_honest_head_does_not_carry_to_the_merge_head(self):
        honest = proof(self.u, "calx/calx")
        r = resolve_cutoff(self.u, self.merge_head_proof(), self.by[self.u], admit(self.u, honest))
        self.assertEqual(r["status"], "attested")
        self.assertIn("asOfHead", r["reasons"][0])

    def test_selection_with_no_proofs_selects_nothing_and_reads_no_score(self):
        sel = select_cases(load_proposal(self.pp), self.projection, {})
        self.assertEqual((sel["dev"], sel["frozen"], sel["allReproducible"], sel["scoresRead"]), ([], [], False, False))
        self.assertEqual(len(sel["exclusions"]), 4)

    def test_unproven_dev_candidate_advances_by_declared_rank(self):
        d0, d1 = ranked()["calx"]
        proofs = {d1: proof(d1, "calx/calx")}
        sel = select_cases(load_proposal(self.pp), self.projection, proofs, {d1: admit(d1, proofs[d1])})
        self.assertEqual(sel["dev"], [d1])
        self.assertEqual(sel["frozen"], [])
        self.assertTrue(sel["differsFromDeclared"])
        self.assertIn({"url": d0, "repo": "calx", "rank": 1, "reasons": ["no cutoff proof supplied"]}, sel["exclusions"])


# ---------------------------------------------------------------- semantic judgments, dedup, denominators
JUDGE = {"model": "invented-judge", "extractionPrompt": phaseb.EXTRACT_V, "dedupPrompt": phaseb.DEDUP_V,
         "matchPrompt": phaseb.MATCH_V, "schemaSha256": "sha256:" + "0" * 64, "runRef": "run-invented"}


def judgments(case, tool, cands, groups=None, judge=JUDGE):
    """cands: [(sourceCommentId, text, golden|None)]; groups: list of index lists (first = representative)."""
    cs = [{"id": f"cand:{i}", "sourceCommentId": c, "text": t} for i, (c, t, _) in enumerate(cands)]
    groups = groups or [[i] for i in range(len(cs))]
    return {"schema": "semantic-judgments@1", "caseUrl": case.url, "tool": tool, "judge": dict(judge),
            "extraction": {"candidates": cs},
            "duplicateGroups": [{"id": f"grp:{n}", "representative": f"cand:{g[0]}", "members": [f"cand:{i}" for i in g]}
                                for n, g in enumerate(groups)],
            "matches": [{"candidate": f"cand:{g[0]}", "golden": cands[g[0]][2], "reason": "r"} for g in groups]}


class Scoring(Rig):
    def setUp(self):
        super().setUp()
        self.u = ranked()["calx"][0]
        self.data[self.u] = entry(self.u, comments=[comment(f"INVENTED-BODY {n}", line=n) for n in range(1, 4)])
        self.write()
        self.src = self.source()
        self.case = self.src.cases[self.u]
        self.ids = [c.id for c in self.case.review("coderabbit").comments]
        idx = self.case.index
        self.g = {k: f"gold:{idx}:{n}" for n, k in enumerate(("bug", "perf", "style", "sec"), 1)}

    def big(self):
        a, b, c = self.ids
        g = self.g
        cands = [(a, "c0", g["bug"]), (a, "c1 dup", g["bug"]), (b, "c2", g["perf"]), (b, "c3", g["style"]),
                 (c, "c4", None), (c, "c5", g["bug"]), (c, "c6", g["sec"])]
        return judgments(self.case, "coderabbit", cands, groups=[[0, 1], [2], [3], [4], [5], [6]])

    def test_hand_computed_profiles_dedup_excluded_multimatch(self):
        row = score_case(self.case, self.big())
        v = row["views"]
        want = {"strict": (3, 1, 2, 2, 2), "core": (4, 1, 1, 3, 3), "all": (5, 1, 0, 4, 4)}
        for prof, (tp, fp, ex, rec, tot) in want.items():
            k = v[prof]["counts"]
            self.assertEqual((k["tp"], k["fp"], k["excluded"], k["goldRecalled"], k["goldTotal"]), (tp, fp, ex, rec, tot), prof)
            self.assertAlmostEqual(v[prof]["native"]["precision"]["value"], tp / (tp + fp))
            self.assertEqual(v[prof]["native"]["recall"]["value"], 1.0)
        self.assertAlmostEqual(v["strict"]["native"]["f1"]["value"], 2 * 0.75 / 1.75)
        self.assertAlmostEqual(v["strict"]["native"]["f2"]["value"], 5 * 0.75 / (4 * 0.75 + 1))
        self.assertAlmostEqual(v["core"]["native"]["f1"]["value"], 2 * 0.8 / 1.8)
        self.assertEqual((row["candidates"], row["representatives"], row["duplicateMembersNotCounted"]), (7, 6, 1))
        self.assertEqual(row["multiMatchedGolden"]["core"], [self.g["bug"]])

    def test_LIMIT_multimatch_precision_numerator_differs_from_golden_count(self):
        """Upstream (score_profiles.py 103-118) uses ONE true_positives list for both precision and recall. Ours counts
        matched representatives for precision and distinct goldens for recall, so under multi-match the
        `upstreamCompatZero` view reproduces only the undefined->0 convention, not upstream equivalence (unproven)."""
        a, b, _ = self.ids
        row = score_case(self.case, judgments(self.case, "coderabbit", [(a, "x", self.g["bug"]), (b, "y", self.g["bug"])]))
        z = row["views"]["core"]["upstreamCompatZero"]
        self.assertEqual((z["precision"]["numerator"], z["recall"]["numerator"]), (2, 1))
        self.assertIn("multiMatchedGolden", score_suite(self.src.cases, [], tools=["coderabbit"])["unverifiedSemantics"])

    def test_duplicate_member_is_not_an_independent_false_positive(self):
        a, b, _ = self.ids
        split = judgments(self.case, "coderabbit", [(a, "x", None), (b, "y", None)])
        grouped = judgments(self.case, "coderabbit", [(a, "x", None), (b, "y", None)], groups=[[0, 1]])
        self.assertEqual(score_case(self.case, split)["views"]["core"]["counts"]["fp"], 2)
        self.assertEqual(score_case(self.case, grouped)["views"]["core"]["counts"]["fp"], 1)

    def test_native_null_reason_vs_separately_named_upstream_zero(self):
        u = ranked()["disc"][0]
        self.data[u] = entry(u, gold=[("INVENTED-GOLD naming", "Low", "style")])
        self.write()
        case = self.source().cases[u]
        row = score_case(case, judgments(case, "coderabbit", []))
        s = row["views"]["strict"]
        for k in ("precision", "recall", "f1", "f2"):
            self.assertIsNone(s["native"][k]["value"], k)
            self.assertTrue(s["native"][k]["undefinedReason"], k)
            self.assertEqual(s["upstreamCompatZero"][k]["value"], 0.0, k)
        self.assertEqual(set(s), {"counts", "native", "upstreamCompatZero"})
        # defined-but-zero stays 0.0 natively, not null
        c = case.review("coderabbit").comments[0].id
        z = score_case(case, judgments(case, "coderabbit", [(c, "x", None)]))["views"]["all"]["native"]
        self.assertEqual((z["precision"]["value"], z["recall"]["value"], z["f1"]["value"]), (0.0, 0.0, 0.0))

    def test_no_line_overlap_or_text_heuristic(self):
        a = self.ids[0]
        gold_text = GOLD[0][0]
        row = score_case(self.case, judgments(self.case, "coderabbit", [(a, gold_text, None)]))
        self.assertEqual(row["views"]["core"]["counts"]["tp"], 0)   # identical text, judged unmatched -> FP
        moved = copy.deepcopy(self.data)
        for c in moved[self.u]["reviews"][2]["review_comments"]:
            c["path"], c["line"] = "elsewhere.py", 999
        self.write(data=moved)
        case2 = self.source().cases[self.u]
        doc = lambda case: judgments(case, "coderabbit",
                                     [(case.review("coderabbit").comments[0].id, "t", self.g["bug"])])
        self.assertEqual(score_case(self.case, doc(self.case))["views"], score_case(case2, doc(case2))["views"])

    def test_judgment_validation_refusals(self):
        a, b, _ = self.ids
        other = self.case.review("greptile-v5").comments[0].id
        good = judgments(self.case, "coderabbit", [(a, "x", self.g["bug"]), (b, "y", None)], groups=[[0, 1]])
        bad = {}
        d = copy.deepcopy(good); d["extraction"]["candidates"][0]["sourceCommentId"] = other; bad["foreign comment"] = ("judgments", d)
        d = copy.deepcopy(good); d["matches"].append({"candidate": "cand:1", "golden": None, "reason": "r"}); bad["member judged"] = ("judgments", d)
        d = copy.deepcopy(good); d["matches"] = []; bad["rep unjudged"] = ("incomplete", d)
        d = copy.deepcopy(good); d["duplicateGroups"][0]["members"] = ["cand:0"]; bad["ungrouped"] = ("incomplete", d)
        d = copy.deepcopy(good); d["duplicateGroups"].append({"id": "g2", "representative": "cand:1", "members": ["cand:1"]}); bad["two groups"] = ("judgments", d)
        d = copy.deepcopy(good); d["matches"][0]["golden"] = "gold:99:1"; bad["unknown gold"] = ("judgments", d)
        d = copy.deepcopy(good); d["caseUrl"] = ranked()["calx"][1]; bad["case url"] = ("judgments", d)
        d = copy.deepcopy(good); d["judge"]["temperature"] = "0"; bad["judge key"] = ("judgments", d)
        d = copy.deepcopy(good); d["duplicateGroups"][0]["representative"] = "cand:9"; bad["rep not member"] = ("judgments", d)
        for name, (code, doc) in bad.items():
            with self.subTest(name):
                self.refused(code, score_case, self.case, doc)
        score_case(self.case, good)                                  # control

    def test_suite_pools_micro_counts_lists_missing_and_refuses_judge_mix(self):
        u2 = ranked()["calx"][1]
        c2 = self.src.cases[u2]
        d1 = judgments(self.case, "coderabbit", [(self.ids[0], "x", self.g["bug"])])
        d2 = judgments(c2, "coderabbit", [(c2.review("coderabbit").comments[0].id, "y", None)])
        rep = score_suite(self.src.cases, [d1, d2], tools=["coderabbit"])
        t = rep["tools"]["coderabbit"]
        self.assertEqual(t["pooled"]["core"]["counts"], {"tp": 1, "fp": 1, "excluded": 0, "goldRecalled": 1, "goldTotal": 6})
        self.assertEqual((t["casesScored"], len(t["missing"]), t["complete"], rep["complete"]), (2, 2, False, False))
        self.assertEqual(rep["primary"]["name"], "core/F1")
        self.assertIn("NOT reference-compatible", rep["unverifiedSemantics"])
        self.assertIn("B2/B3 are on HOLD", rep["unverifiedSemantics"])
        self.assertEqual(rep["referenceCompatibleView"]["status"], "unavailable")
        other = dict(JUDGE, model="other-judge")
        d3 = judgments(c2, "greptile-v5", [(c2.review("greptile-v5").comments[0].id, "z", None)], judge=other)
        self.refused("judge-mismatch", score_suite, self.src.cases, [d1, d3], tools=["coderabbit", "greptile-v5"])

    def test_case_without_the_tool_review_is_incomplete_not_zero(self):
        u2 = ranked()["calx"][1]
        self.data[u2]["reviews"] = [r for r in self.data[u2]["reviews"] if r["tool"] != "coderabbit"]
        self.write()
        src = self.source()
        d = judgments(src.cases[u2], "coderabbit", [])
        d["tool"] = "coderabbit"
        t = score_suite(src.cases, [d], tools=["coderabbit"], urls=[u2])["tools"]["coderabbit"]
        self.assertEqual((t["casesScored"], len(t["incomplete"]), t["pooled"]), (0, 1, None))

    def test_N5_raw_comments_with_no_candidate_are_reported(self):
        a, b, c = self.ids
        row = score_case(self.case, judgments(self.case, "coderabbit", [(a, "x", self.g["bug"])]))
        self.assertIn(b, json.dumps(row))
        self.assertIn(c, json.dumps(row))

    def test_N5_fixed_dropping_comments_still_raises_precision_but_is_now_reported(self):
        a, b, c = self.ids
        full = judgments(self.case, "coderabbit", [(a, "x", self.g["bug"]), (b, "y", None), (c, "z", None)])
        cut = judgments(self.case, "coderabbit", [(a, "x", self.g["bug"])])
        pf = score_case(self.case, full)["views"]["core"]["native"]["precision"]["value"]
        rc = score_case(self.case, cut)
        self.assertEqual((round(pf, 4), rc["views"]["core"]["native"]["precision"]["value"]), (0.3333, 1.0))
        self.assertEqual((rc["rawComments"], rc["uncoveredCommentIds"]), (3, [b, c]))
        self.assertEqual(score_case(self.case, full)["uncoveredCommentIds"], [])

    def test_N6_judgments_for_unrequested_cases_or_tools_are_not_silently_dropped(self):
        d = judgments(self.case, "coderabbit", [(self.ids[0], "x", None)])
        stray = dict(d, caseUrl="https://github.com/calx/calx/pull/999")
        with self.assertRaises(BenchmarkError):
            score_suite(self.src.cases, [d, stray], tools=["coderabbit"])

    def test_N6_fixed_stray_case_or_tool_judgment_refused_with_judgments_code(self):
        d = judgments(self.case, "coderabbit", [(self.ids[0], "x", None)])
        for stray in (dict(d, caseUrl="https://github.com/calx/calx/pull/999"), dict(d, tool="greptile-v5")):
            e = self.refused("judgments", score_suite, self.src.cases, [d, stray], tools=["coderabbit"])
            self.assertIn("not requested", e.message)

    def test_cli_score_end_to_end(self):
        jp = self.ops / "j.json"
        jp.write_text(json.dumps([self.big()]))
        rc, out, _ = self.cli("score", "--pins", str(self.pins), "--data", str(self.dp), "--labels", str(self.lp),
                              "--proposal", str(self.pp), "--judgments", str(jp), "--tools", "coderabbit",
                              "--out", str(self.ops / "score.json"))
        self.assertEqual(rc, 0)
        rep = json.loads(out)
        self.assertEqual(rep["tools"]["coderabbit"]["pooled"]["core"]["counts"]["tp"], 4)
        self.assertNotIn("INVENTED-GOLD", out)
        self.assertNotIn("INVENTED-BODY", out)


# ---------------------------------------------------------------- native vs upstream reference matching semantics
def reference_counts(goldens, candidates, groups, results):
    """Test oracle for the pinned upstream counting rule (step3_judge_comments.py 275-377, score_profiles.py 97-118;
    read as text, not executed). results: ordered [(golden_text, candidate_text, match, confidence)] in upstream's
    golden-major order. Returns (tp_goldens, fp_candidates, fn) for one case, or None when upstream skips it."""
    if not goldens:
        return None
    best = {g: 0.0 for g in goldens}
    hit = {g: False for g in goldens}
    cm = dict.fromkeys(candidates, False)
    sib = {}
    for grp in groups or []:
        texts = {candidates[i] for i in grp}
        for i in grp:
            sib[candidates[i]] = texts - {candidates[i]}
    for g, c, match, conf in results:
        if match and conf > best[g]:
            best[g], hit[g], cm[c] = conf, True, True
            for s in sib.get(c, ()):
                cm[s] = True
    tp = sum(hit.values())
    return tp, sum(1 for v in cm.values() if not v), len(goldens) - tp


class MatchingSemantics(Rig):
    """Bounded many-to-one / one-to-many / sibling / zero-gold controls (martian-matching-semantics receipt).
    Native counts are the package's; reference numbers come from the oracle above. They are expected to DIFFER;
    the gate is that both stay separately named and neither is called the other."""

    def setUp(self):
        super().setUp()
        self.u = ranked()["calx"][0]
        self.data[self.u] = entry(self.u, gold=GOLD[:2], comments=[comment(f"INVENTED-BODY {n}", line=n) for n in (1, 2)])
        self.write()
        self.src = self.source()
        self.case = self.src.cases[self.u]
        self.a, self.b = [c.id for c in self.case.review("coderabbit").comments]
        self.g1, self.g2 = (g.id for g in self.case.golden)

    def native(self, cands, groups=None):
        k = score_case(self.case, judgments(self.case, "coderabbit", cands, groups))["views"]["core"]
        return (k["counts"]["tp"], k["counts"]["fp"], k["counts"]["goldRecalled"]), k["native"]["precision"]["value"]

    def test_many_to_one_native_counts_representatives_reference_counts_goldens(self):
        (tp, fp, rec), p = self.native([(self.a, "x", self.g1), (self.b, "y", self.g1)])
        self.assertEqual(((tp, fp, rec), p), ((2, 0, 1), 1.0))
        G = [GOLD[0][0], GOLD[1][0]]
        tie = reference_counts(G, ["x", "y"], None, [(G[0], "x", True, .9), (G[0], "y", True, .9)])
        rising = reference_counts(G, ["x", "y"], None, [(G[0], "x", True, .8), (G[0], "y", True, .9)])
        self.assertEqual(tie, (1, 1, 1))          # equal confidence: second candidate is an upstream FP
        self.assertEqual(rising, (1, 0, 1))       # strictly higher: order-sensitive, no FP
        self.assertNotEqual(tp / (tp + fp), tie[0] / (tie[0] + tie[1]))

    def test_unmatched_duplicate_group_native_one_fp_reference_every_member(self):
        (_, fp, _), _ = self.native([(self.a, "x", None), (self.b, "y", None)], groups=[[0, 1]])
        G = [GOLD[0][0], GOLD[1][0]]
        ref = reference_counts(G, ["x", "y"], [[0, 1]], [(g, c, False, 0) for g in G for c in ("x", "y")])
        self.assertEqual((fp, ref[1]), (1, 2))
        matched = reference_counts(G, ["x", "y"], [[0, 1]], [(G[0], "x", True, .9)])
        self.assertEqual(matched[1], 0)           # a matched candidate protects its siblings in both views
        (_, fp, _), _ = self.native([(self.a, "x", self.g1), (self.b, "y", None)], groups=[[0, 1]])
        self.assertEqual(fp, 0)

    def test_zero_gold_case_native_counts_fp_reference_skips(self):
        u = ranked()["disc"][0]
        self.data[u] = entry(u, gold=[])
        self.write()
        src = self.source()
        c = src.cases[u]
        d = judgments(c, "coderabbit", [(c.review("coderabbit").comments[0].id, "x", None)])
        t = score_suite(src.cases, [d], tools=["coderabbit"], urls=[u])["tools"]["coderabbit"]
        self.assertEqual((t["casesScored"], t["pooled"]["core"]["counts"]["fp"]), (1, 1))
        self.assertIsNone(reference_counts([], ["x"], None, []))

    @unittest.expectedFailure
    def test_S1_one_candidate_may_match_two_goldens(self):
        doc = judgments(self.case, "coderabbit", [(self.a, "x", self.g1)])
        doc["matches"].append({"candidate": "cand:0", "golden": self.g2, "reason": "r"})
        row = score_case(self.case, doc)
        self.assertEqual(row["views"]["core"]["counts"]["goldRecalled"], 2)

    def test_S1_symptom_one_to_many_is_unrepresentable(self):
        doc = judgments(self.case, "coderabbit", [(self.a, "x", self.g1)])
        doc["matches"].append({"candidate": "cand:0", "golden": self.g2, "reason": "r"})
        e = self.refused("judgments", score_case, self.case, doc)
        self.assertIn("two matches", e.message)
        G = [GOLD[0][0], GOLD[1][0]]
        self.assertEqual(reference_counts(G, ["x"], None, [(G[0], "x", True, .9), (G[1], "x", True, .9)]), (2, 0, 0))
        self.assertNotIn("confidence", json.dumps(phaseb.SCHEMAS[phaseb.MATCH_V]))   # order rule needs it

    @unittest.expectedFailure
    def test_S2_report_has_a_separately_named_reference_compatible_view(self):
        (tp, fp, _), _ = self.native([(self.a, "x", None), (self.b, "y", None)], groups=[[0, 1]])
        views = score_case(self.case, judgments(self.case, "coderabbit", [(self.a, "x", None), (self.b, "y", None)],
                                                [[0, 1]]))["views"]["core"]
        others = {k: v for k, v in views.items() if k not in ("counts", "native", "upstreamCompatZero")}
        self.assertTrue(any(isinstance(v, dict) and v.get("counts", {}).get("fp") == 2 for v in others.values()))

    def test_S2_symptom_upstream_named_view_reuses_native_counts(self):
        k = score_case(self.case, judgments(self.case, "coderabbit", [(self.a, "x", None), (self.b, "y", None)],
                                            [[0, 1]]))["views"]["core"]
        self.assertEqual(set(k), {"counts", "native", "upstreamCompatZero"})
        self.assertEqual(k["upstreamCompatZero"]["precision"]["denominator"], k["native"]["precision"]["denominator"])
        self.assertEqual(k["upstreamCompatZero"]["precision"]["denominator"], 1)   # reference would be 2


# ---------------------------------------------------------------- Phase B interface honesty
class PhaseB(Rig):
    def test_interface_only_scoring_accounting_no_calls(self):
        self.assertEqual((phaseb.SEAM["status"], phaseb.SEAM["callsMade"]), ("unresolved", 0))
        self.assertEqual((phaseb.ACCOUNTING["category"], phaseb.ACCOUNTING["reviewCost"],
                          phaseb.ACCOUNTING["countsTowardAggregateCap"]), ("scoring", False, True))
        callables = [n for n in dir(phaseb) if callable(getattr(phaseb, n)) and not n.startswith("_")]
        self.assertFalse([n for n in callables if any(w in n.lower() for w in ("call", "send", "invoke", "run", "post"))])

    def test_match_request_carries_no_path_or_line(self):
        case = self.source().cases[ranked()["calx"][0]]
        reps = [{"id": "cand:0", "text": "INVENTED candidate"}]
        content = json.dumps(phaseb.match_request(reps, case)["messages"])
        self.assertNotIn("src/a.py", content)
        self.assertNotIn("(src", content)
        self.assertIn("(src/a.py:3)", json.dumps(phaseb.extraction_request(case.review("coderabbit"))))  # control
        self.refused("judgments", phaseb.validate_match, ["cand:0"], case,
                     {"matches": [{"candidate": "cand:0", "golden": "gold:99:1", "reason": ""}]})
        self.refused("incomplete", phaseb.validate_match, ["cand:0", "cand:1"], case,
                     {"matches": [{"candidate": "cand:0", "golden": None, "reason": ""}]})


if __name__ == "__main__":
    unittest.main()
