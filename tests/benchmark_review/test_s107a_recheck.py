"""S1-07a-inputs-recheck: independent recheck of B1/N1-N6 under the declared API changes (S1-07a-fix-inputs handoff).

Invented tiny cases and metadata-shaped receipts only; tool ids mirror the metadata receipt. CONTROL tests must pass;
`*_LIMIT_*` / `*_GAP_*` tests pin a known open limit so it stays visible (they pass today and say what is missing).
"""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from reviewer.benchmark import phaseb
from reviewer.benchmark.cutoff import resolve_cutoff, select_cases
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.loader import load_proposal, load_source
from reviewer.benchmark.model import KNOWN_SEVERITIES, build_case
from reviewer.benchmark.projection import project_metadata, resolve_versions
from reviewer.benchmark.scoring import score_case, score_suite

from .test_s107a_gate import (JUDGE, TOOLS, Rig, admit, comment, entry, ev, judgments,
                              proof, ranked)

# A version-rules v2 policy of the shape the project plans to use; the skips are invented.
SRC = {"blob": "fa3f38ce", "quote": "invented"}


def fam2(prefix, hidden, primary=None, secondary=(), skipped=()):
    d = {"prefix": prefix, "upstreamHidden": list(hidden), "skipped": list(skipped), "source": SRC}
    if primary is not None:
        d.update(primary=primary, primaryBasis="COMPARISON-POLICY 2026-10-26 highest surviving id",
                 secondary=list(secondary))
    return d


def rules2():
    return {"schema": "benchmark-version-rules@2",
            "selectionDecision": {"by": "root", "at": "2026-10-26", "ref": "COMPARISON-POLICY.md", "scoresSeen": False},
            "families": {"cubic": fam2("cubic", ["cubic-dev", "cubic-v3"], "cubic-v2"),
                         "coderabbit": fam2("coderabbit", [], "coderabbit"),
                         "greptile": fam2("greptile", ["greptile", "greptile-v4"], "greptile-v5", ["greptile-v4-1"])}}


class SummaryComments(Rig):
    """B1 at census proportions: 3616/9574 comments are (null, null) summaries (benchmark-real-shape-refusal.json)."""

    def mixed(self, u, n_inline=3, n_summary=2):
        cs = [comment(f"INVENTED-BODY summary {i}", path=None, line=None) for i in range(n_summary)]
        cs += [comment(f"INVENTED-BODY inline {i}", path=f"src/{i}.py", line=i + 1) for i in range(n_inline)]
        cs.append(comment("INVENTED-BODY outdated", path="src/o.py", line=None))
        self.data[u] = entry(u, comments=cs)

    def test_control_every_comment_survives_loader_projection_and_inspect(self):
        for us in ranked().values():
            for u in us:
                self.mixed(u)
        self.write()
        raw = sum(len(r["review_comments"]) for e in self.data.values() for r in e["reviews"])
        raw_summary = sum(c["path"] is None for e in self.data.values() for r in e["reviews"] for c in r["review_comments"])
        src = self.source()
        loaded = sum(len(r.comments) for c in src.cases.values() for r in c.reviews)
        proj = project_metadata(src)
        self.assertEqual(loaded, raw)
        self.assertEqual(sum(r["commentCount"] for c in proj["cases"] for r in c["reviews"]), raw)
        self.assertEqual(sum(r["summaryCommentCount"] for c in proj["cases"] for r in c["reviews"]), raw_summary)
        self.assertEqual(raw_summary, 4 * len(TOOLS) * 2)
        rep = src.report()
        self.assertEqual(rep["cases"], 4)
        out = json.dumps(rep) + json.dumps(proj)
        self.assertNotIn("INVENTED-BODY", out)

    def test_control_ids_distinct_stable_and_typed(self):
        u = ranked()["calx"][0]
        self.mixed(u)
        self.write()
        a = [c.id for c in self.source().cases[u].review("coderabbit").comments]
        b = [c.id for c in load_source(self.pins, self.dp, self.lp, self.pp).cases[u].review("coderabbit").comments]
        self.assertEqual(a, b)
        self.assertEqual(len(set(a)), len(a))
        variants = [(None, None), ("None", None), ("", None), ("a", None), ("a", 0), ("a", 3), ("3", 3)]
        ids = {build_case(u, 0, entry(u, comments=[comment("INVENTED-BODY s", path=p, line=l)])).reviews[0].comments[0].id
               for p, l in variants}
        self.assertEqual(len(ids), len(variants))
        # the url and tool are inside the id: the same comment under another tool/case is a different id
        e = entry(u, tools=("coderabbit", "greptile-v5"), comments=[comment("INVENTED-BODY s", path=None, line=None)])
        c = build_case(u, 0, e)
        self.assertNotEqual(c.reviews[0].comments[0].id, c.reviews[1].comments[0].id)

    def test_refusal_matrix_for_malformed_comment_types(self):
        u = ranked()["calx"][0]
        bad = {"null path int line": (None, 4), "bool line": ("a", True), "float line": ("a", 3.0),
               "str line": ("a", "3"), "int path": (3, None), "list path": (["a"], 1)}
        for name, (p, l) in bad.items():
            with self.subTest(name):
                self.refused("shape", build_case, u, 0, entry(u, comments=[comment("INVENTED-BODY", path=p, line=l)]))
        for k in ("body", "created_at"):
            c = comment("INVENTED-BODY")
            c[k] = None
            with self.subTest(k):
                self.refused("shape", build_case, u, 0, entry(u, comments=[c]))

    def test_control_summary_is_citable_counted_and_reported_when_uncited(self):
        u = ranked()["calx"][0]
        self.mixed(u, n_inline=1, n_summary=2)
        self.write()
        case = self.source().cases[u]
        cs = case.review("coderabbit").comments
        s0, s1, inline, outdated = cs[0].id, cs[1].id, cs[2].id, cs[3].id
        doc = judgments(case, "coderabbit", [(s0, "x", f"gold:{case.index}:1"), (inline, "y", None)])
        row = score_case(case, doc)
        self.assertEqual(row["views"]["core"]["counts"]["tp"], 1)
        self.assertEqual((row["rawComments"], row["uncoveredCommentIds"]), (4, [s1, outdated]))
        cov = score_suite({u: case}, [doc], tools=["coderabbit"])["tools"]["coderabbit"]["extractionCoverage"]
        self.assertEqual(cov, {"rawComments": 4, "uncoveredComments": 2, "casesWithUncovered": [u]})

    def test_GAP_phaseb_extraction_renders_summary_metadata_as_None_None(self):
        """Not owned by the fix ticket (phaseb.py). Interface text only, but must be null-aware before Phase B."""
        u = ranked()["calx"][0]
        self.mixed(u, n_inline=0, n_summary=1)
        self.write()
        text = json.dumps(phaseb.extraction_request(self.source().cases[u].review("coderabbit")))
        self.assertIn("(None:None)", text)

    def test_LIMIT_identical_comments_in_one_review_share_an_id(self):
        u = ranked()["calx"][0]
        c = build_case(u, 0, entry(u, comments=[comment("INVENTED-BODY same")] * 2)).reviews[0].comments
        self.assertEqual((len(c), c[0].id == c[1].id), (2, True))   # both kept and counted; one citation covers both


# Public oracle for the accepted gold severity strings: stated here independently of reviewer.benchmark.model, so this
# test needs no private receipt. Matching is exact; anything else is refused (see the invalid controls below).
PUBLIC_SEVERITY_VOCABULARY = ("Critical", "High", "Medium", "Low")


class Severity(Rig):
    def test_vocabulary_equals_the_public_oracle_and_all_four_load(self):
        self.assertEqual(len(set(PUBLIC_SEVERITY_VOCABULARY)), 4)
        self.assertEqual(set(PUBLIC_SEVERITY_VOCABULARY), set(KNOWN_SEVERITIES))
        u = ranked()["calx"][0]
        self.data[u] = entry(u, gold=[(f"INVENTED-GOLD {s}", s, "bug") for s in sorted(PUBLIC_SEVERITY_VOCABULARY)])
        self.write()
        self.assertEqual(sorted(g.severity for g in self.source().cases[u].golden), sorted(PUBLIC_SEVERITY_VOCABULARY))
        for s in ("critical", "Medium ", "Info", ""):
            self.data[u] = entry(u, gold=[("INVENTED-GOLD x", s, "bug")])
            self.write()
            self.assertIn(self.refused_code(), ("severity", "shape"), repr(s))   # "" is refused by the type check

    def refused_code(self):
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        return cm.exception.code


class DuplicateReview(Rig):
    def test_distinct_tools_load_and_a_repeated_tool_refuses_the_import(self):
        u = ranked()["calx"][0]
        self.assertEqual(len(self.source().cases[u].reviews), len(TOOLS))           # control
        r = copy.deepcopy(next(x for x in self.data[u]["reviews"] if x["tool"] == "greptile-v5"))
        r["repo_name"], r["review_comments"] = "x__greptile-v5__rerun", []
        self.data[u]["reviews"].append(r)
        self.write()
        self.refused("shape", self.source)


class VersionsV2(Rig):
    def proj(self):
        return project_metadata(self.source())

    def test_root_planned_policy_resolves_with_explicit_primary_and_full_audit(self):
        v = resolve_versions(self.proj(), rules2())
        self.assertEqual((v["status"], v["rulesVersion"]), ("resolved", 2))
        self.assertEqual(v["chosen"], {"cubic": "cubic-v2", "coderabbit": "coderabbit", "greptile": "greptile-v5"})
        self.assertEqual(v["selectionDecision"], rules2()["selectionDecision"])
        for fam in ("cubic", "coderabbit", "greptile"):
            self.assertEqual(v["families"][fam]["choiceBasis"], "explicit-primary", fam)
        g = {a["id"]: (a["status"], a["reason"]) for a in v["families"]["greptile"]["audit"]}
        self.assertEqual({k: s for k, (s, _) in g.items()}, {"greptile": "excluded", "greptile-v4": "excluded",
                                                             "greptile-v4-1": "not-selected", "greptile-v5": "survives"})
        self.assertIn("hidden by the pinned upstream", g["greptile-v4"][1])
        self.assertIn("secondary", g["greptile-v4-1"][1])
        c = {a["id"]: a["status"] for a in v["families"]["cubic"]["audit"]}
        self.assertEqual(c, {"cubic-dev": "excluded", "cubic-v2": "survives"})    # unobserved cubic-v3 is not invented
        audited = {a["id"] for f in v["families"].values() for a in f["audit"]}
        self.assertEqual(audited, set(TOOLS))                                     # every observed family id
        self.assertNotIn("supersed", json.dumps(v).lower())                       # never "superseded by upstream"
        self.assertEqual(len(v["attempted"]), 4)

    def test_secondary_keeps_its_own_common_eligible_set(self):
        u1, u2 = ranked()["calx"]
        self.data[u2]["reviews"] = [r for r in self.data[u2]["reviews"] if r["tool"] != "greptile-v4-1"]
        self.write()
        r = rules2()
        r["families"]["greptile"]["skipped"] = [{"tool": "greptile-v5", "prUrl": u1}]
        v = resolve_versions(self.proj(), r)
        self.assertEqual(set(v["omitted"]), {u1})
        (sec,) = v["secondaryComparisons"]
        self.assertEqual((sec["family"], sec["tool"], sec["chosen"]["greptile"]), ("greptile", "greptile-v4-1",
                                                                                   "greptile-v4-1"))
        self.assertEqual(set(sec["omitted"]), {u2})
        self.assertEqual(len(v["commonEligibleSet"]), 3)
        self.assertEqual(len(sec["commonEligibleSet"]), 3)
        self.assertNotEqual(set(v["commonEligibleSet"]), set(sec["commonEligibleSet"]))

    def test_missing_hidden_or_foreign_primary_leaves_unresolved_with_nothing_chosen(self):
        cases = {"missing primary": dict(primary="greptile-v6"), "hidden primary": dict(primary="greptile-v4"),
                 "other family primary": dict(primary="cubic-v2"),
                 "hidden secondary": dict(primary="greptile-v5", secondary=["greptile"]),
                 "missing secondary": dict(primary="greptile-v5", secondary=["greptile-v9"])}
        for name, kw in cases.items():
            with self.subTest(name):
                r = rules2()
                r["families"]["greptile"] = fam2("greptile", ["greptile", "greptile-v4"], **kw)
                v = resolve_versions(self.proj(), r)
                self.assertEqual((v["status"], v["commonEligibleSet"]), ("unresolved", None))
                self.assertNotIn("chosen", v)
                self.assertIsNone(v["families"]["greptile"]["chosen"])

    def test_primary_outside_prefix_is_unresolved_and_audited(self):
        r = rules2()
        r["families"]["cubic"] = fam2("cubic-v", [], "cubic-dev")
        v = resolve_versions(self.proj(), r)
        self.assertEqual(v["status"], "unresolved")
        a = {x["id"]: x for x in v["families"]["cubic"]["audit"]}
        self.assertEqual(a["cubic-dev"]["status"], "excluded")
        self.assertIn("prefix", a["cubic-dev"]["reason"])

    def test_without_primary_two_survivors_stay_unresolved(self):
        r = rules2()
        r["families"]["greptile"] = fam2("greptile", ["greptile", "greptile-v4"])
        v = resolve_versions(self.proj(), r)
        self.assertEqual((v["status"], v["families"]["greptile"]["candidates"]), ("unresolved",
                                                                                  ["greptile-v4-1", "greptile-v5"]))

    def test_malformed_v2_documents_refused(self):
        bad = {}
        r = rules2(); del r["selectionDecision"]; bad["no selectionDecision"] = r
        r = rules2(); r["selectionDecision"] = {}; bad["empty selectionDecision"] = r
        r = rules2(); r["extra"] = 1; bad["extra top key"] = r
        r = rules2(); g = r["families"]["greptile"]; g["superseded"] = g.pop("upstreamHidden"); bad["v1 key in v2"] = r
        r = rules2(); del r["families"]["greptile"]["secondary"]; bad["primary without secondary"] = r
        r = rules2(); r["families"]["greptile"]["secondary"] = ["greptile-v5"]; bad["primary also secondary"] = r
        r = rules2(); r["families"]["greptile"]["primaryBasis"] = ""; bad["empty primaryBasis"] = r
        r = rules2(); r["families"]["greptile"]["secondary"] = ["greptile-v4-1"] * 2; bad["repeated secondary"] = r
        r = rules2(); r["schema"] = "benchmark-version-rules@1"; bad["primary in v1"] = r
        for name, doc in bad.items():
            with self.subTest(name):
                self.refused("rules", resolve_versions, self.proj(), doc)


class Admission(Rig):
    """N4: `attested` for structurally plausible self-attestation; `proven` only with a separate root admission that
    binds URL/repo/base/head/merge-base/every evidence digest. The proof cannot approve itself."""

    def setUp(self):
        super().setUp()
        self.projection = project_metadata(self.source())
        self.by = {c["url"]: c for c in self.projection["cases"]}
        self.u = ranked()["calx"][0]
        self.p = proof(self.u, "calx/calx")

    def status(self, p, a=None, url=None):
        url = url or self.u
        return resolve_cutoff(url, p, self.by[url], a)

    def test_control_positive_admission_and_digest_recipe_independent(self):
        self.assertEqual(self.status(self.p, admit(self.u, self.p))["status"], "proven")
        # admit() writes the binding out itself; it must equal what the package says root has to bind
        b = self.status(self.p)["binding"]
        a = admit(self.u, self.p)
        self.assertEqual(b, {k: a[k] for k in b})

    def test_proof_cannot_approve_itself(self):
        selfish = dict(self.p, status="proven", admission=admit(self.u, self.p), admittedBy="root")
        self.assertEqual(self.status(selfish)["status"], "attested")
        sel = select_cases(load_proposal(self.pp), self.projection, {self.u: selfish})
        self.assertEqual((sel["dev"], sel["frozen"], sel["attested"]), ([], [], [self.u]))
        for who in ("benchmark-author", "proof", "Root", "root "):
            self.assertEqual(self.status(self.p, admit(self.u, self.p, admittedBy=who))["status"], "attested", who)

    def test_admission_binding_field_mutations_are_rejected(self):
        other = proof(self.u, "calx/calx", asOfBase="3" * 40, asOfHead="4" * 40, mergeBase="3" * 40)
        muts = {"asOfBase": dict(asOfBase="3" * 40), "asOfHead": dict(asOfHead="4" * 40),
                "mergeBase": dict(mergeBase="3" * 40), "resolvedRepo": dict(resolvedRepo="calx/calx-fork"),
                "originalUrl": dict(originalUrl=ranked()["calx"][1]),
                "evidenceDigests": dict(evidenceDigests=admit(self.u, other | {"evidence": [ev("commit-time", "g")] +
                                                                              self.p["evidence"]})["evidenceDigests"]),
                "unsorted digests": dict(evidenceDigests=admit(self.u, self.p)["evidenceDigests"][::-1]),
                "decisionRef": dict(decisionRef=" "), "admittedAt": dict(admittedAt="yesterday"),
                "schema": dict(schema="benchmark-cutoff-admission@2")}
        for name, kw in muts.items():
            with self.subTest(name):
                self.assertEqual(self.status(self.p, admit(self.u, self.p, **kw))["status"], "attested")
        extra = admit(self.u, self.p) | {"note": "x"}
        missing = admit(self.u, self.p)
        del missing["decisionRef"]
        for a in (extra, missing, [admit(self.u, self.p)], "root"):
            self.assertEqual(self.status(self.p, a)["status"], "attested")

    def test_proof_edits_after_admission_drop_back_to_attested(self):
        a = admit(self.u, self.p)
        edits = {"asOfHead": dict(asOfHead="5" * 40), "asOfBase": dict(asOfBase="5" * 40),
                 "mergeBase": dict(mergeBase="5" * 40), "resolvedRepo": dict(resolvedRepo="calx/other"),
                 "evidence value": dict(evidence=[dict(self.p["evidence"][0], value="6" * 40), self.p["evidence"][1]]),
                 "evidence observedAt": dict(evidence=[dict(self.p["evidence"][0], observedAt="u"), self.p["evidence"][1]]),
                 "evidence added": dict(evidence=self.p["evidence"] + [ev("upstream-pin", "pinned-ref")]),
                 "evidence removed": dict(evidence=self.p["evidence"] + [ev("upstream-pin", "pinned-ref")])}
        for name, kw in edits.items():
            q = copy.deepcopy(self.p)
            q.update(kw)
            if name == "evidence removed":                     # admit the longer list, then drop one item
                a2 = admit(self.u, q)
                q["evidence"] = q["evidence"][:2]
                self.assertEqual(self.status(q, a2)["status"], "attested", name)
                continue
            self.assertIn(self.status(q, a)["status"], ("attested", "unproven"), name)
            self.assertNotEqual(self.status(q, a)["status"], "proven", name)

    def test_admission_cannot_rescue_structural_failures(self):
        for name, p in {"merged-head source": proof(self.u, "calx/calx", evidence=self.p["evidence"] +
                                                    [ev("upstream-pin", "merge-commit")]),
                        "late head": proof(self.u, "calx/calx", headCommittedAt="2026-02-01T00:00:00Z"),
                        "no review-time": proof(self.u, "calx/calx", evidence=[self.p["evidence"][0]])}.items():
            self.assertEqual(self.status(p, admit(self.u, p))["status"], "unproven", name)

    def test_admission_for_one_url_does_not_transfer_and_non_roster_keys_refused(self):
        u2 = ranked()["calx"][1]
        p2 = proof(u2, "calx/calx")
        self.assertEqual(self.status(p2, admit(self.u, self.p), url=u2)["status"], "attested")
        self.refused("roster", select_cases, load_proposal(self.pp), self.projection, {self.u: self.p},
                     {"https://github.com/calx/calx/pull/999": admit(self.u, self.p)})

    def test_selection_takes_only_admitted_and_lists_attested(self):
        d0, d1 = ranked()["calx"]
        f0 = ranked()["disc"][0]
        pf = proof(f0, "ai-code-review-evaluation/disc-graphite", evidence=self.p["evidence"] +
                   [ev("fork-mapping", "original-url-commit")])
        proofs = {d0: proof(d0, "calx/calx"), d1: proof(d1, "calx/calx"), f0: pf}
        sel = select_cases(load_proposal(self.pp), self.projection, proofs, {d0: admit(d0, proofs[d0])})
        self.assertEqual((sel["dev"], sel["frozen"]), ([d0], []))
        self.assertEqual(sel["attested"], sorted([d1, f0]))
        self.assertFalse(sel["scoresRead"])
        reasons = {x["url"]: x["reasons"][0] for x in sel["exclusions"]}
        self.assertIn("root admission", reasons[d1])

    def test_LIMIT_headCommittedAt_is_not_bound_by_the_admission(self):
        """Low: the temporal sanity input can be edited after admission and the case stays proven. Admission binds the
        fields the ticket names; binding a whole-proof digest (or headCommittedAt) would close this."""
        a = admit(self.u, self.p)
        q = dict(self.p, headCommittedAt="2025-12-31T23:59:59Z")
        self.assertEqual(self.status(q, a)["status"], "proven")

    def test_GAP_cli_select_has_no_admissions_input_so_nothing_can_be_proven(self):
        pj, pr = self.ops / "projection.json", self.ops / "proofs.json"
        pj.write_text(json.dumps(self.projection))
        pr.write_text(json.dumps({self.u: self.p}))
        rc, out, _ = self.cli("select", "--projection", str(pj), "--proposal", str(self.pp), "--proofs", str(pr))
        sel = json.loads(out)
        self.assertEqual((rc, sel["dev"], sel["frozen"], sel["attested"]), (0, [], [], [self.u]))
        with self.assertRaises(SystemExit) as cm:
            self.cli("select", "--projection", str(pj), "--proposal", str(self.pp), "--proofs", str(pr),
                     "--admissions", str(pr))
        self.assertEqual(cm.exception.code, 2)


class ScoringHonesty(Rig):
    def setUp(self):
        super().setUp()
        self.src = self.source()
        self.u = ranked()["calx"][0]
        self.case = self.src.cases[self.u]
        self.cid = self.case.review("coderabbit").comments[0].id

    def test_extra_judgments_refused_and_requested_missing_still_listed(self):
        d = judgments(self.case, "coderabbit", [(self.cid, "x", None)])
        rep = score_suite(self.src.cases, [d], tools=["coderabbit"])                       # control
        self.assertEqual(len(rep["tools"]["coderabbit"]["missing"]), 3)
        self.refused("judgments", score_suite, self.src.cases, [d], tools=["coderabbit"], urls=[ranked()["calx"][1]])
        self.refused("judgments", score_suite, self.src.cases, [d, "not a doc"], tools=["coderabbit"])
        self.refused("judgments", score_suite, self.src.cases, [d, dict(d)], tools=["coderabbit"])   # repeat key

    def test_native_zero_label_honest_and_reference_view_unavailable(self):
        rep = score_suite(self.src.cases, [judgments(self.case, "coderabbit", [(self.cid, "x", None)])],
                          tools=["coderabbit"])
        z = rep["tools"]["coderabbit"]["pooled"]["core"]["upstreamCompatZero"]
        self.assertIn("native counts", z["label"])
        self.assertIn("not the reference formula", z["label"])
        self.assertEqual(rep["referenceCompatibleView"]["status"], "unavailable")
        self.assertEqual(rep["judge"], JUDGE)


DEMO = Path(__file__).resolve().parents[2] / "examples" / "benchmark_demo.py"


class PublicRecipe(unittest.TestCase):
    """The documented offline how-to (reviewer/benchmark/README.md) is runnable: examples/benchmark_demo.py drives the real
    `reference-score` entry point on invented data and checks hand-derived counts plus the refusal and incomplete controls."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("benchmark_demo_under_test", DEMO)
        cls.demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.demo)

    def test_recipe_runs_offline_with_normal_and_refusal_controls(self):
        with tempfile.TemporaryDirectory() as t:
            log = []
            res = self.demo.run(Path(t) / "work", log)
            self.assertGreaterEqual(len(log), 30)
            self.assertFalse([x for x in log if x.startswith("FAIL")])
            c = res["controls"]
            self.assertEqual({k: v["exit"] for k, v in c.items() if k in ("incomplete", "missing", "pair-error")},
                             {"incomplete": 0, "missing": 0, "pair-error": 0})
            self.assertEqual({k: (v["exit"], v["code"]) for k, v in c.items() if "code" in v},
                             {"report-inside-store": (2, "boundary"), "report-inside-reviewer-root": (2, "boundary"),
                              "report-already-exists": (2, "io"), "tampered-data": (1, "tamper"),
                              "pins-inside-store": (1, "pins"), "wrong-expected-revision": (1, "pins"),
                              "wrong-candidate-digest": (1, "judgments"), "null-confidence": (1, "judgments"),
                              "document-for-unrequested-tool": (1, "judgments"), "mixed-judges": (1, "judge-mismatch")})
            report = json.loads(Path(res["report"]).read_text())
            self.assertEqual(report["tools"]["demo-a"]["pooled"]["core"]["counts"], {"tp": 2, "fp": 1, "fn": 2, "prs": 2})
            self.assertNotIn("INVENTED", json.dumps(report))

    def test_recipe_refuses_a_nonempty_or_reviewer_root_workdir(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "x").write_text("occupied")
            with self.assertRaises(SystemExit):
                self.demo.run(Path(t))
        with self.assertRaises(SystemExit):
            self.demo.run(DEMO.parents[1] / "tests" / "demo-must-not-exist")

    def test_recipe_has_no_network_process_or_environment_access(self):
        banned = ("urllib", "http", "socket", "ssl", "requests", "httpx", "subprocess", "os", "shutil", "webbrowser",
                  "reviewer.gateway", "reviewer.runtime", "reviewer.pipeline", "reviewer.pilot")
        tree = ast.parse(DEMO.read_text())
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
            for n in names:
                self.assertFalse(any(n == b or n.startswith(b + ".") for b in banned), f"imports {n}")
        text = DEMO.read_text()
        for needle in ("environ", "getenv", ".env", "openrouter", "api_key", "orchestration/"):
            self.assertNotIn(needle, text, needle)


if __name__ == "__main__":
    unittest.main()
