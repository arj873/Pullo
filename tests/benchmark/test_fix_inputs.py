"""S1-07a-fix-inputs controls: real-shaped nullable comments (B1), severity (N1), duplicate reviews (N2), version audit
and explicit primary choice (N3), extraction coverage (N5), extra judgments (N6) and attested-vs-admitted cutoffs (N4).
All data is invented."""

import copy
import json

from reviewer.benchmark.cutoff import ADMISSION_SCHEMA, attestation_binding, check_admission, resolve_cutoff, select_cases
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.loader import load_proposal
from reviewer.benchmark.model import KNOWN_SEVERITIES
from reviewer.benchmark.projection import project_metadata, resolve_versions
from reviewer.benchmark.scoring import score_case, score_suite

from .helpers import Fx
from .test_projection_cutoff import admit, good_proof
from .test_scoring import JUDGE


def comment(path="a.py", line=3, body="BODYTEXT x", stamp="2025-02-01T10:00:00Z"):
    return {"path": path, "line": line, "body": body, "created_at": stamp}


class Shape(Fx):
    def first_url(self):
        return next(iter(self.data))

    def set_comments(self, tool, comments):
        e = self.data[self.first_url()]
        next(r for r in e["reviews"] if r["tool"] == tool)["review_comments"] = comments
        self.write_all()

    def test_B1_summary_and_anchored_comments_kept_with_distinct_stable_ids(self):
        cs = [comment(None, None, "same"), comment("None", None, "same"), comment("a.py", None, "same"),
              comment("a.py", 3, "same"), comment("a.py", 0, "same")]
        self.set_comments("cubic-v2", cs)
        ids = [c.id for c in self.source().cases[self.first_url()].review("cubic-v2").comments]
        self.assertEqual(len(ids), 5)
        self.assertEqual(len(set(ids)), 5)                      # null != "None"; null line != 3 != 0
        again = [c.id for c in self.source().cases[self.first_url()].review("cubic-v2").comments]
        self.assertEqual(ids, again)
        got = self.source().cases[self.first_url()].review("cubic-v2").comments[0]
        self.assertEqual((got.path, got.line, got.body), (None, None, "same"))

    def test_B1_malformed_comment_types_refused(self):
        for bad in (comment(None, 3), comment(7, None), comment("a.py", "3"), comment("a.py", True),
                    comment("a.py", 1.5), comment("a.py", 3, None), comment("a.py", 3, "b", 5)):
            self.set_comments("cubic-v2", [comment(), bad])
            with self.assertRaises(BenchmarkError, msg=str(bad)) as cm:
                self.source()
            self.assertEqual(cm.exception.code, "shape")

    def test_B1_projection_counts_summaries_and_cited_summary_scores(self):
        self.set_comments("cubic-v2", [comment(None, None, "SUMMBODY"), comment()])
        src = self.source()
        proj = project_metadata(src)
        rev = next(r for c in proj["cases"] if c["url"] == self.first_url() for r in c["reviews"] if r["tool"] == "cubic-v2")
        self.assertEqual((rev["commentCount"], rev["summaryCommentCount"]), (2, 1))
        self.assertNotIn("SUMMBODY", json.dumps(proj))
        case = src.cases[self.first_url()]
        summ = case.review("cubic-v2").comments[0].id
        doc = {"schema": "semantic-judgments@1", "caseUrl": case.url, "tool": "cubic-v2", "judge": dict(JUDGE),
               "extraction": {"candidates": [{"id": "cand:1", "sourceCommentId": summ, "text": "t"}]},
               "duplicateGroups": [{"id": "g", "representative": "cand:1", "members": ["cand:1"]}],
               "matches": [{"candidate": "cand:1", "golden": case.golden[0].id, "reason": "r"}]}
        row = score_case(case, doc)
        self.assertEqual(row["views"]["all"]["counts"]["tp"], 1)
        self.assertEqual(len(row["uncoveredCommentIds"]), 1)        # N5: the anchored comment is reported, not hidden

    def test_N1_severity_exact_vocabulary(self):
        self.assertEqual(KNOWN_SEVERITIES, {"Critical", "High", "Low", "Medium"})
        for bad in ("high", "HIGH", " High", "Severe", "Info"):
            self.data[self.first_url()]["golden_comments"][0]["severity"] = bad
            self.write_all()
            with self.assertRaises(BenchmarkError, msg=bad) as cm:
                self.source()
            self.assertEqual(cm.exception.code, "severity")
        for ok in sorted(KNOWN_SEVERITIES):
            self.data[self.first_url()]["golden_comments"][0]["severity"] = ok
            self.write_all()
            self.source()

    def test_N2_duplicate_tool_review_refused(self):
        e = self.data[self.first_url()]
        e["reviews"].append(copy.deepcopy(e["reviews"][0]))
        self.write_all()
        with self.assertRaises(BenchmarkError) as cm:
            self.source()
        self.assertIn("more than one review", cm.exception.message)


def rules_v2(**fam):
    base = {"source": {"blob": "x", "quote": "q"}, "skipped": []}
    out = {"cubic": {"prefix": "cubic-v", "upstreamHidden": ["cubic-v1"], **base},
           "coderabbit": {"prefix": "coderabbit", "upstreamHidden": [], **base},
           "greptile": {"prefix": "greptile", "upstreamHidden": ["greptile", "greptile-v4"], **base,
                        "primary": "greptile-v5", "primaryBasis": "root pre-score rule: highest surviving id",
                        "secondary": ["greptile-v4-1"]}}
    for k, v in fam.items():
        out[k] = v
    return {"schema": "benchmark-version-rules@2", "selectionDecision": {"by": "root", "at": "2026-10-26"}, "families": out}


class Versions(Fx):
    def setUp(self):
        super().setUp()
        for e in self.data.values():
            e["reviews"] = [r for r in e["reviews"] if not r["tool"].startswith("greptile")]
            for t in ("greptile", "greptile-v4", "greptile-v4-1", "greptile-v5", "cubic-dev"):
                r = copy.deepcopy(e["reviews"][0])
                r["tool"] = t
                e["reviews"].append(r)
        self.write_all()
        self.proj = project_metadata(self.source())

    def audit(self, res, fam):
        return {a["id"]: a for a in res["families"][fam]["audit"]}

    def test_v2_explicit_primary_secondary_and_hidden_kept_separate(self):
        res = resolve_versions(self.proj, rules_v2())
        self.assertEqual(res["status"], "resolved")
        self.assertEqual(res["chosen"], {"cubic": "cubic-v2", "coderabbit": "coderabbit-v1", "greptile": "greptile-v5"})
        g = res["families"]["greptile"]
        self.assertEqual(g["choiceBasis"], "explicit-primary")
        self.assertEqual(g["candidates"], ["greptile-v4-1", "greptile-v5"])
        a = self.audit(res, "greptile")
        self.assertEqual(a["greptile"]["reason"], "hidden by the pinned upstream rules")
        self.assertEqual(a["greptile-v4"]["status"], "excluded")
        self.assertEqual(a["greptile-v4-1"]["status"], "not-selected")       # not claimed hidden by upstream
        self.assertIn("secondary", a["greptile-v4-1"]["reason"])
        self.assertNotIn("superseded", json.dumps(res).lower().replace("hidden by the pinned", ""))
        sec = res["secondaryComparisons"]
        self.assertEqual([(s["family"], s["tool"]) for s in sec], [("greptile", "greptile-v4-1")])
        self.assertEqual(sec[0]["chosen"]["greptile"], "greptile-v4-1")
        self.assertEqual(len(sec[0]["commonEligibleSet"]) + len(sec[0]["omitted"]), 6)
        self.assertEqual(len(res["attempted"]), 6)

    def test_secondary_and_primary_rows_keep_their_own_omissions(self):
        rules = rules_v2()
        url = self.proj["cases"][0]["url"]
        rules["families"]["greptile"]["skipped"] = [{"tool": "greptile-v4-1", "prUrl": url}]
        res = resolve_versions(self.proj, rules)
        self.assertIn(url, res["commonEligibleSet"])                         # primary row unaffected
        self.assertIn(url, res["secondaryComparisons"][0]["omitted"])        # secondary row retains its omission

    def test_v1_ambiguity_still_unresolved_and_v2_without_primary_too(self):
        r1 = {"schema": "benchmark-version-rules@1", "families": {
            f: {"prefix": p, "superseded": s, "skipped": [], "source": {"b": 1}}
            for f, p, s in (("cubic", "cubic-v", ["cubic-v1"]), ("coderabbit", "coderabbit", []),
                            ("greptile", "greptile", ["greptile", "greptile-v4"]))}}
        res = resolve_versions(self.proj, r1)
        self.assertEqual(res["status"], "unresolved")
        self.assertEqual(res["families"]["greptile"]["candidates"], ["greptile-v4-1", "greptile-v5"])
        v2 = rules_v2()
        for k in ("primary", "primaryBasis", "secondary"):
            del v2["families"]["greptile"][k]
        self.assertEqual(resolve_versions(self.proj, v2)["status"], "unresolved")

    def test_primary_must_be_an_observed_survivor(self):
        for bad in ("greptile-v4", "greptile-v9", "greptile"):
            r = rules_v2()
            r["families"]["greptile"]["primary"] = bad
            res = resolve_versions(self.proj, r)
            self.assertEqual(res["status"], "unresolved", bad)
            self.assertIsNone(res["families"]["greptile"]["chosen"])
        r = rules_v2()
        r["families"]["greptile"]["secondary"] = ["greptile-v4"]               # hidden id cannot be a secondary
        self.assertEqual(resolve_versions(self.proj, r)["status"], "unresolved")

    def test_v2_schema_strictness(self):
        for mut in (lambda r: r.pop("selectionDecision"), lambda r: r["families"]["greptile"].pop("primaryBasis"),
                    lambda r: r["families"]["greptile"].update(secondary=["greptile-v5"]),
                    lambda r: r["families"]["cubic"].update(superseded=[]),
                    lambda r: r["families"]["cubic"].update(primary="cubic-v2")):
            r = rules_v2()
            mut(r)
            with self.assertRaises(BenchmarkError):
                resolve_versions(self.proj, r)

    def test_N3_every_family_id_listed_including_prefix_exclusions(self):
        res = resolve_versions(self.proj, rules_v2())
        a = self.audit(res, "cubic")
        self.assertEqual(set(a), {"cubic-dev", "cubic-v1", "cubic-v2"})
        self.assertIn("outside the rule prefix", a["cubic-dev"]["reason"])
        self.assertEqual(a["cubic-v1"]["reason"], "hidden by the pinned upstream rules")
        self.assertEqual(a["cubic-v2"]["status"], "survives")
        # unresolved results carry the audit too
        r = rules_v2()
        r["families"]["greptile"].update(primary="greptile-v9")
        self.assertTrue(resolve_versions(self.proj, r)["families"]["greptile"]["audit"])


class Coverage(Fx):
    def setUp(self):
        super().setUp()
        self.src = self.source()
        self.url = next(iter(self.src.cases))
        self.case = self.src.cases[self.url]
        self.rc = self.case.review("cubic-v2").comments[0].id

    def doc(self, tool="cubic-v2", url=None, rc=None):
        return {"schema": "semantic-judgments@1", "caseUrl": url or self.url, "tool": tool, "judge": dict(JUDGE),
                "extraction": {"candidates": [{"id": "cand:1", "sourceCommentId": rc or self.rc, "text": "t"}]},
                "duplicateGroups": [{"id": "g", "representative": "cand:1", "members": ["cand:1"]}],
                "matches": [{"candidate": "cand:1", "golden": None, "reason": "r"}]}

    def test_N5_suite_reports_uncovered_raw_comment_ids(self):
        e = self.data[self.url]
        next(r for r in e["reviews"] if r["tool"] == "cubic-v2")["review_comments"].append(comment(None, None, "omitted"))
        self.write_all()
        src = self.source()
        case = src.cases[self.url]
        omitted = case.review("cubic-v2").comments[1].id
        rep = score_suite(src.cases, [self.doc(rc=case.review("cubic-v2").comments[0].id)], tools=["cubic-v2"], urls=[self.url])
        t = rep["tools"]["cubic-v2"]
        self.assertEqual(t["cases"][0]["uncoveredCommentIds"], [omitted])
        self.assertEqual(t["extractionCoverage"], {"rawComments": 2, "uncoveredComments": 1, "casesWithUncovered": [self.url]})

    def test_N6_extra_or_malformed_judgment_documents_refused(self):
        other = [u for u in self.src.cases if u != self.url][0]
        for docs in ([self.doc(), self.doc(url=other)], [self.doc(), self.doc(tool="cubic-v1")], [self.doc(), "junk"],
                     [self.doc(), None]):
            with self.assertRaises(BenchmarkError, msg=str(docs[1])[:30]) as cm:
                score_suite(self.src.cases, docs, tools=["cubic-v2"], urls=[self.url])
            self.assertEqual(cm.exception.code, "judgments")
        score_suite(self.src.cases, [self.doc()], tools=["cubic-v2"], urls=[self.url])

    def test_zero_view_is_labelled_and_no_reference_view_is_claimed(self):
        rep = score_suite(self.src.cases, [self.doc()], tools=["cubic-v2"], urls=[self.url])
        z = rep["tools"]["cubic-v2"]["pooled"]["core"]["upstreamCompatZero"]
        self.assertIn("ONLY", z["label"])
        self.assertIn("not the reference formula", z["label"])
        self.assertEqual(rep["referenceCompatibleView"]["status"], "unavailable")
        self.assertIn("B2/B3", rep["unverifiedSemantics"])


class Admission(Fx):
    def setUp(self):
        super().setUp()
        self.proj = project_metadata(self.source())
        self.by = {c["url"]: c for c in self.proj["cases"]}
        self.prop = load_proposal(self.pp)
        self.u = self.prop.universe["alpha"][0]
        self.p = good_proof(self.u)

    def status(self, proof=None, admission=None):
        return resolve_cutoff(self.u, proof or self.p, self.by[self.u], admission)

    def test_plausible_self_attestation_is_attested_never_proven(self):
        r = self.status()
        self.assertEqual(r["status"], "attested")
        self.assertEqual(r["binding"], attestation_binding(self.p))
        self.assertIn("root admission", " ".join(r["reasons"]))
        selfclaim = dict(self.p, status="proven", reasonIfUnproven="")
        self.assertEqual(self.status(selfclaim)["status"], "attested")      # proof's own status field is never read

    def test_positive_control_exact_admission_proves(self):
        r = self.status(admission=admit(self.p))
        self.assertEqual((r["status"], r["reasons"]), ("proven", []))
        self.assertEqual(check_admission(self.u, self.p, admit(self.p)), [])

    def test_negative_controls_each_binding_field_and_authority(self):
        def tamper(k, v):
            a = admit(self.p)
            a[k] = v
            return a
        cases = [("asOfHead", tamper("asOfHead", "9" * 40)), ("asOfBase", tamper("asOfBase", "9" * 40)),
                 ("mergeBase", tamper("mergeBase", "9" * 40)), ("resolvedRepo", tamper("resolvedRepo", "o/r")),
                 ("evidenceDigests", tamper("evidenceDigests", ["sha256:" + "0" * 64])),
                 ("different original URL", tamper("originalUrl", "https://github.com/acme/other/pull/9")),
                 ("not by root", tamper("admittedBy", "worker")), ("decisionRef", tamper("decisionRef", " ")),
                 ("admittedAt", tamper("admittedAt", "soon")), ("schema", tamper("schema", "x@1")),
                 ("exactly", dict(admit(self.p), extra=1)), ("exactly", {k: v for k, v in admit(self.p).items() if k != "decisionRef"})]
        for frag, adm in cases:
            r = self.status(admission=adm)
            self.assertEqual(r["status"], "attested", frag)
            self.assertIn(frag, " ".join(r["reasons"]))
        self.assertEqual(self.status(admission="root-approved")["status"], "attested")

    def test_admission_binds_evidence_after_proof_is_edited(self):
        adm = admit(self.p)
        edited = copy.deepcopy(self.p)
        edited["evidence"][0]["value"] = "other-value"
        self.assertEqual(self.status(edited, adm)["status"], "attested")
        extra = copy.deepcopy(self.p)
        extra["evidence"].append({"kind": "upstream-pin", "source": "pin", "observedAt": "t", "value": "v"})
        self.assertEqual(self.status(extra, adm)["status"], "attested")

    def test_admission_cannot_rescue_a_failing_proof(self):
        bad = copy.deepcopy(self.p)
        bad["evidence"].append({"kind": "upstream-pin", "source": "merged-head", "observedAt": "t", "value": "v"})
        r = self.status(bad, admit(bad))
        self.assertEqual(r["status"], "unproven")
        late = dict(self.p, headCommittedAt="2025-03-01T00:00:00Z")
        self.assertEqual(self.status(late, admit(late))["status"], "unproven")

    def test_selection_ignores_attested_and_uses_only_admitted(self):
        proofs = {u: good_proof(u) for us in self.prop.universe.values() for u in us}
        sel = select_cases(self.prop, self.proj, proofs)
        self.assertEqual((sel["dev"], sel["frozen"]), ([], []))
        self.assertEqual(len(sel["attested"]), 6)
        self.assertTrue(all("root admission" in e["reasons"][0] for e in sel["exclusions"]))
        adm = {u: admit(p) for u, p in proofs.items()}
        part = {u: a for u, a in adm.items() if u != self.u}
        sel = select_cases(self.prop, self.proj, proofs, part)
        self.assertNotIn(self.u, sel["dev"] + sel["frozen"])
        self.assertEqual(sel["attested"], [self.u])
        self.assertEqual(sel["coverage"]["reproducible"], 5)
        full = select_cases(self.prop, self.proj, proofs, adm)
        self.assertTrue(full["allReproducible"])
        self.assertEqual(full["attested"], [])

    def test_admission_for_unknown_url_refused(self):
        with self.assertRaises(BenchmarkError):
            select_cases(self.prop, self.proj, {}, {"https://github.com/x/y/pull/1": admit(self.p)})
        self.assertEqual(ADMISSION_SCHEMA, "benchmark-cutoff-admission@1")
