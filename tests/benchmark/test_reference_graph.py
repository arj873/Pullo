"""S1-22 all-pairs reference report. Invented fixtures only; expected values are hand-derived from the pinned
semantics (strict confidence improvement, literal-text collapse, pooled micro, profile-filtered TP/FN)."""

import contextlib
import copy
import hashlib
import io
import json
import math
import pathlib

from reviewer.benchmark import __main__ as cli
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.jsonio import digest
from reviewer.benchmark.reference_graph import score_reference_case, score_reference_suite
from reviewer.benchmark.scoring import REFERENCE_VIEW, score_suite

from .helpers import Fx

JUDGE = {"model": "fixture-judge", "extractionPrompt": "e@v1", "dedupPrompt": "d@v1", "matchPrompt": "m@v1",
         "schemaSha256": "s", "runRef": "fixture"}
TOOL = "cubic-v2"


def cand_list(case, tool, texts):
    rc = case.review(tool).comments[0].id
    return [{"id": f"cand:{i}", "sourceCommentId": rc, "text": t} for i, t in enumerate(texts, 1)]


def make_doc(case, texts, hits=None, errs=(), groups=None, tool=TOOL, judge=None, order=None):
    """All golden x candidate pairs. hits {(gold_index, cand_number): confidence}; others non-matches at 0.99."""
    cands = cand_list(case, tool, texts)
    hits = hits or {}
    pairs = []
    for gi, g in enumerate(case.golden):
        for c in cands:
            n = int(c["id"].split(":")[1])
            if (gi, n) in errs:
                pairs.append({"golden": g.id, "candidate": c["id"], "error": "timed out"})
            else:
                pairs.append({"golden": g.id, "candidate": c["id"], "match": (gi, n) in hits,
                              "confidence": hits.get((gi, n), 0.99)})
    ordered = [cands[i] for i in order] if order else cands
    return {"schema": "reference-judgments@1", "caseUrl": case.url, "tool": tool, "judge": judge or dict(JUDGE),
            "extraction": {"candidates": ordered},
            "duplicateGroups": {"candidateListSha256": digest([[c["id"], c["text"]] for c in ordered]),
                                "groups": groups or []},
            "pairs": pairs}


class Base(Fx):
    def setUp(self):
        super().setUp()
        self.src = self.source()
        self.urls = list(self.src.cases)
        self.case = self.src.cases[self.urls[0]]       # gold: bug, perf, style, security

    def refused(self, doc, code="judgments", case=None):
        with self.assertRaises(BenchmarkError) as cm:
            score_reference_case(case or self.case, doc)
        self.assertEqual(cm.exception.code, code, cm.exception.message)


class Counting(Base):
    TEXTS = ["t1", "t2", "t1"]
    # g0: c1 .4 improves, c2 .8 improves (c1 stays matched). g1: c2 .5. g3: c1 .6 then c3 .6 (tie, no improvement).
    HITS = {(0, 1): 0.4, (0, 2): 0.8, (1, 2): 0.5, (3, 1): 0.6, (3, 3): 0.6}

    def test_many_to_many_confidence_order_and_literal_duplicate_candidate(self):
        row = score_reference_case(self.case, make_doc(self.case, self.TEXTS, self.HITS, groups=[[0, 2]]))
        ev = row["evaluation"]
        self.assertEqual((ev["tp"], ev["fp"], ev["fn"], ev["totalCandidates"], ev["totalGolden"]), (3, 0, 1, 3, 4))
        g = [x.id for x in self.case.golden]
        self.assertEqual([(t["goldenIds"], t["matchedCandidateId"], t["confidence"]) for t in ev["truePositives"]],
                         [([g[0]], "cand:2", 0.8), ([g[1]], "cand:2", 0.5), ([g[3]], "cand:1", 0.6)])
        self.assertEqual([f["goldenIds"] for f in ev["falseNegatives"]], [[g[2]]])
        self.assertEqual([(i["golden"], i["candidate"]) for i in ev["provenance"]["improvements"]],
                         [(g[0], "cand:1"), (g[0], "cand:2"), (g[1], "cand:2"), (g[3], "cand:1")])
        self.assertEqual(ev["provenance"]["candidateCollapsedIds"], [["cand:1", "cand:3"]])
        self.assertEqual((row["pairsExpected"], row["candidates"], row["status"]), (12, 3, "scored"))

    def test_candidate_order_changes_the_result(self):
        # same judgments, extraction order reversed for the first two: c2 (.8) is now processed before c1 (.4)
        row = score_reference_case(self.case, make_doc(self.case, ["t1", "t2"], {(0, 1): 0.4, (0, 2): 0.8}, order=[1, 0]))
        ev = row["evaluation"]
        self.assertEqual((ev["tp"], ev["fp"]), (1, 1))                     # c1 never improves -> false positive
        self.assertEqual(ev["falsePositives"], [{"candidateIds": ["cand:1"]}])
        row = score_reference_case(self.case, make_doc(self.case, ["t1", "t2"], {(0, 1): 0.4, (0, 2): 0.8}))
        self.assertEqual((row["evaluation"]["tp"], row["evaluation"]["fp"]), (1, 0))

    def test_literal_duplicate_golden_text_collapses_with_last_category(self):
        url = self.urls[0]
        self.data[url]["golden_comments"][2]["comment"] = self.data[url]["golden_comments"][0]["comment"]
        self.write_all()
        case = self.source().cases[url]
        row = score_reference_case(case, make_doc(case, ["x"], {(0, 1): 0.5}))
        ev = row["evaluation"]
        g = [x.id for x in case.golden]
        self.assertEqual(ev["truePositives"], [{"goldenIds": [g[0], g[2]], "severity": "Low", "category": "style",
                                                "matchedCandidateId": "cand:1", "confidence": 0.5}])
        self.assertEqual((ev["tp"], ev["fn"], ev["totalGolden"]), (1, 2, 4))
        self.assertEqual(ev["provenance"]["goldenCollapsedIds"], [[g[0], g[2]]])
        rep = score_reference_suite({url: case}, [make_doc(case, ["x"], {(0, 1): 0.5})], tools=[TOOL], source=self.source())
        v = rep["tools"][TOOL]["pooled"]
        self.assertEqual(v["strict"]["counts"]["tp"], 0)                   # last duplicate's category 'style' wins
        self.assertEqual(v["all"]["counts"]["tp"], 1)

    def test_zero_candidates_gives_uncollapsed_fn_and_undefined_precision(self):
        row = score_reference_case(self.case, make_doc(self.case, []))
        ev = row["evaluation"]
        self.assertEqual((ev["tp"], ev["fp"], ev["fn"], row["pairsExpected"]), (0, 0, 4, 0))
        rep = score_reference_suite({self.case.url: self.case}, [make_doc(self.case, [])], tools=[TOOL], source=self.src)
        core = rep["tools"][TOOL]["pooled"]["core"]
        self.assertEqual((core["counts"]["fn"], core["undefined"], core["f1"]), (3, ["precision"], 0.0))
        self.assertTrue(rep["complete"])

    def test_zero_gold_case_is_skipped_and_listed(self):
        url = self.urls[1]
        self.data[url]["golden_comments"] = []
        self.write_all()
        src = self.source()
        z = src.cases[url]
        docs = [make_doc(z, ["a", "b"]), make_doc(src.cases[self.urls[0]], ["t1"], {(0, 1): 0.5})]
        row = score_reference_case(z, docs[0])
        self.assertEqual((row["status"], row["pairsExpected"]), ("skipped-zero-gold", 0))
        rep = score_reference_suite(src.cases, docs, tools=[TOOL], urls=[url, self.urls[0]], source=src)
        t = rep["tools"][TOOL]
        self.assertEqual((t["zeroGoldSkipped"], t["casesScored"], t["complete"]), ([url], 1, True))
        self.assertEqual(t["pooled"]["all"]["counts"]["prs"], 1)
        only = score_reference_suite(src.cases, [docs[0]], tools=[TOOL], urls=[url], source=src)
        self.assertFalse(only["complete"])                                  # nothing scored
        self.assertIsNone(only["tools"][TOOL]["pooled"])

    def test_pooled_profiles_and_named_zero_convention(self):
        rep = score_reference_suite({self.case.url: self.case}, [make_doc(self.case, self.TEXTS, self.HITS)], tools=[TOOL],
                                    source=self.src)
        p = rep["tools"][TOOL]["pooled"]
        # strict: TP bug+security; perf excluded; style FN excluded. core: +perf. all: style FN counts.
        self.assertEqual([p[k]["counts"] for k in ("strict", "core", "all")],
                         [{"tp": 2, "fp": 0, "fn": 0, "prs": 1}, {"tp": 3, "fp": 0, "fn": 0, "prs": 1},
                          {"tp": 3, "fp": 0, "fn": 1, "prs": 1}])
        self.assertEqual(p["core"]["f1"], 1.0)
        self.assertAlmostEqual(p["all"]["f1"], 6 / 7)
        self.assertAlmostEqual(p["all"]["f2"], 15 / 19)
        self.assertEqual(p["all"]["zeroConvention"], "reference-undefined-is-0")
        self.assertEqual(rep["primary"]["name"], "core/F1")
        self.assertEqual(rep["secondary"], ["strict/F1", "all/F1", "core/F2", "strict/F2", "all/F2"])


class Validation(Base):
    def doc(self, **kw):
        return make_doc(self.case, ["t1", "t2"], {(0, 1): 0.5}, **kw)

    def test_legacy_v1_documents_are_refused_not_converted(self):
        d = self.doc()
        d["schema"] = "semantic-judgments@1"
        self.refused(d)
        v1 = {"schema": "semantic-judgments@1", "caseUrl": self.case.url, "tool": TOOL, "judge": JUDGE,
              "extraction": {"candidates": []}, "duplicateGroups": [], "matches": []}
        self.refused(v1)
        self.refused(None)
        self.refused([])

    def test_pair_set_problems(self):
        d = self.doc()
        miss = copy.deepcopy(d)
        miss["pairs"].pop()
        self.refused(miss, "incomplete")
        extra = copy.deepcopy(d)
        extra["pairs"].append({"golden": "gold:9:9", "candidate": "cand:1", "match": False, "confidence": 0.1})
        self.refused(extra)
        extra = copy.deepcopy(d)
        extra["pairs"].append(copy.deepcopy(extra["pairs"][0]))
        self.refused(extra)
        unknown = copy.deepcopy(d)
        unknown["pairs"][0]["candidate"] = "cand:99"
        self.refused(unknown, "judgments")
        nonstr = copy.deepcopy(d)
        nonstr["pairs"][0]["golden"] = ["x"]
        self.refused(nonstr)

    def test_confidence_match_and_error_shapes(self):
        for bad in (None, True, "0.5", math.nan, math.inf, -math.inf, [0.5]):
            d = self.doc()
            d["pairs"][0].update(match=True, confidence=bad)
            self.refused(d)
        d = self.doc()
        del d["pairs"][0]["confidence"]
        self.refused(d)
        for bad in (1, 0, "true", None):
            d = self.doc()
            d["pairs"][0]["match"] = bad
            self.refused(d)
        for bad in ("", None, 5):
            d = self.doc()
            d["pairs"][0] = {"golden": d["pairs"][0]["golden"], "candidate": "cand:1", "error": bad}
            self.refused(d)
        d = self.doc()
        d["pairs"][0]["error"] = "e"
        self.refused(d)                                                    # error plus match/confidence
        d = self.doc()
        d["pairs"][0]["reason"] = "x"
        self.refused(d)                                                    # unknown key

    def test_confidence_is_not_range_limited_or_clamped(self):
        # upstream compares unbounded finite numbers: 1.5 improves and is reported as 1.5; -0.1 never improves.
        d = self.doc()
        d["pairs"][0].update(match=True, confidence=1.5)
        d["pairs"][1].update(match=True, confidence=-0.1)
        ev = score_reference_case(self.case, d)["evaluation"]
        self.assertEqual([t["confidence"] for t in ev["truePositives"]], [1.5])

    def test_whitespace_only_candidate_text_is_kept_not_trimmed_or_dropped(self):
        row = score_reference_case(self.case, make_doc(self.case, [" ", "\n\t", " "], {(0, 1): 0.5}))
        ev = row["evaluation"]
        self.assertEqual((row["candidates"], row["pairsExpected"], ev["totalCandidates"]), (3, 12, 3))
        self.assertEqual((ev["tp"], ev["fp"]), (1, 1))                      # " " (c1,c3 literal dup) matched; "\n\t" FP
        self.assertEqual(ev["provenance"]["candidateCollapsedIds"], [["cand:1", "cand:3"]])
        self.assertEqual(ev["falsePositives"], [{"candidateIds": ["cand:2"]}])

    def test_top_level_judge_and_identity(self):
        for mut in (lambda d: d.update(extra=1), lambda d: d.pop("pairs"), lambda d: d.update(caseUrl="https://x/y"),
                    lambda d: d["judge"].pop("runRef"), lambda d: d["judge"].update(model=""),
                    lambda d: d["judge"].update(more="x"), lambda d: d.update(tool=7)):
            d = self.doc()
            mut(d)
            self.refused(d)
        d = self.doc()
        d["tool"] = "no-such-tool"
        self.refused(d, "missing")

    def test_candidates_and_group_binding(self):
        for mut in (lambda d: d["extraction"]["candidates"][0].update(text=""),
                    lambda d: d["extraction"]["candidates"][0].update(sourceCommentId="rc2:other"),
                    lambda d: d["extraction"]["candidates"][1].update(id="cand:1"),
                    lambda d: d["extraction"]["candidates"][0].update(extra=1),
                    lambda d: d["extraction"].update(extra=1)):
            d = self.doc()
            mut(d)
            self.refused(d)
        d = self.doc()
        d["extraction"]["candidates"][0]["text"] = "changed"                 # list no longer matches its digest
        self.refused(d)
        d = self.doc()
        d["extraction"]["candidates"].reverse()                            # reordering breaks the binding too
        self.refused(d)
        for groups in ([[0, 5]], [[-1]], [[True]], [[0, 0]], [[]], [0], "x", [[0.0]]):
            d = self.doc(groups=groups)
            self.refused(d)
        d = self.doc()
        d["duplicateGroups"]["extra"] = 1
        self.refused(d)
        d = make_doc(self.case, [], groups=[[0]])
        self.refused(d)                                                    # groups into an empty list

    def test_overlapping_groups_are_reported_not_hidden(self):
        row = score_reference_case(self.case, self.doc(groups=[[0, 1], [1]]))
        self.assertEqual((row["duplicateGroups"], row["overlappingGroupIndices"]), (2, 1))


class Suite(Base):
    def good(self, case, tool=TOOL, **kw):
        return make_doc(case, ["t1", "t2"], {(0, 1): 0.5}, tool=tool, **kw)

    def test_missing_incomplete_errors_and_no_favourable_partial(self):
        c = self.src.cases
        miss = self.good(c[self.urls[1]])
        miss["pairs"].pop()
        docs = [self.good(c[self.urls[0]]), miss]
        rep = score_reference_suite(c, docs, tools=[TOOL], urls=self.urls[:3])
        t = rep["tools"][TOOL]
        self.assertEqual((t["missing"], [i["caseUrl"] for i in t["incomplete"]], t["casesScored"]),
                         ([self.urls[2]], [self.urls[1]], 1))
        self.assertFalse(t["complete"] or rep["complete"])
        self.assertIsNone(t["pooled"])
        self.assertTrue(t["partialPooled"]["notAScore"])
        self.assertEqual(rep["attempted"], {"urls": self.urls[:3], "tools": [TOOL], "subset": True})

    def test_pair_errors_pool_like_upstream_but_never_complete(self):
        c = self.src.cases
        d = make_doc(c[self.urls[0]], ["t1", "t2"], {(0, 1): 0.5}, errs={(1, 2)})
        rep = score_reference_suite(c, [d], tools=[TOOL], urls=[self.urls[0]])
        t = rep["tools"][TOOL]
        self.assertEqual((t["pairErrorCases"], t["complete"], t["pooled"]), ([self.urls[0]], False, None))
        self.assertEqual(t["cases"][0]["evaluation"]["errorsCount"], 1)
        self.assertIsNotNone(t["partialPooled"])

    def test_missing_tool_review_is_incomplete(self):
        c = self.src.cases
        d = self.good(c[self.urls[0]], tool="greptile-v1")
        rep = score_reference_suite(c, [self.good(c[self.urls[0]]), d], tools=[TOOL, "greptile-v1"], urls=[self.urls[0]],
                                    source=self.src)
        self.assertTrue(rep["tools"]["greptile-v1"]["complete"])
        rep = score_reference_suite(c, [self.good(c[self.urls[0]])], tools=[TOOL, "greptile-v1"], urls=[self.urls[0]],
                                    source=self.src)
        self.assertEqual(rep["tools"]["greptile-v1"]["missing"], [self.urls[0]])
        self.assertFalse(rep["complete"])

    def test_hidden_tool_gets_no_pooled_view(self):
        url = self.urls[0]
        self.data[url]["reviews"].append(copy.deepcopy(self.data[url]["reviews"][0]) | {"tool": "qodo"})
        self.write_all()
        src = self.source()
        rep = score_reference_suite(src.cases, [self.good(src.cases[url], tool="qodo")], tools=["qodo"], urls=[url])
        t = rep["tools"]["qodo"]
        self.assertEqual((t["referenceHidden"], t["pooled"], t["partialPooled"], t["complete"]), (True, None, None, False))
        self.assertEqual(t["casesScored"], 1)

    def test_mismatched_judges_extra_duplicate_and_bad_requests_refused(self):
        c = self.src.cases
        a, b = self.good(c[self.urls[0]]), self.good(c[self.urls[1]], judge=dict(JUDGE, model="other"))
        with self.assertRaises(BenchmarkError) as cm:
            score_reference_suite(c, [a, b], tools=[TOOL], urls=self.urls[:2])
        self.assertEqual(cm.exception.code, "judge-mismatch")
        for kw, docs in (({"urls": [self.urls[0]]}, [a, b]),                       # extra document, unrequested case
                         ({"urls": [self.urls[0]]}, [a, a]),                       # duplicate (case, tool)
                         ({"urls": ["https://nope/1"]}, [a]), ({"urls": []}, [a]),
                         ({"urls": [self.urls[0]] * 2}, [a])):
            with self.assertRaises(BenchmarkError):
                score_reference_suite(c, docs, tools=[TOOL], **kw)
        for tools in ([], [TOOL, TOOL], [""], "cubic-v2"):
            with self.assertRaises(BenchmarkError):
                score_reference_suite(c, [a], tools=tools, urls=[self.urls[0]])
        with self.assertRaises(BenchmarkError):
            score_reference_suite(c, [self.good(c[self.urls[0]], tool=TOOL) | {"schema": "semantic-judgments@1"}],
                                  tools=[TOOL], urls=[self.urls[0]])

    def test_report_carries_no_gold_or_candidate_text_and_names_the_view(self):
        c = self.src.cases
        d = make_doc(c[self.urls[0]], ["CANDSECRET one", "CANDSECRET two"], {(0, 1): 0.5}, groups=[[0, 1]])
        rep = score_reference_suite(c, [d], tools=[TOOL], urls=[self.urls[0]], source=self.src)
        blob = json.dumps(rep)
        for leaked in ("GOLDTEXT", "BODYTEXT", "CANDSECRET"):
            self.assertNotIn(leaked, blob)
        self.assertEqual(rep["sourcePins"]["revision"], self.src.revision)
        self.assertEqual(rep["judgeDigest"], digest(JUDGE))
        self.assertEqual(rep["referenceView"]["pinnedSources"]["revision"], "e616e849755441da38f18bf3adba2c9583b03803")
        self.assertEqual(rep["tools"][TOOL]["cases"][0]["evaluation"]["provenance"]["siblingMarked"],
                         [{"via": "cand:1", "candidateIds": ["cand:2"]}])
        self.assertTrue(any("U2" in u for u in rep["unresolved"]))
        self.assertIn("No parity claim", rep["referenceView"]["label"])
        self.assertEqual(rep["tools"][TOOL]["extractionCoverage"]["rawComments"], 1)

    def test_native_scorer_is_unchanged(self):
        rep = score_suite(self.src.cases, [], tools=[TOOL], urls=[self.urls[0]])
        self.assertEqual(rep["schema"], "benchmark-score-report@1")
        self.assertEqual(rep["referenceCompatibleView"], REFERENCE_VIEW)
        self.assertEqual(REFERENCE_VIEW["status"], "unavailable")


class Gates(Base):
    """S1-22 independent-review fixes G1-G7."""

    def good(self, case, tool=TOOL, **kw):
        return make_doc(case, ["t1", "t2"], {(0, 1): 0.5}, tool=tool, **kw)

    def test_g1_pair_error_text_never_reaches_the_report(self):
        c = self.src.cases
        d = self.good(c[self.urls[0]])
        d["pairs"][1] = {"golden": d["pairs"][1]["golden"], "candidate": d["pairs"][1]["candidate"],
                         "error": "judge echoed ERRSECRET " + c[self.urls[0]].golden[0].comment + " and the candidate t2"}
        rep = score_reference_suite(c, [d], tools=[TOOL], urls=[self.urls[0]], source=self.src)
        blob = json.dumps(rep)
        self.assertNotIn("ERRSECRET", blob)
        self.assertNotIn(c[self.urls[0]].golden[0].comment, blob)
        err = rep["tools"][TOOL]["cases"][0]["evaluation"]["errors"]
        self.assertEqual(err, [{"golden": d["pairs"][1]["golden"], "candidate": d["pairs"][1]["candidate"],
                                "status": "judge-error"}])
        self.assertFalse(rep["complete"])

    def test_g1_refusal_messages_do_not_echo_producer_strings(self):
        d = self.good(self.case)
        d["extraction"]["candidates"][0]["sourceCommentId"] = "ECHOME"
        d["duplicateGroups"]["candidateListSha256"] = digest([[x["id"], x["text"]] for x in d["extraction"]["candidates"]])
        with self.assertRaises(BenchmarkError) as cm:
            score_reference_case(self.case, d)
        self.assertNotIn("ECHOME", cm.exception.message)
        d = self.good(self.case)
        d["caseUrl"] = "https://nope/ECHOME"
        with self.assertRaises(BenchmarkError) as cm:
            score_reference_suite(self.src.cases, [d], tools=[TOOL], urls=[self.urls[0]])
        self.assertNotIn("ECHOME", cm.exception.message)

    def test_g4_source_must_bind_the_scored_cases(self):
        c = self.src.cases
        d = self.good(c[self.urls[0]])
        rep = score_reference_suite(c, [d], tools=[TOOL], urls=[self.urls[0]], source=self.src)
        self.assertEqual((rep["sourceBound"], rep["sourcePins"]["boundCaseUrls"], rep["complete"]),
                         (True, [self.urls[0]], True))
        self.assertIn("not a signature", rep["sourcePins"]["attestation"])
        self.assertEqual(rep["judgeStatus"], "producer-declared, unverified")
        self.data[self.urls[0]]["golden_comments"][0]["comment"] = "different gold"
        self.write_all()
        other = self.source()
        for bad in (other, object(), {"revision": "x"}, "src"):             # different cases, non-Source objects
            with self.assertRaises(BenchmarkError) as cm:
                score_reference_suite(c, [d], tools=[TOOL], urls=[self.urls[0]], source=bad)
            self.assertEqual(cm.exception.code, "source")

    def test_g4_absent_source_is_explicitly_unbound_and_never_complete(self):
        c = self.src.cases
        rep = score_reference_suite(c, [self.good(c[self.urls[0]])], tools=[TOOL], urls=[self.urls[0]])
        t = rep["tools"][TOOL]
        self.assertEqual((rep["sourceBound"], rep["sourcePins"], rep["complete"], t["complete"], t["pooled"]),
                         (False, None, False, False, None))
        self.assertTrue(t["partialPooled"]["notAScore"])

    def test_g2_list_identity_is_a_typed_refusal(self):
        c = self.src.cases
        for key, val in (("caseUrl", [self.urls[0]]), ("tool", [TOOL]), ("tool", None), ("caseUrl", {"a": 1})):
            d = self.good(c[self.urls[0]])
            d[key] = val
            with self.assertRaises(BenchmarkError) as cm:
                score_reference_suite(c, [d], tools=[TOOL], urls=[self.urls[0]])
            self.assertEqual(cm.exception.code, "judgments")

    def norev(self, case, **kw):
        return self.good(case, **kw) | {"tool": "no-such-tool"}              # well-formed, but that tool has no review

    def test_g3_structure_is_checked_before_the_missing_review(self):
        d = self.norev(self.case)
        d["extra"] = 1
        self.refused(d)                                                    # structural refusal, not `missing`
        d = self.norev(self.case)
        d["pairs"][0].update(confidence=None)
        self.refused(d)
        self.refused(self.norev(self.case), "missing")  # well-formed: still just missing

    def test_g5_judge_is_checked_across_incomplete_and_missing_review_documents(self):
        c = self.src.cases
        a = self.good(c[self.urls[0]])
        for other in (dict(self.good(c[self.urls[1]], judge=dict(JUDGE, model="other"))),
                      self.norev(c[self.urls[1]], judge=dict(JUDGE, runRef="other"))):
            if other["tool"] == TOOL:
                other["pairs"].pop()                                       # incomplete
            tools = [TOOL, "no-such-tool"] if other["tool"] != TOOL else [TOOL]
            with self.assertRaises(BenchmarkError) as cm:
                score_reference_suite(c, [a, other], tools=tools, urls=self.urls[:2])
            self.assertEqual(cm.exception.code, "judge-mismatch")

    def test_g6_subset_uses_membership_not_order(self):
        c = self.src.cases
        docs = [self.good(c[u]) for u in self.urls]
        rev = list(reversed(self.urls))
        self.assertFalse(score_reference_suite(c, docs, tools=[TOOL], urls=rev, source=self.src)["attempted"]["subset"])
        self.assertTrue(score_reference_suite(c, docs[:1], tools=[TOOL], urls=self.urls[:1])["attempted"]["subset"])

    def test_g7_declarations_are_labelled_unverified(self):
        rep = score_reference_suite(self.src.cases, [self.good(self.case)], tools=[TOOL], urls=[self.case.url],
                                    source=self.src)
        self.assertTrue(any("producer declarations" in n and "not proved opaque" in n for n in rep["notices"]))

    def test_huge_int_confidence_is_refused_not_a_raw_overflow(self):
        d = self.good(self.case)
        d["pairs"][0].update(match=True, confidence=10 ** 400)
        self.refused(d)


class Cli(Base):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def args(self, jp, *extra):
        return ["reference-score", "--pins", str(self.pins_path), "--data", str(self.dp), "--labels", str(self.lp),
                "--proposal", str(self.pp), "--judgments", str(jp), *extra]

    def test_end_to_end_subset_then_o_excl_and_boundary(self):
        c = self.src.cases
        docs = [make_doc(c[u], ["t1", "t2"], {(0, 1): 0.5}) for u in self.urls[:2]]
        jp = self.tmp / "j.json"
        jp.write_text(json.dumps(docs))
        dest = self.tmp / "reports" / "ref.json"
        dest.parent.mkdir()
        rc, out, _ = self.run_cli(*self.args(jp, "--tools", TOOL, "--cases", *self.urls[:2], "--out", str(dest)))
        self.assertEqual(rc, 0)
        rep = json.loads(dest.read_text())
        self.assertEqual(json.loads(out)["reportSha256"], "sha256:" + hashlib.sha256(dest.read_bytes()).hexdigest())
        self.assertTrue(rep["complete"])
        self.assertTrue(rep["attempted"]["subset"])
        # per case: tp=1 (bug), fn perf+security (core), fp 1 (t2 unmatched); two cases pooled
        self.assertEqual(rep["tools"][TOOL]["pooled"]["core"]["counts"], {"tp": 2, "fp": 2, "fn": 4, "prs": 2})
        self.assertNotIn("GOLDTEXT", dest.read_text())
        self.assertEqual(rep["sourcePins"]["files"], self.source().file_digests)
        rc, _, _ = self.run_cli(*self.args(jp, "--tools", TOOL, "--cases", *self.urls[:2], "--out", str(dest)))
        self.assertEqual(rc, 2)                                            # O_EXCL
        inside = pathlib.Path(cli.REPO) / "tests" / "should-not-exist-ref.json"
        rc, _, _ = self.run_cli(*self.args(jp, "--tools", TOOL, "--cases", *self.urls[:2], "--out", str(inside)))
        self.assertEqual(rc, 2)
        self.assertFalse(inside.exists())

    def test_default_all_cases_incomplete_and_refusals(self):
        c = self.src.cases
        jp = self.tmp / "j.json"
        jp.write_text(json.dumps(make_doc(c[self.urls[0]], ["t1"], {(0, 1): 0.5})))   # single object accepted
        rc, out, _ = self.run_cli(*self.args(jp, "--tools", TOOL))
        rep = json.loads(out)
        self.assertEqual((rc, rep["complete"], len(rep["tools"][TOOL]["missing"]), rep["attempted"]["subset"]),
                         (0, False, len(self.urls) - 1, False))
        self.assertIsNone(rep["tools"][TOOL]["pooled"])
        v1 = self.tmp / "v1.json"
        v1.write_text(json.dumps([{"schema": "semantic-judgments@1", "caseUrl": self.urls[0], "tool": TOOL}]))
        rc, _, err = self.run_cli(*self.args(v1, "--tools", TOOL))
        self.assertEqual(rc, 1)
        self.assertIn("refused", err)
        rc, _, _ = self.run_cli(*self.args(jp, "--tools", TOOL, "--cases", "https://nope/1"))
        self.assertEqual(rc, 1)
        rc, _, _ = self.run_cli(*self.args(jp, "--cases", self.urls[0]))      # --tools required
        self.assertEqual(rc, 2)
        rc, _, _ = self.run_cli("score", "--pins", str(self.pins_path), "--data", str(self.dp), "--labels", str(self.lp),
                                "--proposal", str(self.pp), "--judgments", str(jp), "--tools", TOOL)
        self.assertEqual(rc, 1)                                            # native score refuses a reference doc
