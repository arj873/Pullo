"""S1-22 independent gate and re-gate (reviewer: not the graph author). Invented fixtures only; oracles hand-derived from
the pinned semantics (S3:241-381, SP:85-133), not from the author's tests. The G1-G6 repros of
orchestration/handoffs/S1-22-review.md were converted after the re-gate (orchestration/handoffs/S1-22-regate.md) proved
each fixed. Scores need a bound source; source=None is an explicit unbound control."""

import contextlib
import io
import json
import random
import unittest

from reviewer.benchmark import __main__ as cli
from reviewer.benchmark.errors import BenchmarkError
from reviewer.benchmark.jsonio import digest
from reviewer.benchmark.reference_graph import (PAIR_ERROR_CLASS, SOURCE_ATTESTATION, UNRESOLVED, score_reference_case,
                                                score_reference_suite)
from reviewer.benchmark.scoring import REFERENCE_VIEW

from tests.benchmark.helpers import Fx

J = {"model": "inv-judge", "extractionPrompt": "x@1", "dedupPrompt": "d@1", "matchPrompt": "m@1",
     "schemaSha256": "sha256:00", "runRef": "inv"}
T = "cubic-v2"
SECRET = ("GOLDTEXT", "BODYTEXT", "CANDTEXT", "TITLETEXT")


def mk(case, texts, hits=(), errs=(), groups=(), tool=T, judge=None, ids=None):
    """Own builder. texts in extraction order; hits {(golden index, cand position): confidence}; others no-match 0.9."""
    rc = case.review(tool).comments[0].id
    ids = ids or [f"k{i}" for i in range(len(texts))]
    cands = [{"id": i, "sourceCommentId": rc, "text": t} for i, t in zip(ids, texts)]
    hits, pairs = dict(hits), []
    for gi, g in enumerate(case.golden):
        for ci, c in enumerate(cands):
            if (gi, ci) in errs:
                pairs.append({"golden": g.id, "candidate": c["id"], "error": "timeout"})
            else:
                pairs.append({"golden": g.id, "candidate": c["id"], "match": (gi, ci) in hits,
                              "confidence": hits.get((gi, ci), 0.9)})
    return {"schema": "reference-judgments@1", "caseUrl": case.url, "tool": tool, "judge": dict(judge or J),
            "extraction": {"candidates": cands},
            "duplicateGroups": {"candidateListSha256": digest([[c["id"], c["text"]] for c in cands]),
                                "groups": [list(g) for g in groups]},
            "pairs": pairs}


# gold per case: 0 bug, 1 perf, 2 style, 3 security. P/Q/R/P = literal duplicate text at positions 0 and 3.
TEXTS = ["CANDTEXT P", "CANDTEXT Q", "CANDTEXT R", "CANDTEXT P"]
HITS = {(0, 1): 0.6, (0, 0): 0.6, (1, 2): 0.4, (1, 3): 0.8, (3, 1): 0}


class Base(Fx):
    def setUp(self):
        super().setUp()
        self.src = self.source()
        self.urls = list(self.src.cases)
        self.case = self.src.cases[self.urls[0]]

    def suite(self, docs, tools=(T,), urls=None, source="bound"):
        source = self.src if source == "bound" else source
        return score_reference_suite(self.src.cases, docs, tools=list(tools), urls=urls, source=source)


class Semantics(Base):
    def test_hand_oracle_order_tie_zero_confidence_and_text_collapse(self):
        row = score_reference_case(self.case, mk(self.case, TEXTS, HITS))
        ev, gi = row["evaluation"], {g.id: str(i) for i, g in enumerate(self.case.golden)}
        # g0: k0 0.6 improves first, k1 tie does not; g1: k2 0.4 then k3 0.8 both improve; g3: match at 0 never counts
        self.assertEqual([(gi[t["goldenIds"][0]], t["matchedCandidateId"], t["confidence"]) for t in ev["truePositives"]],
                         [("0", "k0", 0.6), ("1", "k3", 0.8)])
        self.assertEqual([gi[f["goldenIds"][0]] for f in ev["falseNegatives"]], ["2", "3"])
        self.assertEqual(ev["falsePositives"], [{"candidateIds": ["k1"]}])
        self.assertEqual((ev["tp"], ev["fp"], ev["fn"], ev["totalCandidates"], ev["totalGolden"]), (2, 1, 2, 4, 4))
        self.assertEqual([(i["candidate"], i["confidence"]) for i in ev["provenance"]["improvements"]],
                         [("k0", 0.6), ("k2", 0.4), ("k3", 0.8)])
        self.assertEqual(ev["provenance"]["candidateCollapsedIds"], [["k0", "k3"]])
        self.assertEqual((row["pairsExpected"], row["candidates"], row["goldenCount"]), (16, 4, 4))

    def test_pair_list_order_is_irrelevant_extraction_order_is_not(self):
        d = mk(self.case, TEXTS, HITS)
        base = score_reference_case(self.case, d)["evaluation"]
        random.Random(3).shuffle(d["pairs"])
        self.assertEqual(score_reference_case(self.case, d)["evaluation"], base)
        # swap R/P' positions: g1 now sees 0.8 before 0.4, so R never improves and becomes FP
        texts = [TEXTS[0], TEXTS[1], TEXTS[3], TEXTS[2]]
        hits = {(0, 1): 0.6, (0, 0): 0.6, (1, 3): 0.4, (1, 2): 0.8}
        ev = score_reference_case(self.case, mk(self.case, texts, hits, ids=["k0", "k1", "k3", "k2"]))["evaluation"]
        self.assertEqual(ev["falsePositives"], [{"candidateIds": ["k1"]}, {"candidateIds": ["k2"]}])

    def test_siblings_reported_by_id_only(self):
        row = score_reference_case(self.case, mk(self.case, TEXTS, HITS, groups=[[1, 2]]))
        ev = row["evaluation"]
        self.assertEqual((ev["fp"], ev["falsePositives"]), (0, []))
        self.assertEqual(ev["provenance"]["siblingMarked"], [{"via": "k2", "candidateIds": ["k1"]}])
        self.assertEqual(row["duplicateGroups"], 1)

    def test_duplicate_golden_text_last_category_wins(self):
        url = self.urls[0]
        self.data[url]["golden_comments"] = [{"comment": "GOLDTEXT same", "severity": "Low", "category": "style"},
                                             {"comment": "GOLDTEXT same", "severity": "High", "category": "bug"}]
        self.write_all()
        src = self.source()
        case = src.cases[url]
        rep = score_reference_suite(src.cases, [mk(case, ["CANDTEXT a"], {(0, 0): 0.5})], tools=[T], urls=[url],
                                    source=src)
        ev = rep["tools"][T]["cases"][0]["evaluation"]
        self.assertEqual((ev["tp"], ev["fn"], ev["totalGolden"]), (1, 0, 2))
        self.assertEqual((ev["truePositives"][0]["category"], ev["truePositives"][0]["goldenIds"]),
                         ("bug", [case.golden[0].id, case.golden[1].id]))
        self.assertEqual(rep["tools"][T]["pooled"]["strict"]["counts"], {"tp": 1, "fp": 0, "fn": 0, "prs": 1})

    def test_pooled_profiles_and_named_zero(self):
        a, b = self.src.cases[self.urls[0]], self.src.cases[self.urls[1]]
        rep = self.suite([mk(a, TEXTS, HITS), mk(b, [])], urls=self.urls[:2])
        p = rep["tools"][T]["pooled"]
        # case a: TP bug,perf; FN style,security; FP 1. case b: zero candidates -> 4 uncollapsed FN.
        self.assertEqual(p["strict"]["counts"], {"tp": 1, "fp": 1, "fn": 3, "prs": 2})
        self.assertEqual(p["core"]["counts"], {"tp": 2, "fp": 1, "fn": 4, "prs": 2})
        self.assertEqual(p["all"]["counts"], {"tp": 2, "fp": 1, "fn": 6, "prs": 2})
        self.assertAlmostEqual(p["all"]["precision"], 2 / 3)
        self.assertAlmostEqual(p["all"]["recall"], 1 / 4)
        self.assertAlmostEqual(p["all"]["f1"], 2 * (2 / 3) * (1 / 4) / (2 / 3 + 1 / 4))
        self.assertAlmostEqual(p["all"]["f2"], 5 * (2 / 3) * (1 / 4) / (4 * (2 / 3) + 1 / 4))
        self.assertEqual((rep["primary"]["name"], rep["complete"]), ("core/F1", True))
        z = self.suite([mk(b, [])], urls=[self.urls[1]])["tools"][T]["pooled"]["strict"]
        self.assertEqual((z["precision"], z["f1"], z["undefined"], z["zeroConvention"]),
                         (0.0, 0.0, ["precision"], "reference-undefined-is-0"))

    def test_hidden_tool_validated_but_never_pooled(self):
        for u in self.urls:
            self.data[u]["reviews"].append({**self.data[u]["reviews"][0], "tool": "mra-inv"})
        self.write_all()
        src = self.source()
        case = src.cases[self.urls[0]]
        rep = score_reference_suite(src.cases, [mk(case, ["CANDTEXT a"], {(0, 0): 0.5}, tool="mra-inv")],
                                    tools=["mra-inv"], urls=[self.urls[0]], source=src)
        e = rep["tools"]["mra-inv"]
        self.assertEqual((e["referenceHidden"], e["complete"], e["pooled"], e["partialPooled"]), (True, False, None, None))
        bad = mk(case, ["CANDTEXT a"], tool="mra-inv")
        bad["pairs"][0]["confidence"] = None
        with self.assertRaises(BenchmarkError):
            score_reference_suite(src.cases, [bad], tools=["mra-inv"], urls=[self.urls[0]], source=src)


    def test_unbounded_confidence_and_whitespace_text_unchanged(self):
        # g0: -0.5 never improves (FP), 1.5 improves (TP, not clamped), the tie at 1.5 does not (FP)
        row = score_reference_case(self.case, mk(self.case, ["CANDTEXT a", "CANDTEXT b", "CANDTEXT c"],
                                                 {(0, 0): -0.5, (0, 1): 1.5, (0, 2): 1.5}))
        ev = row["evaluation"]
        self.assertEqual((ev["tp"], ev["fp"], ev["fn"]), (1, 2, 3))
        self.assertEqual((ev["truePositives"][0]["matchedCandidateId"], ev["truePositives"][0]["confidence"]), ("k1", 1.5))
        # whitespace-only text is a candidate (not trimmed or dropped); " x " and "x" stay distinct texts
        ev = score_reference_case(self.case, mk(self.case, ["   ", " CANDTEXT x ", "CANDTEXT x"]))["evaluation"]
        self.assertEqual((ev["totalCandidates"], ev["fp"], ev["provenance"]["candidateCollapsedIds"]), (3, 3, []))
        ok = mk(self.case, ["CANDTEXT a"], {(0, 0): 1e300})
        self.assertEqual(score_reference_case(self.case, ok)["evaluation"]["tp"], 1)
        for huge in (10 ** 400, float("inf"), -float("inf")):
            d = mk(self.case, ["CANDTEXT a"])
            d["pairs"][0]["confidence"] = huge
            with self.subTest(huge=str(huge)[:8]), self.assertRaises(BenchmarkError) as cm:
                score_reference_case(self.case, d)
            self.assertEqual(cm.exception.code, "judgments")


class Completeness(Base):
    def test_missing_incomplete_error_and_skipped_withhold_headline(self):
        u0, u1, u2 = self.urls[:3]
        c0, c1 = self.src.cases[u0], self.src.cases[u1]
        short = mk(c1, ["CANDTEXT q"])
        short["pairs"].pop()
        rep = self.suite([mk(c0, TEXTS, HITS, errs={(2, 0)}), short], urls=[u0, u1, u2])
        e = rep["tools"][T]
        self.assertEqual((e["missing"], [i["caseUrl"] for i in e["incomplete"]], e["pairErrorCases"]), ([u2], [u1], [u0]))
        self.assertEqual((e["complete"], e["pooled"], rep["complete"]), (False, None, False))
        self.assertTrue(e["partialPooled"]["notAScore"])
        self.assertEqual(e["cases"][0]["pairErrors"], 1)

    def test_zero_gold_case_is_skipped_not_missing(self):
        u = self.urls[0]
        self.data[u]["golden_comments"] = []
        self.write_all(labels=None)
        src = self.source()
        rep = score_reference_suite(src.cases, [mk(src.cases[u], ["CANDTEXT a"]), mk(src.cases[self.urls[1]], [])],
                                    tools=[T], urls=self.urls[:2], source=src)
        e = rep["tools"][T]
        self.assertEqual((e["zeroGoldSkipped"], e["casesScored"], e["missing"], e["complete"]), ([u], 1, [], True))
        self.assertEqual(e["pooled"]["all"]["counts"]["prs"], 1)

    def test_unbound_control_has_same_numbers_but_no_score(self):
        a, b = self.src.cases[self.urls[0]], self.src.cases[self.urls[1]]
        docs = [mk(a, TEXTS, HITS), mk(b, [])]
        bound = self.suite(docs, urls=self.urls[:2])
        free = self.suite(docs, urls=self.urls[:2], source=None)
        e = free["tools"][T]
        self.assertEqual((free["sourcePins"], free["sourceBound"], free["complete"]), (None, False, False))
        self.assertEqual((e["sourceBound"], e["complete"], e["pooled"]), (False, False, None))
        self.assertEqual(e["partialPooled"], {"notAScore": True, "views": bound["tools"][T]["pooled"]})
        self.assertEqual((e["missing"], e["incomplete"], e["pairErrorCases"]), ([], [], []))
        self.assertEqual(e["cases"], bound["tools"][T]["cases"])


class Refusals(Base):
    def assert_refused(self, doc, code="judgments"):
        with self.assertRaises(BenchmarkError) as cm:
            score_reference_case(self.case, doc)
        self.assertEqual(cm.exception.code, code)

    def test_document_and_pair_refusals(self):
        good = mk(self.case, ["CANDTEXT a", "CANDTEXT b"], {(0, 0): 0.7})
        muts = {
            "v1 schema": lambda d: d.update(schema="semantic-judgments@1"),
            "extra top key": lambda d: d.update(matches=[]),
            "wrong case": lambda d: d.update(caseUrl=self.urls[1]),
            "judge extra key": lambda d: d["judge"].update(temperature="0"),
            "judge empty": lambda d: d["judge"].update(model=""),
            "foreign comment": lambda d: d["extraction"]["candidates"][0].update(
                sourceCommentId=self.case.review("cubic-v1").comments[0].id),
            "dup cand id": lambda d: d["extraction"]["candidates"][1].update(id="k0"),
            "empty text": lambda d: d["extraction"]["candidates"][0].update(text=""),
            "order digest": lambda d: d["extraction"]["candidates"].reverse(),
            "group out of range": lambda d: d["duplicateGroups"].update(groups=[[0, 2]]),
            "group bool": lambda d: d["duplicateGroups"].update(groups=[[True, 0]]),
            "group empty": lambda d: d["duplicateGroups"].update(groups=[[]]),
            "group repeat": lambda d: d["duplicateGroups"].update(groups=[[1, 1]]),
            "dup pair": lambda d: d["pairs"].append(dict(d["pairs"][0])),
            "unknown golden": lambda d: d["pairs"][0].update(golden="gold:999:0"),
            "unhashable pair id": lambda d: d["pairs"][0].update(candidate=["k0"]),
            "null confidence": lambda d: d["pairs"][0].update(confidence=None),
            "bool confidence": lambda d: d["pairs"][0].update(confidence=True),
            "nan confidence": lambda d: d["pairs"][0].update(confidence=float("nan")),
            "str confidence": lambda d: d["pairs"][0].update(confidence="0.9"),
            "missing confidence": lambda d: d["pairs"][0].pop("confidence"),
            "truthy match": lambda d: d["pairs"][0].update(match="false"),
            "error plus match": lambda d: d["pairs"][0].update(error="e"),
            "empty error": lambda d: d["pairs"].__setitem__(0, {"golden": d["pairs"][0]["golden"],
                                                               "candidate": "k0", "error": ""}),
        }
        for name, f in muts.items():
            d = json.loads(json.dumps(good))
            f(d)
            with self.subTest(name):
                self.assert_refused(d)
        d = json.loads(json.dumps(good))
        d["pairs"].pop()
        self.assert_refused(d, "incomplete")

    def test_suite_level_refusals(self):
        d0 = mk(self.case, ["CANDTEXT a"])
        other = mk(self.src.cases[self.urls[1]], ["CANDTEXT a"], judge={**J, "model": "other"})
        cases = {"duplicate doc": ([d0, d0], [T], self.urls[:2]),
                 "unrequested doc": ([d0], [T], [self.urls[1]]),
                 "mixed judge": ([d0, other], [T], self.urls[:2]),
                 "repeated url": ([d0], [T], [self.urls[0]] * 2),
                 "unknown url": ([d0], [T], ["https://example/none"]),
                 "repeated tool": ([d0], [T, T], self.urls[:1]),
                 "not a list": (d0, [T], self.urls[:1])}
        for name, (docs, tools, urls) in cases.items():
            with self.subTest(name), self.assertRaises(BenchmarkError):
                score_reference_suite(self.src.cases, docs, tools=tools, urls=urls, source=self.src)


class Leakage(Base):
    def test_clean_report_has_no_gold_review_or_candidate_text(self):
        docs = [mk(self.src.cases[u], TEXTS, HITS, groups=[[1, 2]]) for u in self.urls[:2]]
        s = json.dumps(self.suite(docs, urls=self.urls[:2]))
        for marker in SECRET:
            self.assertNotIn(marker, s)

    def test_FIXED_G1_pair_error_strings_never_reach_report(self):
        d = mk(self.case, ["CANDTEXT a", "CANDTEXT b"], {(1, 1): 0.7}, errs={(0, 0)})
        d["pairs"][0]["error"] = "judge reply echoed GOLDTEXT null deref and CANDTEXT a BODYTEXT TITLETEXT " * 9
        rep = self.suite([d], urls=self.urls[:1])
        s = json.dumps(rep)
        self.assertFalse(any(m in s for m in SECRET))
        self.assertNotIn("reply echoed", s)
        row = rep["tools"][T]["cases"][0]
        ev = row["evaluation"]
        self.assertEqual(ev["errors"], [{"golden": self.case.golden[0].id, "candidate": "k0", "status": PAIR_ERROR_CLASS}])
        # the error stays an error (not a no-match), the case is not complete, upstream counts are kept
        self.assertEqual((ev["errorsCount"], row["pairErrors"], ev["tp"], ev["fp"], ev["fn"]), (1, 1, 1, 1, 3))
        e = rep["tools"][T]
        self.assertEqual((e["pairErrorCases"], e["complete"], e["pooled"]), ([self.case.url], False, None))
        self.assertEqual(e["partialPooled"]["views"]["all"]["counts"], {"tp": 1, "fp": 1, "fn": 3, "prs": 1})

    def test_refusal_and_reason_strings_carry_no_marker(self):
        ids = ["CANDTEXT id0", "CANDTEXT id1"]
        good = mk(self.case, ["CANDTEXT a", "CANDTEXT b"], {(0, 0): 0.7}, ids=ids)
        muts = [lambda d: d.update(caseUrl="GOLDTEXT url"),
                lambda d: d["extraction"]["candidates"][1].update(id=ids[0]),
                lambda d: d["extraction"]["candidates"][0].update(sourceCommentId="BODYTEXT c"),
                lambda d: d["pairs"][0].update(golden="GOLDTEXT g"),
                lambda d: d["pairs"][0].update(candidate="CANDTEXT none"),
                lambda d: d["pairs"].append(dict(d["pairs"][0])),
                lambda d: d["pairs"][0].update(confidence="CANDTEXT 0.9"),
                lambda d: d["pairs"][0].update(match="CANDTEXT"),
                lambda d: d["duplicateGroups"].update(candidateListSha256="CANDTEXT"),
                lambda d: d["judge"].update(model=["GOLDTEXT"])]
        for i, f in enumerate(muts):
            d = json.loads(json.dumps(good))
            f(d)
            with self.subTest(i), self.assertRaises(BenchmarkError) as cm:
                score_reference_case(self.case, d)
            self.assertFalse(any(m in cm.exception.message for m in SECRET), cm.exception.message)
        short = json.loads(json.dumps(good))
        short["pairs"].pop()
        rep = self.suite([short], urls=self.urls[:1])
        self.assertFalse(any(m in json.dumps(rep["tools"][T]["incomplete"]) for m in SECRET))


    def test_NOTE_G7_free_form_ids_and_judge_strings_are_echoed(self):
        # Documented limit: candidate ids and judge strings are producer-supplied and copied verbatim.
        d = mk(self.case, ["CANDTEXT a"], ids=["CANDTEXT a"], judge={**J, "runRef": "BODYTEXT run"})
        s = json.dumps(self.suite([d], urls=self.urls[:1]))
        self.assertIn("CANDTEXT", s)
        self.assertIn("BODYTEXT", s)


class Fixed(Base):
    def test_FIXED_G2_non_string_identity_is_typed_refusal(self):
        for key, val in (("caseUrl", [self.case.url]), ("tool", [T]), ("tool", {"t": T}), ("caseUrl", None)):
            d = mk(self.case, ["CANDTEXT a"])
            d[key] = val
            with self.subTest(key=key, val=val), self.assertRaises(BenchmarkError) as cm:
                self.suite([d], urls=self.urls[:1])
            self.assertEqual(cm.exception.code, "judgments")

    def test_FIXED_G3_structure_checked_before_review_lookup(self):
        bad = {"schema": "reference-judgments@1", "caseUrl": self.case.url, "tool": "no-review", "judge": 5,
               "extraction": 1, "duplicateGroups": 1, "pairs": 1}
        with self.assertRaises(BenchmarkError) as cm:
            self.suite([bad], tools=["no-review"], urls=self.urls[:1])
        self.assertEqual(cm.exception.code, "judgments")
        # a well-formed document (zero candidates, so no comment citation) for a tool without a review is incomplete
        ok = mk(self.case, [])
        ok["tool"] = "no-review"
        e = self.suite([ok], tools=["no-review"], urls=self.urls[:1])["tools"]["no-review"]
        self.assertEqual(([i["caseUrl"] for i in e["incomplete"]], e["complete"]), ([self.case.url], False))
        self.assertEqual(e["incomplete"][0]["reason"], "no review by 'no-review' for this case")  # requested tool only

    def test_FIXED_G4_source_must_hold_the_attempted_cases(self):
        d = mk(self.case, ["CANDTEXT a"], {(0, 0): 0.5})
        u0, u1 = self.urls[:2]
        orig = self.src

        class Unrelated:
            revision, file_digests = "f" * 40, {"benchmark_data.json": "sha256:" + "0" * 64}

        class Partial:
            revision, file_digests, cases = orig.revision, dict(orig.file_digests), {u1: orig.cases[u1]}
        self.data[u0]["golden_comments"][0]["comment"] = "GOLDTEXT changed"
        self.write_all()
        changed = self.source()
        for name, src in (("no cases", Unrelated()), ("not a source", object()), ("dict", {"revision": "x"}),
                          ("other data", changed), ("lacks url", Partial())):
            with self.subTest(name), self.assertRaises(BenchmarkError) as cm:
                self.suite([d], urls=[u0], source=src)
            self.assertEqual(cm.exception.code, "source")
        # binding is per attempted URL: u1 is equal in both sources, so the changed source binds a u1-only request
        rep = self.suite([mk(orig.cases[u1], ["CANDTEXT a"])], urls=[u1], source=changed)
        self.assertEqual((rep["sourcePins"]["boundCaseUrls"], rep["complete"]), ([u1], True))
        self.assertEqual(rep["sourcePins"]["files"], dict(changed.file_digests))

    def test_FIXED_G4_bound_pins_shape_and_attestation_text(self):
        rep = self.suite([mk(self.src.cases[u], []) for u in self.urls[:2]], urls=self.urls[:2])
        self.assertEqual(rep["sourcePins"], {"revision": self.src.revision, "files": dict(self.src.file_digests),
                                             "boundCaseUrls": self.urls[:2], "attestation": SOURCE_ATTESTATION})
        self.assertTrue(rep["sourceBound"])
        for phrase in ("not re-read or re-verify", "not a signature or cryptographic proof"):
            self.assertIn(phrase, SOURCE_ATTESTATION)

    def test_NOTE_G4_in_memory_binding_accepts_unverified_metadata(self):
        # Documented limit: a hand-built object holding the genuine cases binds; its revision/file digests are copied,
        # not verified. The attestation says so; this is not file or cryptographic verification.
        cases = self.src.cases

        class Forged:
            revision, file_digests = "f" * 40, {"benchmark_data.json": "sha256:" + "0" * 64}
        Forged.cases = cases
        rep = self.suite([mk(self.case, ["CANDTEXT a"])], urls=self.urls[:1], source=Forged())
        self.assertEqual((rep["sourcePins"]["revision"], rep["complete"]), ("f" * 40, True))

    def test_FIXED_G4b_unpinned_report_is_not_complete(self):
        rep = self.suite([mk(self.case, ["CANDTEXT a"], {(0, 0): 0.5})], urls=self.urls[:1], source=None)
        self.assertEqual((rep["sourcePins"], rep["sourceBound"], rep["complete"]), (None, False, False))
        self.assertEqual((rep["tools"][T]["pooled"], rep["tools"][T]["partialPooled"]["notAScore"]), (None, True))

    def test_FIXED_G5_judge_checked_on_every_validated_document(self):
        other = {**J, "model": "other"}
        a, b = self.src.cases[self.urls[0]], self.src.cases[self.urls[1]]
        short = mk(b, ["CANDTEXT a"], judge=other)
        short["pairs"].pop()
        noreview = mk(b, [], judge=other)
        noreview["tool"] = "no-review"
        for u in self.urls[:2]:
            self.data[u]["reviews"].append({**self.data[u]["reviews"][0], "tool": "mra-inv"})
        self.write_all()
        src = self.source()
        hidden = mk(src.cases[self.urls[1]], ["CANDTEXT a"], tool="mra-inv", judge=other)
        runs = {"incomplete": ([mk(a, ["CANDTEXT a"]), short], [T], self.src),
                "missing review": ([mk(a, ["CANDTEXT a"]), noreview], [T, "no-review"], self.src),
                "second tool": ([mk(a, ["CANDTEXT a"]), mk(a, ["CANDTEXT a"], tool="cubic-v1", judge=other)],
                                [T, "cubic-v1"], self.src),
                "hidden tool": ([mk(src.cases[self.urls[0]], ["CANDTEXT a"]), hidden], [T, "mra-inv"], src)}
        for name, (docs, tools, s) in runs.items():
            with self.subTest(name), self.assertRaises(BenchmarkError) as cm:
                score_reference_suite(s.cases, docs, tools=tools, urls=self.urls[:2], source=s)
            self.assertEqual(cm.exception.code, "judge-mismatch")
        # an unrequested document is refused outright, never silently ignored
        with self.assertRaises(BenchmarkError) as cm:
            self.suite([mk(a, ["CANDTEXT a"]), mk(b, ["CANDTEXT a"], judge=other)], urls=self.urls[:1])
        self.assertEqual(cm.exception.code, "judgments")
        same = mk(b, ["CANDTEXT a"])
        same["pairs"].pop()
        rep = self.suite([mk(a, ["CANDTEXT a"]), same], urls=self.urls[:2])
        self.assertEqual((rep["judge"], rep["judgeDigest"], rep["complete"]), (J, digest(J), False))

    def test_FIXED_G6_subset_flag_is_set_membership(self):
        docs = [mk(self.src.cases[u], []) for u in self.urls]
        self.assertFalse(self.suite(docs, urls=list(reversed(self.urls)))["attempted"]["subset"])
        self.assertTrue(self.suite(docs[:1], urls=self.urls[:1])["attempted"]["subset"])

    def test_G7_declarations_labelled_and_U2_still_unbuilt(self):
        rep = self.suite([mk(self.case, ["CANDTEXT a"])], urls=self.urls[:1])
        self.assertEqual(rep["judgeStatus"], "producer-declared, unverified")
        self.assertTrue(any("not proved opaque" in n for n in rep["notices"]))
        self.assertTrue(any(u.startswith("U2") and "not built" in u for u in UNRESOLVED))
        self.assertIn("No parity claim", rep["referenceView"]["label"])


class Cli(Base):
    def run_cli(self, *extra, judgments=None):
        jp = self.ops / "judgments.json"
        if judgments is not None:
            jp.write_text(judgments if isinstance(judgments, str) else json.dumps(judgments))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(extra))
        return rc, out.getvalue(), err.getvalue()

    def args(self, cmd="reference-score", *more):
        return [cmd, "--pins", str(self.pins_path), "--data", str(self.dp), "--labels", str(self.lp),
                "--proposal", str(self.pp), "--judgments", str(self.ops / "judgments.json"), *more]

    def test_subset_report_o_excl_and_boundaries(self):
        docs = [mk(self.case, TEXTS, HITS)]
        out = self.ops / "rep.json"
        rc, so, _ = self.run_cli(*self.args("reference-score", "--tools", T, "--cases", self.urls[0], "--out", str(out)),
                                 judgments=docs)
        rep = json.loads(so)
        self.assertEqual((rc, rep["attempted"]["subset"], rep["complete"]), (0, True, True))
        self.assertEqual(rep["sourcePins"]["revision"], self.src.revision)
        self.assertEqual(rep["sourcePins"]["files"], dict(self.src.file_digests))
        self.assertEqual((rep["sourceBound"], rep["sourcePins"]["boundCaseUrls"]), (True, [self.urls[0]]))
        self.assertEqual(json.loads(out.read_text())["tools"], rep["tools"])
        self.assertFalse(any(m in out.read_text() for m in SECRET))
        rc, _, err = self.run_cli(*self.args("reference-score", "--tools", T, "--cases", self.urls[0], "--out", str(out)))
        self.assertNotEqual(rc, 0)
        self.assertIn("refused", err)
        for bad in (cli.REPO / "tests" / "s122-should-not-exist.json", self.store / "rep.json"):
            rc, _, err = self.run_cli(*self.args("reference-score", "--tools", T, "--cases", self.urls[0],
                                                 "--out", str(bad)))
            self.assertEqual((rc, json.loads(err)["code"]), (2, "boundary"))
            self.assertFalse(bad.exists())

    def test_malformed_json_and_v1_refused_without_traceback(self):
        for payload in ("{not json", '[{"confidence": NaN}]', json.dumps([{"schema": "semantic-judgments@1"}])):
            rc, so, err = self.run_cli(*self.args("reference-score", "--tools", T), judgments=payload)
            self.assertNotEqual(rc, 0, payload)
            self.assertEqual((so, json.loads(err)["status"]), ("", "refused"))

    def test_cli_pair_error_text_and_huge_numbers(self):
        d = mk(self.case, TEXTS, HITS, errs={(0, 0)})
        d["pairs"][0]["error"] = "GOLDTEXT null deref CANDTEXT P BODYTEXT"
        out = self.ops / "err.json"
        rc, so, _ = self.run_cli(*self.args("reference-score", "--tools", T, "--cases", self.urls[0], "--out", str(out)),
                                 judgments=[d])
        self.assertEqual((rc, json.loads(so)["complete"]), (0, False))
        for text in (so, out.read_text()):
            self.assertFalse(any(m in text for m in SECRET))
        base = json.dumps([mk(self.case, ["CANDTEXT a"])])
        for lit in ("1e400", "1" + "0" * 400, "-1e400"):
            payload = base.replace('"confidence": 0.9', '"confidence": ' + lit, 1)
            self.assertNotEqual(payload, base)
            rc, so, err = self.run_cli(*self.args("reference-score", "--tools", T, "--cases", self.urls[0]),
                                       judgments=payload)
            self.assertEqual((rc, so, json.loads(err)["code"]), (1, "", "judgments"), lit[:6])

    def test_cli_without_cases_binds_every_case(self):
        docs = [mk(self.src.cases[u], []) for u in self.urls]
        rc, so, _ = self.run_cli(*self.args("reference-score", "--tools", T), judgments=docs)
        rep = json.loads(so)
        self.assertEqual((rc, rep["attempted"]["subset"], rep["complete"]), (0, False, True))
        self.assertEqual(rep["sourcePins"]["boundCaseUrls"], self.urls)

    def test_native_commands_unchanged(self):
        rc, so, _ = self.run_cli("verify-pins", "--pins", str(self.pins_path), "--data", str(self.dp),
                                 "--labels", str(self.lp))
        self.assertEqual((rc, json.loads(so)["status"]), (0, "verified"))
        rc, so, _ = self.run_cli("inspect", "--pins", str(self.pins_path), "--data", str(self.dp),
                                 "--labels", str(self.lp), "--proposal", str(self.pp))
        self.assertEqual(rc, 0)
        rc, _, err = self.run_cli(*self.args("score", "--tools", T), judgments=[mk(self.case, ["CANDTEXT a"])])
        self.assertEqual((rc, json.loads(err)["status"]), (1, "refused"))  # native score never accepts all-pairs docs
        self.assertEqual(REFERENCE_VIEW["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
