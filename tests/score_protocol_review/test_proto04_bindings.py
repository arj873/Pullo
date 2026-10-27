"""SCORE-PROTO-04 independent proofs of the PROTO-03 guards that the retained PROTO-02 repros alone do not isolate.
Invented data, fake `call`; every admission comes from the real gate -> plan_pairs -> admit_complete_set path."""
import dataclasses
import unittest

from tests.score_protocol_review.common import A, CFG, JUDGE, REF, URL, Fake, Res, cands, units


def genuine(us):
    plans, over = A.plan_pairs(CFG, REF, [(m, e) for m, e, _ in us])
    g = A.gate([e for _, e, _ in us], [d for _, _, d in us])
    adm = A.admit_complete_set(g, plans, over, lambda p: True)
    assert g.ok and adm.admitted, (g.failures, adm.reason)
    return plans, adm


PAIR = {"match": True, "confidence": 1}


class AdmissionBinding(unittest.TestCase):
    def test_genuine_admission_sends_only_its_own_complete_set(self):
        c, us = units(texts=("alpha", "beta"))
        plans, adm = genuine(us)
        f = Fake(pair=PAIR)
        for p in plans:
            A.run_pairs(f, adm, p)
        self.assertEqual(len(f.log), sum(len(p.requests) for p in plans))

    def test_genuine_plan_of_another_set_is_refused_by_digest_membership(self):
        c, us = units(texts=("alpha", "beta"))
        _, adm = genuine(us)
        c2, us2 = units(texts=("alpha", "gamma"))                       # same tools/cases, different candidate text
        other, _ = genuine(us2)
        f = Fake(pair=PAIR)
        for p in other:
            with self.assertRaises(PermissionError):
                A.run_pairs(f, adm, p)
        self.assertEqual(f.log, [])

    def test_forged_or_edited_admission_and_plan_are_refused_with_zero_calls(self):
        c, us = units(texts=("alpha", "beta"))
        plans, adm = genuine(us)
        c2, us2 = units(texts=("alpha", "gamma"))
        other, _ = genuine(us2)
        f = Fake(pair=PAIR)
        forged = [dataclasses.replace(adm, plan_digests=tuple(p.digest for p in other)),     # digests swapped, seal stale
                  dataclasses.replace(adm, pairs=adm.pairs + 1),
                  dataclasses.replace(adm, units_digest="0" * 64),
                  A.Admission(True, "admitted", adm.pairs, adm.plan_digests, adm.units_digest, ""),
                  A.Admission(True, "admitted", adm.pairs)]
        for a in forged:
            with self.subTest(admission=repr(a)[:60]), self.assertRaises(PermissionError):
                A.run_pairs(f, a, plans[0])
        edited = dataclasses.replace(plans[0], requests=plans[0].requests[:1])                # sliced sealed plan
        swapped = dataclasses.replace(plans[0], requests=other[0].requests)                   # requests of a different candidate set (same-text units have identical neutral requests)
        for p in (edited, swapped, dataclasses.replace(plans[0], digest=plans[1].digest)):
            with self.subTest(plan="edited"), self.assertRaises(PermissionError):
                A.run_pairs(f, adm, p)
        self.assertEqual(f.log, [])

    def test_post_admission_mutation_of_a_request_is_refused(self):
        c, us = units(texts=("alpha", "beta"))
        plans, adm = genuine(us)
        plans[0].requests[0][2]["params"]["maxOutputTokens"] = 257
        f = Fake(pair=PAIR)
        with self.assertRaises(PermissionError):
            A.run_pairs(f, adm, plans[0])
        self.assertEqual(f.log, [])

    def test_admission_requires_every_unit_plan_and_nothing_extra(self):
        c, us = units(texts=("alpha", "beta"))
        plans, over = A.plan_pairs(CFG, REF, [(m, e) for m, e, _ in us])
        g = A.gate([e for _, e, _ in us], [d for _, _, d in us])
        asked = []
        for subset in (plans[:1], plans + plans[:1], ()):
            a = A.admit_complete_set(g, subset, over, lambda p: asked.append(1) or True)
            self.assertEqual((a.admitted, a.reason), (False, "plan-mismatch"))
        self.assertEqual(asked, [])


class StaleDedupAssembly(unittest.TestCase):
    def test_valid_current_admission_still_cannot_assemble_stale_dedup(self):
        c, us = units(texts=("alpha", "beta"))
        m, e, d = us[0]
        e2 = A.Extraction(e.tool, e.case_url, "ok", tuple({**x, "text": x["text"] + " CHANGED"} for x in e.candidates))
        d2 = A.run_dedup(Fake(dedup={"groups": [[0], [1]]}), CFG, REF, m, e2)
        g = A.gate([e2], [d2])
        self.assertTrue(g.ok)
        self.assertFalse(A.gate([e2], [d]).ok)
        plans, over = A.plan_pairs(CFG, REF, [(m, e2)])
        adm = A.admit_complete_set(g, plans, over, lambda p: True)
        pr = A.run_pairs(Fake(pair=PAIR), adm, plans[0])
        with self.assertRaises(ValueError):
            A.build_document(m, e2, d, pr, JUDGE)                                           # stale list-A dedup
        doc = A.build_document(m, e2, d2, pr, JUDGE)                                        # current dedup assembles
        self.assertEqual(doc["duplicateGroups"]["candidateListSha256"], d2.list_sha256)

    def test_reordered_list_is_stale(self):
        c, us = units(texts=("alpha", "beta"))
        m, e, d = us[0]
        e2 = A.Extraction(e.tool, e.case_url, "ok", tuple(reversed(e.candidates)))
        self.assertFalse(A.gate([e2], [d]).ok)


class ErrorMapping(unittest.TestCase):
    def test_explicit_codes_and_unknown_shapes(self):
        want = {"schema-invalid": "schema-invalid", "repair-exhausted": "schema-invalid", "deadline-exceeded": "provider-timeout",
                "provider-timeout": "provider-timeout", "budget-exhausted": "budget-refused", "cancelled": "provider-error", "internal": "provider-error"}
        for code, cls in want.items():
            self.assertEqual(A.classify_error({"code": code}), cls, code)
        for odd in (None, "schema-invalid", {}, {"code": None}, {"code": 7}, {"code": "schema-invalid-x"}, {"code": "x-schema-invalid"},
                    {"code": "timeout"}, {"code": ["schema-invalid"]}, {"message": "schema-invalid deadline"}, {"code": "provider-error", "message": "schema-invalid"}):
            self.assertEqual(A.classify_error(odd), "provider-error", repr(odd))

    def test_pair_run_reports_fixed_class_never_a_match(self):
        for code, cls in (("repair-exhausted", "schema-invalid"), ("deadline-exceeded", "provider-timeout")):
            c, us = units(("zeta-tool",), texts=("only one",), ngold=1)
            plans, adm = genuine(us)
            p = A.run_pairs(Fake(pair=Res(error={"code": code, "message": "RAWSENTINEL"})), adm, plans[0]).pairs[0]
            self.assertEqual(p["error"], cls)
            self.assertNotIn("match", p)
            self.assertNotIn("RAWSENTINEL", repr(p))


class DeclaredSet(unittest.TestCase):
    def test_declared_cardinality_and_association(self):
        c, us = units()
        exts, dds = [u[1] for u in us], [u[2] for u in us]
        declared = [(e.tool, e.case_url) for e in exts]
        self.assertTrue(A.gate(exts, dds, declared).ok)
        self.assertFalse(A.gate(exts[:1], dds[:1], declared).ok)                            # declared unit has no extraction/dedup
        self.assertFalse(A.gate(exts, dds, declared[:1]).ok)                                # extra undeclared unit
        self.assertFalse(A.gate(exts, dds[:1], declared).ok)                                # missing dedup
        self.assertFalse(A.gate(exts, dds, declared + declared[:1]).ok)                     # duplicate declared
        self.assertFalse(A.gate(exts + exts[:1], dds, declared).ok)                         # duplicate extraction

    def test_empty_is_refused_but_nonempty_zero_candidate_set_is_complete_not_dropped(self):
        g0 = A.gate([], [])
        self.assertFalse(g0.ok)
        self.assertFalse(A.admit_complete_set(g0, (), (), lambda p: True).admitted)
        self.assertFalse(A.attempt_set([], [], A.admit_complete_set(g0, (), (), lambda p: True), ())["complete"])
        c, us = units(texts=())                                                              # valid, non-empty set, zero candidates each
        self.assertEqual(len(us), 2)
        plans, adm = genuine(us)
        self.assertTrue(adm.admitted)
        f = Fake(pair=PAIR)
        prs = [A.run_pairs(f, adm, p) for p in plans]
        self.assertEqual(f.log, [])
        att = A.attempt_set([u[1] for u in us], [u[2] for u in us], adm, prs)
        self.assertTrue(att["complete"])
        self.assertEqual(len({(u["tool"], u["case"]) for u in att["units"]}), 2)            # no unit dropped
        c, us = units(texts=("alpha", "beta"))                                               # dropped unit is NOT complete
        plans, adm = genuine(us)
        att = A.attempt_set([u[1] for u in us], [u[2] for u in us], adm, [A.run_pairs(Fake(pair=PAIR), adm, plans[0])])
        self.assertFalse(att["complete"])


if __name__ == "__main__":
    unittest.main()
