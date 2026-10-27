"""SCORE-PROTO-02 retained reproductions of OPEN findings (expected to FAIL on the candidate; do not weaken or xfail).

F1 gate() ignores a missing dedup unit: an extraction with no dedup record still passes the host gate.
F2 an Admission is not bound to the planned request set: a forged/other-set Admission(True, ...) runs any plan's pairs.
F3 a dedup result computed for one candidate list can be assembled with a different list of the same size, and the
   document still carries a digest that matches the NEW list (stale-list binding is not checked at assembly).
F4 Gateway `schema-invalid` / `repair-exhausted` are reported as `provider-error`, not the fixed `schema-invalid` class.
F5 load_score_config on invalid UTF-8 raises UnicodeDecodeError instead of the fixed ScoreConfigError refusal.
F6 an empty declared set is vacuously `complete` with an admitted reservation."""
import tempfile
import unittest
from pathlib import Path

from tests.score_protocol_review.common import A, CFG, JUDGE, REF, URL, Fake, Res, cands, case, units
from reviewer.score_config import ScoreConfigError, load_score_config


class Open(unittest.TestCase):
    def test_F1_gate_refuses_an_extraction_with_no_dedup_record(self):
        c, us = units()
        exts = [u[1] for u in us]
        g = A.gate(exts, [us[0][2]])                 # second tool's dedup unit is MISSING
        self.assertFalse(g.ok)

    def test_F2_admission_is_bound_to_the_planned_set(self):
        c, us = units()
        plans, _ = A.plan_pairs(CFG, REF, [(m, e) for m, e, _ in us])
        g = A.gate([u[1] for u in us], [u[2] for u in us])
        adm = A.admit_complete_set(g, plans[:1], (), lambda p: True)          # admission for ONE tool's plan only
        f = Fake(pair={"match": True, "confidence": 1})
        try:
            A.run_pairs(f, adm, plans[1])                                     # ... must not run the OTHER plan
        except PermissionError:
            return
        self.fail("an admission for a different request set sent pairs")

    def test_F3_stale_dedup_cannot_be_assembled_with_a_different_candidate_list(self):
        c, us = units(texts=("alpha", "beta"))
        m, e, d = us[0]
        e2 = A.Extraction(e.tool, e.case_url, "ok", tuple({**x, "text": x["text"] + " CHANGED"} for x in e.candidates))
        # PROTO-04 fixture setup only: a VALID current-list-B dedup/gate/admission, so the stale list-A dedup reaches ASSEMBLY.
        d2 = A.run_dedup(Fake(dedup={"groups": [[0], [1]]}), CFG, REF, m, e2)
        g = A.gate([e2], [d2])
        self.assertTrue(g.ok)
        self.assertFalse(A.gate([e2], [d]).ok)                                   # gate also refuses the stale list-A dedup directly
        plans, over = A.plan_pairs(CFG, REF, [(m, e2)])
        adm = A.admit_complete_set(g, plans, over, lambda p: True)
        self.assertTrue(adm.admitted)
        pr = A.run_pairs(Fake(pair={"match": True, "confidence": 1}), adm, plans[0])
        try:
            doc = A.build_document(m, e2, d, pr, JUDGE)
        except (ValueError, PermissionError, KeyError):
            return
        self.assertEqual(doc["duplicateGroups"]["candidateListSha256"], d.list_sha256)   # the dedup's own digest, not a recomputed one

    def test_F4_gateway_schema_failures_keep_their_fixed_class(self):
        for code in ("schema-invalid", "repair-exhausted"):
            self.assertEqual(A.classify_error({"code": code}), "schema-invalid", code)

    def test_F5_invalid_utf8_config_gets_the_fixed_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_bytes(b"schema = \xff\xfe\n")
            with self.assertRaises(ScoreConfigError):
                load_score_config(p)

    def test_F6_empty_declared_set_is_not_a_complete_comparison(self):
        g = A.gate([], [])
        adm = A.admit_complete_set(g, (), (), lambda p: True)
        att = A.attempt_set([], [], adm, ())
        self.assertFalse(att["complete"])


if __name__ == "__main__":
    unittest.main()
