"""V6G (ORPHAN-ACK, incident run_83361955b98f30dc): a scoring call in flight when its host died (a machine reboot) leaves an intent with
NO result row. The ledger counts it at its worst case and, before v6g, held every new scoring process forever (an intent without a result
was never acknowledged, and only the admitting instance may write its result). v6g acknowledges such an orphan by call key with a null
generation id (`orphanIntent` true); its worst case stays counted everywhere. Offline, invented files."""

from __future__ import annotations

import json

from reviewer.gateway.errors import AuthorizationError
from reviewer.runtime import RuntimeLedger
from tests.runtime.common import OPUS, SONNET
from tests.score_runtime.test_hold_acknowledge import EV, AckBase
from tests.score_runtime.test_score_runtime import S

W = 58_640


class OrphanAcknowledge(AckBase):
    def setUp(self):
        super().setUp()
        self.dead = RuntimeLedger(self.ledger_path, 50_000_000)       # the killed run's own instance (it admitted the calls)

    def orphan(self, key="o1", worst=W):
        self.assertIsNone(self.dead.admit(key, worst, model=OPUS, **S))  # intent written, then the process died: no result

    def test_hold_clears_for_the_acknowledged_orphan_and_money_is_unchanged(self):
        self.known("a", 3000)
        self.orphan()
        sc = self.lg.totals("scoring")
        self.assertEqual((sc["unknownBoundUsdMicros"], sc["calls"]), (W, 2))
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        with self.assertRaises(AuthorizationError):
            self.sp()
        totals, before = self.all_totals(), self.sha()
        pre = self.lg.acknowledge("o1", None, evidence=EV, apply=False)
        self.assertEqual(self.sha(), before)                              # preview writes nothing
        self.assertEqual((pre["appended"], pre["holdBefore"], pre["holdAfter"], pre["countedUsdMicros"], pre["countedBasis"],
                          pre["impliedCallUsdMicros"]), (False, {"reason": "prior-unresolved-scoring-exposure"}, None, W, None, 0))
        res = self.lg.acknowledge("o1", None, evidence=EV, apply=True)
        self.assertTrue(res["appended"])
        self.assertEqual((res["before"], res["scoringBefore"]), (res["after"], res["scoringAfter"]))
        self.assertIsNone(self.lg.scoring_startup_hold())
        self.assertEqual(self.all_totals(), totals)                       # the worst case still counted in every total
        row = self.rows()[-1]
        self.assertEqual({k: row[k] for k in ("type", "callKey", "generationId", "scope", "reasonCode", "impliedCallUsdMicros",
                                              "countedUsdMicros", "countedBasis", "orphanIntent")},
                         {"type": "acknowledge", "callKey": "o1", "generationId": None, "scope": "scoring-startup-hold",
                          "reasonCode": "generation-not-found", "impliedCallUsdMicros": 0, "countedUsdMicros": W, "countedBasis": None,
                          "orphanIntent": True})
        self.assertEqual([r["type"] for r in self.rows()], ["intent", "result", "intent", "acknowledge"])   # nothing else written
        self.sp()                                                         # a new scoring provider now constructs
        again = self.lg.acknowledge("o1", None, evidence=EV, apply=True)  # idempotent; other evidence refused
        self.assertEqual((again["appended"], again["alreadyAcknowledged"]), (False, True))
        with self.assertRaises(ValueError):
            self.lg.acknowledge("o1", None, evidence={**EV, "note": "other"}, apply=True)

    def test_the_acknowledged_worst_case_still_counts_against_the_caps(self):
        self.orphan()
        self.lg.acknowledge("o1", None, evidence=EV, apply=True)
        cap = S["category_cap"]
        self.assertEqual(self.lg.admit("n1", cap - W + 1, model=OPUS, **S),
                         {"reason": "scoring-campaign-cap", "wouldReach": cap + 1, "limit": cap})
        self.assertIsNone(self.lg.admit("n2", cap - W, model=OPUS, **S))
        small = RuntimeLedger(self.ledger_path, cap + 1)                  # the runtime cap counts it too
        self.assertEqual(small.admit("n3", 2, model=SONNET)["reason"], "runtime-aggregate-cap")

    def test_implied_charge_in_zero_to_worst_case(self):
        self.orphan()
        charged = {**EV, "keyRemainingAfterMicros": EV["keyRemainingAfterMicros"] - W}      # the key charged exactly the worst case
        self.assertEqual(self.lg.acknowledge("o1", None, evidence=charged, apply=False)["impliedCallUsdMicros"], W)
        for bad in ({**EV, "keyRemainingAfterMicros": EV["keyRemainingAfterMicros"] - W - 1},  # more than the counted worst case
                    {**EV, "sumOtherOfficialMicros": EV["sumOtherOfficialMicros"] + 1}):   # negative
            with self.subTest(ev=bad), self.assertRaises(ValueError):
                self.lg.acknowledge("o1", None, evidence=bad, apply=True)
        self.assertEqual([r["type"] for r in self.rows()], ["intent"])

    def test_refusals_write_nothing(self):
        self.orphan()
        self.lg.admit("mine", 4000, model=OPUS, **S)                       # admitted by THIS instance: may still be in flight
        self.dead.admit("rev", 5000, model=SONNET)                         # a REVIEW orphan: not the scoring hold
        before = self.sha()
        for key, gen, why in (("mine", None, "admitted by this ledger instance"),
                              ("o1", "gen-x", "carries that generation id"),           # an orphan has no generation id to name
                              ("rev", None, "not a scoring call"),
                              ("nope", None, "not a scoring call")):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, why):
                self.lg.acknowledge(key, gen, evidence=EV, apply=True)
        self.assertEqual(self.sha(), before)
        self.assertIsNotNone(self.lg.scoring_startup_hold())

    def test_each_orphan_needs_its_own_ack(self):
        self.orphan("o1")
        self.orphan("o2", 1234)
        self.lg.acknowledge("o1", None, evidence=EV, apply=True)
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.lg.acknowledge("o2", None, evidence=EV, apply=True)
        self.assertIsNone(self.lg.scoring_startup_hold())

    def test_a_late_result_ends_the_orphan_ack(self):
        self.orphan()
        self.lg.acknowledge("o1", None, evidence=EV, apply=True)
        self.assertIsNone(self.lg.scoring_startup_hold())
        self.dead.finish("o1", outcome="unknown", generationId="gen-late", costBasis="unknown")   # its own instance after all
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.lg.acknowledge("o1", "gen-late", evidence=EV, apply=True)    # then only the rules for a result row apply
        self.assertIsNone(self.lg.scoring_startup_hold())

    def test_forged_orphan_ack_rows_do_not_release(self):
        self.orphan()
        with self.ledger_path.open("a") as f:
            for ack in ({"type": "acknowledge", "callKey": "o1", "generationId": None},                   # no orphanIntent
                        {"type": "acknowledge", "callKey": "o1", "generationId": None, "orphanIntent": "true"},
                        {"type": "acknowledge", "callKey": "other", "generationId": None, "orphanIntent": True},
                        {"type": "note", "callKey": "o1", "generationId": None, "orphanIntent": True}):
                f.write(json.dumps(ack) + "\n")
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.assertEqual(self.lg.totals("scoring")["unknownBoundUsdMicros"], W)

    def test_the_v6d_null_generation_ack_is_unchanged(self):
        self.lg.admit("u503", 52_296, model=OPUS, **S)
        self.lg.finish("u503", outcome="unknown", httpStatus=503, errorKind="http-503", generationId=None, costBasis="unknown")
        res = self.lg.acknowledge("u503", None, evidence=EV, apply=True)
        self.assertEqual((res["countedBasis"], res["holdAfter"]), ("unknown-worst-case", None))
        self.assertNotIn("orphanIntent", self.rows()[-1])
        self.assertIsNone(self.lg.scoring_startup_hold())
