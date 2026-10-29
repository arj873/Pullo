"""HOLD-ACK-01: an append-only `acknowledge` row lets a new scoring process start past ONE unresolvable scoring call
(generation record permanently missing) while its worst-case charge stays counted everywhere. Offline, invented files."""

from __future__ import annotations

import hashlib
import io
import json

from reviewer.gateway.errors import AuthorizationError
from reviewer.runtime import RuntimeLedger
from reviewer.runtime import acknowledge as ACK
from tests.runtime.common import OPUS, SONNET
from tests.score_runtime.test_score_runtime import S, ProviderBase

WORST = 121_032
EV = {"reasonCode": "generation-not-found", "keyRemainingBeforeMicros": 48_000_000,
      "keyRemainingAfterMicros": 47_900_000, "sumOtherOfficialMicros": 100_000}       # implied charge of the call: 0


class AckBase(ProviderBase):
    def setUp(self):
        super().setUp()
        self.op.mkdir(parents=True, exist_ok=True)
        self.lg = RuntimeLedger(self.ledger_path, 50_000_000)

    def sha(self):
        return hashlib.sha256(self.ledger_path.read_bytes()).hexdigest() if self.ledger_path.exists() else None

    def filtered(self, key="cf", gen="gen-cf", worst=WORST):
        """The real shape: HTTP 200, finish_reason content_filter, no usage -> unknown-worst-case."""
        self.lg.admit(key, worst, model=OPUS, **S)
        self.lg.finish(key, outcome="processed", httpStatus=200, generationId=gen, resolvedModel=OPUS,
                       finishReason="content_filter", note="invalid-output", accountableUsdMicros=worst,
                       accountableBasis="unknown-worst-case", accountableEstimated=True)

    def known(self, key, cost=1000, gen=None):
        self.lg.admit(key, 5000, model=OPUS, **S)
        self.lg.finish(key, outcome="processed", generationId=gen or "gen-" + key, routerCostUsdMicros=cost,
                       tokenPricedUsdMicros=cost, upstreamInferenceCostUsdMicros=None, isByok=None)

    def all_totals(self):
        return [self.lg.totals(), self.lg.totals("scoring"), self.lg.totals("review")]

    def rows(self):
        return [json.loads(x) for x in self.ledger_path.read_text().splitlines()]


class Acknowledge(AckBase):
    def test_hold_clears_for_the_acknowledged_call_only_and_money_is_unchanged(self):
        self.known("a", 3000)
        self.filtered()
        self.lg.admit("rev", 9000, model=SONNET)                   # unrelated review exposure
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        with self.assertRaises(AuthorizationError):
            self.sp()
        totals, before = self.all_totals(), self.sha()
        pre = self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=False)
        self.assertEqual(self.sha(), before)                          # preview writes nothing
        self.assertEqual((pre["appended"], pre["holdBefore"], pre["holdAfter"]),
                         (False, {"reason": "prior-unresolved-scoring-exposure"}, None))
        self.assertEqual((pre["countedUsdMicros"], pre["countedBasis"], pre["impliedCallUsdMicros"]),
                         (WORST, "unknown-worst-case", 0))
        self.assertIsNotNone(self.lg.scoring_startup_hold())
        res = self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=True)
        self.assertTrue(res["appended"])
        self.assertEqual(res["before"], res["after"])
        self.assertEqual(res["scoringBefore"], res["scoringAfter"])
        self.assertIsNone(self.lg.scoring_startup_hold())
        self.assertEqual(self.all_totals(), totals)                  # every total identical, incl. committed/cap
        sc = self.lg.totals("scoring")
        self.assertEqual((sc["unknownBoundUsdMicros"], sc["knownUsdMicros"], sc["committedUsdMicros"]),
                         (WORST, 3000, WORST + 3000))
        self.assertEqual(self.lg.totals()["committedUsdMicros"], WORST + 3000 + 9000)
        row = self.rows()[-1]
        self.assertEqual({k: row[k] for k in ("type", "callKey", "generationId", "scope", "reasonCode",
                                              "keyRemainingBeforeMicros", "keyRemainingAfterMicros",
                                              "sumOtherOfficialMicros", "impliedCallUsdMicros", "countedUsdMicros",
                                              "countedBasis")},
                         {"type": "acknowledge", "callKey": "cf", "generationId": "gen-cf", "scope": "scoring-startup-hold",
                          "reasonCode": "generation-not-found", "keyRemainingBeforeMicros": 48_000_000,
                          "keyRemainingAfterMicros": 47_900_000, "sumOtherOfficialMicros": 100_000,
                          "impliedCallUsdMicros": 0, "countedUsdMicros": WORST, "countedBasis": "unknown-worst-case"})
        self.sp()                                                    # a new scoring provider now constructs

    def test_acknowledged_charge_still_counts_against_every_cap(self):
        self.filtered()
        self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=True)
        cap = S["category_cap"]
        self.assertEqual(self.lg.admit("n1", cap - WORST + 1, model=OPUS, **S),
                         {"reason": "scoring-campaign-cap", "wouldReach": cap + 1, "limit": cap})
        self.assertIsNone(self.lg.admit("n2", cap - WORST, model=OPUS, **S))
        small = RuntimeLedger(self.ledger_path, cap + 1)              # runtime cap counts it too
        self.assertEqual(small.admit("n3", 2, model=SONNET)["reason"], "runtime-aggregate-cap")

    def test_second_unacknowledged_unknown_row_still_holds(self):
        self.filtered("cf", "gen-cf")
        self.filtered("cf2", "gen-cf2")
        self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=True)
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "prior-unresolved-scoring-exposure"})
        self.lg.acknowledge("cf2", "gen-cf2", evidence=EV, apply=True)
        self.assertIsNone(self.lg.scoring_startup_hold())

    def test_orphan_intent_estimated_row_and_unreadable_ledger_still_hold(self):
        self.filtered()
        self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=True)
        self.lg.admit("orphan", 1000, model=OPUS, **S)                # crashed: intent, no result
        self.assertIsNotNone(self.lg.scoring_startup_hold())
        with self.assertRaises(ValueError):                           # and an orphan can never be acknowledged
            self.lg.acknowledge("orphan", "gen-x", evidence=EV, apply=True)
        self.ledger_path.unlink()
        self.filtered()
        self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=True)
        self.lg.admit("est", 5000, model=OPUS, **S)                   # estimated basis (zero cost, no token price)
        self.lg.finish("est", outcome="processed", generationId="gen-est", routerCostUsdMicros=0)
        self.assertEqual(self.lg.totals("scoring")["estimatedUsdMicros"], 5000)
        self.assertIsNotNone(self.lg.scoring_startup_hold())
        with self.ledger_path.open("a") as f:
            f.write("not json\n")
        self.assertEqual(self.lg.scoring_startup_hold(), {"reason": "scoring-ledger-unreadable"})

    def test_forged_or_mismatched_ack_row_does_not_release(self):
        self.filtered()
        with self.ledger_path.open("a") as f:
            for ack in ({"type": "acknowledge", "callKey": "cf", "generationId": "gen-other"},
                        {"type": "acknowledge", "callKey": "other", "generationId": "gen-cf"}):
                f.write(json.dumps(ack) + "\n")
        self.assertIsNotNone(self.lg.scoring_startup_hold())
        self.assertEqual(self.lg.totals("scoring")["unknownBoundUsdMicros"], WORST)

    def test_refusals_write_nothing(self):
        self.filtered()
        self.known("k")
        self.lg.admit("rec", 5000, model=OPUS, **S)
        self.lg.finish("rec", outcome="processed", generationId="gen-rec", costBasis="unknown", tokenPricedUsdMicros=100)
        self.lg.reconcile("rec", {"id": "gen-rec", "total_cost": "0.000100"})
        self.lg.admit("rev", 5000, model=SONNET)                      # review call with unknown cost
        self.lg.finish("rev", outcome="unknown", generationId="gen-rev", costBasis="unknown")
        self.lg.admit("rej", 5000, model=OPUS, **S)
        self.lg.finish("rej", outcome="rejected-before-processing", generationId="gen-rej", errorKind="http-400")
        self.lg.admit("orphan", 5000, model=OPUS, **S)
        self.lg.admit("est", 5000, model=OPUS, **S)                   # estimated (zero-unverifiable), not unknown
        self.lg.finish("est", outcome="processed", generationId="gen-est", routerCostUsdMicros=0)
        self.lg.admit("flo", 5000, model=OPUS, **S)                   # estimated (suspect-floored-to-token-priced)
        self.lg.finish("flo", outcome="processed", generationId="gen-flo", routerCostUsdMicros=1, tokenPricedUsdMicros=900)
        self.assertEqual(self.lg.totals("scoring")["estimatedUsdMicros"], 5000 + 900)
        before = self.sha()
        cases = [("nope", "gen-cf"), ("cf", "gen-wrong"), ("cf", ""), ("k", "gen-k"), ("rec", "gen-rec"),
                 ("rev", "gen-rev"), ("rej", "gen-rej"), ("orphan", "gen-orphan"), ("est", "gen-est"),
                 ("flo", "gen-flo")]
        for ck, gid in cases:
            with self.subTest(ck=ck, gid=gid), self.assertRaises(ValueError):
                self.lg.acknowledge(ck, gid, evidence=EV, apply=True)
        bad_ev = [None, {}, {**EV, "extra": 1}, {k: v for k, v in EV.items() if k != "sumOtherOfficialMicros"},
                  {**EV, "reasonCode": "usage-zero"}, {**EV, "keyRemainingAfterMicros": -1},
                  {**EV, "sumOtherOfficialMicros": True}, {**EV, "sumOtherOfficialMicros": 1.0},
                  {**EV, "note": "x" * 501}, {**EV, "note": 3},
                  {**EV, "sumOtherOfficialMicros": 100_001},                              # implied charge negative
                  {**EV, "keyRemainingAfterMicros": 47_900_000 - WORST - 1}]             # implied > counted
        for ev in bad_ev:
            with self.subTest(ev=ev), self.assertRaises(ValueError):
                self.lg.acknowledge("cf", "gen-cf", evidence=ev, apply=True)
        with self.assertRaises(ValueError):
            self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply="yes")
        self.assertEqual(self.sha(), before)
        self.assertIsNotNone(self.lg.scoring_startup_hold())

    def test_implied_charge_up_to_counted_bound_is_accepted(self):
        self.filtered()
        res = self.lg.acknowledge("cf", "gen-cf", evidence={**EV, "keyRemainingAfterMicros": 47_900_000 - WORST,
                                                              "note": "key delta includes this call"}, apply=True)
        self.assertEqual(res["impliedCallUsdMicros"], WORST)
        self.assertEqual(self.rows()[-1]["note"], "key delta includes this call")

    def test_double_acknowledge_is_idempotent_and_different_evidence_is_refused(self):
        self.filtered()
        self.assertTrue(self.lg.acknowledge("cf", "gen-cf", evidence={**EV, "note": "n"}, apply=True)["appended"])
        before = self.sha()
        again = self.lg.acknowledge("cf", "gen-cf", evidence={**EV, "note": "n"}, apply=True)
        self.assertEqual((again["appended"], again["alreadyAcknowledged"], again["holdAfter"]), (False, True, None))
        self.assertEqual(again["before"], again["after"])
        for ev in ({**EV, "note": "different"}, EV, {**EV, "sumOtherOfficialMicros": 99_999, "note": "n"}):
            for apply in (False, True):
                with self.subTest(ev=ev, apply=apply), self.assertRaises(ValueError):
                    self.lg.acknowledge("cf", "gen-cf", evidence=ev, apply=apply)
        self.assertEqual(self.sha(), before)

    def test_missing_ledger_is_never_created(self):
        self.assertFalse(self.ledger_path.exists())
        for apply in (False, True):
            with self.subTest(apply=apply), self.assertRaises(ValueError):
                self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=apply)
        self.assertFalse(self.ledger_path.exists())

    def test_reconcile_still_resolves_an_acknowledged_call(self):
        self.filtered()
        self.lg.acknowledge("cf", "gen-cf", evidence=EV, apply=True)
        self.lg.reconcile("cf", {"id": "gen-cf", "total_cost": "0.002000"})
        sc = self.lg.totals("scoring")
        self.assertEqual((sc["unknownBoundUsdMicros"], sc["knownUsdMicros"]), (0, 2000))
        self.assertIsNone(self.lg.scoring_startup_hold())

    def test_secret_shaped_note_is_redacted(self):
        self.filtered()
        self.lg.acknowledge("cf", "gen-cf", evidence={**EV, "note": "sk-or-v1-" + "a" * 64}, apply=True)
        self.assertNotIn("sk-or-v1-" + "a" * 64, self.ledger_path.read_text())


class AcknowledgeCli(AckBase):
    def write_ev(self, **doc):
        p = self.tmp / "ack.json"
        p.write_text(json.dumps({"generationId": "gen-cf", "evidence": EV, **doc}))
        return str(p)

    def run_cli(self, *argv):
        out = io.StringIO()
        return ACK.main(list(argv), out=out), json.loads(out.getvalue())

    def test_preview_writes_nothing_then_apply_appends_once(self):
        self.known("k")
        self.filtered()
        ev = self.write_ev(callKey="cf")
        before = self.sha()
        rc, rep = self.run_cli("--ledger", str(self.ledger_path), "--evidence", ev)
        self.assertEqual((rc, rep["ok"], rep["applied"], rep["callKey"]), (0, True, False, "cf"))
        self.assertIsNone(rep["holdAfter"])
        self.assertEqual(self.sha(), before)
        self.assertIsNotNone(self.lg.scoring_startup_hold())
        totals = self.all_totals()
        rc, rep = self.run_cli("--ledger", str(self.ledger_path), "--evidence", ev, "--apply")
        self.assertEqual((rc, rep["applied"]), (0, True))
        self.assertEqual(len(self.rows()), 5)
        self.assertEqual(self.all_totals(), totals)
        self.assertIsNone(self.lg.scoring_startup_hold())
        after = self.sha()
        rc, rep = self.run_cli("--ledger", str(self.ledger_path), "--evidence", ev, "--apply")
        self.assertEqual((rc, rep["applied"], rep["alreadyAcknowledged"]), (0, False, True))
        self.assertEqual(self.sha(), after)

    def test_refusals_and_missing_ledger_never_created(self):
        self.filtered()
        before = self.sha()
        for ev in (self.write_ev(callKey="other"), self.write_ev(generationId="gen-none"),
                   self.write_ev(evidence={**EV, "reasonCode": "usage-zero"}), self.write_ev(extra=1)):
            rc, rep = self.run_cli("--ledger", str(self.ledger_path), "--evidence", ev, "--apply")
            self.assertEqual((rc, rep["ok"]), (1, False))
        bad = self.tmp / "bad.json"
        bad.write_text("not json")
        self.assertEqual(self.run_cli("--ledger", str(self.ledger_path), "--evidence", str(bad), "--apply")[0], 1)
        big = self.tmp / "big.json"
        big.write_text(json.dumps({"generationId": "gen-cf", "evidence": EV, "pad": "x" * (1 << 20)}))
        self.assertEqual(self.run_cli("--ledger", str(self.ledger_path), "--evidence", str(big), "--apply")[0], 1)
        link = self.tmp / "link.json"
        link.symlink_to(self.write_ev())
        self.assertEqual(self.run_cli("--ledger", str(self.ledger_path), "--evidence", str(link), "--apply")[0], 1)
        self.assertEqual(self.sha(), before)
        with self.ledger_path.open("a") as f:                           # malformed ledger shape -> one fixed code
            f.write("[]\n")
        rc, rep = self.run_cli("--ledger", str(self.ledger_path), "--evidence", self.write_ev(), "--apply")
        self.assertEqual((rc, rep), (1, {"ok": False, "error": "malformed-input"}))
        missing = self.op / "missing.jsonl"
        with self.assertRaises(SystemExit):
            ACK.main(["--ledger", str(missing), "--evidence", self.write_ev()], out=io.StringIO())
        self.assertFalse(missing.exists())


class ForgedRows(AckBase):
    """note()/finish() can never write a row of another type (which would bypass acknowledge/reconcile checks)."""

    def test_note_only_writes_note_rows(self):
        self.filtered()
        before = self.sha()
        for t in ("acknowledge", "reconcile", "intent", "result", ""):
            with self.subTest(t=t), self.assertRaises(ValueError):
                self.lg.note(type=t, callKey="cf", generationId="gen-cf")
        self.assertEqual(self.sha(), before)
        self.assertIsNotNone(self.lg.scoring_startup_hold())
        self.lg.note(type="note", keyRemainingUsd="1")                  # the provider's own key-status shape
        self.lg.note(keyRemainingUsd="1")
        self.assertEqual([r["type"] for r in self.rows()[-2:]], ["note", "note"])

    def test_finish_cannot_set_type_or_call_key(self):
        self.lg.admit("r1", 1000, model=SONNET)
        self.lg.admit("r2", 1000, model=SONNET)
        before = self.sha()
        with self.assertRaises(ValueError):
            self.lg.finish("r1", type="acknowledge", outcome="processed", generationId="g")
        with self.assertRaises(ValueError):
            self.lg.finish("r1", callKey="r2", outcome="processed", generationId="g")
        self.assertEqual(self.sha(), before)
