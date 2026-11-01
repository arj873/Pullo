"""CAP150 (v6c): the live score_host_cli path opens the trial ledger under the $150 total, so scoring is still admitted after more
than $50 of committed review spend (up to the 100M aggregate ceiling). Fake inputs/auth/state/transport only (the SCORE-HOST-05
fixture); no real data, key, network or provider."""

from __future__ import annotations

import json
import os

from reviewer.gateway import SpendBook, trusted_authorization
from reviewer.runtime import RuntimeLedger
from reviewer.runtime.catalog import TRIAL_TOTAL_USD_MICROS
from reviewer.runtime.scoring_budget import SCORING_AGGREGATE_CEILING_MAX
from tests.score_host_operator.test_operator import Fixture

REVIEW_SPEND = 52_000_000                                              # above the old $50 total, below the 100M aggregate ceiling


class LiveAboveFifty(Fixture):
    def setUp(self):
        super().setUp()
        self.auth_doc = {**self.auth_doc, "maxUsdMicrosTotal": TRIAL_TOTAL_USD_MICROS}
        self.auth_path.write_text(json.dumps(self.auth_doc))
        os.chmod(self.auth_path, 0o600)
        self.handle = trusted_authorization(self.auth_path)
        led = RuntimeLedger(self.state / "runtime-ledger.jsonl", TRIAL_TOTAL_USD_MICROS)
        k = "rev|INVESTIGATE|investigator|a|0|0"
        self.assertIsNone(led.admit(k, REVIEW_SPEND, model="anthropic/claude-sonnet-5.5"))
        led.finish(k, outcome="processed", generationId="gen-review", routerCostUsdMicros=REVIEW_SPEND, isByok=False,
                   tokenPricedUsdMicros=REVIEW_SPEND)
        book = SpendBook(self.handle, self.state / "spend-book.jsonl")
        self.assertIsNone(book.reserve("review", REVIEW_SPEND))
        book.settle("review", REVIEW_SPEND)
        self.before = led.totals()
        self.assertEqual((self.before["committedUsdMicros"], self.before["capUsdMicros"]), (REVIEW_SPEND, TRIAL_TOTAL_USD_MICROS))

    def test_live_scoring_is_admitted_above_fifty_dollars_committed(self):
        self.assertTrue(50_000_000 < REVIEW_SPEND < SCORING_AGGREGATE_CEILING_MAX)
        b = self.write_baseline(initial={"scoring": 0, "all": REVIEW_SPEND, "bookCommitted": REVIEW_SPEND, "bookInflight": 0})
        rc, rep, _ = self.live(base=b)
        self.assertEqual(rc, 0, rep)
        self.assertTrue(rep["complete"])
        self.assertEqual(len(self.cap.bodies), 16)                     # every scoring call went out (2 extract, 2 dedup, 12 pairs)
        rows = [json.loads(x) for x in (self.state / "runtime-ledger.jsonl").read_text().splitlines() if x.strip()]
        intents = [r for r in rows if r.get("type") == "intent" and r.get("category") == "scoring"]
        self.assertEqual(len(intents), 16)                             # each admitted by the ledger the CLI opened (cap = the $150 total)
        after = RuntimeLedger(self.state / "runtime-ledger.jsonl", TRIAL_TOTAL_USD_MICROS).totals()
        self.assertGreaterEqual(after["committedUsdMicros"], REVIEW_SPEND)


if __name__ == "__main__":
    import unittest
    unittest.main()
