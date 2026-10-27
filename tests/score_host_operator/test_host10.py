"""SCORE-HOST-10: a canary receipt (proof AND the actual evidence file) may be valid for at most 24h. FAKE files only."""
from __future__ import annotations

import json
import os

from tests.score_host_operator.test_operator import Fixture, sha256_hex


class Ttl(Fixture):
    def with_times(self, observed, expires, *, evidence=True, proof=True):
        base = self.baseline_doc()                                        # writes valid fake receipts, exact-24h by default
        ev = json.loads((self.tmp / "evidence" / "canary.json").read_text())
        if evidence:
            ev["observedAt"], ev["expiresAt"] = observed, expires
        base["canaryProof"]["sha256"] = self.evidence("canary.json", ev)
        if proof:
            base["canaryProof"]["observedAt"], base["canaryProof"]["expiresAt"] = observed, expires
        p = self.tmp / "op" / "ttl-baseline.json"
        if p.exists():
            p.unlink()
        p.write_text(json.dumps(base))
        os.chmod(p, 0o600)
        rc, rep, _ = self.live(base=p)
        return rc, rep.get("reason")

    def test_exact_24h_and_shorter_are_admitted(self):
        for obs, exp in (("2026-10-27T15:30:00Z", "2026-10-28T15:30:00Z"),                  # exactly 24h
                         ("2026-10-27T15:30:00Z", "2026-10-28T15:29:59Z"),                  # 1s short
                         ("2026-10-27T15:30:00Z", "2026-10-27T17:30:00Z")):                 # 2h
            self.setUp()
            self.assertEqual(self.with_times(obs, exp), (0, None), (obs, exp))

    def test_over_limit_is_refused_by_proof_and_by_the_actual_evidence(self):
        for obs, exp in (("2026-10-27T15:30:00Z", "2026-10-28T15:30:00.000001Z"),           # 24h + 1 microsecond
                         ("2026-10-27T15:30:00Z", "2026-10-28T15:30:01Z"),
                         ("2026-10-27T15:30:00Z", "2026-11-26T15:30:00Z")):                  # 30 days
            self.setUp()
            self.assertEqual(self.with_times(obs, exp), (2, "canary-ttl"), (obs, exp))

    def test_actual_evidence_alone_is_checked_even_if_proof_fields_look_fine(self):
        # evidence file carries a 30-day window while the proof fields say 24h: the binding/TTL on the real receipt refuses it
        rc, reason = self.with_times("2026-10-27T15:30:00Z", "2026-11-26T15:30:00Z", proof=False)
        self.assertEqual(rc, 2)
        self.assertIn(reason, ("canary-ttl", "evidence-binding"))

    def test_invalid_order_and_future_start_are_refused(self):
        for obs, exp in (("2026-10-28T15:30:00Z", "2026-10-27T15:30:00Z"),                  # expires before observed
                         ("2026-10-27T15:30:00Z", "2026-10-27T15:30:00Z"),                  # zero-length
                         ("2026-10-28T15:30:00Z", "2026-10-29T15:30:00Z")):                 # observed in the future (now 2026-10-27T16:00Z)
            self.setUp()
            rc, reason = self.with_times(obs, exp)
            self.assertEqual(rc, 2, (obs, exp))
            self.assertIn(reason, ("canary-ttl", "canary-proof-missing-or-stale"))

    def test_other_bindings_still_refuse(self):
        base = self.baseline_doc()
        ev = json.loads((self.tmp / "evidence" / "canary.json").read_text())
        ev["route"] = "anthropic/claude-sonnet-5.5"
        base["canaryProof"]["sha256"] = self.evidence("canary.json", ev)
        p = self.tmp / "op" / "b2.json"
        p.write_text(json.dumps(base))
        os.chmod(p, 0o600)
        rc, rep, _ = self.live(base=p)
        self.assertEqual((rc, rep["reason"]), (2, "evidence-binding"))
