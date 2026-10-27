"""SCORE-HOST-11 TTL boundary on actual evidence content (proof and evidence times agree; only the span varies)."""
from tests.score_operator_review.test_host08_gate import CanaryTime


class Ttl(CanaryTime):
    def span(self, expires):
        rc, rep, _ = self.live(base=self._with_canary_times("2026-10-27T15:00:00Z", expires))
        return rc, rep.get("reason")

    def test_exact_24h_admitted(self):
        self.assertEqual(self.span("2026-10-28T15:00:00Z")[0], 0)

    def test_tighter_than_24h_admitted(self):
        self.assertEqual(self.span("2026-10-27T20:00:00Z")[0], 0)

    def test_24h_plus_one_second_and_30_days_refused_with_fixed_code(self):
        self.assertEqual(self.span("2026-10-28T15:00:01Z"), (2, "canary-ttl"))

    def test_30_days_refused_with_fixed_code(self):
        self.assertEqual(self.span("2026-11-26T15:00:00Z"), (2, "canary-ttl"))

    def test_reversed_window_refused(self):
        self.assertEqual(self.span("2026-10-27T14:00:00Z")[0], 2)
