"""SCORE-HOST-02 retained reproductions of OPEN findings (expected RED on the candidate; no xfail, do not weaken)."""
import unittest

from tests.score_host_review.common import EVR, EVR2, S, URL, Env


class Open(Env):
    def test_H1_execute_offline_must_refuse_a_non_capture_transport(self):
        """`execute_offline` injects ANY callable transport and ANY Secret into the real provider; only the method NAME keeps it offline.
        A real HttpsTransport + real key passed here would go live. Offline entry must refuse a transport that is not the fake capture class."""
        sent = []

        def real_like(req):                                   # stands in for an HttpsTransport that would reach the network
            sent.append(req)
            return S.CaptureTransport()(req)
        h = self.host(transport=real_like)
        with self.assertRaises(S.ScoreHostError):
            h.execute_offline()
        self.assertEqual(sent, [], "an arbitrary (potentially live) transport was used by the 'offline' entry")

    def test_H2_replay_must_recheck_declared_set_and_config_pins(self):
        """replay() never runs _check_pins: a baseline whose declared set drifted gets a (partial) report instead of a fixed refusal."""
        h = self.host()
        h.execute_offline()
        from reviewer.gateway.trace import bytes_digest
        trace = self.store / f"{h.run_id}.trace.jsonl"
        pin = bytes_digest(trace.read_bytes())
        drift = self.host(declared=[(URL, "zeta-tool")])
        with self.assertRaises(S.ScoreHostError) as c:
            drift.replay(trace, pin, EVR2)
        self.assertEqual(c.exception.reason, "declared-set-drift")


if __name__ == "__main__":
    unittest.main()
