"""Pair cap 256 -> 1024 (profile pullo-score@2): @1-era traces and canary receipts are refused under @2, even with a
tighter 256 config whose config digest equals the @1 one. Offline: invented cases, fake transport, scratch state only."""

from __future__ import annotations

import json
import unittest

from reviewer import score_host as H
from reviewer import score_host_cli as C
from reviewer.gateway.trace import bytes_digest
from reviewer.score_baseline import BaselineError, load_baseline, verify
from reviewer.score_config import parse_score_config
from tests.score_host import test_score_host as SH
from tests.score_host_operator.test_operator import NOW, ROOT, Fixture

# The @1 program's pins (pair cap 256, profile pullo-score@1), computed from 26c6ea17 before the raise.
V1_CONFIG_DIGEST = "sha256:046aac9631a7efda5ef5deebc7cbf15b8821af8400b970bf7e28de17b40de00a"
V1_POLICY_DIGEST = "dab1568e7c10240b28cde8fcd70999d03f9197ad0415cc198e67bdb596e3030a"


def cfg_256():
    text = (ROOT / "pullo-score.toml").read_text()
    return parse_score_config(text.replace("[caps.pair]\nmax_output_tokens = 1024\n", "[caps.pair]\nmax_output_tokens = 256\n"))


class TighterConfigIsTheV1Config(unittest.TestCase):
    def test_256_config_digest_equals_v1_but_policy_differs(self):
        self.assertEqual(cfg_256().digest, V1_CONFIG_DIGEST)       # so config pins alone cannot tell @1 from @2-at-256
        self.assertNotEqual(H.policy_digest(), V1_POLICY_DIGEST)


class V1TraceRefused(SH.Env):
    def record_v1(self, cfg):
        """Simulate the @1 program: same code path, but the recorded profile is pullo-score@1 with the 256 pair cap."""
        h = self.host(cfg=cfg)
        h.profile, h.profile_ref = cfg.profile(SH.PRICE, version=1), "pullo-score@1"
        self.assertTrue(h.execute_offline()["complete"])
        pairs = [b for b in self.transport.bodies if b["response_format"]["json_schema"]["name"] == "ScorePair"]
        self.assertEqual({b["max_tokens"] for b in pairs}, {256})
        trace = self.store / f"{h.run_id}.trace.jsonl"
        return h, trace, bytes_digest(trace.read_bytes())

    def test_v1_trace_refused_by_v2_host_even_with_256_config(self):
        cfg = cfg_256()
        v1, trace, pin = self.record_v1(cfg)
        control = self.host(cfg=cfg)                                   # control: the same trace replays under an @1 host
        control.baseline = v1.baseline
        control.profile, control.profile_ref = cfg.profile(SH.PRICE, version=1), "pullo-score@1"
        self.assertTrue(control.replay(trace, pin, SH.EVR2)["complete"])
        r = self.host(cfg=cfg)                                         # @2 host, same 256 config digest, same baseline
        r.baseline = v1.baseline
        self.assertEqual((r.profile_ref, r.cfg.digest), ("pullo-score@2", V1_CONFIG_DIGEST))
        with self.assertRaises(H.ScoreHostError) as cm:
            r.replay(trace, pin, SH.EVR2)
        self.assertEqual(cm.exception.reason, "replay-trace-refused")   # gateway: recorded profile @1 != @2

    def test_v1_profile_ref_refused_at_construction(self):
        for ref in ("pullo-score@1", "pullo-score@3", "other@2", "pullo-score"):
            with self.subTest(ref=ref), self.assertRaises(H.ScoreHostError) as cm:
                self.host_with_ref(ref)
            self.assertEqual(cm.exception.reason, "profile-ref-mismatch")
        self.assertEqual(self.host_with_ref("pullo-score@2").profile_ref, "pullo-score@2")

    def host_with_ref(self, ref):
        h = self.host()
        return H.ScoreHost(h.cfg, h.baseline, h.units, profile_ref=ref, price=SH.PRICE, auth=h.auth, book=h.book,
                           ledger=h.ledger, key=SH.KEY, transport=h.transport, store_dir=self.store, eval_run_id=SH.EVR)


class V1CanaryReceiptRefused(Fixture):
    def receipt(self, cfg, policy):
        return {"schema": "pullo-canary-evidence@1", "roles": ["extractor", "deduper", "matcher"], "route": "anthropic/claude-opus-5.5",
                "authDigest": self.handle.digest, "observedAt": "2026-10-27T15:30:00Z", "expiresAt": "2026-10-28T15:30:00Z",
                "probes": {"extractor": 1, "deduper": 1, "matcher": 1}, "configDigest": cfg.digest,
                "promptSha256": dict(cfg.prompt_sha256), "schemaSha256": H.schema_sha256(), "policySha256": policy, "outcome": "ok"}

    def verify_with(self, cfg, receipt_policy, **over):
        """Root baseline for a run with `cfg` (scoreConfig.digest = cfg.digest) whose canary receipt carries `receipt_policy`."""
        doc = self.baseline_doc()                                      # writes the fixture receipts; ours replaces canary.json after
        sha = self.evidence("canary.json", self.receipt(cfg, receipt_policy))
        doc.update({"scoreConfig": {**doc["scoreConfig"], "digest": cfg.digest}, "canaryProof": {**doc["canaryProof"], "sha256": sha}, **over})
        b = self.tmp / "op/b.json"
        if b.exists():
            b.unlink()
        b.write_text(json.dumps(doc))
        b.chmod(0o600)
        return verify(load_baseline(b), now=NOW, auth_handle=self.handle, require_proofs=True, **C._pins(cfg))

    def test_control_v2_receipt_at_256_verifies(self):
        self.assertEqual(self.verify_with(cfg_256(), H.policy_digest()).mode, "campaign")

    def test_v1_canary_receipt_refused_even_with_256_config(self):
        cfg = cfg_256()
        self.assertEqual(cfg.digest, V1_CONFIG_DIGEST)
        with self.assertRaises(BaselineError) as cm:                   # @2 baseline + @1 receipt: receipt policy pin differs
            self.verify_with(cfg, V1_POLICY_DIGEST)
        self.assertEqual(cm.exception.reason, "evidence-binding")
        with self.assertRaises(BaselineError) as cm:                   # a whole @1 baseline (policySha256 @1) under @2
            self.verify_with(cfg, V1_POLICY_DIGEST, policySha256=V1_POLICY_DIGEST)
        self.assertEqual(cm.exception.reason, "pin-drift")


if __name__ == "__main__":
    unittest.main()
