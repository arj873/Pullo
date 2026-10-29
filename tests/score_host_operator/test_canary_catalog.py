"""SCORE-HOST-12: the canary admits only on the full catalog evidence (same check as live), never needing its own receipt.
FAKE evidence/auth/state/key/transport only; no actual canary."""
from __future__ import annotations

import json
import os

from reviewer import score_host as H
from tests.score_host_operator.test_operator import EVR, NOW, Fixture, sha256_hex


class CanaryCatalog(Fixture):
    def canary_base(self, **over):
        return self.write_baseline(mode="canary", declared=[list(x) for x in H.CANARY_DECLARED], canaryProof=None,
                                   inputs=[{"path": "cases.json", "sha256": sha256_hex((self.inp / "cases.json").read_bytes())}], **over)

    def run_canary(self, base):
        return self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=base)

    def assert_denied_early(self, base, reason):
        before = sorted(p.name for p in self.state.iterdir())
        rc, rep, _ = self.run_canary(base)
        self.assertEqual((rc, rep), (2, {"ok": False, "reason": reason}))
        self.assertEqual(self.calls, {"key": 0, "transport": 0})                 # before key loader and transport factory
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), before)    # no ledger/book/lock/state mutation
        self.assertEqual(list((self.tmp / "out").iterdir()), [])                  # no output

    def test_valid_fake_catalog_admits_exactly_three_probes_without_canary_receipt(self):
        rc, rep, _ = self.run_canary(self.canary_base())
        self.assertEqual(rc, 0, rep)
        self.assertEqual([x["response_format"]["json_schema"]["name"] for x in self.cap.bodies], ["ScoreExtractionSegments", "ScoreDedup", "ScorePair"])
        self.assertEqual((rep["canaryOk"], rep["probeCalls"]), (True, {"extractor": 1, "deduper": 1, "matcher": 1}))

    def test_missing_catalog_proof_refused(self):
        self.assert_denied_early(self.canary_base(catalogProof=None), "catalog-proof-missing-or-stale")

    def test_stale_catalog_proof_refused(self):
        rc, rep, _ = self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=self.canary_base(), now="2026-10-29T00:00:00Z")
        self.assertEqual((rc, rep["reason"]), (2, "catalog-proof-missing-or-stale"))
        self.assertEqual(self.calls, {"key": 0, "transport": 0})

    def test_missing_evidence_file_refused(self):
        base = self.canary_base()
        os.unlink(self.tmp / "evidence" / "catalog.json")
        rc, rep, _ = self.run_canary(base)
        self.assertEqual(rc, 2)
        self.assertFalse(rep["ok"])
        self.assertEqual(self.calls, {"key": 0, "transport": 0})
        self.assertEqual(list((self.tmp / "out").iterdir()), [])

    def test_modified_evidence_refused(self):
        base = self.canary_base()
        p = self.tmp / "evidence" / "catalog.json"
        d = json.loads(p.read_text())
        d["provider"] = "other"
        p.write_text(json.dumps(d))
        self.assert_denied_early(base, "evidence-drift")

    def test_wrong_sha_in_proof_refused(self):
        base = self.canary_base()
        doc = json.loads(base.read_text())
        doc["catalogProof"]["sha256"] = "0" * 64
        base.write_text(json.dumps(doc))
        self.assert_denied_early(base, "evidence-drift")

    def test_forged_binding_refused(self):
        base = self.canary_base()
        p = self.tmp / "evidence" / "catalog.json"
        d = json.loads(p.read_text())
        d["model"] = "anthropic/claude-haiku-5.5"
        p.write_text(json.dumps(d))
        doc = json.loads(base.read_text())
        doc["catalogProof"]["sha256"] = sha256_hex(p.read_bytes())               # hash consistent, content forged
        base.write_text(json.dumps(doc))
        self.assert_denied_early(base, "evidence-binding")

    def test_plan_and_replay_do_not_need_catalog_evidence(self):
        base = self.write_baseline(catalogProof=None, canaryProof=None, liveAuthorized=False)
        rc, rep, _ = self.op("plan", base=base)
        self.assertEqual((rc, rep.get("plan")), (0, True))
        self.assertEqual(self.calls, {"key": 0, "transport": 0})
