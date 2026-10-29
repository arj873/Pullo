"""SCORE-HOST-13 independent gate: BOTH paid commands (live, canary) admit only on the full catalog evidence, the canary needs
no receipt of its own, a campaign still needs one, and plan/replay stay key/auth/state free. FAKE evidence/auth/key/state/transport
only; no actual canary and no actual environment."""
from __future__ import annotations

import json
import os

from reviewer import score_host as H
from tests.score_host_operator.test_operator import EVR, EVR2, NOW, SENT, Fixture, sha256_hex

PAID = ("live", "canary")


class Gate(Fixture):
    def base_for(self, cmd, **over):
        if cmd == "canary":
            over = {"mode": "canary", "declared": [list(x) for x in H.CANARY_DECLARED], "canaryProof": None,
                    "inputs": [{"path": "cases.json", "sha256": sha256_hex((self.inp / "cases.json").read_bytes())}], **over}
        return self.write_baseline(**over)

    def run_paid(self, cmd, base, **kw):
        return self.op(cmd, "--confirm-live", "--eval-run-id", EVR, base=base, **kw)

    def snapshot(self):
        return (sorted(p.name for p in self.state.iterdir()), sorted(p.name for p in (self.tmp / "evidence").iterdir()))

    def denied(self, cmd, base, reason=None, **kw):
        before = self.snapshot()
        rc, rep, raw = self.run_paid(cmd, base, **kw)
        self.assertEqual(rc, 2, (cmd, reason, rep))
        self.assertFalse(rep["ok"], (cmd, rep))
        self.assertEqual(set(rep), {"ok", "reason"})
        if reason is not None:
            self.assertEqual(rep["reason"], reason, cmd)
        self.assertEqual(self.calls, {"key": 0, "transport": 0}, cmd)             # before key loader and transport factory
        self.assertEqual(self.snapshot(), before, cmd)                              # no state/book/ledger/lock, no new receipt
        self.assertEqual(list((self.tmp / "out").iterdir()), [], cmd)               # no output
        self.assertNotIn(SENT, raw)
        self.calls.update(key=0, transport=0)

    def rebind(self, base, mutate, **proof):
        """Rewrite catalog evidence with `mutate(ev)` and re-bind the proof hash so only the CONTENT is wrong."""
        doc = json.loads(base.read_text())
        p = self.tmp / "evidence" / "catalog.json"
        ev = json.loads(p.read_text())
        mutate(ev)
        doc["catalogProof"]["sha256"] = self.evidence("catalog.json", ev)
        doc["catalogProof"].update(proof)
        base.write_text(json.dumps(doc))

    # ---- valid path ---------------------------------------------------------------------------------------------------
    def canary_ok(self, proof):
        base = self.base_for("canary", canaryProof=proof)
        ev_before = sorted(p.name for p in (self.tmp / "evidence").iterdir())
        rc, rep, _ = self.run_paid("canary", base)
        self.assertEqual(rc, 0, rep)
        self.assertEqual([x["response_format"]["json_schema"]["name"] for x in self.cap.bodies], ["ScoreExtractionSegments", "ScoreDedup", "ScorePair"])
        self.assertEqual((rep["canaryOk"], rep["probeCalls"], rep["canary"]), (True, {"extractor": 1, "deduper": 1, "matcher": 1}, True))
        self.assertEqual(self.calls, {"key": 1, "transport": 1})
        self.assertEqual(sorted(p.name for p in (self.tmp / "evidence").iterdir()), ev_before)      # no receipt written

    def test_valid_fake_catalog_canary_exactly_three_probes_without_receipt(self):
        self.canary_ok(None)

    def test_canary_never_reads_a_junk_canary_proof(self):               # nothing circular: the field is ignored in canary mode
        self.canary_ok({"junk": 1})

    def test_canary_never_reads_a_dangling_canary_proof(self):
        self.canary_ok({"roles": [], "sha256": "0" * 64, "path": "nope.json"})

    def test_valid_fake_live_still_admitted(self):
        rc, rep, _ = self.run_paid("live", self.base_for("live"))
        self.assertEqual(rc, 0, rep)
        self.assertEqual(self.calls, {"key": 1, "transport": 1})

    # ---- both paid commands: absent / stale / forged catalog evidence refused before anything ---------------------------
    def test_missing_catalog_proof_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd):
                self.denied(cmd, self.base_for(cmd, catalogProof=None), "catalog-proof-missing-or-stale")

    def test_stale_and_not_yet_valid_catalog_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd, case="expired"):
                self.denied(cmd, self.base_for(cmd), "catalog-proof-missing-or-stale", now="2026-10-28T15:00:00Z")   # == expiresAt
            with self.subTest(cmd=cmd, case="early"):
                self.denied(cmd, self.base_for(cmd), "catalog-proof-missing-or-stale", now="2026-10-27T14:59:59Z")

    def test_stale_price_version_in_proof_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd):
                base = self.base_for(cmd)
                doc = json.loads(base.read_text())
                doc["catalogProof"]["priceVersion"] = "old-price"
                base.write_text(json.dumps(doc))
                self.denied(cmd, base, "catalog-proof-missing-or-stale")

    def test_missing_evidence_file_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd):
                base = self.base_for(cmd)
                os.unlink(self.tmp / "evidence" / "catalog.json")
                self.denied(cmd, base)

    def test_modified_evidence_and_wrong_hash_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd, case="modified"):
                base = self.base_for(cmd)
                p = self.tmp / "evidence" / "catalog.json"
                p.write_text(p.read_text().replace("anthropic", "other", 1))
                self.denied(cmd, base, "evidence-drift")
            with self.subTest(cmd=cmd, case="wrong-sha"):
                base = self.base_for(cmd)
                doc = json.loads(base.read_text())
                doc["catalogProof"]["sha256"] = "f" * 64
                base.write_text(json.dumps(doc))
                self.denied(cmd, base, "evidence-drift")

    def test_hash_consistent_but_forged_or_mismatched_content_refused_for_both(self):
        forged = {
            "route": lambda e: e.update(model="anthropic/claude-haiku-5.5"),
            "provider": lambda e: e.update(provider="openai"),
            "price": lambda e: e.update(priceVersion="old-price"),
            "observed": lambda e: e.update(observedAt="2026-10-27T14:00:00Z"),
            "expires": lambda e: e.update(expiresAt="2026-10-30T15:00:00Z"),
            "extra-key": lambda e: e.update(extra=1),
            "missing-key": lambda e: e.pop("provider"),
        }
        for cmd in PAID:
            for name, mut in forged.items():
                with self.subTest(cmd=cmd, forged=name):
                    base = self.base_for(cmd)
                    self.rebind(base, mut)
                    self.denied(cmd, base, "evidence-binding")

    def test_wrong_schema_and_non_object_evidence_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd, case="schema"):
                base = self.base_for(cmd)
                self.rebind(base, lambda e: e.update(schema="pullo-canary-evidence@1"))      # the other receipt's schema
                self.denied(cmd, base, "evidence-malformed")
            with self.subTest(cmd=cmd, case="not-json"):
                base = self.base_for(cmd)
                doc = json.loads(base.read_text())
                p = self.tmp / "evidence" / "catalog.json"
                p.write_bytes(b"not json")
                doc["catalogProof"]["sha256"] = sha256_hex(b"not json")
                base.write_text(json.dumps(doc))
                self.denied(cmd, base, "evidence-malformed")

    def test_unsafe_evidence_file_refused_for_both(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd, case="mode-0644"):
                base = self.base_for(cmd)
                os.chmod(self.tmp / "evidence" / "catalog.json", 0o644)
                self.denied(cmd, base)
            with self.subTest(cmd=cmd, case="symlink"):
                base = self.base_for(cmd)
                p = self.tmp / "evidence" / "catalog.json"
                real = self.tmp / "evidence" / "real.json"
                p.rename(real)
                p.symlink_to(real)
                self.denied(cmd, base)
                p.unlink()
                real.unlink()
            with self.subTest(cmd=cmd, case="path-escape"):
                base = self.base_for(cmd)
                doc = json.loads(base.read_text())
                outside = self.tmp / "outside.json"
                outside.write_bytes((self.tmp / "evidence" / "catalog.json").read_bytes())
                os.chmod(outside, 0o600)
                doc["catalogProof"]["path"] = "../outside.json"
                base.write_text(json.dumps(doc))
                self.denied(cmd, base)

    # ---- campaign still needs its own receipt; canary evidence is checked only there ----------------------------------------
    def test_campaign_live_still_requires_valid_canary_receipt_before_key(self):
        self.denied("live", self.base_for("live", canaryProof=None), "canary-proof-missing-or-stale")
        base = self.base_for("live")
        doc = json.loads(base.read_text())
        doc["canaryProof"]["sha256"] = "0" * 64
        base.write_text(json.dumps(doc))
        self.denied("live", base, "evidence-drift")

    def test_canary_receipt_cannot_stand_in_for_catalog_evidence(self):
        for cmd in PAID:
            with self.subTest(cmd=cmd):
                base = self.base_for(cmd, catalogProof=None)          # a perfectly valid campaign canaryProof (live) must not help
                self.denied(cmd, base, "catalog-proof-missing-or-stale")

    # ---- plan / replay unchanged ----------------------------------------------------------------------------------------------
    def test_plan_needs_no_catalog_canary_key_or_state(self):
        base = self.write_baseline(catalogProof=None, canaryProof=None, liveAuthorized=False)
        rc, rep, raw = self.op("plan", base=base)
        self.assertEqual((rc, rep.get("plan"), rep.get("realScoring")), (0, True, False))
        self.assertEqual(self.calls, {"key": 0, "transport": 0})
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertNotIn(SENT, raw)

    def test_replay_needs_no_catalog_canary_auth_key_or_state(self):
        rc, rep, _ = self.run_paid("live", self.base_for("live"))
        self.assertEqual(rc, 0, rep)
        trace = next((self.tmp / "out").glob("*.trace.jsonl"))
        pin = "sha256:" + sha256_hex(trace.read_bytes())
        self.calls.update(key=0, transport=0)
        before = {p.name: p.read_bytes() for p in self.state.iterdir()}
        b = self.write_baseline("replay.json", tracePins=[pin], catalogProof=None, canaryProof=None, liveAuthorized=False)
        os.remove(self.auth_path)
        os.remove(self.env)
        rc, rep, raw = self.op("replay", "--trace", str(trace), "--eval-run-id", EVR2, base=b, store="out2")
        self.assertEqual((rc, rep.get("replay"), rep.get("liveCalls")), (0, True, 0), rep)
        self.assertEqual(self.calls, {"key": 0, "transport": 0})
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.state.iterdir()})
        self.assertNotIn(SENT, raw)
