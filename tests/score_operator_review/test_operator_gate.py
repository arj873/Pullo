"""SCORE-HOST-06 independent operator source gate. Fake inputs/auth/state/transport only; no real key/network/provider.
Tests named red_* encode REQUIRED behaviour that the candidate does not meet (retained RED, not xfail)."""
from __future__ import annotations

import json
import os
import socket
import stat
import sys
import unittest
from pathlib import Path

from reviewer import score_host as H
from reviewer import score_host_cli as C
from reviewer.score_baseline import sha256_hex
from tests.score_host_operator.test_operator import EVR, SENT, Fixture, NOW


class Positive(Fixture):
    def test_plan_denies_socket_and_key_and_leaves_state(self):
        os.remove(self.env)
        real = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network"))
        try:
            rc, rep, raw = self.op("plan")
        finally:
            socket.socket = real
        self.assertEqual((rc, rep["synthetic"], rep["realScoring"]), (0, True, False))
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertNotIn(SENT, raw)

    def test_documents_store_is_0600_and_cli_modules_never_import_review_pipeline_or_tools(self):
        self.op("plan")
        for p in (self.tmp / "out").iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        for m in ("reviewer.pipeline", "reviewer.tools"):
            self.assertNotIn(m, sys.modules)

    def test_budget_constants_pinned(self):
        from reviewer.runtime.scoring_budget import SCORING_AGGREGATE_CEILING_MAX, SCORING_CATEGORY_CAP_MAX
        self.assertEqual((H.PER_RUN_MAX, SCORING_CATEGORY_CAP_MAX, SCORING_AGGREGATE_CEILING_MAX), (4_000_000, 8_000_000, 20_000_000))

    def test_competitor_title_and_blank_pullo_title_refused(self):
        from reviewer.score_render import adapt
        with self.assertRaises(ValueError):
            adapt("competitor", "i", "p", 1, "T", "b", "2026-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            adapt("pullo", "i", "p", 1, "  ", "b", "2026-01-01T00:00:00Z")
        self.assertEqual(adapt("competitor", "i", "p", 1, None, " x \n", "t").body, " x \n")


class Red(Fixture):
    def test_red_proof_sha256_is_unverified_fabricated_proofs_admit_live(self):
        # fixture proofs carry sha256 "000..0"/"111..1"; no external evidence file exists or is consulted.
        # SETUP (HOST06 fixture migration): forge proof hashes bound to no evidence content; bytes of the evidence files are not those hashed.
        doc = self.baseline_doc()
        forged = self.write_baseline(catalogProof={**doc["catalogProof"], "sha256": "0" * 64},
                                     canaryProof={**doc["canaryProof"], "sha256": "1" * 64})
        rc, rep, _ = self.live(base=forged)
        self.assertEqual(rc, 2, "live admitted on proofs whose sha256 is bound to no evidence")

    def test_red_source_code_not_bound_baseline_lists_only_the_toml(self):
        # sourceRoot is an unrelated dir holding only the config; running reviewer/* modules are never hashed.
        # SETUP (HOST06 fixture migration): explicitly construct the config-only, unrelated-sourceRoot baseline.
        cfg_only = [{"path": "pullo-score.toml", "sha256": sha256_hex(self.config.read_bytes())}]
        bad = self.write_baseline(sourceRoot=str(self.src), sourceFiles=cfg_only)
        doc = json.loads(bad.read_text())
        self.assertEqual([f["path"] for f in doc["sourceFiles"]], ["pullo-score.toml"])
        rc, rep, _ = self.live(base=bad)
        self.assertEqual(rc, 2, "live admitted although no running reviewer/*.py is bound by the baseline")

    def test_red_module_name_spoof_labels_synthetic_transport_real(self):
        spoof = type("HttpsTransport", (H.CaptureTransport,), {"__module__": "reviewer.runtime.openrouter"})
        self.transport = lambda: (setattr(self, "cap", spoof()) or self.cap)
        rc, rep, _ = self.live()
        self.assertEqual(rc, 0, rep)
        self.assertFalse(rep["realScoring"], "spoofed class counted as real scoring")
        self.assertNotEqual(rep["mode"], "live")

    def test_red_inputs_hash_checked_then_reread_toctou(self):
        orig, evil = C.verify, json.dumps(__import__("tests.score_host_operator.test_operator", fromlist=["x"]).cases_doc(("zeta-tool", "alpha-tool")))
        evil = evil.replace("gold 1", "TAMPERED gold 1")
        def swap(*a, **k):
            v = orig(*a, **k)
            (self.inp / "cases.json").write_text(evil)
            return v
        C.verify = swap
        try:
            rc, rep, _ = self.live()
        finally:
            C.verify = orig
        self.assertEqual(rc, 2, "cases.json content used differs from the hash-verified bytes")


if __name__ == "__main__":
    unittest.main()
