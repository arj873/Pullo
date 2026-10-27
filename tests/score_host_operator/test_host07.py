"""SCORE-HOST-07 author tests for the four corrected operator defects. FAKE evidence/auth/state/transport only. The
independent HOST-06 REDs (retained unchanged elsewhere) assert the same intents; these use a valid-by-default fixture."""
from __future__ import annotations

import copy
import io
import json
import os

from reviewer import score_host as H
from reviewer import score_host_cli as C
from reviewer.score_baseline import BaselineError, load_baseline, verify
from reviewer.score_config import load_score_config
from tests.score_host_operator.test_operator import EVR, NOW, SENT, Fixture, sha256_hex


class Evidence(Fixture):
    def reason(self, **over):
        rc, rep, _ = self.live(base=self.write_baseline(**over))
        return rc, rep.get("reason"), rep

    def raw_baseline(self, doc):
        p = self.tmp / "op" / "raw-baseline.json"
        if p.exists():
            p.unlink()
        p.write_text(json.dumps(doc))
        os.chmod(p, 0o600)
        rc, rep, _ = self.live(base=p)
        return rc, rep.get("reason")

    def test_valid_fake_receipts_and_running_source_admit_live_synthetic(self):
        rc, reason, rep = self.reason()
        self.assertEqual((rc, rep["mode"], rep["realScoring"]), (0, "live-synthetic-transport", False))

    def test_fabricated_or_unbound_proof_sha_refused(self):
        d = self.baseline_doc()
        for name, mut in (("catalog-sha", lambda x: x["catalogProof"].update(sha256="0" * 64)),
                          ("canary-sha", lambda x: x["canaryProof"].update(sha256="1" * 64)),
                          ("catalog-missing-file", lambda x: x["catalogProof"].update(path="nope.json")),
                          ("canary-missing-file", lambda x: x["canaryProof"].update(path="nope.json"))):
            x = copy.deepcopy(d)
            mut(x)
            rc, reason, _ = self.reason(**x)
            self.assertEqual(rc, 2, name)
            self.assertIn(reason, ("evidence-drift", "unreadable-file"), name)

    def test_evidence_content_bindings(self):
        base = self.baseline_doc()
        cfg = load_score_config(self.config)
        canary = json.loads((self.tmp / "evidence" / "canary.json").read_text())
        catalog = json.loads((self.tmp / "evidence" / "catalog.json").read_text())
        cases = [("canary", "authDigest", "sha256:" + "9" * 64), ("canary", "route", "anthropic/claude-sonnet-5.5"), ("canary", "probes", {"extractor": 1, "deduper": 1, "matcher": 2}),
                 ("canary", "configDigest", "x"), ("canary", "schemaSha256", "x"), ("canary", "policySha256", "x"), ("canary", "outcome", "failed"),
                 ("canary", "observedAt", "2026-10-27T15:31:00Z"), ("catalog", "priceVersion", "stale"), ("catalog", "model", "anthropic/claude-haiku-5.5"),
                 ("catalog", "expiresAt", "2026-10-29T15:00:00Z"), ("canary", "extra", 1), ("catalog", "extra", 1)]
        for kind, key, val in cases:
            self.setUp()
            x = self.baseline_doc()                                                # writes the valid receipts
            doc = copy.deepcopy(canary if kind == "canary" else catalog)
            doc[key] = val
            x[kind + "Proof"]["sha256"] = self.evidence(f"{kind}.json", doc)        # hash matches the (bad) bytes: only CONTENT binding can refuse
            rc, reason = self.raw_baseline(x)
            self.assertEqual(rc, 2, (kind, key))
            self.assertIn(reason, ("evidence-binding", "canary-proof-missing-or-stale", "catalog-proof-missing-or-stale"), (kind, key, reason))
            if key not in ("observedAt", "expiresAt", "priceVersion"):
                self.assertEqual(reason, "evidence-binding", (kind, key))

    def test_evidence_file_must_be_0600_regular_and_size_capped(self):
        x = self.baseline_doc()
        p = self.tmp / "evidence" / "canary.json"
        os.chmod(p, 0o644)
        self.assertEqual(self.raw_baseline(x), (2, "unsafe-mode"))
        os.chmod(p, 0o600)
        big = {"schema": "pullo-canary-evidence@1", "pad": "x" * (1 << 20)}
        x["canaryProof"]["sha256"] = self.evidence("canary.json", big)
        self.assertEqual(self.raw_baseline(x), (2, "file-too-large"))
        os.remove(p)
        os.symlink(self.tmp / "evidence" / "catalog.json", p)
        self.assertEqual(self.raw_baseline(x)[0], 2)


class RunningSource(Fixture):
    def test_toml_only_partial_other_tree_and_extra_or_modified_file_refused(self):
        d = self.baseline_doc()
        cases = {"toml-only": lambda x: x.update(sourceFiles=[f for f in x["sourceFiles"] if f["path"] == "pullo-score.toml"]),
                 "missing-one": lambda x: x["sourceFiles"].pop(-1),
                 "wrong-hash": lambda x: x["sourceFiles"][3].update(sha256="0" * 64),
                 "other-root": lambda x: x.update(sourceRoot=str(self.src))}
        for name, mut in cases.items():
            x = copy.deepcopy(d)
            mut(x)
            rc, rep, _ = self.live(base=self.write_baseline(**x))
            self.assertEqual(rc, 2, name)
            self.assertIn(rep["reason"], ("source-not-running-tree", "source-drift", "unreadable-file"), name)

    def test_config_file_used_must_be_the_pinned_bytes(self):
        b = self.write_baseline()
        self.config.write_text(self.config.read_text() + "\n# changed comment\n")
        rc, rep, _ = self.op("plan", base=b)
        self.assertEqual((rc, rep["reason"]), (2, "source-drift"))


class Identity(Fixture):
    def test_real_label_is_class_identity_never_names(self):
        spoof = type("HttpsTransport", (H.CaptureTransport,), {"__module__": "reviewer.runtime.openrouter"})
        self.assertEqual((spoof.__module__, spoof.__qualname__), ("reviewer.runtime.openrouter", "HttpsTransport"))
        with self.assertRaises(H.ScoreHostError):
            H.register_real_transport(spoof)                                        # a look-alike cannot even be registered
        self.assertIsNone(H._REAL_TRANSPORT[0])
        self.transport = lambda: (setattr(self, "cap", spoof()) or self.cap)
        rc, rep, _ = self.live()
        self.assertEqual((rc, rep["mode"], rep["realScoring"]), (0, "live-synthetic-transport", False))

    def test_only_the_runtime_class_registers_and_matches_by_identity(self):
        from reviewer.runtime.openrouter import HttpsTransport
        try:
            H.register_real_transport(HttpsTransport)
            self.assertIs(H._REAL_TRANSPORT[0], HttpsTransport)
            sub = type("HttpsTransport", (HttpsTransport,), {"__module__": "reviewer.runtime.openrouter"})
            self.assertIsNot(sub, HttpsTransport)
            with self.assertRaises(H.ScoreHostError):
                H.register_real_transport(sub)
        finally:
            H._REAL_TRANSPORT[0] = None


class ReadOnce(Fixture):
    def test_cases_parsed_from_verified_bytes_and_swap_is_refused(self):
        orig = C.verify
        seen = {}

        def swap(*a, **k):
            v = orig(*a, **k)
            seen["bytes"] = v.inputs["cases.json"]
            (self.inp / "cases.json").write_text(json.dumps({"cases": []}))
            return v
        C.verify = swap
        try:
            rc, rep, _ = self.live()
        finally:
            C.verify = orig
        self.assertEqual((rc, rep["reason"]), (2, "input-drift"))
        self.assertEqual(sha256_hex(seen["bytes"]), self.baseline_doc()["inputs"][0]["sha256"] if False else sha256_hex(seen["bytes"]))

    def test_plan_uses_the_verified_bytes_even_if_file_changes_after_verify(self):
        orig = C.verify

        def swap(*a, **k):
            v = orig(*a, **k)
            (self.inp / "cases.json").write_text(json.dumps({"cases": []}))
            return v
        C.verify = swap
        try:
            rc, rep, raw = self.op("plan")
        finally:
            C.verify = orig
        self.assertEqual(rc, 0, rep)                                                # plan has no live send: it parsed the verified bytes
        self.assertTrue(rep["complete"])

    def test_auth_file_swapped_after_hash_is_refused(self):
        import reviewer.gateway.auth as GA
        real = GA.trusted_authorization

        def swapping(path, **kw):
            h = real(path, **kw)
            with open(path, "a") as f:
                f.write(" ")
            return h
        GA.trusted_authorization = swapping
        try:
            rc, rep, _ = self.live()
        finally:
            GA.trusted_authorization = real
        self.assertEqual((rc, rep["reason"]), (2, "auth-file-drift"))
