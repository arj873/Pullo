"""SCORE-HOST-05 operator entry: fake inputs/auth/state/transport only. No real data, key, network or provider."""

from __future__ import annotations

import fcntl
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from reviewer import score_host as H
from reviewer import score_host_cli as C
from reviewer.gateway import trusted_authorization
from reviewer.runtime.catalog import PRICE_VERSION
from reviewer.score_baseline import BaselineError, load_baseline, read_regular, sha256_hex
from reviewer.score_config import load_score_config
from reviewer.score_render import adapt, render_pullo
from tests.score_gateway import helpers as GH

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-10-27T16:00:00Z"
SENT = "RAWSENTINEL_77aa"
URL = "https://example.invalid/case/1"
FAKE_LIVE_KEY = "sk-or-v1-" + "a1b2" * 12
EVR = "evr_3333333333333333"
EVR2 = "evr_4444444444444444"


def cases_doc(tools=("zeta-tool", "alpha-tool")):
    revs = []
    for t in tools:
        com = [{"id": f"REALCID-{t}-{n}", "path": f"src/p{n}.py", "line": n, "origin": "pullo" if t == "zeta-tool" else "competitor",
                "title": f"Title {n}" if t == "zeta-tool" else None,
                "body": f"  Invented body long enough to extract, item {n} {SENT}  \n" if t != "zeta-tool" else f"Body of item {n} is long enough to extract {SENT}",
                "ts": "2026-01-01T00:00:00Z"} for n in (1, 2, 3)]
        revs.append({"tool": t, "comments": com})
    return {"cases": [{"url": URL, "repo": "r/r", "golden": [{"id": f"REALGOLD-{n}", "comment": f"gold {n} {SENT}", "severity": "high", "category": "bug"}
                                                              for n in (1, 2)], "reviews": revs}]}


class Fixture(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        for d in ("src", "inputs", "state", "out", "op", "evidence"):
            (self.tmp / d).mkdir()
        self.src, self.inp, self.state = self.tmp / "src", self.tmp / "inputs", self.tmp / "state"
        (self.src / "pullo-score.toml").write_text((ROOT / "pullo-score.toml").read_text())
        self.config = self.src / "pullo-score.toml"
        self.write_inputs(cases_doc())
        self.auth_path = self.tmp / "op/auth.json"
        self.auth_doc = {**GH.AUTH_DOC, "id": "fake", "maxUsdMicrosPerRun": 4_000_000, "maxUsdMicrosTotal": 50_000_000}
        self.auth_path.write_text(json.dumps(self.auth_doc))
        os.chmod(self.auth_path, 0o600)
        self.env = self.tmp / "op/.env"
        self.env.write_text(f"openrouter_key={FAKE_LIVE_KEY}\n")
        os.chmod(self.env, 0o600)
        self.handle = trusted_authorization(self.auth_path)
        self.calls = {"key": 0, "transport": 0}

    def write_inputs(self, doc):
        (self.inp / "cases.json").write_text(json.dumps(doc))

    def running_source(self):
        """HOST-07 fixture migration: the baseline must bind EVERY file of the running reviewer package (module origins)."""
        import hashlib
        pkg = ROOT / "reviewer"
        return [{"path": "reviewer/" + p.relative_to(pkg).as_posix(), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in sorted(pkg.rglob("*")) if p.is_file() and "__pycache__" not in p.parts]

    def evidence(self, name, doc):
        """Valid FAKE receipt file (0600) whose bytes the proof's sha256 binds; real evidence is root's later."""
        p = self.tmp / "evidence" / name
        if p.exists():
            p.unlink()
        p.write_text(json.dumps(doc))
        os.chmod(p, 0o600)
        return sha256_hex(p.read_bytes())

    def baseline_doc(self, **over):
        cfg = load_score_config(self.config)
        from reviewer import score_render
        cat_sha = self.evidence("catalog.json", {"schema": "pullo-catalog-evidence@1", "priceVersion": PRICE_VERSION, "model": "anthropic/claude-opus-5.5",
                                                 "provider": "anthropic", "observedAt": "2026-10-27T15:00:00Z", "expiresAt": "2026-10-28T15:00:00Z"})
        can_sha = self.evidence("canary.json", {"schema": "pullo-canary-evidence@1", "roles": ["extractor", "deduper", "matcher"],
                                                "route": "anthropic/claude-opus-5.5", "authDigest": self.handle.digest, "observedAt": "2026-10-27T15:30:00Z",
                                                "expiresAt": "2026-10-28T15:30:00Z", "probes": {"extractor": 1, "deduper": 1, "matcher": 1},
                                                "configDigest": cfg.digest, "promptSha256": dict(cfg.prompt_sha256), "schemaSha256": H.schema_sha256(),
                                                "policySha256": H.policy_digest(), "outcome": "ok"})
        d = {"schema": "pullo-score-launch-baseline@1", "mode": "campaign", "declared": [[URL, "zeta-tool"], [URL, "alpha-tool"]],
             "scoreConfig": {"path": "pullo-score.toml", "sha256": sha256_hex((ROOT / "pullo-score.toml").read_bytes()), "digest": cfg.digest},
             "promptSha256": dict(cfg.prompt_sha256), "schemaSha256": H.schema_sha256(), "policySha256": H.policy_digest(),
             "rendererSha256": sha256_hex(Path(score_render.__file__).read_bytes()), "sourceRoot": str(ROOT),
             "sourceFiles": [{"path": "pullo-score.toml", "sha256": sha256_hex((ROOT / "pullo-score.toml").read_bytes())}] + self.running_source(),
             "inputRoot": str(self.inp), "inputs": [{"path": "cases.json", "sha256": sha256_hex((self.inp / "cases.json").read_bytes())}],
             "stateDir": str(self.state),
             "auth": {"path": str(self.auth_path), "sha256": sha256_hex(self.auth_path.read_bytes()), "digest": self.handle.digest,
                      "expiresAt": self.auth_doc["expiresAt"]},
             "initial": {"scoring": 0, "all": 0, "bookCommitted": 0, "bookInflight": 0},
             "catalogProof": {"priceVersion": PRICE_VERSION, "sha256": cat_sha, "observedAt": "2026-10-27T15:00:00Z", "expiresAt": "2026-10-28T15:00:00Z", "path": "catalog.json"},
             "canaryProof": {"roles": ["extractor", "deduper", "matcher"], "sha256": can_sha, "path": "canary.json", "observedAt": "2026-10-27T15:30:00Z",
                             "expiresAt": "2026-10-28T15:30:00Z", "authDigest": self.handle.digest, "route": "anthropic/claude-opus-5.5"},
             "tracePins": [], "liveAuthorized": True, "envFile": str(self.env), "evidenceRoot": str(self.tmp / "evidence")}
        d.update(over)
        return d

    def write_baseline(self, _name="baseline.json", **over):
        p = self.tmp / "op" / _name
        if p.exists():
            p.unlink()
        p.write_text(json.dumps(self.baseline_doc(**over)))
        os.chmod(p, 0o600)
        return p

    def key_loader(self, path, **kw):
        self.calls["key"] += 1
        from reviewer.runtime.envfile import load_openrouter_key
        return load_openrouter_key(path, **kw)

    def transport(self):
        self.calls["transport"] += 1
        self.cap = H.CaptureTransport()
        return self.cap

    def op(self, cmd, *extra, base=None, store="out", now=NOW, **kw):
        out = io.StringIO()
        b = base or self.write_baseline()
        args = [cmd, "--config", str(self.config), "--baseline", str(b), "--store", str(self.tmp / store), *extra]
        rc = C.main(args, out=out, now=now, _transport_factory=self.transport, _key_loader=self.key_loader, **kw)
        return rc, json.loads(out.getvalue().strip().splitlines()[-1]), out.getvalue()

    def live(self, *extra, **kw):
        return self.op("live", "--confirm-live", "--eval-run-id", EVR, *extra, **kw)


class Plan(Fixture):
    def test_plan_is_synthetic_touches_no_original_state_or_key_and_renders_once(self):
        os.remove(self.env)                                            # plan must not need or read the key file
        rc, rep, raw = self.op("plan")
        self.assertEqual(rc, 0, rep)
        self.assertTrue(rep["complete"] and rep["synthetic"] and rep["plan"])
        self.assertFalse(rep["realScoring"])
        self.assertEqual(list(self.state.iterdir()), [])               # original state dir untouched (no ledger, book or lock)
        self.assertNotIn(SENT, raw)
        self.assertEqual(rep["fitTotals"]["kind"], "worst-case reservation, not a bill")
        docs = next((self.tmp / "out").glob("*.documents.json"))
        self.assertEqual(stat.S_IMODE(docs.stat().st_mode), 0o600)
        txt = docs.read_text()
        self.assertIn("Title 1\\n\\nBody of item 1", txt)              # Pullo title + blank + body, rendered once
        self.assertIn("  Invented body long enough to extract, item 1", txt)   # competitor whitespace preserved

    def test_plan_refuses_drift_before_anything(self):
        for name, mut in (("source", lambda: self.config.write_text(self.config.read_text() + "\n# x")),
                          ("input", lambda: self.write_inputs(cases_doc(("zeta-tool", "alpha-tool", "x"))))):
            self.setUp()
            b = self.write_baseline()
            mut()
            rc, rep, _ = self.op("plan", base=b)
            self.assertEqual((rc, rep["ok"]), (2, False), name)
            self.assertIn(rep["reason"], ("source-drift", "input-drift"))
            self.assertEqual(list((self.tmp / "out").iterdir()), [])

    def test_symlink_and_nonregular_inputs_are_refused(self):
        real = self.inp / "real.json"
        real.write_text(json.dumps(cases_doc()))
        (self.inp / "cases.json").unlink()
        os.symlink(real, self.inp / "cases.json")
        with self.assertRaises(BaselineError):
            read_regular("cases.json", root=self.inp)
        rc, rep, _ = self.op("plan", base=self.write_baseline())
        self.assertEqual((rc, rep["ok"]), (2, False))
        with self.assertRaises(BaselineError):
            read_regular(self.tmp, root=None)                          # a directory is not a regular file


class Live(Fixture):
    def test_guarded_live_path_with_fake_transport_is_labelled_synthetic_never_real(self):
        rc, rep, raw = self.live()
        self.assertEqual(rc, 0, rep)
        self.assertTrue(rep["complete"])
        self.assertEqual((rep["mode"], rep["realScoring"]), ("live-synthetic-transport", False))
        self.assertEqual(self.calls, {"key": 1, "transport": 1})
        self.assertTrue((self.state / "scorer.lock").exists())         # canonical lock lives in the ORIGINAL state dir
        self.assertTrue((self.state / "runtime-ledger.jsonl").exists())
        names = [b["response_format"]["json_schema"]["name"] for b in self.cap.bodies]
        self.assertEqual(names, ["ScoreExtraction"] * 2 + ["ScoreDedup"] * 2 + ["ScorePair"] * 12)
        wire = json.dumps(self.cap.bodies)
        for leak in ("REALGOLD", "REALCID", "zeta-tool", "alpha-tool", "src/p1.py", "example.invalid"):
            self.assertNotIn(leak, wire)
        self.assertNotIn(SENT, raw)
        self.assertEqual(rep["fitTotals"]["pairs"], 12)

    def refused(self, reason, *extra, base=None, **kw):
        rc, rep, _ = self.live(*extra, base=base, **kw)
        self.assertEqual((rc, rep["reason"]), (2, reason))
        self.assertEqual(self.calls, {"key": 0, "transport": 0}, "key/transport touched before refusal")
        self.assertEqual(list(self.state.iterdir()), [])                # no ledger, book or lock created
        self.assertEqual(list((self.tmp / "out").iterdir()), [])

    def test_missing_confirm_and_unauthorized_baseline_refuse_before_key(self):
        rc, rep, _ = self.op("live", "--eval-run-id", EVR)
        self.assertEqual((rc, rep["reason"]), (2, "live-needs-confirm"))
        self.assertEqual(self.calls, {"key": 0, "transport": 0})
        self.refused("live-not-authorized", base=self.write_baseline(liveAuthorized=False))

    def test_stale_or_missing_catalog_and_canary_proofs_refuse_before_key(self):
        self.refused("catalog-proof-missing-or-stale", base=self.write_baseline(catalogProof={**self.baseline_doc()["catalogProof"], "priceVersion": "old"}))
        self.refused("catalog-proof-missing-or-stale", base=self.write_baseline(catalogProof={**self.baseline_doc()["catalogProof"], "expiresAt": "2026-10-27T15:59:59Z"}))
        self.refused("canary-proof-missing-or-stale", base=self.write_baseline(canaryProof=None))
        self.refused("canary-proof-missing-or-stale", base=self.write_baseline(canaryProof={**self.baseline_doc()["canaryProof"], "roles": ["extractor"]}))
        self.refused("canary-proof-missing-or-stale", base=self.write_baseline(canaryProof={**self.baseline_doc()["canaryProof"], "authDigest": "sha256:" + "0" * 64}))
        self.refused("canary-proof-missing-or-stale", base=self.write_baseline(canaryProof={**self.baseline_doc()["canaryProof"], "route": "anthropic/claude-sonnet-5.5"}))

    def test_auth_expiry_and_digest_drift_refuse(self):
        self.refused("auth-drift", base=self.write_baseline(auth={**self.baseline_doc()["auth"], "digest": "sha256:" + "0" * 64}))
        self.refused("auth-expired", now="2099-06-01T00:00:00Z", base=self.write_baseline(catalogProof={**self.baseline_doc()["catalogProof"], "expiresAt": "2100-01-01T00:00:00Z", "observedAt": "2026-01-01T00:00:00Z"},
                                                                                         canaryProof={**self.baseline_doc()["canaryProof"], "expiresAt": "2100-01-01T00:00:00Z", "observedAt": "2026-01-01T00:00:00Z"},
                                                                                         auth={**self.baseline_doc()["auth"], "expiresAt": "2099-01-01T00:00:00Z"}))

    def test_source_input_config_and_declared_set_drift_refuse(self):
        b = self.write_baseline(sourceFiles=[{"path": "pullo-score.toml", "sha256": "0" * 64}])
        self.refused("source-drift", base=b)
        self.refused("input-drift", base=self.write_baseline(inputs=[{"path": "cases.json", "sha256": "0" * 64}]))
        self.refused("pin-drift", base=self.write_baseline(rendererSha256="0" * 64))
        self.refused("prompt-drift", base=self.write_baseline(promptSha256={"extract": "0" * 64}))
        self.refused("declared-case-missing", base=self.write_baseline(declared=[["https://example.invalid/other", "zeta-tool"]]))

    def test_state_drift_refuses_after_key_but_before_any_send(self):
        from reviewer.gateway import SpendBook
        self.state.mkdir(exist_ok=True)
        bk = SpendBook(self.handle, self.state / "spend-book.jsonl")
        bk.reserve("prior", 1)
        bk.settle("prior", 1000)                                       # book committed 1000, baseline pins 0
        rc, rep, _ = self.live()
        self.assertEqual((rc, rep["reason"]), (2, "book-state-drift"))
        self.assertEqual(self.cap.bodies if hasattr(self, "cap") else [], [])

    def test_canonical_lock_is_shared_across_output_dirs(self):
        self.state.mkdir(exist_ok=True)
        fd = os.open(self.state / "scorer.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        for store in ("out", "out2"):
            rc, rep, _ = self.live(store=store)
            self.assertEqual((rc, rep["reason"]), (2, "scorer-lock-held"))
        self.assertFalse(hasattr(self, "cap") and self.cap.bodies)

    def test_host_level_guards_a_hand_built_verified_or_placeholder_key_cannot_go_live(self):
        from reviewer.score_baseline import Verified
        rc, rep, _ = self.live()
        self.assertEqual(rc, 0)
        h = H.ScoreHost.__new__(H.ScoreHost)
        h.baseline_file_sha256 = "x"
        h.lock_path = Path("l")
        for v in (None, Verified("x", "campaign", True, "0" * 64)):
            with self.assertRaises(H.ScoreHostError) as cm:
                h.execute_live(transport=lambda r: None, key=None, verified=v, confirm=True)
            self.assertEqual(cm.exception.reason, "live-not-authorized")

    def test_canary_probes_exactly_three_roles_inside_same_caps_and_needs_no_canary_proof(self):
        b = self.write_baseline(mode="canary", declared=[list(x) for x in H.CANARY_DECLARED], canaryProof=None, inputs=[{"path": "cases.json", "sha256": sha256_hex((self.inp / "cases.json").read_bytes())}])
        rc, rep, _ = self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=b)
        self.assertEqual(rc, 0, rep)
        names = [x["response_format"]["json_schema"]["name"] for x in self.cap.bodies]
        self.assertEqual(sorted(set(names)), ["ScoreDedup", "ScoreExtraction", "ScorePair"])
        self.assertEqual(rep["realScoring"], False)
        # a campaign baseline cannot run canary mode and vice versa; a non-preregistered set is refused
        rc, rep, _ = self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=self.write_baseline())
        self.assertEqual((rc, rep["reason"]), (2, "mode-mismatch"))
        rc, rep, _ = self.op("canary", "--confirm-live", "--eval-run-id", EVR, base=self.write_baseline(mode="canary"))
        self.assertEqual((rc, rep["reason"]), (2, "canary-set-not-preregistered"))


class Replay(Fixture):
    def test_replay_needs_pinned_trace_fresh_id_and_touches_no_key_auth_or_state(self):
        rc, rep, _ = self.live()
        self.assertEqual(rc, 0)
        trace = next((self.tmp / "out").glob("*.trace.jsonl"))
        pin = "sha256:" + sha256_hex(trace.read_bytes())
        self.calls.update(key=0, transport=0)
        before = {p.name: p.read_bytes() for p in self.state.iterdir()}
        b = self.write_baseline(tracePins=[pin])
        empty = self.write_baseline("empty.json", tracePins=[])
        b = self.write_baseline(tracePins=[pin])
        os.remove(self.auth_path)                                     # replay must not read authorization
        os.remove(self.env)
        rc, rep, raw = self.op("replay", "--trace", str(trace), "--eval-run-id", EVR2, base=b, store="out2")
        self.assertEqual(rc, 0, rep)
        self.assertEqual((rep["liveCalls"], rep["complete"], rep["replay"]), (0, True, True))
        self.assertEqual(self.calls, {"key": 0, "transport": 0})
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.state.iterdir()})
        self.assertNotIn(SENT, raw)
        rc, rep, _ = self.op("replay", "--trace", str(trace), "--eval-run-id", EVR2, base=empty, store="out3")
        self.assertEqual((rc, rep["reason"]), (2, "trace-pin-not-in-baseline"))
        rc, rep, _ = self.op("replay", "--trace", str(trace), "--eval-run-id", "evr_1111111111111111", base=b, store="out4")
        self.assertEqual(rc, 2)


class Misc(Fixture):
    def test_renderer_and_reconcile_and_imports(self):
        self.assertEqual(render_pullo("T", "B\n"), "T\n\nB\n")
        with self.assertRaises(ValueError):
            render_pullo(" ", "b")
        self.assertEqual(adapt("competitor", "c", "p", 1, None, "  raw \n", "t").body, "  raw \n")
        with self.assertRaises(ValueError):
            adapt("competitor", "c", "p", 1, "title", "b", "t")
        rc, rep, _ = self.op("reconcile", "--evidence", str(self.tmp / "e.json"), base=self.write_baseline()) if False else (None, None, None)
        out = io.StringIO()
        rc = C.main(["reconcile", "--baseline", str(self.write_baseline()), "--evidence", "x"], out=out, now=NOW)
        self.assertNotEqual(rc, 0)                                    # missing ledger: the accepted mechanism refuses, nothing created
        self.assertFalse((self.state / "runtime-ledger.jsonl").exists())
        import subprocess
        import sys
        code = (f"import sys; sys.path.insert(0, {str(ROOT)!r}); import reviewer.score_host_cli;"
                "print([m for m in sys.modules if m.startswith(('reviewer.pipeline','reviewer.tools','reviewer.config','reviewer.pilot','reviewer.scoring','reviewer.evaluation'))])")
        o = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True)
        self.assertEqual(o.stdout.strip(), "[]", o.stderr[-300:])


if __name__ == "__main__":
    unittest.main()
