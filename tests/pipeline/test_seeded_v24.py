"""investigator.impact@v24 (reviewer.pipeline.seeded; root card ccfilter-1): v21's VERIFY -> JUDGE -> PUBLISH on a SEEDED
candidate list. Offline: the v21 rig (test_dual_v21.V21Rig, scripted claude-cli fakes), no network, no credential.
  1. profile / Plan / policy / templates / identity: v21's but the investigator promptVersion, the Plan reason and the seed record;
  2. seeded.load refusals and seeded.drafts (drops, truncation, the host's own head-line citation);
  3. end to end: no INVESTIGATE model call, one seed.input event, the union merge, two agentic verifiers, JUDGE, comments with
     seedRef provenance (never a sourceCallId), review.md disclosure of the candidate mode, strict replay byte-identical, and a
     replay with another seed refused;
  4. provenance negatives (contracts.check_finding_provenance with seedRef);
  5. benchmark options: v24 needs seed_candidates, nothing else takes it, a malformed seed is refused before any run;
  6. V21 parity: v21 recordings byte-identical to the pre-change source 2eff0f8 (tests/pipeline/v21_pins_2eff0f8.json)."""
from __future__ import annotations

import copy
import dataclasses
import io
import json
import runpy
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from reviewer.contracts import check_finding_provenance, validate
from reviewer.contracts.canonical import hypothesis_id
from reviewer.contracts.entities import validate_trace
from reviewer.gateway.trace import load_trace
from reviewer.pilot import benchmark as B
from reviewer.pilot import repository_profile as RP
from reviewer.pipeline import RetrievalPolicy, dual, identity, prompts, seeded
from reviewer.pipeline.engine import Engine

import tests.pilot.test_benchmark_host as TBH
from tests.pipeline import test_dual_v21 as T
from tests.pipeline.helpers import judge, model_calls, script
from tests.pipeline.test_coverage_v12 import ROOT, md_of, payload
from tests.pipeline.test_impact_pipeline import w

INV24 = prompts.INVESTIGATOR_IMPACT_V24_PROMPT
V24_PROFILE = copy.deepcopy(T.V21_PROFILE)
V24_PROFILE["roles"]["investigator"]["promptVersion"] = INV24
V24_POLICY = RetrievalPolicy(investigator_prompt=INV24, verifier_prompt=T.VER, run_tool_calls=400)
V24_PLAN = copy.deepcopy(T.V21_PLAN)
SRC = {"arm": "ccbo", "case": "mini", "model": "claude-cli/claude-opus-5-5", "promptSha256": "a" * 64, "commentsSha256": "b" * 64,
       "settleReceiptSha256": "c" * 64}
LIB = "load_user lost the cache default; Profile.show passes one argument"
SB = "handle_b dropped the active-user and size guards its siblings keep"


def seed_doc(items, mode="reuse"):
    return {"schema": seeded.SEED_SCHEMA, "mode": mode, "source": dict(SRC), "items": items}


ITEMS = [dict(x, id=f"ccbo-mini-{n}") for n, x in enumerate((
         {"file": "src/lib.py", "line": 1, "body": LIB},
         {"file": "src/handlers/b.py", "line": 2, "body": SB},
         {"file": "src/lib.py", "line": 1, "body": "load_user lost the cache default, so Profile.show passes one argument"},
         {"file": "src/svc.py", "line": 999, "body": "an off-by-one past the end"},
         {"file": "src/use.py", "line": 6, "body": "Profile.show calls load_user with one argument"},
         {"file": "../etc/passwd", "line": 1, "body": "outside"}))]


def sid(n, item):
    return hypothesis_id(seeded.AGENT, n, item["body"], item["file"], item["line"])


class V24Rig(T.V21Rig):
    seed = None

    def spec(self, mini, backend, **kw):
        return dataclasses.replace(super().spec(mini, backend, **kw), seed=copy.deepcopy(self.seed))

    def record_v24(self, m, scr, **kw):
        kw.setdefault("profile", V24_PROFILE)
        kw.setdefault("retrieval", V24_POLICY)
        kw.setdefault("plan", V24_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v24(self, m, res, **kw):
        kw.setdefault("profile", V24_PROFILE)
        kw.setdefault("retrieval", V24_POLICY)
        kw.setdefault("plan", V24_PLAN)
        return self.replay(m, res, **kw)

    def run24(self, m):
        ids = {"l": sid(0, ITEMS[0]), "b": sid(1, ITEMS[1])}
        scr = script(T.vcc("verifier-01", m, path="src/lib.py", line=1), T.vcc("verifier-02", m, path="src/handlers/b.py", line=2),
                     judge(w([ids["l"]]), w([ids["b"]])))
        return scr, ids


# ---------------------------------------------------------------- 1. rules

class Rules(unittest.TestCase):
    def test_profile_plan_policy_templates(self):
        self.assertEqual(RP.IMPACT_VERSIONS[24], INV24)
        p21, p24 = RP.repository_profile(True, T.CC, impact_version=21), RP.repository_profile(True, T.CC, impact_version=24)
        self.assertEqual(validate("ModelProfile", p24), [])
        self.assertEqual(p24["roles"]["investigator"], dict(p21["roles"]["investigator"], promptVersion=INV24))
        self.assertEqual({k: v for k, v in p24["roles"].items() if k != "investigator"},
                         {k: v for k, v in p21["roles"].items() if k != "investigator"})
        for live in (True, False):
            a, b = RP.repository_plan(p21, live_stage_timing=live), RP.repository_plan(p24, live_stage_timing=live)
            self.assertEqual(validate("Plan", b), [])
            self.assertEqual({k: v for k, v in a.items() if k != "reasons"}, {k: v for k, v in b.items() if k != "reasons"})
            self.assertTrue(dual.is_v21_plan(b))
            self.assertEqual(a["reasons"][0], b["reasons"][0])
            self.assertTrue(b["reasons"][1].startswith(INV24 + ": INVESTIGATE makes no model call"))
        pol = RP.repository_policy(True, impact_version=24)
        self.assertEqual((pol.seeded, pol.dual_pass, pol.agentic_review, pol.whole_change, pol.broad_agentic),
                         (True, True, True, True, True))
        self.assertFalse(RP.repository_policy(True, impact_version=21).seeded)
        d21, d24 = prompts.impact_template_digests(T.INV21), prompts.impact_template_digests(INV24)
        self.assertEqual({k: v for k, v in d24.items() if k != "seeded"}, d21)
        self.assertEqual(set(d24) - set(d21), {"seeded"})
        self.assertEqual(prompts.V24_TEMPLATES, {"seedRule": seeded.SEED_RULE, "seedSchema": seeded.SEED_SCHEMA,
                                                 "behavior": seeded.BEHAVIOR})

    def test_identity_binds_the_seed(self):
        r = V24Rig()
        r.setUp()
        try:
            m = r.case12()
            backend, _ = r.record_backend(script())
            r.seed = seed_doc(ITEMS)
            s1 = r.spec(m, backend, profile=V24_PROFILE, plan=V24_PLAN, retrieval=V24_POLICY)
            r.seed = seed_doc(ITEMS, mode="live")
            s2 = r.spec(m, backend, profile=V24_PROFILE, plan=V24_PLAN, retrieval=V24_POLICY)
            r.seed = None
            s0 = r.spec(m, backend, profile=V24_PROFILE, plan=V24_PLAN, retrieval=V24_POLICY)
            self.assertNotEqual(identity.config_snapshot_id(s1), identity.config_snapshot_id(s2))
            other = [dict(x) for x in ITEMS]
            other[1]["body"] += " (another baseline answer)"                              # F2 identity-no-digest: same mode, same count
            r.seed = seed_doc(other)
            s3 = r.spec(m, backend, profile=V24_PROFILE, plan=V24_PLAN, retrieval=V24_POLICY)
            self.assertNotEqual(identity.config_snapshot_id(s1), identity.config_snapshot_id(s3))
            self.assertNotEqual(seeded.identity_doc(seed_doc(ITEMS)), seeded.identity_doc(seed_doc(other)))
            with self.assertRaises(Exception) as ctx:
                identity.config_snapshot_id(s0)
            self.assertIn("needs its seed document", str(ctx.exception))
            self.assertEqual(identity.plan_specialists(s1), dual.plan_specialists())
        finally:
            r.tearDown()


# ---------------------------------------------------------------- 2. seed rules

class SeedRules(unittest.TestCase):
    def raw(self, doc):
        return json.dumps(doc).encode()

    def test_load_accepts_exactly_the_schema(self):
        d = seed_doc(ITEMS)
        self.assertEqual(seeded.load(self.raw(d)), d)
        self.assertEqual(seeded.digest(d), seeded.digest(json.loads(json.dumps(d))))
        self.assertNotEqual(seeded.digest(d), seeded.digest(seed_doc(ITEMS[:1])))
        bad = [b"\xff", b"[]", self.raw({**d, "x": 1}), self.raw({**d, "schema": "other@1"}), self.raw({**d, "mode": "fresh"}),
               self.raw({**d, "source": {**SRC, "extra": 1}}), self.raw({**d, "source": {**SRC, "commentsSha256": "x"}}),
               self.raw({**d, "source": {**SRC, "arm": ""}}), self.raw({**d, "items": {}}),
               self.raw({**d, "items": [{"file": "a", "line": 1, "id": "x-0"}]}),
               self.raw({**d, "items": [{"file": "", "line": 1, "body": "b", "id": "x-0"}]}),      # F2: each with a valid id, so the
               self.raw({**d, "items": [{"file": "a", "line": 0, "body": "b", "id": "x-0"}]}),     # field's own guard is what refuses it
               self.raw({**d, "items": [{"file": "a", "line": True, "body": "b", "id": "x-0"}]}),  # F2 load-bool-line: a bool is not an int
               self.raw({**d, "items": [{"file": "a", "line": 1.0, "body": "b", "id": "x-0"}]}),
               self.raw({**d, "items": [{"file": "a", "line": 1, "body": "  ", "id": "x-0"}]}),
               self.raw({**d, "items": [{"file": "a", "line": 1, "body": "b", "id": "x-0", "severity": "P0"}]}),
               self.raw({**d, "items": [{"file": "a", "line": 1, "body": "b"}]}),                        # SEED ID: required
               self.raw({**d, "items": [{"file": "a", "line": 1, "body": "b", "id": "Bad Id"}]}),
               self.raw({**d, "items": [{"file": "a", "line": 1, "body": "b", "id": "x-0"}] * 2}),      # ids unique
               self.raw({**d, "items": [{"file": "a", "line": 1, "body": "b", "id": f"x-{n}"} for n in range(seeded.MAX_ITEMS + 1)]}),
               b'{"schema": "a", "schema": "b"}', b"x" * (seeded.MAX_SEED_BYTES + 1)]
        for raw in bad:
            with self.subTest(raw=raw[:60]), self.assertRaises(seeded.SeedError):
                seeded.load(raw)

    def test_drafts(self):
        lines = {"src/lib.py": ["def load_user(uid, cache, region):", "    return {'id': uid}"]}
        long = {"file": "src/lib.py", "line": 2, "body": "y" * (seeded.CLAIM_MAX + 5), "id": "ccbo-mini-long"}
        out, dropped, cut = seeded.drafts(seed_doc(ITEMS[:1] + [long] + ITEMS[3:]), lines.get, "snap:sha256:" + "0" * 64,
                                          {"src/lib.py", "src/svc.py"})
        self.assertEqual([n for n, _ in out], [0, 1])
        self.assertEqual(dropped, [{"index": 2, "reason": "no-such-line"}, {"index": 3, "reason": "not-a-changed-file"},
                                   {"index": 4, "reason": "bad-path"}])
        self.assertEqual(cut, 1)
        d0 = out[0][1]
        self.assertEqual(d0, {"claim": LIB, "category": "bug", "suspectedSeverity": "P1", "impact": "incorrect-result",
                              "location": {"path": "src/lib.py", "line": 1},
                              "evidence": [{"kind": "code", "path": "src/lib.py", "lines": [1, 1], "commit": "snap:sha256:" + "0" * 64,
                                            "excerpt": "def load_user(uid, cache, region):"}]})
        self.assertEqual(validate("HypothesisDraft", d0), [])
        past = {"file": "src/lib.py", "line": len(lines["src/lib.py"]) + 1, "body": "one past the end", "id": "ccbo-mini-past"}
        last = dict(past, line=len(lines["src/lib.py"]), id="ccbo-mini-last")
        out3, dropped3, _ = seeded.drafts(seed_doc([last, past]), lines.get, "snap:sha256:" + "0" * 64, {"src/lib.py"})
        self.assertEqual(([n for n, _ in out3], dropped3), ([0], [{"index": 1, "reason": "no-such-line"}]))   # F2 drafts-off-by-one
        self.assertEqual(len(out[1][1]["claim"]), seeded.CLAIM_MAX)
        out2, dropped2, _ = seeded.drafts(seed_doc(ITEMS[4:5]), lambda p: ["x"] * 9, "snap:sha256:" + "0" * 64, None)
        self.assertEqual(([n for n, _ in out2], dropped2), ([0], []))           # unknown change list: not applied


# ---------------------------------------------------------------- 3. end to end

class EndToEnd(V24Rig):
    def test_seeded_run(self):
        m = self.case12()
        self.seed = seed_doc(ITEMS)
        scr, ids = self.run24(m)
        res, spy = self.record_v24(m, scr)
        self.assertEqual(res.status, "completed", res.receipt)
        calls = model_calls(res)
        self.assertEqual([c["stage"] for c in calls if c["stage"] == "INVESTIGATE"], [])       # no investigator call
        self.assertEqual([(c["stage"], c["agentId"]) for c in calls],
                         [("VERIFY", "verifier-01"), ("VERIFY", "verifier-02"), ("JUDGE", "judge")])
        events = load_trace(res.trace_path).events
        self.assertEqual(validate_trace(events), [])
        seeds = [e for e in events if e["type"] == "seed.input"]
        self.assertEqual(len(seeds), 1)
        ref = "sha256:" + seeded.digest(self.seed)
        self.assertEqual((seeds[0]["seed"], seeds[0]["mode"], [(x["index"], x["id"]) for x in seeds[0]["drafts"]]),
                         (ref, "reuse", [(0, "ccbo-mini-0"), (1, "ccbo-mini-1"), (2, "ccbo-mini-2")]))
        inv = payload(res, "INVESTIGATE")
        self.assertEqual(inv["agents"], [{"agentId": "seed", "specialist": "seed", "status": "completed"}])
        rec = inv["seed"]
        self.assertEqual((rec["mode"], rec["sha256"], rec["items"], rec["candidates"], rec["truncatedClaims"], rec["source"]),
                         ("reuse", seeded.digest(self.seed), 6, 3, 0, SRC))
        self.assertEqual(rec["dropped"], [{"index": 3, "reason": "no-such-line"}, {"index": 4, "reason": "not-a-changed-file"},
                                          {"index": 5, "reason": "bad-path"}])
        self.assertTrue(all(h["seedRef"] == {"seed": ref, "index": n, "id": f"ccbo-mini-{n}"} and "sourceCallId" not in h
                            for n, h in enumerate(inv["hypotheses"])))
        self.assertEqual([x["id"] for x in rec["drafts"]], ["ccbo-mini-0", "ccbo-mini-1", "ccbo-mini-2"])
        ver = payload(res, "VERIFY")
        self.assertEqual([f["id"] for f in ver["findings"]], [ids["l"], ids["b"]])
        merged = [d for d in ver["drops"] if d["reason"] == "merged"]
        self.assertEqual([d["subjectIds"] for d in merged], [[sid(2, ITEMS[2])]])
        for f in ver["findings"]:
            self.assertNotIn("sourceCallId", f)
            self.assertEqual(f["seedRef"]["seed"], ref)
            self.assertEqual(validate("Finding", f), [])
            self.assertEqual(check_finding_provenance(f, events), [])
        self.assertEqual(len(T.comments_of(res)), 2)
        cdoc = json.loads((Path(res.run_dir) / "comments.json").read_text())          # SEED ID on every published comment
        self.assertEqual(cdoc["seedIds"], {c["id"]: [{ids["l"]: "ccbo-mini-0", ids["b"]: "ccbo-mini-1"}[h] for h in c["findingIds"]]
                                           for c in cdoc["comments"]})
        self.assertEqual(sorted(x for v in cdoc["seedIds"].values() for x in v), ["ccbo-mini-0", "ccbo-mini-1"])
        self.assertEqual([f["seedRef"]["id"] for f in ver["findings"]], ["ccbo-mini-0", "ccbo-mini-1"])
        md = md_of(res)
        self.assertIn(f"Seeded review ({seeded.BEHAVIOR}, {seeded.SEED_RULE})", md)
        self.assertIn("candidate mode `reuse`: the settled baseline review's own answer, no new candidate call", md)
        self.assertIn("- Seed: 3 candidate(s) kept, 3 dropped before VERIFY (1 bad path, 1 not in a changed file, 1 line not in "
                      "the head file)", md)
        self.assertIn(f"- Union ({dual.UNION_RULE}, one seed lane): 1 restatement(s)", md)
        self.assertNotIn("- Passes:", md)
        self.assertIn("- Agentic verify (", md)
        # strict replay: byte-identical outputs with the same seed
        rep = self.replay_v24(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        backend, _ = self.record_backend(script())
        self.assertEqual(res.run["configSnapshotId"], identity.config_snapshot_id(
            self.spec(m, backend, profile=V24_PROFILE, plan=V24_PLAN, retrieval=V24_POLICY)))
        # another seed (here: the live mode) is another run identity: the recording does not replay it
        self.seed = seed_doc(ITEMS, mode="live")
        (self.tmp / "replay2").mkdir()
        try:
            got = self.replay_v24(m, res, out=self.tmp / "replay2")
        except Exception as e:                     # noqa: BLE001 - refused before or during the replay
            got = e
        self.assertFalse(getattr(got, "status", None) == "completed", got)

    def test_live_mode_disclosed_and_empty_seed_completes(self):
        m = self.case12()
        self.seed = seed_doc(ITEMS[:1], mode="live")
        res, _ = self.record_v24(m, script(T.vcc("verifier-01", m, path="src/lib.py", line=1), judge(w([sid(0, ITEMS[0])]))))
        self.assertEqual(res.status, "completed")
        self.assertIn("candidate mode `live`: a fresh baseline call for this run", md_of(res))
        self.seed = seed_doc([])
        self.out = self.tmp / "o-empty"
        self.out.mkdir()
        res2, _ = self.record_v24(m, script(), out_root=self.out)
        self.assertEqual(res2.status, "completed")
        self.assertEqual(payload(res2, "INVESTIGATE")["hypotheses"], [])
        self.assertEqual([c for c in model_calls(res2) if c["stage"] in ("INVESTIGATE", "VERIFY")], [])

    def test_no_seed_fails_closed(self):
        m = self.case12()
        self.seed = None
        with self.assertRaises(Exception) as ctx:
            self.record_v24(m, script())
        self.assertIn("needs its seed document", str(ctx.exception))


# ---------------------------------------------------------------- 4. provenance negatives

class Provenance(V24Rig):
    def test_seed_ref_must_match_the_one_seed_event(self):
        m = self.case12()
        self.seed = seed_doc(ITEMS)
        scr, ids = self.run24(m)
        res, _ = self.record_v24(m, scr)
        events = load_trace(res.trace_path).events
        f = payload(res, "VERIFY")["findings"][0]
        self.assertEqual(check_finding_provenance(f, events), [])
        bad = {"other digest": {**f, "seedRef": {**f["seedRef"], "seed": "sha256:" + "1" * 64}},
               "other index": {**f, "seedRef": {**f["seedRef"], "index": 1}},
               "other id": {**f, "seedRef": {**f["seedRef"], "id": "ccbo-mini-1"}},
               "edited claim": {**f, "claim": f["claim"] + " (edited)"},
               "both sources": {**f, "sourceCallId": "call_0000000000000000"}}
        for name, g in bad.items():
            with self.subTest(name):
                self.assertNotEqual(check_finding_provenance(g, events), [])
        seed = next(e for e in events if e["type"] == "seed.input")
        twice = events + [dict(seed, seq=len(events))]
        self.assertNotEqual(check_finding_provenance(f, twice), [])
        none = [e for e in events if e["type"] != "seed.input"]
        self.assertNotEqual(check_finding_provenance(f, none), [])
        edited = [dict(e, drafts=[dict(x, draft=dict(x["draft"], suspectedSeverity="P0")) for x in e["drafts"]])
                  if e["type"] == "seed.input" else e for e in events]
        self.assertNotEqual(check_finding_provenance(f, edited), [])


# ---------------------------------------------------------------- 5. benchmark options

class Options(TBH.Base):
    def test_v24_needs_a_seed_and_nothing_else_takes_one(self):
        self.assertEqual(self.refused(impact_version=24), "impact_version 24 needs seed_candidates (its candidate list)")
        for over in ({"seed_candidates": "x.json"}, {"seed_candidates": "x.json", "impact_version": 21}):
            with self.subTest(**over):
                self.assertEqual(self.refused(**over), "seed_candidates is only for impact_version 24 (a seed document path)")
        self.assertEqual(self.refused(impact_version=24, seed_candidates=""),
                         "seed_candidates is only for impact_version 24 (a seed document path)")
        self.assertIn("seed_candidates: benchmark data, label, gold and competitor-review paths are not launch inputs",
                      self.refused(impact_version=24, seed_candidates=str(self.tmp / "gold.json")))

    def test_a_bad_seed_file_is_refused_before_any_run(self):
        before = self.w.state_bytes()
        p = self.tmp / "seed.json"
        p.write_text('{"schema": "x"}')
        self.assertTrue(self.refused(impact_version=24, seed_candidates=str(p)).startswith("seed candidates refused: "))
        self.assertTrue(self.refused(impact_version=24, seed_candidates=str(self.tmp / "missing.json"))
                        .startswith("seed candidates are unreadable"))
        self.assertEqual(self.w.state_bytes(), before)

    def test_benchmark_identity_binds_the_seed_digest(self):
        """F2 identity-no-digest: two same-mode, same-count seeds that differ in one body give two config identities (so two eval
        run ids); the identity records the seed's sha256."""
        cfg = B.effective_config(self.w.options())
        docs = [seed_doc(ITEMS), seed_doc([dict(x, body=x["body"] + " (other)") if n == 1 else x for n, x in enumerate(ITEMS)])]
        idents = []
        for n, doc in enumerate(docs):
            p = self.tmp / f"seed-{n}.json"
            p.write_text(json.dumps(doc))
            ing = B.ingest(self.w.options(impact_version=24, seed_candidates=str(p)), cfg)
            self.assertEqual(ing.seed, doc)
            idents.append(B.config_identity(ing, {"p": 1}, {"q": 1}, None, True, cfg))
        self.assertEqual([i["seedCandidates"]["sha256"] for i in idents], [seeded.digest(d) for d in docs])
        self.assertEqual(idents[0]["seedCandidates"]["mode"], idents[1]["seedCandidates"]["mode"])
        self.assertNotEqual(idents[0], idents[1])
        o = self.w.options(impact_version=24, seed_candidates=str(self.tmp / "seed-0.json"))
        self.assertNotEqual(B.eval_run_id(o, idents[0]), B.eval_run_id(o, idents[1]))

    def test_parser_and_identity(self):
        a = B._parser().parse_args(["--mode", "plan", "--case-url", "u", "--cutoff-proof", "p", "--admission", "a", "--decision",
                                    "d", "--launch-baseline", "l", "--store", "s", "--base-import-pins", "b",
                                    "--head-import-pins", "h", "--out", "o", "--impact-version", "24", "--seed-candidates", "x"])
        self.assertEqual((a.impact_version, a.seed_candidates), (24, "x"))
        self.assertIn("seed_candidates", {f.name for f in dataclasses.fields(B.BenchmarkOptions)})
        self.assertIsNone(B.BenchIngested.__dataclass_fields__["seed"].default)


# ---------------------------------------------------------------- 6. V21 parity

class V21Parity(unittest.TestCase):
    def test_v21_recordings_are_byte_identical_to_the_pre_change_source(self):
        pins = json.loads((ROOT / "tests/pipeline/v21_pins_2eff0f8.json").read_text())
        buf = io.StringIO()
        with redirect_stdout(buf):
            runpy.run_path(str(ROOT / "tests/pipeline/v21_pin_scenarios.py"), run_name="__main__")
        self.assertEqual(json.loads(buf.getvalue()), pins)
        self.assertEqual(set(pins), {"e2e", "judge_merge"})
        self.assertFalse(Engine.__dict__.get("v24", False))


if __name__ == "__main__":
    unittest.main()
