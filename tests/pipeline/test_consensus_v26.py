"""investigator.impact@v26 (reviewer.pipeline.consensus; res2 CARD-v26-build e24326b1, root GO 2026-11-12T08:25Z): K6 consensus
inside Pullo. Offline: the v24 rig (test_seeded_v24.V24Rig on test_dual_v21.V21Rig), no network, no credential, no model call.
  1. rules: profile / Plan / policy / templates are v24's but the investigator promptVersion, the Plan reason and the consensus
     templates; the identity binds the seed (mode, n/k, a witness body); MATCHER_SHA and the vendored block are pinned;
  2. matcher vectors (each same_defect branch, the min(d, 50) cap, the tie-break, assign == assign_pairs), k-of-n vectors (n=3 of
     one witness == K6, a 0-comment witness, k=2 of 3) and title_of golden vectors;
  3. seed@2 refusals (every card section 1 refusal), @2 refused at v24, @1 refused at v26, every other version refuses a seed;
  4. end to end: 0 model calls, one seed.input event with the consensus record, no-witness and location drops by id,
     witness-supported findings with provenance, verbatim comments (body, title_of, anchor, no suggestion), comments.json
     seedIds + witnessIds, review.md disclosure, strict replay byte-identical, another seed refused; live mode; a 0-comment
     witness; an unpublishable body; an identical repeat; a missing seed fails closed;
  5. contract negatives (check_finding_provenance, the Verification variants, the consensus event invariant);
  6. benchmark options and the zero-request plan / live mode on the claude-cli benchmark rig;
  7. V24 parity: v24 recordings byte-identical to 2bae112 (tests/pipeline/v24_pins_2bae112.json)."""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import io
import json
import runpy
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from reviewer.config import resolve_config
from reviewer.contracts import check_finding_provenance, validate
from reviewer.contracts.canonical import hypothesis_id
from reviewer.contracts.entities import validate_trace
from reviewer.gateway.trace import load_trace
from reviewer.pilot import benchmark as B
from reviewer.pilot import repository_profile as RP
from reviewer.pipeline import RetrievalPolicy, consensus as K, dual, identity, prompts, seeded
from reviewer.pipeline.engine import Engine

import tests.pilot.test_benchmark_host as TBH
from tests.config import test_claude_cli_integration as CI
from tests.pipeline import test_dual_v21 as T
from tests.pipeline import test_seeded_v24 as S
from tests.pipeline.helpers import model_calls, script
from tests.pipeline.test_coverage_v12 import ROOT, md_of, payload

INV26 = prompts.INVESTIGATOR_IMPACT_V26_PROMPT
V26_PROFILE = copy.deepcopy(T.V21_PROFILE)
V26_PROFILE["roles"]["investigator"]["promptVersion"] = INV26
V26_POLICY = RetrievalPolicy(investigator_prompt=INV26, verifier_prompt=T.VER, run_tool_calls=400)
V26_PLAN = copy.deepcopy(T.V21_PLAN)


def src(arm, model, run, **over):
    return {"arm": arm, "case": "mini", "runId": run, "model": model, "settleReceiptSha256": "c" * 64,
            "commentsSha256": "b" * 64, "promptTextSha256": "d" * 64, "bodySha256": "e" * 64, "diffSha256": "f" * 64,
            "cliVersion": "2.1.317", "exportVersion": 21, "reviewerManifestSha256": "a" * 64, **over}


# the witness answer: W[0] restates candidate 2 (it wins the one-to-one pairing over candidate 0), W[1] candidate 3 (whose line is
# not in the head file), W[2] candidate 4 (not a changed file), W[3] candidate 5 (bad path)
W = [{"id": "ccbs-mini-0", "file": "src/lib.py", "line": 2,
      "body": "load_user lost its cache default so Profile.show passes one argument"},
     {"id": "ccbs-mini-1", "file": "src/svc.py", "line": 990, "body": "an off-by-one past the end of the list"},
     {"id": "ccbs-mini-2", "file": "src/use.py", "line": 6, "body": "Profile.show calls load_user with only one argument"},
     {"id": "ccbs-mini-3", "file": "../etc/passwd", "line": 1, "body": "outside"}]


def seed_doc(items=None, witnesses=None, mode="reuse", n=None, k=1):
    ws = [W] if witnesses is None else witnesses
    n = len(ws) if n is None else n
    return {"schema": K.SEED_SCHEMA, "mode": mode, "rule": {"id": K.RULE, "n": n, "k": k},
            "candidates": {"source": src("ccbo", K.CANDIDATE_MODEL, "ccb-r0"), "items": S.ITEMS if items is None else items},
            "witnesses": [{"source": src("ccbs" + ("" if j == 0 else f"w{j}"), K.WITNESS_MODEL, f"ccb-r{j + 1}"), "items": w}
                          for j, w in enumerate(ws)]}


def it(n, file, line, body, prefix="c"):
    return {"id": f"{prefix}-{n}", "file": file, "line": line, "body": body}


class V26Rig(S.V24Rig):
    def record_v26(self, m, scr=None, **kw):
        kw.setdefault("profile", V26_PROFILE)
        kw.setdefault("retrieval", V26_POLICY)
        kw.setdefault("plan", V26_PLAN)
        return self.record_turn(m, script() if scr is None else scr, **kw)

    def replay_v26(self, m, res, **kw):
        kw.setdefault("profile", V26_PROFILE)
        kw.setdefault("retrieval", V26_POLICY)
        kw.setdefault("plan", V26_PLAN)
        return self.replay(m, res, **kw)

    def fresh(self, name):
        self.out = self.tmp / name
        self.out.mkdir()
        return self.out


# ---------------------------------------------------------------- 1. rules

class Rules(unittest.TestCase):
    def test_profile_plan_policy_templates(self):
        self.assertEqual(RP.IMPACT_VERSIONS[26], INV26)
        p24, p26 = RP.repository_profile(True, T.CC, impact_version=24), RP.repository_profile(True, T.CC, impact_version=26)
        self.assertEqual(validate("ModelProfile", p26), [])
        self.assertEqual(p26["roles"]["investigator"], dict(p24["roles"]["investigator"], promptVersion=INV26))
        self.assertEqual({k: v for k, v in p26["roles"].items() if k != "investigator"},
                         {k: v for k, v in p24["roles"].items() if k != "investigator"})
        for live in (True, False):
            a, b = RP.repository_plan(p24, live_stage_timing=live), RP.repository_plan(p26, live_stage_timing=live)
            self.assertEqual(validate("Plan", b), [])
            self.assertEqual({k: v for k, v in a.items() if k != "reasons"}, {k: v for k, v in b.items() if k != "reasons"})
            self.assertTrue(dual.is_v21_plan(b))
            self.assertEqual(a["reasons"][0], b["reasons"][0])
            self.assertTrue(b["reasons"][1].startswith(INV26 + ": the run makes no model call - consensus.k6@v26"))
        pol = RP.repository_policy(True, impact_version=26)
        self.assertEqual((pol.consensus, pol.seeded, pol.dual_pass, pol.agentic_review, pol.whole_change, pol.broad_agentic),
                         (True, True, True, True, True, True))
        for v in (21, 24):
            self.assertFalse(RP.repository_policy(True, impact_version=v).consensus)
        self.assertEqual(RP.repository_policy(True, impact_version=24).to_doc(),
                         dict(pol.to_doc(), investigator_prompt=prompts.INVESTIGATOR_IMPACT_V24_PROMPT))
        d24, d26 = prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_V24_PROMPT), prompts.impact_template_digests(INV26)
        self.assertEqual({k: v for k, v in d26.items() if k != "consensus"}, d24)
        self.assertEqual(set(d26) - set(d24), {"consensus"})
        self.assertEqual(prompts.V26_TEMPLATES, {"consensusRule": K.RULE, "seedSchema": K.SEED_SCHEMA, "behavior": K.BEHAVIOR,
                                                 "matcher": K.MATCHER_ID, "verdict": K.VERDICT})
        self.assertIn(INV26, prompts.AGENTIC_PROMPTS)

    def test_matcher_pins(self):
        self.assertEqual(K.MATCHER_SHA, "873543d788416b3a97b86b5234af434172dcb175741683e3b3ed6d20798639da")
        self.assertEqual(K.MATCHER_SHA, hashlib.sha256(seeded.canonical(K.MATCHER)).hexdigest())
        text = (ROOT / "reviewer/pipeline/consensus.py").read_text()
        self.assertEqual(hashlib.sha256(K.vendored_block(text).encode()).hexdigest(), K.VENDORED_SHA256)
        self.assertEqual(K.MATCHER["vendoredSha256"], K.VENDORED_SHA256)
        self.assertEqual((set(K.MATCHER["stop"]), K.MATCHER["tokenRegex"], K.MATCHER["tickRegex"]),
                         (K.STOP, K.TOK.pattern, K.TICK.pattern))
        self.assertEqual(len(K.STOP), 88)

    def test_identity_binds_the_seed(self):
        r = V26Rig()
        r.setUp()
        try:
            m = r.case12()
            backend, _ = r.record_backend(script())
            ids = []
            w2 = copy.deepcopy(W)
            w2[0]["body"] += " (again)"
            for doc in (seed_doc(), seed_doc(mode="live"), seed_doc(witnesses=[W, W], k=1), seed_doc(witnesses=[W, W], k=2),
                        seed_doc(witnesses=[w2])):
                r.seed = doc
                ids.append(identity.config_snapshot_id(r.spec(m, backend, profile=V26_PROFILE, plan=V26_PLAN,
                                                              retrieval=V26_POLICY)))
            self.assertEqual(len(set(ids)), len(ids))
            for bad in (None, S.seed_doc(S.ITEMS)):                   # no seed, or v24's seed@1
                r.seed = bad
                with self.assertRaises(Exception) as ctx:
                    identity.config_snapshot_id(r.spec(m, backend, profile=V26_PROFILE, plan=V26_PLAN, retrieval=V26_POLICY))
                self.assertIn("investigator.impact@v26 needs its seed document", str(ctx.exception))
            r.seed = seed_doc()
            self.assertEqual(identity.plan_specialists(r.spec(m, backend, profile=V26_PROFILE, plan=V26_PLAN,
                                                              retrieval=V26_POLICY)), dual.plan_specialists())
        finally:
            r.tearDown()


# ---------------------------------------------------------------- 2. matcher, k-of-n and title vectors

class Vectors(unittest.TestCase):
    def test_same_defect_branches(self):
        f = "f.py"
        cases = [  # (a, b, similarity, same_defect, score)
            (it(0, f, 10, "Foo bar baz qux"), it(0, f, 12, "foo zzz yyy www vvv uuu ttt sss rrr ppp"),
             (0.07692307692307693, 0.0, 2), True, 0.06892307692307692),                      # d<=3 and jac>=.06
            (it(0, f, 10, "calls `load_user` twice here"),
             it(0, f, 11, "aaa bbb ccc ddd eee fff ggg hhh iii jjj kkk lll mmm nnn `load_user`"),
             (0.058823529411764705, 1.0, 1), True, 0.5548235294117647),                      # d<=3 and kov>=.34 only
            (it(0, f, 10, "cache default lost in load_user"), it(0, f, 24, "load_user cache default missing now zzz"),
             (0.5, 0.0, 14), True, 0.444),                                                   # d<=15 and jac>=.18
            (it(0, f, 10, "cache default lost in `load_user` path"), it(0, f, 90, "the `load_user` cache default is lost"),
             (0.8, 1.0, 80), True, 1.1),                                                     # far: jac>=.30 and kov>=.5; min(d, 50)
            (it(0, f, 10, "cache default lost in load_user aaa bbb"), it(0, f, 40, "cache default lost ccc ddd eee"),
             (0.3333333333333333, 0.0, 30), False, None)]                                    # far without code overlap
        for a, b, sim, same, sc in cases:
            with self.subTest(a=a["body"]):
                self.assertEqual(K.similarity(a, b), sim)
                self.assertIs(K.same_defect(a, b), same)
                if sc is not None:
                    self.assertEqual(K.score(a, b), sc)
        self.assertIsNone(K.similarity(it(0, "a.py", 1, "x yyy"), it(0, "b.py", 1, "x yyy")))     # another file never matches
        self.assertFalse(K.same_defect(it(0, "a.py", 1, "same words here"), it(0, "b.py", 1, "same words here")))

    def test_one_to_one_and_tie_break(self):
        a = [it(0, "f.py", 5, "the cache default is lost"), it(1, "f.py", 5, "the cache default is lost")]
        o = [it(0, "f.py", 5, "the cache default is lost", "w")]
        self.assertEqual(K.assign_pairs(a, o), [(1, 0)])              # equal scores: sorted(..., reverse=True) takes i=1
        self.assertEqual(K.assign(a, o), {1})
        o2 = o + [it(1, "f.py", 6, "the cache default is lost now", "w")]
        pairs = K.assign_pairs(a, o2)
        self.assertEqual(sorted(pairs), [(0, 1), (1, 0)])
        self.assertEqual({i for i, _ in pairs}, K.assign(a, o2))
        many = [it(n, "f.py", n, f"cache default lost item{n % 3} `load_user`") for n in range(9)]
        others = [it(n, "f.py", n + 2, f"lost cache default item{n % 2} `load_user`", "w") for n in range(5)]
        got = K.assign_pairs(many, others)
        self.assertEqual({i for i, _ in got}, K.assign(many, others))
        self.assertEqual(len({j for _, j in got}), len(got))

    def test_k_of_n(self):
        cands = [it(0, "f.py", 1, "the cache default is lost in load_user"), it(1, "f.py", 30, "the size guard is missing"),
                 it(2, "g.py", 3, "unrelated thing about permissions")]
        w0 = [it(0, "f.py", 2, "load_user lost the cache default", "w"), it(1, "f.py", 31, "size guard missing in handler", "w")]
        k6 = K.table(seed_doc(cands, [w0]))
        self.assertEqual([r["supported"] for r in k6], [True, True, False])
        three = K.table(seed_doc(cands, [w0, w0, w0], k=3))           # n=3 of the same witness == K6
        self.assertEqual([r["supported"] for r in three], [r["supported"] for r in k6])
        self.assertEqual([r["votes"] for r in three], [3, 3, 0])
        self.assertEqual([[p["witness"] for p in r["pairs"]] for r in three], [[0, 1, 2], [0, 1, 2], []])
        self.assertEqual([r["supported"] for r in K.table(seed_doc(cands, [[]]))], [False, False, False])   # 0-comment witness
        w1 = [it(0, "f.py", 1, "cache default lost by load_user", "w")]
        w2 = [it(0, "f.py", 29, "missing size guard", "w")]
        two = K.table(seed_doc(cands, [w0[:1], w1, w2], k=2))
        self.assertEqual([(r["votes"], r["supported"]) for r in two], [(2, True), (1, False), (0, False)])
        self.assertEqual([r["seedId"] for r in two], ["c-0", "c-1", "c-2"])
        self.assertEqual(set(two[0]["pairs"][0]), {"witness", "witnessId", "jac", "kov", "d", "score"})

    def test_title_of(self):
        for body, want in (("## Bug: foo bar. More text", "Bug: foo bar."),
                           ("\n\n  **Null deref** in `x`. Then more", "Null deref** in `x`."),
                           ("- item one\nsecond line", "item one"), ("> quoted", "quoted"), ("`code` first", "code` first"),
                           ("x" * 130, "x" * 120), (("y " * 70) + ". z", ("y " * 60).rstrip()), ("###", K.TITLE_FALLBACK),
                           ("  \n\t\n", K.TITLE_FALLBACK), ("Version 1.2 is wrong", "Version 1.2 is wrong"),
                           ("e.g. this", "e.g.")):
            with self.subTest(body=body[:30]):
                self.assertEqual(K.title_of(body), want)
                self.assertTrue(0 < len(K.title_of(body)) <= K.TITLE_MAX)


# ---------------------------------------------------------------- 3. seed refusals

class SeedRules(unittest.TestCase):
    def raw(self, doc):
        return json.dumps(doc).encode()

    def test_load_accepts_exactly_the_schema_at_v26_only(self):
        d = seed_doc()
        self.assertEqual(seeded.load(self.raw(d), 26), d)
        self.assertEqual(seeded.load(self.raw(seed_doc(witnesses=[W, W, []], k=2)), 26)["rule"], {"id": K.RULE, "n": 3, "k": 2})
        with self.assertRaises(seeded.SeedError):
            seeded.load(self.raw(d))                                   # @2 at v24 (the default version)
        with self.assertRaises(seeded.SeedError):
            seeded.load(self.raw(S.seed_doc(S.ITEMS)), 26)            # @1 at v26
        for v in (None, 21, 25, 27, True):
            for doc in (d, S.seed_doc(S.ITEMS)):                     # neither seed shape is taken by any other version
                with self.subTest(version=v, schema=doc["schema"]), self.assertRaises(seeded.SeedError) as ctx:
                    seeded.load(self.raw(doc), v)
                self.assertIn("only impact_version 24", str(ctx.exception))
        self.assertEqual(seeded.load(self.raw(S.seed_doc(S.ITEMS)), 24), S.seed_doc(S.ITEMS))   # v24 unchanged

    def test_refusals(self):
        d = seed_doc()
        cs, w0 = d["candidates"]["source"], d["witnesses"][0]

        def wsrc(**over):
            return {**d, "witnesses": [{**w0, "source": {**w0["source"], **over}}]}
        bad = {
            "extra top key": {**d, "x": 1}, "missing witnesses": {k: v for k, v in d.items() if k != "witnesses"},
            "schema @1": {**d, "schema": seeded.SEED_SCHEMA}, "mode": {**d, "mode": "fresh"},
            "rule id": {**d, "rule": {"id": "k6@0", "n": 1, "k": 1}}, "rule extra": {**d, "rule": {**d["rule"], "x": 1}},
            "n 0": {**d, "rule": {"id": K.RULE, "n": 0, "k": 1}}, "n 4": {**d, "rule": {"id": K.RULE, "n": 4, "k": 1}},
            "n bool": {**d, "rule": {"id": K.RULE, "n": True, "k": 1}}, "k 0": {**d, "rule": {"id": K.RULE, "n": 1, "k": 0}},
            "k > n": {**d, "rule": {"id": K.RULE, "n": 1, "k": 2}},
            "len(witnesses) != n": {**d, "rule": {"id": K.RULE, "n": 2, "k": 1}},
            "witnesses not a list": {**d, "witnesses": {}},
            "block extra key": {**d, "candidates": {**d["candidates"], "x": 1}},
            "source extra key": {**d, "candidates": {**d["candidates"], "source": {**cs, "x": 1}}},
            "source missing key": {**d, "candidates": {**d["candidates"],
                                                       "source": {k: v for k, v in cs.items() if k != "runId"}}},
            "source sha": {**d, "candidates": {**d["candidates"], "source": {**cs, "bodySha256": "x"}}},
            "source export not int": {**d, "candidates": {**d["candidates"], "source": {**cs, "exportVersion": "21"}}},
            "candidate model": {**d, "candidates": {**d["candidates"], "source": {**cs, "model": K.WITNESS_MODEL}}},
            "witness model": wsrc(model=K.CANDIDATE_MODEL),
            "case differs": wsrc(case="other"), "prompt differs": wsrc(promptTextSha256="1" * 64),
            "body differs": wsrc(bodySha256="1" * 64), "diff differs": wsrc(diffSha256="1" * 64),
            "cli differs": wsrc(cliVersion="2.1.322"), "export differs": wsrc(exportVersion=24),
            "manifest differs": wsrc(reviewerManifestSha256="1" * 64), "runId repeats": wsrc(runId=cs["runId"]),
            "empty id": {**d, "candidates": {**d["candidates"], "items": [dict(S.ITEMS[0], id="")]}},
            "duplicate id": {**d, "candidates": {**d["candidates"], "items": [S.ITEMS[0], S.ITEMS[0]]}},
            "malformed id": {**d, "candidates": {**d["candidates"], "items": [dict(S.ITEMS[0], id="Bad Id")]}},
            "witness duplicate id": {**d, "witnesses": [{**w0, "items": [W[0], W[0]]}]},
            "witness item extra key": {**d, "witnesses": [{**w0, "items": [dict(W[0], title="t")]}]},
            "line bool": {**d, "candidates": {**d["candidates"], "items": [dict(S.ITEMS[0], line=True)]}}}
        for name, doc in bad.items():
            with self.subTest(name), self.assertRaises(seeded.SeedError):
                seeded.load(self.raw(doc), 26)
        same_ids = {**d, "witnesses": [{**w0, "items": [dict(W[0], id=S.ITEMS[0]["id"])]}]}    # unique only within a block
        self.assertEqual(seeded.load(self.raw(same_ids), 26), same_ids)


# ---------------------------------------------------------------- 4. end to end

class EndToEnd(V26Rig):
    def test_reuse_run(self):
        m = self.case12()
        self.seed = seed_doc()
        res, spy = self.record_v26(m)
        self.assertEqual(res.status, "completed", res.receipt)
        self.assertEqual(model_calls(res), [])                                      # 0 model calls in the whole run
        events = load_trace(res.trace_path).events
        self.assertEqual(validate_trace(events), [])
        self.assertEqual([e for e in events if e["type"] in ("model.call", "cost")], [])
        seeds = [e for e in events if e["type"] == "seed.input"]
        self.assertEqual(len(seeds), 1)
        ref = "sha256:" + seeded.digest(self.seed)
        rows = K.table(self.seed)
        self.assertEqual((seeds[0]["seed"], seeds[0]["mode"], [(x["index"], x["id"]) for x in seeds[0]["drafts"]]),
                         (ref, "reuse", [(2, "ccbo-mini-2")]))
        self.assertEqual(seeds[0]["consensus"], {"rule": K.RULE, "matcherSha256": K.MATCHER_SHA, "n": 1, "k": 1,
                                                 "tableSha256": K.table_digest(rows), "table": rows})
        inv = payload(res, "INVESTIGATE")
        self.assertEqual(inv["agents"], [{"agentId": "seed", "specialist": "seed", "status": "completed"}])
        self.assertNotIn("seed", inv)
        rec = inv["consensus"]
        self.assertEqual((rec["mode"], rec["sha256"], rec["n"], rec["k"], rec["items"], rec["witnessItems"], rec["supported"],
                          rec["candidates"], rec["matcherSha256"], rec["table"]),
                         ("reuse", seeded.digest(self.seed), 1, 1, 6, [4], 4, 1, K.MATCHER_SHA, rows))
        self.assertEqual(rec["dropped"], [{"index": 0, "id": "ccbo-mini-0", "reason": "no-witness", "votes": 0},
                                          {"index": 1, "id": "ccbo-mini-1", "reason": "no-witness", "votes": 0},
                                          {"index": 3, "id": "ccbo-mini-3", "reason": "no-such-line"},
                                          {"index": 4, "id": "ccbo-mini-4", "reason": "not-a-changed-file"},
                                          {"index": 5, "id": "ccbo-mini-5", "reason": "bad-path"}])
        self.assertEqual([r["pairs"][0]["witnessId"] for r in rows if r["pairs"]],
                         ["ccbs-mini-0", "ccbs-mini-1", "ccbs-mini-2", "ccbs-mini-3"])
        h = inv["hypotheses"]
        self.assertEqual([x["seedRef"] for x in h], [{"seed": ref, "index": 2, "id": "ccbo-mini-2"}])
        self.assertEqual(h[0]["id"], S.sid(2, S.ITEMS[2]))
        ver = payload(res, "VERIFY")
        self.assertEqual((ver["verifications"], ver["drops"]), ([], []))
        f = ver["findings"][0]
        self.assertEqual(f["verification"], {"verdict": K.VERDICT, "rule": K.RULE, "callIds": [], "evidence": [],
                                             "witnessRefs": [{"witness": 0, "witnessId": "ccbs-mini-0"}]})
        self.assertEqual(f["severityBasis"], {"impact": seeded.IMPACT, "reachable": False})
        self.assertNotIn("sourceCallId", f)
        self.assertEqual((validate("Finding", f), check_finding_provenance(f, events)), ([], []))
        cs = T.comments_of(res)
        self.assertEqual(len(cs), 1)
        c = cs[0]
        body = S.ITEMS[2]["body"]
        self.assertEqual((c["body"], c["title"], c["anchor"]["path"], c["anchor"]["startLine"], c["anchor"]["endLine"],
                          c["findingIds"], c["severity"], c["proposedSeverity"]),
                         (body, K.title_of(body), "src/lib.py", 1, 1, [f["id"]], "P2", "P1"))
        self.assertNotIn("suggestion", c)
        cdoc = json.loads((Path(res.run_dir) / "comments.json").read_text())
        self.assertEqual((cdoc["seedIds"], cdoc["witnessIds"]), ({c["id"]: ["ccbo-mini-2"]}, {c["id"]: [[0, "ccbs-mini-0"]]}))
        md = md_of(res)
        for line in (f"- Consensus review ({K.BEHAVIOR}, {K.RULE}): the candidates are the 6 comment(s) of ONE plain "
                     f"`{K.CANDIDATE_MODEL}` baseline answer (arm `ccbo`)", "0 model calls in this run.",
                     "candidate mode `reuse` (the settled baseline answers, no new call)",
                     f"at least 1 of 1 witness(es) raised the same defect (matcher `{K.MATCHER_ID}`, sha256 "
                     f"{K.MATCHER_SHA[:16]}", "; 4 of 6 supported.",
                     "- Dropped: 2 without witness support (ccbo-mini-0, ccbo-mini-1); location 1 bad path, 1 not in a changed "
                     "file, 1 line not in the head file (ccbo-mini-3, ccbo-mini-4, ccbo-mini-5); 0 body not publishable "
                     "verbatim (none).", "- Published: 1 comment(s)"):
            self.assertIn(line, md)
        for absent in ("- Seed: ", "- Union (", "- Agentic verify (", "- Passes:"):
            self.assertNotIn(absent, md)
        # strict replay: byte-identical outputs with the same seed
        rep = self.replay_v26(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        backend, _ = self.record_backend(script())
        self.assertEqual(res.run["configSnapshotId"], identity.config_snapshot_id(
            self.spec(m, backend, profile=V26_PROFILE, plan=V26_PLAN, retrieval=V26_POLICY)))
        # another seed (here: k-of-n of two witnesses) is another run identity: the recording does not replay it
        for n, other in enumerate((seed_doc(mode="live"), seed_doc(witnesses=[W, W], k=2))):
            self.seed = other
            try:
                got = self.replay_v26(m, res, out=self.fresh(f"replay{n}"))
            except Exception as e:                     # noqa: BLE001 - refused before or during the replay
                got = e
            self.assertFalse(getattr(got, "status", None) == "completed", got)

    def test_live_mode_two_of_three_and_a_silent_witness(self):
        m = self.case12()
        self.seed = seed_doc(mode="live", witnesses=[W, W[:1], []], k=2)
        res, _ = self.record_v26(m)
        self.assertEqual((res.status, model_calls(res)), ("completed", []))
        rec = payload(res, "INVESTIGATE")["consensus"]
        self.assertEqual([r["votes"] for r in rec["table"]], [0, 0, 2, 1, 1, 1])
        self.assertEqual([x["id"] for x in rec["drafts"]], ["ccbo-mini-2"])
        self.assertEqual([d["reason"] for d in rec["dropped"]], ["no-witness"] * 5)
        self.assertEqual(json.loads((Path(res.run_dir) / "comments.json").read_text())["witnessIds"],
                         {T.comments_of(res)[0]["id"]: [[0, "ccbs-mini-0"], [1, "ccbs-mini-0"]]})
        md = md_of(res)
        self.assertIn("candidate mode `live` (fresh baseline calls made by the host for this run)", md)
        self.assertIn("at least 2 of 3 witness(es)", md)
        self.assertIn("(`ccbs` 4 comment(s), `ccbsw1` 1 comment(s), `ccbsw2` 0 comment(s))", md)
        self.seed = seed_doc(witnesses=[[]])                    # a witness with 0 comments silences the PR (valid, disclosed)
        res2, _ = self.record_v26(m, out_root=self.fresh("o-silent"))
        self.assertEqual((res2.status, T.comments_of(res2), model_calls(res2)), ("completed", [], []))
        self.assertIn("0 of 6 supported", md_of(res2))
        self.seed = seed_doc(items=[])
        res3, _ = self.record_v26(m, out_root=self.fresh("o-empty"))
        self.assertEqual((res3.status, payload(res3, "INVESTIGATE")["hypotheses"]), ("completed", []))

    def test_unpublishable_bodies_and_an_identical_repeat(self):
        m = self.case12()
        lib = "load_user lost the cache default; Profile.show passes one argument"
        items = [it(0, "src/lib.py", 1, lib, "ccbo-mini"), it(1, "src/lib.py", 1, lib, "ccbo-mini"),
                 it(2, "src/lib.py", 1, lib + " " + "x" * K.BODY_MAX, "ccbo-mini"),
                 it(3, "src/lib.py", 1, lib + " token ghp_" + "A" * 36, "ccbo-mini")]
        ws = [it(n, "src/lib.py", 1, lib, "ccbs-mini") for n in range(4)]
        self.seed = seed_doc(items=items, witnesses=[ws])
        res, _ = self.record_v26(m)
        self.assertEqual(res.status, "completed", res.receipt)
        rec = payload(res, "INVESTIGATE")["consensus"]
        self.assertEqual(rec["supported"], 4)
        self.assertEqual(rec["dropped"], [{"index": 2, "id": "ccbo-mini-2", "reason": "unpublishable-body"},
                                          {"index": 3, "id": "ccbo-mini-3", "reason": "unpublishable-body"}])
        cs = T.comments_of(res)
        self.assertEqual(len(cs), 1)
        ids = [hypothesis_id(seeded.AGENT, n, lib, "src/lib.py", 1) for n in (0, 1)]
        self.assertEqual(cs[0]["findingIds"], ids)
        merged = [d for d in payload(res, "JUDGE")["drops"] if d["reason"] == "merged"]
        self.assertEqual([d["subjectIds"] for d in merged], [[ids[1]]])
        self.assertEqual(json.loads((Path(res.run_dir) / "comments.json").read_text())["seedIds"],
                         {cs[0]["id"]: ["ccbo-mini-0", "ccbo-mini-1"]})
        self.assertIn("2 body not publishable verbatim (ccbo-mini-2, ccbo-mini-3)", md_of(res))

    def test_no_seed_or_a_v24_seed_fails_closed(self):
        m = self.case12()
        for bad in (None, S.seed_doc(S.ITEMS)):
            self.seed = bad
            with self.subTest(seed=bool(bad)), self.assertRaises(Exception) as ctx:
                self.record_v26(m, out_root=self.fresh(f"o-{bool(bad)}"))
            self.assertIn("investigator.impact@v26 needs its seed document", str(ctx.exception))


# ---------------------------------------------------------------- 5. contract negatives

class Provenance(V26Rig):
    def run_one(self):
        m = self.case12()
        self.seed = seed_doc()
        res, _ = self.record_v26(m)
        return load_trace(res.trace_path).events, payload(res, "VERIFY")["findings"][0]

    def test_witness_supported_is_bound_to_the_consensus_record(self):
        events, f = self.run_one()
        self.assertEqual(check_finding_provenance(f, events), [])
        ver = f["verification"]
        bad = {"other witness id": {**f, "verification": {**ver, "witnessRefs": [{"witness": 0, "witnessId": "ccbs-mini-1"}]}},
               "extra witness ref": {**f, "verification": {**ver, "witnessRefs": ver["witnessRefs"] * 2}},
               "reachable": {**f, "severityBasis": {**f["severityBasis"], "reachable": True}},
               "other seed index": {**f, "seedRef": {**f["seedRef"], "index": 0, "id": "ccbo-mini-0"}},
               "edited claim": {**f, "claim": f["claim"] + " (edited)"},
               "both sources": {**f, "sourceCallId": "call_0000000000000000"}}
        for name, g in bad.items():
            with self.subTest(name):
                self.assertNotEqual(check_finding_provenance(g, events), [])
        seed = next(e for e in events if e["type"] == "seed.input")
        no_con = [{k: v for k, v in e.items() if k != "consensus"} if e is seed else e for e in events]   # a v24 run's event
        self.assertNotEqual(check_finding_provenance(f, no_con), [])
        unsupported = copy.deepcopy(seed)
        row = unsupported["consensus"]["table"][2]
        row.update(pairs=[], votes=0, supported=False)
        self.assertNotEqual(check_finding_provenance(f, [unsupported if e is seed else e for e in events]), [])
        liar = copy.deepcopy(seed)
        liar["consensus"]["table"][2]["supported"] = False                  # votes 1 >= k but not supported: invalid event
        self.assertNotEqual(validate("TraceEvent", liar), [])
        self.assertNotEqual(check_finding_provenance(f, [liar if e is seed else e for e in events]), [])
        # an unsupported candidate's draft slipped into the event: the row refuses it
        forged = copy.deepcopy(seed)
        d0 = seeded.drafts({"items": S.ITEMS}, lambda p: ["def load_user(uid, cache, region):"] * 9, "x", None)[0][0][1]
        forged["drafts"].append({"index": 0, "id": "ccbo-mini-0", "draft": dict(d0, evidence=f["evidence"][:1] and
                                                                                [dict(seed["drafts"][0]["draft"]["evidence"][0])])})
        g = {**f, "id": hypothesis_id(seeded.AGENT, 0, S.ITEMS[0]["body"], "src/lib.py", 1), "claim": S.ITEMS[0]["body"],
             "seedRef": {**f["seedRef"], "index": 0, "id": "ccbo-mini-0"}}
        self.assertTrue(any("does not support this seed item" in str(i)
                            for i in check_finding_provenance(g, [forged if e is seed else e for e in events])))

    def test_verdict_variants(self):
        events, f = self.run_one()
        ver = f["verification"]
        for name, v in {"a call id": {**ver, "callIds": ["call_0000000000000000"]},
                        "evidence": {**ver, "evidence": f["evidence"]}, "no witness": {**ver, "witnessRefs": []},
                        "other rule": {**ver, "rule": "k6@0"}, "confirmed fields": {**ver, "verifierFamily": "x"},
                        "unknown verdict": {**ver, "verdict": "supported"}}.items():
            with self.subTest(name):
                self.assertNotEqual(validate("Finding", {**f, "verification": v}), [])
        # a confirmed verdict on a v26 seed item is refused (v26 publishes only witness-supported)
        conf = {**f, "verification": {"verdict": "confirmed", "refutationAttempts": 1, "verifierFamily": "claude", "notes": "",
                                      "evidence": f["evidence"], "callIds": ["call_0000000000000000"]}}
        self.assertEqual(validate("Finding", conf), [])
        self.assertTrue(any("only as witness-supported" in str(i) for i in check_finding_provenance(conf, events)))

    def test_v24_and_v21_findings_cannot_claim_witness_support(self):
        m = self.case12()
        self.seed = S.seed_doc(S.ITEMS)
        scr, _ = self.run24(m)
        res, _ = self.record_v24(m, scr)
        events = load_trace(res.trace_path).events
        f = payload(res, "VERIFY")["findings"][0]
        self.assertEqual(check_finding_provenance(f, events), [])
        g = {**f, "verification": {"verdict": K.VERDICT, "rule": K.RULE, "callIds": [], "evidence": [],
                                   "witnessRefs": [{"witness": 0, "witnessId": "ccbs-mini-0"}]},
             "severityBasis": {"impact": f["impact"], "reachable": False}}
        self.assertEqual(validate("Finding", g), [])
        self.assertTrue(any("needs its run's impact@v26 seed.input consensus record" in str(i)
                            for i in check_finding_provenance(g, events)))
        v21 = {k: v for k, v in g.items() if k != "seedRef"} | {"sourceCallId": "call_0000000000000000"}
        self.assertNotEqual(check_finding_provenance(v21, events), [])


# ---------------------------------------------------------------- 6. benchmark options, plan and live

class Options(TBH.Base):
    def test_v26_needs_a_seed_and_v21_takes_none(self):
        self.assertEqual(self.refused(impact_version=26),
                         "impact_version 26 needs seed_candidates (its candidate and witness answers)")
        self.assertEqual(self.refused(impact_version=24), "impact_version 24 needs seed_candidates (its candidate list)")
        for over in ({"seed_candidates": "x.json"}, {"seed_candidates": "x.json", "impact_version": 21}):
            with self.subTest(**over):
                self.assertEqual(self.refused(**over), "seed_candidates is only for impact_version 24 or 26 (a seed document path)")
        self.assertIn("seed_candidates: benchmark data, label, gold and competitor-review paths are not launch inputs",
                      self.refused(impact_version=26, seed_candidates=str(self.tmp / "gold.json")))

    def test_a_wrong_schema_seed_is_refused_before_any_run(self):
        before = self.w.state_bytes()
        for v, doc in ((26, S.seed_doc(S.ITEMS)), (24, seed_doc())):
            p = self.tmp / f"seed{v}.json"
            p.write_text(json.dumps(doc))
            with self.subTest(version=v):
                self.assertTrue(self.refused(impact_version=v, seed_candidates=str(p)).startswith("seed candidates refused: "))
        self.assertEqual(self.w.state_bytes(), before)
        self.assertIn("26", B._parser().format_help())


class ZeroRequestBenchmark(TBH.Base):
    """The claude-cli benchmark rig (CI.BenchmarkClaudeCli's setup; GATED benchmark.py): impact@v26 plans and runs with NO model
    request and no CLI spawn."""

    def setUp(self):
        super().setUp()                                        # v24 / v26 carry v21's $10 PACING Plan ceiling
        self.w.auth.write_text(json.dumps(dict(CI.SUB_ONLY, maxUsdMicrosPerRun=10_000_000)))
        base = dict(self.w.baseline_doc, reviewConfigDigest=resolve_config(CI.VARIANT).models.digest,
                    authorizationSha256="sha256:" + hashlib.sha256(self.w.auth.read_bytes()).hexdigest())
        self.w.write_roots(baseline=base)

    def seed_file(self, **kw):
        p = self.tmp / "seed26.json"
        p.write_text(json.dumps(seed_doc(**kw)))
        return str(p)

    def test_plan_is_a_zero_request_plan(self):
        before = self.w.state_bytes()
        with mock.patch.object(CI.O, "run_bounded_stream", side_effect=CI.no_cli):
            rep = B.run_benchmark(self.w.options(config=str(CI.VARIANT), impact_version=26, seed_candidates=self.seed_file()),
                                  key_loader=self.boom)
        self.assertEqual((rep["status"], rep["ok"]), ("planned", True), rep.get("plan"))
        p = rep["plan"]
        self.assertEqual((p["firstRequest"], p["capturedCount"], p["capturedRequests"], p["worstCaseAdmissionUsdMicros"]),
                         (None, 0, [], None))
        self.assertEqual(rep["zeroRequestRun"], {"behavior": K.BEHAVIOR, "capturedCount": 0, "status": "completed"})
        self.assertEqual(p["investigator"]["promptVersion"], INV26)
        self.assertEqual(rep["seedCandidates"], K.identity_doc(seed_doc()))
        self.assertFalse(any("no first request was captured" in u for u in rep["unmetGates"]))
        self.assertEqual(self.w.state_bytes(), before)
        # v24 on the same rig still needs (and captures) its first request: the zero-request rule is v26's only
        s24 = self.tmp / "seed24.json"
        s24.write_text(json.dumps(S.seed_doc([dict(S.ITEMS[0], file="README.md")])))
        with mock.patch.object(CI.O, "run_bounded_stream", side_effect=CI.no_cli):
            rep24 = B.run_benchmark(self.w.options(config=str(CI.VARIANT), impact_version=24, seed_candidates=str(s24)),
                                    key_loader=self.boom)
        self.assertNotIn("zeroRequestRun", rep24)                  # a v24 run that made no request is NOT a plan
        self.assertEqual((rep24["status"], rep24["plan"]["capturedCount"], rep24["plan"]["pipeline"]["status"]),
                         ("plan-failed", 0, "completed"))
        self.assertIn("no first request was captured: the pipeline never reached a model call", rep24["unmetGates"])

    def test_live_spawns_nothing(self):
        runners = []
        d, opts = CI.cli_live(self.w, self.tmp, config=str(CI.VARIANT), impact_version=26, seed_candidates=self.seed_file())
        factory = CI.scripted_claude([], runners)
        snaps = []

        def live_terra(profile, ledger, scope, snapshot=None):    # v26's profile is agentic (v24's): the PR snapshot is built
            snaps.append(snapshot)
            return factory(profile, ledger, scope)
        with mock.patch.object(B, "live_terra", side_effect=live_terra), \
                mock.patch.object(B, "OpenRouterProvider", side_effect=AssertionError("no OpenRouter adapter")):
            rep = B.run_benchmark(opts, key_loader=self.boom, transport=lambda *a: self.fail("OpenRouter must not be used"))
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 0), rep.get("error"))
        self.assertEqual((runners, snaps), ([], []))          # no claude-cli adapter, preflight, spawn or PR snapshot at all
        ledger = d / CI.TERRA_LEDGER_NAME
        self.assertEqual(ledger.read_text().splitlines() if ledger.exists() else [], [])
        events = [json.loads(x) for x in Path(rep["paths"]["trace"]).read_text().splitlines()]
        self.assertEqual([e for e in events if e.get("type") in ("model.call", "cost")], [])
        self.assertEqual(rep["seedCandidates"]["rule"], K.RULE)


# ---------------------------------------------------------------- 7. V24 parity

class V24Parity(unittest.TestCase):
    def test_v24_recordings_are_byte_identical_to_the_pre_change_source(self):
        pins = json.loads((ROOT / "tests/pipeline/v24_pins_2bae112.json").read_text())
        buf = io.StringIO()
        with redirect_stdout(buf):
            runpy.run_path(str(ROOT / "tests/pipeline/v24_pin_scenarios.py"), run_name="__main__")
        self.assertEqual(json.loads(buf.getvalue()), pins)
        self.assertEqual(set(pins), {"e2e", "live"})
        self.assertFalse(Engine.__dict__.get("v26", False))


if __name__ == "__main__":
    unittest.main()
