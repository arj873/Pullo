"""Real score-family Gateway + scripted provider composition for two tools (no network, invented data)."""
from __future__ import annotations

import copy
import json
import tempfile

from tests.score_protocol_review.common import A, CFG, JUDGE, REF, case, P
from tests.score_gateway import helpers as H
from reviewer.benchmark.reference_graph import score_reference_case

PROFILE = CFG.profile(H.PROFILE["roles"]["extractor"]["price"])


def make_gateway(tmp, script):
    from reviewer.contracts.budget import STANDARD_S0A_BUDGET
    from reviewer.contracts.canonical import score_run_id
    from reviewer.gateway import Gateway, Recorder, ScriptedScoreProvider, SpendBook
    h = H.handle(tmp)
    prov = ScriptedScoreProvider(script)
    seen = []
    orig = prov.call
    prov.call = lambda req, key: (seen.append(copy.deepcopy(req)), orig(req, key))[1]
    rid = score_run_id(H.EVR, H.CASE, 0)
    rec = Recorder(rid, None, family="score")
    gw = Gateway(mode="live", profile=PROFILE, budget={**STANDARD_S0A_BUDGET, "maxUsdMicros": 4_000_000}, run_id=rid, family="score",
                 providers={"anthropic": prov}, authorization=h, book=SpendBook(h), recorder=rec, eval_run_id=H.EVR,
                 eval_case_id=H.CASE, repeat=0, clock=H.NOW)
    rec.start(H.run_doc("live", h=h, profile=REF))
    return gw, rec, prov, seen


def run_two_tool_complete(t):
    tools = ("zeta-tool", "alpha-tool")
    c = case(tools, ngold=2)
    ms = [A.build_mapping(c, tool, f"u001-t{n:02d}") for n, tool in enumerate(tools, 1)]
    ext = {"candidates": [{"sourceCommentId": "c001", "start": 0, "end": 11}, {"sourceCommentId": "c002", "start": 11, "end": 12}]}   # v3 spans
    entries = []
    for m in ms:
        entries.append(("extractor", 0, "response", H.response("extractor", ext), m.agent))
    for m in ms:
        entries.append(("deduper", 0, "response", H.response("deduper", {"groups": [[0], [1]]}), m.agent))
    for m in ms:
        entries += [("matcher", i, "response", H.response("matcher", {"match": i % 2 == 0, "confidence": 0.25 * (i + 1)}), m.agent) for i in range(4)]
    with tempfile.TemporaryDirectory() as tmp:
        gw, rec, prov, seen = make_gateway(tmp, H.script(entries))
        exts = [A.run_extract(gw.call, CFG, REF, m) for m in ms]
        dds = [A.run_dedup(gw.call, CFG, REF, m, e) for m, e in zip(ms, exts)]
        t.assertEqual(prov.calls, 4)                                  # all extraction + dedup, ZERO pairs so far
        g = A.gate(exts, dds)
        plans, over = A.plan_pairs(CFG, REF, [(m, e) for m, e in zip(ms, exts)])
        adm = A.admit_complete_set(g, plans, over, lambda p: sum(len(x.requests) for x in p) == 8)
        t.assertEqual((g.ok, adm.admitted, adm.pairs), (True, True, 8))
        prs = [A.run_pairs(gw.call, adm, p) for p in plans]
        t.assertEqual((prov.calls, prov.missing), (12, []))
        H.finish(gw, rec)
    reqs = [json.dumps({k: v for k, v in r.items() if k != "messages"}, sort_keys=True) for r in seen]
    t.assertEqual(len(set(reqs[:2])), 1)                              # extraction settings identical across the two tools
    t.assertEqual({r["model"] for r in seen}, {"anthropic/claude-opus-5.5"})
    t.assertTrue(all(r["tools"] == [] for r in seen))
    wire = json.dumps(seen)
    for leak in ("REALCID", "REALGOLD", "zeta-tool", "alpha-tool", "temperature", "top_p", "effort"):
        t.assertNotIn(leak, wire)
    for m, e, d, pr in zip(ms, exts, dds, prs):
        score_reference_case(c, A.build_document(m, e, d, pr, JUDGE))
    att = A.attempt_set(exts, dds, adm, prs)
    t.assertTrue(att["complete"])
