"""V19 AGENTIC: investigator.impact@v19 = impact@v16's one reviewer as ONE agentic read-only claude-cli session
(claude-cli-isolated@6: the investigator role carries params.agentic, the gateway reserves the session budget, the live
host opens the adapter with the run's exported PR snapshot), v16's VERIFY, and a JUDGE rule that drops findings the judge
leaves out as without a concrete wrong behaviour; v19 Plans carry the $10 ceiling. reviewer.pipeline.agentic.

Invented self-contained fixtures (the v12/v16 rig), a scripted synthetic provider standing in for the agentic claude-cli
adapter (ccprov's runtime tests prove the session itself), the real engine, contracts, gateway and tools. No network,
key, state, CLI or live call. These tests prove the mechanics; they do NOT show that a real model finds more."""

from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import unittest
from pathlib import Path
from unittest import mock

from reviewer.config import resolve_config
from reviewer.contracts import validate
from reviewer.contracts.entities import validate_trace
from reviewer.gateway import DisabledProvider, SpendBook, trusted_authorization
from reviewer.gateway.providers import SyntheticProvider
from reviewer.pilot import providers as PV
from reviewer.pilot import repository as REPO
from reviewer.pilot import repository_profile as RP
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.pipeline import PipelineError, RecordBackend, RetrievalPolicy, agentic, identity, prompts, whole
from reviewer.pipeline import load_result
from reviewer.runtime.catalog import CLAUDE_CLI_DEFAULT_MODEL, claude_cli_agentic_spec

from tests.pipeline.helpers import NOW, SpyProvider, entry, events_of, judge, model_calls, resp, script, tool_calls
from tests.pipeline.test_coverage_v12 import ROOT, final, hid, inv_calls, md_of, payload, rf, turn, vdone
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PROFILE
from tests.pipeline.test_whole_v16 import V16_PLAN, V16_POLICY, V16_PROFILE, V16Rig, comments_of

INV19, VER = prompts.INVESTIGATOR_IMPACT_V19_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
CLI = CLAUDE_CLI_DEFAULT_MODEL
V19_PROFILE = copy.deepcopy(V3_PROFILE)       # the real v19 claude-cli investigator role; the other roles synthetic
V19_PROFILE["roles"]["investigator"] = copy.deepcopy(RP.repository_profile(
    True, resolve_config(ROOT / "pullo-claude-cli-sj.toml").models, impact_version=19)["roles"]["investigator"])
V19_POLICY = RetrievalPolicy(investigator_prompt=INV19, verifier_prompt=VER, run_tool_calls=400)
V19_PLAN = copy.deepcopy(V16_PLAN)
V19_PLAN["specialists"] = agentic.plan_specialists()
V19_PLAN["budget"]["maxUsdMicros"] = RP.V19_RUN_CEILING_USD_MICROS
A, R = agentic.AGENT, agentic.AGENT + whole.REASK_SUFFIX
USAGE = {"uncachedInputTokens": 20_000, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 2_000,
         "reasoningTokens": 0}             # a session reports its measured usage (the gateway settles it, not the budget)
AUTH19 = {"schema": "spend-authorization@1", "id": "v19-test", "issuedBy": "operator", "expiresAt": "2099-01-01T00:00:00Z",
          "purpose": "offline v19 test, scripted providers", "providers": ["synthetic", "claude-cli"],
          "models": ["synthetic-fixture", CLI], "maxUsdMicrosPerRun": 10_000_000, "maxUsdMicrosTotal": 100_000_000}


def cli(agent, ordinal, output, attempt=0):
    """A scripted answer of the agentic claude-cli session (one call; it explored inside its sandbox)."""
    r = resp({"contextRequests": [], "output": output})
    r["resolvedModel"], r["usage"] = CLI, dict(USAGE)
    return entry("INVESTIGATE", "investigator", agent, ordinal, attempt, response=r)


def cli_bad(agent, ordinal):
    return [entry("INVESTIGATE", "investigator", agent, ordinal, a, response=dict(
        resp(None, status="invalid-output", raw="{half"), resolvedModel=CLI, usage=dict(USAGE))) for a in (0, 1)]


class FakeAgentic:
    """Stands in for the agentic claude-cli adapter at the provider boundary (the session itself is ccprov's, proven in
    tests/runtime/test_claude_agentic): serves the scripted answer of a session and records each request; a claude-cli
    request without params.agentic is refused (only the v19 investigator is agentic here)."""
    name = "claude-cli"

    def __init__(self, scr):
        self.inner = SyntheticProvider(scr)
        self.requests: list = []

    @property
    def calls(self):
        return self.inner.calls

    def call(self, request, key):
        self.requests.append(copy.deepcopy(request))
        if "agentic" not in (request.get("params") or {}):
            raise ValueError("the fake agentic adapter serves agentic requests only")
        return self.inner.call(dict(request, provider="synthetic"), key)


class V19Rig(V16Rig):
    def setUp(self):
        super().setUp()
        (self.tmp / "operator/auth.json").write_text(json.dumps(AUTH19))
        self.handle = trusted_authorization(self.tmp / "operator/auth.json", forbidden_roots=[self.tmp / "cases"])
        self.book = SpendBook(self.handle)

    def record_backend(self, scr):
        spy = SpyProvider(scr)
        self.spies.append(spy)
        self.agentic = FakeAgentic(scr)
        providers = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai"), "synthetic": spy,
                     "claude-cli": self.agentic}
        return RecordBackend(self.handle, self.book, providers, lambda: NOW), spy

    def record_v19(self, m, scr, **kw):
        kw.setdefault("profile", V19_PROFILE)
        kw.setdefault("retrieval", V19_POLICY)
        kw.setdefault("plan", V19_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v19(self, m, res, **kw):
        kw.setdefault("profile", V19_PROFILE)
        kw.setdefault("retrieval", V19_POLICY)
        kw.setdefault("plan", V19_PLAN)
        return self.replay(m, res, **kw)

    def run19(self, m, judged=(0, 1, 2), session=None, judge_entry=None):
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = session if session is not None else [cli(A, 0, {"hypotheses": [hl, hb, hs]})]
        ag = R if session is not None and any(x["agentId"] == R for x in session) else A
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), vdone("verifier-02", m, path="src/handlers/b.py", line=2),
              vdone("verifier-03", m, path="src/svc.py", line=2)]
        ids = [hid(ag, n, h) for n, h in enumerate((hl, hb, hs))]
        e += [judge_entry] if judge_entry is not None else [judge(*[w([ids[n]]) for n in judged])]
        return script(*[x for x in e if x is not None]), ids


# ---------------------------------------------------------------- 1. pure rules, profile, Plan, ceiling

class Rules(unittest.TestCase):
    def test_profile_plan_policy_identity(self):
        self.assertEqual(RP.IMPACT_VERSIONS[19], INV19)
        self.assertEqual(claude_cli_agentic_spec({"agentic": agentic.spec()}), agentic.spec())
        c = resolve_config(ROOT / "pullo-claude-cli-sj.toml").models
        p16, p19 = RP.repository_profile(True, c, impact_version=16), RP.repository_profile(True, c, impact_version=19)
        self.assertEqual(validate("ModelProfile", p19), [])
        self.assertEqual(p19["roles"]["investigator"]["params"], dict(p16["roles"]["investigator"]["params"],
                                                                     agentic=agentic.spec()))
        self.assertEqual({r: s for r, s in p19["roles"].items() if r != "investigator"},
                         {r: s for r, s in p16["roles"].items() if r != "investigator"})      # only the investigator is agentic
        for live in (True, False):
            a, b = RP.repository_plan(p16, live_stage_timing=live), RP.repository_plan(p19, live_stage_timing=live)
            self.assertEqual(validate("Plan", b), [])
            self.assertEqual(dict(b["budget"], maxUsdMicros=0), dict(a["budget"], maxUsdMicros=0))
            self.assertEqual((a["budget"]["maxUsdMicros"], b["budget"]["maxUsdMicros"]), (4_000_000, 10_000_000))
            self.assertEqual(b["specialists"], ["whole", "agentic"])
        self.assertEqual(RP.repository_plan(p19, live_stage_timing=True)["budget"]["stageCeilingsSec"]["INVESTIGATE"],
                         1800)                                                    # a 900 s session and its re-ask
        with self.assertRaises(Exception) as ctx:                                 # a claude-cli investigator only
            RP.repository_profile(True, None, impact_version=19)
        self.assertIn("needs a claude-cli investigator", str(ctx.exception))
        pol = RP.repository_policy(True, impact_version=19)
        self.assertEqual((pol.agentic_review, pol.whole_change, pol.impact, pol.run_tool_calls), (True, True, True, 400))
        self.assertFalse(RP.repository_policy(True, impact_version=16).agentic_review)
        t19 = prompts.impact_template_digests(INV19)
        self.assertEqual({k: v for k, v in t19.items() if k != "agenticReview"},
                         prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_V16_PROMPT))
        self.assertEqual(prompts.v19_judge_task(V3_PROFILE["roles"]["judge"]["promptVersion"]),
                         prompts.judge_task(V3_PROFILE["roles"]["judge"]["promptVersion"]) + " " + prompts.V19_JUDGE_RULE)
        d = agentic.identity_doc(V19_POLICY, V19_PLAN["budget"], 50, 5)
        self.assertEqual((d["session"]["maxRequests"], d["session"]["sessionDeadlineSec"], d["session"]["budgetUsdMicros"],
                          d["judge"]["dropReason"]), (30, 900, 5_000_000, "below-threshold"))

    def test_live_hosts_accept_exactly_each_plans_reviewed_ceiling(self):
        class Ledger:
            def totals(self):
                return {"committedUsdMicros": 0}
        c = resolve_config(ROOT / "pullo-claude-cli-sj.toml").models
        p19 = RP.repository_plan(RP.repository_profile(True, c, impact_version=19), live_stage_timing=True)
        p16 = RP.repository_plan(RP.repository_profile(True, c, impact_version=16), live_stage_timing=True)
        REPO._check_ceiling(Ledger(), p19)
        REPO._check_ceiling(Ledger(), p16)
        for plan, micros in ((p19, RUN_CEILING_USD_MICROS), (p16, RP.V19_RUN_CEILING_USD_MICROS)):
            with self.subTest(plan=plan["specialists"]), self.assertRaises(REPO.RepositoryError):
                REPO._check_ceiling(Ledger(), dict(plan, budget=dict(plan["budget"], maxUsdMicros=micros)))
        for v in sorted(set(RP.IMPACT_VERSIONS) - set(RP.ALT_IMPACT_VERSIONS) - {19}):   # no other Plan may carry it
            p = RP.repository_plan(RP.repository_profile(True, None, impact_version=v))
            with self.subTest(v=v), self.assertRaises(REPO.RepositoryError):
                REPO._check_ceiling(Ledger(), dict(p, budget=dict(p["budget"], maxUsdMicros=RP.V19_RUN_CEILING_USD_MICROS)))


# ---------------------------------------------------------------- 2. end to end through the gateway

class EndToEnd(V19Rig):
    def test_one_agentic_session_then_verify_and_the_judge_rule(self):
        m = self.case12()
        scr, ids = self.run19(m, judged=(0, 1))                                  # the judge leaves the third out
        res, spy = self.record_v19(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        calls = inv_calls(res)
        self.assertEqual([(e["agentId"], e["request"]["hop"]) for e in calls], [(A, 0)])
        self.assertEqual(calls[0]["request"]["params"]["agentic"], agentic.spec())
        self.assertEqual((calls[0]["request"]["provider"], calls[0]["request"]["model"]), ("claude-cli", CLI))
        cost = next(e["record"] for e in events_of(res) if e["type"] == "cost" and e["record"]["callId"] == calls[0]["callId"])
        self.assertEqual(cost["reservedUsdMicros"], agentic.BUDGET_USD_MICROS)   # the gateway reserves the session budget
        self.assertFalse([t for t in tool_calls(res) if t["agentId"] == whole.HEAD_AGENT])   # no host head reads
        d = doc_of(calls[0]["request"])
        self.assertEqual(d["task"], prompts.V19_WHOLE_TASK)
        self.assertEqual(d["agenticReview"], prompts.agentic_block(agentic.spec()))
        self.assertTrue(d["wholeChange"]["diffsShown"] > 0 and not [c for c in d["context"] if c["tool"] == "read_file"])
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")], ["verifier-01", "verifier-02", "verifier-03"])
        self.assertFalse(any("agentic" in (e["request"].get("params") or {}) for e in model_calls(res, "VERIFY")
                             + model_calls(res, "JUDGE")))                       # only the investigator is agentic
        jreq = model_calls(res, "JUDGE")[0]["request"]
        self.assertTrue(doc_of(jreq)["task"].endswith(prompts.V19_JUDGE_RULE))
        self.assertEqual(len(doc_of(jreq)["verifiedFindings"]), 3)                     # the judge sees every finding
        drops = payload(res, "JUDGE")["drops"]
        self.assertEqual([(x["subjectIds"], x["reason"]) for x in drops], [([ids[2]], "below-threshold")])
        self.assertIn("judge-concrete@1", drops[0]["detail"])
        self.assertEqual(sorted(c["findingIds"][0] for c in comments_of(res)), sorted(ids[:2]))
        md = md_of(res)
        self.assertIn("Agentic whole-change review (agentic-whole-review@1)", md)
        self.assertIn("1 agentic session(s) (claude-cli-isolated@6", md)
        self.assertIn("JUDGE rule (judge-concrete@1): 1 finding(s) left out", md)

    def test_the_judge_sees_every_finding_even_beyond_the_cap_and_the_cap_applies_after_its_drops(self):
        m = self.case12()
        scr, ids = self.run19(m, judged=(1, 2))                                  # the judge leaves the first out
        res, _ = self.record_v19(m, scr, comment_cap=2)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(len(doc_of(model_calls(res, "JUDGE")[0]["request"])["verifiedFindings"]), 3)
        drops = payload(res, "JUDGE")["drops"]
        self.assertEqual([(x["subjectIds"], x["reason"]) for x in drops], [([ids[0]], "below-threshold")])
        self.assertEqual(sorted(c["findingIds"][0] for c in comments_of(res)), sorted(ids[1:]))   # 2 left, cap 2: no over-cap

    def test_one_hop_a_session_asking_for_context_runs_no_host_read_and_is_re_asked_for_its_answer(self):
        m = self.case12()
        hl = self.h_lib(m)
        ask = cli(A, 0, None)
        ask["response"]["output"] = {"contextRequests": [rf("src/use.py", 1, 7)], "output": None}
        scr = script(ask, cli(R, 0, {"hypotheses": [hl]}), vdone("verifier-01", m, path="src/lib.py", line=1),
                     judge(w([hid(R, 0, hl)])))
        res, _ = self.record_v19(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        first = inv_calls(res, A)
        self.assertEqual(len(first), 1)                                          # one hop: its request is the last turn
        self.assertTrue(doc_of(first[0]["request"])["retrieval"]["lastTurn"])
        self.assertFalse([t for t in tool_calls(res) if t["stage"] == "INVESTIGATE" and "requestedBy" in t])
        self.assertEqual([(a["agentId"], a["status"]) for a in payload(res, "INVESTIGATE")["agents"]],
                         [(A, "failed"), (R, "completed")])

    def test_strict_replay_load_and_identity(self):
        m = self.case12()
        scr, _ = self.run19(m)
        res, _ = self.record_v19(m, scr)
        rep = self.replay_v19(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        self.assertEqual(load_result(self.out, res.run_id).status, "completed")
        backend, _ = self.record_backend(scr)
        spec = self.spec(m, backend, profile=V19_PROFILE, plan=V19_PLAN, retrieval=V19_POLICY)
        cfg = identity.config_snapshot_id(spec)
        with mock.patch.object(agentic, "MAX_REQUESTS", 29):
            self.assertNotEqual(cfg, identity.config_snapshot_id(spec))
        with self.assertRaises(PipelineError):                                  # the Plan must name the agentic marker
            self.record_v19(m, scr, plan=V16_PLAN)

    def test_a_judge_that_is_unavailable_drops_nothing(self):
        m = self.case12()
        scr, ids = self.run19(m, judge_entry=entry("JUDGE", "judge", "judge", 0, error={
            "code": "provider-error", "message": "scripted", "retryable": False, "stage": "JUDGE",
            "detail": {"outcome": "rejected-before-processing"}}))
        res, _ = self.record_v19(m, scr)
        self.assertFalse([x for x in payload(res, "JUDGE")["drops"] if x["reason"] == "below-threshold"])
        self.assertEqual(len(comments_of(res)), 3)                               # deterministic wording, as v16

    def test_a_rejected_judge_output_drops_nothing(self):
        m = self.case12()
        scr, ids = self.run19(m, judge_entry=judge(w(["hyp_" + "0" * 16])))      # names no surviving finding
        res, _ = self.record_v19(m, scr)
        self.assertIn(("JUDGE", "agent-failure"), [(i["stage"], i["reason"]) for i in res.incomplete])
        self.assertFalse([x for x in payload(res, "JUDGE")["drops"] if x["reason"] == "below-threshold"])
        self.assertEqual(len(comments_of(res)), 3)

    def test_an_out_of_schema_session_is_re_asked_as_a_second_agentic_session(self):
        m = self.case12()
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        scr, ids = self.run19(m, session=[*cli_bad(A, 0), cli(R, 0, {"hypotheses": [hl, hb, hs]})])
        res, _ = self.record_v19(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        calls = inv_calls(res)
        self.assertEqual([e["agentId"] for e in calls], [A, A, R])              # the call, its one repair, the re-ask
        self.assertTrue(all(e["request"]["params"]["agentic"] == agentic.spec() for e in calls))
        self.assertEqual(len(comments_of(res)), 3)

    def test_v16_is_untouched_by_the_v19_paths(self):
        from tests.pipeline.test_whole_v16 import V16Rig as R16
        self.assertTrue(issubclass(R16, V16Rig))
        self.assertFalse(agentic.is_v19_plan(V16_PLAN) or agentic.is_agentic_profile(V16_PROFILE))
        self.assertTrue(whole.is_v16_plan(V16_PLAN) and not whole.is_v16_plan(V19_PLAN))


# ---------------------------------------------------------------- 3. the host: the PR snapshot and the agentic adapter

class Host(V19Rig):
    def test_export_snapshot_writes_verified_files_privately_and_leaves_out_links_git_and_env(self):
        files = {"src/a.py": "A = 1\n", ".env": "SECRET=1\n", ".git/config": "[core]\n", "run.sh": "echo hi\n",
                 "docs/x.md": "x\n"}
        m = self.mini("snap", base=files, head=dict(files, **{"src/a.py": "A = 2\n"}))
        snap, parent = PV.export_snapshot(m.base, m.head)
        try:
            self.assertEqual(snap.problems(), [])
            self.assertEqual(stat.S_IMODE(os.stat(parent).st_mode), 0o700)
            self.assertEqual(Path(snap.head, "src/a.py").read_text(), "A = 2\n")
            self.assertEqual(Path(snap.base, "src/a.py").read_text(), "A = 1\n")
            for top in (".env", ".git"):
                self.assertFalse(Path(snap.head, top).exists())
            self.assertFalse(str(parent).startswith(str(Path.home())))
        finally:
            shutil.rmtree(parent)

    def test_f3_every_exported_file_is_fresh_even_when_the_source_tree_is_hard_linked(self):
        files = {"src/a.py": "SAME = 1\n", "src/b.py": "SAME = 1\n"}
        m = self.mini("links", base=files, head=files)
        head_root = Path(m.head.root)
        os.unlink(head_root / "src/b.py")                                      # the source tree now holds a hard link
        os.link(head_root / "src/a.py", head_root / "src/b.py")
        from reviewer.runtime.claude_agentic import Snapshot
        self.assertTrue(any("hard link" in x for x in Snapshot(head=str(head_root)).problems()))   # F3 is live
        snap, parent = PV.export_snapshot(m.base, m.head)
        try:
            self.assertEqual(snap.problems(), [])
            for root in (snap.head, snap.base):
                for f in Path(root).rglob("*"):
                    if f.is_file():
                        self.assertEqual(os.lstat(f).st_nlink, 1, f)
            self.assertEqual(Path(snap.head, "src/b.py").read_text(), "SAME = 1\n")
        finally:
            shutil.rmtree(parent)

    def test_live_terra_opens_the_adapter_agentic_with_the_snapshot_and_refuses_without_one(self):
        c = resolve_config(ROOT / "pullo-claude-cli-sj.toml").models
        p19, p16 = RP.repository_profile(True, c, impact_version=19), RP.repository_profile(True, c, impact_version=16)
        seen = []

        def factory(**kw):
            seen.append(kw)
            return DisabledProvider("claude-cli")
        with self.assertRaises(PipelineError) as ctx:
            PV.live_terra(p19, None, "scope", claude_factory=factory)
        self.assertIn("needs the run's PR snapshot", str(ctx.exception))
        snap = object()
        PV.live_terra(p19, None, "scope", claude_factory=factory, snapshot=snap)
        PV.live_terra(p16, None, "scope", claude_factory=factory)
        self.assertEqual((seen[0]["agentic"], seen[0]["agentic_snapshot"]), (True, snap))
        self.assertNotIn("agentic", seen[1])                                     # v16 opens the adapter exactly as before



# ---------------------------------------------------------------- 4. parity: v16 unchanged

# impact@v16 recordings (e2e, reviewer re-ask, verifier re-ask note, limit re-ask) made on the PRE-CHANGE source f4fb624
# (equal to 9ca3210's) with the same rig (/var/tmp/pullo-cap150/v16work/pin_v16.py); this branch must reproduce them byte
# for byte (v12 and older: test_whole_v16.V12Parity and test_coverage_v12).
PRE_V19_V16_PINS = json.loads('{"e2e": {"INVESTIGATE": "sha256:bf83fe9f3cdd50bbce90cee8d3885d346851c6db5b6656d044ec83459eea4e12", "PUBLISH": "sha256:cc87c000468053ce75253435c110ff5063707ff2e9fdbacba6e7b874bc68e76f", "VERIFY": "sha256:1e35f18422b104a338ab4dc00512e27918007572a2905393fcd26a03ab8d403c", "cfg": "sha256:6278b96cdc0f028e5410d5167c1ba50046dac175da156abf81fd69860aad26a1", "requests": ["sha256:210027a8e9f73fe5425c9cb3913fe12ab486eb8f223c2be67e48acfb1624e60e", "sha256:eca2ad05a66a069a2c6c5c3e225a7bfa82200d5ec3db1af9661474a0a7b99c73", "sha256:8509717d1077e9a1566fbd2f47ad0b9e163dee62b5f317052547124607cf8b10", "sha256:7f965a73f4f31cbf7b828bd38f3336a7b81ae7f76a708166de3b939a00af5ae1", "sha256:3914c2de10447086c6939c06eb8b0ae217d2faffd3a6cc3a49776adf246b11ee", "sha256:2a6536e7e0199bcd9eab60ca795728410d78c07a695079b81671415aa53c5620"], "trace": "sha256:90f3c2925072817a4f65797c78f52d2cf2b0622cef4516c11b28c1ad91d2e232"}, "limit_reask": {"INVESTIGATE": "sha256:b292cd9acde83ca0471bbaf2a10b50e7e99ba7fb90b523de0899488da58fa055", "PUBLISH": "sha256:1eb9e8410cdc7c1689a81c482b6a856da3d126fd27d9474046f1698e8f17ea4a", "VERIFY": "sha256:be35f609c7a6488972cad2fac877d3085d5937fb17509caf821df01d161290b7", "cfg": "sha256:6278b96cdc0f028e5410d5167c1ba50046dac175da156abf81fd69860aad26a1", "requests": ["sha256:210027a8e9f73fe5425c9cb3913fe12ab486eb8f223c2be67e48acfb1624e60e", "sha256:893269f13b3d5db64ea59ad11383540cbf35abeb666cb436b7e0e9b514ede98e", "sha256:a9c2dc06ffc1db9141e617491560d6e285c43aa784d3abf47774819d2f33c0ae", "sha256:bc1de3b64be3c2f9f7bd4dd0a23dd18c5bac5f32f5b476282d01ff000887efc2", "sha256:cedb3b5e9f5c46817be94de320e47794a1d870360506da3ddcc8f38343d35af9", "sha256:86cc67a2c315a333363a917619b2b454363105be4c047f89392377e51f0ff1c5"], "trace": "sha256:7551ca4f582d305115df8d88505afac352c9d42167e04b95ae35fbfef89979c3"}, "reviewer_reask": {"INVESTIGATE": "sha256:895cb054b5e0824b751fc500da606c827bf4d22f2c43c7f170e50ac93900fe4a", "PUBLISH": "sha256:25f0577a0aff4ea4319d5ab99413acb264337d85640f228c967a268920878aab", "VERIFY": "sha256:58282967bccd7fc81b3cb1f45eb93308e5799a984b21765ded4fe70624bdc418", "cfg": "sha256:6278b96cdc0f028e5410d5167c1ba50046dac175da156abf81fd69860aad26a1", "requests": ["sha256:210027a8e9f73fe5425c9cb3913fe12ab486eb8f223c2be67e48acfb1624e60e", "sha256:44fecf4dacddfe4efaeac75696ede3386cb4e2ef247903d5daa480d38aa45524", "sha256:760494b798d3b893d265e659be279d1bc7d5f7d14693403eb35d14895f28a1ec", "sha256:210027a8e9f73fe5425c9cb3913fe12ab486eb8f223c2be67e48acfb1624e60e", "sha256:9241b3d6db4a70fb989e90d87b0d8fdc913f63fc1580af859dc32ef1eb55440e", "sha256:cedb3b5e9f5c46817be94de320e47794a1d870360506da3ddcc8f38343d35af9", "sha256:9ecc11bb31877237bf1c9ae0f0a4a5c2afda49ea5a4a45c02b3bb641a16b509b", "sha256:3603b17f9deb02d5e4533912087025bcfa176eb7e336474b8eece39b0e35100f", "sha256:dc058382148984c93bcf54a2f140abffed22dcd9e88bf582eb75f8d56b6480f6"], "trace": "sha256:2b3c406e75935063e16919c421827b2d0a2b297adf12f73c3db6b392d27422f6"}, "verifier_note": {"INVESTIGATE": "sha256:bf83fe9f3cdd50bbce90cee8d3885d346851c6db5b6656d044ec83459eea4e12", "PUBLISH": "sha256:e47adf5c2fba4f338bb0c50accbd6666dcefcd18f918f4920842f74f1a087fc4", "VERIFY": "sha256:c0f401cc0b10fc4ef4f8e45a59aeb96c1e7cb953072f7de2412d58d990fe168f", "cfg": "sha256:6278b96cdc0f028e5410d5167c1ba50046dac175da156abf81fd69860aad26a1", "requests": ["sha256:210027a8e9f73fe5425c9cb3913fe12ab486eb8f223c2be67e48acfb1624e60e", "sha256:eca2ad05a66a069a2c6c5c3e225a7bfa82200d5ec3db1af9661474a0a7b99c73", "sha256:8509717d1077e9a1566fbd2f47ad0b9e163dee62b5f317052547124607cf8b10", "sha256:d6ecc7a43ccd4db587990ac5f4321dd368fc8c61758770681dcf196605d9235c", "sha256:93a49708446799aeb0bf92303dda06df4052ecd21b1f8ab9875a63916f23de76", "sha256:7477ec681e3f59fd005757fea920d99296b51c469ede821d9bf78ba911bfd13d", "sha256:7f965a73f4f31cbf7b828bd38f3336a7b81ae7f76a708166de3b939a00af5ae1", "sha256:3914c2de10447086c6939c06eb8b0ae217d2faffd3a6cc3a49776adf246b11ee", "sha256:eda22ef3b59b9cd433bf2adb9304d682b12c5565d0f64f8543e0abd9642aa9c3"], "trace": "sha256:2de4cccdd8e08a6ad751e21f5c152902675d2ed5037c6ca072cd595a878d8178"}}')


class V16Parity(unittest.TestCase):
    def test_v16_recordings_are_byte_identical_to_the_pre_change_source(self):
        import io
        import runpy
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            runpy.run_path(str(ROOT / "tests/pipeline/v16_pin_scenarios.py"), run_name="__main__")
        self.assertEqual(json.loads(buf.getvalue()), PRE_V19_V16_PINS)


if __name__ == "__main__":
    unittest.main()
