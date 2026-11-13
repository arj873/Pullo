"""TOURNAMENT-V10: investigator.impact@v10 = the impact@v3 configuration UNCHANGED (contracts, logic, safety with the v3
lens texts, per-lane tool/spend/time numbers, v3 VERIFY and verifier) plus the same three lenses run again as
`contracts.alt`, `logic.alt`, `safety.alt` on an ALTERNATE investigator model (`[review.investigator_alt]` ->
ModelProfile.alternates.investigator), merged restatement-only (cross-model-merge@1).

Invented self-contained fixtures, scripted synthetic providers that answer PER MODEL (a lane sent to the wrong model gets
no scripted answer), the real engine, contracts, gateway and tools. No network, key, state or live call. These tests
prove the mechanics (the v3 lanes keep exactly v3's lane specs and requests, refusal without an alternate, the
alternate-model spend cap inside v3's investigation share, lane ids, restatement-only merge, v3 VERIFY, identity binding,
strict replay and load, v3 and v7 byte identity); they do NOT show that a second model finds more real defects."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from reviewer.config import ReviewModels, resolve_config
from reviewer.contracts import validate
from reviewer.contracts.budget import HOST_STOP_RECORDING, investigation_limit, stage_ceiling
from reviewer.contracts.canonical import digest
from reviewer.contracts.entities import validate_trace
from reviewer.gateway import DisabledProvider
from reviewer.pipeline import PipelineError, RecordBackend, RetrievalPolicy, identity, lanes, prompts, run_review
from reviewer.pipeline import specialists, sweeps

from tests.pipeline.helpers import NOW, events_of, hyp, judge, model_calls, script, vfinal
from tests.pipeline.test_cross_model_v7 import (ALT_MODEL, ALT_PRICE, MAIN_MODEL, V1_V5_REPO, V7_PLAN, V7_POLICY,
                                                V7_PROFILE, CrossRig, PerModel, answered_by, repo_identity)
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PLAN, V3_POLICY, V3_PROFILE, ask, inv_calls, sfail, sfinal, shid

ROOT = Path(__file__).resolve().parents[2]
INV10, VER = prompts.INVESTIGATOR_IMPACT_V10_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
V3_LANES = ("contracts", "logic", "safety")
ALT = ("contracts.alt", "logic.alt", "safety.alt")
ALL = V3_LANES + ALT

V10_PROFILE = copy.deepcopy(V3_PROFILE)
V10_PROFILE["roles"]["investigator"]["promptVersion"] = INV10
V10_PROFILE["alternates"] = {"investigator": dict(copy.deepcopy(V10_PROFILE["roles"]["investigator"]), model=ALT_MODEL,
                                                  price=ALT_PRICE)}
V10_POLICY = RetrievalPolicy(investigator_prompt=INV10, verifier_prompt=VER, run_tool_calls=220)
V10_PLAN = copy.deepcopy(V3_PLAN)
V10_PLAN["specialists"] = list(ALL)
V10_PLAN["budget"].update(maxToolCalls=220, stageCeilingsSec={"INVESTIGATE": 240})    # as repository_plan builds it

# impact@v7 recording and repository identity from the pre-change source (e0118001, the gated v7 head):
# CrossRig.e2e on the 9-path case (eval id a...), and digest([profile, Plan, live Plan, policy, impact templates]) of
# repository_profile(impact_version=7) under pullo-terra.toml.
# v7_repo_* re-pinned for the DEADLINE time successor (2026-11-02, as v6cd): its legacy Plan run deadlines 3000/2400
V7_PINS = json.loads("""{"v7_e2e": {"INVESTIGATE": "sha256:9d13d0f02425d5b08fa6d311fea9715341cbf2b1cb8a6cabab6018a4c77619c5", "PUBLISH": "sha256:6be145b79c2542de0cd7a9044fb94511c750f2bf8a1219e663d2046240568861", "VERIFY": "sha256:fdb654b889fe3b0cf8b2511782e9680e84c7994a161d7dd632b27e63693336da", "cfg": "sha256:5a57bd0cec90eede96808ebde12a6df9d0dbbf789982661c4718b4b2e0470ac2", "requests": ["sha256:59630fd815416f501e3fda3a8f6f3847dafa2cce8a3f0f6d3ee513ebe5aec216", "sha256:171138bf227bfcea547598cf0590b8ec160cb91c70e587d44a4c194b623cc878", "sha256:88f5d57ce7f80a018cde73d70236b043640ed17b89b2dc67ce40933bcb3d65be", "sha256:4e1702fdfe7dba1bff25e92d4b300f76a2e1dedca6a84a3baf6f94f0abdfaf48", "sha256:8a7563fd3c45ade67019839a25a6ecd0783ef1bb6581bc7dfa5888e1aeb1e42f", "sha256:e0f0933f1fa5b28cb9e75ceeb85f27f83f4c060fccf1508d503fa8c7cc6efb0b", "sha256:fac4848ab94404b7b10438fcd65d91c9ba0af1710600e450693b6d9435ad14c9", "sha256:7652614e677b10b1aa567d2cfdc7c27497ee4c11d2af0c74d3c8744737cd60fb", "sha256:278d00286b6aca36d18d660c69eae52b10271b13720d30ac34851d88a3d0b5ee", "sha256:d53b4f9e813be4d52ab8498803645362fff29aca14397c46d2cc2cd2d1d6b8b8", "sha256:07178753dc9218ea9f1e0330eebb10c343f084940abfad3284c6e0697efbe239", "sha256:7cbd9d40f00deb69173a5e7780bd702cd05d8cab8eaac92b7b93bde297e0a842", "sha256:304ec5369b45cf796a2e7bcb7120c068f1f102fb8274446fcff3d4af0343025d", "sha256:fbce68fb09757c8360f3c41d34f98f12f06ea6a2f8b1cfb5e9047676bc7cfa47", "sha256:cd8a24722eab09da0bb0922a4bda2185189b4d2e703a4f9e3247ec8edbf53a41", "sha256:f2899ce0b250fe52fd7aca3b67977eda0d406aa69449e5e6ea32bcfc005d04b1", "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24", "sha256:a742f7ff0a8e7525ced31d285adede847b130c476171536bbc0b717ab6f15136", "sha256:1cf20e36998b0c4010720a2a8817da18e9d5f14d0486a0484ad0c1fe145c0bc8", "sha256:f7b4f0d29c58c0d05c7edef8a2e762cec911e5f9a343dfd9647ca8ed1b9e32d6", "sha256:b09abdb9016229c01dce583cc0db8af792a117b838fdbf31cb0d481540a95e40"], "trace": "sha256:127ce47a52e2e3eefa10d4f27eda28af36e661d346680dea6a4985236903a89f"}, "v7_repo_pullo-terra.toml": "sha256:89f9b0db8a37cefcaaab67debc0d7584fdd46fbb98ca693ea9ebaa6e14efcec6"}""")


def pin_of(res):
    a = res.receipt["artifactDigests"]
    return {"cfg": res.run["configSnapshotId"], "trace": res.receipt["traceDigest"], "INVESTIGATE": a["INVESTIGATE"],
            "VERIFY": a["VERIFY"], "PUBLISH": a["PUBLISH"], "requests": [e["requestHash"] for e in model_calls(res)]}


def terra():
    return resolve_config(ROOT / "pullo-terra.toml").models


class V10Rig(CrossRig):
    def record_v10(self, m, main, alt, **kw):
        kw.setdefault("profile", V10_PROFILE)
        kw.setdefault("plan", V10_PLAN)
        kw.setdefault("retrieval", V10_POLICY)
        return self.record_v7(m, main, alt, **kw)

    def replay_v10(self, m, res, **kw):
        kw.setdefault("profile", V10_PROFILE)
        kw.setdefault("retrieval", V10_POLICY)
        kw.setdefault("plan", V10_PLAN)
        return self.replay(m, res, **kw)

    def record_timed(self, m, main, alt, seconds_per_alt_call, **kw):
        """record_v10 with a host clock that only moves when the ALTERNATE model is called (each such call takes
        `seconds_per_alt_call`), so lane time slices and run deadlines fall exactly inside the alternate lanes."""
        now = [0.0]
        self.clock = lambda: now[0]

        class Timed(PerModel):
            def call(self, request, key):
                if request["model"] == ALT_MODEL:
                    now[0] += seconds_per_alt_call
                return super().call(request, key)
        spy = Timed({MAIN_MODEL: main, ALT_MODEL: alt})
        providers = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai"), "synthetic": spy}
        backend = RecordBackend(self.handle, self.book, providers, lambda: NOW)
        kw.setdefault("retrieval", V10_POLICY)
        return run_review(self.spec(m, backend, profile=kw.pop("profile", V10_PROFILE), plan=kw.pop("plan"), **kw)), spy

    def lanes6(self, **finals):
        main, alt = [], []
        for a in ALL:
            (alt if a in ALT else main).extend([ask(a, 0), sfinal(a, 1, *finals.get(a, ()))])
        return main, [answered_by(e, ALT_MODEL) for e in alt]

    def e2e(self, m):
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        dup = dict(hu, claim="clamp swaps lo and hi values")            # a true restatement of hu: merged into it
        near = dict(hu, claim="max gets hi as its first argument so every input above lo is returned as hi")
        main, alt = self.lanes6(contracts=[hc], logic=[hu],
                                **{"contracts.alt": [near], "logic.alt": [dup], "safety.alt": [hio]})
        # VERIFY (v3 round-robin over completed lanes): contracts 0, logic 0, contracts.alt 0, [logic.alt 0 merged],
        # safety.alt 0
        main += [vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                 vfinal(2, m, path="src/app/util.py", line=2), vfinal(3, m, path="src/app/io.py", line=2),
                 judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hu)]), w([shid("contracts.alt", 0, near)]),
                       w([shid("safety.alt", 0, hio)]))]
        return script(*main), script(*alt), (hc, hu, hio, dup, near)


# ---------------------------------------------------------------- profile, Plan, policy

class Resolution(unittest.TestCase):
    def test_v10_profile_plan_and_policy_bind_the_alternate_model(self):
        from reviewer.pilot import repository_profile as RP
        p = RP.repository_profile(True, terra(), impact_version=10)
        self.assertEqual(validate("ModelProfile", p), [])
        inv, alt = p["roles"]["investigator"], p["alternates"]["investigator"]
        self.assertEqual((inv["model"], alt["model"], alt["provider"], alt["family"], inv["promptVersion"]),
                         ("gpt-6.1-terra", "gpt-5.6-terra", "openai", "gpt", INV10))
        self.assertEqual({k: v for k, v in alt.items() if k not in ("model", "price")},
                         {k: v for k, v in inv.items() if k not in ("model", "price")})
        for live, stages, clock in ((True, {"INVESTIGATE": 600, "VERIFY": 450, "JUDGE": 200}, (1_650, 1_350)),
                                    (False, {"INVESTIGATE": 240}, (3_000, 2_400))):   # legacy: the v6cd run deadlines
            plan = RP.repository_plan(p, live_stage_timing=live)
            self.assertEqual(validate("Plan", plan), [])
            self.assertEqual(plan["specialists"], list(ALL))
            b = plan["budget"]
            self.assertEqual(b["stageCeilingsSec"], stages)
            self.assertEqual((b["wallClockSec"], b["softDeadlineSec"]), clock)
            self.assertEqual((b["maxUsdMicros"], b["verifyReserveBp"], b["maxToolCalls"], b["maxToolCallsPerAgent"]),
                             (4_000_000, 3000, 220, 60))
            self.assertIn("investigator.impact@v10: lanes contracts.alt, logic.alt, safety.alt on the alternate "
                          "investigator openai/gpt-5.6-terra", plan["reasons"][1])
        pol = RP.repository_policy(True, impact_version=10)
        self.assertEqual((pol.specialists, pol.five_lanes, pol.cross_model, pol.cross_v3, pol.diff_sweep,
                          pol.exploration_floor, pol.run_tool_calls), (ALL, False, True, True, False, True, 220))
        self.assertFalse(any(RP.repository_policy(True, impact_version=v).cross_v3 for v in (1, 2, 3, 4, 5, 7)))
        self.assertEqual(RP.ALT_IMPACT_VERSIONS, {7: prompts.INVESTIGATOR_IMPACT_V7_PROMPT, 10: INV10})
        other = RP.repository_profile(True, ReviewModels("gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.1-terra",
                                                         "anthropic/claude-haiku-5.5"), impact_version=10)
        self.assertNotEqual(digest(other), digest(p))
        self.assertNotEqual(digest(RP.repository_plan(other)), digest(RP.repository_plan(p)))

    def test_v10_refuses_without_an_alternate_or_with_the_investigators_own_model(self):
        from reviewer.pilot import repository_profile as RP
        from reviewer.pilot.profile import ProfileError
        for models in (None, ReviewModels.uniform("gpt-6.1-terra"),
                       ReviewModels("gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.1-terra")):
            with self.subTest(models=models), self.assertRaises(ProfileError) as c:
                RP.repository_profile(True, models, impact_version=10)
            self.assertIn("v10", str(c.exception))
        p = RP.repository_profile(True, terra(), impact_version=10)
        del p["alternates"]
        with self.assertRaises(ProfileError) as c:
            RP.repository_plan(p)
        self.assertIn("investigator.impact@v10", str(c.exception))
        self.assertIn("v3 specialists alone", str(c.exception))

    def test_v1_v7_repository_identities_are_byte_identical(self):
        from reviewer.pilot import repository_profile as RP
        t = terra()
        self.assertEqual(digest(repo_identity(t)), V1_V5_REPO["pullo-terra.toml"])
        self.assertEqual(digest(repo_identity(resolve_config(ROOT / "pullo.toml").models)), V1_V5_REPO["pullo.toml"])
        p7 = RP.repository_profile(True, t, impact_version=7)
        self.assertEqual(digest([digest(p7), digest(RP.repository_plan(p7)),
                                 digest(RP.repository_plan(p7, live_stage_timing=True)),
                                 RP.repository_policy(True, impact_version=7).digest,
                                 prompts.impact_template_digests(RP.IMPACT_VERSIONS[7])]),
                         V7_PINS["v7_repo_pullo-terra.toml"])
        self.assertFalse(any("alternates" in RP.repository_profile(True, t, impact_version=v) for v in range(1, 6)))


# ---------------------------------------------------------------- the v3 lanes are exactly v3's

class V3LaneSpecs(unittest.TestCase):
    """v10's non-alternate lanes get exactly the v3 lane specs: profile role, prompt texts, tool-call, spend and time
    ceilings and per-agent caps, on the live and on the legacy pilot Plans."""

    def test_v10_v3_lanes_have_exactly_v3s_lane_specs_on_the_pilot(self):
        from reviewer.pilot import repository_profile as RP
        t = terra()
        p3, p10 = (RP.repository_profile(True, t, impact_version=v) for v in (3, 10))
        pol3, pol10 = (RP.repository_policy(True, impact_version=v) for v in (3, 10))
        # the profile: the same three roles, only the investigator prompt id differs; v10 adds the alternate
        strip = lambda p: dict(p, roles=dict(p["roles"], investigator=dict(p["roles"]["investigator"],  # noqa: E731
                                                                          promptVersion=None)))
        self.assertEqual(strip(p3), strip({k: v for k, v in p10.items() if k != "alternates"}))
        # the policy: every numeric per-agent limit equal (run_tool_calls grows by the alternate lanes' pool)
        d3, d10 = pol3.to_doc(), pol10.to_doc()
        for k in ("investigator_turns", "verifier_turns", "requests_per_turn", "agent_tool_calls",
                  "hypothesis_tool_calls", "context_chars", "verifier_prompt", "version"):
            self.assertEqual(d3[k], d10[k], k)
        self.assertEqual((d3["run_tool_calls"], d10["run_tool_calls"]), (160, 220))
        for live in (True, False):
            b3 = RP.repository_plan(p3, live_stage_timing=live)["budget"]
            b10 = RP.repository_plan(p10, live_stage_timing=live)["budget"]
            with self.subTest(live=live):
                for k in ("maxUsdMicros", "verifyReserveBp", "maxToolCallsPerAgent", "maxToolOutputTokensPerAgent",
                          "maxRetriesPerCall"):
                    self.assertEqual(b3[k], b10[k], k)
                # DEADLINE time successor (2026-11-02, as v6cd): v3's live table and the run deadlines moved (900/600/400,
                # 3000/2400); v10's own V10_* table is unchanged (no claude-cli arm runs v10), so it no longer tracks v3's
                # numbers and is pinned absolutely: VERIFY 450, JUDGE 200, deadlines 1650/1350 live (legacy: the tables')
                self.assertEqual((stage_ceiling("JUDGE", b3), stage_ceiling("JUDGE", b10)),
                                 (400, 200) if live else (stage_ceiling("JUDGE", b10),) * 2)
                self.assertEqual((stage_ceiling("VERIFY", b3), stage_ceiling("VERIFY", b10)),
                                 (600, 450) if live else (45, 45))
                self.assertEqual((b3["wallClockSec"], b3["softDeadlineSec"]), (3_000, 2_400))
                self.assertEqual((b10["wallClockSec"], b10["softDeadlineSec"]), (1_650, 1_350) if live else (3_000, 2_400))
                if live:
                    self.assertEqual(b3["stageCeilingsSec"], {"INVESTIGATE": 900, "VERIFY": 600, "JUDGE": 400})
                host = 60
                self.assertEqual(lanes.v10_tool_cumulative(pol10, b10, host)[:3],
                                 specialists.cumulative(specialists.tool_pool(pol3, b3, host)))
                self.assertEqual(lanes.v10_primary_spend_cumulative(b10), specialists.cumulative(investigation_limit(b3)))
                self.assertEqual(lanes.v10_time_slices(stage_ceiling("INVESTIGATE", b10))[:3],      # live: v3's pre-successor 300 s
                                 specialists.time_slices(300 if live else stage_ceiling("INVESTIGATE", b3)))
                # all of INVESTIGATE stays within v3's own share: VERIFY + JUDGE keep at least what v3 reserves
                self.assertEqual(lanes.v10_spend_top(b10), investigation_limit(b3))
                for host in (7, 13, 60):           # any host tool limit: the v3 lanes keep the v3 pool split
                    self.assertEqual(lanes.v10_tool_cumulative(pol10, b10, host)[:3],
                                     specialists.cumulative(specialists.tool_pool(pol3, b3, host)), host)

    def test_v10_v3_lanes_run_v3s_tasks_and_templates(self):
        for a in V3_LANES:
            self.assertEqual(prompts.specialist_task(prompts.lens_of(a)), prompts.investigator_v3_task(a))
            self.assertEqual(prompts.specialist_task(prompts.lens_of(a + ".alt")), prompts.investigator_v3_task(a))
        t3, t10 = prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_V3_PROMPT), prompts.impact_template_digests(
            INV10)
        self.assertEqual({k: v for k, v in t10.items() if k != "crossModel"}, t3)
        self.assertIn("crossModel", t10)


class V3LaneRequests(V10Rig):
    def test_v10_v3_lane_requests_are_v3s_requests(self):
        """Same case, same v3 lane answers: every investigator request of a v10 v3 lane equals the v3 run's request
        except for the investigator prompt id; the alternate lanes come after, on the alternate model."""
        m3, m10 = self.big(), self.big()
        hc = self.h_core(m3)
        res3, _ = self.record_v3(m3, self.big_v3_script(m3))
        self.assertEqual(res3.status, "completed", res3.incomplete)
        main, alt = self.lanes6(contracts=[self.h_core(m10)])
        main += [vfinal(0, m10, path="src/app/core.py", line=3), judge(w([shid("contracts", 0, hc)]))]
        res10, spy = self.record_v10(m10, script(*main), script(*alt), eval_id="evr_" + "b" * 16)
        self.assertEqual(res10.status, "completed", res10.incomplete)

        def lane_requests(res, lanes_):
            out = []
            for c in inv_calls(res):
                if c["agentId"] in lanes_:
                    r = dict(c["request"])
                    r.pop("promptVersion")
                    out.append((c["agentId"], c["ordinal"], r))
            return out
        self.assertEqual(lane_requests(res10, V3_LANES), lane_requests(res3, V3_LANES))
        self.assertEqual([(c["agentId"], c["ordinal"]) for c in inv_calls(res10)], [(a, k) for a in ALL for k in (0, 1)])
        self.assertEqual({c["request"]["model"] for c in inv_calls(res10) if c["agentId"] in ALT}, {ALT_MODEL})
        self.assertEqual({c["request"]["promptVersion"] for c in inv_calls(res10)}, {INV10})


# ---------------------------------------------------------------- pure rules

class Rules(unittest.TestCase):
    def test_lane_ids_and_tasks(self):
        self.assertEqual(prompts.V10_AGENTS, ALL)
        self.assertEqual(lanes.V10_ALT_AGENTS, ALT)
        self.assertEqual([prompts.lens_of(a) for a in ALL], list(V3_LANES) * 2)
        self.assertTrue(all(prompts.is_alt_lane(a) for a in ALT) and not any(prompts.is_alt_lane(a) for a in V3_LANES))
        self.assertTrue(all(prompts.is_alt_lane(a) for a in prompts.V7_ALT_AGENTS))     # v7 keeps its alternate lanes
        for a in ALL:
            self.assertEqual(validate("Plan", dict(V10_PLAN, specialists=[a])), [])        # a contract slug
        self.assertTrue(lanes.is_v10_plan(V10_PLAN) and not lanes.is_v7_plan(V10_PLAN))
        self.assertFalse(specialists.is_v3_plan(V10_PLAN) or lanes.is_v5_plan(V10_PLAN))
        self.assertTrue(specialists.is_specialist_plan(V10_PLAN))
        self.assertIsNone(lanes.lane_order(V10_PLAN))                       # no near-duplicate cap (no collapses)
        with self.assertRaises(ValueError):
            prompts.investigator_task(INV10)

    def test_v10_merges_only_restatements_across_its_six_lanes(self):
        from tests.pipeline.test_lanes_v5 import H
        kept = H(1, "logic", "util.py", 10, claim="clamp swaps lo and hi")
        same = H(2, "logic.alt", "util.py", 10, claim="clamp swaps lo and hi values")
        other = H(3, "contracts.alt", "util.py", 11, end=12, claim="max gets hi first so inputs above lo come back as hi")
        apart = H(4, "safety.alt", "util.py", 12, claim="clamp swaps lo and hi")               # within 3, no overlap
        field = H(5, "safety", "util.py", 10, claim="clamp swaps `lo` and hi")                 # other distinctive token
        hs = [kept, field, other, same, apart]
        # among the v3 lanes, exactly v3's merge (specialist-merge@2 merges `field` into `kept`); the alternate lanes
        # are merged into that result only when they restate a kept hypothesis (cross-model-merge@1)
        v3_groups = specialists.merge([kept, field])
        self.assertEqual(v3_groups, [{"keptId": kept["id"], "mergedIds": [field["id"]], "rule": "specialist-merge@2"}])
        self.assertEqual(lanes.v10_merge(hs), v3_groups + [{"keptId": kept["id"], "mergedIds": [same["id"]],
                                                            "rule": "cross-model-merge@1"}])
        self.assertEqual(lanes.v10_merge([kept, field]), specialists.merge([kept, field]))      # no alt: exactly v3
        # an alternate restatement of a hypothesis v3 merged away is compared with the kept ones only: `field` names
        # another distinctive token than `kept`, so its alternate restatement is a new candidate
        self.assertEqual(lanes.v10_merge([kept, field, dict(field, id="hyp_" + "f" * 16, specialist="safety.alt")]),
                         v3_groups)
        self.assertEqual(lanes.lane_merge(V10_PLAN, hs), lanes.v10_merge(hs))
        self.assertEqual(validate("StagePayload", {"stage": "INVESTIGATE", "hypotheses": [], "agents": [],
                                                   "merges": lanes.v10_merge(hs)}), [])

    def test_budget_split_on_the_pilot(self):
        from reviewer.pilot import repository_profile as RP
        p = RP.repository_profile(True, terra(), impact_version=10)
        pol = RP.repository_policy(True, impact_version=10)
        for live, secs in ((True, [100 * (i + 1) for i in range(6)]), (False, [40 * (i + 1) for i in range(6)])):
            d = lanes.v10_budget_doc(pol, RP.repository_plan(p, live_stage_timing=live)["budget"], 60)
            self.assertEqual((d["agents"], d["altAgents"]), (list(ALL), list(ALT)))
            self.assertEqual(d["toolCalls"]["cumulative"], [20 * (i + 1) for i in range(6)])   # v3 lanes keep 20..60
            self.assertEqual(d["timeSec"]["cumulative"], secs)                                # v3 lanes keep their slices
            s = d["spendUsdMicros"]
            self.assertEqual(s["cumulative"], [933_333, 1_866_666, 2_800_000])               # exactly v3's
            self.assertEqual(s["share"], 2_800_000)
            self.assertEqual(s["finalAnswer"]["rule"], lanes.V10_FINAL_RULE)
        b = {"maxUsdMicros": 4_000_000, "verifyReserveBp": 3000}
        # the alternate lanes POOL at most $1.50 (never past v3's $2.80 share): every alternate lane's ceiling is the
        # alternate cap; v3 lanes at $0.70 / $0.85 / $0.90 -> INVESTIGATE <= $2.20 / $2.35 / $2.40, VERIFY + JUDGE
        # >= $1.80 / $1.65 / $1.60
        for start, top in ((700_000, 2_200_000), (850_000, 2_350_000), (900_000, 2_400_000), (2_600_000, 2_800_000)):
            self.assertEqual([lanes.v10_alt_spend_ceiling(start, j, b) for j in range(3)], [top] * 3)
            self.assertEqual(lanes.v10_alt_top(start, b), top)
        self.assertEqual(4_000_000 - lanes.v10_alt_top(900_000, b), 1_600_000)
        for start in (0, 1, 999_999, 2_799_999, 2_800_000, 3_100_000):     # never above v3's INVESTIGATE share
            self.assertTrue(all(lanes.v10_alt_spend_ceiling(start, j, b) <= 2_800_000 for j in range(3)), start)
        self.assertEqual(b["maxUsdMicros"] - lanes.v10_spend_top(b), 1_200_000)     # VERIFY + JUDGE keep v3's >= 30%

    def test_final_answer_reserve_rule(self):
        # lane j explores only while spend + r + 1.25 r <= alt_top - (A-1-j) r (the last lane: also - 0.25 r)
        due = lanes.v10_final_answer_due
        self.assertEqual([due(1_000_000, 2_275_000, 300_000, 0), due(1_000_000, 2_274_999, 300_000, 0)], [False, True])
        self.assertEqual([due(1_000_000, 1_975_000, 300_000, 1), due(1_000_000, 1_974_999, 300_000, 1)], [False, True])
        self.assertEqual([due(1_000_000, 1_750_000, 300_000, 2), due(1_000_000, 1_749_999, 300_000, 2)], [False, True])
        self.assertTrue(due(1_000_000, 1_000_001, 1, 2))
        # realistic: v3 lanes at $0.90 (alt_top $2.40); contracts.alt explores on a 40-60k-token gpt-5.6-terra
        # request (r $0.29-0.34) and goes to its final answer at 90k (r $0.42)
        from reviewer.contracts.budget import reservation
        from reviewer.pilot import repository_profile as RP
        alt = RP.repository_profile(True, terra(), impact_version=10)["alternates"]["investigator"]
        r = {t: reservation(alt["price"], t, alt["caps"]["maxOutputTokens"]) for t in (40_000, 50_000, 60_000, 90_000)}
        top = lanes.v10_alt_top(900_000, {"maxUsdMicros": 4_000_000, "verifyReserveBp": 3000})
        self.assertEqual([due(900_000, top, r[t], 0) for t in (40_000, 50_000, 60_000, 90_000)],
                         [False, False, False, True])
        from reviewer.contracts.budget import reservation
        from reviewer.pilot import repository_profile as RP
        alt = RP.repository_profile(True, terra(), impact_version=10)["alternates"]["investigator"]
        self.assertEqual([reservation(alt["price"], t, alt["caps"]["maxOutputTokens"]) for t in (40_000, 90_000)],
                         [292_000, 417_000])                  # gpt-5.6-terra worst case at 40k / 90k input tokens


# ---------------------------------------------------------------- end to end

class EndToEnd(V10Rig):
    def test_six_lanes_on_two_models_with_merge_and_v3_verify(self):
        m = self.big()
        main, alt, (hc, hu, hio, dup, near) = self.e2e(m)
        res, spy = self.record_v10(m, main, alt)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual([(c["agentId"], c["ordinal"]) for c in inv_calls(res)], [(a, k) for a in ALL for k in (0, 1)])
        by_lane = {(c["agentId"] in ALT, c["request"]["role"], c["request"]["model"]) for c in model_calls(res)}
        self.assertEqual({(role, model) for a, role, model in by_lane if a}, {("investigator", ALT_MODEL)})
        self.assertEqual({(role, model) for a, role, model in by_lane if not a},
                         {("investigator", MAIN_MODEL), ("verifier", MAIN_MODEL), ("judge", MAIN_MODEL)})
        self.assertEqual(spy.inner[ALT_MODEL].calls, 6)                       # 3 lanes x 2 hops
        firsts = [r for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0]
        self.assertEqual([doc_of(r)["task"] for r in firsts], [prompts.investigator_v3_task(prompts.lens_of(a))
                                                               for a in ALL])
        self.assertEqual({r["promptVersion"] for r in firsts}, {INV10})
        # this rig's host tool limit is 50, so v3's pool is 50: the v3 lanes get v3's cumulative 16, 33, 50 (one call
        # used per earlier lane); the alternate lanes follow at 66, 83, 100, each held to the per-agent cap of 50
        self.assertEqual(specialists.cumulative(specialists.tool_pool(V3_POLICY, V3_PLAN["budget"], 50)), [16, 33, 50])
        self.assertEqual([doc_of(r)["retrieval"]["toolCallsRemaining"] for r in firsts], [16, 32, 48, 50, 50, 50])
        costs = [e["record"] for e in events_of(res) if e["type"] == "cost"]
        self.assertEqual({c["priceVersion"] for c in costs if c["model"] == ALT_MODEL}, {"synthetic-alt@1"})
        pay = self.payload(res)["payload"]
        self.assertEqual([a["agentId"] for a in pay["agents"]], list(ALL))
        self.assertNotIn("collapses", pay)
        self.assertEqual(pay["merges"], [{"keptId": shid("logic", 0, hu), "mergedIds": [shid("logic.alt", 0, dup)],
                                          "rule": lanes.CROSS_MERGE_RULE}])
        # the distinct alternate-model defect next to hu is kept and verified on its own; the restatement is merged
        # and dropped after hu was confirmed; one verifier session as in v3
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, hc), shid("logic", 0, hu), shid("contracts.alt", 0, near),
                          shid("safety.alt", 0, hio)])
        self.assertEqual({e["agentId"] for e in model_calls(res, "VERIFY")}, {"verifier"})
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["contracts", "contracts.alt", "logic",
                                                                         "safety.alt"])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual([d["subjectIds"] for d in vpay["drops"] if d["reason"] == "merged"],
                         [[shid("logic.alt", 0, dup)]])
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("- safety.alt: completed; 1 resolved hypothesis(es)", md)
        self.assertIn(f"alternate investigator model {ALT_MODEL}", md)

    def test_strict_replay_and_load_rederive_a_v10_run(self):
        from reviewer.pipeline import runner
        m = self.big()
        main, alt, _ = self.e2e(m)
        res, _ = self.record_v10(m, main, alt)
        rep = self.replay_v10(m, res)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(rep.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
        for st in ("INVESTIGATE", "VERIFY", "JUDGE"):
            self.assertEqual(rep.receipt["artifactDigests"][st], res.receipt["artifactDigests"][st], st)
        self.assertEqual([h["id"] for h in rep.hypotheses], [h["id"] for h in res.hypotheses])
        self.assertEqual(runner.load_result(self.out, res.run_id).hypotheses, res.hypotheses)
        with mock.patch.object(lanes, "v10_merge", lambda hyps: []):            # the v10 merge is re-derived on load
            with self.assertRaises(PipelineError) as c:
                runner.load_result(self.out, res.run_id)
        self.assertEqual(c.exception.code, "checkpoint-invalid")
        other = copy.deepcopy(V10_PROFILE)
        other["alternates"]["investigator"]["model"] = "synthetic-other-fixture"
        with self.assertRaises(PipelineError) as c:
            self.replay_v10(m, res, profile=other, eval_id="evr_" + "9" * 16)
        self.assertEqual(c.exception.code, "identity-mismatch")

    def v3_only_script(self, m, **alt_finals):
        """v3 lanes find hc and hu (both confirmed); the alternate lanes' scripted answers are `alt_finals`."""
        hc, hu = self.h_core(m), self.h_util(m)
        main, alt = self.lanes6(contracts=[hc], logic=[hu], **alt_finals)
        main += [vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                 judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hu)]))]
        return main, alt

    def test_alternate_lane_budget_exhaustion_keeps_the_run_completed_with_a_coverage_note(self):
        m = self.big()
        main, alt = self.v3_only_script(m)               # contracts.alt answers (nothing); the later two are capped
        orig = lanes.v10_alt_spend_ceiling
        share = lambda start, j, budget: orig(start, j, budget) if j == 0 else start      # noqa: E731
        with mock.patch.object(lanes, "v10_alt_spend_ceiling", share):
            res, spy = self.record_v10(m, script(*main), script(*alt))
            rep = self.replay_v10(m, res)
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        inv = self.payload(res)
        self.assertEqual(inv["status"], "completed")
        notes = lanes.v10_alt_coverage(inv["payload"], events_of(res), res.incomplete)
        self.assertEqual(notes, [f"alt-lane-capped: {a} (`budget-exhausted`; status budget)" for a in ALT[1:]])
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("does not make the run partial", md)
        self.assertIn("  - alt-lane-capped: logic.alt (`budget-exhausted`; status budget)", md)
        self.assertNotIn("## Incomplete", md)
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["contracts", "logic"])
        agents = {a["agentId"]: a for a in inv["payload"]["agents"]}
        self.assertTrue(all(agents[a]["status"] == "completed" for a in V3_LANES + ALT[:1]))
        self.assertEqual([agents[a]["status"] for a in ALT[1:]], ["budget"] * 2)
        errs = [e["error"] for e in events_of(res) if e["type"] == "error"
                and (e["error"].get("detail") or {}).get("scope") == "alternate-model-share"]
        self.assertEqual({e["detail"]["rule"] for e in errs}, {lanes.V10_BUDGET_RULE})
        self.assertEqual(spy.inner[ALT_MODEL].calls, 2)                 # contracts.alt's two hops only
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, self.h_core(m)), shid("logic", 0, self.h_util(m))])
        # replay and load re-derive the completed status and the review.md coverage note
        self.assertEqual((rep.status, rep.incomplete), ("completed", []))
        from reviewer.pipeline import runner
        self.assertEqual(runner.load_result(self.out, res.run_id).status, "completed")

    def test_no_alternate_answer_at_all_makes_the_run_partial(self):
        m = self.big()
        main, alt = self.v3_only_script(m)
        with mock.patch.object(lanes, "v10_alt_spend_ceiling", lambda start, j, budget: start):   # no room at all
            res, spy = self.record_v10(m, script(*main), script(*alt))
            rep = self.replay_v10(m, res)
        self.assertEqual(res.status, "partial")
        self.assertEqual([(i["stage"], i["reason"]) for i in res.incomplete], [("INVESTIGATE", "agent-failure")])
        self.assertTrue(res.incomplete[0]["detail"].startswith("no-alternate-answer: "))
        notes = lanes.v10_alt_coverage(self.payload(res)["payload"], events_of(res), res.incomplete)
        self.assertEqual(notes, [f"alt-lane-capped: {a} (`budget-exhausted`; status budget)" for a in ALT]
                         + ["no-alternate-answer: no alternate lane answered (counted as incomplete)"])
        self.assertEqual(spy.inner[ALT_MODEL].calls, 0)
        self.assertEqual((rep.status, rep.incomplete), (res.status, res.incomplete))

    def test_a_tight_alternate_share_still_gets_an_answer_through_the_final_answer_turn(self):
        m = self.big()
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        main, _ = self.v3_only_script(m)
        # every alternate hop is "too expensive to explore": each lane's first hop is its final-answer turn
        alt = [answered_by(e, ALT_MODEL) for e in (sfinal("contracts.alt", 0, hio), sfinal("logic.alt", 0),
                                                    sfinal("safety.alt", 0))]
        main = main[:-1] + [vfinal(2, m, path="src/app/io.py", line=2),
                            judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hu)]),
                                  w([shid("contracts.alt", 0, hio)]))]
        with mock.patch.object(lanes, "V10_FINAL_GROWTH_BP", 10 ** 12):
            res, spy = self.record_v10(m, script(*main), script(*alt))
            rep = self.replay_v10(m, res)
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        self.assertEqual((rep.status, rep.incomplete), ("completed", []))
        alt_reqs = [r for r in spy.requests if r["model"] == ALT_MODEL]
        self.assertEqual(len(alt_reqs), 3)                                 # one final-answer call per lane
        self.assertTrue(all("This is your last turn" in json.dumps(doc_of(r)["retrieval"]) for r in alt_reqs))
        self.assertFalse(any(json.dumps(doc_of(r)["retrieval"]).count("This is your last turn")
                             for r in spy.requests if r["model"] == MAIN_MODEL and r["role"] == "investigator"))
        self.assertFalse(any(e["agentId"] in ALT for e in events_of(res) if e["type"] == "tool.call"))
        floors = [(e["agentId"], e["decision"], e.get("reason")) for e in events_of(res)
                  if e["type"] == "retrieval.floor" and e["agentId"] in ALT]
        self.assertEqual(floors, [(a, "skipped", "turns") for a in ALT])  # no floor continuation past the reserve
        self.assertEqual([a["status"] for a in self.payload(res)["payload"]["agents"]], ["completed"] * 6)
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["contracts", "contracts.alt", "logic"])

    def test_investigate_stays_within_v3s_share_and_verify_keeps_its_floor(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        res, _ = self.record_v10(m, main, alt)
        costs = [e["record"] for e in events_of(res) if e["type"] == "cost"]
        inv = sum(c["usdMicros"] for c in costs if c["stage"] == "INVESTIGATE")
        budget = V10_PLAN["budget"]
        self.assertLessEqual(inv, investigation_limit(budget))
        self.assertGreaterEqual(budget["maxUsdMicros"] - investigation_limit(budget), 1_200_000)
        # the alternate lanes' ceilings are the even split of what the v3 lanes left, never above the share
        errs_seen = []
        orig = lanes.v10_alt_spend_ceiling

        def spy(start, j, b):
            errs_seen.append(orig(start, j, b))
            return errs_seen[-1]
        with mock.patch.object(lanes, "v10_alt_spend_ceiling", spy):
            self.record_v10(self.big(), *self.e2e(self.big())[:2], eval_id="evr_" + "d" * 16)
        self.assertEqual(len(errs_seen), 3)
        # one pooled alternate cap S + $1.50 for every alternate lane, under v3's $2.80 share
        self.assertEqual(len(set(errs_seen)), 1)
        self.assertLessEqual(errs_seen[-1], investigation_limit(budget))

    def test_contracts_alt_explores_on_a_realistic_request_and_every_lane_answers(self):
        """The engine with a realistic gpt-5.6-terra worst-case reservation per call ($0.317, a ~50k-token request):
        contracts.alt explores (its first hop is not its last turn and runs a tool); as the pooled room is used, the
        later lanes keep room for their final answers and are sent final-answer turns; every alternate lane answers
        and the alternate lanes' spend stays within the alternate cap."""
        import reviewer.pipeline.engine as E
        m = self.big()
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        main, _ = self.v3_only_script(m)
        alt = [answered_by(e, ALT_MODEL) for e in (ask("contracts.alt", 0), sfinal("contracts.alt", 1, hio),
                                                    ask("logic.alt", 0), sfinal("logic.alt", 1),
                                                    sfinal("safety.alt", 0))]
        main = main[:-1] + [vfinal(2, m, path="src/app/io.py", line=2),
                            judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hu)]),
                                  w([shid("contracts.alt", 0, hio)]))]
        with mock.patch.object(E, "reservation", lambda price, tokens, out: 317_000):
            res, spy = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        modes = [(c["agentId"], c["request"]["hop"], doc_of(c["request"])["retrieval"]["lastTurn"])
                 for c in inv_calls(res) if c["agentId"] in ALT]
        self.assertEqual(modes, [("contracts.alt", 0, False), ("contracts.alt", 1, True), ("logic.alt", 0, False),
                                 ("logic.alt", 1, True), ("safety.alt", 0, True)])
        self.assertTrue(any(e["agentId"] == "contracts.alt" for e in events_of(res) if e["type"] == "tool.call"))
        self.assertEqual([a["status"] for a in self.payload(res)["payload"]["agents"]], ["completed"] * 6)
        self.assertIn("contracts.alt", {f["specialist"] for f in res.findings})
        costs = [e["record"] for e in events_of(res) if e["type"] == "cost" and e["record"]["stage"] == "INVESTIGATE"]
        s = sum(c["usdMicros"] for c in costs if c["model"] == MAIN_MODEL)
        self.assertLessEqual(sum(c["usdMicros"] for c in costs if c["model"] == ALT_MODEL),
                             lanes.v10_alt_top(s, V10_PLAN["budget"]) - s)

    def test_live_calls_disabled_on_the_alternate_lanes_makes_the_run_partial(self):
        m = self.big()
        main, _ = self.v3_only_script(m)
        alt = [*sfail("contracts.alt", 0, code="live-calls-disabled")]     # systemic: no further alternate lane
        res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual(res.status, "partial")
        inv = [i for i in res.incomplete if i["stage"] == "INVESTIGATE"]
        self.assertEqual([i["reason"] for i in inv], ["agent-failure"] * 4)
        self.assertEqual([i["detail"].split(":")[0] for i in inv[:3]], [f"specialist {a}" for a in ALT])
        self.assertTrue(all("live-calls-disabled" in i["detail"] for i in inv[:3]))
        self.assertTrue(inv[3]["detail"].startswith("no-alternate-answer"))
        notes = lanes.v10_alt_coverage(self.payload(res)["payload"], events_of(res), res.incomplete)
        self.assertTrue(all("counted as incomplete" in n for n in notes))

    def test_an_answer_from_a_different_model_on_one_alternate_lane_makes_the_run_partial(self):
        m = self.big()
        main, alt = self.v3_only_script(m)
        # logic.alt's answer names the investigator's model instead of the alternate it was sent to
        alt = [e if e["agentId"] != "logic.alt" else dict(e, response=dict(e["response"], resolvedModel=MAIN_MODEL))
               for e in alt]
        res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual(res.status, "partial")
        inv = [i for i in res.incomplete if i["stage"] == "INVESTIGATE"]
        self.assertEqual(inv[0]["reason"], "agent-failure")
        self.assertTrue(inv[0]["detail"].startswith("specialist logic.alt: contract-violation"))
        agents = {a["agentId"]: a for a in self.payload(res)["payload"]["agents"]}
        self.assertEqual(agents["contracts.alt"]["status"], "completed")       # an alternate answer exists
        self.assertEqual(agents["logic.alt"]["error"]["code"], "contract-violation")
        self.assertNotIn("no-alternate-answer", " ".join(i["detail"] for i in inv))

    def test_alternate_model_failure_keeps_the_run_completed_with_a_coverage_note(self):
        m = self.big()
        hc, hu = self.h_core(m), self.h_util(m)
        main, _ = self.v3_only_script(m)
        # contracts.alt: the alternate provider fails (rejected); logic.alt: it fails again after its first hop;
        # safety.alt answers with a restatement of hu (merged, not verified again)
        alt = [answered_by(e, ALT_MODEL) if "response" in e else e
               for e in [*sfail("contracts.alt", 0), ask("logic.alt", 0), *sfail("logic.alt", 1),
                         ask("safety.alt", 0), sfinal("safety.alt", 1, dict(hu, claim="clamp swaps lo and hi values"))]]
        res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        inv = self.payload(res)["payload"]
        self.assertEqual([(a["agentId"], a["status"]) for a in inv["agents"]],
                         [(a, "completed") for a in V3_LANES] + [("contracts.alt", "failed"), ("logic.alt", "failed"),
                                                                ("safety.alt", "completed")])
        self.assertEqual(lanes.v10_alt_coverage(inv, events_of(res), res.incomplete),
                         ["alt-lane-failed: contracts.alt (`provider-error`; status failed)",
                          "alt-lane-failed: logic.alt (`provider-error`; status failed)"])
        self.assertEqual(inv["merges"], [{"keptId": shid("logic", 0, hu), "mergedIds": [
            shid("safety.alt", 0, dict(hu, claim="clamp swaps lo and hi values"))], "rule": lanes.CROSS_MERGE_RULE}])
        self.assertIn("alt-lane-failed: logic.alt", Path(res.review_path).read_text(encoding="utf-8"))
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["contracts", "logic"])

    def test_a_v3_lane_budget_exhaustion_still_makes_the_run_partial_as_in_v3(self):
        m = self.big()
        main, alt = self.v3_only_script(m)
        main = [e for e in main if e["agentId"] != "safety"]           # safety never reaches its provider
        big = 10 ** 9
        with mock.patch.object(lanes, "v10_primary_spend_cumulative", lambda budget: [big, big, 1]):
            res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual(res.status, "partial")
        self.assertEqual([(i["stage"], i["reason"]) for i in res.incomplete], [("INVESTIGATE", "budget")])
        self.assertIn("specialist safety: budget-exhausted", res.incomplete[0]["detail"])
        errs = [e["error"] for e in events_of(res) if e["type"] == "error"
                and (e["error"].get("detail") or {}).get("scope") == "specialist-share"]
        self.assertEqual({e["detail"]["rule"] for e in errs}, {specialists.BUDGET_RULE})
        agents = {a["agentId"]: a["status"] for a in self.payload(res)["payload"]["agents"]}
        self.assertEqual(agents, {"contracts": "completed", "logic": "completed", "safety": "budget",
                                  "contracts.alt": "completed", "logic.alt": "completed", "safety.alt": "completed"})

    def test_unused_v3_room_never_rolls_into_the_alternate_lanes(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        seen = []
        orig = lanes.v10_alt_spend_ceiling

        def spy_ceiling(start, j, budget):
            seen.append((start, j))
            return orig(start, j, budget)
        with mock.patch.object(lanes, "v10_alt_spend_ceiling", spy_ceiling):
            res, _ = self.record_v10(m, main, alt)
        v3_spend = sum(e["record"]["usdMicros"] for e in events_of(res) if e["type"] == "cost"
                       and e["record"]["stage"] == "INVESTIGATE" and e["record"]["model"] == MAIN_MODEL)
        self.assertEqual(seen, [(v3_spend, 0), (v3_spend, 1), (v3_spend, 2)])     # S = the v3 lanes' actual spend


class Refusal(V10Rig):
    def test_v10_without_an_alternate_is_refused_before_any_model_call(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        plain = copy.deepcopy(V10_PROFILE)
        del plain["alternates"]
        for prof in (plain, dict(copy.deepcopy(V10_PROFILE), alternates={"investigator": dict(
                V10_PROFILE["roles"]["investigator"], model=MAIN_MODEL)})):
            with self.subTest(prof=prof.get("alternates")), self.assertRaises(PipelineError) as c:
                self.record_v10(m, main, alt, profile=prof)
            self.assertEqual(c.exception.code, "invalid-input")
            if "alternates" not in prof:       # the same-model alternate already fails the ModelProfile invariant
                self.assertIn("investigator.impact@v10 needs an alternate investigator model", str(c.exception))
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_alternates_do_not_belong_to_v3(self):
        m = self.big()
        p3 = copy.deepcopy(V3_PROFILE)
        p3["alternates"] = copy.deepcopy(V10_PROFILE["alternates"])
        p3["alternates"]["investigator"]["promptVersion"] = p3["roles"]["investigator"]["promptVersion"]
        with self.assertRaises(PipelineError) as c:
            self.record_v10(m, script(), script(), profile=p3, plan=V3_PLAN, retrieval=V3_POLICY)
        self.assertIn("investigator.impact@v10", str(c.exception))

    def test_plan_must_name_the_six_lanes(self):
        m = self.big()
        for plan in (V3_PLAN, V7_PLAN):
            with self.subTest(plan=plan["specialists"]), self.assertRaises(PipelineError) as c:
                self.record_v10(m, script(), script(), plan=plan)
            self.assertIn("investigator.impact@v10 needs Plan.specialists", str(c.exception))


class V3Verify(V10Rig):
    v3_only_script = EndToEnd.v3_only_script

    def test_verify_is_v3s_output_order_round_robin_with_the_v3_cap(self):
        m = self.big()
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        conf2 = hyp(m, "src/app/conf.py", 2, claim="RETRIES is too high", severity="P2",
                    evidence=[m.cite("src/app/conf.py", 2)])
        main, alt = self.lanes6(contracts=[conf2, hc], logic=[hu], **{"safety.alt": [hio]})
        main += [vfinal(0, m, path="src/app/conf.py", line=2), vfinal(1, m, path="src/app/util.py", line=2),
                 judge()]
        with mock.patch.object(specialists, "MAX_VERIFY_CANDIDATES", 2):
            res, _ = self.record_v10(m, script(*main), script(*alt))
        # v3: output order inside a lane (conf2 before the P1 hc), round-robin across the v3 lanes, cap -> over-cap;
        # the alternate lanes' candidates come only after all of v3's
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, conf2), shid("logic", 0, hu)])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        over = [d for d in vpay["drops"] if d["reason"] == "over-cap"]
        self.assertEqual([d["subjectIds"] for d in over], [[shid("contracts", 1, hc)], [shid("safety.alt", 0, hio)]])
        self.assertIn("round-robin specialist order", over[0]["detail"])
        self.assertEqual({e["request"]["model"] for e in model_calls(res, "VERIFY")}, {MAIN_MODEL})   # verifier unchanged

    def test_with_no_alternate_hypothesis_verify_is_exactly_v3s(self):
        """Same case and v3 lane answers (with a v3 merge, a refuted kept hypothesis and its merge retry); the alternate
        lanes answer with nothing: VERIFY's candidates, requests, merges and drops equal the v3 run's."""
        def parts(m):
            hc, hu = self.h_core(m), self.h_util(m)
            dup = dict(hc, claim="the loop drops the first element of the list")    # v3 merge into hc (same spot)
            conf2 = hyp(m, "src/app/conf.py", 2, claim="RETRIES is too high", severity="P2",
                        evidence=[m.cite("src/app/conf.py", 2)])
            finals = {"contracts": [hc, conf2], "logic": [dup], "safety": [hu]}
            ver = [vfinal(0, m, verdict="refuted"), vfinal(1, m, path="src/app/util.py", line=2),
                   vfinal(2, m, path="src/app/conf.py", line=2), vfinal(3, m, path="src/app/core.py", line=3),
                   judge()]
            return finals, ver
        m3, m10 = self.big(), self.big()
        finals, ver = parts(m3)
        v3_main = [e for a in V3_LANES for e in (ask(a, 0), sfinal(a, 1, *finals[a]))]
        res3, _ = self.record_v3(m3, script(*v3_main, *ver))
        finals, ver = parts(m10)
        main, alt = self.lanes6(**finals)
        res10, _ = self.record_v10(m10, script(*main, *ver), script(*alt), eval_id="evr_" + "c" * 16)
        p3, p10 = (json.loads((Path(r.run_dir) / r.stages["VERIFY"]["path"]).read_text())["payload"]
                   for r in (res3, res10))
        self.assertEqual(self.payload(res10)["payload"]["merges"], self.payload(res3)["payload"]["merges"])
        self.assertEqual(len(self.payload(res3)["payload"]["merges"]), 1)
        self.assertEqual([e["request"] for e in model_calls(res10, "VERIFY")],
                         [e["request"] for e in model_calls(res3, "VERIFY")])
        self.assertEqual(len(model_calls(res3, "VERIFY")), 4)                     # 3 kept + the merge retry
        self.assertEqual(p10["drops"], p3["drops"])
        self.assertEqual([v["hypothesisId"] for v in p10["verifications"]],
                         [v["hypothesisId"] for v in p3["verifications"]])

    def test_alternate_candidates_follow_all_of_v3s_verify_including_its_merge_retry(self):
        m = self.big()
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        dup = dict(hc, claim="the loop drops the first element of the list")
        main, alt = self.lanes6(contracts=[hc], logic=[dup], **{"contracts.alt": [hio]})
        main += [vfinal(0, m, verdict="refuted"), vfinal(1, m, path="src/app/core.py", line=3),
                 vfinal(2, m, path="src/app/io.py", line=2), judge()]
        res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, hc), shid("logic", 0, dup), shid("contracts.alt", 0, hio)])

    @staticmethod
    def floor_after(n):
        """A JUDGE-reserve floor that is out of reach for the first `n` VERIFY checks, then reached."""
        calls = [0]

        def floor(budget):
            calls[0] += 1
            return 10 ** 12 if calls[0] <= n else 0
        return floor

    def reserve_script(self, m):
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        main, alt = self.lanes6(contracts=[hc], logic=[hu], **{"contracts.alt": [hio]})
        return main, alt, (hc, hu, hio)

    def test_a_judge_reserve_stop_that_cuts_only_alternate_candidates_is_a_coverage_note(self):
        m = self.big()
        main, alt, (hc, hu, hio) = self.reserve_script(m)
        main += [vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                 judge(w([shid("contracts", 0, hc)]), w([shid("logic", 0, hu)]))]
        with mock.patch.object(sweeps, "judge_reserve_floor", self.floor_after(2)):
            res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, hc), shid("logic", 0, hu)])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual([(d["subjectIds"], d["reason"]) for d in vpay["drops"]],
                         [([shid("contracts.alt", 0, hio)], "budget")])
        notes = lanes.v10_alt_coverage(self.payload(res)["payload"], events_of(res), res.incomplete, vpay["drops"])
        self.assertEqual(notes, ["alt-candidates-unverified: 1 alternate-lane candidate(s) not verified "
                                 "(`budget-exhausted`: VERIFY kept the JUDGE reserve)"])
        self.assertIn("alt-candidates-unverified: 1", Path(res.review_path).read_text(encoding="utf-8"))
        self.assertEqual(len(model_calls(res, "JUDGE")), 1)                  # JUDGE ran

    def test_a_judge_reserve_stop_that_cuts_a_v3_candidate_is_incomplete(self):
        m = self.big()
        main, alt, (hc, hu, hio) = self.reserve_script(m)
        main += [vfinal(0, m, path="src/app/core.py", line=3), judge(w([shid("contracts", 0, hc)]))]
        with mock.patch.object(sweeps, "judge_reserve_floor", self.floor_after(1)):
            res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual(res.status, "partial")
        self.assertEqual([(i["stage"], i["reason"]) for i in res.incomplete], [("VERIFY", "budget")])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual([d["subjectIds"] for d in vpay["drops"] if d["reason"] == "budget"],
                         [[shid("logic", 0, hu)], [shid("contracts.alt", 0, hio)]])
        self.assertEqual(len(model_calls(res, "JUDGE")), 1)

    def test_a_final_answer_turn_that_still_requests_context_is_noted_as_turns(self):
        m = self.big()
        main, _ = self.v3_only_script(m)
        alt = [answered_by(e, ALT_MODEL) for e in (ask("contracts.alt", 0), sfinal("logic.alt", 0),
                                                    sfinal("safety.alt", 0))]
        with mock.patch.object(lanes, "V10_FINAL_GROWTH_BP", 10 ** 12):
            res, _ = self.record_v10(m, script(*main), script(*alt))
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        notes = lanes.v10_alt_coverage(self.payload(res)["payload"], events_of(res), res.incomplete)
        self.assertEqual(notes, ["alt-lane-capped: contracts.alt (`turns`; status failed)"])
        self.assertFalse(any(e["agentId"] == "contracts.alt" for e in events_of(res) if e["type"] == "tool.call"))


class AltDeadlines(V10Rig):
    v3_only_script = EndToEnd.v3_only_script

    def plan(self, investigate, soft=4_000):
        plan = copy.deepcopy(V10_PLAN)
        plan["budget"].update(wallClockSec=5_000, softDeadlineSec=soft, hostStopRecording=HOST_STOP_RECORDING,
                              stageCeilingsSec={"INVESTIGATE": investigate, "VERIFY": 300, "JUDGE": 200})
        return plan

    def test_an_alternate_lanes_own_time_slice_is_a_coverage_note(self):
        m = self.big()
        main, _ = self.v3_only_script(m)
        # slices 100..600 s; the v3 lanes take no time, every alternate call 450 s: contracts.alt is stopped by its
        # 400 s slice after its first hop, logic.alt (500 s) answers at once and its floor continuation is stopped,
        # safety.alt starts past the 600 s stage ceiling (its slice)
        alt = [answered_by(e, ALT_MODEL) for e in (ask("contracts.alt", 0), sfinal("logic.alt", 0))]
        res, _ = self.record_timed(m, script(*main), script(*alt), 450.0, plan=self.plan(600))
        self.assertEqual((res.status, res.incomplete), ("completed", []))
        inv = self.payload(res)["payload"]
        self.assertEqual([a["status"] for a in inv["agents"]][3:], ["failed", "completed", "failed"])
        notes = lanes.v10_alt_coverage(inv, events_of(res), res.incomplete)
        self.assertEqual(notes, ["alt-lane-capped: contracts.alt (`deadline-exceeded`: lane time slice; status failed)",
                                 "alt-lane-capped: logic.alt (`deadline-exceeded`; its first-hop draft answer was used)",
                                 "alt-lane-capped: safety.alt (`deadline-exceeded`: lane time slice; status failed)"])

    def test_a_run_deadline_during_the_alternate_lanes_is_incomplete(self):
        m = self.big()
        main, _ = self.v3_only_script(m)
        # the soft run deadline (250 s) passes during contracts.alt (each alternate call 300 s): no further alternate
        # lane starts, which is the run's deadline, not a lane cap
        alt = [answered_by(e, ALT_MODEL) for e in (ask("contracts.alt", 0), sfinal("contracts.alt", 1))]
        res, _ = self.record_timed(m, script(*main), script(*alt), 300.0, plan=self.plan(3_000, soft=250))
        self.assertEqual(res.status, "partial")
        inv = [i for i in res.incomplete if i["stage"] == "INVESTIGATE"]
        self.assertEqual([(i["reason"], i["detail"].split(":")[0]) for i in inv],
                         [("soft-deadline", "specialist logic.alt"), ("soft-deadline", "specialist safety.alt")])
        notes = lanes.v10_alt_coverage(self.payload(res)["payload"], events_of(res), res.incomplete)
        self.assertEqual(notes, [f"alt-lane-stopped: {a} (`deadline-exceeded`: soft run deadline; status failed; "
                                 "counted as incomplete)" for a in ALT[1:]])

    def test_the_optional_end_classifier(self):
        e = lambda code, msg="m": {"code": code, "message": msg}       # noqa: E731
        optional = [None, e("budget-exhausted"), e("provider-error"), e("provider-timeout"), e("repair-exhausted"),
                    e("schema-invalid"), e("deadline-exceeded", "INVESTIGATE time slice of specialist logic.alt reached"),
                    e("deadline-exceeded", "INVESTIGATE stage ceiling reached")]
        counted = [e("live-calls-disabled"), e("model-unresolved"), e("contract-violation"), e("internal"),
                   e("deadline-exceeded", "hard run deadline reached"),
                   e("deadline-exceeded", "soft deadline: no new agent starts")]
        self.assertTrue(all(lanes.v10_optional_error(x) for x in optional))
        self.assertFalse(any(lanes.v10_optional_error(x) for x in counted))
        self.assertEqual([lanes.v10_deadline_cause(x) for x in counted[-2:]], ["hard run deadline", "soft run deadline"])


# ---------------------------------------------------------------- identity

class Bytes(CrossRig):
    def test_v7_runs_are_byte_identical_to_the_pre_change_recording(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        res, _ = self.record_v7(m, main, alt, eval_id="evr_" + "a" * 16)
        self.assertEqual(pin_of(res), V7_PINS["v7_e2e"])


class Identity(V10Rig):
    def test_v10_rules_and_the_alternate_model_are_bound_into_the_v10_identity_only(self):
        m = self.big()
        backend, _ = self.record_backend(script())
        spec = self.spec(m, backend, profile=V10_PROFILE, plan=V10_PLAN, retrieval=V10_POLICY)
        v3 = self.spec(m, backend, profile=V3_PROFILE, plan=V3_PLAN, retrieval=V3_POLICY)
        v7 = self.spec(m, backend, profile=V7_PROFILE, plan=V7_PLAN, retrieval=V7_POLICY)
        base, b3, b7 = (identity.config_snapshot_id(s) for s in (spec, v3, v7))
        self.assertEqual(len({base, b3, b7}), 3)
        for name, value in (("V10_FINAL_GROWTH_BP", 15_000), ("V10_LAST_LANE_MARGIN_BP", 0),
                            ("V10_ALT_ROOM_USD_MICROS", 1_000_000), ("V10_FINAL_TEXT", "x"), ("V10_BUDGET_TEXT", "x"),
                            ("V10_VERIFY_TEXT", "x"),
                            ("V10_BEHAVIOR", "x")):
            orig = getattr(lanes, name)
            try:
                setattr(lanes, name, value)
                self.assertNotEqual(identity.config_snapshot_id(spec), base, name)
                self.assertEqual(identity.config_snapshot_id(v3), b3, name)
                self.assertEqual(identity.config_snapshot_id(v7), b7, name)
            finally:
                setattr(lanes, name, orig)
        other = copy.deepcopy(V10_PROFILE)
        other["alternates"]["investigator"]["model"] = "synthetic-other-fixture"
        self.assertNotEqual(identity.config_snapshot_id(self.spec(m, backend, profile=other, plan=V10_PLAN,
                                                                  retrieval=V10_POLICY)), base)
        old = prompts.IMPACT_V10_TEMPLATES["crossModel"]
        try:
            prompts.IMPACT_V10_TEMPLATES["crossModel"] = {"version": "x"}
            self.assertNotEqual(identity.config_snapshot_id(spec), base)
            self.assertEqual(identity.config_snapshot_id(v3), b3)
            self.assertEqual(identity.config_snapshot_id(v7), b7)
        finally:
            prompts.IMPACT_V10_TEMPLATES["crossModel"] = old
        self.assertEqual(identity.plan_specialists(spec), list(ALL))


if __name__ == "__main__":
    unittest.main()
