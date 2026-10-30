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
from reviewer.contracts.budget import investigation_limit, stage_ceiling
from reviewer.contracts.canonical import digest
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, lanes, prompts, specialists, sweeps

from tests.pipeline.helpers import events_of, hyp, judge, model_calls, script, vfinal
from tests.pipeline.test_cross_model_v7 import (ALT_MODEL, ALT_PRICE, MAIN_MODEL, V1_V5_REPO, V7_PLAN, V7_POLICY,
                                                V7_PROFILE, CrossRig, PerModel, answered_by, repo_identity)
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PLAN, V3_POLICY, V3_PROFILE, ask, inv_calls, sfinal, shid

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
V7_PINS = json.loads("""{"v7_e2e": {"INVESTIGATE": "sha256:9d13d0f02425d5b08fa6d311fea9715341cbf2b1cb8a6cabab6018a4c77619c5", "PUBLISH": "sha256:6be145b79c2542de0cd7a9044fb94511c750f2bf8a1219e663d2046240568861", "VERIFY": "sha256:fdb654b889fe3b0cf8b2511782e9680e84c7994a161d7dd632b27e63693336da", "cfg": "sha256:5a57bd0cec90eede96808ebde12a6df9d0dbbf789982661c4718b4b2e0470ac2", "requests": ["sha256:59630fd815416f501e3fda3a8f6f3847dafa2cce8a3f0f6d3ee513ebe5aec216", "sha256:171138bf227bfcea547598cf0590b8ec160cb91c70e587d44a4c194b623cc878", "sha256:88f5d57ce7f80a018cde73d70236b043640ed17b89b2dc67ce40933bcb3d65be", "sha256:4e1702fdfe7dba1bff25e92d4b300f76a2e1dedca6a84a3baf6f94f0abdfaf48", "sha256:8a7563fd3c45ade67019839a25a6ecd0783ef1bb6581bc7dfa5888e1aeb1e42f", "sha256:e0f0933f1fa5b28cb9e75ceeb85f27f83f4c060fccf1508d503fa8c7cc6efb0b", "sha256:fac4848ab94404b7b10438fcd65d91c9ba0af1710600e450693b6d9435ad14c9", "sha256:7652614e677b10b1aa567d2cfdc7c27497ee4c11d2af0c74d3c8744737cd60fb", "sha256:278d00286b6aca36d18d660c69eae52b10271b13720d30ac34851d88a3d0b5ee", "sha256:d53b4f9e813be4d52ab8498803645362fff29aca14397c46d2cc2cd2d1d6b8b8", "sha256:07178753dc9218ea9f1e0330eebb10c343f084940abfad3284c6e0697efbe239", "sha256:7cbd9d40f00deb69173a5e7780bd702cd05d8cab8eaac92b7b93bde297e0a842", "sha256:304ec5369b45cf796a2e7bcb7120c068f1f102fb8274446fcff3d4af0343025d", "sha256:fbce68fb09757c8360f3c41d34f98f12f06ea6a2f8b1cfb5e9047676bc7cfa47", "sha256:cd8a24722eab09da0bb0922a4bda2185189b4d2e703a4f9e3247ec8edbf53a41", "sha256:f2899ce0b250fe52fd7aca3b67977eda0d406aa69449e5e6ea32bcfc005d04b1", "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24", "sha256:a742f7ff0a8e7525ced31d285adede847b130c476171536bbc0b717ab6f15136", "sha256:1cf20e36998b0c4010720a2a8817da18e9d5f14d0486a0484ad0c1fe145c0bc8", "sha256:f7b4f0d29c58c0d05c7edef8a2e762cec911e5f9a343dfd9647ca8ed1b9e32d6", "sha256:b09abdb9016229c01dce583cc0db8af792a117b838fdbf31cb0d481540a95e40"], "trace": "sha256:127ce47a52e2e3eefa10d4f27eda28af36e661d346680dea6a4985236903a89f"}, "v7_repo_pullo-terra.toml": "sha256:c04fc69abc3bb0a8f00d943653de461881d8d82976f69b819493701f0e84a541"}""")


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
        for live, stages, clock in ((True, {"INVESTIGATE": 600, "VERIFY": 300, "JUDGE": 200}, (1_500, 1_200)),
                                    (False, {"INVESTIGATE": 240}, (1_200, 900))):
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
                for st in ("VERIFY", "JUDGE"):          # VERIFY and JUDGE keep v3's ceilings
                    self.assertEqual(stage_ceiling(st, b3), stage_ceiling(st, b10), st)
                host = 60
                self.assertEqual(lanes.v10_tool_cumulative(pol10, b10, host)[:3],
                                 specialists.cumulative(specialists.tool_pool(pol3, b3, host)))
                self.assertEqual(lanes.v10_primary_spend_cumulative(b10), specialists.cumulative(investigation_limit(b3)))
                self.assertEqual(lanes.v10_time_slices(stage_ceiling("INVESTIGATE", b10))[:3],
                                 specialists.time_slices(stage_ceiling("INVESTIGATE", b3)))
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
        # the v3 rule (specialist-merge@2) would merge every later one into `kept`
        self.assertEqual(specialists.merge([kept, field], list(V3_LANES))[0]["mergedIds"], [field["id"]])
        self.assertEqual(lanes.v10_merge(hs), [{"keptId": kept["id"], "mergedIds": [same["id"]],
                                                "rule": "cross-model-merge@1"}])
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
            self.assertEqual((s["share"], s["altTop"], s["altCumulative"]),
                             (2_800_000, 1_200_000, [400_000, 800_000, 1_200_000]))
        b = {"maxUsdMicros": 4_000_000, "verifyReserveBp": 3000}
        self.assertEqual([lanes.v10_alt_spend_ceiling(1_000_000, j, b) for j in range(3)],
                         [1_400_000, 1_800_000, 2_200_000])
        # v3 lanes that spent nearly their whole share leave the alternate model only up to v3's investigation share
        self.assertEqual([lanes.v10_alt_spend_ceiling(2_600_000, j, b) for j in range(3)], [2_800_000] * 3)
        self.assertEqual(b["maxUsdMicros"] - lanes.v10_spend_top(b), 1_200_000)     # VERIFY + JUDGE keep v3's >= 30%


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

    def test_alternate_model_spend_is_capped_without_touching_the_v3_lanes(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        with mock.patch.object(lanes, "V10_ALT_SPEND_BP", 1):            # $0.0004 for all alternate lanes
            res, spy = self.record_v10(m, main, alt)
        self.assertEqual(res.status, "partial")
        agents = {a["agentId"]: a for a in self.payload(res)["payload"]["agents"]}
        self.assertTrue(all(agents[a]["status"] == "completed" for a in V3_LANES))
        self.assertEqual([agents[a]["status"] for a in ALT], ["budget"] * 3)
        errs = [e["error"] for e in events_of(res) if e["type"] == "error"
                and (e["error"].get("detail") or {}).get("scope") == "alternate-model-share"]
        self.assertEqual({e["detail"]["rule"] for e in errs}, {lanes.V10_BUDGET_RULE})
        self.assertEqual(spy.inner[ALT_MODEL].calls, 1)                 # the first call was admitted below the cap
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")][:2],
                         [shid("contracts", 0, self.h_core(m)), shid("logic", 0, self.h_util(m))])

    def test_a_v3_lane_over_its_v3_share_names_the_v3_rule(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        with mock.patch.object(lanes, "v10_primary_spend_cumulative", lambda budget: [1, 1, 1]):
            res, _ = self.record_v10(m, main, alt)
        errs = [e["error"] for e in events_of(res) if e["type"] == "error"
                and (e["error"].get("detail") or {}).get("scope") == "specialist-share"]
        self.assertTrue(errs)
        self.assertEqual({e["detail"]["rule"] for e in errs}, {specialists.BUDGET_RULE})

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
        # v3: output order inside a lane (conf2 before the P1 hc), round-robin across lanes, cap -> over-cap
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, conf2), shid("logic", 0, hu)])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        over = [d for d in vpay["drops"] if d["reason"] == "over-cap"]
        self.assertEqual([d["subjectIds"] for d in over], [[shid("safety.alt", 0, hio)], [shid("contracts", 1, hc)]])
        self.assertIn("round-robin specialist order", over[0]["detail"])
        self.assertEqual({e["request"]["model"] for e in model_calls(res, "VERIFY")}, {MAIN_MODEL})   # verifier unchanged

    def test_verify_has_no_judge_reserve_stop_as_in_v3(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        with mock.patch.object(sweeps, "judge_reserve_floor", lambda budget: 0):
            res, _ = self.record_v10(m, main, alt)
        self.assertEqual(len(model_calls(res, "VERIFY")), 4)
        self.assertEqual(res.status, "completed", res.incomplete)


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
        for name, value in (("V10_ALT_SPEND_BP", 2000), ("V10_BUDGET_TEXT", "x"), ("V10_VERIFY_TEXT", "x"),
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
