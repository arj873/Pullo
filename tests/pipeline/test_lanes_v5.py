"""SPECIALISTS-V5-01: investigator.impact@v5 five specialist lanes (contracts, logic, safety unchanged; consistency,
hygiene new) and the near-duplicate cap, through the real engine, contracts, gateway (scripted synthetic provider) and
tools.

Invented self-contained fixtures only: no network, key, state, target repository or live call. These tests prove the
mechanics (lane order and texts, the five-lane budget/time split, the near-duplicate cap and its disclosure, round-robin
VERIFY with a scaled cap, renewed sessions and the JUDGE reserve, identity binding, strict replay and load) and that
impact@v1-v4 stay byte-identical. They do NOT show that the new lanes make a real model find more defects."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import validate
from reviewer.contracts.canonical import digest
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, lanes, prompts, specialists, sweeps

from tests.pipeline.helpers import TURN_PLAN, entry, events_of, hyp, judge, model_calls, script, tool_calls, treq, vfinal
from tests.pipeline.test_diff_shards import V4_PLAN, V4_POLICY, V4_PROFILE, DiffShardRig, Identity as V4Identity
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PLAN, V3_POLICY, V3_PROFILE, ask, inv_calls, sfail, sfinal, shid, sturn

INV5, VER = prompts.INVESTIGATOR_IMPACT_V5_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
LANES = ("contracts", "logic", "safety", "consistency", "hygiene")
V5_PROFILE = copy.deepcopy(V3_PROFILE)
V5_PROFILE["roles"]["investigator"]["promptVersion"] = INV5
V5_POLICY = RetrievalPolicy(investigator_prompt=INV5, verifier_prompt=VER, run_tool_calls=320)
V5_PLAN = copy.deepcopy(TURN_PLAN)
V5_PLAN["specialists"] = list(LANES)
V5_PLAN["budget"].update(maxToolCalls=320, stageCeilingsSec={"INVESTIGATE": 200})     # as repository_plan builds it

# impact@v4 recordings from the pre-change source (main 71b17981): DiffShardRig.e2e_script on the 9-path case (eval id
# c...) and SpecRig.three_script on the small case (eval id d...).
V4_PINS = {
 "v4_big": {
  "INVESTIGATE": "sha256:350f0b72a5478715f94973328d5596c0a0d2cabff3cd2a63c4c7f9fcca003a79",
  "PUBLISH": "sha256:96aec1c823accd5caaf9d21fde71adde91019b76dc671efb9e28841e2ac697a9",
  "VERIFY": "sha256:354b3c8f6e217f8400324d15f92491a11371fc8e68f8ea851f7ae8c44c75c602",
  "cfg": "sha256:97ef13ef709cbb9b60553d3636de37adc80a7240a95cb246fa9021295460bd26",
  "requests": [
   "sha256:ce18825b43b9789db9209cbd279a34c2d93401cd99ae3d66d53617d4ff48fc17",
   "sha256:4150a24da2d2ee92e775976a66182ec4ce7dd0028f45bdcf405970f448a3da08",
   "sha256:860d83ca83303e890dc23f43a4b406268d92f1c42d302186d392641647f78504",
   "sha256:e2f0b00169ee7701cfed3592f590bf8b8471e2f5136158ec26434d28953562ae",
   "sha256:dbb30027e06e385cb5ee18a9620a08c4032941cb5537042b017b2107a253bfea",
   "sha256:e0b277e91533fc3491e32d7bc43bb9730db4cccf2e5010337ad14506b3865aa2",
   "sha256:5a56c3342818f4a5818242d2524e2fc11495a7a1ae56823c07a69be8d7402d1d",
   "sha256:f618b5c478b74eaa6de64619162957e2bfc4e0aa44c5c14e696731a0190a5612",
   "sha256:fce8da1c4458272bb0d75104799083927861e7a4f8d3aae039202ac27ce121ce",
   "sha256:bfbe6bf341b87428756e20705718cde3c7c1c461a2b88190b31058820f3ceab3",
   "sha256:d077ef091ae7bf97ee30a0ae0f8f244c4f99852bbb67b09df160f82e15c0d9bf",
   "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24",
   "sha256:f7f6efab4fd3884f62c8f6f277dac3e2ac3b7c59922dd4df0725f7d1a24948a2",
   "sha256:af5a41a6b008aba3289726d0d4fc92facba1d7ec674142ebb07030cfeabc5ddb",
   "sha256:db1d123d7053c44d54e25d1ba423b57a77ecec79b2aaf209fda8f8339698f2cf"
  ],
  "trace": "sha256:f9f0b8dbac56bbcfa6fba0df8e27bdeda1ead33662eda9818408d96d063660e2"
 },
 "v4_small": {
  "INVESTIGATE": "sha256:04f14c00962c1ded027a0072681c925cf836d10cfdc893fed3f8cac0c0e99b48",
  "PUBLISH": "sha256:40cf804050ddfac1f97330fbad045957f9ccdba75c520dccf90afe66068c0451",
  "VERIFY": "sha256:3d0a51535ff9c17425184cdfcd5ba0ca1de9360307bc5a2f6b861fdb2836f7f6",
  "cfg": "sha256:3f072ded9b8751ad7da33aa55151957387e06202a057e53b4d3f495a95b5acc9",
  "requests": [
   "sha256:8af6f3b4b73e53f78c95c2064aab2f3afe7c67ae087a77a49736a8b27b56f785",
   "sha256:9364de1de4a002655dff2c871791331610b2b40b56ba76ddeb68c194d2e1585c",
   "sha256:67d6d0cc7fd91185247ebcefbe8913287f64a61331066bdcd365652da3d4ac4b",
   "sha256:dee5042bd2923500af41d0addf801b3f9e2173e74abef78776c4eca99a6622e3",
   "sha256:05a9ef2a8e402c0524da309644a76758f2067255759f176e0ab7227d45bf92f6",
   "sha256:209153e150c480873584e1cee8f86520e8729dc71bb1cd9652c6126cb9379184",
   "sha256:8ad1f0c65134754c71c69fa1d0bc598a7fb329c6c698f3820b6c6402e3080440",
   "sha256:3c7948f5f213e4c23c8ef5e614f3512e1097d68a975aee0c053338e64297f8c6",
   "sha256:4439dc8da87e024380f3394dac4865254b899b631042ad1843e51789c43952f6",
   "sha256:08d029d2693d44b1517c2c4c36607c7d25b66a43818e25637e9151b0f553d3ae"
  ],
  "trace": "sha256:3e7bf367ade5156a67f2357ef154e68989f346c1686b6f79570958c522b811c5"
 }
}
# repository_profile / plan / plan with live stage timing / policy digests of impact@v4, pre-change
V4_REPO = ("sha256:2cc9cc678304bfa6ff56d70fc9ef4d82d2f1ca06cd2b0f317ec549265e39faaf",
           "sha256:fd9cda7e7053f74eb5019de49785a63020a50a621a04b8d135f5dd722e315836",
           "sha256:19cc8495db25df43942addafce7ffffca7a37855774b93dfb68bcba775a705ee",
           "sha256:d9e5643ee15334d5fbc4a99e9c2be125376133154e7a10d63d87f4afc23bdc6f")


DTO_BASE = ("def to_dto(user):\n    dto.userId = user.userId\n    dto.orgId = user.orgId\n    dto.teamId = user.teamId\n"
            "    return dto\n")
DTO_HEAD = ("def to_dto(user):\n    dto.userId = user.orgId\n    dto.orgId = user.orgId\n    dto.teamId = user.teamId\n"
            "    dto.userId = user.teamId\n")


def lanes_of(res):
    return [(c["agentId"], c["ordinal"]) for c in inv_calls(res)]


class LaneRig(DiffShardRig):
    def record_v5(self, m, scr, **kw):
        kw.setdefault("profile", V5_PROFILE)
        kw.setdefault("retrieval", V5_POLICY)
        kw.setdefault("plan", V5_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v5(self, m, res, **kw):
        kw.setdefault("profile", V5_PROFILE)
        kw.setdefault("retrieval", V5_POLICY)
        kw.setdefault("plan", V5_PLAN)
        return self.replay(m, res, **kw)

    def h_test(self, m, claim="the test asserts the buggy total", line=5, extra=()):
        return hyp(m, "tests/test_core.py", line, claim=claim, category="test-gap", severity="P2",
                   impact="regression", evidence=[m.cite("tests/test_core.py", line), *extra])

    def five(self, m, **finals):
        out = []
        for a in LANES:
            out += [ask(a, 0), sfinal(a, 1, *finals.get(a, ()))]
        return out

    def e2e_script(self, m):
        hc, hu, ht = self.h_core(m), self.h_util(m), self.h_test(m)
        scr = script(*self.five(m, contracts=[hc], consistency=[hu], hygiene=[ht]),
                     vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                     vfinal(2, m, path="tests/test_core.py", line=5),
                     judge(w([shid("contracts", 0, hc)]), w([shid("consistency", 0, hu)]), w([shid("hygiene", 0, ht)])))
        return scr, (hc, hu, ht)


# ---------------------------------------------------------------- pure rules

def H(n, agent, path, line, cat="bug", paths=1, items=1, sev="P1", mech=True, claim="field total is read twice",
      end=None):
    ev = [{"kind": "code", "path": f"{path}" if i == 0 else f"other{i}.py"} for i in range(paths)]
    ev += [{"kind": "code", "path": path} for _ in range(items - paths)]
    h = {"id": f"hyp_{n:016x}", "specialist": agent, "category": cat, "suspectedSeverity": sev, "claim": claim,
         "location": {"path": path, "line": line, **({"endLine": end} if end else {})}, "evidence": ev}
    if mech:
        h["mechanism"] = "m"
    return h


class Rules(unittest.TestCase):
    def test_five_lane_budget_and_time_split_on_the_pilot(self):
        from reviewer.pilot.repository_profile import repository_plan, repository_policy, repository_profile
        p5 = repository_profile(True, impact_version=5)
        for live, secs in ((True, [100, 200, 300, 400, 500]), (False, [40, 80, 120, 160, 200])):
            plan = repository_plan(p5, live_stage_timing=live)
            d = lanes.budget_doc(repository_policy(True, impact_version=5), plan["budget"], 60)
            self.assertEqual(d["agents"], list(LANES))
            self.assertEqual(d["toolCalls"]["cumulative"], [20, 40, 60, 80, 100])        # the v3 lane size each
            self.assertEqual(d["spendUsdMicros"]["cumulative"], [440_000, 880_000, 1_320_000, 1_760_000, 2_200_000])
            self.assertEqual(d["timeSec"]["cumulative"], secs)                           # the v3 per-lane seconds
        self.assertEqual(lanes.spend_top({"maxUsdMicros": 4_000_000, "verifyReserveBp": 3000}), 2_200_000)
        self.assertEqual(lanes.spend_top({"maxUsdMicros": 4_000_000, "verifyReserveBp": 6000}), 1_600_000)
        self.assertEqual(sweeps.judge_reserve_floor({"maxUsdMicros": 4_000_000}), 3_700_000)
        self.assertEqual((lanes.verify_cap(5), lanes.verify_cap(3), lanes.verify_cap(9)), (28, 20, 40))
        self.assertEqual(specialists.time_slices(300), [100, 200, 300])                  # the v3 default is unchanged
        self.assertEqual(specialists.cumulative(60), [20, 40, 60])

    def test_distinct_defects_on_adjacent_lines_are_never_collapsed(self):
        # the gate's case: one lane, one category, three different wrong-field bugs on lines 10/11/12 of one mapping block
        hs = [H(1, "consistency", "map.py", 10, claim="user.email is assigned from the name field"),
              H(2, "consistency", "map.py", 11, claim="user.phone copies the email value"),
              H(3, "consistency", "map.py", 12, claim="address is filled from billing instead of shipping")]
        self.assertEqual(lanes.collapse(hs, []), [])
        # even with similar wording, non-overlapping lines are different spots
        same = [H(n, "consistency", "map.py", 10 + n, claim="field total is read twice") for n in range(3)]
        self.assertEqual(lanes.collapse(same, []), [])

    def test_true_near_duplicates_collapse_to_the_best_evidenced_with_best_first_fallback_order(self):
        hs = [H(1, "logic", "a.py", 10, claim="the loop skips the first item of items"),
              H(2, "logic", "a.py", 10, paths=2, claim="the loop skips the first item"),
              H(3, "logic", "a.py", 9, end=11, items=3, claim="loop skips the first item of the list"),
              H(4, "logic", "a.py", 10, claim="the timeout is never refreshed inside the retry"),   # same spot, other claim
              H(5, "logic", "a.py", 10, cat="security", claim="the loop skips the first item"),     # other category
              H(6, "hygiene", "b.py", 10, claim="the loop skips the first item")]                  # other file
        got = lanes.collapse(hs, [])
        self.assertEqual(got, [{"keptIds": [hs[1]["id"]], "collapsedIds": [hs[2]["id"], hs[0]["id"]],
                                "rule": "near-duplicate-cap@3"}])
        self.assertEqual(lanes.collapse(list(hs), []), got)                               # deterministic
        merged = [{"keptId": hs[1]["id"], "mergedIds": [hs[2]["id"]], "rule": specialists.MERGE_RULE}]
        self.assertEqual(lanes.collapse(hs, merged)[0]["collapsedIds"], [hs[0]["id"]])   # the merge decides first
        self.assertTrue(lanes.similar({"claim": "Loop skips first item"}, {"claim": "the loop skips the first item"}))
        self.assertFalse(lanes.similar({"claim": "a b"}, {"claim": "c d"}))

    def test_templated_claims_naming_different_fields_are_never_collapsed(self):
        # the re-gate's case: one block range, claims differing only in the field (Jaccard ~0.78)
        a = H(1, "consistency", "dto.py", 10, end=14, claim="toDto copies user.orgId into dto.userId instead of user.userId")
        b = H(2, "consistency", "dto.py", 10, end=14, claim="toDto copies user.teamId into dto.userId instead of user.userId")
        self.assertGreaterEqual(len(lanes.claim_words(a["claim"]) & lanes.claim_words(b["claim"]))
                                / len(lanes.claim_words(a["claim"]) | lanes.claim_words(b["claim"])), 0.75)
        self.assertEqual(lanes.collapse([a, b], []), [])
        for x, y in (("off by one in `retries`", "off by one in `attempts`"), ("limit 10 is wrong", "limit 20 is wrong"),
                     ("MAX_SIZE ignored here", "MIN_SIZE ignored here"), ("uses fooBar", "uses fooBaz")):
            self.assertFalse(lanes.similar({"claim": x}, {"claim": y}), (x, y))
        self.assertEqual(lanes.distinctive("toDto copies user.orgId"), frozenset({"toDto", "user.orgId"}))

    def test_value_order_inside_a_lane(self):
        ds = [{"suspectedSeverity": "P2"}, {"suspectedSeverity": "P0"}, {"suspectedSeverity": "P1", "confidence": 0.2},
              {"suspectedSeverity": "P1", "confidence": 0.9}, {"suspectedSeverity": "P1"}]
        self.assertEqual(sorted(range(5), key=lambda n: lanes.value_key(ds[n], n)), [1, 3, 2, 4, 0])

    def test_lane_tasks_keep_the_v3_lenses_and_add_two(self):
        for a in ("contracts", "logic", "safety"):
            self.assertEqual(prompts.specialist_task(a), prompts.investigator_v3_task(a))
        for a in ("consistency", "hygiene"):
            t = prompts.specialist_task(a)
            self.assertTrue(t.startswith(prompts.INVESTIGATOR_IMPACT_V2_TASK + " Specialist lens ("))
            low = " ".join(t.split()).lower()
            self.assertIn("concrete", low)
            self.assertIn("give one hypothesis per defect", low)
        cons = " ".join(prompts.specialist_task("consistency").split())
        for k in ("operand by operand", "siblings", "read them with read_file even though they are unchanged",
                  "every branch that a configuration flag"):
            self.assertIn(k, cons)
        hyg = " ".join(prompts.specialist_task("hygiene").split())
        for k in ("never refreshes", "default", "early return", "cannot fail", "passes for a different failure",
                  "low (P2)", "Never report style", "A test that merely could check more is not a defect"):
            self.assertIn(k, hyg)
        self.assertNotIn("check too little", hyg)
        self.assertEqual(prompts.V5_AGENTS, LANES)


# ---------------------------------------------------------------- end to end

class EndToEnd(LaneRig):
    def test_five_lanes_run_in_order_with_their_tasks_and_verify_round_robin(self):
        m = self.big()
        scr, (hc, hu, ht) = self.e2e_script(m)
        res, spy = self.record_v5(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual(lanes_of(res), [(a, k) for a in LANES for k in (0, 1)])
        firsts = [r for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0]
        self.assertEqual([doc_of(r)["task"] for r in firsts], [prompts.specialist_task(a) for a in LANES])
        self.assertEqual({r["promptVersion"] for r in firsts}, {INV5})
        for r in firsts:
            self.assertEqual(doc_of(r)["retrieval"]["tools"], prompts.IMPACT_RETRIEVAL_TOOLS)
        # cumulative ceilings 20/40/60/80/100 with rollover (each lane logged one call); the test host limit is 50
        self.assertEqual([doc_of(r)["retrieval"]["toolCallsRemaining"] for r in firsts], [20, 39, 50, 50, 50])
        pay = self.payload(res)["payload"]
        self.assertEqual([a["agentId"] for a in pay["agents"]], list(LANES))
        self.assertEqual((pay["merges"], pay["collapses"]), ([], []))
        self.assertNotIn("sweep", pay)
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, hc), shid("consistency", 0, hu), shid("hygiene", 0, ht)])
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["consistency", "contracts", "hygiene"])
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("- hygiene: completed; 1 resolved hypothesis(es)", md)
        self.assertIn("Near-duplicates collapsed before verification (same file, category and spot; the best evidenced "
                      "kept): 0", md)

    def test_strict_replay_and_load_rederive_a_v5_run(self):
        from reviewer.pipeline import runner
        m = self.big()
        res, _ = self.record_v5(m, self.e2e_script(m)[0])
        rep = self.replay_v5(m, res)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(rep.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
        for st in ("INVESTIGATE", "VERIFY"):
            self.assertEqual(rep.receipt["artifactDigests"][st], res.receipt["artifactDigests"][st], st)
        self.assertEqual([h["id"] for h in rep.hypotheses], [h["id"] for h in res.hypotheses])
        self.assertEqual(runner.load_result(self.out, res.run_id).hypotheses, res.hypotheses)
        with mock.patch.object(lanes, "collapse", lambda hyps, merges: [{"keptIds": [hyps[0]["id"]],
                                                                         "collapsedIds": [hyps[1]["id"]],
                                                                         "rule": "near-duplicate-cap@3"}]):
            with self.assertRaises(PipelineError) as c:
                runner.load_result(self.out, res.run_id)
        self.assertEqual(c.exception.code, "checkpoint-invalid")
        with self.assertRaises(PipelineError) as c:
            self.replay(m, res, profile=V3_PROFILE, plan=V3_PLAN, retrieval=V3_POLICY, eval_id="evr_" + "9" * 16)
        self.assertEqual(c.exception.code, "identity-mismatch")


class NearDuplicates(LaneRig):
    def dups(self, m):
        h1 = self.h_test(m, "the test asserts the buggy total value")
        h2 = self.h_test(m, "the test asserts the buggy total", extra=[m.cite("src/app/core.py", 3)])
        h3 = self.h_test(m, "this test asserts the buggy total value too")
        return h1, h2, h3

    def test_true_near_duplicates_are_collapsed_before_verify_and_disclosed(self):
        m = self.big()
        h1, h2, h3 = self.dups(m)
        scr = script(*self.five(m, hygiene=[h1, h2, h3]), vfinal(0, m, path="tests/test_core.py", line=5), judge())
        res, _ = self.record_v5(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        ids = [shid("hygiene", n, h) for n, h in enumerate((h1, h2, h3))]
        pay = self.payload(res)["payload"]
        self.assertEqual(pay["collapses"], [{"keptIds": [ids[1]], "collapsedIds": [ids[0], ids[2]],
                                             "rule": "near-duplicate-cap@3"}])
        self.assertEqual([h["id"] for h in pay["hypotheses"]], ids)                     # kept in the artifact
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")], [ids[1]])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual(sorted((d["subjectIds"][0], d["reason"]) for d in vpay["drops"]),
                         sorted([(ids[0], "merged"), (ids[2], "merged")]))
        self.assertIn("near-duplicate-cap@3", vpay["drops"][0]["detail"])
        self.assertIn("the best evidenced kept): 2", Path(res.review_path).read_text(encoding="utf-8"))

    def test_a_refuted_kept_member_hands_verify_the_best_collapsed_one(self):
        m = self.big()
        h1, h2, h3 = self.dups(m)
        ids = [shid("hygiene", n, h) for n, h in enumerate((h1, h2, h3))]
        scr = script(*self.five(m, hygiene=[h1, h2, h3]),
                     vfinal(0, m, verdict="refuted", evidence=[m.cite("tests/test_core.py", 5)]),
                     vfinal(1, m, path="tests/test_core.py", line=5), judge(w([ids[0]])))
        res, _ = self.record_v5(m, scr)
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")], [ids[1], ids[0]])
        self.assertEqual([f["id"] for f in res.findings], [ids[0]])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual([(d["subjectIds"], d["reason"]) for d in vpay["drops"]],
                         [([ids[1]], "refuted"), ([ids[2]], "merged")])

    def test_orgid_and_teamid_defects_over_one_block_are_both_verified(self):
        m = self.mini("dto-1", base={"src/dto.py": DTO_BASE}, head={"src/dto.py": DTO_HEAD})
        ha, hb = (hyp(m, "src/dto.py", 2, end=5, claim=f"toDto copies user.{f} into dto.userId instead of user.userId",
                      category="bug", evidence=[m.cite("src/dto.py", 2, 5)]) for f in ("orgId", "teamId"))
        scr = script(*self.five(m, consistency=[ha, hb]), vfinal(0, m, path="src/dto.py", line=3),
                     vfinal(1, m, path="src/dto.py", line=3), judge())
        res, _ = self.record_v5(m, scr)
        self.assertEqual(self.payload(res)["payload"]["collapses"], [])
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("consistency", 0, ha), shid("consistency", 1, hb)])
        self.assertEqual(len(res.findings), 2)

    def test_a_collapsed_merge_keeper_still_hands_verify_its_own_duplicate(self):
        m = self.big()
        c1 = hyp(m, "src/app/core.py", 3, claim="the loop skips the first item", evidence=[m.cite("src/app/core.py", 3)])
        k1 = hyp(m, "src/app/core.py", 3, claim="the loop skips the first item of the list",
                 evidence=[m.cite("src/app/core.py", 3), m.cite("src/app/use.py", 5)])
        d1 = hyp(m, "src/app/core.py", 4, claim="items[0] is never added", evidence=[m.cite("src/app/core.py", 4)])
        ids = {"c1": shid("contracts", 0, c1), "k1": shid("contracts", 1, k1), "d1": shid("logic", 0, d1)}
        refute = lambda n: vfinal(n, m, verdict="refuted", evidence=[m.cite("src/app/core.py", 3)])  # noqa: E731
        scr = script(*self.five(m, contracts=[c1, k1], logic=[d1]), refute(0), refute(1),
                     vfinal(2, m, path="src/app/core.py", line=4), judge(w([ids["d1"]])))
        res, _ = self.record_v5(m, scr)
        pay = self.payload(res)["payload"]
        self.assertEqual(pay["merges"], [{"keptId": ids["c1"], "mergedIds": [ids["d1"]], "rule": specialists.MERGE_RULE}])
        self.assertEqual(pay["collapses"], [{"keptIds": [ids["k1"]], "collapsedIds": [ids["c1"]],
                                             "rule": "near-duplicate-cap@3"}])
        # k1 refuted -> the collapse fallback verifies c1 (refuted) -> c1's own merged duplicate d1 is still retried
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [ids["k1"], ids["c1"], ids["d1"]])
        self.assertEqual([f["id"] for f in res.findings], [ids["d1"]])

    def test_judge_is_offered_one_group_for_a_defect_confirmed_by_both_fallbacks(self):
        m = self.big()
        k = hyp(m, "src/app/core.py", 3, claim="the loop skips the first item of the list",
                evidence=[m.cite("src/app/core.py", 3), m.cite("src/app/use.py", 5)])
        c = hyp(m, "src/app/core.py", 3, claim="the loop skips the first item", evidence=[m.cite("src/app/core.py", 3)])
        d = hyp(m, "src/app/core.py", 3, claim="range(1, n) drops items[0]", evidence=[m.cite("src/app/core.py", 3)])
        ids = {"k": shid("contracts", 0, k), "c": shid("contracts", 1, c), "d": shid("logic", 0, d)}
        scr = script(*self.five(m, contracts=[k, c], logic=[d]),
                     vfinal(0, m, verdict="refuted", evidence=[m.cite("src/app/core.py", 3)]),
                     vfinal(1, m, path="src/app/core.py", line=3), vfinal(2, m, path="src/app/core.py", line=3),
                     judge(w([ids["c"], ids["d"]])))
        res, spy = self.record_v5(m, scr)
        pay = self.payload(res)["payload"]
        self.assertEqual(pay["merges"][0]["mergedIds"], [ids["d"]])                    # d: a cross-lane duplicate of k
        self.assertEqual(pay["collapses"][0]["collapsedIds"], [ids["c"]])              # c: a near-duplicate of k
        self.assertEqual(sorted(f["id"] for f in res.findings), sorted([ids["c"], ids["d"]]))   # confirmed twice
        jreq = doc_of(next(r for r in spy.requests if r["role"] == "judge"))
        self.assertIn(sorted([ids["c"], ids["d"]]), [sorted(g) for g in jreq["duplicateCandidateGroups"]])
        self.assertEqual(len(res.comments), 1)                                          # the judge merged them
        self.assertEqual(sorted(res.comments[0]["findingIds"]), sorted([ids["c"], ids["d"]]))

    def test_the_gates_adjacent_distinct_defects_are_all_verified(self):
        m = self.big()
        hs = [hyp(m, "src/app/core.py", k, claim=c, category="bug", evidence=[m.cite("src/app/core.py", k)])
              for k, c in ((2, "the sum starts from the wrong field"), (3, "the range skips index zero"),
                           (4, "the accumulator adds the wrong element"))]
        scr = script(*self.five(m, consistency=hs), *[vfinal(n, m, path="src/app/core.py", line=k)
                                                       for n, k in enumerate((2, 3, 4))], judge())
        res, _ = self.record_v5(m, scr)
        self.assertEqual(self.payload(res)["payload"]["collapses"], [])
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("consistency", n, h) for n, h in enumerate(hs)])
        self.assertEqual(len(res.findings), 3)

    def test_cross_lane_duplicates_keep_the_v3_merge_rule(self):
        m = self.big()
        hc = self.h_core(m)
        scr = script(*self.five(m, contracts=[hc], consistency=[hc]), vfinal(0, m, path="src/app/core.py", line=3),
                     judge(w([shid("contracts", 0, hc)])))
        res, _ = self.record_v5(m, scr)
        pay = self.payload(res)["payload"]
        self.assertEqual(pay["merges"], [{"keptId": shid("contracts", 0, hc), "mergedIds": [shid("consistency", 0, hc)],
                                          "rule": specialists.MERGE_RULE}])
        self.assertEqual(pay["collapses"], [])


class BudgetsAndVerify(LaneRig):
    def test_each_lane_verifies_its_most_valuable_hypotheses_first(self):
        m = self.big()
        lo = hyp(m, "src/app/conf.py", 1, claim="timeout too short", severity="P2", evidence=[m.cite("src/app/conf.py", 1)])
        hi = hyp(m, "src/app/core.py", 3, claim="the loop skips the first item", severity="P0",
                 evidence=[m.cite("src/app/core.py", 3)])
        hu = self.h_util(m)
        scr = script(*self.five(m, logic=[lo, hi], hygiene=[hu]), vfinal(0, m, path="src/app/core.py", line=3),
                     vfinal(1, m, path="src/app/util.py", line=2), vfinal(2, m, path="src/app/conf.py", line=1), judge())
        res, _ = self.record_v5(m, scr)
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("logic", 1, hi), shid("hygiene", 0, hu), shid("logic", 0, lo)])

    def test_tool_calls_follow_the_five_lane_ceilings_with_rollover(self):
        m = self.big()
        reqs = [treq("read_file", side="head", path="src/app/use.py", start_line=k, end_line=k) for k in range(1, 6)]
        with mock.patch.object(lanes, "LANE_TOOL_CALLS", 2):          # pool 10 -> ceilings 2 / 4 / 6 / 8 / 10
            scr = script(ask("contracts", 0), sfinal("contracts", 1), ask("logic", 0), sfinal("logic", 1),
                         sturn("safety", 0, reqs[:5]), sfinal("safety", 1),   # 4 of its 6 - 2 run, the 5th is refused
                         ask("consistency", 0), sfinal("consistency", 1), ask("hygiene", 0), sfinal("hygiene", 1),
                         judge())
            res, spy = self.record_v5(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        rem = [doc_of(r)["retrieval"]["toolCallsRemaining"] for r in spy.requests
               if r["role"] == "investigator" and r["hop"] == 0]
        self.assertEqual(rem, [2, 3, 4, 1, 2])           # unused room rolls forward; a refused logged call counts
        got = [(e["agentId"], e["result"]["status"]) for e in tool_calls(res, "INVESTIGATE")]
        self.assertEqual([st for a, st in got if a == "safety"], ["ok"] * 4 + ["unavailable"])
        self.assertLessEqual(sum(1 for _, st in got if st == "ok"), 10)

    def test_round_robin_across_five_lanes_with_cap_and_renewed_sessions(self):
        m = self.big()
        hs = {"contracts": [self.h_core(m)], "logic": [hyp(m, "src/app/conf.py", 1, claim="timeout too short",
                                                           evidence=[m.cite("src/app/conf.py", 1)])],
              "consistency": [self.h_util(m), self.h_io(m)], "hygiene": [self.h_test(m)]}

        def vent(agent, k, path, line):
            v = vfinal(k, m, path=path, line=line)
            v["agentId"] = agent
            return v
        scr = script(*self.five(m, **hs), vent("verifier", 0, "src/app/core.py", 3),
                     vent("verifier", 1, "src/app/conf.py", 1), vent("verifier-02", 0, "src/app/util.py", 2),
                     vent("verifier-02", 1, "tests/test_core.py", 5), judge())
        with mock.patch.object(lanes, "MAX_VERIFY_CANDIDATES_V5", 4), \
                mock.patch.object(sweeps, "VERIFY_SESSION_CANDIDATES", 2):
            res, _ = self.record_v5(m, scr)
        self.assertEqual(validate_trace(events_of(res)), [])
        order = [shid("contracts", 0, hs["contracts"][0]), shid("logic", 0, hs["logic"][0]),
                 shid("consistency", 0, hs["consistency"][0]), shid("hygiene", 0, hs["hygiene"][0])]
        v = model_calls(res, "VERIFY")
        self.assertEqual([e["request"]["hypothesisId"] for e in v], order)
        self.assertEqual([e["agentId"] for e in v], ["verifier", "verifier", "verifier-02", "verifier-02"])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        over = [d for d in vpay["drops"] if d["reason"] == "over-cap"]
        self.assertEqual([d["subjectIds"] for d in over], [[shid("consistency", 1, hs["consistency"][1])]])
        self.assertIn("five specialist lanes", over[0]["detail"])

    def test_verify_keeps_the_judge_reserve(self):
        m = self.big()
        with mock.patch.object(sweeps, "judge_reserve_floor", lambda budget: 0):
            res, _ = self.record_v5(m, self.e2e_script(m)[0])
        self.assertEqual(res.status, "partial")
        self.assertEqual(model_calls(res, "VERIFY"), [])
        self.assertIn("budget", {i["reason"] for i in res.incomplete if i["stage"] == "VERIFY"})

    def test_a_failed_lane_does_not_fail_the_run(self):
        m = self.big()
        hc = self.h_core(m)
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), ask("logic", 0), sfinal("logic", 1),
                     ask("safety", 0), sfinal("safety", 1), *sfail("consistency", 0), ask("hygiene", 0),
                     sfinal("hygiene", 1), vfinal(0, m, path="src/app/core.py", line=3),
                     judge(w([shid("contracts", 0, hc)])))
        res, _ = self.record_v5(m, scr)
        self.assertEqual(res.status, "partial")
        self.assertEqual([a["status"] for a in self.payload(res)["payload"]["agents"]],
                         ["completed", "completed", "completed", "failed", "completed"])


# ---------------------------------------------------------------- identity

class Identity(LaneRig):
    pin_of = V4Identity.pin_of

    def test_v4_runs_are_byte_identical_to_the_pre_change_recordings(self):
        m = self.big()
        res, _ = self.record_v4(m, DiffShardRig.e2e_script(self, m)[0], eval_id="evr_" + "c" * 16)
        self.assertEqual(self.pin_of(res), V4_PINS["v4_big"])
        small = self.case()
        r2, _ = self.record_v4(small, self.three_script(small)[0], eval_id="evr_" + "d" * 16)
        self.assertEqual(self.pin_of(r2), V4_PINS["v4_small"])
        self.assertNotIn("collapses", self.payload(res)["payload"])

    def test_v5_lanes_texts_and_rules_are_bound_into_the_v5_identity_only(self):
        m = self.big()
        backend, _ = self.record_backend(script())
        spec = self.spec(m, backend, profile=V5_PROFILE, plan=V5_PLAN, retrieval=V5_POLICY)
        others = [self.spec(m, backend, profile=V3_PROFILE, plan=V3_PLAN, retrieval=V3_POLICY),
                  self.spec(m, backend, profile=V4_PROFILE, plan=V4_PLAN, retrieval=V4_POLICY)]
        base, obase = identity.config_snapshot_id(spec), [identity.config_snapshot_id(s) for s in others]
        for name, value in (("NEAR_DUP_CAP", 2), ("NEAR_DUP_SIMILARITY", 0.6), ("LANE_TOOL_CALLS", 19),
                            ("INVESTIGATE_SPEND_BP", 5000), ("MAX_VERIFY_CANDIDATES_V5", 25), ("NEAR_DUP_TEXT", "x")):
            orig = getattr(lanes, name)
            try:
                setattr(lanes, name, value)
                self.assertNotEqual(identity.config_snapshot_id(spec), base, name)
                self.assertEqual([identity.config_snapshot_id(s) for s in others], obase, name)
            finally:
                setattr(lanes, name, orig)
        old = prompts.IMPACT_V5_TEMPLATES["lensesV5"]
        try:
            prompts.IMPACT_V5_TEMPLATES["lensesV5"] = old[:1]
            self.assertNotEqual(identity.config_snapshot_id(spec), base)
            self.assertEqual([identity.config_snapshot_id(s) for s in others], obase)
        finally:
            prompts.IMPACT_V5_TEMPLATES["lensesV5"] = old
        self.assertEqual(identity.config_snapshot_id(spec), base)
        self.assertEqual(identity.plan_specialists(spec), list(LANES))

    def test_plan_must_name_the_five_lanes(self):
        m = self.big()
        with self.assertRaises(PipelineError) as c:
            self.record_v5(m, script(), plan=V3_PLAN)
        self.assertIn("investigator.impact@v5", str(c.exception))
        with self.assertRaises(PipelineError):
            self.record_v3(m, script(), plan=V5_PLAN)

    def test_payload_contract(self):
        hid0, hid1 = "hyp_" + "a" * 16, "hyp_" + "b" * 16
        base = {"stage": "INVESTIGATE", "hypotheses": [], "agents": [], "merges": []}
        ok = dict(base, collapses=[{"keptIds": [hid0], "collapsedIds": [hid1], "rule": "near-duplicate-cap@3"}])
        self.assertEqual(validate("StagePayload", ok), [])
        for bad in ([{"keptIds": [hid0], "collapsedIds": [], "rule": "near-duplicate-cap@3"}],
                    [{"keptIds": [hid0], "collapsedIds": [hid1], "rule": "x@1"}]):
            self.assertNotEqual(validate("StagePayload", dict(base, collapses=bad)), [])


class Pilot(unittest.TestCase):
    def test_v5_is_opt_in_and_v4_keeps_its_bytes(self):
        from reviewer.pilot.repository_profile import (DEFAULT_IMPACT_VERSION, IMPACT_VERSIONS, V5_MAX_TOOL_CALLS,
                                                       repository_plan, repository_policy, repository_profile)
        self.assertEqual(DEFAULT_IMPACT_VERSION, 2)
        self.assertEqual(IMPACT_VERSIONS[5], INV5)
        p4 = repository_profile(True, impact_version=4)
        self.assertEqual((digest(p4), digest(repository_plan(p4)), digest(repository_plan(p4, live_stage_timing=True)),
                          repository_policy(True, impact_version=4).digest), V4_REPO)
        p5 = repository_profile(True, impact_version=5)
        got = (digest(p5), digest(repository_plan(p5)), digest(repository_plan(p5, live_stage_timing=True)),
               repository_policy(True, impact_version=5).digest)
        self.assertFalse(set(got) & set(V4_REPO))
        live = repository_plan(p5, live_stage_timing=True)
        self.assertEqual(validate("Plan", live), [])
        self.assertEqual(live["specialists"], list(LANES))
        self.assertEqual(live["budget"]["stageCeilingsSec"], {"INVESTIGATE": 500, "VERIFY": 420, "JUDGE": 200})
        self.assertEqual((live["budget"]["maxUsdMicros"], live["budget"]["verifyReserveBp"]), (4_000_000, 3000))
        self.assertEqual(live["budget"]["maxToolCalls"], V5_MAX_TOOL_CALLS)
        pol = repository_policy(True, impact_version=5)
        self.assertEqual((pol.specialists, pol.five_lanes, pol.diff_sweep, pol.run_tool_calls),
                         (LANES, True, False, V5_MAX_TOOL_CALLS))
        self.assertFalse(any(repository_policy(True, impact_version=v).five_lanes for v in (1, 2, 3, 4)))


if __name__ == "__main__":
    unittest.main()
