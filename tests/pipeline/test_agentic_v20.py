"""V20 BROAD: investigator.impact@v20 = impact@v19 with ONE change, the agentic reviewer's task: v16's broad task (every
issue a senior reviewer would raise) plus "use the read tools to confirm each claim against the code before reporting it"
(prompts.V20_WHOLE_TASK, agentic.BROAD_RULE). The session, admission, re-asks, VERIFY, the JUDGE rule and the Plan with its
$10 ceiling are v19's. reviewer.pipeline.agentic.

The v19 rig (invented fixtures, a scripted fake agentic adapter, the real engine, contracts, gateway and tools). No network,
key, state, CLI or live call. These tests prove the mechanics; they do NOT show that a real model finds more."""

from __future__ import annotations

import copy
import dataclasses
import json
import unittest

from reviewer.config import resolve_config
from reviewer.contracts import validate
from reviewer.contracts.entities import validate_trace
from reviewer.pilot import repository as REPO
from reviewer.pilot import repository_profile as RP
from reviewer.pilot.profile import RUN_CEILING_USD_MICROS
from reviewer.pipeline import RetrievalPolicy, agentic, identity, prompts, whole

from tests.pipeline.helpers import events_of, judge, model_calls, script
from tests.pipeline.test_agentic_v19 import (A, R, V19_PLAN, V19_POLICY, V19_PROFILE, V19Rig, cli, cli_bad, EndToEnd as E19)
from tests.pipeline.test_coverage_v12 import ROOT, hid, inv_calls, md_of, payload, vdone
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_whole_v16 import comments_of

INV19, INV20, VER = (prompts.INVESTIGATOR_IMPACT_V19_PROMPT, prompts.INVESTIGATOR_IMPACT_V20_PROMPT,
                     prompts.VERIFIER_IMPACT_PROMPT)
CC = resolve_config(ROOT / "pullo-claude-cli-sj.toml").models
V20_PROFILE = copy.deepcopy(V19_PROFILE)       # the real v20 claude-cli investigator role (asserted below)
V20_PROFILE["roles"]["investigator"]["promptVersion"] = INV20
V20_POLICY = RetrievalPolicy(investigator_prompt=INV20, verifier_prompt=VER, run_tool_calls=400)
V20_PLAN = V19_PLAN                            # the same Plan (specialists, $10 ceiling)
TASK_LINE = "Task (agentic-broad@1)"
CONFIRM = "Use the read tools to confirm each claim against the code before reporting it"


def v16_broad_list():
    """v16's issue list, verbatim (from 'List EVERY issue' to its end)."""
    t = prompts.V16_WHOLE_TASK
    i = t.index("List EVERY issue")
    return t[i:t.index("made wrong or misleading.", i) + len("made wrong or misleading.")]


# ---------------------------------------------------------------- 1. profile, Plan, policy, texts, identity

class Rules(unittest.TestCase):
    def test_v20_profile_and_plan_are_v19s_but_the_investigator_prompt_and_the_plan_reason(self):
        self.assertEqual(RP.IMPACT_VERSIONS[20], INV20)
        p19, p20 = RP.repository_profile(True, CC, impact_version=19), RP.repository_profile(True, CC, impact_version=20)
        self.assertEqual(validate("ModelProfile", p20), [])
        self.assertEqual(p20["roles"]["investigator"], V20_PROFILE["roles"]["investigator"])   # the rig's role is real
        self.assertEqual(p20["roles"]["investigator"]["params"]["agentic"], agentic.spec())
        back = copy.deepcopy(p20)
        back["roles"]["investigator"]["promptVersion"] = INV19
        self.assertEqual(back, p19)
        for live in (True, False):
            a, b = RP.repository_plan(p19, live_stage_timing=live), RP.repository_plan(p20, live_stage_timing=live)
            self.assertEqual(validate("Plan", b), [])
            self.assertTrue(b["reasons"][1].startswith(INV20 + ": one agentic read-only claude-cli reviewer session"))
            self.assertEqual(b["reasons"][1], a["reasons"][1].replace(INV19, INV20, 1))
            self.assertEqual(dict(b, reasons=a["reasons"]), a)
            self.assertEqual((b["budget"]["maxUsdMicros"], b["specialists"]), (10_000_000, ["whole", "agentic"]))
        with self.assertRaises(Exception) as ctx:                                 # a claude-cli investigator only
            RP.repository_profile(True, None, impact_version=20)
        self.assertIn("investigator.impact@v20 needs a claude-cli investigator", str(ctx.exception))

    def test_v20_policy_is_v19s_plus_the_broad_flag(self):
        pol, p19 = RP.repository_policy(True, impact_version=20), RP.repository_policy(True, impact_version=19)
        self.assertEqual(pol, V20_POLICY)
        self.assertEqual((pol.broad_agentic, pol.agentic_review, pol.whole_change, pol.impact, pol.run_tool_calls),
                         (True, True, True, True, 400))
        self.assertEqual(dataclasses.replace(pol, investigator_prompt=INV19), p19)
        self.assertFalse(p19.broad_agentic or RP.repository_policy(True, impact_version=16).broad_agentic)

    def test_only_the_task_text_differs_from_v19(self):
        t19, t20 = prompts.impact_template_digests(INV19), prompts.impact_template_digests(INV20)
        self.assertEqual({k: v for k, v in t20.items() if k != "agenticReview"},
                         {k: v for k, v in t19.items() if k != "agenticReview"})
        self.assertNotEqual(t20["agenticReview"], t19["agenticReview"])
        self.assertEqual({k: v for k, v in prompts.V20_TEMPLATES.items() if k not in ("task", "taskVersion")},
                         {k: v for k, v in prompts.V19_TEMPLATES.items() if k != "task"})
        self.assertEqual((prompts.V20_TEMPLATES["task"], prompts.V20_TEMPLATES["taskVersion"]),
                         (prompts.V20_WHOLE_TASK, agentic.BROAD_RULE))
        self.assertEqual((prompts.investigator_task(INV20), prompts.investigator_task(INV19)),
                         (prompts.V20_WHOLE_TASK, prompts.V19_WHOLE_TASK))

    def test_the_v20_task_is_v16s_broad_task_plus_the_confirm_rule_in_the_agentic_setting(self):
        t = prompts.V20_WHOLE_TASK
        self.assertIn(v16_broad_list(), t)                                      # every issue, v16's words
        self.assertIn(CONFIRM, t)
        self.assertLess(t.index(v16_broad_list()), t.index(CONFIRM))
        for s in ("missing or ineffective tests", "performance regressions on a real path", "API and contract behaviour",
                  "documentation, docstrings or comments", "P2 everything else worth fixing",
                  "a location on a changed line of the head snapshot", "at most wholeChange.maxHypotheses",
                  "for a missing test, the changed behaviour no test exercises", "Skip pure style, naming and formatting"):
            self.assertIn(s, t)
        for s in ("Report only issues that cause concrete wrong behaviour", "Do not report style, naming, refactoring, "
                  "missing tests", "P2 a real but minor wrong behaviour"):                  # v19's narrowing is gone
            self.assertIn(s, prompts.V19_WHOLE_TASK)
            self.assertNotIn(s, t)
        for s in ("read-only tools (Read, Grep, Glob) over the head snapshot", "agenticReview says where",
                  "(as you read them with Read)"):                                  # v19's agentic setting stays
            self.assertIn(s, prompts.V19_WHOLE_TASK)
            self.assertIn(s, t)
        for s in ("head content of the changed files", "read_file, search_literal", "leave `output` null"):
            self.assertIn(s, prompts.V16_WHOLE_TASK)                             # v16's host reads: not in one hop
            self.assertNotIn(s, t)
        self.assertTrue(t.endswith("Give your final answer in `output` and leave contextRequests empty."))

    def test_identity_names_the_task_rule_for_v20_only(self):
        d19 = agentic.identity_doc(V19_POLICY, V19_PLAN["budget"], 50, 5)
        d20 = agentic.identity_doc(V20_POLICY, V20_PLAN["budget"], 50, 5)
        self.assertNotIn("task", d19)                                            # v19 run ids unchanged
        self.assertEqual(d20["task"], {"rule": "agentic-broad@1", "prompt": INV20})
        self.assertEqual({k: v for k, v in d20.items() if k != "task"}, d19)

    def test_live_hosts_accept_the_ten_dollar_ceiling_for_a_v20_plan_and_nothing_else(self):
        class Ledger:
            def totals(self):
                return {"committedUsdMicros": 0}
        p20 = RP.repository_plan(RP.repository_profile(True, CC, impact_version=20), live_stage_timing=True)
        self.assertTrue(agentic.is_v19_plan(p20))
        REPO._check_ceiling(Ledger(), p20)
        with self.assertRaises(REPO.RepositoryError):
            REPO._check_ceiling(Ledger(), dict(p20, budget=dict(p20["budget"], maxUsdMicros=RUN_CEILING_USD_MICROS)))


# ---------------------------------------------------------------- 2. end to end through the gateway

class EndToEnd(V19Rig):
    def record_v20(self, m, scr, **kw):
        kw.setdefault("profile", V20_PROFILE)
        kw.setdefault("retrieval", V20_POLICY)
        kw.setdefault("plan", V20_PLAN)
        return self.record_turn(m, scr, **kw)

    def test_one_agentic_session_with_the_broad_task_then_v19s_verify_and_judge_rule(self):
        m = self.case12()
        scr, ids = self.run19(m, judged=(0, 1))                                  # the judge leaves the third out
        res, _ = self.record_v20(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        calls = inv_calls(res)
        self.assertEqual([(e["agentId"], e["request"]["hop"]) for e in calls], [(A, 0)])
        req = calls[0]["request"]
        self.assertEqual((req["promptVersion"], req["provider"], req["params"]["agentic"]),
                         (INV20, "claude-cli", agentic.spec()))
        d = doc_of(req)
        self.assertEqual(d["task"], prompts.V20_WHOLE_TASK)
        self.assertEqual(d["agenticReview"], prompts.agentic_block(agentic.spec()))
        self.assertEqual(d["wholeChange"]["maxHypotheses"], whole.MAX_HYPOTHESES)
        self.assertEqual(whole.MAX_HYPOTHESES, 15)
        self.assertFalse([c for c in d["context"] if c["tool"] == "read_file"])  # no host head reads, as v19
        jreq = model_calls(res, "JUDGE")[0]["request"]
        self.assertTrue(doc_of(jreq)["task"].endswith(prompts.V19_JUDGE_RULE))   # the JUDGE rule is kept
        drops = payload(res, "JUDGE")["drops"]
        self.assertEqual([(x["subjectIds"], x["reason"]) for x in drops], [([ids[2]], "below-threshold")])
        self.assertEqual(sorted(c["findingIds"][0] for c in comments_of(res)), sorted(ids[:2]))
        md = md_of(res)
        self.assertIn(TASK_LINE + ": the reviewer was asked for every issue a senior reviewer would raise", md)
        self.assertIn("JUDGE rule (judge-concrete@1): 1 finding(s) left out", md)

    def test_v19_review_md_has_no_task_line(self):
        m = self.case12()
        scr, _ = self.run19(m)
        res, _ = self.record_v19(m, scr)
        self.assertEqual(doc_of(inv_calls(res)[0]["request"])["task"], prompts.V19_WHOLE_TASK)
        self.assertNotIn(TASK_LINE, md_of(res))

    def test_the_schema_re_ask_keeps_the_broad_task(self):
        m = self.case12()
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        scr, _ = self.run19(m, session=[*cli_bad(A, 0), cli(R, 0, {"hypotheses": [hl, hb, hs]})])
        res, _ = self.record_v20(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        calls = inv_calls(res)
        self.assertEqual([e["agentId"] for e in calls], [A, A, R])               # the call, its repair, the re-ask
        self.assertEqual(doc_of(inv_calls(res, R)[0]["request"])["task"], prompts.V20_WHOLE_TASK)
        self.assertEqual(len(comments_of(res)), 3)

    def test_the_tool_re_ask_appends_the_tool_note_to_the_broad_task(self):
        m = self.case12()
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        scr, _ = self.run19(m, session=[E19.tool_kill(self, A), cli(R, 0, {"hypotheses": [hl, hb, hs]})])
        res, _ = self.record_v20(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual([(a["agentId"], a["status"]) for a in payload(res, "INVESTIGATE")["agents"]],
                         [(A, "failed"), (R, "completed")])
        self.assertEqual(doc_of(inv_calls(res, R)[0]["request"])["task"],
                         prompts.V20_WHOLE_TASK + " " + prompts.V19_TOOL_NOTE)
        self.assertIn("Tool re-ask (agentic-tool-reask@1): 1 session(s) ended", md_of(res))

    def test_strict_replay_and_v20_has_its_own_config_identity(self):
        m = self.case12()
        scr, _ = self.run19(m)
        res, _ = self.record_v20(m, scr)
        rep = self.replay(m, res, profile=V20_PROFILE, retrieval=V20_POLICY, plan=V20_PLAN)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual(rep.receipt["artifactDigests"], res.receipt["artifactDigests"])
        backend, _ = self.record_backend(scr)
        c19 = identity.config_snapshot_id(self.spec(m, backend, profile=V19_PROFILE, plan=V19_PLAN, retrieval=V19_POLICY))
        c20 = identity.config_snapshot_id(self.spec(m, backend, profile=V20_PROFILE, plan=V20_PLAN, retrieval=V20_POLICY))
        self.assertEqual(res.run["configSnapshotId"], c20)
        self.assertNotEqual(c19, c20)


# ---------------------------------------------------------------- 3. v19 is byte-unchanged

PRE_V20_V19_PINS = json.loads('{"e2e": {"INVESTIGATE": "sha256:0221bdc35060920119975a454058e4289239c9fb18115d1df6df6543ea8b4d87", "PUBLISH": "sha256:07081e7ad783fb24bb5a8effec2d748a1efd5a025005cf09394cddf25efca561", "VERIFY": "sha256:e9ef27ea889320eb1e690d0766f42f617ad33986b26cf1708b16eee25d1e2255", "cfg": "sha256:7a6aa9f392a53aa288582719c3d346ddaa400efb7453c27055b781d5535de320", "requests": ["sha256:dfd9750a7fda8d0141b7574b76549fa776b455081029c075aa4bbae0dc3c84f9", "sha256:8509717d1077e9a1566fbd2f47ad0b9e163dee62b5f317052547124607cf8b10", "sha256:7f965a73f4f31cbf7b828bd38f3336a7b81ae7f76a708166de3b939a00af5ae1", "sha256:3914c2de10447086c6939c06eb8b0ae217d2faffd3a6cc3a49776adf246b11ee", "sha256:930f1f5026979035e59d3b80aadc5ae6dcae6dd9b8abe90be613b069e09a1b4f"], "trace": "sha256:9e06b87e30a948ffdbceb419451b9b322cf4d076251d7c1d1925d9610fc12041"}, "judge_unavailable": {"INVESTIGATE": "sha256:0221bdc35060920119975a454058e4289239c9fb18115d1df6df6543ea8b4d87", "PUBLISH": "sha256:efbf28470cc6a86edf2b955553ebe0c8116888795b0a87f6ed00bee66e5fd176", "VERIFY": "sha256:e9ef27ea889320eb1e690d0766f42f617ad33986b26cf1708b16eee25d1e2255", "cfg": "sha256:7a6aa9f392a53aa288582719c3d346ddaa400efb7453c27055b781d5535de320", "requests": ["sha256:dfd9750a7fda8d0141b7574b76549fa776b455081029c075aa4bbae0dc3c84f9", "sha256:8509717d1077e9a1566fbd2f47ad0b9e163dee62b5f317052547124607cf8b10", "sha256:7f965a73f4f31cbf7b828bd38f3336a7b81ae7f76a708166de3b939a00af5ae1", "sha256:3914c2de10447086c6939c06eb8b0ae217d2faffd3a6cc3a49776adf246b11ee", "sha256:930f1f5026979035e59d3b80aadc5ae6dcae6dd9b8abe90be613b069e09a1b4f"], "trace": "sha256:1ed6f071204abd05974e3a112711131ce7a04e616ee04f3ad2c5e2731c83bb79"}, "schema_reask": {"INVESTIGATE": "sha256:e1f102a4394c4b0a2c98c7821374d82ca3d97b454f3b50e496521b4a26eefb2f", "PUBLISH": "sha256:8d1a595cc7a017db7cb059753ab3f287f69d236316bd857f3b88e73440e36fb2", "VERIFY": "sha256:70f909bd084c6d36ecd13bf4889e674c6e56f368f5675fcefc3062884968a6ca", "cfg": "sha256:7a6aa9f392a53aa288582719c3d346ddaa400efb7453c27055b781d5535de320", "requests": ["sha256:dfd9750a7fda8d0141b7574b76549fa776b455081029c075aa4bbae0dc3c84f9", "sha256:df53687cf2cd90b1175b385f45ee710af1cc5401596e594ae84cb63e2ad0c424", "sha256:dfd9750a7fda8d0141b7574b76549fa776b455081029c075aa4bbae0dc3c84f9", "sha256:cedb3b5e9f5c46817be94de320e47794a1d870360506da3ddcc8f38343d35af9", "sha256:9ecc11bb31877237bf1c9ae0f0a4a5c2afda49ea5a4a45c02b3bb641a16b509b", "sha256:3603b17f9deb02d5e4533912087025bcfa176eb7e336474b8eece39b0e35100f", "sha256:c6ec9c3db1fe3544f56e1f1e62fd08c540a8487c7b3b1508f65675b9f48241d8"], "trace": "sha256:2004608f707066685b5dd5e26af9d6c7fbec460f815fd343f6a4415e27278f7c"}, "tool_reask": {"INVESTIGATE": "sha256:cb47bc67e78bdf2ab159505b3c07f1f6bd740d0f12f8dcfea9b3717ff4007021", "PUBLISH": "sha256:b89f53312656479fb7b4e3573e0cc8a65225464604380510bedfd323d7229374", "VERIFY": "sha256:b42ea6be68bcf26aab37b07d298a3d8053bc2bf72e0e7eac83007132e2399446", "cfg": "sha256:7a6aa9f392a53aa288582719c3d346ddaa400efb7453c27055b781d5535de320", "requests": ["sha256:dfd9750a7fda8d0141b7574b76549fa776b455081029c075aa4bbae0dc3c84f9", "sha256:b06a896a0d117256330c4c33e50387301a61b262c4afd5c63c9485ccf5a4284c", "sha256:cedb3b5e9f5c46817be94de320e47794a1d870360506da3ddcc8f38343d35af9", "sha256:9ecc11bb31877237bf1c9ae0f0a4a5c2afda49ea5a4a45c02b3bb641a16b509b", "sha256:3603b17f9deb02d5e4533912087025bcfa176eb7e336474b8eece39b0e35100f", "sha256:c6ec9c3db1fe3544f56e1f1e62fd08c540a8487c7b3b1508f65675b9f48241d8"], "trace": "sha256:05972d19ce8b3f48822c1ebdb4eb85884dc15d53bb144c18b485279134f7434e"}}')


class V19Parity(unittest.TestCase):
    def test_v19_recordings_are_byte_identical_to_the_pre_change_source(self):
        import io
        import runpy
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            runpy.run_path(str(ROOT / "tests/pipeline/v19_pin_scenarios.py"), run_name="__main__")
        self.assertEqual(json.loads(buf.getvalue()), PRE_V20_V19_PINS)


if __name__ == "__main__":
    unittest.main()
