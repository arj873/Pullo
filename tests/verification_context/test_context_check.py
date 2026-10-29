"""VERIFY-CONTEXT-01: the opt-in context-check@1 prompt arm. Invented self-contained fixtures, scripted fake backend and
fake transport only: no network, key, state, target or live call.

These tests prove routing, identity and mechanics: the default stays byte-identical, the opt-in arm selects and binds its
own task text on the existing schemas, tool/call/budget behaviour is unchanged, replay is strict, and a bad selector is
refused before key/state/output. They do NOT show that the prompt makes a model more accurate: whether a real verifier
checks a concrete subclaim is an empirical question for a separately admitted run. A lying fake verifier that cites
relevant-looking code is accepted here, as it would be by the host; that is an acknowledged semantic limit."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import unittest
from pathlib import Path

from reviewer.config import ReviewModels
from reviewer.contracts.canonical import digest, profile_digest
from reviewer.pilot import benchmark as B
from reviewer.pilot.profile import MODEL
from reviewer.pilot.repository_profile import repository_plan, repository_policy, repository_profile
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, prompts
from reviewer.pipeline.retrieval import VERIFIER_CONTEXT_CHECK_PROMPT

import tests.pilot.test_benchmark_host as TBH
from tests.pipeline.helpers import (BASE, HEAD, TURN_PLAN, TURN_PROFILE, Rig, entry, events_of, hid, hyp, ifinal, iturn,
                                    judge, model_calls, script, tcid, terr, tool_calls, treq, vfinal, vturn)

CTX, FACT = prompts.VERIFIER_CONTEXT_CHECK_PROMPT, prompts.JUDGE_FACT_WORDING_PROMPT

# ---- default behaviour recorded from this source BEFORE the experiment was added (see the handoff for how)
GOLD = {
    "templates": {"formats": "sha256:2b00ef28c2365414ff2a1cf35929264bf9dcffa1dfdad816684d4142fac7d2d7",
                  "investigator": "sha256:fc2162773b1a7a09f31c656aff7f6cb56d62ca3d74ddba82aa58f28e39841226",
                  "judge": "sha256:47940b1d08d749cea46bc89fee3bcd18b19c065533e0c1ea713649ee57a2c5e9",
                  "system": "sha256:74c09d41cc972615e4ba90b0e0f26da881ab385049664e25c0be5cbc5daedee6",
                  "verifier": "sha256:39c7688baba0dc1c2c56175896f025e3fc95e8662d7c916b58be1a64549b9c7d"},
    "retrievalTemplates": {"citations": "sha256:5c1b95c2cf243364402a3473dc1341d866f4928627aefbb9350a6ea42b851357",
                           "formats": "sha256:169faeb87a5049bfeeb397fd21343dfe8fe57786bb32d6adae520a2c7a0e5267",
                           "investigator": "sha256:1e64c7da5be7ef8052fe70b51f10eaf4dac74f1fa99d3c7f8d3c7c381562a124",
                           "system": "sha256:8d29afec1bf40c2bfb56df3dd59e94b6f5f696f7712c2d00f6595f71e09b7547",
                           "tools": "sha256:6211830613da24eab4b6d1bbd7a0cc7229fd3da39bdf27fda57f47f2fcda03bb",
                           "verifier": "sha256:7fc903e7f9a68ad7f99bebee9567843bf478140abf2291b245bc9926570d9769"},
    "engineIdentity": "sha256:9238adb1cc170f79625c1b0da27a2dcafba51d7ee1c4a0d91c2c73d20a44e299",
    "profileOn": "sha256:f113cf0fa903a2e5cd4b4410a85a3025389cb257fc45cf2eb662241acabe7c85",
    "profileOff": "sha256:60750b6fbecd9ed73d9b1faba9e3fa49e7bb8dc19523775fbedeab1bf5fc762e",
    "plan": "sha256:18bedae1e19e8460affb22388cb88188b8ec2b1ace72c9d2238be84774f4b306",
    "policy": "sha256:2c5b1add3d9dc8946fbeb006677ed090163541570965faa419fff9bb1a97f48c",
    "policyDoc": {"agent_tool_calls": 60, "context_chars": 240000, "hypothesis_tool_calls": 12,
                  "investigator_prompt": "investigator.retrieve@v2", "investigator_turns": 8, "requests_per_turn": 6,
                  "run_tool_calls": 160, "verifier_prompt": "verifier.refute@v4", "verifier_turns": 4,
                  "version": "retrieval@2"},
    "configSnapshotId": "sha256:9788a25c0da5b5426cbf838152243f27bddd24955d6337c06e9d269333c27a76",
    "requests": [["investigator", 0, "sha256:25665f1603ca1c908d09d42d99a869472a33ed460284eead8b88075c47c5e67f"],
                 ["investigator", 1, "sha256:be654338abe7bdbe901a4e543ea7130ad5f05ebf3bce814140f89babb1c7c2a1"],
                 ["verifier", 0, "sha256:d7fc4d47a15a65287ed161deef628503cb9edaf4c02d52ca51c86e197ff246e8"],
                 ["verifier", 1, "sha256:c336cd07983a97406c1437ff414398f4b4ec5c7911967541ed19915d4111b854"],
                 ["judge", None, "sha256:159f6313299e125b53d69ea00b4c1ca3b999a1a39647a0c4a2a5b97222174f69"]],
    "benchFirst": "c5957b0563b88b06acd539c9570a78cc9ed0f4b61f45146a377214fb368164a3",   # retrieval@2 arm (pre-IMPACT-01)
    "benchRetrievalOff": "ad9d35d729aca26ba50148bd1032a65aa3ab36e01af55a0af74633de11366aac",
}
# IMPACT-01: the pilot repository default is now impact mode (investigator.impact@v1 / verifier.impact@v1). The pins
# above stay the pre-change retrieval@2 arm (reproduced by repository_profile/policy(..., impact=False)); these are the
# new defaults. Recorded from this source; same plan, numeric policy limits and models.
IMPACT_GOLD = {
    "profileOn": "sha256:3e62ef3208e068fafde841cb7d220094f15ed0e08a11bf185097b8299f16bdf7",
    "policy": "sha256:c849a611a21899ac9c64ac149ce2b0b4edb36ebcf544111987cebd91c639e559",
    "benchFirst": "77da9a6a63e9d3f83d0e9cb4eb2fc60e81fc4a35891ed3a1cc412d7d88cfc526",   # impact-map@2 rows (O2 quoting)
}

UTIL = "def close_stream():\n    return None\n\ndef is_open():\n    return True\n"
BASE_U, HEAD_U = {**BASE, "src/util.py": UTIL}, {**HEAD, "src/util.py": UTIL}


def ctx_profile():
    p = copy.deepcopy(TURN_PROFILE)
    p["roles"]["verifier"]["promptVersion"] = CTX
    p["roles"]["judge"]["promptVersion"] = FACT
    return p


def ctx_policy():
    return RetrievalPolicy(verifier_prompt=CTX)


def task_of(request):
    return json.loads(request["messages"][1]["content"])["task"]


def doc_of(request):
    return json.loads(request["messages"][1]["content"])


def w(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


class Base_(Rig):
    def case(self):
        return self.mini(base=BASE_U, head=HEAD_U)

    def ask_script(self, m, h, *, notes="checked"):
        """The Chains script: investigator searches then answers; verifier reads the unchanged helper then confirms."""
        read_id = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/util.py", start_line=1, end_line=2)
        return script(
            iturn(0, [treq("search_literal", side="head", query="close_stream")]), ifinal(1, h),
            vturn(0, [treq("read_file", side="head", path="src/util.py", start_line=1, end_line=2)]),
            vfinal(1, m, evidence=[m.cite("src/a.py", 2), {"kind": "tool-ref", "toolCallId": read_id, "index": 0}],
                   notes=notes),
            judge(w([hid(0, h)])))

    def local_script(self, m, h, *, notes="checked"):
        """A self-contained local defect: the verifier answers at hop 0 and asks for nothing."""
        return script(iturn(0, [treq("search_literal", side="head", query="close_stream")]), ifinal(1, h),
                      vfinal(0, m, evidence=[m.cite("src/a.py", 2)], notes=notes), judge(w([hid(0, h)])))

    def arm(self, scr, m, experiment, **kw):
        if experiment:
            kw.update(profile=ctx_profile(), plan=TURN_PLAN, retrieval=ctx_policy())
        return self.record_turn(m, scr, **kw)


# ======================================================================== 1. the default is unchanged

class DefaultUnchanged(Base_):
    def test_baseline_templates_profiles_policy_and_engine_identity_equal_the_pre_change_values(self):
        ms = ReviewModels.uniform(MODEL)
        self.assertEqual(prompts.template_digests(), GOLD["templates"])
        self.assertEqual(prompts.retrieval_template_digests(), GOLD["retrievalTemplates"])
        self.assertEqual(digest(identity.engine_identity()), GOLD["engineIdentity"])
        on, off = repository_profile(True, ms, impact=False), repository_profile(False, ms)
        self.assertEqual((profile_digest(on), profile_digest(off)), (GOLD["profileOn"], GOLD["profileOff"]))
        self.assertEqual(digest(repository_plan(on)), GOLD["plan"])
        pol = repository_policy(True, impact=False)
        self.assertEqual((pol.digest, pol.to_doc()), (GOLD["policy"], GOLD["policyDoc"]))
        # naming the baseline explicitly is the default
        self.assertEqual(profile_digest(repository_profile(True, ms, "baseline", impact=False)), GOLD["profileOn"])
        self.assertEqual(repository_policy(True, "baseline", impact=False).digest, GOLD["policy"])
        self.assertIsNone(repository_policy(False))
        # IMPACT-01 default (impact mode): new pins; the plan and retrieval-off profile are unchanged
        self.assertEqual(profile_digest(repository_profile(True, ms)), IMPACT_GOLD["profileOn"])
        self.assertEqual(digest(repository_plan(repository_profile(True, ms))), GOLD["plan"])
        self.assertEqual(repository_policy(True).digest, IMPACT_GOLD["policy"])
        self.assertEqual(profile_digest(repository_profile(False, ms, impact=True)), GOLD["profileOff"])

    def test_baseline_run_requests_tasks_comment_and_config_identity_equal_the_pre_change_values(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        res, _ = self.arm(self.ask_script(m, h), m, False)
        self.assertEqual((res.status, len(res.findings), len(res.comments)), ("completed", 1, 1))
        self.assertEqual(res.receipt["configSnapshotId"], GOLD["configSnapshotId"])
        got = [[e["request"]["role"], e["request"].get("hop"), digest(e["request"])]
               for e in events_of(res) if e.get("type") == "model.call"]
        self.assertEqual(got, GOLD["requests"])
        ver, jdg = model_calls(res, "VERIFY")[0]["request"], model_calls(res, "JUDGE")[0]["request"]
        self.assertEqual(task_of(ver), prompts.VERIFIER_REFUTE_TASK)
        self.assertEqual(task_of(jdg), prompts.JUDGE_TASK)
        self.assertEqual((ver["promptVersion"], jdg["promptVersion"]), ("verifier.refute@v4", "judge.wording@v1"))
        self.assertNotIn("experiment", json.dumps(self.config_ident(res)))

    @staticmethod
    def config_ident(res):
        return {k: v for k, v in res.receipt.items() if k in ("versions", "profile")}

    def test_an_unknown_or_custom_prompt_id_keeps_the_baseline_text(self):
        self.assertEqual(prompts.verifier_task("verifier.refute@v4"), prompts.VERIFIER_REFUTE_TASK)
        self.assertEqual(prompts.verifier_task("anything.else@v9"), prompts.VERIFIER_REFUTE_TASK)
        self.assertEqual(prompts.judge_task("judge.wording@v1"), prompts.JUDGE_TASK)
        self.assertEqual(prompts.judge_task("judge.v7@v1"), prompts.JUDGE_TASK)
        self.assertEqual(prompts.verifier_task(CTX), prompts.VERIFIER_CONTEXT_CHECK_TASK)
        self.assertEqual(prompts.judge_task(FACT), prompts.JUDGE_FACT_TASK)


# ======================================================================== 2. the opt-in arm: ids, requests, identity

class OptInArm(Base_):
    def run_both(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        base, _ = self.arm(self.ask_script(m, h), m, False)
        exp, _ = self.arm(self.ask_script(m, h), m, True, eval_id="evr_" + "2" * 16)
        return m, h, base, exp

    def test_ids_requests_and_bound_task_text_differ_only_where_selected(self):
        _, _, base, exp = self.run_both()
        self.assertEqual((exp.status, len(exp.findings), len(exp.comments)), ("completed", 1, 1))
        bv, ev = model_calls(base, "VERIFY"), model_calls(exp, "VERIFY")
        bj, ej = model_calls(base, "JUDGE")[0]["request"], model_calls(exp, "JUDGE")[0]["request"]
        # the investigator is untouched: byte-identical requests, so the plan's first request is identical in both arms
        for a, b in zip(model_calls(base, "INVESTIGATE"), model_calls(exp, "INVESTIGATE")):
            self.assertEqual(digest(a["request"]), digest(b["request"]))
        self.assertEqual([c["request"]["promptVersion"] for c in ev], [CTX, CTX])
        self.assertEqual(ej["promptVersion"], FACT)
        self.assertEqual(task_of(ev[0]["request"]), prompts.VERIFIER_CONTEXT_CHECK_TASK)
        self.assertEqual(task_of(ev[1]["request"]), prompts.VERIFIER_CONTEXT_CHECK_TASK)
        self.assertEqual(task_of(ej), prompts.JUDGE_FACT_TASK)
        self.assertNotEqual(digest(bv[0]["request"]), digest(ev[0]["request"]))
        self.assertNotEqual(digest(bj), digest(ej))
        # same output schemas on every hop and for the judge: no schema or contract surface changes
        self.assertEqual({c["request"]["outputSchema"] for c in ev}, {"VerifierTurn"})
        self.assertEqual(ej["outputSchema"], "JudgeOutput")
        # everything but the two task strings and prompt ids is the baseline document
        d_b, d_e = doc_of(bv[0]["request"]), doc_of(ev[0]["request"])
        self.assertEqual({k: v for k, v in d_b.items() if k != "task"}, {k: v for k, v in d_e.items() if k != "task"})
        self.assertEqual({k: v for k, v in doc_of(bj).items() if k != "task"},
                         {k: v for k, v in doc_of(ej).items() if k != "task"})

    def test_identity_binds_the_selected_task_text_profile_and_policy(self):
        _, _, base, exp = self.run_both()
        self.assertNotEqual(base.receipt["configSnapshotId"], exp.receipt["configSnapshotId"])
        self.assertEqual(base.receipt["configSnapshotId"], GOLD["configSnapshotId"])
        digs = prompts.experiment_task_digests()
        self.assertEqual(set(digs), {"verifier", "judge"})
        self.assertNotIn(digs["verifier"], GOLD["retrievalTemplates"].values())
        self.assertNotIn(digs["judge"], GOLD["templates"].values())
        # editing an experimental task text changes the identity (the digest is of the actual text, not of the id)
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        before = identity.config_snapshot_id(self.spec_for(m, True))
        for key, const in (("verifier", "VERIFIER_CONTEXT_CHECK_TASK"), ("judge", "JUDGE_FACT_TASK")):
            old = prompts.EXPERIMENT_TASKS[key]
            try:
                prompts.EXPERIMENT_TASKS[key] = old + " Additional rule."
                self.assertNotEqual(identity.config_snapshot_id(self.spec_for(m, True)), before, key)
            finally:
                prompts.EXPERIMENT_TASKS[key] = old
            self.assertEqual(identity.config_snapshot_id(self.spec_for(m, True)), before)
        # the baseline identity does not read the experimental text at all
        old = prompts.EXPERIMENT_TASKS["verifier"]
        try:
            prompts.EXPERIMENT_TASKS["verifier"] = "edited"
            self.assertEqual(identity.config_snapshot_id(self.spec_for(m, False)), GOLD["configSnapshotId"])
        finally:
            prompts.EXPERIMENT_TASKS["verifier"] = old

    def spec_for(self, m, experiment):
        backend, _ = self.record_backend(script())
        if experiment:
            return self.spec(m, backend, profile=ctx_profile(), plan=TURN_PLAN, retrieval=ctx_policy())
        return self.spec(m, backend, profile=TURN_PROFILE, plan=TURN_PLAN)

    def test_models_caps_tools_budget_and_policy_limits_are_the_baselines(self):
        ms = ReviewModels.uniform(MODEL)
        b, e = repository_profile(True, ms), repository_profile(True, ms, "context-check@1")
        for role in ("investigator", "verifier", "judge"):
            rb, re_ = copy.deepcopy(b["roles"][role]), copy.deepcopy(e["roles"][role])
            rb.pop("promptVersion"), re_.pop("promptVersion")
            self.assertEqual(rb, re_, role)
            self.assertEqual((re_["caps"]["maxRetries"], re_["caps"]["maxRepairs"], re_["fallbacks"]), (0, 0, []))
        self.assertEqual(e["roles"]["investigator"]["promptVersion"], b["roles"]["investigator"]["promptVersion"])
        self.assertEqual((e["roles"]["verifier"]["promptVersion"], e["roles"]["judge"]["promptVersion"]), (CTX, FACT))
        self.assertEqual({k: v for k, v in e.items() if k != "roles"}, {k: v for k, v in b.items() if k != "roles"})
        self.assertEqual(digest(repository_plan(e)), digest(repository_plan(b)))
        pb, pe = repository_policy(True).to_doc(), repository_policy(True, "context-check@1").to_doc()
        self.assertEqual({k: v for k, v in pb.items() if k != "verifier_prompt"},
                         {k: v for k, v in pe.items() if k != "verifier_prompt"})
        self.assertEqual(pe["verifier_prompt"], CTX)
        self.assertEqual(repository_plan(e)["budget"]["maxUsdMicros"], 4_000_000)

    def test_half_a_selection_or_a_non_turn_verifier_is_a_typed_refusal_before_any_call(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        only_judge = copy.deepcopy(TURN_PROFILE)
        only_judge["roles"]["judge"]["promptVersion"] = FACT
        only_verifier = copy.deepcopy(TURN_PROFILE)
        only_verifier["roles"]["verifier"]["promptVersion"] = CTX
        non_turn = copy.deepcopy(ctx_profile())
        non_turn["roles"]["verifier"].update(outputSchema="VerifierOutput")
        for name, kw in (("judge only", dict(profile=only_judge)),
                         ("verifier only", dict(profile=only_verifier, retrieval=ctx_policy())),
                         ("non-turn verifier", dict(profile=non_turn, retrieval=ctx_policy()))):
            with self.subTest(name):
                res = None
                with self.assertRaises(PipelineError) as c:
                    res, spy = self.record_turn(m, self.ask_script(m, h), **kw)
                self.assertEqual(c.exception.code, "invalid-input")
        for spy in self.spies:
            self.assertEqual(spy.calls, 0)

    def test_the_policy_prompt_must_still_match_the_profile_prompt(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        with self.assertRaises(PipelineError) as c:
            self.record_turn(m, self.ask_script(m, h), profile=ctx_profile(), plan=TURN_PLAN)   # baseline policy
        self.assertEqual(c.exception.code, "invalid-input")


# ======================================================================== 3. mechanics of the intended instructions

class Mechanics(Base_):
    def test_a_verifier_that_asks_for_missing_context_then_finds_a_concrete_defect_reaches_the_judge_with_its_notes(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        notes = "Verified: the sign flip at src/a.py:2. Not checked: other callers; no setting was looked up."
        res, _ = self.arm(self.ask_script(m, h, notes=notes), m, True)
        self.assertEqual((res.status, len(res.findings), len(res.comments)), ("completed", 1, 1))
        reqs = [t for t in tool_calls(res) if "requestedBy" in t]
        self.assertEqual([(t["agentId"], t["tool"]) for t in reqs], [("generalist", "search_literal"), ("verifier", "read_file")])
        ver = model_calls(res, "VERIFY")
        self.assertEqual(ver[1]["request"]["contextResults"], [tcid("VERIFY", "verifier", 2, "read_file", side="head",
                                                                     path="src/util.py", start_line=1, end_line=2)])
        jd = doc_of(model_calls(res, "JUDGE")[0]["request"])
        self.assertEqual(jd["task"], prompts.JUDGE_FACT_TASK)
        item = jd["verifiedFindings"][0]
        self.assertEqual(item["verifierNotes"], notes)               # the uncertainty reaches the judge unchanged
        self.assertTrue(any("util.py" in e["path"] for e in item["evidence"] if e["path"]))
        for phrase in ("hypotheses", "confidence alone is not evidence", "not checked", "larger than the finding shows"):
            self.assertIn(phrase, jd["task"])
        vt = prompts.VERIFIER_CONTEXT_CHECK_TASK
        for phrase in ("central defect", "setting names", "argument counts", "exception messages", "ask for the definition",
                       "Do not request context for a self-contained local defect", "did not check"):
            self.assertIn(phrase, vt)
        self.assertEqual(res.comments[0]["severity"], "P1")             # no severity change from the instructions

    def test_a_self_contained_local_case_adds_no_tools_beyond_the_baseline(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        base, _ = self.arm(self.local_script(m, h), m, False)
        exp, _ = self.arm(self.local_script(m, h), m, True, eval_id="evr_" + "3" * 16)
        for r in (base, exp):
            self.assertEqual(r.status, "completed")
            self.assertEqual([t for t in tool_calls(r, "VERIFY") if "requestedBy" in t], [])
        count = lambda r: (len(tool_calls(r)), len(model_calls(r)))                 # noqa: E731
        self.assertEqual(count(base), count(exp))
        self.assertEqual([c["request"]["hop"] for c in model_calls(exp, "VERIFY")], [0])

    def test_same_call_tool_and_budget_caps_are_enforced_in_the_experimental_arm(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        # a verifier that keeps asking until the turn cap ends uncertain, exactly as in the baseline arm
        asks = [vturn(n, [treq("read_file", side="head", path="src/util.py", start_line=1, end_line=2 + n)])
                for n in range(4)]
        scr = script(iturn(0, [treq("search_literal", side="head", query="close_stream")]), ifinal(1, h), *asks)
        base, _ = self.arm(scr, m, False)
        exp, _ = self.arm(scr, m, True, eval_id="evr_" + "4" * 16)
        for r in (base, exp):
            self.assertEqual(len(r.findings), 0)
            self.assertEqual(len(model_calls(r, "VERIFY")), RetrievalPolicy().verifier_turns)
        self.assertEqual((len(tool_calls(base)), len(model_calls(base))), (len(tool_calls(exp)), len(model_calls(exp))))
        self.assertEqual(exp.receipt["cost"]["liveCalls"], base.receipt["cost"]["liveCalls"])

    def test_judge_unavailable_uses_the_unchanged_baseline_fallback_and_it_may_repeat_unverified_text(self):
        """Disclosure, not a fix: this prompt-only arm keeps the baseline fallback, which prints the claim, mechanism and
        verifier notes verbatim. It is not an audited path."""
        m = self.case()
        h = hyp(m, "src/a.py", 2, claim="Claim also mentions the avatar limit.", mechanism="Mechanism text.")
        fail = [entry("JUDGE", "judge", "judge", 0, k, error=terr("provider-error", "JUDGE")) for k in range(3)]
        scr = script(iturn(0, [treq("search_literal", side="head", query="close_stream")]), ifinal(1, h),
                     vfinal(0, m, evidence=[m.cite("src/a.py", 2)], notes="unverified detail stays here"), *fail)
        base, _ = self.arm(scr, m, False)
        exp, _ = self.arm(scr, m, True, eval_id="evr_" + "5" * 16)
        self.assertEqual(len(exp.comments), 1)
        self.assertEqual((exp.comments[0]["title"], exp.comments[0]["body"]),
                         (base.comments[0]["title"], base.comments[0]["body"]))
        self.assertIn("avatar limit", exp.comments[0]["body"])
        self.assertIn("unverified detail stays here", exp.comments[0]["body"])
        self.assertTrue(any(i.get("stage") == "JUDGE" for i in exp.incomplete))

    def test_acknowledged_limit_a_lying_verifier_with_relevant_looking_code_is_accepted(self):
        """The host checks that a citation resolves and is tied to the location, not that the verifier's prose follows
        from it. A fake verifier that states an invented detail while citing the changed line is confirmed. The prompt
        asks otherwise; nothing here (or in the host) proves it can make a real model comply."""
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        lie = "Raises ArgumentError (5 for 2..4); an unrelated setting `max_avatar_size_kb` is ignored too."
        res, _ = self.arm(self.local_script(m, h, notes=lie), m, True)
        self.assertEqual((res.status, len(res.findings)), ("completed", 1))
        self.assertEqual(res.findings[0]["verification"]["notes"], lie)

    def test_strict_replay_of_baseline_and_experimental_recordings_costs_nothing_and_does_not_cross(self):
        m = self.case()
        h = hyp(m, "src/a.py", 2)
        for experiment in (False, True):
            with self.subTest(experiment=experiment):
                res, _ = self.arm(self.ask_script(m, h), m, experiment, eval_id="evr_" + ("6" if experiment else "7") * 16)
                kw = dict(profile=ctx_profile(), plan=TURN_PLAN, retrieval=ctx_policy()) if experiment else \
                    dict(profile=TURN_PROFILE, plan=TURN_PLAN)
                for n in ("rp", "x"):
                    (self.tmp / f"{n}-{experiment}").mkdir()
                rr = self.replay(m, res, out=self.tmp / ("rp-%s" % experiment), **kw)
                self.assertEqual((rr.status, rr.cost["liveCalls"], rr.cost["replayedCalls"]), ("completed", 0, 5))
                self.assertEqual(rr.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
                strip = lambda cs: [{k: v for k, v in c.items() if k != "runId"} for c in cs]     # noqa: E731
                self.assertEqual(strip(rr.comments), strip(res.comments))
                # the other arm's profile cannot replay this recording
                other = dict(profile=TURN_PROFILE, plan=TURN_PLAN) if experiment else \
                    dict(profile=ctx_profile(), plan=TURN_PLAN, retrieval=ctx_policy())
                with self.assertRaises(PipelineError) as c:
                    self.replay(m, res, out=self.tmp / ("x-%s" % experiment), eval_id="evr_" + "8" * 16, **other)
                self.assertNotEqual(c.exception.code, "path-escape")
                self.assertEqual(list((self.tmp / ("x-%s" % experiment)).iterdir()), [])     # nothing written


# ======================================================================== 4. the benchmark host selector

class Selector(TBH.Base):
    def test_default_plan_equals_the_pre_change_first_request_policy_and_profile(self):
        rep = self.plan()
        p = rep["plan"]
        self.assertEqual(p["firstRequest"]["bodySha256"], IMPACT_GOLD["benchFirst"])        # IMPACT-01 default
        self.assertEqual((p["profile"], digest(p["retrievalPolicy"])), ("pilot-repository@1", IMPACT_GOLD["policy"]))
        self.assertEqual(self.plan(retrieval=False)["plan"]["firstRequest"]["bodySha256"], GOLD["benchRetrievalOff"])
        self.assertEqual(rep["experiment"], {"id": "baseline", "verifierPrompt": "verifier.impact@v1",
                                              "judgePrompt": "judge.wording@v1"})
        self.assertEqual(self.plan(experiment="baseline")["plan"]["configIdentityDigest"], p["configIdentityDigest"])

    def test_plan_reports_the_selected_arm_and_binds_it_without_changing_the_first_request_or_ceiling(self):
        base, exp = self.plan(), self.plan(experiment="context-check@1")
        self.assertEqual((exp["status"], exp["ok"]), ("planned", True))
        e = exp["experiment"]
        self.assertEqual((e["id"], e["verifierPrompt"], e["judgePrompt"]), ("context-check@1", CTX, FACT))
        self.assertEqual(e["taskDigests"], prompts.experiment_task_digests())
        self.assertFalse(e["audited"])
        self.assertIn("repeat", e["fallbackWording"])
        self.assertIn("not an audit", e["note"])
        bp, ep = base["plan"], exp["plan"]
        self.assertEqual(ep["firstRequest"]["bodySha256"], bp["firstRequest"]["bodySha256"])       # investigator hop 0
        self.assertIn("identical in every arm", ep["firstRequestNote"])
        self.assertNotEqual(ep["profileDigest"], bp["profileDigest"])
        self.assertNotEqual(ep["configIdentityDigest"], bp["configIdentityDigest"])
        self.assertEqual(ep["retrievalPolicy"]["verifier_prompt"], CTX)
        for k in ("runCeilingUsdMicros", "worstCaseAdmissionUsdMicros", "retries", "repairs", "outputCaps", "models",
                  "providerCalls", "networkCalls", "keyRead", "capturedCount"):
            self.assertEqual(ep[k], bp[k], k)
        self.assertEqual(exp["plan"]["profile"], "pilot-repository@1")
        self.assertEqual(self.loads, [])
        self.assertIn("experiment: context-check@1", B.render(exp))

    def test_unsupported_selectors_are_refused_before_state_key_or_output(self):
        before = self.w.state_bytes()
        for name, over in (("unknown", dict(experiment="bogus")), ("empty", dict(experiment="")),
                           ("case", dict(experiment="Context-Check@1")), ("none", dict(experiment=None)),
                           ("needs retrieval", dict(experiment="context-check@1", retrieval=False))):
            with self.subTest(name):
                self.refused(**over)
        self.w.seed()
        for over in (dict(experiment="bogus"), dict(experiment="context-check@1", retrieval=False)):
            with self.subTest(live=over):
                with self.assertRaises(B.BenchmarkLaunchError):
                    B.run_benchmark(self.w.live_options(**over), key_loader=self.boom)
                self.assertFalse(self.w.out.exists())
        self.assertEqual(self.loads, [])

    def test_cli_selector_choices(self):
        ap = B._parser()
        base = ["--case-url", TBH.URL, "--cutoff-proof", "a", "--admission", "b", "--decision", "c", "--launch-baseline", "d",
                "--store", "e", "--base-import-pins", "f", "--head-import-pins", "g", "--out", "h"]
        self.assertEqual(ap.parse_args(base).experiment, "baseline")
        self.assertEqual(ap.parse_args(base + ["--experiment", "context-check@1"]).experiment, "context-check@1")
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            ap.parse_args(base + ["--experiment", "nope"])

    def test_live_experimental_run_sends_the_selected_task_text_reports_it_and_replays_strictly(self):
        model = self.model()
        rep, _ = self.live(model, experiment="context-check@1")
        self.assertEqual((rep["status"], rep["ok"]), ("completed", True))
        self.assertEqual(rep["experiment"]["id"], "context-check@1")
        self.assertEqual(rep["providerCalls"], 5)
        tasks = [json.loads(b["messages"][1]["content"])["task"] for b in model.bodies]
        self.assertEqual(tasks[0], prompts.INVESTIGATOR_IMPACT_TASK)          # IMPACT-01: the pilot default investigator
        self.assertEqual(tasks[2], prompts.VERIFIER_CONTEXT_CHECK_TASK)
        self.assertEqual(tasks[3], prompts.VERIFIER_CONTEXT_CHECK_TASK)
        self.assertEqual(tasks[4], prompts.JUDGE_FACT_TASK)
        # strict replay: zero live calls, no key/auth; the same selector is required
        before = self.w.state_bytes()
        trace, pin = rep["paths"]["trace"], rep["traceDigest"]["value"]
        out = self.tmp / "replay-exp"
        o = self.w.options(mode="replay", auth=None, out_dir=str(out), replay_trace=trace, trace_digest=pin,
                           experiment="context-check@1")
        rr = B.run_benchmark(o, key_loader=self.boom)
        self.assertEqual((rr["status"], rr["replay"]["liveCalls"], rr["replay"]["newSpendUsdMicros"]), ("completed", 0, 0))
        self.assertEqual(rr["experiment"]["id"], "context-check@1")
        self.assertEqual(self.w.state_bytes(), before)
        wrong = self.tmp / "replay-baseline"
        with self.assertRaises(PipelineError):
            B.run_benchmark(self.w.options(mode="replay", auth=None, out_dir=str(wrong), replay_trace=trace,
                                           trace_digest=pin), key_loader=self.boom)
        self.assertFalse(wrong.exists())

    def test_live_baseline_run_still_sends_the_baseline_task_text(self):
        model = self.model()
        rep, _ = self.live(model)
        self.assertEqual(rep["experiment"]["id"], "baseline")
        tasks = [json.loads(b["messages"][1]["content"])["task"] for b in model.bodies]
        self.assertEqual((tasks[2], tasks[3], tasks[4]),        # IMPACT-01: the baseline arm's verifier is impact mode's
                         (prompts.VERIFIER_IMPACT_TASK, prompts.VERIFIER_IMPACT_TASK, prompts.JUDGE_TASK))

    def test_identity_carries_the_experiment_only_when_selected(self):
        from reviewer.config import resolve_config
        cfg = resolve_config()
        ing = B.ingest(self.w.options(), cfg)
        b_o, e_o = self.w.options(), self.w.options(experiment="context-check@1")
        pb, plb, pob = B._profile_parts(b_o, cfg)
        pe, ple, poe = B._profile_parts(e_o, cfg)
        ib = B.config_identity(ing, pb, plb, pob, True, cfg, "baseline")
        self.assertNotIn("experiment", ib)
        self.assertEqual(ib, B.config_identity(ing, pb, plb, pob, True, cfg))
        ie = B.config_identity(ing, pe, ple, poe, True, cfg, "context-check@1")
        self.assertEqual(ie["experiment"]["tasks"], prompts.experiment_task_digests())
        self.assertNotEqual(B.eval_run_id(b_o, ib), B.eval_run_id(e_o, ie))
        self.assertNotIn(str(self.tmp), json.dumps(ie))


class ReportPromptLabels(TBH.Base):
    """VERIFY-CONTEXT-03 (H1): experiment.verifierPrompt/judgePrompt are the ids of the profile the run used, on every
    report path and in the text render. Retrieval off keeps the v1 verifier, with or without the selector's default."""

    def ids(self, rep):
        return rep["experiment"]["verifierPrompt"], rep["experiment"]["judgePrompt"]

    def used(self, **over):
        from reviewer.config import resolve_config
        p, _, _ = B._profile_parts(self.w.options(**over), resolve_config())
        return p["roles"]["verifier"]["promptVersion"], p["roles"]["judge"]["promptVersion"]

    def check_text(self, rep):
        v, j = self.ids(rep)
        self.assertIn(f"(verifier {v}, judge {j})", B.render(rep))

    def test_expected_ids_are_pinned_so_a_wrong_profile_cannot_pass_by_agreement(self):
        self.assertEqual(self.used(retrieval=False), ("verifier.refute@v1", "judge.wording@v1"))
        self.assertEqual(self.used(retrieval=True), ("verifier.impact@v1", "judge.wording@v1"))     # IMPACT-01 default
        self.assertEqual(self.used(retrieval=True, experiment="context-check@1"), (CTX, FACT))

    def test_plan_report_names_the_prompts_in_force_for_retrieval_on_off_and_the_arm(self):
        for kw in (dict(retrieval=True), dict(retrieval=False), dict(retrieval=True, experiment="context-check@1")):
            with self.subTest(**kw):
                rep = self.plan(**kw)
                self.assertEqual(self.ids(rep), self.used(**kw))
                self.check_text(rep)
        self.assertEqual(self.ids(self.plan(retrieval=False)), ("verifier.refute@v1", "judge.wording@v1"))

    def test_plan_routing_and_identity_are_unchanged_by_the_label_fix(self):
        p = self.plan()["plan"]
        self.assertEqual(p["firstRequest"]["bodySha256"], IMPACT_GOLD["benchFirst"])
        self.assertEqual(self.plan(retrieval=False)["plan"]["firstRequest"]["bodySha256"], GOLD["benchRetrievalOff"])
        self.assertEqual(digest(p["retrievalPolicy"]), IMPACT_GOLD["policy"])
        self.assertNotEqual(self.plan(retrieval=False)["plan"]["configIdentityDigest"], p["configIdentityDigest"])

    def test_live_and_replay_reports_name_the_prompts_in_force_with_retrieval_off(self):
        m = self.model()
        s = m.default_script()
        m.script = [s[1]["output"], s[3]["output"], s[4]]       # no context hops without retrieval
        rep, _ = self.live(m, retrieval=False)
        self.assertEqual(rep["status"], "completed")
        self.assertEqual(self.ids(rep), ("verifier.refute@v1", "judge.wording@v1"))
        self.check_text(rep)
        trace, pin = rep["paths"]["trace"], rep["traceDigest"]["value"]
        rr = B.run_benchmark(self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "rp"), replay_trace=trace,
                                            trace_digest=pin, retrieval=False), key_loader=self.boom)
        self.assertEqual((rr["status"], rr["replay"]["liveCalls"]), ("completed", 0))
        self.assertEqual(self.ids(rr), ("verifier.refute@v1", "judge.wording@v1"))
        self.check_text(rr)

    def test_live_retrieval_on_baseline_and_arm_reports_name_the_prompts_in_force(self):
        rep, _ = self.live()
        self.assertEqual(self.ids(rep), ("verifier.impact@v1", "judge.wording@v1"))
        self.check_text(rep)
        self.w = TBH.BWorld(self.tmp / "w2")
        rep, _ = self.live(experiment="context-check@1")
        self.assertEqual(self.ids(rep), (CTX, FACT))
        self.assertIs(rep["experiment"]["audited"], False)
        self.check_text(rep)

    def test_pipeline_refused_and_interrupted_reports_name_the_prompts_in_force(self):
        def refuse(spec):
            raise PipelineError("config", "stopped")

        def interrupt(spec):
            raise KeyboardInterrupt

        for retrieval, want in ((False, ("verifier.refute@v1", "judge.wording@v1")),
                                (True, ("verifier.impact@v1", "judge.wording@v1"))):
            with self.subTest(retrieval=retrieval, path="refused"):
                self.w = TBH.BWorld(self.tmp / f"r{retrieval}")
                self.w.seed()
                rep = B.run_benchmark(self.w.live_options(retrieval=retrieval), transport=self.model(),
                                      key_loader=self.loader, runner=refuse)
                self.assertEqual(rep["status"], "pipeline-refused")
                self.assertEqual(self.ids(rep), want)
                self.check_text(rep)
            with self.subTest(retrieval=retrieval, path="interrupted"):
                self.w = TBH.BWorld(self.tmp / f"i{retrieval}")
                self.w.seed()
                with self.assertRaises(KeyboardInterrupt):
                    B.run_benchmark(self.w.live_options(retrieval=retrieval), transport=self.model(),
                                    key_loader=self.loader, runner=interrupt)
                doc = json.loads((Path(self.w.out) / "report.json").read_text())
                self.assertEqual(doc["status"], "interrupted")
                self.assertEqual(self.ids(doc), want)

    def test_the_report_reads_the_profile_it_is_given_not_the_selector_or_a_literal(self):
        prof = repository_profile(False)
        prof["roles"]["verifier"]["promptVersion"] = "verifier.refute@v9"
        prof["roles"]["judge"]["promptVersion"] = "judge.wording@v9"
        for exp in ("baseline", "context-check@1"):
            self.assertEqual(self.ids({"experiment": B.experiment_report(exp, prof)}),
                             ("verifier.refute@v9", "judge.wording@v9"))
        with self.assertRaises(TypeError):
            B.experiment_report("baseline")          # no profile, no guess

    def test_an_unknown_selector_is_still_refused_before_inputs_state_key_or_output(self):
        before = self.w.state_bytes()
        for over in (dict(experiment="bogus"), dict(experiment="context-check@1", retrieval=False)):
            with self.subTest(**over), self.assertRaises(Exception):
                B.run_benchmark(self.w.live_options(**over), transport=self.model(), key_loader=self.boom)
        self.assertEqual(self.w.state_bytes(), before)
        self.assertFalse(self.w.out.exists())


if __name__ == "__main__":
    unittest.main()
