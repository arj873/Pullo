"""VERIFY-CONTEXT-02-review: independent gate of the opt-in context-check@1 prompt arm (VERIFY-CONTEXT-01).

Invented fixtures, scripted fake backend and fake OpenRouter transport only: no network, key, state, target, gold, Git
history or private orchestration. The suite checks mechanics (selection, routing, identity binding, refusals, strict
replay, unchanged fallback and report wording). It says nothing about whether the experimental prompt makes a real
model more accurate."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer.config import ReviewModels, resolve_config
from reviewer.contracts.canonical import digest
from reviewer.pilot import benchmark as B
from reviewer.pilot.profile import MODEL, ProfileError
from reviewer.pilot.repository_profile import (check_experiment, repository_plan, repository_policy,
                                               repository_profile)
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, prompts

import tests.pilot.test_benchmark_host as TBH
from tests.pipeline.helpers import (TURN_PLAN, TURN_PROFILE, Rig, hid, hyp, ifinal, judge, model_calls, script, tcid,
                                    treq, vfinal, vturn)

CTX, FACT = prompts.VERIFIER_CONTEXT_CHECK_PROMPT, prompts.JUDGE_FACT_WORDING_PROMPT
ARM = prompts.EXPERIMENT_CONTEXT_CHECK

METER_BASE = "def clamp(v, lo, hi):\n    return max(lo, min(v, hi))\n\n\ndef scale(v):\n    return v * 10\n"
METER_HEAD = "def clamp(v, lo, hi):\n    return min(lo, max(v, hi))\n\n\ndef scale(v):\n    return v * 10\n"
LIMITS = "LOW = 0\nHIGH = 100\n"
FILES_BASE = {"pkg/meter.py": METER_BASE, "pkg/limits.py": LIMITS}
FILES_HEAD = {"pkg/meter.py": METER_HEAD, "pkg/limits.py": LIMITS}
CLAIM = "clamp swaps min and max so every value collapses to lo"
EVR_A, EVR_B = "evr_" + "a1" * 8, "evr_" + "b2" * 8


def doc(request) -> dict:
    return json.loads(request["messages"][1]["content"])


def sha_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(text, sort_keys=True).encode()).hexdigest()


def arm_profile(base=TURN_PROFILE):
    p = copy.deepcopy(base)
    p["roles"]["verifier"]["promptVersion"] = CTX
    p["roles"]["judge"]["promptVersion"] = FACT
    return p


def without(d: dict, *paths) -> dict:
    d = copy.deepcopy(d)
    for path in paths:
        cur = d
        for k in path[:-1]:
            cur = cur[k]
        cur.pop(path[-1], None)
    return d


# ======================================================================== 0. environment control

class TempRoot(unittest.TestCase):
    def test_CONTROL_effective_temporary_root_is_writable_and_outside_every_git_work_tree(self):
        real = Path(os.path.realpath(tempfile.gettempdir()))
        self.assertTrue(os.access(real, os.W_OK), f"{real} is not writable")
        bad = [str(a) for a in (real, *real.parents) if os.path.lexists(a / ".git")]
        self.assertEqual(bad, [], "a .git above the temporary root makes repository imports refuse (bad-store)")


# ======================================================================== 1. selector and profile/policy surface

class Selector(unittest.TestCase):
    def test_only_the_exact_ids_are_accepted_and_the_arm_needs_retrieval(self):
        check_experiment("baseline", True)
        check_experiment("baseline", False)
        check_experiment(ARM, True)
        for bad in ("Context-Check@1", "context-check@1 ", "context-check@2", "context-check", "", "BASELINE", None, 1,
                    ("context-check@1",)):
            with self.subTest(bad=bad), self.assertRaises((ProfileError, TypeError)):
                check_experiment(bad, True)
        with self.assertRaises(ProfileError):
            check_experiment(ARM, False)
        for fn in (lambda: repository_profile(False, None, ARM), lambda: repository_policy(False, ARM),
                   lambda: repository_profile(True, None, "context-check@2")):
            with self.assertRaises(ProfileError):
                fn()

    def test_prompt_id_pairs_select_the_arm_only_when_both_are_named(self):
        ok = {(None, "judge.wording@v1"): "baseline", ("verifier.refute@v4", "judge.wording@v1"): "baseline",
              ("verifier.custom@v9", "judge.custom@v2"): "baseline", (CTX, FACT): ARM}
        for (v, j), want in ok.items():
            self.assertEqual(prompts.experiment_in_force(v, j), want)
        for v, j in ((CTX, "judge.wording@v1"), ("verifier.refute@v4", FACT), (None, FACT), ("verifier.custom@v9", FACT)):
            with self.subTest(v=v, j=j), self.assertRaises(ValueError):
                prompts.experiment_in_force(v, j)

    def test_the_arm_changes_only_two_prompt_ids_and_the_policy_prompt(self):
        for models in (None, ReviewModels.uniform(MODEL)):
            base, arm = repository_profile(True, models), repository_profile(True, models, ARM)
            self.assertEqual((arm["roles"]["verifier"]["promptVersion"], arm["roles"]["judge"]["promptVersion"]),
                             (CTX, FACT))
            paths = (("roles", "verifier", "promptVersion"), ("roles", "judge", "promptVersion"))
            self.assertEqual(without(base, *paths), without(arm, *paths))
            self.assertEqual((arm["id"], arm["version"]), (base["id"], base["version"]))
            self.assertEqual(repository_plan(base), repository_plan(arm))
            self.assertNotEqual(digest(base), digest(arm))
        pb, pa = repository_policy(True).to_doc(), repository_policy(True, ARM).to_doc()
        self.assertEqual(pa.pop("verifier_prompt"), CTX)
        self.assertEqual(pb.pop("verifier_prompt"), "verifier.impact@v1")      # IMPACT-01: pilot default
        self.assertEqual(pa, pb)

    def test_baseline_template_digest_sets_never_contain_the_experimental_text(self):
        t, rt = prompts.template_digests(), prompts.retrieval_template_digests()
        self.assertEqual(set(t), {"system", "investigator", "verifier", "judge", "formats"})
        self.assertEqual(set(rt), {"system", "investigator", "verifier", "tools", "citations", "formats"})
        exp = set(prompts.experiment_task_digests().values())
        self.assertFalse(exp & set(t.values()) or exp & set(rt.values()))
        with mock.patch.object(prompts, "VERIFIER_CONTEXT_CHECK_TASK", "mutated verifier"), \
                mock.patch.dict(prompts.EXPERIMENT_TASKS, verifier="mutated verifier", judge="mutated judge"):
            self.assertEqual((prompts.template_digests(), prompts.retrieval_template_digests()), (t, rt))
        # each role keeps its own baseline task for every id but the arm's
        for v in ("verifier.refute@v4", "verifier.refute@v1", "x"):
            self.assertIs(prompts.verifier_task(v), prompts.VERIFIER_REFUTE_TASK)
        for j in ("judge.wording@v1", FACT.upper(), "x"):
            self.assertIs(prompts.judge_task(j), prompts.JUDGE_TASK)


# ======================================================================== 2. pipeline: wire text, identity, refusals

class _Meter(Rig):
    def meter(self):
        return self.mini("meter-1", base=FILES_BASE, head=FILES_HEAD)

    def hyp(self, m):
        return hyp(m, "pkg/meter.py", 2, claim=CLAIM, mechanism="min and max are swapped; HIGH=100 is never reached.")

    def asking(self, m, h, *, judge_ids=None, notes="clamp swap confirmed; callers not checked"):
        read = dict(side="head", path="pkg/limits.py", start_line=1, end_line=2)
        rid = tcid("VERIFY", "verifier", 2, "read_file", **read)
        return script(ifinal(0, h), vturn(0, [treq("read_file", **read)]),
                      vfinal(1, m, evidence=[m.cite("pkg/meter.py", 2), {"kind": "tool-ref", "toolCallId": rid,
                                                                            "index": 0}], notes=notes),
                      judge({"findingIds": judge_ids or [hid(0, h)], "title": "clamp inverted",
                             "body": "clamp returns lo for any input."}))

    def run_arm(self, scr, m, arm, **kw):
        if arm:
            kw.update(profile=arm_profile(), retrieval=RetrievalPolicy(verifier_prompt=CTX))
        kw.setdefault("eval_id", EVR_B if arm else EVR_A)
        return self.record_turn(m, scr, **kw)

    def spec_for(self, m, arm, **kw):
        backend, _ = self.record_backend(script())
        if arm:
            kw.setdefault("retrieval", RetrievalPolicy(verifier_prompt=CTX))
            kw["profile"] = arm_profile()
        kw.setdefault("profile", TURN_PROFILE)
        return self.spec(m, backend, plan=TURN_PLAN, **kw)


class Pipeline(_Meter):

    def test_selected_task_text_reaches_every_verifier_hop_and_the_judge_and_matches_the_bound_digest(self):
        m = self.meter()
        h = self.hyp(m)
        res, spy = self.run_arm(self.asking(m, h), m, True)
        self.assertEqual((res.status, len(res.findings), len(res.comments)), ("completed", 1, 1))
        ver, jdg = model_calls(res, "VERIFY"), model_calls(res, "JUDGE")
        self.assertEqual(len(ver), 2)
        for c in ver:
            self.assertEqual((c["request"]["promptVersion"], doc(c["request"])["task"]),
                             (CTX, prompts.VERIFIER_CONTEXT_CHECK_TASK))
            self.assertEqual(c["request"]["outputSchema"], "VerifierTurn")
        self.assertEqual((jdg[0]["request"]["promptVersion"], doc(jdg[0]["request"])["task"]),
                         (FACT, prompts.JUDGE_FACT_TASK))
        self.assertEqual(jdg[0]["request"]["outputSchema"], "JudgeOutput")
        bound = prompts.experiment_task_digests()
        self.assertEqual(bound, {"verifier": sha_text(doc(ver[0]["request"])["task"]),
                                 "judge": sha_text(doc(jdg[0]["request"])["task"])})
        # investigator is untouched by the arm
        for c in model_calls(res, "INVESTIGATE"):
            self.assertEqual(doc(c["request"])["task"], prompts.INVESTIGATOR_RETRIEVE_TASK)

    def test_baseline_arm_sends_the_baseline_texts(self):
        m = self.meter()
        h = self.hyp(m)
        res, _ = self.run_arm(self.asking(m, h), m, False)
        self.assertEqual({doc(c["request"])["task"] for c in model_calls(res, "VERIFY")}, {prompts.VERIFIER_REFUTE_TASK})
        self.assertEqual(doc(model_calls(res, "JUDGE")[0]["request"])["task"], prompts.JUDGE_TASK)

    def test_identity_binds_arm_and_task_text_and_ignores_it_for_the_baseline(self):
        m = self.meter()
        base, arm = identity.config_snapshot_id(self.spec_for(m, False)), identity.config_snapshot_id(self.spec_for(m, True))
        self.assertNotEqual(base, arm)
        for patch in ({"verifier": prompts.VERIFIER_CONTEXT_CHECK_TASK + " "},
                      {"judge": prompts.JUDGE_FACT_TASK.replace("hypotheses", "facts")}):
            with self.subTest(role=next(iter(patch))):
                with mock.patch.dict(prompts.EXPERIMENT_TASKS, patch):
                    self.assertNotEqual(identity.config_snapshot_id(self.spec_for(m, True)), arm)
                    self.assertEqual(identity.config_snapshot_id(self.spec_for(m, False)), base)
        # a different policy number or judge model would also re-identify the arm (profile/policy are bound)
        tighter = RetrievalPolicy(verifier_prompt=CTX).tightened(verifier_turns=3)
        self.assertNotEqual(identity.config_snapshot_id(self.spec_for(m, True, retrieval=tighter)), arm)

    def test_half_selection_custom_ids_and_a_legacy_verifier_are_refused_before_any_call(self):
        legacy_with_fact = copy.deepcopy(TURN_PROFILE)
        legacy_with_fact["roles"]["verifier"].update(outputSchema="VerifierOutput", promptVersion="verifier.refute@v1")
        legacy_with_fact["roles"]["judge"]["promptVersion"] = FACT
        only_judge = copy.deepcopy(TURN_PROFILE)
        only_judge["roles"]["judge"]["promptVersion"] = FACT
        only_ver = arm_profile()
        only_ver["roles"]["judge"]["promptVersion"] = "judge.wording@v1"
        custom = arm_profile()
        custom["roles"]["verifier"]["promptVersion"] = "verifier.custom@v9"
        cases = {"judge only": (only_judge, None), "verifier only": (only_ver, RetrievalPolicy(verifier_prompt=CTX)),
                 "custom verifier + fact judge": (custom, RetrievalPolicy(verifier_prompt="verifier.custom@v9")),
                 "legacy verifier + fact judge": (legacy_with_fact, RetrievalPolicy()),
                 "profile/policy disagree": (arm_profile(), RetrievalPolicy())}
        for name, (profile, pol) in cases.items():
            with self.subTest(name):
                m = self.mini("half-" + name.replace(" ", "-").replace("/", "-"), base=FILES_BASE, head=FILES_HEAD)
                out = self.tmp / ("out-" + str(len(self.spies)))
                out.mkdir()
                with self.assertRaises(PipelineError) as c:
                    self.record(m, self.asking(m, self.hyp(m)), profile=profile, plan=TURN_PLAN, retrieval=pol,
                                out_root=out)
                self.assertEqual(c.exception.code, "invalid-input")
                self.assertEqual((self.spies[-1].calls, self.spies[-1].requests), (0, []))
                self.assertEqual(list(out.iterdir()), [])

    def test_strict_replay_is_per_arm_with_zero_live_calls(self):
        m = self.meter()
        h = self.hyp(m)
        rec = {arm: self.run_arm(self.asking(m, h), m, arm)[0] for arm in (False, True)}
        same = {False: dict(profile=TURN_PROFILE), True: dict(profile=arm_profile(),
                                                               retrieval=RetrievalPolicy(verifier_prompt=CTX))}
        for arm in (False, True):
            with self.subTest(arm=arm):
                for d in (f"rp-{arm}", f"x-{arm}"):
                    (self.tmp / d).mkdir()
                rr = self.replay(m, rec[arm], plan=TURN_PLAN, out=self.tmp / f"rp-{arm}", eval_id=EVR_B if arm else EVR_A,
                                 **same[arm])
                self.assertEqual((rr.status, rr.cost["liveCalls"]), ("completed", 0))
                self.assertEqual(rr.receipt["configSnapshotId"], rec[arm].receipt["configSnapshotId"])
                self.assertEqual([c["body"] for c in rr.comments], [c["body"] for c in rec[arm].comments])
                with self.assertRaises(PipelineError):
                    self.replay(m, rec[arm], plan=TURN_PLAN, out=self.tmp / f"x-{arm}", eval_id=EVR_B if arm else EVR_A,
                                **same[not arm])


# ======================================================================== 3. results, fallback and no inflation

class Results(_Meter):
    def test_same_script_gives_same_counts_severity_and_location_in_both_arms(self):
        m = self.meter()
        h = self.hyp(m)
        a, b = (self.run_arm(self.asking(m, h), m, arm)[0] for arm in (False, True))
        for r in (a, b):
            self.assertEqual((r.status, len(r.findings), len(r.comments), len(r.drops)), ("completed", 1, 1, 0))
        ca, cb = a.comments[0], b.comments[0]
        keys = ("severity", "proposedSeverity", "severityCeiling", "category", "path", "startLine", "endLine", "anchor",
                "evidenceStrength")
        self.assertEqual({k: ca.get(k) for k in keys}, {k: cb.get(k) for k in keys})
        self.assertEqual(a.findings[0]["severityBasis"], b.findings[0]["severityBasis"])
        self.assertEqual([c["request"]["role"] for c in model_calls(a)], [c["request"]["role"] for c in model_calls(b)])

    def test_an_uncertain_verifier_leaves_no_finding_or_placeholder_comment_in_either_arm(self):
        m = self.meter()
        h = self.hyp(m)
        scr = lambda: script(ifinal(0, h), vfinal(0, verdict="uncertain", evidence=[],      # noqa: E731
                                                  notes="could not obtain the callers"))
        for arm in (False, True):
            with self.subTest(arm=arm):
                r, _ = self.run_arm(scr(), m, arm, eval_id=("evr_" + ("c3" if arm else "d4") * 8))
                self.assertEqual((len(r.findings), len(r.comments)), (0, 0))
                self.assertFalse(model_calls(r, "JUDGE"))
                self.assertTrue(all(c.get("findingIds") for c in r.comments))

    def test_rejected_judge_in_the_arm_uses_the_unchanged_fallback_and_marks_it_incomplete(self):
        m = self.meter()
        h = self.hyp(m)
        notes = "verified the swap at line 2; HIGH value and callers NOT checked"
        r, _ = self.run_arm(self.asking(m, h, judge_ids=["F-not-a-survivor"], notes=notes), m, True)
        self.assertEqual((len(r.findings), len(r.comments)), (1, 1))
        title, body = prompts.fallback_wording(r.findings[0])
        self.assertEqual((r.comments[0]["title"], r.comments[0]["body"]), (title, body))
        # the fallback repeats the investigator's unverified mechanism verbatim: disclosed limit, not hidden
        self.assertIn("HIGH=100 is never reached", r.comments[0]["body"])
        self.assertTrue(any(i.get("stage") == "JUDGE" for i in r.incomplete))
        self.assertNotRegex(r.comments[0]["body"].lower(), r"\baudit")
        self.assertEqual(r.comments[0]["severity"], self.run_arm(self.asking(m, h), m, False,
                                                                 eval_id="evr_" + "e5" * 8)[0].comments[0]["severity"])


# ======================================================================== 4. benchmark host: plan, refusals, live, replay

class Bench(TBH.Base):
    def test_unsupported_selectors_are_refused_before_inputs_cfg_state_output_or_key(self):
        before = self.w.state_bytes()
        for bad in ("Context-Check@1", "context-check@2", "", None):
            with self.subTest(bad=bad):
                self.assertIn("experiment", self.refused(experiment=bad))
        self.assertIn("retrieval", self.refused(experiment=ARM, retrieval=False))
        # the selector is checked before any input file is opened: missing inputs are not what is reported
        o = self.w.live_options(experiment="context-check@9", cutoff_proof=str(self.tmp / "nope.json"),
                                config=str(self.tmp / "nope.toml"))
        with mock.patch.object(B, "ingest", side_effect=AssertionError("ingest reached")), \
                mock.patch.object(B, "effective_config", side_effect=AssertionError("config reached")):
            with self.assertRaises(B.BenchmarkLaunchError) as c:
                B.run_benchmark(o, key_loader=self.boom)
        self.assertIn("experiment", str(c.exception))
        self.assertEqual(self.w.state_bytes(), before)
        self.assertFalse(self.w.out.exists())

    def test_plan_first_request_ceiling_and_caps_equal_but_bound_digests_differ(self):
        base, arm = self.plan(), self.plan(experiment=ARM)
        self.assertEqual((base["status"], arm["status"]), ("planned", "planned"))
        bp, ap = base["plan"], arm["plan"]
        self.assertEqual(bp["firstRequest"]["bodySha256"], ap["firstRequest"]["bodySha256"])
        for k in ("runCeilingUsdMicros", "worstCaseAdmissionUsdMicros", "retries", "repairs", "outputCaps",
                  "retrievalPolicy", "models", "profile"):
            if k == "retrievalPolicy":
                self.assertEqual({**bp[k], "verifier_prompt": CTX}, ap[k])
            else:
                self.assertEqual(bp[k], ap[k], k)
        self.assertNotEqual(bp["profileDigest"], ap["profileDigest"])
        self.assertNotEqual(bp["configIdentityDigest"], ap["configIdentityDigest"])
        self.assertEqual(arm["experiment"]["taskDigests"], prompts.experiment_task_digests())
        self.assertNotIn("taskDigests", base["experiment"])

    def test_reports_never_call_the_arm_audited_and_disclose_the_fallback(self):
        rep = self.plan(experiment=ARM)
        e = rep["experiment"]
        self.assertIs(e["audited"], False)
        self.assertIn("fallback", e["fallbackWording"])
        self.assertIn("not an audit", e["note"])
        self.assertIn("no correctness claim", e["note"])
        text = json.dumps(rep).lower()
        for overclaim in ('"audited": true', "verified correct", "proven", "precision", "recall"):
            self.assertNotIn(overclaim, text)

    def test_baseline_report_names_the_prompts_actually_in_force(self):
        """Report truthfulness (H1 repro): experiment.verifierPrompt/judgePrompt must equal the profile the run used.
        `experiment_report` now takes that profile (VERIFY-CONTEXT-03); the repro passes the profile in force and pins
        the ids so agreement with a wrong profile cannot pass."""
        want = {True: ("verifier.impact@v1", "judge.wording@v1"), False: ("verifier.refute@v1", "judge.wording@v1")}
        for retrieval in (True, False):
            with self.subTest(retrieval=retrieval):
                cfg = resolve_config()
                o = self.w.options(retrieval=retrieval)
                profile, _, _ = B._profile_parts(o, cfg)
                rep = B.experiment_report(o.experiment, profile)
                got = (rep["verifierPrompt"], rep["judgePrompt"])
                self.assertEqual(got, (profile["roles"]["verifier"]["promptVersion"],
                                       profile["roles"]["judge"]["promptVersion"]))
                self.assertEqual(got, want[retrieval])

    def test_every_report_path_names_the_profile_the_pipeline_actually_received(self):
        """Independent of `_profile_parts`: a runner records `spec.profile` as the engine saw it, and the plan, live,
        refused, interrupted and replay headers plus the text render must carry exactly those ids. Retrieval off
        (verifier.refute@v1) is the case the old literal got wrong."""
        seen = []

        def spy(spec):
            seen.append((spec.profile["roles"]["verifier"]["promptVersion"], spec.profile["roles"]["judge"]["promptVersion"]))
            return B.run_review(spec)

        def refuse(spec):
            seen.append((spec.profile["roles"]["verifier"]["promptVersion"], spec.profile["roles"]["judge"]["promptVersion"]))
            raise PipelineError("config", "stopped")

        def interrupt(spec):
            seen.append((spec.profile["roles"]["verifier"]["promptVersion"], spec.profile["roles"]["judge"]["promptVersion"]))
            raise KeyboardInterrupt

        ids = lambda r: (r["experiment"]["verifierPrompt"], r["experiment"]["judgePrompt"])      # noqa: E731
        for n, (retrieval, exp) in enumerate(((True, "baseline"), (False, "baseline"), (True, ARM))):
            with self.subTest(retrieval=retrieval, experiment=exp):
                self.w = TBH.BWorld(self.tmp / f"s{n}")
                seen.clear()
                plan = B.run_benchmark(self.w.options(retrieval=retrieval, experiment=exp), key_loader=self.boom, runner=spy)
                self.assertEqual(ids(plan), seen[-1])
                self.assertIn("(verifier %s, judge %s)" % seen[-1], B.render(plan))
                for name, runner, status in (("refused", refuse, "pipeline-refused"), ("interrupted", interrupt, "interrupted")):
                    w = TBH.BWorld(self.tmp / f"s{n}{name}")
                    w.seed()
                    seen.clear()
                    if name == "refused":
                        rep = B.run_benchmark(w.live_options(retrieval=retrieval, experiment=exp), transport=self.model(),
                                              key_loader=self.loader, runner=runner)
                    else:
                        with self.assertRaises(KeyboardInterrupt):
                            B.run_benchmark(w.live_options(retrieval=retrieval, experiment=exp), transport=self.model(),
                                            key_loader=self.loader, runner=runner)
                        rep = json.loads((Path(w.out) / "report.json").read_text())
                    self.assertEqual((rep["status"], ids(rep)), (status, seen[-1]))
        # retrieval off keeps the v1 verifier: the profile the engine saw, not the retrieval-on id
        self.assertEqual(self._off_ids(), ("verifier.refute@v1", "judge.wording@v1"))

    def _off_ids(self):
        seen = []
        w = TBH.BWorld(self.tmp / "off")
        B.run_benchmark(w.options(retrieval=False), key_loader=self.boom,
                        runner=lambda spec: (seen.append((spec.profile["roles"]["verifier"]["promptVersion"],
                                                          spec.profile["roles"]["judge"]["promptVersion"])),
                                             B.run_review(spec))[1])
        return seen[-1]

    def test_live_and_replay_headers_with_retrieval_off_match_the_prompts_used(self):
        m = self.model()
        s = m.default_script()
        m.script = [s[1]["output"], s[3]["output"], s[4]]                      # no context hops without retrieval
        rep, _ = self.live(model=m, retrieval=False)
        self.assertEqual(rep["status"], "completed")
        pin = rep["traceDigest"]["value"]
        rr = B.run_benchmark(self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "rp-off"),
                                            replay_trace=rep["paths"]["trace"], trace_digest=pin, retrieval=False),
                             key_loader=self.boom)
        self.assertEqual(rr["replay"]["liveCalls"], 0)
        for r in (rep, rr):
            self.assertEqual((r["experiment"]["verifierPrompt"], r["experiment"]["judgePrompt"]),
                             ("verifier.refute@v1", "judge.wording@v1"))
            self.assertIn("(verifier verifier.refute@v1, judge judge.wording@v1)", B.render(r))
        written = json.loads((self.w.out / "report.json").read_text())
        self.assertEqual(written["experiment"], rep["experiment"])

    def test_CONTROL_a_literal_prompt_id_in_the_report_is_caught(self):
        """In-process mutation, no source edit: the old hard-coded v4 must fail the retrieval-off truthfulness check."""
        real = B.experiment_report

        def literal(experiment, profile):
            return {**real(experiment, profile), "verifierPrompt": "verifier.refute@v4"}

        rep_ok = B.run_benchmark(self.w.options(retrieval=False), key_loader=self.boom)
        self.assertEqual(rep_ok["experiment"]["verifierPrompt"], "verifier.refute@v1")
        with mock.patch.object(B, "experiment_report", literal):
            self.w = TBH.BWorld(self.tmp / "mut")
            rep = B.run_benchmark(self.w.options(retrieval=False), key_loader=self.boom)
        self.assertNotEqual(rep["experiment"]["verifierPrompt"], "verifier.refute@v1")

    def test_live_arm_sends_selected_text_on_the_wire_and_replays_only_under_the_same_selector(self):
        rep, model = self.live(experiment=ARM)
        self.assertEqual((rep["status"], rep["ok"], rep["providerCalls"]), ("completed", True, 5))
        users = [json.loads(next(m["content"] for m in b["messages"] if m["role"] == "user")) for b in model.bodies]
        self.assertEqual([u["task"] for u in users[2:4]], [prompts.VERIFIER_CONTEXT_CHECK_TASK] * 2)
        self.assertEqual(users[4]["task"], prompts.JUDGE_FACT_TASK)
        self.assertEqual(users[0]["task"], prompts.INVESTIGATOR_IMPACT_V2_TASK)    # EXPLORE-FLOOR: pilot default
        self.assertIs(rep["experiment"]["audited"], False)
        trace, pin = rep["paths"]["trace"], rep["traceDigest"]["value"]
        ok = self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "rp-ok"), replay_trace=trace,
                            trace_digest=pin, experiment=ARM)
        rr = B.run_benchmark(ok, key_loader=self.boom)
        self.assertEqual((rr["status"], rr["replay"]["liveCalls"], rr["replay"]["consumedZeroLive"]),
                         ("completed", 0, True))
        bad = self.w.options(mode="replay", auth=None, out_dir=str(self.tmp / "rp-bad"), replay_trace=trace,
                             trace_digest=pin)
        with self.assertRaises(PipelineError):
            B.run_benchmark(bad, key_loader=self.boom)
        self.assertFalse((self.tmp / "rp-bad").exists())


if __name__ == "__main__":
    unittest.main()
