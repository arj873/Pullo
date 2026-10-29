"""IMPACT-01: impact-aware review through the real engine, contracts, gateway (scripted synthetic provider) and tools.

Invented self-contained fixtures only: no network, key, state, target repository or live call. These tests prove
mechanics (the impact map is built and placed first, find_references is offered and logged, the new prompt texts are
selected and bound, a cross-file finding can be confirmed, coverage is disclosed and replay is strict). They do NOT show
that a real model reviews more broadly: that is an empirical question for a separately admitted run."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from reviewer.contracts.canonical import digest, profile_digest
from reviewer.pilot.repository_profile import repository_plan, repository_policy, repository_profile
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, impactcov, prompts
from reviewer.tools import IMPACT_TOOLS, Limits, normalize
from reviewer.contracts.canonical import tool_call_id

from tests.pipeline.helpers import (TURN_PLAN, TURN_PROFILE, Rig, events_of, hid, hyp, ifinal, iturn, judge,
                                    model_calls, script, tool_calls, treq, vfinal, vturn)

INV, VER = prompts.INVESTIGATOR_IMPACT_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
IMPACT_PROFILE = copy.deepcopy(TURN_PROFILE)
IMPACT_PROFILE["roles"]["investigator"]["promptVersion"] = INV
IMPACT_PROFILE["roles"]["verifier"]["promptVersion"] = VER
POLICY = RetrievalPolicy(investigator_prompt=INV, verifier_prompt=VER)

LIB_BASE = "def load_user(uid, cache=True):\n    return {'id': uid}\n\n\ndef unrelated():\n    return 1\n"
LIB_HEAD = "def load_user(uid, cache, region):\n    return {'id': uid}\n\n\ndef unrelated():\n    return 1\n"
USE = ("from src.lib import load_user\n\n\nclass Profile:\n    def show(self, uid):\n"
       "        user = load_user(uid)\n        return user['id']\n")
BASE = {"src/lib.py": LIB_BASE, "src/use.py": USE, "docs/notes.md": "load_user is documented here\n"}
HEAD = {"src/lib.py": LIB_HEAD, "src/use.py": USE, "docs/notes.md": "load_user is documented here\n"}


def tcid(stage, agent, ordinal, tool, **args):
    return tool_call_id(stage, agent, ordinal, tool, normalize(tool, args, Limits()))


def doc_of(request):
    return json.loads(request["messages"][1]["content"])


def w(ids, title="T", body="B"):
    return {"findingIds": list(ids), "title": title, "body": body}


class ImpactRig(Rig):
    def case(self, base=None, head=None):
        return self.mini(base=base or BASE, head=head or HEAD)

    def cross_file_script(self, m):
        """Investigator: find_references + read the dependent, then a cross-file claim citing BOTH sides. Verifier:
        reads the dependent itself, confirms citing the changed line and the dependent line."""
        h = hyp(m, "src/lib.py", 1, claim="load_user no longer has a default for cache; Profile.show calls it with one "
                "argument", category="breaking-change", impact="crash",
                mechanism="src/use.py:6 calls load_user(uid) without cache/region: TypeError",
                evidence=[m.cite("src/lib.py", 1), m.cite("src/use.py", 6)])
        read_id = tcid("VERIFY", "verifier", 2, "read_file", side="head", path="src/use.py", start_line=5, end_line=7)
        scr = script(
            iturn(0, [treq("find_references", side="head", symbol="load_user"),
                      treq("read_file", side="head", path="src/use.py", start_line=1, end_line=7)]),
            ifinal(1, h),
            vturn(0, [treq("read_file", side="head", path="src/use.py", start_line=5, end_line=7)]),
            vfinal(1, m, evidence=[m.cite("src/lib.py", 1), {"kind": "tool-ref", "toolCallId": read_id, "index": 0}],
                   notes="read the dependent: Profile.show passes one argument"),
            judge(w([hid(0, h)])))
        return scr, h

    def record_impact(self, m, scr, **kw):
        kw.setdefault("profile", IMPACT_PROFILE)
        kw.setdefault("retrieval", POLICY)
        return self.record_turn(m, scr, **kw)


class ImpactPipeline(ImpactRig):
    def test_prepare_logs_one_host_impact_scan_and_the_map_names_the_dependent(self):
        m = self.case()
        scr, _ = self.cross_file_script(m)
        res, spy = self.record_impact(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        scans = [e for e in tool_calls(res, "PREPARE") if e["tool"] == "impact_scan"]
        self.assertEqual(len(scans), 1)
        self.assertEqual((scans[0]["agentId"], scans[0]["args"]), ("prepare", {}))
        listing = scans[0]["result"]["evidence"][0]["excerpt"]
        self.assertIn('## load_user (function, definition line changed) defined "src/lib.py":1', listing)
        self.assertIn('"src/use.py":6 in "def show(self, uid):" (L5)', listing)
        self.assertNotIn('"src/lib.py":1 ', listing.split("\n", 3)[3])        # the changed definition line is excluded
        code = [(x["path"], x["lines"]) for x in scans[0]["result"]["evidence"][1:]]
        self.assertIn(("src/use.py", [6, 6]), code)
        self.assertTrue(all(x.get("resolved") is True for x in scans[0]["result"]["evidence"][1:]))

    def test_first_request_puts_the_impact_map_first_offers_find_references_and_uses_the_impact_task(self):
        m = self.case()
        scr, _ = self.cross_file_script(m)
        res, spy = self.record_impact(m, scr)
        first = doc_of(spy.requests[0])
        self.assertEqual(spy.requests[0]["promptVersion"], INV)
        self.assertEqual(first["task"], prompts.INVESTIGATOR_IMPACT_TASK)
        self.assertEqual(first["context"][0]["tool"], "impact_scan")
        self.assertEqual([t["tool"] for t in first["retrieval"]["tools"]],
                         ["list_files", "read_file", "search_literal", "diff", "find_references"])
        self.assertNotIn("impact_scan", json.dumps(first["retrieval"]))
        # the impact map is citable like any host-prepared result
        self.assertIn(first["context"][0]["toolCallId"], [r["toolCallId"] for r in first["citations"]["citableRefs"]])
        # safety framing is kept
        self.assertEqual(spy.requests[0]["messages"][0]["content"], prompts.RETRIEVAL_SYSTEM)
        self.assertIn("untrusted data", first["task"])

    def test_find_references_is_run_and_logged_and_counts_against_the_tool_budget(self):
        m = self.case()
        scr, _ = self.cross_file_script(m)
        res, spy = self.record_impact(m, scr)
        fr = [e for e in tool_calls(res, "INVESTIGATE") if e["tool"] == "find_references"]
        self.assertEqual(len(fr), 1)
        self.assertEqual(fr[0]["args"], {"side": "head", "symbol": "load_user", "path_prefix": "", "limit": 50,
                                         "offset": 0})
        self.assertEqual(fr[0]["result"]["status"], "ok")
        self.assertIn("requestedBy", fr[0])
        self.assertEqual(res.retrieval["summary"]["requestedToolCalls"],
                         sum(1 for e in tool_calls(res) if "requestedBy" in e))
        hop1 = doc_of(spy.requests[1])
        self.assertEqual(hop1["history"][0]["results"][0]["tool"], "find_references")

    def test_cross_file_finding_is_confirmed_by_reading_the_dependent_and_keeps_both_citations(self):
        m = self.case()
        scr, h = self.cross_file_script(m)
        res, spy = self.record_impact(m, scr)
        self.assertEqual(len(res.findings), 1, res.drops)
        f = res.findings[0]
        self.assertEqual({e["path"] for e in f["evidence"]}, {"src/lib.py", "src/use.py"})
        self.assertIn("src/use.py", {e.get("path") for e in f["verification"]["evidence"]})
        vreq = next(r for r in spy.requests if r["role"] == "verifier")
        self.assertEqual(doc_of(vreq)["task"], prompts.VERIFIER_IMPACT_TASK)
        self.assertIn("find_references", [t["tool"] for t in doc_of(vreq)["retrieval"]["tools"]])
        self.assertEqual(len(res.comments), 1)

    def test_coverage_is_disclosed_in_review_md_receipt_and_result(self):
        m = self.case()
        scr, _ = self.cross_file_script(m)
        res, _ = self.record_impact(m, scr)
        imp = res.impact
        self.assertEqual(imp["schema"], "impact-coverage@1")
        self.assertEqual((imp["symbols"], imp["truncated"], imp["findReferencesCalls"]), (1, False, 1))
        self.assertEqual(imp["references"], 3)          # src/use.py:1, src/use.py:6, docs/notes.md:1
        self.assertEqual(imp["files"], 2)
        self.assertEqual((imp["dependentFilesKnown"], imp["dependentFilesOpened"], imp["otherFilesOpened"]), (2, 1, 0))
        self.assertEqual(res.receipt["impact"], imp)
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("## Impact coverage", md)
        self.assertIn("Impact: 1 changed symbol(s) analysed (of 1 found), 3 reference(s) in 2 file(s); 1 of 2 known "
                      "dependent file(s) opened, 0 other file(s) outside the change opened; 1 find_references call(s).",
                      md)
        self.assertEqual(impactcov.summarize(events_of(res), {"src/lib.py"}), imp)

    def test_strict_replay_reproduces_the_impact_run_and_its_outputs(self):
        m = self.case()
        scr, _ = self.cross_file_script(m)
        res, _ = self.record_impact(m, scr)
        rep = self.replay(m, res, profile=IMPACT_PROFILE, plan=TURN_PLAN, retrieval=POLICY)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(rep.impact, res.impact)
        def body(r):      # everything but the run id and the cost basis (synthetic vs replayed) is identical
            return Path(r.review_path).read_text(encoding="utf-8").replace(r.run_id, "R").split("## Cost")[0]
        self.assertEqual(body(rep), body(res))
        self.assertIn("## Impact coverage", body(rep))
        # R3: the replayed impact scan is the recorded one, field for field (only deterministic caps can stop it)
        scan = lambda r: [{k: e[k] for k in ("toolCallId", "args", "resultHash", "result")}     # noqa: E731
                          for e in tool_calls(r, "PREPARE") if e["tool"] == "impact_scan"]
        self.assertEqual(scan(rep), scan(res))
        self.assertEqual(len(scan(rep)), 1)

    def test_impact_mode_is_bound_into_the_config_identity(self):
        m = self.case()
        s1, _ = self.cross_file_script(m)
        res, _ = self.record_impact(m, s1)
        s2, _ = self.cross_file_script(m)
        legacy, _ = self.record_turn(m, s2, eval_id="evr_" + "3" * 16)
        self.assertNotEqual(res.run["configSnapshotId"], legacy.run["configSnapshotId"])

    def test_no_symbols_still_yields_a_disclosed_map(self):
        m = self.case(base={"README.md": "old\n", "src/use.py": USE}, head={"README.md": "new\n", "src/use.py": USE})
        res, _ = self.record_impact(m, script(ifinal(0)))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual((res.impact["symbols"], res.impact["references"], res.impact["dependentFilesOpened"]),
                         (0, 0, 0))
        scan = next(e for e in tool_calls(res, "PREPARE") if e["tool"] == "impact_scan")
        self.assertIn("No changed definitions were detected", scan["result"]["evidence"][0]["excerpt"])

    def test_large_diff_cannot_push_the_impact_map_out_of_the_first_request(self):
        big_b = "".join(f"def f{i}(x):\n    return '{'b' * 150}' + x\n" for i in range(400))
        big_h = "".join(f"def f{i}(x):\n    return '{'h' * 150}' + x\n" for i in range(400))
        base, head = dict(BASE), dict(HEAD)
        for n in range(6):        # each diff result is capped at 24k chars: six of them exceed the 100k budget
            base[f"src/big{n}.py"], head[f"src/big{n}.py"] = big_b, big_h
        m = self.case(base=base, head=head)
        res, spy = self.record_impact(m, script(ifinal(0)))
        ctx = doc_of(spy.requests[0])["context"]
        self.assertEqual(ctx[0]["tool"], "impact_scan")
        self.assertTrue(ctx[0]["excerpts"])
        self.assertTrue(any(c["tool"] == "diff" and not c["excerpts"] for c in ctx))    # the budget did bind


class LegacyUnchanged(ImpactRig):
    def test_legacy_profile_has_no_impact_scan_no_find_references_and_no_impact_section(self):
        m = self.case()
        h = hyp(m, "src/lib.py", 1)
        res, spy = self.record_turn(m, script(iturn(0, [treq("find_references", side="head", symbol="load_user")]),
                                              ifinal(1, h), vfinal(0, m, path="src/lib.py", line=1),
                                              judge(w([hid(0, h)]))))
        self.assertFalse(any(e["tool"] == "impact_scan" for e in tool_calls(res)))
        fr = [e for e in tool_calls(res, "INVESTIGATE") if e["args"].get("requested") == "find_references"]
        self.assertEqual(len(fr), 1)
        self.assertEqual(fr[0]["result"]["notice"], "No such tool. Available: list_files, read_file, search_literal, diff.")
        first = doc_of(spy.requests[0])
        self.assertEqual(first["task"], prompts.INVESTIGATOR_RETRIEVE_TASK)
        self.assertEqual(first["retrieval"]["tools"], prompts.RETRIEVAL_TOOLS)
        self.assertIsNone(res.impact)
        self.assertNotIn("impact", res.receipt)
        self.assertNotIn("Impact coverage", Path(res.review_path).read_text(encoding="utf-8"))

    def test_impact_verifier_without_impact_investigator_is_refused_before_any_call(self):
        m = self.case()
        p = copy.deepcopy(TURN_PROFILE)
        p["roles"]["verifier"]["promptVersion"] = VER
        with self.assertRaises(PipelineError) as cm:
            self.record_turn(m, script(), profile=p, retrieval=RetrievalPolicy(verifier_prompt=VER))
        self.assertIn("impact verifier prompt", str(cm.exception))

    def test_frozen_retrieval_templates_are_untouched_and_impact_templates_are_separate(self):
        self.assertNotIn("find_references", json.dumps(prompts.RETRIEVAL_TEMPLATES))
        self.assertEqual(prompts.IMPACT_RETRIEVAL_TOOLS[:4], prompts.RETRIEVAL_TOOLS)
        self.assertEqual(set(prompts.impact_template_digests()), {"investigator", "verifier", "tools"})
        self.assertEqual(prompts.investigator_task("investigator.retrieve@v2"), prompts.INVESTIGATOR_RETRIEVE_TASK)
        self.assertEqual(prompts.verifier_task("verifier.refute@v4"), prompts.VERIFIER_REFUTE_TASK)
        self.assertEqual(IMPACT_TOOLS[-1], "find_references")


class RepositoryProfile(unittest.TestCase):
    def test_pilot_default_is_impact_mode_and_impact_false_is_the_earlier_profile(self):
        on = repository_profile(True, impact_version=1)
        self.assertEqual((on["roles"]["investigator"]["promptVersion"], on["roles"]["verifier"]["promptVersion"]),
                         (INV, VER))
        pol = repository_policy(True, impact_version=1)
        self.assertTrue(pol.impact)
        self.assertFalse(pol.exploration_floor)
        self.assertEqual((pol.investigator_prompt, pol.verifier_prompt), (INV, VER))
        # EXPLORE-FLOOR: the default is impact@v2 (same verifier, same numeric limits)
        v2 = repository_policy(True)
        self.assertEqual((v2.investigator_prompt, v2.verifier_prompt), (prompts.INVESTIGATOR_IMPACT_V2_PROMPT, VER))
        self.assertTrue(v2.impact and v2.exploration_floor)
        self.assertEqual(repository_profile(True)["roles"]["investigator"]["promptVersion"],
                         prompts.INVESTIGATOR_IMPACT_V2_PROMPT)
        old = repository_profile(True, impact=False)
        self.assertEqual(old["roles"]["investigator"]["promptVersion"], "investigator.retrieve@v2")
        self.assertEqual(repository_policy(True, impact=False), RetrievalPolicy())
        # numeric caps and plan are identical in both arms
        self.assertEqual(digest(repository_plan(on)), digest(repository_plan(old)))
        self.assertEqual({k: v for k, v in pol.to_doc().items() if not k.endswith("_prompt")},
                         {k: v for k, v in RetrievalPolicy().to_doc().items() if not k.endswith("_prompt")})
        self.assertNotEqual(profile_digest(on), profile_digest(old))

    def test_context_check_experiment_composes_with_impact(self):
        pol = repository_policy(True, prompts.EXPERIMENT_CONTEXT_CHECK, impact_version=1)
        self.assertEqual((pol.investigator_prompt, pol.verifier_prompt), (INV, prompts.VERIFIER_CONTEXT_CHECK_PROMPT))
        pol2 = repository_policy(True, prompts.EXPERIMENT_CONTEXT_CHECK)
        self.assertEqual((pol2.investigator_prompt, pol2.verifier_prompt),
                         (prompts.INVESTIGATOR_IMPACT_V2_PROMPT, prompts.VERIFIER_CONTEXT_CHECK_PROMPT))
        self.assertEqual(repository_policy(True, prompts.EXPERIMENT_CONTEXT_CHECK, impact=False),
                         RetrievalPolicy(verifier_prompt=prompts.VERIFIER_CONTEXT_CHECK_PROMPT))


if __name__ == "__main__":
    unittest.main()
