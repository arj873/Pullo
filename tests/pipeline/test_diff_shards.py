"""SHARD-COVERAGE-01: investigator.impact@v4 diff-shard sweep investigators, through the real engine, contracts, gateway
(scripted synthetic provider) and tools.

Invented self-contained fixtures only: no network, key, state, target repository or live call. These tests prove the
mechanics (deterministic sharding, per-file dispositions with one bounded continuation, coverage disclosure in the
INVESTIGATE artifact, the trace and review.md, round-robin VERIFY with a scaled cap and renewed verifier sessions,
graceful sweep failures, time slices, identity binding, strict replay) and that impact@v1/@v2/@v3 stay byte-identical.
They do NOT show that sweeps make a real model find more defects: that needs an admitted run."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from reviewer.contracts import validate
from reviewer.contracts.budget import HOST_STOP_RECORDING, investigation_limit
from reviewer.contracts.canonical import digest
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, prompts, specialists, sweeps
from reviewer.tools import SWEEP_TOOLS, ArgError, Limits, ToolSession, full_view, normalize

from tests.pipeline.helpers import (TURN_PLAN, entry, events_of, hyp, judge, model_calls, resp, script, tool_calls,
                                    treq, vfinal)
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import (V3_PLAN, V3_POLICY, V3_PROFILE, SpecRig, ask, inv_calls, sfail, sfinal,
                                             shid, sturn)

INV4, VER = prompts.INVESTIGATOR_IMPACT_V4_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
AGENTS = ("contracts", "logic", "safety")
V4_PROFILE = copy.deepcopy(V3_PROFILE)
V4_PROFILE["roles"]["investigator"]["promptVersion"] = INV4
V4_POLICY = RetrievalPolicy(investigator_prompt=INV4, verifier_prompt=VER, run_tool_calls=400)
V4_PLAN = copy.deepcopy(TURN_PLAN)
V4_PLAN["specialists"] = list(AGENTS) + ["diff-sweep"]
V4_PLAN["budget"].update(maxToolCalls=400, stageCeilingsSec={"INVESTIGATE": 240})   # as repository_plan builds it

# A 9-path change: 6 reviewable files (two shards of three), a deleted file, a lockfile and a binary file.
BIG_BASE = {
    "src/app/core.py": "def total(items):\n    s = 0\n    for i in range(len(items)):\n        s += items[i]\n    return s\n",
    "src/app/io.py": "def read(path):\n    with open(path) as f:\n        return f.read()\n",
    "src/app/util.py": "def clamp(x, lo, hi):\n    return max(lo, min(x, hi))\n",
    "src/app/old.py": "def legacy():\n    return 0\n",
    "src/app/use.py": "from app.core import total\n\n\ndef report(xs):\n    return total(xs)\n",
    "tests/test_core.py": "from app.core import total\n\n\ndef test_total():\n    assert total([1, 2]) == 3\n",
    "docs/guide.md": "# Guide\n\nCall total(items).\n",
    "package-lock.json": "{\"lockfileVersion\": 1}\n",
    "assets/blob.bin": "\x00\x01base\n",
}
BIG_HEAD = {
    "src/app/core.py": "def total(items):\n    s = 0\n    for i in range(1, len(items)):\n        s += items[i]\n    return s\n",
    "src/app/io.py": "def read(path):\n    f = open(path)\n    return f.read()\n",
    "src/app/util.py": "def clamp(x, lo, hi):\n    return max(hi, min(x, lo))\n",
    "src/app/conf.py": "TIMEOUT = 30\nRETRIES = 3\n",
    "src/app/use.py": BIG_BASE["src/app/use.py"],
    "tests/test_core.py": "from app.core import total\n\n\ndef test_total():\n    assert total([1, 2]) == 2\n",
    "docs/guide.md": "# Guide\n\nCall total(items) with a list.\n",
    "package-lock.json": "{\"lockfileVersion\": 2}\n",
    "assets/blob.bin": "\x00\x01head\n",
}
CHANGED = sorted(p for p in BIG_BASE.keys() | BIG_HEAD.keys() if BIG_BASE.get(p) != BIG_HEAD.get(p))
SHARD1 = ["docs/guide.md", "src/app/conf.py", "src/app/core.py"]
SHARD2 = ["src/app/io.py", "src/app/util.py", "tests/test_core.py"]
EXCLUDED = [{"path": "assets/blob.bin", "reason": "no-text-diff"}, {"path": "package-lock.json", "reason": "generated"},
            {"path": "src/app/old.py", "reason": "deleted"}]

# Recorded from the pre-change source (af00d48f): v3 runs of SpecRig.three_script on the small case (eval id 6...) and
# of DiffShardRig.big_v3_script on the 9-path case (eval id 7...). A v3 run must never shard: every request hash, config
# identity, artifact digest and the whole trace digest stay these bytes.
V3_SMALL_PIN = {
    "cfg": "sha256:96ff7073024599f3fcc621397590d16c93314081aa597e0e67521256f1baed2b",
    "trace": "sha256:dc6a99832af2528dc38287c30bde5eb95a3bd8e0d2b7ee5d703af65e547efdfd",
    "INVESTIGATE": "sha256:e44eca59265b7ac03e97a6b0cf5f114c305d8920a2bdfaeb68e30f94d98b30f0",
    "VERIFY": "sha256:e2c66caba2986cf760b5ac52ee2f2264324048d77dcd7622f4964b4bf8abe180",
    "PUBLISH": "sha256:07c34c158f9a733eff44470a202e20fe19dddb57b3ee391593dbbe5cbcc5b470",
    "requests": ["sha256:c86937b5b36a46b70d9ede67ef17faf86f9e653421344867ea85fa77bcc50fb5",
                 "sha256:3c2c629ae05437701444471cde6aece420fc943b252f29fc7b14f638a404580e",
                 "sha256:09ee726c74ea9bbd85ffac9dcfed0641914ea66e34c4af15178d8c4c8473da92",
                 "sha256:da0cb1c8e76fccd1eb6fa885dbcd6c17ff494329d9f6f639b870d97137557c11",
                 "sha256:05bd7b22ba77f5ba162e212bc184e9b0674cb7f37f65bd805bfec1c74649c14d",
                 "sha256:c28618a1a7ffc297d389cc7bf850aab52722e09c533f0de83df4e9cae9234b28",
                 "sha256:8ad1f0c65134754c71c69fa1d0bc598a7fb329c6c698f3820b6c6402e3080440",
                 "sha256:3c7948f5f213e4c23c8ef5e614f3512e1097d68a975aee0c053338e64297f8c6",
                 "sha256:4439dc8da87e024380f3394dac4865254b899b631042ad1843e51789c43952f6",
                 "sha256:08d029d2693d44b1517c2c4c36607c7d25b66a43818e25637e9151b0f553d3ae"]}
V3_BIG_PIN = {
    "cfg": "sha256:115710dad082670188263260fada269c18532bbe766a6c0814ff7d3234ea44e6",
    "trace": "sha256:1de25e2461a9a7df99e88de123a7af9a5d663e572c62a6e1f54a9c564794a618",
    "INVESTIGATE": "sha256:1c2cd61694aeb99090bdd28382a6b51f252d668f077d482c21470e2d53250a1b",
    "VERIFY": "sha256:f908b25ada856cda7d05b2ff4f23c866620e9c9b88b59755a31542d17a459c21",
    "PUBLISH": "sha256:bf403bd9e44dfe96f53dc3a9018dade8955d4c6e18a67d4f034eb4e35c952e17",
    "requests": ["sha256:3cf5a97cb3c7fb0af7294202df927a7dc763bb08187b6f30b2db629eea5896ad",
                 "sha256:aa869b8af67bf361b167d0ed6daa085e6e851db6e9a6f792b0810b0c7c945856",
                 "sha256:56f72f47e02cf20cc0087372df61a72208a80fd589d12d24ba811dc2e039b838",
                 "sha256:18d8a09c792b98e843792dd5efe0c94672d704c481ff7d9cc87a62ee363e022a",
                 "sha256:751caf3341bbb6fe0358effe08c0f519fc153c001f7fe6ec94f4286234c0b21a",
                 "sha256:9f3b07fd14e076c94f2f9dfb44b93ee341075f02ac524cf35ea1ca188d447794",
                 "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24",
                 "sha256:f93a06328bca99579885cab3de47fde0c45f8db0ba9c34cbdc98e1fe0bdf2389"]}
def disp(path, reason="checked the changed lines and their callers"):
    return treq("file_disposition", path=path, reason=reason)


def sweep_calls(res):
    return [e for e in inv_calls(res) if e["agentId"].startswith("sweep-")]


def sweep_events(res):
    return [(e["agentId"], e["decision"], e["missing"]) for e in events_of(res) if e["type"] == "sweep.disposition"]


class DiffShardRig(SpecRig):
    def big(self):
        return self.mini("big-1", base=BIG_BASE, head=BIG_HEAD)

    def record_v4(self, m, scr, **kw):
        kw.setdefault("profile", V4_PROFILE)
        kw.setdefault("retrieval", V4_POLICY)
        kw.setdefault("plan", V4_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v4(self, m, res, **kw):
        kw.setdefault("profile", V4_PROFILE)
        kw.setdefault("retrieval", V4_POLICY)
        kw.setdefault("plan", V4_PLAN)
        return self.replay(m, res, **kw)

    # hypotheses on the 9-path case
    def h_core(self, m):
        return hyp(m, "src/app/core.py", 3, claim="the loop skips the first item", category="bug",
                   impact="incorrect-result", evidence=[m.cite("src/app/core.py", 3)])

    def h_util(self, m):
        return hyp(m, "src/app/util.py", 2, claim="clamp swaps lo and hi", category="bug",
                   impact="incorrect-result", evidence=[m.cite("src/app/util.py", 2)])

    def h_io(self, m):
        return hyp(m, "src/app/io.py", 2, claim="the file handle is never closed", category="bug",
                   impact="regression", evidence=[m.cite("src/app/io.py", 2)])

    def big_v3_script(self, m):
        hc = self.h_core(m)
        return script(ask("contracts", 0), sfinal("contracts", 1, hc), ask("logic", 0), sfinal("logic", 1),
                      ask("safety", 0), sfinal("safety", 1), vfinal(0, m, path="src/app/core.py", line=3),
                      judge(w([shid("contracts", 0, hc)])))

    def specialists_part(self, m, hc=None):
        return [ask("contracts", 0), sfinal("contracts", 1, *([hc] if hc else [])), ask("logic", 0), sfinal("logic", 1),
                ask("safety", 0), sfinal("safety", 1)]

    def e2e_script(self, m):
        """contracts finds core.py; sweep-01 records two dispositions and repeats the core.py claim (merged);
        sweep-02 answers at once with util.py, gets the one continuation, records tests/test_core.py and adds io.py."""
        hc, hu, hi = self.h_core(m), self.h_util(m), self.h_io(m)
        scr = script(*self.specialists_part(m, hc),
                     sturn("sweep-01", 0, [disp("docs/guide.md", "wording only"), disp("src/app/conf.py", "constants")]),
                     sfinal("sweep-01", 1, hc),
                     sfinal("sweep-02", 0, hu),
                     sturn("sweep-02", 1, [disp("tests/test_core.py", "the test follows the new total")]),
                     sfinal("sweep-02", 2, hi),
                     vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                     vfinal(2, m, path="src/app/io.py", line=2),
                     judge(w([shid("contracts", 0, hc)]), w([shid("sweep-02", 0, hu)]), w([shid("sweep-02", 0, hi)])))
        return scr, (hc, hu, hi)


# ---------------------------------------------------------------- the pure shard rule

def frow(path, status="modified"):
    return {"path": path, "status": status, "additions": 1, "deletions": 1}


def dev(path, chars=10, status="ok"):
    return {"type": "tool.call", "stage": "PREPARE", "tool": "diff", "args": {"path": path},
            "result": {"status": status, "evidence": [{"excerpt": "x" * chars}] if chars else []}}


class ShardRule(unittest.TestCase):
    def test_reviewable_keeps_tests_and_docs_and_excludes_only_non_reviewable_files(self):
        files = [frow("src/a.py"), frow("tests/test_a.py"), frow("docs/a.md"), frow("gone.py", "deleted"),
                 frow("yarn.lock"), frow("web/app.min.js"), frow("vendor/x.py"), frow("img.png"), frow("same.py"),
                 frow("nodiff.py")]
        diffs = {p: dev(p) for p in ("src/a.py", "tests/test_a.py", "docs/a.md", "yarn.lock", "web/app.min.js",
                                     "vendor/x.py")}
        diffs["img.png"] = dev("img.png", 0, "unavailable")
        diffs["same.py"] = dev("same.py", 0, "empty")
        rev, out = sweeps.reviewable(files, diffs)
        self.assertEqual([p for p, _ in rev], ["docs/a.md", "src/a.py", "tests/test_a.py"])     # path order
        self.assertEqual({x["path"]: x["reason"] for x in out},
                         {"gone.py": "deleted", "yarn.lock": "generated", "web/app.min.js": "generated",
                          "vendor/x.py": "generated", "img.png": "no-text-diff", "same.py": "no-text-diff",
                          "nodiff.py": "no-text-diff"})

    def test_shards_are_deterministic_even_and_order_preserving(self):
        def mk(n, chars=100):
            return [(f"f{i:03d}.py", chars) for i in range(n)]
        sizes = lambda n, c=100: [len(s) for s in sweeps.shards(mk(n, c))[0]]   # noqa: E731
        self.assertEqual([sizes(n) for n in (0, 1, 3)], [[], [], []])           # tiny: no shards (v3 behaviour)
        self.assertEqual(sizes(4), [4])
        self.assertEqual(sizes(5), [5])
        self.assertEqual(sizes(6), [3, 3])
        self.assertEqual(sizes(7), [4, 3])
        self.assertEqual(sizes(15), [5, 5, 5])
        self.assertEqual(sizes(28), [5, 5, 5, 5, 4, 4])
        self.assertEqual(sizes(40), [7, 7, 7, 7, 6, 6])                         # MAX_SHARDS: larger shards
        self.assertEqual(sizes(4, 25_000), [2, 1, 1])                            # ceil(100k / 40k) = 3 shards
        self.assertEqual(sizes(6, 25_000), [2, 2, 1, 1])                         # ceil(150k / 40k) = 4 shards
        sh, over = sweeps.shards(mk(70))
        self.assertEqual(([len(s) for s in sh], over), ([10] * 6, [f"f{i:03d}.py" for i in range(60, 70)]))
        files = mk(28)
        sh, _ = sweeps.shards(files)
        self.assertEqual([p for s in sh for p, _ in s], [p for p, _ in files])  # contiguous, path order, no file twice
        self.assertEqual(sweeps.shards(list(files)), sweeps.shards(files))
        rows = [frow(p) for p, _ in files]
        diffs = {p: dev(p, 100) for p, _ in files}
        for perm in (list(reversed(rows)), rows[7:] + rows[:7]):                 # PREPARE order does not matter
            self.assertEqual(sweeps.shards(sweeps.reviewable(perm, diffs)[0]), sweeps.shards(files))

    def test_char_budget_raises_the_shard_count(self):
        k = lambda n, c: len(sweeps.shards([(f"f{i}", c) for i in range(n)])[0])   # noqa: E731
        self.assertEqual(k(4, 100), 1)
        self.assertEqual(k(4, 15_000), 2)            # 60k chars > 40k
        self.assertEqual(k(5, 30_000), 4)            # 150k chars -> 4 shards
        self.assertEqual(k(4, 1_000_000), 4)         # never more shards than files
        self.assertEqual(k(9, 1_000_000), sweeps.MAX_SHARDS)

    def test_budget_time_and_verify_rules(self):
        self.assertEqual(sweeps.specialist_ceiling(600), 300)
        self.assertEqual(specialists.time_slices(sweeps.specialist_ceiling(600)), [100, 200, 300])   # = v3 live
        self.assertEqual(specialists.time_slices(sweeps.specialist_ceiling(240)), [40, 80, 120])     # = v3 legacy
        self.assertEqual(sweeps.time_slices(600, 3), [400, 500, 600])
        self.assertEqual(sweeps.time_slices(600, 1), [600])
        self.assertIsNone(sweeps.time_slices(None, 2))
        self.assertEqual(sweeps.tool_ceilings(30, [3, 5, 1]), [45, 62, 75])
        self.assertEqual(sweeps.spend_ceilings(100, 1000, 3), [400, 700, 1000])
        self.assertEqual(sweeps.spend_ceilings(1500, 1000, 2), [1000, 1000])     # share used up: nothing left
        self.assertEqual([sweeps.verify_cap(k) for k in (0, 1, 2, 5, 6)], [20, 24, 28, 40, 40])
        self.assertEqual([sweeps.verifier_agent(p, 0) for p in (0, 9, 10, 35)], ["verifier"] * 4)
        self.assertEqual([sweeps.verifier_agent(p, 2) for p in (0, 9, 10, 19, 20, 39)],
                         ["verifier", "verifier", "verifier-02", "verifier-02", "verifier-03", "verifier-04"])
        self.assertEqual(sweeps.merge_order([{"agentId": "sweep-01"}, {"agentId": "contracts"},
                                             {"agentId": "sweep-02"}]),
                         ["contracts", "logic", "safety", "sweep-01", "sweep-02"])

    def test_the_sweep_block_bounds_the_changed_path_list(self):
        many = [f"f{i:04d}.py" for i in range(prompts.MAX_LISTED_PATHS + 7)]
        b = prompts.sweep_block(2, 3, many[:2], many)
        self.assertEqual((len(b["allChangedPaths"]), b["allChangedPathsOmitted"]), (prompts.MAX_LISTED_PATHS, 7))
        self.assertNotIn("allChangedPathsOmitted", prompts.sweep_block(1, 1, many[:2], many[:3]))

    def test_merge_with_the_v4_order_keeps_the_earlier_agent(self):
        def H(agent, path, line, cat="bug"):
            return {"id": f"hyp_{agent[:4]}{line:012d}"[:20], "specialist": agent, "category": cat,
                    "location": {"path": path, "line": line}}
        hs = [H("contracts", "a.py", 3), H("sweep-01", "a.py", 4), H("sweep-02", "a.py", 5), H("sweep-01", "b.py", 1)]
        order = ["contracts", "logic", "safety", "sweep-01", "sweep-02"]
        got = specialists.merge(hs, order)
        self.assertEqual(got, [{"keptId": hs[0]["id"], "mergedIds": [hs[1]["id"], hs[2]["id"]],
                                "rule": specialists.MERGE_RULE}])
        with self.assertRaises(KeyError):          # the v3 default order knows no sweep agent
            specialists.merge(hs)


# ---------------------------------------------------------------- the file_disposition tool

class DispositionTool(DiffShardRig):
    def session(self, m):
        view = full_view(m.base.root, m.base.manifest, m.head.root, m.head.manifest)
        return ToolSession(view, stage="INVESTIGATE", agent_id="sweep-01", tools=SWEEP_TOOLS)

    def test_records_only_a_head_file_with_a_one_line_reason(self):
        m = self.big()
        s = self.session(m)
        ok = s.call("file_disposition", {"path": "src/app/io.py", "reason": "open/close checked"})
        self.assertEqual((ok.result["status"], ok.result["evidence"]), ("ok", []))
        self.assertIn("examined, no issue", ok.result["notice"])
        gone = s.call("file_disposition", {"path": "src/app/old.py", "reason": "deleted"})
        self.assertEqual(gone.result["status"], "unavailable")
        for args in ({"path": "src/app/io.py"}, {"path": "src/app/io.py", "reason": ""},
                     {"path": "src/app/io.py", "reason": "two\nlines"}, {"path": "src/app/io.py", "reason": "x" * 301},
                     {"path": "src/app/io.py", "reason": 3}, {"path": "src/app/io.py", "reason": "ok", "extra": 1},
                     {"path": "../etc/passwd", "reason": "ok"}):
            with self.subTest(args=args):
                self.assertEqual(s.call("file_disposition", args).result["status"], "denied")
        with self.assertRaises(ArgError):
            normalize("file_disposition", {"path": "a.py", "reason": "ghp_" + "A1b2C3d4" * 5}, Limits())
        self.assertEqual(normalize("file_disposition", {"path": "a.py", "reason": "fine"}, Limits()),
                         {"path": "a.py", "reason": "fine"})
        # an impact (non-sweep) session does not offer it
        view = full_view(m.base.root, m.base.manifest, m.head.root, m.head.manifest)
        other = ToolSession(view, stage="INVESTIGATE", agent_id="contracts", tools=SWEEP_TOOLS[:-1])
        self.assertEqual(other.call("file_disposition", {"path": "src/app/io.py", "reason": "x"}).tool, "unknown-tool")


# ---------------------------------------------------------------- end to end

class EndToEnd(DiffShardRig):
    def test_sweeps_cover_every_shard_file_with_a_disposition(self):
        m = self.big()
        scr, (hc, hu, hi) = self.e2e_script(m)
        res, spy = self.record_v4(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual([(c["agentId"], c["ordinal"]) for c in inv_calls(res)],
                         [(a, k) for a in AGENTS for k in (0, 1)]
                         + [("sweep-01", 0), ("sweep-01", 1), ("sweep-02", 0), ("sweep-02", 1), ("sweep-02", 2)])
        reqs = [r for r in spy.requests if r["role"] == "investigator"]
        # the specialists' requests are the v3 ones: lens tasks, impact tools, no sweep block
        for r in reqs[:6]:
            d = doc_of(r)
            self.assertNotIn("sweep", d)
            self.assertEqual(d["retrieval"]["tools"], prompts.IMPACT_RETRIEVAL_TOOLS)
            self.assertIn(d["task"], [prompts.investigator_v3_task(a) for a in AGENTS])
        s1, s2 = doc_of(reqs[6]), doc_of(reqs[8])
        for d, shard, k in ((s1, SHARD1, 1), (s2, SHARD2, 2)):
            self.assertEqual(d["task"], prompts.SWEEP_TASK)
            self.assertEqual(d["retrieval"]["tools"], prompts.SWEEP_RETRIEVAL_TOOLS)
            self.assertEqual(d["sweep"], {"version": "diff-shard-sweep@1", "shard": k, "shards": 2, "shardPaths": shard,
                                          "allChangedPaths": CHANGED})
            # context: the changed-path list and the full diffs of the shard's own files, nothing else
            ctx = [(c["tool"], c["args"].get("path")) for c in d["context"]]
            self.assertEqual(ctx, [("diff", None)] + [("diff", p) for p in shard])
            self.assertTrue(all(c["excerpts"] for c in d["context"]))
        cont = doc_of(reqs[9])
        self.assertEqual(cont["dispositionCheck"]["missingDispositions"], ["src/app/io.py", "tests/test_core.py"])
        self.assertEqual(cont["dispositionCheck"]["instruction"], prompts.SWEEP_DISPOSITION_CONTINUATION)
        self.assertEqual([h["claim"] for h in cont["dispositionCheck"]["earlierHypotheses"]], [hu["claim"]])
        self.assertEqual((reqs[9]["hop"], reqs[10]["hop"]), (0, 1))  # a new chain of the same agent and session
        self.assertEqual(sweep_events(res), [("sweep-01", "complete", []),
                                             ("sweep-02", "continue", ["src/app/io.py", "tests/test_core.py"]),
                                             ("sweep-02", "final", [])])
        pay = self.payload(res)["payload"]
        self.assertEqual([a["agentId"] for a in pay["agents"]], list(AGENTS) + ["sweep-01", "sweep-02"])
        cov = pay["sweep"]
        self.assertEqual(validate("SweepCoverage", cov), [])
        self.assertEqual(cov["shards"], [{"agentId": "sweep-01", "paths": SHARD1, "diffChars": cov["shards"][0]["diffChars"]},
                                         {"agentId": "sweep-02", "paths": SHARD2, "diffChars": cov["shards"][1]["diffChars"]}])
        self.assertEqual(cov["excluded"], EXCLUDED)
        self.assertEqual({f["path"]: (f["agentId"], f["disposition"], f["hypotheses"]) for f in cov["files"]},
                         {"docs/guide.md": ("sweep-01", "no-issue", 0), "src/app/conf.py": ("sweep-01", "no-issue", 0),
                          "src/app/core.py": ("sweep-01", "issue", 1), "src/app/io.py": ("sweep-02", "issue", 1),
                          "src/app/util.py": ("sweep-02", "issue", 1), "tests/test_core.py": ("sweep-02", "no-issue", 0)})
        self.assertEqual(next(f for f in cov["files"] if f["path"] == "docs/guide.md")["reason"], "wording only")
        self.assertEqual(cov["summary"], {"swept": 6, "issue": 3, "noIssue": 3, "uncovered": 0})
        self.assertEqual(cov["reviewable"], 6)
        trace_cov = [e["coverage"] for e in events_of(res) if e["type"] == "investigate.coverage"]
        self.assertEqual(trace_cov, [cov])                           # the same summary in the trace
        # sweep-01's core.py claim duplicates contracts' (merged before VERIFY); the rest is verified round-robin
        self.assertEqual(pay["merges"], [{"keptId": shid("contracts", 0, hc), "mergedIds": [shid("sweep-01", 0, hc)],
                                          "rule": specialists.MERGE_RULE}])
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, hc), shid("sweep-02", 0, hu), shid("sweep-02", 0, hi)])
        self.assertEqual(sorted(f["specialist"] for f in res.findings), ["contracts", "sweep-02", "sweep-02"])
        self.assertEqual(len(res.comments), 3)
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("## Diff-shard sweep coverage", md)
        self.assertIn("Swept files with a disposition: 6 of 6 (3 with a resolved hypothesis, 3 examined with no issue)",
                      md)
        self.assertIn("`src/app/old.py` (deleted)", md)

    def test_strict_replay_reproduces_a_v4_run_and_load_rederives_it(self):
        from reviewer.pipeline import runner
        m = self.big()
        res, _ = self.record_v4(m, self.e2e_script(m)[0])
        rep = self.replay_v4(m, res)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(rep.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
        self.assertEqual([h["id"] for h in rep.hypotheses], [h["id"] for h in res.hypotheses])
        self.assertEqual(rep.receipt["artifactDigests"]["INVESTIGATE"], res.receipt["artifactDigests"]["INVESTIGATE"])
        self.assertEqual(sweep_events(rep), sweep_events(res))
        loaded = runner.load_result(self.out, res.run_id)
        self.assertEqual(loaded.hypotheses, res.hypotheses)
        with mock.patch.object(sweeps, "is_v4_plan", lambda plan: False):
            with self.assertRaises(PipelineError) as c:
                runner.load_result(self.out, res.run_id)
        self.assertEqual(c.exception.code, "checkpoint-invalid")
        with self.assertRaises(PipelineError) as c:            # a v4 recording does not replay under v3
            self.replay(m, res, profile=V3_PROFILE, plan=V3_PLAN, retrieval=V3_POLICY, eval_id="evr_" + "9" * 16)
        self.assertEqual(c.exception.code, "identity-mismatch")


class Dispositions(DiffShardRig):
    def test_a_file_still_without_a_disposition_is_disclosed_as_uncovered(self):
        m = self.big()
        hu = self.h_util(m)
        scr = script(*self.specialists_part(m),
                     sturn("sweep-01", 0, [disp(p) for p in SHARD1]), sfinal("sweep-01", 1),
                     sfinal("sweep-02", 0, hu),
                     sfinal("sweep-02", 1),                         # the continuation answers without dispositions
                     vfinal(0, m, path="src/app/util.py", line=2), judge(w([shid("sweep-02", 0, hu)])))
        res, spy = self.record_v4(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(sweep_events(res), [("sweep-01", "complete", []),
                                             ("sweep-02", "continue", ["src/app/io.py", "tests/test_core.py"]),
                                             ("sweep-02", "final", ["src/app/io.py", "tests/test_core.py"])])
        self.assertEqual(sum(1 for r in spy.requests if r["role"] == "investigator" and "dispositionCheck" in doc_of(r)),
                         1)                                        # the continuation is sent once
        cov = self.payload(res)["payload"]["sweep"]
        self.assertEqual(cov["summary"], {"swept": 6, "issue": 1, "noIssue": 3, "uncovered": 2})
        self.assertEqual(sorted(f["path"] for f in cov["files"] if f["disposition"] == "uncovered"),
                         ["src/app/io.py", "tests/test_core.py"])
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("`src/app/io.py` (sweep-02): NOT COVERED", md)
        self.assertIn("Uncovered (no disposition after the one continuation): 2", md)

    def test_a_disposition_for_another_shard_or_a_failed_record_does_not_count(self):
        m = self.big()
        scr = script(*self.specialists_part(m),
                     sturn("sweep-01", 0, [disp("docs/guide.md"), disp("src/app/io.py"), disp("src/app/old.py"),
                                           treq("file_disposition", path="src/app/core.py", reason="")]),
                     sfinal("sweep-01", 1), sfinal("sweep-01", 2),
                     sturn("sweep-02", 0, [disp(p) for p in SHARD2]), sfinal("sweep-02", 1), judge())
        res, _ = self.record_v4(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        cov = self.payload(res)["payload"]["sweep"]
        got = {f["path"]: f["disposition"] for f in cov["files"]}
        self.assertEqual(got["docs/guide.md"], "no-issue")
        self.assertEqual((got["src/app/conf.py"], got["src/app/core.py"]), ("uncovered", "uncovered"))
        self.assertEqual(got["src/app/io.py"], "no-issue")          # only sweep-02's own record counts for its file
        statuses = [e["result"]["status"] for e in tool_calls(res, "INVESTIGATE") if e["agentId"] == "sweep-01"]
        self.assertEqual(statuses, ["ok", "ok", "unavailable", "denied"])

    def test_a_failed_continuation_keeps_the_first_answer_and_discloses_the_files(self):
        m = self.big()
        hu = self.h_util(m)
        scr = script(*self.specialists_part(m),
                     sturn("sweep-01", 0, [disp(p) for p in SHARD1]), sfinal("sweep-01", 1),
                     sfinal("sweep-02", 0, hu), *sfail("sweep-02", 1),
                     vfinal(0, m, path="src/app/util.py", line=2), judge(w([shid("sweep-02", 0, hu)])))
        res, _ = self.record_v4(m, scr)
        self.assertNotEqual(res.status, "failed")
        self.assertEqual([(a, d) for a, d, _ in sweep_events(res)],
                         [("sweep-01", "complete"), ("sweep-02", "continue"), ("sweep-02", "draft")])
        ev = [e for e in events_of(res) if e["type"] == "sweep.disposition"][-1]
        self.assertEqual((ev["reason"], ev["errorCode"]), ("call-failed", "provider-error"))
        self.assertEqual([h["specialist"] for h in res.hypotheses], ["sweep-02"])      # the first answer is kept
        self.assertEqual([f["specialist"] for f in res.findings], ["sweep-02"])
        cov = self.payload(res)["payload"]["sweep"]
        self.assertEqual(cov["summary"]["uncovered"], 2)


class Tolerance(DiffShardRig):
    def test_one_failed_sweep_does_not_fail_the_run(self):
        m = self.big()
        hu = self.h_util(m)
        scr = script(*self.specialists_part(m), *sfail("sweep-01", 0),
                     sturn("sweep-02", 0, [disp("src/app/io.py"), disp("tests/test_core.py")]), sfinal("sweep-02", 1, hu),
                     vfinal(0, m, path="src/app/util.py", line=2), judge(w([shid("sweep-02", 0, hu)])))
        res, _ = self.record_v4(m, scr)
        self.assertEqual(res.status, "partial")
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([(a["agentId"], a["status"]) for a in agents][3:], [("sweep-01", "failed"),
                                                                             ("sweep-02", "completed")])
        inc = [i for i in res.incomplete if i["stage"] == "INVESTIGATE"]
        self.assertEqual([(i["reason"], i["detail"].split(":")[0]) for i in inc], [("agent-failure", "specialist sweep-01")])
        cov = self.payload(res)["payload"]["sweep"]
        self.assertEqual({f["path"] for f in cov["files"] if f["disposition"] == "uncovered"}, set(SHARD1))
        self.assertEqual(sweep_events(res)[0][:2], ("sweep-01", "no-answer"))
        self.assertEqual([f["specialist"] for f in res.findings], ["sweep-02"])
        self.assertEqual(validate_trace(events_of(res)), [])

    def test_an_unknown_provider_outcome_starts_no_further_sweep(self):
        m = self.big()
        scr = script(*self.specialists_part(m), *sfail("sweep-01", 0, outcome=None), judge())
        res, _ = self.record_v4(m, scr)
        self.assertNotEqual(res.status, "failed")
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([a["status"] for a in agents[3:]], ["failed", "failed"])
        self.assertIn("not started", agents[4]["error"]["message"])
        self.assertEqual({c["agentId"] for c in sweep_calls(res)}, {"sweep-01"})

    def test_a_systemic_specialist_failure_starts_no_sweep(self):
        m = self.big()
        err = {"code": "model-unresolved", "message": "x", "retryable": False, "stage": "INVESTIGATE"}
        scr = script(ask("contracts", 0), sfinal("contracts", 1),
                     entry("INVESTIGATE", "investigator", "logic", 0, error=err), judge())
        res, _ = self.record_v4(m, scr)
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual([a["agentId"] for a in agents], list(AGENTS) + ["sweep-01", "sweep-02"])
        self.assertEqual(sweep_calls(res), [])
        self.assertTrue(all("not started" in a["error"]["message"] for a in agents[2:]))

    def test_time_slices_stop_a_sweep_and_the_next_one_runs(self):
        m = self.big()
        hu = self.h_util(m)
        plan = copy.deepcopy(V4_PLAN)
        plan["budget"].update(stageCeilingsSec={"INVESTIGATE": 2400, "VERIFY": 3000}, wallClockSec=10_000,
                              softDeadlineSec=9_000, hostStopRecording=HOST_STOP_RECORDING)
        self.assertEqual(sweeps.time_slices(2400, 2), [1800, 2400])
        # 50 s per provider call; the clock jumps 1500 s once the six specialist calls are done, so sweep-01 starts
        # at 1800 s = the end of its slice and is stopped by the gate; sweep-02 (slice ends at the 2400 s ceiling) runs
        self.clock = lambda: (50.0 * (n := self.spies[-1].calls if self.spies else 0)) + (1500.0 if n >= 6 else 0.0)
        scr = script(*self.specialists_part(m),
                     sturn("sweep-02", 0, [disp("src/app/io.py"), disp("tests/test_core.py")]), sfinal("sweep-02", 1, hu),
                     vfinal(0, m, path="src/app/util.py", line=2), judge(w([shid("sweep-02", 0, hu)])))
        res, _ = self.record_v4(m, scr, plan=plan)
        self.assertEqual(res.status, "partial")
        agents = self.payload(res)["payload"]["agents"]
        self.assertEqual(agents[3]["agentId"], "sweep-01")
        self.assertEqual(agents[3]["error"]["code"], "deadline-exceeded")
        self.assertIn("time slice of specialist sweep-01 reached (1800s of the 2400s", agents[3]["error"]["message"])
        self.assertEqual(agents[4]["status"], "completed")
        stops = [e["code"] for e in events_of(res) if e["type"] == "host.stop" and e["stage"] == "INVESTIGATE"]
        self.assertEqual(stops, ["stage-deadline"])
        rep = self.replay_v4(m, res, plan=plan)
        self.assertEqual((rep.status, rep.error), (res.status, None))
        self.assertEqual(rep.receipt["artifactDigests"]["INVESTIGATE"], res.receipt["artifactDigests"]["INVESTIGATE"])

    def test_sweep_budgets_follow_the_cumulative_ceilings(self):
        m = self.big()
        reads = [treq("read_file", side="head", path="src/app/use.py", start_line=k, end_line=k) for k in range(1, 6)]
        with mock.patch.object(sweeps, "SWEEP_TOOL_CALLS", 1):            # shares: 1 + 3 files = 4 per sweep
            scr = script(*self.specialists_part(m),
                         sturn("sweep-01", 0, reads[:2]), sturn("sweep-01", 1, [disp(p) for p in SHARD1]),
                         sfinal("sweep-01", 2), sfinal("sweep-01", 3),
                         sturn("sweep-02", 0, [disp(p) for p in SHARD2]), sfinal("sweep-02", 1), judge())
            res, spy = self.record_v4(m, scr)
        got = [(e["agentId"], e["tool"], e["result"]["status"]) for e in tool_calls(res, "INVESTIGATE")
               if e["agentId"].startswith("sweep-")]
        # sweep-01: 2 reads + 2 records fit its 4, the third record is refused (unavailable), so core.py is uncovered
        self.assertEqual([s for a, _, s in got if a == "sweep-01"], ["ok", "ok", "ok", "ok", "unavailable"])
        # sweep-02's ceiling is cumulative (base + 4 + 4): 8 - 5 calls logged by sweep-01 leaves exactly its 3 records
        self.assertEqual([s for a, _, s in got if a == "sweep-02"], ["ok", "ok", "ok"])
        cov = self.payload(res)["payload"]["sweep"]
        self.assertEqual({f["path"]: f["disposition"] for f in cov["files"]}["src/app/core.py"], "uncovered")
        firsts = [doc_of(r)["retrieval"]["toolCallsRemaining"] for r in spy.requests
                  if r["role"] == "investigator" and r["hop"] == 0 and "sweep" in doc_of(r)]
        self.assertEqual(firsts[0], 4)


class VerifyFairness(DiffShardRig):
    def test_round_robin_across_lanes_with_a_scaled_cap_and_renewed_sessions(self):
        m = self.big()
        hc1, hc2 = self.h_core(m), self.h_util(m)
        h1a = hyp(m, "src/app/conf.py", 1, claim="the timeout is too short", category="bug",
                  evidence=[m.cite("src/app/conf.py", 1)])
        h1b = hyp(m, "docs/guide.md", 3, claim="the guide does not mention empty lists", category="bug",
                  evidence=[m.cite("docs/guide.md", 3)])
        h2a = self.h_io(m)

        def vent(agent, k, path, line):
            v = vfinal(k, m, path=path, line=line)
            v["agentId"] = agent
            return v
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc1, hc2), ask("logic", 0), sfinal("logic", 1),
                     ask("safety", 0), sfinal("safety", 1),
                     sturn("sweep-01", 0, [disp("src/app/core.py")]), sfinal("sweep-01", 1, h1a, h1b),
                     sturn("sweep-02", 0, [disp("src/app/util.py"), disp("tests/test_core.py")]),
                     sfinal("sweep-02", 1, h2a),
                     vent("verifier", 0, "src/app/core.py", 3), vent("verifier", 1, "src/app/conf.py", 1),
                     vent("verifier-02", 0, "src/app/io.py", 2), vent("verifier-02", 1, "src/app/util.py", 2),
                     judge())
        with mock.patch.object(sweeps, "MAX_VERIFY_CANDIDATES_V4", 4), \
                mock.patch.object(sweeps, "VERIFY_SESSION_CANDIDATES", 2):
            res, _ = self.record_v4(m, scr)
        self.assertEqual(validate_trace(events_of(res)), [])
        order = [shid("contracts", 0, hc1), shid("sweep-01", 0, h1a), shid("sweep-02", 0, h2a), shid("contracts", 1, hc2)]
        vcalls = model_calls(res, "VERIFY")
        self.assertEqual([e["request"]["hypothesisId"] for e in vcalls], order)
        self.assertEqual([e["agentId"] for e in vcalls], ["verifier", "verifier", "verifier-02", "verifier-02"])
        self.assertEqual({e["agentId"] for e in tool_calls(res, "VERIFY")}, {"verifier", "verifier-02"})
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        drops = [d for d in vpay["drops"] if d["reason"] == "over-cap"]
        self.assertEqual([d["subjectIds"] for d in drops], [[shid("sweep-01", 1, h1b)]])
        self.assertIn("round-robin across specialist and sweep lanes", drops[0]["detail"])
        self.assertEqual(len(res.findings), 4)
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("over-cap", md)                                 # the truncation is disclosed


# ---------------------------------------------------------------- byte identity and identity binding

class Identity(DiffShardRig):
    def pin_of(self, res):
        a = res.receipt["artifactDigests"]
        return {"cfg": res.run["configSnapshotId"], "trace": res.receipt["traceDigest"], "INVESTIGATE": a["INVESTIGATE"],
                "VERIFY": a["VERIFY"], "PUBLISH": a["PUBLISH"], "requests": [e["requestHash"] for e in model_calls(res)]}

    def test_v3_runs_are_byte_identical_to_the_pre_change_recordings(self):
        m = self.case()
        res, _ = self.record_v3(m, self.three_script(m)[0], eval_id="evr_" + "6" * 16)
        self.assertEqual(self.pin_of(res), V3_SMALL_PIN)
        big = self.big()
        res, _ = self.record_v3(big, self.big_v3_script(big), eval_id="evr_" + "7" * 16)
        self.assertEqual(self.pin_of(res), V3_BIG_PIN)                  # 6 reviewable files and still no sweep
        self.assertFalse(any(e["type"] in ("sweep.disposition", "investigate.coverage") for e in events_of(res)))
        self.assertNotIn("sweep", self.payload(res)["payload"])

    def test_a_tiny_v4_diff_behaves_exactly_as_v3_except_version_tags(self):
        m = self.case()                                             # one changed file: no shards
        v3, spy3 = self.record_v3(m, self.three_script(m)[0], eval_id="evr_" + "a" * 16)
        v4, spy4 = self.record_v4(m, self.three_script(m)[0], eval_id="evr_" + "b" * 16)
        self.assertEqual((v4.status, v3.status), ("completed", "completed"))

        def strip(r):
            r = copy.deepcopy(r)
            r.pop("promptVersion", None)
            return r
        self.assertEqual([strip(r) for r in spy4.requests], [strip(r) for r in spy3.requests])
        self.assertEqual({r["promptVersion"] for r in spy4.requests if r["role"] == "investigator"}, {INV4})
        self.assertEqual([h["id"] for h in v4.hypotheses], [h["id"] for h in v3.hypotheses])
        self.assertEqual([f["id"] for f in v4.findings], [f["id"] for f in v3.findings])
        p3, p4 = self.payload(v3)["payload"], self.payload(v4)["payload"]
        cov = p4.pop("sweep")
        same_run = lambda p, r: json.loads(json.dumps(p).replace(r.run_id, "RUN"))     # noqa: E731
        self.assertEqual(same_run(p4, v4), same_run(p3, v3))
        self.assertEqual((cov["shards"], cov["files"], cov["note"]), ([], [], sweeps.NOTE_TINY))
        ev3 = [(e["type"], e.get("toolCallId")) for e in events_of(v3) if e["type"] == "tool.call"]
        ev4 = [(e["type"], e.get("toolCallId")) for e in events_of(v4) if e["type"] == "tool.call"]
        self.assertEqual(ev4, ev3)
        self.assertNotEqual(v4.run["configSnapshotId"], v3.run["configSnapshotId"])

    def test_sweep_rules_and_texts_are_bound_into_the_v4_identity_only(self):
        m = self.big()
        backend, _ = self.record_backend(script())
        spec = self.spec(m, backend, profile=V4_PROFILE, plan=V4_PLAN, retrieval=V4_POLICY)
        v3spec = self.spec(m, backend, profile=V3_PROFILE, plan=V3_PLAN, retrieval=V3_POLICY)
        base, v3base = identity.config_snapshot_id(spec), identity.config_snapshot_id(v3spec)
        for mod, name, value in ((sweeps, "MAX_SHARDS", 5), (sweeps, "MAX_FILES_PER_SHARD", 4),
                                 (sweeps, "SHARD_DIFF_CHARS", 1), (sweeps, "SWEEP_TOOL_CALLS", 3),
                                 (sweeps, "CONTINUATION_HOPS", 2), (sweeps, "MAX_VERIFY_CANDIDATES_V4", 30),
                                 (sweeps, "VERIFY_SESSION_CANDIDATES", 5), (sweeps, "RULE_TEXT", "x")):
            orig = getattr(mod, name)
            try:
                setattr(mod, name, value)
                self.assertNotEqual(identity.config_snapshot_id(spec), base, name)
                self.assertEqual(identity.config_snapshot_id(v3spec), v3base, name)
            finally:
                setattr(mod, name, orig)
        for key in ("sweep", "sweepContinuation"):
            old = prompts.IMPACT_V4_TEMPLATES[key]
            try:
                prompts.IMPACT_V4_TEMPLATES[key] = old + " "
                self.assertNotEqual(identity.config_snapshot_id(spec), base, key)
                self.assertEqual(identity.config_snapshot_id(v3spec), v3base, key)
            finally:
                prompts.IMPACT_V4_TEMPLATES[key] = old
        self.assertEqual(identity.config_snapshot_id(spec), base)
        self.assertEqual(identity.plan_specialists(spec), ["contracts", "logic", "safety", "diff-sweep"])

    def test_plan_must_name_the_specialists_and_the_sweep_marker(self):
        m = self.big()
        with self.assertRaises(PipelineError) as c:
            self.record_v4(m, script(), plan=V3_PLAN)
        self.assertEqual(c.exception.code, "invalid-input")
        self.assertIn("diff-shard sweep marker", str(c.exception))
        with self.assertRaises(PipelineError):
            self.record_v3(m, script(), plan=V4_PLAN)

    def test_investigate_payload_and_trace_contracts(self):
        cov = sweeps.coverage(2, [{"agentId": "sweep-01", "paths": ["a.py"], "diffChars": 3}], [],
                              [{"path": "a.py", "agentId": "sweep-01", "disposition": "uncovered", "hypotheses": 0}])
        self.assertEqual(validate("SweepCoverage", cov), [])
        base = {"stage": "INVESTIGATE", "hypotheses": [], "agents": [], "merges": []}
        self.assertEqual(validate("StagePayload", dict(base, sweep=cov)), [])
        for bad in (dict(cov, version="x@1"), dict(cov, files=[dict(cov["files"][0], disposition="maybe")]),
                    dict(cov, excluded=[{"path": "a.py", "reason": "boring"}])):
            self.assertNotEqual(validate("StagePayload", dict(base, sweep=bad)), [])


class Pilot(unittest.TestCase):
    """repository_profile / plan / policy: v4 is opt-in, every v1-v3 selection keeps its pinned bytes."""

    def test_v1_to_v3_selections_keep_their_bytes_and_v4_is_new(self):
        from reviewer.pilot.repository_profile import (DEFAULT_IMPACT_VERSION, IMPACT_VERSIONS, V4_MAX_TOOL_CALLS,
                                                       repository_plan, repository_policy, repository_profile)
        self.assertEqual(DEFAULT_IMPACT_VERSION, 2)
        self.assertEqual(IMPACT_VERSIONS[4], INV4)
        got = {}
        for v in (1, 2, 3, 4):
            p = repository_profile(True, impact_version=v)
            got[v] = (digest(p), digest(repository_plan(p)), digest(repository_plan(p, live_stage_timing=True)),
                      repository_policy(True, impact_version=v).digest)
        for v, want in REPO_DIGESTS.items():
            self.assertEqual(got[v], want, v)
        old = {g for v in (1, 2, 3) for g in got[v]}
        self.assertFalse(old & set(got[4]))                                  # v4 shares no digest with v1-v3
        p4 = repository_profile(True, impact_version=4)
        legacy, live = repository_plan(p4), repository_plan(p4, live_stage_timing=True)
        for plan in (legacy, live):
            self.assertEqual(validate("Plan", plan), [])
            self.assertEqual(plan["specialists"], ["contracts", "logic", "safety", "diff-sweep"])
            self.assertEqual(plan["budget"]["maxToolCalls"], V4_MAX_TOOL_CALLS)
            self.assertEqual((plan["budget"]["maxUsdMicros"], plan["budget"]["verifyReserveBp"]), (4_000_000, 3000))
        self.assertEqual(legacy["budget"]["stageCeilingsSec"], {"INVESTIGATE": 240})
        self.assertEqual(live["budget"]["stageCeilingsSec"], {"INVESTIGATE": 600, "VERIFY": 450, "JUDGE": 200})
        self.assertEqual((live["budget"]["wallClockSec"], live["budget"]["softDeadlineSec"]), (1500, 1200))
        self.assertEqual(repository_policy(True, impact_version=4).run_tool_calls, V4_MAX_TOOL_CALLS)
        self.assertTrue(repository_policy(True, impact_version=4).diff_sweep)
        self.assertFalse(any(repository_policy(True, impact_version=v).diff_sweep for v in (1, 2, 3)))


# pre-change (af00d48f) digests: (profile, plan, plan with live stage timing, policy) for impact v1-v3
REPO_DIGESTS = {
    1: ("sha256:3e62ef3208e068fafde841cb7d220094f15ed0e08a11bf185097b8299f16bdf7",
        "sha256:18bedae1e19e8460affb22388cb88188b8ec2b1ace72c9d2238be84774f4b306",
        "sha256:e50f514549e522e70f4d58064524a6f01924032662db33930b827deec26e561b",
        "sha256:c849a611a21899ac9c64ac149ce2b0b4edb36ebcf544111987cebd91c639e559"),
    2: ("sha256:216a6748aef63f2aeb9a53ec28b14d7e8575713f596a8f909cf94a7b51f1c9a6",
        "sha256:18bedae1e19e8460affb22388cb88188b8ec2b1ace72c9d2238be84774f4b306",
        "sha256:e50f514549e522e70f4d58064524a6f01924032662db33930b827deec26e561b",
        "sha256:d80e2c255d0a6247abe4d739a72566066155069d846e4b707ddb0d34694913f9"),
    3: ("sha256:0959087c4958b516e6fb984d611b9535ec46d6325047e54290586d41ec98367a",
        "sha256:9244e9a26da37d0b807fff9731d4499e843123b3d558b70a89aa5e246bf433d8",
        "sha256:0ec7f78996de044b19cf8ed6a4bb69d17082f0211d5d293a472ad17f43673571",
        "sha256:5913eba11ee09a1ecf782dff5b8efb75d8d9d3ea9879f931802b9e27d779392f"),
}


if __name__ == "__main__":
    unittest.main()
