"""TOURNAMENT-V12: investigator.impact@v12 = coverage-forced deep investigation on the primary investigator model: the
three v3 lenses (v3 lens texts + a depth paragraph), then one coverage investigator per unit of a deterministic
changed-file partition, a host-enforced depth floor, per-candidate verifier sessions and a dynamic comment cap.

Invented self-contained fixtures, a scripted synthetic provider, the real engine, contracts, gateway and tools. No
network, key, state or live call. These tests prove the mechanics (coverage invariant, exploration floor and its
continuations, budget split, VERIFY session isolation, dynamic cap, identity binding, strict replay and load, v3 parity);
they do NOT show that a real model finds more real defects: that needs an admitted run."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from reviewer.config import resolve_config
from reviewer.contracts import validate
from reviewer.contracts.budget import investigation_limit
from reviewer.contracts.canonical import digest, hypothesis_id
from reviewer.contracts.entities import validate_trace
from reviewer.pipeline import PipelineError, RetrievalPolicy, deepcov, identity, prompts, specialists, sweeps
from reviewer.pipeline import load_result

from tests.pipeline.helpers import entry, events_of, hyp, judge, model_calls, resp, script, tool_calls, treq
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_specialists import V3_PLAN, V3_PROFILE, SpecRig

ROOT = Path(__file__).resolve().parents[2]
INV12, VER = prompts.INVESTIGATOR_IMPACT_V12_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
LENS = ("contracts", "logic", "safety")

V12_PROFILE = copy.deepcopy(V3_PROFILE)
V12_PROFILE["roles"]["investigator"]["promptVersion"] = INV12
V12_POLICY = RetrievalPolicy(investigator_prompt=INV12, verifier_prompt=VER, run_tool_calls=400)
V12_PLAN = copy.deepcopy(V3_PLAN)
V12_PLAN["specialists"] = deepcov.plan_specialists()
V12_PLAN["budget"].update(maxToolCalls=400, stageCeilingsSec={"INVESTIGATE": 280})   # as repository_plan builds it

HANDLER = ("def handle_{n}(req, user):\n    if not user.active:\n        return None\n    if req.size > LIMIT:\n"
           "        return None\n    return process(req)\n")
CORE_BASE = {
    "src/lib.py": "def load_user(uid, cache=True):\n    return {'id': uid}\n",
    "src/use.py": ("from src.lib import load_user\n\n\nclass Profile:\n    def show(self, uid):\n"
                   "        user = load_user(uid)\n        return user['id']\n"),
    "src/svc.py": "def total(items):\n    t = 0\n    for i in items:\n        t += i\n    return t\n",
    "src/handlers/a.py": HANDLER.format(n="a"),
    "src/handlers/b.py": HANDLER.format(n="b"),
    "src/handlers/c.py": HANDLER.format(n="c"),
    "src/ws.py": "def ws():\n    return 1\n",
    "src/old.py": "OLD = 1\n",
    "docs/notes.md": "notes\n",
    "tests/test_lib.py": "def test_x():\n    assert True\n",
    "package-lock.json": "{}\n",
    "web/locales/en/common.json": "{\"a\": \"b\"}\n",
}
CORE_HEAD = dict(CORE_BASE)
CORE_HEAD.pop("src/old.py")
CORE_HEAD.update({
    "src/lib.py": "def load_user(uid, cache, region):\n    return {'id': uid}\n",
    "src/svc.py": "def total(items):\n    t = 1\n    for i in items:\n        t += i\n    return t\n",
    "src/handlers/a.py": HANDLER.format(n="a").replace("LIMIT", "MAX_LIMIT"),
    "src/handlers/b.py": "def handle_b(req, user):\n    return process(req)\n",
    "src/handlers/c.py": HANDLER.format(n="c").replace("return process(req)", "return process(req, user)"),
    "src/ws.py": "def ws():\n        return 1\n",
    "docs/notes.md": "notes updated\n",
    "tests/test_lib.py": "def test_x():\n    assert 1 == 1\n",
    "package-lock.json": "{\"v\": 2}\n",
    "web/locales/en/common.json": "{\"a\": \"c\"}\n",
})
# Recorded from the PRE-CHANGE source (6218ac4, the gated v10 head) by running the same fixtures there:
# SpecRig.three_script (impact@v3) and V10Rig.e2e (impact@v10) recordings (config id, trace, artifact digests, every
# request hash), and digest([profile, Plan, live Plan, policy, impact templates]) of repository_profile(impact_version=v)
# under pullo-terra.toml for v = 1, 2, 3, 4, 5, 7, 10.
# repo_v1..repo_v10 re-pinned for the DEADLINE time successor (2026-11-02, as v6cd + cand12cd): only the Plan run
# deadlines (3000/2400) and the default live stage ceilings (900/600/400) differ; profiles, policies, templates unchanged.
PRE_V12_PINS = json.loads('{"repo_v1": "sha256:88d742d1781a37feaa2de79cd6ec4dfe92d9eb0b7e47e45fc7b6567f86032cae", "repo_v10": "sha256:75ecce07e87c2799962c63bac381f0c6a0cc38fb7e6c27d76e74d4545c9baac2", "repo_v2": "sha256:19d2ffff953bb6365065e3c57d5874d380db00cfac1ecbcda59d75449f1ee1c1", "repo_v3": "sha256:603662826ff9fe63777b006db8ba1eecaa2437ce3e3fe7b2b9e0140d1e0609f8", "repo_v4": "sha256:c42e3b3b0343358c1f3319f2e2d120dd388d21f3c504fdf49376282e529e1266", "repo_v5": "sha256:99da1c95192909e4a00a1a67c169797e9d9ce1a6f259a5a9d7bdc27a523ad772", "repo_v7": "sha256:89f9b0db8a37cefcaaab67debc0d7584fdd46fbb98ca693ea9ebaa6e14efcec6", "v10_e2e": {"INVESTIGATE": "sha256:02e2ecfc9fd0de79b0d20513ccce2c8aaa517f74b4c61e1a338cd357f1d48470", "PUBLISH": "sha256:e7a5fc36a7ec6a5696a4e5c301657da1f766b9cc99d5b020db7f73ed6071a7f9", "VERIFY": "sha256:e31572fcc9bf601485d58c0ea23802ae6145684fa1a8e2427a5f3f38bf0461bb", "cfg": "sha256:8b556222ccb86cb3c14ef5e9d5d167650bf1b0af5608cbfa0129b2755740bcc8", "requests": ["sha256:1803235218a19f77ce7341534edf342d53da58c0ec3e275b958211a4a9d33e20", "sha256:4b0067c8870491575c88d19a7bda30a755e1eeed6adf6e901a89dc945cba8b70", "sha256:2faa4bcf86a11f92f0016fde8ed2a5bb3fe972ccfb26334f3fdbdcddb71e8509", "sha256:d0d834befb7347cde90958415bfebd99fea62cd85c5449ecc628f6a3f81243bc", "sha256:66a75f28d09f670ff7dcfd2981eba1d38bcb98dd23d3886babbc00728fa50f48", "sha256:00a13e5954b7e0b5a029ca6cd0720fa2bdac47ee8bf99fe658d1efa8ee4a03ff", "sha256:749d743bbf6980b10f149fb858cb7309002b4834e5f054b1f09f02a784931c14", "sha256:65a93955aeed7e7549149869a1a823816d96ded98d74afd4126c048c8168b3a3", "sha256:af024adaf21e416ebfe3b59d1f878870f15d555df300d3f696ce91d6430e8319", "sha256:9bdf09f33056361bde58f386f6e31ce7678f024c329d55765e1846e047533b88", "sha256:ff86947dda34071f9d130837c6fc2a5b5d8f0cf42a128cb6784e954458187492", "sha256:c5cdf828d276b08530171e34a2369443039e6891a0800d1835ee0005d7be356c", "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24", "sha256:b89b100e688337937dd8a8378ae4894fefe042c81fcced6b0a51ebe91e89a357", "sha256:4bcac6ad7b5d1cd50a69f5bd33337fa41b586ce03e92043e789c356bfafb0ff7", "sha256:cd4a8dc5c3cdf7c5d22c153510eb085c9f0f01cfce6e0f4185550c7bc1ade73e", "sha256:89dc8c652778d4a43350552d1ff6d3461b067c2e1be1e811ad11aebd9aa75ef3"], "trace": "sha256:f3ca00fa838b500b0100d62046c92a040a70456a7a9392e32e02347b02c751ff"}, "v3_e2e": {"INVESTIGATE": "sha256:e44eca59265b7ac03e97a6b0cf5f114c305d8920a2bdfaeb68e30f94d98b30f0", "PUBLISH": "sha256:07c34c158f9a733eff44470a202e20fe19dddb57b3ee391593dbbe5cbcc5b470", "VERIFY": "sha256:e2c66caba2986cf760b5ac52ee2f2264324048d77dcd7622f4964b4bf8abe180", "cfg": "sha256:96ff7073024599f3fcc621397590d16c93314081aa597e0e67521256f1baed2b", "requests": ["sha256:c86937b5b36a46b70d9ede67ef17faf86f9e653421344867ea85fa77bcc50fb5", "sha256:3c2c629ae05437701444471cde6aece420fc943b252f29fc7b14f638a404580e", "sha256:09ee726c74ea9bbd85ffac9dcfed0641914ea66e34c4af15178d8c4c8473da92", "sha256:da0cb1c8e76fccd1eb6fa885dbcd6c17ff494329d9f6f639b870d97137557c11", "sha256:05bd7b22ba77f5ba162e212bc184e9b0674cb7f37f65bd805bfec1c74649c14d", "sha256:c28618a1a7ffc297d389cc7bf850aab52722e09c533f0de83df4e9cae9234b28", "sha256:8ad1f0c65134754c71c69fa1d0bc598a7fb329c6c698f3820b6c6402e3080440", "sha256:3c7948f5f213e4c23c8ef5e614f3512e1097d68a975aee0c053338e64297f8c6", "sha256:4439dc8da87e024380f3394dac4865254b899b631042ad1843e51789c43952f6", "sha256:08d029d2693d44b1517c2c4c36607c7d25b66a43818e25637e9151b0f553d3ae"], "trace": "sha256:fd3d80ac1023733918058d3ad6e7bcc9ef808badb2f3a8c5db90392d558bb99d"}}')

ELIGIBLE = ["src/handlers/a.py", "src/handlers/b.py", "src/handlers/c.py", "src/lib.py", "src/svc.py"]
SKIPPED = {"docs/notes.md": "docs", "package-lock.json": "generated", "src/old.py": "deleted",
           "src/ws.py": "no-code-change", "tests/test_lib.py": "tests", "web/locales/en/common.json": "localisation"}


def turn(agent, ordinal, requests=None, output=None):
    return entry("INVESTIGATE", "investigator", agent, ordinal, response=resp({"contextRequests": requests or [],
                                                                              "output": output}))


def final(agent, ordinal, *hyps):
    return turn(agent, ordinal, output={"hypotheses": list(hyps)})


def vdone(agent, m, *, path, line, verdict="confirmed"):
    out = {"verdict": verdict, "reachable": True, "impact": "incorrect-result",
           "evidence": [m.cite(path, line)] if verdict == "confirmed" else [], "notes": "checked"}
    return entry("VERIFY", "verifier", agent, 0, response=resp({"contextRequests": [], "output": out}))


def rf(path, a=1, b=None):
    return treq("read_file", side="head", path=path, start_line=a, end_line=b or a + 3)


def lens_reads(k=0):
    """Six distinct reads a lens lane makes in one turn (meets the lens floor)."""
    return [rf(p, 1 + k) for p in ("src/lib.py", "src/use.py", "src/svc.py", "src/handlers/a.py",
                                   "src/handlers/b.py", "src/handlers/c.py")]


def hid(agent, n, h):
    return hypothesis_id(agent, n, h["claim"], h["location"]["path"], h["location"]["line"])


def unit_turns(agent, files, ctx_paths):
    """Two request turns that meet a unit's floor: read every own file, then context beyond them."""
    first = [rf(p) for p in files] + [rf(p, 2) for p in ctx_paths[:6 - len(files)]]
    rest = [rf(p, 3) for p in ctx_paths] + [treq("find_references", side="head", symbol="load_user"),
                                            treq("search_literal", side="head", query="process(")]
    need = max(deepcov.UNIT_FLOOR_READS, 2 * len(files)) - len(first)
    return [turn(agent, 0, first), turn(agent, 1, rest[:max(need, 1) + 1][:6])]


class V12Rig(SpecRig):
    def case12(self):
        return self.mini("mini-v12", base=CORE_BASE, head=CORE_HEAD)

    def record_v12(self, m, scr, **kw):
        kw.setdefault("profile", V12_PROFILE)
        kw.setdefault("retrieval", V12_POLICY)
        kw.setdefault("plan", V12_PLAN)
        return self.record_turn(m, scr, **kw)

    def replay_v12(self, m, res, **kw):
        kw.setdefault("profile", V12_PROFILE)
        kw.setdefault("retrieval", V12_POLICY)
        kw.setdefault("plan", V12_PLAN)
        return self.replay(m, res, **kw)

    def h_lib(self, m):
        return hyp(m, "src/lib.py", 1, claim="load_user lost the cache default; Profile.show passes one argument",
                   category="breaking-change", impact="crash", evidence=[m.cite("src/lib.py", 1), m.cite("src/use.py", 6)])

    def h_b(self, m):
        return hyp(m, "src/handlers/b.py", 2, claim="handle_b dropped the active-user and size guards its siblings keep",
                   category="security", impact="security-exposure", severity="P1",
                   evidence=[m.cite("src/handlers/b.py", 2), m.cite("src/handlers/a.py", 2)])

    def h_svc(self, m):
        return hyp(m, "src/svc.py", 2, claim="total starts at 1, so an empty list sums to 1", category="bug",
                   impact="incorrect-result", severity="P2", evidence=[m.cite("src/svc.py", 2)])

    def e2e(self, m):
        """Lens lanes: one turn of six reads, then an answer (floor met). Units cover-01 (handlers a, b) and cover-02
        (handlers c, lib, svc): two request turns each, then an answer. VERIFY: one session per candidate."""
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = []
        for a, hs_ in (("contracts", [hl]), ("logic", []), ("safety", [])):
            e += [turn(a, 0, lens_reads()), final(a, 1, *hs_)]
        e += unit_turns("cover-01", ["src/handlers/a.py", "src/handlers/b.py"], ["src/handlers/c.py", "src/use.py"])
        e += [final("cover-01", 2, hb)]
        e += unit_turns("cover-02", ["src/handlers/c.py", "src/lib.py", "src/svc.py"], ["src/use.py", "src/handlers/a.py"])
        e += [final("cover-02", 2, hs)]
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), vdone("verifier-02", m, path="src/handlers/b.py", line=2),
              vdone("verifier-03", m, path="src/svc.py", line=2),
              judge(w([hid("contracts", 0, hl)]), w([hid("cover-01", 0, hb)]), w([hid("cover-02", 0, hs)]))]
        return script(*e), (hl, hb, hs)


def inv_calls(res, agent=None):
    return [e for e in model_calls(res, "INVESTIGATE") if agent is None or e["agentId"] == agent]


def payload(res, stage):
    return json.loads((Path(res.run_dir) / res.stages[stage]["path"]).read_text())["payload"]


def md_of(res):
    return (Path(res.run_dir) / "review.md").read_text()


def fake_diff(path, rows):
    """A logged PREPARE per-file diff event, as the plan reads it (status ok, one excerpt)."""
    text = "\n".join([f"# diff {path}", f"--- base/{path}", f"+++ head/{path}"] + rows)
    return {"result": {"status": "ok", "evidence": [{"excerpt": text}]}}


def change(n=1, start=1):
    return [f"@@ -{start},{n} +{start},{n} @@"] + [f"-old{i}" for i in range(n)] + [f"+new{i}" for i in range(n)]


KEYCLOAK_LIKE = (  # path shapes of a 28-file change (no repository content): 26 eligible + 2 tests
    ["server-spi-private/src/main/java/org/x/models/Constants.java",
     "server-spi-private/src/main/java/org/x/grants/OAuth2GrantType.java",
     "server-spi-private/src/main/java/org/x/grants/OAuth2GrantTypeFactory.java",
     "services/src/main/java/org/x/oidc/TokenManager.java"]
    + [f"services/src/main/java/org/x/oidc/encode/{n}.java" for n in ("AccessTokenContext", "DefaultEncoder",
                                                                         "DefaultEncoderFactory", "Encoder",
                                                                         "EncoderFactory", "EncoderSpi")]
    + [f"services/src/main/java/org/x/oidc/grants/{n}GrantTypeFactory.java" for n in
       ("AuthorizationCode", "ClientCredentials", "Permission", "PreAuthorizedCode", "RefreshToken",
        "ResourceOwnerPasswordCredentials", "TokenExchange")]
    + ["services/src/main/java/org/x/oidc/grants/OAuth2GrantTypeBase.java",
       "services/src/main/java/org/x/oidc/grants/PreAuthorizedCodeGrantType.java",
       "services/src/main/java/org/x/oidc/grants/ResourceOwnerPasswordCredentialsGrantType.java",
       "services/src/main/java/org/x/oidc/grants/ciba/CibaGrantTypeFactory.java",
       "services/src/main/java/org/x/oidc/grants/device/DeviceGrantTypeFactory.java",
       "services/src/main/java/org/x/oidc/mappers/AbstractMapper.java",
       "services/src/main/java/org/x/oidc/exchange/StandardExchangeProvider.java",
       "services/src/main/resources/META-INF/services/org.x.EncoderFactory",
       "services/src/main/resources/META-INF/services/org.x.Spi",
       "services/src/test/java/org/x/oidc/encode/DefaultEncoderTest.java",
       "testsuite/integration/tests/base/src/test/java/org/x/AssertEvents.java"])


# ---------------------------------------------------------------- 1. coverage invariant (partition)

class Partition(unittest.TestCase):
    def check_invariant(self, files, plan_doc):
        changed = [f["path"] for f in files]
        in_units = [p["path"] for u in plan_doc["units"] for p in u["files"]]
        skipped = [s["path"] for s in plan_doc["skipped"]]
        self.assertEqual(sorted(in_units + skipped), sorted(changed))          # every changed file, exactly once
        self.assertEqual(len(set(in_units + skipped)), len(changed))
        self.assertTrue(all(s["reason"] in deepcov.SKIP_REASONS for s in plan_doc["skipped"]))
        self.assertEqual(plan_doc["eligible"], len(in_units))
        self.assertLessEqual(len(plan_doc["units"]), deepcov.MAX_UNITS)
        self.assertTrue(all(u["files"] for u in plan_doc["units"]))
        self.assertEqual(in_units, sorted(in_units))                           # consecutive, path order
        self.assertEqual([u["agentId"] for u in plan_doc["units"]],
                         [f"cover-{j + 1:02d}" for j in range(len(plan_doc["units"]))])

    def test_every_eligible_file_is_in_one_unit_and_every_other_has_a_skip_reason(self):
        files = [{"path": p, "status": "deleted" if p == "src/old.py" else "modified"} for p in
                 ELIGIBLE + list(SKIPPED)]
        diffs = {p: fake_diff(p, change()) for p in ELIGIBLE + ["docs/notes.md", "tests/test_lib.py",
                                                                  "package-lock.json", "web/locales/en/common.json"]}
        diffs["src/ws.py"] = fake_diff("src/ws.py", ["@@ -2 +2 @@", "-    return 1", "+        return 1"])
        plan_doc = deepcov.plan(files, diffs)
        self.check_invariant(files, plan_doc)
        self.assertEqual({s["path"]: s["reason"] for s in plan_doc["skipped"]}, SKIPPED)
        self.assertEqual([[f["path"] for f in u["files"]] for u in plan_doc["units"]],
                         [ELIGIBLE[:2], ELIGIBLE[2:]])

    def test_a_28_file_change_gives_four_units_covering_all_26_eligible_files(self):
        files = [{"path": p, "status": "added"} for p in KEYCLOAK_LIKE]
        diffs = {p: fake_diff(p, change(5 + (i % 7) * 20)) for i, p in enumerate(KEYCLOAK_LIKE)}
        plan_doc = deepcov.plan(files, diffs)
        self.check_invariant(files, plan_doc)
        self.assertEqual(len(KEYCLOAK_LIKE), 28)
        self.assertEqual((plan_doc["eligible"], len(plan_doc["units"])), (26, 4))
        self.assertEqual(sorted(s["reason"] for s in plan_doc["skipped"]), ["tests", "tests"])
        sizes = [len(u["files"]) for u in plan_doc["units"]]
        self.assertEqual(sum(sizes), 26)
        self.assertLessEqual(max(sizes) - min(sizes), 6)                       # balanced by weight

    def test_tests_are_investigated_when_the_change_has_nothing_else(self):
        files = [{"path": "tests/test_a.py", "status": "modified"}, {"path": "src/x.test.ts", "status": "added"}]
        plan_doc = deepcov.plan(files, {f["path"]: fake_diff(f["path"], change()) for f in files})
        self.check_invariant(files, plan_doc)
        self.assertEqual(plan_doc["eligible"], 2)

    def test_skip_rules(self):
        self.assertTrue(all(deepcov.is_test(p) for p in (
            "tests/sentry/x.py", "src/test/java/A.java", "a/test_b.py", "a/b_test.go", "A/BTest.java", "x.spec.ts",
            "x.test.tsx", "a/b_spec.rb", "lib/conftest.py", "repo.mock.ts")))
        self.assertFalse(any(deepcov.is_test(p) for p in ("src/latest.py", "src/contest/x.py", "src/attest.go")))
        files = [{"path": p, "status": "modified"} for p in ("README.md", "CHANGELOG", "i18n/de.json",
                                                              "res/messages_de.properties", "go.sum", "a.min.js")]
        plan_doc = deepcov.plan(files, {f["path"]: fake_diff(f["path"], change()) for f in files})
        self.assertEqual([s["reason"] for s in plan_doc["skipped"]],
                         ["docs", "docs", "generated", "generated", "localisation", "localisation"])
        self.assertEqual(plan_doc["units"], [])

    def test_changed_ranges_and_code_change(self):
        rows = ["@@ -1,3 +1,4 @@", " a", "+b", " c", " d", "@@ -20 +21,2 @@", "-x", "+y", "+z", "@@ -40,2 +42,0 @@",
                "-gone", "-gone2"]
        self.assertEqual(deepcov.changed_ranges(rows), [[1, 4], [21, 22], [42, 42]])
        self.assertFalse(deepcov.code_changed(["@@ -1 +1 @@", "-  x = 1", "+    x = 1"]))
        self.assertFalse(deepcov.code_changed(["@@ -1 +1,2 @@", "+", "+   "]))
        self.assertTrue(deepcov.code_changed(["@@ -1 +1 @@", "-x = 1", "+x = 2"]))

    def test_random_changes_keep_the_invariant(self):
        import random
        rnd = random.Random(12)
        names = ["src/a/b.py", "src/a/c.py", "docs/x.md", "tests/t.py", "go.sum", "web/locales/en/x.json", "lib/k.go",
                 "lib/k_test.go", "pkg/m/n.ts", "pkg/m/n.spec.ts", "README.rst", "app/models/u.rb", "app/c.rb"]
        for _ in range(200):
            pick = rnd.sample(names, rnd.randint(1, len(names)))
            extra = [f"gen/f{i}.py" for i in range(rnd.randint(0, 40))]
            files = [{"path": p, "status": rnd.choice(["modified", "added", "deleted"])} for p in pick + extra]
            diffs = {f["path"]: fake_diff(f["path"], change(rnd.randint(1, 400))) for f in files if rnd.random() < .95}
            self.check_invariant(files, deepcov.plan(files, diffs))


# ---------------------------------------------------------------- 2. budget split, time, tool shares

class Budget(unittest.TestCase):
    B = dict(V12_PLAN["budget"])

    def test_spend_split_keeps_verify_and_judge_above_the_v3_floor(self):
        b = self.B
        self.assertEqual(b["maxUsdMicros"], 4_000_000)
        self.assertEqual(deepcov.spend_top(b), 2_600_000)
        self.assertEqual(deepcov.lens_top(b), 1_200_000)
        self.assertEqual([deepcov.agent_ceiling(False, i, s, b, 3) for i, s in ((0, 0), (1, 550_000), (2, 1_000_000))],
                         [400_000, 875_000, 1_200_000])                # fair share of what is left; overshoot spreads
        self.assertEqual(deepcov.agent_ceiling(False, 2, 1_300_000, b, 3), 1_300_001)   # a lens lane always answers
        v3_floor = b["maxUsdMicros"] - investigation_limit(b)                    # v3 keeps 30% for VERIFY + JUDGE
        self.assertEqual(v3_floor, 1_200_000)
        self.assertGreaterEqual(b["maxUsdMicros"] - deepcov.spend_top(b), v3_floor)
        self.assertEqual([deepcov.agent_ceiling(True, j, s, b, 4) for j, s in
                          ((0, 1_000_000), (1, 1_550_000), (2, 1_900_000), (3, 2_300_000))],
                         [1_400_000, 1_900_000, 2_250_000, 2_600_000])
        self.assertEqual(deepcov.agent_ceiling(True, 1, 2_700_000, b, 2), 2_700_000)   # no room left: not run
        self.assertLess(sweeps.judge_reserve_floor(b), b["maxUsdMicros"])

    def test_final_answer_turn_before_the_share_is_used(self):
        self.assertFalse(deepcov.final_answer_due(600, 1_000, 400))
        self.assertTrue(deepcov.final_answer_due(601, 1_000, 400))
        # Terra-scale: a $0.40 lens share explores twice at ~$0.15-0.17 per hop, then answers
        spent, hops = 0, 0
        for r in (150_000, 160_000, 170_000, 180_000):
            if deepcov.final_answer_due(spent, 400_000, r):
                break
            spent, hops = spent + r, hops + 1
        self.assertEqual(hops, 2)

    def test_tool_shares_and_time_slices(self):
        self.assertEqual(deepcov.lens_tool_cumulative(), [16, 32, 48])
        self.assertEqual(deepcov.unit_tool_ceilings(40, [2, 7, 1]), [52, 79, 88])
        self.assertEqual(deepcov.time_slices(900, 4), ([120, 240, 360], [495, 630, 765, 900]))
        self.assertEqual(deepcov.time_slices(280, 1), ([37, 74, 112], [280]))
        self.assertEqual(deepcov.time_slices(None, 2), (None, None))

    def test_repository_profile_plan_and_policy(self):
        from reviewer.pilot import repository_profile as RP
        t = resolve_config(ROOT / "pullo-terra.toml").models
        p = RP.repository_profile(True, t, impact_version=12)
        self.assertEqual(validate("ModelProfile", p), [])
        self.assertNotIn("alternates", p)                                       # primary model only
        self.assertEqual(p["roles"]["investigator"]["promptVersion"], INV12)
        for live, stages, clock in ((True, {"INVESTIGATE": 1800, "VERIFY": 1080, "JUDGE": 400}, (4_000, 3_400)),   # cand12cd time successor
                                    (False, {"INVESTIGATE": 280}, (3_000, 2_400))):   # legacy: the v6cd run deadlines
            plan = RP.repository_plan(p, live_stage_timing=live)
            self.assertEqual(validate("Plan", plan), [])
            self.assertEqual(plan["specialists"], ["contracts", "logic", "safety", "coverage-units"])
            b = plan["budget"]
            self.assertEqual(b["stageCeilingsSec"], stages)
            self.assertEqual((b["wallClockSec"], b["softDeadlineSec"]), clock)
            self.assertEqual((b["maxUsdMicros"], b["verifyReserveBp"], b["maxToolCalls"], b["maxToolCallsPerAgent"]),
                             (4_000_000, 3000, 400, 60))
        pol = RP.repository_policy(True, impact_version=12)
        self.assertEqual((pol.specialists, pol.coverage_forced, pol.exploration_floor, pol.cross_model, pol.five_lanes,
                          pol.diff_sweep, pol.impact, pol.run_tool_calls), (LENS, True, False, False, False, False, True,
                                                                            400))
        self.assertFalse(any(RP.repository_policy(True, impact_version=v).coverage_forced for v in (1, 2, 3, 4, 5, 7, 10)))
        q = dict(p, alternates={"investigator": p["roles"]["investigator"]})
        with self.assertRaises(Exception):
            RP.repository_plan(q)


# ---------------------------------------------------------------- 3. end to end

class EndToEnd(V12Rig):
    def test_e2e_lenses_then_units_then_per_candidate_verify(self):
        m = self.case12()
        scr, (hl, hb, hs) = self.e2e(m)
        res, spy = self.record_v12(m, scr)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual(list(dict.fromkeys(e["agentId"] for e in inv_calls(res))),
                         ["contracts", "logic", "safety", "cover-01", "cover-02"])
        inv = payload(res, "INVESTIGATE")
        self.assertEqual([h["specialist"] for h in inv["hypotheses"]], ["contracts", "cover-01", "cover-02"])
        self.assertEqual(inv["merges"], [])
        self.assertEqual([e["agentId"] for e in model_calls(res, "VERIFY")], ["verifier-01", "verifier-02", "verifier-03"])
        self.assertEqual(len(json.loads((Path(res.run_dir) / "comments.json").read_text())["comments"]), 3)
        md = md_of(res)
        self.assertIn("## Coverage-forced investigation", md)
        self.assertIn("Eligible files read and investigated by their coverage investigator: 5 of 5", md)
        self.assertIn("`src/ws.py` (no-code-change)", md)
        for a in LENS:
            self.assertIn(f"Lens lane {a}: 1 request turn(s), 6 distinct read(s); depth floor met", md)

    def test_requests_carry_the_lens_task_and_the_unit_block(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        res, spy = self.record_v12(m, scr)
        hop0 = [doc_of(r) for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0]
        firsts = {d.get("coverageUnit", {}).get("unit", 0): d for d in hop0}
        lens_docs = hop0[:3]
        for a, d in zip(LENS, lens_docs):
            self.assertEqual(d["task"], prompts.investigator_v3_task(a) + " " + prompts.V12_LENS_DEPTH)
            self.assertNotIn("coverageUnit", d)
            self.assertEqual(d["context"][0]["tool"], "impact_scan")
        u1 = firsts[1]
        self.assertEqual(u1["task"], prompts.V12_UNIT_TASK)
        self.assertEqual([f["path"] for f in u1["coverageUnit"]["files"]], ELIGIBLE[:2])
        self.assertEqual(u1["coverageUnit"]["files"][1]["changedHeadLines"], [[1, 2]])
        self.assertEqual(u1["coverageUnit"]["depthFloorRule"], deepcov.FLOOR_TEXT)
        self.assertEqual({s["path"] for s in u1["coverageUnit"]["notInvestigatedByUnits"]}, set(SKIPPED))
        # a unit's context: the impact map, the changed-path listing and its own files' diffs only
        self.assertEqual([(c["tool"], c["args"].get("path")) for c in u1["context"]],
                         [("impact_scan", None), ("diff", None), ("diff", ELIGIBLE[0]), ("diff", ELIGIBLE[1])])

    def test_strict_replay_and_load_reproduce_the_run(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        res, _ = self.record_v12(m, scr)
        rep = self.replay_v12(m, res)
        self.assertEqual(rep.status, "completed", rep.incomplete)
        self.assertEqual({k: v for k, v in rep.receipt["artifactDigests"].items()},
                         res.receipt["artifactDigests"])
        loaded = load_result(self.out, res.run_id)
        self.assertEqual(loaded.status, "completed")

    def test_identity_binds_the_v12_rules(self):
        m = self.case12()
        scr, _ = self.e2e(m)
        backend, _ = self.record_backend(scr)
        spec = self.spec(m, backend, profile=V12_PROFILE, plan=V12_PLAN, retrieval=V12_POLICY)
        cfg = identity.config_snapshot_id(spec)
        spec3 = self.spec(m, backend, profile=V3_PROFILE, plan=V3_PLAN,
                          retrieval=RetrievalPolicy(investigator_prompt=prompts.INVESTIGATOR_IMPACT_V3_PROMPT,
                                                    verifier_prompt=VER))
        self.assertNotEqual(cfg, identity.config_snapshot_id(spec3))
        doc = deepcov.identity_doc(V12_POLICY, V12_PLAN["budget"], 50, 5)
        self.assertEqual((doc["behavior"], doc["floor"]["rule"], doc["verify"]["maxCandidates"],
                          doc["commentCap"]["max"]), (deepcov.BEHAVIOR, "depth-floor@1", 20, 8))
        t = prompts.impact_template_digests(INV12)
        self.assertIn("coverageForced", t)
        self.assertEqual({k: v for k, v in t.items() if k != "coverageForced"},
                         prompts.impact_template_digests(prompts.INVESTIGATOR_IMPACT_V3_PROMPT))
        with self.assertRaises(PipelineError) as c:            # the Plan must name the lenses and the unit marker
            self.record_v12(m, scr, plan=V3_PLAN)
        self.assertIn("impact@v12", str(c.exception))
        with self.assertRaises(PipelineError):                  # no alternate model: v12 is primary-only
            self.record_v12(m, scr, profile=dict(V12_PROFILE, alternates={
                "investigator": V12_PROFILE["roles"]["investigator"]}))


# ---------------------------------------------------------------- 4. depth floor

class Floor(V12Rig):
    def lens_ok(self, skip=()):
        e = []
        for a in LENS:
            if a not in skip:
                e += [turn(a, 0, lens_reads()), final(a, 1)]
        return e

    def units_ok(self, skip=()):
        e = []
        if "cover-01" not in skip:
            e += unit_turns("cover-01", ELIGIBLE[:2], ["src/handlers/c.py", "src/use.py"]) + [final("cover-01", 2)]
        if "cover-02" not in skip:
            e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2)]
        return e

    def test_an_answer_before_any_read_is_a_draft_and_the_continuation_reads_first(self):
        m = self.case12()
        d, h = self.h_svc(m), dict(self.h_lib(m))
        e = [final("contracts", 0, d),                                             # hop 0: no read -> draft
             turn("contracts", 1, lens_reads()), final("contracts", 2, h)]
        e += self.lens_ok(skip=("contracts",)) + self.units_ok()
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), judge()]
        res, spy = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        cont = [doc_of(r) for r in spy.requests if r["role"] == "investigator" and "depthFloor" in doc_of(r)
                and r["hop"] == 0]
        self.assertEqual(len(cont), 1)                                            # one continuation chain
        df = cont[0]["depthFloor"]
        self.assertEqual((df["continuation"], df["maxContinuations"], df["instruction"]),
                         (1, 2, prompts.V12_FLOOR_CONTINUATION))
        self.assertEqual(df["unmet"], ["request turns that ran a read: 0 of 1", "distinct reads that ran: 0 of 6"])
        self.assertEqual(df["draftHypotheses"][0]["claim"], d["claim"])
        inv = payload(res, "INVESTIGATE")
        self.assertEqual([h_["claim"] for h_ in inv["hypotheses"] if h_["specialist"] == "contracts"], [h["claim"]])
        self.assertIn("Lens lane contracts: 1 request turn(s), 6 distinct read(s); depth floor met after 1 "
                      "continuation(s)", md_of(res))

    def test_a_unit_that_answers_after_one_turn_is_sent_back_with_its_reads_re_shown_and_citable(self):
        m = self.case12()
        first = [rf("src/handlers/a.py"), rf("src/use.py", 2)]                     # b.py never read, 2 reads
        hb = self.h_b(m)
        read_b = treq("read_file", side="head", path="src/handlers/b.py", start_line=1, end_line=2)
        e = self.lens_ok() + [turn("cover-01", 0, first), final("cover-01", 1)]
        e += [turn("cover-01", 2, [read_b, rf("src/handlers/c.py", 2), rf("src/svc.py"),
                                   treq("find_references", side="head", symbol="handle_b")]),
              turn("cover-01", 3, [rf("src/use.py", 3), rf("src/lib.py", 1, 2)]),
              final("cover-01", 4, hb)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2)]
        e += [vdone("verifier-01", m, path="src/handlers/b.py", line=2), judge()]
        res, spy = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        rr = [t for t in tool_calls(res, "INVESTIGATE") if t["agentId"] == "cover-01.reread"]
        self.assertEqual([(t["tool"], t["args"]["path"]) for t in rr],
                         [("read_file", "src/handlers/a.py"), ("read_file", "src/use.py")])
        self.assertTrue(all("requestedBy" not in t for t in rr))                 # host-prepared, not reads
        cont = next(r for r in spy.requests if r["role"] == "investigator" and "depthFloor" in doc_of(r))
        d = doc_of(cont)
        self.assertIn("changed lines not yet read with read_file (side head): src/handlers/b.py [[1, 2]]",
                      d["depthFloor"]["unmet"])
        self.assertEqual(cont["contextResults"][-2:], [t["toolCallId"] for t in rr])
        cite = {c["toolCallId"] for c in d["citations"]["citableRefs"]}
        self.assertTrue({t["toolCallId"] for t in rr} <= cite)                   # re-shown reads stay citable
        st = deepcov.floor_status(events_of(res), "cover-01", {p: [[1, 6]] for p in ELIGIBLE[:2]})
        self.assertTrue(st["met"], st)
        self.assertEqual(st["filesRead"], ELIGIBLE[:2])
        self.assertEqual([h_["specialist"] for h_ in payload(res, "INVESTIGATE")["hypotheses"]], ["cover-01"])

    def test_at_most_two_continuations_then_the_answer_stands_and_is_disclosed(self):
        m = self.case12()
        hb = self.h_b(m)
        e = self.lens_ok() + [final("cover-01", 0), final("cover-01", 1), final("cover-01", 2, hb)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2)]
        e += [vdone("verifier-01", m, path="src/handlers/b.py", line=2), judge()]
        res, spy = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)                 # a unit floor waiver is not incomplete
        self.assertEqual(deepcov.continuations(events_of(res), "cover-01"), 2)
        self.assertEqual(len(inv_calls(res, "cover-01")), 3)
        self.assertIn("Coverage investigator cover-01 (2 file(s)): completed; 0 request turn(s), 0 distinct read(s), "
                      "0 own file(s) read, 0 context read(s); depth floor NOT met after 2 continuation(s)", md_of(res))
        self.assertIn("`src/handlers/b.py` (cover-01): NOT READ by its coverage investigator", md_of(res))

    def test_nothing_new_to_read_waives_the_floor(self):
        m = self.case12()
        e = []
        for a in LENS:
            reads = lens_reads()[:3]
            e += [turn(a, 0, reads), turn(a, 1, reads), final(a, 2)]            # the repeat runs no new read
        e += self.units_ok() + [judge()]
        res, spy = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertFalse(any("depthFloor" in doc_of(r) for r in spy.requests))
        ev = events_of(res)
        last = inv_calls(res, "logic")[-1]["callId"]
        self.assertEqual(deepcov.waiver(ev, "logic", last, 8), "nothing-new")
        self.assertIn("Lens lane logic: 1 request turn(s), 3 distinct read(s); depth floor NOT met", md_of(res))

    def test_waiver_rules_from_the_trace(self):
        def call(cid, hop, **r):
            doc = {"retrieval": {"turn": hop, "turnsAllowed": 8, "lastTurn": False, "toolsExhausted": False,
                                 "toolCallsRemaining": 5, "contextExhausted": False, **r}}
            return {"type": "model.call", "stage": "INVESTIGATE", "role": "investigator", "agentId": "a",
                    "callId": cid, "request": {"hop": hop, "outputSchema": "InvestigatorTurn",
                                               "messages": [{}, {"content": json.dumps(doc)}]},
                    "response": {"status": "ok", "output": {"contextRequests": [], "output": {"hypotheses": []}}}}
        self.assertIsNone(deepcov.waiver([call("c1", 0)], "a", "c1", 8))
        self.assertEqual(deepcov.waiver([call("c1", 0, toolsExhausted=True)], "a", "c1", 8), "tool-calls")
        self.assertEqual(deepcov.waiver([call("c1", 0, toolCallsRemaining=0)], "a", "c1", 8), "tool-calls")
        self.assertEqual(deepcov.waiver([call("c1", 0, contextExhausted=True)], "a", "c1", 8), "context-chars")
        self.assertEqual(deepcov.waiver([call("c1", 0, lastTurn=True)], "a", "c1", 8), "spend")
        self.assertEqual(deepcov.waiver([call("c1", 7, lastTurn=True, turn=7)], "a", "c1", 8), "turns")
        self.assertEqual(deepcov.waiver([call(f"c{i}", i) for i in range(7)], "a", "c6", 8), "turns")

    def test_a_forced_final_turn_from_the_unit_spend_share_waives_the_floor_without_an_incomplete(self):
        from unittest import mock
        m = self.case12()
        real = deepcov.agent_ceiling
        hb = self.h_b(m)

        def tight(unit, j, spent, budget, k, top=None):  # cover-01: no room to explore -> its hop 0 is its final turn
            return spent + 1 if unit and j == 0 else real(unit, j, spent, budget, k, top)
        e = self.lens_ok() + [final("cover-01", 0, hb)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2)]
        e += [vdone("verifier-01", m, path="src/handlers/b.py", line=2), judge()]
        with mock.patch.object(deepcov, "agent_ceiling", tight):
            res, spy = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        c = inv_calls(res, "cover-01")
        self.assertEqual(len(c), 1)
        self.assertTrue(doc_of(c[0]["request"])["retrieval"]["lastTurn"])
        self.assertEqual(deepcov.waiver(events_of(res), "cover-01", c[0]["callId"], 8), "spend")
        self.assertEqual([h_["specialist"] for h_ in payload(res, "INVESTIGATE")["hypotheses"]], ["cover-01"])

    def test_a_unit_without_spend_room_is_a_coverage_note_not_an_incomplete_run(self):
        from unittest import mock
        m = self.case12()
        e = self.lens_ok() + unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"])
        e += [final("cover-02", 2), judge()]
        real = deepcov.agent_ceiling
        with mock.patch.object(deepcov, "agent_ceiling",
                               lambda u, j, s, b, k, top=None: s if u and j == 0 else real(u, j, s, b, k, top)):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        agents = {a["agentId"]: a for a in payload(res, "INVESTIGATE")["agents"]}
        self.assertEqual((agents["cover-01"]["status"], agents["cover-01"]["error"]["detail"]["scope"]),
                         ("budget", "unit-share"))
        md = md_of(res)
        self.assertIn("Coverage investigator cover-01 (2 file(s)): budget (`budget-exhausted`)", md)
        self.assertIn("Eligible files read and investigated by their coverage investigator: 3 of 5", md)

    def test_a_lens_lane_spend_share_end_keeps_v3_semantics(self):
        from unittest import mock
        m = self.case12()
        e = [turn("logic", 0, lens_reads()), final("logic", 1), turn("safety", 0, lens_reads()), final("safety", 1)]
        e += self.units_ok() + [judge()]
        real = deepcov.agent_ceiling
        with mock.patch.object(deepcov, "agent_ceiling",
                               lambda u, j, s, b, k, top=None: 0 if not u and j == 0 else real(u, j, s, b, k, top)):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "partial")
        self.assertEqual([(i["stage"], i["reason"]) for i in res.incomplete], [("INVESTIGATE", "budget")])


# ---------------------------------------------------------------- 5. VERIFY: per-candidate sessions

class VerifyIsolation(V12Rig):
    """The funnel's sentry95633 failure: v3 verifies every candidate in ONE `verifier` session, so the per-agent
    tool-output limit is shared and an early candidate that reads a lot leaves the later ones without their host context
    (VERIFY tool-calls-exhausted, a partial run). v12 gives each verified candidate its own session."""
    BIG = "".join(f"value_{i:05d} = compute(item_{i:05d}, scale=1, offset={i}, mode='strict')\n" for i in range(1200))
    SMALL_BASE = {"src/p.py": "def p(x):\n    return x + 1\n", "src/q.py": "def q(x):\n    return x + 2\n",
                  "src/big.py": BIG}
    SMALL_HEAD = {"src/p.py": "def p(x):\n    return x - 1\n", "src/q.py": "def q(x):\n    return x - 2\n",
                  "src/big.py": BIG}
    TOKENS = 15_000                                     # 45k chars per agent: two 24k reads exceed it

    def budget_plan(self, plan):
        p = copy.deepcopy(plan)
        p["budget"]["maxToolOutputTokensPerAgent"] = self.TOKENS
        return p

    def hyps(self, m):
        return [hyp(m, "src/p.py", 2, claim="p subtracts instead of adding"),
                hyp(m, "src/q.py", 2, claim="q subtracts instead of adding")]

    @staticmethod
    def big_reads():
        return [treq("read_file", side="head", path="src/big.py", start_line=1 + 400 * i, end_line=400 * (i + 1))
                for i in range(2)]

    def test_each_candidate_gets_its_own_verifier_session_so_later_ones_are_not_starved(self):
        m = self.mini("mini-ver", base=self.SMALL_BASE, head=self.SMALL_HEAD)
        hp, hq = self.hyps(m)
        small = [rf("src/p.py", 1, 2), rf("src/q.py", 1, 2)]
        e = [turn("contracts", 0, small), final("contracts", 1, hp, hq)]
        for a in ("logic", "safety"):
            e += [turn(a, 0, small), final(a, 1)]
        e += [turn("cover-01", 0, small), final("cover-01", 1)]
        e += [entry("VERIFY", "verifier", "verifier-01", 0, response=resp({"contextRequests": self.big_reads(),
                                                                          "output": None})),
              entry("VERIFY", "verifier", "verifier-01", 1, response=resp({"contextRequests": [], "output": {
                  "verdict": "confirmed", "reachable": True, "impact": "incorrect-result",
                  "evidence": [m.cite("src/p.py", 2)], "notes": "checked"}})),
              vdone("verifier-02", m, path="src/q.py", line=2), judge()]
        res, _ = self.record_v12(m, script(*e), plan=self.budget_plan(V12_PLAN))
        self.assertNotIn("VERIFY", [i["stage"] for i in res.incomplete], res.incomplete)
        host = [(t["agentId"], t["tool"], t["result"]["status"]) for t in tool_calls(res, "VERIFY")
                if "requestedBy" not in t]
        self.assertEqual(host, [("verifier-01", "read_file", "ok"), ("verifier-01", "diff", "ok"),
                                ("verifier-02", "read_file", "ok"), ("verifier-02", "diff", "ok")])
        used = sum(len(x["excerpt"]) for t in tool_calls(res, "VERIFY") if t["agentId"] == "verifier-01"
                   for x in t["result"]["evidence"])
        self.assertGreater(used, self.TOKENS * 3)       # candidate 1 alone went past the per-agent limit
        self.assertEqual(len(payload(res, "VERIFY")["findings"]), 2)

    def test_v3_one_shared_session_starves_the_second_candidate_on_the_same_budget(self):
        m = self.mini("mini-ver3", base=self.SMALL_BASE, head=self.SMALL_HEAD)
        hp, hq = self.hyps(m)
        from tests.pipeline.test_specialists import ask, sfinal
        from tests.pipeline.helpers import vfinal, vturn
        e = [ask("contracts", 0), sfinal("contracts", 1, hp, hq), ask("logic", 0), sfinal("logic", 1),
             ask("safety", 0), sfinal("safety", 1), vturn(0, self.big_reads()), vfinal(1, m, path="src/p.py", line=2),
             vfinal(2, m, path="src/q.py", line=2), judge()]
        res, _ = self.record_v3(m, script(*e), plan=self.budget_plan(V3_PLAN))
        self.assertEqual(res.status, "partial")
        self.assertIn(("VERIFY", "tool-calls-exhausted"), [(i["stage"], i["reason"]) for i in res.incomplete])


# ---------------------------------------------------------------- 6. merge and VERIFY order

class MergeAndOrder(V12Rig):
    def test_a_unit_restatement_merges_into_the_lens_hypothesis_and_a_distinct_defect_is_kept(self):
        m = self.case12()
        hl = self.h_lib(m)
        same = dict(hl, claim="load_user lost the cache default so Profile.show passes one argument")
        other = hyp(m, "src/lib.py", 1, claim="region is never used by load_user", category="breaking-change",
                    impact="crash", evidence=[m.cite("src/lib.py", 1)])
        hyps = [dict(hl, id="hyp_" + "1" * 16, specialist="contracts"),
                dict(same, id="hyp_" + "2" * 16, specialist="cover-02"),
                dict(other, id="hyp_" + "3" * 16, specialist="cover-02")]
        self.assertEqual(deepcov.merge(hyps), [{"keptId": "hyp_" + "1" * 16, "mergedIds": ["hyp_" + "2" * 16],
                                                "rule": "cross-model-merge@1"}])
        lens_dup = [dict(hl, id="hyp_" + "4" * 16, specialist="contracts"),
                    dict(other, id="hyp_" + "5" * 16, specialist="safety")]
        self.assertEqual(deepcov.merge(lens_dup), specialists.merge(lens_dup))   # lens lanes: exactly v3's merge

    def test_verify_takes_lens_candidates_first_then_units_by_value(self):
        m = self.case12()
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        low = dict(hs, suspectedSeverity="P2")
        high = dict(self.h_b(m), claim="handle_b skips the size limit", location={"path": "src/handlers/b.py", "line": 1},
                    evidence=[m.cite("src/handlers/b.py", 1)], suspectedSeverity="P0")
        e = []
        for a, hh in (("contracts", [hl]), ("logic", []), ("safety", [])):
            e += [turn(a, 0, lens_reads()), final(a, 1, *hh)]
        e += unit_turns("cover-01", ELIGIBLE[:2], ["src/handlers/c.py", "src/use.py"]) + [final("cover-01", 2, hb, high)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2, low)]
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), vdone("verifier-02", m, path="src/handlers/b.py", line=1),
              vdone("verifier-03", m, path="src/svc.py", line=2), vdone("verifier-04", m, path="src/handlers/b.py", line=2),
              judge()]
        res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        order = [c["request"]["hypothesisId"] for c in model_calls(res, "VERIFY")]
        self.assertEqual(order, [hid("contracts", 0, hl), hid("cover-01", 1, high), hid("cover-02", 0, low),
                                 hid("cover-01", 0, hb)])


# ---------------------------------------------------------------- 7. dynamic comment cap

def comment(sev, strength, line):
    return ({}, {"severity": sev, "evidenceStrength": strength, "anchor": {"path": "a", "startLine": line},
                 "fingerprint": str(line)})


class DynamicCap(V12Rig):
    def test_extra_comments_only_while_p0_p1_with_strong_evidence(self):
        q = [comment("P1", "verifier-traced", i) for i in range(7)] + [comment("P2", "verifier-traced", 9)]
        self.assertEqual(deepcov.comment_cap(q, 5), 7)
        self.assertEqual(deepcov.comment_cap([comment("P0", "verifier-traced", i) for i in range(12)], 5), 8)
        self.assertEqual(deepcov.comment_cap([comment("P1", "cited", i) for i in range(9)], 5), 5)
        self.assertEqual(deepcov.comment_cap([comment("P2", "reproduced", i) for i in range(9)], 5), 5)
        self.assertEqual(deepcov.comment_cap([comment("P1", "verifier-traced", i) for i in range(3)], 5), 3)
        self.assertEqual(deepcov.comment_cap([comment("P1", "verifier-traced", i) for i in range(12)], 10), 10)
        mixed = ([comment("P1", "verifier-traced", i) for i in range(5)] + [comment("P1", "cited", 20)]
                 + [comment("P1", "verifier-traced", 30 + i) for i in range(3)])   # ranks: traced before cited
        self.assertEqual(deepcov.comment_cap(mixed, 5), 8)

    def test_engine_publishes_up_to_eight_strongly_evidenced_comments(self):
        lines = 60
        base = {"src/many.py": "".join(f"x{i} = {i}\n" for i in range(lines)), "src/other.py": "y = 1\n"}
        head = {"src/many.py": "".join(f"x{i} = {i + 1}\n" for i in range(lines)), "src/other.py": "y = 1\n"}
        m = self.mini("mini-cap", base=base, head=head)
        hs = [hyp(m, "src/many.py", 1 + 6 * i, claim=f"x{6 * i} is off by one for case {i}") for i in range(9)]
        e = [turn("contracts", 0, [rf("src/many.py", 1 + 6 * i) for i in range(6)]), final("contracts", 1, *hs)]
        for a in ("logic", "safety"):
            e += [turn(a, 0, [rf("src/many.py", 2 + 6 * i) for i in range(6)]), final(a, 1)]
        e += [turn("cover-01", 0, [rf("src/many.py", 1), rf("src/other.py", 1, 1)] +
                   [rf("src/many.py", 10 * i) for i in range(1, 5)]),
              turn("cover-01", 1, [rf("src/many.py", 3 + 10 * i) for i in range(4)]), final("cover-01", 2)]
        from tests.pipeline.helpers import tcid
        for i, h in enumerate(hs):
            line = h["location"]["line"]
            a, b = max(1, line - 20), min(lines, line + 20)
            ref = tcid("VERIFY", f"verifier-{i + 1:02d}", 0, "read_file", side="head", path="src/many.py",
                       start_line=a, end_line=b)
            out = {"verdict": "confirmed", "reachable": True, "impact": "incorrect-result",
                   "evidence": [{"kind": "tool-ref", "toolCallId": ref, "index": 0}], "notes": "checked"}
            e.append(entry("VERIFY", "verifier", f"verifier-{i + 1:02d}", 0,
                           response=resp({"contextRequests": [], "output": out})))
        e.append(judge())
        res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        cs = json.loads((Path(res.run_dir) / "comments.json").read_text())["comments"]
        self.assertEqual(len(cs), 8)
        self.assertTrue(all(c["severity"] == "P1" and c["evidenceStrength"] == "verifier-traced" for c in cs))
        over = [d for d in payload(res, "JUDGE")["drops"] if d["reason"] == "over-cap"]
        self.assertEqual(len(over), 1)
        self.assertIn("dynamic cap of 8 (dynamic-comment-cap@1", over[0]["detail"])


# ---------------------------------------------------------------- 8. parity: v1-v10 unchanged

class Parity(unittest.TestCase):
    def test_v1_v10_repository_identities_are_byte_identical_to_the_pre_change_source(self):
        from reviewer.pilot import repository_profile as RP
        t = resolve_config(ROOT / "pullo-terra.toml").models
        for v in (1, 2, 3, 4, 5, 7, 10):
            p = RP.repository_profile(True, t, impact_version=v)
            got = digest([digest(p), digest(RP.repository_plan(p)), digest(RP.repository_plan(p, live_stage_timing=True)),
                          RP.repository_policy(True, impact_version=v).digest,
                          prompts.impact_template_digests(RP.IMPACT_VERSIONS[v])])
            self.assertEqual(got, PRE_V12_PINS[f"repo_v{v}"], f"v{v}")
        self.assertEqual(sorted(RP.IMPACT_VERSIONS), [1, 2, 3, 4, 5, 7, 10, 12, 16, 19, 20, 21])


class V3Parity(SpecRig):
    def test_v3_recording_is_byte_identical_to_the_pre_change_source(self):
        from tests.pipeline.test_cross_model_v10 import pin_of
        m = self.case()
        scr, _ = self.three_script(m)
        res, _ = self.record_v3(m, scr)
        self.assertEqual(pin_of(res), PRE_V12_PINS["v3_e2e"])


class V10Parity(unittest.TestCase):
    def test_v10_recording_is_byte_identical_to_the_pre_change_source(self):
        from tests.pipeline.test_cross_model_v10 import V10Rig, pin_of

        class R(V10Rig):
            def runTest(self):
                m = self.big()
                main, alt, _ = self.e2e(m)
                res, _ = self.record_v10(m, main, alt)
                self.assertEqual(pin_of(res), PRE_V12_PINS["v10_e2e"])
        r = unittest.TextTestRunner(stream=open("/dev/null", "w")).run(R())
        self.assertTrue(r.wasSuccessful(), r.failures + r.errors)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- 9. gate fixes (8ac0b59 GO-WITH-FIXES)

def vfail(agent, code="provider-error"):
    err = {"code": code, "message": "scripted failure", "retryable": True, "stage": "VERIFY",
           "detail": {"outcome": "rejected-before-processing"}}
    return [entry("VERIFY", "verifier", agent, 0, a, error=err) for a in range(3)]


class GateFixes(V12Rig):
    def base_script(self, m, verify):
        hl, hb, hs = self.h_lib(m), self.h_b(m), self.h_svc(m)
        e = []
        for a, hh in (("contracts", [hl]), ("logic", []), ("safety", [])):
            e += [turn(a, 0, lens_reads()), final(a, 1, *hh)]
        e += unit_turns("cover-01", ELIGIBLE[:2], ["src/handlers/c.py", "src/use.py"]) + [final("cover-01", 2, hb)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2, hs)]
        return e + verify + [judge()], (hl, hb, hs)

    def clocked(self, m, scr, when, seconds):
        """record_v12 with a host clock that jumps `seconds` when the provider is first asked for `when(request)`."""
        from unittest import mock
        from tests.pipeline import helpers
        real = helpers.SpyProvider.call
        rig = self

        def call(spy, request, key):
            if when(request) and not getattr(spy, "_jumped", False):
                spy._jumped = True
                rig.clock_value[0] += seconds
            return real(spy, request, key)
        with mock.patch.object(helpers.SpyProvider, "call", call):
            return self.record_v12(m, scr)

    # S1 ---------------------------------------------------------------------------------------------------------
    def test_s1_a_unit_candidate_verifier_failure_is_a_coverage_note(self):
        m = self.case12()
        e, (hl, hb, hs) = self.base_script(m, [vdone("verifier-01", m, path="src/lib.py", line=1), *vfail("verifier-02"),
                                               vdone("verifier-03", m, path="src/svc.py", line=2)])
        res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        drops = {d["subjectIds"][0]: d["reason"] for d in payload(res, "VERIFY")["drops"]}
        self.assertEqual(drops[hid("cover-01", 0, hb)], "verifier-failed")
        self.assertIn("unit-candidates-unverified: 1 coverage-unit candidate(s) without a verdict (verifier-failed 1",
                      md_of(res))

    def test_s1_a_lens_candidate_verifier_failure_stays_incomplete(self):
        m = self.case12()
        e, _ = self.base_script(m, [*vfail("verifier-01"), vdone("verifier-02", m, path="src/handlers/b.py", line=2),
                                    vdone("verifier-03", m, path="src/svc.py", line=2)])
        res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "partial")
        self.assertEqual([(i["stage"], i["reason"]) for i in res.incomplete], [("VERIFY", "verifier-failure")])

    def test_s1_no_unit_candidate_starts_after_the_verify_start_window(self):
        m = self.case12()
        e, (hl, hb, hs) = self.base_script(m, [vdone("verifier-01", m, path="src/lib.py", line=1)])
        res, _ = self.clocked(m, script(*e), lambda r: r["role"] == "verifier", deepcov.verify_unit_slice(45) + 1)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual([c["agentId"] for c in model_calls(res, "VERIFY")], ["verifier-01"])
        d = [x for x in payload(res, "VERIFY")["drops"] if x["reason"] == "deadline"]
        self.assertEqual({x["subjectIds"][0] for x in d}, {hid("cover-01", 0, hb), hid("cover-02", 0, hs)})
        self.assertIn("VERIFY start window for coverage-unit candidates reached (34s of the 45s", d[0]["detail"])
        self.assertIn("unit-candidates-unverified: 2", md_of(res))
        self.assertEqual((deepcov.verify_unit_slice(540), deepcov.verify_unit_slice(45)), (420, 34))

    def test_s1_no_unit_candidate_starts_without_run_tool_calls_left(self):
        from unittest import mock
        m = self.case12()
        e, (hl, hb, hs) = self.base_script(m, [vdone("verifier-01", m, path="src/lib.py", line=1)])
        with mock.patch.object(deepcov, "VERIFY_UNIT_TOOL_MARGIN", 10_000):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        d = [x for x in payload(res, "VERIFY")["drops"] if x["reason"] == "budget"]
        self.assertEqual(len(d), 2)
        self.assertIn("VERIFY stopped starting coverage-unit candidates", d[0]["detail"])

    def test_s1_units_leave_verify_room_for_known_lens_candidates_and_rereads_are_pooled(self):
        b = V12_PLAN["budget"]
        self.assertEqual([deepcov.unit_top(b, n) for n in (0, 8, 12, 20)], [2_600_000, 2_600_000, 2_500_000, 1_700_000])
        self.assertEqual(deepcov.unit_read_cap(40, 200, 5, 36), 40 + 200 - 70 - 36)
        self.assertEqual(deepcov.unit_read_cap(40, 50, 5, 36), 40)
        self.assertEqual(deepcov.MAX_VERIFY, 20)
        from unittest import mock
        m = self.case12()
        first = [rf("src/handlers/a.py"), rf("src/use.py", 2), rf("src/svc.py", 2)]
        e = Floor.lens_ok(self) + [turn("cover-01", 0, first), final("cover-01", 1)]
        e += [turn("cover-01", 2, [rf(p, 3) for p in ELIGIBLE[:2]] + [rf("src/lib.py", 1, 2)]), final("cover-01", 3)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2), judge()]
        with mock.patch.object(deepcov, "REREAD_POOL", 1):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(len([t for t in tool_calls(res, "INVESTIGATE") if t["agentId"].endswith(".reread")]), 1)

    # S2 ---------------------------------------------------------------------------------------------------------
    def test_s2_a_kept_draft_hypothesis_citing_a_tool_ref_survives_the_continuation(self):
        from tests.pipeline.helpers import tcid
        m = self.case12()
        old = tcid("INVESTIGATE", "cover-01", 1, "read_file", side="head", path="src/use.py", start_line=2, end_line=5)
        h = hyp(m, "src/handlers/b.py", 2, claim="handle_b no longer checks the user", category="security",
                impact="security-exposure", evidence=[m.cite("src/handlers/b.py", 2),
                                                      {"kind": "tool-ref", "toolCallId": old, "index": 0}])
        e = Floor.lens_ok(self) + [turn("cover-01", 0, [rf("src/handlers/a.py"), rf("src/use.py", 2)]),
                                   final("cover-01", 1, h)]
        new = tcid("INVESTIGATE", "cover-01.reread", 1, "read_file", side="head", path="src/use.py", start_line=2,
                   end_line=5)
        kept = dict(h, evidence=[m.cite("src/handlers/b.py", 2), {"kind": "tool-ref", "toolCallId": new, "index": 0}])
        e += [turn("cover-01", 2, [rf("src/handlers/b.py", 1, 2), rf("src/handlers/c.py", 2), rf("src/svc.py"),
                                   treq("find_references", side="head", symbol="handle_b")]),
              turn("cover-01", 3, [rf("src/use.py", 3), rf("src/lib.py", 1, 2)]), final("cover-01", 4, kept)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2)]
        e += [vdone("verifier-01", m, path="src/handlers/b.py", line=2), judge()]
        res, spy = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        cont = next(doc_of(r) for r in spy.requests if r["role"] == "investigator" and "depthFloor" in doc_of(r))
        self.assertEqual(cont["depthFloor"]["draftHypotheses"][0]["evidence"][1]["toolCallId"], new)  # remapped
        inv = payload(res, "INVESTIGATE")
        self.assertEqual([x["claim"] for x in inv["hypotheses"] if x["specialist"] == "cover-01"], [h["claim"]])
        self.assertNotIn("cover-01: 1 of 1 answered hypothesis(es) dropped", md_of(res))

    def test_s2_cited_reads_are_re_shown_first_and_an_unresolved_answer_is_disclosed(self):
        ev = [{"type": "tool.call", "stage": "INVESTIGATE", "agentId": "a", "requestedBy": "c", "toolCallId": f"t{i}",
               "tool": "read_file", "args": {"side": "head", "path": f"p{i}", "start_line": 1, "end_line": 2},
               "result": {"status": "ok", "evidence": [{"excerpt": "x" * 10, "lines": [1, 2]}]}} for i in range(5)]
        self.assertEqual([e["toolCallId"] for e in deepcov.reread_events(ev, "a", ("t0",), None, 2)], ["t0", "t4"])
        self.assertEqual([e["toolCallId"] for e in deepcov.reread_events(ev, "a", (), {"p1": [[1, 3]]}, 2)],
                         ["t1", "t4"])
        d = deepcov.remap_draft({"hypotheses": [{"evidence": [{"kind": "tool-ref", "toolCallId": "t0", "index": 0},
                                                               {"kind": "code", "path": "x"}]}]}, {"t0": "r0"})
        self.assertEqual(d["hypotheses"][0]["evidence"][0]["toolCallId"], "r0")
        m = self.case12()
        bad = hyp(m, "src/handlers/b.py", 2, evidence=[{"kind": "tool-ref", "toolCallId": "tool_" + "0" * 16,
                                                         "index": 0}])
        e = Floor.lens_ok(self) + unit_turns("cover-01", ELIGIBLE[:2], ["src/handlers/c.py", "src/use.py"])
        e += [final("cover-01", 2, bad)]
        e += unit_turns("cover-02", ELIGIBLE[2:], ["src/use.py", "src/handlers/a.py"]) + [final("cover-02", 2), judge()]
        res, _ = self.record_v12(m, script(*e))
        self.assertIn("cover-01: 1 of 1 answered hypothesis(es) dropped before VERIFY", md_of(res))

    # S3 ---------------------------------------------------------------------------------------------------------
    def test_s3_a_lens_continuation_stopped_by_its_time_slice_keeps_the_draft_without_an_incomplete(self):
        m = self.case12()
        hl = self.h_lib(m)
        e = [final("contracts", 0, hl)] + Floor.lens_ok(self, skip=("contracts",)) + Floor.units_ok(self)
        e += [vdone("verifier-01", m, path="src/lib.py", line=1), judge()]
        res, _ = self.clocked(m, script(*e), lambda r: r["role"] == "investigator", 40)   # lens slice 0 is 37 s
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(len(inv_calls(res, "contracts")), 1)
        self.assertEqual([x["specialist"] for x in payload(res, "INVESTIGATE")["hypotheses"]], ["contracts"])
        self.assertIn("Lens lane contracts: 0 request turn(s), 0 distinct read(s); depth floor NOT met", md_of(res))

    # S4, N1, N2, N6 ---------------------------------------------------------------------------------------------
    def test_s4_n2_n6_partition_rules(self):
        files = [{"path": p, "status": "modified"} for p in (
            "src/license.go", "app/models/notice.rb", "pkg/changes.py", "web/authors.ts", "LICENSE", "CHANGELOG",
            "src/Latest.java", "src/Contest.kt", "src/FooTest.java", "src/TestFoo.java", "img/a.png", "big/x.sql")]
        diffs = {f["path"]: fake_diff(f["path"], change()) for f in files}
        diffs["img/a.png"] = {"result": {"status": "unavailable", "evidence": [], "notice": "'img/a.png' is binary; "
                                                                                           "text not shown."}}
        diffs["big/x.sql"] = {"result": {"status": "unavailable", "evidence": [],
                                         "notice": "'big/x.sql' has too many lines to diff."}}
        plan_doc = deepcov.plan(files, diffs)
        self.assertEqual({s["path"]: s["reason"] for s in plan_doc["skipped"]},
                         {"LICENSE": "docs", "CHANGELOG": "docs", "src/FooTest.java": "tests", "src/TestFoo.java": "tests",
                          "img/a.png": "binary", "big/x.sql": "oversized"})
        self.assertEqual(plan_doc["eligible"], 6)

    def test_n1_an_own_file_read_counts_only_with_content_on_its_changed_lines(self):
        def read(path, lines, status="ok"):
            return {"type": "tool.call", "stage": "INVESTIGATE", "agentId": "u", "requestedBy": "c", "tool": "read_file",
                    "toolCallId": f"t{path}{lines}", "args": {"side": "head", "path": path, "start_line": (lines or [1])[0]},
                    "result": {"status": status, "evidence": [{"excerpt": "x", "lines": lines}] if lines else []}}
        files = {"a.py": [[40, 45]], "b.py": [[1, 2]], "c.py": [[5, 5]]}
        ev = [read("a.py", [1, 20]), read("b.py", [1, 3]), read("c.py", [], status="empty")]
        self.assertEqual(deepcov.floor_status(ev, "u", files)["filesRead"], ["b.py"])

    # N5 ---------------------------------------------------------------------------------------------------------
    def test_n5_units_not_started_after_an_unknown_provider_outcome_are_notes(self):
        m = self.case12()
        err = {"code": "provider-error", "message": "scripted", "retryable": True, "stage": "INVESTIGATE"}
        e = Floor.lens_ok(self) + [entry("INVESTIGATE", "investigator", "cover-01", 0, a, error=err) for a in range(3)]
        e += [judge()]
        res, _ = self.record_v12(m, script(*e))
        agents = {a["agentId"]: a for a in payload(res, "INVESTIGATE")["agents"]}
        self.assertEqual((agents["cover-01"]["status"], agents["cover-02"]["status"]), ("failed", "failed"))
        self.assertNotIn("INVESTIGATE", [i["stage"] for i in res.incomplete], res.incomplete)


# ---------------------------------------------------------------- 10. re-gate fixes (fb48656 GO-WITH-FIXES)

class RegateFixes(V12Rig):
    base_script = GateFixes.base_script

    def test_r1_spec_and_it_names_outside_tests_are_eligible(self):
        for p in ("operator/src/main/java/org/k/KeycloakSpec.java", "operator/RealmSpec.kt", "src/AUDIT.java",
                  "src/Latest.java", "src/Contest.kt", "src/Spec.java"):
            self.assertFalse(deepcov.is_test(p), p)
        for p in ("src/FooIT.java", "src/FooTest.java", "src/FooTests.kt", "src/TestFoo.java", "src/FooSpec.groovy",
                  "operator/src/test/java/org/k/KeycloakSpec.java"):
            self.assertTrue(deepcov.is_test(p), p)

    def test_r2_a_spend_book_failure_on_a_unit_candidate_stays_incomplete_and_stops_later_units(self):
        from unittest import mock
        from reviewer.gateway import SettlementError
        from reviewer.gateway.gateway import Gateway
        m = self.case12()
        e, (hl, hb, hs) = self.base_script(m, [vdone("verifier-01", m, path="src/lib.py", line=1),
                                               vdone("verifier-03", m, path="src/svc.py", line=2)])
        real = Gateway.call

        def call(gw, stage, role, agent, *a, **kw):
            if stage == "VERIFY" and agent == "verifier-02":
                raise SettlementError("scripted spend-book failure")
            return real(gw, stage, role, agent, *a, **kw)
        with mock.patch.object(Gateway, "call", call):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "partial")
        self.assertIn(("VERIFY", "verifier-failure"), [(i["stage"], i["reason"]) for i in res.incomplete])
        self.assertEqual([c["agentId"] for c in model_calls(res, "VERIFY")], ["verifier-01"])   # no further unit call
        drops = {d["subjectIds"][0]: d for d in payload(res, "VERIFY")["drops"]}
        self.assertIn("needs operator reconciliation", drops[hid("cover-02", 0, hs)]["detail"])

    def test_r2_a_contract_violation_on_a_unit_candidate_stays_incomplete(self):
        from unittest import mock
        from reviewer.gateway import typed_error
        from reviewer.pipeline import engine as E
        from reviewer.pipeline.retrieval import ChainEnd
        m = self.case12()
        e, _ = self.base_script(m, [vdone("verifier-01", m, path="src/lib.py", line=1),
                                    vdone("verifier-03", m, path="src/svc.py", line=2)])
        real = E.Engine._verifier_chain

        def chain(eng, session, *a, **kw):
            if session.agent_id == "verifier-02":
                return ChainEnd(call_ids=[], error=typed_error("contract-violation", "scripted", stage="VERIFY"))
            return real(eng, session, *a, **kw)
        with mock.patch.object(E.Engine, "_verifier_chain", chain):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "partial")
        self.assertIn(("VERIFY", "verifier-failure", "contract-violation"),
                      [(i["stage"], i["reason"], i.get("detail")) for i in res.incomplete])

    def test_r3_unit_top_keeps_verify_room_for_14_lens_candidates_overshoot_and_retries(self):
        b = V12_PLAN["budget"]
        top = deepcov.unit_top(b, 14, overshoot=300_000, retries=2)
        self.assertEqual(top, 1_800_000)
        # worst case: INVESTIGATE ends one final-answer call above the units' top; what is left still covers the
        # JUDGE reserve plus $0.10 for each lens candidate and each merge retry
        left = b["maxUsdMicros"] - (top + 300_000)
        self.assertGreaterEqual(left, b["maxUsdMicros"] - sweeps.judge_reserve_floor(b) + 16 * 100_000)
        self.assertEqual(deepcov.unit_top(b, 0), 2_600_000)

    def test_r3_the_engine_passes_the_largest_logged_reservation_and_merge_groups(self):
        from unittest import mock
        m = self.case12()
        e, (hl, hb, hs) = self.base_script(m, [vdone("verifier-01", m, path="src/lib.py", line=1),
                                               vdone("verifier-02", m, path="src/handlers/b.py", line=2),
                                               vdone("verifier-03", m, path="src/svc.py", line=2)])
        seen, real = [], deepcov.agent_ceiling

        def spy(unit, j, spent, budget, k, top=None):
            if unit:
                seen.append(top)
            return real(unit, j, spent, budget, k, top)
        with mock.patch.object(deepcov, "agent_ceiling", spy):
            res, _ = self.record_v12(m, script(*e))
        self.assertEqual(res.status, "completed", res.incomplete)
        units_start = next(n for n, x in enumerate(events_of(res)) if x["type"] == "model.call"
                           and x["agentId"] == "cover-01")
        r = max(x["record"]["reservedUsdMicros"] for x in events_of(res)[:units_start] if x["type"] == "cost"
                and x["record"]["role"] == "investigator")
        self.assertEqual(seen, [deepcov.unit_top(V12_PLAN["budget"], 1, r, 0)] * 2)
        self.assertGreater(r, 0)
