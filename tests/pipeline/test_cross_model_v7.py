"""TOURNAMENT-V7: investigator.impact@v7 cross-model lanes. The five v5 lanes run unchanged on the configured
investigator model, then the logic, consistency and hygiene lenses run again as `<lens>.alt` lanes on an ALTERNATE
investigator model (`[review.investigator_alt]` -> ModelProfile.alternates.investigator); the merge, near-duplicate cap
and v5 VERIFY rules apply over all eight lanes; the verifier model is unchanged.

Invented self-contained fixtures, scripted synthetic providers that answer PER MODEL (a lane sent to the wrong model gets
no scripted answer), the real engine, contracts, gateway and tools. No network, key, state or live call. These tests
prove the mechanics (role/model resolution, refusal without an alternate, the budget split and the alternate-model cap,
lane ids, VERIFY fairness, identity binding, strict replay and load, v1-v5 byte identity); they do NOT show that a second
model finds more real defects."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reviewer.config import ConfigError, ReviewModels, parse, resolve_config
from reviewer.contracts import validate
from reviewer.contracts.budget import check_spend_authorization
from reviewer.contracts.canonical import digest
from reviewer.contracts.entities import validate_trace
from reviewer.gateway import AuthorizationError, DisabledProvider, SpendBook, SyntheticProvider, trusted_authorization
from reviewer.pipeline import PipelineError, RetrievalPolicy, identity, lanes, prompts, run_review, specialists, sweeps
from reviewer.pipeline import RecordBackend

from tests.pipeline.helpers import AUTH, NOW, entry, events_of, hyp, judge, model_calls, resp, script, vfinal
from tests.pipeline.test_diff_shards import Identity as V4Identity
from tests.pipeline.test_impact_pipeline import doc_of, w
from tests.pipeline.test_lanes_v5 import LANES, V5_PLAN, V5_POLICY, V5_PROFILE, LaneRig
from tests.pipeline.test_specialists import ask, inv_calls, sfinal, shid

ROOT = Path(__file__).resolve().parents[2]
INV7, VER = prompts.INVESTIGATOR_IMPACT_V7_PROMPT, prompts.VERIFIER_IMPACT_PROMPT
ALT = ("logic.alt", "consistency.alt", "hygiene.alt")
ALL = LANES + ALT
MAIN_MODEL, ALT_MODEL = "synthetic-fixture", "synthetic-alt-fixture"
ALT_PRICE = {"priceVersion": "synthetic-alt@1", "inputPerMTokUsdMicros": 6_000_000,
             "cachedInputPerMTokUsdMicros": 600_000, "cacheWriteInputPerMTokUsdMicros": 7_500_000,
             "outputPerMTokUsdMicros": 30_000_000}

V7_PROFILE = copy.deepcopy(V5_PROFILE)
V7_PROFILE["roles"]["investigator"]["promptVersion"] = INV7
V7_PROFILE["alternates"] = {"investigator": dict(copy.deepcopy(V7_PROFILE["roles"]["investigator"]), model=ALT_MODEL,
                                                 price=ALT_PRICE)}
V7_POLICY = RetrievalPolicy(investigator_prompt=INV7, verifier_prompt=VER, run_tool_calls=380)
V7_PLAN = copy.deepcopy(V5_PLAN)
V7_PLAN["specialists"] = list(ALL)
V7_PLAN["budget"].update(maxToolCalls=380, stageCeilingsSec={"INVESTIGATE": 320})     # as repository_plan builds it
V7_AUTH = dict(json.loads(AUTH), models=[MAIN_MODEL, ALT_MODEL])

# impact@v5 recordings from the pre-change source (40c12211, the gated v5 head): LaneRig.e2e_script on the 9-path case
# (eval id e...) and the cross-lane merge script below (eval id f...).
V5_PINS = json.loads("""{"v5_big": {"INVESTIGATE": "sha256:c12215c32c80c0584cc50319e932144e35d945d719c67c5ec8745a4c7b5f8db0", "PUBLISH": "sha256:619d04dc9866210f8ce33ba7bdd3e52f62645cdb87e69b87ffb7c2859d44d4c6", "VERIFY": "sha256:6378142e85c53ced119c54454c3e87600124cf78638fc2065917de07e0a74f38", "cfg": "sha256:0076cd6a36cf1de5f242a8ddb5cb36cedc9aad9d0ea09715ebead363942e246d", "requests": ["sha256:1ae1687964d55ee552590f97bcad196a642252993fe1dbf1ca3992eadf5129ac", "sha256:901b781395730706dc264c3c714e2f17258fa428994ad4bffed194f89d36194e", "sha256:bc7244f97695814208137529a79fee359de3d106b163f95b3de7cfc5df7c7c43", "sha256:00fb612f6100d126ba9b2cf993ac4b823a83120021560ab91f51bf7b095f11f7", "sha256:62fa136baf9bc7f9482fbf6801566af865c57c31c4bb7e2b65043bce0e15595c", "sha256:768bafdc1ce4c6036f2abab75fec5c4e66b59a5ee3e359e3b46a59e908c4b066", "sha256:46d06f38dfe04ddcb68f4ab916a8bc3fe0bf030fc1d0207a87ceb142f37b4202", "sha256:e184b2242c4ab74032f5c8dd52586a007e4bc986150ef9b4fcb5eaadfcf24b75", "sha256:2fcbeaecc69e540dcc05335055b6fb5be1abd61a7e37a522dc1b66473d638a35", "sha256:7ae175f5e7bcfe87d0c40a1fbe207ce07a3d55050cd0100a8be43757fc4c4844", "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24", "sha256:a742f7ff0a8e7525ced31d285adede847b130c476171536bbc0b717ab6f15136", "sha256:f1ae4b9b2af5f52e6f50b9f6fae5b694e6c0b07d4714dcbdc6b0ba6b51f2e8cc", "sha256:493a679a01e3d29e706c37ccfcbe9c1dc25b8fa938af7937792815f42a20389c"], "trace": "sha256:d7b3f27fa85b742988d9705eb684cc490cb33cc62eac6ad8859e7d6bc64eb34e"}, "v5_merge": {"INVESTIGATE": "sha256:ccac7f34f23c8971d8f56473d532009d575af1fdf7224764c1acfbbe3e58f491", "PUBLISH": "sha256:1ec4fd321f090b72a2f550e758a4dbe927573c5411ede59d69a9a45abc3088b4", "VERIFY": "sha256:de3ff0620980d9fcb5d69cb3d53f6db55789a050f6a3c681258e19eee67d4874", "cfg": "sha256:0076cd6a36cf1de5f242a8ddb5cb36cedc9aad9d0ea09715ebead363942e246d", "requests": ["sha256:1ae1687964d55ee552590f97bcad196a642252993fe1dbf1ca3992eadf5129ac", "sha256:901b781395730706dc264c3c714e2f17258fa428994ad4bffed194f89d36194e", "sha256:bc7244f97695814208137529a79fee359de3d106b163f95b3de7cfc5df7c7c43", "sha256:00fb612f6100d126ba9b2cf993ac4b823a83120021560ab91f51bf7b095f11f7", "sha256:62fa136baf9bc7f9482fbf6801566af865c57c31c4bb7e2b65043bce0e15595c", "sha256:768bafdc1ce4c6036f2abab75fec5c4e66b59a5ee3e359e3b46a59e908c4b066", "sha256:46d06f38dfe04ddcb68f4ab916a8bc3fe0bf030fc1d0207a87ceb142f37b4202", "sha256:e184b2242c4ab74032f5c8dd52586a007e4bc986150ef9b4fcb5eaadfcf24b75", "sha256:2fcbeaecc69e540dcc05335055b6fb5be1abd61a7e37a522dc1b66473d638a35", "sha256:7ae175f5e7bcfe87d0c40a1fbe207ce07a3d55050cd0100a8be43757fc4c4844", "sha256:984e996f6bbe4fbf919faa55b794a5bb61331ef004e603a7a750a8c6398abf24", "sha256:f93a06328bca99579885cab3de47fde0c45f8db0ba9c34cbdc98e1fe0bdf2389"], "trace": "sha256:bc6072b30f823b44b8bf7490ee829138a2bd12a54005e57c563e52b0b56905b9"}}""")
# digest of {cfg, "1".."5": [profile, Plan, live Plan, policy digests, impact template digests], tmpl} for the pilot
# repository profiles of impact@v1-v5 under pullo-terra.toml / pullo.toml, from the pre-change source (40c12211)
V1_V5_REPO = {"pullo-terra.toml": "sha256:2e20bee54e8703679bc6fde0689103ec9f09666645d24c9401964b228076dddb",
              "pullo.toml": "sha256:a750ff9f8be30401d074014b959f98a45ff1c6ffa5e735c511e073f996929d73"}
TERRA_DIGEST = "sha256:2edf4941e7e0d9df7c765a4a28c50facceade7697c7e2f79d02e8a574632c150"   # pullo-terra.toml, pre-change


def repo_identity(models) -> dict:
    from reviewer.pilot import repository_profile as RP
    out = {"cfg": models.digest}
    for v in (1, 2, 3, 4, 5):
        p = RP.repository_profile(True, models, impact_version=v)
        out[str(v)] = [digest(p), digest(RP.repository_plan(p)), digest(RP.repository_plan(p, live_stage_timing=True)),
                       RP.repository_policy(True, impact_version=v).digest,
                       prompts.impact_template_digests(RP.IMPACT_VERSIONS[v])]
    out["tmpl"] = prompts.template_digests()
    return out


class PerModel:
    """Synthetic provider with one script PER MODEL: a request is answered only from the script of the model it names."""
    name = "synthetic"

    def __init__(self, scripts: dict):
        self.inner = {m: SyntheticProvider(s) for m, s in scripts.items()}
        self.requests: list = []

    @property
    def calls(self):
        return sum(p.calls for p in self.inner.values())

    def call(self, request, key):
        self.requests.append(copy.deepcopy(request))
        return self.inner[request["model"]].call(request, key)


def answered_by(e: dict, model: str) -> dict:
    """A scripted answer of `model` (the gateway refuses an answer whose resolvedModel is not the requested model)."""
    e = copy.deepcopy(e)
    e["response"]["resolvedModel"] = model
    return e


class CrossRig(LaneRig):
    def setUp(self):
        super().setUp()
        p = self.tmp / "operator/auth.json"
        p.write_text(json.dumps(V7_AUTH))
        os.chmod(p, 0o600)
        self.handle = trusted_authorization(p, forbidden_roots=[self.tmp / "cases"])
        self.book = SpendBook(self.handle)

    def record_v7(self, m, main, alt, **kw):
        spy = PerModel({MAIN_MODEL: main, ALT_MODEL: alt})
        providers = {"anthropic": DisabledProvider("anthropic"), "openai": DisabledProvider("openai"), "synthetic": spy}
        backend = RecordBackend(self.handle, self.book, providers, lambda: NOW)
        profile, plan = kw.pop("profile", V7_PROFILE), kw.pop("plan", V7_PLAN)
        kw.setdefault("retrieval", V7_POLICY)
        return run_review(self.spec(m, backend, profile=profile, plan=plan, **kw)), spy

    def replay_v7(self, m, res, **kw):
        kw.setdefault("profile", V7_PROFILE)
        kw.setdefault("retrieval", V7_POLICY)
        kw.setdefault("plan", V7_PLAN)
        return self.replay(m, res, **kw)

    def lanes8(self, **finals):
        main, alt = [], []
        for a in ALL:
            (alt if a in ALT else main).extend([ask(a, 0), sfinal(a, 1, *finals.get(a, ()))])
        return main, [answered_by(e, ALT_MODEL) for e in alt]

    def e2e(self, m):
        hc, hu, hio = self.h_core(m), self.h_util(m), self.h_io(m)
        dup = dict(hu, claim="clamp swaps lo and hi values")            # a true restatement of hu: merged into it
        near = dict(hu, claim="max gets hi as its first argument so every input above lo is returned as hi")
        main, alt = self.lanes8(contracts=[hc], consistency=[hu],
                                **{"logic.alt": [hio], "consistency.alt": [dup], "hygiene.alt": [near]})
        main += [vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                 vfinal(2, m, path="src/app/io.py", line=2), vfinal(3, m, path="src/app/util.py", line=2),
                 judge(w([shid("contracts", 0, hc)]), w([shid("consistency", 0, hu)]), w([shid("logic.alt", 0, hio)]),
                       w([shid("hygiene.alt", 0, near)]))]
        return script(*main), script(*alt), (hc, hu, hio, dup, near)


# ---------------------------------------------------------------- configuration and role/model resolution

TERRA_ALT = """schema = "pullo-config@1"
[review.investigator]
provider = "openai"
model = "gpt-6.1-terra"
[review.verifier]
provider = "openai"
model = "gpt-6.1-terra"
[review.judge]
provider = "openai"
model = "gpt-6.1-terra"
"""


class Config(unittest.TestCase):
    def test_alternate_investigator_is_parsed_disclosed_and_kept_out_of_the_three_role_digest(self):
        plain = parse(TERRA_ALT)
        alt = parse(TERRA_ALT + '[review.investigator_alt]\nprovider = "openai"\nmodel = "gpt-5.6-terra"\n')
        self.assertIsNone(plain.investigator_alt)
        self.assertEqual(alt.investigator_alt, "gpt-5.6-terra")
        self.assertEqual(alt.provider("investigator_alt"), "openai")
        self.assertEqual(alt.digest, plain.digest)                       # reviewConfigDigest: the three roles only
        self.assertEqual(alt.doc(), plain.doc())
        self.assertEqual(alt.alternates_doc(), {"investigator": {"provider": "openai", "model": "gpt-5.6-terra"}})
        self.assertEqual(plain.alternates_doc(), {})
        from reviewer.config import EffectiveConfig
        rep = EffectiveConfig(alt, "explicit").report()
        self.assertEqual(set(rep["roles"]), {"investigator", "verifier", "judge"})
        self.assertEqual(rep["alternates"]["investigator"]["model"], "gpt-5.6-terra")
        self.assertNotIn("alternates", EffectiveConfig(plain, "explicit").report())
        for bad in ('[review.investigator_alt]\nprovider = "openai"\n',                          # no default model
                    '[review.investigator_alt]\nprovider = "openai"\nmodel = "gpt-6.1-sol"\n',   # not allowlisted
                    '[review.investigator_alt]\nmodel = "gpt-5.6-terra"\n',                      # anthropic allowlist
                    '[review.investigator_alt]\nprovider = "openai"\nmodel = "gpt-5.6-terra"\nfallback = "x"\n',
                    '[review.verifier_alt]\nprovider = "openai"\nmodel = "gpt-5.6-terra"\n'):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                parse(TERRA_ALT + bad)
        with self.assertRaises(ConfigError):
            ReviewModels(investigator_alt="gpt-9-terra")

    def test_pullo_terra_toml_names_gpt_5_6_terra_and_keeps_its_digest(self):
        cfg = resolve_config(ROOT / "pullo-terra.toml")
        self.assertEqual(cfg.models.investigator_alt, "gpt-5.6-terra")
        self.assertEqual(cfg.models.digest, TERRA_DIGEST)
        roles = cfg.report()["roles"]                   # what root's rereview_terra terra_config() checks
        self.assertEqual(set(roles), {"investigator", "verifier", "judge"})
        self.assertTrue(all(v["model"] == "gpt-6.1-terra" and v["provider"] == "openai" for v in roles.values()))
        self.assertIsNone(resolve_config(ROOT / "pullo.toml").models.investigator_alt)

    def test_the_alternate_model_is_served_by_the_isolated_terra_adapter(self):
        from reviewer.runtime import catalog, codex_cli
        self.assertIn("gpt-5.6-terra", catalog.TERRA_MODELS)
        self.assertEqual(catalog.TERRA_REASONING_EFFORT["gpt-5.6-terra"], "medium")
        slugs = [m["slug"] for m in json.loads(codex_cli.pinned_catalog())["models"]]
        self.assertIn("gpt-5.6-terra", slugs)                                   # the pinned (digest-checked) catalog
        ident = codex_cli.isolation_identity("gpt-5.6-terra")
        self.assertEqual(ident["modelCatalogSha256"], codex_cli.TERRA_CATALOG_SHA256)
        req = {"provider": "openai", "model": "gpt-5.6-terra", "role": "investigator", "profile": "p@1",
               "promptVersion": INV7, "outputSchema": "InvestigatorTurn", "params": {"maxOutputTokens": 16000},
               "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}], "tools": []}
        facts = codex_cli.request_facts(req)
        self.assertEqual((facts["model"], facts["priceVersion"]), ("gpt-5.6-terra", catalog.terra_price_version(
            "gpt-5.6-terra")))
        from reviewer.pilot.providers import needs
        prof = {"roles": {r: {"provider": "anthropic"} for r in ("investigator", "verifier", "judge")},
                "alternates": {"investigator": {"provider": "openai"}}}
        self.assertTrue(needs(prof, "openai"))            # the live arm builds the Terra adapter for the alternate
        self.assertFalse(needs({"roles": prof["roles"]}, "openai"))


class Resolution(unittest.TestCase):
    def terra(self):
        return resolve_config(ROOT / "pullo-terra.toml").models

    def test_v7_profile_plan_and_policy_bind_the_alternate_model(self):
        from reviewer.pilot import repository_profile as RP
        p = RP.repository_profile(True, self.terra(), impact_version=7)
        self.assertEqual(validate("ModelProfile", p), [])
        inv, alt = p["roles"]["investigator"], p["alternates"]["investigator"]
        self.assertEqual((inv["model"], alt["model"], alt["provider"], alt["family"]),
                         ("gpt-6.1-terra", "gpt-5.6-terra", "openai", "gpt"))
        self.assertEqual({k: v for k, v in alt.items() if k not in ("model", "price")},
                         {k: v for k, v in inv.items() if k not in ("model", "price")})
        self.assertEqual(alt["price"]["outputPerMTokUsdMicros"], 12_000_000)          # gpt-5.6-terra list rates
        self.assertEqual(inv["promptVersion"], INV7)
        for live, secs in ((True, 800), (False, 320)):
            plan = RP.repository_plan(p, live_stage_timing=live)
            self.assertEqual(validate("Plan", plan), [])
            self.assertEqual(plan["specialists"], list(ALL))
            self.assertEqual(plan["budget"]["stageCeilingsSec"]["INVESTIGATE"], secs)
            self.assertEqual((plan["budget"]["maxUsdMicros"], plan["budget"]["verifyReserveBp"],
                              plan["budget"]["maxToolCalls"]), (4_000_000, 3000, 380))
            self.assertIn("openai/gpt-5.6-terra", plan["reasons"][1])
        pol = RP.repository_policy(True, impact_version=7)
        self.assertEqual((pol.specialists, pol.five_lanes, pol.cross_model, pol.run_tool_calls), (ALL, True, True, 380))
        self.assertFalse(any(RP.repository_policy(True, impact_version=v).cross_model for v in (1, 2, 3, 4, 5)))
        # the alternate model is in the profile and the Plan: another alternate gives other bytes
        other = RP.repository_profile(True, ReviewModels("gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.1-terra",
                                                         "anthropic/claude-haiku-5.5"), impact_version=7)
        self.assertNotEqual(digest(other), digest(p))
        self.assertNotEqual(digest(RP.repository_plan(other)), digest(RP.repository_plan(p)))
        self.assertEqual(other["alternates"]["investigator"]["provider"], "anthropic")

    def test_v7_refuses_without_an_alternate_or_with_the_investigators_own_model(self):
        from reviewer.pilot import repository_profile as RP
        from reviewer.pilot.profile import ProfileError
        for models in (None, ReviewModels.uniform("gpt-6.1-terra"),
                       ReviewModels("gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.1-terra", "gpt-6.1-terra")):
            with self.subTest(models=models), self.assertRaises(ProfileError):
                RP.repository_profile(True, models, impact_version=7)
        p = RP.repository_profile(True, self.terra(), impact_version=7)
        del p["alternates"]
        with self.assertRaises(ProfileError):
            RP.repository_plan(p)

    def test_v1_v5_identities_are_byte_identical_and_ignore_the_alternate(self):
        terra = self.terra()
        self.assertEqual(digest(repo_identity(terra)), V1_V5_REPO["pullo-terra.toml"])
        no_alt = ReviewModels(terra.investigator, terra.verifier, terra.judge)
        self.assertEqual(digest(repo_identity(no_alt)), V1_V5_REPO["pullo-terra.toml"])
        self.assertEqual(digest(repo_identity(resolve_config(ROOT / "pullo.toml").models)), V1_V5_REPO["pullo.toml"])
        from reviewer.pilot import repository_profile as RP
        self.assertEqual(RP.DEFAULT_IMPACT_VERSION, 2)
        self.assertFalse(any("alternates" in RP.repository_profile(True, terra, impact_version=v) for v in range(1, 6)))


# ---------------------------------------------------------------- contracts and gateway

GW_PROFILE = dict(copy.deepcopy(V7_PROFILE), id="smoke-synthetic")      # the gateway helpers' run names this ref


class Contracts(unittest.TestCase):
    def test_an_alternate_changes_only_the_model_of_its_role(self):
        self.assertEqual(validate("ModelProfile", V7_PROFILE), [])
        for name, fn in (("prompt", lambda a: a.update(promptVersion="investigator.impact@v5")),
                         ("caps", lambda a: a["caps"].update(maxOutputTokens=10)),
                         ("schema", lambda a: a.update(outputSchema="InvestigatorOutput")),
                         ("same model", lambda a: a.update(model=MAIN_MODEL))):
            bad = copy.deepcopy(V7_PROFILE)
            fn(bad["alternates"]["investigator"])
            with self.subTest(name):
                self.assertNotEqual(validate("ModelProfile", bad), [])
        for alts in ({}, {"verifier": V7_PROFILE["roles"]["verifier"]}):
            self.assertNotEqual(validate("ModelProfile", dict(V7_PROFILE, alternates=alts)), [])

    def test_spend_authorization_must_cover_the_alternate(self):
        budget = V7_PLAN["budget"]
        self.assertEqual(check_spend_authorization(V7_AUTH, V7_PROFILE, budget, NOW), [])
        probs = check_spend_authorization(json.loads(AUTH), V7_PROFILE, budget, NOW)
        self.assertEqual(probs, [f"alternates.investigator: model {ALT_MODEL} not authorized"])

    def gw(self, profile, models):
        from tests.gateway.helpers import Env
        env = Env()
        env.setUp()
        self.addCleanup(env._t.cleanup)
        scr = script(*[answered_by(entry("INVESTIGATE", "investigator", a, k, response=resp(
            {"contextRequests": [], "output": {"hypotheses": []}})), ALT_MODEL if a == "logic.alt" else MAIN_MODEL)
            for a in ("logic.alt", "logic") for k in (0, 1)])
        return env.live(scr, handle=env.handle(models=models), prof=profile)

    def req(self, model, profile=GW_PROFILE):
        spec = dict(profile["roles"]["investigator"], model=model)
        return {"provider": "synthetic", "model": model, "profile": f"{profile['id']}@{profile['version']}",
                "role": "investigator", "promptVersion": spec["promptVersion"], "outputSchema": spec["outputSchema"],
                "params": copy.deepcopy(spec["params"]), "hop": 0, "contextResults": [],
                "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "{}"}], "tools": []}

    def test_gateway_admits_prices_and_records_the_alternate_and_nothing_else(self):
        g = self.gw(GW_PROFILE, [MAIN_MODEL, ALT_MODEL])
        r = g.call("INVESTIGATE", "investigator", "logic.alt", 0, self.req(ALT_MODEL))
        self.assertIsNone(r.error, r.error)
        r2 = g.call("INVESTIGATE", "investigator", "logic", 0, self.req(MAIN_MODEL))
        self.assertIsNone(r2.error, r2.error)
        costs = [e["record"] for e in g.recorder.events if e["type"] == "cost"]
        self.assertEqual([(c["model"], c["priceVersion"]) for c in costs],
                         [(ALT_MODEL, "synthetic-alt@1"), (MAIN_MODEL, "synthetic@1")])
        self.assertGreater(costs[0]["reservedUsdMicros"], costs[1]["reservedUsdMicros"])   # priced at the alt rates
        third = g.call("INVESTIGATE", "investigator", "logic.alt", 1, self.req("synthetic-third"))
        self.assertEqual(third.error["code"], "contract-violation")
        plain = copy.deepcopy(GW_PROFILE)
        del plain["alternates"]
        g2 = self.gw(plain, [MAIN_MODEL, ALT_MODEL])
        self.assertEqual(g2.call("INVESTIGATE", "investigator", "logic.alt", 0, self.req(ALT_MODEL, plain)).error["code"],
                         "contract-violation")
        with self.assertRaises(AuthorizationError):      # an authorization without the alternate: no live gateway
            self.gw(GW_PROFILE, [MAIN_MODEL])


# ---------------------------------------------------------------- pure rules

class Rules(unittest.TestCase):
    def test_lane_ids_and_tasks(self):
        self.assertEqual(prompts.V7_AGENTS, ALL)
        self.assertEqual(lanes.ALT_AGENTS, ALT)
        self.assertEqual([prompts.lens_of(a) for a in ALL], list(LANES) + ["logic", "consistency", "hygiene"])
        self.assertTrue(all(prompts.is_alt_lane(a) for a in ALT) and not any(prompts.is_alt_lane(a) for a in LANES))
        for a in ALL:
            self.assertEqual(validate("Plan", dict(V7_PLAN, specialists=[a])), [])         # a contract slug
        for a in ALT:            # the alternate lane's task is its lens's v5 task, byte for byte
            self.assertEqual(prompts.specialist_task(prompts.lens_of(a)), prompts.specialist_task(a[:-4]))
        self.assertTrue(lanes.is_v7_plan(V7_PLAN) and not lanes.is_v5_plan(V7_PLAN))
        self.assertTrue(specialists.is_specialist_plan(V7_PLAN))
        self.assertEqual((lanes.lane_order(V7_PLAN), lanes.lane_order(V5_PLAN), lanes.lane_order({"specialists": ["x"]})),
                         (list(ALL), list(LANES), None))
        with self.assertRaises(ValueError):
            prompts.investigator_task(INV7)

    def test_v7_merges_only_true_near_duplicates_across_lanes(self):
        from tests.pipeline.test_lanes_v5 import H
        kept = H(1, "consistency", "util.py", 10, claim="clamp swaps lo and hi")
        same = H(2, "consistency.alt", "util.py", 10, claim="clamp swaps lo and hi values")
        other = H(3, "logic.alt", "util.py", 11, end=12, claim="max gets hi first so inputs above lo come back as hi")
        apart = H(4, "hygiene.alt", "util.py", 12, claim="clamp swaps lo and hi")             # within 3, no overlap
        field = H(5, "hygiene.alt", "util.py", 10, claim="clamp swaps `lo` and hi")           # other distinctive token
        hs = [kept, same, other, apart, field]
        # the inherited v3 rule would merge every one of them into `kept`
        self.assertEqual(specialists.merge(hs, list(ALL))[0]["mergedIds"], [h["id"] for h in hs[1:]])
        self.assertEqual(lanes.cross_merge(hs), [{"keptId": kept["id"], "mergedIds": [same["id"]],
                                                  "rule": "cross-model-merge@1"}])
        self.assertEqual(lanes.lane_merge(V7_PLAN, hs), lanes.cross_merge(hs))
        self.assertEqual(lanes.lane_merge(V5_PLAN, hs[:1]), specialists.merge(hs[:1], list(LANES)))
        merges = {"stage": "INVESTIGATE", "hypotheses": [], "agents": [], "merges": lanes.cross_merge(hs)}
        self.assertEqual(validate("StagePayload", merges), [])
        self.assertTrue(lanes.cross_duplicate(kept, same) and not lanes.cross_duplicate(kept, other))

    def test_budget_split_on_the_pilot(self):
        from reviewer.pilot import repository_profile as RP
        p = RP.repository_profile(True, resolve_config(ROOT / "pullo-terra.toml").models, impact_version=7)
        pol = RP.repository_policy(True, impact_version=7)
        for live, secs in ((True, [100 * (i + 1) for i in range(8)]), (False, [40 * (i + 1) for i in range(8)])):
            d = lanes.cross_budget_doc(pol, RP.repository_plan(p, live_stage_timing=live)["budget"], 60)
            self.assertEqual(d["agents"], list(ALL))
            self.assertEqual(d["toolCalls"]["cumulative"], [20 * (i + 1) for i in range(8)])    # v5 lanes keep 20..100
            self.assertEqual(d["timeSec"]["cumulative"], secs)                                 # v5 lanes keep their slices
            s = d["spendUsdMicros"]
            self.assertEqual(s["cumulative"], [440_000, 880_000, 1_320_000, 1_760_000, 2_200_000])   # exactly v5's
            self.assertEqual((s["altTop"], s["altCumulative"], s["v7Top"]),
                             (1_200_000, [400_000, 800_000, 1_200_000], 2_600_000))
        b = {"maxUsdMicros": 4_000_000, "verifyReserveBp": 3000}
        self.assertEqual([lanes.alt_spend_ceiling(1_000_000, j, b) for j in range(3)], [1_400_000, 1_800_000, 2_200_000])
        # v5 lanes that spent their whole share leave the alternate model only up to the v7 top
        self.assertEqual([lanes.alt_spend_ceiling(2_200_000, j, b) for j in range(3)], [2_600_000] * 3)
        self.assertEqual(b["maxUsdMicros"] - lanes.v7_spend_top(b), 1_400_000)          # VERIFY + JUDGE keep >= 35%
        self.assertLessEqual(lanes.v7_spend_top(b), 4_000_000 * 7000 // 10_000)          # under the gateway share
        self.assertEqual(lanes.verify_cap(8), 40)
        self.assertEqual(lanes.primary_spend_cumulative(b), specialists.cumulative(lanes.spend_top(b), 5))


# ---------------------------------------------------------------- end to end

class EndToEnd(CrossRig):
    def test_eight_lanes_on_two_models_with_merge_and_verify(self):
        m = self.big()
        main, alt, (hc, hu, hio, dup, near) = self.e2e(m)
        res, spy = self.record_v7(m, main, alt)
        self.assertEqual(res.status, "completed", res.incomplete)
        self.assertEqual(validate_trace(events_of(res)), [])
        self.assertEqual([(c["agentId"], c["ordinal"]) for c in inv_calls(res)], [(a, k) for a in ALL for k in (0, 1)])
        models = {(r["role"], r.get("hop") is not None and prompts.is_alt_lane(c["agentId"]), r["model"])
                  for c in model_calls(res) for r in (c["request"],)}
        self.assertEqual({(role, model) for role, a, model in models if a}, {("investigator", ALT_MODEL)})
        self.assertEqual({(role, model) for role, a, model in models if not a},
                         {("investigator", MAIN_MODEL), ("verifier", MAIN_MODEL), ("judge", MAIN_MODEL)})
        self.assertEqual(sum(p.calls for p in [spy.inner[ALT_MODEL]]), 6)               # 3 lanes x 2 hops
        firsts = [r for r in spy.requests if r["role"] == "investigator" and r["hop"] == 0]
        self.assertEqual([doc_of(r)["task"] for r in firsts], [prompts.specialist_task(prompts.lens_of(a)) for a in ALL])
        self.assertEqual({r["promptVersion"] for r in firsts}, {INV7})
        self.assertEqual([doc_of(r)["retrieval"]["toolCallsRemaining"] for r in firsts][:2], [20, 39])
        costs = [e["record"] for e in events_of(res) if e["type"] == "cost"]
        self.assertEqual({c["priceVersion"] for c in costs if c["model"] == ALT_MODEL}, {"synthetic-alt@1"})
        pay = self.payload(res)["payload"]
        self.assertEqual([a["agentId"] for a in pay["agents"]], list(ALL))
        self.assertEqual(pay["merges"], [{"keptId": shid("consistency", 0, hu), "mergedIds": [shid("consistency.alt", 0,
                                                                                                    dup)],
                                          "rule": lanes.CROSS_MERGE_RULE}])
        alt_h = [h for h in pay["hypotheses"] if h["specialist"] == "logic.alt"]
        self.assertEqual([h["modelFamily"] for h in alt_h], ["synthetic"])
        # the distinct alternate-model defect next to hu (same file, category and line, another claim) is kept and
        # verified on its own in the first round; the true restatement is merged and dropped after hu was confirmed
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 0, hc), shid("consistency", 0, hu), shid("logic.alt", 0, hio),
                          shid("hygiene.alt", 0, near)])
        self.assertEqual(sorted(f["specialist"] for f in res.findings),
                         ["consistency", "contracts", "hygiene.alt", "logic.alt"])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual([d["subjectIds"] for d in vpay["drops"] if d["reason"] == "merged"],
                         [[shid("consistency.alt", 0, dup)]])
        md = Path(res.review_path).read_text(encoding="utf-8")
        self.assertIn("- logic.alt: completed; 1 resolved hypothesis(es)", md)
        self.assertIn(f"alternate investigator model {ALT_MODEL}", md)

    def test_strict_replay_and_load_rederive_a_v7_run(self):
        from reviewer.pipeline import runner
        m = self.big()
        main, alt, _ = self.e2e(m)
        res, _ = self.record_v7(m, main, alt)
        rep = self.replay_v7(m, res)
        self.assertEqual(rep.status, "completed", rep.error)
        self.assertEqual(rep.receipt["configSnapshotId"], res.receipt["configSnapshotId"])
        for st in ("INVESTIGATE", "VERIFY", "JUDGE"):
            self.assertEqual(rep.receipt["artifactDigests"][st], res.receipt["artifactDigests"][st], st)
        self.assertEqual([h["id"] for h in rep.hypotheses], [h["id"] for h in res.hypotheses])
        self.assertEqual(runner.load_result(self.out, res.run_id).hypotheses, res.hypotheses)
        with mock.patch.object(lanes, "cross_merge", lambda hyps: []):          # the v7 merge is re-derived on load
            with self.assertRaises(PipelineError) as c:
                runner.load_result(self.out, res.run_id)
        self.assertEqual(c.exception.code, "checkpoint-invalid")
        # the replay must name the same alternate: another alternate model is another profile
        other = copy.deepcopy(V7_PROFILE)
        other["alternates"]["investigator"]["model"] = "synthetic-other-fixture"
        with self.assertRaises(PipelineError) as c:
            self.replay_v7(m, res, profile=other, eval_id="evr_" + "9" * 16)
        self.assertEqual(c.exception.code, "identity-mismatch")

    def test_alternate_model_spend_is_capped_without_touching_the_v5_lanes(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        with mock.patch.object(lanes, "ALT_SPEND_BP", 1):              # $0.0004 for all alternate lanes
            res, spy = self.record_v7(m, main, alt)
        self.assertEqual(res.status, "partial")
        agents = {a["agentId"]: a for a in self.payload(res)["payload"]["agents"]}
        self.assertTrue(all(agents[a]["status"] == "completed" for a in LANES))
        self.assertEqual([agents[a]["status"] for a in ALT], ["budget"] * 3)
        errs = [e["error"] for e in events_of(res) if e["type"] == "error"
                and (e["error"].get("detail") or {}).get("scope") == "alternate-model-share"]
        self.assertEqual({e["detail"]["rule"] for e in errs}, {lanes.CROSS_BUDGET_RULE})
        self.assertEqual(spy.inner[ALT_MODEL].calls, 1)                 # the first call was admitted below the cap
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")][:2],
                         [shid("contracts", 0, self.h_core(m)), shid("consistency", 0, self.h_util(m))])

    def test_unused_v5_room_never_rolls_into_the_alternate_lanes(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        seen = []
        orig = lanes.alt_spend_ceiling

        def spy_ceiling(start, j, budget):
            seen.append((start, j))
            return orig(start, j, budget)
        with mock.patch.object(lanes, "alt_spend_ceiling", spy_ceiling):
            res, _ = self.record_v7(m, main, alt)
        v5_spend = sum(e["record"]["usdMicros"] for e in events_of(res) if e["type"] == "cost"
                       and e["record"]["stage"] == "INVESTIGATE" and e["record"]["model"] == MAIN_MODEL)
        self.assertEqual(seen, [(v5_spend, 0), (v5_spend, 1), (v5_spend, 2)])     # S = the v5 lanes' actual spend


class Refusal(CrossRig):
    def test_v7_without_an_alternate_is_refused_before_any_model_call(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        plain = copy.deepcopy(V7_PROFILE)
        del plain["alternates"]
        for prof in (plain, dict(copy.deepcopy(V7_PROFILE), alternates={"investigator": dict(
                V7_PROFILE["roles"]["investigator"], model=MAIN_MODEL)})):
            with self.subTest(prof=prof.get("alternates")), self.assertRaises(PipelineError) as c:
                self.record_v7(m, main, alt, profile=prof)
            self.assertEqual(c.exception.code, "invalid-input")
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_alternates_belong_to_v7_only(self):
        m = self.big()
        p5 = copy.deepcopy(V5_PROFILE)
        p5["alternates"] = copy.deepcopy(V7_PROFILE["alternates"])
        p5["alternates"]["investigator"]["promptVersion"] = p5["roles"]["investigator"]["promptVersion"]
        with self.assertRaises(PipelineError) as c:
            self.record_v7(m, script(), script(), profile=p5, plan=V5_PLAN, retrieval=V5_POLICY)
        self.assertIn("investigator.impact@v7", str(c.exception))
        with self.assertRaises(PipelineError) as c:
            self.record_v7(m, script(), script(), plan=V5_PLAN)
        self.assertIn("investigator.impact@v7", str(c.exception))


class VerifyFairness(CrossRig):
    def test_an_alternate_lanes_best_hypothesis_is_verified_before_any_lanes_second(self):
        m = self.big()
        hc, hu, ht, hio = self.h_core(m), self.h_util(m), self.h_test(m), self.h_io(m)
        conf2 = hyp(m, "src/app/conf.py", 2, claim="RETRIES is too high", severity="P2",
                    evidence=[m.cite("src/app/conf.py", 2)])
        conf1 = hyp(m, "src/app/conf.py", 1, claim="TIMEOUT is too long", category="performance", severity="P2",
                    impact="performance", evidence=[m.cite("src/app/conf.py", 1)])
        main, alt = self.lanes8(contracts=[conf2, hc], consistency=[hu], hygiene=[ht], **{"logic.alt": [conf1, hio]})
        main += [vfinal(0, m, path="src/app/core.py", line=3), vfinal(1, m, path="src/app/util.py", line=2),
                 vfinal(2, m, path="tests/test_core.py", line=5), vfinal(3, m, path="src/app/io.py", line=2),
                 vfinal(4, m, path="src/app/conf.py", line=2), judge()]
        with mock.patch.object(lanes, "MAX_VERIFY_CANDIDATES_V5", 5):
            res, _ = self.record_v7(m, script(*main), script(*alt))
        self.assertEqual([e["request"]["hypothesisId"] for e in model_calls(res, "VERIFY")],
                         [shid("contracts", 1, hc), shid("consistency", 0, hu), shid("hygiene", 0, ht),
                          shid("logic.alt", 1, hio), shid("contracts", 0, conf2)])
        vpay = json.loads((Path(res.run_dir) / res.stages["VERIFY"]["path"]).read_text())["payload"]
        self.assertEqual([d["subjectIds"] for d in vpay["drops"] if d["reason"] == "over-cap"],
                         [[shid("logic.alt", 0, conf1)]])
        self.assertEqual({e["request"]["model"] for e in model_calls(res, "VERIFY")}, {MAIN_MODEL})   # verifier unchanged

    def test_verify_keeps_the_judge_reserve(self):
        m = self.big()
        main, alt, _ = self.e2e(m)
        with mock.patch.object(sweeps, "judge_reserve_floor", lambda budget: 0):
            res, _ = self.record_v7(m, main, alt)
        self.assertEqual(model_calls(res, "VERIFY"), [])
        self.assertIn("budget", {i["reason"] for i in res.incomplete if i["stage"] == "VERIFY"})


class V5Bytes(LaneRig):          # the original synthetic authorization: its digest is in the trace
    pin_of = V4Identity.pin_of

    def test_v5_runs_are_byte_identical_to_the_pre_change_recordings(self):
        m = self.big()
        res, _ = self.record_v5(m, self.e2e_script(m)[0], eval_id="evr_" + "e" * 16)
        self.assertEqual(self.pin_of(res), V5_PINS["v5_big"])
        m2 = self.big()
        hc = self.h_core(m2)
        dup = dict(hc, claim="the loop skips the first item of the list")
        scr = script(ask("contracts", 0), sfinal("contracts", 1, hc), ask("logic", 0), sfinal("logic", 1, dup),
                     ask("safety", 0), sfinal("safety", 1), ask("consistency", 0), sfinal("consistency", 1),
                     ask("hygiene", 0), sfinal("hygiene", 1), vfinal(0, m2, path="src/app/core.py", line=3),
                     judge(w([shid("contracts", 0, hc)])))
        res2, _ = self.record_v5(m2, scr, eval_id="evr_" + "f" * 16)
        self.assertEqual(self.pin_of(res2), V5_PINS["v5_merge"])
        self.assertNotIn("alternate investigator", Path(res.review_path).read_text(encoding="utf-8"))


class Identity(CrossRig):

    def test_v7_rules_and_the_alternate_model_are_bound_into_the_v7_identity_only(self):
        m = self.big()
        backend, _ = self.record_backend(script())
        spec = self.spec(m, backend, profile=V7_PROFILE, plan=V7_PLAN, retrieval=V7_POLICY)
        v5 = self.spec(m, backend, profile=V5_PROFILE, plan=V5_PLAN, retrieval=V5_POLICY)
        base, b5 = identity.config_snapshot_id(spec), identity.config_snapshot_id(v5)
        for name, value in (("ALT_SPEND_BP", 2000), ("V7_INVESTIGATE_SPEND_BP", 6000), ("CROSS_BUDGET_TEXT", "x")):
            orig = getattr(lanes, name)
            try:
                setattr(lanes, name, value)
                self.assertNotEqual(identity.config_snapshot_id(spec), base, name)
                self.assertEqual(identity.config_snapshot_id(v5), b5, name)
            finally:
                setattr(lanes, name, orig)
        other = copy.deepcopy(V7_PROFILE)
        other["alternates"]["investigator"]["model"] = "synthetic-other-fixture"
        self.assertNotEqual(identity.config_snapshot_id(self.spec(m, backend, profile=other, plan=V7_PLAN,
                                                                  retrieval=V7_POLICY)), base)
        old = prompts.IMPACT_V7_TEMPLATES["crossModel"]
        try:
            prompts.IMPACT_V7_TEMPLATES["crossModel"] = {"version": "x"}
            self.assertNotEqual(identity.config_snapshot_id(spec), base)
            self.assertEqual(identity.config_snapshot_id(v5), b5)
        finally:
            prompts.IMPACT_V7_TEMPLATES["crossModel"] = old
        self.assertEqual(identity.plan_specialists(spec), list(ALL))

    def test_plan_must_name_the_eight_lanes(self):
        m = self.big()
        with self.assertRaises(PipelineError) as c:
            self.record_v7(m, script(), script(), plan=V5_PLAN)
        self.assertIn("investigator.impact@v7", str(c.exception))


if __name__ == "__main__":
    unittest.main()
