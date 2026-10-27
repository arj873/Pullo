"""SCORE-GW-04 boundary probes (independent). P1: the provider copy after timeout injection. P2: profile-supplied
unsafe opaque params. REPRO tests state required behaviour and are retained failing repros, never xfail."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reviewer.contracts import require  # noqa: E402
from reviewer.contracts.canonical import score_request_hash  # noqa: E402
from reviewer.gateway.gateway import _score_params_problem  # noqa: E402
from tests.score_gateway_review import support as S  # noqa: E402
from tests.score_gateway_review.support import Fake  # noqa: E402

CAP = S.PROFILE["roles"]["matcher"]["caps"]["timeoutSec"]


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = self._t.name

    def one(self, extra=None, profile=None, req=None):
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p, profile=profile)
        r = gw.call("MATCH", "matcher", "s1", 0, req or S.request(params=S.params(**(extra or {}))))
        ev = next((e for e in rec.events if e["type"] == "score.model.call"), None)
        return p, r, ev


class P1ProviderCopy(Base):
    def test_default_injection_changes_only_params_timeout_and_stays_a_valid_score_request(self):
        p, r, ev = self.one()
        self.assertTrue(r.ok)
        sent = p.seen[0][0]
        require("ScoreRequest", sent)
        self.assertEqual({k for k in sent if sent[k] != ev["request"][k]}, {"params"})
        self.assertEqual({k for k in set(sent["params"]) | set(ev["request"]["params"])
                          if sent["params"].get(k) != ev["request"]["params"].get(k)}, {"timeoutSec"})
        self.assertEqual(sent["params"]["timeoutSec"], CAP)
        self.assertNotIn("timeoutSec", ev["request"]["params"])           # the recorded request is not mutated
        self.assertEqual(ev["requestHash"], score_request_hash(ev["request"]))      # record hash binds the recorded request
        self.assertIsNone(_score_params_problem(sent["params"], S.PROFILE["roles"]["matcher"]))   # copy passes own policy
        score_request_hash(sent)                                           # copy is hashable (ScoreRequest-valid)

    def test_explicit_timeouts_are_sent_unchanged_and_hash_equal(self):
        for t in (1, CAP - 1, CAP):
            p, r, ev = self.one({"timeoutSec": t})
            self.assertTrue(r.ok)
            self.assertEqual(p.seen[0][0], ev["request"])
            self.assertEqual(score_request_hash(p.seen[0][0]), ev["requestHash"])
            self.assertEqual(p.seen[0][0]["params"]["timeoutSec"], t)

    def test_injection_is_deterministic_and_replay_independent(self):
        gw, rec, tr = S.three_role_trace(self.tmp)
        rg, rrec = S.replay(tr)
        for role in S.ROLES:                      # replay with the same un-injected request hits by recorded hash
            self.assertTrue(rg.call(S.STAGE[role], role, "s1", 0, S.request(role)).ok)
        self.assertEqual(rg.report()["liveCalls"], 0)

    def test_every_role_gets_its_own_cap_in_the_provider_copy(self):
        p = Fake()
        gw, rec, _ = S.live(self.tmp, p)
        for role in S.ROLES:
            self.assertTrue(gw.call(S.STAGE[role], role, "s1", 0, S.request(role)).ok)
        for (sent, _k), role in zip(p.seen, S.ROLES):
            self.assertEqual(sent["params"]["timeoutSec"], S.PROFILE["roles"][role]["caps"]["timeoutSec"])
            require("ScoreRequest", sent)

    def test_refused_timeouts_never_reach_provider_and_leak_nothing(self):
        for bad in (0, -1, CAP + 1, True, 1.5, "60", None, [60], 10**9):
            p, r, ev = self.one({"timeoutSec": bad})
            self.assertEqual((p.calls, r.error["code"]), (0, "contract-violation"), bad)
            self.assertNotIn("stage", r.error)


class P2ProfileSuppliedParams(Base):
    UNSAFE = ("provider_order", "providerOptions", "extra_headers", "api_base", "endpoint", "max_price", "mcp",
              "tool_resources", "openrouter", "base_url_override")

    def profile_with(self, k, v="x"):
        prof = copy.deepcopy(S.PROFILE)
        prof["roles"]["matcher"]["params"][k] = v
        return prof

    def test_listed_hidden_keys_in_profile_are_still_refused(self):
        for k in ("tools", "provider", "fallbacks", "route", "models", "headers", "baseUrl", "apiKey"):
            prof = self.profile_with(k, {"x": 1})
            try:
                p, r, ev = self.one(profile=prof, req=S.request(params=copy.deepcopy(prof["roles"]["matcher"]["params"])))
            except Exception:
                continue                           # refused at construction is fine
            self.assertEqual(p.calls, 0, k)

    def test_REPRO_profile_supplied_unlisted_routing_headers_endpoint_never_reach_provider(self):
        reached = []
        for k in self.UNSAFE:
            prof = self.profile_with(k, ["evil"] if k == "provider_order" else {"x": "y"})
            try:
                p, r, ev = self.one(profile=prof,
                                    req=S.request(params=copy.deepcopy(prof["roles"]["matcher"]["params"])))
            except Exception:
                continue
            if p.calls and k in p.seen[0][0]["params"]:
                reached.append(k)
        self.assertEqual(reached, [], "a trusted-profile param equal to the request authorizes itself; "
                                      "the key policy must apply to profile-sourced keys too")

    def test_safe_profile_params_pass_and_unsafe_request_extras_still_refused(self):
        p, r, ev = self.one()
        self.assertTrue(r.ok)
        p, r, ev = self.one({"provider_order": ["x"]})
        self.assertEqual(p.calls, 0)

    def test_profile_override_keys_cannot_loosen_the_caps(self):
        for k, v in (("timeoutSec", 99999), ("timeoutSec", True), ("maxOutputTokens", 10**9), ("max_tokens", -1)):
            prof = self.profile_with(k, v)
            p, r, ev = self.one(profile=prof, req=S.request(params=copy.deepcopy(prof["roles"]["matcher"]["params"])))
            self.assertEqual(p.calls, 0, (k, v))
