"""S0-05 gateway: script loader, trusted authorization, spend book, live/recording path, budgets."""

from __future__ import annotations

import copy
import json
import os
import threading
import unittest
from pathlib import Path

from reviewer.contracts import require
from reviewer.contracts.canonical import call_id, cost_id, request_hash, scoped_key
from reviewer.gateway import (AuthorizationError, AuthorizationHandle, DisabledProvider, Gateway,
                              GatewayConfigError, ProviderResult, Recorder, ScriptError, SpendBook,
                              SyntheticProvider, TraceError, default_providers, load_script, load_trace,
                              parse_script, parse_ts, trusted_authorization, typed_error)
from tests.gateway.helpers import (AUTH_DOC, BUDGET, NOW, OK_OUT, PROFILE, ZERO, Env, entry, profile, request,
                                   response, run_doc, script, terr)

GH = "ghp_" + "A1b2C3d4" * 5


class ScriptTests(unittest.TestCase):
    def body(self, *entries, **top):
        return json.dumps({"schemaVersion": 1, "entries": list(entries), **top})

    def test_valid_script_and_lookup_returns_copies(self):
        sc = parse_script(self.body(entry(response=response()), entry(attempt=1, error=terr())))
        self.assertEqual(len(sc), 2)
        kind, doc = sc.lookup(("INVESTIGATE", "investigator", "generalist", 0, 0))
        self.assertEqual(kind, "response")
        doc["status"] = "mutated"
        self.assertEqual(sc.lookup(("INVESTIGATE", "investigator", "generalist", 0, 0))[1]["status"], "ok")
        self.assertEqual(sc.lookup(("INVESTIGATE", "investigator", "generalist", 0, 1))[0], "error")
        self.assertIsNone(sc.lookup(("INVESTIGATE", "investigator", "generalist", 1, 0)))

    def test_rejections(self):
        good = entry(response=response())
        cases = {
            "duplicate key": self.body(good, good),
            "both": self.body(entry(response=response(), error=terr())),
            "neither": self.body(entry()),
            "unknown entry field": self.body({**good, "extra": 1}),
            "unknown top field": self.body(good, other=1),
            "bad schemaVersion": json.dumps({"schemaVersion": 2, "entries": []}),
            "bool schemaVersion": json.dumps({"schemaVersion": True, "entries": []}),
            "bad stage": self.body(entry(stage="NOPE", response=response())),
            "bad role": self.body(entry(role="admin", response=response())),
            "bad agent": self.body(entry(agent="Bad Agent", response=response())),
            "negative ordinal": self.body(entry(ordinal=-1, response=response())),
            "float attempt": self.body({**good, "attempt": 1.0}),
            "attempt too big": self.body(entry(attempt=11, response=response())),
            "invalid response doc": self.body(entry(response={"status": "ok"})),
            "ok without output": self.body(entry(response=response(output=None))),
            "invalid error doc": self.body(entry(error={"code": "nope"})),
            "secret in response": self.body(entry(response=response(output={"k": GH}))),
            "dup json key": '{"schemaVersion":1,"schemaVersion":1,"entries":[]}',
            "nan": '{"schemaVersion":1,"entries":[],"x":NaN}',
            "not object": "[]",
            "garbage": "{nope",
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(ScriptError):
                parse_script(text)

    def test_load_script_refuses_symlink_and_missing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td, "s.json")
            p.write_text(self.body(entry(response=response())))
            self.assertEqual(len(load_script(p)), 1)
            Path(td, "l.json").symlink_to(p)
            with self.assertRaises(ScriptError):
                load_script(Path(td, "l.json"))
            with self.assertRaises(ScriptError):
                load_script(Path(td, "nope.json"))

    def test_missing_entry_is_a_typed_failure_never_a_fallback(self):
        prov = SyntheticProvider(script())
        r = prov.call(request(), ("INVESTIGATE", "investigator", "generalist", 0, 0))
        self.assertEqual((r.error["code"], r.outcome), ("provider-error", "not-sent"))
        self.assertEqual(prov.missing, [("INVESTIGATE", "investigator", "generalist", 0, 0)])
        with self.assertRaises(ValueError):
            prov.call(request(provider="openai"), ("INVESTIGATE", "investigator", "generalist", 0, 0))


class AuthTests(Env):
    def test_handle_cannot_be_forged_or_copied(self):
        with self.assertRaises(AuthorizationError):
            AuthorizationHandle(object(), AUTH_DOC)
        h = self.handle()
        for fn in (copy.copy, copy.deepcopy):
            with self.assertRaises(TypeError):
                fn(h)
        import pickle
        with self.assertRaises(TypeError):
            pickle.dumps(h)
        h.auth["maxUsdMicrosTotal"] = 1                  # returned copy: no effect on the handle
        self.assertEqual(h.auth["maxUsdMicrosTotal"], AUTH_DOC["maxUsdMicrosTotal"])

    def test_dicts_and_content_cannot_authorize_a_gateway(self):
        for bad in (AUTH_DOC, None, "x", {"id": "x"}):
            with self.assertRaises(AuthorizationError):
                Gateway(mode="live", profile=PROFILE, budget=BUDGET, run_id=run_doc("live", auth_digest="sha256:" + "0" * 64)["id"],
                        providers=default_providers(script()), authorization=bad)

    def test_path_inside_a_content_root_is_refused_even_via_symlink(self):
        content = self.tmp / "case"
        content.mkdir()
        (content / "auth.json").write_text(json.dumps(AUTH_DOC))
        with self.assertRaises(AuthorizationError):
            trusted_authorization(content / "auth.json", forbidden_roots=[content])
        (self.auth_dir / "link.json").symlink_to(content / "auth.json")
        with self.assertRaises(AuthorizationError):
            trusted_authorization(self.auth_dir / "link.json", forbidden_roots=[content])
        self.assertIsInstance(trusted_authorization(content / "auth.json"), AuthorizationHandle)  # no roots given

    def test_invalid_authorization_files(self):
        for name, text in {"garbage": "{x", "dup": '{"id":"a","id":"b"}', "partial": json.dumps({"id": "x"}),
                           "dev-model": json.dumps({**AUTH_DOC, "models": ["claude-opus-5-5"]}),
                           "per-run>total": json.dumps({**AUTH_DOC, "maxUsdMicrosPerRun": 10, "maxUsdMicrosTotal": 5}),
                           "huge": " " * 70000}.items():
            p = self.auth_dir / f"{name}.json"
            p.write_text(text)
            with self.subTest(name), self.assertRaises(AuthorizationError):
                trusted_authorization(p)

    def live_gw(self, h, prof=PROFILE, budget=BUDGET, now=NOW):
        return Gateway(mode="live", profile=prof, budget=budget, run_id=run_doc("live", auth_digest=h.digest)["id"],
                       providers=default_providers(script()), authorization=h, book=SpendBook(h), clock=lambda: now)

    def test_construction_checks_profile_budget_and_clock(self):
        h = self.handle()
        self.live_gw(h)
        with self.assertRaises(AuthorizationError):          # expired
            self.live_gw(self.handle(expiresAt="2026-01-01T00:00:00Z"))
        with self.assertRaises(AuthorizationError):          # profile model not in the authorization
            self.live_gw(self.handle(models=["other-model"]))
        with self.assertRaises(AuthorizationError):          # plan ceiling above per-run ceiling
            self.live_gw(self.handle(maxUsdMicrosPerRun=1000))
        with self.assertRaises(AuthorizationError):          # unresolved role
            self.live_gw(h, prof=profile(judge={"resolved": False}))

    def test_timestamps_parse_strictly(self):
        self.assertLess(parse_ts("2026-01-01T00:00:00Z"), parse_ts("2026-01-01T00:00:00.5Z"))
        for bad in ("", "0", "2026-01-01T00:00:00Z extra", "2026-01-01 00:00:00Z", None, 5, "2026-13-01T00:00:00Z"):
            with self.subTest(bad), self.assertRaises(ValueError):
                parse_ts(bad)

    def test_mode_misuse(self):
        h = self.handle()
        rid = run_doc("live", auth_digest=h.digest)["id"]
        for kw in ({"mode": "strict-replay", "authorization": h}, {"mode": "strict-replay"},
                   {"mode": "disabled", "authorization": h}, {"mode": "live"}, {"mode": "bogus"}):
            with self.subTest(kw), self.assertRaises(GatewayConfigError):
                Gateway(profile=PROFILE, budget=BUDGET, run_id=rid, **kw)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="disabled", profile=PROFILE, budget=BUDGET, run_id="not-a-run")
        other = self.handle(id="other-auth")
        with self.assertRaises(AuthorizationError):          # book of a different authorization
            Gateway(mode="live", profile=PROFILE, budget=BUDGET, run_id=rid, providers=default_providers(script()),
                    authorization=h, book=SpendBook(other))


class RunBindingTests(Env):
    def test_run_start_must_name_this_run_mode_and_authorization_digest(self):
        h = self.handle()
        rd = run_doc("live", auth_digest="sha256:" + "0" * 64)       # wrong digest
        rec = Recorder(rd["id"])
        rec.start(rd)
        with self.assertRaises(AuthorizationError):
            Gateway(mode="live", profile=PROFILE, budget=BUDGET, run_id=rd["id"], providers=default_providers(script()),
                    authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        rd = run_doc("live", auth_digest=h.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        with self.assertRaises(GatewayConfigError):                  # live run doc but replay gateway
            Gateway(mode="strict-replay", profile=PROFILE, budget=BUDGET, run_id=rd["id"], recorder=rec,
                    replay=load_trace(self.record_min(h)))

    def record_min(self, h):
        gw = self.live(script(entry(response=response())), handle=h)
        gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        return self.finish(gw)


class BookTests(Env):
    def test_book_semantics_and_race(self):
        h = self.handle(maxUsdMicrosTotal=1000, maxUsdMicrosPerRun=1000)
        book = SpendBook(h)
        results = []
        def go(i):
            results.append(book.reserve(f"k{i}", 100))
        ts = [threading.Thread(target=go, args=(i,)) for i in range(40)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sum(r is None for r in results), 10)
        self.assertEqual(book.totals()["inflight"], 1000)
        refused = next(r for r in results if r)
        self.assertEqual((refused["code"], refused["detail"]["scope"]), ("budget-exhausted", "total"))
        book.release("k0", "not-sent") if results[0] is None else None
        with self.assertRaises(ValueError):
            book.release("k1", "provider-timeout")           # unknown outcomes stay charged
        self.assertEqual(book.retain("k1"), 100)
        with self.assertRaises(ValueError):
            book.settle("k1", 5)                              # closed already
        with self.assertRaises(ValueError):
            book.reserve("k2", 1)                             # duplicate while open
        with self.assertRaises(ValueError):
            book.settle("k2", -1)

    def test_file_book_is_shared_across_instances_isolated_by_authorization_and_fails_closed(self):
        h = self.handle(maxUsdMicrosTotal=300, maxUsdMicrosPerRun=300)
        store = self.tmp / "book.jsonl"
        a, b = SpendBook(h, store), SpendBook(h, store)
        self.assertIsNone(a.reserve("r1/c1", 200))
        self.assertEqual(b.reserve("r2/c1", 200)["detail"]["scope"], "total")   # b sees a's reservation
        a.settle("r1/c1", 250)
        self.assertEqual(b.totals(), {"committed": 250, "inflight": 0, "limit": 300})
        self.assertIsNone(b.reserve("r2/c2", 50))
        self.assertIsNotNone(b.reserve("r2/c3", 1))
        other = SpendBook(self.handle(id="other", maxUsdMicrosTotal=300, maxUsdMicrosPerRun=300), store)
        self.assertEqual(other.totals()["committed"], 0)                         # per-authorization
        store.write_text(store.read_text() + "garbage\n")
        with self.assertRaises(ValueError):
            a.totals()
        self.assertEqual(oct(store.stat().st_mode & 0o777), "0o600")
        link = self.tmp / "l.jsonl"
        link.symlink_to(store)
        with self.assertRaises(OSError):
            SpendBook(h, link).totals()

    def test_file_book_concurrent_threads(self):
        h = self.handle(maxUsdMicrosTotal=500, maxUsdMicrosPerRun=500)
        store = self.tmp / "b.jsonl"
        books = [SpendBook(h, store) for _ in range(4)]
        out = []
        def go(i):
            out.append(books[i % 4].reserve(f"k{i}", 100))
        ts = [threading.Thread(target=go, args=(i,)) for i in range(30)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sum(r is None for r in out), 5)

    def test_book_requires_a_handle(self):
        with self.assertRaises(AuthorizationError):
            SpendBook(AUTH_DOC)


class LivePathTests(Env):
    def call(self, gw, **kw):
        return gw.call("INVESTIGATE", "investigator", "generalist", 0, kw.pop("req", request()), **kw)

    def test_records_the_actual_request_and_cost_with_synthetic_provenance(self):
        gw = self.live(script(entry(response=response())))
        r = self.call(gw)
        self.assertTrue(r.ok)
        ev = self.finish(gw)
        mc = next(e for e in ev if e["type"] == "model.call")
        cost = next(e for e in ev if e["type"] == "cost")["record"]
        self.assertEqual(mc["request"], request())
        self.assertEqual(mc["requestHash"], request_hash(request()))
        self.assertEqual(mc["callId"], call_id("INVESTIGATE", "investigator", "generalist", 0, 0))
        self.assertEqual(cost["id"], cost_id(mc["callId"]))
        self.assertEqual((cost["basis"], cost["kind"], cost["provider"], cost["usage"]), ("synthetic", "eval", "synthetic", ZERO))
        self.assertGreater(cost["usdMicros"], 0)
        self.assertEqual(cost["reservedUsdMicros"], cost["usdMicros"])      # unknown usage keeps the reservation
        self.assertEqual(gw.live_calls, 1)
        load_trace(ev)                                                        # recording verifies independently

    def test_trace_file_roundtrip_and_no_overwrite(self):
        p = self.tmp / "trace.jsonl"
        gw = self.live(script(entry(response=response())), trace=p)
        self.call(gw)
        self.finish(gw)
        self.assertEqual(load_trace(p).model_calls, 1)
        with self.assertRaises(FileExistsError):
            Recorder(gw.run_id, p)
        os.symlink(p, self.tmp / "l.jsonl")
        with self.assertRaises(OSError):
            Recorder(gw.run_id, self.tmp / "l.jsonl")

    def test_known_usage_settles_measured_amount_labelled_synthetic(self):
        usage = {"uncachedInputTokens": 1000, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 100, "reasoningTokens": 0}
        gw = self.live(script(entry(response=response(usage=usage))))
        self.call(gw)
        cost = next(e for e in self.finish(gw) if e["type"] == "cost")["record"]
        self.assertEqual(cost["usdMicros"], 3000 + 1500)
        self.assertEqual(cost["basis"], "synthetic")
        self.assertNotIn("overrun", cost)
        self.assertEqual(gw.new_spend_usd_micros, 4500)

    def test_overrun_is_charged_flagged_reported_and_blocks_later_calls(self):
        usage = {"uncachedInputTokens": 10**9, "cachedInputTokens": 0, "cacheWriteInputTokens": 0, "outputTokens": 0, "reasoningTokens": 0}
        book = SpendBook(self.handle())
        gw = self.live(script(entry(response=response(usage=usage)), entry(ordinal=1, response=response())), book=book)
        r = self.call(gw)
        self.assertTrue(r.ok and r.attempts[0].overrun)
        self.assertEqual(len(gw.overruns), 1)
        self.assertEqual(gw.report()["overruns"][0]["chargedUsdMicros"], 3_000_000_000)
        r2 = gw.call("INVESTIGATE", "investigator", "generalist", 1, request(text="other"))
        self.assertEqual(r2.error["code"], "budget-exhausted")
        cost = next(e for e in self.finish(gw) if e["type"] == "cost")["record"]
        self.assertTrue(cost["overrun"])
        self.assertGreater(book.totals()["committed"], BUDGET["maxUsdMicros"])

    def test_timeout_is_retained_not_released_and_retried_as_new_admissions(self):
        sc = script(entry(error=terr()), entry(attempt=1, error=terr()), entry(attempt=2, response=response()))
        book = SpendBook(self.handle())
        gw = self.live(sc, book=book)
        r = self.call(gw)
        self.assertTrue(r.ok)
        self.assertEqual([a.attempt for a in r.attempts], [0, 1, 2])
        self.assertEqual(len(set(a.call_id for a in r.attempts)), 3)
        self.assertEqual(len(gw.retained), 2)
        costs = [e["record"] for e in self.finish(gw) if e["type"] == "cost"]
        self.assertEqual([c["usdMicros"] for c in costs[:2]], [c["reservedUsdMicros"] for c in costs[:2]])   # charged in full
        self.assertEqual(book.totals()["committed"], sum(c["usdMicros"] for c in costs))
        self.assertEqual(gw.provider.calls, 3)

    def test_release_only_for_known_not_processed_outcomes(self):
        for outcome, charged in (("not-sent", 0), ("rejected-before-processing", 0), ("processed", None),
                                 ("something-else", None), (None, None)):
            with self.subTest(outcome):
                e = terr("provider-error", False, **({"outcome": outcome} if outcome else {}))
                gw = self.live(script(entry(error=e)))
                r = self.call(gw)
                self.assertEqual(r.error["code"], "provider-error")
                cost = next(x for x in self.finish(gw) if x["type"] == "cost")["record"]
                if charged == 0:
                    self.assertEqual(cost["usdMicros"], 0)
                    self.assertEqual(gw.report()["spend"]["committed"], 0)
                else:
                    self.assertEqual(cost["usdMicros"], cost["reservedUsdMicros"])
                    self.assertGreater(gw.report()["spend"]["committed"], 0)

    def test_nonretryable_errors_return_immediately(self):
        gw = self.live(script(entry(error=terr("provider-error", False))))
        r = self.call(gw)
        self.assertEqual(len(r.attempts), 1)
        self.assertEqual(gw.provider.calls, 1)

    def test_retry_limit_is_min_of_run_and_role(self):
        sc = script(*[entry(attempt=i, error=terr()) for i in range(4)])
        gw = self.live(sc, budget={**BUDGET, "maxRetriesPerCall": 1})        # role says 2, run says 1
        r = self.call(gw)
        self.assertEqual((len(r.attempts), r.error["code"]), (2, "provider-timeout"))
        caps = {"caps": {**PROFILE["roles"]["investigator"]["caps"], "maxRetries": 0}}
        gw = self.live(sc, prof=profile(investigator=caps))                  # role says 0
        self.assertEqual(len(self.call(gw).attempts), 1)
        gw = self.live(sc, budget={**BUDGET, "maxRetriesPerCall": 3})        # role 2 < run 3
        self.assertEqual(len(self.call(gw).attempts), 3)

    def test_script_miss_is_typed_no_fallback_and_released(self):
        gw = self.live(script())
        r = self.call(gw)
        self.assertEqual(r.error["code"], "provider-error")
        self.assertEqual(gw.report()["spend"]["committed"], 0)
        self.assertEqual(gw.provider.missing, [("INVESTIGATE", "investigator", "generalist", 0, 0)])

    def test_repair_is_bounded_to_one_and_admitted_separately(self):
        bad = response(status="invalid-output")
        gw = self.live(script(entry(response=bad), entry(attempt=1, response=response())))
        seen = []
        def repair(resp):
            seen.append(resp["rawText"])
            return request(text="Repair: your output was not valid JSON")
        r = self.call(gw, repair=repair)
        self.assertTrue(r.ok)
        self.assertEqual(seen, ["{not json"])
        ev = self.finish(gw)
        calls = [e for e in ev if e["type"] == "model.call"]
        self.assertEqual(calls[1]["repairOf"], calls[0]["callId"])
        self.assertEqual(calls[1]["attempt"], 1)
        # second invalid answer -> repair-exhausted, no second repair
        gw = self.live(script(entry(response=bad), entry(attempt=1, response=bad), entry(attempt=2, response=response())))
        r = self.call(gw, repair=repair)
        self.assertEqual((r.error["code"], len(r.attempts)), ("repair-exhausted", 2))
        # caps.maxRepairs = 0 or no builder -> schema-invalid after one attempt
        gw = self.live(script(entry(response=bad)), prof=profile(investigator={"caps": {**PROFILE["roles"]["investigator"]["caps"], "maxRepairs": 0}}))
        r = self.call(gw, repair=repair)
        self.assertEqual((r.error["code"], len(r.attempts)), ("schema-invalid", 1))
        gw = self.live(script(entry(response=bad)))
        self.assertEqual(self.call(gw).error["code"], "schema-invalid")

    def test_broken_repair_builder_is_contained(self):
        gw = self.live(script(entry(response=response(status="invalid-output"))))
        r = self.call(gw, repair=lambda resp: 1 / 0)
        self.assertEqual(r.error["code"], "internal")

    def test_repair_request_is_checked_like_any_other(self):
        gw = self.live(script(entry(response=response(status="invalid-output")), entry(attempt=1, response=response())))
        r = self.call(gw, repair=lambda resp: request(model="gpt-elsewhere"))
        self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(gw.provider.calls, 1)


class PerRunAndTotalBudgetTests(Env):
    def test_per_run_ceiling_enforced(self):
        gw = self.live(script(entry(response=response()), entry(ordinal=1, response=response())),
                       budget={**BUDGET, "maxUsdMicros": 100_000, "verifyReserveBp": 0})
        r1 = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        r2 = gw.call("INVESTIGATE", "investigator", "generalist", 1, request(text="two"))
        self.assertTrue(r1.ok)
        err = r2.error
        self.assertEqual((err["code"], err["detail"]["scope"]), ("budget-exhausted", "run"))
        self.assertEqual(gw.provider.calls, 1)

    def test_authorized_per_run_ceiling_lowers_the_run_ceiling(self):
        h = self.handle(maxUsdMicrosPerRun=4_000_000)
        gw = self.live(script(entry(response=response())), handle=h, budget={**BUDGET, "maxUsdMicros": 4_000_000})
        self.assertEqual(gw._ledger.budget["maxUsdMicros"], 4_000_000)

    def test_total_authorized_budget_is_enforced_across_runs(self):
        h = self.handle(maxUsdMicrosTotal=130_000, maxUsdMicrosPerRun=130_000)
        book = SpendBook(h)
        bud = {**BUDGET, "maxUsdMicros": 130_000, "verifyReserveBp": 0}
        gws = [self.live(script(entry(response=response())), handle=h, book=book, budget=bud) for _ in range(3)]
        rs = [g.call("INVESTIGATE", "investigator", "generalist", 0, request()) for g in gws]
        self.assertEqual([r.ok for r in rs], [True, True, False])
        self.assertEqual(rs[2].error["detail"]["scope"], "total")
        self.assertEqual(gws[2].provider.calls, 0)                   # refused before any provider call
        self.assertEqual(gws[2].report()["spend"]["committed"], 0)    # run reservation was returned
        self.assertEqual(book.totals()["committed"], 2 * 60_668)

    def test_total_budget_shared_through_a_store_file(self):
        h = self.handle(maxUsdMicrosTotal=70_000, maxUsdMicrosPerRun=70_000)
        store = self.tmp / "book"
        bud = {**BUDGET, "maxUsdMicros": 70_000, "verifyReserveBp": 0}
        a = self.live(script(entry(response=response())), handle=h, book=SpendBook(h, store), budget=bud)
        b = self.live(script(entry(response=response())), handle=h, book=SpendBook(h, store), budget=bud)
        self.assertTrue(a.call("INVESTIGATE", "investigator", "generalist", 0, request()).ok)
        self.assertEqual(b.call("INVESTIGATE", "investigator", "generalist", 0, request()).error["code"], "budget-exhausted")

    def test_concurrent_calls_never_exceed_ceilings(self):
        n = 20
        entries = [entry(agent=f"agent-{i}", response=response()) for i in range(n)]
        h = self.handle()
        book = SpendBook(h)
        gw = self.live(script(*entries), handle=h, book=book, budget={**BUDGET, "maxUsdMicros": 300_000})
        out = []
        def go(i):
            out.append(gw.call("INVESTIGATE", "investigator", f"agent-{i}", 0, request(text=f"diff {i}")))
        ts = [threading.Thread(target=go, args=(i,)) for i in range(n)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        ok = sum(r.ok for r in out)
        self.assertEqual(ok, 3)                                         # investigation share: 70% of 300000
        self.assertTrue(all(r.error["code"] == "budget-exhausted" for r in out if not r.ok))
        self.assertEqual(gw.provider.calls, 3)
        self.assertLessEqual(book.totals()["committed"], 300_000)
        self.assertEqual(book.totals()["inflight"], 0)


class RequestPolicyTests(Env):
    def call(self, gw, req, role="investigator"):
        return gw.call("INVESTIGATE", role, "generalist", 0, req)

    def test_every_request_is_checked_against_profile_role(self):
        gw = self.live(script(entry(response=response())))
        bad = {"wrong model": request(model="gpt-elsewhere"), "wrong provider": request(provider="openai"),
               "wrong profile": request(profile="other@1"), "wrong role field": request(role="verifier"),
               "wrong prompt": request(promptVersion="other.prompt@v9"),
               "wrong schema": request(outputSchema="JudgeOutput"),
               "output cap exceeded": request(params={"temperature": 0, "maxOutputTokens": 10**6}),
               "output cap float": request(params={"max_tokens": 1.5}),
               "not an object": [], "not valid": {"provider": "synthetic"}}
        for name, req in bad.items():
            with self.subTest(name):
                r = self.call(gw, req)
                self.assertEqual(r.error["code"], "contract-violation", r.error)
        self.assertEqual(gw.provider.calls, 0)
        self.assertEqual(gw.report()["spend"]["committed"], 0)

    def test_authorization_provider_and_model_checked_on_every_request(self):
        gw = self.live(script(entry(response=response()), entry(ordinal=1, response=response())))
        self.assertTrue(self.call(gw, request()).ok)
        gw.auth = self.handle(id="narrowed", models=["another-model"])        # authorization no longer covers the model
        r = gw.call("INVESTIGATE", "investigator", "generalist", 1, request(text="again"))
        self.assertEqual(r.error["code"], "live-calls-disabled")
        gw.auth = self.handle(id="narrowed2", providers=["openai"])
        r = gw.call("INVESTIGATE", "investigator", "generalist", 1, request(text="again"))
        self.assertEqual(r.error["code"], "live-calls-disabled")
        self.assertEqual(gw.provider.calls, 1)

    def test_authorization_expiring_mid_run_stops_calls(self):
        now = {"t": NOW}
        gw = self.live(script(entry(response=response()), entry(ordinal=1, response=response())),
                       handle=self.handle(expiresAt="2026-10-25T13:00:00Z"), clock=lambda: now["t"])
        self.assertTrue(self.call(gw, request()).ok)
        for t in ("2026-10-25T13:00:00Z", "", "garbage", None):
            now["t"] = t
            r = gw.call("INVESTIGATE", "investigator", "generalist", 1, request(text="x"))
            self.assertEqual(r.error["code"], "live-calls-disabled", t)
        self.assertEqual(gw.provider.calls, 1)

    def test_unresolved_role_is_model_unresolved(self):
        gw = Gateway(mode="disabled", profile=profile(judge={"resolved": False}), budget=BUDGET, run_id=run_doc("live", auth_digest="x")["id"])
        r = gw.call("JUDGE", "judge", "judge", 0, request("judge"))
        self.assertEqual(r.error["code"], "model-unresolved")

    def test_live_provider_adapters_are_disabled_stubs(self):
        prof = profile(**{r: {"provider": "anthropic", "family": "claude", "model": "claude-sonnet-5-5", "resolved": True}
                          for r in ("investigator", "verifier", "judge")})
        h = self.handle(providers=["anthropic"], models=["claude-sonnet-5-5"])
        stub = default_providers()["anthropic"]
        self.assertIsInstance(stub, DisabledProvider)
        self.assertEqual(stub.call({}, ()).error["code"], "live-calls-disabled")
        rid = run_doc("live", auth_digest=h.digest)["id"]
        gw = Gateway(mode="live", profile=prof, budget=BUDGET, run_id=rid, providers=default_providers(), authorization=h, book=SpendBook(h), clock=lambda: NOW)
        req = request(provider="anthropic", model="claude-sonnet-5-5")
        r = gw.call("INVESTIGATE", "investigator", "generalist", 0, req)
        self.assertEqual(r.error["code"], "live-calls-disabled")
        self.assertEqual(gw.report()["spend"]["committed"], 0)
        self.assertEqual(next(e for e in gw.recorder.events if e["type"] == "cost")["record"]["usdMicros"], 0)

    def test_disabled_gateway_refuses_everything(self):
        gw = Gateway(mode="disabled", profile=PROFILE, budget=BUDGET, run_id=run_doc("live", auth_digest="x")["id"])
        r = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        self.assertEqual(r.error["code"], "live-calls-disabled")
        self.assertEqual(gw.live_calls, 0)

    def test_bad_call_coordinates_raise(self):
        gw = self.live(script())
        for args in (("NOPE", "investigator", "a", 0), ("INVESTIGATE", "root", "a", 0), ("INVESTIGATE", "investigator", "A b", 0),
                     ("INVESTIGATE", "investigator", "a", -1), ("INVESTIGATE", "investigator", "a", True)):
            with self.assertRaises(ValueError):
                gw.call(*args, request())


class RedactionAndIdTests(Env):
    def test_redacted_before_hashing_and_before_persistence(self):
        secret_req = request(text=f"token = '{GH}'\nvalue")
        gw = self.live(script(entry(response=response())))
        self.assertTrue(gw.call("INVESTIGATE", "investigator", "generalist", 0, secret_req).ok)
        ev = self.finish(gw)
        mc = next(e for e in ev if e["type"] == "model.call")
        self.assertNotIn(GH, json.dumps(ev))
        self.assertEqual(mc["redactions"], {"github-token": 1})
        clean = request(text="token = '[REDACTED:github-token]'\nvalue")
        self.assertEqual(mc["requestHash"], request_hash(clean))
        # a different secret value hashes the same: the hash never depends on secret text
        gw2 = self.live(script(entry(response=response())))
        gw2.call("INVESTIGATE", "investigator", "generalist", 0, request(text="token = '" + "ghp_" + "Z9y8X7w6" * 5 + "'\nvalue"))
        self.assertEqual(next(e for e in self.finish(gw2) if e["type"] == "model.call")["requestHash"], mc["requestHash"])

    def test_provider_response_secrets_are_redacted_and_counted(self):
        class Leaky:
            name = "synthetic"
            calls = 0
            def call(self, req, key):
                return ProviderResult(response(output={"note": f"key {GH}"}), None, "processed")
        gw = self.live(script())
        gw.providers["synthetic"] = Leaky()
        r = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
        self.assertNotIn(GH, json.dumps(r.response))
        ev = self.finish(gw)
        self.assertNotIn(GH, json.dumps(ev))
        self.assertEqual(next(e for e in ev if e["type"] == "model.call")["redactions"], {"github-token": 1})
        load_trace(ev)

    def test_run_ids_in_requests_are_rejected_without_a_provider_call(self):
        gw = self.live(script(entry(response=response())))
        for text in ("see run_" + "0" * 16, "eval evr_" + "1" * 16):
            r = gw.call("INVESTIGATE", "investigator", "generalist", 0, request(text=text))
            self.assertEqual(r.error["code"], "contract-violation")
        self.assertEqual(gw.provider.calls, 0)

    def test_unusable_adapters_and_garbage_are_contained_and_charged(self):
        class Boom:
            name = "synthetic"
            def call(self, req, key):
                raise RuntimeError("socket exploded")
        class Garbage:
            name = "synthetic"
            def call(self, req, key):
                return ProviderResult({"status": "ok"}, None, "processed")
        class WrongModel:
            name = "synthetic"
            def call(self, req, key):
                return ProviderResult(response(resolvedModel="gpt-elsewhere"), None, "processed")
        for prov, code in ((Boom(), "provider-error"), (Garbage(), "contract-violation"), (WrongModel(), "contract-violation")):
            gw = self.live(script())
            gw.providers["synthetic"] = prov
            r = gw.call("INVESTIGATE", "investigator", "generalist", 0, request())
            self.assertEqual(r.error["code"], code)
            self.assertGreater(gw.report()["spend"]["committed"], 0)    # possibly processed: charged
            load_trace(self.finish(gw))


if __name__ == "__main__":
    unittest.main()
