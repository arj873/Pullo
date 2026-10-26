"""Independent review tests for S0-05 (reviewer/gateway). Reviewer-owned, offline, stdlib only.

`test_GWn_*` asserts the CORRECT behaviour: FAIL/ERROR = reproduced defect (GW-n ids in
handoffs/S0-05-review.md). `test_CONTROL_*` pass today. No __init__.py on purpose (the author's
`discover -s tests -t .` must not collect these). Builders are reused read-only from
tests/gateway/helpers.py. No provider, network or target-repository access.

Run: nice -n 19 python3 -m unittest discover -s tests/gateway_review -v
"""
from __future__ import annotations

import copy
import json
import multiprocessing as mp
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts.canonical import call_id, scoped_key  # noqa: E402
from reviewer.gateway import (Gateway, GatewayConfigError, Recorder, SpendBook, TraceError,  # noqa: E402
                              default_providers, load_trace, trusted_authorization)
from reviewer.gateway.providers import ProviderResult  # noqa: E402
from tests.gateway import helpers as H  # noqa: E402

INV = ("INVESTIGATE", "investigator", "generalist")
RESERVE = 60_668          # reservation of H.request() under the smoke profile (observed)


def inv_call(gw, ordinal=0, req=None, **kw):
    return gw.call(*INV, ordinal, req or H.request(), **kw)


def cid(ordinal=0, attempt=0, stage="INVESTIGATE", role="investigator", agent="generalist"):
    return call_id(stage, role, agent, ordinal, attempt)


def inv_out(n):
    """A schema-valid InvestigatorOutput whose single hypothesis claim is `claim <n>` (GW-02-review: D3 validates ok output)."""
    return {"hypotheses": [{"claim": f"claim {n}", "category": "bug", "suspectedSeverity": "P1", "impact": "crash",
                            "location": {"path": f"src/f{n}.py", "line": n + 1},
                            "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16}]}]}


# ------------------------------------------------------------------ audit hook (installed once)
_AUDIT = {"on": False, "allow": (), "hits": []}
_NET = ("socket.", "subprocess.", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
        "urllib.", "http.client.", "ftplib.", "smtplib.", "ssl.", "webbrowser.")


def _hook(event, args):
    if not _AUDIT["on"]:
        return
    if event.startswith(_NET):
        _AUDIT["hits"].append((event, repr(args)[:120]))
    elif event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        mode, flags = (args[1] if len(args) > 1 else None), (args[2] if len(args) > 2 else 0)
        writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or \
            (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        path = os.path.realpath(os.fsdecode(args[0]))
        if writes and not path.startswith(_AUDIT["allow"]):
            _AUDIT["hits"].append(("write-open", path))


sys.addaudithook(_hook)


# ------------------------------------------------------------------ forked workers (module level)
def _book_worker(auth_path, store, n, out):
    b = SpendBook(trusted_authorization(auth_path), store=store)
    ok = 0
    for i in range(n):
        k = f"w{os.getpid()}-{i}"
        if b.reserve(k, 70_000) is None:
            ok += 1
            if i % 3 == 0:
                b.retain(k)
            elif i % 3 == 1:
                b.settle(k, 50_000)
            else:
                b.release(k, "not-sent")
    out.put(ok)


def _crash_after_reserve(auth_path, store):
    SpendBook(trusted_authorization(auth_path), store=store).reserve("crashed-call", 123_456)
    os._exit(17)                     # no settle/retain/release: simulated crash


class Base(H.Env):
    def auth_file(self, **over):
        p = self.auth_dir / f"a-{len(list(self.auth_dir.iterdir()))}.json"
        p.write_text(json.dumps({**H.AUTH_DOC, **over}))
        return p

    def gw_for(self, handle, rd, rec, providers, **kw):
        return Gateway(mode="live", profile=kw.pop("prof", H.PROFILE), budget=kw.pop("budget", H.BUDGET),
                       run_id=rd["id"], providers=providers, authorization=handle, recorder=rec,
                       clock=kw.pop("clock", lambda: H.NOW), cost_kind="eval", eval_run_id=H.EVR,
                       eval_case_id="case-a", **kw)


# ================================================================== defects (expected to FAIL today)
class Defects(Base):
    def test_GW1_total_ceiling_holds_across_runs_when_no_book_is_passed(self):
        """Live mode with book=None silently builds a fresh per-gateway SpendBook, so
        maxUsdMicrosTotal is only per-run. Correct: refuse to build, or share the total."""
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        budget = dict(H.BUDGET, maxUsdMicros=100_000)
        sc = H.script(H.entry(response=H.response()))
        ok = 0
        for _ in range(3):
            try:
                gw = self.live(sc, handle=h, budget=budget)      # book omitted
            except GatewayConfigError:
                return                                           # acceptable fix: explicit book required
            ok += inv_call(gw).ok
        self.assertLessEqual(ok * RESERVE, 100_000, f"{ok} runs x {RESERVE} admitted under a 100000 total")

    def test_GW2_replay_recomputes_the_charge_of_errored_calls(self):
        """Replay settles an errored call with the RECORDED usdMicros (gateway.py:468-475), so a
        trace edit turning a retained timeout charge into 0 replays as 'not charged, not retained'."""
        gw = self.live(H.script(H.entry(error=H.terr("provider-timeout", retryable=False))))
        self.assertEqual(inv_call(gw).attempts[0].charge_usd_micros, RESERVE)
        ev = copy.deepcopy(self.finish(gw))
        for e in ev:
            if e["type"] == "cost":
                e["record"]["usdMicros"] = 0
        try:
            rp = self.replayer(ev)
        except TraceError:
            return
        r = inv_call(rp)
        self.assertTrue(r.error["code"] == "replay-mismatch" or r.attempts[0].charge_usd_micros == RESERVE,
                        f"tampered charge replayed: {r.error['code']}, charge {r.attempts[0].charge_usd_micros}, "
                        f"retained {rp.report()['retainedCalls']}")

    def test_GW3_edited_response_is_not_replayed_as_genuine(self):
        """Nothing binds the recorded response: load_trace recomputes request-side hashes only and
        strict replay takes no expected trace digest, so a forged output replays as ok."""
        gw = self.live(H.script(H.entry(response=H.response(output={"hypotheses": []}))))
        inv_call(gw)
        ev = copy.deepcopy(self.finish(gw))
        for e in ev:
            if e["type"] == "model.call":
                e["response"]["output"] = {"hypotheses": "FORGED"}
        try:
            rp = self.replayer(ev)
        except TraceError:
            return
        r = inv_call(rp)
        self.assertFalse(r.ok and r.output == {"hypotheses": "FORGED"}, "forged response replayed as ok")

    def test_GW4_reused_call_coordinates_are_refused_before_the_provider(self):
        """A second live call with the same (stage, role, agent, ordinal) gets attempt 0 again: same
        callId, a second provider call, and a trace load_trace then rejects as duplicate."""
        gw = self.live(H.script(H.entry(response=H.response())))
        self.assertTrue(inv_call(gw).ok)
        second = inv_call(gw, req=H.request(text="a different prompt"))
        self.assertFalse(second.ok, "second call under the same identity was answered")
        self.assertEqual(gw.provider.calls, 1, "provider contacted twice for one call identity")
        load_trace(self.finish(gw))      # the run's own trace must stay loadable

    def test_GW5a_run_start_written_after_construction_is_still_bound(self):
        """The spendAuthorization check only runs if run.start already exists at construction."""
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = H.run_doc("live", auth_digest=other.digest)
        rec = Recorder(rd["id"])
        gw = self.gw_for(h, rd, rec, default_providers(H.script(H.entry(response=H.response()))),
                         book=SpendBook(h))          # GW1: an explicit book is now mandatory
        rec.start(rd)                    # names a different authorization
        self.assertFalse(inv_call(gw).ok, "live call admitted under a run.start naming another authorization")

    def test_GW5b_recorder_for_another_run_is_refused(self):
        """Recorder.run_id is never compared with Gateway.run_id: events and cost records then name
        different runs inside one trace."""
        h = self.handle()
        rd = H.run_doc("live", auth_digest=h.digest)
        rec = Recorder("run_" + "f" * 16)
        with self.assertRaises(GatewayConfigError):
            self.gw_for(h, rd, rec, default_providers(H.script(H.entry(response=H.response()))))

    def test_GW6_processed_call_is_recorded_even_if_the_book_fails_at_settlement(self):
        """If the spend book fails after the provider answered, the exception escapes before any
        model.call/cost event: provider work happened (and may be billed) with no trace evidence."""
        store = self.tmp / "spend.jsonl"
        h = self.handle()
        book = SpendBook(h, store=store)

        class Corrupting:
            name, calls = "synthetic", 0

            def call(self, req, key):
                self.calls += 1
                with open(store, "a") as f:
                    f.write("{torn")      # e.g. a concurrent writer died mid-line / disk full
                return ProviderResult(H.response(), None, "processed")

        rd = H.run_doc("live", auth_digest=h.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        prov = Corrupting()
        gw = self.gw_for(h, rd, rec, {"synthetic": prov}, book=book)
        try:
            inv_call(gw)
        except Exception:  # noqa: BLE001 - raising is acceptable; losing the evidence is not
            pass
        self.assertEqual(prov.calls, 1)
        self.assertIn("model.call", [e["type"] for e in rec.events], "processed provider call left no trace event")

    def test_GW7_total_ceiling_refusal_replays(self):
        """A recorded total-scope budget refusal always replays as replay-mismatch, because replay
        has no book and recomputes only the run ledger. The handoff says budget refusals reproduce."""
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        book, budget = SpendBook(h), dict(H.BUDGET, maxUsdMicros=100_000)
        sc = H.script(H.entry(response=H.response()))
        inv_call(self.live(sc, handle=h, book=book, budget=budget))
        gw = self.live(sc, handle=h, book=book, budget=budget)
        self.assertEqual(inv_call(gw).error["detail"]["scope"], "total")
        r = inv_call(self.replayer(self.finish(gw), budget=budget))
        self.assertEqual(r.error["code"], "budget-exhausted", "recorded total refusal did not reproduce")

    def test_GW8_mismatched_attempts_are_not_reported_as_replayed(self):
        """replayedCalls is incremented before the reservation/charge comparison, so a drifted
        replay reports replayedCalls=1 with no reproduced call."""
        gw = self.live(H.script(H.entry(response=H.response())))
        inv_call(gw)
        drift = H.profile(investigator={"caps": {**H.PROFILE["roles"]["investigator"]["caps"], "maxOutputTokens": 3999}})
        rp = self.replayer(self.finish(gw), prof=drift)
        self.assertEqual(inv_call(rp, req=H.request(params=H.PROFILE["roles"]["investigator"]["params"])).error["code"],
                         "replay-mismatch")
        self.assertEqual(rp.report()["replayedCalls"], 0)

    def test_GW9_trace_without_run_end_is_not_a_complete_recording(self):
        """load_trace accepts a prefix with no run.end (crash or truncation) and LoadedTrace has no
        completeness flag, so strict replay cannot tell a whole recording from a cut one.
        Policy question for root; either refusal or an explicit `complete` flag passes."""
        gw = self.live(H.script(H.entry(response=H.response()), H.entry(ordinal=1, response=H.response())))
        inv_call(gw)
        inv_call(gw, 1, H.request(text="b"))
        ev = self.finish(gw)
        try:
            tr = load_trace(ev[:3])
        except TraceError:
            return
        self.assertFalse(getattr(tr, "complete", True), "truncated trace indistinguishable from a complete one")

    def test_GW10_retries_after_a_repair_are_not_labelled_repairs(self):
        """`repair_of` is never reset, so retries of a repair request are recorded with repairOf:
        one logical call then shows 3 repairs against a cap of 1, and no attempt says retryOf."""
        sc = H.script(H.entry(attempt=0, response=H.response(status="invalid-output")),
                      H.entry(attempt=1, error=H.terr()), H.entry(attempt=2, error=H.terr()),
                      H.entry(attempt=3, response=H.response()))
        gw = self.live(sc)
        self.assertTrue(inv_call(gw, repair=lambda resp: H.request(text="repair")).ok)
        repaired = [e["attempt"] for e in gw.recorder.events if e["type"] == "model.call" and "repairOf" in e]
        self.assertEqual(repaired, [1], "retries of the repair request recorded as repairs")


# ================================================================== controls (expected to PASS)
class Controls(Base):
    # -- replay hash recomputation / occurrence matching
    def test_CONTROL_request_edit_with_stale_hash_is_rejected_and_recomputed_hash_misses(self):
        gw = self.live(H.script(H.entry(response=H.response())))
        inv_call(gw)
        ev = self.finish(gw)
        stale = copy.deepcopy(ev)
        for e in stale:
            if e["type"] == "model.call":
                e["request"]["messages"][1]["content"] += " "
        with self.assertRaises(TraceError):
            load_trace(stale)
        from reviewer.contracts.canonical import request_hash
        fixed = copy.deepcopy(stale)
        for e in fixed:
            if e["type"] == "model.call":
                e["requestHash"] = request_hash(e["request"])
        # GW3: the ORIGINAL pin rejects the edited bytes; only a caller who deliberately trusts the edit re-pins it
        # (digest taken here with hashlib over the serialized edit, not learned by a replay check).
        import hashlib
        edited = "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in fixed).encode()
        with self.assertRaises(TraceError):
            self.replayer(fixed, pin=self.pins[fixed[0]["runId"]])
        r = inv_call(self.replayer(fixed, pin="sha256:" + hashlib.sha256(edited).hexdigest()))
        self.assertEqual(r.error["code"], "replay-miss")        # original request no longer matches

    def test_CONTROL_identical_requests_by_two_agents_never_swap_and_extra_occurrence_misses(self):
        # GW-02-review: the per-agent marker was an unknown field {"n": k} (schema-invalid under D3); it is now the
        # claim of a schema-valid hypothesis. Same request for both agents, same swap/miss/unconsumed assertions.
        sc = H.script(H.entry(agent="a1", response=H.response(output=inv_out(1))),
                      H.entry(agent="a2", response=H.response(output=inv_out(2))))
        gw = self.live(sc)
        for a in ("a1", "a2"):
            self.assertTrue(gw.call("INVESTIGATE", "investigator", a, 0, H.request()).ok)
        rp = self.replayer(self.finish(gw))
        claim = lambda r: r.output["hypotheses"][0]["claim"]          # noqa: E731
        self.assertEqual(claim(rp.call("INVESTIGATE", "investigator", "a2", 0, H.request())), "claim 2")
        self.assertEqual(claim(rp.call("INVESTIGATE", "investigator", "a1", 0, H.request())), "claim 1")
        self.assertEqual(rp.call("INVESTIGATE", "investigator", "a1", 0, H.request()).error["code"], "replay-miss")
        self.assertEqual(rp.call("INVESTIGATE", "investigator", "a3", 0, H.request()).error["code"], "replay-miss")
        self.assertEqual(rp.report()["liveCalls"], 0)
        self.assertEqual(rp.unconsumed(), 0)

    def test_CONTROL_same_hash_recorded_under_other_identity_is_mismatch(self):
        gw = self.live(H.script(H.entry(agent="a1", response=H.response())))
        gw.call("INVESTIGATE", "investigator", "a1", 0, H.request())
        rp = self.replayer(self.finish(gw))
        self.assertEqual(rp.call("INVESTIGATE", "investigator", "a1", 1, H.request()).error["code"], "replay-mismatch")

    def test_CONTROL_cost_and_call_cross_tampering_is_rejected(self):
        gw = self.live(H.script(H.entry(response=H.response(usage={**H.ZERO, "uncachedInputTokens": 10,
                                                                         "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
                                                                         "outputTokens": 5}))))
        inv_call(gw)
        ev = self.finish(gw)
        for edit in (lambda e: e["record"].update(model="other"),
                     lambda e: e["record"]["usage"].update(outputTokens=6),
                     lambda e: e["record"].update(callId=cid(1), id=__import__("reviewer.contracts.canonical",
                                                                                 fromlist=["cost_id"]).cost_id(cid(1)))):
            bad = copy.deepcopy(ev)
            edit(next(e for e in bad if e["type"] == "cost"))
            with self.assertRaises(TraceError):
                load_trace(bad)

    # -- retry / repair admission
    def test_CONTROL_retry_and_repair_each_admitted_with_bounded_attempts(self):
        inv = H.response(status="invalid-output")
        sc = H.script(H.entry(attempt=0, response=inv), H.entry(attempt=1, error=H.terr()),
                      H.entry(attempt=2, error=H.terr()), H.entry(attempt=3, error=H.terr()),
                      H.entry(attempt=4, response=H.response()))
        gw = self.live(sc)
        r = inv_call(gw, repair=lambda resp: H.request(text="repair: return valid JSON"))
        # 1 first + 1 repair + min(Budget 2, role 2) retries = 4 attempts; attempt 4 never reached
        self.assertEqual([a.attempt for a in r.attempts], [0, 1, 2, 3])
        self.assertEqual(r.error["code"], "provider-timeout")
        self.assertEqual(len({a.call_id for a in r.attempts}), 4)
        self.assertEqual(gw.provider.calls, 4)
        self.assertEqual(gw.report()["spend"]["committed"], sum(a.charge_usd_micros for a in r.attempts))

    def test_CONTROL_retry_is_refused_by_budget_not_bypassed(self):
        budget = dict(H.BUDGET, maxUsdMicros=RESERVE * 2 + 10, verifyReserveBp=0)
        sc = H.script(*(H.entry(attempt=a, error=H.terr()) for a in range(3)))
        gw = self.live(sc, budget=budget)
        r = inv_call(gw)
        self.assertEqual([a.outcome for a in r.attempts], ["provider-timeout", "provider-timeout", "budget-exhausted"])
        self.assertEqual(gw.provider.calls, 2)
        self.assertLessEqual(gw.report()["spend"]["committed"], budget["maxUsdMicros"])

    def test_CONTROL_zero_retry_budget_means_no_retry(self):
        gw = self.live(H.script(H.entry(error=H.terr()), H.entry(attempt=1, response=H.response())),
                       budget=dict(H.BUDGET, maxRetriesPerCall=0))
        self.assertEqual(len(inv_call(gw).attempts), 1)

    # -- unknown-spend retention / release
    def test_CONTROL_unknown_usage_keeps_full_reservation(self):
        gw = self.live(H.script(H.entry(response=H.response())))          # all usage null
        r = inv_call(gw)
        self.assertTrue(r.ok)
        cost = [e for e in gw.recorder.events if e["type"] == "cost"][0]["record"]
        self.assertEqual((cost["usdMicros"], cost["basis"], cost["usage"]["outputTokens"]), (RESERVE, "synthetic", None))

    def test_CONTROL_only_provider_error_not_sent_or_rejected_releases(self):
        cases = [(H.terr("provider-error", False, outcome="not-sent"), 0),
                 (H.terr("provider-error", False, outcome="rejected-before-processing"), 0),
                 (H.terr("provider-timeout", False, outcome="not-sent"), RESERVE),     # timeout never released
                 (H.terr("provider-error", False, outcome="processed"), RESERVE),
                 (H.terr("provider-error", False), RESERVE),
                 (H.terr("internal", False, outcome="not-sent"), RESERVE)]
        for err, charge in cases:
            with self.subTest(err=err):
                gw = self.live(H.script(H.entry(error=err)))
                self.assertEqual(inv_call(gw).attempts[0].charge_usd_micros, charge)

    # -- cross-run book: persistence, concurrency, crash
    def test_CONTROL_file_book_never_exceeds_total_across_processes(self):
        ap = self.auth_file(maxUsdMicrosTotal=1_000_000, maxUsdMicrosPerRun=1_000_000)
        store = self.tmp / "shared.jsonl"
        ctx = mp.get_context("fork")
        q = ctx.Queue()
        ps = [ctx.Process(target=_book_worker, args=(str(ap), str(store), 8, q)) for _ in range(6)]
        for p in ps:
            p.start()
        for p in ps:
            p.join(60)
        self.assertTrue(all(p.exitcode == 0 for p in ps))
        admitted = sum(q.get(timeout=5) for _ in ps)
        tot = SpendBook(trusted_authorization(ap), store=store).totals()
        self.assertEqual(tot["inflight"], 0)
        self.assertLessEqual(tot["committed"], 1_000_000)
        self.assertGreater(admitted, 1_000_000 // 70_000)            # releases let more in, never over
        self.assertEqual(oct(store.stat().st_mode & 0o777), "0o600")

    def test_CONTROL_crashed_reservation_stays_charged_and_blocks_reuse(self):
        ap = self.auth_file()
        store = self.tmp / "crash.jsonl"
        p = mp.get_context("fork").Process(target=_crash_after_reserve, args=(str(ap), str(store)))
        p.start()
        p.join(30)
        self.assertEqual(p.exitcode, 17)
        book = SpendBook(trusted_authorization(ap), store=store)
        self.assertEqual(book.totals()["inflight"], 123_456)
        with self.assertRaises(ValueError):                         # operator must reconcile
            book.reserve("crashed-call", 1)

    def test_CONTROL_torn_book_fails_closed(self):
        h = self.handle()
        store = self.tmp / "torn.jsonl"
        book = SpendBook(h, store=store)
        book.reserve("k", 1)
        with open(store, "a") as f:
            f.write('{"op":"close","key":"k","cha')
        with self.assertRaises(ValueError):
            book.reserve("k2", 1)

    def test_CONTROL_book_store_symlink_refused(self):
        h = self.handle()
        real = self.tmp / "real.jsonl"
        real.write_text("")
        link = self.tmp / "link.jsonl"
        link.symlink_to(real)
        with self.assertRaises(OSError):
            SpendBook(h, store=link).totals()

    # -- authorization scope / expiry
    def test_CONTROL_expiry_boundary_and_bad_clock(self):
        for now, ok in (("2026-12-30T23:59:59.999999Z", True), ("2026-12-31T00:00:00Z", False),
                        ("2026-12-31T00:00:00.000001Z", False), ("2026-12-30 23:00:00", False), ("", False)):
            with self.subTest(now=now):
                t = {"v": H.NOW}
                gw = self.live(H.script(H.entry(response=H.response())), clock=lambda: t["v"])
                t["v"] = now
                r = inv_call(gw)
                self.assertEqual(r.ok, ok)
                if not ok:
                    self.assertEqual((r.error["code"], gw.provider.calls), ("live-calls-disabled", 0))

    def test_CONTROL_replay_and_disabled_refuse_authorization_and_providers(self):
        gw = self.live(H.script(H.entry(response=H.response())))
        inv_call(gw)
        tr = load_trace(self.finish(gw))
        rd, evr = H.replay_run_doc(tr.run_id)
        common = dict(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr)
        for extra in ({"authorization": self.handle()}, {"providers": default_providers(H.script())},
                      {"book": SpendBook(self.handle())}):
            with self.subTest(extra=list(extra)), self.assertRaises(GatewayConfigError):
                Gateway(**common, **extra)

    def test_CONTROL_handle_fields_are_copies(self):
        h = self.handle()
        h.auth["maxUsdMicrosTotal"] = 10**12
        self.assertEqual(h.auth["maxUsdMicrosTotal"], H.AUTH_DOC["maxUsdMicrosTotal"])

    # -- absence of external I/O
    def test_CONTROL_record_load_replay_do_no_network_process_or_outside_writes(self):
        sc = H.script(H.entry(error=H.terr()), H.entry(attempt=1, response=H.response()),
                      H.entry(ordinal=1, response=H.response(status="invalid-output")),
                      H.entry(ordinal=1, attempt=1, response=H.response()))
        trace = self.tmp / "t.jsonl"
        h = self.handle()
        book = SpendBook(h, store=self.tmp / "b.jsonl")
        _AUDIT.update(on=True, allow=(os.path.realpath(self.tmp),), hits=[])
        try:
            gw = self.live(sc, handle=h, book=book, trace=trace)
            inv_call(gw)
            inv_call(gw, 1, repair=lambda r: H.request(text="fix"))
            self.finish(gw)
            rp = self.replayer(load_trace(trace).events)
            inv_call(rp)
            inv_call(rp, 1, repair=lambda r: H.request(text="fix"))
        finally:
            _AUDIT["on"] = False
        self.assertEqual(_AUDIT["hits"], [])
        self.assertEqual(rp.report()["liveCalls"], 0)

    # -- truthful synthetic / replay provenance
    def test_CONTROL_synthetic_and_replayed_provenance(self):
        gw = self.live(H.script(H.entry(response=H.response()), H.entry(ordinal=1, error=H.terr(retryable=False))))
        inv_call(gw)
        inv_call(gw, 1, H.request(text="b"))
        ev = self.finish(gw)
        live_costs = [e["record"] for e in ev if e["type"] == "cost"]
        self.assertEqual({c["basis"] for c in live_costs}, {"synthetic"})
        rp = self.replayer(ev)
        inv_call(rp)
        inv_call(rp, 1, H.request(text="b"))
        rep = rp.report()
        self.assertEqual((rep["liveCalls"], rep["newSpendUsdMicros"], rep["replayedCalls"]), (0, 0, 2))
        self.assertEqual(rep["replayedUsdMicros"], sum(c["usdMicros"] for c in live_costs))
        for c in (e["record"] for e in rp.recorder.events if e["type"] == "cost"):
            self.assertEqual((c["basis"], c["runId"]), ("replayed", rp.run_id))
            self.assertIn(c["replayOf"], {x["id"] for x in live_costs})

    def test_CONTROL_concurrent_live_calls_respect_run_ceiling(self):
        n = 12
        budget = dict(H.BUDGET, maxUsdMicros=RESERVE * 5, verifyReserveBp=0)
        gw = self.live(H.script(*(H.entry(ordinal=i, response=H.response()) for i in range(n))), budget=budget)
        res = [None] * n
        ts = [threading.Thread(target=lambda i=i: res.__setitem__(i, inv_call(gw, i))) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(r.ok for r in res), 5)
        load_trace(self.finish(gw))


if __name__ == "__main__":
    unittest.main()
