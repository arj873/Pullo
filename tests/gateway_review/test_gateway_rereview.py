"""Independent RE-review tests for S0-05 after the GW1-GW10 corrections. Reviewer-owned, offline, stdlib only.

Unlike test_gateway_review.py this file does NOT use the author's Env.live()/Env.replayer(): those auto-inject
a SpendBook and learn/pin the trace digest, which can hide a missing-book or missing-pin defect. Here every
Gateway is built directly. The pin is ALWAYS computed independently with hashlib over the bytes of the file as
the recorder wrote it, before any tampering, and is passed explicitly. Only pure data builders are reused
from tests/gateway/helpers.py (request/response/script/entry/terr/profile).

`test_NEWn_*` asserts the CORRECT behaviour: FAIL = a reproduced remaining defect (ids in
handoffs/S0-05-rereview.md). Every other test is an independent control that passes today.

Run: nice -n 19 python3 -m unittest discover -s tests/gateway_review -v
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reviewer.contracts import ContractViolation, loads_strict  # noqa: E402,F401
from reviewer.contracts.canonical import call_id, idempotency_key_eval, run_id  # noqa: E402
from reviewer.gateway import (AuthorizationError, Gateway, GatewayConfigError, Recorder, SpendBook,  # noqa: E402
                              TraceError, default_providers, load_trace, trusted_authorization)
from reviewer.gateway.errors import SettlementError  # noqa: E402
from reviewer.gateway.providers import ProviderResult  # noqa: E402
from tests.gateway import helpers as H  # noqa: E402

INV = ("INVESTIGATE", "investigator", "generalist")
RESERVE = 60_668                      # reservation of H.request() under the smoke profile (observed)
NOW = H.NOW


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def ser(events) -> bytes:
    """Same line format the Recorder writes, produced here independently."""
    return "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in events).encode()


def rundoc(n, mode="live", auth_digest=None, replay_of=None):
    """Distinct run per n (distinct evalCaseId -> distinct idempotency key -> distinct run id)."""
    evr = H.EVR
    key = idempotency_key_eval(evr, f"case-{n}", 0, H.BASE_SNAP, H.HEAD_SNAP)
    d = H.run_doc("live", auth_digest=auth_digest)
    d.update(evalCaseId=f"case-{n}", idempotencyKey=key, id=run_id(key, 1), mode=mode)
    if mode == "live":
        d["spendAuthorization"] = auth_digest
        d.pop("replayOf", None)
    else:
        d.pop("spendAuthorization", None)
        d["replayOf"] = replay_of
    return d


def inv_out(n):
    """A schema-valid InvestigatorOutput whose single hypothesis claim is `claim <n>` (GW-02-review: D3 validates ok output)."""
    return {"hypotheses": [{"claim": f"claim {n}", "category": "bug", "suspectedSeverity": "P1", "impact": "crash",
                            "location": {"path": f"src/f{n}.py", "line": n + 1},
                            "evidence": [{"kind": "tool-ref", "toolCallId": "tool_" + "1" * 16}]}]}


class Direct(unittest.TestCase):
    """Direct constructors. No author Env, no auto book, no auto pin."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        (self.tmp / "operator").mkdir()
        self.n = 0

    # -- construction -------------------------------------------------------------
    def handle(self, **over):
        p = self.tmp / "operator" / f"auth-{len(list((self.tmp / 'operator').iterdir()))}.json"
        p.write_text(json.dumps({**H.AUTH_DOC, **over}))
        return trusted_authorization(p)

    def mk(self, providers, *, book, handle, n=None, budget=None, prof=None, start=True, path=True, clock=None,
           recorder=None, **kw):
        """Explicit live gateway. `book` is REQUIRED here on purpose; nothing is injected."""
        if n is None:
            self.n += 1
            n = self.n
        rd = rundoc(n, auth_digest=handle.digest)
        tpath = self.tmp / f"trace-{n}.jsonl" if path else None
        rec = recorder or Recorder(rd["id"], tpath)
        if start:
            rec.start(rd)
        gw = Gateway(mode="live", profile=prof or H.PROFILE, budget=budget or H.BUDGET, run_id=rd["id"],
                     providers=providers, authorization=handle, book=book, recorder=rec,
                     clock=clock or (lambda: NOW), **kw)
        gw.rd, gw.path = rd, tpath
        self.addCleanup(rec.close)
        return gw

    def synth(self, *entries):
        return default_providers(H.script(*entries))

    def seal(self, gw):
        """End the run and return (events, pin) where pin = sha256 of the file bytes the recorder wrote."""
        gw.recorder.end("completed")
        data = gw.path.read_bytes()
        return gw.recorder.events, sha(data)

    def replay(self, source, pin, *, budget=None, prof=None, start=True, **kw):
        tr = load_trace(source)
        rd = rundoc(9000, mode="strict-replay", replay_of=tr.run_id)
        rec = Recorder(rd["id"])
        if start:
            rec.start(rd)
        gw = Gateway(mode="strict-replay", profile=prof or H.PROFILE, budget=budget or H.BUDGET, run_id=rd["id"],
                     replay=tr, recorder=rec, expected_trace_digest=pin, **kw)
        gw.rd = rd
        return gw

    def one_call_trace(self, entry=None):
        h = self.handle()
        gw = self.mk(self.synth(entry or H.entry(response=H.response())), book=SpendBook(h), handle=h)
        gw.call(*INV, 0, H.request())
        events, pin = self.seal(gw)
        return gw, events, pin

    def tampered_file(self, name, events):
        p = self.tmp / name
        p.write_bytes(ser(events))
        return p


# ===================================================================== GW1: explicit shared book
class MissingBook(Direct):
    def test_live_without_book_is_refused_and_nothing_is_built(self):
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        provs = self.synth(H.entry(response=H.response()))
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                    authorization=h, recorder=rec, clock=lambda: NOW)
        self.assertEqual(provs["synthetic"].calls, 0)

    def test_live_with_explicit_none_or_non_book_is_refused(self):
        h = self.handle()
        for bad in (None, {}, object(), "book", SpendBook):
            with self.subTest(book=repr(bad)[:30]), self.assertRaises(GatewayConfigError):
                self.mk(self.synth(), book=bad, handle=h, path=False)

    def test_book_of_another_authorization_is_refused(self):
        a, b = self.handle(), self.handle(id="other-authorization")
        with self.assertRaises(AuthorizationError):
            self.mk(self.synth(), book=SpendBook(b), handle=a, path=False)


# ===================================================================== GW1: shared cross-run caps
class SharedCaps(Direct):
    def _three_runs(self, books, h, budget):
        outs, provs = [], []
        for i, book in enumerate(books):
            p = self.synth(H.entry(response=H.response()))
            gw = self.mk(p, book=book, handle=h, n=100 + i, budget=budget)
            outs.append(gw.call(*INV, 0, H.request()))
            provs.append(p["synthetic"])
            gw.recorder.end("completed")
        return outs, provs

    def test_one_in_memory_book_caps_the_total_over_three_runs(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        book = SpendBook(h)
        budget = dict(H.BUDGET, maxUsdMicros=100_000)
        outs, provs = self._three_runs([book] * 3, h, budget)
        self.assertEqual([o.ok for o in outs], [True, False, False])
        self.assertEqual([o.error["detail"]["scope"] for o in outs[1:]], ["total", "total"])
        self.assertEqual(sum(p.calls for p in provs), 1, "a refused run must not contact the provider")
        t = book.totals()
        self.assertLessEqual(t["committed"] + t["inflight"], 100_000)
        self.assertEqual(t["inflight"], 0)

    def test_file_book_shared_by_separate_book_objects_caps_the_total(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        store = self.tmp / "total.jsonl"
        budget = dict(H.BUDGET, maxUsdMicros=100_000)
        outs, provs = self._three_runs([SpendBook(h, store=store) for _ in range(3)], h, budget)
        self.assertEqual([o.ok for o in outs], [True, False, False])
        self.assertEqual(sum(p.calls for p in provs), 1)

    def test_continued_evaluation_after_restart_sees_earlier_spend(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        store = self.tmp / "restart.jsonl"
        budget = dict(H.BUDGET, maxUsdMicros=100_000)
        first = self.mk(self.synth(H.entry(response=H.response())), book=SpendBook(h, store=store), handle=h, n=1,
                        budget=budget)
        self.assertTrue(first.call(*INV, 0, H.request()).ok)
        del first
        again = self.mk(self.synth(H.entry(response=H.response())), book=SpendBook(h, store=store), handle=h, n=2,
                        budget=budget)
        self.assertEqual(again.call(*INV, 0, H.request()).error["code"], "budget-exhausted")

    def test_book_refusal_does_not_leak_run_reservation(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        book, budget = SpendBook(h), dict(H.BUDGET, maxUsdMicros=100_000)
        self.mk(self.synth(H.entry(response=H.response())), book=book, handle=h, n=1,
                budget=budget).call(*INV, 0, H.request())
        gw = self.mk(self.synth(H.entry(response=H.response())), book=book, handle=h, n=2, budget=budget)
        self.assertEqual(gw.call(*INV, 0, H.request()).error["detail"]["scope"], "total")
        sp = gw.report()["spend"]
        self.assertEqual((sp["committed"], sp["inflight"]), (0, 0))


# ===================================================================== GW3: external pin, edits, completeness
class Pin(Direct):
    def test_missing_or_malformed_pin_is_refused(self):
        _, events, pin = self.one_call_trace()
        tr = load_trace(events)
        rd = rundoc(9001, mode="strict-replay", replay_of=tr.run_id)
        base = dict(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr)
        bad = [("absent", {}), ("none", {"expected_trace_digest": None}), ("empty", {"expected_trace_digest": ""}),
               ("noprefix", {"expected_trace_digest": pin[7:]}), ("upper", {"expected_trace_digest": pin.upper()}),
               ("short", {"expected_trace_digest": pin[:-1]}), ("bytes", {"expected_trace_digest": pin.encode()}),
               ("padded", {"expected_trace_digest": pin + "\n"})]
        for name, extra in bad:
            with self.subTest(pin=name), self.assertRaises(GatewayConfigError):
                Gateway(**base, **extra)
        Gateway(**base, expected_trace_digest=pin)            # the real pin is accepted

    def test_wrong_but_wellformed_pin_is_trace_error(self):
        _, events, pin = self.one_call_trace()
        wrong = "sha256:" + ("0" * 64)
        self.assertNotEqual(wrong, pin)
        with self.assertRaises(TraceError):
            self.replay(events, wrong)

    def test_pin_only_for_strict_replay(self):
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"],
                    providers=self.synth(), authorization=h, book=SpendBook(h), expected_trace_digest="sha256:" + "1" * 64)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="disabled", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"],
                    expected_trace_digest="sha256:" + "1" * 64)

    def test_recorder_digest_equals_independent_hash_of_file_and_loaded_digest(self):
        gw, events, pin = self.one_call_trace()
        self.assertEqual(gw.recorder.trace_digest(), pin)
        self.assertEqual(load_trace(gw.path).byte_digest, pin)
        self.assertEqual(load_trace(gw.path.read_bytes()).byte_digest, pin)
        self.assertEqual(load_trace(events).byte_digest, pin)

    def test_genuine_trace_replays_with_original_pin(self):
        gw, events, pin = self.one_call_trace()
        rp = self.replay(gw.path, pin)
        r = rp.call(*INV, 0, H.request())
        self.assertTrue(r.ok)
        self.assertEqual((rp.report()["liveCalls"], rp.unconsumed()), (0, 0))

    def test_edited_response_in_file_is_rejected_by_the_original_pin(self):
        gw, events, pin = self.one_call_trace(H.entry(response=H.response(output={"hypotheses": []})))
        forged = copy.deepcopy(events)
        for e in forged:
            if e["type"] == "model.call":
                e["response"]["output"] = {"hypotheses": "FORGED"}
        p = self.tampered_file("forged.jsonl", forged)
        tr = load_trace(p)                       # internally consistent: hashes alone cannot see this edit
        self.assertNotEqual(tr.byte_digest, pin)
        with self.assertRaises(TraceError):
            self.replay(p, pin)                  # the ORIGINAL pin (from record time) is what catches it

    def test_edited_response_consistent_with_edited_cost_is_also_rejected(self):
        gw, events, pin = self.one_call_trace()
        forged = copy.deepcopy(events)
        use = {"uncachedInputTokens": 1, "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
               "outputTokens": 1, "reasoningTokens": 0}
        for e in forged:
            if e["type"] == "model.call":
                e["response"]["usage"] = use
            elif e["type"] == "cost":
                e["record"]["usage"] = use
                e["record"]["usdMicros"] = 1
        p = self.tampered_file("forged2.jsonl", forged)
        load_trace(p)                            # self-consistent as far as shape goes (charge recompute is replay-side)
        with self.assertRaises(TraceError):
            self.replay(p, pin)

    def test_whitespace_or_key_order_only_edit_changes_bytes_and_is_rejected(self):
        gw, events, pin = self.one_call_trace()
        text = gw.path.read_bytes().decode()
        p = self.tmp / "ws.jsonl"
        p.write_bytes(text.replace('"schema": "trace-event@1"', '"schema":"trace-event@1"').replace(",", ", ", 1).encode())
        if p.read_bytes() == gw.path.read_bytes():
            self.skipTest("recorder writes compact separators already")
        with self.assertRaises(TraceError):
            self.replay(p, pin)

    def test_deleted_call_cost_pair_with_renumbered_seq_is_rejected_by_pin(self):
        h = self.handle()
        gw = self.mk(self.synth(H.entry(response=H.response()), H.entry(ordinal=1, response=H.response())),
                     book=SpendBook(h), handle=h)
        gw.call(*INV, 0, H.request())
        gw.call(*INV, 1, H.request(text="second"))
        events, pin = self.seal(gw)
        cut = [e for e in copy.deepcopy(events) if not (e["type"] in ("model.call", "cost") and
                                                         (e.get("ordinal") == 1 or e.get("record", {}).get("callId") ==
                                                          call_id(*INV, 1, 0)))]
        for i, e in enumerate(cut):
            e["seq"] = i
        p = self.tampered_file("cut.jsonl", cut)
        load_trace(p)                            # loads: shape cannot tell (this is why the pin exists)
        with self.assertRaises(TraceError):
            self.replay(p, pin)

    def test_CONTROL_deliberate_trusted_edited_trace_with_explicit_repin(self):
        """A caller who CHOOSES to trust an edited trace re-pins it explicitly. This documents that the pin is
        equality with a trusted value only (and that a pin learned from the edited file would always match).
        GW-02-review: the edit was {"hypotheses": "TRUSTED-EDIT"} (schema-invalid under D3); it is now a different
        schema-valid answer, so the repinned edit is actually SERVED rather than refused by local validation."""
        gw, events, pin = self.one_call_trace(H.entry(response=H.response(output=inv_out(1))))
        edited = copy.deepcopy(events)
        for e in edited:
            if e["type"] == "model.call":
                e["response"]["output"] = inv_out(9)
        p = self.tampered_file("trusted-edit.jsonl", edited)
        with self.assertRaises(TraceError):
            self.replay(p, pin)
        repin = sha(p.read_bytes())              # explicit operator decision, not derived inside a replay check
        self.assertNotEqual(repin, pin)
        r = self.replay(p, repin).call(*INV, 0, H.request())
        self.assertEqual(r.output, inv_out(9))
        self.assertEqual(self.replay(gw.path, pin).call(*INV, 0, H.request()).output, inv_out(1))

    def test_CONTROL_stale_request_hash_edit_rejected_then_repinned_edit_misses(self):
        """Adapted from Controls.test_CONTROL_request_edit_...: the original pin rejects the edited bytes; only an
        explicit repin of the recomputed-hash edit reaches the request-hash miss."""
        from reviewer.contracts.canonical import request_hash
        gw, events, pin = self.one_call_trace()
        stale = copy.deepcopy(events)
        for e in stale:
            if e["type"] == "model.call":
                e["request"]["messages"][1]["content"] += " "
        with self.assertRaises(TraceError):
            load_trace(stale)
        fixed = copy.deepcopy(stale)
        for e in fixed:
            if e["type"] == "model.call":
                e["requestHash"] = request_hash(e["request"])
        p = self.tampered_file("fixed.jsonl", fixed)
        with self.assertRaises(TraceError):
            self.replay(p, pin)
        r = self.replay(p, sha(p.read_bytes())).call(*INV, 0, H.request())
        self.assertEqual(r.error["code"], "replay-miss")


class Incomplete(Direct):
    def _two_call_run(self):
        h = self.handle()
        gw = self.mk(self.synth(H.entry(response=H.response()), H.entry(ordinal=1, response=H.response())),
                     book=SpendBook(h), handle=h)
        gw.call(*INV, 0, H.request())
        gw.call(*INV, 1, H.request(text="second"))
        events, pin = self.seal(gw)
        return gw, events, pin

    def test_prefix_without_run_end_is_refused_by_default_for_every_source(self):
        gw, events, pin = self._two_call_run()
        raw = gw.path.read_bytes()
        lines = raw.decode().splitlines(keepends=True)
        for cut in (2, 3, len(lines) - 1):
            prefix = "".join(lines[:cut]).encode()
            with self.subTest(cut=cut):
                with self.assertRaises(TraceError):
                    load_trace(events[:cut])
                with self.assertRaises(TraceError):
                    load_trace(prefix)
                pp = self.tmp / f"prefix-{cut}.jsonl"
                pp.write_bytes(prefix)
                with self.assertRaises(TraceError):
                    load_trace(pp)

    def test_explicit_partial_load_is_flagged_and_strict_replay_refuses_it_even_with_its_own_pin(self):
        gw, events, pin = self._two_call_run()
        lines = gw.path.read_bytes().decode().splitlines(keepends=True)
        prefix = "".join(lines[:-1]).encode()
        tr = load_trace(prefix, allow_partial=True)
        self.assertFalse(tr.complete)
        self.assertTrue(load_trace(gw.path).complete)
        rd = rundoc(9002, mode="strict-replay", replay_of=tr.run_id)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                    expected_trace_digest=sha(prefix))

    def test_run_end_not_last_or_duplicated_does_not_load(self):
        gw, events, pin = self._two_call_run()
        extra = copy.deepcopy(events)
        end = copy.deepcopy(extra[-1])
        end["seq"] = len(extra)
        with self.assertRaises(TraceError):
            load_trace(extra + [end])                    # two run.end
        tail = copy.deepcopy(events[1])
        tail["seq"] = len(extra)
        with self.assertRaises(TraceError):
            load_trace(extra + [tail])                   # event after run.end

    def test_stripped_run_end_with_repinned_partial_still_refused(self):
        gw, events, pin = self._two_call_run()
        p = self.tampered_file("noend.jsonl", events[:-1])
        with self.assertRaises(TraceError):
            self.replay(p, sha(p.read_bytes()))


# ===================================================================== GW6: processed-call evidence on settlement error
class _Corrupting:
    name = "synthetic"

    def __init__(self, store, make):
        self.store, self.make, self.calls = store, make, 0

    def call(self, req, key):
        self.calls += 1
        with open(self.store, "a") as f:
            f.write("{torn")                       # a dead concurrent writer / disk error
        return self.make()


class SettlementEvidence(Direct):
    def _run(self, make, expect_usd):
        h = self.handle()
        store = self.tmp / "spend.jsonl"
        prov = _Corrupting(store, make)
        gw = self.mk({"synthetic": prov}, book=SpendBook(h, store=store), handle=h)
        with self.assertRaises(SettlementError):
            gw.call(*INV, 0, H.request())
        types = [e["type"] for e in gw.recorder.events]
        self.assertEqual(types, ["run.start", "model.call", "cost", "error"])
        cost = gw.recorder.events[2]["record"]
        self.assertEqual(cost["usdMicros"], expect_usd)
        self.assertEqual(gw.recorder.events[3]["error"]["code"], "internal")
        self.assertEqual(gw.recorder.events[3]["error"]["detail"]["callId"], gw.recorder.events[1]["callId"])
        self.assertEqual(vars(gw._ledger.spend())["inflight"], 0, "run ledger must be closed even when the book failed")
        self.assertEqual((prov.calls, gw.live_calls), (1, 1))
        events, pin = self.seal(gw)
        tr = load_trace(gw.path)                   # the evidence is a loadable, pinnable, replayable trace
        self.assertEqual(tr.byte_digest, pin)
        return gw, events, pin

    def test_response_commit_failure_keeps_model_call_and_charge(self):
        self._run(lambda: ProviderResult(H.response(), None, "processed"), RESERVE)

    def test_released_error_failure_keeps_model_call(self):
        self._run(lambda: ProviderResult(None, H.terr("provider-error", False, outcome="not-sent"), "not-sent"), 0)

    def test_retained_error_failure_keeps_model_call_and_full_charge(self):
        gw, _, _ = self._run(lambda: ProviderResult(None, H.terr("provider-timeout", False), "unknown"), RESERVE)
        self.assertEqual(len(gw.retained), 1)

    def test_wrong_model_billed_failure_keeps_usage(self):
        self._billed()

    def _billed(self):
        h = self.handle()
        store = self.tmp / "spend2.jsonl"
        use = {"uncachedInputTokens": 5, "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
               "outputTokens": 7, "reasoningTokens": 0}
        prov = _Corrupting(store, lambda: ProviderResult(H.response(resolvedModel="other-model", usage=use),
                                                         None, "processed"))
        gw = self.mk({"synthetic": prov}, book=SpendBook(h, store=store), handle=h)
        with self.assertRaises(SettlementError):
            gw.call(*INV, 0, H.request())
        call, cost = gw.recorder.events[1], gw.recorder.events[2]["record"]
        self.assertEqual(call["error"]["code"], "contract-violation")
        self.assertEqual(cost["usage"], use)
        self.assertLess(cost["usdMicros"], RESERVE)
        gw.recorder.end("completed")
        load_trace(gw.path)

    def test_reservation_time_book_failure_never_contacts_the_provider_and_frees_the_run_ledger(self):
        h = self.handle()
        store = self.tmp / "bad.jsonl"
        book = SpendBook(h, store=store)
        book.reserve("seed", 1)
        store.write_text(store.read_text() + "{torn")
        prov = _Corrupting(store, lambda: ProviderResult(H.response(), None, "processed"))
        gw = self.mk({"synthetic": prov}, book=book, handle=h)
        with self.assertRaises(ValueError):
            gw.call(*INV, 0, H.request())
        self.assertEqual(prov.calls, 0)
        self.assertEqual(vars(gw._ledger.spend())["inflight"], 0)


# ===================================================================== GW5: binding on every attempt
class _Mutating:
    """Provider whose first answer rewrites the recorder's run.start (simulates a binding that stops holding
    between attempts) and returns a retryable timeout."""
    name = "synthetic"

    def __init__(self, rec, result_first, then):
        self.rec, self.first, self.then, self.calls = rec, result_first, then, 0

    def call(self, req, key):
        self.calls += 1
        if self.calls == 1:
            self.rec.events[0]["run"]["spendAuthorization"] = "sha256:" + "9" * 64
            return self.first
        return self.then


class Binding(Direct):
    def test_run_start_written_after_construction_naming_another_authorization_admits_nothing(self):
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = rundoc(1, auth_digest=other.digest)
        rec = Recorder(rd["id"])
        provs = self.synth(H.entry(response=H.response()))
        gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                     authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        rec.start(rd)
        r = gw.call(*INV, 0, H.request())
        self.assertEqual((r.ok, r.error["code"], provs["synthetic"].calls), (False, "contract-violation", 0))
        # GW-02 (NEW6): was ["run.start", "error"]; a binding refusal must not write into the misbound recorder
        self.assertEqual([e["type"] for e in rec.events], ["run.start"])
        self.assertEqual(gw.book.totals()["committed"] + gw.book.totals()["inflight"], 0)
        self.assertEqual((gw.report()["liveCalls"], gw.report()["newSpendUsdMicros"]), (0, 0))
        rec.events[0]["run"]["spendAuthorization"] = h.digest      # binding repaired in memory
        self.assertTrue(gw.call(*INV, 0, H.request()).ok, "the refused attempt consumed the coordinate")
        self.assertEqual(provs["synthetic"].calls, 1)

    def test_recorder_without_run_start_admits_nothing_and_appends_nothing(self):
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        rec = Recorder(rd["id"])
        provs = self.synth(H.entry(response=H.response()))
        gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                     authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        r = gw.call(*INV, 0, H.request())
        self.assertEqual((r.error["code"], provs["synthetic"].calls, rec.events), ("contract-violation", 0, []))

    def test_run_start_variants_are_refused(self):
        h = self.handle()
        variants = {
            "no spendAuthorization": lambda d: d.pop("spendAuthorization"),
            "replay mode": lambda d: d.update(mode="strict-replay", replayOf="run_" + "a" * 16) or d.pop("spendAuthorization"),
            "other run id inside run.start": lambda d: d.update(id="run_" + "d" * 16),
        }
        for name, edit in variants.items():
            with self.subTest(variant=name):
                rd = rundoc(1, auth_digest=h.digest)
                rec = Recorder(rd["id"])
                bad = copy.deepcopy(rd)
                edit(bad)
                try:
                    rec.start(bad)
                except Exception:      # noqa: BLE001 - contract refuses the event: equally acceptable
                    continue
                provs = self.synth(H.entry(response=H.response()))
                try:
                    gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                                 authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
                except GatewayConfigError:
                    continue
                self.assertFalse(gw.call(*INV, 0, H.request()).ok)
                self.assertEqual(provs["synthetic"].calls, 0)

    def test_recorder_run_id_mismatch_refused_in_live_and_replay(self):
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        other = Recorder("run_" + "f" * 16)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=self.synth(),
                    authorization=h, book=SpendBook(h), recorder=other)
        _, events, pin = self.one_call_trace()
        tr = load_trace(events)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rundoc(9003, "strict-replay",
                    replay_of=tr.run_id)["id"], replay=tr, recorder=other, expected_trace_digest=pin)

    def test_binding_is_rechecked_on_the_repair_attempt(self):
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        prov = _Mutating(rec, ProviderResult(H.response(status="invalid-output"), None, "processed"),
                         ProviderResult(H.response(), None, "processed"))
        gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers={"synthetic": prov},
                     authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        r = gw.call(*INV, 0, H.request(), repair=lambda resp: H.request(text="repair"))
        self.assertEqual(prov.calls, 1, "repair attempt was admitted under a broken binding")
        self.assertEqual(r.error["code"], "contract-violation")

    def test_binding_is_rechecked_on_the_retry_attempt(self):
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        rec = Recorder(rd["id"])
        rec.start(rd)
        prov = _Mutating(rec, ProviderResult(None, H.terr("provider-timeout", True), "unknown"),
                         ProviderResult(H.response(), None, "processed"))
        gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers={"synthetic": prov},
                     authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        r = gw.call(*INV, 0, H.request())
        self.assertEqual(prov.calls, 1, "retry attempt was admitted under a broken binding")
        self.assertEqual(r.error["code"], "contract-violation")

    def test_replay_recorder_without_run_start_consumes_nothing(self):
        _, events, pin = self.one_call_trace()
        rp = self.replay(events, pin, start=False)
        r = rp.call(*INV, 0, H.request())
        self.assertEqual((r.error["code"], rp.unconsumed(), rp.recorder.events), ("contract-violation", 1, []))
        rd = rp.rd
        rp.recorder.start(rd)
        self.assertTrue(rp.call(*INV, 0, H.request()).ok)       # the same occurrence is still available

    def test_replay_gateway_with_a_live_run_start_is_refused_at_construction(self):
        _, events, pin = self.one_call_trace()
        tr = load_trace(events)
        rd = rundoc(9004, auth_digest="sha256:" + "1" * 64)      # a live run doc on a replay gateway
        rec = Recorder(rd["id"])
        rec.start(rd)
        with self.assertRaises(GatewayConfigError):
            Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                    recorder=rec, expected_trace_digest=pin)


# ===================================================================== GW2: errored-call charge recomputation
def _usage(i=5, o=7):
    return {"uncachedInputTokens": i, "cachedInputTokens": 0, "cacheWriteInputTokens": 0,
            "outputTokens": o, "reasoningTokens": 0}


ERR_CASES = {
    "timeout-retained": (H.entry(error=H.terr("provider-timeout", False)), None, RESERVE),
    "provider-error-not-sent-released": (H.entry(error=H.terr("provider-error", False, outcome="not-sent")), None, 0),
    "provider-error-rejected-released": (
        H.entry(error=H.terr("provider-error", False, outcome="rejected-before-processing")), None, 0),
    "provider-error-processed-retained": (H.entry(error=H.terr("provider-error", False, outcome="processed")), None, RESERVE),
    "internal-claims-not-sent-retained": (H.entry(error=H.terr("internal", False, outcome="not-sent")), None, RESERVE),
    "wrong-model-billed": (H.entry(response=H.response(resolvedModel="other-model", usage=_usage())), None, "billed"),
}


class ErrorCharge(Direct):
    def _record(self, entry):
        h = self.handle()
        gw = self.mk(self.synth(entry), book=SpendBook(h), handle=h)
        r = gw.call(*INV, 0, H.request())
        events, pin = self.seal(gw)
        return gw, r, events, pin

    def test_live_and_replay_charge_the_same_amount_for_every_error_class(self):
        for name, (entry, _, want) in ERR_CASES.items():
            with self.subTest(case=name):
                gw, r, events, pin = self._record(entry)
                live = r.attempts[0].charge_usd_micros
                if want == "billed":
                    self.assertLess(live, RESERVE)
                else:
                    self.assertEqual(live, want)
                rp = self.replay(gw.path, pin)
                r2 = rp.call(*INV, 0, H.request())
                self.assertEqual(r2.error["code"], r.error["code"])
                self.assertEqual(r2.attempts[0].charge_usd_micros, live)
                self.assertEqual(rp.report()["retainedCalls"] != [], gw.report()["retainedCalls"] != [])
                self.assertEqual(rp.report()["replayedUsdMicros"], live)
                self.assertEqual((rp.report()["replayedCalls"], rp.unconsumed()), (1, 0))

    def _repinned(self, events, edit, name="edit.jsonl"):
        bad = copy.deepcopy(events)
        edit(bad)
        return self.tampered_file(name, bad)

    def test_retained_error_with_zero_cost_is_rejected_even_when_the_edit_is_repinned(self):
        gw, r, events, pin = self._record(H.entry(error=H.terr("provider-timeout", False)))
        def zero(evs):
            for e in evs:
                if e["type"] == "cost":
                    e["record"]["usdMicros"] = 0
        p = self._repinned(events, zero)
        with self.assertRaises(TraceError):
            load_trace(p)                         # fails before any pin question: charge class is recomputed on load

    def test_released_error_with_full_cost_is_rejected_even_when_repinned(self):
        gw, r, events, pin = self._record(H.entry(error=H.terr("provider-error", False, outcome="not-sent")))
        def full(evs):
            for e in evs:
                if e["type"] == "cost":
                    e["record"]["usdMicros"] = e["record"]["reservedUsdMicros"]
        with self.assertRaises(TraceError):
            load_trace(self._repinned(events, full))

    def test_stripped_provider_outcome_cannot_turn_a_release_into_zero_charge(self):
        gw, r, events, pin = self._record(H.entry(error=H.terr("provider-error", False, outcome="not-sent")))
        def strip(evs):
            for e in evs:
                if e["type"] == "model.call":
                    e["error"]["detail"].pop("providerOutcome")
        with self.assertRaises(TraceError):
            load_trace(self._repinned(events, strip))        # no stamp = retained = must carry the full reservation

    def test_unknown_cost_none_on_retained_replays_as_the_full_reservation(self):
        gw, r, events, pin = self._record(H.entry(error=H.terr("provider-timeout", False)))
        def none(evs):
            for e in evs:
                if e["type"] == "cost":
                    e["record"]["usdMicros"] = None
        p = self._repinned(events, none)
        r2 = self.replay(p, sha(p.read_bytes())).call(*INV, 0, H.request())
        self.assertEqual(r2.attempts[0].charge_usd_micros, RESERVE)

    def test_billed_wrong_model_charge_is_recomputed_from_recorded_usage(self):
        gw, r, events, pin = self._record(H.entry(response=H.response(resolvedModel="other-model", usage=_usage())))
        def zero_charge(evs):
            for e in evs:
                if e["type"] == "cost":
                    e["record"]["usdMicros"] = 0
        p = self._repinned(events, zero_charge)
        load_trace(p)
        r2 = self.replay(p, sha(p.read_bytes())).call(*INV, 0, H.request())
        self.assertEqual(r2.error["code"], "replay-mismatch")
        def more_usage(evs):
            for e in evs:
                if e["type"] == "cost":
                    e["record"]["usage"] = _usage(500, 700)
        p2 = self._repinned(events, more_usage, "usage.jsonl")
        r3 = self.replay(p2, sha(p2.read_bytes())).call(*INV, 0, H.request())
        self.assertEqual(r3.error["code"], "replay-mismatch")


# ===================================================================== GW7/GW8: total refusals, replay counting
class TotalRefusals(Direct):
    def _recorded_total_refusal(self):
        h = self.handle(maxUsdMicrosTotal=100_000, maxUsdMicrosPerRun=100_000)
        book, budget = SpendBook(h), dict(H.BUDGET, maxUsdMicros=100_000)
        self.mk(self.synth(H.entry(response=H.response())), book=book, handle=h, n=1,
                budget=budget).call(*INV, 0, H.request())
        gw = self.mk(self.synth(H.entry(response=H.response())), book=book, handle=h, n=2, budget=budget)
        r = gw.call(*INV, 0, H.request())
        self.assertEqual(r.error["detail"]["scope"], "total")
        events, pin = self.seal(gw)
        return gw, events, pin, budget

    def test_total_refusal_reproduces_truthfully_and_charges_nothing(self):
        gw, events, pin, budget = self._recorded_total_refusal()
        rp = self.replay(gw.path, pin, budget=budget)
        r = rp.call(*INV, 0, H.request())
        self.assertEqual((r.error["code"], r.error["detail"]["scope"]), ("budget-exhausted", "total"))
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["replayedUsdMicros"], rp.unconsumed()), (1, 0, 0))
        self.assertEqual((rep["spend"]["committed"], rep["spend"]["inflight"]), (0, 0))

    def test_total_refusal_is_a_mismatch_when_the_run_ledger_alone_would_refuse(self):
        gw, events, pin, _ = self._recorded_total_refusal()
        tight = dict(H.BUDGET, maxUsdMicros=30_000, verifyReserveBp=0)
        rp = self.replay(gw.path, pin, budget=tight)
        r = rp.call(*INV, 0, H.request())
        self.assertEqual(r.error["code"], "replay-mismatch")
        rep = rp.report()
        self.assertEqual((rep["replayedCalls"], rep["replayedUsdMicros"], rp.unconsumed()), (0, 0, 1))

    def test_run_scope_refusal_reproduces_only_under_a_run_refusal(self):
        h = self.handle()
        tight = dict(H.BUDGET, maxUsdMicros=30_000, verifyReserveBp=0)
        gw = self.mk(self.synth(H.entry(response=H.response())), book=SpendBook(h), handle=h, budget=tight)
        r = gw.call(*INV, 0, H.request())
        self.assertEqual(r.error["detail"]["scope"], "run")
        events, pin = self.seal(gw)
        same = self.replay(gw.path, pin, budget=tight).call(*INV, 0, H.request())
        self.assertEqual(same.error["code"], "budget-exhausted")
        roomy = self.replay(gw.path, pin).call(*INV, 0, H.request())      # standard budget would have admitted it
        self.assertEqual(roomy.error["code"], "replay-mismatch")

    def test_mismatches_are_not_counted_and_leave_the_occurrence_replayable(self):
        gw, events, pin = self.one_call_trace()
        drift = H.profile(investigator={"caps": {**H.PROFILE["roles"]["investigator"]["caps"], "maxOutputTokens": 3999}})
        rp = self.replay(gw.path, pin, prof=drift)
        req = H.request(params=H.PROFILE["roles"]["investigator"]["params"])
        self.assertEqual(rp.call(*INV, 0, req).error["code"], "replay-mismatch")
        self.assertEqual((rp.report()["replayedCalls"], rp.report()["replayedUsdMicros"], rp.unconsumed()), (0, 0, 1))


# ===================================================================== GW4: duplicate call identity
class DuplicateIdentity(Direct):
    def test_reused_coordinates_are_refused_before_the_provider_and_the_trace_stays_loadable(self):
        h = self.handle()
        provs = self.synth(H.entry(response=H.response()))
        gw = self.mk(provs, book=SpendBook(h), handle=h)
        self.assertTrue(gw.call(*INV, 0, H.request()).ok)
        second = gw.call(*INV, 0, H.request(text="a different prompt"))
        self.assertEqual((second.ok, second.error["code"], provs["synthetic"].calls), (False, "contract-violation", 1))
        events, pin = self.seal(gw)
        self.assertEqual(sum(e["type"] == "model.call" for e in events), 1)
        self.assertEqual(sum(e["type"] == "error" for e in events), 1)
        self.assertEqual(load_trace(gw.path).byte_digest, pin)
        self.assertEqual(gw.report()["spend"]["committed"], RESERVE)       # nothing charged for the refused reuse

    def test_reuse_after_a_retry_chain_is_refused(self):
        h = self.handle()
        provs = self.synth(H.entry(error=H.terr()), H.entry(attempt=1, response=H.response()))
        gw = self.mk(provs, book=SpendBook(h), handle=h)
        self.assertTrue(gw.call(*INV, 0, H.request()).ok)
        self.assertEqual(provs["synthetic"].calls, 2)
        r = gw.call(*INV, 0, H.request(text="again"))
        self.assertEqual((r.error["code"], provs["synthetic"].calls), ("contract-violation", 2))

    def test_early_refusals_do_not_consume_the_identity(self):
        h = self.handle()
        gw = self.mk(self.synth(H.entry(response=H.response())), book=SpendBook(h), handle=h)
        bad = H.request()
        bad["profile"] = "someone-else@1"
        self.assertEqual(gw.call(*INV, 0, bad).error["code"], "contract-violation")
        self.assertTrue(gw.call(*INV, 0, H.request()).ok)

    def test_budget_refused_identity_is_consumed_because_it_was_recorded_as_a_model_call(self):
        h = self.handle()
        tight = dict(H.BUDGET, maxUsdMicros=30_000, verifyReserveBp=0)
        gw = self.mk(self.synth(H.entry(response=H.response())), book=SpendBook(h), handle=h, budget=tight)
        self.assertEqual(gw.call(*INV, 0, H.request()).error["code"], "budget-exhausted")
        again = gw.call(*INV, 0, H.request())
        self.assertEqual(again.error["code"], "contract-violation")
        gw.recorder.end("completed")
        load_trace(gw.path)

    def test_concurrent_reuse_admits_exactly_one(self):
        h = self.handle()
        provs = self.synth(H.entry(response=H.response()))
        gw = self.mk(provs, book=SpendBook(h), handle=h)
        out = [None] * 8
        ts = [threading.Thread(target=lambda i=i: out.__setitem__(i, gw.call(*INV, 0, H.request(text=f"t{i}"))))
              for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(o.ok for o in out), 1)
        self.assertEqual(provs["synthetic"].calls, 1)
        gw.recorder.end("completed")
        load_trace(gw.path)

    def test_replay_reuse_is_a_miss_not_a_second_serving(self):
        gw, events, pin = self.one_call_trace()
        rp = self.replay(gw.path, pin)
        self.assertTrue(rp.call(*INV, 0, H.request()).ok)
        again = rp.call(*INV, 0, H.request())
        self.assertEqual(again.error["code"], "replay-miss")
        self.assertEqual((rp.report()["replayedCalls"], rp.unconsumed()), (1, 0))


# ===================================================================== GW10: retry / repair provenance + complete trace
class Provenance(Direct):
    def _chain(self):
        h = self.handle()
        sc = self.synth(H.entry(attempt=0, error=H.terr()),
                        H.entry(attempt=1, response=H.response(status="invalid-output")),
                        H.entry(attempt=2, error=H.terr()),
                        H.entry(attempt=3, response=H.response()))
        gw = self.mk(sc, book=SpendBook(h), handle=h)
        r = gw.call(*INV, 0, H.request(), repair=lambda resp: H.request(text="repair"))
        self.assertTrue(r.ok)
        events, pin = self.seal(gw)
        return gw, r, events, pin

    def test_exact_provenance_of_retry_repair_retry(self):
        gw, r, events, pin = self._chain()
        calls = [e for e in events if e["type"] == "model.call"]
        costs = {e["record"]["callId"]: e["record"] for e in events if e["type"] == "cost"}
        ids = [c["callId"] for c in calls]
        self.assertEqual([c["attempt"] for c in calls], [0, 1, 2, 3])
        self.assertEqual([c.get("repairOf") for c in calls], [None, None, ids[1], None])
        self.assertEqual([costs[i].get("retryOf") for i in ids], [None, ids[0], None, ids[2]])

    def test_complete_trace_shape_and_replay_of_the_whole_chain(self):
        gw, r, events, pin = self._chain()
        self.assertEqual(events[0]["type"], "run.start")
        self.assertEqual(events[-1]["type"], "run.end")
        self.assertEqual([e["seq"] for e in events], list(range(len(events))))
        self.assertEqual(sum(e["type"] == "model.call" for e in events), sum(e["type"] == "cost" for e in events))
        self.assertEqual(sum(e["type"] == "model.call" for e in events), 4)
        rp = self.replay(gw.path, pin)
        r2 = rp.call(*INV, 0, H.request(), repair=lambda resp: H.request(text="repair"))
        self.assertTrue(r2.ok)
        self.assertEqual([a.attempt for a in r2.attempts], [0, 1, 2, 3])
        self.assertEqual((rp.report()["liveCalls"], rp.report()["replayedCalls"], rp.unconsumed()), (0, 4, 0))
        replay_costs = [e["record"] for e in rp.recorder.events if e["type"] == "cost"]
        self.assertEqual([c.get("retryOf") is not None for c in replay_costs], [False, True, False, True])
        self.assertTrue(all(c["basis"] == "replayed" for c in replay_costs))
        # the replay's own recording is complete, loadable and has its own externally computable digest
        rp.recorder.end("completed")
        self.assertEqual(rp.recorder.trace_digest(), sha(ser(rp.recorder.events)))
        self.assertTrue(load_trace(rp.recorder.events).complete)

    def test_provenance_drift_is_a_replay_mismatch_under_an_explicit_repin(self):
        gw, r, events, pin = self._chain()
        calls = [e for e in events if e["type"] == "model.call"]
        def drop_repair(evs):
            for e in evs:
                if e["type"] == "model.call" and e["attempt"] == 2:
                    e.pop("repairOf")
        def drop_retry(evs):
            for e in evs:
                if e["type"] == "cost" and e["record"].get("retryOf"):
                    e["record"].pop("retryOf")
        for name, fn in (("repairOf", drop_repair), ("retryOf", drop_retry)):
            with self.subTest(dropped=name):
                bad = copy.deepcopy(events)
                fn(bad)
                p = self.tampered_file(f"prov-{name}.jsonl", bad)
                rp = self.replay(p, sha(p.read_bytes()))
                out = rp.call(*INV, 0, H.request(), repair=lambda resp: H.request(text="repair"))
                self.assertEqual(out.error["code"], "replay-mismatch")
                self.assertEqual(calls[0]["attempt"], 0)


# ===================================================================== optional hypothesisId (concurrent contract work)
class HypothesisId(Direct):
    def _field_exists(self):
        from reviewer.contracts import require
        probe = H.request("verifier")
        probe["hypothesisId"] = "hyp_" + "1" * 16
        try:
            require("ModelRequest", probe)
            return True
        except ContractViolation:
            return False

    def test_verifier_subject_flows_into_the_hash_and_replay_when_the_contract_has_it(self):
        if not self._field_exists():
            self.skipTest("ModelRequest.hypothesisId not (yet) in the contract: observed, not a gateway defect")
        h = self.handle()
        stage, role = "VERIFY", "verifier"
        def req(hyp):
            r = H.request("verifier")
            if hyp:
                r["hypothesisId"] = hyp
            return r
        a, b = "hyp_" + "1" * 16, "hyp_" + "2" * 16
        # GW-02-review: scripted answers were {"hypotheses": []} (an investigator shape, schema-invalid for a verifier
        # under D3); they are now schema-valid VerifierOutput documents. Subject/hash/replay assertions unchanged.
        gw = self.mk(self.synth(H.entry(stage=stage, role=role, response=H.response(output=H.verifier_out())),
                                H.entry(stage=stage, role=role, agent="generalist", ordinal=1,
                                        response=H.response(output=H.verifier_out("confirmed")))),
                     book=SpendBook(h), handle=h)
        self.assertTrue(gw.call(stage, role, "generalist", 0, req(a)).ok)
        self.assertTrue(gw.call(stage, role, "generalist", 1, req(None)).ok)       # no subject: still a valid call
        events, pin = self.seal(gw)
        hashes = [e["requestHash"] for e in events if e["type"] == "model.call"]
        self.assertEqual(len(set(hashes)), 2)
        rp = self.replay(gw.path, pin)
        self.assertEqual(rp.call(stage, role, "generalist", 0, req(b)).error["code"], "replay-miss")
        self.assertEqual(rp.call(stage, role, "generalist", 0, req(a)).output, H.verifier_out())
        self.assertEqual(rp.call(stage, role, "generalist", 1, req(None)).output, H.verifier_out("confirmed"))
        self.assertEqual((rp.report()["liveCalls"], rp.unconsumed()), (0, 0))


# ===================================================================== NEW defects found in the corrected code (FAIL = repro)
class NewDefects(Direct):
    def test_NEW1_provider_error_coded_budget_exhausted_must_not_make_the_runs_own_trace_unloadable(self):
        """A synthetic script (or adapter) error with code 'budget-exhausted' is retained live (full reservation) but
        error_charge_class() keys on the CODE and says 'refused' (charge 0), so load_trace rejects the gateway's own
        recording: 'a refused call cannot carry a charge'. The run can then be neither pinned nor replayed."""
        h = self.handle()
        gw = self.mk(self.synth(H.entry(error=H.terr("budget-exhausted", False, scope="run"))),
                     book=SpendBook(h), handle=h)
        r = gw.call(*INV, 0, H.request())
        self.assertEqual(r.attempts[0].charge_usd_micros, RESERVE)           # live charged the reservation
        gw.recorder.end("completed")
        try:
            load_trace(gw.path)
        except TraceError as e:
            self.fail(f"gateway's own trace is unloadable: {e}")

    def test_NEW2_run_start_profile_must_be_the_gateways_profile(self):
        """_binding_problem binds run id, mode and authorization but not run.profile: a recorder whose run.start
        names another profile is admitted, so the trace claims a profile the calls did not use."""
        h = self.handle()
        rd = rundoc(1, auth_digest=h.digest)
        rd["profile"] = "someone-else@9"
        rec = Recorder(rd["id"])
        rec.start(rd)
        provs = self.synth(H.entry(response=H.response()))
        try:
            gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                         authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        except GatewayConfigError:
            return
        self.assertFalse(gw.call(*INV, 0, H.request()).ok, "call admitted under a run.start naming another profile")

    def test_NEW3_replay_run_start_must_name_the_recorded_run(self):
        """A strict-replay run.start whose replayOf is NOT the replayed trace's run id is admitted and served."""
        _, events, pin = self.one_call_trace()
        tr = load_trace(events)
        rd = rundoc(9005, mode="strict-replay", replay_of="run_" + "e" * 16)
        rec = Recorder(rd["id"])
        rec.start(rd)
        try:
            gw = Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                         recorder=rec, expected_trace_digest=pin)
        except GatewayConfigError:
            return
        self.assertFalse(gw.call(*INV, 0, H.request()).ok, "replay served under a run.start naming another recording")

    def test_NEW4_trace_with_two_run_start_events_must_not_load(self):
        """Recorder.start() can be called twice and validate_trace accepts a second run.start naming a different
        authorization; the gateway binds only events[0]. Whoever reads the trace sees conflicting run documents."""
        h = self.handle()
        gw = self.mk(self.synth(H.entry(response=H.response())), book=SpendBook(h), handle=h)
        gw.call(*INV, 0, H.request())
        second = rundoc(1, auth_digest="sha256:" + "9" * 64)
        gw.recorder.start(second)
        gw.recorder.end("completed")
        with self.assertRaises(TraceError):
            load_trace(gw.path)

    def test_NEW5_gateway_must_check_the_pin_against_the_events_it_serves(self):
        """Gateway compares the pin with the LoadedTrace.byte_digest ATTRIBUTE. Mutating the loaded events after
        load_trace() (trusted in-process code, not reviewed content) still passes the pin and is served. Hardening:
        recompute the digest from the events, or freeze them. Low: reviewed content cannot reach this."""
        gw, events, pin = self.one_call_trace()
        tr = load_trace(gw.path)
        for lst in tr.calls.values():
            lst[0]["response"]["output"] = {"hypotheses": "MUTATED-AFTER-LOAD"}
        rd = rundoc(9006, mode="strict-replay", replay_of=tr.run_id)
        rec = Recorder(rd["id"])
        rec.start(rd)
        try:
            rp = Gateway(mode="strict-replay", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], replay=tr,
                         recorder=rec, expected_trace_digest=pin)
        except (TraceError, GatewayConfigError):
            return
        r = rp.call(*INV, 0, H.request())
        self.assertNotEqual(r.output, {"hypotheses": "MUTATED-AFTER-LOAD"})

    def test_NEW6_refusals_before_the_binding_check_must_not_write_into_an_unbound_recorder(self):
        """Request-validation, expiry and scope refusals call _refuse() before _bound(), so an error event is
        appended to a recorder whose run.start names another authorization."""
        h, other = self.handle(), self.handle(id="other-authorization")
        rd = rundoc(1, auth_digest=other.digest)
        rec = Recorder(rd["id"])
        provs = self.synth(H.entry(response=H.response()))
        gw = Gateway(mode="live", profile=H.PROFILE, budget=H.BUDGET, run_id=rd["id"], providers=provs,
                     authorization=h, book=SpendBook(h), recorder=rec, clock=lambda: NOW)
        rec.start(rd)
        bad = H.request()
        bad["profile"] = "someone-else@1"
        gw.call(*INV, 0, bad)
        self.assertEqual([e["type"] for e in rec.events], ["run.start"], "error event written into an unbound trace")


if __name__ == "__main__":
    unittest.main()
