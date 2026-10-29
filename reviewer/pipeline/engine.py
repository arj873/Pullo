"""The eight-stage engine: INGEST -> PREPARE -> TRIAGE -> INVESTIGATE -> VERIFY -> JUDGE -> PUBLISH -> LEARN.

One `Engine` drives one run (record or strict replay) against an already created run directory, recorder and
gateway. `runner.run_review` owns pre-flight, idempotency and resume. Design rules:

* A stage reads only the previous artifacts, the run, the Plan and the logged trace, so a resumed run rebuilds
  the same state from disk that a continuing run holds in memory.
* A stage artifact is stored durably BEFORE its stage.end/checkpoint events are appended.
* One ToolSession per (stage, agent). PREPARE uses agent `prepare`; VERIFY uses agent `verifier` for every
  candidate, so the per-agent cap spans candidates, and the global cap is computed from the logged tool calls.
* Findings are built only from the actual investigator output, the actual verifier output and resolved
  citations, then proven with contracts.check_finding_provenance against this run's logged events.
* Replay: after each stage the recomputed events must equal the recording's events for that stage (compare.py);
  a difference turns that stage into a failed artifact (never a silent pass) and skips the rest.
"""

from __future__ import annotations

import dataclasses
import json

from reviewer.contracts import (check_finding_provenance, citable_tool_calls, is_turn_schema, require, terminal_payload,
                                validate)
from reviewer.contracts.budget import (HOST_STOP_RECORDING_V1, HOST_STOP_RECORDING_V2, deadline_state,
                                      investigation_limit, stage_ceiling, stage_deadline_exceeded)
from reviewer.contracts.canonical import artifact_digest, digest, hypothesis_id
from reviewer.contracts.severity import RANK, materialize_evidence
from reviewer.contracts.snapshot import verify_manifest
from reviewer.contracts.stages import STAGES, artifact_name
from reviewer.gateway import SettlementError, typed_error
from reviewer.tools import (HOST_IMPACT_TOOLS, IMPACT_TOOLS, SWEEP_TOOLS, TOOLS, Limits, ToolSession, full_view,
                            import_view, omissions_from_records)

from . import coverage as cov_mod
from . import identity, impactcov, judging, lanes, prompts, render, repocov, retrieval, snaps, specialists, sweeps
from .compare import first_difference, segment
from .errors import PipelineError

SPECIALIST = "generalist"
VERIFIER_AGENT = "verifier"
JUDGE_AGENT = "judge"
PREPARE_AGENT = "prepare"
CONTEXT_CHARS = 100_000        # model-visible context budget per request (deterministic truncation)
VERIFY_WINDOW = 20             # lines of head context around a candidate location

REPLAY_CODES = ("replay-miss", "replay-mismatch")
# investigator.impact@v3: a specialist failure with one of these would repeat for every later specialist (no live calls,
# no resolved model, a router answering with another model or a malformed provider envelope), so none is started. The
# same holds for any failure whose provider outcome is unknown (charged at its worst case; the provider's state is
# unclear), so one bad contact is never multiplied by the number of specialists.
V3_SYSTEMIC_CODES = ("live-calls-disabled", "model-unresolved", "contract-violation")

AGENT_FAIL_CODES = ("provider-timeout", "provider-error", "schema-invalid", "repair-exhausted",
                    "contract-violation", "internal", "model-unresolved", "live-calls-disabled")


def v3_stops_later_specialists(err: dict) -> bool:
    detail = err.get("detail")
    return err["code"] in V3_SYSTEMIC_CODES or (isinstance(detail, dict) and detail.get("providerOutcome") == "unknown")


def empty_payload(stage: str, run: dict, plan: dict, base_id: str, head_id: str) -> dict:
    return {
        "INGEST": lambda: {"run": run},
        "PREPARE": lambda: {"baseSnapshotId": base_id, "headSnapshotId": head_id,
                            "diffDigest": digest({"base": base_id, "head": head_id, "changes": []}), "files": []},
        "TRIAGE": lambda: {"plan": plan},
        "INVESTIGATE": lambda: {"hypotheses": [], "agents": []},
        "VERIFY": lambda: {"findings": [], "verifications": [], "drops": []},
        "JUDGE": lambda: {"comments": [], "drops": []},
        "PUBLISH": lambda: {"sink": "local-file", "path": "comments.json", "commentIds": [], "summary": "none"},
        "LEARN": lambda: {"enabled": False},
    }[stage]()


def omission_notes(events: list, stage: str, incomplete: list, agent: str | None = None) -> list[str]:
    out = []
    for e in events:
        if e["type"] == "tool.call" and e["stage"] == stage and (agent is None or e["agentId"] == agent):
            r = e["result"]
            if r["status"] not in ("ok", "empty") or r["truncated"] is not None or r["completeness"] != "exact":
                out.append(f"{e['tool']} {json.dumps(e['args'], sort_keys=True)}: {r['status']}"
                           + (f"; {r['notice']}" if r["notice"] else ""))
    out += [f"{i['stage']} incomplete: {i['reason']}" for i in incomplete]
    return out


def model_visible_omissions(events: list, incomplete: list) -> list[str]:
    """What the investigator was told was omitted or rewritten (read back from its logged request)."""
    for e in events:
        if e["type"] == "model.call" and e["stage"] == "INVESTIGATE":
            try:
                return list(json.loads(e["request"]["messages"][1]["content"]).get("omitted", []))
            except (ValueError, KeyError, IndexError, AttributeError):
                return []
    return omission_notes(events, "PREPARE", incomplete)


def render_outputs(run: dict, status: str, incomplete: list, error: dict | None, artifacts: dict, events: list,
                   cov: dict | None) -> tuple[bytes, bytes, list]:
    """(comments.json bytes, review.md bytes, comments) as a pure function of the judged artifacts, the logged
    trace and the terminal status. PUBLISH writes these bytes; resume and load re-derive them and compare, so the
    files a human reads are bound to the JUDGE artifact and not to a receipt hash someone could edit along."""
    comments = [] if status == "failed" else list(artifacts["JUDGE"]["payload"]["comments"])
    drops = list(artifacts["VERIFY"]["payload"]["drops"]) + list(artifacts["JUDGE"]["payload"]["drops"])
    files = artifacts["PREPARE"]["payload"]["files"]
    notes = model_visible_omissions(events, incomplete) + omission_notes(events, "VERIFY", incomplete)
    used = sum(1 for e in events if e["type"] == "tool.call")
    costs = [e["record"] for e in events if e["type"] == "cost"]
    basis = {}
    for c in costs:
        basis[c["basis"]] = basis.get(c["basis"], 0) + 1
    cost_note = (f"{len(costs)} model-call cost record(s) by basis {json.dumps(basis, sort_keys=True)}. "
                 "Synthetic and replayed amounts are not provider spend; no per-review cost target is claimed.")
    cdoc = None if cov is None else coverage_doc(cov)
    retrieval_run = any(e["type"] == "model.call" and "hop" in e["request"] for e in events)
    impact = impactcov.summarize(events, {f["path"] for f in files})     # None unless an impact map was made
    cbytes = render.comments_bytes(render.comments_doc(run, status, comments, cdoc))
    md = render.review_md(run=run, status=status, comments=comments, drops=drops, incomplete=incomplete,
                          error=error, changed=files, context_notes=notes, tool_calls=used, cost_note=cost_note,
                          coverage=cdoc, retrieval=retrieval_run, impact=impact,
                          specialists=(artifacts["INVESTIGATE"]["payload"]
                                       if specialists.is_specialist_plan(artifacts["TRIAGE"]["payload"]["plan"])
                                       else None),
                          sweep=artifacts["INVESTIGATE"]["payload"].get("sweep"))
    return cbytes, md.encode("utf-8"), comments


def coverage_doc(cov: dict, limit: int = 50) -> dict:
    """Model-visible statement + bounded detail (+ the host record digest for the bundle). `cov` is a
    historical-coverage@1 (partial view) or a repository-coverage@1 (complete imports)."""
    if repocov.is_repository(cov):
        return {"statement": repocov.statement(cov), "detail": repocov.detail(cov, limit), "digest": digest(cov)}
    return {"statement": cov_mod.statement(cov), "detail": cov_mod.detail(cov, limit), "digest": digest(cov)}


def unread_note(unread: list, limit: int = 6) -> str:
    """Requested-but-never-run targets, bounded, for artifacts (a request is data, never a finding)."""
    shown = [f"{r['tool']} {json.dumps(r['args'], sort_keys=True)}"[:120] for r in unread[:limit]]
    more = f" (+{len(unread) - limit} more)" if len(unread) > limit else ""
    return "; ".join(shown) + more


def classify(error: dict) -> tuple[str, str | None]:
    """TypedError -> (run status, incomplete reason|None) for a fatal stage failure."""
    code = error["code"]
    if code == "cancelled":
        return "cancelled", "cancelled"
    if code == "deadline-exceeded":
        return "failed", "deadline"
    if code == "budget-exhausted":
        return "failed", "budget"
    if code in AGENT_FAIL_CODES:
        return "failed", "agent-failure"
    return "failed", None


def _agent_status(error: dict) -> str:
    return {"provider-timeout": "timeout", "cancelled": "cancelled", "budget-exhausted": "budget"}.get(
        error["code"], "failed")


class Engine:
    def __init__(self, spec, run: dict, rd, recorder, gateway, *, orig: dict | None, prior_artifacts: dict | None,
                 prior_model_calls: int, guard=None):
        self.spec, self.case, self.host = spec, spec.case, spec.host
        self.profile, self.plan, self.budget = spec.profile, spec.plan, spec.plan["budget"]
        self.policy = identity.retrieval_policy(spec)           # None unless a role returns the Turn envelope
        self.impact = identity.impact_mode(spec)                # impact map + find_references + impact prompts
        # investigator.impact@v3: specialist investigator agent ids in run order (None: the one generalist agent)
        self.specialists = self.policy.specialists if self.impact else None
        # investigator.impact@v4: diff-shard sweep investigators run after the specialists (reviewer.pipeline.sweeps)
        self.sweep = bool(self.impact and self.policy.diff_sweep)
        # investigator.impact@v5: five specialist lanes with the lanes.py split and near-duplicate cap
        self.five = bool(self.impact and self.policy.five_lanes)
        self.off_shard: dict[str, str] = {}     # v4 VERIFY: sweep drafts located outside their own shard -> agent
        self._tool_share: int | None = None     # v3: tool calls the running specialist may still use (its share)
        self._spend_ceiling: int | None = None  # v3: cumulative INVESTIGATE spend ceiling of the running agent
        self._time_slice: tuple | None = None   # v3: (agent, slice end sec, stage ceiling sec) of the running agent
        self.guard = guard
        self._ordinals: dict[tuple, int] = {}
        self._gate_n: dict[str, int] = {}      # per-STAGE count of gate checks (host-stop@2 position); reset per stage run
        self.run, self.rd, self.recorder, self.gw = run, rd, recorder, gateway
        self.pv = spec.plan["version"]
        self.base_id, self.head_id = self.case["base"]["snapshotId"], self.case["head"]["snapshotId"]
        self.profile_ref = f"{spec.profile['id']}@{spec.profile['version']}"
        self.cov = spec.coverage                # None = two full pinned snapshots (the S0-07 first slice)
        self.rcov = (None if spec.imports is None else
                     repocov.build(spec.imports, spec.base.manifest, spec.head.manifest, spec.case))
        if self.cov is not None:
            self.view = cov_mod.build_view(self.cov, spec.base, spec.head)
        else:       # imports: the view's coverage, notes and provenance carry the VERIFIED records' omissions
            om = None if spec.imports is None else omissions_from_records(spec.imports.base, spec.imports.head)
            self.view = (full_view(spec.base.root, spec.base.manifest, spec.head.root, spec.head.manifest) if om is None else
                         import_view(spec.base.root, spec.base.manifest, spec.head.root, spec.head.manifest, om))
        self.resolver = self.view.resolver()
        self.clock = self.host.clock
        self.t0 = self.clock()
        if self.guard is not None:
            self.guard.t0 = self.t0
        self.orig = orig                      # replay: {stage: recorded events}
        self._check_recorded_stops()
        self.expected_unconsumed = prior_model_calls
        self.artifacts: dict[str, dict] = {}
        self.digests: dict[str, str] = {}
        self.stage_ms: dict[str, int | None] = {}
        self.fatal: dict | None = None
        self.incomplete: list[dict] = []
        self.needs_reconciliation = False
        self.replay_broken = False
        self.resumed_from: str | None = None
        for st, art in (prior_artifacts or {}).items():
            self._adopt(st, art, artifact_digest(art), None)
        if prior_artifacts:
            self.resumed_from = next((st for st in STAGES if st not in prior_artifacts), "run.end")

    # ------------------------------------------------------------------ state
    def _adopt(self, stage, art, dig, ms):
        self.artifacts[stage], self.digests[stage], self.stage_ms[stage] = art, dig, ms
        if art["status"] == "failed" and self.fatal is None:
            err = art["error"]
            status, reason = classify(err)
            self.fatal = {"status": status, "error": err, "stage": stage, "reason": reason}
        if stage != "LEARN" and art["status"] != "skipped":
            for i in art.get("incomplete", []):
                self._note(i)

    def _note(self, inc: dict) -> dict:
        key = (inc["stage"], inc["reason"], inc.get("detail"))
        if all((i["stage"], i["reason"], i.get("detail")) != key for i in self.incomplete):
            self.incomplete.append(inc)
        return inc

    def _inc(self, stage: str, reason: str, detail: str | None = None) -> dict:
        d = {"stage": stage, "reason": reason}
        if detail:
            d["detail"] = detail[:2000]
        return self._note(d)

    def set_fatal(self, stage: str, error: dict, *, reason: str | None = None, force: bool = False) -> None:
        if error["code"] in REPLAY_CODES:
            self.replay_broken, force = True, True
        if self.fatal is None or force:
            status, derived = classify(error)
            reason = reason or derived
            self.fatal = {"status": status, "error": error, "stage": stage, "reason": reason}
            if reason:
                self._inc(stage, reason, error["code"])

    def terminal(self) -> tuple[str, list, dict | None]:
        if self.fatal:
            return self.fatal["status"], list(self.incomplete), self.fatal["error"]
        return ("partial" if self.incomplete else "completed"), list(self.incomplete), None

    def events(self) -> list:
        return self.recorder.events

    def tool_calls(self) -> dict:
        return {e["toolCallId"]: e for e in self.recorder.events if e["type"] == "tool.call"}

    def model_event(self, call_id: str) -> dict | None:
        return next((e for e in self.recorder.events if e["type"] == "model.call" and e["callId"] == call_id), None)

    # ------------------------------------------------------------------ gating
    def gate(self, stage: str, stage_t0: float, *, new_agent: bool = False, scope: str = "tool"):
        """None when work may start, else (incomplete reason, TypedError). Checked before every tool and
        model call; never hidden behind a retry. With budget.hostStopRecording a stop is a `host.stop` trace
        event, and strict replay takes the decision from the recording at the same position (never the clock);
        cancellation is still honored."""
        scope = "new-agent" if new_agent else scope
        policy = self.budget.get("hostStopRecording")
        recording = policy is not None
        n = self._gate_n[stage] = self._gate_n.get(stage, 0) + 1     # EVERY check counts, stop or not, event or not
        ordinal = n if policy == HOST_STOP_RECORDING_V2 else None
        if recording and self.orig is not None:
            stop = self._recorded_stop(stage, scope, ordinal)
            if stop is None and self.host.cancel is not None and self.host.cancel():
                stop = "cancelled"
        else:
            stop = self._clock_stop(stage, stage_t0, new_agent)
        if stop is None:
            return None
        if recording:
            extra = {} if ordinal is None else {"gateOrdinal": ordinal}
            self.recorder.append("host.stop", stage=stage, scope=scope, code=stop,
                                 afterSeq=len(self.recorder.events) - 1, **extra)
        if stop == "cancelled":
            return "cancelled", typed_error("cancelled", "run cancelled by the host", stage=stage)
        if stop == "soft-deadline":
            return "soft-deadline", typed_error("deadline-exceeded", "soft deadline: no new agent starts", stage=stage)
        msg = "hard run deadline reached" if stop == "hard-deadline" else f"{stage} stage ceiling reached"
        if stop == "stage-deadline" and self._time_slice is not None and stage == "INVESTIGATE":
            agent, end, ceiling = self._time_slice
            msg = f"INVESTIGATE time slice of {self.agent_label(agent)} {agent} reached ({end}s of the {ceiling}s stage ceiling)"
        return "deadline", typed_error("deadline-exceeded", msg, stage=stage)

    def _clock_stop(self, stage: str, stage_t0: float, new_agent: bool) -> str | None:
        if self.host.cancel is not None and self.host.cancel():
            return "cancelled"
        state = deadline_state(self.budget, max(0.0, self.clock() - self.t0))
        if state == "hard":
            return "hard-deadline"
        if stage_deadline_exceeded(stage, max(0.0, self.clock() - stage_t0), self.budget):
            return "stage-deadline"
        if self._time_slice is not None and stage == "INVESTIGATE" \
                and max(0.0, self.clock() - stage_t0) >= self._time_slice[1]:
            return "stage-deadline"             # v3: this specialist's cumulative time slice (specialists.TIME_RULE)
        if state == "soft" and new_agent:
            return "soft-deadline"
        return None

    def _recorded_stop(self, stage: str, scope: str, ordinal: int | None = None) -> str | None:
        """Replay: the stop code the recording holds at exactly this position (stage, scope, last event seq, and for
        host-stop@2 the stage's gate ordinal). host-stop@1 recordings keep their coarse (stage, scope, afterSeq)
        position: two adjacent gates at one seq cannot be told apart (documented limitation, not silently upgraded)."""
        at = len(self.recorder.events) - 1
        return next((e["code"] for e in self.orig.get(stage, ())
                     if e["type"] == "host.stop" and e["afterSeq"] == at and e["scope"] == scope
                     and (ordinal is None or e.get("gateOrdinal") == ordinal)), None)

    def _check_recorded_stops(self) -> None:
        """Strict replay refuses an incoherent recording BEFORE any gate runs (so before any live access): host stops
        without a policy, a v1 policy with ordinals, or a v2 stop whose gateOrdinal is missing, not an int >= 1, or not
        strictly increasing within its stage."""
        if self.orig is None:
            return
        policy = self.budget.get("hostStopRecording")
        for stage, events in self.orig.items():
            last = 0
            for e in events:
                if e["type"] != "host.stop":
                    continue
                o = e.get("gateOrdinal")
                bad = (policy is None and "the Plan has no hostStopRecording policy"
                       or policy == HOST_STOP_RECORDING_V1 and "gateOrdinal" in e and "host-stop@1 carries no gateOrdinal"
                       or policy == HOST_STOP_RECORDING_V2 and (isinstance(o, bool) or not isinstance(o, int) or o < 1
                                                                or o <= last) and "missing, invalid or non-increasing gateOrdinal")
                if bad:
                    raise PipelineError("replay-recording", f"{stage}: host.stop incoherent with the Plan: {bad}")
                last = o or last

    def next_ordinal(self, stage: str, role: str, agent: str) -> int:
        """Fresh monotonic ordinal of a retrieval hop for (stage, role, agent); never reused in a run."""
        key = (stage, role, agent)
        n = self._ordinals.get(key, 0)
        self._ordinals[key] = n + 1
        return n

    def turn_role(self, role: str) -> bool:
        return is_turn_schema(self.profile["roles"][role]["outputSchema"])

    def citable(self, call_id: str) -> dict:
        """The tool calls the model call `call_id` was shown and may cite (contracts.citable_tool_calls)."""
        return citable_tool_calls(call_id, list(self.recorder.events))

    def fatal_tamper(self, stage: str) -> None:
        self.set_fatal(stage, typed_error(
            "contract-violation", "a pinned snapshot no longer matches its manifest (tamper)", stage=stage,
            detail={"kind": "snapshot-tamper"}))

    def agent_label(self, agent: str) -> str:
        """How messages name an INVESTIGATE agent: 'specialist' (always under v3), 'sweep investigator' for a v4 sweep."""
        return "sweep investigator" if self.sweep and agent not in specialists.AGENTS else "specialist"

    def session_hard_limit(self) -> int:
        """Tool calls one ToolSession may log at all: the host limit and the Plan per-agent budget."""
        return min(identity.tool_limits(self.spec).max_calls, self.budget["maxToolCallsPerAgent"])

    def agent_limit(self) -> int:
        """Tool calls one agent session may make: host limit and plan per-agent budget (not the run remainder).
        A v3 specialist is further held to its share of the investigator tool-call pool (specialists.BUDGET_RULE)."""
        cap = min(identity.tool_limits(self.spec).max_calls, self.budget["maxToolCallsPerAgent"])
        if self._tool_share is not None:
            cap = min(cap, self._tool_share)
        return cap

    def limits_for(self) -> Limits:
        used = sum(1 for e in self.recorder.events if e["type"] == "tool.call")
        remaining = max(0, self.budget["maxToolCalls"] - used)
        return dataclasses.replace(identity.tool_limits(self.spec), max_calls=min(self.agent_limit(), remaining))

    def new_session(self, stage: str, agent: str) -> ToolSession:
        tools = TOOLS if not self.impact else (HOST_IMPACT_TOOLS if stage == "PREPARE" else IMPACT_TOOLS)
        return ToolSession(self.view, stage=stage, agent_id=agent, limits=self.limits_for(), clock=self.clock,
                           tools=tools)

    def tool(self, session: ToolSession, tool: str, args: dict, stage_t0: float):
        """-> (ToolCall|None, why). Never calls past a cap, deadline or cancellation."""
        if len(session.calls) >= session.limits.max_calls:
            return None, "tool-calls-exhausted"
        used = sum(len(x["excerpt"]) for e in self.recorder.events
                   if e["type"] == "tool.call" and e["stage"] == session.stage and e["agentId"] == session.agent_id
                   for x in e["result"]["evidence"])
        if used > self.budget["maxToolOutputTokensPerAgent"] * 3:      # ~3 chars per token, conservative
            return None, "tool-calls-exhausted"
        g = self.gate(session.stage, stage_t0, scope="tool")
        if g is not None:
            return None, g[0]
        call = session.call(tool, args)
        self.recorder.append("tool.call", **call.trace_fields())
        if session.tampered:
            self.fatal_tamper(session.stage)
        return call, None

    # ------------------------------------------------------------------ model calls
    def model_call(self, stage: str, role: str, agent: str, ordinal: int, request: dict):
        """-> (output, error, attempts). Output is validated against the role schema; a status-ok answer whose
        output fails that schema is a typed schema-invalid failure (the gateway only repairs
        status=invalid-output answers, so there is no second attempt to make)."""
        schema = request["outputSchema"]
        if self._spend_ceiling is not None and stage == "INVESTIGATE" and role == "investigator":
            spent = self.stage_spend(stage)
            if spent >= self._spend_ceiling:      # v3 specialist spend share (before any gateway admission)
                sweep = self.agent_label(agent) != "specialist"
                err = typed_error("budget-exhausted", f"{self.agent_label(agent)} {agent} reached its INVESTIGATE spend share",
                                  stage=stage, detail={"scope": "sweep-share" if sweep else "specialist-share",
                                                       "rule": sweeps.BUDGET_RULE if sweep else specialists.BUDGET_RULE,
                                                       "spentUsdMicros": spent, "ceilingUsdMicros": self._spend_ceiling})
                self.recorder.append("error", error=err)
                return None, err, []
        try:
            res = self.gw.call(stage, role, agent, ordinal, request, repair=prompts.repair_builder(request, schema))
        except SettlementError as e:
            self.needs_reconciliation = True
            err = typed_error("internal", "spend book failed after provider contact; operator reconciliation required",
                              stage=stage, detail={"cause": type(e).__name__})
            return None, err, []
        if res.error is not None:
            return None, res.error, res.attempts
        issues = validate(schema, res.output)
        if issues:
            err = typed_error("schema-invalid", f"{schema} failed validation: {issues[0]}", stage=stage,
                              detail={"issues": [str(i) for i in issues[:3]]})
            self.recorder.append("error", error=err)
            return None, err, res.attempts
        return res.output, None, res.attempts

    def run_spend(self) -> int:
        """USD micros of every logged cost record of the run (the reservation when the charge is unknown)."""
        return sum(r["usdMicros"] if r["usdMicros"] is not None else r["reservedUsdMicros"]
                   for e in self.recorder.events if e["type"] == "cost" for r in (e["record"],))

    def stage_spend(self, stage: str) -> int:
        """USD micros of every logged cost record of `stage` (the reservation when the charge is unknown)."""
        return sum(r["usdMicros"] if r["usdMicros"] is not None else r["reservedUsdMicros"]
                   for e in self.recorder.events if e["type"] == "cost"
                   for r in (e["record"],) if r.get("stage") == stage)

    # ------------------------------------------------------------------ stage driver
    def run_stage(self, stage: str, fn) -> None:
        if stage in self.artifacts:
            return
        r = self.recorder
        r.append("stage.start", stage=stage)
        start = len(r.events) - 1
        self._gate_n[stage] = 0
        t0 = self.clock()
        if self.guard is not None:
            self.guard.stage_t0[stage] = t0
        try:
            status, payload, error, inc = fn(t0)
        except PipelineError:
            raise
        except Exception as e:  # noqa: BLE001 - a handled terminal outcome, not a crash
            error = typed_error("internal", f"{stage} failed internally: {type(e).__name__}", stage=stage)
            status, payload, inc = "failed", self.empty(stage), []
            self.set_fatal(stage, error)
        if error is not None and status == "failed":
            self.set_fatal(stage, error)
        host_stopped = self.fatal is not None and self.fatal["error"]["code"] in ("cancelled", "deadline-exceeded")
        if host_stopped and self.orig is not None and self.budget.get("hostStopRecording") is not None and any(
                e["type"] == "host.stop" for e in (*self.orig[stage], *r.events[start:])):
            host_stopped = False        # a recorded stop is reproduced and compared like any other event
        if self.orig is not None and not self.replay_broken and not host_stopped:   # a host stop is not a divergence
            want = self.orig[stage][:-2]                               # everything before stage.end/checkpoint
            diff = first_difference(want, r.events[start:])
            if diff is not None:
                status, payload, inc = "failed", self.empty(stage), []
                error = typed_error("replay-mismatch", f"{stage}: {diff}", stage=stage)
                self.set_fatal(stage, error)
        art = self.artifact(stage, status, payload, error, inc)
        dig = artifact_digest(art)
        if self.orig is not None and not self.replay_broken and not host_stopped \
                and dig != self.orig[stage][-2].get("artifactDigest"):
            status, payload, inc = "failed", self.empty(stage), []
            error = typed_error("replay-mismatch", f"{stage}: recomputed artifact differs from the recording",
                                stage=stage)
            self.set_fatal(stage, error)
            art = self.artifact(stage, status, payload, error, inc)
            dig = artifact_digest(art)
        self.rd.write_artifact(artifact_name(stage, self.pv), (json.dumps(art, sort_keys=True, indent=2,
                                                                          ensure_ascii=False) + "\n").encode())
        end = {"stage": stage, "status": status, "artifactDigest": dig}
        if error is not None:
            end["error"] = error
        r.append("stage.end", **end)
        r.append("checkpoint", stage=stage, planVersion=self.pv, artifactDigest=dig)
        self.artifacts[stage], self.digests[stage] = art, dig
        self.stage_ms[stage] = int(max(0.0, self.clock() - t0) * 1000)
        for i in art.get("incomplete", []):
            if stage != "LEARN" and status != "skipped":
                self._note(i)
        if self.host.hooks.after_checkpoint is not None:
            self.host.hooks.after_checkpoint(stage, dig)

    def empty(self, stage: str) -> dict:
        p = empty_payload(stage, self.run, self.plan, self.base_id, self.head_id)
        if stage == "INVESTIGATE" and self.specialists is not None:
            p["merges"] = []                    # v3 payloads always carry the merge record
        return p

    def artifact(self, stage, status, payload, error, inc) -> dict:
        i = STAGES.index(stage)
        start = next(n for n in range(len(self.recorder.events) - 1, -1, -1)
                     if self.recorder.events[n]["type"] == "stage.start" and self.recorder.events[n]["stage"] == stage)
        cost_ids = []
        for e in self.recorder.events[start:]:
            if e["type"] == "cost" and e["record"]["id"] not in cost_ids:
                cost_ids.append(e["record"]["id"])
        art = {"schema": "stage-artifact@1", "runId": self.run["id"], "stage": stage, "planVersion": self.pv,
               "status": status, "inputDigest": None if i == 0 else self.digests[STAGES[i - 1]],
               "payload": {"stage": stage, **payload}, "costRecordIds": cost_ids}
        if error is not None:
            art["error"] = error
        if inc:
            art["incomplete"] = inc
        return require("StageArtifact", art)

    def skipped(self, stage: str):
        inc = []
        if self.fatal and self.fatal["reason"]:
            inc = [{"stage": self.fatal["stage"], "reason": self.fatal["reason"],
                    "detail": f"{stage} skipped after a failed {self.fatal['stage']}"}]
        return "skipped", self.empty(stage), None, inc

    def run_all(self) -> None:
        for stage, fn in (("INGEST", self.ingest), ("PREPARE", self.prepare), ("TRIAGE", self.triage),
                          ("INVESTIGATE", self.investigate), ("VERIFY", self.verify), ("JUDGE", self.judge),
                          ("PUBLISH", self.publish), ("LEARN", self.learn)):
            self.run_stage(stage, fn)

    # ------------------------------------------------------------------ INGEST, TRIAGE, LEARN
    def ingest(self, t0):
        return "completed", {"run": self.run}, None, []

    def triage(self, t0):
        if self.fatal:
            return self.skipped("TRIAGE")
        return "completed", {"plan": self.plan}, None, []

    def learn(self, t0):
        return "skipped", {"enabled": False}, None, [{"stage": "LEARN", "reason": "disabled-in-eval"}]

    # ------------------------------------------------------------------ PREPARE
    def prepare(self, t0):
        stage = "PREPARE"
        problems = []
        for name, snap in (("base", self.spec.base), ("head", self.spec.head)):
            for p in verify_manifest(snap.root, snap.manifest):
                problems.append(f"{name}: {p}")
        if problems:
            err = typed_error("contract-violation", "a pinned snapshot does not match its manifest (tamper); "
                              "nothing was read from it", stage=stage,
                              detail={"kind": "snapshot-tamper", "problems": problems[:5]})
            return "failed", self.empty(stage), err, []
        g = self.gate(stage, t0)
        if g is not None:
            err = g[1]
            return "failed", self.empty(stage), err, []
        session = self.new_session(stage, PREPARE_AGENT)
        inc, files, rows = [], [], []
        call, why = self.tool(session, "diff", {}, t0)
        gap_rows = []
        if call is None:
            inc.append(self.stopped(stage, why, "changed-path listing not collected"))
        else:
            rows = self._rows(call.result)
            _, why = self.tool(session, "list_files", {"side": "head", "limit": 200}, t0)
            if why:
                inc.append(self.stopped(stage, why, "head file listing not collected"))
        if self.cov is not None:
            # partial coverage: the host's record IS the change list. The tool listing may only agree with it.
            want, gap_rows = cov_mod.rows_of(self.cov)
            gap_paths = {e["path"] for e in gap_rows} | {e["previousPath"] for e in gap_rows if e["previousPath"]}
            extra = sorted(r for r in set(rows) - set(want) if r[1] not in gap_paths)   # tool sees a one-sided gap as A/D
            if extra:
                err = typed_error("contract-violation", "the diff tool listed a path the host coverage does not "
                                  f"record as changed ({extra[0][1]!r}); context must never read as a change",
                                  stage=stage, detail={"kind": "coverage-mismatch"})
                return "failed", self.empty(stage), err, []
            rows = want
        for letter, path in rows:
            call, why = self.tool(session, "diff", {"path": path}, t0)
            if call is None:
                inc.append(self.stopped(stage, why, f"diff of {path} and later paths not collected"))
                break
            adds, dels = self._count(call.result)
            files.append({"path": path, "status": {"A": "added", "D": "deleted", "M": "modified"}[letter],
                          "additions": adds, "deletions": dels})
        if self.impact and not self.fatal:      # deterministic impact pre-pass: one host-only, logged tool call
            call, why = self.tool(session, "impact_scan", {}, t0)
            if call is None:
                inc.append(self.stopped(stage, why, "impact map (impact_scan) not collected"))
        if self.fatal:
            return "failed", self.empty(stage), self.fatal["error"], []
        if session.incomplete and not inc:
            inc.append(self._inc(stage, session.incomplete))
        bm = {e["path"]: e["sha256"] for e in self.spec.base.manifest["entries"]}
        hm = {e["path"]: e["sha256"] for e in self.spec.head.manifest["entries"]}
        dd = digest({"base": self.base_id, "head": self.head_id,
                     "changes": [[l, p, bm.get(p), hm.get(p)] for l, p in rows]})
        # files for which no per-file diff was collected are still changed paths: list them with zero counts
        have = {f["path"] for f in files}
        for letter, path in rows:
            if path not in have:
                files.append({"path": path, "status": {"A": "added", "D": "deleted", "M": "modified"}[letter],
                              "additions": 0, "deletions": 0})
        for e in gap_rows:        # recorded as changed but one-sided/ambiguous: listed with the RECORDED status, never diffed, never a real add/delete
            files.append({"path": e["path"], "status": {"added": "added", "removed": "deleted"}.get(e["status"],
                                                                                                    "modified"),
                          "additions": 0, "deletions": 0})
        return "completed", {"baseSnapshotId": self.base_id, "headSnapshotId": self.head_id, "diffDigest": dd,
                             "files": files}, None, inc

    def stopped(self, stage: str, why: str, detail: str) -> dict:
        """Record why tool work stopped (cap, deadline or cancellation); cancellation also ends the run."""
        if why == "cancelled":
            self.set_fatal(stage, typed_error("cancelled", "run cancelled by the host", stage=stage))
        return self._inc(stage, why, detail)

    @staticmethod
    def _rows(result: dict) -> list[tuple[str, str]]:
        out = []
        if result["status"] in ("ok", "partial"):
            for e in result["evidence"]:
                for line in e["excerpt"].split("\n"):
                    if len(line) > 2 and line[0] in "ADM" and line[1] == " ":
                        out.append((line[0], line[2:]))
        return out

    @staticmethod
    def _count(result: dict) -> tuple[int, int]:
        a = d = 0
        for e in result["evidence"]:
            for line in e["excerpt"].split("\n"):
                if line.startswith("+") and not line.startswith("+++"):
                    a += 1
                elif line.startswith("-") and not line.startswith("---"):
                    d += 1
        return a, d

    def omissions(self, stage: str, agent: str | None = None) -> list[str]:
        return omission_notes(self.recorder.events, stage, self.incomplete, agent)

    def bounded_context(self, items: list[dict]) -> tuple[list[dict], list[str]]:
        total, out, notes = 0, [], []
        for it in items:
            size = sum(len(x) for x in it["excerpts"])
            if total + size > CONTEXT_CHARS:
                out.append({**it, "excerpts": [], "notice": (it["notice"] + " Excerpts omitted: request context budget.").strip()})
                notes.append(f"{it['tool']} result {it['toolCallId']} omitted from the request (context budget)")
                continue
            total += size
            out.append(it)
        return out, notes

    @staticmethod
    def unrendered_ids(items: list[dict], events: list[dict]) -> frozenset:
        """Host-prepared results the model is told about but whose excerpts bounded_context replaced by the omitted
        marker. `items` and `events` are the same results in the same order."""
        return frozenset(ev["toolCallId"] for it, ev in zip(items, events)
                         if not it["excerpts"] and retrieval.excerpt_chars(ev) > 0)

    # ------------------------------------------------------------------ INVESTIGATE
    def investigate(self, t0):
        stage = "INVESTIGATE"
        if self.fatal:
            return self.skipped(stage)
        if self.specialists is not None:
            return self._investigate_v3(stage, t0)
        g = self.gate(stage, t0, new_agent=True)
        if g is not None:
            return self._agent_failed(g[1], reason=g[0])
        ctx, notes = self._investigate_context()
        floor_inc: list = []                    # impact@v2 exploration floor fell back to the draft (else empty)
        if self.turn_role("investigator"):
            ctx, notes = self._cap_host_results(ctx, notes)
            end, floor_inc = self._investigator_chain(stage, t0, ctx, notes)
            if end.error is not None:
                return self._agent_failed(end.error, reason=end.stop[0] if end.stop else None)
            if end.exhausted is not None:
                return self._investigator_exhausted(stage, end)
            out, source = end.payload, end.final_call
        else:
            req = prompts.investigator_request(self.profile, self.profile_ref, self.case, ctx,
                                               self.omissions("PREPARE") + notes, coverage=self.coverage_doc())
            out, err, attempts = self.model_call(stage, "investigator", SPECIALIST, 0, req)
            if err is not None:
                return self._agent_failed(err)
            source = next(a.call_id for a in reversed(attempts) if a.outcome == "ok")
        hyps = self._hypotheses(SPECIALIST, out, source)
        return ("partial" if floor_inc else "completed"), {
            "hypotheses": hyps, "agents": [{"agentId": SPECIALIST, "specialist": SPECIALIST, "status": "completed"}]}, \
            None, floor_inc

    def _investigate_context(self) -> tuple[list, list]:
        items = prompts.context_items(self.recorder.events, "PREPARE")
        if self.impact:         # the impact map goes first so the request context budget never drops it
            items = [i for i in items if i["tool"] == "impact_scan"] + [i for i in items if i["tool"] != "impact_scan"]
        return self.bounded_context(items)

    def _hypotheses(self, agent: str, out: dict, source: str) -> list[dict]:
        """The agent's final InvestigatorOutput -> the Hypothesis documents whose citations and location resolve."""
        tools = self.citable(source)
        family = self.profile["roles"]["investigator"]["family"]
        changed = self.changed_head_paths()
        hyps = []
        for n, d in enumerate(out["hypotheses"]):
            hid = hypothesis_id(agent, n, d["claim"], d["location"]["path"], d["location"]["line"])
            ev, problems = materialize_evidence(d["evidence"], tools, f"investigator:{agent}", self.resolver)
            if not problems and not snaps.location_ok(self.spec.head.root, self.spec.head.manifest, d["location"]):
                problems = ["location does not exist in the pinned head snapshot"]
            if not problems and changed is not None and d["location"]["path"] not in changed:
                problems = ["location is in a file this change did not modify"]
            if problems or not ev:
                continue
            h = {"id": hid, "runId": self.run["id"], "specialist": agent, "claim": d["claim"],
                 "category": d["category"], "suspectedSeverity": d["suspectedSeverity"], "impact": d["impact"],
                 "location": d["location"], "evidence": ev, "modelFamily": family, "sourceCallId": source}
            for k in ("mechanism", "reach", "confidence"):
                if k in d:
                    h[k] = d[k]
            if validate("Hypothesis", h):
                continue
            hyps.append(h)
        return hyps

    def _cap_host_results(self, ctx: list, notes: list) -> tuple[list, list]:
        """A request lists at most MAX_HOST_RESULTS host-prepared results; the rest are named as omitted."""
        if len(ctx) > retrieval.MAX_HOST_RESULTS:
            notes = notes + [f"{len(ctx) - retrieval.MAX_HOST_RESULTS} host-prepared result(s) omitted from the "
                             "first request (list bound)"]
            ctx = ctx[:retrieval.MAX_HOST_RESULTS]
        return ctx, notes

    def _investigator_chain(self, stage, t0, ctx, notes, agent: str = SPECIALIST, task: str | None = None):
        """-> (ChainEnd, [incomplete]). The incomplete list is empty except when the impact@v2 exploration floor fell
        back to the draft answer. `agent`/`task` name a v3 specialist and its lens task (default: the generalist and
        the policy's investigator task)."""
        events = self.tool_calls()
        host = [events[c["toolCallId"]] for c in ctx]
        doc = prompts.investigator_doc(self.case, ctx, self.omissions("PREPARE") + notes, self.coverage_doc(),
                                       task=task if task is not None
                                       else prompts.investigator_task(self.policy.investigator_prompt))
        if self.coverage_doc() is None:
            doc["coverage"] = ("Two full pinned snapshots are available through retrieval requests; the starting "
                               "context below is bounded and may be truncated or omitted.")
        session = self.new_session(stage, agent)
        unrendered = self.unrendered_ids(ctx, host)

        def chain(turns):
            return retrieval.Chain(self, stage=stage, role="investigator", agent=agent, session=session, t0=t0,
                                   turns=turns, policy=self.policy, host_events=host, unrendered=unrendered)

        def build(d):
            return lambda hop, state: prompts.turn_request(
                self.profile, self.profile_ref, "investigator", d, state, self.policy.requests_per_turn,
                retrieval.RETRIEVAL_VERSION, tools=self.retrieval_tools())

        first = chain(self.policy.investigator_turns)
        end = first.run(build(doc))
        if not self.policy.exploration_floor or end.payload is None or first.history:
            return end, []
        return self._exploration_floor(stage, first, end, chain, build, doc, agent)

    def _exploration_floor(self, stage, first, draft_end, chain, build, doc, agent: str = SPECIALIST):
        """investigator.impact@v2: the agent gave a final answer on its first hop without requesting any context.
        That answer is a DRAFT. When at least two turns, a tool call and context budget remain, the host sends its one
        fixed continuation (prompts.EXPLORATION_FLOOR_CONTINUATION with the draft) as a new chain of the same agent,
        session and budgets (at most identity.FLOOR_MAX_HOPS hops, never more turns than the first chain left), and
        accepts that chain's final answer as it stands. The floor guarantees one extra prompt, not that the model uses a tool.
        Without a final answer there the draft is used: a host stop (deadline) or the run ceiling (budget-exhausted)
        is also disclosed as incomplete; a provider/schema failure or reaching the hop/turn/tool/context limit is
        disclosed only by the trace event (the run stays completed, as with the draft alone). A replay failure,
        cancellation or a spend-book failure (needs reconciliation) fails the agent exactly as impact@v1 would.
        Every decision is a `retrieval.floor` trace event, so the floor is auditable and replays deterministically."""
        draft_id = draft_end.final_call
        rec = dict(stage=stage, agentId=agent, version=prompts.EXPLORATION_FLOOR_VERSION, draftCallId=draft_id)
        turns_left = self.policy.investigator_turns - draft_end.hops
        skip = ("turns" if turns_left < 2 else "tool-calls" if first.tools_exhausted or first._allowed() == 0
                else "context-chars" if first.context_exhausted else None)
        if skip is not None:
            self.recorder.append("retrieval.floor", decision="skipped", reason=skip, **rec)
            return draft_end, []
        self.recorder.append("retrieval.floor", decision="continue", **rec)
        second = chain(min(turns_left, identity.FLOOR_MAX_HOPS))
        end = second.run(build(dict(doc, explorationFloor=prompts.exploration_floor_block(draft_end.payload))))
        end.hops += draft_end.hops
        end.call_ids = draft_end.call_ids + end.call_ids
        if end.payload is not None:
            self.recorder.append("retrieval.floor", decision="final", finalCallId=end.final_call, **rec)
            return end, []
        if end.error is not None and (end.error["code"] in REPLAY_CODES or end.error["code"] in ("cancelled", "internal")
                                      or self.needs_reconciliation):
            return end, []                       # never masked by the draft: fail exactly as impact@v1 would
        inc = []
        if end.error is not None:
            code = end.error["code"]
            why = "stopped" if end.stop is not None else "call-failed"
            self.recorder.append("retrieval.floor", decision="draft", reason=why, errorCode=code, **rec)
            limit = ("deadline" if end.stop is not None or code == "deadline-exceeded"
                     else "budget" if code == "budget-exhausted" else None)
            if limit is not None:                # a real run limit, not just a missing second answer
                n = len(draft_end.payload["hypotheses"])
                who = "" if agent == SPECIALIST else f"specialist {agent}: "
                inc = [self._inc(stage, limit, f"{who}the exploration-floor continuation was stopped ({code}); the "
                                               f"first-hop draft answer ({n} hypothesis(es)) was used")]
        else:
            self.recorder.append("retrieval.floor", decision="draft", reason=end.exhausted, **rec)
        draft_end.hops, draft_end.call_ids = end.hops, end.call_ids
        draft_end.tool_calls = end.tool_calls
        return draft_end, inc

    @staticmethod
    def _exhausted_detail(end) -> str:
        return (f"investigator retrieval ended at the {end.exhausted} limit after {end.hops} hop(s) and "
                f"{end.tool_calls} requested tool call(s) without a final answer; {len(end.unread)} pending "
                f"request(s) were not run: {unread_note(end.unread)}")

    def _investigator_exhausted(self, stage, end):
        inc = [self._inc(stage, "tool-calls-exhausted", self._exhausted_detail(end))]
        payload = {"hypotheses": [], "agents": [{"agentId": SPECIALIST, "specialist": SPECIALIST, "status": "failed"}]}
        return "partial", payload, None, inc

    # ------------------------------------------------------------------ INVESTIGATE: impact@v3 specialists
    def _investigate_v3(self, stage, t0):
        """investigator.impact@v3: the specialists run one after another in prompts.SPECIALIST_AGENTS order, each a v2
        investigator chain (own session and ordinals, the exploration floor, the same prefetched context) with its lens
        task, under its cumulative tool-call and spend ceiling (specialists.BUDGET_RULE). Tolerance:

        * a replay failure, cancellation, an internal error or a spend-book failure (needs reconciliation) fails the
          stage at once, exactly as impact@v2 fails;
        * any other end of one specialist without an answer is recorded in `agents` (status + error), disclosed as an
          INVESTIGATE incomplete entry (its run limit: deadline / soft-deadline / budget, an exhausted counter:
          tool-calls-exhausted, anything else: agent-failure) and the next specialist runs; a systemic failure or an
          unknown provider outcome starts no further specialist (each disclosed as agent-failure);
        * each specialist also has a cumulative time slice of the INVESTIGATE stage ceiling (specialists.TIME_RULE),
          enforced by the gate as a stage-deadline stop; a stopped specialist uses its floor draft when it has one;
        * when no specialist gave an answer or was exhausted, the stage fails with the first specialist's error, as
          the one v2 investigator would.

        The payload lists every hypothesis that resolved (agent order, then output order) and the deterministic
        `merges` (specialists.MERGE_RULE) that VERIFY applies before any verifier call."""
        tool_cum = specialists.cumulative(specialists.tool_pool(self.policy, self.budget,
                                                                identity.tool_limits(self.spec).max_calls))
        spend_cum = specialists.cumulative(investigation_limit(self.budget))
        ceiling = stage_ceiling(stage, self.budget)
        # impact@v4: the specialists split HALF of the (doubled) v4 ceiling exactly as v3 splits its ceiling
        slices = specialists.time_slices(sweeps.specialist_ceiling(ceiling) if self.sweep else ceiling)
        if self.five:                            # impact@v5: the same cumulative scheme over five lanes (lanes.py)
            k = len(self.specialists)
            tool_cum = specialists.cumulative(lanes.tool_pool(self.policy, self.budget, k), k)
            spend_cum = specialists.cumulative(lanes.spend_top(self.budget), k)
            slices = specialists.time_slices(ceiling, k)
        agents, hyps, inc = [], [], []
        first_err = None                     # (error, reason) of the first specialist that failed or was stopped
        usable = 0
        ctx = notes = None
        systemic = False                     # impact@v4: a systemic failure also starts no sweep

        def failed(agent, err, why):
            agents.append({"agentId": agent, "specialist": agent, "status": _agent_status(err), "error": err})
            inc.append(self._inc_doc(stage, why, f"{self.agent_label(agent)} {agent}: {err['code']}: {err['message']}"))

        for i, agent in enumerate(self.specialists):
            # the agent's cumulative time slice gates its start and each of its tool and model calls (the last
            # agent's slice is the stage ceiling itself, so no extra stop exists for it)
            self._time_slice = None if slices is None or slices[i] >= ceiling else (agent, slices[i], ceiling)
            try:
                g = self.gate(stage, t0, new_agent=True)
                if g is not None:
                    reason, err = g
                    if err["code"] == "cancelled":
                        agents.append({"agentId": agent, "specialist": agent, "status": _agent_status(err),
                                       "error": err})
                        return self._v3_failed(agents, err, reason)
                    failed(agent, err, reason)
                    first_err = first_err or (err, reason)
                    continue
                if ctx is None:
                    ctx, notes = self._cap_host_results(*self._investigate_context())
                used = sum(1 for e in self.recorder.events if e["type"] == "tool.call" and e["stage"] == stage)
                self._tool_share, self._spend_ceiling = max(0, tool_cum[i] - used), spend_cum[i]
                try:
                    end, floor_inc = self._investigator_chain(stage, t0, ctx, notes, agent,
                                                              prompts.specialist_task(agent))
                finally:
                    self._tool_share = self._spend_ceiling = None
            finally:
                self._time_slice = None
            inc.extend(floor_inc)
            if end.error is not None:
                err, reason = end.error, (end.stop[0] if end.stop else None)
                if err["code"] in REPLAY_CODES or err["code"] in ("cancelled", "internal") or self.needs_reconciliation:
                    agents.append({"agentId": agent, "specialist": agent, "status": _agent_status(err), "error": err})
                    return self._v3_failed(agents, err, reason)
                limit = reason or {"deadline-exceeded": "deadline", "budget-exhausted": "budget"}.get(err["code"])
                failed(agent, err, limit or "agent-failure")
                first_err = first_err or (err, reason)
                if v3_stops_later_specialists(err):    # systemic or unknown outcome: start no further specialist
                    for later in self.specialists[i + 1:]:
                        failed(later, typed_error(
                            err["code"], f"not started: specialist {agent} failed with {err['code']} (systemic or "
                            "unknown provider outcome), which must not be repeated by every specialist", stage=stage),
                            "agent-failure")
                    systemic = err
                    break
            elif end.exhausted is not None:
                agents.append({"agentId": agent, "specialist": agent, "status": "failed"})
                inc.append(self._inc_doc(stage, "tool-calls-exhausted",
                                         f"specialist {agent}: " + self._exhausted_detail(end)))
                usable += 1
            else:
                agents.append({"agentId": agent, "specialist": agent, "status": "completed"})
                hyps.extend(self._hypotheses(agent, end.payload, end.final_call))
                usable += 1
            if self.fatal:                       # e.g. a snapshot tamper during this specialist's tool calls
                break
        cov = None
        if self.sweep:                           # investigator.impact@v4: the diff-shard sweep phase
            out = self._sweep_phase(stage, t0, ceiling, agents, hyps, inc, systemic, failed)
            if out[0] == "fatal":
                return self._v3_failed(agents, *out[1])
            _, n_usable, err_reason, cov = out
            usable += n_usable
            first_err = first_err or err_reason
        if not usable:
            return self._v3_failed(agents, *first_err)
        if self.five:                            # impact@v5: merge in lane order, then the near-duplicate cap
            merges = specialists.merge(hyps, list(self.specialists))
            payload = {"hypotheses": hyps, "agents": agents, "merges": merges,
                       "collapses": lanes.collapse(hyps, merges)}
            return ("partial" if inc else "completed"), payload, None, inc
        if not self.sweep:
            payload = {"hypotheses": hyps, "agents": agents, "merges": specialists.merge(hyps)}
            return ("partial" if inc else "completed"), payload, None, inc
        payload = {"hypotheses": hyps, "agents": agents,
                   "merges": specialists.merge(hyps, sweeps.merge_order(agents)), "sweep": cov}
        self.recorder.append("investigate.coverage", stage=stage, coverage=cov)
        return ("partial" if inc else "completed"), payload, None, inc

    @staticmethod
    def _inc_doc(stage: str, reason: str, detail: str) -> dict:
        """An incomplete entry returned with the stage artifact (run_stage notes it on the run)."""
        return {"stage": stage, "reason": reason, "detail": detail[:2000]}

    def _v3_failed(self, agents: list, err: dict, reason: str | None):
        """The v3 stage failure: as Engine._agent_failed, with every specialist's status so far."""
        if reason == "soft-deadline":
            self.set_fatal("INVESTIGATE", err, reason="soft-deadline")
        return "failed", {"hypotheses": [], "agents": agents, "merges": []}, err, []

    # ------------------------------------------------------------------ INVESTIGATE: impact@v4 diff-shard sweeps
    def shard_plan(self) -> tuple[list, list, list, list]:
        """-> (reviewable [(path, chars)], shards [[(path, chars)]], excluded [{path, reason}], all changed paths),
        a pure function of the PREPARE artifact and its logged per-file diff results (sweeps.SHARD_RULE)."""
        files = self.artifacts["PREPARE"]["payload"]["files"]
        diffs = {}
        for e in self.recorder.events:
            if e["type"] == "tool.call" and e["stage"] == "PREPARE" and e["tool"] == "diff" \
                    and e["args"].get("path") is not None:
                diffs.setdefault(e["args"]["path"], e)
        rev, excluded = sweeps.reviewable(files, diffs)
        shard_list, over = sweeps.shards(rev)
        excluded = excluded + [{"path": p, "reason": "shard-limit"} for p in over]
        return rev, shard_list, sorted(excluded, key=lambda x: x["path"]), sorted(f["path"] for f in files)

    def _sweep_context(self, paths: list[str]) -> tuple[list, list]:
        """The sweep's prefetched context: the PREPARE changed-path list and the PREPARE diffs of its shard files."""
        mine = set(paths)
        items = [i for i in prompts.context_items(self.recorder.events, "PREPARE")
                 if i["tool"] == "diff" and (i["args"].get("path") is None or i["args"]["path"] in mine)]
        return self._cap_host_results(*self.bounded_context(items))

    def _dispositions(self, agent: str, paths: list[str], found: list[dict]) -> dict:
        """path -> (disposition, reason|None, toolCallId|None, owner hypothesis count) for a sweep's shard files."""
        records = {}
        for e in self.recorder.events:
            if e["type"] == "tool.call" and e["stage"] == "INVESTIGATE" and e["agentId"] == agent \
                    and e["tool"] == "file_disposition" and e["result"]["status"] == "ok":
                records.setdefault(e["args"]["path"], e)
        out = {}
        for p in paths:
            n = sum(1 for h in found if h["location"]["path"] == p)
            if n:
                out[p] = ("issue", None, None, n)
            elif p in records:
                out[p] = ("no-issue", records[p]["args"]["reason"].strip()[:300], records[p]["toolCallId"], 0)
            else:
                out[p] = ("uncovered", None, None, 0)
        return out

    def _missing(self, agent: str, paths: list[str], found: list[dict]) -> list[str]:
        return [p for p, d in self._dispositions(agent, paths, found).items() if d[0] == "uncovered"]

    def _sweep_phase(self, stage, t0, ceiling, agents, hyps, inc, systemic, failed):
        """investigator.impact@v4: one sweep investigator per diff shard, in shard order, after the specialists, under
        the cumulative sweep ceilings of sweeps.BUDGET_RULE. -> ("fatal", (error, reason)) when the stage must fail as
        v3 would (replay failure, cancellation, internal error, spend-book failure), else ("ok", usable sweeps,
        (error, reason)|None of the first failed sweep, SweepCoverage)."""
        rev, shard_list, excluded, all_paths = self.shard_plan()
        k = len(shard_list)
        ids = [sweeps.agent_id(j) for j in range(k)]
        shard_docs = [{"agentId": a, "paths": [p for p, _ in sh], "diffChars": sum(c for _, c in sh)}
                      for a, sh in zip(ids, shard_list)]
        found_by: dict[str, list] = {a: [] for a in ids}
        out_of_shard = [0]                       # sweep hypotheses outside their own shard (sweeps.SCOPE_RULE)

        def cov(note=None):
            files = []
            for d in shard_docs:
                for p, (disp, reason, tid, n) in self._dispositions(d["agentId"], d["paths"],
                                                                    found_by[d["agentId"]]).items():
                    f = {"path": p, "agentId": d["agentId"], "disposition": disp, "hypotheses": n}
                    if reason is not None:
                        f["reason"], f["toolCallId"] = reason, tid
                    files.append(f)
            return sweeps.coverage(len(rev), shard_docs, excluded, files, note, out_of_shard[0])

        if not k:
            return "ok", 0, None, cov(sweeps.NOTE_TINY)
        if self.fatal:                           # e.g. a snapshot tamper: the run fails; no sweep starts
            return "ok", 0, None, cov()
        if systemic:
            for a in ids:
                failed(a, typed_error(systemic["code"], f"not started: a specialist failed with {systemic['code']} "
                                      "(systemic or unknown provider outcome), which must not be repeated by every "
                                      "diff-shard sweep", stage=stage), "agent-failure")
            return "ok", 0, None, cov()
        tool_cum = sweeps.tool_ceilings(self._investigate_reads(stage), k)
        spend_cum = sweeps.spend_ceilings(self.stage_spend(stage), self.budget, k)
        slices = sweeps.time_slices(ceiling, k)
        usable, first_err = 0, None
        for j, (agent, d) in enumerate(zip(ids, shard_docs)):
            self._time_slice = None if slices is None or slices[j] >= ceiling else (agent, slices[j], ceiling)
            try:
                g = self.gate(stage, t0, new_agent=True)
                if g is not None:
                    reason, err = g
                    if err["code"] == "cancelled":
                        agents.append({"agentId": agent, "specialist": agent, "status": _agent_status(err),
                                       "error": err})
                        return "fatal", (err, reason)
                    failed(agent, err, reason)
                    first_err = first_err or (err, reason)
                    continue
                ctx, notes = self._sweep_context(d["paths"])
                self._tool_share = max(0, tool_cum[j] - self._investigate_reads(stage))
                self._spend_ceiling = spend_cum[j]
                try:
                    end, found, more, dropped = self._sweep_agent(stage, t0, agent, j, k, d["paths"], all_paths, ctx,
                                                                  notes)
                    out_of_shard[0] += dropped
                finally:
                    self._tool_share = self._spend_ceiling = None
            finally:
                self._time_slice = None
            inc.extend(more)
            if end.payload is None and end.error is not None:
                err, reason = end.error, (end.stop[0] if end.stop else None)
                if err["code"] in REPLAY_CODES or err["code"] in ("cancelled", "internal") or self.needs_reconciliation:
                    agents.append({"agentId": agent, "specialist": agent, "status": _agent_status(err), "error": err})
                    return "fatal", (err, reason)
                limit = reason or {"deadline-exceeded": "deadline", "budget-exhausted": "budget"}.get(err["code"])
                failed(agent, err, limit or "agent-failure")
                first_err = first_err or (err, reason)
                if v3_stops_later_specialists(err):    # systemic or unknown outcome: start no further sweep
                    for later in ids[j + 1:]:
                        failed(later, typed_error(
                            err["code"], f"not started: sweep {agent} failed with {err['code']} (systemic or unknown "
                            "provider outcome), which must not be repeated by every sweep", stage=stage),
                            "agent-failure")
                    break
            elif end.payload is None:            # an exhausted counter ended the first chain without an answer
                agents.append({"agentId": agent, "specialist": agent, "status": "failed"})
                inc.append(self._inc_doc(stage, "tool-calls-exhausted",
                                         f"sweep investigator {agent}: " + self._exhausted_detail(end)))
                usable += 1
            else:
                agents.append({"agentId": agent, "specialist": agent, "status": "completed"})
                found_by[agent] = found
                hyps.extend(found)
                usable += 1
            if self.fatal:
                break
        return "ok", usable, first_err, cov()

    def _investigate_reads(self, stage: str) -> int:
        """INVESTIGATE tool calls that count against read budgets (file_disposition records have their own)."""
        return sum(1 for e in self.recorder.events if e["type"] == "tool.call" and e["stage"] == stage
                   and e["tool"] != retrieval.DISPOSITION_TOOL)

    def _in_shard(self, found: list, paths: list) -> tuple[list, int]:
        """sweeps.SCOPE_RULE: a sweep keeps only its hypotheses located in its own shard."""
        mine = set(paths)
        keep = [h for h in found if h["location"]["path"] in mine]
        return keep, len(found) - len(keep)

    def _sweep_agent(self, stage, t0, agent, j, k, paths, all_paths, ctx, notes):
        """One diff-shard sweep investigator: its retrieval chain, then the disposition check and at most one
        continuation (sweeps.DISPOSITION_RULE). -> (ChainEnd, [resolved in-shard hypotheses], [incomplete], number of
        resolved hypotheses dropped as outside the shard). The ChainEnd is the first chain's (payload set when it gave a
        final answer), or the continuation's error when that must fail the stage as v3 would (payload then None)."""
        events = self.tool_calls()
        host = [events[c["toolCallId"]] for c in ctx]
        doc = prompts.investigator_doc(self.case, ctx, self.omissions("PREPARE") + notes, self.coverage_doc(),
                                       task=prompts.SWEEP_TASK)
        if self.coverage_doc() is None:
            doc["coverage"] = ("Two full pinned snapshots are available through retrieval requests; the starting "
                               "context below is bounded and may be truncated or omitted.")
        doc["sweep"] = prompts.sweep_block(j + 1, k, paths, all_paths)
        session = ToolSession(self.view, stage=stage, agent_id=agent, limits=self.limits_for(), clock=self.clock,
                              tools=SWEEP_TOOLS)
        unrendered = self.unrendered_ids(ctx, host)

        allowance = (frozenset(paths), sweeps.disposition_allowance(len(paths)))

        def chain(turns):
            return retrieval.Chain(self, stage=stage, role="investigator", agent=agent, session=session, t0=t0,
                                   turns=turns, policy=self.policy, host_events=host, unrendered=unrendered,
                                   dispositions=allowance)

        def build(d):
            return lambda hop, state: prompts.turn_request(
                self.profile, self.profile_ref, "investigator", d, state, self.policy.requests_per_turn,
                retrieval.RETRIEVAL_VERSION, tools=prompts.SWEEP_RETRIEVAL_TOOLS)

        rec = dict(stage=stage, agentId=agent, version=sweeps.DISPOSITION_RULE)
        first = chain(self.policy.investigator_turns)
        end = first.run(build(doc))
        if end.payload is None:
            why = "stopped" if end.stop is not None else "call-failed" if end.error is not None else end.exhausted
            extra = {"errorCode": end.error["code"]} if why in ("stopped", "call-failed") else {}
            self.recorder.append("sweep.disposition", decision="no-answer", reason=why,
                                 missing=self._missing(agent, paths, []), **extra, **rec)
            return end, [], [], 0
        found, dropped = self._in_shard(self._hypotheses(agent, end.payload, end.final_call), paths)
        missing = self._missing(agent, paths, found)
        if not missing:
            self.recorder.append("sweep.disposition", decision="complete", answerCallId=end.final_call, missing=[],
                                 **rec)
            return end, found, [], dropped
        skip = ("context-chars" if first.context_exhausted else "tool-calls" if first.disposition_left() <= 0 else None)
        if skip is not None:                     # no disposition can be recorded any more: no continuation
            self.recorder.append("sweep.disposition", decision="skipped", reason=skip, answerCallId=end.final_call,
                                 missing=missing, **rec)
            return end, found, [], dropped
        self.recorder.append("sweep.disposition", decision="continue", answerCallId=end.final_call, missing=missing,
                             **rec)
        second = chain(sweeps.CONTINUATION_HOPS).run(
            build(dict(doc, dispositionCheck=prompts.disposition_block(missing, end.payload))))
        if second.payload is not None:
            have = {h["id"] for h in found}
            more, dropped2 = self._in_shard([h for h in self._hypotheses(agent, second.payload, second.final_call)
                                             if h["id"] not in have], paths)
            found = found + more
            self.recorder.append("sweep.disposition", decision="final", finalCallId=second.final_call,
                                 missing=self._missing(agent, paths, found), **rec)
            return end, found, [], dropped + dropped2
        if second.error is not None and (second.error["code"] in REPLAY_CODES
                                         or second.error["code"] in ("cancelled", "internal")
                                         or self.needs_reconciliation):
            return second, [], [], 0              # never masked by the first answer: fail exactly as v3 would
        inc = []
        if second.error is not None:
            code = second.error["code"]
            why = "stopped" if second.stop is not None else "call-failed"
            self.recorder.append("sweep.disposition", decision="draft", reason=why, errorCode=code,
                                 missing=self._missing(agent, paths, found), **rec)
            limit = ("deadline" if second.stop is not None or code == "deadline-exceeded"
                     else "budget" if code == "budget-exhausted" else None)
            if limit is not None:
                inc = [self._inc_doc(stage, limit, f"sweep investigator {agent}: the disposition continuation was stopped ({code}); "
                                                   "files without a disposition are disclosed as uncovered")]
        else:
            self.recorder.append("sweep.disposition", decision="draft", reason=second.exhausted,
                                 missing=self._missing(agent, paths, found), **rec)
        return end, found, inc, dropped

    @property
    def coverage_record(self) -> dict | None:
        """The host coverage record that is rendered into comments.json/review.md (None = plain full view)."""
        return self.rcov if self.rcov is not None else self.cov

    def coverage_doc(self) -> dict | None:
        """Model-visible partial/repository coverage statement + bounded detail; None for the plain full view
        (prompt unchanged)."""
        if self.rcov is not None:
            return coverage_doc(self.rcov, 100)
        return None if self.cov is None else coverage_doc(self.cov, 100)

    def changed_head_paths(self) -> set | None:
        """Head-side paths this change touches, from PREPARE; None when the change list is unknown (a full-view
        PREPARE that could not list it), in which case the changed-file requirement cannot be applied."""
        art = self.artifacts["PREPARE"]
        if art.get("incomplete") and self.cov is None:
            return None
        return {f["path"] for f in art["payload"]["files"] if f["status"] != "deleted"}

    def _agent_failed(self, err: dict, reason: str | None = None):
        payload = {"hypotheses": [], "agents": [{"agentId": SPECIALIST, "specialist": SPECIALIST,
                                                 "status": _agent_status(err), "error": err}]}
        if reason == "soft-deadline":
            self.set_fatal("INVESTIGATE", err, reason="soft-deadline")
        return "failed", payload, err, []

    # ------------------------------------------------------------------ VERIFY
    def candidates(self) -> tuple[list, dict]:
        """-> ([(original index n, hypothesis id, draft)], {id: Hypothesis}) rebuilt from the logged successful
        investigator call and the INVESTIGATE artifact (so a resumed run needs nothing else)."""
        hyps = {h["id"]: h for h in self.artifacts["INVESTIGATE"]["payload"]["hypotheses"]}
        if self.specialists is not None:
            return self._v3_candidates(), hyps
        # the last usable INVESTIGATE answer that carries a role payload (a non-final Turn hop has none); with the
        # impact@v2 exploration floor, the answer its last retrieval.floor decision names (the draft when it was used)
        src = self._floor_source()
        drafts = next((p["hypotheses"] for e in reversed(self.recorder.events)
                       if e["type"] == "model.call" and e["stage"] == "INVESTIGATE"
                       and (src is None or e["callId"] == src)
                       and (p := terminal_payload(e)) is not None), [])
        return [(n, hypothesis_id(SPECIALIST, n, d["claim"], d["location"]["path"], d["location"]["line"]), d)
                for n, d in enumerate(drafts)], hyps

    def _v3_candidates(self) -> list:
        """investigator.impact@v3: every completed specialist's accepted answer, interleaved round-robin in specialist
        order (contracts 0, logic 0, safety 0, contracts 1, ...), as [(running index, hypothesis id, draft)]. The
        running index is unique across specialists. impact@v5 orders each lane by value first (lanes.value_key)."""
        lane_list = []
        for a in self.artifacts["INVESTIGATE"]["payload"]["agents"]:
            if a["status"] != "completed":
                continue
            agent = a["agentId"]
            if self.sweep and agent not in specialists.AGENTS:      # impact@v4 diff-shard sweep lane
                lane_list.append(self._sweep_lane(agent))
                continue
            src = self._floor_source(agent)
            drafts = next((p["hypotheses"] for e in reversed(self.recorder.events)
                           if e["type"] == "model.call" and e["stage"] == "INVESTIGATE" and e["agentId"] == agent
                           and (src is None or e["callId"] == src)
                           and (p := terminal_payload(e)) is not None), [])
            order = (sorted(range(len(drafts)), key=lambda n: lanes.value_key(drafts[n], n)) if self.five
                     else range(len(drafts)))          # impact@v5: a lane's most valuable hypotheses first
            lane_list.append([(hypothesis_id(agent, n, drafts[n]["claim"], drafts[n]["location"]["path"],
                                         drafts[n]["location"]["line"]), drafts[n]) for n in order])
        out = [lane[k] for k in range(max(map(len, lane_list), default=0)) for lane in lane_list if k < len(lane)]
        return [(i, hid, d) for i, (hid, d) in enumerate(out)]

    def _sweep_lane(self, agent: str) -> list:
        """An impact@v4 sweep's VERIFY lane: the hypotheses of its first final answer, then those its disposition
        continuation added (per its `sweep.disposition` events), as [(hypothesis id, draft)] without repeated ids. A
        draft located outside the sweep's shard is noted in self.off_shard (VERIFY drops it, sweeps.SCOPE_RULE)."""
        srcs = [e.get("answerCallId") or e["finalCallId"] for e in self.recorder.events
                if e["type"] == "sweep.disposition" and e["agentId"] == agent
                and e["decision"] in ("complete", "continue", "skipped", "final")]
        cov = self.artifacts["INVESTIGATE"]["payload"].get("sweep") or {"shards": []}
        mine = next((set(d["paths"]) for d in cov["shards"] if d["agentId"] == agent), set())
        lane, seen = [], set()
        for src in srcs:
            ev = self.model_event(src)
            for n, d in enumerate(((terminal_payload(ev) if ev is not None else None) or {"hypotheses": []})["hypotheses"]):
                hid = hypothesis_id(agent, n, d["claim"], d["location"]["path"], d["location"]["line"])
                if d["location"]["path"] not in mine:
                    self.off_shard[hid] = agent
                if hid not in seen:
                    seen.add(hid)
                    lane.append((hid, d))
        return lane

    def sweep_shards(self) -> int:
        """Number of impact@v4 diff shards of this run (0 without sweeps), from the INVESTIGATE artifact."""
        cov = self.artifacts["INVESTIGATE"]["payload"].get("sweep") if self.sweep else None
        return 0 if cov is None else len(cov["shards"])

    def _floor_source(self, agent: str | None = None) -> str | None:
        """The investigator call whose answer INVESTIGATE used, per the last `retrieval.floor` decision that settles it
        (skipped/draft: the draft, final: the continuation's final answer). None without such an event (every
        non-v2 run, and a v2 run whose first answer requested context), so candidates() keeps its rule. `agent`
        (v3) restricts it to that specialist's decisions."""
        ev = next((e for e in reversed(self.recorder.events) if e["type"] == "retrieval.floor"
                   and e["stage"] == "INVESTIGATE" and e["decision"] != "continue"
                   and (agent is None or e["agentId"] == agent)), None)
        if ev is None:
            return None
        return ev["finalCallId"] if ev["decision"] == "final" else ev["draftCallId"]

    def verify(self, t0):
        stage = "VERIFY"
        if self.fatal:
            return self.skipped(stage)
        cands, hyps = self.candidates()
        findings, records, drops, inc = [], [], [], []
        session = self.new_session(stage, VERIFIER_AGENT)
        shards = self.sweep_shards()                  # impact@v4: the cap scales with the shards; sessions renew
        cap = sweeps.verify_cap(shards) if self.sweep else specialists.MAX_VERIFY_CANDIDATES
        scaled = self.sweep or self.five
        if self.five:                                 # impact@v5: the cap scales with the extra lanes
            shards, cap = lanes.extra_lanes(self.specialists), lanes.verify_cap(len(self.specialists))
        collapsed = {m: g["keptIds"] for g in (self.artifacts["INVESTIGATE"]["payload"].get("collapses", ())
                                               if self.five else ()) for m in g["collapsedIds"]}
        sessions = {VERIFIER_AGENT: session}
        stop = None                                   # (reason, error) once a global stop applies
        family = self.profile["roles"]["verifier"]["family"]
        v3 = self.specialists is not None
        merges = self.artifacts["INVESTIGATE"]["payload"].get("merges", ()) if v3 else ()
        merged_into = {m: g["keptId"] for g in merges for m in g["mergedIds"]}
        outcome: dict = {}                            # v3: verified hypothesis id -> it became a finding
        kept = 0

        def attempt(n, hid):
            """Verify one candidate (gate, stop, verifier chain). -> True to stop the stage loop (fatal)."""
            nonlocal stop
            if stop is None:
                g = self.gate(stage, t0)
                if g is not None:
                    stop = g
            if stop is None and shards and self.run_spend() >= sweeps.judge_reserve_floor(self.budget):
                stop = ("budget", typed_error(       # impact@v4: keep the JUDGE spend reserve (sweeps.JUDGE_RESERVE_BP)
                    "budget-exhausted", "VERIFY stopped before this candidate to keep the JUDGE spend reserve "
                    f"({sweeps.JUDGE_RESERVE_BP} bp of the run ceiling, {sweeps.BUDGET_RULE})", stage=stage,
                    detail={"scope": "judge-reserve", "spentUsdMicros": self.run_spend(),
                            "floorUsdMicros": sweeps.judge_reserve_floor(self.budget)}))
            if self.fatal and self.fatal["status"] == "failed" and self.fatal["stage"] == stage:
                return True
            if stop is not None:
                reason, err = stop
                inc.append(self._inc(stage, reason))
                if reason == "cancelled":
                    self.set_fatal(stage, err)
                drops.append({"subjectIds": [hid], "stage": "VERIFY", "reason": reason,
                              "detail": err["message"][:500]})
                return False
            name = sweeps.verifier_agent(kept - 1, shards) if scaled else VERIFIER_AGENT
            if name not in sessions:
                sessions[name] = self.new_session(stage, name)
            rec, finding, drop, more = self.verify_one(sessions[name], n, hyps[hid], t0, family)
            inc.extend(more)
            if rec is None:
                return False
            records.append(rec)
            outcome[hid] = finding is not None
            if finding is not None:
                findings.append(finding)
            if drop is not None:
                drops.append(drop)
            return False

        def over_cap(hid) -> bool:
            nonlocal kept
            if not v3:
                return False
            kept += 1
            if kept <= cap:
                return False
            drops.append({"subjectIds": [hid], "stage": "VERIFY", "reason": "over-cap",
                          "detail": (f"more than {cap} distinct specialist and diff-shard sweep hypotheses "
                                     f"({sweeps.VERIFY_RULE}); later ones (round-robin across specialist and sweep "
                                     "lanes) are not verified" if self.sweep else
                                     f"more than {cap} distinct specialist lane hypotheses ({lanes.VERIFY_RULE}); later "
                                     "ones (round-robin across the five specialist lanes) are not verified" if self.five
                                     else f"more than {specialists.MAX_VERIFY_CANDIDATES} distinct specialist "
                                     "hypotheses; later ones (round-robin specialist order) are not verified")})
            return True

        for n, hid, draft in cands:
            if hid in self.off_shard:           # impact@v4: a sweep's draft outside its own shard takes no slot
                drops.append({"subjectIds": [hid], "stage": "VERIFY", "reason": "suppressed",
                              "detail": f"located outside the shard of {self.off_shard[hid]} ({sweeps.SCOPE_RULE}); "
                                        "that file is reviewed by its own sweep investigator"})
                continue
            if hid not in hyps:
                drops.append({"subjectIds": [hid], "stage": "VERIFY", "reason": "invalid-citation",
                              "detail": "investigator citation or location did not resolve against the pinned snapshots, "
                                        "or lies outside the files this change modified"})
                continue
            if hid in merged_into:              # v3: a later specialist's duplicate, decided after its kept one
                continue
            if hid in collapsed:                # impact@v5: a true near-duplicate, decided after its kept member(s)
                continue
            if over_cap(hid):
                continue
            if attempt(n, hid):
                break
        else:
            # v3: a kept hypothesis that yielded no finding hands VERIFY its first merged duplicate (within the cap);
            # every other duplicate is dropped as merged, without a verifier call
            index = {hid: n for n, hid, _ in cands}
            # impact@v5: the near-duplicate fallback first, so a collapsed merge keptId verified without a finding
            # still hands VERIFY its own first merged duplicate below (lanes.NEAR_DUP_RULE)
            halted = self.five and self._verify_collapsed(index, hyps, outcome, attempt, over_cap, drops, lambda: stop)
            for g in sorted(merges if not halted else (), key=lambda g: index.get(g["keptId"], len(index))):
                dups = [m for m in g["mergedIds"] if m in hyps and m in index]
                retry = bool(dups) and outcome.get(g["keptId"]) is False and stop is None
                if retry and not over_cap(dups[0]):
                    if attempt(index[dups[0]], dups[0]):
                        break
                    dups = dups[1:]
                elif retry:
                    dups = dups[1:]                  # over-cap already recorded its drop
                for m in dups:
                    drops.append({"subjectIds": [m], "stage": "VERIFY", "reason": "merged",
                                  "detail": f"duplicate of {g['keptId']} ({specialists.MERGE_RULE}: same head path and "
                                            f"category, start lines within {specialists.MERGE_LINE_WINDOW}; the "
                                            "earlier specialist's is kept)"})
        if self.fatal and self.fatal["stage"] == stage and self.fatal["status"] == "failed":
            return "failed", self.empty(stage), self.fatal["error"], []
        for sess in sessions.values():
            if sess.incomplete and not any(i["reason"] == sess.incomplete for i in inc):
                inc.append(self._inc(stage, sess.incomplete))
        status = "partial" if inc else "completed"
        return status, {"findings": findings, "verifications": records, "drops": drops}, None, inc

    def _verify_collapsed(self, index, hyps, outcome, attempt, over_cap, drops, stopped) -> bool:
        """impact@v5 (lanes.NEAR_DUP_RULE): a near-duplicate group none of whose kept members yielded a finding hands
        VERIFY its best collapsed member (within the cap); every other collapsed member is dropped as merged.
        -> True when a verifier attempt failed the stage (nothing further runs)."""
        for g in sorted(self.artifacts["INVESTIGATE"]["payload"].get("collapses", ()),
                        key=lambda g: min(index.get(k, len(index)) for k in g["keptIds"])):
            rest = [m for m in g["collapsedIds"] if m in hyps and m in index]
            verified = [outcome.get(k) for k in g["keptIds"]]
            retry = bool(rest) and all(v is False for v in verified) and stopped() is None
            if retry and not over_cap(rest[0]):
                if attempt(index[rest[0]], rest[0]):
                    return True
                rest = rest[1:]
            elif retry:
                rest = rest[1:]                          # over-cap already recorded its drop
            for m in rest:
                drops.append({"subjectIds": [m], "stage": "VERIFY", "reason": "merged",
                              "detail": f"near-duplicate of {', '.join(g['keptIds'])} ({lanes.NEAR_DUP_RULE}: same "
                                        "head path, category and overlapping lines, similar claim; the best evidenced "
                                        "is verified and this one only if that yields no finding)"[:2000]})
        return False

    def verify_one(self, session, n, hyp, t0, family):
        """-> (VerificationRecord, Finding|None, DropRecord|None, [incomplete])."""
        stage, hid = "VERIFY", hyp["id"]
        inc = []
        loc = hyp["location"]
        items, omitted, host_ids = [], [], []
        window = self.context_window(loc)
        plan = ([("read_file", window)] if window else []) + [("diff", {"path": loc["path"]})]
        if window is None:
            omitted.append(f"read_file window for {loc['path']} not requested: file not readable as pinned text")
        for tool, args in plan:
            call, why = self.tool(session, tool, args, t0)
            if call is None:
                omitted.append(f"{tool} for {loc['path']} not collected: {why}")
                inc.append(self.stopped(stage, why, f"{tool} context for {hid} not collected"))
                continue
            r = call.result
            host_ids.append(call.tool_call_id)
            items.append({"toolCallId": call.tool_call_id, "tool": tool, "args": call.args, "status": r["status"],
                          "completeness": r["completeness"], "truncated": r["truncated"], "notice": r["notice"],
                          "excerpts": [e["excerpt"] for e in r["evidence"]]})
        if self.fatal and self.fatal["status"] == "failed":
            return None, None, None, inc
        items, notes = self.bounded_context(items)
        if self.turn_role("verifier"):
            end = self._verifier_chain(session, t0, hyp, items, omitted + notes, host_ids)
            call_ids = end.call_ids
            if end.error is not None:
                return self._verify_failed(hid, end.error, call_ids, inc)
            if end.exhausted is not None:
                return self._verify_exhausted(hid, end, call_ids, inc)
            out, final = end.payload, end.final_call
        else:
            req = prompts.verifier_request(self.profile, self.profile_ref, self.case, hyp, items, omitted + notes,
                                           coverage=self.coverage_doc())
            g = self.gate(stage, t0, scope="model")  # the last tool call may have crossed a deadline / cancel
            if g is not None:
                return self._verify_failed(hid, g[1], [], inc)
            out, err, attempts = self.model_call(stage, "verifier", session.agent_id, n, req)
            call_ids = [a.call_id for a in attempts if a.call_id]
            if err is not None:
                return self._verify_failed(hid, err, call_ids, inc)
            final = next(a.call_id for a in reversed(attempts) if a.outcome == "ok")
        ev, problems = materialize_evidence(out["evidence"], self.citable(final), f"verifier:{session.agent_id}",
                                            self.resolver)
        rec = {"hypothesisId": hid, "verdict": out["verdict"], "evidence": ev, "callIds": call_ids[-10:],
               "notes": out["notes"][:4000]}
        if out["verdict"] == "refuted":
            if problems or not ev:
                rec["verdict"] = "uncertain"
                rec["notes"] = ("Refutation had no resolvable citation and was converted to uncertain. "
                                + rec["notes"])[:4000]
                return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": "uncertain",
                                   "detail": "uncited or unresolvable refutation"}, inc
            return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": "refuted"}, inc
        if out["verdict"] == "uncertain":
            return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": "uncertain"}, inc
        if problems or not ev:
            rec["verdict"] = "uncertain"
            rec["evidence"] = []
            return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": "invalid-citation",
                               "detail": "; ".join(problems)[:1000] or "confirmation had no citation"}, inc
        if not self.relevant_citation(hyp, ev):
            rec["verdict"] = "uncertain"
            rec["evidence"] = []
            return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": "invalid-citation",
                               "detail": "no verifier citation is tied to the proposed location or to the code "
                                         "the investigator cited; resolvable but unrelated code does not "
                                         "verify a claim"}, inc
        finding = {k: hyp[k] for k in ("id", "runId", "specialist", "claim", "category", "suspectedSeverity", "impact",
                                       "location", "evidence", "modelFamily", "sourceCallId")}
        for k in ("mechanism", "reach", "confidence"):
            if k in hyp:
                finding[k] = hyp[k]
        finding["verification"] = {"verdict": "confirmed", "refutationAttempts": 1, "verifierFamily": family,
                                   "notes": out["notes"][:4000], "evidence": ev, "callIds": [final]}
        finding["severityBasis"] = {"impact": out["impact"], "reachable": out["reachable"]}
        problems = [str(i) for i in validate("Finding", finding)] + \
                   [str(i) for i in check_finding_provenance(finding, list(self.recorder.events))]
        if problems:
            err = typed_error("contract-violation", "confirmed finding failed provenance: " + problems[0][:300],
                              stage=stage)
            return self._verify_failed(hid, err, call_ids, inc)
        rec["verdict"] = "confirmed"
        return rec, finding, None, inc

    def _verifier_chain(self, session, t0, hyp, items, omitted, host_ids):
        events = self.tool_calls()
        host = [events[i] for i in host_ids]
        doc = prompts.verifier_doc(self.case, hyp, items, omitted, self.coverage_doc(),
                                   task=prompts.verifier_task(self.policy.verifier_prompt))
        chain = retrieval.Chain(self, stage="VERIFY", role="verifier", agent=session.agent_id, session=session, t0=t0,
                                turns=self.policy.verifier_turns, policy=self.policy, hypothesis_id=hyp["id"],
                                host_events=host, hyp_calls_used=len(host),
                                unrendered=self.unrendered_ids(items, host))
        return chain.run(lambda hop, state: prompts.turn_request(
            self.profile, self.profile_ref, "verifier", doc, state, self.policy.requests_per_turn,
            retrieval.RETRIEVAL_VERSION, hypothesis_id=hyp["id"], tools=self.retrieval_tools()))

    def retrieval_tools(self) -> list | None:
        """The model-visible tool list: None keeps the frozen retrieval@2 list (legacy bytes unchanged)."""
        return prompts.IMPACT_RETRIEVAL_TOOLS if self.impact else None

    def _verify_exhausted(self, hid, end, call_ids, inc):
        """A retrieval cap ended the chain: no final answer exists and none is invented. The claim stays
        uncertain; pending requests are recorded as unread, never as findings."""
        detail = (f"verifier retrieval for {hid} ended at the {end.exhausted} limit after {end.hops} hop(s) and "
                  f"{end.tool_calls} requested tool call(s) without a final answer; {len(end.unread)} pending "
                  f"request(s) were not run: {unread_note(end.unread)}")
        inc.append(self._inc("VERIFY", "tool-calls-exhausted", detail))
        rec = {"hypothesisId": hid, "verdict": "uncertain", "evidence": [], "callIds": call_ids[-10:],
               "notes": ("No verifier verdict: " + detail)[:4000]}
        return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": "uncertain",
                           "detail": detail[:2000]}, inc

    def relevant_citation(self, hyp: dict, ev: list) -> bool:
        """True when at least one verifier citation bears on THIS claim: code on the proposed path within the
        context window of the location, code overlapping a code citation of the proposal, or a tool result for the
        proposed path. Further citations (other files, callers) are kept as extra proof but cannot stand alone."""
        loc = hyp["location"]
        lo, hi = loc["line"] - VERIFY_WINDOW, loc.get("endLine", loc["line"]) + VERIFY_WINDOW
        proposed = [(e["path"], e["lines"]) for e in hyp["evidence"] if e["kind"] == "code"]
        tools = self.tool_calls()
        for e in ev:
            if e["kind"] == "code":
                a, b = e["lines"]
                if e["path"] == loc["path"] and a <= hi and b >= lo:
                    return True
                if any(p == e["path"] and a <= pb and b >= pa for p, (pa, pb) in proposed):
                    return True
            else:
                tc = tools.get(e.get("toolCallId"))
                if tc is not None and tc["args"].get("path") == loc["path"]:
                    return True
        return False

    def context_window(self, loc: dict) -> dict | None:
        """Head lines around a candidate. The end is snapped back off trailing blank lines: contracts
        excerpt_matches strips one trailing newline from an excerpt, so a range that ENDS on a blank line can
        never resolve and read_file would report the pinned file as tampered (reported to the contracts/tools
        owners, see S0-07.md "Module defects"). Line data comes from the pinned snapshot, not from a model."""
        head = self.spec.head
        lines = snaps.head_lines(head.root, head.manifest, loc["path"])
        if lines is None:
            return None
        start = max(1, loc["line"] - VERIFY_WINDOW)
        end = min(len(lines), loc.get("endLine", loc["line"]) + VERIFY_WINDOW)
        while end >= start and lines[end - 1] == "":
            end -= 1
        if end < start:
            return None
        return {"side": "head", "path": loc["path"], "start_line": start, "end_line": end}

    def _verify_failed(self, hid, err, call_ids, inc):
        rec = {"hypothesisId": hid, "verdict": "failed", "evidence": [], "callIds": call_ids[-10:], "error": err}
        if err["code"] in REPLAY_CODES:
            self.set_fatal("VERIFY", err)
            return rec, None, None, inc
        if err["code"] == "cancelled":
            reason, drop = "cancelled", "cancelled"
        elif err["code"] == "deadline-exceeded":
            reason, drop = "deadline", "deadline"
        elif err["code"] == "budget-exhausted":
            reason, drop = "budget", "budget"
        else:
            reason, drop = "verifier-failure", "verifier-failed"
        inc.append(self._inc("VERIFY", reason, err["code"]))
        if reason == "cancelled":
            self.set_fatal("VERIFY", err)
        return rec, None, {"subjectIds": [hid], "stage": "VERIFY", "reason": drop,
                           "detail": f"{err['code']}: {err['message']}"[:1000]}, inc

    # ------------------------------------------------------------------ JUDGE
    def judge(self, t0):
        stage = "JUDGE"
        if self.fatal and self.fatal["status"] == "failed":
            return self.skipped(stage)
        vpayload = self.artifacts["VERIFY"]["payload"]
        findings = vpayload["findings"]
        inc, drops = [], []
        comments: list[dict] = []
        if findings:
            comments, drops, inc = self._judge_findings(findings, t0)
            if self.fatal and self.fatal["status"] == "failed":
                return "failed", self.empty(stage), self.fatal["error"], []
        if self.orig is not None and self.fatal is None:
            got = self.gw.unconsumed()
            if got != self.expected_unconsumed:
                err = typed_error("replay-mismatch", f"{got - self.expected_unconsumed} recorded model call(s) "
                                  "were never consumed by the replay", stage=stage)
                return "failed", self.empty(stage), err, []
        status = "partial" if inc else "completed"
        return status, {"comments": comments, "drops": drops}, None, inc

    def _judge_findings(self, findings, t0):
        stage = "JUDGE"
        inc, drops = [], []
        events = list(self.recorder.events)
        for f in findings:                                       # revalidate against this run's actual events
            bad = check_finding_provenance(f, events)
            if bad:
                self.set_fatal(stage, typed_error("contract-violation", "finding failed provenance revalidation: "
                                                  + str(bad[0])[:300], stage=stage))
                return [], [], []
        index = {h: n for n, h, _ in self.candidates()[0]}
        live = []
        for f in findings:
            if judging.disabled_by_config(f):
                drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "ignored-by-config",
                              "detail": f"category {f['category']} is disabled by default"})
            else:
                live.append((index.get(f["id"], 10**6), f))
        live.sort(key=lambda t: t[0])
        tools = self.tool_calls()
        head = self.spec.head
        entries, seen_fp, same_claim = [], {}, {}
        for idx, f in live:
            loc = f["location"]
            anchor = snaps.anchor_text(head.root, head.manifest, loc["path"], loc["line"], loc.get("endLine", loc["line"]))
            if anchor is None:
                drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "suppressed",
                              "detail": "anchor lines do not exist in the pinned head file"})
                continue
            title, body = prompts.fallback_wording(f)
            c = judging.build_comment(f, run_id=self.run["id"], head_snapshot_id=self.head_id, anchor=anchor,
                                      tool_calls=tools, title=title, body=body, suggestion=None)
            if c["fingerprint"] in seen_fp:       # identical category, path, anchor text AND claim: same claim twice
                keeper = seen_fp[c["fingerprint"]]
                same_claim.setdefault(keeper, []).append(f["id"])
                drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "merged",
                              "detail": f"identical claim and anchor as {keeper}; its id is kept on that comment"})
                continue
            seen_fp[c["fingerprint"]] = f["id"]
            entries.append((f, c))
        order = {f["id"]: index.get(f["id"], 10**6) for f, _ in entries}
        by_id = {f["id"]: (f, c) for f, c in entries}
        # issue-key equality only nominates candidate duplicates: nothing is merged unless the judge proposes it
        groups = judging.candidate_groups([f for f, _ in entries])
        top, over = judging.rank_and_cap(entries, self.host.comment_cap)
        top_ids = {f["id"] for f, _ in top}
        in_play = [g for g in groups if any(i in top_ids for i in g)]
        judged = top + [(f, c) for f, c in over if any(f["id"] in g for g in in_play)]
        wording, proposed = {}, []
        if judged:
            g = self.gate(stage, t0, scope="model")
            if g is not None:
                inc.append(self._inc(stage, g[0], "deterministic wording used"))
                if g[0] == "cancelled":
                    self.set_fatal(stage, g[1])
            else:
                req = prompts.judge_request(self.profile, self.profile_ref, self.case,
                                            [(f, c["severity"]) for f, c in judged], in_play,
                                            coverage=self.coverage_doc(),
                                            task=prompts.judge_task(self.profile["roles"]["judge"]["promptVersion"]))
                out, err, _ = self.model_call(stage, "judge", JUDGE_AGENT, 0, req)
                if err is not None:
                    if err["code"] in REPLAY_CODES:
                        self.set_fatal(stage, err)
                    else:
                        reason = {"budget-exhausted": "budget", "deadline-exceeded": "deadline",
                                  "cancelled": "cancelled"}.get(err["code"], "agent-failure")
                        inc.append(self._inc(stage, reason, f"judge unavailable ({err['code']}); deterministic wording"))
                        if reason == "cancelled":
                            self.set_fatal(stage, err)
                else:
                    wording, proposed, problem = prompts.check_wording(out, [f["id"] for f, _ in judged], in_play)
                    if problem:
                        wording, proposed = {}, []
                        inc.append(self._inc(stage, "agent-failure", f"judge output rejected: {problem}"))
        if self.fatal and self.fatal["status"] == "failed":
            return [], [], []
        final, away = [], set()
        for ids in proposed:                       # host-validated judge groups: primary = most severe, then earliest
            members = sorted((by_id[i] for i in ids), key=lambda fc: (RANK[fc[1]["severity"]], order[fc[0]["id"]]))
            title, body, sug = wording.pop(ids[0])
            merged = judging.merge_group(members, title, body, sug)
            final.append((members[0][0], merged))
            for f, _ in members[1:]:
                away.add(f["id"])
                drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "merged",
                              "detail": f"judge-proposed duplicate of {members[0][0]['id']} inside one issue-key@2 "
                                        "candidate group; host-validated, claim and evidence kept on that comment"})
            away.add(members[0][0]["id"])
        for f, c in entries:
            if f["id"] in away:
                continue
            if f["id"] in wording:
                title, body, sug = wording[f["id"]]
                c = judging.build_comment(f, run_id=self.run["id"], head_snapshot_id=self.head_id,
                                          anchor=snaps.anchor_text(head.root, head.manifest, f["location"]["path"],
                                                                   f["location"]["line"],
                                                                   f["location"].get("endLine", f["location"]["line"])),
                                          tool_calls=tools, title=title, body=body, suggestion=sug)
            final.append((f, c))
        top, over = judging.rank_and_cap(final, self.host.comment_cap)
        for f, c in over:
            drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "over-cap",
                          "detail": f"ranked below the cap of {self.host.comment_cap}"})
        comments = []
        for f, c in top:
            extra = [i for fid in c["findingIds"] for i in same_claim.get(fid, []) if i not in c["findingIds"]]
            if extra:
                c = {**c, "findingIds": (c["findingIds"] + extra)[:50]}
            bad = judging.revalidate_comment(
                c, head_snapshot_id=self.head_id, resolver=self.resolver,
                anchor_ok=lambda p, a, b: snaps.anchor_text(head.root, head.manifest, p, a, b) is not None)
            if bad:
                self.set_fatal(stage, typed_error("contract-violation", "comment failed final validation: " + bad[0][:300],
                                                  stage=stage))
                return [], [], []
            comments.append(c)
        return comments, drops, inc

    # ------------------------------------------------------------------ PUBLISH
    def publish(self, t0):
        status, incomplete, error = self.terminal()
        cbytes, mbytes, comments = render_outputs(self.run, status, incomplete, error, self.artifacts,
                                                  list(self.recorder.events), self.coverage_record)
        self.rd.write("comments.json", cbytes)
        self.rd.write("review.md", mbytes)
        payload = {"sink": "local-file", "path": "comments.json", "commentIds": [c["id"] for c in comments],
                   "summary": render.summary_line(status, comments, incomplete, error)}
        return "completed", payload, None, []

    def check_adopted_outputs(self) -> None:
        """Resume after the PUBLISH checkpoint: the files on disk must be what the checkpointed artifacts render."""
        if "PUBLISH" not in self.artifacts:
            return
        status, incomplete, error = self.terminal()
        cbytes, mbytes, _ = render_outputs(self.run, status, incomplete, error, self.artifacts,
                                           list(self.recorder.events), self.coverage_record)
        for name, want in (("comments.json", cbytes), ("review.md", mbytes)):
            if self.rd.read(name) != want:
                raise PipelineError("checkpoint-invalid", f"{name} on disk is not what the checkpointed JUDGE/VERIFY "
                                    "artifacts render (edited after PUBLISH?); nothing was resumed")
