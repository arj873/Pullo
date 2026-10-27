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
from reviewer.contracts.budget import deadline_state, stage_deadline_exceeded
from reviewer.contracts.canonical import artifact_digest, digest, hypothesis_id
from reviewer.contracts.severity import RANK, materialize_evidence
from reviewer.contracts.snapshot import verify_manifest
from reviewer.contracts.stages import STAGES, artifact_name
from reviewer.gateway import SettlementError, typed_error
from reviewer.tools import Limits, ToolSession, full_view, import_view, omissions_from_records

from . import coverage as cov_mod
from . import identity, judging, prompts, render, repocov, retrieval, snaps
from .compare import first_difference, segment
from .errors import PipelineError

SPECIALIST = "generalist"
VERIFIER_AGENT = "verifier"
JUDGE_AGENT = "judge"
PREPARE_AGENT = "prepare"
CONTEXT_CHARS = 100_000        # model-visible context budget per request (deterministic truncation)
VERIFY_WINDOW = 20             # lines of head context around a candidate location

REPLAY_CODES = ("replay-miss", "replay-mismatch")
AGENT_FAIL_CODES = ("provider-timeout", "provider-error", "schema-invalid", "repair-exhausted",
                    "contract-violation", "internal", "model-unresolved", "live-calls-disabled")


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
    cbytes = render.comments_bytes(render.comments_doc(run, status, comments, cdoc))
    md = render.review_md(run=run, status=status, comments=comments, drops=drops, incomplete=incomplete,
                          error=error, changed=files, context_notes=notes, tool_calls=used, cost_note=cost_note,
                          coverage=cdoc, retrieval=retrieval_run)
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
        self.guard = guard
        self._ordinals: dict[tuple, int] = {}
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
    def gate(self, stage: str, stage_t0: float, *, new_agent: bool = False):
        """None when work may start, else (incomplete reason, TypedError). Checked before every tool and
        model call; never hidden behind a retry."""
        if self.host.cancel is not None and self.host.cancel():
            return "cancelled", typed_error("cancelled", "run cancelled by the host", stage=stage)
        elapsed = max(0.0, self.clock() - self.t0)
        state = deadline_state(self.budget, elapsed)
        if state == "hard":
            return "deadline", typed_error("deadline-exceeded", "hard run deadline reached", stage=stage)
        if stage_deadline_exceeded(stage, max(0.0, self.clock() - stage_t0)):
            return "deadline", typed_error("deadline-exceeded", f"{stage} stage ceiling reached", stage=stage)
        if state == "soft" and new_agent:
            return "soft-deadline", typed_error("deadline-exceeded", "soft deadline: no new agent starts", stage=stage)
        return None

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

    def agent_limit(self) -> int:
        """Tool calls one agent session may make: host limit and plan per-agent budget (not the run remainder)."""
        return min(identity.tool_limits(self.spec).max_calls, self.budget["maxToolCallsPerAgent"])

    def limits_for(self) -> Limits:
        used = sum(1 for e in self.recorder.events if e["type"] == "tool.call")
        remaining = max(0, self.budget["maxToolCalls"] - used)
        return dataclasses.replace(identity.tool_limits(self.spec), max_calls=min(self.agent_limit(), remaining))

    def new_session(self, stage: str, agent: str) -> ToolSession:
        return ToolSession(self.view, stage=stage, agent_id=agent, limits=self.limits_for(), clock=self.clock)

    def tool(self, session: ToolSession, tool: str, args: dict, stage_t0: float):
        """-> (ToolCall|None, why). Never calls past a cap, deadline or cancellation."""
        if len(session.calls) >= session.limits.max_calls:
            return None, "tool-calls-exhausted"
        used = sum(len(x["excerpt"]) for e in self.recorder.events
                   if e["type"] == "tool.call" and e["stage"] == session.stage and e["agentId"] == session.agent_id
                   for x in e["result"]["evidence"])
        if used > self.budget["maxToolOutputTokensPerAgent"] * 3:      # ~3 chars per token, conservative
            return None, "tool-calls-exhausted"
        g = self.gate(session.stage, stage_t0)
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

    # ------------------------------------------------------------------ stage driver
    def run_stage(self, stage: str, fn) -> None:
        if stage in self.artifacts:
            return
        r = self.recorder
        r.append("stage.start", stage=stage)
        start = len(r.events) - 1
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
        return empty_payload(stage, self.run, self.plan, self.base_id, self.head_id)

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
        g = self.gate(stage, t0, new_agent=True)
        if g is not None:
            return self._agent_failed(g[1], reason=g[0])
        ctx, notes = self.bounded_context(prompts.context_items(self.recorder.events, "PREPARE"))
        if self.turn_role("investigator"):
            ctx, notes = self._cap_host_results(ctx, notes)
            end = self._investigator_chain(stage, t0, ctx, notes)
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
        tools = self.citable(source)
        family = self.profile["roles"]["investigator"]["family"]
        changed = self.changed_head_paths()
        hyps = []
        for n, d in enumerate(out["hypotheses"]):
            hid = hypothesis_id(SPECIALIST, n, d["claim"], d["location"]["path"], d["location"]["line"])
            ev, problems = materialize_evidence(d["evidence"], tools, f"investigator:{SPECIALIST}", self.resolver)
            if not problems and not snaps.location_ok(self.spec.head.root, self.spec.head.manifest, d["location"]):
                problems = ["location does not exist in the pinned head snapshot"]
            if not problems and changed is not None and d["location"]["path"] not in changed:
                problems = ["location is in a file this change did not modify"]
            if problems or not ev:
                continue
            h = {"id": hid, "runId": self.run["id"], "specialist": SPECIALIST, "claim": d["claim"],
                 "category": d["category"], "suspectedSeverity": d["suspectedSeverity"], "impact": d["impact"],
                 "location": d["location"], "evidence": ev, "modelFamily": family, "sourceCallId": source}
            for k in ("mechanism", "reach", "confidence"):
                if k in d:
                    h[k] = d[k]
            if validate("Hypothesis", h):
                continue
            hyps.append(h)
        return "completed", {"hypotheses": hyps, "agents": [{"agentId": SPECIALIST, "specialist": SPECIALIST,
                                                             "status": "completed"}]}, None, []

    def _cap_host_results(self, ctx: list, notes: list) -> tuple[list, list]:
        """A request lists at most MAX_HOST_RESULTS host-prepared results; the rest are named as omitted."""
        if len(ctx) > retrieval.MAX_HOST_RESULTS:
            notes = notes + [f"{len(ctx) - retrieval.MAX_HOST_RESULTS} host-prepared result(s) omitted from the "
                             "first request (list bound)"]
            ctx = ctx[:retrieval.MAX_HOST_RESULTS]
        return ctx, notes

    def _investigator_chain(self, stage, t0, ctx, notes):
        events = self.tool_calls()
        host = [events[c["toolCallId"]] for c in ctx]
        doc = prompts.investigator_doc(self.case, ctx, self.omissions("PREPARE") + notes, self.coverage_doc(),
                                       task=prompts.INVESTIGATOR_RETRIEVE_TASK)
        if self.coverage_doc() is None:
            doc["coverage"] = ("Two full pinned snapshots are available through retrieval requests; the starting "
                               "context below is bounded and may be truncated or omitted.")
        chain = retrieval.Chain(self, stage=stage, role="investigator", agent=SPECIALIST,
                                session=self.new_session(stage, SPECIALIST), t0=t0,
                                turns=self.policy.investigator_turns, policy=self.policy, host_events=host,
                                unrendered=self.unrendered_ids(ctx, host))
        return chain.run(lambda hop, state: prompts.turn_request(
            self.profile, self.profile_ref, "investigator", doc, state, self.policy.requests_per_turn,
            retrieval.RETRIEVAL_VERSION))

    def _investigator_exhausted(self, stage, end):
        detail = (f"investigator retrieval ended at the {end.exhausted} limit after {end.hops} hop(s) and "
                  f"{end.tool_calls} requested tool call(s) without a final answer; {len(end.unread)} pending "
                  f"request(s) were not run: {unread_note(end.unread)}")
        inc = [self._inc(stage, "tool-calls-exhausted", detail)]
        payload = {"hypotheses": [], "agents": [{"agentId": SPECIALIST, "specialist": SPECIALIST, "status": "failed"}]}
        return "partial", payload, None, inc

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
        # the last usable INVESTIGATE answer that carries a role payload (a non-final Turn hop has none)
        drafts = next((p["hypotheses"] for e in reversed(self.recorder.events)
                       if e["type"] == "model.call" and e["stage"] == "INVESTIGATE"
                       and (p := terminal_payload(e)) is not None), [])
        return [(n, hypothesis_id(SPECIALIST, n, d["claim"], d["location"]["path"], d["location"]["line"]), d)
                for n, d in enumerate(drafts)], hyps

    def verify(self, t0):
        stage = "VERIFY"
        if self.fatal:
            return self.skipped(stage)
        cands, hyps = self.candidates()
        findings, records, drops, inc = [], [], [], []
        session = self.new_session(stage, VERIFIER_AGENT)
        stop = None                                   # (reason, error) once a global stop applies
        family = self.profile["roles"]["verifier"]["family"]
        for n, hid, draft in cands:
            if hid not in hyps:
                drops.append({"subjectIds": [hid], "stage": "VERIFY", "reason": "invalid-citation",
                              "detail": "investigator citation or location did not resolve against the pinned snapshots, "
                                        "or lies outside the files this change modified"})
                continue
            if stop is None:
                g = self.gate(stage, t0)
                if g is not None:
                    stop = g
            if self.fatal and self.fatal["status"] == "failed" and self.fatal["stage"] == stage:
                break
            if stop is not None:
                reason, err = stop
                inc.append(self._inc(stage, reason))
                if reason == "cancelled":
                    self.set_fatal(stage, err)
                drops.append({"subjectIds": [hid], "stage": "VERIFY", "reason": reason,
                              "detail": err["message"][:500]})
                continue
            rec, finding, drop, more = self.verify_one(session, n, hyps[hid], t0, family)
            inc.extend(more)
            if rec is None:
                continue
            records.append(rec)
            if finding is not None:
                findings.append(finding)
            if drop is not None:
                drops.append(drop)
        if self.fatal and self.fatal["stage"] == stage and self.fatal["status"] == "failed":
            return "failed", self.empty(stage), self.fatal["error"], []
        if session.incomplete and not any(i["reason"] == session.incomplete for i in inc):
            inc.append(self._inc(stage, session.incomplete))
        status = "partial" if inc else "completed"
        return status, {"findings": findings, "verifications": records, "drops": drops}, None, inc

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
            g = self.gate(stage, t0)                  # the last tool call may have crossed a deadline / cancel
            if g is not None:
                return self._verify_failed(hid, g[1], [], inc)
            out, err, attempts = self.model_call(stage, "verifier", VERIFIER_AGENT, n, req)
            call_ids = [a.call_id for a in attempts if a.call_id]
            if err is not None:
                return self._verify_failed(hid, err, call_ids, inc)
            final = next(a.call_id for a in reversed(attempts) if a.outcome == "ok")
        ev, problems = materialize_evidence(out["evidence"], self.citable(final), f"verifier:{VERIFIER_AGENT}",
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
        chain = retrieval.Chain(self, stage="VERIFY", role="verifier", agent=VERIFIER_AGENT, session=session, t0=t0,
                                turns=self.policy.verifier_turns, policy=self.policy, hypothesis_id=hyp["id"],
                                host_events=host, hyp_calls_used=len(host),
                                unrendered=self.unrendered_ids(items, host))
        return chain.run(lambda hop, state: prompts.turn_request(
            self.profile, self.profile_ref, "verifier", doc, state, self.policy.requests_per_turn,
            retrieval.RETRIEVAL_VERSION, hypothesis_id=hyp["id"]))

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
            g = self.gate(stage, t0)
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
