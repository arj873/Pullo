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

from reviewer.contracts import check_finding_provenance, require, validate
from reviewer.contracts.budget import deadline_state, stage_deadline_exceeded
from reviewer.contracts.canonical import artifact_digest, digest, hypothesis_id
from reviewer.contracts.severity import materialize_evidence
from reviewer.contracts.snapshot import verify_manifest
from reviewer.contracts.stages import STAGES, artifact_name
from reviewer.gateway import SettlementError, typed_error
from reviewer.tools import Limits, ToolSession, full_view

from . import judging, prompts, render, snaps
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
                 prior_model_calls: int):
        self.spec, self.case, self.host = spec, spec.case, spec.host
        self.profile, self.plan, self.budget = spec.profile, spec.plan, spec.plan["budget"]
        self.run, self.rd, self.recorder, self.gw = run, rd, recorder, gateway
        self.pv = spec.plan["version"]
        self.base_id, self.head_id = self.case["base"]["snapshotId"], self.case["head"]["snapshotId"]
        self.profile_ref = f"{spec.profile['id']}@{spec.profile['version']}"
        self.view = full_view(spec.base.root, spec.base.manifest, spec.head.root, spec.head.manifest)
        self.resolver = self.view.resolver()
        self.clock = self.host.clock
        self.t0 = self.clock()
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

    def limits_for(self) -> Limits:
        base = self.host.tool_limits or Limits()
        used = sum(1 for e in self.recorder.events if e["type"] == "tool.call")
        remaining = max(0, self.budget["maxToolCalls"] - used)
        cap = min(base.max_calls, self.budget["maxToolCallsPerAgent"], remaining)
        return dataclasses.replace(base, max_calls=cap)

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
            self.set_fatal(session.stage, typed_error(
                "contract-violation", "a pinned snapshot no longer matches its manifest (tamper)", stage=session.stage,
                detail={"kind": "snapshot-tamper"}))
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
        if self.orig is not None and not self.replay_broken:
            want = self.orig[stage][:-2]                               # everything before stage.end/checkpoint
            diff = first_difference(want, r.events[start:])
            if diff is not None:
                status, payload, inc = "failed", self.empty(stage), []
                error = typed_error("replay-mismatch", f"{stage}: {diff}", stage=stage)
                self.set_fatal(stage, error)
        art = self.artifact(stage, status, payload, error, inc)
        dig = artifact_digest(art)
        if self.orig is not None and not self.replay_broken and dig != self.orig[stage][-2].get("artifactDigest"):
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
        if call is None:
            inc.append(self.stopped(stage, why, "changed-path listing not collected"))
        else:
            rows = self._rows(call.result)
            _, why = self.tool(session, "list_files", {"side": "head", "limit": 200}, t0)
            if why:
                inc.append(self.stopped(stage, why, "head file listing not collected"))
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
        out = []
        for e in self.recorder.events:
            if e["type"] == "tool.call" and e["stage"] == stage and (agent is None or e["agentId"] == agent):
                r = e["result"]
                if r["status"] not in ("ok", "empty") or r["truncated"] is not None or r["completeness"] != "exact":
                    out.append(f"{e['tool']} {json.dumps(e['args'], sort_keys=True)}: {r['status']}"
                               + (f"; {r['notice']}" if r["notice"] else ""))
        out += [f"{i['stage']} incomplete: {i['reason']}" for i in self.incomplete]
        return out

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

    # ------------------------------------------------------------------ INVESTIGATE
    def investigate(self, t0):
        stage = "INVESTIGATE"
        if self.fatal:
            return self.skipped(stage)
        g = self.gate(stage, t0, new_agent=True)
        if g is not None:
            return self._agent_failed(g[1], reason=g[0])
        ctx, notes = self.bounded_context(prompts.context_items(self.recorder.events, "PREPARE"))
        req = prompts.investigator_request(self.profile, self.profile_ref, self.case, ctx,
                                           self.omissions("PREPARE") + notes)
        out, err, attempts = self.model_call(stage, "investigator", SPECIALIST, 0, req)
        if err is not None:
            return self._agent_failed(err)
        source = next(a.call_id for a in reversed(attempts) if a.outcome == "ok")
        tools = self.tool_calls()
        family = self.profile["roles"]["investigator"]["family"]
        hyps = []
        for n, d in enumerate(out["hypotheses"]):
            hid = hypothesis_id(SPECIALIST, n, d["claim"], d["location"]["path"], d["location"]["line"])
            ev, problems = materialize_evidence(d["evidence"], tools, f"investigator:{SPECIALIST}", self.resolver)
            if not problems and not snaps.location_ok(self.spec.head.root, self.spec.head.manifest, d["location"]):
                problems = ["location does not exist in the pinned head snapshot"]
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
        ev = next((e for e in reversed(self.recorder.events) if e["type"] == "model.call"
                   and e["stage"] == "INVESTIGATE" and e["response"] is not None
                   and e["response"]["status"] == "ok"), None)
        drafts = ev["response"]["output"]["hypotheses"] if ev else []
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
                              "detail": "investigator citation or location did not resolve against the pinned snapshots"})
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
        items, omitted = [], []
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
            items.append({"toolCallId": call.tool_call_id, "tool": tool, "args": call.args, "status": r["status"],
                          "completeness": r["completeness"], "truncated": r["truncated"], "notice": r["notice"],
                          "excerpts": [e["excerpt"] for e in r["evidence"]]})
        if self.fatal and self.fatal["status"] == "failed":
            return None, None, None, inc
        items, notes = self.bounded_context(items)
        req = prompts.verifier_request(self.profile, self.profile_ref, self.case, hyp, items, omitted + notes)
        out, err, attempts = self.model_call(stage, "verifier", VERIFIER_AGENT, n, req)
        call_ids = [a.call_id for a in attempts if a.call_id]
        if err is not None:
            return self._verify_failed(hid, err, call_ids, inc)
        final = next(a.call_id for a in reversed(attempts) if a.outcome == "ok")
        ev, problems = materialize_evidence(out["evidence"], self.tool_calls(), f"verifier:{VERIFIER_AGENT}",
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
        kept, merged = judging.merge_duplicates(live)
        for dup, keeper in merged:
            drops.append({"subjectIds": [dup["id"]], "stage": "JUDGE", "reason": "merged",
                          "detail": f"same issue as {keeper['id']} (issue-key@1); earliest candidate retained"})
        tools = self.tool_calls()
        head = self.spec.head
        entries, seen_fp = [], {}
        for idx, f in kept:
            loc = f["location"]
            anchor = snaps.anchor_text(head.root, head.manifest, loc["path"], loc["line"], loc.get("endLine", loc["line"]))
            if anchor is None:
                drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "suppressed",
                              "detail": "anchor lines do not exist in the pinned head file"})
                continue
            title, body = prompts.fallback_wording(f)
            c = judging.build_comment(f, run_id=self.run["id"], head_snapshot_id=self.head_id, anchor=anchor,
                                      tool_calls=tools, title=title, body=body, suggestion=None)
            if c["fingerprint"] in seen_fp:
                drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "merged",
                              "detail": f"same fingerprint as {seen_fp[c['fingerprint']]}"})
                continue
            seen_fp[c["fingerprint"]] = f["id"]
            entries.append((f, c))
        top, over = judging.rank_and_cap(entries, self.host.comment_cap)
        for f, c in over:
            drops.append({"subjectIds": [f["id"]], "stage": "JUDGE", "reason": "over-cap",
                          "detail": f"ranked below the cap of {self.host.comment_cap}"})
        wording = {}
        if top:
            g = self.gate(stage, t0)
            if g is not None:
                inc.append(self._inc(stage, g[0], "deterministic wording used"))
                if g[0] == "cancelled":
                    self.set_fatal(stage, g[1])
            else:
                req = prompts.judge_request(self.profile, self.profile_ref, self.case,
                                            [(f, c["severity"]) for f, c in top])
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
                    wording, problem = prompts.check_wording(out, [f["id"] for f, _ in top])
                    if problem:
                        wording = {}
                        inc.append(self._inc(stage, "agent-failure", f"judge output rejected: {problem}"))
        if self.fatal and self.fatal["status"] == "failed":
            return [], [], []
        comments = []
        for f, c in top:
            if f["id"] in wording:
                title, body, sug = wording[f["id"]]
                c = judging.build_comment(f, run_id=self.run["id"], head_snapshot_id=self.head_id,
                                          anchor=snaps.anchor_text(head.root, head.manifest, f["location"]["path"],
                                                                   f["location"]["line"],
                                                                   f["location"].get("endLine", f["location"]["line"])),
                                          tool_calls=tools, title=title, body=body, suggestion=sug)
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
    def model_visible_omissions(self) -> list[str]:
        """What the investigator was told was omitted or rewritten (read back from its logged request)."""
        for e in self.recorder.events:
            if e["type"] == "model.call" and e["stage"] == "INVESTIGATE":
                try:
                    return list(json.loads(e["request"]["messages"][1]["content"]).get("omitted", []))
                except (ValueError, KeyError, IndexError, AttributeError):
                    return []
        return self.omissions("PREPARE")

    def publish(self, t0):
        status, incomplete, error = self.terminal()
        comments = []
        if not (self.fatal and self.fatal["status"] == "failed"):
            comments = list(self.artifacts["JUDGE"]["payload"]["comments"])
        drops = list(self.artifacts["VERIFY"]["payload"]["drops"]) + list(self.artifacts["JUDGE"]["payload"]["drops"])
        files = self.artifacts["PREPARE"]["payload"]["files"]
        notes = self.model_visible_omissions() + self.omissions("VERIFY")
        used = sum(1 for e in self.recorder.events if e["type"] == "tool.call")
        costs = [e["record"] for e in self.recorder.events if e["type"] == "cost"]
        basis = {}
        for c in costs:
            basis[c["basis"]] = basis.get(c["basis"], 0) + 1
        cost_note = (f"{len(costs)} model-call cost record(s) by basis {json.dumps(basis, sort_keys=True)}. "
                     "Synthetic and replayed amounts are not provider spend; no per-review cost target is claimed.")
        doc = render.comments_doc(self.run, status, comments)
        cbytes = render.comments_bytes(doc)
        md = render.review_md(run=self.run, status=status, comments=comments, drops=drops, incomplete=incomplete,
                              error=error, changed=files, context_notes=notes, tool_calls=used, cost_note=cost_note)
        self.rd.write("comments.json", cbytes)
        self.rd.write("review.md", md.encode("utf-8"))
        payload = {"sink": "local-file", "path": "comments.json", "commentIds": [c["id"] for c in comments],
                   "summary": render.summary_line(status, comments, incomplete, error)}
        return "completed", payload, None, []
