"""Offline REAL-CLI proof of the claude-cli gateway repair (CLAUDE-CLI-REPAIR1; tests only, never part of a live run).

Run as `python3 -I -c "...claude_repair_proof import main..."` INSIDE `bwrap --unshare-net` (argv()) with a JSON spec on stdin
{"claude", "model", "answers": [text | {"cut": text}, ...], "expect": [text, ...]} ({"cut": ...}: that POST stops at its own
max_tokens, TIMEOUT-FIX). A loopback fake Anthropic Messages endpoint streams answers[k] as the text of
the k-th POST. The REAL `claude -p` runs through the live adapter (its bwrap sandbox and its host forwarder, a DUMMY OAuth token
on the live fd path; the forwarder's UPSTREAM is the loopback fake - the only difference from a live call) under Pullo's real
Gateway with the pilot profile (claude-cli roles: maxRepairs 1) and the engine's claude-cli repair builder
(prompts.repair_issues_builder). No network exists in the namespace and no real credential is read.
Prints one JSON document: the logical call's result, its attempts, each CLI call (model, whether its stdin carries the repair
message, the local schema issue, each `expect` text as the model reads it, and the schema projection AFTER the repair message), the
adapter's ledger rows, the trace's model.call provenance and the fake's POST count."""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading

from reviewer.config import ReviewModels
from reviewer.gateway import Gateway, Recorder, SpendBook, trusted_authorization
from reviewer.pilot.profile import live_plan, live_profile
from reviewer.pipeline import prompts
from reviewer.runtime import claude_cli as C
from reviewer.runtime.claude_capture import DUMMY_TOKEN
from reviewer.runtime.envfile import Secret
from reviewer.runtime.receipts import RuntimeLedger
from tests.gateway.helpers import EVR, NOW, run_doc
from tests.pilot.helpers import AUTH

ISSUE = b"$.hypotheses[0].claim: required: missing"      # what the local check of INVALID must show the repair call
INVALID = json.dumps({"hypotheses": [{"bogus": 1}]})       # valid JSON, schema-invalid (no claim, category, ...)
VALID = json.dumps({"hypotheses": []})
WHOLE_TEXT = {"duplicate-key": ('{"hypotheses": [], "hypotheses": []}', "invalid JSON: duplicate key 'hypotheses'"),   # pilot data
              "unterminated": ('{"hypotheses": [{"claim": "x}]}', "invalid JSON: Unterminated string starting at: line 1 column 27"),
              "unknown-field": ('{"hypotheses": [], "evidence_note": "x"}', "$.evidence_note: unknown-field: not allowed"),
              "prose-only": ("I looked at the diff and found nothing.", 'it starts with text, not with \\"{\\"')}


class _Scripted(http.server.BaseHTTPRequestHandler):
    answers: list = []
    posts: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.posts.append("GET")
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        k = sum(1 for p in self.posts if p == "POST")
        self.posts.append("POST")
        a = self.answers[k] if k < len(self.answers) else VALID
        cut = isinstance(a, dict)                    # {"cut": text}: stopped at the request's own max_tokens (TIMEOUT-FIX)
        text = a["cut"] if cut else a
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("request-id", f"req_repair_proof_{k}")
        self.send_header("connection", "close")
        self.end_headers()

        def ev(name, o):
            self.wfile.write(f"event: {name}\ndata: {json.dumps(o)}\n\n".encode())
            self.wfile.flush()
        ev("message_start", {"type": "message_start", "message": {
            "id": f"msg_repair_proof_{k}", "type": "message", "role": "assistant", "model": body.get("model"), "content": [],
            "stop_reason": None, "stop_sequence": None,
            "usage": {"input_tokens": 1200, "output_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}}})
        ev("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        ev("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}})
        ev("content_block_stop", {"type": "content_block_stop", "index": 0})
        ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": "max_tokens" if cut else "end_turn", "stop_sequence": None},
                             "usage": {"output_tokens": body.get("max_tokens") if cut else 20}})
        ev("message_stop", {"type": "message_stop"})
        self.close_connection = True


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> int:
    spec = json.loads(sys.stdin.read())
    model = spec["model"]
    _Scripted.answers, _Scripted.posts = list(spec["answers"]), []
    expect = [e.encode() for e in spec.get("expect", [])]
    srv = _Server(("127.0.0.1", 0), _Scripted)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp(prefix="rvw-claude-repair-proof-")
    cli = []
    try:
        ledger = RuntimeLedger(os.path.join(tmp, "led.jsonl"), 50_000_000)
        token = C.AccessToken(Secret(DUMMY_TOKEN), None, "repair-proof-dummy")
        prov = C.ClaudeCliProvider(enabled=True, preflight={"supported": True}, claude=spec.get("claude", "claude"),
                                   ledger=ledger, timeout_sec=60, models=[model], token_loader=lambda: token,
                                   upstream=f"http://127.0.0.1:{srv.server_address[1]}")   # the ONLY difference from live
        real = prov._run

        def run(argv, stdin, env, cwd, timeout, **kw):
            _, inner = C.split_sandbox(argv)
            tail = stdin.rfind(b'<output-schema name="')
            cli.append({"model": inner[inner.index("--model") + 1], "repairMessage": b'"schemaIssues"' in stdin,
                        "issueShown": ISSUE in stdin, "expectShown": [e in stdin for e in expect], "stdinBytes": len(stdin),
                        "schemaAfterRepair": b'"schemaIssues"' in stdin and stdin.rfind(b'"schemaIssues"') < tail})
            return real(argv, stdin, env, cwd, timeout, **kw)
        prov._run = run
        profile = live_profile(models=ReviewModels.uniform(model))
        ref = f"{profile['id']}@{profile['version']}"
        auth = os.path.join(tmp, "auth.json")
        with open(auth, "w") as f:
            json.dump(dict(AUTH, id="claude-cli-repair-proof", providers=["claude-cli"], models=[model]), f)
        h = trusted_authorization(auth)
        rd = dict(run_doc("live", auth_digest=h.digest), profile=ref)
        rec = Recorder(rd["id"])
        rec.start(rd)
        gw = Gateway(mode="live", profile=profile, budget=live_plan(profile)["budget"], run_id=rd["id"],
                     providers={"claude-cli": prov}, authorization=h, book=SpendBook(h), recorder=rec,
                     clock=lambda: NOW, cost_kind="eval", eval_run_id=EVR, eval_case_id="case-a")
        req = prompts._request(profile, ref, "investigator", {"task": "Repair proof: answer with the JSON the format asks.",
                                                              "answerFormat": prompts.INVESTIGATOR_FORMAT})
        res = gw.call("INVESTIGATE", "investigator", "generalist", 0, req,
                      repair_with_issues=prompts.repair_issues_builder(req, req["outputSchema"]))
        rows = [json.loads(x) for x in open(ledger.path).read().splitlines() if x.strip()]
    finally:
        srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)
    calls = [e for e in rec.events if e.get("type") == "model.call"]
    print(json.dumps({
        "model": model, "maxRepairs": profile["roles"]["investigator"]["caps"]["maxRepairs"],
        "result": {"ok": res.response is not None, "status": (res.response or {}).get("status"),
                   "error": (res.error or {}).get("code"), "repairsUsed": ((res.error or {}).get("detail") or {}).get("repairsUsed")},
        "attempts": [{"attempt": a.attempt, "outcome": a.outcome} for a in res.attempts],
        "cli": cli, "posts": _Scripted.posts.count("POST"), "others": [p for p in _Scripted.posts if p != "POST"],
        "rows": [{"attempt": int(r["callKey"].rsplit("|", 1)[1]), "outcome": r.get("outcome"), "note": r.get("note"),
                  "requestsSent": (r.get("isolation") or {}).get("requestsSent")} for r in rows if r.get("type") == "result"],
        "trace": [{"attempt": e.get("attempt"), "repairOf": e.get("repairOf"), "callId": e.get("callId"),
                   "status": (e.get("response") or {}).get("status")} for e in calls]}))
    return 0


def argv(bwrap: str, repo: str) -> list[str]:
    code = (f"import sys; sys.path.insert(0, {repo!r}); "
            "from tests.runtime.claude_repair_proof import main; raise SystemExit(main())")
    return [bwrap, "--unshare-net", "--die-with-parent", "--dev-bind", "/", "/", "--", sys.executable, "-I", "-c", code]
