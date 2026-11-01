"""Offline loopback request-capture proof for the opencode adapter (OPENCODE-FREE-PROVIDER; internal).

Run as `python3 -I -c "...opencode_capture import main..."` INSIDE `bwrap --unshare-net` (opencode_cli.capture_argv) with a
JSON spec on stdin: {"opencode", "model", "mode": "answer"|"toolcall", "timeout"}. It starts a fake OpenAI-compatible
chat-completions endpoint on 127.0.0.1, then drives the REAL `opencode run` through the live adapter class with Pullo's
exact argv, env and per-call config; the only difference is the `opencode` provider's baseURL, pointed at the fake. No
network exists in the namespace, so no request can reach a model, and no credential exists in the per-call home.
Prints one JSON document: captured request bodies (prompt text replaced by its digest), the adapter's verdict and the
expected prompt digest. `analyse()` (run by the caller, outside the namespace) turns that into problems."""

from __future__ import annotations

import hashlib
import http.server
import json
import socketserver
import sys
import threading

from . import opencode_cli as O
from .catalog import OPENCODE_MODELS

ANSWER = {"hypotheses": []}
SCHEMA = "InvestigatorOutput"
MARKERS = ("AGENTS.md", "CLAUDE.md", "<available_skills>", "Instructions from:", "# Skills", "MCP server")


def probe_request(model: str) -> dict:
    return {"provider": O.PROVIDER, "model": model, "profile": "opencode-capture@1", "role": "investigator",
            "promptVersion": "investigator.generalist@v1", "outputSchema": SCHEMA, "tools": [],
            "params": {"maxOutputTokens": 1000},
            "messages": [{"role": "system", "content": "PULLO-CAPTURE-SYSTEM"}, {"role": "user", "content": O.PROBE}]}


def _digest(s) -> str:
    return hashlib.sha256(str(s).encode()).hexdigest()


class _Fake(http.server.BaseHTTPRequestHandler):
    log: list = []
    mode = "answer"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.log.append({"method": "GET", "path": self.path[:200]})
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        self.log.append({"method": "POST", "path": self.path[:200], "body": body})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()

        def ev(o):
            self.wfile.write(b"data: " + json.dumps(o).encode() + b"\n\n")
            self.wfile.flush()
        base = {"id": "chatcmpl-pullo-capture", "object": "chat.completion.chunk", "created": 1,
                "model": body.get("model") if isinstance(body, dict) else "?"}
        if self.mode == "toolcall":
            ev({**base, "choices": [{"index": 0, "finish_reason": None, "delta": {"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_1", "type": "function",
                 "function": {"name": "read", "arguments": "{\"filePath\": \"/etc/hostname\"}"}}]}}]})
            ev({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 5, "total_tokens": 105}})
        else:
            ev({**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": json.dumps(ANSWER)},
                                     "finish_reason": None}]})
            ev({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1200, "completion_tokens": 20, "total_tokens": 1220}})
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class _CaptureProvider(O.OpenCodeFreeProvider):
    base_url = None

    def _config(self, model, out_name):
        return O.config_text(model, out_name, base_url=self.base_url)


def _scrub_body(body, prompt: str):
    """Keep the request's structure; replace message texts by digests (the system text keeps its CLI-added tail)."""
    if not isinstance(body, dict):
        return body
    out = {k: v for k, v in body.items() if k != "messages"}
    msgs = []
    for m in body.get("messages") or []:
        if not isinstance(m, dict):
            msgs.append({"malformed": True})
            continue
        c = m.get("content")
        d = {"role": m.get("role"), "contentSha256": _digest(c), "contentChars": len(c) if isinstance(c, str) else None,
             "hasToolCalls": bool(m.get("tool_calls"))}
        if m.get("role") == "system" and isinstance(c, str):
            d["startsWithBase"] = c.startswith(O.BASE_INSTRUCTIONS.rstrip("\n"))
            tail = c[len(O.BASE_INSTRUCTIONS.rstrip("\n")):] if d["startsWithBase"] else c
            d["extraChars"] = len(tail)
            d["markers"] = [k for k in MARKERS if k in tail]
        if m.get("role") == "user" and isinstance(c, str):
            d["isPrompt"] = c == prompt
        msgs.append(d)
    out["messages"] = msgs
    return out


def main() -> int:
    spec = json.loads(sys.stdin.read())
    model, mode = spec["model"], spec.get("mode", "answer")
    if model not in OPENCODE_MODELS or mode not in ("answer", "toolcall"):
        print(json.dumps({"error": "bad spec"}))
        return 2
    _Fake.log, _Fake.mode = [], mode
    srv = _Server(("127.0.0.1", 0), _Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        prov = _CaptureProvider(enabled=True, preflight={"supported": True}, opencode=spec.get("opencode", "opencode"),
                                timeout_sec=int(spec.get("timeout", 45)), models=[model])
        prov.base_url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
        req = probe_request(model)
        prompt = O._prompt(req)
        res = prov.call(req, ("INVESTIGATE", "investigator", "capture", 0, 0))
    finally:
        srv.shutdown()
    verdict = {"outcome": res.outcome}
    if res.response is not None:
        verdict.update(status=res.response.get("status"), outputOk=res.response.get("output") == ANSWER)
    if res.error is not None:
        d = res.error.get("detail") or {}
        verdict.update(code=res.error.get("code"), reason=d.get("reason"), itemType=d.get("itemType"))
    posts = [x for x in _Fake.log if x["method"] == "POST"]
    print(json.dumps({"mode": mode, "model": model, "posts": len(posts), "gets": [x["path"] for x in _Fake.log
                                                                                 if x["method"] == "GET"],
                      "paths": sorted({x["path"] for x in posts}), "bodies": [_scrub_body(x["body"], prompt) for x in posts],
                      "verdict": verdict, "disabled": prov.disabled_reason,
                      "expectedResponseFormat": O.response_format(SCHEMA)
                      if OPENCODE_MODELS[model]["structured"] == "json-schema" else None}))
    return 0


def analyse(out: dict, model: str, mode: str) -> dict:
    """Problems in a capture result (pure; runs outside the namespace)."""
    problems = []
    if not isinstance(out, dict) or out.get("model") != model or out.get("mode") != mode:
        return {"supported": False, "problems": ["capture result is not for this model/mode"]}
    bodies = [b for b in out.get("bodies") or [] if isinstance(b, dict)]
    want_model = OPENCODE_MODELS[model]["cliModel"].split("/", 1)[1]
    tools = sorted({str(t)[:40] for b in bodies for t in (b.get("tools") or [])})
    if not bodies:
        problems.append("the CLI sent no request to the loopback endpoint")
    if out.get("paths") and out["paths"] != ["/v1/chat/completions"]:
        problems.append("the CLI posted to an unexpected path")
    for b in bodies:
        if b.get("tools"):
            problems.append("a request offered tools")
        if any(k in b for k in ("tool_choice", "functions", "function_call")):
            problems.append("a request carried tool-choice fields")
        if b.get("model") != want_model:
            problems.append("the request named a different model")
    if bodies:
        first = bodies[0]
        msgs = first.get("messages") or []
        if [m.get("role") for m in msgs] != ["system", "user"]:
            problems.append(f"first request is not exactly [system, user]: {[m.get('role') for m in msgs][:6]}")
        else:
            s, u = msgs
            if not s.get("startsWithBase"):
                problems.append("the system text does not start with BASE_INSTRUCTIONS")
            if s.get("markers"):
                problems.append("the system text carries instruction/skill markers: " + ", ".join(s["markers"]))
            if (s.get("extraChars") or 0) > 3000:
                problems.append("the CLI added more than 3000 chars of system text")
            if not u.get("isPrompt"):
                problems.append("the user text is not exactly the Pullo prompt")
        want_rf = out.get("expectedResponseFormat")
        if want_rf is not None and first.get("response_format") != want_rf:
            problems.append("the request lacks the pinned json_schema response_format")
    v = out.get("verdict") or {}
    if mode == "answer":
        if out.get("posts") != 1:
            problems.append(f"expected exactly one request, saw {out.get('posts')}")
        if v.get("status") != "ok" or not v.get("outputOk"):
            problems.append("the scripted answer did not come back through the adapter as status ok")
    else:
        if v.get("reason") != "isolation-violation" or v.get("itemType") != "tool-attempt":
            problems.append("a scripted tool call was not reported as a tool attempt")
        if out.get("disabled"):
            problems.append(f"the tool call disabled the adapter ({out['disabled']}): it may have executed")
        if (out.get("posts") or 0) > O.STEPS:
            problems.append("the CLI looped beyond the agent step bound")
    if out.get("gets"):
        problems.append("the CLI made GET requests to the provider endpoint")
    return {"supported": not problems, "problems": sorted(set(problems)), "posts": out.get("posts"), "tools": tools,
            "verdict": v}


if __name__ == "__main__":
    raise SystemExit(main())
