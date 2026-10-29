"""Offline request-capture proof for the Codex CLI adapter (TERRA-ARM-01 gate B1).

`codex debug prompt-input` does not show the TOOL surface, and a tool the model is offered but never calls leaves no
JSONL item, so the event audit cannot see it. This proof runs the REAL `codex exec` with Pullo's exact argv/-c/--disable
settings against a loopback fake Responses endpoint and inspects the captured request BODY:

  * the child runs inside `bwrap --unshare-net` (a private network namespace with only loopback), so nothing can leave
    the host whatever the CLI tries;
  * the isolated CODEX_HOME holds a FAKE API key written by this harness (never the operator's login; no ChatGPT
    credential exists anywhere in the probe);
  * the fake endpoint answers with a 400 (capture mode) or a scripted final message (answer mode, used by tests).

`analyse_body` requires: no top-level tools and no additional_tools except the allowlisted inert `request_user_input`
(it asks the user a question; in `codex exec` there is no user, and the adapter's audit fails any item it produces),
no collaboration/agent namespace, and no skills/AGENTS/permissions/multi-agent developer text.

Run as `python3 -m reviewer.runtime.codex_capture` with a JSON spec on stdin (internal; see codex_cli.check_request_isolation)."""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_KEY = "sk-pullo-capture-fake-not-a-key"
ALLOWED_INERT_TOOLS = frozenset({"request_user_input"})
FORBIDDEN_TEXT = ("<skills_instructions>", "AGENTS.md", "spawn_agent", "<permissions instructions>", "multi_agent_mode",
                  "sub-agent", "apply_patch")


def _tool_names(node) -> list[str]:
    out = []
    if isinstance(node, list):
        for x in node:
            out += _tool_names(x)
    elif isinstance(node, dict):
        name = node.get("name") or node.get("type")
        inner = node.get("tools")
        if isinstance(inner, list):
            out.append(f"namespace:{name}")
            out += _tool_names(inner)
        elif isinstance(name, str):
            out.append(name)
    return out


def _texts(item) -> list[str]:
    c = item.get("content")
    if isinstance(c, str):
        return [c]
    return [x.get("text", "") for x in c or [] if isinstance(x, dict)]


def analyse_body(body: dict) -> dict:
    """-> {'tools': [...], 'namespaces': [...], 'violations': [...]} for one captured Responses request body."""
    tools = _tool_names(body.get("tools") or [])
    dev_texts = []
    for it in body.get("input") or []:
        if not isinstance(it, dict):
            continue
        if it.get("type") == "additional_tools":
            tools += _tool_names(it.get("tools") or [])
        elif it.get("role") in ("developer", "system"):
            dev_texts += _texts(it)
    if isinstance(body.get("instructions"), str):
        dev_texts.append(body["instructions"])
    plain = [t for t in tools if not t.startswith("namespace:")]
    spaces = [t[len("namespace:"):] for t in tools if t.startswith("namespace:")]
    violations = [f"tool offered: {t}" for t in plain if t not in ALLOWED_INERT_TOOLS]
    violations += [f"tool namespace offered: {n}" for n in spaces if n != "functions"]
    violations += [f"developer text contains {m!r}" for m in FORBIDDEN_TEXT if any(m in t for t in dev_texts)]
    return {"tools": sorted(set(plain)), "namespaces": sorted(set(spaces)), "violations": violations,
            "developerTextBytes": sum(len(t) for t in dev_texts)}


def _sse(events) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


def answer_stream(text: str, *, tool_call: dict | None = None, rid: str = "resp_capture") -> bytes:
    usage = {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 5,
             "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 15}
    item = tool_call or {"type": "message", "role": "assistant", "id": "msg_capture",
                         "content": [{"type": "output_text", "text": text}]}
    return _sse([{"type": "response.created", "response": {"id": rid}},
                 {"type": "response.output_item.done", "output_index": 0, "item": item},
                 {"type": "response.completed", "response": {"id": rid, "usage": usage}}])


def serve(mode: str, answer: str | None, tool_call: dict | None):
    """Start the loopback fake endpoint. -> (server, port, record)."""
    record = {"posts": [], "gets": []}

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            n = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(n)
            try:
                record["posts"].append({"path": self.path, "body": json.loads(raw)})
            except ValueError:
                record["posts"].append({"path": self.path, "body": None, "undecodable": len(raw)})
            if mode == "answer":
                first = len(record["posts"]) == 1
                out = answer_stream(answer or "{}", tool_call=tool_call if first else None,
                                    rid=f"resp_{len(record['posts'])}")
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
            else:
                out = b'{"error":{"message":"pullo capture","type":"invalid_request_error"}}'
                self.send_response(400)
                self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def do_GET(self):
            record["gets"].append(self.path)
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], record


def main() -> int:
    """Inside the network namespace: build an isolated home with a FAKE key, run codex against loopback, print JSON."""
    from . import codex_cli as C, schemas
    import tempfile
    import shutil

    spec = json.loads(sys.stdin.read())
    model, mode = spec["model"], spec.get("mode", "capture")
    srv, port, record = serve(mode, spec.get("answer"), spec.get("toolCall"))
    work = tempfile.mkdtemp(prefix="rvw-codex-capture-")
    try:
        made = C.isolated_home(work, None, with_auth=False, model=model)
        with open(os.path.join(made["codexHome"], "auth.json"), "w") as f:     # a fake key, written by this harness
            json.dump({"OPENAI_API_KEY": FAKE_KEY}, f)
        cwd = os.path.join(work, "cwd")
        os.mkdir(cwd)
        sp = os.path.join(work, "schema.json")
        with open(sp, "wb") as f:
            f.write(schemas.schema_bytes(spec.get("schema", "InvestigatorOutput"), "openai-strict"))
        catalog = made["catalog"]
        if spec.get("catalogEntryOverride"):      # tests only: reproduce a server-style catalog (code_mode_only ...)
            doc = json.loads(open(catalog).read())
            for e in doc["models"]:
                e.update(spec["catalogEntryOverride"])
            with open(catalog, "w") as f:
                json.dump(doc, f)
        argv = C.build_argv(spec.get("codex", "codex"), sp, cwd, model, instructions_file=made["instructions"],
                            catalog_file=catalog)
        argv = argv[:-1] + ["-c", f'openai_base_url="http://127.0.0.1:{port}/v1"', "-"]
        res = C.run_bounded(argv, spec.get("prompt", C.PROBE).encode(), made["env"], cwd, float(spec.get("timeout", 45)))
        out = {"rc": res.returncode, "timedOut": res.timed_out, "posts": len(record["posts"]), "gets": record["gets"],
               "bodies": [p["body"] for p in record["posts"][:3]],
               "events": [ln for ln in res.stdout.decode("utf-8", "replace").splitlines() if ln.strip()][:60],
               "stdout": res.stdout.decode("utf-8", "replace")[-200_000:],
               "stderrTail": res.stderr.decode("utf-8", "replace")[-600:]}
    finally:
        srv.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
