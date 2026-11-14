"""A fake `claude` CLI for the pullo-judge tests (no network, no model). install(dir, ...) writes an executable `claude` whose
behaviour comes from a JSON config file next to it (the skill passes the child a fixed environment, so the fake cannot read test
environment variables). Every call is logged (argv, the system prompt, stdin, the env flags, cwd) to calls.jsonl beside it.

Modes, per call number (config "modes": {"<n>": mode}, else config "mode"): ok | fenced | prose | usage-limit | overage | tool-use |
wrong-model | max-tokens | retry | timeout | auth | invalid | no-init | overage-two (an overage rate_limit_event, then an allowed
one: the gate's F1 probe) | term-parent / kill-parent (SIGTERM / SIGKILL the skill process mid-call) | prose-after (the JSON, then
prose) | shapes (each pair answer takes the layout of a real calibration failure, failure_shapes.json: its masked preamble and
fence around this fake's JSON; other stages answer ok)."""
import json
import os
import stat
import sys
from pathlib import Path

TEMPLATE = r'''#!{python} -IB
import json, os, signal, sys, time
from pathlib import Path
HERE = Path({here!r})
cfg = json.loads((HERE / "fake-config.json").read_text())
sys.path.insert(0, {tests!r})
from fake_answers import answer
argv = sys.argv[1:]
if argv == ["--version"]:
    print(cfg.get("version", "2.1.322") + " (Claude Code)"); sys.exit(0)
state = HERE / "fake-state.json"
n = (json.loads(state.read_text())["n"] if state.exists() else 0) + 1
state.write_text(json.dumps({{"n": n}}))
mode = cfg.get("modes", {{}}).get(str(n), cfg.get("mode", "ok"))
system = argv[argv.index("--system-prompt") + 1] if "--system-prompt" in argv else None
stdin = sys.stdin.buffer.read().decode("utf-8")
env = {{k: v for k, v in os.environ.items()}}
with open(HERE / "calls.jsonl", "a") as f:
    f.write(json.dumps({{"n": n, "mode": mode, "argv": [a for a in argv if a != system], "system": system, "stdin": stdin,
                        "env": env, "cwd": os.getcwd()}}) + "\n")
if mode in ("term-parent", "kill-parent"):
    os.kill(os.getppid(), signal.SIGTERM if mode == "term-parent" else signal.SIGKILL)
    if mode == "term-parent":
        time.sleep(30)                                                  # the skill kills this process group on its way out
    sys.exit(0)
model = "claude-opus-4-1" if mode == "wrong-model" else argv[argv.index("--model") + 1]
def out(ev):
    sys.stdout.write(json.dumps(ev) + "\n"); sys.stdout.flush()
if mode != "no-init":
    plugins = [{{"name": "agents-md", "source": "cc-plugin-agents-md@builtin", "path": "builtin"}}]
    if mode == "user-plugin":
        plugins.append({{"name": "easel", "source": "cc-plugin-easel@user", "path": "/home/x/.claude/plugins/easel"}})
    out({{"type": "system", "subtype": "init", "tools": ["Read"] if mode == "tool-use-init" else [], "mcp_servers": [],
         "model": model, "claude_code_version": cfg.get("version", "2.1.322"), "slash_commands": [], "skills": [], "plugins": plugins}})
if mode == "hook":
    out({{"type": "system", "subtype": "hook_response", "hook_name": "SessionStart:startup", "output": "extra context"}})
if mode == "timeout":
    time.sleep(30); sys.exit(0)
if mode == "retry":
    out({{"type": "system", "subtype": "api_retry", "attempt": 1}}); time.sleep(5); sys.exit(1)
name = system.split("The schema (", 1)[1].split(",", 1)[0]
value = answer(name, stdin)
text = json.dumps(value)
if mode == "fenced":
    text = "```json\n" + text + "\n```"
if mode == "prose":
    text = "Here is the answer: " + text
if mode == "prose-after":
    text = text + "\nSo that is the answer."
if mode == "shapes" and name == "ScorePair":
    shapes = json.loads((Path({tests!r}) / "failure_shapes.json").read_text())["shapes"]
    sh = shapes[n % len(shapes)]
    text = sh["prefix"] + text + sh["suffix"]
if mode == "invalid":
    text = "not json"
rate = {{"status": "allowed", "rateLimitType": "five_hour", "isUsingOverage": mode == "overage"}}
usage = {{"input_tokens": 300, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 20}}
if mode == "usage-limit":
    out({{"type": "rate_limit_event", "rate_limit_info": {{"status": "rejected", "rateLimitType": "five_hour", "resetsAt": 1999999999}}}})
    out({{"type": "assistant", "is_api_error_message": True, "error": "rate_limit", "api_error_status": 429,
         "message": {{"content": [{{"type": "text", "text": "You've hit your limit · resets 3:30pm (America/Chicago)"}}]}}}})
    out({{"type": "result", "subtype": "success", "is_error": True, "result": "You've hit your limit · resets 3:30pm (America/Chicago)",
         "num_turns": 1, "usage": {{}}, "modelUsage": {{}}, "api_error_status": 429}})
    sys.exit(1)
if mode == "auth":
    out({{"type": "result", "subtype": "success", "is_error": True, "result": "Not logged in · Please run /login", "num_turns": 1,
         "usage": {{}}, "modelUsage": {{}}}})
    sys.exit(1)
if mode == "overage-two":
    out({{"type": "rate_limit_event", "rate_limit_info": {{"status": "allowed_warning", "rateLimitType": "five_hour", "isUsingOverage": True}}}})
    out({{"type": "rate_limit_event", "rate_limit_info": {{"status": "allowed", "rateLimitType": "seven_day", "isUsingOverage": False}}}})
else:
    out({{"type": "rate_limit_event", "rate_limit_info": rate}})
if mode == "tool-use":
    out({{"type": "assistant", "message": {{"content": [{{"type": "tool_use", "name": "Read", "input": {{}}}}]}}}}); time.sleep(5); sys.exit(0)
out({{"type": "assistant", "message": {{"content": [{{"type": "thinking", "thinking": "", "signature": "x"}}, {{"type": "text", "text": text}}]}}}})
if mode == "max-tokens":
    out({{"type": "user", "message": {{"content": [{{"type": "text", "text": "Output token limit hit. Resume directly"}}]}}}})
    time.sleep(5); sys.exit(0)
out({{"type": "result", "subtype": "success", "is_error": False, "result": text, "num_turns": 1, "usage": usage,
     "modelUsage": {{model: {{"inputTokens": 300, "outputTokens": 20}}}}, "stop_reason": "end_turn", "session_id": "fake-session",
     "total_cost_usd": 0.0}})
'''


def install(where: Path, **config) -> Path:
    where = Path(where)
    where.mkdir(parents=True, exist_ok=True)
    (where / 'fake-config.json').write_text(json.dumps(config))
    exe = where / 'claude'
    exe.write_text(TEMPLATE.format(python=sys.executable, here=str(where), tests=str(Path(__file__).resolve().parent)))
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    return exe


def set_config(where: Path, **config) -> None:
    (Path(where) / 'fake-config.json').write_text(json.dumps(config))
    st = Path(where) / 'fake-state.json'
    if st.exists():
        st.unlink()


def calls(where: Path) -> list:
    p = Path(where) / 'calls.jsonl'
    return [json.loads(x) for x in p.read_text().splitlines() if x] if p.exists() else []
