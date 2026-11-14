---
name: pullo-judge
description: "Score prepared Pullo benchmark campaigns with Pullo's judge v6ecc2: the v6e scoring judge (Opus 5.5, the same prompts, parsing, matching and budgets) run through the Claude Code CLI on the subscription instead of OpenRouter. Use when you are handed one or more pullo-v6ecc job files (operator/v6ecc-job.json) to judge. Reports counts and paths only; never prints gold, review or answer text."
---

# Pullo judge (v6ecc2)

A job is one campaign that Pullo's scoring tools sealed for judging: its cases, the frozen judge export and every pin. This skill
makes the judge calls (one `claude -p` call per judge request, one at a time) and writes the judgments in the v6e format, labelled
v6ecc2. Root settles and reports them afterwards (`score_v5.py v6ecc-settle`, `replay`, `report_v5.py`).

## 1. Run the jobs

Run each batch in ONE subagent or lane tab (`subagent_type`: `pullo-judge` if listed, else `general-purpose`). Never start two
batches at the same time: the script holds a per-user lock and refuses a second run.

```
nice -n 19 python3 -I ~/.claude/skills/pullo-judge/scripts/pullo_judge.py judge <job.json> [<job.json> ...]
```

Run it with Bash `run_in_background: true`: each judge call takes about 5-20 s, and a campaign makes one extraction and one dedup
call per tool plus one call per (gold, candidate) pair, so a large campaign can run for hours. The first stdout line names the
summary file (`summary`); the same summary is the last stdout line when the run ends.

## 2. Report

The last stdout line is JSON. Report it as is: `status`, and per job `name`, `status`, `processed` / `calls`, `latch`, `result`.

- `"status": "done"`: every job ran. A job with `"status": "incomplete"` did not finish (an invalid answer, a timeout, a CLI error);
  it is never scored. Report it; root re-plans it.
- `"status": "latched"` (exit 3): a usage limit, rate limit, auth or billing error, extra usage, or an isolation problem stopped
  the run. Jobs in `notStarted` were not touched. Report the latch type and `latchWords` (the CLI's reset time) and STOP. Do not
  retry, do not `unlatch` yourself: root decides when the limit has reset.
- `"status": "refused"` or `"error"` (exit 2): report the `reason` code (and `stoppedAt`, the job it stopped at) and stop. Jobs
  before it keep their results; jobs in `notStarted` were not touched.
- `"status": "interrupted"` (exit 4): the run was stopped (SIGTERM or Ctrl-C). The job it stopped at has a result marked
  incomplete. Report it and stop.

## Rules

- Never open the trace, documents or cases files: they hold gold and review text. The result and calls files hold counts only.
- Never edit a job, the judge export or the script. Never add `--parallel` unless root says so.
- Extra usage must stay OFF on the account: an answer served from extra usage is discarded and latches the run.
- Do not post anything anywhere. The script opens no network connection itself; only the Claude CLI talks to Anthropic.

## What the script does

- Loads the frozen judge export named by the job, re-hashes every file against its pinned manifest, and checks that the script
  itself is the export's frozen copy.
- Runs the frozen v6e ScoreHost pipeline (extraction, dedup, the complete-set fit, pairs) unchanged. Only the transport changes.
- Each judge request becomes one CLI call:
  - `--system-prompt` = the judge's own system message + the response schema; stdin = the judge's user message, byte for byte;
  - `--model claude-opus-5-5 --effort high`, max tokens = the request's (8000 / 4000 / 1024), the v6e per-stage timeout;
  - no tools, `--strict-mcp-config`, no settings, no session persistence, no retries; `PATH=/usr/bin:/bin`; Claude Code 2.1.322 exactly.
- The answer text goes to the frozen parser unchanged, with two exceptions: one whole-answer ```json fence is removed (counted as
  `fencedJson`), and a short preamble before ONE JSON object that ends the answer is dropped (counted as `proseStripped`; v6ecc2's
  only change from v6ecc). Anything else goes on as is, and the frozen parser refuses it.
- Writes `v6ecc-output/` in the campaign dir: `<run>.trace.jsonl` and `<run>.documents.json` (v6e format), `v6ecc-calls.jsonl`
  (one row per call: hashes, tokens, outcome; no text, not even the dropped preamble) and `v6ecc-result.json`.
- `check <job.json>` verifies a job with no CLI call. `unlatch` clears the latch (root only, after the limit resets).
