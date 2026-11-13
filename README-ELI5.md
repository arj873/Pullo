# Pullo in plain English

## The short version

Pullo is an AI code reviewer built around one idea: **don't trust the first answer.**

When you give it a code change, three AI passes run in sequence:

1. **Investigator:** reads the change, plus the code that depends on it, and lists possible bugs.
2. **Verifier:** takes each possible bug and tries to back it up with real code. If it can't point to actual lines it read, the claim is dropped.
3. **Judge:** turns the claims that survived into review comments.

The output is a set of comments saved on your machine. Pullo never edits the code, never runs it, and never posts anything to GitHub. You decide what to do with the comments.

It also controls cost and is reproducible. Each review has a hard dollar cap. Every step is recorded, so you can replay a review later and get the identical result without paying for it again.

**Status:** early (pre-alpha). It has shown that the pipeline works end to end, but nobody has measured how many real bugs it catches or how often it's wrong.

---

## The technical version

### 1. Inputs are pinned

A review starts from two exact commit SHAs, base and head, never from a branch name. `python3 -m reviewer.repoimport fetch` / `capture-pins` imports both trees into a local store and writes `repo-import-pins@1` files. The PR identity (repo, number, base, merge-base, head, capture time) is written to an `ordinary-pr-pins@1` record, and its digest is kept in an operator baseline. If anything doesn't match its pin, the run refuses to start.

The reviewed repository is treated as **data only**. Nothing from it is executed or imported, and Pullo must be run from its own checkout, never from inside the repo under review.

### 2. Pipeline stages

| Stage | What happens |
| :- | :- |
| **PREPARE** | Builds a bounded starting context from the diff. Runs a host-side **impact scan**, a heuristic map of changed or removed definitions and their whole-word references outside the changed lines. Lockfiles, generated or minified files, and files over 5,000 lines are skipped, and each skip is disclosed. |
| **INVESTIGATE** | The investigator model gets read-only tools (open files, `find_references`) and returns **hypotheses**: possible defects, each with a file, line range and category. |
| **VERIFY** | A separate verifier pass tries to confirm each hypothesis with cited evidence. At most 20 hypotheses are verified. The rest are dropped as `over-cap`. |
| **JUDGE** | Writes the verified findings up as local review comments in `review.md`, with `report.json` alongside. |

### 3. Making the investigator actually look around

- **Exploration floor (impact v2, the default).** If the model gives a final answer on its first step without requesting any context, that answer is treated as a draft. While turns and tool budget remain, the host sends one fixed follow-up ("test this against the dependents"), allowing up to 3 more steps. This guarantees the extra prompt, not that the model actually opens more files.
- **Specialists (impact v3, opt-in, `impact_version=3`).** Three investigators run in order, each with an extra focus:
  - **contracts:** interfaces and the code that depends on them.
  - **logic:** edge cases inside the changed code.
  - **safety:** error paths, resource/lock/transaction lifecycle, concurrency, security, data integrity.

  They share the budget of one v2 investigator through cumulative ceilings: 20/40/60 tool calls, $0.93/$1.87/$2.80, and 100/200/300 seconds. Unused room carries over to the next specialist.
- **Deduplication.** A later specialist's hypothesis is merged into an earlier one when both have the same file and category and their start lines are at most 3 apart. VERIFY takes hypotheses round-robin across specialists. If a hypothesis fails verification, its first merged duplicate gets a turn.

### 4. Why the verifier can't just make things up

Citations are checked for **provenance**. A cited excerpt must match text that a tool actually returned earlier in the same retrieval chain, logged in full. Verifier citations must use references the host can resolve to real content. Invalid evidence IDs are refused, and the claim is dropped rather than repaired. These checks were hardened in PR #10 and PR #13.

### 5. Models, money and modes

- **Models** are set per role (investigator, verifier, judge) in `pullo.toml`. Only an exact allowlist is accepted: `anthropic/claude-sonnet-5.5`, `claude-haiku-5.5` and `claude-opus-5.5`, all via OpenRouter. There are no retries and no fallback model.
- **Spend** is capped at **$4 per run**, and the total across runs is capped by a durable spend ledger. Each check runs before a call, so a single call can finish slightly above a ceiling.
- **Run modes:**
  - `plan` sends nothing. It builds the first real request with a transport that refuses to send, then reports the request hash and worst-case cost.
  - `live` needs `--confirm-live`, a spend authorization, an existing state directory, and the API key from your `.env`, which is read by a single trusted loader.
  - `replay` re-executes a recorded `trace.jsonl` (checked against a digest you keep separately) with **zero** model calls. The hypotheses, findings, comments and call counts must match exactly.

### 6. Reproducibility

Every model call and tool call goes through a gateway that writes a trace. Requests are canonicalised to JSON and digested. Config, prompts, profile, contracts version (`s0a-contracts@7`) and import identities are all bound into the run identity, so a trace only replays under the exact software and config that recorded it.

### 7. What's been observed so far

- **Synthetic smoke suite:** 6 scripted cases record and strictly replay offline, with 19/19 calls replayed and $0 spent. This checks the mechanics only.
- **Real pinned public PR:** one bounded Sonnet run completed and replayed identically. It produced no hypotheses and no comments.
- **Planted clock-unit bug:** the full chain ran (1 hypothesis → 1 verified finding → 1 comment) with 4 model calls and 9 tool calls, and it replayed exactly.

None of this measures precision, recall, cost per review, or how Pullo compares with other reviewers. See [README.md](README.md) for the known open limits.

### Try it offline

```sh
python3 -m reviewer smoke record --out /tmp/smoke-rec
python3 -m reviewer smoke replay --recording /tmp/smoke-rec --out /tmp/smoke-rep \
  --manifest-digest sha256:<digest printed by record>
```

This needs Python 3.14 and the standard library only. It uses no key, no network and no spend.
