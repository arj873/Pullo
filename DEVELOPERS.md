# Developing Pullo

This page covers how the code is laid out, how to run it and its tests, how a change becomes a measured version, and the safety rules every change must keep. [HOW-IT-WORKS.md](HOW-IT-WORKS.md) has the flow diagrams.

## 1. Layout

| Path | What lives there |
|---|---|
| `reviewer/contracts/` | Typed entities (Hypothesis, Finding, Comment…), canonical JSON, digests, the JSON schema |
| `reviewer/gateway/` | The model gateway: provider calls, trace, strict replay |
| `reviewer/tools/` | Read-only repository tools (view, search) for the staged pipeline |
| `reviewer/pipeline/` | The review engine: INVESTIGATE → VERIFY → JUDGE → PUBLISH, prompts, render, store. `consensus.py` holds v26's vote and matcher, and `seeded.py` the seeded-candidate ingest it builds on |
| `reviewer/runtime/` | Trusted-host adapters: the Claude Code CLI adapter (`claude_cli.py`), OpenRouter, the model catalog, and the spend constants (`scoring_budget.py`) |
| `reviewer/pilot/`, `reviewer/repoimport/`, `reviewer/historical/` | Launchers and importers that pin a repository or a commit pair by object id |
| `reviewer/benchmark/`, `reviewer/scoring/` | The offline benchmark scorer and the smoke scorer |
| `integrations/claude-code/` | The `pullo-review` skill (`skills/pullo-review/`) and the `pullo-reviewer` subagent (`agents/`) |
| `tests/` | The offline test suite |
| `fixtures/`, `examples/` | Synthetic smoke cases and an invented-data benchmark demo |

The benchmark harness that drives live runs and scoring (review drivers, the scorer, receipts, preregistrations and reports) is kept private, outside this repository. The method and rules it follows are described below and in HOW-IT-WORKS.md.

## 2. Setup

- **Python:** 3.14, standard library only. There is nothing to install.
- **`gh`:** logged in. The skill uses it read-only for PR diffs and metadata, and to post a review only when asked.
- **Claude Code CLI:** for live reviews. The benchmark pins version 2.1.322; the skill works with any recent CLI. If several `claude` binaries are installed, check which one is first on your `PATH`.
- **TMPDIR:** use a non-Git directory on disk, not `/tmp`. `/tmp` can be RAM-backed, and a stray `/tmp/.git` makes the importer correctly refuse its store.
- **CPU:** run anything heavy (the suite, the smoke recorder) under `nice -n 19`.

## 3. Run things

```sh
# the offline test suite
nice -n 19 python3 -B -m unittest discover -s tests -t .

# the synthetic smoke suite (record, then strict replay)
nice -n 19 python3 -m reviewer smoke record --out /var/tmp/smoke-rec
nice -n 19 python3 -m reviewer smoke replay --recording /var/tmp/smoke-rec --out /var/tmp/smoke-rep --manifest-digest sha256:DIGEST_FROM_RECORD

# a live v26 review of a PR (3 Claude Code calls on your subscription)
python3 -I integrations/claude-code/skills/pullo-review/scripts/pullo_review.py review https://github.com/OWNER/REPO/pull/123
```

- Known defects are kept as expected-failure tests, so the repro stays in the tree. Tests that need private fixtures skip. The ids are in [KNOWN_TEST_ISSUES.md](KNOWN_TEST_ISSUES.md).
- **Guard any test that drives a real code path with a fake CLI.** Use a masked `HOME` (an empty dir), a scratch `TMPDIR` and no network, and check afterwards that no file outside your scratch dir changed. One unguarded mutation run once reached the real CLI and made 12 real calls. Those runs are now blacklisted from every score.

## 4. The skill

`integrations/claude-code/` is the source of truth for the skill. Install it with:

```sh
cp -r integrations/claude-code/skills/pullo-review ~/.claude/skills/
cp integrations/claude-code/agents/pullo-reviewer.md ~/.claude/agents/
```

- **The script:** `scripts/pullo_review.py` is self-contained, standard library only. It reuses v26's fixed prompt and a byte-for-byte copy of the matcher from `reviewer/pipeline/consensus.py`.
- **Self-checks:** at start it checks the prompt's sha256 and the matcher block's sha256, and refuses to run if either was edited. If you change the method on purpose, change it in `consensus.py` first, then re-vendor it and update both pins.
- **Two deliberate differences from the benchmark arm:**
  - comments on files the PR deletes are kept, anchored on the base side;
  - a failed witness degrades to a flagged 1-of-1 review instead of an empty one.
- **Tests:** after any change, run it on a small public PR and on a scratch local branch with a planted bug. Check `review.json` (all three answers, the votes and every drop).

## 5. How versions are built and measured

A *version* (v3 … v26) is a reviewer commit, frozen into an **export**: a manifest that lists every file with its sha256. The benchmark refuses to run an export whose manifest sha is not pinned. The judge is frozen the same way, and a new judge version may change only budget constants, which is proven on every load.

Each change goes through:

1. **Card:** the coordinator writes the task with its acceptance evidence.
2. **Build:** one developer builds ONE diff, with proofs: guarded tests, mutants, and a rescore of every existing result to show nothing else moved.
3. **Gate:** a different developer reads the diff in full and runs their own mutants. The answer is GO, GO with fixes, or no-go. Authors never approve their own gate.
4. **Apply, freeze, pin:** the gated diff is applied, the export frozen, and its manifest sha pinned.
5. **Parity:** re-run on old inputs and expect byte-identical output.
6. **Tuning shake-out:** a live run on the tuning PRs, with the prediction written down first.
7. **Held-out one shot:** preregister, run once on a sealed batch, score, report, unseal.

## 6. Integrity rules

- **Tuning and held-out never mix.** Rules are tuned on tuning PRs only. A held-out batch is used once per version, and it is burned for tuning once its result is read.
- **Gold stays out.** Gold issues and competitor review text never enter a developer's or a reviewer's context. Developers see scores, not gold text.
- **Preregister first.** A write-once file fixes the version, cases, attempt rule, judge and pass rule before anything runs. The tools refuse to start until its sha256 is pinned.
- **No silent fallback.** A PR whose review could not run scores as an empty review, never as a weaker fallback.
- **Disclose everything:** judge-version mixes, re-fetches, retries, repo overlaps.

## 7. Safety rules

- **Read-only.** Reviews never push, never post unless the user asks, and never run scripts from the reviewed repository.
- **Untrusted data.** Reviewed code, PR text and instruction files can't change permissions, suppress findings or authorize tools. Review calls run with no tools, no settings, no CLAUDE.md and no MCP servers.
- **Keys stay out.** No key or credential is ever written to this repository or shown to a model. The skill never passes `ANTHROPIC_API_KEY`, so reviews run on the Claude Code subscription.
- **Spend is capped.** Paid benchmark scoring runs under hard caps (`reviewer/runtime/scoring_budget.py`), with no automatic paid retry and no fallback model.

## 8. Gotchas

- `claude -p --output-format json` prints one result object on some CLI versions and a list of events on others. Read the event with `type == "result"`.
- In a diff, a removed line that starts with `-- ` (an SQL comment, say) looks like a file header. Count hunk lines from the `@@` header instead of matching prefixes.
- The CLI has a midnight-UTC model-availability latch. Avoid long runs that span 00:00Z.
- zsh does not word-split `$VAR`, and `echo ====` fails there. Run shell runbooks under `bash`.
