# Pullo

Read-only AI code review with independent verification. Pullo investigates a change, asks a separate pass to challenge each finding, and produces local review comments with pinned evidence. Authors decide which changes to make.

Pullo is in pre-alpha. The current working milestone is a six-case synthetic recording and strict replay (19/19 replayed calls, zero live calls, zero provider spend). Real provider adapters and historical PR integration are still under review and are not part of this checkpoint. Review quality has not been measured: no precision/recall, parity or cost-per-review claim is made.

The Python package is named `reviewer`; the product name is Pullo. The smoke harness is offline and stdlib-only (tested on Python 3.14).

**License:** none chosen yet. Until one is added, all rights are reserved; this checkpoint is not licensed open source.

## Record and replay the six smoke cases

```sh
python3 -m reviewer smoke record --out /tmp/smoke-rec
python3 -m reviewer smoke replay --recording /tmp/smoke-rec --out /tmp/smoke-rep
```

`record` runs every case of `fixtures/smoke` through the real pipeline (INGEST → … → LEARN) with the scripted
synthetic provider, scores each actual result and writes a validated EvalReport. `replay` re-executes all cases
offline against the recorded traces with zero provider calls, compares the recomputed hypotheses, findings,
comments, statuses and call counts with the recording, and writes its own report.

Both need a new or empty `--out` directory outside the suite (and, for replay, outside the recording).
Options: `--suite DIR` (another synthetic suite); `replay --manifest-digest sha256:…` pins the recording's
`eval.json` bytes (the digest `record` prints on its last line).

Exit codes: `0` all cases ran, all scorer expectations met and (replay) every comparison equal; `1` a report
was written but something failed (see the summary); `2` refused before any case ran.

Output: `summary.txt` (also printed), `report.json` (EvalReport), `eval.json` (record: the trusted replay pin —
per-case original trace digest, outcome digest, config identity), `outcomes/<case>.json`, `runs/<runId>/`
(trace, stage artifacts, `comments.json`, `review.md`, receipt), `suite/` (frozen read-only suite copy) and,
for record, `operator/` (synthetic-only authorization and the single shared spend book).

## What this does not show

- Synthetic smoke checks mechanics only. Precision/recall here say nothing about review quality or parity.
- No real provider, credential, network call or paid spend is possible from these commands. Synthetic prices
  in the cost lines are not spend.
- Comments are local drafts; nothing is posted and no reviewed repository code is executed.
- No CLI resume of an interrupted evaluation and no stage-replay entry point yet.

## Tests

```sh
python3 -m unittest discover -s tests -t .
```

The published suite is self-contained: 497 tests, offline, no credentials or network. At the frozen checkpoint
it passes with 1 skip (needs a private historical fixture) and 2 expected failures (known defects tracked as
expected-failure tests: a repair-path gateway case and blank-line range citation).

Not included in this checkpoint: tests and tooling that require raw historical pull-request fixtures (third-party
source, licensing not bundled), the live provider/runtime adapters, and the historical-input bridge. Those are
unfinished and under review, so the corpus-importer unit tests that depend on them are withheld too.
