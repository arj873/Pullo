# Pullo

Read-only AI code review with independent verification. Pullo investigates a change, asks a separate pass to challenge each finding, and produces local review comments with pinned evidence. Authors decide which changes to make.

**Status: pre-alpha.** Review quality has not been measured. There is no precision/recall figure, no competitive-quality claim and no cost-per-review claim (including any mid-sized-review price target). Treat everything below as mechanics, not capability.

This repository state is a **checkpoint for review, not a release**. The public default test suite currently exits successfully, with explicit optional skips and expected-failure repros (see Tests).

The Python package is named `reviewer`; the product name is Pullo. Everything is stdlib-only (tested on Python 3.14).

**License:** none chosen yet. Until one is added, all rights are reserved; this checkpoint is not licensed open source.

## What exists

- Typed contracts, a canonical-JSON/digest layer, a model gateway with a trace and strict replay, read-only repository tools, a staged pipeline (investigate, verify, judge) and local review output.
- Read-only importers that pin a historical commit pair or a repository head/base by object ID. Reviewed code is data: nothing from a reviewed repository is executed, and nothing is posted upstream.
- Bounded live trials through trusted-host launchers (`reviewer.runtime`, `reviewer.pilot`) against Anthropic Sonnet via OpenRouter, with a hard spend cap, an exact model allowlist, no retries and no fallback. These need a key and a trusted host; they are not run by anything below, and no key is bundled.
- An experimental benchmark scorer exists in the project's working tree but is **not part of this checkpoint**; it will be proposed separately. Nothing here depends on it and no benchmark score is claimed.

## What has actually been observed

- Synthetic smoke suite: six scripted cases record and strictly replay offline (19/19 replayed calls, zero live calls, zero spend). This checks mechanics only.
- First repository-backed trial (a real pinned public pull request, one bounded Sonnet run): it completed and replayed identically, with no hypotheses and no comments. An independent read found no concrete defect in what the model was shown. That is not a clean-repository claim and not a recall measurement.
- First synthetic positive trial (a planted clock-unit bug): the investigator found the intended hypothesis, but the verifier's final output carried invalid evidence identifiers and was refused by validation. Result: partial, one dropped hypothesis, no finding, no comment, and the judge did not run. This is a preserved format/provenance failure, not a successful end-to-end positive case. The strict replay of it was identical.

## Known open limits

- General live fork and stage-replay run-mode binding are not implemented. There is no CLI resume of an interrupted evaluation.
- Preventive isolation for the second (Terra-tier) model path is not done; that path is not claimed to work.
- Retrieval quality, model-vs-model comparison and the benchmark pipeline are unmeasured.
- The hosted public suite passes, but its 30 skips and 22 expected failures leave meaningful gates open (see Tests).
- Source docstrings still mention private project-coordination documents that are not in this repository.

## Review models

Set the investigator, verifier and judge models in `pullo.toml`. Each role can use a different model:

```toml
schema = "pullo-config@1"

[review.investigator]
provider = "anthropic"
model = "anthropic/claude-sonnet-5.5"

[review.verifier]
provider = "anthropic"
model = "anthropic/claude-sonnet-5.5"

[review.judge]
provider = "anthropic"
model = "anthropic/claude-sonnet-5.5"
```

The supported IDs are `anthropic/claude-sonnet-5.5`, `anthropic/claude-haiku-5.5` and `anthropic/claude-opus-5.5`, through OpenRouter. The OpenAI CLI path remains pending its isolation checks.

The historical, repository and synthetic review commands accept `--config /path/to/pullo.toml`. By default they read Pullo's own file, independently of the current directory or reviewed repository. Model selection does not change spending limits or permissions. Keep API keys outside this file.

## Run the offline smoke suite

```sh
python3 -m reviewer smoke record --out /tmp/smoke-rec
python3 -m reviewer smoke replay --recording /tmp/smoke-rec --out /tmp/smoke-rep
```

`record` runs every case in `fixtures/smoke` through the pipeline with a scripted synthetic provider, scores each result and writes a validated report. `replay` re-executes all cases offline against the recorded traces, with zero provider calls, and compares hypotheses, findings, comments, statuses and call counts.

Both need a new or empty `--out` directory outside the suite (and, for replay, outside the recording). Options: `--suite DIR`; `replay --manifest-digest sha256:...` pins the recording's `eval.json` bytes (printed on `record`'s last line). Exit codes: `0` all cases ran and every expectation/comparison held; `1` a report was written but something failed; `2` refused before any case ran.

No credential, network call or paid spend is possible from these commands. Prices in the cost lines are synthetic. Comments are local drafts.

## Tests

```sh
nice -n 19 python3 -B -m unittest discover -s tests -t .
```

The suite is offline and needs no credentials or network. [Hosted CI for PR #9](https://github.com/arj873/Pullo/actions/runs/40306956738) ran 2,401 tests with zero errors or unexpected failures, 30 skips and 22 expected failures. A later provenance PR has its own check and is not included in these counts. Limits remain visible:

- Raw third-party pull-request fixtures and private operator evidence are not published. Corpus-only test modules are left out of this repository; included tests requiring those inputs use explicit skips. Static historical import-boundary tests run without the private corpus.
- Known defects are kept as expected-failure tests so the repro stays in the tree.
- Some tests skip when a private fixture is absent.
- Local tests under `/tmp` can encounter an unrelated intermittent `/tmp/.git`, which makes the importer correctly reject a temporary store. Use a verified non-Git `TMPDIR` locally; hosted CI did not encounter this.

See `KNOWN_TEST_ISSUES.md` for the exact test IDs and counts at this checkpoint.
