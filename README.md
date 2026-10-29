# Pullo

Read-only AI code review with independent verification. Pullo investigates a change, asks a separate pass to challenge each finding, and produces local review comments with pinned evidence. Authors decide which changes to make.

**Status: pre-alpha.** Review quality has not been measured. There is no precision/recall figure, no competitive-quality claim and no cost-per-review claim (including any mid-sized-review price target). Treat everything below as mechanics, not capability.

This repository state is a **checkpoint for review, not a release**. Historical evidence: the earlier public checkpoint `c2b8ef758cecfe92984f963c929d0fb35cd6c46e` had a default test suite that exited successfully, with explicit optional skips and expected-failure repros (see Tests). Those counts describe that checkpoint, not a tree that adds the offline benchmark scorer.

The Python package is named `reviewer`; the product name is Pullo. Everything is stdlib-only (tested on Python 3.14).

**License:** none chosen yet. Until one is added, all rights are reserved; this checkpoint is not licensed open source.

## What exists

- Typed contracts, a canonical-JSON/digest layer, a model gateway with a trace and strict replay, read-only repository tools, a staged pipeline (investigate, verify, judge) and local review output. Citation provenance checks require complete logged excerpts rendered at an eligible hop of the same retrieval chain; verifier citation templates use references the host can materialize. These controls were hardened in [PR #10](https://github.com/arj873/Pullo/pull/10) and [PR #13](https://github.com/arj873/Pullo/pull/13).
- Read-only importers that pin a historical commit pair or a repository head/base by object ID. Reviewed code is data: nothing from a reviewed repository is executed, and nothing is posted upstream.
- Bounded live trials through trusted-host launchers (`reviewer.runtime`, `reviewer.pilot`) against Anthropic Sonnet via OpenRouter, with a hard spend cap, an exact model allowlist, no retries and no fallback. These need a key and a trusted host; they are not run by anything below, and no key is bundled.
- An experimental **offline benchmark scorer** (`reviewer.benchmark`) that counts and pools externally supplied judgments over a pinned source, with a runnable invented-data recipe. See [Offline benchmark scorer](#offline-benchmark-scorer-experimental). It has no live producer and no benchmark score is claimed.

## What has actually been observed

- Synthetic smoke suite: six scripted cases record and strictly replay offline (19/19 replayed calls, zero live calls, zero spend). This checks mechanics only.
- First repository-backed trial (a real pinned public pull request, one bounded Sonnet run): it completed and replayed identically, with no hypotheses and no comments. An independent read found no concrete defect in what the model was shown. That is not a clean-repository claim and not a recall measurement.
- First synthetic positive trial (a planted clock-unit bug): the investigator found the intended hypothesis, but invalid verifier evidence identifiers were refused. The run was partial, with one dropped hypothesis and no finding or comment; strict replay was identical.
- A subsequent bounded Sonnet positive control on the planted clock-unit bug completed all stages: one hypothesis, one verification, one finding and one local comment, with no drops. Four model calls and nine tool calls were reproduced by strict offline replay, with no new model calls or spend during replay. Independent adjudication accepted the trigger, impact, location and excerpts. This establishes full-chain mechanics on one synthetic case; it does not measure real-review quality, model-family independence or cost per review.

## Known open limits

- General live fork and stage-replay run-mode binding are not implemented. There is no CLI resume of an interrupted evaluation.
- Preventive isolation for the second (Terra-tier) model path is not done; that path is not claimed to work.
- Retrieval quality, model-vs-model comparison and the benchmark pipeline are unmeasured. The benchmark package has no live producer, no paid scoring, no historical-eligibility proof from its CLI and no quality or competitive claim.
- The hosted public suite at the earlier checkpoint passed, but its 30 skips and 22 expected failures left meaningful gates open (see Tests). The benchmark package adds two native-scorer expected failures; its own counts are reconciled from hosted CI, not stated here.
- Source docstrings still mention private project-coordination documents that are not in this repository.

## Impact mode (repository reviews)

With retrieval on, the repository pilot reviews in impact mode by default (`investigator.impact@v3` and `verifier.impact@v1`; `impact_version=2` selects `investigator.impact@v2` and `impact_version=1` the earlier `investigator.impact@v1`, each byte for byte as before).

In v3, INVESTIGATE runs three specialist investigators one after another, always in the order `contracts`, `logic`, `safety`. Each is a v2 investigator with the same prefetched context and the v2 exploration floor. Its task is the v2 task plus one host-written lens paragraph: contracts and dependents; logic and edge cases inside the changed code; or failure paths and safety (error handling, resource, lock and transaction lifecycle, concurrency, security, data integrity). The three share the investigator budget that one v2 investigator had. Each runs under cumulative ceilings: specialist i may start a tool call only while INVESTIGATE has made fewer than pool*(i+1)/3 calls, and an investigator call only while INVESTIGATE spend is below share*(i+1)/3. The pool is the 60-call per-agent cap, giving ceilings of 20, 40 and 60. The share is the Plan's investigation share ($2.80 of the $4 ceiling), giving ceilings of $0.93, $1.87 and $2.80. Unused room rolls forward. The spend check runs before each call, so one call can end above the ceiling. Per-agent caps (8 turns, 60 tool calls, context characters) still apply to each specialist. The run-wide tool cap (160), the run ceiling and the stage deadlines are unchanged, and the INVESTIGATE stage ceiling is shared by the three specialists in turn. Before VERIFY, a later specialist's hypothesis is merged into the first kept hypothesis of an earlier specialist when both have the same head path and category and overlapping lines. Merged hypotheses stay in the INVESTIGATE artifact's `merges` list and are dropped in VERIFY as `merged`, without a verifier call. At most 20 distinct hypotheses go to VERIFY; any beyond that are dropped as `over-cap`. If one specialist fails, the others still run. A failure that would repeat for every specialist (live calls disabled, model unresolved, contract violation) or one with an unknown provider outcome starts no further specialist. Replay, cancellation, internal and spend-book failures fail the run, as in v2. If no specialist answers, the run fails as v2 would. Only a deadline, soft-deadline or budget stop, or an exhausted retrieval counter, marks INVESTIGATE partial. `review.md` lists each specialist's status. Expected cost: about three times the investigator calls of v2. Measured v2 runs used 1 to 4 investigator calls, so v3 should use about 3 to 12. The verifier and judge calls stay the same, because duplicates are merged. Add roughly $0.2 to $0.8 per review at measured Sonnet 5.5 prices, all within the same $4 ceiling.

In v2 the engine enforces an exploration floor: a final answer given on the first hop, before any context request, is treated as a draft. If turns and tool budget remain, the host sends one fixed continuation (at most 3 more hops) that asks the model to test the draft against dependents. The next final answer is used. The floor guarantees one extra prompt, not that the model actually opens dependents. If the continuation fails or reaches its limits, the draft is used; only a deadline stop or the run ceiling also marks the run partial. A spend-book failure still fails the run, as in v1. Each decision is a `retrieval.floor` trace event. PREPARE logs one host-only `impact_scan`: a bounded, heuristic map of changed or removed definitions and their whole-word references outside the changed lines. The investigator may also request `find_references`. The prompts ask the investigator to check dependents and to cite both the changed code and the dependent code. `review.md` and the receipt disclose how many changed symbols were analysed, how many references were found, and how many dependent files were opened. Scans stop only on deterministic caps; a wall-clock safety abort fails the call outright. Lockfiles, generated or minified files, and files over 5000 lines are skipped for symbol extraction, and each skip is disclosed.

There is no `--no-impact` CLI flag. Runs recorded before impact mode (Cal 14740, Grafana 94942, Sentry 95633 and earlier) are replayed only with their own frozen exports, never with this tree. In code, `repository_profile(..., impact=False)` and `repository_policy(..., impact=False)` still give the earlier retrieval@2 profile and policy byte for byte.

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
nice -n 19 python3 -m reviewer smoke record --out /tmp/smoke-rec
nice -n 19 python3 -m reviewer smoke replay --recording /tmp/smoke-rec --out /tmp/smoke-rep --manifest-digest sha256:REPLACE_WITH_DIGEST_PRINTED_BY_RECORD
```

`record` runs every case in `fixtures/smoke` through the pipeline with a scripted synthetic provider, scores each result and writes a validated report. `replay` re-executes all cases offline against the recorded traces, with zero provider calls, and compares hypotheses, findings, comments, statuses and call counts.

Replace `REPLACE_WITH_DIGEST_PRINTED_BY_RECORD` with the hexadecimal digest from the last line of `record` output. Both need a new or empty `--out` directory outside the suite (and, for replay, outside the recording). Options: `--suite DIR`; `replay --manifest-digest sha256:...` pins the recording's `eval.json` bytes (printed on `record`'s last line). Exit codes: `0` all cases ran and every expectation/comparison held; `1` a report was written but something failed; `2` refused before any case ran.

No credential, network call or paid spend is possible from these commands. Prices in the cost lines are synthetic. Comments are local drafts.

## Offline benchmark scorer (experimental)

`reviewer.benchmark` verifies a pinned benchmark source and counts judgments that someone else produced. It never calls a model, network or provider. Ordinary structured report fields omit gold and comment text, evidence bodies and free pair-error messages, but ids, case URLs, tool names, the judge block and other source metadata are caller-controlled, echoed unverified and can contain any text, and error diagnostics may echo malformed input. Keep reports and diagnostics scorer-side and review them before sharing; they are not proved opaque.

```sh
nice -n 19 python3 -B examples/benchmark_demo.py
```

The demo builds an **invented** source, pins it, writes all-pairs judgments, runs `python3 -m reviewer.benchmark reference-score` in-process and checks hand-derived counts, then shows the refusal and incomplete/missing/error/hidden controls. Two scorers stay separate: the native view (`score`) and the reference-count view (`reference-score`, all-pairs judgments, undefined ratios reported as a named zero). Neither is a quality measurement. Names and settings of a judge model are declarations the package does not verify; only the raw source files are verified, against pins. The `select` CLI has no `--admissions` option yet (the API supports admission documents).

Exact flags, the pinning/store/output boundary, the judgments schema and the known limits are in [reviewer/benchmark/README.md](reviewer/benchmark/README.md). Nothing here reads real benchmark data.

## Tests

```sh
nice -n 19 python3 -B -m unittest discover -s tests -t .
```

The suite is offline and needs no credentials or network. Historical evidence for the earlier public checkpoint: [hosted CI for PR #13](https://github.com/arj873/Pullo/actions/runs/40324991362) completed on 2026-10-26: **2,441 tests, OK, 30 skips, 22 expected failures**, with zero errors or unexpected failures. Contract export and all six smoke record/replay cases also passed. Its head commit and the public checkpoint above share tree `d1e467637f6a8ad173bd855d084680c0c519a728`; these counts include the citation-provenance hardening. Limits remain visible:

- Raw third-party pull-request fixtures and private operator evidence are not published. Corpus-only test modules are left out of this repository; included tests requiring those inputs use explicit skips. Static historical import-boundary tests run without the private corpus.
- Known defects are kept as expected-failure tests so the repro stays in the tree.
- Some tests skip when a private fixture is absent.
- Local tests under `/tmp` can encounter an unrelated intermittent `/tmp/.git`, which makes the importer correctly reject a temporary store. Use a verified non-Git `TMPDIR` locally; hosted CI did not encounter this.

See [KNOWN_TEST_ISSUES.md](KNOWN_TEST_ISSUES.md) for the exact public test IDs, reasons and counts at this checkpoint.
