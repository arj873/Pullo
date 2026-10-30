# Offline benchmark scorer (experimental)

Counts and pools **externally supplied** judgments over a pinned benchmark source. It is pure, offline and stdlib-only: it makes no model, network, provider, credential or Git call, and it never runs anything from the data it reads.

**Status: pre-alpha mechanics.** There is no live producer in this repository (nothing here extracts candidates, groups duplicates or judges matches with a model), no paid scoring, no historical-eligibility proof from the CLI, and no quality or competitive claim. A number from this package is a count over judgments somebody else supplied.

"Root" and "trusted host" in these docs and in the source are project roles (the orchestrator and the machine that holds credentials). They do not mean the Unix superuser; no command here needs `sudo` or uid 0.

## Try it in two minutes

```sh
nice -n 19 python3 -B examples/benchmark_demo.py
```

[`examples/benchmark_demo.py`](../../examples/benchmark_demo.py) builds an **invented** two-PR source, pins it, writes all-pairs judgments, calls the real `reference-score` entry point in-process and checks the result against hand-derived counts. It then runs the normal and refusal controls below. Files go to a new temporary directory (or `--workdir DIR`, which must be new or empty and outside `reviewer/`, `fixtures/` and `tests/`). It never reads real benchmark files.

## Two scorers, kept apart

| | native (`score`) | reference (`reference-score`) |
|---|---|---|
| input | `semantic-judgments@1`: a representative candidate per duplicate group is matched to one golden id or `null` | `reference-judgments@1`: a judgment for **every** golden x candidate pair, with a finite confidence |
| report | `benchmark-score-report@1` | `reference-score-report@1` |
| counting | each matched representative is a true positive; an unmatched duplicate group is one false positive; zero-gold cases are scored; a candidate cannot match two goldens | follows the pinned upstream counting rules, quirks included (below) |
| undefined ratio | `null` with a reason, plus a separately labelled `upstreamCompatZero` | `0.0` under the named convention `reference-undefined-is-0`, listed in `undefined` |

The native view is **not** the reference formula and says so in its own report (`referenceCompatibleView.status: "unavailable"`). The reference view is a separate reimplementation of the counting of upstream revision `e616e849755441da38f18bf3adba2c9583b03803`, read as text and never executed; it claims no parity with upstream results. Native judgments are never expanded into pairs, and the two reports must not be compared as if they measured the same thing.

Reference counting rules, preserved on purpose: golden-major, candidate-minor order; a golden comment's match is replaced only by a **strictly higher** confidence; the first match wins ties; identical golden (or candidate) text is collapsed; a candidate matched through a duplicate group marks its siblings matched; a case with no golden comments is skipped and listed; with no candidates every golden is a false negative. Precision, recall and F-scores pool micro counts per tool over scored cases for the `strict`, `core` and `all` category profiles; the primary view is `core/F1`.

## Commands

All commands: `nice -n 19 python3 -B -m reviewer.benchmark <command> ...`.

| command | needs | does |
|---|---|---|
| `verify-pins` | `--pins --data --labels [--expect-revision]` | checks size, sha256 and Git blob id of both files against the pins |
| `inspect` | the above + `--proposal` | loads and validates the roster and cases; prints counts and file digests only |
| `project` | the above + `[--rules]` | metadata-only projection and tool-version resolution |
| `select` | `--projection --proposal --proofs` | cutoff-proof selection (see the admission gap) |
| `score` | the above + `--judgments --tools` | the native scorer |
| `reference-score` | `--pins --data --labels --proposal --judgments --tools [--cases URL...] [--expect-revision] [--out]` | the reference scorer |

`--judgments` is one document or a JSON list of documents; `--tools` lists distinct tool names; `--cases` restricts to a subset of roster URLs (the report says `subset: true`). Exit codes: `0` a report was produced (it may still say *not complete*); `1` refused because of content (`tamper`, `pins`, `judgments`, `shape`, `roster`, `json`, `judge-mismatch`, ...); `2` refused because of location or arguments (`io`, `boundary`, `args`, or an argparse usage error). A refusal writes one JSON line to stderr and scores nothing.

## Pinning, store and output boundary

- **Pins** (`benchmark-source-pins@1`): `revision` (40 hex) and, for each of `benchmark_data.json` and `pr_labels.json`, `bytes`, `gitBlobSha` and `sha256` (`sha256:<64 hex>`). A pin file from a capture receipt is also accepted. Pins come from a trusted source, never from the store they verify: a pins file inside the directory that holds either data file is refused. `--expect-revision` must equal the pinned revision.
- **Store**: the directory of the data and labels files holds gold and tool comments. Files are opened without following symlinks, must be regular files, are capped at 64 MiB, and must match the pins byte for byte (same-length edits are detected). Duplicate JSON keys, `NaN`/`Infinity` and deep nesting are refused.
- **Roster**: `proposal` (`benchmark-partition-proposal@1`) lists the PR URLs in ascending sha256 rank with dev/frozen candidates that partition them. The data URLs, the label URLs (minus the exact `https://example/pr` fixture) and the roster must be equal.
- **Output**: `--out` is created exclusively (never overwritten, mode `0600`) and must not be inside the store, or inside `reviewer/`, `fixtures/` or `tests/` of the checkout. Ordinary structured report fields carry ids, fixed status classes and counts, and omit gold text, comment text and free pair-error messages (a pair `error` string is reported only as the class `judge-error`). That is not an opacity guarantee: case URLs, tool names, candidate and comment ids, the full `judge` block (top level and per case) and other source metadata are caller-controlled, echoed verbatim and unverified, so they can contain any text, including paths or body text; shared JSON diagnostics can also echo parts of malformed input. Keep `--out` files, stdout and refusal lines scorer-side and review them before sharing; this is a disclosure limit, not a sanitizer or a cryptographic trust claim. The stdout copy also carries `reportSha256` of the written file.
- **Data shape** (`golden`/`reviews`): gold severity is exactly `Critical`, `High`, `Medium` or `Low` (no case folding or trimming) and category one of `bug security concurrency data api perf test_gap doc_defect style speculative`; a summary comment has `path: null` and `line: null`; one review per tool per case. Anything else is refused, not inferred.

## Writing `reference-judgments@1`

One document per (case URL, tool); keys exactly `schema caseUrl tool judge extraction duplicateGroups pairs`.

```json
{"schema": "reference-judgments@1", "caseUrl": "<roster url>", "tool": "demo-a",
 "judge": {"model": "...", "extractionPrompt": "...", "dedupPrompt": "...", "matchPrompt": "...",
           "schemaSha256": "sha256:...", "runRef": "..."},
 "extraction": {"candidates": [{"id": "demo-a:1", "sourceCommentId": "rc2:...", "text": "..."}]},
 "duplicateGroups": {"candidateListSha256": "sha256:...", "groups": [[1, 2]]},
 "pairs": [{"golden": "gold:0:1", "candidate": "demo-a:1", "match": true, "confidence": 0.9},
           {"golden": "gold:0:2", "candidate": "demo-a:1", "error": "judge call failed"}]}
```

- **Candidates**: unique non-empty `id`, non-empty `text`, and a `sourceCommentId` that is a comment id of **this tool's review of this case**. Golden ids are `gold:<case index>:<n>`; comment ids (`rc2:...`) are derived by the loader, so a producer gets them from `reviewer.benchmark.load_source(...).cases[url].review(tool).comments[i].id`. No CLI prints them. Comments no candidate cites are reported (`uncoveredCommentIds`, `extractionCoverage`), not counted as false positives.
- **Duplicate groups**: non-empty lists of distinct, in-range, 0-based indices into the candidate list, in order. `candidateListSha256` is `"sha256:" +` sha256 of the canonical JSON (sorted keys, separators `,` `:`, UTF-8, no NaN) of `[[id, text], ...]` in candidate order. Order matters: a later group overwrites the sibling set of a shared candidate, and candidate order drives the strict-improvement rule. The demo shows and cross-checks the recipe.
- **Pairs**: **all** G x C golden x candidate pairs, each exactly once, each either `{golden, candidate, match: bool, confidence: finite number}` or `{golden, candidate, error: non-empty string}`. A missing pair makes the case *incomplete*. `null`, string, boolean, `NaN` and infinite confidences are refused, and confidence is not clamped to `[0, 1]`: upstream compares unbounded numbers. With zero candidates there are zero pairs, and the document is still required.
- **Judge block**: all six keys, non-empty strings. One report must use a single judge configuration (`judge-mismatch` otherwise). The block, the tool names and the candidate ids are **producer declarations echoed unverified**; nothing binds them to a prompt, schema or model. Supported input can set `judge.model` (or any judge string) to arbitrary text and it appears unchanged in stdout and a saved report; this reproduces and is disclosed, not sanitized. A different judge's scores, including upstream's, are not comparable.

## What the report says when things are missing

| situation | result |
|---|---|
| every requested case and tool scored, source bound | `complete: true`; `pooled` has `strict`/`core`/`all` counts, precision, recall, F1, F2 |
| a pair absent (*incomplete*) or no document at all (*missing*) | tool `complete: false`, listed under `incomplete` / `missing`, `pooled: null`; `partialPooled` is labelled `notAScore` |
| a pair with `error` | counted in `errorsCount`, skipped in matching, reported as class `judge-error` (the string is not copied); the tool is not complete (`pairErrorCases`) |
| reference-hidden tool (upstream's list, or the prefix `mra-`) | `referenceHidden: true`, never `complete`, no pooled numbers |
| case without gold | `skipped-zero-gold`, listed |
| precision or recall with a zero denominator | `0.0`, named in `undefined` with `zeroConvention: "reference-undefined-is-0"` |

Not-complete reports are mechanics output, not scores. Case, tool, judgment and boundary problems that are not "missing data" are refusals.

## Verified versus declared

The CLI verifies the two raw files against the pins and binds the report to that loaded source (`sourcePins`). That binding compares the supplied in-memory source with the cases scored; it is not a signature. The low-level API `score_reference_suite(cases, docs, tools=..., source=None)` skips binding altogether: the report is then never complete and says so. In both paths, model names, prompt names, run references and other judge settings are unverified declarations.

## Admission gap in `select`

`select_cases(proposal, projection, proofs, admissions)` (API) supports separate root admission documents, which are what turn a self-attested cutoff proof into `proven`. The `select` **CLI has no `--admissions` option**: passing it exits `2` as an unknown argument, so from the CLI no case can become `proven` and all stay `attested`. This is pinned by `tests.benchmark_review.test_s107a_recheck.Admission.test_GAP_cli_select_has_no_admissions_input_so_nothing_can_be_proven`.

## Known repros and tests

Two native-scorer limits are kept as expected-failure tests in `tests/benchmark_review/test_s107a_gate.py` (`MatchingSemantics`):

- `tests.benchmark_review.test_s107a_gate.MatchingSemantics.test_S1_one_candidate_may_match_two_goldens`
- `tests.benchmark_review.test_s107a_gate.MatchingSemantics.test_S2_report_has_a_separately_named_reference_compatible_view`

Both stay open for the native view; the reference view is where all-pairs counting lives. Their count in the public inventory (`KNOWN_TEST_ISSUES.md`) is reconciled from the hosted CI of the pull request that ships this package, not predicted here.

Run the benchmark tests, and the offline recipe check, from a checkout:

```sh
nice -n 19 python3 -B -m unittest discover -s tests/benchmark -t .
nice -n 19 python3 -B -m unittest discover -s tests/benchmark_review -t .
nice -n 19 python3 -B -m unittest tests.benchmark_review.test_s107a_recheck.PublicRecipe
```

`PublicRecipe` runs the demo and its normal/refusal controls with no network, provider, key or state access. The severity vocabulary test states its oracle in the test file and needs no private receipt.

## Common-judge extraction versions

The common judge (`allpairs.py`, `score_prompts.py`, `pullo-score.toml`) extracts with `bench.extract@v3`. The host splits each comment into numbered segments (`score_prompts.segments`). The model answers only `{sourceCommentId, startSegment, endSegment}` in the `ScoreExtractionSegments` schema, and code joins those exact segments into the candidate text. The model never copies comment text. That copying is what `bench.extract@v2` (`ScoreExtraction`) did, and the provider's output filter stopped it on long comments.

- v2-era score traces, canaries and witnesses are verified only with the frozen judge export built from `69b676c8`. Current main no longer accepts `ScoreExtraction` for the extractor role.
- v2 and v3 documents (`judge.extractionPrompt`) must never be mixed in one comparison. Every arm of a comparison is scored by one judge version.

## Common-judge output caps

`pullo-score.toml` caps output at 8000 tokens for extract, 4000 for dedup and 1024 for pair (`bench.pair@v2`, `ScorePair`). The same numbers are the policy maxima in `reviewer/score_config.py` `MAX_OUTPUT`. A lower value loads. A higher value is refused as widening.

The pair cap was 256 until 2026-10-29. Opus 5.5 counts its reasoning tokens against `max_tokens`. In 492 real pair calls the median was 17 output tokens and 7 calls used more than 200. Three calls stopped with `finish_reason` `length` at 255-256 reasoning tokens and produced no JSON. Each became invalid output, and because the campaign is all-or-nothing it had no headline. The cap is now 1024. Sampling and effort stay omitted, and retries stay 0.

- The raise bumps the score profile to `pullo-score@2`. It also changes the config digest and the host policy digest, because `policy_digest` now covers `MAX_OUTPUT` and the profile ref. Traces, canaries and witnesses recorded at 256 (`pullo-score@1`) do not verify under the new pins. That holds even with a tighter 256 config, whose config digest equals the @1 one: the gateway refuses the trace on its profile, and the baseline refuses the receipt on its policy pin. `ScoreHost` refuses a `profile_ref` other than the profile's `id@version` (`profile-ref-mismatch`).
- The complete-set pair fit (`score_host._fit`) reserves the full 1024 output tokens for every pair. That is 768 more tokens per pair than before. The 4M run ceiling is unchanged; the scoring sub-cap was raised from 8M to 16M by the user (2026-10-29), then to 30M (2026-10-30), with the scoring-time aggregate ceiling raised by the same +14M from 20M to 34M.

Admission impact, measured on the offline host test's synthetic pairs (12 pairs, invented test price):

| Per pair | At 256 | At 1024 | Change |
|---|---|---|---|
| Gateway reservation | 8,444 micros | 27,650 micros | about 3.3x |
| Adapter worst case | 29,224 micros | 44,592 micros | about 1.5x |

- The 4M run ceiling now admits about 144 synthetic-size pairs. It admitted about 473 before.
- At the old 8M scoring cap the 1024 cap admitted about 179 pairs in total (about 273 at 256); the 16M cap roughly doubled that headroom, still inside the then 20M scoring-time aggregate ceiling (now 30M inside 34M).
- At the pinned Opus gateway price, the reservation is 6,755 -> 22,120 micros per pair, which is about 180 pairs per run. The adapter worst case does not depend on the profile price.
- Real campaigns so far peaked at 84 pairs, so they still fit. A larger declared set is refused whole (`does-not-fit`) and is never split.

## Not here

A live producer (extraction, deduplication or matching with a model) and its accounting, a scoring canary or campaign, historical-eligibility admission from the CLI, raw golden or competitor data, and any quality or cost claim. `phaseb.py` only defines request and schema text and makes no call.
