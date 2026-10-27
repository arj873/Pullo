# Reviewing an open pull request (ordinary current-PR host)

`python3 -m reviewer.pilot.ordinary` runs Pullo's existing repository review on **one open PR** of a repository, given
two pinned commits (base and head) and their two complete, verified repository imports. It is advisory, read-only and
local: output goes to a fresh local directory, nothing is posted upstream, and no reviewed code is executed or
imported. It is not a historical case: no merged status or cutoff is claimed.

## What you must supply (trusted operator inputs, held outside the output and the reviewed repo)

1. `ordinary-pr-pins@1`: `caseId` (`<owner>--<repo>--<number>`), `repo`, `prNumber`, `baseSha`, `mergeBase` (or null),
   `textRef` (= mergeBase, else baseSha), `headSha`, `state: "open"`, and the real UTC `capturedAt`. You verify the
   PR's state and commits yourself; this module checks only the pin, not GitHub.
2. An `operator-pin-baseline@1` record holding the digest of those pins.
3. Two `repo-import-pins@1` files and the import store, made with `python3 -m reviewer.repoimport fetch` /
   `capture-pins` at the base (`textRef`) and head commits.
4. A plain, empty directory named like the case id (`--case-dir`; never read).
5. For plan and live: an operator spend authorization. For live: an existing, previously used durable spending state
   directory, its expected baseline micros, and the host `.env` read by the one trusted key loader.
6. Optionally a review-model config (`--config`, `pullo.toml` format). The default is the bundled `pullo.toml`:
   Sonnet 5.5 for every role. The Terra (OpenAI) path is held and refused. There is no fallback model.

Run these commands from a trusted Pullo installation or checkout, not from the reviewed repository.

## Commands (placeholders)

```
python3 -m reviewer.pilot.ordinary --mode plan  --case-dir D --pr-pins P --pr-baseline B --store S \
  --base-import-pins BP --head-import-pins HP --out OUT_PLAN --auth AUTH
python3 -m reviewer.pilot.ordinary --mode live --case-dir D --pr-pins P --pr-baseline B --store S \
  --base-import-pins BP --head-import-pins HP --out OUT --auth AUTH --state-dir STATE --env ENV \
  --baseline-micros N --confirm-live
python3 -m reviewer.pilot.ordinary --mode replay --case-dir D --pr-pins P --pr-baseline B --store S \
  --base-import-pins BP --head-import-pins HP --out OUT_REPLAY --replay-trace TRACE \
  --trace-digest sha256:<64 hex>
```

Plan sends nothing: it builds the first real request with a refusing transport and reports its hash and worst-case
cost; compare that hash before going live. Replay reads no key, authorization or state and needs the trace digest you
stored outside the output directory.

## Limits that stay fixed

The run ceiling is **$4**, the aggregate is capped by the spending state, and there are no retries, repairs or
fallbacks. No flag widens a model, cap or budget. The reviewer sees no PR title or body; the starting context is a
bounded selection and import omissions are disclosed in the report. `origin.json` beside `report.json` records the PR
identity and pin digest.

## Identities and old traces

Config, profile, prompts, contracts (`s0a-contracts@7`) and import identities are versioned and bound into the run
identity. A trace replays only under the software and configuration that recorded it: keep the frozen software for old
traces. No claim is made that a trace recorded under an earlier contracts version replays under `@7`.

## Evidence so far

One real self-review of an open Pullo PR completed with 0 findings and one Sonnet call (about $0.107 official); its
strict replay used no new spend. It was a single-sample mechanics check, not a quality benchmark: initial context was
bounded, a generated-schema diff was unavailable, some test diffs were partial and the model made no follow-up
retrieval requests. No precision or recall claim.

Arbitrary-URL onboarding is not provided: you create the pins and imports yourself.
