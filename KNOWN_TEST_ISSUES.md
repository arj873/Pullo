# Known test issues at this checkpoint

Command: `python3 -m unittest discover -s tests -t .` from a clean export of this tree (no `orchestration/`, no `fixtures/historical`, no credentials).

Observed result (2026-10-26, Python 3.14, exact export of the first commit of this branch): **Ran 1316 tests, errors=6, skipped=2, expected failures=13.** The README and this file are the only later additions to that tree.

## Errors that need private inputs absent from this repository (5)

Each reads private operator evidence or a third-party historical fixture that is deliberately not published. The rest of each file runs and passes.

| Test | Missing input |
|---|---|
| `tests.runtime.test_s0b01b.OldLedgerReplay.test_reconcile_cli_previews_then_applies_and_never_creates_a_ledger` | `orchestration/validation/first-live-sonnet-canary-reconciliation.json` |
| `tests.runtime.test_s0b01b.OldLedgerReplay.test_reconcile_with_saved_host_evidence_is_append_only_idempotent_and_exact` | same |
| `tests.runtime_review.test_s0b01b_review.OldRowReplay.test_cli_refuses_missing_ledger_and_unknown_generation` | same |
| `tests.runtime_review.test_s0b01b_review.OldRowReplay.test_reconcile_cli_preview_then_apply_then_repeat_with_the_repo_evidence` | same |
| `tests.tools.test_partial_union.RealFixture1347.test_bridge_recipe_keeps_head_context_out_of_the_changed_list` | third-party historical case directory |

## Unexplained intermittent error (1 in this run)

`tests.pilot_review.test_repository_gate.Live.test_CONTROL_no_retry_no_repair_no_second_attempt_for_http_errors_and_unusable_answers` (subtest `[500]`) errored with `RepoImportError: bad-store: store must be outside every Git repository work tree`.

- An earlier broader run errored on a different pilot test with the same message (`tests.pilot.test_repository.CliTests.test_config_identity_binds_pins_records_profile_policy_and_retrieval`).
- Re-running those tests alone (their class, `tests/pilot`, and the module) passes every time.
- Cause not identified. The store check refuses a store that has a `.git` entry in any ancestor, so something transiently puts one above the test's temporary directory during the full run. Not hidden or skipped.

## Excluded from this repository (not published)

`tests/corpus`, `tests/corpus_review`, `tests/historical`, `tests/tools/test_tr_fixes.py`: they need raw third-party pull-request fixtures or private corpus manifests. Their code under `reviewer/corpus` and `reviewer/historical` is included.

## Expected failures (13) and skips (2)

Expected failures are known defects or open gates kept as `expectedFailure` repros in the tree (find them with `grep -rn expectedFailure tests`). The skips need a private fixture.
