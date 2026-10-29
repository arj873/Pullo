# Known test issues at the public checkpoint

The documented public checkpoint is commit `c2b8ef758cecfe92984f963c929d0fb35cd6c46e`, tree `d1e467637f6a8ad173bd855d084680c0c519a728`. [Hosted CI for PR #13](https://github.com/arj873/Pullo/actions/runs/40324991362) completed on 2026-10-26: **2,441 tests, OK, 30 skipped, 22 expected failures, zero errors or unexpected failures**. The tested PR head `1b8b90e0f017a0980e6bd665ba28c644bfb76e5c` has the same tree. Contract export and all six smoke record/strict-replay cases also passed. These counts include the citation-provenance changes from PR #10 and PR #13.

Run the offline suite from a clean checkout:

```sh
nice -n 19 python3 -B -m unittest discover -s tests -t .
```

It needs no credentials or network. The counts describe this pinned hosted environment, rather than every local installation.

## Skips

The public repository excludes raw third-party historical pull-request fixtures and private operator reconciliation evidence. Included tests requiring them skip explicitly; static historical import-boundary tests run without that corpus. Installed-CLI metadata and permission-sensitive probes can also skip when the required executable is absent or runner privileges make the probe meaningless. The hosted run reported 30 skips. Skips do not establish that those behaviours passed.

## Expected failures

The 22 IDs below are the public checkpoint's expected-failure repros that account for the hosted result. Each asserts desired behaviour for an unresolved defect, hardening request or safety condition. An expected failure keeps the suite exit code green while preserving the repro; an unexpected success requires independent regression review before removing its marker. The source links point to published tests, which contain the assertions and nearby controls. Unpublished benchmark tests are excluded from this inventory.

### Gateway and trace binding

- `tests.gateway_review.test_gateway_gw02_review.PostLoadMutation.test_OPEN_NEW7_verify_events_with_the_genuine_bytes_binds_the_pin_to_other_events` — The exported trusted-object helper can bind a genuine byte digest to a different event list; the normal load-from-bytes replay path parses its own events. [Source](tests/gateway_review/test_gateway_gw02_review.py).

### Historical pins

- `tests.historical_review.test_bridge_fix_review.TypedPins.test_F13_write_pins_escapes_with_ValueError_for_non_json_numbers_in_the_view_part` — Non-JSON numbers in view pins can escape write_pins as a raw ValueError instead of a typed error. [Source](tests/historical_review/test_bridge_fix_review.py).

### Verification, duplicate handling and replay

- `tests.integration_review.test_corrections_review.VerifierRelevance.test_DEFECT_LOW_echoing_the_investigators_cross_file_citation_must_not_verify_a_location_nobody_looked_at` — Echoing investigator evidence from another file can confirm a finding at a location the verifier did not inspect. [Source](tests/integration_review/test_corrections_review.py).
- `tests.integration_review.test_corrections_review.DuplicateHandling.test_DEFECT_LOW_an_identical_claim_twin_must_not_lower_the_comment_severity` — An identical-claim twin can lower the retained comment severity. [Source](tests/integration_review/test_corrections_review.py).
- `tests.integration_review.test_corrections_review.DuplicateHandling.test_DEFECT_LOW_an_identical_claim_twin_must_keep_its_own_evidence_on_the_comment` — Evidence belonging only to an identical-claim twin can disappear from the retained comment. [Source](tests/integration_review/test_corrections_review.py).
- `tests.integration_review.test_corrections_review.DuplicateHandling.test_DEFECT_LOW_a_merged_comment_never_silently_truncates_a_member_claim` — Merged comment length limits can silently cut a member claim. [Source](tests/integration_review/test_corrections_review.py).
- `tests.integration_review.test_integration_review.Evaluator.test_DEFECT_N7_replay_without_an_operator_supplied_digest_is_not_reported_as_pinned` — Replay without an operator-supplied manifest digest can still report itself as pinned. [Source](tests/integration_review/test_integration_review.py).

### Pilot planning, output paths and live gates

- `tests.pilot_review.test_repository_gate.Plan.test_NEW_authorization_claim_DEFECT_an_unproven_authorization_must_not_be_reported_as_covering_the_ceiling` — A refused/unproven plan can still claim authorization covers its profile and ceiling. [Source](tests/pilot_review/test_repository_gate.py).
- `tests.pilot_review.test_repository_gate.Plan.test_NEW_R1_plan_blind_spot_DEFECT_the_plan_must_warn_when_the_first_request_omits_excerpts_for_budget` — The plan does not warn that the first request omits excerpts for its context budget; this is a reporting gap, separate from citation enforcement. [Source](tests/pilot_review/test_repository_gate.py).
- `tests.pilot_review.test_s0b01c_review.PartialStatus.test_DEFECT_plan_reports_planned_when_the_dry_pipeline_refused_before_any_request` — A refused dry plan can report planned/success despite producing no first request. [Source](tests/pilot_review/test_s0b01c_review.py).
- `tests.pilot_review.test_s0b01c_review.ReplayAndOutputs.test_DEFECT_replay_outputs_survive_under_out` — Reported replay output paths do not survive beneath the requested output directory. [Source](tests/pilot_review/test_s0b01c_review.py).
- `tests.pilot_review.test_s0b01c_review.ReplayAndOutputs.test_DEFECT_summaries_symlink_cannot_write_outside_out` — A summaries-directory symlink can direct writes outside the requested output directory. [Source](tests/pilot_review/test_s0b01c_review.py).
- `tests.pilot_review.test_s0b01c_review.Hardening.test_HARDEN_live_requires_a_pins_baseline` — Live historical evaluation does not require a pins baseline (hardening request). [Source](tests/pilot_review/test_s0b01c_review.py).
- `tests.pilot_review.test_s0b01c_review.Hardening.test_HARDEN_live_refuses_an_empty_ledger_as_existing_state` — An empty ledger can be accepted as existing shared spending state (hardening request). [Source](tests/pilot_review/test_s0b01c_review.py).
- `tests.pilot_review.test_s0b01c_review.Hardening.test_CONDITION_live_role_timeouts_within_s0b01b_condition_2` — Live role timeout caps exceed the 120-second condition asserted by this test. [Source](tests/pilot_review/test_s0b01c_review.py).

### Positive-control source baseline

- `tests.positive_pilot_review.test_positive_gate.SourceFreeze.test_stray_pycache_or_pyc_in_the_fixture_is_not_hidden_from_the_baseline` — The positive-fixture baseline ignores pycache/pyc files that the snapshot manifest can include. [Source](tests/positive_pilot_review/test_positive_gate.py).

### Terra CLI path (fixed in TERRA-ARM-01; no longer expected failures)

Terra (provider `openai`, GPT Terra via the installed Codex CLI) is un-held behind the per-call isolation
`codex-isolated-home@2` (fresh CODEX_HOME, pinned model catalog, strict `-c` overrides, offline prompt-input and
loopback request-capture proofs in every live preflight). These three former expected failures now pass:

- `tests.runtime_review.test_codex_review.CodexReview.test_F6_unrecognised_event_types_must_fail_closed` — unknown CLI event types, item events without an item and malformed JSONL lines now abort the call as an isolation violation.
- `tests.runtime_review.test_codex_review.RunBounded.test_F8_detached_grandchild_holding_the_pipes_must_not_hang_run_bounded` — bounded execution uses non-blocking pipes and a selector, so a detached descendant holding the pipes no longer hangs it.
- `tests.runtime_review.test_s106a_review.CodexTurnsHeld.test_codex_duplicate_json_keys_are_invalid_not_last_wins` — CLI answers are parsed strictly; duplicate keys are invalid output, never last-key-wins.

### Repository tools

- `tests.tools_review.test_s104_omission_seam.Seam.test_NEW_F1b_DEFECT_omission_kinds_are_restricted_to_the_importers_fixed_vocabulary` — Omission-kind labels are not restricted to the importer vocabulary. [Source](tests/tools_review/test_s104_omission_seam.py).
- `tests.tools_review.test_s104_retrieval_gate.PagingOracle.test_NEW1_DEFECT_a_truncated_page_always_offers_a_parseable_cursor_or_says_it_cannot` — A truncated directory page can advertise an unparseable cursor without saying continuation is unavailable. [Source](tests/tools_review/test_s104_retrieval_gate.py).
- `tests.tools_review.test_tools_review.TR2Pins.test_NEW1_corpus_valid_all_added_pr_can_be_viewed` — An all-added-files historical PR lacks a base directory and is refused instead of exposing an empty base view. [Source](tests/tools_review/test_tools_review.py).

### Additional environment-dependent marker

There are **23 expectedFailure markers** in the published, discoverable test source. The additional ID is `tests.runtime_review.test_codex_review.IsolationBoundary.test_F1_tool_exposure_features_still_enabled_after_the_adapters_disable_list` ([source](tests/runtime_review/test_codex_review.py)). Its class skips when `codex` is not installed. Reconciling the source markers with the hosted totals identifies this conditional class skip as the extra marker; the hosted log reports aggregate results rather than individual test IDs. It is not counted among the 22 expected failures listed above. The test checks whether default-enabled tool-related CLI features remain outside the adapter disable list. It does not establish effective tool isolation. Local CLI availability can change skip/expected-failure counts. Tool isolation is established separately by the loopback request-capture proof (`reviewer/runtime/codex_capture.py`), which the remaining `tool_search_always_defer_mcp_tools` (a removed, non-disableable feature) does not affect.

## Local temporary-directory interference

Some local runs using the default `/tmp` have encountered a separate process's intermittent `/tmp/.git`, causing the repository importer to correctly reject temporary stores beneath it. Do not remove unknown host files or weaken the importer guard. Use a verified non-Git temporary root such as `TMPDIR=/var/tmp` when running these tests locally. The hosted clean-checkout suite above had no such error.

The suite verifies mechanics and known controls. Its green exit code does not measure review precision, recall, safety against all adversarial input, cost per review or competitive quality.
