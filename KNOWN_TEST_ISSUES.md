# Known test issues at the public checkpoint

Run the offline suite with `nice -n 19 python3 -B -m unittest discover -s tests -t .` from a clean checkout. It uses no credentials or network. [Hosted CI for PR #9](https://github.com/arj873/Pullo/actions/runs/40306956738) completed on 2026-10-26: **2,401 tests, OK, 30 skipped, 22 expected failures, zero errors or unexpected failures**. This is the completed full run after the startup-cleanup PR. A later provenance change is under review and is not included in these counts.

## Skips

The public repository excludes raw third-party historical pull-request fixtures and private operator reconciliation evidence. Tests that require them are marked with explicit `skipUnless` checks; the hosted run reported 30 skips. Static historical import-boundary gauges now run without that corpus. Permission-sensitive tests can also skip when the runner's privileges make the permission probe meaningless. Skips are not evidence that those behaviours passed on the public checkout.

## Expected failures

Twenty-two tests remain marked `expectedFailure` for disclosed, unresolved defects or safety conditions. They are part of the default suite and produce a non-failing result while still pinning their intended behaviour. Examples include Terra CLI isolation/parser issues, a gateway trusted-object edge case, and benchmark input/scoring gates. Search `rg -n 'expectedFailure' tests` for the markers and read their companion handoffs for scope. An unexpected success should prompt marker removal and an independent regression review.

## Local temporary-directory interference

Some local runs using the default `/tmp` have encountered a separate process's intermittent `/tmp/.git`, causing the repository importer to correctly reject temporary stores beneath it. Do not remove unknown host files or weaken the importer guard. Use a verified non-Git temporary root such as `TMPDIR=/var/tmp` when running these tests locally. The hosted clean-checkout suite above had no such error.

The suite verifies mechanics and known controls. Its green exit code is not a measurement of review precision, recall, safety against all adversarial input, cost per review or competitive quality.
