"""R-01 historical PR input preparation (public read-only GitHub GET, stdlib only).

Layout per case under fixtures/historical/<caseId>/:
  input/    reviewer-visible: pinned diff, changed-file text, optional context
  source/   collection metadata and merge outcome; never shown to the reviewer
"""
