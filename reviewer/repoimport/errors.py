"""Typed refusals of the repository importer."""

from __future__ import annotations

CODES = frozenset({
    "bad-input", "bad-url", "bad-commit", "bad-store", "store-exists", "fetch-failed", "unreproducible",
    "git-failed", "timeout", "too-large", "identity-mismatch", "malformed-object", "incomplete-store",
    "relates-mismatch", "tamper", "bad-pins", "internal",
})


class RepoImportError(ValueError):
    def __init__(self, code: str, message: str):
        assert code in CODES, code
        super().__init__(f"{code}: {message}")
        self.code = code
        self.detail = message
