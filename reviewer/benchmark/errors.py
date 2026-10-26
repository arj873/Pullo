"""Typed refusal for the benchmark package. `code` is stable; `message` is for people."""

from __future__ import annotations


class BenchmarkError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message
