"""Reviewer/scorer separation checks. The source store is never a reviewer root and reports never land in one."""

from __future__ import annotations

from pathlib import Path

from .errors import BenchmarkError


def _related(a: Path, b: Path) -> bool:
    return a == b or a in b.parents or b in a.parents


def assert_disjoint(path, protected, what: str) -> None:
    p = Path(path).resolve(strict=False)
    for r in protected:
        if _related(p, Path(r).resolve(strict=False)):
            raise BenchmarkError("boundary", f"{what} overlaps a protected root ({Path(r).name})")


def assert_reviewer_root(root, store_dirs) -> None:
    """A snapshot root may not be, contain or sit inside the scorer source store."""
    assert_disjoint(root, store_dirs, "snapshot root")


def assert_report_location(out, reviewer_roots, store_dirs) -> None:
    assert_disjoint(out, [*reviewer_roots, *store_dirs], "report path")


def assert_case_input(doc) -> None:
    """The real closed CaseInput contract is the gate: gold, labels or review text cannot be added to it."""
    from reviewer.contracts.schema import require
    require("CaseInput", doc)
