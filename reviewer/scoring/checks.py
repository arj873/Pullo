"""`python3 -m reviewer.scoring check`: every suite-level check, reported as problems (never a traceback)."""

from __future__ import annotations

from pathlib import Path

from reviewer.contracts.redaction import REDACTION_VERSION, contains_protected

from .errors import ScoringError
from .scripts import check_case_script
from .suite import Suite, _real, check_isolation

_EXPECTED = (ScoringError, ValueError, OSError)   # ContractInputError is a ValueError


def _files(suite: Suite) -> list[str]:
    """Every suite file the reviewer or its scripted provider can see, plus the scorer's own."""
    rels = ["suite.json"]
    for case in suite.cases.values():
        rels += [case.input_path, case.script_path]
        if case.labels is not None:
            rels.append(case.labels_path)
        for side, man in (("base", case.base_manifest), ("head", case.head_manifest)):
            rels += [f"{case.input[side]['root']}/{e['path']}" for e in man["entries"]]
    return rels


def check_protected(suite: Suite) -> list[str]:
    """Problems for any suite file that still matches a protected-secret pattern (the corpus loader
    rescans every blob; a regenerated suite must not be able to skip that)."""
    problems = []
    for rel in _files(suite):
        p = _real(suite.root, rel)
        if p.is_file() and contains_protected(p.read_text(encoding="utf-8", errors="replace")):
            problems.append(f"{rel}: contains protected text ({REDACTION_VERSION})")
    return problems


def check_redaction_version(suite: Suite) -> list[str]:
    """A synthetic suite's description records the redaction version its excerpts were validated
    under (the manifest has no dedicated key). A bump forces a regeneration and review."""
    if suite.manifest["synthetic"] and REDACTION_VERSION not in suite.manifest["description"]:
        return [f"suite.json: description does not record {REDACTION_VERSION}; regenerate and re-review"]
    return []


def check_suite(suite: Suite) -> list[str]:
    problems: list[str] = []
    steps = [("isolation", lambda: check_isolation(suite)),
             ("protected text", lambda: check_protected(suite)),
             ("redaction version", lambda: check_redaction_version(suite))]
    steps += [(f"script {cid}", lambda cid=cid: check_case_script(suite, cid)) for cid in suite.cases]
    for name, step in steps:
        try:
            problems += step()
        except _EXPECTED as e:
            problems.append(f"{name}: {type(e).__name__}: {e}")
    return problems
