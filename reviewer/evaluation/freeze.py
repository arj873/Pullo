"""Private frozen copy of a synthetic suite, validated before any case runs.

The scorer's identity helpers (`scripts_identity`, `synthetic_config_digest`) read files at call time. Running them
against the shared fixture tree would let a concurrent edit change the bytes between hashing and use. The
evaluator therefore copies the suite into its own output directory (regular files only, read-only), checks the
copy against the source, validates it under the real Plan/profile caps and from then on reads only the copy.
Labels in the copy are outside every snapshot root the engine is given, so they are never model-visible.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from reviewer.contracts.budget import effective_retry_limits
from reviewer.gateway.script import MAX_SCRIPT_BYTES
from reviewer.scoring import ScoringError
from reviewer.scoring.checks import check_protected, check_redaction_version
from reviewer.scoring.scripts import check_case_script
from reviewer.scoring.suite import Suite, check_isolation, load_suite, scripts_identity

from .errors import EvalError

MAX_FILES = 10_000
MAX_FILE_BYTES = 16 << 20


def _refuse_special(path: Path, st: os.stat_result) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise EvalError("suite", f"symlink in suite: {path}")
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise EvalError("suite", f"special file in suite: {path}")


def _read_regular(path: Path, limit: int) -> bytes:
    """Bytes of a regular, non-symlink file, at most `limit` bytes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as e:
        raise EvalError("suite", f"cannot open {path}: {e.strerror}") from None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise EvalError("suite", f"not a regular file: {path}")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise EvalError("suite", f"file too large: {path}")
    return data


def freeze_suite(src, dest) -> Path:
    """Copy the suite tree at `src` into the new directory `dest`; files become read-only."""
    src = Path(src)
    try:
        st = os.lstat(src)
    except OSError:
        raise EvalError("suite", f"suite directory {str(src)!r} does not exist") from None
    if not stat.S_ISDIR(st.st_mode):
        raise EvalError("suite", f"suite path {str(src)!r} is not a directory (or is a symlink)")
    dest = Path(dest)
    dest.mkdir()
    count = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel = Path(dirpath).relative_to(src)
        for name in sorted(dirnames + filenames):
            p = Path(dirpath) / name
            st = os.lstat(p)
            _refuse_special(p, st)
            count += 1
            if count > MAX_FILES:
                raise EvalError("suite", "suite has too many files")
            target = dest / rel / name
            if stat.S_ISDIR(st.st_mode):
                target.mkdir()
            else:
                data = _read_regular(p, MAX_FILE_BYTES)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
    return dest


def real_limits(profile: dict, plan: dict) -> dict[str, tuple[int, int]]:
    """{role: (retries, repairs)} that the gateway actually applies (min of run and role caps)."""
    return {role: effective_retry_limits(plan["budget"], r["caps"]) for role, r in profile["roles"].items()}


def load_frozen(src, frozen, profile: dict, plan: dict) -> Suite:
    """Load source and frozen copy, require equal identity, validate the copy. Returns the frozen Suite."""
    try:
        source = load_suite(Path(src))
        suite = load_suite(Path(frozen))
    except (ScoringError, ValueError, OSError) as e:
        raise EvalError("suite", f"suite does not load: {e}") from None
    if not suite.manifest["synthetic"]:
        raise EvalError("suite", "smoke evaluation needs a synthetic suite; real PRs stay unscored")
    if suite.digest is None or suite.digest != source.digest:
        raise EvalError("suite", "frozen copy does not match the source suite (dataset digest)")
    scripts_dir = Path(frozen) / "scripts"
    if not scripts_dir.is_dir() or scripts_dir.is_symlink():
        raise EvalError("suite", "suite has no scripts/ directory")
    named = {Path(c.script_path).name for c in suite.cases.values()}
    stray = sorted(set(os.listdir(scripts_dir)) - named)
    if stray:
        raise EvalError("suite", f"scripts/ holds files no case names: {stray[:5]}")
    try:
        if scripts_identity(suite) != scripts_identity(source):
            raise EvalError("suite", "frozen scripts differ from the source suite")
    except ScoringError as e:
        raise EvalError("suite", str(e)) from None
    limits = real_limits(profile, plan)
    problems: list[str] = []
    for name, step in (("isolation", lambda: check_isolation(suite)),
                       ("protected text", lambda: check_protected(suite)),
                       ("redaction version", lambda: check_redaction_version(suite)),
                       *((f"script {cid}", lambda cid=cid: check_case_script(suite, cid, limits=limits))
                         for cid in sorted(suite.cases))):
        try:
            problems += step()
        except (ScoringError, ValueError, OSError, TypeError) as e:
            problems.append(f"{name}: {type(e).__name__}: {e}")
    if problems:
        raise EvalError("suite", "suite check failed: " + "; ".join(problems[:10]))
    return suite


def script_bytes(suite: Suite, case_id: str, identity: list[list[str]]) -> bytes:
    """The case's script, read once, strictly by case id; its sha256 must equal the hashed identity entry."""
    case = suite.cases[case_id]
    want = dict(identity).get(case.script_path)
    if want is None:
        raise EvalError("suite", f"{case_id}: script missing from the hashed identity")
    data = _read_regular(suite.root / case.script_path, MAX_SCRIPT_BYTES)
    if hashlib.sha256(data).hexdigest() != want:
        raise EvalError("suite", f"{case_id}: script bytes changed after the identity was computed")
    return data
