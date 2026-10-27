"""SCORE-HOST-02 independent gate helpers. Candidate tree = SCORE_HOST_SRC (explicit) else this checkout root.
Offline: invented sentinels, fake transport, scratch ledger/book/auth. Reuses the author's read-only fixture builder `Env`."""
import os
import sys
from pathlib import Path

SRC = os.environ.get("SCORE_HOST_SRC") or str(Path(__file__).resolve().parents[2])
sys.path.insert(0, SRC)
sys.dont_write_bytecode = True
import tests  # noqa: E402
if str(Path(SRC) / "tests") not in tests.__path__:
    tests.__path__.append(str(Path(SRC) / "tests"))
from reviewer import score_host as S                                    # noqa: E402
assert Path(S.__file__).resolve().is_relative_to(Path(SRC).resolve()), "host imported from outside the candidate tree"
from tests.score_host.test_score_host import (CFG, EVR, EVR2, KEY, OPUS, SCOPE, SENT, URL, Env, make_case)  # noqa: E402,F401
ROOT = Path(SRC)
