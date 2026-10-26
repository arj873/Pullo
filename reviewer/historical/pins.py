"""Trusted bridge pins: captured once from a known-good case at import/audit time, stored OUTSIDE the corpus.

A `historical-bridge-pins@1` document wraps the tools' `historical-view-pins@1` (layer manifests plus the
case.json/context.json digests) with the PR origin, the capture time (`capturedAt`, the as-of of these inputs)
and optional host-supplied PR text. Review-time code only loads and checks pins; it never captures them.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from reviewer.contracts.canonical import canonical_json
from reviewer.contracts.redaction import contains_protected, redact
from reviewer.corpus.inputs import load_reviewer_input
from reviewer.tools import ViewError, capture_historical_pins, historical_input_view

PINS_SCHEMA = "historical-bridge-pins@1"
VIEW_PINS_SCHEMA = "historical-view-pins@1"
PINS_MAX_BYTES = 64 << 20
TITLE_MAX, BODY_MAX = 500, 20_000          # CaseInput.pr limits
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_SHA = re.compile(r"[0-9a-f]{40}")
_CASE_ID = re.compile(r"([A-Za-z0-9._-]+)--([A-Za-z0-9._-]+)--([1-9][0-9]{0,9})")
_PR_KEYS = {"title", "body", "asOf", "redactions"}
_MAX_DEPTH = 32                            # real pins nest about 6 deep


class BridgeError(ValueError):
    pass


def origin_of(case: dict) -> dict:
    """Original PR identity of a corpus case.json document."""
    m = _CASE_ID.fullmatch(case["id"])
    if m is None:
        raise BridgeError("case id is not <owner>--<repo>--<pr number>")
    return {"repo": case["repo"], "prNumber": int(m.group(3)), "baseSha": case["base"]["sha"],
            "mergeBase": case["base"]["mergeBase"], "textRef": case["base"]["textRef"], "headSha": case["head"]["sha"]}


def _pr_text(pr_text, captured_at: str):
    """Host-supplied PR title/body (e.g. as fetched at import). Protected text is redacted here, once."""
    if pr_text is None:
        return None
    if not isinstance(pr_text, dict) or set(pr_text) - {"title", "body", "asOf"} or \
            not isinstance(pr_text.get("title"), str) or not isinstance(pr_text.get("body"), str):
        raise BridgeError("pr_text must be {title: str, body: str, asOf?: timestamp}")
    as_of = pr_text.get("asOf", captured_at)
    if not isinstance(as_of, str) or not _TS.fullmatch(as_of):
        raise BridgeError("pr_text.asOf must be YYYY-MM-DDTHH:MM:SSZ")
    title, tc = redact(pr_text["title"])
    body, bc = redact(pr_text["body"])
    if len(title) > TITLE_MAX or len(body) > BODY_MAX:
        raise BridgeError(f"PR title/body exceed {TITLE_MAX}/{BODY_MAX} characters; truncate explicitly before capture")
    counts = dict(tc)
    for k, n in bc.items():
        counts[k] = counts.get(k, 0) + n
    return {"title": title, "body": body, "asOf": as_of, "redactions": dict(sorted(counts.items()))}


def capture_bridge_pins(case_dir, *, captured_at: str, pr_text=None) -> dict:
    """TRUSTED TIME ONLY: run on a case directory known to be good (right after a reviewed import), then
    store the result outside the corpus with `write_pins`. Calling this on the directory you are about to
    review and passing the result straight to `materialize` proves nothing: it pins whatever is on disk."""
    if not isinstance(captured_at, str) or not _TS.fullmatch(captured_at):
        raise BridgeError("captured_at must be YYYY-MM-DDTHH:MM:SSZ")
    case_dir = Path(case_dir)
    try:
        view_pins = capture_historical_pins(case_dir)
        case = load_reviewer_input(case_dir)["case"]
        historical_input_view(case_dir, pins=view_pins)      # the directory still equals what was pinned
    except ViewError as e:
        raise BridgeError(f"case is not a valid trusted input: {e}") from None
    except Exception as e:  # noqa: BLE001 - loader errors fail closed
        raise BridgeError(f"case is not a valid trusted input ({type(e).__name__})") from None
    return check_pins({"schema": PINS_SCHEMA, "caseId": case_dir.name, "capturedAt": captured_at,
                       "origin": origin_of(case), "view": view_pins, "prText": _pr_text(pr_text, captured_at)})


def _plain(v, depth: int = 0):
    """A plain-data snapshot of JSON-shaped input, taken ONCE: dict/list subclasses are read through the
    base type (an overridden __getitem__ cannot answer differently later), scalars must be exact
    str/int/float/bool/None, and strings must be UTF-8 encodable (no lone surrogates)."""
    if depth > _MAX_DEPTH:
        raise BridgeError("pins nest too deeply")
    if isinstance(v, dict):
        out = {}
        for k, x in dict.items(v):
            if type(k) is not str:
                raise BridgeError("pins are malformed")
            out[_plain(k, depth)] = _plain(x, depth + 1)
        return out
    if isinstance(v, (list, tuple)):
        return [_plain(x, depth + 1) for x in (list.__iter__(v) if isinstance(v, list) else tuple.__iter__(v))]
    if type(v) is str:
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            raise BridgeError("pins hold a string that is not valid UTF-8 (lone surrogate)") from None
        return v
    if v is None or type(v) in (bool, int, float):     # wrong-typed numbers are refused by the shape checks
        return v
    raise BridgeError("pins are malformed")


def check_pins(pins) -> dict:
    """Closed-shape check of a bridge pins document. A plain-data private snapshot is taken first and
    that snapshot is validated and returned, so later changes to (or tricks of) the caller's object
    cannot reach it. The embedded view pins are checked in depth by `historical_input_view` itself."""
    try:
        pins = _plain(pins)
        if not isinstance(pins, dict) or set(pins) != {"schema", "caseId", "capturedAt", "origin", "view", "prText"} \
                or pins["schema"] != PINS_SCHEMA or not isinstance(pins["caseId"], str) \
                or not _CASE_ID.fullmatch(pins["caseId"]) \
                or not isinstance(pins["capturedAt"], str) or not _TS.fullmatch(pins["capturedAt"]):
            raise BridgeError("not a historical-bridge-pins@1 document")
        o = pins["origin"]
        if not isinstance(o, dict) or set(o) != {"repo", "prNumber", "baseSha", "mergeBase", "textRef", "headSha"} \
                or not isinstance(o["repo"], str) or type(o["prNumber"]) is not int \
                or o["prNumber"] != int(_CASE_ID.fullmatch(pins["caseId"]).group(3)) \
                or not all(isinstance(o[k], str) and _SHA.fullmatch(o[k]) for k in ("baseSha", "textRef", "headSha")) \
                or not (o["mergeBase"] is None or (isinstance(o["mergeBase"], str) and _SHA.fullmatch(o["mergeBase"]))) \
                or o["textRef"] != (o["mergeBase"] or o["baseSha"]):
            raise BridgeError("pins.origin is malformed or inconsistent")
        v = pins["view"]
        if not isinstance(v, dict) or v.get("schema") != VIEW_PINS_SCHEMA or v.get("caseId") != pins["caseId"]:
            raise BridgeError("pins.view is not historical-view-pins@1 for this case")
        p = pins["prText"]
        if p is not None:
            if not isinstance(p, dict) or set(p) != _PR_KEYS or not isinstance(p["title"], str) \
                    or not isinstance(p["body"], str) or len(p["title"]) > TITLE_MAX or len(p["body"]) > BODY_MAX \
                    or not isinstance(p["asOf"], str) or not _TS.fullmatch(p["asOf"]) \
                    or not isinstance(p["redactions"], dict) \
                    or not all(isinstance(k, str) and type(n) is int and n > 0 for k, n in p["redactions"].items()):
                raise BridgeError("pins.prText is malformed")
            if contains_protected(p["title"]) or contains_protected(p["body"]):
                raise BridgeError("pins.prText contains protected text (not redacted at capture)")
        return pins
    except BridgeError:
        raise
    except Exception:  # noqa: BLE001
        raise BridgeError("pins are malformed") from None


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def write_pins(path, pins) -> None:
    """Write pins as canonical JSON with exclusive create (never overwrites); the file is made read-only."""
    data = canonical_json(check_pins(pins))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        raise BridgeError(f"cannot create pins file: {e.strerror}") from None
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.fchmod(fd, 0o444)
    except OSError as e:
        raise BridgeError(f"cannot write pins file: {e.strerror}") from None
    finally:
        os.close(fd)


def read_nofollow(path, cap: int) -> bytes:
    """Bytes of a regular, non-link file of at most `cap` bytes. Never blocks on a FIFO."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise BridgeError(f"{Path(path).name} cannot be opened as a regular file") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap:
            raise BridgeError(f"{Path(path).name} is not a regular file within {cap} bytes")
        chunks, got = [], 0
        while got <= cap and (chunk := os.read(fd, min(1 << 16, cap + 1 - got))):
            chunks.append(chunk)
            got += len(chunk)
        if got > cap:
            raise BridgeError(f"{Path(path).name} grew past {cap} bytes")
        return b"".join(chunks)
    except OSError as e:
        raise BridgeError(f"{Path(path).name} cannot be read: {e.strerror}") from None
    finally:
        os.close(fd)


def load_pins(path, *, case_dir) -> dict:
    """Load externally stored pins for `case_dir`. A pin file inside the case directory is refused: it
    would be under the control of whoever controls the reviewed input."""
    p, case = Path(os.path.realpath(path)), Path(os.path.realpath(case_dir))
    if _inside(p, case):
        raise BridgeError("pins must be stored outside the case directory")
    try:
        pins = json.loads(read_nofollow(path, PINS_MAX_BYTES))
    except BridgeError:
        raise
    except (ValueError, RecursionError):
        raise BridgeError("pins file is not JSON (or nests too deeply)") from None
    pins = check_pins(pins)
    if pins["caseId"] != Path(case_dir).name:
        raise BridgeError("pins are for a different case")
    return pins
