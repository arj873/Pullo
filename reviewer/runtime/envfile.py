"""Host-only .env parsing for `openrouter_key`.

The file is data: no shell evaluation, no `export`, no interpolation, and only the one wanted key is kept.
The value lives in a `Secret` whose repr/str/pickle never show it. Model workers must never call this on
the real file; only the trusted host launcher does, at execution time."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

KEY_NAME = "openrouter_key"
MAX_ENV_BYTES = 64 << 10
_VALUE = re.compile(r"[\x21-\x7e]{16,512}")      # printable ASCII, no whitespace


class EnvFileError(ValueError):
    """The env file is unusable. Messages never contain file content."""


class Secret:
    __slots__ = ("_v",)

    def __init__(self, value: str):
        if not isinstance(value, str) or not _VALUE.fullmatch(value):
            raise EnvFileError("secret has an unacceptable shape")
        self._v = value

    def reveal(self) -> str:
        return self._v

    def scrub(self, text: str) -> str:
        """Remove this exact secret (and its Bearer form) from text that may be persisted."""
        return text.replace(self._v, "[REDACTED:runtime-key]") if isinstance(text, str) else text

    def __repr__(self):
        return "Secret(***)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("secrets cannot be pickled")

    def __copy__(self):
        raise TypeError("secrets cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("secrets cannot be copied")

    def __eq__(self, other):
        return self is other

    __hash__ = object.__hash__


def load_openrouter_key(path, *, forbidden_roots=()) -> Secret:
    """Parse `openrouter_key=<value>` (optionally quoted) from a 0600, owner-only regular file.
    Refuses symlinks, group/other-accessible files, other owners, oversized files, a path under any
    forbidden content root, a missing key or a duplicated key."""
    real = Path(os.path.realpath(path))
    for root in forbidden_roots:
        r = Path(os.path.realpath(root))
        if real == r or r in real.parents:
            raise EnvFileError("env file may not come from a content root")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise EnvFileError(f"cannot open env file: {e.strerror}") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise EnvFileError("env file is not a regular file")
        if st.st_mode & 0o077:
            raise EnvFileError("env file must not be accessible to group/other (chmod 600)")
        if st.st_uid != os.geteuid():
            raise EnvFileError("env file must be owned by the running user")
        data = f.read(MAX_ENV_BYTES + 1)
    if len(data) > MAX_ENV_BYTES:
        raise EnvFileError("env file too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise EnvFileError("env file is not UTF-8") from None
    found = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        name, _, value = s.partition("=")
        if name.strip() != KEY_NAME:
            continue
        if found is not None:
            raise EnvFileError("duplicate key in env file")
        v = value.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        found = v
    if found is None:
        raise EnvFileError(f"{KEY_NAME} not found")
    return Secret(found)
