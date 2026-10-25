"""Trusted SpendAuthorization handling and the cross-run spend book.

An authorization is accepted only as an `AuthorizationHandle`, which only `trusted_authorization`
can mint: it reads an operator-controlled file and refuses any path inside a content root
(repo, case, snapshot, fixtures). Nothing read from a request, script, trace, case or model
output can create one.

`SpendBook` enforces maxUsdMicrosTotal across runs (and processes, with a store file). It is
conservative: an open reservation left by a crash stays charged.
"""

from __future__ import annotations

import copy
import datetime as dt
import fcntl
import json
import os
import re
import threading
from pathlib import Path

from reviewer.contracts import ContractInputError, ContractViolation, loads_strict, require
from reviewer.contracts.budget import authorization_digest, release_allowed

from .errors import AuthorizationError, typed_error

_TOKEN = object()
_TS = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z")
MAX_AUTH_BYTES = 64 << 10
MAX_BOOK_BYTES = 32 << 20


def parse_ts(text) -> dt.datetime:
    """Strict UTC timestamp (the contract's Timestamp shape) -> aware datetime; ValueError otherwise."""
    m = _TS.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise ValueError(f"not a UTC timestamp: {str(text)[:40]!r}")
    frac = (m.group(2) or "").ljust(6, "0")[:6]
    return dt.datetime.fromisoformat(m.group(1)).replace(microsecond=int(frac or 0), tzinfo=dt.timezone.utc)


class AuthorizationHandle:
    """Opaque proof that an operator-issued authorization was loaded from trusted config."""
    __slots__ = ("_auth", "_digest")

    def __init__(self, token, auth: dict):
        if token is not _TOKEN:
            raise AuthorizationError("construct with trusted_authorization(); never from content")
        self._auth = copy.deepcopy(auth)
        self._digest = authorization_digest(auth)

    @property
    def auth(self) -> dict:
        return copy.deepcopy(self._auth)

    @property
    def digest(self) -> str:
        return self._digest

    def __repr__(self):
        return f"AuthorizationHandle({self._auth['id']})"

    def __reduce__(self):
        raise TypeError("authorization handles cannot be pickled or copied across trust boundaries")

    def __copy__(self):
        raise TypeError("authorization handles cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("authorization handles cannot be copied")


def trusted_authorization(path, *, forbidden_roots=()) -> AuthorizationHandle:
    """Load an operator-issued SpendAuthorization.

    `forbidden_roots`: directories holding untrusted content (repo checkouts, case inputs,
    snapshots, fixtures). A path inside any of them, or reached through a symlink into one,
    is refused. The file must be strict JSON and a valid SpendAuthorization."""
    p = Path(path)
    real = Path(os.path.realpath(p))
    for root in forbidden_roots:
        r = Path(os.path.realpath(root))
        if real == r or r in real.parents:
            raise AuthorizationError(f"authorization may not come from content root {r}")
    try:
        fd = os.open(real, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as e:
        raise AuthorizationError(f"cannot open authorization: {e.strerror}") from e
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_AUTH_BYTES + 1)
    if len(data) > MAX_AUTH_BYTES:
        raise AuthorizationError("authorization file too large")
    try:
        doc = require("SpendAuthorization", loads_strict(data))
    except (ContractInputError, ContractViolation) as e:
        raise AuthorizationError(f"invalid authorization: {e}") from e
    return AuthorizationHandle(_TOKEN, doc)


class SpendBook:
    """Total-budget accounting for one authorization across runs.

    reserve/settle/retain/release mirror contracts.budget.Ledger but against
    maxUsdMicrosTotal. With `store` (a file in operator-controlled space) the book is shared by
    every run and process using that file; without it, by every gateway holding this object."""

    def __init__(self, handle: AuthorizationHandle, store=None):
        if not isinstance(handle, AuthorizationHandle):
            raise AuthorizationError("SpendBook needs a trusted AuthorizationHandle")
        self.handle = handle
        self.limit = handle.auth["maxUsdMicrosTotal"]
        self._lock = threading.Lock()
        self._mem: list[dict] = []
        self.store = Path(store) if store is not None else None

    # -- state is a replay of an append-only operation list
    @staticmethod
    def _state(ops):
        open_, committed = {}, 0
        for op in ops:
            if op["op"] == "reserve":
                if op["key"] in open_:
                    raise ValueError(f"book corrupt: duplicate reservation {op['key']}")
                open_[op["key"]] = op["amount"]
            elif op["op"] == "close":
                if op["key"] not in open_:
                    raise ValueError(f"book corrupt: close of unknown reservation {op['key']}")
                del open_[op["key"]]
                committed += op["charge"]
            else:
                raise ValueError("book corrupt: unknown op")
        return open_, committed

    def _transact(self, fn):
        with self._lock:
            if self.store is None:
                ops = self._mem
                result, new = fn(*self._state(ops))
                ops.extend(new)
                return result
            fd = os.open(self.store, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                size = os.fstat(fd).st_size
                if size > MAX_BOOK_BYTES:
                    raise ValueError("spend book too large; refusing")
                raw = os.pread(fd, size, 0).decode("utf-8")
                mine = []
                for line in raw.splitlines():
                    op = json.loads(line)
                    if op.get("auth") == self.handle.digest:
                        mine.append(op)
                result, new = fn(*self._state(mine))
                if new:
                    blob = "".join(json.dumps({**o, "auth": self.handle.digest}, sort_keys=True) + "\n" for o in new)
                    os.write(fd, blob.encode("utf-8"))
                    os.fsync(fd)
                return result
            finally:
                os.close(fd)

    def totals(self) -> dict:
        def f(open_, committed):
            return {"committed": committed, "inflight": sum(open_.values()), "limit": self.limit}, []
        return self._transact(f)

    def reserve(self, key: str, amount: int) -> dict | None:
        """None when admitted; a budget-exhausted TypedError for the total ceiling otherwise."""
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            raise ValueError("amount must be a non-negative integer")

        def f(open_, committed):
            if key in open_:
                raise ValueError(f"reservation {key} already open")
            would = committed + sum(open_.values()) + amount
            if would > self.limit:
                return typed_error("budget-exhausted", "total authorized ceiling",
                                   detail={"scope": "total", "wouldReach": would, "limit": self.limit}), []
            return None, [{"op": "reserve", "key": key, "amount": amount}]
        return self._transact(f)

    def _close(self, key: str, charge) -> int:
        def f(open_, committed):
            if key not in open_:
                raise ValueError(f"reservation {key} not open")
            c = open_[key] if charge is None else charge
            return c, [{"op": "close", "key": key, "charge": c}]
        return self._transact(f)

    def settle(self, key: str, usd_micros: int) -> int:
        if not isinstance(usd_micros, int) or isinstance(usd_micros, bool) or usd_micros < 0:
            raise ValueError("usd_micros must be a non-negative integer")
        return self._close(key, usd_micros)

    def retain(self, key: str) -> int:
        return self._close(key, None)

    def release(self, key: str, outcome: str) -> None:
        if not release_allowed(outcome):
            raise ValueError(f"cannot release on outcome {outcome!r}; use retain()")
        self._close(key, 0)
