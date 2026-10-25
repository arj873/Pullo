"""Dependency-free schema DSL.

Every wire document in Stage 0A is plain JSON. A schema here both validates a
document (returning path-addressed Issues) and exports JSON Schema 2020-12 so
non-Python tools can read the same contract. Cross-field rules that JSON Schema
cannot express are Invariants: executed here, listed under `x-invariants` in
the export.

`validate` never raises on untrusted input. Before any schema runs, the whole
document passes a bounded, iterative JSON-safety walk (depth, node count,
string/array size, string keys, encodable text, interoperable integers, finite
floats). Use `loads_strict` to parse untrusted text: it rejects duplicate keys
and NaN/Infinity literals.

Known divergences from the exported JSON Schema (also stated in the bundle):
- Python rejects integer-valued floats (1.0) where JSON Schema "integer" accepts them.
- Safety limits (nesting depth, node count), duplicate keys and lone surrogates
  cannot be expressed in JSON Schema; only Python enforces them.
- Patterns are written in the common subset of Python `re` and ECMA-262
  ([0-9] not \\d). Python uses fullmatch; the export anchors with ^(?:...)$.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

REGISTRY: dict[str, "Schema"] = {}

MAX_SAFE_INT = 2**53 - 1          # JSON numbers above this lose precision outside Python
MAX_DEPTH = 64
MAX_NODES = 1_000_000
MAX_STRING = 4_000_000            # characters
MAX_CONTAINER = 200_000           # items per array/object


@dataclass(frozen=True)
class Issue:
    path: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.code}: {self.message}"


class ContractViolation(ValueError):
    def __init__(self, name: str, issues: list[Issue]):
        self.name = name
        self.issues = issues
        shown = "; ".join(str(i) for i in issues[:5])
        more = f" (+{len(issues) - 5} more)" if len(issues) > 5 else ""
        super().__init__(f"{name}: {shown}{more}")


class ContractInputError(ValueError):
    """Untrusted text could not be parsed as strict JSON."""


def _encodable(s: str) -> bool:
    try:
        s.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def json_issues(doc: Any, path: str = "$") -> list[Issue]:
    """Bounded iterative check that `doc` is plain, interoperable JSON."""
    out: list[Issue] = []
    stack: list[tuple[Any, str, int]] = [(doc, path, 0)]
    nodes = 0
    while stack:
        v, p, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            out.append(Issue(path, "too-large", f"more than {MAX_NODES} JSON nodes"))
            break
        if depth > MAX_DEPTH:
            out.append(Issue(p, "too-deep", f"nesting deeper than {MAX_DEPTH}"))
            continue
        if v is None or isinstance(v, bool):
            continue
        if isinstance(v, int):
            if abs(v) > MAX_SAFE_INT:
                out.append(Issue(p, "int-range", "integer outside +/-(2**53-1)"))
        elif isinstance(v, float):
            if not math.isfinite(v):
                out.append(Issue(p, "non-finite", "NaN/Infinity are not JSON"))
        elif isinstance(v, str):
            if len(v) > MAX_STRING:
                out.append(Issue(p, "too-long", f"string longer than {MAX_STRING}"))
            elif not _encodable(v):
                out.append(Issue(p, "encoding", "string is not valid UTF-8 (lone surrogate)"))
        elif isinstance(v, list):
            if len(v) > MAX_CONTAINER:
                out.append(Issue(p, "too-large", f"array longer than {MAX_CONTAINER}"))
                continue
            stack.extend((x, f"{p}[{i}]", depth + 1) for i, x in enumerate(v))
        elif isinstance(v, dict):
            if len(v) > MAX_CONTAINER:
                out.append(Issue(p, "too-large", f"object larger than {MAX_CONTAINER}"))
                continue
            for k, x in v.items():
                if not isinstance(k, str):
                    out.append(Issue(p, "key-type", f"non-string key {k!r}"))
                    continue
                if not _encodable(k):
                    out.append(Issue(p, "encoding", "key is not valid UTF-8"))
                    continue
                stack.append((x, f"{p}.{k}", depth + 1))
        else:
            out.append(Issue(p, "type", f"not JSON: {type(v).__name__}"))
    return out


def loads_strict(text: str | bytes) -> Any:
    """Parse untrusted JSON: duplicate keys, NaN/Infinity and unsafe values are errors."""

    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ContractInputError(f"duplicate key {k!r}")
            d[k] = v
        return d

    def constant(name):
        raise ContractInputError(f"{name} is not JSON")

    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        doc = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except ContractInputError:
        raise
    except (ValueError, RecursionError) as e:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise ContractInputError(f"invalid JSON: {str(e)[:200]}") from None
    issues = json_issues(doc)
    if issues:
        raise ContractInputError("; ".join(str(i) for i in issues[:3]))
    return doc


class Schema:
    description: str | None = None

    def check(self, v: Any, path: str, out: list[Issue]) -> None:
        raise NotImplementedError

    def to_json(self) -> dict:
        raise NotImplementedError

    def _doc(self, d: dict) -> dict:
        if self.description:
            d["description"] = self.description
        return d

    def describe(self, text: str) -> "Schema":
        self.description = text
        return self


class Str(Schema):
    def __init__(self, min_len: int = 0, max_len: int | None = None, pattern: str | None = None):
        self.min_len, self.max_len, self.pattern = min_len, max_len, pattern
        self._re = re.compile(pattern) if pattern else None

    def check(self, v, path, out):
        if not isinstance(v, str):
            out.append(Issue(path, "type", "expected string"))
            return
        if not _encodable(v):
            out.append(Issue(path, "encoding", "string is not valid UTF-8 (lone surrogate)"))
            return
        if len(v) < self.min_len:
            out.append(Issue(path, "min-length", f"shorter than {self.min_len}"))
        if self.max_len is not None and len(v) > self.max_len:
            out.append(Issue(path, "max-length", f"longer than {self.max_len}"))
        if self._re and not self._re.fullmatch(v):
            out.append(Issue(path, "pattern", f"does not match {self.pattern}"))

    def to_json(self):
        d: dict = {"type": "string"}
        if self.min_len:
            d["minLength"] = self.min_len
        if self.max_len is not None:
            d["maxLength"] = self.max_len
        if self.pattern:
            d["pattern"] = f"^(?:{self.pattern})$"
        return self._doc(d)


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class RelPath(Schema):
    """Repo-relative POSIX path: no leading '/', no '.'/'..'/empty segments, no '\\' or control chars."""

    def check(self, v, path, out):
        if not isinstance(v, str):
            out.append(Issue(path, "type", "expected string"))
            return
        if not is_safe_relpath(v):
            out.append(Issue(path, "unsafe-path", f"not a safe repo-relative path: {v!r}"))

    def to_json(self):
        return self._doc({
            "type": "string", "minLength": 1, "maxLength": 1024,
            "pattern": r"^(?!/)(?![\s\S]*\\)(?![\s\S]*[\x00-\x1f\x7f])"
                       r"(?!(?:[\s\S]*/)?\.{1,2}(?:/|$))(?![\s\S]*//)(?![\s\S]*/$).+$",
        })


def is_safe_relpath(p: str) -> bool:
    if not isinstance(p, str) or not p or len(p) > 1024 or p.startswith("/") or "\\" in p:
        return False
    if _CONTROL.search(p) or not _encodable(p):
        return False
    return all(seg not in ("", ".", "..") for seg in p.split("/"))


class Enum(Schema):
    def __init__(self, *values: str):
        self.values = values

    def check(self, v, path, out):
        if not isinstance(v, str) or v not in self.values:
            out.append(Issue(path, "enum", f"{v!r} not in {list(self.values)}"))

    def to_json(self):
        return self._doc({"enum": list(self.values)})


class Const(Schema):
    def __init__(self, value: Any):
        self.value = value

    def check(self, v, path, out):
        if type(v) is not type(self.value) or v != self.value:
            out.append(Issue(path, "const", f"expected {self.value!r}"))

    def to_json(self):
        return self._doc({"const": self.value})


class Int(Schema):
    """Integer within +/-(2**53-1) unless narrower bounds are given."""

    def __init__(self, minimum: int | None = None, maximum: int | None = None):
        self.minimum = -MAX_SAFE_INT if minimum is None else minimum
        self.maximum = MAX_SAFE_INT if maximum is None else maximum

    def check(self, v, path, out):
        if not isinstance(v, int) or isinstance(v, bool):
            out.append(Issue(path, "type", "expected integer"))
            return
        if v < self.minimum:
            out.append(Issue(path, "minimum", f"{v} < {self.minimum}"))
        if v > self.maximum:
            out.append(Issue(path, "maximum", f"{v} > {self.maximum}"))

    def to_json(self):
        return self._doc({"type": "integer", "minimum": self.minimum, "maximum": self.maximum})


class Num(Schema):
    def __init__(self, minimum: float | None = None, maximum: float | None = None):
        self.minimum, self.maximum = minimum, maximum

    def check(self, v, path, out):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            out.append(Issue(path, "type", "expected number"))
            return
        if isinstance(v, int) and abs(v) > MAX_SAFE_INT:
            out.append(Issue(path, "int-range", "integer outside +/-(2**53-1)"))
            return
        if isinstance(v, float) and not math.isfinite(v):
            out.append(Issue(path, "type", "expected finite number"))
            return
        if self.minimum is not None and v < self.minimum:
            out.append(Issue(path, "minimum", f"{v} < {self.minimum}"))
        if self.maximum is not None and v > self.maximum:
            out.append(Issue(path, "maximum", f"{v} > {self.maximum}"))

    def to_json(self):
        d: dict = {"type": "number"}
        if self.minimum is not None:
            d["minimum"] = self.minimum
        if self.maximum is not None:
            d["maximum"] = self.maximum
        return self._doc(d)


class Bool(Schema):
    def check(self, v, path, out):
        if not isinstance(v, bool):
            out.append(Issue(path, "type", "expected boolean"))

    def to_json(self):
        return self._doc({"type": "boolean"})


class Json(Schema):
    """Any plain JSON value. Opaque: never interpreted or stripped by contract helpers."""

    def check(self, v, path, out):
        out.extend(json_issues(v, path))

    def to_json(self):
        return self._doc({})


class Nullable(Schema):
    def __init__(self, inner: Schema):
        self.inner = inner

    def check(self, v, path, out):
        if v is not None:
            self.inner.check(v, path, out)

    def to_json(self):
        return self._doc({"anyOf": [{"type": "null"}, self.inner.to_json()]})


class Arr(Schema):
    def __init__(self, item: Schema, min_items: int = 0, max_items: int | None = None,
                 unique: bool = False):
        self.item, self.min_items, self.max_items, self.unique = item, min_items, max_items, unique

    def check(self, v, path, out):
        if not isinstance(v, list):
            out.append(Issue(path, "type", "expected array"))
            return
        if len(v) < self.min_items:
            out.append(Issue(path, "min-items", f"fewer than {self.min_items}"))
        if self.max_items is not None and len(v) > self.max_items:
            out.append(Issue(path, "max-items", f"more than {self.max_items}"))
            return
        for i, x in enumerate(v):
            self.item.check(x, f"{path}[{i}]", out)
        if self.unique:
            seen = [json.dumps(x, sort_keys=True, default=repr) for x in v]
            if len(set(seen)) != len(seen):
                out.append(Issue(path, "unique", "duplicate items"))

    def to_json(self):
        d: dict = {"type": "array", "items": self.item.to_json()}
        if self.min_items:
            d["minItems"] = self.min_items
        if self.max_items is not None:
            d["maxItems"] = self.max_items
        if self.unique:
            d["uniqueItems"] = True
        return self._doc(d)


@dataclass(frozen=True)
class Invariant:
    id: str
    text: str
    fn: Callable[[dict], Iterable[tuple[str, str]]]  # yields (relative path, message)


@dataclass
class Obj(Schema):
    """Closed object: unknown keys are errors (this is what keeps labels out of inputs)."""

    required: dict[str, Schema]
    optional: dict[str, Schema] = field(default_factory=dict)
    invariants: list[Invariant] = field(default_factory=list)
    description: str | None = None

    def check(self, v, path, out):
        if not isinstance(v, dict):
            out.append(Issue(path, "type", "expected object"))
            return
        before = len(out)
        for k, s in self.required.items():
            if k not in v:
                out.append(Issue(f"{path}.{k}", "required", "missing"))
            else:
                s.check(v[k], f"{path}.{k}", out)
        for k, s in self.optional.items():
            if k in v:
                s.check(v[k], f"{path}.{k}", out)
        for k in v:
            if k not in self.required and k not in self.optional:
                out.append(Issue(f"{path}.{k!s}", "unknown-field", "not allowed"))
        if len(out) == before:  # invariants assume structural validity
            for inv in self.invariants:
                try:
                    for rel, msg in inv.fn(v):
                        out.append(Issue(f"{path}{rel}", inv.id, msg))
                except Exception as e:  # noqa: BLE001 - an invariant bug must not crash validation
                    out.append(Issue(path, inv.id, f"invariant could not be evaluated: {e!r}"))

    def to_json(self):
        props = {k: s.to_json() for k, s in {**self.required, **self.optional}.items()}
        d: dict = {"type": "object", "properties": props,
                   "required": list(self.required), "additionalProperties": False}
        if self.invariants:
            d["x-invariants"] = [f"{i.id}: {i.text}" for i in self.invariants]
        return self._doc(d)


class Union(Schema):
    """Tagged union on a string discriminator field."""

    def __init__(self, tag: str, variants: dict[str, Schema]):
        self.tag, self.variants = tag, variants

    def check(self, v, path, out):
        if not isinstance(v, dict):
            out.append(Issue(path, "type", "expected object"))
            return
        t = v.get(self.tag)
        if not isinstance(t, str) or t not in self.variants:
            out.append(Issue(f"{path}.{self.tag}", "enum",
                             f"{str(t)[:80]!r} not in {list(self.variants)}"))
            return
        self.variants[t].check(v, path, out)

    def to_json(self):
        return self._doc({"oneOf": [s.to_json() for s in self.variants.values()]})


class Ref(Schema):
    def __init__(self, name: str):
        self.name = name

    def check(self, v, path, out):
        REGISTRY[self.name].check(v, path, out)

    def to_json(self):
        return {"$ref": f"#/$defs/{self.name}"}


def define(name: str, schema: Schema) -> Ref:
    if name in REGISTRY:
        raise KeyError(f"schema {name} already defined")
    REGISTRY[name] = schema
    return Ref(name)


def validate(name: str, doc: Any) -> list[Issue]:
    """Never raises for document content; unknown entity names raise KeyError."""
    schema = REGISTRY[name]
    out = json_issues(doc)
    if out:
        return out
    try:
        schema.check(doc, "$", out)
    except Exception as e:  # noqa: BLE001
        out.append(Issue("$", "internal-validator-error", repr(e)[:200]))
    return out


def require(name: str, doc: Any) -> Any:
    """Return doc unchanged if valid, else raise ContractViolation."""
    issues = validate(name, doc)
    if issues:
        raise ContractViolation(name, issues)
    return doc


BUNDLE_DESCRIPTION = (
    "Generated from reviewer/contracts/entities.py; do not edit by hand. The Python validator "
    "is authoritative and stricter than this bundle: (1) x-invariants (cross-field rules) are "
    "enforced only in Python; (2) Python rejects integer-valued floats such as 1.0 where JSON "
    "Schema 'integer' accepts them; (3) nesting depth (64), node/size limits, duplicate keys "
    "and lone surrogates cannot be expressed here; use reviewer.contracts.loads_strict; "
    "(4) every pattern uses the Python/ECMA-262 common subset ([0-9], no \\d) and is anchored "
    "with ^(?:...)$, while Python uses fullmatch. Canonical hashes are recomputed only by "
    "Python (see canonical.py).")


def export_bundle(version: str) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"reviewer-contracts-{version}",
        "title": "Reviewer Stage 0A contracts",
        "description": BUNDLE_DESCRIPTION,
        "$defs": {name: REGISTRY[name].to_json() for name in sorted(REGISTRY)},
    }
