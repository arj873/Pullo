"""Provider-specific projections of the authoritative role schemas, plus local validation.

The Python contract validator is authoritative. A projection only guides the provider; unsupported
keywords are removed explicitly (never treated as enforced), and every output is re-validated locally."""

from __future__ import annotations

import copy
import json

from reviewer.contracts import SCORE_ROLE_SCHEMA, export_bundle, is_turn_schema, validate
from reviewer.contracts.entities import ROLE_SCHEMAS

PROJECTION_VERSION = "role-schema-projection@2"
_STRIP = frozenset({"minLength", "maxLength", "minimum", "maximum", "pattern", "uniqueItems", "minItems",
                    "maxItems", "maxProperties", "propertyNames", "x-invariants", "format"})
SCHEMA_NAMES = tuple(n for names in ROLE_SCHEMAS.values() for n in names)      # review family (legacy projections)
SCORE_SCHEMA_NAMES = tuple(SCORE_ROLE_SCHEMA.values())                            # score family: ScoreExtractionSegments/Dedup/Pair
ALL_SCHEMA_NAMES = SCHEMA_NAMES + SCORE_SCHEMA_NAMES
FAMILY_ROLE_SCHEMAS = {"review": dict(ROLE_SCHEMAS), "score": {r: (n,) for r, n in SCORE_ROLE_SCHEMA.items()}}
_DEFS = export_bundle("runtime")["$defs"]


def _inline(node, seen=()):
    if isinstance(node, list):
        return [_inline(x, seen) for x in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        name = node["$ref"].rsplit("/", 1)[-1]
        if name in seen:
            raise ValueError(f"recursive schema {name} cannot be projected")
        return _inline(_DEFS[name], seen + (name,))
    return {k: _inline(v, seen) for k, v in node.items()}


def select_schema(request, family: str = "review") -> str | None:
    """The schema a request asks for: request.outputSchema, legal only for its role in `family` (default review:
    ROLE_SCHEMAS; "score": SCORE_ROLE_SCHEMA). Never coerced; a role of the other family yields None."""
    if not isinstance(request, dict) or family not in FAMILY_ROLE_SCHEMAS:
        return None
    role, name = request.get("role"), request.get("outputSchema")
    return name if isinstance(role, str) and isinstance(name, str) and name in FAMILY_ROLE_SCHEMAS[family].get(role, ()) else None


def request_family(request) -> str | None:
    """'score' / 'review' from the request ROLE (never from params); None for a role of neither family."""
    role = request.get("role") if isinstance(request, dict) else None
    if not isinstance(role, str):
        return None
    return "score" if role in FAMILY_ROLE_SCHEMAS["score"] else "review" if role in FAMILY_ROLE_SCHEMAS["review"] else None


def _is_map(node) -> bool:
    return isinstance(node, dict) and node.get("type") == "object" and isinstance(node.get("additionalProperties"), dict) \
        and "propertyNames" in node


def original(output_schema: str) -> dict:
    """The authoritative role schema with $refs inlined (still carries every constraint)."""
    if output_schema not in ALL_SCHEMA_NAMES:
        raise KeyError(output_schema)
    return _inline(_DEFS[output_schema])


def _project(node, flavor):
    if isinstance(node, list):
        return [_project(x, flavor) for x in node]
    if not isinstance(node, dict):
        return node
    if _is_map(node):    # open object (contracts Map): strict providers reject it, so it travels as key/value entries
        pat = node["propertyNames"].get("pattern", "")
        return {"type": "array", "items": {
            "type": "object", "required": ["key", "value"], "additionalProperties": False,
            "properties": {"key": {"type": "string", "description": f"must match {pat}" if pat else "object key"},
                           "value": _project(node["additionalProperties"], flavor)}},
            **({"description": node["description"]} if "description" in node else {})}
    out = {}
    for k, v in node.items():
        if k in _STRIP:
            continue
        if k == "properties":
            out[k] = {pk: _project(pv, flavor) for pk, pv in v.items()}
        elif k == "oneOf":
            out["anyOf"] = _project(v, flavor)
        elif k == "const":
            out["enum"] = [v]
        else:
            out[k] = _project(v, flavor)
    if flavor == "openai-strict" and "properties" in out:
        req = set(out.get("required", []))
        for pk in list(out["properties"]):
            if pk not in req:
                out["properties"][pk] = {"anyOf": [out["properties"][pk], {"type": "null"}]}
        out["required"] = list(out["properties"])
    return out


def provider_schema(output_schema: str, flavor: str) -> dict:
    """flavor: 'anthropic' (optional keys stay optional) or 'openai-strict' (every key required, optional
    ones nullable; `normalize_output` drops those nulls before local validation)."""
    if flavor not in ("anthropic", "openai-strict"):
        raise ValueError(flavor)
    return _project(original(output_schema), flavor)


def _entries_to_map(value):
    """[{key, value}, ...] -> dict, or the list unchanged when malformed/duplicated so local validation rejects it."""
    if not isinstance(value, list):
        return value
    out = {}
    for e in value:
        if not isinstance(e, dict) or set(e) != {"key", "value"} or not isinstance(e["key"], str) or e["key"] in out:
            return value
        out[e["key"]] = e["value"]
    return out


def _normalize(value, node, strip_nulls):
    """Walk the authoritative schema beside the answer: rebuild Map nodes and (strict flavor) drop the forced optional nulls.
    Nothing else is rewritten; a required nullable key keeps its null, and nulls inside map values are data."""
    if not isinstance(node, dict):
        return value
    if _is_map(node):
        m = _entries_to_map(value)
        if isinstance(m, dict):
            return {k: _normalize(v, node["additionalProperties"], strip_nulls) for k, v in m.items()}
        return m
    if "properties" in node and isinstance(value, dict):
        req = set(node.get("required", []))
        out = {}
        for k, v in value.items():
            if strip_nulls and v is None and k in node["properties"] and k not in req:
                continue
            out[k] = _normalize(v, node["properties"].get(k), strip_nulls)
        return out
    if isinstance(value, list) and "items" in node:
        return [_normalize(v, node["items"], strip_nulls) for v in value]
    if "oneOf" in node and isinstance(value, dict):
        for alt in node["oneOf"]:
            kind = alt.get("properties", {}).get("kind", {}).get("const")
            if kind is not None and value.get("kind") == kind:
                return _normalize(value, alt, strip_nulls)
    if "anyOf" in node and isinstance(value, dict):      # nullable envelope member: walk the object alternative
        for alt in node["anyOf"]:
            if isinstance(alt, dict) and "properties" in alt:
                return _normalize(value, alt, strip_nulls)
    return value


def strip_optional_nulls(value, node):
    """Remove null values the strict projection forced for keys the authoritative schema calls optional."""
    return _normalize(value, node, True)


def normalize_output(output_schema: str, value, flavor: str):
    return _normalize(value, original(output_schema), flavor == "openai-strict")


def local_issues(output_schema: str, value) -> list[str]:
    """Authoritative validation. Empty list = valid."""
    return [str(i) for i in validate(output_schema, value)][:5]


def schema_bytes(output_schema: str, flavor: str) -> bytes:
    return json.dumps(provider_schema(output_schema, flavor), sort_keys=True).encode()


def projection_snapshot() -> dict:
    return copy.deepcopy({f"{n}/{f}": provider_schema(n, f) for n in SCHEMA_NAMES
                          for f in ("anthropic", "openai-strict")})


def score_projection_snapshot() -> dict:
    return copy.deepcopy({f"{n}/{f}": provider_schema(n, f) for n in SCORE_SCHEMA_NAMES
                          for f in ("anthropic", "openai-strict")})
