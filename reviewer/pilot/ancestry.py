"""Offline proof that the proof's merge base is an ancestor of the head, from raw Git commit objects (BENCH-ANCESTRY-01).

The proof is a chain of raw commit objects ordered head-to-base. Every object is hashed here (Git SHA-1 commit oid) and
parsed by the existing repoimport helper; every adjacent next oid must be one of the current commit's parents, so any
valid multi-commit path, or any parent of a merge, is accepted and nothing else is. Pure: no network, no Git binary, no
target code. Commit messages are hashed and skipped over, never returned."""

from __future__ import annotations

import base64
import binascii
import re

from reviewer.repoimport import RepoImportError
from reviewer.repoimport.gitobjects import commit_tree_and_parents
from reviewer.repoimport.gitrun import oid_of

SCHEMA = "benchmark-ancestry@1"
CHAIN_MIN, CHAIN_MAX = 2, 1024
RAW_MAX = 64 * 1024
_OID = re.compile(r"[0-9a-f]{40}")


class AncestryError(Exception):
    pass


def verify_chain(proof, head: str, base: str) -> list:
    """Return [(oid, treeOid, parents)] head-to-base, or raise AncestryError."""
    if not isinstance(proof, dict) or set(proof) != {"schema", "commits"} or proof["schema"] != SCHEMA:
        raise AncestryError("ancestryProof must be exactly {schema: benchmark-ancestry@1, commits}")
    commits = proof["commits"]
    if not isinstance(commits, list) or not CHAIN_MIN <= len(commits) <= CHAIN_MAX:
        raise AncestryError(f"ancestryProof.commits must be a list of {CHAIN_MIN}..{CHAIN_MAX} commits")
    out, seen = [], set()
    for i, c in enumerate(commits):
        if not isinstance(c, dict) or set(c) != {"oid", "rawBase64"} or not all(isinstance(c[k], str) for k in c):
            raise AncestryError(f"ancestry commit {i} must be exactly {{oid, rawBase64}} strings")
        if not _OID.fullmatch(c["oid"]):
            raise AncestryError(f"ancestry commit {i} oid is not a 40-hex object id")
        if c["oid"] in seen:
            raise AncestryError(f"ancestry commit {i} repeats an object id")
        seen.add(c["oid"])
        if len(c["rawBase64"]) > (RAW_MAX * 4) // 3 + 8:
            raise AncestryError(f"ancestry commit {i} raw object is over the {RAW_MAX}-byte cap")
        try:
            raw = base64.b64decode(c["rawBase64"].encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            raise AncestryError(f"ancestry commit {i} rawBase64 is not strict base64") from None
        if len(raw) > RAW_MAX or base64.b64encode(raw).decode() != c["rawBase64"]:
            raise AncestryError(f"ancestry commit {i} raw object is oversized or non-canonical base64")
        if oid_of("commit", raw) != c["oid"]:
            raise AncestryError(f"ancestry commit {i} raw bytes do not hash to its oid")
        try:
            tree, parents = commit_tree_and_parents(raw)
        except RepoImportError:
            raise AncestryError(f"ancestry commit {i} is not a parseable commit object") from None
        out.append((c["oid"], tree, parents))
    if out[0][0] != head:
        raise AncestryError("ancestry chain does not start at the proof's head")
    if out[-1][0] != base:
        raise AncestryError("ancestry chain does not end at the proof's merge base")
    for i in range(len(out) - 1):
        if out[i + 1][0] not in out[i][2]:
            raise AncestryError(f"ancestry commit {i + 1} is not a parent of commit {i}")
    return out


def check_endpoints(chain: list, head_record: dict, base_record: dict) -> None:
    """The chain's end objects must equal the verified imports' commit, tree and parents."""
    for name, (oid, tree, parents), rec in (("head", chain[0], head_record), ("base", chain[-1], base_record)):
        if rec.get("commitSha") != oid or rec.get("treeOid") != tree or rec.get("parents") != parents:
            raise AncestryError(f"ancestry {name} commit differs from the verified {name} import record")
