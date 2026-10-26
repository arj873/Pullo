"""Import caps. A cap breach is a typed refusal (`too-large`), never silent truncation; a per-file cap is an
`oversize` omission that stays visible in the record and the coverage statement."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from reviewer.contracts.canonical import digest

POLICY_SCHEMA = "repo-import-policy@1"
OMISSION_KINDS = ("submodule", "lfs", "binary", "oversize", "unsafe", "colliding", "unsupported", "redaction")


@dataclass(frozen=True)
class ImportPolicy:
    max_files: int = 60_000                 # leaf entries in the pinned tree (all kinds)
    max_tree_entries: int = 240_000         # tree entries visited, directories included (bounds shared-subtree DAGs)
    max_total_bytes: int = 400 << 20        # bytes written into tree/
    max_file_bytes: int = 1 << 20           # per file; larger is omitted as `oversize`
    max_pack_bytes: int = 512 << 20         # object store size during/after fetch
    max_tree_object_bytes: int = 16 << 20   # one tree object
    max_commit_bytes: int = 1 << 20
    max_depth: int = 60                     # directory components
    max_symlink_bytes: int = 4096
    fetch_timeout_s: int = 600
    read_timeout_s: int = 1800          # whole materialization
    max_stderr_bytes: int = 64 << 10

    def __post_init__(self):
        for k, v in asdict(self).items():
            if type(v) is not int or v <= 0:
                raise ValueError(f"policy {k} must be a positive int")

    def doc(self) -> dict:
        d = {"schema": POLICY_SCHEMA, **asdict(self)}
        return {**d, "digest": digest(d)}
