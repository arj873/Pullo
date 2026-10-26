"""Validated remotes. Production accepts only `https://github.com/<owner>/<repo>[.git]`."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .errors import RepoImportError

_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
COMMIT = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Remote:
    url: str
    owner: str
    name: str
    kind: str = "github"                # "github" | "local-fixture" (tests only)

    @property
    def slug(self) -> str:
        return f"{self.owner}--{self.name}".lower()

    @property
    def repo(self) -> str:
        return f"{self.owner}/{self.name}"


def github_remote(url) -> Remote:
    if not isinstance(url, str) or not url.isascii() or not url.isprintable() or " " in url:
        raise RepoImportError("bad-url", "repository URL must be printable ASCII")
    m = re.fullmatch(r"https://github\.com/([^/?#@:\\]+)/([^/?#@:\\]+?)(?:\.git)?/?", url)
    if m is None:
        raise RepoImportError("bad-url", "only https://github.com/<owner>/<repo> is accepted")
    owner, name = m.groups()
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(name) or name in (".", "..") or name.startswith("-") \
            or name.endswith(".git"):
        raise RepoImportError("bad-url", "invalid owner or repository name")
    return Remote(f"https://github.com/{owner}/{name}", owner, name)


def local_fixture_remote(path, owner="fix", name="repo") -> Remote:
    """TESTS ONLY (not exported, no CLI): a `file://` URL of a local bare repository the test owns."""
    p = os.path.realpath(path)
    return Remote("file://" + p, owner, name, kind="local-fixture")


def check_commit(commit) -> str:
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise RepoImportError("bad-commit", "commit must be exactly 40 lowercase hex characters (no refs or branches)")
    return commit
