"""Trusted review-model configuration (CFG-01): which model answers each review role.

User-facing review models live in `pullo.toml` at Pullo's own application root (the checkout this module is in),
or in a file the operator names with `--config`. The file is NEVER discovered from the reviewed target, the
current working directory or repository instructions. It selects models only: no secrets, hooks, budgets, retries,
fallbacks or account settings, and it cannot authorize anything the spend authorization and the exact OpenRouter
allowlist do not already allow. Unknown fields, unsupported providers and unknown models are refused, never
replaced by a fallback. Development-worker models are a separate concern and are not read here.

Identity: the effective selection is bound through the ModelProfile it produces (role model and price are in the
profile digest). The config's absolute path and file bytes are never part of identity or of any model request."""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

from reviewer.contracts.canonical import digest
from reviewer.runtime.catalog import ALLOWED_ROUTER_MODELS

APP_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = APP_ROOT / "pullo.toml"
SCHEMA = "pullo-config@1"
DOC_SCHEMA = "pullo-review-models@1"
DEFAULT_MODEL = "anthropic/claude-sonnet-5.5"
ROLES = ("investigator", "verifier", "judge")
PROVIDER = "anthropic"                      # Anthropic models through OpenRouter: the only runnable provider today
HELD_PROVIDERS = {"openai": "OpenAI (Terra) is held: the installed-CLI path needs its preventive isolation and "
                            "parser/process gates, which are not accepted yet. It is not enabled and there is no "
                            "fallback to another provider"}
MAX_BYTES = 8192
_TOP, _REVIEW, _ROLE = {"schema", "review"}, set(ROLES), {"provider", "model"}


class ConfigError(ValueError):
    """A refusal before any output, state, key or model action. Messages never echo file content at length."""


def _shown(v) -> str:
    s = v if isinstance(v, str) else type(v).__name__
    return repr(s[:60] + ("..." if len(s) > 60 else ""))


@dataclass(frozen=True)
class ReviewModels:
    investigator: str = DEFAULT_MODEL
    verifier: str = DEFAULT_MODEL
    judge: str = DEFAULT_MODEL

    def __post_init__(self):
        for r in ROLES:
            m = getattr(self, r)
            if not isinstance(m, str) or m not in ALLOWED_ROUTER_MODELS:
                raise ConfigError(f"{r}: model {_shown(m)} is not in the exact OpenRouter allowlist")

    @classmethod
    def uniform(cls, model: str) -> "ReviewModels":
        return cls(model, model, model)

    def model(self, role: str) -> str:
        return getattr(self, role)

    def doc(self) -> dict:
        return {"schema": DOC_SCHEMA, "roles": {r: {"provider": PROVIDER, "model": self.model(r)} for r in ROLES}}

    @property
    def digest(self) -> str:
        return digest(self.doc())

    def summary(self) -> str:
        """The single model if all roles agree, else 'mixed' (see `roles` for the truth)."""
        s = {self.model(r) for r in ROLES}
        return s.pop() if len(s) == 1 else "mixed"


@dataclass(frozen=True)
class EffectiveConfig:
    models: ReviewModels
    source: str                   # "builtin-default" | "app-default" | "explicit"

    def report(self) -> dict:
        """What reports/receipts show. No path: an absolute local path is not evidence and must not leak."""
        return {"source": self.source, "digest": self.models.digest, "schema": DOC_SCHEMA,
                "roles": {r: {"provider": PROVIDER, "model": self.models.model(r)} for r in ROLES}}


def _read(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise ConfigError("config file is missing, unreadable or a symlink") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ConfigError("config path is not a regular file")
        raw = os.read(fd, MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise ConfigError(f"config file exceeds {MAX_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("config file is not UTF-8") from None
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text) or "\x7f" in text:
        raise ConfigError("config file contains control characters")
    return text


def parse(text: str) -> ReviewModels:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"config is not valid TOML: {str(e)[:120]}") from None
    if set(doc) - _TOP:
        raise ConfigError(f"unknown top-level field(s): {sorted(map(_shown, set(doc) - _TOP))}")
    if doc.get("schema") != SCHEMA:
        raise ConfigError(f"config must declare schema = \"{SCHEMA}\"")
    review = doc.get("review", {})
    if not isinstance(review, dict) or set(review) - _REVIEW:
        raise ConfigError(f"[review] allows only the role tables {list(ROLES)}")
    chosen = {}
    for r in ROLES:
        t = review.get(r, {})
        if not isinstance(t, dict) or set(t) - _ROLE:
            raise ConfigError(f"[review.{r}] allows only provider and model")
        provider = t.get("provider", PROVIDER)
        if not isinstance(provider, str):
            raise ConfigError(f"{r}: provider must be a string")
        if provider in HELD_PROVIDERS:
            raise ConfigError(f"{r}: {HELD_PROVIDERS[provider]}")
        if provider != PROVIDER:
            raise ConfigError(f"{r}: unsupported provider {_shown(provider)} (supported: {PROVIDER})")
        chosen[r] = t.get("model", DEFAULT_MODEL)
    return ReviewModels(**chosen)


def resolve_config(path=None, *, forbidden_roots=()) -> EffectiveConfig:
    """The effective review-model config. `path=None` means Pullo's own `pullo.toml` (builtin defaults if the
    application checkout has none): never anything found relative to the working directory or the target.
    An explicit path must not lie inside any `forbidden_roots` (reviewed source, corpus, store, output)."""
    if path is None:
        if os.path.lexists(DEFAULT_CONFIG_PATH):
            return EffectiveConfig(parse(_read(DEFAULT_CONFIG_PATH)), "app-default")
        return EffectiveConfig(ReviewModels(), "builtin-default")
    if not isinstance(path, (str, os.PathLike)) or not str(path):
        raise ConfigError("--config needs a file path")
    p = Path(os.path.abspath(path))
    real = Path(os.path.realpath(p))
    for root in forbidden_roots:
        r = Path(os.path.realpath(root))
        if real == r or r in real.parents:
            raise ConfigError("config file must lie outside the reviewed source, corpus, store and output roots")
    return EffectiveConfig(parse(_read(p)), "explicit")


def reconcile_legacy_model(cfg: EffectiveConfig, legacy_model: str | None) -> EffectiveConfig:
    """Legacy `--model X`: never a silent override. It is accepted only as a no-op that agrees with the config
    already in effect (the default file, not an explicit --config); any disagreement is a conflict."""
    if legacy_model is None:
        return cfg
    if cfg.source == "explicit":
        raise ConfigError("--model conflicts with --config: set the models in the config file")
    if any(cfg.models.model(r) != legacy_model for r in ROLES):
        raise ConfigError("--model conflicts with the effective config; set review models in pullo.toml or --config")
    return cfg
