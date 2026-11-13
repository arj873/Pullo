"""Test-package bootstrap. CLAUDE-CLI-PROVIDER re-gate R2: the claude-cli adapter's production defaults - the forwarder's upstream
https://api.anthropic.com and the default OAuth token loader (the user's REAL ~/.claude/.credentials.json) - FAIL CLOSED under the
test suite: the upstream becomes a closed loopback port and the default loader raises. A test that needs a forwarder or a token must
pass its own (a loopback upstream, a FakeForwarder, a dummy token); the trusted hosts and the canary are not under this package. The
real loader stays reachable as claude_cli.LIVE_DEFAULT_TOKEN_LOADER for the tests that exercise it against a scratch TOKEN_FILE."""

from reviewer.runtime import claude_cli as _claude_cli

CLOSED_UPSTREAM = "http://127.0.0.1:9"          # nothing listens on the discard port: a relay attempt fails at connect, on-host


def _no_default_credential():
    raise _claude_cli.ClaudeAuthUnavailable("tests: the default OAuth token loader is disabled (pass a dummy token_loader)")


_claude_cli.LIVE_DEFAULT_TOKEN_LOADER = _claude_cli.default_token_loader
_claude_cli.UPSTREAM = CLOSED_UPSTREAM
_claude_cli.default_token_loader = _no_default_credential
