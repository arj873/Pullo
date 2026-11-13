---
name: add-sdk-connector
description: Add a new SDK connector to Pullo so review roles can be answered through another agent SDK (for example Gemini CLI, Cursor, Amp, or a local model runner) selected with --connector. Use when someone asks to plug a new SDK, CLI or subscription into Pullo's model calls.
argument-hint: "<sdk name, e.g. gemini-sdk>"
---

# Add an SDK connector to Pullo

A connector lets Pullo's review roles (investigator, verifier, judge) be answered through an agent SDK running under
the user's own login, instead of the paid OpenRouter key. Built-in examples:

- `reviewer/connectors/claude_sdk.py`: Claude Agent SDK, provider slot `anthropic`
- `reviewer/connectors/codex_sdk.py`: Codex Python SDK, provider slot `openai`
- `reviewer/connectors/base.py`: `SdkConnector`, which holds **all** the safety and accounting logic

Read all three before writing anything. New connector requested: **$ARGUMENTS**

## Ground rules (don't break these)

- **Only implement `invoke()`, `models()`, `sdk_model()` and optionally `estimate()`/`abort()`.** Never override
  `call()`, `_interpret()` or `_done()`. They enforce the call cap, the deadline, the empty per-call working
  directory, strict output parsing, honest usage reporting and the ledger receipts.
- **No tools, ever.** Configure the SDK so the model gets no tools, no MCP servers, no skills or plugins, no
  project or user settings, no web access, a single turn, and the empty `cwd` you're given. Pullo treats the reviewed
  code as data, and a reviewer that can run commands breaks that rule.
- **Detect anything you can't prevent.** Append to `reply.violations` for every tool call, tool result, command,
  file change, web search, permission denial or unknown message/item type the SDK reports. The base then discards the
  output and disables the connector for the rest of the run. When in doubt, flag it: fail closed.
- **Never guess a token count.** Leave an `SdkReply` token field as `None` when the SDK doesn't report it. Never
  write `0` for "unknown".
- **Billing must be what it says.** Connectors are `subscription-consumption`. If an environment variable would
  make the SDK bill an API key instead, as `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` can, refuse in `__init__` with
  `ConnectorUnavailable` and name the variable.
- **Raise `NotSent` only when you're sure nothing left the machine**, for example when the binary is missing or the
  user isn't logged in. Any other exception is treated as "outcome unknown", which is the safe default.
- **No new required dependencies.** Pullo is stdlib-only. Import the SDK only inside your `load_sdk()` override,
  with a plain `import x` statement wrapped in `try/except ImportError: raise cls.missing()`. Never import it at
  module import time. **Don't use `importlib`, `__import__` or `import_module`**: the boundary test
  `tests/ci04_review` forbids dynamic imports anywhere outside `reviewer/historical`. Tests use a fake SDK object.
- **No silent model swaps.** Set `reply.resolved_model` to whatever the SDK says answered. If that isn't the
  requested model, the gateway records a wrong-model contract violation. Never set a fallback model.

## Steps

1. **Pick the slot and models.** The connector answers ONE provider slot from `pullo.toml`: `anthropic` (models in
   `ALLOWED_ROUTER_MODELS`) or `openai` (models in `TERRA_MODELS`), both in `reviewer/runtime/catalog.py`.
   - If the SDK serves one of those model families, reuse the slot and map ids in `sdk_model()`.
   - If it serves a different model family, stop and tell the user. That needs a new provider slot, a pinned price
     snapshot and an allowlist in `reviewer/config.py` and `catalog.py`, plus authorization updates. That is a
     larger change for the maintainer (Arjun) to approve; it isn't a connector-only change.

2. **Create `reviewer/connectors/<name>.py`**, using `claude_sdk.py` as the template:
   ```python
   class GeminiSdkConnector(SdkConnector):
       connector_id = "gemini-sdk"            # the --connector value
       name = "anthropic" | "openai"          # the slot it answers
       sdk_module = "the_import_name"
       install_hint = "pip install ..., then log in with ..."
       schema_flavor = "anthropic" | "openai-strict"   # see reviewer/runtime/schemas.provider_schema
       isolation_version = "gemini-sdk-no-tools@1"     # bump whenever the isolation settings change

       @classmethod
       def load_sdk(cls):
           try:
               import the_import_name
           except ImportError:
               raise cls.missing() from None
           return the_import_name

       @classmethod
       def models(cls): ...
       def sdk_model(self, model): ...
       def invoke(self, *, prompt, system, schema, model, max_output_tokens, timeout, cwd) -> SdkReply: ...
       def estimate(self, model, reply): ...  # API-equivalent micros + priceVersion, from catalog.py
   ```
   In `invoke()`, send `system` as the system prompt and `prompt` as the single user message. Pass `schema` to the
   SDK's structured-output option only if that option does NOT work through a tool call. Otherwise append the schema
   to the system prompt, as `claude_sdk.py` does. Respect `timeout`: raise `TimeoutError` on expiry, and implement
   `abort()` if the SDK holds a process you can close.

3. **Register it** in `reviewer/connectors/__init__.py` by adding the class to `CONNECTORS`. The `--connector`
   choices on both review hosts come from there automatically.

4. **Write tests** in `tests/connectors/test_<name>.py`, using `tests/connectors/test_connectors.py` as the pattern:
   a fake SDK object passed as `sdk=`, `environ={}`, and a temporary `RuntimeLedger`. At minimum, cover:
   - success: output parsed, `resolvedModel`, usage mapping, receipt `kind` and `billingKind`, the isolation options
     actually passed to the SDK, and an empty `cwd` that is deleted afterwards
   - a tool or action item, which must produce `isolation-violation`, discard the output and disable the connector
   - a wrong model passed through, invalid JSON giving `invalid-output`, unknown usage staying `None`
   - binary missing giving `not-sent`, a crash or timeout giving `unknown`, and a billing env var being refused
   - a request for the other slot being refused before the SDK is touched
   `RegistryTests.test_every_connector_declares_its_contract` checks the class attributes for you.

5. **Run the checks** (Python 3.14):
   ```sh
   python3 -B -m unittest tests.connectors -v
   nice -n 19 python3 -B -m unittest discover -s tests -t .
   python3 -m reviewer.contracts export --check
   ```
   The full suite must keep its existing skip and expected-failure counts (see `KNOWN_TEST_ISSUES.md`).

6. **Document it.** Add a row to the connector table in `README.md` (section "SDK connectors") with the install
   and login steps and the isolation version. Then add a module docstring that states plainly what is configured
   versus proven, and every known limit, such as output tokens that can't be capped or a worker that can't be killed.

7. **Don't run it live on your own.** A live call spends the user's subscription. If the user wants a live check,
   suggest `--mode plan` first, then one `--mode live` run with `--confirm-live`, which they start themselves.

## How it is wired (for orientation)

`--connector <id>` → `reviewer/pilot/repository.py` (`live_mode`) → `providers.check_connector_roles` (every role
must use the connector's slot) → `providers.open_connector_state` (its own `subscription-ledger.jsonl`, never the
OpenRouter trial state) → `providers.live_connector` (constructs it, which loads the SDK and checks the billing
env) → the gateway sees `billing_kind == "subscription-consumption"` and keeps the call out of the paid SpendBook,
recording an `estimated` cost. Replay never touches a connector: it reads the recorded trace.
