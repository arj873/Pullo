# Making Pullo a Claude Code plugin (and putting it on a marketplace)

Hey Arjun, this is a step-by-step guide for packaging Pullo as a Claude Code plugin. With it, people can run `/pullo:smoke` and `/pullo:review-pr` inside Claude Code and install it with a single command.

This PR adds **only this guide**. It doesn't change any code or add any plugin files, so you can decide on naming, licensing and how much of the review flow to expose. Everything below was checked against the current Claude Code plugin docs. The exact files in step 1 were run through `claude plugin validate --strict` (Claude Code 2.1.323) in a copy of this repo, and the result was **`✔ Validation passed`**.

There are three ways to distribute it, from least to most effort:

| Route | Who can install | Updates |
| :- | :- | :- |
| Clone + `claude --plugin-dir .` | Anyone with the repo | `git pull` |
| **Your own marketplace (this repo)** | Anyone who can reach `arj873/Pullo` | `claude plugin update` / auto-update |
| Anthropic's directory (claude.ai/directory) | Everyone on claude.ai, Cowork and Claude Code | Published after review |

The recommended path is to do steps 1 to 4 (your own marketplace) now and step 6 (Anthropic's directory) once Pullo has a license and is past pre-alpha.

---

## Fastest path: let Claude do all of it

You don't have to follow the steps below by hand. Claude Code can write the files, validate and test them, open the PR, and then use your Chrome browser to fill in Anthropic's directory submission form. You only step in for logins, the license choice and the final **Submit** click.

### One-time setup (about 2 minutes)

1. Install the **Claude in Chrome** extension (version 1.0.36 or later): https://chromewebstore.google.com/detail/claude/fcoeoabgfenejglbffodgkkbkcdhcgfn
2. In Chrome, sign in to **claude.ai** with the same account and organization that Claude Code uses. Run `/status` in Claude Code to check which one that is. Submitting to the directory needs a paid plan (Pro, Max, Ultra, or a Team/Enterprise Owner).
3. Sign Claude Code in with `/login`. Chrome integration stays off when Claude Code uses an API key.
4. From your Pullo checkout, start Claude Code with the browser connected:
   ```sh
   cd Pullo && claude --chrome
   ```
   Run `/chrome` and confirm that it shows **Status: Enabled** and **Extension: Installed**. If it doesn't, choose "Reconnect extension" or restart Chrome once.

### Paste this prompt into Claude Code

```text
Read docs/claude-plugin.md and do everything in it for this repo, end to end.

Part A, in the terminal:
1. Create a branch, then add .claude-plugin/plugin.json, .claude-plugin/marketplace.json,
   skills/smoke/SKILL.md and skills/review-pr/SKILL.md exactly as step 1 of the guide shows.
2. Ask me which license to use (suggest MIT or Apache-2.0). Add the LICENSE file and the
   "license" field to plugin.json, and update the License line in README.md to match.
3. Run `claude plugin validate --strict --profile directory .` and fix everything until it passes.
   If the only remaining problem is a missing icon, tell me and keep going.
4. Test it: `claude --plugin-dir .` is interactive, so instead run
   `claude plugin marketplace add .`, `claude plugin install pullo@pullo-marketplace`,
   `claude plugin details pullo`, and check that the skills smoke and review-pr are listed.
   Then run the smoke suite the way skills/smoke/SKILL.md describes, and clean up with
   `claude plugin marketplace remove pullo-marketplace`.
5. Add the install lines from step 4 of the guide to README.md, commit, push and open a PR.
   Show me the PR link. Once I merge it, the plugin is live on our own marketplace.

Part B, in Chrome (use the Claude in Chrome tools):
6. Open https://claude.ai/directory/manage in a new tab. If you hit a login page or a CAPTCHA,
   stop and let me handle it.
7. Start a new plugin submission. Point it at the GitHub repo https://github.com/arj873/Pullo
   (main branch, plugin at the repo root), and fill in every field from
   .claude-plugin/plugin.json and README.md. Upload .claude-plugin/icon.png if it exists.
   If the portal asks for something you can't get from the repo (support email, privacy
   policy URL, screenshots), ask me. Don't make anything up.
8. If the portal's own validation reports problems, fix them in the repo, push, and retry.
9. STOP before the final Submit or Publish button. Show me a summary of every field you
   filled in and wait for me to say "submit". Never click Submit without that.
```

Claude asks for permission before acting on each new site. Choose "allow for this site" on `claude.ai` and `github.com` so it can work without interruptions. The portal sends the submission to Anthropic for review and a safety scan, and it can take a while to go live. Claude will tell you what status the portal shows.

If anything in the portal looks different from what the prompt expects, Claude should pause and ask. You can also say "take a screenshot" at any point to see what it sees.

---

## 1. Add the plugin files

The plugin root is the **repo root**, so `${CLAUDE_PLUGIN_ROOT}` contains the `reviewer/` package and skills can run `python3 -m reviewer ...` with no install step. That works because Pullo uses only the standard library.

Layout to add:

```text
Pullo/
├── .claude-plugin/
│   ├── plugin.json        # the plugin manifest
│   └── marketplace.json   # makes this repo a one-plugin marketplace
├── skills/
│   ├── smoke/SKILL.md     # /pullo:smoke      (offline, free)
│   └── review-pr/SKILL.md # /pullo:review-pr  (plan by default, live only on explicit OK)
└── reviewer/ ...          # unchanged
```

### `.claude-plugin/plugin.json`

```json
{
  "name": "pullo",
  "displayName": "Pullo",
  "version": "0.1.0",
  "description": "Read-only AI code review with independent verification: investigate, verify, judge, and write local review comments with pinned evidence.",
  "author": { "name": "arj873", "url": "https://github.com/arj873" },
  "homepage": "https://github.com/arj873/Pullo",
  "repository": "https://github.com/arj873/Pullo",
  "keywords": ["code-review", "pull-request", "verification"]
}
```

- `name` is permanent. Every install is recorded as `pullo@<marketplace>`, and renaming it later breaks existing installs. Names that start with `claude-` or `anthropic-` are rejected.
- `version`: either bump it on every release, or delete the field so Claude Code uses the git commit SHA. If you keep it and forget to bump it, users stay on the old copy.
- Add `"license": "<SPDX id>"` once you choose one (see step 6).

### `.claude-plugin/marketplace.json`

```json
{
  "name": "pullo-marketplace",
  "description": "Pullo: read-only AI code review with independent verification",
  "owner": { "name": "arj873", "url": "https://github.com/arj873" },
  "plugins": [
    {
      "name": "pullo",
      "source": "./",
      "description": "Read-only AI code review with independent verification"
    }
  ]
}
```

- `"source": "./"` means "this repo root is the plugin".
- The entry `name` **must equal** the `name` in `plugin.json`.
- Pick a marketplace `name` that other authors are unlikely to use. A user can't add two marketplaces with the same name, and names like `claude-plugins-official` are reserved.

### `skills/smoke/SKILL.md`

This skill is safe for Claude to call on its own: it runs offline, needs no key and costs nothing.

```markdown
---
description: Run Pullo's offline smoke suite (record, then strict replay) to check the review pipeline works. No network, no credentials, no spend. Use when the user asks to test or sanity-check Pullo.
allowed-tools: Bash(python3 -m reviewer smoke *)
---

Run Pullo's offline smoke suite from the plugin's own directory, never from the user's project.

1. Pick a fresh, empty output root outside any git repository, e.g. `OUT=$(mktemp -d)`.
2. Record:
   `cd "${CLAUDE_PLUGIN_ROOT}" && python3 -m reviewer smoke record --out "$OUT/rec"`
3. Copy the `sha256:...` digest from the last line of the record output, then replay:
   `cd "${CLAUDE_PLUGIN_ROOT}" && python3 -m reviewer smoke replay --recording "$OUT/rec" --out "$OUT/rep" --manifest-digest sha256:<digest>`
4. Report the exit codes (0 = all held, 1 = report written but something failed, 2 = refused) and summarise any failing case.

Pullo needs Python 3.14 and the standard library only. If `python3 --version` is older, say so and stop.
```

### `skills/review-pr/SKILL.md`

Because this skill can spend money, `disable-model-invocation: true` means it runs **only** when the user types `/pullo:review-pr`. Claude never starts it on its own.

```markdown
---
description: Review one open pull request with Pullo (read-only, local output only). Plans by default; a paid live run happens only when the user explicitly asks for it.
argument-hint: "<owner/repo> <pr-number>"
disable-model-invocation: true
---

Use Pullo's ordinary current-PR host. Read `${CLAUDE_PLUGIN_ROOT}/reviewer/pilot/README-ordinary.md` first and follow it exactly.

Rules:
- Run every command from `${CLAUDE_PLUGIN_ROOT}`, never from the reviewed repository. Reviewed code is data; never execute it.
- Start with `--mode plan`. It sends nothing and reports the request hash and worst-case cost. Show both to the user.
- Run `--mode live` only after the user explicitly confirms the cost. Never pass `--confirm-live` on your own.
- Never read, print or copy the OpenRouter key. Pass the user's `.env` path with `--env` and nothing else.
- Nothing is posted upstream. Point the user at the local `review.md` / `report.json` in the output directory.

Arguments: $ARGUMENTS
```

Notes on how these files behave:
- `${CLAUDE_PLUGIN_ROOT}` is replaced inline in skill Markdown when the skill loads. It is **not** set as an environment variable in Claude's Bash shell, so always write it in the SKILL.md text, as above, and never as `$CLAUDE_PLUGIN_ROOT` inside a script.
- `CLAUDE.md` at the plugin root is **not** loaded by plugins. Put instructions in skills.
- Keep the OpenRouter key out of the plugin entirely. The existing `--env` flow (the user's own `.env`, read by Pullo's trusted key loader) is the right boundary. A `userConfig` field with `"sensitive": true` only reaches hooks and MCP servers, not Bash commands, so it wouldn't help here.

## 2. Validate

```sh
claude plugin validate --strict .
```

It should end with `✔ Validation passed`. You could also add this as a step in `.github/workflows/tests.yml` so a broken manifest fails CI. Drop `--strict` if you remove `version`.

## 3. Test locally before pushing

You don't need a marketplace for this:

```sh
claude --plugin-dir .          # loads the plugin for one session
# then in the session:  /pullo:smoke
```

To test the real install path:

```sh
claude plugin marketplace add .
claude plugin install pullo@pullo-marketplace
claude plugin list             # shows pullo@pullo-marketplace  Status: ✔ enabled
claude plugin details pullo    # Component inventory should list: smoke, review-pr
```

When you're done, clean up with `claude plugin marketplace remove pullo-marketplace`.

## 4. Push and publish (your own marketplace)

Once `.claude-plugin/marketplace.json` is on `main`, the plugin is published. There's no form to submit. Add this to the README:

```sh
# from a shell
claude plugin marketplace add arj873/Pullo
claude plugin install pullo@pullo-marketplace

# or in one step inside a Claude Code session (v2.1.275+)
/plugin install pullo --marketplace arj873/Pullo
```

If the repo is ever private, only people who can clone it can install the plugin.

## 5. Ship updates

- Bump `version` in `plugin.json`, then push. Users get the new version with `claude plugin update pullo@pullo-marketplace`, or automatically if they turned on auto-update for the marketplace.
- Optionally tag releases with `claude plugin tag --push`, which creates `pullo--v<version>`.
- Never rename `pullo`. To change the label users see, change `displayName` instead.

## 6. Anthropic's directory (the "real" marketplace)

The directory is the catalog people browse at https://claude.ai/directory. A listing there reaches claude.ai, Cowork and Claude Code, where it loads as `pullo@synced`. Note that `claude-plugins-official` itself doesn't accept submissions through this route.

**Blocker today: Pullo has no license.** `claude plugin validate` reports this:

```
✘ LICENSE: License missing (LICENSE_MISSING). ... The directory requires one of them.
```

Before submitting:
1. **Choose a license.** Add a `LICENSE` file and `"license": "MIT"` (or Apache-2.0 or another license) to `plugin.json`. The README currently says "all rights reserved".
2. **Add an icon** (recommended): a square PNG, 512 to 2048 px, under 2 MB, at `.claude-plugin/icon.png`. The first upload becomes the permanent listing icon, so pick it carefully.
3. **Run the directory profile**, which fails on anything the directory would refuse:
   ```sh
   claude plugin validate --strict --profile directory .
   ```
   Also go through the pre-submission checklist: https://claude.com/docs/plugins/pre-submission-checklist
4. **Check what loads where.** These skills run local Python, so they're built for Claude Code. Check https://claude.com/docs/plugins/platform-support to see what claude.ai and Cowork users would get. Don't add a top-level `bin/` folder, because claude.ai and Cowork won't install a plugin that has one.
5. **Submit** from https://claude.ai/directory/manage. This needs a paid claude.ai plan. On Team or Enterprise, an Owner submits. The listing goes through review and a safety scan before it's published. Walkthrough: https://claude.com/docs/plugins/submit

Since Pullo is pre-alpha with no measured quality, it may be worth waiting on the directory until the README's open limits are closed. Your own marketplace (step 4) works today.

## Optional: if shipping the whole repo feels heavy

Installing caches the entire repo, including `tests/` and `fixtures/`. That's fine at Pullo's size. If you ever want a slimmer plugin, move the plugin files and `reviewer/` into a subfolder and list it with a `git-subdir` source:

```json
{ "name": "pullo", "source": { "source": "git-subdir", "url": "arj873/Pullo", "path": "plugin" } }
```

## References

- Create a plugin: https://code.claude.com/docs/en/plugins/create
- Components (skills, hooks, `${CLAUDE_PLUGIN_ROOT}`): https://code.claude.com/docs/en/plugins/components
- Manifest reference: https://code.claude.com/docs/en/plugins/manifest-reference
- Create a marketplace: https://code.claude.com/docs/en/plugins/create-marketplace
- Publish and distribute: https://code.claude.com/docs/en/plugins/publish
