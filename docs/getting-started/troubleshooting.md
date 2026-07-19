---
title: Troubleshooting
description: Placeholder values, hanging reads, surprise Touch ID prompts, and stale-agent warnings.
---

# Troubleshooting

- **Your app got placeholder values.** Under `jit run` this is handled for
  you (the mount is swapped for a compatible file, and the real values are in
  the environment), so this usually means the app read the mount *outside*
  `jit run` and outside a reveal window. Run it with `jit run`, or
  `jit agent reveal <path>` then restart the app. `jit agent status` shows
  what the last reader was served. Background:
  [Live-mounted files](../run/mounts.md).
- **A script says `.env` is missing, or a tool ignores it.** A migrated
  `.env` is a named pipe, not a regular file, so a `[ -f .env ]` /
  `Path.is_file()` guard outside `jit run` sees "not a regular file." Run the
  script with `jit run` — it swaps in a plain file for the run, so the guard
  passes. If instead a tool reads values *from the file itself* (like
  `docker compose` env_file) and gets nothing, use `jit run --live`, or pin
  `read_as_file: true` in the project's `.jit/config.yaml`. See
  [Which command delivers a secret](./choosing.md).
- **A command hangs reading `.env`.** The agent probably isn't running or
  serving that mount; `jit status` will say. `jit agent install` (re)starts
  it.
- **"No secret stored at ..." or a doctor failure.** A profile references a
  vault path that's gone (usually a `jit vault rm` after migration).
  Re-set it with `jit vault set <path>`, or update the profile.
- **A Touch ID prompt appeared and you don't know why.** Read it - it names
  what it's for and what set it off ("unlock the vault for profile
  `mcp-jamf`, launched by claude"). If it's already gone, `jit agent status`
  shows who unlocked the current session and what dropped it, and
  `jit agent history` lists every unlock and lock since the agent started:

  ```
  Session history (most recent first):
    • unlocked 4s ago (13:19:19) - launched by claude
        ~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve
    • locked   10s ago (13:19:13) - explicit lock, launched by claude
  ```

  A common surprise: opening an editor. If your project's `.mcp.json` wraps
  an MCP server in `jit run --profile ...`, then starting that editor starts
  a secret-injecting process, which prompts if the session has lapsed.
- **Touch ID prompts feel too frequent.** First find out what's asking -
  `jit agent history` (above) names each one. If they're all legitimate,
  [install the agent](../agent/index.md) or lengthen its window:
  `jit agent install --ttl 1h`.
- **"different build" warning from `jit status`.** The running agent is an
  older binary than the CLI you're typing. Run `jit agent install` again to
  restart it on the current one (see
  [Upgrading](./install.md#upgrading)).
- **A wrapped tool stopped authenticating.** See
  [Wrap troubleshooting](../wrap/troubleshooting.md) - `jit wrap doctor`
  checks every shim, PATH entry, and profile.
- **Shell completion isn't working.** See the diagnosis notes under
  [Install → Shell completion](./install.md#shell-completion).
