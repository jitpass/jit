---
title: Troubleshooting
description: Placeholder values, hanging reads, surprise Touch ID prompts, MCP servers that fail to start, and stale-service warnings.
---

# Troubleshooting

- **Your app got placeholder values.** Under `jit run` this is handled for
  you (the mount is swapped for a compatible file, and the real values are in
  the environment), so this usually means the app read the mount *outside*
  `jit run`. Launch it through `jit run` (or `jit run --live` if the tool
  reads the `.env` file itself) - that's the only thing that makes a mount
  serve real values. `jit service status` shows what the last reader was
  served. Background: [Live-mounted files](../run/mounts.md).
- **A script says `.env` is missing, or a tool ignores it.** A migrated
  `.env` is a named pipe, not a regular file, so a `[ -f .env ]` /
  `Path.is_file()` guard outside `jit run` sees "not a regular file." Run the
  script with `jit run` - it swaps in a plain file for the run, so the guard
  passes. If instead a tool reads values *from the file itself* (like
  `docker compose` env_file) and gets nothing, use `jit run --live`, or pin
  `read_as_file: true` in the project's `.jit/config.yaml`. See
  [Which command delivers a secret](./delivering-secrets.md).
- **A command hangs reading `.env`.** The service is the mount's writer and
  normally auto-starts; if it crashed the read blocks with nothing serving it.
  `jit status` will say. `jit service restart` (re)starts it.
- **"No secret stored at ..." or a doctor failure.** A profile references a
  vault path that's gone (usually a `jit vault rm` after migration).
  Re-set it with `jit vault set <path>`, or update the profile.
- **A Touch ID prompt appeared and you don't know why.** Read it - it names
  what it's for and what set it off ("unlock the vault for profile
  `mcp-jamf`, launched by claude"). If it's already gone, `jit service status`
  shows who unlocked the current session and what dropped it, and
  `jit audit` lists every command, unlock, and lock, newest first:

  ```
  time=2026-07-22 13:19:19 level=info kind=unlock status=ok method=touchid-or-passcode cmd="~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve" parent=claude
  time=2026-07-22 13:19:13 level=info kind=lock reason="explicit lock"
  ```

  A common surprise: opening an editor. If your project's `.mcp.json` wraps
  an MCP server in `jit run --profile ...`, then starting that editor starts
  a secret-injecting process, which prompts if the session has lapsed.
- **An MCP server fails to start, and its log mentions an approval prompt.**
  The server launched with the session locked and no terminal for anyone to
  see the prompt from, so jit gave up after 20 seconds rather than hang past
  the host's own startup timeout. Run `jit unlock`, then restart the server
  (usually: restart the editor). Approving the prompt late works too - the
  challenge outlives the launch that asked for it, so the next start needs
  no prompt at all. Doing `jit unlock` before opening the editor avoids it
  entirely.
- **An MCP server fails to start and nothing else explains why.** Run
  `jit doctor`: an `[mcp]` finding means the entry jit wrote no longer works
  - the jit binary it names has moved, or its profile is gone. Hosts report
  only "server failed", so this is the only place the two get connected. See
  [MCP configs](../migrate/mcp.md#checking-a-migrated-config).
- **Touch ID prompts feel too frequent.** First find out what's asking -
  `jit audit` (above) names each one. If they're all legitimate,
  lengthen the [service's](../service/index.md) session window:
  `jit service ttl 1h`. The idle window can go up to 8 hours - a session ends
  there regardless, so a longer value is refused rather than silently ignored.
- **"different build" warning from `jit status`.** The running service is an
  older binary than the CLI you're typing - usually right after an upgrade.
  `jit upgrade` restarts the service for you, so you won't see this if you
  upgraded that way; otherwise run `jit service restart` to move it onto the
  current binary now (it also switches on its own within a few seconds once
  idle). See [Upgrading](./install.md#upgrading).
- **`jit grant --process` says the service predates tree grants.** The running
  service is an older binary that would have granted your whole terminal
  instead of only the named program - wider than the prompt you approved. jit
  revokes that grant on the spot rather than leaving it standing; run
  `jit service restart` and create it again. Same cause as the "different
  build" warning above.
- **A grant covers your tool but a mounted file still prompts.** Grants cover
  pull-at-use delivery, not FIFO mounts, which keep their own
  [consent gating](../service/consent.md). See
  [the honest limits](../service/grants.md#the-honest-limits).
- **A wrapped tool stopped authenticating.** See
  [Wrap troubleshooting](../wrap/troubleshooting.md) - `jit doctor --wrap`
  checks every shim, PATH entry, and profile.
- **Shell completion isn't working.** See the diagnosis notes under
  [Install → Shell completion](./install.md#shell-completion).
