---
title: Migrating MCP and AI tool configs
description: Secrets in mcp.json env blocks and --env-file targets move to the vault; the server command is wrapped in jit run.
---

# MCP / AI tool configs

MCP server configs - a project's `mcp.json`, Claude Desktop's config,
Claude Code's `~/.claude.json` - hand secrets to servers two ways: a
plaintext `env` block, or a pointer to a plaintext file. `jit migrate`
(category `mcp`) handles both, moving the values into the vault and
rewriting the server's `command` to launch through `jit run`:

```json
{
  "mcpServers": {
    "jamf": {
      "command": "/opt/homebrew/bin/jit",
      "args": ["run", "--profile", "mcp-jamf", "--", "uvx", "jamf-mcp-server"]
    }
  }
}
```

The server gets its secrets injected into its environment at launch, and
they exist only inside that process, for its lifetime. This also keeps
plaintext secrets out of anything that reads your editor config - including
the AI tools themselves.

Every other field on the entry (`cwd`, `type`, `alwaysAllow`, anything a
newer schema adds) is preserved untouched.

## Servers that read an `--env-file`

Plenty of servers never put a credential in the config at all. They pass a
path instead:

```json
"okta-mcp-server": {
  "command": "uv",
  "args": ["run", "--env-file", "./servers/okta/.env", "okta-mcp-server"]
}
```

The credential is in the `.env`, and the config holds only a pointer.
`jit migrate` follows it: the file's variables move into the same
`mcp-<server>` profile as an env block would, the `--env-file` flag is
removed from the rewritten args, and the file itself is replaced with a
[pointer file](./env-files.md) naming the vault paths.

The flag has to go with the file. Left in place it would aim the launcher
at the pointer file and set every credential to a literal
`jit://vault/...` string, so the server would start and nothing would work.

Three things:

- **Two files change.** You name a config; a `.env` elsewhere on disk
  becomes a pointer. The plan says so before you approve it
  (`also rewrites .../servers/okta/.env`), and both are backed up.
- **`jit migrate undo` restores both**, byte-for-byte, in one run. Undoing
  the config alone would put `--env-file` back pointing at a pointer file.
- **A variable in both places resolves to the `env` block.** The host sets
  that on the child process directly, so it is the more explicit of the two.
- **An unparseable line stops the run** before anything is touched, rather
  than silently dropping a variable the server needs. Fix or comment out the
  line and re-run. A multi-line PEM must be quoted, or written as one line
  with `\n` escapes.

A pointer that names a file which doesn't exist is left alone: there is
nothing to read, and stripping the flag would remove something you still
need once the path is fixed.

## What to expect

- **Starting your editor now starts a secret-injecting process.** If the
  service's session has lapsed, that's a Touch ID prompt naming the profile
  and the caller ("unlock the vault for profile `mcp-jamf`, launched by
  claude") - the most common "why did that prompt appear?" case. See
  [Provenance](../service/provenance.md).
- **One prompt covers every server.** Hosts launch their servers at once,
  and the service serializes them behind a single challenge, so a fleet of
  wrapped servers costs one approval, not one each.
- **Nobody at the keyboard.** A server launched with no terminal (an MCP
  host at login) waits 20 seconds for that approval and then exits with an
  explanation, rather than hanging until the host's own startup timeout
  kills it. The message lands in the host's server log. Run `jit unlock`
  and start the server again; approving the prompt late also works, since
  the challenge outlives the launch that asked for it.
- **Restart the host to pick up the change.** A running server keeps the
  environment it started with. `jit migrate` says so when it rewrites a
  config.
- Claude Desktop's config and `~/.claude.json` are machine-wide - name them
  explicitly to convert them; a project `.mcp.json` is picked up when you
  name that project's directory.

### Claude Code's `~/.claude.json`

That file is Claude Code's whole application state, and it holds MCP servers
in two places: the ordinary top-level `mcpServers` block, and a `projects`
map keying a **second set of server definitions by project directory**.
`jit migrate ~/.claude.json` converts both.

Three things:

- **Each project block gets its own profile namespace.** Two projects
  routinely define a server under the same name (`github`, `postgres`), with
  different tokens. Those land in `mcp-github` and `mcp-github-2` rather than
  one overwriting the other's vault value, and each project's rewritten entry
  names the profile holding *its* credential. `jit status --secrets` shows
  which is which.
- **The rest of the file is left alone.** Only the servers blocks are
  rewritten; everything Claude Code keeps around them - startup counts,
  per-project `allowedTools`, conversation history - survives byte-for-byte.
- **A project block jit cannot parse is reported, not skipped.** It stays
  untouched and migrate says so:

  ```
  ○ project block /Users/you/proj couldn't be parsed and was left unchanged
  ```

  Its servers are *not* migrated, so whatever `jit scan` flagged there is
  still in plaintext. Fix the JSON and re-run.

Restart Claude Code afterwards - a running MCP server keeps the environment
it started with.
- Rotating: `jit vault set` on the paths shown by
  `jit status --secrets`; restart the MCP server (usually: restart
  the editor) to pick up the new value.

## Checking a migrated config

`jit doctor` verifies the entries jit itself wrote, under an `[mcp]`
heading. A migrated entry pins an absolute path to the jit binary and a
profile name, and nothing else ever re-reads either:

```
[mcp]  2
  ✗ MCP server "caido" in ~/work/.mcp.json launches jit at /usr/local/bin/jit,
    which isn't there, so the host can't start this server at all
```

That happens when jit moves (a different install method, a workspace copied
between machines) or when a profile is deleted. The host reports only
"server failed", so nothing else would connect it back to jit. A bare
`uv`/`npx` command is deliberately not checked: it resolves against the PATH
the host gives the server, which jit can't see from a shell.

Reversing the migration: [`jit migrate undo`](./undo-and-remove.md).
