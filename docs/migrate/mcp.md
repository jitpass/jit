---
title: Migrating MCP and AI tool configs
description: Secrets in mcp.json env blocks move to the vault; the server command is wrapped in jit run.
---

# MCP / AI tool configs

MCP server configs - a project's `mcp.json`, Claude Desktop's config - pass
secrets to servers through plaintext `env` blocks. `jit migrate` (category
`mcp`) moves each env-block value into the vault and rewrites the server's
`command` to launch through `jit run`:

```json
{
  "mcpServers": {
    "jamf": {
      "command": "jit",
      "args": ["run", "--profile", "mcp-jamf", "--", "uvx", "jamf-mcp-server"]
    }
  }
}
```

The server gets its secrets injected into its environment at launch, and
they exist only inside that process, for its lifetime. This also keeps
plaintext secrets out of anything that reads your editor config - including
the AI tools themselves.

## What to expect

- **Starting your editor now starts a secret-injecting process.** If the
  service's session has lapsed, that's a Touch ID prompt naming the profile
  and the caller ("unlock the vault for profile `mcp-jamf`, launched by
  claude") - the most common "why did that prompt appear?" case. See
  [Provenance](../service/provenance.md).
- Claude Desktop's config is machine-wide, so it's covered by
  `jit migrate home`; a project `.mcp.json` is covered by `local` too.
- Rotating: `jit vault set` on the paths shown by
  `jit profile show mcp-<name>`; restart the MCP server (usually: restart
  the editor) to pick up the new value.

Reversing the migration: [`jit migrate undo`](./undo-and-remove.md).
