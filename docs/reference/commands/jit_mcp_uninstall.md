## jit mcp uninstall

Remove jit's MCP server from Claude Desktop or Cursor

### Synopsis

Remove the "jit" entry from the app's MCP servers. Nothing else in the
file changes, and a copy of it as it was is saved beside it first, as
'jit mcp install' does. Your AI jobs stay; only this app's way in goes.

```
jit mcp uninstall [--client claude-desktop|cursor] [flags]
```

### Options

```
      --client string   the AI app: claude-desktop or cursor (default "claude-desktop")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit mcp](jit_mcp.md)	 - MCP server that lets AI apps run AI jobs (started by the app)

