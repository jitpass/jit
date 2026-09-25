## jit mcp install

Add jit's MCP server to Claude Desktop

### Synopsis

Add one entry, "jit", to Claude Desktop's MCP servers, so Cowork can list
and run your AI jobs. The config file is backed up first, beside itself,
and nothing else in it changes. Claude Desktop reads it at start, so quit
and reopen it afterwards.

Connecting approves nothing. Claude can only run jobs you approved with
'jit job allow', and can only propose new ones for you to approve.

```
jit mcp install [--client claude-desktop] [flags]
```

### Options

```
      --client string    the AI app: claude-desktop (default "claude-desktop")
      --command string   the jit to start (default: the jit on your PATH)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit mcp](jit_mcp.md)	 - MCP server that lets AI apps run AI jobs (started by the app)

