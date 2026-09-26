## jit mcp install

Add jit's MCP server to Claude Desktop or Cursor

### Synopsis

Add one entry, "jit", to the app's MCP servers, so its agent can list
and run your AI jobs: Claude Desktop (the default) or Cursor. Nothing else
in the file changes: the rest keeps its order, spacing and characters. A
config that is a link to another file is edited there, and stays a link.

First, a copy of the file as it was is saved beside it, named
<file>.jit-backup-<date>-<time>. The copy holds whatever the file held,
API keys included, so only you can read it, jit keeps only the latest
one, and jit scan reports any key in it.

The app reads its config at start, so quit and reopen it afterwards.

Connecting approves nothing. Claude can only run jobs you approved with
'jit job allow', and can only propose new ones for you to approve.

```
jit mcp install [--client claude-desktop|cursor] [flags]
```

### Options

```
      --client string    the AI app: claude-desktop or cursor (default "claude-desktop")
      --command string   the jit to start (default: the jit on your PATH when it has jit mcp, else this one)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit mcp](jit_mcp.md)	 - MCP server that lets AI apps run AI jobs (started by the app)

