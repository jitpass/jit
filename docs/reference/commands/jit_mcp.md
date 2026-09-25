## jit mcp

MCP server that lets AI apps run AI jobs (started by the app)

### Synopsis

jit mcp is an MCP server over stdin and stdout. An AI app starts it on
this Mac (Claude Desktop and Cursor do, from their config) and gets three
tools: list_jobs, run_job and request_job. It is how Claude Desktop's Cowork,
whose shell is a Linux VM that cannot run jit, runs your approved AI jobs.

It never holds a key. It asks the jit service to run a job by name and
relays the output, in which the service has already hidden every secret
value. A proposal from request_job creates nothing: it answers with the
'jit job allow' line for you to run.

You do not run this by hand. 'jit mcp install' adds it to Claude Desktop,
and 'jit mcp install --client cursor' to Cursor.

```
jit mcp
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit mcp install](jit_mcp_install.md)	 - Add jit's MCP server to Claude Desktop or Cursor
* [jit mcp status](jit_mcp_status.md)	 - Show whether an AI app can reach jit's MCP server
* [jit mcp uninstall](jit_mcp_uninstall.md)	 - Remove jit's MCP server from Claude Desktop or Cursor

