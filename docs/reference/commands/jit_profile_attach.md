## jit profile attach

Record an MCP config on the profiles its tools use

### Synopsis

Records <config> on every global profile its tools use that doesn't
record it yet: one whose recorded config is deleted, one that records
no config, or one that records another live config (it then records
both). Deleted configs are dropped from the record. Name profiles to
attach only those.

A profile that records a config goes with it: `jit migrate remove` of
that config's project deletes it too, so the list is shown and
confirmed first. Nothing is read from the vault and no Touch ID is
needed.

--dry-run shows the list and stops. With --format json it prints
config and profiles (name, status, owners, adds).

```
jit profile attach <config> [profile]... [flags]
```

### Examples

```
  jit profile attach ~/code/myapp/.mcp.json
  jit profile attach ~/code/myapp/.mcp.json mcp-github
  jit profile attach --dry-run --format json ~/code/myapp/.mcp.json
```

### Options

```
      --dry-run         show what would be recorded; change nothing
      --format string   dry-run output format: "text" (default) or "json" (default "text")
  -y, --yes             skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit profile](jit_profile.md)	 - Write, edit, and delete profile manifests

