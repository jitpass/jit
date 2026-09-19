## jit profile adopt

Make an MCP config the owner of the profiles it launches

### Synopsis

Records <config> as an owner of every global profile it launches but
doesn't own: one whose owner file is gone, one with no owner at all, or
one another live config owns (both then own it). Owners whose file is
gone are dropped. Name profiles to adopt only those.

Owning a profile means `jit migrate remove` of that config's project
deletes it too, so the list is shown and confirmed first. Nothing is
read from the vault and no Touch ID is needed.

--dry-run shows the list and stops. With --format json it prints
config and profiles (name, status, owners, adds).

```
jit profile adopt <config> [profile]... [flags]
```

### Examples

```
  jit profile adopt ~/Security-Ops/.mcp.json
  jit profile adopt ~/Security-Ops/.mcp.json mcp-okta
  jit profile adopt --dry-run --format json ~/Security-Ops/.mcp.json
```

### Options

```
      --dry-run         show what would be adopted; change nothing
      --format string   dry-run output format: "text" (default) or "json" (default "text")
  -y, --yes             skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit profile](jit_profile.md)	 - Manage which configs own a profile, and delete one

