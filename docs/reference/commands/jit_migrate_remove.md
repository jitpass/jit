## jit migrate remove

Remove jit from this project completely (restore plaintext, delete its secrets)

### Synopsis

jit migrate remove takes jit back out of the current project: every live
mount and pointer file under this directory tree becomes a plain file
again, and any server in the project's own mcp.json/.mcp.json launching
through jit gets its plaintext env block back (all written from the
CURRENT vault values, so edits made with `jit vault set` since migration
are kept), and then the project's profile manifests — including the ones
created for this project's MCP servers — the vault secrets they
reference, the project's encrypted file backups, any reveal hooks
migrate wired into .envrc/package.json, and the .jit/ directory itself
are all deleted.

Machine-level migrations (shell configs, AWS, kubeconfig, Terraform
Cloud, GCP application-default credentials, the global ~/.npmrc,
Claude Desktop's MCP config) are not touched — they aren't part of any
one project; reverse those with `jit migrate undo`.

A vault secret also referenced by a profile OUTSIDE this project is
kept (and reported), never deleted out from under the other profile.

This both writes real secret values back to disk in PLAINTEXT and
permanently deletes them from the vault, so it always requires its own
Touch ID/passcode approval — a running agent session is deliberately
not enough.

```
jit migrate remove [flags]
```

### Options

```
  -y, --yes   skip the confirmation prompt and remove immediately
```

### Options inherited from parent commands

```
      --dry-run        preview the plan for this scope without changing anything
      --only strings   scope a run to just these comma-separated categories: env,shell,mcp,aws,kube,terraform,gcp,npmrc (default: all)
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit audit reports

