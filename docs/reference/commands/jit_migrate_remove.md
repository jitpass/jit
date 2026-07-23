## jit migrate remove

Remove jit from a project completely (restore plaintext, delete its secrets)

### Synopsis

jit migrate remove takes jit back out of a project you name: every live
mount and pointer file under that project tree becomes a plain file
again, and any server in the project's own mcp.json/.mcp.json launching
through jit gets its plaintext env block back (all written from the
CURRENT vault values, so edits made with `jit vault set` since migration
are kept), and then the project's profile manifests, including the ones
created for this project's MCP servers, the vault secrets they
reference, the project's encrypted file backups, and the .jit/ directory
itself are all deleted.

You must name the project to remove; a bare `jit migrate remove` with no
path does nothing. Name a FOLDER to remove that project, or name any
FILE inside a project (e.g. its .env) and jit resolves up to the .jit/
project that owns it and removes the whole thing. Name several to remove
several, each confirmed on its own.

Machine-level migrations (shell configs, AWS, kubeconfig, Terraform
Cloud, GCP application-default credentials, the global ~/.npmrc,
Claude Desktop's MCP config) are not touched, they aren't part of any
one project; reverse those with `jit migrate undo`.

A vault secret also referenced by a profile OUTSIDE this project is
kept (and reported), never deleted out from under the other profile.

This both writes real secret values back to disk in PLAINTEXT and
permanently deletes them from the vault, so it always requires its own
Touch ID/passcode approval, a running service session is deliberately
not enough.

```
jit migrate remove <file-or-dir>... [flags]
```

### Examples

```
  jit migrate remove ~/proj
  jit migrate remove ~/proj/.env   # removes the whole ~/proj project
```

### Options

```
  -y, --yes   skip the confirmation prompt and remove immediately
```

### Options inherited from parent commands

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,shell,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc (default: all)
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

