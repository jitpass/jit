## jit migrate path

Convert only the specific file(s)/folder(s) you name, no directory walk

### Synopsis

Converts only the exact file(s) and/or folder(s) you name, nothing else is
discovered or touched. Use this when a `jit migrate home` sweep of a large
$HOME would take too long and you already know which secret you want moved:
a single project's .env, one ~/.zshrc, a directory of tfvars files.

Each target is resolved on its own:

  A file       is routed to the right category by what it is. A project file
               (.env, *.tfvars, mcp.json/.mcp.json, .npmrc) migrates exactly as
               `jit migrate local` would migrate it. A machine-wide file at a
               known path (a shell config like ~/.zshrc, ~/.aws/credentials,
               ~/.kube/config, Terraform Cloud creds, ~/.docker/config.json,
               ~/.git-credentials, GCP application-default credentials, a SOPS
               age key, ~/.netrc, Claude Desktop's MCP config, the global
               ~/.npmrc) is routed to that category's `home` handling.
  A directory  is walked like `jit migrate local` rooted at that directory:
               its .env/tfvars/mcp/npmrc findings only, never the machine-wide
               fixed-path files (those aren't "under" any project directory).

Unlike `jit migrate home`, path targets are explicit, so nothing is skipped
for looking archived/backup-like. Naming a file is itself the decision to
convert it. The per-category outcome (live mount, exec plugin, credential
helper, ...) is identical to the other scopes; see `jit migrate local --help` and
`jit migrate home --help` for the detail. Every run still prints the full
plan and asks for confirmation, backs each file up into the vault first, and
is reversible with `jit migrate undo`.

```
jit migrate path <file-or-dir>...
```

### Examples

```
  jit migrate path ~/proj/.env
  jit migrate path ~/.zshrc ~/proj/.env
  jit migrate path ~/proj/config --dry-run
  jit migrate path ~/.aws/credentials --only aws
```

### Options inherited from parent commands

```
      --dry-run        preview the plan for this scope without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,shell,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports

