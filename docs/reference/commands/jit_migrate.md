## jit migrate

Guided fix path for findings jit scan reports (name the file(s) to convert)

### Synopsis

jit migrate moves the plaintext secrets jit scan finds into the encrypted
vault and rewrites each file so everything keeps working without the secret
sitting on disk. It's a separate command from jit scan, not a flag on it,
so the read-only scanner can never be turned into a mutating one by a
mistyped flag.

You must name the file(s) and/or folder(s) to convert — jit migrate never
sweeps your whole machine on its own. Nothing is discovered or touched
except the targets you name, so a bare `jit migrate` with no path does
nothing. Each target is resolved on its own:

  A file       is routed to the right category by what it is. A project file
               (.env, *.tfvars, mcp.json/.mcp.json, .npmrc) has its secrets
               moved into a profile and the vault, the file keeps working as a
               live mount (a git-safe <file>.pointers companion is written
               alongside). A machine-wide file at a known path (a shell config
               like ~/.zshrc, ~/.aws/credentials, ~/.kube/config, Terraform
               Cloud creds, ~/.docker/config.json, ~/.git-credentials, GCP
               application-default credentials, a SOPS age key, ~/.netrc,
               Claude Desktop's MCP config, the global ~/.npmrc) is routed to
               that credential type's handling (credential_process, exec
               plugin, credential helper, or live mount, as appropriate).
  A directory  is walked for its .env/tfvars/mcp/npmrc findings only, never
               the machine-wide fixed-path files (those aren't "under" any
               project directory) — name them explicitly to convert them.

Targets are explicit, so nothing is skipped for looking archived/backup-like:
naming a file is itself the decision to convert it. Every run prints the full
plan and asks for confirmation before touching anything, and every modified
file is backed up (encrypted, into the vault) first, `jit migrate undo <path>`
restores a migrated file from that backup.

```
jit migrate <file-or-dir>...
```

### Examples

```
  jit migrate ~/proj/.env         # migrate just one file
  jit migrate ~/proj              # walk one project for .env/tfvars/mcp/npmrc
  jit migrate ~/.zshrc ~/proj/.env
  jit migrate ~/proj/.env --dry-run   # preview the plan, change nothing
  jit migrate ~/.aws/credentials --only aws
  jit migrate undo ~/proj/.env    # restore a migrated file from its backup
```

### Options

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,shell,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc,loose (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit migrate path](jit_migrate_path.md)	 - Alias for `jit migrate <file-or-dir>...`
* [jit migrate remove](jit_migrate_remove.md)	 - Remove jit from a project completely (restore plaintext, delete its secrets)
* [jit migrate undo](jit_migrate_undo.md)	 - Restore named migrated files from their encrypted pre-migration backups

