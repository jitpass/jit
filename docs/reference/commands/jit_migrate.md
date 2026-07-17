## jit migrate

Guided fix path for findings jit audit reports

### Synopsis

jit migrate moves the plaintext secrets jit audit finds into the encrypted
vault and rewrites each file so everything keeps working without the secret
sitting on disk. It's a separate command from jit audit, not a flag on it,
so the read-only scanner can never be turned into a mutating one by a
mistyped flag.

Pick a scope:

  jit migrate local   only what's under the current directory tree
                       (.env files, project mcp.json, project .npmrc)
  jit migrate home    the whole machine: everything local finds, anywhere
                       under $HOME, plus the machine-wide files that live at
                       fixed home paths (shell configs, ~/.aws/credentials,
                       ~/.kube/config, Terraform Cloud credentials, GCP
                       application-default credentials, Claude Desktop's MCP
                       config, the global ~/.npmrc)

Every run prints the full plan and asks for confirmation before touching
anything, and every modified file is backed up (encrypted, into the vault)
first, `jit migrate undo` restores any migrated file from that backup.
See each subcommand's --help for exactly what happens to each kind of file.

### Examples

```
  jit migrate local --dry-run    # preview this project's plan, change nothing
  jit migrate local              # fix this project
  jit migrate home --only aws,kube
  jit migrate undo               # restore migrated files from their backups
```

### Options

```
      --dry-run        preview the plan for this scope without changing anything
      --only strings   scope a run to just these comma-separated categories: env,shell,mcp,aws,kube,terraform,gcp,npmrc (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit migrate home](jit_migrate_home.md)	 - Convert findings anywhere under $HOME, the whole machine, not just this project
* [jit migrate local](jit_migrate_local.md)	 - Convert findings under the current directory only
* [jit migrate remove](jit_migrate_remove.md)	 - Remove jit from this project completely (restore plaintext, delete its secrets)
* [jit migrate undo](jit_migrate_undo.md)	 - Restore migrated files from their encrypted pre-migration backups

