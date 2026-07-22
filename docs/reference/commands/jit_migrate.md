## jit migrate

Guided fix path for findings jit scan reports

### Synopsis

jit migrate moves the plaintext secrets jit scan finds into the encrypted
vault and rewrites each file so everything keeps working without the secret
sitting on disk. It's a separate command from jit scan, not a flag on it,
so the read-only scanner can never be turned into a mutating one by a
mistyped flag.

By default it covers the same ground jit scan scans, the whole machine:
`jit migrate` is `jit migrate home`. Narrow the scope with a subcommand:

  jit migrate local   only what's under the current directory tree
                       (.env files, tfvars files, project mcp.json, project .npmrc)
  jit migrate home    the default: everything local finds, anywhere
                       under $HOME, plus the machine-wide files that live at
                       fixed home paths (shell configs, ~/.aws/credentials,
                       ~/.kube/config, Terraform Cloud credentials,
                       ~/.docker/config.json registry logins,
                       ~/.git-credentials HTTPS logins, GCP
                       application-default credentials, Claude Desktop's MCP
                       config, the global ~/.npmrc)
  jit migrate path    only the specific file(s)/folder(s) you name, with no
                       directory walk (e.g. one project's .env, a single
                       ~/.zshrc). The fast choice when a home sweep would
                       take too long and you already know what to move

Every run prints the full plan and asks for confirmation before touching
anything, and every modified file is backed up (encrypted, into the vault)
first, `jit migrate undo` restores any migrated file from that backup.
See each subcommand's --help for exactly what happens to each kind of file.

```
jit migrate [flags]
```

### Examples

```
  jit migrate --dry-run          # preview the whole-machine plan, change nothing
  jit migrate                    # fix everything the plan shows
  jit migrate local --dry-run    # preview just this project's plan
  jit migrate home --only aws,kube
  jit migrate path ~/proj/.env   # migrate just one file, no walk
  jit migrate undo               # restore migrated files from their backups
```

### Options

```
      --dry-run            preview the plan for this scope without changing anything
      --include-archived   also convert findings under an archived/backup-looking directory (archive, archived, backup, backups, .trash)
      --only strings       scope a run to just these comma-separated categories: env,tfvars,shell,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc (default: all)
  -y, --yes                skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit migrate home](jit_migrate_home.md)	 - Convert findings anywhere under $HOME, the whole machine, not just this project
* [jit migrate local](jit_migrate_local.md)	 - Convert findings under the current directory only
* [jit migrate path](jit_migrate_path.md)	 - Convert only the specific file(s)/folder(s) you name, no directory walk
* [jit migrate remove](jit_migrate_remove.md)	 - Remove jit from this project completely (restore plaintext, delete its secrets)
* [jit migrate undo](jit_migrate_undo.md)	 - Restore migrated files from their encrypted pre-migration backups

