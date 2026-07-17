## jit migrate home

Convert findings anywhere under $HOME, the whole machine, not just this project

### Synopsis

Converts findings anywhere under $HOME, the whole machine, not just this
project. Covers everything `jit migrate local` does (see its --help for the
per-category detail), discovered across every project under $HOME, plus the
machine-wide files that live at fixed home paths:

  Shell configs    Secret-shaped `export KEY=value` lines in .zshrc/.bashrc/
                   etc. move into the vault; the file loads them back via
                   `eval "$(jit export --profile ...)"` instead.
  AWS              ~/.aws/credentials profiles move into the vault; the AWS
                   CLI/SDK fetches them live via a credential_process line
                   in ~/.aws/config, no keys on disk at all.
  kubeconfig       A user's bearer token or client-certificate pair moves
                   into the vault; kubectl fetches it via an exec block.
  Terraform Cloud  ~/.terraform.d/credentials.tfrc.json tokens move into the
                   vault; terraform fetches them through its own
                   credentials-helper protocol (`terraform login`/`logout`
                   keep working). Fails loud, before touching anything, if a
                   different credentials helper is already configured.
  GCP              ~/.config/gcloud/application_default_credentials.json's
                   refresh token (or a service account key's private key)
                   moves into the vault; the file keeps working as a live
                   mount, Google SDKs read the same path, non-secret fields
                   preserved verbatim. (GCP has no AWS-style
                   credential_process hook for these credential types, so
                   the mount is what keeps SDKs working with no key on disk.)
  Claude Desktop's MCP config and the global ~/.npmrc get the same
  treatment as project MCP configs and .npmrc files.

Skips anything under an archived/backup-looking directory (archive,
archived, backup, backups, .trash) unless --include-archived: converting a
forgotten project's .env into a live mount nobody will ever serve again
would make it unreadable, which is worse than plaintext.

```
jit migrate home [flags]
```

### Examples

```
  jit migrate home --dry-run
  jit migrate home --only aws,kube
  jit migrate home --include-archived
```

### Options

```
      --include-archived   also convert findings under an archived/backup-looking directory (archive, archived, backup, backups, .trash)
```

### Options inherited from parent commands

```
      --dry-run        preview the plan for this scope without changing anything
      --only strings   scope a run to just these comma-separated categories: env,shell,mcp,aws,kube,terraform,gcp,npmrc (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit audit reports

