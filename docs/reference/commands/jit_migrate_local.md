## jit migrate local

Convert findings under the current directory only

### Synopsis

Converts findings under the current directory tree ONLY, nothing outside
the project you're standing in is discovered or touched. Machine-wide files
(shell configs, AWS, kubeconfig, Terraform Cloud, Docker registry logins,
GCP application-default credentials, Claude Desktop's config, the global
~/.npmrc) live at fixed paths under $HOME, so only `jit migrate home` ever
includes them.

What happens per category:

  .env files   Keys move into a profile and the vault; the file itself keeps
               working as a live mount served by jit agent, showing
               fake-looking values until revealed (`jit agent reveal`, wired
               automatically into an existing .envrc or package.json
               dev/start script when one exists). A git-safe <file>.pointers
               companion is written alongside, listing vault paths only,
               always safe to open or commit.
  tfvars       Secret-shaped `name = "value"` assignments in terraform.tfvars
               and *.auto.tfvars move into the vault, one profile per directory.
               Terraform reads them back as TF_VAR_ environment variables when
               you run it through jit: `jit run --profile <p> -- terraform apply`.
  MCP configs  Each server's env-block secrets move into the vault, and the
               server's command is rewritten to launch via `jit run`.
  .npmrc       Secret lines move into the vault; the file keeps working as a
               live mount, with non-secret settings preserved verbatim.

Migrating never scrubs git history: a value that was ever committed stays
recoverable via `git log -p` regardless, jit warns per file instead of
implying "migrated = safe".

```
jit migrate local
```

### Examples

```
  jit migrate local --dry-run
  jit migrate local --only env
```

### Options inherited from parent commands

```
      --dry-run        preview the plan for this scope without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,shell,mcp,aws,kube,terraform,docker,gcp,sops,npmrc (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit audit reports

