## jit migrate settings

Move the plain settings out of profiles protected before settings stayed plain

### Synopsis

Read every vault entry that came from a protected .env, and move the ones the scan
does not count as secrets (URLs, IDs, file names, flags) out of the vault into plain
settings beside it. Values the scan counts as secrets, and names that look like one,
stay in the vault. Files keep working; nothing needs a restart.

Judging a value means reading it, so this asks for Touch ID once, --dry-run included.

```
jit migrate settings [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json"; json needs --yes (default "text")
```

### Options inherited from parent commands

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,k8s-secret,shell,history,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc,pypirc,cargo,streamlit,loose,cache (default: all)
      --quiet          suppress the progress spinner/status trail (results still print)
  -y, --yes            skip the confirmation prompt and proceed immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

