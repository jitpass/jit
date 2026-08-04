## jit migrate path

Alias for `jit migrate <file-or-dir>...`

### Synopsis

Alias for `jit migrate <file-or-dir>...` — see `jit migrate --help`.

```
jit migrate path <file-or-dir>... [flags]
```

### Options

```
      --mount   for a loose secret file, keep it live at its path as a mount (real value to jit run grants, a decoy otherwise) instead of replacing it with a pointer; also required to protect a file that mixes a secret with other content
```

### Options inherited from parent commands

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,k8s-secret,shell,history,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc,pypirc,loose (default: all)
      --quiet          suppress the progress spinner/status trail (results still print)
  -y, --yes            skip the confirmation prompt and proceed immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

