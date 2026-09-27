## jit migrate preview

Show where each .env variable would go, before anything moves

### Synopsis

Show, for each named .env, which variables would go to the vault and which would stay as
plain settings, and for each MCP config, the .env files it reads. Nothing is read from
the vault and nothing changes. Setting values are shown; secrets never are.

```
jit migrate preview <file>... [flags]
```

### Options

```
      --format string         output format: "json" (required) (default "text")
      --secret stringArray    as jit migrate's --secret
      --setting stringArray   as jit migrate's --setting
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

