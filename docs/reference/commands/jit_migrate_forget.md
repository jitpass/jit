## jit migrate forget

Delete a pointer file nothing uses any more

### Synopsis

Deletes a jit pointer file (a `.pointers` companion, or a file jit
rewrote in place) that no longer refers to anything: no registered
mount serves it, and the vault holds nothing under the group it
names. These are what a renamed or never-restored vault group leaves
behind, and `jit doctor` reports them as [stale pointers].

It refuses any file that fails those tests, so it cannot delete a
live mount's companion or a file jit did not write. Nothing else is
touched: no profile, no mount, no secret. Compare `jit migrate
remove`, which takes a whole project back out of jit.

No value is read, so no Touch ID is needed.

```
jit migrate forget <pointer file>... [flags]
```

### Examples

```
  jit migrate forget ~/code/myapp/.env.pointers
  jit migrate forget --dry-run ~/code/myapp/.env.pointers
```

### Options

```
      --dry-run   show what would be deleted; change nothing
  -y, --yes       skip the confirmation prompt
```

### Options inherited from parent commands

```
      --only strings   scope a run to just these comma-separated categories: env,tfvars,k8s-secret,shell,history,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc,pypirc,cargo,streamlit,loose,cache (default: all)
      --quiet          suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

