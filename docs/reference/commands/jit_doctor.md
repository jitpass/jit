## jit doctor

One-shot health check: profiles, secrets, service, backup, and wrap shims

### Synopsis

jit doctor is the single "what's wrong" rollup for a jit setup. Its core
job: verify that every secret path a profile references actually exists in
the vault AND that its envelope is one this build of jit can read, failing
fast with a named problem instead of letting an app crash later on an empty
environment variable or a value that won't decrypt. It never decrypts a
value (existence and envelope structure are both plaintext on disk), so it
never needs local authentication and is safe to run often.

By default it checks every profile visible from the current directory: both
project-local ones under .jit/profiles/ and the home-rooted global ones
jit migrate writes for shell-config/MCP/AWS/kubeconfig/npmrc secrets,
the same set `jit profile list` shows. It also folds in the health checks
that used to take `jit status` and `jit wrap doctor` to see: the background
service, your vault backup, and any wrapped-tool shims.

It exits non-zero only when a profile's secret is missing, corrupt, or
unparseable. Everything else it reports is an advisory warning, never a
failure: an orphaned secret (with --orphans), a profile name shadowed
across scopes, a stopped service, a stale or missing vault backup, a broken
shim. Use --profile to narrow the run to a single profile (the system-
health sections are skipped then), --verbose to list every reference it
cleared, and --format json for a machine-readable snapshot.

```
jit doctor [flags]
```

### Options

```
      --format string    output format: "text" (default) or "json" (default "text")
      --orphans          also warn about vault secrets no profile references (advisory, never a failure)
      --profile string   check only this profile, and skip the service/backup/wrap health sections
      --verbose          on success, list every variable→path reference that was checked
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

