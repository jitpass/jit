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
plus the profile behind every registered mount — which may live in a project
tree this directory never walks into, yet is being served right now. That is
the same set `jit status --secrets` and `jit vault orphans` reconcile. It also
folds in the health checks that used to take `jit status` and `jit wrap doctor`
to see: the background service, your vault backup, and any wrapped-tool shims.

It exits non-zero when a secret this setup depends on cannot be read: a
profile's secret missing, corrupt, or unparseable, or the whole vault
unreadable because this Mac's master key is gone from the keychain or a
master-key rotation never finished. Everything else it reports is an
advisory warning, never a failure: an orphaned secret (with --orphans), a
profile name shadowed across scopes, a mount whose profile won't load, a
stopped service, a stale or missing vault backup, a broken shim.

Use --profile to narrow the run to a single profile. The service, backup and
shim sections are skipped then; the whole-vault key checks are not, because
with no master key no profile resolves and saying otherwise would be false.
--verbose lists every reference it cleared, and --format json prints a
machine-readable snapshot.

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

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

