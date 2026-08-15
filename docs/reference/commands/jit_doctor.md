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
folds in the health checks that used to take `jit status` and the retired
`jit wrap doctor` to see: the background service, your vault backup, and
every wrapped tool's shim, PATH entry and profile.

It exits 2 when something this setup depends on is actually broken: a
secret missing, corrupt, or unparseable; the whole vault unreadable
because this Mac's master key is gone from the keychain or a master-key
rotation never finished; or a wrapped tool's installation damaged, which
means that tool now runs unwrapped or not at all. Everything else it
reports is an advisory warning: orphaned secrets no profile references
(a count by default; --orphans lists each, `jit vault orphans` adds
origins and can prune), vault groups that look like the same file stored
twice (name-level evidence only — `jit vault duplicates` compares the
values, which doctor never decrypts), a referenced secret whose recorded
origin file is gone from disk, a profile name shadowed across scopes, a
mount whose profile won't load or whose project was deleted without
unmounting, a stopped service, a stale or missing vault backup, more than one jit
installed on PATH (a Homebrew copy and a tarball copy each answering to
the name, with which copy runs decided by PATH order), and any shim
complaint that is only true of the shell you happen to be in — a CI job
that doesn't put the shim dir on PATH is not a broken machine. --strict
makes those count too.

Exit 2 is the FINDINGS code, matching `jit scan --fail-on`; exit 1 means
doctor itself couldn't run (a bad flag, an unreadable vault root), which a
pipeline needs to tell apart from a machine that is genuinely broken.

Use --profile to narrow the run to a single profile. The service, backup and
shim sections are skipped then; the whole-vault key checks are not, because
with no master key no profile resolves and saying otherwise would be false.
Use --wrap for the shim check on its own — it never opens the vault, so it
still works when the vault is the thing that's broken. --verbose lists every
check that passed, not just the ones that failed, and --format json prints a
machine-readable snapshot.

```
jit doctor [flags]
```

### Examples

```
  jit doctor
  jit doctor --verbose --orphans   # also what passed, and each unreferenced secret
  jit doctor --wrap                # only the shims, no vault access
  jit doctor --strict              # advisory warnings gate too, for CI
```

### Options

```
      --format string          output format: "text" (default) or "json" (default "text")
      --orphans                list each unreferenced vault secret; without it the count alone is reported
      --profile string         check only this profile, and skip the service/backup/wrap health sections
      --strict                 exit non-zero on advisory warnings too, for a pipeline that wants them to gate
      --verbose                also list every check that passed, not just the ones that failed
      --wrap jit wrap doctor   check only the wrapped-tool shims, without opening the vault (replaces jit wrap doctor)
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime

