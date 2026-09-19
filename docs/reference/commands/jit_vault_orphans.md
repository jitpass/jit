## jit vault orphans

List (and with --prune delete) secrets no profile references

### Synopsis

Lists every stored secret that no profile jit can currently see points at,
grouped by path with each secret's recorded origin: the leftovers a
path-only `jit migrate undo`/`remove` leaves in the vault once the profile
that named them is gone. With --prune, they are permanently deleted after a
[y/N] confirmation and a fresh Touch ID/passcode.

"Referenced" is judged against everything jit can find: the current
directory's profile store, the global one, every project store under your
home folder, the profile behind every registered mount, and pointer files
(jit's own in-place pointer files and ~/.clisso.yaml). A file among those
that can't be read stops the command instead of making its secrets look
orphaned. A project outside your home folder is not searched, so check each
secret's origin before pruning.

A registered mount whose profile is gone — a project directory deleted
without `jit unmount` first — is reported as a stale mount registration,
and --prune clears it too (a registry edit; no secret value is touched).

```
jit vault orphans [flags]
```

### Options

```
      --format string   output format: "text" (default) or "json" (each orphan with its recorded origin) (default "text")
      --prune           delete the orphaned secrets (default: only list them)
  -y, --yes             with --prune, skip the confirmation prompt
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

