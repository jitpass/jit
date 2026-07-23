## jit vault orphans

List (and with --prune delete) secrets no profile references

### Synopsis

Lists every stored secret that no profile jit can currently see points at,
grouped by path with each secret's recorded origin: the leftovers a
path-only `jit migrate undo`/`remove` leaves in the vault once the profile
that named them is gone. With --prune, they are permanently deleted after a
[y/N] confirmation and a fresh Touch ID/passcode.

"Referenced" is judged against every profile jit can see: the project-local
(current directory) and global profile stores, plus the profile behind every
registered mount. A secret used ONLY by a different project you're not in and
haven't mounted would look orphaned here, so check each secret's origin
before pruning, and delete a single one with `jit vault rm <path>` if unsure.

```
jit vault orphans [flags]
```

### Options

```
      --prune   delete the orphaned secrets (default: only list them)
  -y, --yes     with --prune, skip the confirmation prompt
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

