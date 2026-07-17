## jit vault prune

Delete stale encrypted file backups, keeping each file's newest

### Synopsis

jit migrate backs a file up into the vault (under _backups/...) every time
it rewrites one, and `jit migrate undo` snapshots the pre-undo state too, so
repeated migrate/undo cycles accumulate backups indefinitely, nothing
expires them automatically, on purpose (a recovery snapshot silently aging
out is worse than a big vault). This prunes the accumulation: for every
file, the NEWEST backup, the one `jit migrate undo` would restore, is
kept, and every older one is permanently deleted.

Backups taken by jit builds before the undo index existed aren't touched
(they're invisible to undo but may be your only copy), see them with
`jit vault list --all` and delete by hand with `jit vault rm` if wanted.

```
jit vault prune [flags]
```

### Options

```
  -y, --yes   skip the confirmation prompt
```

### SEE ALSO

* [jit vault](jit_vault.md)	 - Manage the local encrypted secret vault

