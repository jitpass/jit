## jit migrate undo

Restore migrated files from their encrypted pre-migration backups

### Synopsis

jit migrate undo puts back what jit migrate rewrote, using the encrypted
backup every category stores in the vault before touching a file:
.env live mounts become plain files again, rewritten shell configs/
MCP configs/AWS files/kubeconfigs/npmrc files get their exact original
bytes back. With no argument it restores EVERY file with a recorded
backup (each to its most recent one). Pass one or more paths to scope
it: a file path restores just that file, a DIRECTORY path restores every
migrated file recorded under that tree — so you can undo a single project
without disturbing anything migrated elsewhere.

A file that can't be restored (its backup was cleaned from the vault, a
symlink reappeared at the path, …) is reported and skipped — the rest
still restore, and the command exits non-zero if any file failed, so a
single missing backup never silently aborts the whole batch partway.

What it does per file: if the file is a registered live mount, the
running agent stops serving it first (other mounts are undisturbed), the
registry entry and the .pointers companion are removed, then the backed-
up content is written back. The current content is snapshotted into the
vault before being overwritten, so an undo is itself undoable — nothing
is ever simply destroyed.

It also reverses the `jit agent reveal` hook migrate wired into a
mount's .envrc/package.json — surgically, removing only jit's own
marked command for the mount being restored, so a script you edited
yourself is never touched and another mount's hook is left intact. Once
a hook file has no jit command left, its .jit-bak backup is cleaned up.

What it deliberately does NOT do: vault secrets and profile manifests
stay (`jit migrate remove` deletes a project's completely).

Like every restore-to-plaintext operation, this writes real secret
values back to disk — it prints the full plan and confirms first
(--yes skips, --dry-run previews only).

Backups made by jit builds before this command existed aren't in its
index — restore those by hand: `jit vault list` (look under _backups/)
+ `jit vault get <path>`.

```
jit migrate undo [path...]
```

### Options inherited from parent commands

```
      --dry-run        preview the plan for this scope without changing anything
      --only strings   scope a run to just these comma-separated categories: env,shell,mcp,aws,kube,terraform,gcp,npmrc (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit audit reports

