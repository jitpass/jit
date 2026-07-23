## jit migrate undo

Restore named migrated files from their encrypted pre-migration backups

### Synopsis

jit migrate undo puts back what jit migrate rewrote, using the encrypted
backup every category stores in the vault before touching a file:
.env live mounts become plain files again, rewritten shell configs/
MCP configs/AWS files/kubeconfigs/npmrc files get their exact original
bytes back. You must name what to restore: a file path restores just
that file, a DIRECTORY path restores every migrated file recorded under
that tree, so you can undo a single project without disturbing anything
migrated elsewhere. A bare `jit migrate undo` with no path does nothing.

A file that can't be restored (its backup was cleaned from the vault, a
symlink reappeared at the path, …) is reported and skipped, the rest
still restore, and the command exits non-zero if any file failed, so a
single missing backup never silently aborts the whole batch partway.

What it does per file: if the file is a registered live mount, the
running service stops serving it first (other mounts are undisturbed), the
registry entry and the .pointers companion are removed, then the backed-
up content is written back. The current content is snapshotted into the
vault before being overwritten, so an undo is itself undoable, nothing
is ever simply destroyed.

What it deliberately does NOT do: vault secrets and profile manifests
stay (`jit migrate remove` deletes a project's completely).

Like every restore-to-plaintext operation, this writes real secret
values back to disk, it prints the full plan and confirms first
(--yes skips, --dry-run previews only).

To see every restorable file first, run `jit migrate undo <dir> --dry-run`
(e.g. your $HOME). Backups made by jit builds before this command existed
aren't in its index, restore those by hand: `jit vault list` (look under
_backups/) + `jit vault get <path>`.

```
jit migrate undo <path>...
```

### Examples

```
  jit migrate undo ~/proj/.env    # restore one migrated file
  jit migrate undo ~/proj         # restore everything migrated under a project
  jit migrate undo ~/proj --dry-run
```

### Options inherited from parent commands

```
      --dry-run        preview the plan without changing anything
      --only strings   scope a run to just these comma-separated categories: env,tfvars,shell,mcp,aws,kube,terraform,docker,git,gcp,sops,npmrc,netrc (default: all)
  -y, --yes            skip the confirmation prompt and migrate immediately
```

### SEE ALSO

* [jit migrate](jit_migrate.md)	 - Guided fix path for findings jit scan reports (name the file(s) to convert)

