---
title: Undo, unmount, and remove
description: Every jit change is reversible - restore single files, whole trees, or exit a project completely.
---

# Undo, unmount, and remove

Before any file is rewritten, its exact original bytes are backed up,
encrypted, into the vault. That makes three levels of "put it back"
possible, from mildest to total:

## `jit unmount <path>` - one live mount back to a plain file

Decrypts the vault values and writes them out as a regular plain file
again. The vault secrets and profile stay put - you're only choosing to
have this one file on disk in plaintext again.

## `jit migrate undo <path>...` - restore from backup, byte-for-byte

Restores migrated files, of any category, from their encrypted
pre-migration backups. You name what to restore: a file restores that
file, a directory restores everything recorded under it. The vault stays
untouched. A bare `jit migrate undo` with no path does nothing.

Files deleted by [`jit migrate --clean`](./index.md#finishing-deletions---clean)
restore the same way: the plan labels them "deleted by jit migrate
--clean, will be re-created", and the restore brings the file back
byte-for-byte, permissions included.

```
jit migrate undo ~/code/myapp/.env   # one file
jit migrate undo ~/code/myapp        # everything migrated under a project
jit migrate undo ~                   # everything anywhere, in one go
```

With [shell completion](../getting-started/install.md#shell-completion)
installed, `jit migrate undo <TAB>` lists exactly the files that have a
restorable backup, plus each one's parent directory, so you never have to
guess which paths are in play. Add `--dry-run` to preview the plan first.

An undo is itself undoable: every `jit migrate undo` snapshots the
pre-undo state too. Backups accumulate by design and nothing expires them
automatically - [`jit vault prune`](../vault/maintenance.md) cleans up
stale ones while keeping each file's newest.

When an undone file was a **loose secret** (a bare `token.txt` migrated on its
own), its dedicated vault secret is unshared and has no further use once the
file is back, so undo ends by pointing you at the one command that clears it
too: `jit migrate remove <file>` (below).

!!! note "Shell history"
    Undo restores a redacted history file byte-for-byte, like any other
    category. `jit migrate remove` does **not** cover history: the vaulted
    credentials stay, which is usually what you want, since they are now the
    only copy of a value you may still need to rotate. Delete them by hand
    with `jit vault rm zsh_history/<VAR>` once you have.

## `jit migrate remove <file-or-dir>...` - the full exit from a project

Removes jit completely from a project you name: every file back to
plaintext, plus the project's profiles, vault secrets, encrypted backups,
and `.jit/` directory all deleted. Name the project **folder**, or name any
**file inside it** (its `.env`, say) and jit resolves up to the project
that owns it and removes the whole thing:

```
jit migrate remove ~/code/myapp        # the folder is the project
jit migrate remove ~/code/myapp/.env   # removes the whole ~/code/myapp project
```

A bare `jit migrate remove` with no path does nothing.

### Removing a loose secret

A **loose secret** migrated on its own (a bare `token.txt`, no project of its
own) has no project to tear down - its profile lives in the home-level global
store alongside every machine-level migration. Naming it removes just **that
one file's** footprint: its plaintext back on disk, then its dedicated profile,
vault secret(s), and backup deleted. Nothing else in the global store is
touched.

```
jit migrate remove ~/token.txt   # removes just that loose secret
```

Because that global store is not a project, `jit migrate remove` will never
escalate a loose file to it, and naming your home directory itself is refused
outright - it would otherwise read as "remove every migration at once."

The vault secrets it deletes are not only the ones a profile references: any
migrated secret whose recorded origin falls inside the project tree is swept
out too, so secrets stranded by an earlier `undo` (their profile already gone)
don't linger. A secret another profile or mount still references is always
kept. For orphaned secrets that a project removal can't reach - older ones with
no recorded origin, or ones tied to no single project - use
[`jit vault orphans`](../vault/maintenance.md).

### undo vs. remove

| | `jit migrate undo` | `jit migrate remove` |
|---|---|---|
| File contents | exact original bytes from the pre-migration **backup** | current **vault values** written back as plaintext |
| The vault | **kept** - secrets and profiles stay | **deleted** - profiles, secrets, backups, and `.jit/` erased |
| Reversibility | itself undoable | **permanent** |

(For a loose secret's pointer file, `remove` restores the exact original bytes
from the backup rather than the vault values - a bare token file would otherwise
come back reshaped as `KEY=value` lines.)

## All three always re-authenticate - and it's logged

`jit unmount`, `jit migrate undo`, and `jit migrate remove` each force
their own fresh Touch ID/passcode approval on **every** invocation, even
with the service unlocked - never a cached session. Putting secrets back on
disk in plaintext, or deleting them outright, should never happen silently
on an unlock some other process is riding. Each run also records that a
fresh fingerprint gated it in the application audit log, visible as `auth=`
in [`jit audit`](../service/provenance.md), so the trail proves a live approval
stood behind every restore and removal.

For wrapped CLI tools, the equivalent is
[`jit wrap undo <tool>`](../wrap/troubleshooting.md).
