---
title: Vault maintenance
description: Prune stale file backups, empty the vault, or destroy it entirely.
---

# Vault maintenance - `rekey`, `prune`, `orphans`, `clean`, `delete`

These commands run in increasing order of severity. The destructive ones
confirm first (`-y` skips the prompt) and require a fresh Touch ID/passcode.

## `jit vault rekey` - rotate the master key

Generates a new master encryption key, re-wraps every stored secret's key
under it (live secrets, file backups, and archived versions - the encrypted
values themselves are never touched), then replaces the old master key. One
Touch ID/passcode approval covers the whole run.

Run it if the old key may have been exposed, or simply on a schedule - the
master key otherwise never changes for its whole life. Safe to interrupt at
any point: both keys exist until the final step, every re-wrapped secret is
verified before it's written, re-running `jit vault rekey` finishes an
interrupted rotation, and other vault commands refuse to write while one is
in progress.

## `jit vault prune` - delete stale file backups

Encrypted file backups accumulate by design: every `jit migrate` rewrite
stores one, and every `jit migrate undo` snapshots the pre-undo state too
(so an undo is itself undoable). Nothing expires them automatically. If
repeated migrate/undo cycles have grown the count past what you care to
keep (`jit vault list --all` shows them), `prune` deletes the stale ones
while keeping each file's newest backup, so
[`jit migrate undo`](../migrate/undo-and-remove.md) keeps working.

## `jit vault orphans` - find and delete secrets nothing references

Lists every stored secret that no profile jit can see points at, grouped by
path with each secret's recorded origin. These are the leftovers a path-only
[`jit migrate undo`/`remove`](../migrate/undo-and-remove.md) can leave behind
once the profile that named a secret is gone. By default it only lists them;
`--prune` deletes them, after a confirmation and a fresh Touch ID/passcode.

"Referenced" is judged against every profile jit can see: the project-local
(current directory) and global profile stores, plus the profile behind every
registered mount. A secret used only by another project you are not in and
have not mounted would look orphaned here, so check each secret's origin
before pruning, or delete just one with `jit vault rm <path>`.

## `jit vault clean` - delete every secret

Empties the vault - every secret gone - but the vault itself stays set up
(the master key survives, so `jit vault set` works immediately after).
Note that profiles and mounts referencing the deleted secrets will fail
until re-populated; `jit doctor` will list what's missing.

## `jit vault delete` - destroy the vault

Permanently destroys the whole vault **including its encryption key**.
Nothing is recoverable afterwards short of a
[passphrase-encrypted export](./backup-restore.md) you made earlier. If
the goal is "remove jit from this project," you want
[`jit migrate remove`](../migrate/undo-and-remove.md) instead - it puts
plaintext back before deleting the project's secrets.
