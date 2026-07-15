---
title: Vault maintenance
description: Prune stale file backups, empty the vault, or destroy it entirely.
---

# Vault maintenance - `prune`, `clean`, `delete`

Three commands, in increasing order of severity. All confirm first
(`-y` skips the prompt).

## `jit vault prune` - delete stale file backups

Encrypted file backups accumulate by design: every `jit migrate` rewrite
stores one, and every `jit migrate undo` snapshots the pre-undo state too
(so an undo is itself undoable). Nothing expires them automatically. If
repeated migrate/undo cycles have grown the count past what you care to
keep (`jit vault list --all` shows them), `prune` deletes the stale ones
while keeping each file's newest backup, so
[`jit migrate undo`](../migrate/undo-and-remove.md) keeps working.

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
