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

## `jit migrate undo [path...]` - restore from backup, byte-for-byte

Restores migrated files, of any category, from their encrypted
pre-migration backups. No path means everything; a file restores that
file; a directory restores everything under it. The vault stays untouched.

An undo is itself undoable: every `jit migrate undo` snapshots the
pre-undo state too. Backups accumulate by design and nothing expires them
automatically - [`jit vault prune`](../vault/maintenance.md) cleans up
stale ones while keeping each file's newest.

## `jit migrate remove` - the full exit from a project

Run from the project, this removes jit completely: every file back to
plaintext, plus the project's profiles, vault secrets, encrypted backups,
reveal hooks, and `.jit/` directory all deleted.

## All three always re-authenticate

Each of these asks for its own fresh Touch ID/passcode approval, even with
the agent unlocked: putting secrets back on disk should never happen
silently on a cached session.

For wrapped CLI tools, the equivalent is
[`jit wrap undo <tool>`](../wrap/troubleshooting.md).
