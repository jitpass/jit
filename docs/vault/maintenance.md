---
title: Vault maintenance
description: Prune stale file backups, empty the vault, or destroy it entirely.
---

# Vault maintenance - `rekey`, `duplicates`, `prune`, `orphans`, `clean`, `delete`

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

## `jit vault duplicates` - find groups that hold the same secrets

Answers "which of these look-alike groups can I safely delete?" - the
question a listing can't, because it takes comparing the actual values.
It decrypts every stored secret in memory (nothing is printed or written),
then reports:

- **Duplicated groups**: the same key names migrated from the same file, or
  from two copies of it (a re-migrated project, a copied workspace tree).
  When the values still match, the report names the copy that looks stale
  and the command that retires it cleanly. Which command depends on whether
  the stale copy's file is still on disk:

  | The stale copy's origin file | Command | What it does |
  |---|---|---|
  | still there | [`jit migrate remove <file>`](../migrate/undo-and-remove.md) | un-migrates that one file: **writes its values back as plaintext**, then deletes its profile, its secrets and its backups. Delete the file or folder yourself afterwards if you don't want it. |
  | already gone, nothing references it | `jit vault duplicates --prune` | deletes those secrets for you (see below) |
  | gone, but a profile still names it | `jit vault rm <paths>` | deletes exactly those secrets, leaving you to fix the profile |

  `migrate remove` never deletes a secret another profile outside that
  project also references - it keeps and reports it - so retiring one copy
  cannot break a tool that shares the credential. Copies that have diverged
  (same ancestry, different values now) are reported without a removal pick:
  which copy is right is your call.
- **Shared credentials**: the same value stored by independent files, for
  example one API client used by five export scripts. These are *not* stale
  copies - removing any breaks its tool - and the report lists every place
  a rotation has to reach.

### Why it asks for Touch ID more than once

Comparing values means reading every secret, so this command unlocks the
vault **and** trips the
[per-process consent gate](../service/consent.md) once for each credential
*class* it touches (`aws`, `kube`, `git`, `shell_history`, and the rest -
`dotenv`, `mcp` and `manual` are not gated). A vault holding two gated
classes therefore prompts about three times: the unlock, plus one approval
per class. That is the consent feature doing its job, not a retry loop.
`jit service consent off` removes the per-class half.

### `--prune`

Reporting is the default. `jit vault duplicates --prune` deletes the one
shape that is pure vault garbage: a stale copy whose **origin file is gone
and which no profile references**. It confirms first (`-y` skips the
prompt) and requires a fresh Touch ID/passcode.

It deliberately will not touch the others, and says so instead of
reporting a clean sweep:

```
Deleted 2 duplicated secrets.

Left alone, 2 findings need a command only you should run:
  └ mcp-caido-2: jit migrate remove ~/Desktop/Share/ai_security_workspace/.mcp.json
  └ a, b: copies have diverged, compare them first
```

A copy whose file still exists has to be un-migrated by `jit migrate
remove`, which restores the plaintext, deregisters the mount and drops the
profile - deleting just its secrets would leave a live mount serving a file
nothing can fill. A copy some profile still names is a per-path decision.
Diverged copies and shared credentials are never jit's call.

Note the neighbouring commands delete different things under the same word:
`vault prune` deletes file *backups*, `vault orphans --prune` deletes
*unreferenced* secrets, and this deletes *duplicated* ones. Each
confirmation names its own.

`jit migrate` also discloses on the spot when a file it is migrating stores
values the vault already holds under another group.

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
