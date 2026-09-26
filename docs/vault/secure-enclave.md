---
title: The vault key in the Secure Enclave
description: Keep the vault's master key in your Mac's Secure Enclave - moving it in and back, the recovery file, and what to do on a new or erased Mac.
---

# The vault key in the Secure Enclave

Every secret in the vault is encrypted under one master key. By default that
key is in your login keychain. jit asks for Touch ID before each use, but
that check is jit's own: a program running as you that can read the keychain
item could skip it.

The Secure Enclave is the chip in your Mac that holds keys and never lets
them out. Move the vault key there and it is stored sealed to an enclave
key: opening it takes Touch ID or your password, and the enclave enforces
that, not jit. Only JitPass's signed helper, the `jit` inside JitPass.app,
can use it, and no other program running as you can read it.

It is opt-in and off by default. It needs an Apple Silicon Mac and the
JitPass app.

What does not change: while the vault is unlocked, the background service
holds the key in memory for the session, exactly as before, and the idle
timeout, screen lock and sleep still end that session.

## Before you move: a recovery file

A key in the Secure Enclave can't leave this Mac. No backup, copy or
Migration Assistant run carries it. If this Mac is lost, replaced or erased,
a recovery file is how your secrets come back.

So jit refuses the move until you have a recovery file newer than your
newest secret:

```sh
jit vault export ~/jit-recovery.json
```

Keep the file, and its passphrase, somewhere other than this Mac. Add or
change a secret later and the file is out of date: export again. More in
[Back up and restore](./backup-restore.md).

## Moving the key in

In JitPass, open **Settings › Protection** and choose **Move to Secure
Enclave…** on the Vault key row. The sheet shows your recovery file and can
save a new one.

In a terminal:

```sh
jit vault rekey --wrapper secure-enclave
```

You approve two dialogs: one to read the key from your keychain, and one
from the Secure Enclave to prove the sealed copy opens. Only then is the
keychain copy deleted.

The key itself does not change, only where it is kept, so nothing is
re-encrypted. Standing grants and AI jobs keep working, and their own keys
follow the next time the background service starts, with no prompt and no
re-approval. On a vault whose key is in the Secure Enclave, those keys are
enclave keys too. They open without Touch ID, because your approval was the
decision, and they work while the Mac is locked, so a job that never asks
still runs while you are away.

If a move is interrupted, run the same command again to finish it. Until it
finishes, commands that change the vault refuse.

## Moving it back

In JitPass, open the **···** menu on the Vault key row and choose **Move
Back to Keychain…**. In a terminal:

```sh
jit vault rekey --wrapper keychain
```

The key is a login-keychain item again, where a program running as you
could read it. Your secrets, grants and AI jobs stay as they are.

## Only the jit inside JitPass.app

The Secure Enclave only answers a program signed with JitPass's permission
to use it: the `jit` inside JitPass.app. A `jit` installed any other way
(the release tarball, `go install`, a build of your own) can't move the key.
On a vault whose key is in the Secure Enclave it can't open the vault at
all, and it never falls back to the keychain. It says:

```
this copy of jit can't use the Secure Enclave; use the jit inside JitPass.app
```

Run the `jit` from JitPass.app instead. `which jit` shows which one your
shell finds first.

## A new or erased Mac

The enclave key stays with the Mac that made it. On a new Mac, or this one
after it was erased, the secrets come back from your recovery file.

**The vault folder did not come along.** Set up a vault and import:

```sh
jit vault init
jit vault import ~/jit-recovery.json
```

**The vault folder came along** (Migration Assistant, or a Time Machine
restore). jit finds a sealed key this Mac's Secure Enclave doesn't have, and
`jit doctor` says the vault key is not in this Mac's Secure Enclave. Run the
same two commands: `jit vault init` sets the old sealed key aside (renamed,
never deleted) and makes a new key in your keychain, then
`jit vault import <file>` brings the secrets back. In JitPass,
**Restore from Recovery File…** on the Vault key row does both.

Until every secret sealed to the old key is back, jit keeps track of them
and `jit doctor` reports them (`vault_restore`, below). If you have imported
every recovery file you have and jit can't check what is left (its record of
them is unreadable), stop the tracking yourself:

```sh
jit vault import --finish
```

It lists the secrets that may still not open, asks first, and keeps the old
key's files under a dated name.

Standing grants and AI jobs that never ask used keys in the old Mac's
Secure Enclave, and those stayed behind too. Make those grants again, and
approve your AI jobs again.

The new vault's key is in your keychain. Save a new recovery file, then move
it into the Secure Enclave again whenever you like.

## What `jit doctor` may report

| Finding | What it means | Fix |
|---|---|---|
| `vault_move` | A move of the vault key did not finish. Every command that changes the vault refuses until it does. | Run the same move again: `jit vault rekey --wrapper secure-enclave` or `--wrapper keychain`, as doctor names it. In JitPass, **Finish Move** on the Vault key row. |
| `rekey_unknown` | A change of the vault key is unfinished, and this version of jit can't read its marker file or doesn't know the change (a newer jit started it). Every command that changes the vault refuses. | Update jit, then finish it with the newer jit. If the file can't be read, make it readable again. No command of this jit would work. |
| `vault_key_copy` | The key is in the Secure Enclave, but a key is still in your keychain under the vault key's name, usually the copy a move could not delete. The vault opens fine, but any program running as you can read that key. | `jit vault rekey --wrapper secure-enclave` removes it when it is the same key. If it isn't this vault's key, or can't be read, the command says why and leaves it alone. |
| `vault_restore` | Some secrets are sealed to a key this Mac no longer has, so they can't be opened. | `jit vault import <file>` from a recovery file. If doctor says it couldn't check, `jit vault import --finish` once every recovery file is imported. |
| `vault_key` | The vault holds secrets, but its key is not in this Mac's Secure Enclave, so none of them can be opened. | `jit vault init`, then `jit vault import <file>` (see [A new or erased Mac](#a-new-or-erased-mac)). |

`jit status` shows the same states on its `key` row, and
`jit status --format json` reports where the key is kept as
`vault.key_store`: `"keychain"` or `"secure-enclave"`.

## Where the files are

The sealed key is `vault-key.sealed` in the vault folder,
`~/Library/Application Support/jitpass/`. Its presence is how every jit
knows the vault's key is in the Secure Enclave. The full list is in
[File locations](../reference/file-locations.md).
