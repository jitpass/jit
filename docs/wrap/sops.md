---
title: Wrap sops with jit
description: jit wrap sops runs every sops invocation inside jit run --with sops, so the age private key reaches sops from the vault's live mount and never sits in keys.txt.
---

# sops - Mozilla SOPS (grant shim)

sops reads its age private key from a file (`~/.config/sops/age/keys.txt`
or `$SOPS_AGE_KEY_FILE`). [Migrating that file](../migrate/sops.md) moves
the key into the vault and leaves the path as a live mount that serves a
decoy by default; the real key is served only to a process that holds a
grant on it.

`jit wrap sops` is the shim that takes the grant for you:

```sh
jit migrate ~/.config/sops/age/keys.txt   # once: key into the vault, file becomes a mount
jit wrap sops                             # shim: `sops` now runs jit run --with sops
sops --decrypt secrets.enc.yaml           # as before; the shim grants the real key
```

Each invocation runs `jit run --with sops -- sops ...`: the mount is granted
to that one process under a disclosed Touch ID naming the credential, and
the grant ends with the process. Outside the shim, a reader of `keys.txt`
gets a decoy that fails to decrypt anything.

The wrap injects no environment variables and changes nothing about how
sops is configured. Tools that call sops themselves (kluctl, helm-secrets,
Flux's decryption) reach the real key when they run under the wrapped
`sops` or inside `jit run --with sops`.

## Verify

```sh
sops --decrypt <an encrypted file>
```

Through the wrapped sops this decrypts; `cat ~/.config/sops/age/keys.txt`
still shows the decoy.

## Undo

`jit wrap undo sops` removes the shim; `jit run --with sops -- sops ...`
still works and the mount keeps serving decoys by default. To put the
plaintext key back, use [`jit migrate undo`](../migrate/undo-and-remove.md).
