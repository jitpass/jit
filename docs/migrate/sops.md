---
title: Migrating the SOPS age key
description: The age private key leaves keys.txt for the vault; sops, kluctl, Flux, and helm-secrets keep working via a live mount or sops's own key-command hook.
---

# SOPS (age key)

Teams that keep secrets SOPS-encrypted in git (kluctl, Flux, helm-secrets)
all rely on one file per laptop: the age private key, usually at
`~/.config/sops/age/keys.txt` or its macOS sibling under
`~/Library/Application Support/sops/age/`. That one plaintext line
decrypts every SOPS-encrypted secret in every repo the key guards, for
every environment those repos cover. It is the single highest-value
target on a machine that uses SOPS.

`jit migrate home` (category `sops`) moves the key into the vault and
replaces `keys.txt` with a [live mount](../run/mounts.md) serving a
template: the non-secret comment lines (public key, creation date) pass
through byte-for-byte, and the key line fills from the vault only for a
run you explicitly grant it to with `jit run --with sops`. The age key is a
machine-wide credential, so it is never granted by a project's config, only
by a `--with` you type.

## Two ways tools get the key back

**sops v3.10+ can skip the file entirely.** sops's `SOPS_AGE_KEY_CMD`
hook runs a command to fetch the key on demand, the same shape as AWS's
`credential_process`:

```sh
export SOPS_AGE_KEY_CMD="jit sops-age-key"
```

Every `sops -d` then pulls the key straight from the vault (agent
session, or a Touch ID prompt), no key file read at all.

**Everything else reads the mounted file.** Tools whose embedded sops
predates the hook (older kluctl builds, other readers of `keys.txt`) keep
reading the same path; grant them the key for the run with `--with sops`:

```sh
jit run --with sops -- kluctl deploy -t prod
```

The grant is scoped to that run's process tree and gone when it exits.
`jit run` also injects `SOPS_AGE_KEY` into the child environment, which
current sops and kluctl prefer over the key file, so either mechanism
alone is enough. To keep typing a tool directly (no `jit run` prefix),
`jit wrap add <tool> --grant sops` installs a shim that grants the key
per invocation.

## What to expect

- Outside a run you granted the key to, a reader of `keys.txt` sees a
  placeholder and decryption fails fast with a clear error, exactly the
  decoy-by-default behavior `.env` mounts have.
- The file is machine-wide (one per user), so it's covered by
  `jit migrate home` only, `local` never touches it.
- Files holding **multiple** age keys are skipped, never half-migrated:
  one `SOPS_AGE_KEY` variable can't serve two keys. The audit finding
  stays visible instead.
- Rotating: generate a new key, update the vault path shown by
  `jit profile show sops-age`, and re-encrypt your repos against the new
  recipient.

`jit sops-age-key` is the [plumbing command](../reference/plumbing.md)
`SOPS_AGE_KEY_CMD` invokes - you never run it by hand. Reversing:
`jit unmount <path>` writes the file back plain, or [`jit migrate
undo`](./undo-and-remove.md) restores the original bytes.
