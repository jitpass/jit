---
title: File locations
description: Where the vault, profiles, shims, and rewritten config files live on disk.
---

# File locations

## jit's own state

| Path | What it is |
|---|---|
| `~/Library/Application Support/jitpass/` | the vault - one encrypted file per secret, plus encrypted pre-migration file backups |
| macOS login Keychain | the vault's master encryption key (Touch ID/passcode gated), unless you moved it into the Secure Enclave |
| `~/Library/Application Support/jitpass/vault-key.sealed` | only when the vault's key is in the [Secure Enclave](../vault/secure-enclave.md): the master key, sealed so only this Mac's Secure Enclave can open it. Its presence is how jit knows where the key is |
| `~/Library/Application Support/jitpass/vault-key.sealed.lost` and `.lost.envelopes` | written by `jit vault init` when this Mac's Secure Enclave no longer has the vault's key: the old sealed key, set aside rather than deleted, and a record of which secrets were sealed to it. Renamed with a date once a [restore](../vault/secure-enclave.md#a-new-or-erased-mac) is done |
| `~/Library/Application Support/jitpass/vault-key.sealed.recovered-<time>` | the old sealed key, set aside when `jit vault init` found the same key still in your keychain and restored the vault from it |
| `~/Library/Application Support/jitpass/agent.sock` | the [background service](../service/index.md)'s socket - the one path a [sandboxed caller](../service/sandboxed-callers.md) has to be allowed to reach |
| `~/Library/Application Support/jitpass/jobs.json` | the approved [AI jobs](../service/ai-jobs.md): each job's command, folder, fingerprint and secret paths, and for a job that never asks its secrets' keys sealed under a key of its own, kept where the vault's key is (the keychain, or the Secure Enclave) - never a value or a plain key |
| `~/.jit/profiles/` | global [profile](../run/profiles.md) manifests (machine-wide migrations, `wrap-<tool>` profiles) |
| `<project>/.jit/profiles/` | project profile manifests - names and vault paths only, safe to commit |
| `<project>/.jit/config.yaml` | optional per-project settings, currently `read_as_file: true` to pin [`jit run`](../run/index.md) to live mode - safe to commit |
| `~/.jit/shims/` | PATH shims installed by [`jit wrap`](../wrap/index.md) |
| `~/.jit/guard.zsh` | the zsh history-guard hook installed by [`jit guard history`](./commands/jit_guard_history.md); `~/.zshrc` gains one line sourcing it |
| `~/Library/LaunchAgents/com.jitpass.agent.plist` | the launchd login item for the [background service](../service/index.md) |
| the `jit` binary itself | wherever you installed it (`which jit`) - e.g. `/usr/local/bin/jit` |

[`jit uninstall`](./commands/jit_uninstall.md) reverses all of the above
*except the vault*: it removes the service, shims, and binary but keeps
`~/Library/Application Support/jitpass/` and `~/.jit/` so your secrets
survive, printing where they are. `jit uninstall --purge` also erases the
vault and `~/.jit` (irreversible - `jit vault export` first). Either way it
requires a fresh Touch ID/passcode. The Keychain master key is released when
the vault is gone.

## Files jit rewrites (never owns)

| Path | After migration |
|---|---|
| `<project>/.jit/profiles/<name>.mount` | the project record for that manifest's [live mounts](../run/mounts.md) - relative paths only, no secret and no vault path, safe to commit. It is how jit recognises the project after the folder is renamed, moved or copied (see [`jit mount`](./commands/jit_mount.md)). Written by `jit migrate`; `jit mount record` backfills projects migrated before it existed |
| `<project>/.env` (and layers) | a [live mount](../run/mounts.md), read from the profile manifest in `<project>/.jit/profiles/` |
| `~/.zshrc` / `~/.bashrc` | export lines replaced with `eval "$(jit export --profile ...)"` |
| `~/.aws/config` | gains a `credential_process` line per migrated profile - and one per app captured by [`jit wrap clisso`](../wrap/clisso.md) |
| `~/.clisso.yaml` | each OneLogin provider's `client-secret` becomes a `jit://vault/` pointer; the real config is served over a pipe per run |
| `~/.kube/config` | the user entry gains an `exec` credential-plugin block |
| `~/.terraformrc` | gains a `credentials_helper` block |
| `~/.gitconfig` | `credential.helper` set to `jit` (the plaintext `store` helper removed); `~/.git-credentials` has its migrated logins stripped |
| `.npmrc` (project or `~`) | a live mount serving a template; non-secret lines untouched |
| `mcp.json` / Claude Desktop config / `~/.claude.json` | server `command` wrapped in `jit run` |
| per-tool CLI configs (`~/.config/gh/hosts.yml`, …) | token scrubbed by `jit wrap` - full list per tool in the [wrap catalog](../wrap/index.md) |
| `~/.zsh_history` / `~/.bash_history` / `$HISTFILE` / fish history | each recorded credential replaced in place by a `<jit:redacted:VAR>` marker naming the vault entry that now holds it; every other byte, your commands included, untouched |

Every rewrite is preceded by an encrypted byte-exact backup into the vault
([`jit migrate undo`](../migrate/undo-and-remove.md) restores it).
