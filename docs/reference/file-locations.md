---
title: File locations
description: Where the vault, profiles, shims, and rewritten config files live on disk.
---

# File locations

## jit's own state

| Path | What it is |
|---|---|
| `~/Library/Application Support/jitpass/` | the vault - one encrypted file per secret, plus encrypted pre-migration file backups |
| macOS login Keychain | the vault's master encryption key (Touch ID/passcode gated) |
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
| `<project>/.env` (and layers) | a [live mount](../run/mounts.md), with a `.env.pointers` companion beside it |
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
