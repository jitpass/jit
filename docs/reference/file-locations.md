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
| `~/.jit/shims/` | PATH shims installed by [`jit wrap`](../wrap/index.md) |

## Files jit rewrites (never owns)

| Path | After migration |
|---|---|
| `<project>/.env` (and layers) | a [live mount](../run/mounts.md), with a `.env.pointers` companion beside it |
| `~/.zshrc` / `~/.bashrc` | export lines replaced with `eval "$(jit export --profile ...)"` |
| `~/.aws/config` | gains a `credential_process` line per migrated profile |
| `~/.kube/config` | the user entry gains an `exec` credential-plugin block |
| `~/.terraformrc` | gains a `credentials_helper` block |
| `.npmrc` (project or `~`) | a live mount serving a template; non-secret lines untouched |
| `mcp.json` / Claude Desktop config | server `command` wrapped in `jit run` |
| per-tool CLI configs (`~/.config/gh/hosts.yml`, …) | token scrubbed by `jit wrap` - full list per tool in the [wrap catalog](../wrap/index.md) |

Every rewrite is preceded by an encrypted byte-exact backup into the vault
([`jit migrate undo`](../migrate/undo-and-remove.md) restores it).
