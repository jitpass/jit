---
title: Migrating secrets
description: jit migrate - move plaintext secrets into the vault and rewrite each file so tools keep working.
---

# Migrating secrets - `jit migrate`

`migrate` is the guided fix for what [`jit audit`](../audit/index.md)
finds: it moves each secret into the vault and rewrites the consuming file
via that tool's own native mechanism, so everything keeps working. It's a
separate command from `audit`, deliberately: a read-only scanner can never
be turned into a mutating one by a mistyped flag.

## Pick a scope: `local` or `home`

**`jit migrate local`** only ever touches what's under the directory you're
standing in - one project.

**`jit migrate home`** covers everything under `$HOME`: every project's
`.env`/`mcp.json`/`.npmrc`, plus the machine-wide files that have no
project-scoped form at all - shell configs, `~/.aws/credentials`,
`~/.kube/config`, the Terraform Cloud token file, Claude Desktop's MCP
config, and the global `~/.npmrc`. The plan groups those under a separate
"Machine-wide" section so it's clear they're not part of a directory walk.

`home` skips anything under a directory named `archive`, `archived`,
`backup`, `backups`, or `.trash` by default (pass `--include-archived` to
override): converting a forgotten project's `.env` into a live mount
nothing will ever read again makes it *less* recoverable, not more secure.
`local` never applies this filter; deliberately standing in an old project
and migrating it is an explicit choice.

## Always preview first

`--dry-run` runs the exact same discovery a real run would, so the preview
is accurate:

```
$ cd ~/code/myapp
$ jit migrate local --dry-run
jit migrate - plan (local scope)
Each modified file is backed up before it's rewritten.

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

[DRY RUN] No files will be changed. Run without --dry-run to apply this plan.
```

Then apply it by dropping `--dry-run`. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation; answering `y` triggers the vault writes
(one Touch ID prompt if the agent isn't unlocked yet). Declining aborts
with nothing changed.

## The safety model

Before any file is rewritten, its exact original bytes are backed up,
encrypted, into the vault. [`jit migrate undo`](./undo-and-remove.md)
restores them byte-for-byte at any point later.

If a file being migrated has ever been committed to git, `migrate` warns
explicitly: it never scrubs git history, so the old value is still
recoverable via `git log -p` no matter what happens going forward - rotate
that credential.

## What each category turns into

Limit either scope to specific categories with `--only`
(`jit migrate home --only=env,aws`):

| `--only` | Vault gets | The original file becomes | Guide |
|---|---|---|---|
| `env` | one secret per variable | a live-mounted named pipe, plus a git-safe `.env.pointers` companion | [.env files](./env-files.md) |
| `shell` | one secret per `export KEY=value` line | the export line replaced with `eval "$(jit export --profile ...)"` | [Shell configs](./shell-configs.md) |
| `mcp` | one secret per server's env-block value | the server's `command` rewritten to launch via `jit run` | [MCP / AI tools](./mcp.md) |
| `aws` | the profile's access key/secret/session token | a `credential_process` line in `~/.aws/config`; no file with the real value at all | [AWS](./aws.md) |
| `kube` | the user's bearer token or cert/key pair | an `exec` block calling jit (client-go's exec-plugin protocol) | [Kubernetes](./kubernetes.md) |
| `terraform` | each host's API token | a `credentials_helper` wired into `~/.terraformrc` | [Terraform](./terraform.md) |
| `npmrc` | just the secret lines (`_authToken`, etc.) | a live-mounted pipe serving a template; everything else untouched | [npm](./npm.md) |

GCP application-default credentials are detected by `audit` but have no
migrate path yet.

CLI tool tokens (`gh`, `stripe`, `ngrok`, …) live in their own config files
that `migrate` doesn't cover - that's [`jit wrap`](../wrap/index.md)'s job.

## Leaving is as easy as arriving

`jit migrate undo` restores files, `jit unmount` turns one live mount back
into a plain file, and `jit migrate remove` is the full exit from a
project. All three in **[Undo, unmount, and remove](./undo-and-remove.md)**.
