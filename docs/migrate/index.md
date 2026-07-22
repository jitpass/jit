---
title: Migrating secrets
description: jit migrate - move plaintext secrets into the vault and rewrite each file so tools keep working.
---

# Migrating secrets - `jit migrate`

`migrate` is the guided fix for what [`jit scan`](../audit/index.md)
finds: it moves each secret into the vault and rewrites the consuming file
via that tool's own native mechanism, so everything keeps working. It's a
separate command from `audit`, deliberately: a read-only scanner can never
be turned into a mutating one by a mistyped flag.

## Scope: the whole machine by default

**`jit migrate`** covers the same ground `jit scan` scans - everything
under `$HOME`. That's deliberate: audit's report is machine-wide, so the
command it points you at fixes machine-wide too, no scope decision in
between. It's shorthand for `jit migrate home`: every project's
`.env`/tfvars/`mcp.json`/`.npmrc`, plus the machine-wide files that have
no project-scoped form at all - shell configs, `~/.aws/credentials`,
`~/.kube/config`, the Terraform Cloud token file, Docker registry logins
in `~/.docker/config.json`, git HTTPS logins in `~/.git-credentials`, GCP
application-default credentials, the SOPS age key, `~/.netrc`, Claude
Desktop's MCP config, and the global `~/.npmrc`. The plan groups those under a separate "Machine-wide" section
so it's clear they're not part of a directory walk.

**`jit migrate local`** narrows to one project: only what's under the
directory you're standing in is discovered or touched.

**`jit migrate path <file-or-dir>...`** narrows further still: it converts
only the specific file(s) and folder(s) you name, with no directory walk
beyond a named folder itself. Reach for it when a home sweep of a large
`$HOME` would take too long and you already know which secret you want
moved - one project's `.env`, a single `~/.zshrc`, a directory of tfvars
files. A named project file (`.env`/tfvars/`mcp.json`/`.npmrc`) migrates
exactly as `local` would; a named machine-wide file at a known path (a
shell config like `~/.zshrc`, `~/.aws/credentials`, `~/.kube/config`, and
the rest of the machine-wide list above) routes to that category's `home`
handling; a named directory is walked like `local` rooted there, project
files only. Targets are explicit, so the archived filter doesn't apply -
naming a file is itself the decision to convert it. A missing path or a
symlink fails loud rather than migrating the wrong thing.

A home-scope run skips anything under a directory named `archive`,
`archived`, `backup`, `backups`, or `.trash` by default (pass
`--include-archived` to override): converting a forgotten project's `.env`
into a live mount nothing will ever read again makes it *less*
recoverable, not more secure. Skipped paths are listed at the end of the
plan, and `jit scan` tags the same findings `[archived]`, so the two
reports always agree on what was left alone. `local` never applies the
filter; deliberately standing in an old project and migrating it is an
explicit choice.

## Always preview first

`--dry-run` runs the exact same discovery a real run would, so the preview
is accurate:

```
$ jit migrate --dry-run
jit migrate - plan (home scope)
Each modified file is backed up before it's rewritten.

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

[DRY RUN] No files will be changed. Run without --dry-run to apply this plan.
```

Then apply it by dropping `--dry-run`. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation; answering `y` triggers the vault writes
(one Touch ID prompt if the service isn't unlocked yet). Declining aborts
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
| `tfvars` | one secret per variable, stored as `TF_VAR_<name>` | the secret lines deleted; terraform reads them back as `TF_VAR_` env vars via `jit run` | [Terraform tfvars](./tfvars.md) |
| `shell` | one secret per `export KEY=value` line | the export line replaced with `eval "$(jit export --profile ...)"` | [Shell configs](./shell-configs.md) |
| `mcp` | one secret per server's env-block value | the server's `command` rewritten to launch via `jit run` | [MCP / AI tools](./mcp.md) |
| `aws` | the profile's access key/secret/session token | a `credential_process` line in `~/.aws/config`; no file with the real value at all | [AWS](./aws.md) |
| `kube` | the user's bearer token or cert/key pair | an `exec` block calling jit (client-go's exec-plugin protocol) | [Kubernetes](./kubernetes.md) |
| `terraform` | each host's API token | a `credentials_helper` wired into `~/.terraformrc` | [Terraform](./terraform.md) |
| `docker` | each registry's username + password/token | a credential helper wired into `~/.docker/config.json`; `docker login`/`logout` keep working | [Docker](./docker.md) |
| `git` | each host's username + password/token | `credential.helper` set to jit (the plaintext `store` helper replaced); `git push`/`fetch` over HTTPS keep working | [git](./git.md) |
| `gcp` | the ADC refresh token (or service account private key) | a live-mounted pipe serving a template; non-secret fields untouched | [GCP](./gcp.md) |
| `sops` | the SOPS age private key | a live-mounted pipe serving a template; sops v3.10+ can also fetch the key via `SOPS_AGE_KEY_CMD` | [SOPS](./sops.md) |
| `npmrc` | just the secret lines (`_authToken`, etc.) | a live-mounted pipe serving a template; everything else untouched | [npm](./npm.md) |
| `netrc` | every `password` value in `~/.netrc` | a live-mounted pipe serving a template; `machine`/`login` lines and macdef scripts untouched | [netrc](./netrc.md) |

CLI tool tokens (`gh`, `stripe`, `ngrok`, …) live in their own config files
that `migrate` doesn't cover - that's [`jit wrap`](../wrap/index.md)'s job.

## Leaving is as easy as arriving

`jit migrate undo` restores files, `jit unmount` turns one live mount back
into a plain file, and `jit migrate remove` is the full exit from a
project. All three in **[Undo, unmount, and remove](./undo-and-remove.md)**.
