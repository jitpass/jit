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

## Scope: you name what to convert

`jit migrate` never sweeps your machine on its own. You point it at the
file(s) and/or folder(s) to convert, and nothing else is discovered or
touched:

```
jit migrate ~/code/myapp/.env      # one file
jit migrate ~/code/myapp           # walk one project for .env/tfvars/mcp/npmrc
jit migrate ~/.zshrc ~/code/myapp  # several targets at once
```

Each target is resolved on its own:

- **A file** is routed to the right category by what it is. A project file
  (`.env`, `*.tfvars`, `mcp.json`/`.mcp.json`, `.npmrc`) has its secrets
  moved into a profile and the vault, and the file keeps working. A
  machine-wide file at a known path - a shell config like `~/.zshrc`,
  `~/.aws/credentials`, `~/.kube/config`, the Terraform Cloud token file,
  `~/.docker/config.json`, `~/.git-credentials`, GCP application-default
  credentials, the SOPS age key, `~/.netrc`, Claude Desktop's MCP config,
  the global `~/.npmrc` - is routed to that credential type's handling.
- **A directory** is walked for its `.env`/tfvars/`mcp.json`/`.npmrc`
  findings only, never the machine-wide fixed-path files (those aren't
  "under" any project directory - name them explicitly to convert them).

Targets are explicit, so nothing is skipped for looking archived or
backup-like: naming a file is itself the decision to convert it. A missing
path or a symlink fails loud rather than migrating the wrong thing. A bare
`jit migrate` with no path does nothing.

!!! tip "Find what to name"
    Run [`jit scan`](../audit/index.md) first - it lists every plaintext
    secret on the machine, so you know exactly which files to hand to
    `jit migrate`. `jit migrate path <file-or-dir>...` is a spelled-out
    alias of the bare `jit migrate <file-or-dir>...` form, kept for
    scripts and muscle memory.

## Always preview first

`--dry-run` runs the exact same discovery a real run would, so the preview
is accurate:

```
$ jit migrate ~/code/myapp/.env --dry-run
jit migrate, plan
Each modified file is backed up before it's rewritten.

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

[DRY RUN] No files were changed. Run without --dry-run to apply this plan.
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

Limit a run to specific categories with `--only`
(`jit migrate ~/code/myapp --only=env,aws`):

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
| `loose` | a bare token in a plain file you named (a JWT in `token.txt`) that matches no format above | the value moves to the vault and the file is replaced with a git-safe pointer; retrieve with `jit vault get`. Only when the whole file is the token, a token mixed with other content is left in place | |

The `loose` category never appears on its own, only when you explicitly name
such a file: `jit migrate token.txt`. It is the migrate counterpart to `jit
scan`'s Exposed Secrets finding.

CLI tool tokens (`gh`, `stripe`, `ngrok`, …) live in their own config files
that `migrate` doesn't cover - that's [`jit wrap`](../wrap/index.md)'s job.

## Leaving is as easy as arriving

`jit migrate undo` restores files, `jit unmount` turns one live mount back
into a plain file, and `jit migrate remove` is the full exit from a
project. All three in **[Undo, unmount, and remove](./undo-and-remove.md)**.
