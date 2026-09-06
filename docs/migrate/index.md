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

## Scope: everything the scan found, or exactly what you name

`jit migrate` runs in one of two modes:

**Bare `jit migrate`** protects everything the machine-wide scan judged
protectable. It runs the same scan `jit scan` runs, prints the full plan -
every file it will rewrite and every CLI it will wrap - and asks `[y/N]`
before touching anything. It is exactly the command the scan report's
"jit will protect these" section points at: the manifest you saw there is
the plan you confirm here. Catalog wraps run as part of the plan, each
printing its `jit wrap undo <tool>` line as it happens.

If the scan found a credential in your shell history, the plan also offers
the [history guard](./shell-history.md#stopping-the-next-one) - a zsh hook
that keeps future credential-carrying commands out of the file entirely.
It is announced above the plan, so the same `[y/N]` covers it, and it is
offered only when that finding exists, only on zsh, and only if it is not
already installed. Reverse it with `jit guard history --remove`.

**With arguments**, nothing is discovered or touched except the targets
you name:

```
jit migrate                        # protect everything the scan found
jit migrate ~/code/myapp/.env      # one file
jit migrate ~/code/myapp           # walk one project for .env/tfvars/mcp/npmrc
jit migrate ~/.zshrc ~/code/myapp  # several targets at once
```

Each named target is resolved on its own:

- **A file** is routed to the right category by what it is. A project file
  (`.env`, `*.tfvars`, `mcp.json`/`.mcp.json`, `.npmrc`,
  `.streamlit/secrets.toml`) has its secrets
  moved into a profile and the vault, and the file keeps working. A
  machine-wide file at a known path - a shell config like `~/.zshrc`, a shell
  history file like `~/.zsh_history`, `~/.aws/credentials`, `~/.kube/config`, the Terraform Cloud token file,
  `~/.docker/config.json`, `~/.git-credentials`, `~/.cargo/credentials.toml`,
  GCP application-default
  credentials, the SOPS age key, `~/.netrc`, `~/.pypirc`, Claude Desktop's MCP config,
  Claude Code's `~/.claude.json`, the global `~/.npmrc`,
  `~/.streamlit/secrets.toml` - is routed to that credential type's handling.
- **A directory** is walked for its
  `.env`/tfvars/`mcp.json`/`.npmrc`/`.streamlit/secrets.toml`
  findings only, never the machine-wide fixed-path files (those aren't
  "under" any project directory - name them explicitly to convert them).

Named targets are explicit, so nothing is skipped for looking archived or
backup-like: naming a file is itself the decision to convert it. (Bare
`jit migrate` is the opposite: it skips archived/backup directories and
files that mix secrets with other content, exactly as the scan report
says it will.) A missing path or a symlink fails loud rather than
migrating the wrong thing.

!!! tip "Find what to name"
    Run [`jit scan`](../audit/index.md) first - its green section is the
    bare `jit migrate` plan, and its red section names what only you can
    fix. Hand specific files to `jit migrate <path>` when you want a
    narrower run. `jit migrate path <file-or-dir>...` is a spelled-out
    alias of the `jit migrate <file-or-dir>...` form, kept for scripts
    and muscle memory.

## Always preview first

`--dry-run` runs the exact same discovery a real run would, so the preview
is accurate:

```
$ jit migrate ~/code/myapp/.env --dry-run
[DRY RUN] Preview, this run changes nothing; the plan below is what a real run would do.

jit migrate, plan
Each modified file is backed up before it's rewritten.

Project files you named

[.env file] 1
  → EVERY variable moves to the vault (ordinary config too, so the file still works); the file keeps working as a live, auto-updating mount
  • ~/code/myapp/.env (3 variables, 2 secret-shaped)

────────────────────────────────────────────
  1 change planned across 1 category

[DRY RUN] Apply this plan: jit migrate ~/code/myapp/.env
This only covers what jit migrate can act on; run jit scan for the complete
picture, including findings it can never auto-fix, like private keys.
```

The plan is complete: everything the run will do appears as a counted
category — including CLI wraps, the shell history guard, and AI-agent
cache files holding copies of the values being vaulted, when those
apply. The closing line is your own command minus `--dry-run`, ready to
paste.

Then apply it by running that command. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation; answering `y` triggers the vault writes
(one Touch ID prompt if the service isn't unlocked yet). Declining aborts
with nothing changed.

`jit wrap <tool>`, `jit wrap undo <tool>`, and `jit guard history` take
`--dry-run` too, with the same banner-and-trailer frame.

## The safety model

Before any file is rewritten, its exact original bytes are backed up,
encrypted, into the vault. [`jit migrate undo`](./undo-and-remove.md)
restores them byte-for-byte at any point later.

If a file being migrated has ever been committed to git, `migrate` warns
explicitly: it never scrubs git history, so the old value is still
recoverable via `git log -p` no matter what happens going forward - rotate
that credential.

If a file stores a value the vault already holds under another profile -
the same API client used by several scripts, or a workspace folder you
copied and migrated twice - `migrate` says so on the result line and keeps
going. The copy is stored normally under its own profile, because merging
them would mean one `rm` later breaking every tool that shares it.
[`jit vault duplicates`](../vault/maintenance.md#jit-vault-duplicates---find-groups-that-hold-the-same-secrets)
compares the values and says which copies, if any, are safe to retire.

If the [1Password CLI](../vault/1password.md) is installed and signed
in, migrate also checks each value against your 1Password (once per
run, after you confirm): a value already stored there is vaulted as an
`op://` reference instead of a copy, so rotating it in 1Password is the
only rotation you do. `--no-1password` stores plain copies instead.

## Finishing deletions: `--clean`

Some findings' stated fix is deletion, not migration: a credential file
sitting in the Trash, an archived/backup copy of a secret you already
vaulted, a stray copy in an AI agent's file cache. `jit migrate --clean`
finishes those deletions for you, after the migrations, under a whitelist
it can prove safe:

- **Trash copies** - you already decided the file should not exist;
  vaulting it would preserve what deletion is about to fix, so jit
  finishes the deletion. No vault check needed.
- **Archived/backup copies** - deleted only after *every* secret in the
  file is verified byte-identical to a value already in your vault. The
  delete pass runs after the migrations, so a live `.env` vaulted in the
  same run already proves its archived siblings redundant - one command
  fixes both.
- **AI agent cache leftovers** (pasted text, shell snapshots, agent-made
  backups) - same vault verification.

Nothing else is ever touched: private keys, history lines, and any file
whose secrets can't all be verified stay put, listed with the reason and
the next step. A file that changed between the plan and the delete is
left alone too.

The deletions appear in the plan as their own counted `[deletions]`
category (`--dry-run` shows it, no authentication needed). Applying them
takes two more gates than a migration: a dedicated `y/N` that lists every
path, then a fresh Touch ID/passcode that even `--yes` never skips.

Every deleted file is first backed up, encrypted, into the vault -
[`jit migrate undo <path>`](./undo-and-remove.md) re-creates it exactly,
permissions included. The deletion is final for everyone except you.

Naming a delete-class file explicitly changes its routing:
`jit migrate ~/.Trash/old/.env` (no flag) vaults it, because naming a
file is the decision to convert it - but the same command with `--clean`
finishes its deletion instead, because that is what the flag asks for.

## What each category turns into

Limit a run to specific categories with `--only`
(`jit migrate ~/code/myapp --only=env,aws`):

| `--only` | Vault gets | The original file becomes | Guide |
|---|---|---|---|
| `env` | one secret per variable | a live-mounted named pipe, plus a git-safe `.env.pointers` companion | [.env files](./env-files.md) |
| `tfvars` | one secret per variable, stored as `TF_VAR_<name>` | the secret lines deleted; terraform reads them back as `TF_VAR_` env vars via `jit run` | [Terraform tfvars](./tfvars.md) |
| `shell` | one secret per `export KEY=value` line | the export line replaced with `eval "$(jit export --profile ...)"` | [Shell configs](./shell-configs.md) |
| `history` | one secret per distinct credential recorded in a shell history file (`~/.zsh_history`, `~/.bash_history`, `$HISTFILE`, fish) | every occurrence of the value replaced in place by a `<jit:redacted:VAR>` marker naming the vault entry; the command line itself, and every other byte of the file, untouched | [Shell history](./shell-history.md) |
| `mcp` | one secret per server's env-block value | the server's `command` rewritten to launch via `jit run` | [MCP / AI tools](./mcp.md) |
| `aws` | the profile's access key/secret/session token | a `credential_process` line in `~/.aws/config`; no file with the real value at all | [AWS](./aws.md) |
| `kube` | the user's bearer token or cert/key pair | an `exec` block calling jit (client-go's exec-plugin protocol) | [Kubernetes](./kubernetes.md) |
| `k8s-secret` | one secret per `data:`/`stringData:` value, stored as the base64 string the manifest carries | a live-mounted pipe serving the manifest with placeholders; `jit run -- kubectl apply` gets real values, anything else gets decoys that are never valid base64, so an apply outside jit fails loudly | [Kubernetes Secret manifests](./kubernetes-secret-manifests.md) |
| `terraform` | each host's API token | a `credentials_helper` wired into `~/.terraformrc` | [Terraform](./terraform.md) |
| `docker` | each registry's username + password/token | a credential helper wired into `~/.docker/config.json`; `docker login`/`logout` keep working | [Docker](./docker.md) |
| `git` | each host's username + password/token | `credential.helper` set to jit (the plaintext `store` helper replaced); `git push`/`fetch` over HTTPS keep working | [git](./git.md) |
| `gcp` | the ADC refresh token (or service account private key) | a live-mounted pipe serving a template; non-secret fields untouched | [GCP](./gcp.md) |
| `sops` | the SOPS age private key | a live-mounted pipe serving a template; sops v3.10+ can also fetch the key via `SOPS_AGE_KEY_CMD` | [SOPS](./sops.md) |
| `npmrc` | just the secret lines (`_authToken`, etc.) | a live-mounted pipe serving a template; everything else untouched | [npm](./npm.md) |
| `netrc` | every `password` value in `~/.netrc` | a live-mounted pipe serving a template; `machine`/`login` lines and macdef scripts untouched | [netrc](./netrc.md) |
| `pypirc` | every repository section's `password` in `~/.pypirc` | a live-mounted pipe serving a template; `[distutils]`, `repository` and `username` lines untouched | [PyPI](./pypi.md) |
| `cargo` | each registry's publish token in `~/.cargo/credentials.toml` | a credential provider wired into `~/.cargo/config.toml`; `cargo login`/`logout` keep working, no file with the real value at all | [Cargo](./cargo.md) |
| `streamlit` | every credential-shaped value in a `.streamlit/secrets.toml` (project or global) | a live-mounted pipe serving a template; table headers and connection settings untouched | [Streamlit](./streamlit.md) |
| `loose` | secrets in a plain file you named that matches no format above: a bare token (a JWT in `token.txt`), and any secret-shaped `key = value` assignment (`db_password = ...`) whose value isn't obviously a setting | by default (whole-file token) the value moves to the vault and the file is replaced with a git-safe pointer; retrieve with `jit vault get`. With `--mount`, or for a token mixed with other content, the file stays live at its path as a mount (a template with `${VAR}` placeholders) serving the real value to `jit run` grants and a decoy otherwise | |

The `loose` category never appears on its own, only when you explicitly name
such a file: `jit migrate token.txt`. It is the migrate counterpart to `jit
scan`'s Exposed Secrets finding.

**`--mount`** keeps a loose file live at its path instead of neutralizing it,
for the case where a program actually reads that path at runtime (getting the
real value only under a [`jit run`](../service/index.md) grant, a decoy
otherwise). It is also required to migrate a file that mixes a secret with
other content, since replacing such a file wholesale would lose the rest.

### Example: a bare token in `token.txt`

Say you pasted a JWT into `~/token.txt`. [`jit scan`](../audit/index.md) flags
it, and points you at migrate:

```console
$ jit scan token.txt
  ...
  Exposed Secrets        1 finding(s)

[Exposed Secrets]
  • ~/token.txt
    :1  HIGH  JSON Web Token (JWT)  eyJh**********
```

Preview the fix, then apply it:

```console
$ jit migrate token.txt --dry-run
jit migrate, plan

Project files you named

[loose secret file(s) → the whole file is a bare token; it moves to the vault and the file is replaced with a git-safe pointer (retrieve with `jit vault get`)] (1)
  • ~/token.txt

  1 change(s) planned across 1 category

$ jit migrate token.txt          # drop --dry-run; plan reprints, then Proceed? [y/N]
[loose secret file(s) migrated] (1)
  • ~/token.txt -> profile "token" (1 secret(s)); backup: `jit vault get _backups/Users_you_token.txt.jit-bak-...`, replaced with a safe pointer file (retrieve with `jit vault get token/JSON_WEB_TOKEN_JWT`)
```

`token.txt` no longer holds the token; it is now a git-safe pointer:

```console
$ cat token.txt
# jit pointer file, no secret values here, only vault paths.
# Real values reach a tool through `jit run` (the live mount serves them
# to that run), or `jit export`/`jit vault get`, never from this file. Safe to commit.
JSON_WEB_TOKEN_JWT=jit://vault/token/JSON_WEB_TOKEN_JWT
```

Get the real value back whenever you need it (behind Touch ID):

```console
$ jit vault get token/JSON_WEB_TOKEN_JWT
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...
```

`jit migrate undo` restores the original `token.txt` byte-for-byte from the
backup. Had you passed `--mount`, `token.txt` would instead stay live at its
path, serving the real token to a [`jit run`](../service/index.md) grant and a
decoy to anything else.

CLI tool tokens (`gh`, `stripe`, `ngrok`, …) live in their own config files
that `migrate` doesn't cover - that's [`jit wrap`](../wrap/index.md)'s job.

## Leaving is as easy as arriving

`jit migrate undo` restores files, `jit unmount` turns one live mount back
into a plain file, and `jit migrate remove` is the full exit from a
project. All three in **[Undo, unmount, and remove](./undo-and-remove.md)**.
