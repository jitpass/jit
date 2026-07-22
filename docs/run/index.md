---
title: Run a command with secrets
description: jit run injects a profile's secrets into a process environment - no file on disk at all.
---

# Run a command with secrets - `jit run`

```
$ cd myapp
$ jit run -- npm run dev
jit run: merging .env, .env.local (last wins) - profiles myapp, myapp-local
```

From inside a migrated project, `jit run` needs no arguments beyond your
command. It finds the project's migrated `.env`-family files (looking upward
from wherever you are, the way git finds `.git`) and injects their merged
result in standard dotenv order: `.env` first, `.env.local` overriding it.
It always prints what it merged (real secrets are entering a process, so it
never does that silently), and warns if a layer file exists on disk but was
never migrated.

## Modes

Mode-specific layers (`.env.production`, `.env.development`, ...) are never
merged unless you ask, so production secrets can't ride into a dev run just
because a file exists:

```
$ jit run --mode production -- npm start
jit run: merging .env, .env.production, .env.local (last wins) - profiles myapp, myapp-production, myapp-local
```

Full precedence with a mode: `.env` < `.env.<mode>` < `.env.local` <
`.env.<mode>.local` (the Next.js/CRA convention).

## Flags and process behavior

The `--` is optional (jit stops reading its own flags at the first non-flag
argument), and your command's flags pass straight through. Naming a
[profile](./profiles.md) explicitly turns merging off and uses exactly that
one, handy for a global profile like AWS:

```
$ jit run --profile aws-admin -- terraform plan
```

`jit run` replaces its own process with your command (`execve`); jit itself
is gone from memory the instant your command starts.

## Reading the file itself during a run

A migrated `.env` is a live mount (a named pipe), not a regular file. For the
lifetime of a `jit run`, jit makes that mount compatible with whatever your
command does with it, automatically:

- **By default it swaps in a plain, inert file.** `[ -f .env ]` /
  `Path.is_file()` guards pass, and a script that re-reads the file with
  `source` or a dotenv loader sets nothing (the real values are already in
  the environment). The mount returns to its protected state the instant the
  command exits. This fits shell scripts, dotenv loaders, and anything that
  reads its config from the environment.
- **`--live` keeps the live mount and serves real values through the file**,
  for a tool that reads values *from the file itself* — `docker compose` with
  `env_file:` is the canonical case. jit auto-detects the common ones
  (`docker`, `docker-compose`, `podman`), and a project that always reads the
  file can pin this with `read_as_file: true` in its `.jit/config.yaml`
  instead of typing `--live`.

You rarely think about either mode. If you want the full picture of when to
reach for what, see [Which command delivers a secret](../getting-started/delivering-secrets.md),
and [live-mounted files](./mounts.md) for how the mount itself behaves.

## Granting a machine-global credential file (`--with`)

Some tools read a single machine-wide credential *file* rather than a
project's `.env`: Google's application-default credentials (read by `gcloud`,
`terraform`, and Google SDKs), the SOPS age key, the global `~/.npmrc`,
`~/.netrc` (curl, git, ftp). After
`jit migrate home` vaults one of these, grant it to a run by naming it:

```
$ jit run --with gcp -- terraform apply
```

`--with gcp|sops|npm|netrc` is explicit intent by design. A machine-global
credential is never granted by a project's config or by which directory you
run from, only by a `--with` you type, and every grant prompts a fresh Touch
ID that names the credential (even when the vault is already unlocked). The
real values reach only that run's process tree and the grant ends when the run
exits. An unknown name, or one whose mount isn't migrated, fails loudly rather
than silently serving a decoy.

To keep typing the tool directly, grant-wrap it once with
[`jit wrap add <tool> --grant <name>`](../wrap/index.md); the shim runs
`jit run --with` for you. See
[Which command delivers a secret](../getting-started/delivering-secrets.md)
for when to reach for `--with` versus `--profile` or `jit wrap`.

## The four run modes at a glance

`--live` and `--with` are independent switches, so there are four ways to run
a command. `--live` is about **this project's** files; `--with` is about a
**machine-global** credential. Pick by what your tool actually reads:

| Command | Use it when | What it grants |
| --- | --- | --- |
| `jit run -- <cmd>` | The tool reads secrets from **environment variables** (the common case: `process.env`, most dotenv loaders, shell scripts). | Injects the project's `.env` values into the environment; the mount is swapped for an inert file. |
| `jit run --live -- <cmd>` | The tool reads the project's `.env` **file itself** and ignores the environment (`docker compose` with `env_file:`). Auto-selected for `docker`/`docker-compose`/`podman`. | Serves the project's `.env` mount real values to that run's process tree, per read. |
| `jit run --with <name> -- <cmd>` | The tool reads a **machine-global** credential file — `gcp` (gcloud ADC), `sops`, `npm` (`~/.npmrc`), `netrc`. | Serves that global mount real values to the run, behind a fresh disclosed Touch ID. |
| `jit run --live --with <name> -- <cmd>` | The run needs **both**: it reads the project `.env` file directly *and* a global credential file. | Two independent grants on the same run — project mount (`--live`) and the named global mount (`--with`). |

**How do I know if I need `--live`?** You usually don't decide upfront. Run
the default; if the tool behaves as though its config is empty or missing
(connection refused, a missing key, a blank variable), that's the tell it
read the `.env` file and got the inert swap — re-run with `--live`. Once you
know a project always reads the file, pin `read_as_file: true` in its
`.jit/config.yaml` so you never type `--live` there again.

**Combined example** — a compose stack that reads the project `.env` file and
needs the gcloud ADC to pull an image:

```
$ jit run --live --with gcp -- docker compose up
```

Both grants land on that one run's process tree and end the instant it exits.
(Because docker is auto-detected you could drop `--live` here; writing it is
just clearer.) Whatever the mode, real values flow **only** to the process
tree of the `jit run` you launch — never on an unlock, a `cd`, or a bare
command with no `jit run` in front of it.

## Where else `jit run` shows up

Migrated [MCP configs](../migrate/mcp.md) launch their servers through
`jit run`, and every [wrapped CLI's shim](../wrap/index.md) is `jit run`
under the hood. Same injection, same unlock rules, same
[provenance](../service/provenance.md).
