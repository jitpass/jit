---
title: Which command delivers a secret
description: When to use jit wrap, jit run, jit run --profile, jit run --with, and how a migrated .env stays compatible with your scripts.
---

# Which command delivers a secret

jit has a few ways to get a secret out of the vault and into a program. They
are not alternatives to each other so much as answers to different questions.
This page is the decision guide.

## The one-line answer

| You have… | Use | Why |
|---|---|---|
| A CLI tool that keeps its own token in a dotfile, and you run it by name (`gh`, `aws`, `npm`, `stripe`) | **`jit wrap`** | Set up once; type the tool name normally forever |
| A project `.env` of variables that your scripts read | **`jit migrate`** then **`jit run`** | The file becomes a live mount; scripts run under `jit run` |
| A one-off command that needs a specific profile | **`jit run --profile <name>`** | No setup; name the profile for this run only |
| A machine-wide credential *file* a tool reads (gcloud ADC, SOPS age key, global `~/.npmrc`) | **`jit run --with <name>`** | Explicit intent; a fresh disclosed Touch ID per grant, never authorized by a repo |
| Secrets in your current interactive shell | **`jit export`** | Prints `export` lines to `eval` |

Everything below is the longer "why".

## `jit wrap`: a tool that carries its own token

Reach for `jit wrap` when a command-line tool stores a long-lived token in a
config file and you keep running that tool by typing its name. `gh` (GitHub),
`aws`, `npm`, `stripe`, `doctl`, `vercel` are all like this.

```
jit wrap add gh --env GH_TOKEN=wrap-gh/GH_TOKEN
```

`jit wrap` installs a small shim first on your `PATH`, so typing `gh` runs the
shim, which transparently does `jit run --profile wrap-gh gh …` for you. You
never type `jit run`; the token materializes inside that one process and
nowhere else, not in a dotfile, not in your shell. It works in scripts,
Makefiles, and tools that spawn tools, because the interception is at the
`PATH` level. See [jit wrap](../wrap/index.md).

**Use `jit wrap` when:** the tool has its own token and you want it to "just
work" by name, forever, without thinking about jit. One setup per tool.

## `jit run`: a project's `.env`

When it is a *project's* `.env` full of variables that your own scripts read,
migrate the project and run your commands under `jit run`:

```
jit migrate .              # .env secrets move to the vault; .env becomes a live mount
jit run -- ./deploy.sh      # scripts run with the secrets injected into their environment
```

`jit run` finds the project's migrated `.env` layers (walking up from your
directory, the way git finds `.git`), injects their merged values into the
command's environment, and then replaces itself with the command, so jit is
gone from memory the instant your command starts.

**Use `jit run` when:** it is a project `.env`, and you are running scripts or
a dev server in that project.

## `jit run --profile`: a one-off with a named profile

When you just want one command to run with one specific profile's secrets, and
you do not want to set up a shim, name the profile directly:

```
jit run --profile aws-admin -- terraform plan
```

This is the manual, one-time version of what `jit wrap` automates. Use it for
occasional or scripted commands where typing the prefix is fine.

## `jit run --with`: a machine-global credential file

Some credentials are neither a project's `.env` nor a tool's own dotfile
token. They are a single machine-wide *file* that many tools read: Google's
application-default credentials (`~/.config/gcloud/…`, read by gcloud,
terraform, and every Google SDK), the SOPS age key, the global `~/.npmrc`,
`~/.netrc` (curl, git, ftp, wget).
Naming one of these files in `jit migrate` vaults the secret inside it and
live-mounts the file.

One of these unlocks a lot and belongs to your whole machine, not a project,
so jit never grants it just because you `cd`'d into a directory or a repo's
config asked. You grant it with explicit intent:

```
jit run --with gcp -- terraform apply     # scoped to this run, gone on exit
```

`--with gcp|sops|npm|netrc` names the credential. Every grant prompts a fresh
**disclosed Touch ID that names the credential**, even when the vault is
already unlocked, so a script that slipped a `--with` into a command can't
siphon a machine-wide credential silently. The real values reach only that
run's process tree, and the grant ends when the run exits.

To keep typing the tool directly, with no `jit run` prefix, grant-wrap it once:

```
jit wrap add gcloud --grant gcp           # then `gcloud …` grants the ADC per call
```

**Use `jit run --with` when:** a tool reads a machine-wide credential file and
you want it available for one run (or, grant-wrapped, every time you type the
tool). See [jit run](../run/index.md) and the per-credential pages for
[gcp](../migrate/gcp.md), [sops](../migrate/sops.md), and [npm](../migrate/npm.md).

## How a migrated `.env` stays compatible with your scripts

A migrated `.env` is a live mount (a named pipe), not a plain file, so it can
serve fake placeholder values by default and real ones only when appropriate.
That protects the file at rest, but a named pipe is not a *regular* file, and
plenty of scripts check `[ -f .env ]` / `Path.is_file()`, or re-read the file
and would otherwise pull placeholder values over the real ones jit injected.

`jit run` handles this automatically, for the run's lifetime only:

- **Default, the compatibility swap.** Each mount becomes a plain, inert
  comment-only file for the run. `[ -f .env ]` passes, re-reading it with
  `source`/dotenv sets nothing (the real values are already in the
  environment), and the mount returns to its protected state the instant the
  command exits. This fits the overwhelming majority: shell scripts, dotenv
  loaders, anything that reads its config from the environment.

- **`--live`, keep the live mount and grant real file reads.** For a tool
  that reads values *from the `.env` file itself* rather than the environment.
  The clearest case is `docker compose` with `env_file:`, which copies the
  file's contents into containers and ignores the injected environment. `jit
  run` auto-detects the common ones (`docker`, `docker-compose`, `podman`), so
  you rarely type `--live` by hand.

You do not normally think about either mode; the default just works, and the
failure mode of the rare wrong guess is loud and self-explaining (a tool that
needed the file sees an obviously-inert file that tells you to use `--live`,
not silent placeholder-value errors).

## When to set `read_as_file: true`

If a project's tools *always* read the `.env` file itself (a compose-based
project, say), pin live mode once instead of typing `--live` on every run.
Put this in the project's `.jit/config.yaml`:

```yaml
read_as_file: true
```

Every `jit run` at or under that project then keeps the live mount and grants
the run real file reads, exactly as `--live` would.

**Only set this when the project genuinely reads the file**, not the
environment. It is deliberately an explicit declaration and not a guess:
choosing live for a project whose scripts actually guard with `[ -f .env ]`
would break those guards. When in doubt, leave it unset; the default swap is
the compatible one.
