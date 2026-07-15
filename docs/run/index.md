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

## Where else `jit run` shows up

Migrated [MCP configs](../migrate/mcp.md) launch their servers through
`jit run`, and every [wrapped CLI's shim](../wrap/index.md) is `jit run`
under the hood. Same injection, same unlock rules, same
[provenance](../agent/provenance.md).
