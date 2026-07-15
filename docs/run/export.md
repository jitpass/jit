---
title: Shell exports
description: jit export prints export statements for a profile's secrets - eval it to load your current shell.
---

# Secrets in your current shell - `jit export`

```
$ eval "$(jit export)"
jit export: merging .env, .env.local (last wins) - profiles myapp, myapp-local
```

`jit export` selects profiles exactly like [`jit run`](./index.md): same
layer merge, same `--mode`, same `--profile` override. The merge
announcement goes to stderr, so `eval` never swallows it.

Run it *without* `eval` to see a whole profile's resolved values printed
in your terminal - useful for a quick check, with the obvious caveat that
you're printing secrets to your screen.

## Migrated shell configs use this

When [`jit migrate` converts a shell config](../migrate/shell-configs.md),
the plaintext `export` lines are replaced with exactly this pattern:

```sh
eval "$(jit export --profile <name>)"
```

Every new shell then loads its secrets from the vault at startup. A shell
that's already running keeps the values it loaded - open a new one (or
re-run the `eval` line) after rotating a value.
