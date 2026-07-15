---
title: Wrap a custom tool
description: jit wrap add - wrap any CLI that reads its credential from an environment variable, no catalog entry needed.
---

# Custom tools - `jit wrap add`

Any tool that reads its credential from an environment variable can be
wrapped, catalog entry or not:

```sh
jit vault set mycompany/MYTOOL_TOKEN            # 1. put the secret in the vault
jit wrap add mytool --env MYTOOL_TOKEN=mycompany/MYTOOL_TOKEN   # 2. wrap
```

This installs a `~/.jit/shims/mytool` shim and a `wrap-mytool` profile
mapping each `--env VAR=<vault-path>` pair. `--env` repeats for tools
that need several variables:

```sh
jit wrap add wiz \
  --env WIZ_CLIENT_ID=wiz/WIZ_CLIENT_ID \
  --env WIZ_CLIENT_SECRET=wiz/WIZ_CLIENT_SECRET
```

Each `mytool` invocation then gets those variables injected from the
vault, for that process only - same mechanics, same
[agent](../agent/index.md) gating, and same
[`jit wrap undo mytool`](./troubleshooting.md) as a
[cataloged tool](./index.md).

## What `add` doesn't do

A hand-wrapped tool has no catalog entry, so jit can't discover the
token's plaintext source or scrub it - steps a cataloged
`jit wrap <tool>` does for you. If the token currently lives in a shell
export or `.env` file, [`jit migrate`](../migrate/index.md) cleans that
up; if it lives in the tool's own config file, remove it yourself after
vaulting (the tool now gets the env var, which CLIs typically prefer over
their config file - check yours does).

## Graduating into the catalog

If the tool has a well-known config file, consider
[adding it to the catalog](./index.md#adding-a-tool) - one data block and
one fixture, and `jit audit` starts flagging its token for everyone.
