---
title: Wrap the Snowflake CLI with jit
description: Keep your Snowflake connection password out of ~/.snowflake/config.toml - injected as SNOWFLAKE_PASSWORD just-in-time.
---

# snow - Snowflake CLI

`snow connection add` stores a connection's password in plaintext in
`~/.snowflake/config.toml`. Wrapping moves it into the vault and injects it as
`SNOWFLAKE_PASSWORD` into each `snow` invocation only.

Snowflake itself requires this file to be `0600` and refuses to run when it's
more permissive - a fair signal from the vendor about what's in it. `0600`
still means anything running as you can read it, which is what wrapping fixes.

## Wrap it

```sh
jit wrap snow
```

jit reads the first `[connections.<name>]` block's `password` from
`config.toml`, stores it at `wrap-snow/SNOWFLAKE_PASSWORD`, scrubs the
plaintext (original backed up encrypted), and installs the `~/.jit/shims/snow`
shim plus the `wrap-snow` profile.

## Verify

```sh
snow connection test
```

## How it works

The shim injects `SNOWFLAKE_PASSWORD` from the vault into each `snow` process.
Snowflake CLI resolves connection parameters in this documented order:

1. command-line flags
2. environment variables (`SNOWFLAKE_PASSWORD`, or the per-connection
   `SNOWFLAKE_CONNECTIONS_<NAME>_PASSWORD`)
3. `config.toml` / `connections.toml`

The injected variable therefore takes priority over anything left on disk.
Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo snow
```

## Notes

- **Multiple connections:** only the first `[connections.<name>]` block's
  password is auto-migrated - the active one for single-connection setups. For
  others, use the per-connection variable
  `SNOWFLAKE_CONNECTIONS_<NAME>_PASSWORD` via
  [`jit wrap add`](./custom-tools.md).
- **`connections.toml` is not auto-migrated.** That file puts each connection
  at the top level (`[myconn]`), so there's no fixed section name to address.
  Vault it yourself first:
  `jit vault set wrap-snow/SNOWFLAKE_PASSWORD`, then `jit wrap snow`.
- **Key-pair and SSO auth are out of scope.** `private_key_file` points at a
  key file rather than holding a secret inline - that key is
  [`jit migrate`](../migrate/index.md)'s territory, and a browser SSO
  connection has no durable password to move.
- Non-secret settings (`account`, `user`, `warehouse`) stay in `config.toml`;
  only the `password` line is scrubbed.
