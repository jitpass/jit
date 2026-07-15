---
title: Wrap the Databricks CLI with jit
description: Keep your Databricks personal access token out of ~/.databrickscfg - injected as DATABRICKS_TOKEN just-in-time.
---

# databricks - Databricks CLI

`databricks configure` stores a personal access token in plaintext in
`~/.databrickscfg`. Wrapping moves it into the vault and injects it as
`DATABRICKS_TOKEN` into each `databricks` invocation only.

## Wrap it

```sh
jit wrap databricks
```

jit reads the `DEFAULT` profile's token from `.databrickscfg` (INI
format), stores it at `wrap-databricks/DATABRICKS_TOKEN`, scrubs the
plaintext (original backed up encrypted), and installs the
`~/.jit/shims/databricks` shim plus the `wrap-databricks` profile.

## Verify

```sh
databricks current-user me
```

## How it works

The shim injects `DATABRICKS_TOKEN` from the vault into each `databricks`
process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo databricks
```

## Notes

- **Multiple workspace profiles:** only the `DEFAULT` profile's token is
  auto-migrated. Vault other profiles' tokens yourself and wire them via
  [`jit wrap add`](./custom-tools.md).
- The host URL stays in `.databrickscfg` - it isn't a secret; only the
  token line is scrubbed.
