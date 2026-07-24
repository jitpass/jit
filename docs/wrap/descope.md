---
title: Wrap the Descope CLI with jit
description: Vault your Descope management key and inject it as DESCOPE_MANAGEMENT_KEY just-in-time.
---

# descope - Descope CLI

The `descope` CLI authenticates with two environment variables: a
**management key** (`DESCOPE_MANAGEMENT_KEY`, the secret) and a **project id**
(`DESCOPE_PROJECT_ID`, a non-secret identifier). Descope's docs have you export
both in your shell profile (`~/.zshrc`), so there's no dedicated config file.
Wrapping vaults the management key and injects it into each `descope`
invocation only.

## Wrap it

```sh
jit vault set wrap-descope/DESCOPE_MANAGEMENT_KEY   # paste a key from app.descope.com/settings/company/managementkeys
jit wrap descope
```

jit stores the key at `wrap-descope/DESCOPE_MANAGEMENT_KEY` and installs the
`~/.jit/shims/descope` shim plus the `wrap-descope` profile. Keep
`DESCOPE_PROJECT_ID` as a normal export - it isn't a secret, and the CLI needs
it alongside the key.

## Verify

```sh
descope flow list
```

## How it works

The shim injects `DESCOPE_MANAGEMENT_KEY` from the vault into each `descope`
process - the CLI's documented credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo descope
```

## Notes

- **Already have the key exported in `~/.zshrc`?** That's a plaintext secret in
  a shell config, which [`jit migrate ~/.zshrc`](../migrate/shell-configs.md)
  handles directly - it vaults `DESCOPE_MANAGEMENT_KEY` and leaves a hook so new
  shells still get it. Use `migrate` for the shell-export path; use `wrap` to
  gate the key per `descope` invocation.
- `DESCOPE_PROJECT_ID` is a public project identifier, not a credential, so jit
  doesn't vault it.
