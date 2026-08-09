---
title: Wrap the Kiro CLI with jit
description: Keep your Kiro API key out of shell exports - injected as KIRO_API_KEY just-in-time.
---

# kiro-cli - Kiro CLI

Kiro CLI's headless mode authenticates with an API key in the
`KIRO_API_KEY` environment variable, and the docs have you `export` it -
which lands the key in a shell rc file, CI config, and every process your
shell starts. Wrapping stores the key in the vault and injects it into
each `kiro-cli` invocation only.

## Wrap it

There is no standard file the key lives in (the interactive login is
subscription OAuth, not an API key), so vault the key first, then wrap:

```sh
jit vault set wrap-kiro-cli/KIRO_API_KEY
jit wrap kiro-cli
```

## Verify

```sh
kiro-cli chat --no-interactive "say hi"
```

## How it works

The shim injects `KIRO_API_KEY` from the vault into each `kiro-cli`
process. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo kiro-cli
```

## Notes

- **The interactive subscription login is left alone.** The browser
  sign-in stores an OAuth session, not an API key - the wrap is for the
  headless/API-key path (scripts, CI).
- API keys are generated in the Kiro dashboard and are only available on
  paid plans; if your subscription is admin-managed, API key generation
  has to be enabled by the administrator first.
- If the key is already a plaintext `export` in `~/.zshrc`,
  `jit migrate ~/.zshrc` handles that copy.
