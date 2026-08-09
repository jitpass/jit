---
title: Wrap the Cursor CLI with jit
description: Keep your Cursor API key out of shell exports - injected as CURSOR_API_KEY just-in-time.
---

# cursor-agent - Cursor CLI

Cursor's CLI takes an API key for automation via the `CURSOR_API_KEY`
environment variable, and its docs have you `export` it - which lands the
key in a shell rc file and in every process your shell starts. Wrapping
stores the key in the vault and injects it into each `cursor-agent`
invocation only.

## Wrap it

There is no standard file the key lives in (browser login stores an OAuth
session, not an API key), so vault the key first, then wrap:

```sh
jit vault set wrap-cursor-agent/CURSOR_API_KEY
jit wrap cursor-agent
```

## Verify

```sh
cursor-agent status
```

## How it works

The shim injects `CURSOR_API_KEY` from the vault into each `cursor-agent`
process. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo cursor-agent
```

## Notes

- **The installer creates two names for the same binary**: `agent`
  (primary in Cursor's docs) and `cursor-agent` (legacy). This catalog
  entry shims `cursor-agent` - a name that can only mean Cursor. If you
  invoke it as `agent`, wrap that name by hand:
  `jit wrap add agent --env CURSOR_API_KEY=wrap-cursor-agent/CURSOR_API_KEY`
  (both shims then read the same vault secret).
- **Browser login (`agent login`) is left alone.** It stores an OAuth
  session, not the API key, and doesn't need wrapping - the wrap is for
  the API-key automation path (scripts, CI, headless use).
- If the key is already a plaintext `export` in `~/.zshrc`,
  `jit migrate ~/.zshrc` handles that copy.
