---
title: Wrap the OpenAI CLI with jit
description: Keep your OpenAI API key off disk entirely - injected as OPENAI_API_KEY just-in-time.
---

# openai - OpenAI CLI

The OpenAI CLI reads its key from `OPENAI_API_KEY`, and there's no
standard config file it writes - in practice the key lives wherever you
pasted it, usually a shell `export` line ([`jit scan`](../audit/index.md)
flags those; [`jit migrate`](../migrate/shell-configs.md) fixes them).
Wrapping keeps the key in the vault and injects it per invocation instead.

## Wrap it

Because there's no file to discover the key from, put it in the vault
first, then wrap:

```sh
jit vault set wrap-openai/OPENAI_API_KEY   # prompts for the key
jit wrap openai
```

This installs the `~/.jit/shims/openai` shim and the `wrap-openai`
profile.

## Verify

Run any `openai` command - it authenticates without `OPENAI_API_KEY`
appearing in your shell environment or any file.

## How it works

The shim injects `OPENAI_API_KEY` from the vault into each `openai`
process. If you previously had an `export OPENAI_API_KEY=...` line,
remove it (or let `jit migrate ~/.zshrc` convert it) - a shell export
overrides the shim's injection. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo openai
```

## Notes

- The same pattern works for any SDK-driven script you run through
  [`jit run`](../run/index.md): point a profile at
  `wrap-openai/OPENAI_API_KEY` and the key never touches your shell.
