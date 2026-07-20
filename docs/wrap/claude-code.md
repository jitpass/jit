---
title: Wrap Claude Code with jit
description: Keep your Anthropic API key off disk entirely - injected as ANTHROPIC_API_KEY just-in-time.
---

# claude - Claude Code

Claude Code reads its key from `ANTHROPIC_API_KEY`, and there's no
standard config file it writes - in practice the key lives wherever you
pasted it, usually a shell `export` line ([`jit audit`](../audit/index.md)
flags those; [`jit migrate`](../migrate/shell-configs.md) fixes them).
Wrapping keeps the key in the vault and injects it per invocation instead.

(This page is named `claude-code.md`, not `claude.md`: on the default
case-insensitive macOS filesystem, a docs page literally named `claude.md`
gets picked up by Claude Code's own project-instructions discovery as a
directory-scoped `CLAUDE.md` - not something we want to ship into every
contributor's checkout.)

## Wrap it

Because there's no file to discover the key from, put it in the vault
first, then wrap:

```sh
jit vault set wrap-claude/ANTHROPIC_API_KEY   # prompts for the key
jit wrap claude
```

This installs the `~/.jit/shims/claude` shim and the `wrap-claude`
profile.

## Verify

Run any `claude` command - it authenticates without `ANTHROPIC_API_KEY`
appearing in your shell environment or any file.

## How it works

The shim injects `ANTHROPIC_API_KEY` from the vault into each `claude`
process. If you previously had an `export ANTHROPIC_API_KEY=...` line,
remove it (or let `jit migrate home` convert it) - a shell export
overrides the shim's injection. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo claude
```

## Notes

- **This is for API-key billing, not a Claude subscription.** A
  Pro/Max/Team subscription authenticates through a separate OAuth login
  Claude Code keeps in the macOS Keychain (already encrypted at rest -
  nothing for jit to move). Setting `ANTHROPIC_API_KEY` switches Claude
  Code onto pay-per-token API billing instead, which is the right call for
  a service account, CI, or a standalone Claude API integration, but not
  something to do to a personal subscription login by accident.
- The same pattern works for any script calling the Claude API directly:
  point a profile at `wrap-claude/ANTHROPIC_API_KEY` and run it through
  [`jit run`](../run/index.md) instead of exporting the key into your
  shell.
