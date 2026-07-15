---
title: Wrap troubleshooting
description: jit wrap list, doctor, and undo - diagnosing shims, PATH order, and wrap profiles.
---

# Wrap troubleshooting

## See what's wrapped: `jit wrap list`

Shows every wrapped tool with its shim health and PATH position - whether
the shim actually wins when you type the command.

## Diagnose: `jit wrap doctor`

Verifies, for every wrapped tool: the shim exists in `~/.jit/shims/`,
that directory precedes the real binary's location on PATH, and the
`wrap-<tool>` profile's vault paths all resolve
(like [`jit doctor`](../run/profiles.md#checking-a-profiles-health-jit-doctor),
but wrap-specific).

## Common symptoms

- **The tool says it's unauthenticated.** Usually PATH order: something
  put the real binary's directory ahead of `~/.jit/shims/`, so the shim
  never runs. `jit wrap doctor` names the offender. Also check nothing
  exports the tool's env var in your shell - a live export overrides the
  shim's injection.
- **"command not found" or exit 127 from a wrapped tool.** The shim
  couldn't find the real binary to exec into (was the tool uninstalled or
  moved?). A shim never silently degrades to running without injection -
  failing loudly is deliberate.
- **A Touch ID prompt on a wrapped call.** The agent session had lapsed;
  the prompt names the tool and its caller. With the
  [agent installed](../agent/index.md), it's once per session window, and
  each call costs ~25 ms after that.
- **The tool re-wrote its config file** (a re-`login`, a token rotation
  command). The new token is on disk in plaintext again; re-run
  `jit wrap <tool>` to vault it. [`jit audit`](../audit/index.md) will
  flag it in the meantime.

## Unwrap: `jit wrap undo <tool>`

Removes the tool's shim and its `wrap-<tool>` profile. The vaulted secret
stays (delete it with `jit vault rm` if you're done with it), and a
scrubbed config file is restored byte-for-byte by
[`jit migrate undo`](../migrate/undo-and-remove.md).
