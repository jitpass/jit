---
title: Wrap troubleshooting
description: jit wrap list, doctor, and undo - diagnosing shims, PATH order, and wrap profiles.
---

# Wrap troubleshooting

## See what's wrapped: `jit wrap list`

Shows every wrapped tool with its shim health and PATH position - whether
the shim actually wins when you type the command.

## Diagnose: `jit doctor --wrap`

Verifies, for every wrapped tool: the shim exists in `~/.jit/shims/`,
that directory precedes the real binary's location on PATH, and the
`wrap-<tool>` profile's vault paths all resolve.

It never opens the vault, so it still works when the vault is the thing
that's broken. Add `--verbose` to list the checks that passed as well as the
ones that failed - right after `jit wrap add`, "shim, real binary, and
profile all resolve" is usually the answer you want.

A plain [`jit doctor`](../run/profiles.md#checking-a-profiles-health-jit-doctor)
includes these checks too, alongside everything else; `--wrap` just narrows
the run.

!!! note "`jit wrap doctor` has been removed"

    Typing it points you here rather than failing obscurely. It existed as a
    second command only because severity used to live on the command rather
    than the check: it exited non-zero for every failed check while
    `jit doctor` treated all of them as advisory, so the same facts got two
    verdicts depending on which one you typed. Severity now lives on the
    check - a damaged shim installation fails the run, while "the shim dir
    isn't on PATH in *this* shell" stays advisory, because a CI job that
    doesn't put it there is not a broken machine. With that settled, a second
    command had nothing left to offer.

## Common symptoms

- **The tool says it's unauthenticated.** Usually PATH order: something
  put the real binary's directory ahead of `~/.jit/shims/`, so the shim
  never runs. `jit doctor --wrap` names the offender. Also check nothing
  exports the tool's env var in your shell - a live export overrides the
  shim's injection.
- **"command not found" or exit 127 from a wrapped tool.** The shim
  couldn't find the real binary to exec into (was the tool uninstalled or
  moved?). A shim never silently degrades to running without injection -
  failing loudly is deliberate.
- **A Touch ID prompt on a wrapped call.** The service session had lapsed;
  the prompt names the tool and its caller. With the
  [service running](../service/index.md), it's once per session window, and
  each call costs ~25 ms after that.
- **Tab-completing a wrapped tool.** Most CLIs' completion scripts re-run
  the tool itself on every `<TAB>` (`gh __complete ...`), which lands on the
  shim. With the session unlocked that takes the normal injected path, so
  completions that need the credential (`kubectl <TAB>` listing pods) work;
  with it locked, the real tool runs *uninjected* and just offers fewer
  suggestions. A keystroke never raises a Touch ID prompt - if completing
  needs the credential, unlock first (`jit unlock`).
- **The tool re-wrote its config file** (a re-`login`, a token rotation
  command). The new token is on disk in plaintext again; re-run
  `jit wrap <tool>` to vault it. [`jit scan`](../audit/index.md) will
  flag it in the meantime.

## Unwrap: `jit wrap undo <tool>`

Removes the tool's shim and its `wrap-<tool>` profile. The vaulted secret
stays (delete it with `jit vault rm` if you're done with it), and a
scrubbed config file is restored byte-for-byte by
[`jit migrate undo`](../migrate/undo-and-remove.md).
