---
title: Provenance
description: Every Touch ID prompt names its caller, and the agent keeps the history - jit agent status and history.
---

# Provenance - every prompt tells you why

A Touch ID prompt you can't explain is one you'll approve out of habit -
which defeats the point of asking. So when jit asks, it names what it's
asking *for* and what set it off:

> jit is trying to **unlock the vault for profile "mcp-jamf", launched by claude**.

That's an MCP server your editor started, wanting the secrets in your
`mcp-jamf` profile. Approve or cancel on the facts, not on a guess.

## Where the caller's name comes from

Who the caller is comes from the kernel: its pid on the agent's socket,
then its command line and parent chain - never from anything the caller
says about itself, so it can't be faked by a process filling in a field.
It is used to *explain* and to *audit*, never to decide: naming a caller
is not authenticating one, and jit doesn't pretend otherwise (see
[Security architecture](../security/architecture.md)).

## Asking afterwards: `status` and `history`

"Why did that happen?" is usually asked *after* the prompt is gone.

- `jit agent status` shows who unlocked the current session and what
  dropped it, plus each mount's reveal state and what the most recent
  reader was actually served, real or decoy, and by which process. If a
  Touch ID prompt is sitting on your screen *right now*, status names what
  triggered it while it's still up - it answers immediately instead of
  waiting for the prompt to resolve.
- `jit agent history` lists every unlock and lock the agent has seen and
  what caused each:

  ```
  Session history (most recent first):
    • unlocked 4s ago (13:19:19) - launched by claude
        ~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve
    • locked   10s ago (13:19:13) - explicit lock, launched by claude
  ```

History survives agent restarts (it's kept in `agent-history.jsonl`
alongside the vault, as well as in the agent's log), and each restart
appears in the list as its own "started" entry - so events on either side
of one are never mistaken for a single session. Both commands take
`--format json`.
