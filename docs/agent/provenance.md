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
  dropped it, plus whether each mount is decoy or grant-serving (and to
  which run) and what the most recent reader was actually served, real or
  decoy, and by which process. If a
  Touch ID prompt is sitting on your screen *right now*, status names what
  triggered it while it's still up - it answers immediately instead of
  waiting for the prompt to resolve.
- `jit agent history` lists every unlock, denial, use, and lock the agent
  has seen and what caused each:

  ```
  Session history (most recent first):
    • locked   2s ago (13:21:40) - explicit lock, launched by claude
    • used     8s ago (13:21:34) - read a secret ×4, launched by claude
        ~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve
        secrets (caller-reported): caido/api-token, caido/proxy-cert
    • unlocked 25s ago (13:21:17) - launched by claude
        ~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve
    • denied   3m ago (13:18:02) - launched by Code
        ~/some-script.sh
        unlocking: local authentication failed: the user canceled
  ```

Four kinds of event appear:

- **unlocked** - a Touch ID/passcode prompt the human approved, with the
  command that triggered it and what launched that command.
- **denied** - a prompt the human *refused* (or that failed), same
  provenance, plus why. A refusal also pauses automatic re-prompts for a
  short cooldown, so a retrying caller can't turn one deliberate "no"
  into a prompt storm - during the pause, only an explicit
  `jit agent unlock` will prompt again.
- **used** - what flowed through the already-open session *between* the
  prompts: reads, stores, and grants that rode the cached unlock,
  collapsed per caller (a profile resolve's burst of reads is one entry,
  not ten). The secret names are what the calling jit process reported
  about itself - useful for audit, labeled `caller-reported` because,
  unlike everything else on these lines, they don't come from the kernel.
- **locked** - what dropped the session: an idle timeout, the screen
  locking, or an explicit `jit agent lock`.

History survives agent restarts (it's kept in `agent-history.jsonl`
alongside the vault, as well as in the agent's log), and each restart
appears in the list as its own "started" entry - so events on either side
of one are never mistaken for a single session. Both commands take
`--format json`.

For the raw, timestamped record behind all of this - including per-mount
reader lineage and serve errors - `jit agent log` prints the tail of the
agent's own log file, and `jit agent log -f` follows it live.
