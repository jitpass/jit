---
title: Provenance
description: Every Touch ID prompt names its caller, and the service keeps the history - jit service status and jit audit.
---

# Provenance - every prompt tells you why

A Touch ID prompt you can't explain is one you'll approve out of habit -
which defeats the point of asking. So when jit asks, it names what it's
asking *for* and what set it off:

> jit is trying to **unlock the vault for profile "mcp-jamf", launched by claude**.

That's an MCP server your editor started, wanting the secrets in your
`mcp-jamf` profile. Approve or cancel on the facts, not on a guess.

## Where the caller's name comes from

Who the caller is comes from the kernel: its pid on the service's socket,
then its command line and parent chain - never from anything the caller
says about itself, so it can't be faked by a process filling in a field.
It is used to *explain* and to *audit*, never to decide: naming a caller
is not authenticating one, and jit doesn't pretend otherwise (see
[Security architecture](../security/architecture.md)).

## Asking afterwards: `status` and `audit`

"Why did that happen?" is usually asked *after* the prompt is gone.

- `jit service status` shows who unlocked the current session and what
  dropped it, plus whether each mount is decoy or grant-serving (and to
  which run) and what the most recent reader was actually served, real or
  decoy, and by which process. If a
  Touch ID prompt is sitting on your screen *right now*, status names what
  triggered it while it's still up - it answers immediately instead of
  waiting for the prompt to resolve.
- `jit audit` prints the durable audit log: every jit command that ran,
  interleaved with every unlock, denial, use, and lock the service has seen
  and what caused each. It's logfmt, newest first, so it greps like a real
  service log:

  ```
  $ jit audit
  time=2026-07-22 13:21:40 level=info kind=lock reason="explicit lock"
  time=2026-07-22 13:21:34 level=info kind=use op="read a secret" count=4 cmd="~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve" parent=claude secrets="caido/api-token, caido/proxy-cert"
  time=2026-07-22 13:21:17 level=info kind=unlock status=ok method=touchid-or-passcode cmd="~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve" parent=claude
  time=2026-07-22 13:18:02 level=warn kind=unlock status=denied method=touchid-or-passcode reason="local authentication failed: the user canceled" cmd="~/some-script.sh" parent=Code
  ```

Among the auth events, six kinds appear:

- **unlock (status=ok)** - a Touch ID/passcode prompt the human approved, with
  the command that triggered it and what launched that command.
- **unlock (status=denied)** - a prompt the human *refused* (or that failed),
  same provenance, plus the reason. A refusal also pauses automatic re-prompts
  for a short cooldown, so a retrying caller can't turn one deliberate "no"
  into a prompt storm - during the pause, only an explicit
  `jit unlock` will prompt again.
- **grant (status=approved)** - a *disclosed* prompt the human approved: a
  `jit run --with` grant of a machine-global credential, a per-process consent
  approval, or a `jit run --trust` registration. These sit on top of the
  session rather than opening one, so they are their own kind rather than an
  unlock, and `reason` is the exact sentence that was on the dialog. Without
  this entry the trail could show every prompt you *refused* and none that you
  allowed, which is the wrong half to be able to prove.
- **use** - what flowed through the already-open session *between* the
  prompts: reads, stores, and grants that rode the cached unlock,
  collapsed per caller (a profile resolve's burst of reads is one entry,
  not ten). The secret names are what the calling jit process reported
  about itself - useful for audit, labeled `caller-reported` because,
  unlike everything else on these lines, they don't come from the kernel.
- **lock** - what dropped the session: an idle timeout, the screen
  locking, or an explicit `jit lock`.
- **error** - something the service refused or failed at its socket: a rejected
  peer (a process the kernel says isn't yours, probing the agent), a malformed
  request, or the accept loop dying. A rejected peer carries the peer's own
  provenance, and used to be logged nowhere. Filter for these with
  `jit audit --kind error`.

The auth events survive service restarts (they're kept in
`agent-history.jsonl` alongside the vault), and each restart appears as its own
`kind=service` entry - so events on either side of one are never mistaken for a
single session. `jit audit` takes `--format json`, and narrows with `--kind`,
`--status`, `--since`/`--until`, `--parent`, `--secret`, and `--grep`; `--follow`
(`-f`) streams new entries live.

The session events above are read only through `jit audit` now; they are no
longer duplicated into the service's own log. That log, `jit service log` (and
`-f` to follow it), is the raw operational record behind the daemon: startup,
per-mount reader lineage, and the prose detail of any serve error.
