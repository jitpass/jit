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
  interleaved with every unlock, grant, denial, use, mount read (decoy or
  real), and lock the service has seen and what caused each. It's logfmt, newest first, so it greps like a real
  service log:

  ```
  $ jit audit
  time=2026-07-22 13:21:40 level=info kind=lock reason="explicit lock"
  time=2026-07-22 13:21:34 level=info kind=use op="read a secret" count=4 cmd="~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve" parent=claude secrets="caido/api-token, caido/proxy-cert"
  time=2026-07-22 13:21:17 level=info kind=unlock status=ok method=touchid-or-passcode cmd="~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve" parent=claude
  time=2026-07-22 13:18:02 level=warn kind=unlock status=denied method=touchid-or-passcode reason="local authentication failed: the user canceled" cmd="~/some-script.sh" parent=Code
  ```

Among the auth events, eight kinds appear:

- **unlock (status=ok)** - a Touch ID/passcode prompt the human approved, with
  the command that triggered it and what launched that command.
- **unlock (status=denied)** - a prompt the human *refused* (or that failed),
  same provenance, plus the reason. A refusal also pauses automatic re-prompts
  for a short cooldown, so a retrying caller can't turn one deliberate "no"
  into a prompt storm - during the pause, only a *fresh* `jit unlock` (one that
  actually challenges you) will prompt again. Consent prompts have their own,
  separate pause: a refused credential request holds that caller and credential
  off for about two seconds, then eight, then thirty, and the next prompt says
  how many times it has already been refused.
- **grant (status=approved)** - a *disclosed* prompt the human approved: a
  `jit run --with` grant of a machine-global credential, a per-process consent
  approval, a `jit run --trust` registration, or a
  [process grant](./grants.md)'s creation or extension. These sit on top of
  the session rather than opening one, so they are their own kind rather than
  an unlock, and `reason` is the exact sentence that was on the dialog. Without
  this entry the trail could show every prompt you *refused* and none that you
  allowed, which is the wrong half to be able to prove.
- **grant (status=ended)** - a [process grant](./grants.md) ending, with the
  reason (`expired`, `revoked` - carrying the revoker's provenance - or the
  anchored process exiting), the grant id, and the vault paths it covered.
  Recorded because a standing approval's *end* is the fact an investigation
  needs: "was the grant still live at the time?" is unanswerable from a trail
  that only records beginnings. `--kind grant` shows a grant's whole life.
- **use** - what flowed through the already-open session *between* the
  prompts: reads, stores, and grants that rode the cached unlock,
  collapsed per caller (a profile resolve's burst of reads is one entry,
  not ten). The secret names are what the calling jit process reported
  about itself - useful for audit, labeled `caller-reported` because,
  unlike everything else on these lines, they don't come from the kernel.
  A read served by a live process grant instead of the session renders as
  its own op, `read a secret via grant`, with the covered path named by the
  service itself rather than caller-reported - so unattended serves are
  never mistaken for session activity.
- **serve** - a reader opened a live mount, and what it got: the decoy
  (`status=decoy`) or the real value (`status=real`), why that verdict, and -
  best-effort, from the kernel - which program read it and what launched that
  program. A decoy read is jit working as designed, and it is also the one
  signal that names a process reading a credential file it has no business in;
  filter for those with `jit audit --status decoy`. The real half answers what
  a grant approval alone can't: not "was this authorized" but "was it actually
  read". Same-mount, same-reader, same-verdict reads inside a window collapse
  into one line carrying a `count` - a dev server's file watcher re-reads a
  mount continuously, and uncollapsed it would push every unlock out of the
  history, the same erasure the error kind's collapsing prevents. An identity
  carried over from a just-missed scan is marked `reader_likely` and rendered
  "(likely)", never as certainty.
- **lock** - what dropped the session: an idle timeout, the maximum session age
  (a session ends 8 hours after the unlock that opened it, however busy it has
  been), the screen locking, or an explicit `jit lock`.
- **error** - something the service refused or failed at its socket: a rejected
  peer (a process the kernel says isn't yours, probing the agent), a malformed
  request, an unwrap whose claimed credential class doesn't match the ciphertext
  it sent (`op=class-mismatch` - a caller holding no vault data trying to summon
  a prompt), or the accept loop dying. A rejected peer carries the peer's own
  provenance, and used to be logged nowhere. Filter for these with
  `jit audit --kind error`.

  Repeated rejections collapse into a single line carrying a `count`, and that
  line names the *first* caller of the window rather than each one. That is
  deliberate and worth knowing when you read the trail forensically: keying
  these per caller would let a flood of throwaway processes - one `fork` each -
  push every real unlock and denial out of the history, so the record of an
  attack would be the first thing the attack erased.

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
