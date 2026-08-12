---
title: Process grants
description: Pre-approve a running tool to use profiles unattended for a bounded time - one Touch ID now, no prompts while you are away, everything on the audit trail.
---

# Process grants - approve now, run unattended

Everything jit serves normally rides a session you opened with Touch ID, and
that session ends when you walk away: idle timeout, screen lock, sleep. That
is the right default, and it has one honest gap - work that runs while you
are *not* there. An AI agent working overnight, a long build, a scheduled
job: the session drops, the next credential read stops on a prompt nobody
will answer.

A **process grant** moves your decision earlier instead of removing it. While
you are at the keyboard, one disclosed Touch ID approves that a specific
**running process** (and everything it launches) may use the secrets of one
or more profiles until a deadline you set:

```sh
jit grant --process claude --profile jamf --profile aws-ci --for 8h
```

The prompt says exactly what you are signing:

> jit is trying to **let claude use 3 secrets (jamf, aws-ci) unattended for 8h**.

From then until it expires, credential reads from that process tree succeed
with no prompts - including while the screen is locked. Everything else
keeps today's behavior: other processes still prompt, other secrets still
prompt, and the vault's management commands still take a fresh gesture.

## What a grant anchors to

A grant names a process that **exists right now** - resolved to a live pid
(and its kernel fork-time stamp), never stored as a name pattern. A new
process that calls itself `claude` tomorrow inherits nothing. If two
processes share the name, jit lists them and makes you pick with `--pid`;
it never guesses.

The covered secrets are resolved from the profiles **at creation time**, by
the service itself, through the same project-then-global profile lookup
`jit run` uses. Editing a profile later never silently widens a standing
grant, and the prompt can never describe a different set than the grant
covers.

## What ends it

Whichever comes first, and each ending lands in `jit audit`:

- **its deadline** - `--for` takes `45m`, `8h`, `3d`, capped at 7 days;
- **the process exiting** - the grant dies with the tree it named;
- **`jit grant revoke <id>`** - immediate, and deliberately needs no
  authentication: reducing access is always free, so the kill switch is the
  easiest command in the feature;
- **a service restart or reboot** - grants live in the service's memory,
  never on disk.

Wanting *more* time is a new decision, so `jit grant extend <id> --for 24h`
puts the same disclosed prompt in front of you that creating it did.

```sh
jit grant list             # what is open: who, which profiles, time left, serves
jit grant revoke g-7f3a2c81
jit grant extend g-7f3a2c81 --for 24h
```

`jit status` carries the same fact as a one-line `grants` row (who, and the
next expiry), so an open grant is visible on the dashboard you already check
rather than only behind its own subcommand. Tab completion knows grants too:
`jit grant revoke <TAB>` offers the live ids with their programs and
expiries, and `--process <TAB>` offers the programs that recently asked jit
for a secret, marked running or not.

## The audit trail tells the whole story

A standing, unattended credential channel is only acceptable if you can read
back everything it did. Each stage is a durable
[`jit audit`](./provenance.md) event:

```
$ jit audit --kind grant
time=... kind=grant status=approved reason="let claude use 2 secrets (jamf) unattended for 8h"
time=... kind=grant status=ended grant=g-7f3a2c81 reason="claude's grant expired"
$ jit audit --kind use
time=... kind=use op="read a secret via grant" count=2 parent=claude secrets="jamf/api-user, jamf/api-pass"
```

Serves under a grant carry their own op (`read a secret via grant`), so
"rode an unlock you gave moments ago" and "rode a standing grant from this
morning" are never the same line.

## The honest limits

- A grant covers **pull-at-use** delivery: credential hooks, wrap shims, and
  `jit run` invocations made under the granted tree. Environment variables a
  `jit run` already injected were handed over up front, grant or no grant.
- Live file mounts keep their own [consent gating](./consent.md); grants do
  not cover FIFO reads.
- Rotating a covered secret changes its key material; the grant simply stops
  matching it and that read falls back to prompting.
- The grant's process match is the anchor for a decision **you** made on a
  Touch ID naming that process; as everywhere in jit, kernel-derived
  identity explains and audits, it never decides on its own (see
  [Security architecture](../security/architecture.md)).
