---
title: Process grants
description: Pre-approve a tool to use profiles unattended - one Touch ID now, until a deadline or until you revoke it, no prompts while you are away, everything on the audit trail.
---

# Process grants - approve now, run unattended

Everything jit serves normally rides a session you opened with Touch ID, and
that session ends when you walk away: idle timeout, screen lock, sleep. That
is the right default, and it has one honest gap - work that runs while you
are *not* there. An AI agent working overnight, a long build, a scheduled
job: the session drops, the next credential read stops on a prompt nobody
will answer.

A **process grant** moves your decision earlier instead of removing it. While
you are at the keyboard, one disclosed Touch ID approves that a program (and
everything it launches) may use the secrets of one or more profiles:

```sh
jit grant --process claude --profile jamf --profile aws-ci --for 8h
```

You choose how it ends, and the two shapes differ in more than duration.
`--for` is above: a deadline of at most 7 days, held in the service's
memory. `--until-revoked` has no deadline at all and holds a key of its
own, so it survives a service restart and a reboot:

```sh
jit grant --process claude --profile mcp-caido --until-revoked
```

[Standing grants](../../design/standing-grants.md) is the design note for
the second shape: what it stores, where, and what it costs you.

The prompt says exactly what you are signing:

> jit is trying to **let claude under iTerm2 use 3 secrets (jamf, aws-ci) unattended for 8h**.

From then until it expires, credential reads from claude sessions in this
terminal succeed with no prompts - including while the screen is locked,
and **including sessions you start later inside the window**: a new tab, a
scheduled script, the next `claude` you launch. Everything else keeps
today's behavior: other processes still prompt, other secrets still prompt,
and the vault's management commands still take a fresh gesture.

## What a grant anchors to

`--process NAME` is scoped to **the terminal you type it in**. The anchor is
the terminal app itself (iTerm2, Terminal, a tmux server, an IDE's terminal,
an SSH connection) - verified through kernel process ancestry, pinned by pid
and fork time. A credential read is served only when the asking process sits
under that exact terminal AND its chain passes through a process named NAME.
Two consequences:

- **Future sessions are covered.** Membership is checked per read against
  the live process tree, not against a list frozen at creation - so you can
  grant before the program even starts (the confirmation says "none running
  yet"), and an automation that fires in ten minutes inside that terminal
  or tmux just works.
- **The name alone never decides.** A process elsewhere on the machine that
  renames itself `claude` inherits nothing: it does not descend from your
  terminal, and no process can fake its place in the kernel's tree. The
  boundary is the terminal you physically granted from; the name only
  narrows what is served inside it. The flip side: a claude under a
  *different* app (say VS Code's terminal) is a different tree - grant
  there too if you want it covered.

`--pid` grants one exact running process instead (and dies when it exits);
its tab completion annotates each candidate with its working directory and
age so same-named processes are tellable apart.

A program with no terminal above it - the JitPass menu bar app - cannot
anchor to "the terminal you type it in", so it may name one explicitly:
"any `claude` under iTerm2". The service accepts only a genuine session
root there (an app the system launched directly, never a process inside
someone's tree and never launchd), and the Touch ID prompt then opens with
who is asking - "JitPass asks: let claude under iTerm2 use 2 secrets …" -
so the tree no longer implies the requester and the prompt says it instead.
Everything else is the same grant: the name only narrows, membership is
decided per read against the live tree, and the human on the prompt is the
decision.

The covered secrets are resolved from the profiles **at creation time**, by
the service itself, through the same project-then-global profile lookup
`jit run` uses. Editing a profile later never silently widens a grant that
already exists, and the prompt can never describe a different set than the
grant covers.

## What ends it

Whichever comes first, and each ending lands in `jit audit`:

- **`jit grant revoke <id>`** - immediate, and deliberately needs no
  authentication: reducing access is always free, so the kill switch is the
  easiest command in the feature. For an `--until-revoked` grant this is the
  **only** ending, and it deletes the key that grant holds;
- **its deadline** - `--for` takes `45m`, `8h`, `3d`, capped at 7 days.
  An `--until-revoked` grant has none;
- **its anchor exiting** - quitting the terminal app ends a `--for
  --process` grant; a `--pid` grant dies with the process it named. An
  `--until-revoked` grant is anchored to the app's executable rather than to
  a running pid, so quitting the app does not end it;
- **a service restart or reboot** - a `--for` grant lives in the service's
  memory and dies with it, recorded as *ended when the service stopped*. An
  `--until-revoked` grant survives both: its covered keys are on disk,
  wrapped under a key that is not.

Wanting *more* time is a new decision, so `jit grant extend <id> --for 24h`
puts the same disclosed prompt in front of you that creating it did. There
is no deadline to move on an `--until-revoked` grant, so `extend` refuses
it; revoke it when you want it to end.

```sh
jit grant list             # what is open: who, which profiles, time left, serves
jit grant revoke g-7f3a2c81
jit grant extend g-7f3a2c81 --for 24h
```

`jit status` carries the same fact as a one-line `grants` row (who, and the
next expiry, or *until revoked* when nothing has one), so an open grant is
visible on the dashboard you already check rather than only behind its own
subcommand. Tab completion knows grants too: `jit grant revoke <TAB>` offers
the live ids with their programs and how each ends, and `--process <TAB>`
offers the programs that recently asked jit for a secret, marked running or
not. `jit grant extend <TAB>` offers only the grants that have a deadline to
move, since it refuses the rest.

## The audit trail tells the whole story

An unattended credential channel is only acceptable if you can read back
everything it did. Each stage is a durable
[`jit audit`](./provenance.md) event:

```
$ jit audit --kind grant
time=... kind=grant status=approved reason="let claude under iTerm2 use 2 secrets (jamf) unattended for 8h"
time=... kind=grant status=ended grant=g-7f3a2c81 reason="claude's grant expired"
# ... or "revoked", "process exited", "ended when the service stopped"
$ jit audit --kind use
time=... kind=use op="read a secret via grant" count=2 parent=claude secrets="jamf/api-user, jamf/api-pass"
```

Serves under a grant carry their own op (`read a secret via grant`), so
"rode an unlock you gave moments ago" and "rode a grant you gave this
morning" are never the same line.

## The honest limits

- A grant covers **pull-at-use** delivery: credential hooks, wrap shims, and
  `jit run` invocations made under the granted tree. Environment variables a
  `jit run` already injected were handed over up front, grant or no grant.
- Live file mounts keep their own [consent gating](./consent.md); grants do
  not cover FIFO reads.
- Rotating a covered secret changes its key material, so the grant stops
  matching it and that read falls back to prompting. The rest of the grant
  keeps working. For an `--until-revoked` grant `jit grant list` says which
  secret stopped and prints the command that covers it again; a `--for`
  grant is short-lived enough that it does not check.
- The grant's process match is the anchor for a decision **you** made on a
  Touch ID naming that process; as everywhere in jit, kernel-derived
  identity explains and audits, it never decides on its own (see
  [Security architecture](../security/architecture.md)).
