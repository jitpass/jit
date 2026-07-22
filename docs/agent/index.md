---
title: The background agent
description: Unlock once per session instead of once per command - a launchd-managed session broker.
---

# The background agent

Without the agent, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 5 minutes of activity. The agent is also the process that
serves [live-mounted files](../run/mounts.md). You don't set it up by hand:
jit installs it automatically the first time a command needs it (your first
`jit migrate` or `jit run`). Everything still works before that, just with
more prompts and no live mounts.

The shared session covers the high-frequency paths - native credential
hooks (`aws`, `kubectl`) and `jit run`. It deliberately does **not** cover
the sensitive [`jit vault`](../vault/index.md) management commands
(`get`/`set`/`rm`/`import`/`restore`/`clean`/`prune`/`delete`/`export`):
those always require a fresh Touch ID/passcode on every run, unlocked or
not, so a deliberate vault operation always takes a live human gesture even
mid-session. (`list`/`history` stay prompt-free - names and timestamps only.)

## Setup is automatic (`jit agent install` to do it eagerly)

The first command that needs the agent installs it for you, silently: a
`jit migrate` that produces a mount, a `jit run` that serves one, or an
explicit `jit agent unlock`. There's no separate setup step to remember.

Run `jit agent install` yourself only when you want to set it up ahead of
time, or to pick the session window (`--ttl`) up front:

```
$ jit agent install
Set up jit agent to start automatically at every login (and restart itself if it crashes), staying unlocked for up to 5m0s after each Touch ID prompt, until you run `jit agent uninstall`? [y/N] y
Installed - jit agent now starts automatically every time you log in (survives reboots) and stays unlocked for up to 5m0s after your last Touch ID prompt.
```

The agent process itself runs indefinitely and never needs Touch ID just
to exist; only the cached key inside it locks after 5 minutes of
inactivity, re-prompting on next use. Change the window with `--ttl`
(`jit agent install --ttl 1h`); the value is baked into the launchd plist.
An automatic first-use install uses the 5m default; run `jit agent install --ttl <d>`
any time to change it.

`jit agent restart` restarts the agent process, the step after
[upgrading the binary](../getting-started/install.md#upgrading), though the
agent also notices a replaced binary itself and restarts onto it once its
session is locked and no prompt is pending. `jit agent uninstall` stops it
and removes it from login startup, and `jit agent run` runs it in the
foreground (normally launchd's job, useful for debugging).

## Locking and unlocking

- `jit agent unlock` - unlock the session now (Touch ID if needed), rather
  than waiting for the next command to trigger it.
- `jit agent lock` - lock immediately: the cached key is dropped and the
  next vault access re-prompts.
- The session also locks itself the moment the screen locks or the machine
  goes to sleep - walking away locks the vault without anyone typing
  anything, and the idle TTL covers the case where you stay at your desk
  but stop using it.
- `jit agent status` - is it running, is it unlocked, when does it lock,
  what mounts is it serving - and, if a Touch ID prompt is up right now,
  who triggered it. `--format json` for scripting.
- `jit agent log` - the tail of the agent's own timestamped log (session
  events, mount reads and who made them, serve errors); `-f` follows it
  live.

## Every unlock is attributed

The agent knows, from the kernel, exactly which process asked for every
unlock - and keeps the history. That's the subject of
**[Provenance](./provenance.md)**.
