---
title: The background service
description: Unlock once per session instead of once per command - a launchd-managed session broker that's a solid part of jit.
---

# The background service

Without the service, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 5 minutes of activity. The service is also the process that
serves [live-mounted files](../run/mounts.md).

It's a solid part of jit, not an optional add-on and not a setup step: it
installs itself the first time a command needs it (your first `jit migrate`
or `jit run`, or an explicit `jit unlock`), starts at every login, and
restarts itself if it crashes. Everything still works before that first use,
just with more prompts and no live mounts.

The shared session covers the high-frequency paths - native credential
hooks (`aws`, `kubectl`) and `jit run`. It deliberately does **not** cover
the sensitive [`jit vault`](../vault/index.md) management commands
(`get`/`set`/`rm`/`import`/`restore`/`clean`/`prune`/`delete`/`export`):
those always require a fresh Touch ID/passcode on every run, unlocked or
not, so a deliberate vault operation always takes a live human gesture even
mid-session. (`list`/`history` stay prompt-free - names and timestamps only.)

## There's no install step

You never install or start the service by hand. The first command that needs
it sets it up silently: a `jit migrate` that produces a mount, a `jit run`
that serves one, or an explicit `jit unlock`. From then on launchd keeps it
running across logins and reboots. It goes away when you remove jit itself.

The service process runs indefinitely and never needs Touch ID just to exist;
only the cached key inside it locks after the session TTL of inactivity
(default 5 minutes), re-prompting on next use.

## Changing the session length

`jit service ttl` shows or changes how long a session stays unlocked after
your last Touch ID prompt:

```
$ jit service ttl
Session TTL: 5m0s (a session locks this long after your last Touch ID prompt).

$ jit service ttl 1h
Session TTL set to 1h0m0s. The background service restarted, so the next vault use prompts Touch ID once.
```

The value is baked into the launchd login item, so it persists across logins
and reboots. Changing it restarts the service, so the current session is
dropped and the next vault use prompts once.

## Managing the running service

- `jit service status` - is it running, is it unlocked, when does it lock,
  what mounts is it serving - and, if a Touch ID prompt is up right now,
  who triggered it. `--format json` for scripting.
- `jit service restart` - restart the service process by hand, the step after
  [upgrading the binary](../getting-started/install.md#upgrading) manually
  (`jit upgrade` does it for you; the service also notices a replaced binary
  itself and restarts onto it within a few seconds once its session is locked
  and no prompt is pending). It also brings the service back if it ever
  stopped, recreating the login item if needed.
- `jit service log` - the tail of the service's raw operational output (startup,
  mount reads and who made them, serve-error detail); `-f` follows it live. The
  session events themselves live in [`jit audit`](./provenance.md), not here.
- `jit service run` - run it in the foreground (normally launchd's job,
  useful for debugging).

## Locking and unlocking

- `jit unlock` - unlock the session now (Touch ID if needed), rather
  than waiting for the next command to trigger it.
- `jit lock` - lock immediately: the cached key is dropped and the
  next vault access re-prompts.
- The session also locks itself the moment the screen locks or the machine
  goes to sleep - walking away locks the vault without anyone typing
  anything, and the idle TTL covers the case where you stay at your desk
  but stop using it.

## Every unlock is attributed

The service knows, from the kernel, exactly which process asked for every
unlock - and keeps the history, which [`jit audit`](./provenance.md)
prints. That's the subject of **[Provenance](./provenance.md)**.
