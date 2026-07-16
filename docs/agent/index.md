---
title: The background agent
description: Unlock once per session instead of once per command - a launchd-managed session broker.
---

# The background agent

Without the agent, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 15 minutes of activity. The agent is also the process that
serves [live-mounted files](../run/mounts.md), so if you migrate a `.env`
file, you want it installed. Everything still works without it, just with
more prompts.

## Install it once: `jit agent install`

```
$ jit agent install
Set up jit agent to start automatically at every login (and restart itself if it crashes), staying unlocked for up to 15m0s after each Touch ID prompt, until you run `jit agent uninstall`? [y/N] y
Installed - jit agent now starts automatically every time you log in (survives reboots) and stays unlocked for up to 15m0s after your last Touch ID prompt.
```

The agent process itself runs indefinitely and never needs Touch ID just
to exist; only the cached key inside it locks after 15 minutes of
inactivity, re-prompting on next use. Change the window with `--ttl`
(`jit agent install --ttl 1h`); the value is baked into the launchd plist.

`jit agent restart` restarts the agent process — the step after
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

## Every unlock is attributed

The agent knows, from the kernel, exactly which process asked for every
unlock - and keeps the history. That's the subject of
**[Provenance](./provenance.md)**.
