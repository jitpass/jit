---
title: Migrating .npmrc tokens
description: Auth tokens leave .npmrc for the vault; the file live-mounts from a template with non-secret settings untouched.
---

# npm (.npmrc)

A project or global `.npmrc` often carries registry auth in plaintext
(`//registry.npmjs.org/:_authToken=npm_...`) next to perfectly harmless
settings. `jit migrate` (category `npmrc`) moves **just the secret lines**
into the vault and replaces the file with a [live
mount](../run/mounts.md) serving a template: the non-secret settings pass
through untouched, and the token slots fill from the vault only for a
`jit run` grant's own process tree.

## What to expect

- `npm install` and friends read the mount like a normal file. Running them
  with [`jit run`](../run/index.md) grants a **project** `.npmrc` to that
  run's process tree automatically (npm reads the real token, scoped to the
  run, gone when it exits), so `jit run npm ci` just works, no window
  needed. The **global** `~/.npmrc` is machine-wide, so it is never granted
  automatically: name it explicitly with `jit run --with npm -- npm ci`,
  which prompts a disclosed Touch ID and scopes the token to that run.
  Outside a grant they see placeholder values (that's the point — launch npm
  through `jit run`); `jit agent status` shows what the last reader was
  served.
- The global `~/.npmrc` is machine-wide, so it's covered by
  `jit migrate home`; a project `.npmrc` is covered by `local` too.
- Rotating a token: `jit vault set` on the path shown in the mount's
  pointers file - the next granted read serves it.

Reversing: `jit unmount <path>` writes the file back plain, or
[`jit migrate undo`](./undo-and-remove.md) restores the original bytes.
