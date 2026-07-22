---
title: Migrating .env files
description: Project .env files become live-mounted files - decoy values by default, real ones only to a jit run grant.
---

# .env files

`jit migrate` moves each variable in a `.env` file into the vault and
replaces the file with a **live mount**: a named pipe the
[service](../service/index.md) serves fresh content into on every read. Two
things sit on disk afterwards, neither containing a secret:

- **The mount** at the original path, so every tool that expects `.env`
  still finds one. It serves fake-looking placeholder values by default and
  real values only to the process tree of a `jit run` grant you launch on
  purpose - a file that served real secrets to whatever opened it would
  defeat the point of moving them off disk.
- **A `.env.pointers` companion**: a plain, regular, git-safe file mapping
  each variable to its vault path (`KEY=jit://vault/<path>`), never to a
  value. This is where you look to answer "where does this variable live
  now?"

## Running the project — it just works

When you run your commands with [`jit run`](../run/index.md), it makes the
mount compatible with whatever your command does for the duration of that
run: by default it swaps in a plain, inert file so `[ -f .env ]` guards pass
and re-reads set nothing (values come from the injected environment), and
`--live` keeps the live file for tools that read values from it directly
(`docker compose` with `env_file:`). You don't configure any of this; see
[Which command delivers a secret](../getting-started/delivering-secrets.md).

Real values reach a tool **only** through `jit run`. An unwrapped command
(`npm run dev` with no `jit run` prefix, or a `cat`) reads the mount cold and
gets decoys - that's the point, not a bug. There is no automatic reveal
window and no reveal command of any kind: launch the tool with `jit run` (or
`jit run --live` for a tool that reads the file itself), and the grant lands
on that run's process tree alone.

Day-to-day behavior of mounts - decoys, the compatibility swap, grants, how
to check what a reader was served - is covered in
**[Live-mounted files](../run/mounts.md)**.

## Layered .env files

The whole `.env` family migrates the same way, and
[`jit run`](../run/index.md) reproduces standard dotenv merge order
(`.env` < `.env.<mode>` < `.env.local` < `.env.<mode>.local`), with
mode-specific layers only merged when you pass `--mode`.

## Rotating a value

After migration, the file on disk is no longer where a secret lives. When
a provider issues you a new key, update the vault, not the file:
`jit vault set myapp/STRIPE_API_KEY`. The mount serves fresh vault content
on every read, so the next granted read sees the new key. Details in
**[The vault](../vault/index.md#changed-an-api-key-update-the-vault-not-the-file)**.

## Reversing it

`jit unmount <path>` turns the mount back into a plain file;
`jit migrate undo` restores the original bytes from backup. See
**[Undo, unmount, and remove](./undo-and-remove.md)**.
