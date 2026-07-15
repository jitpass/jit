---
title: Migrating .env files
description: Project .env files become live-mounted files - decoy values by default, real ones during a revealed window.
---

# .env files

`jit migrate` moves each variable in a `.env` file into the vault and
replaces the file with a **live mount**: a named pipe the
[agent](../agent/index.md) serves fresh content into on every read. Two
things sit on disk afterwards, neither containing a secret:

- **The mount** at the original path, so every tool that expects `.env`
  still finds one. It serves fake-looking placeholder values by default and
  real values only during a short revealed window - a file that served real
  secrets to whatever opened it would defeat the point of moving them off
  disk.
- **A `.env.pointers` companion**: a plain, regular, git-safe file mapping
  each variable to its vault path (`KEY=jit://vault/<path>`), never to a
  value. This is where you look to answer "where does this variable live
  now?"

## The reveal step is wired for you

`jit migrate` wires an automatic reveal into your `.envrc` (direnv) or
`package.json` `dev`/`start` script, so `npm run dev` and friends just
work. The window also opens automatically for 60 seconds whenever the
agent unlocks or a migrate runs. For everything else there's
`jit agent reveal <path>`.

Day-to-day behavior of mounts - decoys, reveal windows, how to check what
a reader was served - is covered in
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
on every read, so the next revealed read sees the new key. Details in
**[The vault](../vault/index.md#changed-an-api-key-update-the-vault-not-the-file)**.

## Reversing it

`jit unmount <path>` turns the mount back into a plain file;
`jit migrate undo` restores the original bytes from backup. See
**[Undo, unmount, and remove](./undo-and-remove.md)**.
