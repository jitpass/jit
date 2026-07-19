---
title: Live-mounted files
description: Migrated .env files serve decoy values by default and real ones during a short revealed window.
---

# Live-mounted files

A migrated `.env` is no longer a regular file: it's a named pipe the
[agent](../agent/index.md) serves fresh content into on every read. One
thing to know up front: **the mount serves fake-looking placeholder values
by default, and real values only during a short revealed window.** A file
that served real secrets to whatever opened it would defeat the point of
moving them off disk.

## In practice you rarely think about this

- `jit run <command>` grants its own command's process tree a
  **run-scoped reveal**: for as long as that command runs, the mounted
  files backing the values it injected serve real content to that run's
  processes (decided per read, by process ancestry), and decoys to
  everything else. A script that re-reads its own `.env` mid-run sees the
  same values it was launched with; the grant ends the moment the command
  exits. `jit agent status` lists any live grant per mount.
- `jit migrate` wires an automatic reveal into your `.envrc` (direnv) or
  `package.json` `dev`/`start` script, so `npm run dev` and friends just
  work. The window also opens automatically for 60 seconds whenever the
  agent unlocks or a migrate runs.
- If a process reads `.env` outside a window (say, a dev server restarted
  minutes later), reveal by hand: `jit agent reveal <path>`, with
  `--for <duration>` for a longer window (up to 10 minutes). Revealing
  fails loudly, instead of pretending to work, if a referenced secret is
  missing from the vault; `jit doctor` shows what's missing.
- Wondering whether a mount is revealed right now, or why your app saw
  placeholders? `jit agent status` shows each mount's reveal countdown and
  what the most recent reader was actually served, real or decoy, and by
  which process.

## Peeking at a value

Don't `cat` or open a live-mounted file to "just check what's in it".
Outside the revealed window you'll see decoy values, not an error, and a
named pipe can't support everything a regular file can (`stat` for size,
`mmap`), so editors may behave oddly against it regardless. Instead:

- **Where does a variable live?** Open the `.env.pointers` file next to the
  mount. It's a plain, regular, git-safe file mapping each variable to its
  vault path (`KEY=jit://vault/<path>`), never to a value.
- **What's the actual value?** `jit vault get <path>` prints one secret
  (`--copy` sends it to the clipboard instead), or run `jit export`
  *without* `eval` to see a whole profile's resolved values.

## Back to a plain file

`jit unmount <path>` reverses a single live mount: decrypts the vault
values and writes them out as a regular plain file again (fresh Touch ID
required - see [Undo, unmount, and
remove](../migrate/undo-and-remove.md)).
