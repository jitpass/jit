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

- `jit run <command>` makes this run's mounted files compatible with the
  command reading them, for the run's lifetime only. By **default** it
  swaps each mount to a plain, inert *compatibility file* (comment-only
  pointers): `[ -f .env ]` and `Path.is_file()` guards pass, and
  re-reading the file with `source` or a dotenv loader sets nothing,
  because the real values are already in the run's environment. The decoy
  mount returns the instant the command exits.
- `jit run --live <command>` instead keeps the live mount and grants the
  run's process tree **real file reads** (decided per read, by process
  ancestry; decoys to everything else). Use this for tools that read
  values *from the `.env` file itself* rather than the environment, such
  as `docker compose` with `env_file:` — jit run auto-detects the common
  ones. `jit agent status` shows whether each mount is swapped or granted,
  and for which run.
- A project whose tools **always** read the file itself can pin live mode
  once instead of typing `--live` every time: put `read_as_file: true` in
  the project's `.jit/config.yaml`. Only set it when the project genuinely
  reads the file rather than the environment — it is an explicit
  declaration, not a guess, because choosing live for a project whose
  scripts guard with `[ -f .env ]` would break those guards. See
  [Which command delivers a secret](../getting-started/choosing.md).
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
