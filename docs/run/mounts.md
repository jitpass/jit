---
title: Live-mounted files
description: Migrated .env files serve decoy values by default and real ones only to a jit run grant's own process tree.
---

# Live-mounted files

A migrated `.env` is no longer a regular file: it's a named pipe the
[service](../service/index.md) serves fresh content into on every read. **The
mount serves fake-looking placeholder values by default, and real values only
to the process tree of a `jit run` grant you launch on purpose.** Unlocking the vault, `cd`-ing into a directory, or
a `cat` never makes a mount serve real values. A file that served real
secrets to whatever opened it would defeat the point of moving them off
disk.

## The mechanism, exactly

No kernel extension, no filesystem driver, no FUSE, nothing privileged. The
mount is a plain POSIX FIFO created with `mkfifo(2)` at mode `0600`, and the
delivery is the kernel's own blocking-open semantics:

1. jit replaces the file with a FIFO (`unix.Mkfifo(path, 0600)`).
2. A reader calls `open(".env")`. On a FIFO opened for reading, that call
   **blocks in the kernel** until a writer connects. Your tool is now parked
   in `open(2)`, having read nothing.
3. The [service](../service/index.md) is that writer. It opens the same path
   `O_WRONLY`, which unblocks the reader, decrypts in memory, writes those
   bytes straight into the kernel pipe buffer, and closes.
4. It then loops immediately back to `open(2)` and blocks again, waiting for
   the next reader. That re-open loop is what makes the pipe survive being
   read more than once, which is the part a naive FIFO gets wrong.

The decision of *what* to write happens in step 3, in the service, per read:
decoy bytes for an ambient reader, real bytes only for a process sitting in
an authorized run's tree. Nothing is written to disk at any point in this
sequence, so there is no window in which the plaintext exists as a file, and
no file to recover afterwards. The FIFO has no contents of its own: `cat`ing
it when the service is stopped simply blocks, and when the service is locked
it yields decoys.

The re-open behavior was proven out before it was built on, in
`spike/named-pipe/FINDINGS.md`.

## Real values flow only through `jit run`

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
  ones. `jit service status` shows whether each mount is swapped or granted,
  and for which run.
- `jit run --with <name> <command>` grants a machine-global file-delivered
  credential (`gcp`, `sops`, `npm`, `netrc`, `pypi`) to the run, behind a fresh
  disclosed Touch ID that names the credential. This is the explicit,
  hard-gated path. With per-process consent on (the default), these same
  credential mounts *also* serve real content on a **direct** read, behind a
  consent prompt that names the reader (best-effort identity), so for the
  everyday case you can run the tool without `--with`. That consent path is only
  for the machine-global credential mounts, never for a project's own `.env`.
  See [Global mount grants](../getting-started/delivering-secrets.md) and
  [per-process consent](../service/consent.md).
- A project whose tools **always** read the file itself can pin live mode
  once instead of typing `--live` every time: put `read_as_file: true` in
  the project's `.jit/config.yaml`. Only set it when the project genuinely
  reads the file rather than the environment — it is an explicit
  declaration, not a guess, because choosing live for a project whose
  scripts guard with `[ -f .env ]` would break those guards. See
  [Which command delivers a secret](../getting-started/delivering-secrets.md).
- If a tool reads a project `.env` off disk, run it **through** `jit run`. An
  unwrapped `npm run dev` (no `jit run` prefix) reads the mount cold and
  gets decoys, and that's the point. For a project `.env` there is no automatic
  reveal window and no reveal command of any kind: the only thing that makes it
  serve real values is a `jit run` grant you type. (The machine-global
  credential mounts above are the exception: with consent on, they also serve on
  a direct read, behind a prompt.)
- Wondering why your app saw placeholders, or which run is currently granted
  a mount? `jit service status` shows each mount as decoy or grant-serving,
  and what the most recent reader was actually served, real or decoy, and by
  which process.

## Peeking at a value

Don't `cat` or open a live-mounted file to "just check what's in it".
Without an active `jit run` grant you'll see decoy values, not an error, and
a named pipe can't support everything a regular file can (`stat` for size,
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
