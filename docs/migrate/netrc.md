---
title: Migrating ~/.netrc
description: Passwords and tokens in ~/.netrc move to the vault; curl, git, ftp, and wget keep reading the file exactly as before.
---

# netrc (`~/.netrc`)

`~/.netrc` is the one file curl, git's HTTP credential helper, ftp, and
wget all fall back to for per-host login credentials - a GitHub personal
access token used for `git push` over HTTPS, an internal API's basic-auth
password, an FTP account. Every `password` value in it sits in plaintext,
usually with `chmod 600` as its only protection.

`jit migrate ~/.netrc` (category `netrc`) moves every `password` value into
the vault and replaces `~/.netrc` with a [live mount](../run/mounts.md)
serving a template: `machine`/`default`/`login`/`account` lines, blank
lines, indentation, and any `macdef` scripts pass through byte-for-byte -
only the password values themselves are filled in from the vault, and
only when a read is authorized: with per-process consent on (the default), by
approving the Touch ID prompt when a tool reads the file, or explicitly with
`jit run --with netrc` (for scripts and CI, or a hard gate).
`login` values are left alone: by
convention (curl's own docs, GitHub's PAT-over-HTTPS setup) the field
named `password` is the credential and `login` is a username, not a
secret.

## Using it after migration

**Grant a run the real file:**

```sh
jit run --with netrc -- curl https://api.example.com/data
jit run --with netrc -- git push
```

The grant is scoped to that run's process tree and gone the moment it
exits - curl/git read the file directly, so (unlike an env-var secret)
there's no equivalent "inject it into the environment" shortcut here.
To keep typing `curl`/`git` directly, `jit wrap add <tool> --grant netrc`
installs a shim that grants the file per invocation.

## What to expect

- With consent off and no grant covering the read, a reader of
  `~/.netrc` sees fixed placeholder passwords - curl/git fail fast with a
  clear auth error instead of silently trying a garbage credential against
  a live server. With consent on, a direct read prompts instead and serves the
  real password on approval.
- The file is machine-wide (one per user), so name it explicitly to
  convert it: `jit migrate ~/.netrc`. A project directory walk never
  touches it.
- Only `password` values move. `login`/`account` values and any `macdef`
  script bodies are left exactly as they were, even if a macro happens to
  contain the word "password" in its own text - macro bodies are never
  parsed as netrc grammar.
- A malformed or duplicate `machine` block (the same host appearing
  twice) is handled by keeping the *first* occurrence's value under the
  plain variable name and giving any later duplicate a numbered suffix -
  netrc readers use the first match, so the first occurrence is the one
  that's actually live.
- A `$NETRC` environment variable pointing curl at a different file isn't
  covered by this migration; the standard `~/.netrc` path is.

Reversing: `jit unmount ~/.netrc` writes the file back plain, or
[`jit migrate undo`](./undo-and-remove.md) restores the original bytes.
