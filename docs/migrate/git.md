---
title: Migrating git HTTPS credentials
description: Plaintext logins in ~/.git-credentials move to the vault; a credential helper keeps git push/fetch over HTTPS working.
---

# git HTTPS credentials

Authenticating a `git push` over HTTPS with git's `store` credential
helper writes your username and password (or token) into
`~/.git-credentials`, one `https://user:pass@host` line per host, in
plaintext. Anyone who can read the file can read every git login on the
machine.

`jit migrate` (category `git`) moves each host's credential into the vault
and wires git's own pluggable mechanism, a [credential
helper](https://git-scm.com/docs/gitcredentials), into your git config:

```ini
[credential]
	helper = jit
```

jit sets `credential.helper` to `jit` (removing the plaintext `store`
helper it replaces), installs the `git-credential-jit` helper (a two-line
script in `~/.jit/shims`, which jit keeps on `PATH`), and strips the
migrated line from `~/.git-credentials`. git then asks jit for the
credential on demand (`get`) whenever it pushes or fetches over HTTPS, and
- the part a shim could never cover - a push that authenticates with a
typed-in password afterward lands directly in the vault (`store`) instead
of back in plaintext.

jit keys on host alone, matching git's default
(`credential.useHttpPath=false`): one credential per host, resolved from
any directory a git command runs in.

## What to expect

- Each credential fetch needs the vault unlocked - the
  [agent](../agent/index.md)'s shared session, or a Touch ID prompt. A host
  jit holds nothing for gets an empty answer before any vault access, so
  git just falls through to its next helper or prompts, never a spurious
  Touch ID.
- **Rotating a credential is just authenticating again.** Prefer a scoped
  personal access token over your account password; whatever git stores
  through the helper is what the vault keeps.
- The helper resolves via `PATH` (`~/.jit/shims`), so git invoked from a
  shell, script, hook, or submodule fetch finds it. Open a new shell after
  the first migration if jit just added the `PATH` line.
- `jit wrap git` routes to this same migration.

## git over HTTPS vs. the gh CLI vs. SSH

- **Raw `git` over HTTPS** is what this category covers - `git push`,
  `git fetch`, `git clone https://...`, submodules, and LFS.
- **The `gh` CLI** carries its own OAuth token, migrated separately with
  [`jit wrap gh`](../wrap/gh.md). Note `gh` can also install itself as a
  git credential helper; if it did, that helper stays configured alongside
  jit, and git tries them in order.
- **SSH remotes** don't touch the HTTPS credential path at all - the
  private key is the credential, and jit doesn't move it here.

## A secure helper already configured?

If git already uses a secure helper (macOS `osxkeychain`, Git Credential
Manager), your credentials aren't sitting in plaintext, so there's usually
nothing to migrate. jit only takes over the plaintext `store` helper and
leaves a secure one in place.

`jit git-credential <get|store|erase>` is the [plumbing
command](../reference/plumbing.md) git invokes - you never run it by hand.
Reversing the migration: [`jit migrate undo`](./undo-and-remove.md).
