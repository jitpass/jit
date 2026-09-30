---
title: Wrap the GitHub CLI (gh) with jit
description: Keep your GitHub OAuth token out of ~/.config/gh/hosts.yml - injected as GH_TOKEN just-in-time.
---

# gh - GitHub CLI

`gh auth login` leaves an OAuth token on disk in
`~/.config/gh/hosts.yml` (newer versions may store it in the system
keyring instead). Wrapping moves it into the vault and injects it as
`GH_TOKEN` into each `gh` invocation only.

## Wrap it

```console
$ jit wrap gh
Found the GitHub CLI OAuth token in ~/.config/gh/hosts.yml - moved into the vault at wrap-gh/GH_TOKEN.
Wrapped gh:
  profile  wrap-gh (~/.jit/profiles/wrap-gh.yaml)
  shim     ~/.jit/shims/gh
Scrubbed the plaintext from ~/.config/gh/hosts.yml (original backed up encrypted).
Check it: open a new shell and run `gh auth status`.
```

If the token lives in the keyring rather than the file, jit exports it via
gh's own documented command (`gh auth token`) and vaults that.

## Verify

```sh
gh auth status
```

## How it works

A shim named `gh` sits first on PATH (`~/.jit/shims/gh`). Each invocation
resolves `wrap-gh/GH_TOKEN` from the vault and injects it as `GH_TOKEN`
into that one process - `gh` treats the env var as its credential, exactly
as its docs describe. Scripts, git hooks, and tools that spawn `gh` all go
through the same shim. Details: [how wrapping works](./index.md).

## More than one account

While `gh` is wrapped, the wrap decides which account `gh` uses, not
gh's keyring. gh refuses its own account commands while a token is
injected, so jit answers them itself:

```console
$ gh auth switch --user octo-work
Copied octo-work's token from gh's keyring into the vault.
gh now uses octo-work.
```

- `gh auth switch` moves the wrap to that account. Each account's token
  is kept at `wrap-gh/accounts/<name>`. An account gh is signed in to
  is copied into the vault the first time you switch to it. Switching
  between accounts already in the vault needs no Touch ID. With no
  `--user` and two accounts, it switches to the other one.
- `gh auth login` and `gh auth refresh` run gh with no token
  injected, then copy the new token into the vault and use it.
- `gh auth logout` removes gh's own copy. The vault's copy stays until
  you run `jit vault rm wrap-gh/accounts/<name>`.

These apply to github.com. Commands for another host
(`--hostname ghe.example.com`) behave as they would unwrapped.

## Undo

```sh
jit wrap undo gh
```

Removes the shim and the `wrap-gh` profile;
[`jit migrate undo`](../migrate/undo-and-remove.md) restores the original
`hosts.yml` byte-for-byte if it was scrubbed.

## Notes

- Anything already exporting `GH_TOKEN` in your shell overrides the shim's
  injection (that's gh's own precedence). [`jit scan`](../audit/index.md)
  flags such exports.
