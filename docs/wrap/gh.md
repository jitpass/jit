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

## Undo

```sh
jit wrap undo gh
```

Removes the shim and the `wrap-gh` profile;
[`jit migrate undo`](../migrate/undo-and-remove.md) restores the original
`hosts.yml` byte-for-byte if it was scrubbed.

## Notes

- `gh auth logout` / re-`login` write to gh's own storage again - re-run
  `jit wrap gh` after a re-login to vault the fresh token.
- Anything already exporting `GH_TOKEN` in your shell overrides the shim's
  injection (that's gh's own precedence). [`jit audit`](../audit/index.md)
  flags such exports.
