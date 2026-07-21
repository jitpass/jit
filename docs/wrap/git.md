---
title: Wrap git with jit
description: jit wrap git uses git's native credential-helper hook - git push/fetch over HTTPS keeps working, no shim needed.
---

# git - git over HTTPS (native hook)

`jit wrap git` doesn't install a shim. git has its own pluggable
credential mechanism, a `credential.helper` named in your git config, and
jit hooks that instead, because it covers what a shim can't: `git push`
and `git fetch` over HTTPS, submodule fetches, and Git LFS all resolve
through the same helper, from any directory and any program that shells
out to git.

```sh
jit wrap git
```

routes to the same flow as
[`jit migrate --only=git`](../migrate/git.md): each host's plaintext
login leaves `~/.git-credentials` for the vault, jit sets
`credential.helper` to `jit`, and git fetches the credential on demand
through the `git-credential-jit` helper. A `git push` that authenticates
with a typed-in password afterward lands in the vault too, not back in
plaintext.

The full walkthrough - what gets rewritten, the credential.helper change,
rotation, and the `gh` CLI relationship - is on
**[Migrating git HTTPS credentials](../migrate/git.md)**.

## Undo

[`jit migrate undo`](../migrate/undo-and-remove.md) restores the original
`~/.git-credentials` and git config byte-for-byte from their encrypted
backups.

## Notes

- This covers raw `git` over HTTPS. The `gh` CLI has its own token, wrapped
  separately with [`jit wrap gh`](./gh.md).
- If you authenticate over SSH, there's nothing here to migrate - your key
  is the credential, and it never touches the HTTPS credential path.
- If git already uses a secure helper (`osxkeychain`, Git Credential
  Manager), your credentials aren't in plaintext, so there's usually
  nothing to migrate - jit only takes over the plaintext `store` helper
  and leaves a secure one in place.
