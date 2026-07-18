---
title: Wrap Docker with jit
description: jit wrap docker uses Docker's native credential-helper hook - docker login/logout keep working, no shim needed.
---

# docker - Docker CLI (native hook)

`jit wrap docker` doesn't install a shim. Docker has its own pluggable
credential mechanism - credential helpers named in
`~/.docker/config.json` - and jit hooks that instead, because it covers
what a shim can't: `docker login` and `logout` keep working (a re-login
lands directly in the vault instead of back in base64), and everything
that reads docker's config resolves through the same hook - `docker
compose pull`, buildx, SDKs.

```sh
jit wrap docker
```

routes to the same flow as
[`jit migrate --only=docker`](../migrate/docker.md): each registry's
plaintext login leaves `~/.docker/config.json` for the vault, and docker
fetches it on demand through the `docker-credential-jit` helper.

The full walkthrough - what gets rewritten, Docker Desktop interplay,
rotation via `docker login`, the compose story - is on
**[Migrating Docker registry logins](../migrate/docker.md)**.

## Undo

[`jit migrate undo`](../migrate/undo-and-remove.md) restores the original
`~/.docker/config.json` byte-for-byte from its encrypted backup.

## Note

If Docker Desktop already stores your logins in the macOS keychain
(`"credsStore": "osxkeychain"` or `"desktop"`), there's usually nothing
plaintext to migrate - jit only takes over registries whose credentials
actually sit base64-encoded in the file, and it never replaces an
existing credential store.
