---
title: Wrap the Fly.io CLI (flyctl) with jit
description: Keep your Fly.io access token out of ~/.fly/config.yml - injected as FLY_API_TOKEN just-in-time.
---

# flyctl - Fly.io CLI

`flyctl auth login` stores your access token in plaintext in
`~/.fly/config.yml`. Wrapping moves it into the vault and injects it as
`FLY_API_TOKEN` into each `flyctl` invocation only.

## Wrap it

```sh
jit wrap flyctl
```

jit reads `access_token` from `config.yml`, stores it at
`wrap-flyctl/FLY_API_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/flyctl` shim plus the
`wrap-flyctl` profile.

## Verify

```sh
flyctl auth whoami
```

## How it works

The shim injects `FLY_API_TOKEN` from the vault into each `flyctl`
process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo flyctl
```

## Notes

- If you invoke the tool as `fly` (the common alias/symlink), the wrap
  covers invocations of `flyctl`; wrap `fly` too via
  [`jit wrap add fly --env FLY_API_TOKEN=wrap-flyctl/FLY_API_TOKEN`](./custom-tools.md)
  so both names inject the same vaulted token.
- A re-`flyctl auth login` writes plaintext again - re-run
  `jit wrap flyctl` after.
