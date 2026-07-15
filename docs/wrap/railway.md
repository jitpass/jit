---
title: Wrap the Railway CLI with jit
description: Keep your Railway token out of ~/.railway/config.json - injected as RAILWAY_TOKEN just-in-time.
---

# railway - Railway CLI

`railway login` stores your token in plaintext in
`~/.railway/config.json`. Wrapping moves it into the vault and injects it
as `RAILWAY_TOKEN` into each `railway` invocation only.

## Wrap it

```sh
jit wrap railway
```

jit reads the user token from `config.json`, stores it at
`wrap-railway/RAILWAY_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/railway` shim plus the
`wrap-railway` profile.

## Verify

```sh
railway whoami
```

## How it works

The shim injects `RAILWAY_TOKEN` from the vault into each `railway`
process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo railway
```

## Notes

- A re-`railway login` writes plaintext again - re-run `jit wrap railway`
  after.
