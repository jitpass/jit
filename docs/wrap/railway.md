---
title: Wrap the Railway CLI with jit
description: Keep your Railway token out of ~/.railway/config.json - injected as RAILWAY_API_TOKEN just-in-time.
---

# railway - Railway CLI

`railway login` stores your token in plaintext in
`~/.railway/config.json`. Wrapping moves it into the vault and injects it
as `RAILWAY_API_TOKEN` into each `railway` invocation only.

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

The shim injects `RAILWAY_API_TOKEN` from the vault into each `railway`
process. That is railway's variable for an account token.
`RAILWAY_TOKEN` is for a project token, and railway sends it
differently, so an account token in it doesn't work. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo railway
```

## Notes

- `railway login` runs with no token injected, and jit then moves the
  token it saved into the vault. Current railway logins are browser
  OAuth with a short-lived token jit leaves alone. For those, create an
  account token in Railway and `jit vault set wrap-railway/RAILWAY_TOKEN`.
- Wrapped with an older jit? That wrap injected `RAILWAY_TOKEN`.
  Re-run `jit wrap railway` to switch it; the vaulted token is reused.
