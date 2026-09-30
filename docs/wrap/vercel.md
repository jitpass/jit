---
title: Wrap the Vercel CLI with jit
description: Keep your Vercel token out of com.vercel.cli/auth.json - injected as VERCEL_TOKEN just-in-time.
---

# vercel - Vercel CLI

`vercel login` stores your token in plaintext in
`~/Library/Application Support/com.vercel.cli/auth.json`. Wrapping moves
it into the vault and injects it as `VERCEL_TOKEN` into each `vercel`
invocation only.

## Wrap it

```sh
jit wrap vercel
```

jit reads `token` from `auth.json`, stores it at
`wrap-vercel/VERCEL_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/vercel` shim plus the
`wrap-vercel` profile.

## Verify

```sh
vercel whoami
```

## How it works

The shim injects `VERCEL_TOKEN` from the vault into each `vercel`
process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo vercel
```

## Notes

- `vercel login` is a browser (OAuth) login with a short-lived token
  the CLI refreshes itself. jit runs it with no token injected and
  leaves its result alone, so the wrap keeps the durable token you
  vaulted. Create one at vercel.com/account/tokens and
  `jit vault set wrap-vercel/VERCEL_TOKEN`.
- `vercel logout` runs with no token injected, so it can't revoke the
  wrapped token. `vercel switch` is refused: pass `--scope <team>` on
  each command instead.
