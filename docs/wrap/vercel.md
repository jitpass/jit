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

- A re-`vercel login` writes plaintext again - re-run `jit wrap vercel`
  after.
