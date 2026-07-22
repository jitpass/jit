---
title: Wrap the Supabase CLI with jit
description: Keep your Supabase personal access token out of ~/.supabase/access-token - injected as SUPABASE_ACCESS_TOKEN just-in-time.
---

# supabase - Supabase CLI

`supabase login` stores your personal access token in the OS keyring when
it can, but falls back to plaintext in `~/.supabase/access-token` (the
file's entire contents are the token) - common on headless Linux,
containers, and anywhere the keyring isn't available. Wrapping moves it
into the vault and injects it as `SUPABASE_ACCESS_TOKEN` into each
`supabase` invocation only. The env var is the CLI's highest-priority
token source, so the injection always wins.

## Wrap it

```sh
jit wrap supabase
```

jit reads the token file whole, stores it at
`wrap-supabase/SUPABASE_ACCESS_TOKEN`, scrubs the plaintext (original
backed up encrypted), and installs the `~/.jit/shims/supabase` shim plus
the `wrap-supabase` profile.

## Verify

```sh
supabase projects list
```

## How it works

The shim injects `SUPABASE_ACCESS_TOKEN` from the vault into each
`supabase` process. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo supabase
```

## Notes

- If your login went to the OS keyring (the default on macOS), there is
  no plaintext file and discovery finds nothing - that copy is already
  encrypted at rest, so wrapping is optional. To wrap anyway (e.g. to
  gate use behind the biometric service), generate a token at
  [supabase.com/dashboard/account/tokens](https://supabase.com/dashboard/account/tokens),
  store it with `jit vault set wrap-supabase/SUPABASE_ACCESS_TOKEN`, and
  re-run `jit wrap supabase`.
- Tokens are long-lived with server-managed expiry (no client-side
  refresh), so the vaulted copy keeps working until you revoke it.
- A re-`supabase login` on a keyring-less machine writes the plaintext
  file again - re-run `jit wrap supabase` after.
