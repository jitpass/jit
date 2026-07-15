---
title: Wrap the Stripe CLI with jit
description: Keep your Stripe API key out of ~/.config/stripe/config.toml - injected as STRIPE_API_KEY just-in-time.
---

# stripe - Stripe CLI

`stripe login` stores API keys in plaintext in
`~/.config/stripe/config.toml`. Wrapping moves the key into the vault and
injects it as `STRIPE_API_KEY` into each `stripe` invocation only.

## Wrap it

```sh
jit wrap stripe
```

jit reads the default project's key from `config.toml` - the live-mode key
if present, otherwise the test-mode key - stores it at
`wrap-stripe/STRIPE_API_KEY`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/stripe` shim plus the
`wrap-stripe` profile.

## Verify

```sh
stripe config --list
```

## How it works

The shim injects `STRIPE_API_KEY` from the vault into each `stripe`
process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo stripe
```

## Notes

- A Stripe **live-mode** key on disk is exactly the kind of finding
  [`jit audit`](../audit/index.md) rates as production-indicating - worth
  wrapping first.
- Multiple Stripe projects: the catalog extracts the default project's
  key. For another project's key, use
  [`jit wrap add`](./custom-tools.md) with `STRIPE_API_KEY` pointed at a
  different vault path.
