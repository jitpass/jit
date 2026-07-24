---
title: Wrap the HashiCorp Vault CLI with jit
description: Keep your Vault token out of ~/.vault-token - injected as VAULT_TOKEN just-in-time.
---

# vault - HashiCorp Vault CLI

`vault login` writes your current token to `~/.vault-token`, in plaintext - the
whole file is the token. Wrapping moves it into the vault (jit's vault) and
injects it as `VAULT_TOKEN` into each `vault` invocation only.

## Wrap it

```sh
jit wrap vault
```

jit reads `~/.vault-token`, stores it at `wrap-vault/VAULT_TOKEN`, scrubs the
plaintext (original backed up encrypted), and installs the `~/.jit/shims/vault`
shim plus the `wrap-vault` profile.

## Verify

```sh
vault token lookup
```

## How it works

The shim injects `VAULT_TOKEN` from the vault into each `vault` process -
Vault's documented, highest-priority credential, which overrides the token
file. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo vault
```

## Notes

- **Token TTL.** Vault tokens carry a lease and expire. Wrap a **long-lived**
  token (a periodic or renewable service token, or a dev root token); a
  short-lived one will break when it expires, and you'd re-wrap after the next
  `vault login`. This is the same caveat wrangler's OAuth token has.
- `VAULT_ADDR` and `VAULT_NAMESPACE` are not secrets and are not wrapped - set
  them as normal (usually in your shell profile).
