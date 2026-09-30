---
title: Wrap the Pulumi CLI with jit
description: Inject a durable Pulumi access token as PULUMI_ACCESS_TOKEN just-in-time.
---

# pulumi - Pulumi CLI

Pulumi reads its access token from `PULUMI_ACCESS_TOKEN`. Wrapping keeps that
token in the vault and injects it into each `pulumi` invocation only.

Unlike most wrapped tools, jit does **not** auto-migrate from Pulumi's config
file: `pulumi login` writes the token into `~/.pulumi/credentials.json` under an
`accessTokens` map keyed by the backend URL (`https://api.pulumi.com`), which
jit's flat file selectors can't address. So you provide the token once, then
wrap.

## Wrap it

```sh
jit vault set wrap-pulumi/PULUMI_ACCESS_TOKEN   # paste a token from app.pulumi.com/account/tokens
jit wrap pulumi
```

jit stores it at `wrap-pulumi/PULUMI_ACCESS_TOKEN` and installs the
`~/.jit/shims/pulumi` shim plus the `wrap-pulumi` profile.

## Verify

```sh
pulumi whoami
```

## How it works

The shim injects `PULUMI_ACCESS_TOKEN` from the vault into each `pulumi`
process - the CLI's documented, highest-priority credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo pulumi
```

## Notes

- Create the token at
  [app.pulumi.com/account/tokens](https://app.pulumi.com/account/tokens). A
  durable access token is what `PULUMI_ACCESS_TOKEN` expects; don't paste the
  short-lived value `pulumi login` may have cached.
- Pulumi writes the token it was given into `~/.pulumi/credentials.json`
  on every command, not only on `pulumi login`. So the wrap sets
  `PULUMI_CREDENTIAL_STORE=auto`, which tells Pulumi 3.258.0 and later to
  encrypt that file with a key the OS keeps. Older Pulumi ignores it:
  upgrade, or the wrapped token lands in that file in plaintext. A value
  you set yourself is left alone.
