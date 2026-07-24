---
title: Wrap the Sentry CLI (sentry-cli) with jit
description: Keep your Sentry auth token out of ~/.sentryclirc - injected as SENTRY_AUTH_TOKEN just-in-time.
---

# sentry-cli - Sentry CLI

`sentry-cli login` stores your auth token in plaintext in `~/.sentryclirc`,
under the `[auth]` section. Wrapping moves it into the vault and injects it as
`SENTRY_AUTH_TOKEN` into each `sentry-cli` invocation only.

## Wrap it

```sh
jit wrap sentry-cli
```

jit reads the `[auth] token` from `~/.sentryclirc`, stores it at
`wrap-sentry-cli/SENTRY_AUTH_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/sentry-cli` shim plus the
`wrap-sentry-cli` profile.

## Verify

```sh
sentry-cli info
```

## How it works

The shim injects `SENTRY_AUTH_TOKEN` from the vault into each `sentry-cli`
process - the CLI's documented, highest-priority credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo sentry-cli
```

## Notes

- The scrub only clears the `token` under `[auth]`; the non-secret
  `[defaults]` section (org, project, url) passes through untouched.
- No token in `~/.sentryclirc` yet? Set one first with
  `jit vault set wrap-sentry-cli/SENTRY_AUTH_TOKEN`, then wrap.
