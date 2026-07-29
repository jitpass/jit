---
title: Wrap clisso with jit
description: jit wrap clisso captures the AWS credentials clisso mints at login, so they land in the vault instead of ~/.aws/credentials.
---

# clisso - SSO-minted AWS credentials (capture)

[clisso](https://github.com/allcloud-io/clisso) logs into OneLogin or Okta
and mints temporary AWS credentials - and, by default, writes them to
`~/.aws/credentials` in plaintext. That's a different problem from the
tools above: there's no long-lived token to move into the vault once,
because a fresh secret appears with **every login**, re-creating the
plaintext file [`jit migrate`](../migrate/aws.md) just cleaned.

```sh
jit wrap clisso
```

installs a capture shim. You keep typing exactly what you type today:

```sh
clisso get prod          # MFA prompts appear exactly as before
```

but under the hood the shim runs clisso with its own
`--output credential_process` flag - so the credentials are *printed*, not
written - captures that output, and stores it in the vault as profile
`aws-prod`. The AWS CLI and every SDK fetch it through the same
`credential_process` hook the [aws migration](../migrate/aws.md) wires,
expiration included. **No plaintext AWS credential touches disk at any
point.** If a pre-wrap plaintext section is still sitting in
`~/.aws/credentials` (it would silently outrank the vault in AWS's own
resolution order), the first capture strips it, after an encrypted backup.

The login itself is untouched: capture happens in *your* terminal, so
OneLogin push approvals, OTP entry, device menus, and role selection all
work exactly as before. That's the point of capturing at `clisso get`
rather than having jit re-run clisso in the background when credentials
expire - a background `credential_process` has no terminal to show an MFA
prompt on.

## When the session expires

Nothing changes from your current routine: when the session dies (your
`duration`, up to 12 h), AWS commands report the credentials expired and
you run `clisso get <app>` again. jit serves the real `Expiration` to
SDKs, so long-running processes refresh on schedule instead of caching a
dead token.

## What passes through untouched

Every clisso invocation that isn't a plain `get` - `clisso apps`,
`clisso providers`, `clisso status`, `clisso cp`, `--help` - and any `get`
where you explicitly passed `-o/--output` runs the real clisso unchanged.
The shim reroutes the default destination; it doesn't argue with explicit
flags.

`clisso status` reads `~/.aws/credentials`, which after wrapping stays
empty - use `jit status --secrets` to see the captured profiles instead.

## What this wrap does not cover

clisso's own long-lived secret - the OneLogin API `client-secret` in
`~/.clisso.yaml` - is out of this wrap's scope. `jit scan` reports it as a
manual finding: clisso rewrites that file itself, so jit doesn't protect
it in place. If the machine may be exposed, rotate it in OneLogin.

## Verify

```sh
clisso get <app>
aws sts get-caller-identity --profile <app>
```

## Undo

`jit wrap undo clisso` removes the shim - future logins write plaintext
again, as before. Credentials already captured stay in the vault and keep
serving through `credential_process` until they expire.
