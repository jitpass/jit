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

## The OneLogin client-secret

The same wrap moves clisso's own long-lived secret. A OneLogin provider
keeps its API `client-secret` in `~/.clisso.yaml` in plaintext - and
unlike the sessions it mints, that one never expires: it can start the
whole chain for every configured app. `jit wrap clisso` vaults it and
leaves a pointer in its place:

```yaml
providers:
    acme:
        client-id: abc123
        client-secret: jit://vault/wrap-clisso/acme-client-secret
        type: onelogin
```

On each `clisso get`, jit renders the real config in memory and hands it
to clisso over a pipe (`-c`), so the plaintext exists only inside that one
run. The file on disk stays a decoy.

The pointer is the *stored value*, not a comment, because clisso rewrites
this file itself - `clisso apps create`, `providers create`, `cp` - and
viper preserves values it doesn't understand. After any of those commands
jit reconciles the file automatically: a fresh plaintext secret written by
clisso is moved to the vault and replaced with a pointer before your
prompt returns.

An Okta provider has nothing to move here - its password lives in your OS
keychain already.

If you run clisso *without* the shim (a direct path invocation), the
pointer goes to OneLogin and authentication fails with a clear auth error.
That's deliberate: the alternative is a silent fallback to the plaintext
this wrap exists to remove.

## When the session expires

Nothing changes from your current routine: when the session dies (your
`duration`, up to 12 h), AWS commands report the credentials expired and
you run `clisso get <app>` again. jit serves the real `Expiration` to
SDKs, so long-running processes refresh on schedule instead of caching a
dead token.

## What passes through untouched

Every clisso invocation that isn't a plain `get` - `clisso apps`,
`clisso providers`, `clisso status`, `clisso cp`, `--help` - and any `get`
where you explicitly passed `-o/--output` runs the real clisso unchanged
(config still served, `apps`/`providers`/`cp` still reconciled). The shim
reroutes the default destination; it doesn't argue with explicit flags. A
`-c/--config` you pass yourself is always honored over jit's served one.

`clisso status` reads `~/.aws/credentials`, which after wrapping stays
empty - use `jit status --secrets` to see the captured profiles instead.

## Rotating the client-secret

The new value goes into the vault, not the file:

```sh
jit vault set wrap-clisso/<provider>-client-secret
```

## Verify

```sh
clisso get <app>
aws sts get-caller-identity --profile <app>
```

## Undo

`jit wrap undo clisso` removes the shim. Credentials already captured stay
in the vault and keep serving through `credential_process` until they
expire - but `~/.clisso.yaml` still holds a pointer, so restore it too:

```sh
jit wrap undo clisso
jit migrate undo              # puts the real client-secret back in the file
```

[`jit migrate undo`](../migrate/undo-and-remove.md) restores the config
byte-for-byte from its encrypted backup.
