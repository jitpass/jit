---
title: Wrap the CircleCI CLI with jit
description: Keep your CircleCI personal API token out of the CLI's config file - injected as CIRCLE_TOKEN just-in-time.
---

# circleci - CircleCI CLI

The CircleCI CLI keeps your personal API token in the keyring, or in
plaintext as the top-level `token` field of `~/.config/circleci/config.yml`.
Releases before v1 used `~/.circleci/cli.yml`. Wrapping moves it into the
vault and injects it into each `circleci` invocation only.

## Wrap it

```sh
jit wrap circleci
```

jit reads `token` from whichever of those files has it, stores it at
`wrap-circleci/CIRCLECI_CLI_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/circleci` shim plus the
`wrap-circleci` profile.

## Verify

```sh
circleci auth me
```

On a release older than v1, run `circleci diagnostic` instead.

## How it works

The shim injects the token from the vault into each `circleci` process
twice: as `CIRCLE_TOKEN`, which v1 reads, and as `CIRCLECI_CLI_TOKEN`,
which older releases read. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo circleci
```

## Notes

- The non-secret `host` line passes through untouched; only `token` is
  scrubbed.
- A token in the keyring can't be moved automatically. Set it with
  `jit vault set wrap-circleci/CIRCLECI_CLI_TOKEN`, then wrap.
- No token stored yet? Set one first with
  `jit vault set wrap-circleci/CIRCLECI_CLI_TOKEN`, then wrap.
