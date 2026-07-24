---
title: Wrap the CircleCI CLI with jit
description: Keep your CircleCI personal API token out of ~/.circleci/cli.yml - injected as CIRCLECI_CLI_TOKEN just-in-time.
---

# circleci - CircleCI CLI

`circleci setup` stores your personal API token in plaintext in
`~/.circleci/cli.yml`, as the top-level `token` field. Wrapping moves it into
the vault and injects it as `CIRCLECI_CLI_TOKEN` into each `circleci`
invocation only.

## Wrap it

```sh
jit wrap circleci
```

jit reads `token` from `~/.circleci/cli.yml`, stores it at
`wrap-circleci/CIRCLECI_CLI_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/circleci` shim plus the
`wrap-circleci` profile.

## Verify

```sh
circleci diagnostic
```

## How it works

The shim injects `CIRCLECI_CLI_TOKEN` from the vault into each `circleci`
process - the CLI's documented env credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo circleci
```

## Notes

- The non-secret `host` line in `cli.yml` passes through untouched; only
  `token` is scrubbed.
- No token stored yet? Set one first with
  `jit vault set wrap-circleci/CIRCLECI_CLI_TOKEN`, then wrap.
