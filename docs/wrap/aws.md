---
title: Wrap the AWS CLI with jit
description: jit wrap aws uses AWS's native credential_process hook - covering the CLI and every SDK, no shim needed.
---

# aws - AWS CLI (native hook)

`jit wrap aws` doesn't install a shim. AWS has its own pluggable
credential mechanism - `credential_process` in `~/.aws/config` - and jit
hooks that instead, because it reaches what a shim never could: boto3,
aws-sdk-go, the Terraform AWS provider, and every other SDK that reads
the shared config.

```sh
jit wrap aws
```

routes to the same flow as [`jit migrate --only=aws`](../migrate/aws.md):
the keys leave `~/.aws/credentials` for the vault, and everything fetches
on demand through `credential_process`. After that, **that file no longer
holds the real value** - though the CLI can still cache credentials it
mints for itself, which
[Migrating AWS credentials](../migrate/aws.md#what-jit-does-not-cover)
covers.

The full walkthrough - what gets rewritten, rotation, the plumbing
protocol - is on **[Migrating AWS credentials](../migrate/aws.md)**.

## Verify

```sh
aws sts get-caller-identity
```

## Undo

[`jit migrate undo`](../migrate/undo-and-remove.md) restores
`~/.aws/credentials` byte-for-byte from its encrypted backup.
