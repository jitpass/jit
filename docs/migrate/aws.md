---
title: Migrating AWS credentials
description: ~/.aws/credentials moves to the vault; credential_process serves the CLI and every SDK on demand.
---

# AWS credentials

`~/.aws/credentials` is the classic long-lived plaintext credential file.
`jit migrate` (category `aws`) moves each profile's access key, secret key,
and session token into the vault and wires a `credential_process` line into
`~/.aws/config` - after which **no file with the real value exists at all**:

```ini
[profile myprofile]
credential_process = jit aws-credential-process --profile aws-myprofile
```

`credential_process` is AWS's own extension point, and it's consulted by
everything that reads the shared config: the `aws` CLI, boto3, aws-sdk-go,
the Terraform AWS provider - every SDK. That's why this is a *native hook*
rather than a shim; nothing about how you invoke your tools changes.

## What to expect

- Each credential fetch needs the vault unlocked - the
  [agent](../agent/index.md)'s shared session, or a Touch ID prompt.
- SDKs cache the returned credentials per-process, so a long-running
  process doesn't re-prompt on every API call.
- `jit wrap aws` routes to this same migration - there's one AWS
  mechanism, whichever command you arrive through.

## Rotating keys

New access keys go into the vault, not into a file:
`jit vault set <path>` on the paths shown by
`jit profile show aws-myprofile`. Everything picks the new values up on
its next fetch.

## Plumbing

`jit aws-credential-process` is the [plumbing
command](../reference/plumbing.md) the config invokes - you never run it by
hand. Reversing the migration: [`jit migrate
undo`](./undo-and-remove.md).
