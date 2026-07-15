---
title: Wrap Terraform with jit
description: jit wrap terraform uses Terraform's native credentials_helper hook - terraform login/logout keep working, no shim needed.
---

# terraform - Terraform CLI (native hook)

`jit wrap terraform` doesn't install a shim. Terraform has its own
pluggable credential mechanism - a `credentials_helper` in
`~/.terraformrc` - and jit hooks that instead, because it covers what a
shim can't: `terraform login` and `logout` keep working, with a re-login
landing directly in the vault instead of back in a plaintext file.

```sh
jit wrap terraform
```

routes to the same flow as
[`jit migrate --only=terraform`](../migrate/terraform.md): the Terraform
Cloud token leaves `~/.terraform.d/credentials.tfrc.json` for the vault,
and Terraform fetches it on demand through the helper.

The full walkthrough - what gets rewritten, rotation via `terraform
login`, the helper protocol - is on
**[Migrating Terraform Cloud tokens](../migrate/terraform.md)**.

## Undo

[`jit migrate undo`](../migrate/undo-and-remove.md) restores the original
token file byte-for-byte from its encrypted backup.

## Note

AWS credentials used by the Terraform *AWS provider* are the
[`aws` wrap](./aws.md)'s territory - the two hooks compose: a
`terraform plan` against AWS resolves both through jit.
