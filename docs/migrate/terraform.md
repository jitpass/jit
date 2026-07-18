---
title: Migrating Terraform Cloud tokens
description: The credentials.tfrc.json token moves to the vault; a credentials_helper keeps terraform login/logout working.
---

# Terraform Cloud token

`terraform login` writes a long-lived API token to
`~/.terraform.d/credentials.tfrc.json` in plaintext. `jit migrate`
(category `terraform`) moves each host's token into the vault and wires a
`credentials_helper` into `~/.terraformrc` - Terraform's own pluggable
credential mechanism:

```hcl
credentials_helper "jit" {}
```

Terraform then asks jit for the token on demand (`get`), and - the part a
shim could never cover - **`terraform login` and `logout` keep working**:
a re-login lands directly in the vault (`store`) instead of back in a
plaintext file, and `logout` removes it (`forget`).

## What to expect

- Each token fetch needs the vault unlocked - the
  [agent](../agent/index.md)'s shared session, or a Touch ID prompt.
- **Rotating a token is just `terraform login` again.** No vault commands
  needed; the helper stores the new token for you.
- `jit wrap terraform` routes to this same migration.

`jit terraform-credentials <get|store|forget>` is the [plumbing
command](../reference/plumbing.md) Terraform invokes - you never run it by
hand. Reversing the migration: [`jit migrate undo`](./undo-and-remove.md).

Looking for secrets in **`terraform.tfvars` variable files**? That's the
separate [`tfvars` category](./tfvars.md).
