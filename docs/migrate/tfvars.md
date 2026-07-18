---
title: Migrating Terraform tfvars files
description: Secret values in terraform.tfvars move to the vault; terraform reads them back as TF_VAR_ environment variables through jit run.
---

# Terraform tfvars files

`terraform.tfvars` and `*.auto.tfvars` files routinely hold real secrets -
database passwords, API tokens - as plaintext `name = "value"` lines.
`jit migrate` (category `tfvars`) moves each secret-shaped value into the
vault and deletes its line from the file, leaving a comment naming what
moved and how to run terraform now.

The serving side is Terraform's own variable precedence: `TF_VAR_<name>`
environment variables rank below every tfvars file but above a variable's
`default`. Removing the assignment from the file is exactly what activates
the env var - no wrapper, no rewrite of your Terraform code:

```
$ jit run --profile myapp-tfvars -- terraform apply
```

or, for a whole shell session:

```
$ eval "$(jit export --profile myapp-tfvars)"
```

## What moves, what stays

Only top-level, one-line `name = "value"` string assignments whose name
looks secret-shaped (`*password*`, `*token*`, `*key*`, ...) are migrated.
Everything else - `region`, instance types, maps, lists, heredocs - stays
in the file byte-for-byte. A secret-shaped value the parser can't fully
understand (a heredoc certificate, a list, an interpolated string) is
**left in place and reported**, never half-migrated.

All tfvars files in one directory feed the same Terraform root, so they
migrate together into **one profile per directory**, processed in
Terraform's own precedence order (`terraform.tfvars` first, then
`*.auto.tfvars` lexically) - if the same variable is assigned twice, the
value Terraform would actually have used is what lands in the vault.

## What to expect

- **Run terraform through jit afterwards.** A bare `terraform apply` will
  prompt for the missing variable (or error with `-input=false`) - a loud,
  recoverable failure, never a silently wrong value. The comment jit
  leaves in the file shows the exact `jit run` command.
- Terraform ignores `TF_VAR_` variables that don't match a declared
  `variable` block, so injecting the whole profile is harmless even if
  some entries go stale.
- If the tfvars file was ever committed to git, `migrate` warns: the old
  value is still in git history - rotate it.
- `jit migrate local` covers the project you're standing in;
  `jit migrate home` finds tfvars files across every project under
  `$HOME`.

Looking for the **Terraform Cloud API token** (`terraform login`)? That's
the separate [`terraform` category](./terraform.md). Reversing this
migration: [`jit migrate undo`](./undo-and-remove.md).
