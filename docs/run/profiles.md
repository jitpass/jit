---
title: Profiles
description: The YAML manifest mapping environment variables to vault paths - names only, safe to commit.
---

# Profiles

Migration's bookkeeping unit is the **profile**: a small YAML manifest
mapping environment-variable names to vault paths. `jit migrate` and
`jit wrap` create them automatically; `jit run`, `jit export`, and
`jit doctor` resolve them. You can inspect them any time:

```
$ jit profile list
aws-admin    global    /Users/alex/.jit/profiles/aws-admin.yaml
myapp        project   /Users/alex/code/myapp/.jit/profiles/myapp.yaml

$ jit profile show myapp
myapp (project: /Users/alex/code/myapp/.jit/profiles/myapp.yaml)
  DATABASE_URL -> myapp/DATABASE_URL
  STRIPE_API_KEY -> myapp/STRIPE_API_KEY
```

These never print a secret value, only names and vault paths, which is
exactly why a profile manifest is safe to commit.

Profiles come in two scopes: **project** profiles live in the project's
`.jit/profiles/` (created by `jit migrate local` for that project's
layers), and **global** profiles live in `~/.jit/profiles/` (machine-wide
migrations and [wrapped tools](../wrap/index.md), whose profiles are named
`wrap-<tool>`).

## Checking a profile's health: `jit doctor`

`jit doctor` verifies every path a profile references actually exists in
the vault, catching "the profile says X but nothing's stored there" before
an app crashes on an empty environment variable:

```
$ jit doctor
✓ 2 profile(s), 5 secret reference(s) all resolve cleanly
```

It never decrypts a secret or triggers Touch ID, takes `--format json`,
and exits non-zero on a problem, so it works as a CI health check.
