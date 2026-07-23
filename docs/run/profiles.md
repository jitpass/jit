---
title: Profiles
description: The YAML manifest mapping environment variables to vault paths - names only, safe to commit.
---

# Profiles

Migration's bookkeeping unit is the **profile**: a small YAML manifest
mapping environment-variable names to vault paths. `jit migrate` and
`jit wrap` create them automatically; `jit run`, `jit export`, and
`jit doctor` resolve them. A manifest holds only names and vault paths,
never a secret value, which is exactly why it is safe to commit:

```
# .jit/profiles/myapp.yaml
DATABASE_URL: myapp/DATABASE_URL
STRIPE_API_KEY: myapp/STRIPE_API_KEY
```

To see how your stored secrets line up against your profiles, use
[`jit status --secrets`](../reference/commands/jit_status.md). It reconciles
the vault against the profiles jit can see and sorts every stored secret into
one of three states: **wired here** (a project-local profile uses it),
**managed elsewhere** (referenced only by a global profile or a mount), or
**unreferenced** (a candidate orphan). That is the whole picture a per-manifest
listing could never draw, since a bare manifest says nothing about the secrets
it doesn't touch.

Profiles come in two scopes: **project** profiles live in the project's
`.jit/profiles/` (created when you migrate that project's layers), and
**global** profiles live in `~/.jit/profiles/` (machine-wide
migrations and [wrapped tools](../wrap/index.md), whose profiles are named
`wrap-<tool>`).

## Checking a profile's health: `jit doctor`

`jit doctor` is the one-shot "what's wrong" rollup for a jit setup. Its core
job is to verify every path a profile references: the secret exists in the
vault **and** its envelope is one this build of jit can actually read,
catching both "the profile says X but nothing's stored there" and "the file
is there but corrupt" before an app crashes on an empty (or unreadable)
environment variable:

```
$ jit doctor
✓ 2 profile(s), 5 secret reference(s) all resolve cleanly
```

On the default full run it also folds in the health checks that used to take
[`jit status`](../reference/commands/jit_status.md) and
[`jit wrap doctor`](../wrap/troubleshooting.md) to see: the background service,
your vault backup, and any wrapped-tool shims. These are surfaced as advisory
warnings.

It exits non-zero **only** when a profile's own secret is missing, corrupt, or
unparseable. Everything else it reports is a warning, never a failure:

- an **orphaned** secret in the vault that no profile references (`--orphans`)
- a profile name **shadowed** across scopes (the same name in both project and
  global; the project copy wins and the global one is ignored)
- a stopped service, a stale or missing vault backup, a broken shim

It never decrypts a secret or triggers Touch ID (existence and envelope
structure are both plaintext on disk), so it is safe to run often. Useful
flags:

- `--profile <name>` narrows the run to a single profile and skips the
  service/backup/wrap sections.
- `--verbose` lists every variable-to-path reference it cleared.
- `--format json` prints a machine-readable snapshot: `ok` plus structured
  `problems` and `warnings` arrays (each entry carries `kind`, `profile`,
  `variable`, `path`, and `detail`), and it still exits non-zero on a problem,
  so it works as a CI health check.
