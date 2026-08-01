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
✓ 2 profiles, 5 secret references resolve cleanly
```

It checks project-local profiles, the home-rooted global ones, **and the
profile behind every registered mount** — that last set may live in a project
tree the current directory never walks into, yet jit is serving it right now,
so a broken reference there is just as real. This is the same set
[`jit status`](../reference/commands/jit_status.md) and `jit vault orphans`
reconcile.

On the default full run it also folds in the health checks that used to take
`jit status` and the retired [`jit wrap doctor`](../wrap/troubleshooting.md) to see: the
background service, your vault backup, and any wrapped-tool shims. These are
surfaced as advisory warnings.

It exits **2** when something this setup depends on is actually broken:

- a profile's own secret is **missing**, **corrupt**, or **unparseable**, or
  names something that isn't a legal vault path at all (**bad path**)
- this Mac's **master key is gone** from the keychain, so the whole vault is
  undecryptable — every envelope stays structurally intact, which is exactly
  why nothing else notices
- a **master-key rotation** is in progress or was interrupted, which blocks
  every command that writes to the vault
- a wrapped tool's **shim installation is damaged** — a missing shim, a
  symlink pointing at nothing, a vanished `wrap-<tool>` profile — so that tool
  now runs unwrapped or not at all

Everything else it reports is a warning, never a failure:

- an **orphaned** secret in the vault that no profile references (`--orphans`)
- a profile name **shadowed** across scopes (the same name in both project and
  global; the project copy wins and the global one is ignored)
- a registered **mount** whose profile manifest won't load
- the **audit trail** has stopped recording (writes are swallowed by design,
  so nothing else would ever tell you)
- a stopped service, or a stale or missing vault backup
- a shim complaint that is only true of the shell you are in (the shim dir
  absent from *this* `PATH`) — a CI job that doesn't put it there is not a
  broken machine

It never decrypts a secret or triggers Touch ID (existence and envelope
structure are both plaintext on disk), so it is safe to run often. Useful
flags:

- `--profile <name>` narrows the run to a single profile and skips the
  service/backup/wrap sections. The whole-vault key checks still run: with no
  master key, no profile resolves, and reporting otherwise would be false.
- `--wrap` runs only the wrapped-tool checks, and never opens the vault — so
  it still works when the vault is what's broken. Replaces `jit wrap doctor`.
- `--verbose` lists every check that passed, not just the ones that failed.
- `--strict` makes the advisory warnings count toward the exit code too, for
  a pipeline that wants a stale backup to gate a deploy.
- `--format json` prints a machine-readable snapshot: `schema_version`, a
  `tool` block naming the binary that produced it (version, build, and whether
  it satisfies jit's release-signing requirement), `ok`, and structured
  `problems`/`warnings` arrays — each entry carrying `kind`, `profile`,
  `variable`, `path`, `detail`, and an `action` you can act on without parsing
  prose.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | nothing broken |
| `1` | **doctor itself** couldn't run — a bad flag, an unreadable vault root |
| `2` | findings: something is broken (or, with `--strict`, warned about) |

Exit 2 is the findings code, the same convention
[`jit scan --fail-on`](../reference/commands/jit_scan.md) uses. The split
matters for CI: exit 1 has to mean "the check is broken", or a pipeline
can't tell a genuinely unhealthy machine from a doctor that never ran.
In JSON mode a findings run still prints its full snapshot; an exit-1 run
prints none, which is itself the signal.
