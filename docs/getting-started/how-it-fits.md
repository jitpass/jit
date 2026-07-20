---
title: How it all fits together
description: The mental model - the three ways a tool reads a credential, how you integrate each (migrate vs wrap), and how you run it (native hook, shim, or jit run).
---

# How it all fits together

jit has one job: take the secrets that already sit in plaintext across your
Mac, move them into an encrypted vault, and leave every tool working exactly
as before. This page is the mental model that makes the rest of the docs
click. For the moving parts underneath (the vault, the agent, live mounts),
see **[How it works](./how-it-works.md)**; this page is about how you reason
about the tool.

Two questions organize everything: **how did the secret get into the vault**
(integrate), and **how does it reach the tool at use time** (run).

## The one distinction that decides the rest

A tool reads its credential in exactly one of three ways. This is not a
preference you pick, it is a fact about the tool, and it decides both how you
integrate it and how you run it.

| Delivery model | The tool reads its secret by... | Examples |
| --- | --- | --- |
| **Call-out** | Asking jit on demand through the tool's own credential mechanism. Nothing is stored between calls. | `aws`, `kubectl`, `terraform`, `docker`, modern `sops` |
| **Env-delivered** | Reading an environment variable jit injects into the one process, which then vanishes. | `.env` files, shell configs, tfvars, MCP configs, `gh` / `stripe` tokens |
| **File-delivered** | Reading a file at a fixed path. jit leaves a [live mount](../run/mounts.md) there: decoy by default, real only when granted. | gcloud ADC, SOPS age key, `~/.npmrc` |

## Integrating: two entry points

- **[`jit migrate`](../migrate/index.md)** is the bulk mover. It scans your
  machine, vaults the secrets that live in files it understands, and wires up
  the correct delivery model for each. This is how most things get in.
- **[`jit wrap`](../wrap/index.md)** is the per-tool bridge for a single CLI
  that carries its own token. It either installs a small `PATH` shim (for a
  tool with no native hook, like `gh`) or, for a tool that does have one
  (`aws`, `terraform`, `docker`), routes to migrate's mechanism instead.

So the two overlap: `wrap` is really "handle this one command," and under the
hood it delegates to a native hook or installs a shim as appropriate.

## Running: three patterns, decided by the model

You do not freely choose how a tool runs; its delivery model does. Two of
these three let you "just type the command," but through different machinery,
which is the subtlety worth internalizing.

| Pattern | What you actually run | Who does the work |
| --- | --- | --- |
| **Native hook** (call-out) | `aws s3 ls`, `terraform apply` | The tool calls jit on demand through its own credential mechanism. No prefix, no shim. |
| **Wrap shim** (looks native) | `gh pr list`, `gcloud storage ls` | A `PATH` shim transparently runs `jit run` for you. Feels like the bare tool; it is jit underneath. |
| **Explicit [`jit run`](../run/index.md)** | `jit run ./deploy.sh`, `jit run --with gcp -- terraform apply` | You launch through jit directly: a project's `.env`, a named `--profile`, or a machine-global `--with` grant. |

The subtlety in one line: `aws` is *truly* native (jit hooked its
`credential_process`, nothing wraps it), but a grant-wrapped `gcloud` only
*looks* native, the shim is quietly running `jit run --with gcp -- gcloud`.

## One credential, all the way through

Following the gcloud application-default credentials (a file-delivered
secret) end to end:

1. **Find.** [`jit audit`](../audit/index.md) flags
   `~/.config/gcloud/application_default_credentials.json` as a plaintext
   refresh token.
2. **Integrate.** `jit migrate home --only gcp` moves the secret field into
   the vault and leaves a live mount at the same path. Read it cold now and
   you get a decoy.
3. **Use, one-off.** `jit run --with gcp -- terraform apply` grants the real
   file to that run's process tree, and only that tree, until it exits.
4. **Use, natively.** `jit wrap add gcloud --grant gcp` once, and typing
   `gcloud` after that carries the grant for you.
5. **Throughout.** Every grant is a fresh Touch ID that names the credential,
   even when jit is already unlocked.

## The rule that never bends

Point 5 above is the load-bearing invariant:
**project-local configuration may reconfigure a project's own secrets, but it
never authorizes access to a machine-global credential.** A cloned repo's
`.jit/config.yaml` can never grant your gcloud credentials; a machine-global
grant takes an explicit `--with` you type and forces its own disclosed
challenge. The unlock authorizes the session, not the scope. The full model
is in the **[security architecture](../security/architecture.md)**.
