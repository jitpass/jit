---
title: How it all fits together
description: The mental model - secrets only at the moment of use, the three ways a tool reads a credential, how you integrate each (migrate vs wrap) and run it (native hook, shim, or jit run), and the invariant that keeps it safe.
---

# How it all fits together

jit has one job: take the secrets that already sit in plaintext across your
Mac, move them into an encrypted vault, and leave every tool working exactly
as before.

Two questions organize the whole tool: **how did the secret get into the
vault** (integrate), and **how does it reach the tool at use time** (run).

## Secrets should exist only at the moment of use

On a normal dev machine, secrets are permanent plaintext files: a `.env` per
project, your registry password in `~/.docker/config.json`, a long-lived
Google token in `~/.config/gcloud`, tokens in `~/.npmrc` and `~/.aws`. They
sit there between uses, readable by any process running as you, copied into
every backup.

jit collapses that window. The secret lives encrypted in the vault, and it
becomes readable only for the instant a tool actually needs it, then it is
gone again. Read a migrated file cold and you get a **decoy**, not the secret.

## Find, integrate, use

Three steps, in order. The first is optional discovery, the middle is a
one-time setup per secret, the last is every day.

| Step | Command | What happens |
| --- | --- | --- |
| **1. Find** | `jit scan` | A read-only scan finds every plaintext secret and reports how many jit already protects - and the one command that protects the rest. Never writes, never prints a real value. |
| **2. Integrate** | `jit migrate` / `jit wrap` | Move a secret into the vault and wire up how its tool will get it back. |
| **3. Use** | `jit run` / the tool itself | Run your tools. The secret materializes only for that process, only while it runs. |

## Three ways a tool consumes a credential

A tool reads its secret in exactly one of three ways. It is not a preference
you pick, it is a fact about the tool, and it decides both how you integrate
it and how you run it.

| Delivery model | The tool reads its secret by... | Examples |
| --- | --- | --- |
| **Call-out** | Asking jit on demand through the tool's own credential mechanism. Nothing is stored between calls. | `aws`, `kubectl`, `terraform`, `docker`, modern `sops` |
| **Env-delivered** | Reading an environment variable jit injects into the one process, which then vanishes. | `.env` files, shell configs, tfvars, MCP configs, `gh` / `stripe` tokens |
| **File-delivered** | Reading a file at a fixed path. jit leaves a [live mount](../run/mounts.md) there: decoy by default, real only when granted. | gcloud ADC, SOPS age key, `~/.npmrc`, `~/.netrc` |

## Integrating: two entry points into the vault

- **[`jit migrate`](../migrate/index.md)** is the bulk mover. Bare, it
  executes the whole machine-wide protect plan the scan showed; with a path,
  it vaults just that file or project's secrets and wires up the correct
  delivery model for each. This is how most things get in.
- **[`jit wrap`](../wrap/index.md)** is the per-tool bridge for a single CLI
  that carries its own token. It either installs a small `PATH` shim (for a
  tool with no native hook, like `gh`) or, for a tool that does have one
  (`aws`, `terraform`, `docker`), routes to migrate's mechanism instead.

So the two overlap: `wrap` is really "handle this one command," and under the
hood it delegates to a native hook or installs a shim as appropriate.

## Running: three patterns, decided by the model

You do not freely choose how a tool runs; its delivery model does. Two of
these three let you "just type the command," but through different machinery.

| Pattern | What you actually run | Who does the work |
| --- | --- | --- |
| **Native hook** (call-out) | `aws s3 ls`, `terraform apply` | The tool calls jit on demand through its own credential mechanism. No prefix, no shim. |
| **Wrap shim** (looks native) | `gh pr list`, `gcloud storage ls` | A `PATH` shim transparently runs `jit run` for you. Feels like the bare tool; it is jit underneath. |
| **Explicit [`jit run`](../run/index.md)** | `jit run ./deploy.sh`, `jit run --with gcp -- terraform apply` | You launch through jit directly: a project's `.env`, a named `--profile`, or a machine-global `--with` grant. |

`aws` is *truly* native (jit hooked its
`credential_process`, nothing wraps it), but a grant-wrapped `gcloud` only
*looks* native, the shim is quietly running `jit run --with gcp -- gcloud`.

## One credential, all the way through

Following the gcloud application-default credentials (a file-delivered
secret) end to end:

1. **Find.** [`jit scan`](../audit/index.md) flags
   `~/.config/gcloud/application_default_credentials.json` as a plaintext
   refresh token.
2. **Integrate.** `jit migrate ~/.config/gcloud/application_default_credentials.json`
   moves the secret field into the vault and leaves a live mount at the same
   path. Read it cold now and you get a decoy.
3. **Use, one-off.** `jit run --with gcp -- terraform apply` grants the real
   file to that run's process tree, and only that tree, until it exits.
4. **Use, natively.** `jit wrap add gcloud --grant gcp` once, and typing
   `gcloud` after that carries the grant for you.
5. **Throughout.** Every grant is a fresh Touch ID that names the credential,
   even when jit is already unlocked. A cloned repo's config can never trigger
   it.

## What protects it: the vault, the service, the mounts

For the full model see **[How it works](./how-it-works.md)** and the
[security architecture](../security/architecture.md); in brief:

- **Envelope encryption.** Every secret is its own encrypted file: a
  per-secret data key, wrapped by a single master key. Tampered or swapped
  files fail to decrypt rather than resolving as the wrong secret.
- **Master key in the Keychain.** The master key lives in the macOS login
  Keychain, gated by Touch ID or the device passcode. The vault never syncs
  anywhere; the only way out is an explicit, passphrase-encrypted export.
- **Decoy-by-default mounts.** A migrated file becomes a named pipe. Read it
  outside a grant and you get placeholder values, not the secret, so backups,
  editors, and a stray `cat` see nothing real.
- **The background service.** One [service](../service/index.md) holds the unlocked
  session and serves mounts. It names every caller from the kernel on each
  prompt, and locks on its idle TTL, on screen lock, and on sleep.

## The rule that never bends

The load-bearing invariant:
**project-local configuration may reconfigure a project's own secrets, but it
never authorizes access to a machine-global credential.**

A cloned repo is untrusted input. If a `.jit/config.yaml` could say "grant
this run my gcloud credentials," a malicious repo would siphon them the moment
you ran anything in the directory, riding the Touch ID you approved for the
*project*. So a machine-global grant is never driven by a file. It takes a live
human gesture every time: an explicit `--with` you type, or, with per-process
consent on (the default), approving the disclosed prompt that fires the first
time a tool reads the file. Either way the challenge names what is being
granted, even mid-session. The unlock authorizes the session, not the scope.
Only you widen the scope, and an unexpected prompt is your cue to decline. The full model is in the
**[security architecture](../security/architecture.md)**.

## What jit does not defend against

jit narrows where and when plaintext exists. It does not make a compromised
account safe.

- **A process you grant a secret to can do anything with it.** Delivery hands
  the real value to the target; what it does next is outside jit's control.
  That is why every prompt names the caller: the decision happens before
  delivery.
- **Git history is never rewritten.** A file that was committed still holds
  its old value in `git log -p`. jit warns; the fix is rotating that
  credential.
- **It is a local, macOS tool.** It protects the plaintext on your laptop and
  in your working tree. Once a secret reaches a cluster or a CI store, jit is
  no longer in the loop.
