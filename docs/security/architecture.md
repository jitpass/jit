---
title: Security architecture
description: How jit protects secrets - encryption at rest, the service boundary, provenance - and what it deliberately does not defend against.
---

# Security architecture

This page is the shape of the design; the
[self-reviews](./self-reviews/index.md) are where each claim gets tested,
and [TECH_STACK.md](../../TECH_STACK.md) documents the implementation
choices (crypto primitives, Keychain/Secure Enclave usage, IPC) and their
rationale.

## At rest

Every secret is an individually encrypted file under
`~/Library/Application Support/jitpass/` (envelope encryption - a data key
per secret, wrapped by the master key). Each encrypted payload is bound to
its own vault path and timestamps (AEAD additional authenticated data), so
a swapped, renamed, or metadata-tampered file fails to decrypt instead of
quietly resolving as the wrong secret. Overwrites keep the outgoing value
as an encrypted archived version ([`jit vault history` /
`restore`](../vault/index.md#botched-a-rotation-history--restore), newest 5
per secret; `rm` deletes them with the secret). The master key lives in the
macOS login Keychain, gated by Touch ID / device passcode, and can be
rotated in place with
[`jit vault rekey`](../vault/maintenance.md#jit-vault-rekey---rotate-the-master-key). The vault never syncs
anywhere; the only way secrets leave the machine is an explicit
[passphrase-encrypted export](../vault/backup-restore.md) (Argon2id-derived
key - machine-independent by design, protected only by the passphrase you
choose).

## In use

Secrets materialize at the moment of use and nowhere else:

- [`jit run`](../run/index.md) and [wrap shims](../wrap/index.md) inject
  into exactly one process's environment, then `execve` - jit's own process
  image is replaced, so jit is gone from memory when your command runs.
- [Live mounts](../run/mounts.md) are named pipes: nothing is on disk, and
  reads outside a `jit run` grant get decoy values, not secrets. Under
  `jit run` the mount is either swapped for an inert comment-only file (the
  default - real values reach the command through the environment, never the
  file) or, with `--live`, kept as a pipe that serves real values only to
  that run's own process tree. Neither writes a secret to disk, and both
  end the instant the command exits.
- Machine-global credential *files* (the gcloud ADC, a SOPS age key, the
  global `~/.npmrc`, `~/.netrc`) migrate the same way, but are never granted
  implicitly or silently. Two things can release one, and both take a live
  human gesture: an explicit `jit run --with gcp|sops|npm|netrc|pypi`, which grants
  it to a single run's process tree behind a fresh *disclosed* Touch ID that
  names the credential (a kernel-vouched, hard gate); or, with
  [per-process consent](../service/consent.md) on (the default), a direct read
  of the file, which prompts a disclosed Touch ID naming the reader (best-effort
  identity) and serves the value only on approval. The invariant behind both:
  project-local configuration may reconfigure a project's own secrets, but it
  never authorizes access to a machine-global credential on its own. A cloned
  repo's `.jit/config.yaml`, or a script that slips a `--with` into a command,
  can never hand one out silently; the unlock authorizes the session, not the
  scope, and widening it always takes an explicit `--with` or an approved
  consent prompt.
- Credential-helper fetches ([AWS](../migrate/aws.md),
  [Kubernetes](../migrate/kubernetes.md),
  [Terraform](../migrate/terraform.md)) hand the credential to the
  requesting tool on demand; no intermediate file exists. By default,
  [per-process consent](../service/consent.md) gates each fetch: the first time
  a given tool reaches for one of these credentials in a session, the service
  prompts a fresh Touch ID naming it and remembers the answer until re-lock, so
  a migrated credential is never handed out completely silently even while the
  vault is unlocked.
- The escape hatches are guarded too: `jit vault get --copy` conceals the
  value from clipboard managers and auto-clears it after 45 seconds, and
  `jit export` asks before printing plaintext to a terminal (its output is
  meant for `eval`, not scrollback).

## The service boundary

The [background service](../service/index.md) holds the unlocked session and
serves mounts. Clients reach it over a unix domain socket, and the service
identifies every caller from the kernel (peer credentials on the socket,
then the pid's command line and parent chain) - never from anything the
caller claims about itself.

That identity is used to **explain and to audit, never to decide**: it
names the caller in the Touch ID prompt and in
[`jit audit`](../service/provenance.md), but it is not
authentication, and jit does not pretend a process name is a security
boundary. The human approving the prompt is the decision point; the cached
session locks after its TTL (default 5 minutes, user-configurable with
`--ttl`), on `jit lock`, and the moment the screen locks or the
machine sleeps - the idle TTL is a proxy for "the user left," and those two
events are the OS saying so outright.

The TTL is an *inactivity* timeout, so use extends it - and on its own that
is a bound a busy caller never reaches. A **hard ceiling of 8 hours** from
the unlock itself runs alongside it: past that the session ends and the next
access challenges again, however continuously it has been used. Without it,
anything that could touch the session every few minutes could hold the
master key resident indefinitely on the strength of one Touch ID from that
morning. `--ttl` is bounded by the ceiling, because an inactivity timeout
longer than it could never be reached.

The cached session covers only the high-frequency paths (native credential
hooks and `jit run`), and on top of it [per-process consent](../service/consent.md)
(on by default) prompts once per tool the first time it reaches for a
credential, so nothing is handed out entirely silently even mid-session. The
sensitive `jit vault` management commands
(`get`/`set`/`rm`/`import`/`restore`/`clean`/`prune`/`delete`/`export`)
deliberately bypass it and require a fresh Touch ID/passcode on every
invocation, locked or not - so a process running as you on an unlocked
machine still cannot read, dump, or destroy the vault without a live human
gesture. Only `list`/`history` (names and version timestamps, never a value)
are prompt-free.

**Refusing has to stay cheap.** A consent prompt cannot cache a refusal as a
lasting "no" - the prompt cannot tell a human's decline from a keychain
failure, and treating either as permanent would lock a credential out with no
way back. That left an asymmetry worth naming: saying no cost one full-screen
dialog *per request* while saying yes cost one dialog *once*, so anything
asking in a loop could simply outlast you. Consent prompts now back off per
request after a refusal (about two seconds, then eight, then thirty), and the
prompt says how many times that caller has already been refused. Nothing is
locked out, the next genuine attempt still asks, and a *fresh* `jit unlock` —
one that actually challenges you — clears the pause outright, while an unlock
against an already-open session prompts nobody and so clears nothing. A caller
also cannot conjure a prompt out of
nothing: the credential class it names is verified against the ciphertext it
sent before anyone is asked, so a process holding no vault data at all can no
longer put a dialog on your screen.

## Deliberate limits

jit narrows *where* and *when* plaintext exists; it does not make a
compromised user account safe. The boundaries worth knowing:

- **A process you give a secret to can do anything with it.** Injection
  delivers the real value to the target process; what that process does is
  outside jit's control. That's the point of naming callers on every
  prompt - the decision happens before delivery.
- **Credentials a tool mints for itself are not jit's.** The concrete case:
  after the AWS CLI uses a migrated key to assume a role, it caches the
  resulting STS session in plaintext under `~/.aws/cli/cache`, and
  `aws sso login` writes its tokens to `~/.aws/sso/cache`. jit stores what
  *you* stored; these were minted downstream, will be minted again on the
  next run, and jit does not manage, clean or decoy them. It does now say
  they are there - `jit scan` reports them as out of scope rather than
  walking past hex-named files in the directory it just tidied.
  Relatedly, an assume-role profile carries no key of its own, so jit's AWS
  discovery does not migrate it; migrating its source profile still protects
  the long-lived key it assumes with.
- **Git history is never rewritten.** A migrated file that was ever
  committed still has its old value in `git log -p`; `migrate` warns, and
  the fix is rotating that credential.
- **While real values are available, a mount serves them to readers.**
  For a project `.env`, that happens only under a `jit run --live`/`--with`
  grant (scoped to that run's process tree, for its lifetime, per-read by
  process ancestry, and observable via `jit service status`). For the
  machine-global credential mounts, with consent on, a direct read also serves
  real values, but only after an approved disclosed prompt naming the reader.
  There is no ambient reveal window: unlocking the vault never makes a mount
  serve real values on its own, and a prompt always precedes a consent-served
  read. The ancestry check narrows a grant; it is never the security boundary on
  its own - the boundary is the grant (or the approved prompt), issued only for
  a read the user authorized.

Each published review carries a "known, accepted limitations" list that
states these boundaries precisely as of that review -
[read the latest](./self-reviews/index.md). If you believe a boundary
itself is stated incorrectly, that's worth
[reporting](./reporting.md).
