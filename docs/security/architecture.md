---
title: Security architecture
description: How jit protects secrets - encryption at rest, the agent boundary, provenance - and what it deliberately does not defend against.
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
  reads outside a revealed window get decoy values, not secrets.
- Credential-helper fetches ([AWS](../migrate/aws.md),
  [Kubernetes](../migrate/kubernetes.md),
  [Terraform](../migrate/terraform.md)) hand the credential to the
  requesting tool on demand; no intermediate file exists.
- The escape hatches are guarded too: `jit vault get --copy` conceals the
  value from clipboard managers and auto-clears it after 45 seconds, and
  `jit export` asks before printing plaintext to a terminal (its output is
  meant for `eval`, not scrollback).

## The agent boundary

The [background agent](../agent/index.md) holds the unlocked session and
serves mounts. Clients reach it over a unix domain socket, and the agent
identifies every caller from the kernel (peer credentials on the socket,
then the pid's command line and parent chain) - never from anything the
caller claims about itself.

That identity is used to **explain and to audit, never to decide**: it
names the caller in the Touch ID prompt and in
[`jit agent history`](../agent/provenance.md), but it is not
authentication, and jit does not pretend a process name is a security
boundary. The human approving the prompt is the decision point; the cached
session locks after its TTL (default 15 minutes), on `jit agent lock`,
and the moment the screen locks or the machine sleeps - the idle TTL is
a proxy for "the user left," and those two events are the OS saying so
outright.

## Deliberate limits

jit narrows *where* and *when* plaintext exists; it does not make a
compromised user account safe. The boundaries worth knowing:

- **A process you give a secret to can do anything with it.** Injection
  delivers the real value to the target process; what that process does is
  outside jit's control. That's the point of naming callers on every
  prompt - the decision happens before delivery.
- **Git history is never rewritten.** A migrated file that was ever
  committed still has its old value in `git log -p`; `migrate` warns, and
  the fix is rotating that credential.
- **During a revealed window, a mount serves real values to readers.**
  The window is short, attributed, and observable (`jit agent status`),
  but it is a window.

Each published review carries a "known, accepted limitations" list that
states these boundaries precisely as of that review -
[read the latest](./self-reviews/index.md). If you believe a boundary
itself is stated incorrectly, that's worth
[reporting](./reporting.md).
