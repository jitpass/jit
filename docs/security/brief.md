---
title: Security brief
description: A one-page summary for security reviewers - what jit protects, how, and the boundaries it deliberately does not cross.
---

# Security brief

A self-contained page for a security reviewer. The full design is in the
[architecture](./architecture.md); the honest limits are restated in every
[self-review](./self-reviews/index.md). Crypto primitives and platform APIs are in
[TECH_STACK.md](../../TECH_STACK.md).

## What jit is

A local, macOS-only secrets manager. It takes the plaintext secrets that
already exist across a developer's machine (`.env` files, `~/.aws`, docker,
gcloud, SOPS keys, CLI tokens), moves them into an encrypted local vault, and
rewrites each consuming file so tools keep working. Nothing is added to the
network surface: there is no server, no sync, no telemetry.

## Threat model in one line

jit narrows *where* and *when* a secret exists in plaintext, down to the
moment a tool uses it. It does **not** make an already-compromised user
account safe.

## Architecture at a glance

- **At rest.** Envelope encryption: each secret is its own AEAD-encrypted file
  with a per-secret data key, wrapped by a single master key. Ciphertext is
  bound to the secret's vault path and metadata, so a swapped or renamed file
  fails to decrypt rather than resolving as the wrong secret.
- **Master key.** Held in the macOS login Keychain, released only after a
  Touch ID or device-passcode challenge. See the caveat below about what kind
  of guarantee that is today.
- **In use.** Secrets reach a tool one of three ways, all avoiding a plaintext
  file: environment injection followed by `execve` (jit's own image is
  replaced), a native credential helper the tool already calls, or a live
  named-pipe mount that serves decoys by default and real content only to an
  authorized run's process tree.
- **The service.** A background process holds the unlocked session for a TTL
  (default 5 minutes, configurable) so the user is not prompted per command on
  the high-frequency paths (native hooks, `jit run`). It identifies every
  caller from the kernel (socket peer credentials, then pid, command, and
  parent chain), never from anything the caller claims. It re-locks on the
  TTL, on screen lock, and on sleep. The sensitive `jit vault` management
  commands bypass the session entirely and require a fresh Touch ID/passcode
  every time, so an unlocked session can't be used to read or destroy the
  vault silently.

## The machine-global invariant

Project-local configuration may reconfigure a project's own secrets, but it
**never** authorizes access to a machine-global credential (the gcloud ADC, a
SOPS key, `~/.npmrc`). Those are granted only by an explicit `jit run --with`
the user types, which forces a fresh **disclosed** Touch ID naming the
credential even when the session is already unlocked. The unlock authorizes
the session, not the scope. A cloned repo's config, or a script that slips a
`--with` into a command, cannot hand out a machine-wide credential silently.

## Deliberate limits (stated plainly)

- **Local-auth-bound, not hardware-enforced (today).** The Touch ID gate is an
  application-level LocalAuthentication challenge, not an OS-enforced Keychain
  ACL or a Secure Enclave binding, because a real ACL needs an Apple Developer
  ID signing identity the project does not have yet. A determined attacker with
  local code execution could read the plain Keychain item directly while the
  vault is locked, and could ask the service while it is unlocked. This is the
  accepted Phase 1 boundary.
- **A process you give a secret to can do anything with it.** Delivery is the
  end of jit's control; that is why the decision point is the caller-naming
  prompt, before delivery.
- **Process identity narrows a grant, it is never the boundary.** A run-scoped
  grant serves real content only to the authorized run's tree, checked per
  read and fail-closed. Winning an identity race yields at most what the grant
  already authorized, never more.
- **Git history is never rewritten.** A committed secret still lives in
  `git log -p`; the fix is rotation, which jit cannot do for you.
- **Local machine only.** Once a secret reaches a cluster or a CI store, jit
  is no longer in the loop.

## Trust and distribution

- Source is public on GitHub under the **PolyForm Perimeter License 1.0.0**
  (source-available, not open source); it can be built from source with Go.
- Builds are **ad-hoc signed** today (Developer ID and notarization pending),
  so a dev build's first run shows a one-time Keychain permission prompt.
- No network calls, no telemetry, no auto-update. The vault leaves the machine
  only through an explicit passphrase-encrypted export the user runs.

## Verifying and reporting

- Every published [self-review](./self-reviews/index.md) tests the claims above and
  carries a precise "known, accepted limitations" list as of that review.
- `jit scan` is strictly read-only and masks all values, so it is safe to run
  on a sensitive machine for a firsthand look at what it detects.
- Report an issue, or a boundary you think is mis-stated, through the
  [reporting page](./reporting.md).
