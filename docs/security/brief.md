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

## What you have to trust, and how to check it

- **No custom cryptography.** The primitives are Go's standard library:
  AES-256-GCM (`crypto/aes` + `crypto/cipher`) for both the per-secret data
  keys and the master key wrap, and `crypto/rand` for all key and nonce
  generation. The one exception is deliberate and narrow: a
  passphrase-encrypted [export](../vault/backup-restore.md) derives its key
  with Argon2id from `golang.org/x/crypto`, because a passphrase needs a
  memory-hard KDF and the standard library has none. There are no hand-rolled
  primitives and no novel constructions. What is jit-specific is the
  *composition*: envelope encryption, and binding each ciphertext to the
  secret's vault path and metadata as AEAD additional data so a swapped or
  renamed file fails to decrypt instead of resolving as the wrong secret.
  That composition is the part worth reading critically, and it is under 90
  lines in `internal/vault/crypto.go`.
- **The non-pure-Go surface is four small packages**, and they are named so a
  reviewer can start there rather than hunting: `internal/keychainwrap`
  (Keychain and the Touch ID challenge), `internal/lineage` (libproc, audit
  logging only, never a gate), `internal/pasteboard`, and
  `internal/screenlock`. Everything else is portable Go.
- **The design notes are in the tree.** Each `internal/` package has a
  `doc.go` stating what it does and what it deliberately does not, and the
  hard problems (the named-pipe re-open loop, peer credentials, the Secure
  Enclave entitlement wall) carry their evidence in `spike/*/FINDINGS.md`.
- **Every published [self-review](./self-reviews/index.md)** carries an explicit
  "known, accepted limitations" list as of that review, rather than a summary
  that only reports what passed.

## Architecture at a glance

- **At rest.** Envelope encryption: each secret is its own AEAD-encrypted file
  with a per-secret data key, wrapped by a single master key. Ciphertext is
  bound to the secret's vault path and metadata, so a swapped or renamed file
  fails to decrypt rather than resolving as the wrong secret.
- **Master key.** Held in the macOS login Keychain by default, released
  only after a Touch ID or device-passcode challenge; see the caveat below
  about what kind of guarantee that is. Opt-in since 2.3.0 (JitPass's
  Settings › Protection, or `jit vault rekey --wrapper secure-enclave`): the
  key is sealed to a Secure Enclave key instead, which only JitPass's signed
  helper can use, after a Touch ID or password check the enclave enforces.
  See [The vault key in the Secure Enclave](../vault/secure-enclave.md).
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
  TTL, at a hard 8-hour ceiling measured from the unlock itself (the TTL is an
  inactivity timeout, so without a ceiling anything touching the session every
  few minutes could hold the key resident indefinitely), on screen lock, and on
  sleep. The sensitive `jit vault` management
  commands bypass the session entirely and require a fresh Touch ID/passcode
  every time, so an unlocked session can't be used to read or destroy the
  vault silently.
- **AI jobs.** For an AI tool, the service runs a command the human approved
  and returns its output with every secret value hidden; the tool never
  holds a key. The approval pins the executable, the command line, the
  secrets and a fingerprint of the job's folder, re-checked on every run; any
  change stops the job until the human approves it again. Claude Desktop and
  Cursor reach jobs through `jit mcp`, a plain socket client that can run and
  propose jobs but never approve one.

## The machine-global invariant

Project-local configuration may reconfigure a project's own secrets, but it
**never** authorizes access to a machine-global credential (the gcloud ADC, a
SOPS key, `~/.npmrc`) on its own. Two things can release one, and both take a
live human gesture: an explicit `jit run --with` the user types, or, with
per-process consent on (the default), an approved disclosed prompt when a tool
reads the file. Either way a fresh **disclosed** Touch ID names what is being
granted, even when the session is already unlocked. The unlock authorizes the
session, not the scope. A cloned repo's config, or a script that slips a
`--with` into a command, cannot hand out a machine-wide credential silently.

## Deliberate limits (stated plainly)

- **In the keychain (the default), local-auth-bound, not hardware-enforced.**
  There the Touch ID gate is an application-level LocalAuthentication
  challenge, and the key is a plain login-keychain item: an OS-enforced
  access control needs a provisioning-profile-authorized entitlement that
  macOS will only honor inside an `.app` bundle, and a bare CLI binary has
  nowhere to carry it, signed or not (`spike/secure-enclave-mek/FINDINGS.md`).
  A determined attacker with local code execution could read that item
  directly while the vault is locked, and could ask the service while it is
  unlocked. Moving the key into the Secure Enclave closes the first: the
  sealed key opens only through JitPass's signed helper, after the enclave's
  own Touch ID or password check. It does not close the second: while the
  vault is unlocked, the service holds the key in memory for the session,
  wherever it rests. The Secure Enclave is opt-in, and needs the `jit` inside
  JitPass.app; a tarball or `go install` build keeps the keychain.
- **A process you give a secret to can do anything with it.** Delivery is the
  end of jit's control; that is why the decision point is the caller-naming
  prompt, before delivery.
- **Memory is not protected, and jit does not claim to protect it.** Once a
  value is in the address space of the process that asked for it, jit is out
  of the loop. There is no attempt to lock pages, defeat a debugger, or hide
  from a process running as you with the patience to attach to another one.
  The threat this is built against is the infostealer that globs for `.env`
  and `~/.aws/credentials`, reads them, and exfiltrates, which is the common
  case and the automatable one. If your adversary is instead a targeted
  attacker with local code execution and time, you want VM-level isolation,
  not this.
- **Full-disk encryption solves a different problem.** FileVault protects a
  powered-off or stolen machine. It does nothing once you are logged in and
  the volume is mounted, which is exactly when every process running as you
  can read every plaintext credential on it. The two are complementary; keep
  FileVault on.
- **Credentials a tool mints for itself are not jit's.** After the AWS CLI uses
  a migrated key to assume a role it caches the resulting STS session in
  plaintext under `~/.aws/cli/cache`, and `aws sso login` writes tokens to
  `~/.aws/sso/cache`. jit does not manage, clean or decoy them; it reports them
  as out of scope rather than letting a clean scan imply the directory it just
  tidied is empty.
- **Refusing a prompt is bounded, not permanent.** A declined consent prompt
  cannot be cached as a lasting "no" - the prompt cannot distinguish a human's
  decline from a keychain failure - so it pauses that caller instead (about 2s,
  8s, then 30s), and the prompt reports how many times it has already been
  refused. This closes the asymmetry where saying no cost one dialog per
  request and saying yes cost one dialog once, which let a caller in a loop
  outlast the user. It is UX hardening against prompt fatigue, not a boundary:
  the boundary is still the human answering.
- **Process identity narrows a grant, it is never the boundary.** A run-scoped
  grant serves real content only to the authorized run's tree, checked per
  read and fail-closed. Winning an identity race yields at most what the grant
  already authorized, never more.
- **An AI job trusts the command it runs.** Its command holds the real
  value; the fingerprint guarantees the code that runs is the code approved,
  not that it is honest. Programs it calls from `PATH` are trusted as
  installed, and a change landing between the last check and an import is
  caught by the re-check after the run, not before it.
- **Git history is never rewritten.** A committed secret still lives in
  `git log -p`; the fix is rotation, which jit cannot do for you.
- **Local machine only.** Once a secret reaches a cluster or a CI store, jit
  is no longer in the loop.

## Trust and distribution

- Source is public on GitHub under the **PolyForm Perimeter License 1.0.0**
  (source-available, not open source); it can be built from source with Go.
- Release builds are **Developer-ID signed and notarized by Apple**
  (`Meni Tasa, CZC6BH93GJ`). Homebrew quarantines its download, so Gatekeeper
  verifies it against the notarization ticket before first run; a `curl`
  install sets no quarantine bit, so that check never happens and the tarball
  is the weaker path. `jit doctor` reports the Team ID it verified. Dev builds
  from source are ad-hoc signed, so a dev build's first run shows a one-time
  Keychain permission prompt.
- **No telemetry and no background network activity.** jit makes exactly one
  kind of outbound request, and only when you type it: `jit upgrade` fetches
  the release archive and `checksums.txt`, verifies both the Developer-ID
  signature and the checksum, and refuses to install if either fails (there is
  no override flag). Nothing auto-updates, nothing phones home, and no secret,
  path, or scan result is ever transmitted. The vault leaves the machine only
  through a passphrase-encrypted export you run yourself.

## Verifying and reporting

- Every published [self-review](./self-reviews/index.md) tests the claims above and
  carries a precise "known, accepted limitations" list as of that review.
- `jit scan` is strictly read-only and masks all values, so it is safe to run
  on a sensitive machine for a firsthand look at what it detects.
- Report an issue, or a boundary you think is mis-stated, through the
  [reporting page](./reporting.md).
