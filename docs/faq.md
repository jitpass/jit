---
title: FAQ for developers and security
description: Straight answers to the questions developers and security engineers actually ask about jit - how it works, what it protects, and what it deliberately does not.
---

# FAQ

Two tracks: **[developer questions](#developer-questions)** (using it, day to
day) and **[security questions](#security-questions)** (the threat model and
its limits). Answers are deliberately blunt, including where jit stops. For
security reviewers, the standalone **[security brief](./security/brief.md)**
collects the threat-model answers on one page.

**Developer**

- [Do I have to change how I work?](#do-i-have-to-change-how-i-work)
- [Do I have to prefix everything with `jit run`?](#do-i-have-to-prefix-everything-with-jit-run)
- [How do I know which command to use?](#how-do-i-know-which-command-to-use)
- [Does it tell me when I need to `jit wrap` something?](#does-it-tell-me-when-i-need-to-jit-wrap-something)
- [Does it work inside scripts, Makefiles, and git hooks?](#does-it-work-inside-scripts-makefiles-and-git-hooks)
- [Does it work in CI?](#does-it-work-in-ci)
- [What if a tool breaks after I migrate?](#what-if-a-tool-breaks-after-i-migrate)
- [Which platforms does it run on?](#which-platforms-does-it-run-on)
- [What happens if the agent is locked or not running?](#what-happens-if-the-agent-is-locked-or-not-running)
- [Can my team share a vault?](#can-my-team-share-a-vault)

**Security**

- [What is the threat model in one line?](#what-is-the-threat-model-in-one-line)
- [How are secrets encrypted at rest?](#how-are-secrets-encrypted-at-rest)
- [Where does the master key live, and is it hardware-bound?](#where-does-the-master-key-live-and-is-it-hardware-bound)
- [Can an attacker who already runs code as me read my secrets?](#so-can-an-attacker-who-already-runs-code-as-me-read-my-secrets)
- [Is the master key ever in memory?](#is-the-master-key-ever-in-memory)
- [Can a malicious repo I clone steal my cloud credentials?](#can-a-malicious-repo-i-clone-steal-my-cloud-credentials)
- [The mounts identify the reading process, isn't that spoofable?](#the-mounts-identify-the-reading-process-isnt-that-spoofable)
- [Does jit phone home or sync anywhere?](#does-jit-phone-home-or-sync-anywhere)
- [Is `jit scan` safe to run on a sensitive machine?](#is-jit-audit-safe-to-run-on-a-sensitive-machine)
- [What about secrets already committed to git?](#what-about-secrets-already-committed-to-git)
- [Once a secret reaches a process, what stops it leaking it?](#once-a-secret-reaches-a-process-what-stops-that-process-from-leaking-it)
- [How is it distributed and signed?](#how-is-it-distributed-and-signed)
- [Where can I report a security issue?](#where-can-i-report-a-security-issue)

## Developer questions

### Do I have to change how I work?

No. That is the design constraint. After migrating, your `.env` still loads,
`gh`, `aws`, and `terraform` still run, and your scripts keep passing. jit
rewrites each file to keep working through the tool's own mechanism. The
plaintext just stops living on your disk. See
[How it all fits together](./getting-started/how-it-fits.md).

### Do I have to prefix everything with `jit run`?

Often not. It depends on how the tool reads its credential:

- **Native-hook tools** (`aws`, `kubectl`, `terraform`, `docker`) just run
  normally, jit is called on demand through their own credential mechanism.
- **Wrapped CLIs** (`gh`, `stripe`) run normally too, a `PATH` shim runs
  `jit run` for you invisibly.
- You only type `jit run` explicitly for a project's `.env`, a named
  `--profile`, or a machine-global `--with` grant.

### How do I know which command to use?

You mostly do not decide. Run [`jit scan`](./audit/index.md), and it prints
the exact fix next to every finding, including `jit wrap <tool>` for CLI
tokens. `jit migrate --dry-run` then shows the whole guided plan.
[How the workflow flows](./getting-started/how-it-fits.md#find-integrate-use).

### Does it tell me when I need to `jit wrap` something?

Yes, explicitly. Audit has a **Wrappable CLI Tokens** category whose finding
text is the instruction itself, for example:
`gh token in plaintext; one command moves it into the vault and keeps gh
working: jit wrap gh`. You copy the command it prints.

### Does it work inside scripts, Makefiles, and git hooks?

Yes. Wrapping installs a `PATH` shim, not a shell alias, so any subprocess
that spawns the tool hits the shim too. Overhead is about 25 ms per call with
an unlocked agent.

### Does it work in CI?

No, and it is not meant to. jit is a local developer-machine tool: it protects
plaintext on your laptop and in your working tree. CI secrets belong in the CI
system's own secret store. Once a secret leaves your machine, jit is not in
the loop.

### What if a tool breaks after I migrate?

It is fully reversible: [`jit migrate undo`](./migrate/undo-and-remove.md) or
`jit unmount <path>` restores the original file. Most breakage is a tool that
reads the file itself rather than the environment, the compatibility swap
handles the common cases automatically, and `--live` (or `read_as_file: true`)
covers the rest. Failures are loud and self-explaining, not silent
placeholder errors.

### Which platforms does it run on?

macOS only, currently, because the local-auth and Keychain integration is
macOS-native. There is no Linux or Windows build.

### What happens if the agent is locked or not running?

Commands that need a secret trigger a Touch ID prompt to unlock, or fail
loudly if you decline. A locked agent serves decoys from every mount, so a
cold read is never a real secret.

### Can my team share a vault?

No. The vault never syncs and its encryption is bound to this machine's
Keychain. Export/import is for your own backup and recovery, not team sharing.
Each machine runs its own jit.

## Security questions

### What is the threat model in one line?

jit narrows *where* and *when* a secret exists in plaintext, down to the
moment a tool uses it. It does **not** make a compromised user account safe.
Every deliberate limit is documented in the
[security architecture](./security/architecture.md) and re-stated in each
published [self-review](./security/self-reviews/index.md).

### How are secrets encrypted at rest?

Envelope encryption: each secret is its own authenticated-encrypted file with
a per-secret data key, and those keys are wrapped by a single master key. The
ciphertext is bound to the secret's vault path and metadata, so a swapped or
renamed file fails to decrypt rather than resolving as the wrong secret.
Crypto primitives are in [TECH_STACK.md](../TECH_STACK.md).

### Where does the master key live, and is it hardware-bound?

The master key is in the macOS login Keychain, and every use requires a Touch
ID or device-passcode challenge. Be precise about the guarantee: today that is
an **application-level** local-auth gate (LocalAuthentication), not a
hardware-enforced Keychain ACL or a Secure Enclave binding. A real
OS-enforced ACL needs an Apple Developer ID signing identity the project does
not have yet. So the honest statement is "OS local-authentication-bound," not
"cryptographically enforced against local code execution."

### So can an attacker who already runs code as me read my secrets?

If the agent is unlocked, yes, the same way any local process could ask it,
which is why every prompt names the caller and the session locks aggressively
(TTL, screen lock, sleep). If the agent is locked, the master key sits in a
plain Keychain item with no OS-level ACL today, so a determined local attacker
could read it directly, bypassing the app-level challenge. This is the
accepted Phase 1 boundary, stated plainly rather than hidden.

### Is the master key ever in memory?

Yes, in the background agent for the session TTL (default 5 minutes), so you
are not prompted per command. It is page-locked (kept out of swap) and wiped
when the session locks. jit's own CLI process holds a secret only for the
instant of a single command, then `execve` replaces its whole image.

### Can a malicious repo I clone steal my cloud credentials?

No. That is exactly what the machine-global grant model prevents. A project's
`.jit/config.yaml` can never authorize a machine-global credential (the
gcloud ADC, a SOPS key, `~/.npmrc`). Those are granted only by an explicit
`jit run --with` you type, which forces a fresh **disclosed** Touch ID naming
the credential even when the vault is already unlocked. The unlock authorizes
the session, not the scope, and only you widen the scope.

### The mounts identify the reading process, isn't that spoofable?

Process identity is used to **narrow** a grant, never as the security boundary
on its own. A run-scoped grant serves real content only to the authorized
run's process tree, checked per read by walking ancestry, and it fails closed
on any ambiguity. Even if an attacker won an identity race, the worst they get
is what the grant already authorized for that run, never more. The boundary is
the grant, issued only to a run you authorized.

### Does jit phone home or sync anywhere?

Never. The vault stays on the machine. The only way a secret leaves is an
explicit [passphrase-encrypted export](./vault/backup-restore.md) you run
yourself (an Argon2id-derived key, machine-independent by design).

### Is `jit scan` safe to run on a sensitive machine?

Yes. It is strictly read-only, never writes anything, and never prints a real
value (every preview is masked). Use `jit scan --format ndjson` for
machine-readable output under the same redaction rules.

### What about secrets already committed to git?

jit never rewrites history. A file that was committed still has its old value
in `git log -p`. `migrate` warns you, and the correct fix is rotating that
credential, jit cannot un-leak it.

### Once a secret reaches a process, what stops that process from leaking it?

Nothing, and jit does not claim otherwise. Injection delivers the real value
to the target process, and what it does next is outside jit's control. That is
precisely why the decision point is the Touch ID prompt that names the caller,
before delivery, not after.

### How is it distributed and signed?

The code is public on GitHub under BUSL-1.1 (source-available, not open
source). Builds are ad-hoc signed today (a real Developer ID and notarization
are pending), so the first run of a dev build shows a one-time macOS Keychain
permission prompt. You can also build from source with Go.

### Where can I report a security issue?

Through the [reporting page](./security/reporting.md). If you think a stated
boundary is itself wrong, that is worth reporting too.
