---
title: Per-process credential consent
description: jit prompts Touch ID the first time each tool reaches for a real credential, names who is asking, and remembers your answer for the session.
---

# Per-process credential consent

Once your vault is unlocked, the shared session lets your tools resolve migrated
credentials without prompting again. That is the point of the session: unlock
once, not per command. Per-process consent adds one check on top of it, so a
credential is never handed out completely silently: the **first time each tool
reaches for a gated credential**, the background service prompts a fresh Touch
ID, names who is asking, and remembers an approval for the rest of the session.
(A refusal works differently, and deliberately so - see
[Saying no, repeatedly](#saying-no-repeatedly).)

Consent is **on by default**. A tool you approve once is not asked again until
the session re-locks. The check is **per tool**: approving `terraform`'s use of
your AWS keys does not silently cover a different program that reaches for them,
so an unexpected first use (a postinstall script, a tool you did not launch)
still stops for a prompt you can decline.

```console
# the first time terraform reaches for your AWS keys this session:
#   Touch ID prompt: "use your aws credential for terraform, via claude"
# approve once, and terraform (and anything it launched) is not asked again
# until the vault re-locks.
#
# asked again after you already said no, the prompt says so:
#   "use your aws credential (refused 2 times) for terraform, via claude"
```

## Turning it on and off

```sh
jit service consent          # show whether it's on
jit service consent off      # turn it off (Touch ID required; restarts the service)
jit service consent on       # turn it back on (restarts the service)
```

Turning consent **off** requires a fresh Touch ID or passcode: disabling it
reopens the exact window it closes, so it must never be flippable by a process
running as you that happens to catch the vault unlocked. Turning it back on, or
just reading the state, needs no gesture. (The gate covers the command; someone
who can rewrite the launchd plist by hand bypasses it, the same limit
[uninstall's gate](../reference/commands/jit_uninstall.md) has.)

The setting is baked into the service's launchd plist, so it survives restarts
and logins. Changing it reinstalls the plist (keeping your
[session TTL](./index.md#changing-the-session-length)) and reloads the service
so it takes effect right away.

## What it gates, and what it does not

Consent only prompts for a real machine or tool credential. It gates these
provenance classes:

`aws` · `terraform` · `docker` · `git` · `kube` · `gcp` · `sops` · `npmrc` · `netrc` · `pypirc`

It does **not** prompt for a project's own secrets or anything you already ran
deliberately: `.env` files, shell exports, MCP configs, `tfvars`, manually
stored secrets, bare token files, credentials redacted out of your
[shell history](../migrate/shell-history.md) (nothing reads those back at run
time - they are quarantined in the vault, retrieved by hand with `jit vault
get`), Kubernetes Secret manifest values, or a wrapped CLI's own token (where
the [shim](../wrap/index.md) already makes the call explicit). Those are delivered
through a `jit run` you launched or a shim you installed, so the intent is
already established.

## Two strengths of identity

jit tells you how confident it is in who is asking, because that differs by how
the credential reaches the tool.

**Kernel-vouched.** Credentials delivered over the service's unix socket carry
the caller's identity straight from the kernel (the socket peer PID), which a
process running as you cannot forge. This covers the native hooks: `aws`
(`credential_process`), the `git` and `docker` credential helpers, `kubectl`
exec, and the `sops` age-key hook. The prompt names the exact executable and
what launched it, and that attribution is trustworthy.

**Best-effort.** The machine-global files served over a
[live mount](../run/mounts.md) FIFO (`gcp` application-default credentials,
`~/.npmrc`, `~/.netrc`) have no socket peer, so jit identifies the reader with
an unprivileged process scan. That scan can be spoofed by a process running as
you, so **treat the name on these prompts as a hint, not proof** - the prompt
says "(identified by scan)" to mark it. The vault crypto is unaffected
either way, and if the reader cannot be fully identified the mount serves
decoys rather than guess.

An approval is remembered only for the session and is dropped the moment the
vault re-locks, so consent never outlives the unlock it rode in on.

## Saying no, repeatedly

A refusal is never remembered as a standing "no". It cannot be: the prompt
cannot tell your decline from a keychain failure, and treating either as
permanent would lock a credential out with no way back. That left refusing
more expensive than approving (one dialog per request against one dialog
once), so anything asking in a loop could simply outlast you.

So a refused request now **pauses** rather than being remembered: roughly two
seconds, then eight, then thirty, per caller and credential. During a pause the
caller gets an error and you get nothing on screen. The prompt also tells you
how many times that caller has already been refused, because the tenth
identical dialog means something the first one doesn't.

Nothing is locked out by this. The next genuine attempt after the pause still
asks, an approval clears the escalation, and a fresh `jit unlock` (a person at
the keyboard) clears every pause outright. (Only a *fresh* one: `jit unlock`
against an already-open session prompts nobody, so it deliberately clears
nothing.)

The same pause covers the *widest* approvals too - `jit run --trust`,
creating or extending a [process grant](./grants.md), and a `--with` global
credential grant. Those prompts hand over the most, which made them exactly
the ones a looping process would hammer: without the pause, declining bought
you nothing but the next dialog, until approving became the only way to make
it stop.

## Seeing the request before the dialog: the menu bar app

The system dialog fits one sentence. When the JitPass menu bar app is running,
it is shown each request first, in full: the caller's whole command line, what
launched it, whether the service identified it through the kernel or by a
process scan, which credential it wants, and how many times it has already
been refused. Two answers:

- **Allow with Touch ID** lets the service go on to the same Touch ID prompt
  it would have shown anyway. The app approves nothing on its own; the dialog
  still decides.
- **Deny** refuses without a prompt. The caller gets the same error and the
  same pause a declined dialog gives it.

A request the app is shown and nobody answers is refused after ninety seconds,
like a dialog nobody touched. If the app quits while a request is waiting, the
dialog appears directly. Without the app, nothing changes: the service prompts
exactly as it always has.

This is the service's `consent_list` and `consent_answer` socket operations,
offered to any process running as you. That is safe for the same reason
[revoking a grant](./grants.md) needs no gesture: a deny only reduces access,
and an allow only lets the service ask *you*.

## Pre-authorizing a whole run: `jit run --trust`

When you deliberately launch something that reaches for several credentials (a
`terraform apply`, a build script), you do not want a prompt per credential.
`--trust` pre-authorizes the entire process tree of that run:

```sh
jit run --trust -- terraform apply
```

Registering that trust takes one Touch ID of its own, naming the command and
saying what trusting it means:

```
jit is trying to let terraform and everything it launches reach your
credentials without further prompts.
```

Approve it once, and every process inside that run's tree is then allowed
without a prompt, for any credential, until the next re-lock. A tool launched
through a `jit run --with <cred>` grant is likewise already authorized for that
credential and is not prompted again.

That one prompt is not ceremony. `--trust` is the widest thing you can ask jit
for: it switches off, for a whole process tree, the gate that exists precisely
because code running as you is not automatically code you vetted. The service
learns about a trust root over the same socket any process on your machine can
reach, so if registering one took no gesture, anything that wanted to skip
consent could simply ask to. The human answering the prompt is what makes
`--trust` mean what this page says it means.

## See also

- [The background service](./index.md) - the session this consent rides on
- [Provenance](./provenance.md) - why every prompt names its caller
- [Live-mounted files](../run/mounts.md) - the FIFO mounts the best-effort path covers
- [Security architecture](../security/architecture.md) - the threat model and honest limits
