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
ID, names who is asking, and remembers your answer for the rest of the session.

Consent is **on by default**. A tool you approve once is not asked again until
the session re-locks.

```console
# the first time terraform reaches for your AWS keys this session:
#   Touch ID prompt: "terraform, launched by claude, wants your aws credential"
# approve once, and terraform (and anything it launched) is not asked again
# until the vault re-locks.
```

## Turning it on and off

```sh
jit service consent          # show whether it's on
jit service consent off      # turn it off (restarts the service)
jit service consent on       # turn it back on (restarts the service)
```

The setting is baked into the service's launchd plist, so it survives restarts
and logins. Changing it reinstalls the plist (keeping your
[session TTL](./index.md#changing-the-session-length)) and reloads the service
so it takes effect right away.

## What it gates, and what it does not

Consent only prompts for a real machine or tool credential. It gates these
provenance classes:

`aws` · `terraform` · `docker` · `git` · `kube` · `gcp` · `sops` · `npmrc` · `netrc`

It does **not** prompt for a project's own secrets or anything you already ran
deliberately: `.env` files, shell exports, MCP configs, `tfvars`, manually
stored secrets, bare token files, or a wrapped CLI's own token (where the
[shim](../wrap/index.md) already makes the call explicit). Those are delivered
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
you, so **treat the name on these prompts as a hint, not proof** — the prompt
says "(identified by process scan)" to mark it. The vault crypto is unaffected
either way, and if the reader cannot be fully identified the mount serves
decoys rather than guess.

A decision is remembered only for the session and is dropped the moment the
vault re-locks, so consent never outlives the unlock it rode in on.

## Pre-authorizing a whole run: `jit run --trust`

When you deliberately launch something that reaches for several credentials (a
`terraform apply`, a build script), you do not want a prompt per credential.
`--trust` pre-authorizes the entire process tree of that run:

```sh
jit run --trust -- terraform apply
```

Every process inside that run's tree is then allowed without a prompt, for any
credential, until the next re-lock. A tool launched through a
`jit run --with <cred>` grant is likewise already authorized for that credential
and is not prompted again.

## See also

- [The background service](./index.md) - the session this consent rides on
- [Provenance](./provenance.md) - why every prompt names its caller
- [Live-mounted files](../run/mounts.md) - the FIFO mounts the best-effort path covers
- [Security architecture](../security/architecture.md) - the threat model and honest limits
