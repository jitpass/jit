---
title: Quickstart
description: From plaintext secrets to a clean machine - scan, vault, migrate, wrap.
---

# Quickstart

The whole arc, in five commands:

```sh
jit scan                       # 1. see the problem (read-only, run it anywhere)
jit vault init                  # 2. create the vault (master key in your login keychain)
jit migrate ~/code/myapp --dry-run  # 3. preview the fix for a file or project scan flagged
jit migrate ~/code/myapp        # 4. apply it: plan, [y/N], one Touch ID prompt
jit status                      # 5. vault / service / mounts / backup health, one screen
```

The background service (so you unlock once, not once per command) installs
itself automatically during that `jit migrate` - there's no install step. Pick
a custom session length any time with `jit service ttl <d>`.

Every mutating command prints its plan and asks first; every rewritten file is
backed up (encrypted, into the vault) before it's touched, and
`jit migrate undo` restores any of them byte-for-byte.

After setup, daily life with jit is mostly nothing: your app starts normally,
`aws`/`kubectl`/`terraform` behave exactly as before, and roughly once per
5 minutes of active use, macOS asks for a Touch ID confirmation.

## 1. See what's exposed: `jit scan`

Start here. `jit scan` is strictly read-only under every flag: it never
touches, encrypts, or rewrites anything, and never prints a real secret value
in full, only a masked preview.

```
$ jit scan
jit scan  ~/ · 7 files · 1ms

  YOUR SECRETS: 7 — 0 protected by jit (0%)
  ▱▱▱▱▱▱▱▱▱▱  to 100%: one command +71% · 2 secrets only you can fix +29%

  jit will protect these — 5 secrets in 4 files, 0% → 71%
      → jit migrate
        one command; it vaults the values and rewrites 4 files — every tool that
        reads them keeps working:
  ...
```

The green section is exactly what bare `jit migrate` will do; the red
section is what only you can do. `jit scan --full` shows the per-category
inventory with severities.

With no arguments, `scan` covers your whole home directory, not just your
current directory - the question it answers is "is my machine clean," not "is
this one project clean." To check a single file or folder instead, name it:
`jit scan ./my-project token.txt`. More in
**[Running an audit](../audit/index.md)**.

## 2. Create the vault: `jit vault init`

```
$ jit vault init
Vault initialized at /Users/alex/Library/Application Support/jitpass.
```

This generates a master encryption key and stores it in your macOS Keychain.
You'll see a Touch ID / passcode prompt; that's expected.

### The background service (set up automatically)

Without the service, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 5 minutes of activity (`jit service ttl` to change that). The
service is also what serves live-mounted files.

You never install it as a separate step: the `jit migrate` below sets it up for
you the first time it's needed, and launchd keeps it running across logins. More
in **[The background service](../service/index.md)**.

## 3. Fix what audit found: `jit migrate`

Always preview first. `--dry-run` runs the exact same discovery a real run
would, so the preview is accurate, and `jit migrate` covers the same
whole-machine ground `jit scan` scans, so what the report showed is what
the plan fixes:

```
$ jit migrate ~/code/myapp/.env --dry-run
jit migrate, plan
Each modified file is backed up before it's rewritten.

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • ~/code/myapp/.env

[DRY RUN] No files were changed. Run without --dry-run to apply this plan.
```

Then apply it by dropping `--dry-run`. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation. Name a directory to walk a whole
project (`jit migrate ~/code/myapp`), or a single file to convert just
that one - one `.env`, a `~/.zshrc`, or even a bare token in a plain file
(`jit migrate token.txt`). More in
**[Migrating](../migrate/index.md)**.

## 4. Check health: `jit status`

```
$ jit status
Vault: 5 secret(s) stored.
Service: running and unlocked (locks in 12m30s).
Secrets: 5 stored in 2 group(s).
  Wired here:        2 group(s) via 2 profile(s) (5 reference(s)), all resolve.
  Managed elsewhere: 0 group(s) (referenced only by global profiles or mounts).
  Unreferenced here: none.
Mounts: 1 registered, service unlocked, all serving decoy (real values flow through a jit run grant, or an approved consent prompt for a global credential file).
```

`jit status` is the quick read-only snapshot. Its **Secrets** section
reconciles the vault against your profiles: every stored secret is *wired
here* (a project-local profile uses it), *managed elsewhere* (referenced only
by a global profile or a mount), or *unreferenced* (a candidate orphan). Add
`jit status --secrets` for the full per-group listing. `jit doctor` is the
deeper pass/fail diagnostic (it also verifies each secret's envelope, sweeps
for orphaned secrets, and checks service, backup, and shim health). See
**[Profiles](../run/profiles.md#checking-a-profiles-health-jit-doctor)**.

Neither `jit status` nor `jit doctor` ever decrypts a secret or triggers
Touch ID; both are safe to run as often as you like.

## 5. Run your project: `jit run`

After migration a `.env` serves **decoy** values to anything that reads it
cold: a `cat`, a backup, or a bare `npm run dev`. Real values reach a tool
**only** when you launch it through `jit run`:

```
$ jit run -- npm run dev      # injects your .env secrets into the process
```

There are four modes, split across two independent switches. `--live` is for
**this project's** files, `--with` for a **machine-global** credential:

```
$ jit run -- <cmd>                       # tool reads env vars (the common case)
$ jit run --live -- <cmd>                # tool reads the .env FILE itself (docker compose env_file:)
$ jit run --with gcp -- <cmd>            # tool needs a global cred (gcloud ADC, sops, ~/.npmrc, ~/.netrc)
$ jit run --live --with gcp -- <cmd>     # needs both at once
```

Not sure whether you need `--live`? Just run the default first; if the tool
acts like its config is empty, re-run with `--live`. Full guide, including a
decision table, in **[Run a command with secrets](../run/index.md)**.

## 6. Work that runs while you're away: `jit grant`

The session above ends when you do: idle timeout, screen lock, sleep. That is
the right default until something has to keep running without you - an agent
working overnight, a long build, a scheduled job. Those stop at a prompt
nobody is there to answer.

`jit grant` moves the decision earlier instead of removing it. One Touch ID,
now, approves a named program to use specific profiles until a deadline you
set:

```sh
$ jit grant --process claude --profile jamf --for 8h
```

The prompt names exactly what you're signing ("let claude under iTerm2 use
2 secrets (jamf) unattended for 8h"), and the grant is scoped to the terminal
you typed it in, including sessions you start later inside that window.
Everything else keeps prompting as usual. `jit grant list` shows what's open,
`jit grant revoke` ends one early, and every grant and every use of it lands
in `jit audit`.

More in **[Process grants](../service/grants.md)**.

## Optional: wrap your CLI tools

Dev CLIs like `gh`, `stripe`, and `ngrok` keep their tokens in their own
config files, which `migrate` doesn't cover - `jit wrap <tool>` does. One
command moves the token into the vault and puts a shim on PATH so the
command keeps working exactly as you type it:

```sh
jit wrap gh
```

An SSO CLI is the same command for the opposite problem: `clisso` carries no
token, it *mints* AWS credentials at every login and writes them to
`~/.aws/credentials` in plaintext. `jit wrap clisso` captures each login into
the vault instead, MFA prompts unchanged.

See **[Wrap](../wrap/index.md)** for the full catalog.

---

Next: **[How it works](./how-it-works.md)**
