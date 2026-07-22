---
title: Quickstart
description: From plaintext secrets to a clean machine - audit, vault, agent, migrate, wrap.
---

# Quickstart

The whole arc, in five commands:

```sh
jit audit                     # 1. see the problem (read-only, run it anywhere)
jit vault init                # 2. create the vault (master key in your login keychain)
jit migrate --dry-run         # 3. preview the fix, same whole-machine scope as audit
jit migrate                   # 4. apply it: plan, [y/N], one Touch ID prompt
jit status                    # 5. vault / agent / mounts / backup health, one screen
```

The background helper (so you unlock once, not once per command) installs
itself automatically during that `jit migrate` - no separate step. Run
`jit agent install` yourself only to set it up early or pick a custom `--ttl`.

Every mutating command prints its plan and asks first; every rewritten file is
backed up (encrypted, into the vault) before it's touched, and
`jit migrate undo` restores any of them byte-for-byte.

The rest of this page walks the same steps with what to expect at each.
After setup, daily life with jit is mostly nothing: your app starts normally,
`aws`/`kubectl`/`terraform` behave exactly as before, and roughly once per
5 minutes of active use, macOS asks for a Touch ID confirmation.

## 1. See what's exposed: `jit audit`

Start here. `audit` is strictly read-only under every flag: it never touches,
encrypts, or rewrites anything, and never prints a real secret value in full,
only a masked preview.

```
$ jit audit
jit audit - risk report for alex@Alexs-MacBook-Pro

  RISK LEVEL: HIGH

  Shell Configs          1 finding(s)
  .env Files             1 finding(s)
  ...
```

`audit` always scans your whole home directory, not your current directory -
the question it answers is "is my machine clean," not "is this one project
clean." More in **[Running an audit](../audit/index.md)**.

## 2. Create the vault: `jit vault init`

```
$ jit vault init
Vault initialized at /Users/alex/Library/Application Support/jitpass.
```

This generates a master encryption key and stores it in your macOS Keychain.
You'll see a Touch ID / passcode prompt; that's expected.

### The background agent (set up automatically)

Without the agent, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 5 minutes of activity (`--ttl` to change that). The agent is
also what serves live-mounted files.

You don't install it as a separate step: the `jit migrate` below sets it up
for you the first time it's needed. Run `jit agent install` yourself only to
do that early or pick a custom `--ttl`. More in
**[The background agent](../agent/index.md)**.

## 3. Fix what audit found: `jit migrate`

Always preview first. `--dry-run` runs the exact same discovery a real run
would, so the preview is accurate, and `jit migrate` covers the same
whole-machine ground `jit audit` scans, so what the report showed is what
the plan fixes:

```
$ jit migrate --dry-run
jit migrate - plan (home scope)
Each modified file is backed up before it's rewritten.

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • ~/code/myapp/.env

[DRY RUN] No files will be changed. Run without --dry-run to apply this plan.
```

Then apply it by dropping `--dry-run`. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation. To fix just one project instead, `cd`
into it and run `jit migrate local`: only what's under that directory
tree is discovered or touched. To fix a single named file with no walk at
all - one `.env`, a `~/.zshrc` - run `jit migrate path <file>`. More in
**[Migrating](../migrate/index.md)**.

## 4. Check health: `jit status`

```
$ jit status
Vault: 5 secret(s) stored.
Agent: running and unlocked (locks in 12m30s).
Profiles: 2 profile(s), 5 secret reference(s) all resolve cleanly. Run `jit doctor` to also verify secret integrity.
Mounts: 1 registered, agent unlocked, all serving decoy (real values flow only inside a jit run --live/--with grant).
```

`jit status` is the quick read-only snapshot; `jit doctor` is the deeper
pass/fail diagnostic (it also verifies each secret's envelope, sweeps for
orphaned secrets, and checks agent, backup, and shim health). See
**[Profiles](../run/profiles.md#checking-a-profiles-health-jit-doctor)**.

Neither `jit status` nor `jit doctor` ever decrypts a secret or triggers
Touch ID; both are safe to run as often as you like.

## 5. Run your project: `jit run`

After migration a `.env` serves **decoy** values to anything that reads it
cold — a `cat`, a backup, or a bare `npm run dev`. Real values reach a tool
**only** when you launch it through `jit run`:

```
$ jit run -- npm run dev      # injects your .env secrets into the process
```

There are four modes, split across two independent switches — `--live` for
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

## Optional: wrap your CLI tools

Dev CLIs like `gh`, `stripe`, and `ngrok` keep their tokens in their own
config files, which `migrate` doesn't cover - `jit wrap <tool>` does. One
command moves the token into the vault and puts a shim on PATH so the
command keeps working exactly as you type it:

```sh
jit wrap gh
```

See **[Wrap](../wrap/index.md)** for the full catalog.

## Try it on a fake machine first

Don't want to point a secrets tool at your real machine on day one? Fair.
**[jitpass-playground](https://github.com/jitpass/jitpass-playground)** is a
realistic mock app seeded with synthetic secrets and a guided 10-minute tour:
audit, migrate, watch decoys flip to real values, undo it all.

---

Next: **[How it works](./how-it-works.md)**
