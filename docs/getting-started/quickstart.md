---
title: Quickstart
description: From plaintext secrets to a clean machine - audit, vault, agent, migrate, wrap.
---

# Quickstart

The whole arc, in six commands:

```sh
jit audit                     # 1. see the problem (read-only, run it anywhere)
jit vault init                # 2. create the vault (master key in your login keychain)
jit agent install             # 3. background helper: unlock once, everything shares it
jit migrate local --dry-run   # 4. preview the fix for the project you're in
jit migrate local             # 5. apply it: plan, [y/N], one Touch ID prompt
jit status                    # 6. vault / agent / mounts / backup health, one screen
```

Every mutating command prints its plan and asks first; every rewritten file is
backed up (encrypted, into the vault) before it's touched, and
`jit migrate undo` restores any of them byte-for-byte.

The rest of this page walks the same six steps with what to expect at each.
After setup, daily life with jit is mostly nothing: your app starts normally,
`aws`/`kubectl`/`terraform` behave exactly as before, and roughly once per
15 minutes of active use, macOS asks for a Touch ID confirmation.

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

## 3. Install the background agent: `jit agent install`

Without the agent, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 15 minutes of activity (`--ttl` to change that).

The agent is also what serves live-mounted files, so if you migrate a `.env`
file, you want it installed. Everything still works without it, just with
more prompts. More in **[The background agent](../agent/index.md)**.

## 4–5. Fix a project: `jit migrate local`

Always preview first. `--dry-run` runs the exact same discovery a real run
would, so the preview is accurate:

```
$ cd ~/code/myapp
$ jit migrate local --dry-run
jit migrate - plan (local scope)
Each modified file is backed up before it's rewritten.

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

[DRY RUN] No files will be changed. Run without --dry-run to apply this plan.
```

Then apply it by dropping `--dry-run`. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation. `jit migrate home` does the same for
everything under `$HOME`, including machine-wide files like `~/.zshrc` and
`~/.aws/credentials`. More in **[Migrating](../migrate/index.md)**.

## 6. Check health: `jit status`

```
$ jit status
Vault: 5 secret(s) stored.
Agent: running and unlocked (locks in 12m30s).
Profiles: 2 profile(s), 5 secret reference(s) all resolve cleanly.
Mounts: 1 registered, agent unlocked and serving them.
```

Neither `jit status` nor `jit doctor` ever decrypts a secret or triggers
Touch ID; both are safe to run as often as you like.

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
