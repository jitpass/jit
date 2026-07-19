---
title: Why jit
description: What you get by running jit on your machine, and why it protects secrets a cloud password manager leaves behind.
---

# Why jit

Your working machine collects plaintext secrets. `.env` files,
`~/.aws/credentials`, `export STRIPE_KEY=...` lines in your shell config,
`.npmrc` tokens, kubeconfig keys, MCP server configs. Every one of them is
readable by anything that runs as you: an infostealer from one bad
`curl | sh`, a malicious `npm install`, or one of the AI agents now running in
your editor with your full permissions.

jit finds those secrets, moves them into a local encrypted vault gated by
Touch ID, and rewrites each file so everything keeps working, without the
secret sitting on disk the rest of the time. This page is the short version of
what you get and why it matters.

## The one idea

A secret should exist in plaintext only at the moment it is used: a process
launch, a credential handshake, a revealed file read. jit makes that the
default and keeps the plaintext out of the way the rest of the time.

## 1. See what is already exposed

`jit audit` is a read-only scan of your machine. It never writes, moves, or
"fixes" anything, so it is safe to run before you trust jit with anything else.
In about 340ms it ranks every plaintext secret it finds by risk and gives you a
single exposure score from 0 to 100.

```
jit audit: risk report for alex@Alexs-MacBook-Pro
scan time: 2026-07-06T09:14:22.000Z          duration: 340ms

  RISK LEVEL: CRITICAL
  EXPOSURE:   100/100
  (1 production-indicator/public-IP match(es) found)
    - /Users/alex/code/webapp/.env

  Shell Configs          2 finding(s)
  .env Files             4 finding(s)
  Credential Files       4 finding(s)
  AI Tool / MCP Configs  4 finding(s)
  Private Keys           2 finding(s)
  ───────────────────────────────────
  Total: 18 finding(s)
```

No secret value is ever printed in full. Run `jit audit --score` when you only
want the number, or `jit audit --format ndjson` for machine-readable output.

**Why it matters:** you cannot fix what you cannot see. A password manager
stores the secrets you deliberately put into it; it has no idea what is still
sitting in the clear across your disk right now. jit tells you, before you
change a thing.

## 2. Lock it down without breaking anything

`jit migrate` moves the secrets into the vault and rewrites each file so
your tools keep working, each through that tool's own native mechanism:

| Where the secret lives | How it keeps working after jit |
| --- | --- |
| `.env` files | Live-mounted file: decoy values by default, real ones during a short revealed window |
| Shell config exports | An `eval "$(jit export ...)"` line in the config |
| AWS credentials | `credential_process` in `~/.aws/config`: the CLI and SDKs fetch on demand, no file at all |
| kubeconfig | A kubectl `exec` credential plugin |
| Terraform Cloud token | A `credentials_helper`; `terraform login`/`logout` keep working |
| Docker registry logins | A credential helper; `docker login`/`logout` keep working |
| GCP application-default credentials | Live-mounted from a template; Google SDKs read the same path |
| `.npmrc` auth tokens | Live-mounted from a template; non-secret settings untouched |
| MCP server configs | The server command wrapped in `jit run` |

Nothing about your workflow changes, and nothing is one-way. Before any file is
touched, its exact original bytes are backed up (encrypted) into the vault, and
`jit migrate undo` restores them byte for byte.

**Why it matters:** you do not rewrite a single file by hand, and you do not
risk a broken build. Every change is previewed first (`--dry-run`) and fully
reversible.

## 3. Decoys by default, real values on a timer

A migrated `.env` becomes a live file that serves `jit-hidden-...` decoy values
by default. Real values appear only when you ask - inside a short reveal window
you open on purpose, or for the lifetime of a `jit run` (which delivers them
through the process environment and hands the file itself only to that run) -
and the file goes back to decoys the moment you're done.

**Why it matters:** a backup tool, a file indexer, an infostealer, or an
over-eager agent that reads the file at the wrong moment gets a decoy, not your
production key. You control not just who can read the secret, but *when the
plaintext exists at all*.

## 4. Every prompt names who asked

When jit asks for Touch ID, it names what it is asking for and what set it off:

> jit is trying to **unlock the vault for profile "mcp-jamf", launched by claude**.

The caller identity comes from the kernel (its process id on the socket, then
its command line and parent chain), never from anything the caller says about
itself, so it cannot be faked. It is used to explain and to audit, never to
decide. `jit agent status` shows who unlocked the current session;
`jit agent history` lists every unlock, every declined prompt, and every lock.

**Why it matters:** this is 2026. The AI agents and MCP servers in your editor
run with your full permissions and can read every secret you own. jit puts a
prompt between them and your credentials, and tells you it was the agent that
asked. A prompt you cannot explain is one you approve out of habit; jit gives
you the facts to approve or cancel on.

## 5. Nothing leaves your machine

The vault is a local encrypted store bound to this machine's login Keychain.
Nothing syncs anywhere. There is no account to create, no cloud to trust, no
telemetry, and it works fully offline. jit is free for personal and internal
use.

**Why it matters:** your secrets are not exposed to a vendor breach, a cloud
outage, or a subpoena served on someone else. The only place they exist is the
machine you are already trusting to run your code.

## 6. Keep using your CLIs exactly as before

`jit wrap gh` moves a CLI's token into the vault and installs a PATH shim, so
you keep typing `gh` (or `stripe`, `ngrok`, `doctl`, `vercel`, `railway`,
`flyctl`, `supabase`, `glab`, and more) exactly as you did. On each call the
shim injects the token from the vault into just that one process, gated by the
same biometric agent, at about 25ms overhead. Because it is a shim and not a
shell alias, it keeps working inside scripts, Makefiles, and git hooks.
Anything not in the catalog works through `jit wrap add`.

## Start in one command

```
jit                        # a fresh machine? bare jit walks you through setup
jit audit                  # see what's exposed (read-only, safe anywhere)
jit migrate                # fix everything it found; tools keep working
```

## If you already use 1Password (or another password manager)

Keep it. A cloud password manager is the right home for a secret and the right
way for a team to share one. But it is built for a different job, and there is a
layer it does not reach: the plaintext copies that end up on your own disk.

Here is what jit does that a cloud password manager and its CLI do not:

- **Finds the plaintext you already have.** 1Password stores what you put in it.
  It does not scan your machine and tell you that a production database URL is
  sitting in a `.env`, or that an AWS key is in `~/.aws/credentials` right now.
  `jit audit` does.
- **Migrates your existing files in place.** 1Password's model is to store the
  secret in its cloud and have you rewrite each file to reference it
  (`op://...`) or inject it as an environment variable. jit rewrites the files
  for you through each tool's native credential mechanism
  (`credential_process`, a kubectl exec plugin, a Terraform credentials helper,
  a live-mounted template), and every change is backed up and reversible.
- **Serves decoys with a timed reveal.** A password manager hands your tool the
  real value when asked. jit keeps a decoy in the file and reveals the real
  value only for a short window, so a stray reader gets nothing.
- **Names the process that asked.** A biometric prompt from a password manager
  does not tell you which program triggered it. jit does, and keeps the history.
- **Stays entirely on your machine.** Your secrets do not go to a vendor cloud,
  there is no account or subscription, and it works offline. jit is free for
  personal and internal use.

Both tools gate secrets behind your fingerprint, both can inject a secret into a
process, and both can front a third-party CLI so its token is never stored in
the clear. The difference is where the secret lives, what happens to the
plaintext already on your disk, and who gets told when a secret is used.

The clean setup: keep 1Password for shared team secrets and non-developer
logins, and run jit underneath it to protect the copies that land on your
machine.

## On the roadmap

jit is a local, per-developer tool by design, and it is still early. Here is
what is landing next:

- **Signed, notarized releases and a Homebrew tap.** Installing becomes a plain
  `brew install`, with no Gatekeeper prompts to click through. The Apple
  Developer enrollment that unblocks this is already in progress.
- **Keys in the Secure Enclave.** Hardware-backed, OS-level enforcement of the
  Touch ID gate, on the same signing work.
- **More platforms.** jit goes deep on macOS first; Linux and beyond are on the
  roadmap.

## Try it without touching your real machine

The [jitpass-playground](https://github.com/jitpass/jitpass-playground) is a
mock project seeded with synthetic secrets and a short guided tour: audit,
migrate, watch the decoys flip to real values, and undo it all. It is the
safest way to see the whole flow before day one.
