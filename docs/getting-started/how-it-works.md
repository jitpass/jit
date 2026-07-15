---
title: How jit works
description: The mental model - vault, agent, profiles, live mounts, shims, and provenance.
---

# How it works

jit's job is to make secrets exist in plaintext only at the moment of use -
a process launch, a credential handshake, a revealed file read - and nowhere
the rest of the time. Five pieces make that happen.

## The vault

A local encrypted store at `~/Library/Application Support/jitpass/`. Each
secret is an individually encrypted file; the master key lives in your macOS
login Keychain, gated by a Touch ID/passcode challenge. Nothing syncs
anywhere - the vault's encryption is bound to this machine's keychain
(disaster recovery goes through a
[passphrase-encrypted export](../vault/backup-restore.md) instead).

## The background agent

Unlocking the vault for every single command would mean a Touch ID prompt
per command. The [agent](../agent/index.md) is a launchd-managed process
that holds an unlocked session: you authenticate once, and everything
shares that session for the next 15 minutes of activity (configurable).
It's also the process that serves live-mounted files.

## Profiles

Migration's bookkeeping unit: a small YAML manifest mapping
environment-variable names to vault paths (`STRIPE_API_KEY ->
myapp/STRIPE_API_KEY`). `jit migrate` and `jit wrap` create them;
`jit run`, `jit export`, and `jit doctor` resolve them. A profile never
contains a secret value, only names and paths - which is exactly why it's
safe to commit. More in **[Profiles](../run/profiles.md)**.

## How each secret keeps working

Each credential flows back to its consumer through that tool's own native
mechanism, so nothing about your workflow changes:

| Where the secret lives | Example | How it keeps working after jit |
| --- | --- | --- |
| `.env` files | `DATABASE_URL=...` in a project `.env` | [Live-mounted file](../run/mounts.md): decoy values by default, real ones during a short revealed window |
| Shell config exports | `export STRIPE_KEY=...` in `~/.zshrc` | An [`eval "$(jit export ...)"` line](../migrate/shell-configs.md) in the config |
| MCP server configs | project `mcp.json`, Claude Desktop config | The server command [wrapped in `jit run`](../migrate/mcp.md) |
| AWS credentials | `~/.aws/credentials` | [`credential_process`](../migrate/aws.md) in `~/.aws/config`: the CLI and SDKs fetch on demand, no file at all |
| kubeconfig | client keys/tokens in `~/.kube/config` | A kubectl [`exec` credential plugin](../migrate/kubernetes.md) |
| Terraform Cloud token | `~/.terraform.d/credentials.tfrc.json` | A [`credentials_helper`](../migrate/terraform.md); `terraform login`/`logout` keep working |
| `.npmrc` auth tokens | project or global `.npmrc` | [Live-mounted from a template](../migrate/npm.md); non-secret settings untouched |
| CLI tool tokens | `gh`, `stripe`, `ngrok`, … config files | [`jit wrap`](../wrap/index.md): a PATH shim injects the token per invocation, ~25 ms overhead |

GCP application-default credentials aren't covered yet (audit detects them;
there's no migrate path).

## Every prompt tells you why it appeared

A Touch ID prompt you can't explain is one you'll approve out of habit -
which defeats the point of asking. So when jit asks, it names what it's
asking *for* and what set it off:

> jit is trying to **unlock the vault for profile "mcp-jamf", launched by claude**.

That's an MCP server your editor started, wanting the secrets in your
`mcp-jamf` profile. Approve or cancel on the facts, not on a guess.

The same provenance is kept afterwards: `jit agent status` shows who
unlocked the current session, and `jit agent history` lists every unlock
and lock the agent has seen. Who the caller is comes from the kernel (its
pid on the socket, then its command line and parent chain), never from
anything the caller says about itself. It is used to *explain* and to
*audit*, never to decide. More in **[Provenance](../agent/provenance.md)**
and **[Security architecture](../security/architecture.md)**.

## Everything is reversible

Before any file is rewritten, its exact original bytes are backed up,
encrypted, into the vault. `jit migrate undo` restores them byte-for-byte;
`jit unmount` turns a live mount back into a plain file; `jit migrate
remove` is the full exit from a project; `jit wrap undo` unwraps a tool.
More in **[Undo, unmount, and remove](../migrate/undo-and-remove.md)**.
