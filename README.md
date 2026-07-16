# jitpass: the `jit` CLI

**Just-in-time credentials for your dev machine.**

**[Documentation](./docs/index.md)** ·
[Quickstart](./docs/getting-started/quickstart.md) ·
[Supported tools](./docs/wrap/index.md) ·
[Command reference](./docs/reference/commands/jit.md) ·
[Security](./docs/security/architecture.md)

## Introduction

**The problem.** A working dev machine accumulates plaintext secrets: `.env`
files, `export STRIPE_KEY=...` lines in shell configs, `~/.aws/credentials`,
kubeconfig client keys, Terraform Cloud tokens, `.npmrc` auth tokens, MCP
server configs. Every one of them is readable by anything running as your
user, gets swept into backups and file indexes, and stays on disk long after
the moment you actually needed it.

**What jit does.** `jit` finds those secrets (`jit audit`, strictly
read-only), moves them into a local encrypted vault, and rewrites each file
so everything keeps working without the secret sitting on disk:

```
jit audit                  # what's exposed on this machine? (strictly read-only)
jit migrate local          # fix this project; tools keep working
jit wrap gh                # move a CLI's token into the vault; keep typing `gh` as before
jit run -- npm run dev     # or inject secrets straight into a process, no file at all
```

**How it resolves it.** Secrets materialize at the moment of use (a process
launch, a credential handshake, a revealed file read) and exist nowhere in
plaintext the rest of the time. The vault stores each secret as an
individually encrypted file, gated by a Touch ID/passcode challenge and
unlocked through a background agent, so you authenticate once per session,
not once per command. Every rewritten file is backed up (encrypted, into the
vault) before it's touched, and `jit migrate undo` restores it
byte-for-byte.

**Status: early development, macOS-only.** Everything below works if you
build from source; code signing/notarization and a Homebrew tap are what
stand between this and packaged releases.

### What it covers

Each credential flows back to its consumer through that tool's own native
mechanism, so everything keeps working:

| Where the secret lives | Example | How it keeps working after `jit migrate` |
| --- | --- | --- |
| `.env` files | `DATABASE_URL=...` in a project `.env` | Live-mounted file: decoy values by default, real ones during a short revealed window |
| Shell config exports | `export STRIPE_KEY=...` in `~/.zshrc` | An `eval "$(jit export ...)"` line in the config |
| MCP server configs | project `mcp.json`, Claude Desktop config | The server command wrapped in `jit run` |
| AWS credentials | `~/.aws/credentials` | `credential_process` in `~/.aws/config`: the CLI and SDKs fetch on demand, no file at all |
| kubeconfig | client keys/tokens in `~/.kube/config` | A kubectl `exec` credential plugin |
| Terraform Cloud token | `~/.terraform.d/credentials.tfrc.json` | A `credentials_helper`; `terraform login`/`logout` keep working |
| `.npmrc` auth tokens | project or global `.npmrc` | Live-mounted from a template; non-secret settings untouched |
| CLI tool tokens | `gh`, `glab`, `stripe`, `ngrok`, `doctl` config files | `jit wrap gh`: a PATH shim injects the token per invocation - works in scripts and subprocesses, ~25 ms overhead |

GCP application-default credentials aren't covered yet.

### Every prompt tells you why it appeared

A Touch ID prompt you can't explain is one you'll approve out of habit - which
defeats the point of asking. So when jit asks, it names what it's asking *for*
and what set it off:

> jit is trying to **unlock the vault for profile "mcp-jamf", launched by claude**.

That's an MCP server your editor started, wanting the secrets in your
`mcp-jamf` profile. Approve or cancel on the facts, not on a guess.

The same provenance is kept afterwards, because "why did that happen?" is
usually asked *after* the prompt is gone. `jit agent status` shows who unlocked
the current session and what dropped it - including a prompt that's on your
screen *right now*; `jit agent history` lists every unlock and lock the agent
has seen, and survives the agent's own restarts. What drops a session is
recorded too: the idle TTL, an explicit `jit agent lock`, or the screen
locking / the machine going to sleep - the session dies the moment you leave.

```
Session (most recent first):
  • locked   48m ago (11:48:04) - 15m0s idle timeout
  • unlocked 1h ago (11:33:04) - launched by claude
      ~/go/bin/jit run --profile mcp-jamf -- uv --directory ~/Documents/…
```

Who the caller is comes from the kernel (its pid on the socket, then its
command line and parent chain), never from anything the caller says about
itself - so it can't be faked by a process filling in a field. It is used to
*explain* and to *audit*, never to decide: see the
[security architecture](./docs/security/architecture.md), which also covers
what jit deliberately does *not* defend against.

## Install

jit is macOS-only and needs Touch ID or a device passcode. Two ways in -
no Homebrew tap yet (planned for the first signed release).

### Option A: prebuilt binary (Apple Silicon, no Go required)

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/
```

Optional, for `jit <TAB>` completion (if it errors, see
[Shell completion](#shell-completion-both-options) below):

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc && exec zsh
```

That's the install done. Jump ahead to the **[Quick start](#quick-start)**.

Prebuilt binaries are Apple Silicon only - we don't have Intel hardware to
test on, and won't publish what we can't test. On an Intel Mac, use
Option B (it builds from source, so it works on any Mac).

To verify the download, `checksums.txt` on the
[release page](https://github.com/jitpass/jit/releases/latest) has the
SHA-256s: `shasum -a 256 --check checksums.txt --ignore-missing`.

Use `curl`, not the browser: browser downloads get macOS's quarantine
attribute, and Gatekeeper blocks quarantined binaries that aren't
Developer-ID signed (release builds aren't, yet - same signing work as the
Homebrew tap). If you already downloaded one that way, un-quarantine it
with `xattr -d com.apple.quarantine jit`.

### Option B: build from source with Go

**1. Install Go** (1.26+), if you don't have it:

```sh
brew install go
```

**2. Install jit:**

```sh
go install github.com/jitpass/jit/cmd/jit@latest
```

A locally-compiled binary isn't quarantined either, so there's no
Gatekeeper prompt to click through here.

### Shell completion (both options)

`jit <TAB>` completes subcommands, flags, and their descriptions:

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc && exec zsh
```

**If that prints `command not found: jit` or `command not found:
compdef`** (common with Option B on a fresh Homebrew-installed Go and a
plain zsh setup):
`go install` puts the binary at `~/go/bin/jit`, which isn't on your PATH by
default, and a plain zsh never initializes its completion system. Your
`~/.zshrc` needs these lines, in this order:

```sh
# 1. make jit findable (go install puts it in ~/go/bin)
export PATH="$HOME/go/bin:$PATH"

# 2. init zsh's completion system (skip if oh-my-zsh already does this)
autoload -Uz compinit && compinit

# 3. now this works: jit is on PATH and compdef exists
source <(jit completion zsh)
```

Then `exec zsh` again. bash and fish instructions are in
**[the install guide](./docs/getting-started/install.md#shell-completion)**.

**Contributing rather than just using it?** Build from a clone instead; same
result:

```sh
git clone https://github.com/jitpass/jit.git
cd jit
go install ./cmd/jit
```

> Dev builds are ad-hoc signed, so macOS shows a one-time keychain permission
> dialog per rebuild ("jit wants to use your confidential information…").
> That's expected, not a bug. A stably-signed release build asks once, ever.

### Upgrading

New versions are announced on the
[Releases page](https://github.com/jitpass/jit/releases). Upgrading is two
steps, not one: reinstall the binary, then restart the background agent on it.

**Prebuilt install (Option A)** - no Go needed; the same three install
commands (`releases/latest/download/...` always serves the newest version):

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/                        # 1. reinstall the binary
jit agent install                                  # 2. restart the background agent on it
```

**Source install (Option B):**

```sh
go install github.com/jitpass/jit/cmd/jit@v0.5.0   # 1. reinstall the binary (pin the new tag)
jit agent install                                  # 2. restart the background agent on it
```

Pin the tag rather than `@latest` right after a release: the Go module proxy
caches `@latest`, so it can quietly hand you the previous version for a while.

The second step is the one people skip. If you installed the background agent,
launchd keeps the old process (and the old binary) running right through your
reinstall; every command that talks to it still gets last version's behavior,
which reads as "I upgraded but nothing changed." `jit status` and
`jit agent status` warn with "different build" until you restart it. If you
never ran `jit agent install`, step 1 alone is the whole upgrade.

## Quick start

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
`jit migrate undo` restores any of them byte-for-byte. For the live-mounted
files, the reveal step is wired automatically into your `.envrc` or npm
`dev`/`start` scripts, so the common case needs no manual step.

## Playground

Don't want to point a secrets tool at your real machine on day one? Fair.
**[jitpass-playground](https://github.com/jitpass/jitpass-playground)** is a
realistic mock app seeded with synthetic secrets and a guided 10-minute tour:
audit, migrate, watch decoys flip to real values, undo it all.

## Learn more

The docs live under **[docs/](./docs/index.md)**, organized by task:

- **[Quickstart](./docs/getting-started/quickstart.md)**: setup, migrating, living with the fix, step by step
- **[How it works](./docs/getting-started/how-it-works.md)**: the vault, the agent, mounts, and shims in one page
- **[Command reference](./docs/reference/commands/jit.md)**: every command and flag, generated from the CLI itself
- **[Example audit report](./docs/audit/example-report.md)**: what `jit audit` output looks like (synthetic mockup)
- **[TECH_STACK.md](./TECH_STACK.md)**: implementation choices and why
- **[docs/security/](./docs/security/architecture.md)**: the security model, plus the self-reviews we publish (scope, findings, fixes, and the honest limits)
- **[CONTRIBUTING.md](./CONTRIBUTING.md)**: build/test setup and conventions; sign-off via DCO (`git commit -s`), no CLA

### `jit wrap`: CLI tokens in the vault, muscle memory unchanged

Plenty of developer CLIs keep a long-lived token in a plaintext dotfile -
`gh` in `~/.config/gh/hosts.yml`, plus `glab`, `stripe`, `ngrok`, `doctl`,
and more. `jit wrap` moves that token into the vault and lets you keep
typing the command exactly as before:

```sh
jit wrap gh                # discover the token, vault it, scrub the file
gh pr list                 # works exactly as before - token injected per call
jit wrap list              # what's wrapped, shim health, PATH position
jit wrap undo gh           # restore the original file byte-for-byte
```

Under the hood it installs a PATH shim named after the tool. On each
invocation the shim injects the token from the vault into just that one
process, gated by the same biometric agent as every other jit flow. Because
it's a shim and not a shell alias, it keeps working inside scripts,
Makefiles, git hooks, and any subprocess that spawns the tool - the paths
aliases miss - at about 25 ms overhead per call with an unlocked agent.

`jit audit` flags the tokens worth wrapping and prints the one-command fix.
`aws` and `terraform` are wrapped too, through their own native credential
mechanisms rather than a shim, so every SDK keeps working. Uncataloged
tools work via `jit wrap add <tool> --env VAR=<vault-path>`. Full list,
one page per tool: **[docs/wrap/](./docs/wrap/index.md)**.

## License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](./LICENSE).

In plain terms:

- **Free for almost everyone.** Individual developers, non-commercial use,
  and internal use inside any company (including commercial ones) are all
  permitted at no cost, in production.
- **What's not allowed:** offering jit - hosted, embedded, repackaged, or
  redistributed - as part of a commercial product or service that competes
  with it (credentials injection, secrets management, or CLI wrapping).
  Competitors who want to do that need a commercial license from the
  Licensor.
- **It converts to open source.** On the Change Date stated in
  [LICENSE](./LICENSE) (or four years after a version's first release,
  whichever comes first), that version automatically becomes available
  under the Apache License 2.0.

This summary is informational only; the [LICENSE](./LICENSE) text governs.
All versions of jit, including releases that predate the license change, are
distributed under BUSL-1.1 from 2026-07-14 onward. (Copies obtained under
the earlier Apache-2.0 license before that date retain the rights it
granted - that grant is irrevocable as a matter of law.)
