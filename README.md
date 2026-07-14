# jitpass: the `jit` CLI

**Just-in-time credentials for your dev machine.**

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

GCP application-default credentials aren't covered yet.

## Install

jit is macOS-only and needs Touch ID or a device passcode. Two ways in —
no Homebrew tap yet (planned for the first signed release).

### Option A: prebuilt binary (Apple Silicon, no Go required)

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/
```

Prebuilt binaries are Apple Silicon only — we don't have Intel hardware to
test on, and won't publish what we can't test. On an Intel Mac, use
Option B (it builds from source, so it works on any Mac).

To verify the download, `checksums.txt` on the
[release page](https://github.com/jitpass/jit/releases/latest) has the
SHA-256s: `shasum -a 256 --check checksums.txt --ignore-missing`.

Use `curl`, not the browser: browser downloads get macOS's quarantine
attribute, and Gatekeeper blocks quarantined binaries that aren't
Developer-ID signed (release builds aren't, yet — same signing work as the
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
**[docs/USAGE.md](./docs/USAGE.md#shell-completion)**.

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
steps, not one. Step 1 is reinstalling the binary — for a prebuilt install,
re-run the same three Option A commands (`releases/latest/download/...`
always serves the newest version); from source:

```sh
go install github.com/jitpass/jit/cmd/jit@v0.4.0   # 1. reinstall the binary (pin the new tag)
jit agent install                                  # 2. restart the background agent on it
```

Pin the tag rather than `@latest` right after a release: the Go module proxy
caches `@latest`, so it can quietly hand you the previous version for a while.

Step 2 is the same for both install methods.

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

The day-to-day walkthrough (setup, migrating, living with the fix) is
**[docs/USAGE.md](./docs/USAGE.md)**. Beyond that:

- **[docs/COMMANDS.md](./docs/COMMANDS.md)**: the full command reference, every command and flag
- **[TECH_STACK.md](./TECH_STACK.md)**: implementation choices and why
- **[docs/example-audit-report.md](./docs/example-audit-report.md)**: what `jit audit` output looks like (synthetic mockup)
- **[security/](./security/)**: we review jit's own code for vulnerabilities and publish the results (scope, findings, fixes, and the honest limits)
- **[CONTRIBUTING.md](./CONTRIBUTING.md)**: build/test setup and conventions; sign-off via DCO (`git commit -s`), no CLA

### What the security model is (and isn't)

We'd rather you read the boundaries than discover them:

- **`jit audit` is read-only under every flag, no exceptions.** It also never
  prints a secret value, only masked previews.
- The vault's local-auth gate is currently **enforced by jit's own code via a
  real OS Touch ID/passcode prompt, not yet by OS-enforced Keychain
  ACL/Secure Enclave binding** (that's blocked on a signing identity). It
  protects against file-grabbing malware, backup/index leaks, and casual
  exfiltration. It does not stop an attacker already executing code as your
  user, and we won't tell you otherwise.
- A secret injected into a process is plaintext inside that process; jit
  narrows the exposure window, but it can't sandbox your dependencies.
- The commands that put secrets back on disk (`jit unmount`,
  `jit migrate undo`, `jit vault export`) always re-prompt, by design.
- Each published review in [security/](./security/) ends with the known,
  accepted limitations of the build it covers.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
