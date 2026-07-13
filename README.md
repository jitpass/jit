# jitpass: the `jit` CLI

**Just-in-time credentials for your dev machine.** `jit` finds the plaintext
secrets scattered across your Mac (`.env` files, shell exports, `~/.aws/credentials`,
kubeconfig, Terraform Cloud tokens, `.npmrc`, MCP configs), moves them into a
local encrypted vault, and rewrites each file so **everything keeps working
without the secret sitting on disk**. Secrets materialize at the moment of
use (a process launch, a credential handshake, a revealed file read) and exist
nowhere in plaintext the rest of the time.

```
jit audit                  # what's exposed on this machine? (strictly read-only)
jit migrate local          # fix this project; tools keep working
jit run -- npm run dev     # or inject secrets straight into a process, no file at all
```

**Status: early development, macOS-only.** Everything below works if you build
from source; code signing/notarization and a Homebrew tap are what stand
between this and packaged releases. **[GAPS.md](./GAPS.md)** is
the honest list of everywhere current behavior falls short of the target
design. Read it before assuming a guarantee.

## Try it in a sandbox first

Don't want to point a secrets tool at your real machine on day one? Fair.
**[jitpass-playground](https://github.com/jitpass/jitpass-playground)** is a
realistic mock app seeded with synthetic secrets and a guided 10-minute tour:
audit, migrate, watch decoys flip to real values, undo it all.

## Install

Requires Go 1.26+ and macOS with Touch ID or a device passcode:

```sh
go install github.com/jitpass/jit/cmd/jit@latest   # installs to ~/go/bin; make sure it's on your PATH
```

Until the first signed release (Homebrew tap planned), this builds from source.
That's deliberate: a locally-compiled binary isn't quarantined, so there's no
Gatekeeper prompt to click through. Contributors building from a clone:

```sh
git clone https://github.com/jitpass/jit.git
cd jit
go install ./cmd/jit
```

> Dev builds are ad-hoc signed, so macOS shows a one-time keychain permission
> dialog per rebuild ("jit wants to use your confidential information…").
> That's expected, not a bug. A stably-signed release build asks once, ever.

### Shell completion

`jit <TAB>` completes subcommands, flags, and their descriptions.

**zsh** (macOS default):

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc
exec zsh
```

If you use oh-my-zsh/prezto, that's all. On a *plain* zsh setup, completions
need zsh's completion system initialized first. Add this line **before** the
one above if `jit <TAB>` still completes filenames:

```sh
echo 'autoload -Uz compinit && compinit' >> ~/.zshrc
```

**bash** (requires the `bash-completion` package):

```sh
echo 'source <(jit completion bash)' >> ~/.bashrc
```

**fish**:

```sh
jit completion fish > ~/.config/fish/completions/jit.fish
```

`jit completion <shell> --help` has per-shell details, including system-wide
install locations.

## Quickstart

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
`jit migrate undo` restores any of them byte-for-byte. The full command
walkthrough lives in **[docs/USAGE.md](./docs/USAGE.md)**.

## How it works, in one paragraph

Secrets live as individually encrypted files in a local vault, gated by a
Touch ID/passcode challenge and unlocked through a launchd agent so you
authenticate once per session, not once per command (the commands that write
secrets back to disk always re-prompt, by design: `jit unmount`,
`jit migrate undo`, `jit vault export`). Each credential then
flows back to its consumer through that tool's own native mechanism:
`credential_process` for the AWS CLI/SDK, an exec plugin for kubectl, a
credentials helper for Terraform (`terraform login/logout` keep working), a
`jit run` wrapper for MCP servers, an `eval` line for shell configs, and for
`.env`/`.npmrc` a live-mounted file that serves **decoy values by default**
and real ones only during a short revealed window (wired automatically into your
`.envrc` or npm `dev`/`start` scripts, so the common case needs no manual
step). `jit agent status` shows who read what, and when.

## What the security model is (and isn't)

**We review jit's own code for vulnerabilities and publish the results (scope,
findings, fixes, and the honest limits) in [security/](./security/).** And
we'd rather you read the boundaries than discover them:

- **`jit audit` is read-only under every flag, no exceptions.** It also never
  prints a secret value, only masked previews.
- The vault's local-auth gate is currently **enforced by jit's own code via a
  real OS Touch ID/passcode prompt, not yet by OS-enforced Keychain
  ACL/Secure Enclave binding** (that's blocked on a signing identity; see
  GAPS.md #1). It protects against file-grabbing malware, backup/index leaks,
  and casual exfiltration. It does not stop an attacker already executing
  code as your user, and we won't tell you otherwise.
- A secret injected into a process is plaintext inside that process; jit
  narrows the exposure window, but it can't sandbox your dependencies.
- Full threat model, including everything jit deliberately does *not* defend
  against: **[RFC.md](./RFC.md)**.

## Developing & testing

```sh
go build ./... && go vet ./...
go test -race ./...            # the full suite is designed to run without Touch ID
staticcheck ./... && gosec ./... && govulncheck ./...
```

Anything touching the real keychain/Touch ID is verified manually; the
[playground tour](https://github.com/jitpass/jitpass-playground) is the
end-to-end script for that. Automated tests never touch your real vault,
keychain, or `$HOME`; that isolation is strict (it exists because of real
incidents), and the testing conventions are documented in
**[CONTRIBUTING.md](./CONTRIBUTING.md)**.

Contributions are welcome: sign-off via DCO
(`git commit -s`), no CLA. See **[CONTRIBUTING.md](./CONTRIBUTING.md)**.

## Read these next

- **[docs/USAGE.md](./docs/USAGE.md)**: full command walkthrough
- **[RFC.md](./RFC.md)**: architecture + explicit threat-model boundaries
- **[GAPS.md](./GAPS.md)**: the honest gap list; **[ROADMAP.md](./ROADMAP.md)**: build status
- **[TECH_STACK.md](./TECH_STACK.md)**: implementation choices and why
- **[docs/example-audit-report.md](./docs/example-audit-report.md)**: what `jit audit` output looks like (synthetic mockup)

## License & security

The `jit` CLI is **[Apache-2.0](./LICENSE)**: fully open source, free to use
and build on. It's licensed permissively rather than source-available because
the CLI has no hosted component to wall off; any future team/collaboration
features would be a separate layer, not a restriction on anything here.
Vulnerability reports: **[SECURITY.md](./SECURITY.md)**.
