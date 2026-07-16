---
title: Install jit
description: Prebuilt binary or build from source, shell completion, and how to upgrade.
---

# Install

jit is macOS-only and needs Touch ID or a device passcode. Two ways in -
no Homebrew tap yet (planned for the first signed release).

## Option A: prebuilt binary (Apple Silicon, no Go required)

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/
```

That's the install done - continue with the **[Quickstart](./quickstart.md)**.

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

## Option B: build from source with Go

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

## Shell completion

`jit <TAB>` completes subcommands, flags, and their descriptions. With
completion installed, `jit vault get <TAB>` (and `set`/`rm`) also completes
the secret paths currently stored in your vault - names only, read straight
from the vault's file listing, so it never decrypts anything and never
triggers a Touch ID prompt mid-keystroke.

**zsh** (macOS default):

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc
exec zsh
```

If you use oh-my-zsh/prezto and `jit` is already on your PATH, that's all. On
a *plain* zsh setup (say, Go freshly installed via Homebrew and nothing else
configured), two things must come **before** that line in `~/.zshrc`, in this
order:

```sh
# 1. make jit findable (go install puts it in ~/go/bin)
export PATH="$HOME/go/bin:$PATH"

# 2. init zsh's completion system (skip if oh-my-zsh already does this)
autoload -Uz compinit && compinit

# 3. now this works: jit is on PATH and compdef exists
source <(jit completion zsh)
```

How to tell which piece is missing: `command not found: jit` means PATH,
`command not found: compdef` means `compinit` hasn't run, and `jit <TAB>`
completing plain filenames means the source line never ran at all.

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

## Upgrading

New versions are announced on the
[Releases page](https://github.com/jitpass/jit/releases). Upgrading is two
steps, not one: reinstall the binary, then restart the background agent on it.

**Prebuilt install (Option A)** - no Go needed; the same three install
commands (`releases/latest/download/...` always serves the newest version):

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/                        # 1. reinstall the binary
jit agent restart                                  # 2. restart the background agent on it
```

**Source install (Option B):**

```sh
go install github.com/jitpass/jit/cmd/jit@v0.9.5   # 1. reinstall the binary (pin the new tag)
jit agent restart                                  # 2. restart the background agent on it
```

Pin the tag rather than `@latest` right after a release: the Go module proxy
caches `@latest`, so it can quietly hand you the previous version for a while.

The second step used to be the one people skipped. If you installed the
background agent, launchd keeps the old process (and the old binary) running
right through your reinstall; every command that talks to it still gets last
version's behavior, which reads as "I upgraded but nothing changed."
`jit status` and `jit agent status` warn with "different build" until it's
restarted. The agent also notices the replaced binary itself and restarts
onto it on its own — but only once its session is locked and no prompt is
pending, so `jit agent restart` is for having it now. If you never ran
`jit agent install`, step 1 alone is the whole upgrade.

---

Next: **[Quickstart](./quickstart.md)**
