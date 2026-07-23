---
title: Install jit
description: Prebuilt binary or build from source, shell completion, and how to upgrade or uninstall.
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
The background service that lets you unlock once per session (instead of once per
command) sets itself up automatically the first time you run `jit migrate` or
`jit run`; there's no install step at all. Pick a non-default session length any
time with `jit service ttl <d>` (see
[The background service](../service/index.md)).

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
completion installed it also fills in the *arguments only jit knows*, so you
never have to remember or retype an exact path or name:

| Type this | `<TAB>` offers |
| --- | --- |
| `jit vault get`/`set`/`rm` | secret paths stored in your vault |
| `jit migrate undo` | files with a restorable backup, plus each one's parent directory |
| `jit unmount` | your live-mounted file paths |
| `jit profile show`, any `--profile` | profile names visible from the current directory |
| `jit wrap add` | every tool jit knows how to wrap |
| `jit wrap undo` | the tools you've currently wrapped |
| `--with` / `--grant` | global mount names (`gcp`, `sops`, `npm`, `netrc`) |
| `jit migrate --only` | migration categories, one comma-separated value at a time |

Every one of these is read from a plain file listing, the mount registry, or
a manifest - never by decrypting a secret - so completing an argument never
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

Once you're on **v0.41.0 or newer**, upgrading is one command:

```sh
jit upgrade
```

It fetches the latest release, verifies its SHA-256 against the release
`checksums.txt` *before* anything replaces your binary, swaps the binary jit
runs from (prompting for `sudo` only if that path isn't writable), and
restarts the service onto the new build - so there's no "I upgraded but
nothing changed" gap and nothing to remember. `jit upgrade --force`
reinstalls the latest even when you're already on it. It fetches the
published Apple Silicon release; on an Intel or source install, use the
`go install` line below instead.

New versions are announced on the
[Releases page](https://github.com/jitpass/jit/releases).

### Manual upgrade (your first upgrade onto v0.41.0, Intel, or by preference)

`jit upgrade` only exists once you've installed a build that has it, so the
very first upgrade *onto* v0.41.0 - and every upgrade on an Intel/source
install - uses the same commands as a fresh install. Reinstalling the binary
is the whole upgrade; the running service switches onto it on its own within
a few seconds once its session is locked, and the optional `jit service
restart` just makes that happen *now*.

**Prebuilt (Apple Silicon)** - `releases/latest/download/...` always serves
the newest version:

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/                        # 1. reinstall the binary
jit service restart                                # 2. (optional) switch the running service over now
```

**Source (any Mac):**

```sh
go install github.com/jitpass/jit/cmd/jit@v0.41.0   # 1. reinstall the binary (pin the new tag)
jit service restart                                 # 2. (optional) switch the running service over now
```

Pin the tag rather than `@latest` right after a release: the Go module proxy
caches `@latest`, so it can quietly hand you the previous version for a while.

Why the `jit service restart` line helps. launchd keeps the old service
process (and the old binary) running right through your reinstall, so until it
restarts, every command that talks to it still gets last version's behavior -
`jit status` warns "different build" until then. The service does switch onto
the replaced binary on its own once its session is locked and idle; restart is
for wanting it immediately. It also re-points launchd if the binary moved,
re-bootstraps a service launchd had dropped, and recreates the login item if
it was missing. (`jit upgrade` does this step for you.)

## Uninstalling

```sh
jit uninstall
```

Removes the background service, the wrap shims, and the jit binary. It asks
for a fresh Touch ID / passcode first, so nobody at your unlocked Mac can
remove jit (or your secrets) without you present; `--yes` skips only the typed
y/N confirmation, never the fingerprint.

Your vault is **kept by default**. jit is the only thing that can decrypt it
on this Mac, so uninstall leaves your secrets in place and prints where they
are. Add `--purge` to also erase the vault and the `~/.jit` config - it names
how many secrets that destroys and points you at `jit vault export` first.
`--purge` is irreversible and there is no other copy on the machine, so export
anything you might want back before running it:

```sh
jit vault export ~/jit-backup.age   # protect your secrets first
jit uninstall --purge               # then erase everything, Touch ID required
```

The gate guards the `jit uninstall` path; it is not a substitute for file
permissions - anyone with a shell as you can still delete the files directly.

---

Next: **[Quickstart](./quickstart.md)**
