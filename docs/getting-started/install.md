---
title: Install jit
description: Prebuilt binary or build from source, shell completion, and how to upgrade or uninstall.
---

# Install

jit is macOS-only and needs Touch ID or a device passcode.

## Install (Apple Silicon, no Go required)

With Homebrew:

```sh
brew install jitpass/tap/jitpass
```

Or download the release directly:

```sh
curl -sLO https://dl.jitpass.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/
```

> `dl.jitpass.com` counts the download (client type, version, country -
> never an IP) and redirects to the GitHub release asset; the bytes always
> come from GitHub. The plain
> `github.com/jitpass/jit/releases/latest/download/...` URL works identically
> if you prefer.

> **Already installed from the tarball and switching to Homebrew?** Remove the
> old copy afterwards: `sudo rm /usr/local/bin/jit`. `brew install` doesn't
> replace it, it adds a second jit, and PATH order then silently decides which
> one your shell runs while each upgrades on its own track. `jit doctor` flags
> this state and names both copies.

That's the install done - continue with the **[Quickstart](./quickstart.md)**.
The background service that lets you unlock once per session (instead of once per
command) sets itself up automatically the first time you run `jit migrate` or
`jit run`; there's no install step at all. Pick a non-default session length any
time with `jit service ttl <d>` (see
[The background service](../service/index.md)).

Prebuilt binaries are Apple Silicon only - we don't have Intel hardware to
test on, and won't publish what we can't test. On an Intel Mac, build from
source instead (below) - it works on any Mac.

To verify the download, `checksums.txt` on the
[release page](https://github.com/jitpass/jit/releases/latest) has the
SHA-256s: `shasum -a 256 --check checksums.txt --ignore-missing`.

Release binaries are signed with a Developer ID (`Meni Tasa, CZC6BH93GJ`). To
confirm that signature, run `jit doctor` and read its `jit` line: it reports
`signed CZC6BH93GJ` using the same check `jit upgrade` runs before it will
install anything, so it cannot disagree with what jit itself enforces.

Note that `codesign -dv` *displays* a signature without validating it — a
tampered binary still prints the right `Authority` line. If you would rather
check before running the binary at all, `codesign --verify --strict
$(command -v jit)` verifies its integrity and prints nothing on success. Releases are also **notarized** by Apple, so every route runs
without a Gatekeeper prompt — including ones that quarantine. Homebrew
quarantines its downloads and Gatekeeper clears them against the notarization
ticket, which it fetches online the first time a new version runs (jit ships a
bare Mach-O, and those cannot be stapled). The `curl` install sets no
quarantine flag at all, since macOS only sets it for downloads made by a
browser or other quarantine-aware app.

## Building from source (Intel Macs, contributors)

Everyone else should use the prebuilt binary above. You need this path on an
Intel Mac, or if you're working on jit itself.

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

> Dev builds (unlike releases) are ad-hoc signed, so macOS shows a one-time
> keychain permission dialog per rebuild ("jit wants to use your confidential
> information…"). That's expected, not a bug. A release build, carrying its
> stable Developer ID signature, asks once, ever.

## Shell completion

**Installed with Homebrew, completion is already set up** - the cask installs
`_jit` (plus the bash and fish scripts) into Homebrew's own completion
directories, the same place `gh` and `kubectl` put theirs. Open a new shell
and `jit <TAB>` works. The rest of this section is for tarball and
from-source installs, or for diagnosing a setup where it isn't loading -
`jit doctor` reports a `[completion]` finding with the exact line to add
when your shell has no jit completion reaching it.

`jit <TAB>` completes subcommands, flags, and their descriptions. With
completion installed it also fills in the *arguments only jit knows*, so you
never have to remember or retype an exact path or name:

| Type this | `<TAB>` offers |
| --- | --- |
| `jit vault get`/`set`/`rm` | secret paths stored in your vault (`rm` keeps offering across several) |
| `jit vault restore <path> --version` | that secret's archived version stamps, with ages |
| `jit migrate undo` | files with a restorable backup, plus each one's parent directory |
| `jit unmount` | your live-mounted file paths |
| any `--profile` flag | profile names visible from the current directory |
| `jit grant` | the create shape one flag at a time: `--process` (programs that recently asked for a secret) or `--pid`, then `--profile`, then `--for` |
| `jit grant revoke`/`extend` | your live grant ids, each with its program and expiry |
| `jit wrap add` | every tool jit knows how to wrap, then the required `--env`/`--grant` |
| `jit wrap undo` | the tools you've currently wrapped |
| `--with` / `--grant` | global mount names (`gcp`, `sops`, `npm`, `netrc`, `pypi`) |
| `jit audit` | its filters; `--kind`, `--status`, `--since` and `--format` complete their values |
| any `--format` flag | that command's output formats |
| `jit migrate --only` | migration categories, one comma-separated value at a time |

Every one of these is read from a plain file listing, the mount registry, a
manifest, or a prompt-free service query - never by decrypting a secret - so
completing an argument never triggers a Touch ID prompt mid-keystroke. Where
there is nothing to offer yet (an empty vault, no profiles here, no live
grants), `<TAB>` prints a one-line hint naming the command that changes that
instead of going silent.

Where a command's flags are the thing to complete - `jit grant`, `jit wrap
add`, `jit audit`, `jit export` - `<TAB>` accounts for what you've already
typed: a flag on the line is not offered again (a repeatable one like `--env`
still is), and the commands that build up a single request walk their flags in
order, ending with "press enter" once the line is valid.

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

Installed with Homebrew? It's `brew upgrade jitpass`; a Homebrew-managed jit
declines to self-update and says so.

Otherwise, on **v0.41.0 or newer**, upgrading is one command:

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
curl -sLO https://dl.jitpass.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
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
