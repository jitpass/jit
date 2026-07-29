---
title: What an infostealer actually takes from a dev laptop
description: A walk through the real file-grab list of modern stealers - AMOS, s1ngularity, Shai-Hulud - and why a developer machine is the richest target on the network.
date: 2026-07-20
track: threat-lens
---

# What an infostealer actually takes from a dev laptop

*Track: the threat lens · 2026-07-20 · ~9 min read*

The malware is on the machine for maybe four seconds before it's done.

It doesn't encrypt anything. It doesn't pop a ransom note. It doesn't need
persistence, a kernel exploit, or root. It runs once, as you, reads a
short list of files that are sitting in plaintext exactly where every tool
you use expects them to be, zips them up, and POSTs the archive to an IP
address in a hosting range you've never heard of. By the time your laptop
fan spins up, the operator has your cloud keys, your GitHub token, your
browser session cookies, and a copy of your SSH private key.

This is the boring, profitable middle of the security world: the
*infostealer*. Not glamorous, not targeted, just industrialized. And the
single most valuable machine it can land on is a developer's, because a dev
laptop isn't one set of credentials - it's the keyring for an entire
organization.

Let's walk through what these things actually take. Not the marketing-deck
version - the real file paths, from real 2025 campaigns.

## Two doors, same room

Stealers reach a dev laptop through two very different front doors, and
it's worth seeing both because they converge on the exact same loot.

**Door one: you run it.** The dominant macOS stealer of 2025, **Atomic
macOS Stealer (AMOS)**, spread mostly as "cracked" apps and through
*ClickFix* lures - a fake CAPTCHA or "fix your browser" page that instructs
you to paste a command into Terminal. That paste is the whole exploit. It
runs a script as you, which sidesteps Gatekeeper entirely because *you*
invoked it. By mid-2025, one vendor attributed nearly 40% of its macOS
protection updates to AMOS alone - more than double any other macOS family
([Sophos](https://www.sophos.com/en-us/blog/why-amos-matters-the-macos-malware-stealing-data-at-scale)).

**Door two: your build runs it.** In August 2025, malicious versions of the
popular **Nx** build package shipped to npm in the attack dubbed
[**s1ngularity**](https://www.wiz.io/blog/s1ngularitys-aftermath). The
payload was a `telemetry.js` file that ran on install and walked the
filesystem for wallets, keystores, `.env` files, and SSH keys. Three months
later the [**Shai-Hulud
worm**](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
did it at self-replicating scale, backdooring ~1,000 packages via a
`preinstall` hook and leaking credentials for over 25,000 GitHub
repositories. You didn't paste anything. You ran `npm install`.

Different doors. Now look at what's in the room.

## The file-grab list

Here is the loot, grouped by what it unlocks. Every path below is a real
target from the campaigns above.

### 1. The cloud keys - the crown jewels

```
~/.aws/credentials
~/.config/gcloud/application_default_credentials.json
~/.terraform.d/credentials.tfrc.json
```

These are long-lived, plaintext, and standing at your desk 24/7 whether or
not you're using them. `~/.aws/credentials` is an INI file with your secret
access key sitting in the clear. The gcloud ADC file is JSON with a refresh
token. Shai-Hulud explicitly read the gcloud ADC path and, one better,
called the cloud **instance metadata services** to mint temporary workload
credentials on the spot - the same technique working across classic VMs,
Cloud Functions, and ECS tasks. This is the difference between "someone
stole a key" and "someone is now enumerating your S3 buckets."

### 2. The source-control tokens - how it spreads

```
~/.npmrc            # npm auth token, a bearer credential in plaintext
GitHub tokens on disk (gh config, git credential store, env)
```

Shai-Hulud read `.npmrc` from both the working directory and `$HOME`, used
the npm token to backdoor up to 100 of the victim's *own* published
packages, and used on-disk GitHub credentials to create a public repo named
with an 18-character random string, description `"Sha1-Hulud: The Second
Coming"`, and dumped the harvested secrets straight into it. Your token
isn't just stolen - it's the propagation engine. The worm spreads with no
C2 at all, reading its own code to reinfect the next package.

### 3. The keychain and browser - your live sessions

On macOS, AMOS goes after the login keychain directly:

```
~/Library/Keychains/login.keychain-db
```

It can't read that without your password, so it *asks* - an `osascript`
dialog styled to look like a system prompt:

> "The launcher needs permissions to enable background auto-updates.
> Please enter your password."

You type it. The script runs `security unlock-keychain` and a bundled
Chainbreaker tool dumps the contents into `~/Documents/data/Keychain/kc.db`
for exfiltration ([Picus](https://www.picussecurity.com/resource/blog/atomic-stealer-amos-macos-threat-analysis)).
Alongside that it takes Safari's `Cookies.binarycookies` and the equivalent
cookie and login-data stores for Chrome, Brave, Edge, and Firefox. **Session
cookies are the prize here** - a live cookie skips your password *and* your
MFA, because as far as the app is concerned you're already logged in.

### 4. The private keys and the everything-else sweep

```
~/.ssh/id_ed25519, id_rsa   (unencrypted keys are a free win)
Desktop/ and Documents/     (FileGrabber: files under ~50KB, by extension)
```

AMOS's "FileGrabber" module vacuums small files out of Desktop and Documents
by extension - the size cap (≤50KB) is a deliberate filter for text: notes,
recovery phrases, exported keys, that `secrets.txt` you swore you'd delete.
s1ngularity swept SSH keys and crypto wallets in the same pass. An SSH key
with no passphrase is the cleanest lateral-movement primitive there is.

## Why this works: the boundary nobody set

None of this needs an exploit. There's no CVE here. It works because of one
quiet assumption baked into how developer tooling stores credentials:

> **Anything running as your user can read anything your user can read.**

That's the entire boundary, and it's paper. `~/.aws/credentials`, `.env`,
`.npmrc`, your SSH key - all of them are readable by *any* process running
under your UID. A postinstall script is running as your UID. A pasted
Terminal command is running as your UID. The AI CLI on your PATH is running
as your UID - and s1ngularity was the first documented attack to *notice
that*, invoking installed `claude`, `gemini`, and `q` binaries with flags
like `--dangerously-skip-permissions` and `--yolo` to help it hunt for more
secrets ([InfoQ](https://www.infoq.com/news/2025/10/npm-s1ngularity-shai-hulud/)).

The credentials aren't protected. They're just *lying there*, on the theory
that nothing hostile will ever run as you. On a machine where you routinely
execute thousands of lines of other people's code - every `npm install`,
every `pip install`, every VS Code extension, every MCP server - that theory
is a coin flip you make several times a day.

## The uncomfortable audit

Take thirty seconds and count, on the machine you're reading this on:

- How many `.env` files with real values are in your project folders?
- Is `~/.aws/credentials` populated right now, this second, even though
  you're not deploying anything?
- Is your SSH key passphrase-protected - actually?
- When did you last `docker login`, and where did that token go? (`~/.docker/config.json`, base64, which is not encryption.)
- How many API keys are pasted into an `mcp.json` for some AI tool?

Every "yes" is a file on the grab list. Not hypothetically - those exact
paths, in the campaigns above.

## What jit changes here - and what it doesn't

I build [jit](https://github.com/jitpass/jit), so treat this section as
the interested party talking. Here's the honest version.

jit's whole premise is to attack the boundary above - to make the answer to
"is the credential lying there in plaintext?" be *no*, by default. It moves
those files into an encrypted vault and rewrites each consumer to fetch its
secret at the moment of use through that tool's own native mechanism:
`credential_process` for AWS, a `.env` that's a live mount showing decoy
values until a short reveal window, a PATH shim for `gh` and friends. Run
`jit scan` (strictly read-only) and it'll enumerate exactly the file list
above as it exists on your machine today.

**What that actually stops:** the plaintext-at-rest sweep. A stealer reading
`~/.aws/credentials` gets a `credential_process` line, not a key. Reading
the mounted `.env` outside a reveal window gets decoys. The long-lived loot is
gone, so the four-second smash-and-grab comes up mostly empty.

"Mostly" is doing real work in that sentence, and it took an outside reader to
make me say why — see the fourth bullet below.

**What it does *not* stop, and I won't pretend otherwise:**

- **Malware running as you can still ask the vault at the moment of use.**
  If a process triggers a legitimate reveal or a credential fetch, the real
  value materializes - and a program running as your UID can try to race
  that window. jit shrinks the exposure from *always* to *only at the moment
  of use*; it does not make it zero.
- **The keychain-password dialog still works on the human.** No file-layout
  change defeats a convincing `osascript` prompt. If you type your password
  into malware's dialog, that's a human-trust failure, not a storage one.
- **Live session cookies in your browser** aren't in jit's scope at all.
- **Credentials your tools mint for themselves.** This is the one I had to be
  told. Move your AWS key into the vault, and the CLI can still write a
  plaintext STS session to `~/.aws/cli/cache` the moment it assumes a role;
  `aws sso login` writes tokens to `~/.aws/sso/cache`. Those are short-lived
  rather than standing, which is a genuine improvement and not the same as
  gone — and they sit in the very directory the post above describes jit
  tidying. `jit scan` now names them as out of scope instead of walking past
  hex-named files without comment, because a clean report that omits a live
  session token is worse than no report.

The point isn't that a vault makes you unstealable. It's that "readable by
anything running as my user, forever, whether I'm using it or not" is a
worse default than it needs to be - and for the specific, enormous category
of standing credential files that stealers are built to grab, it's a default
you can simply turn off.

The malware still gets its four seconds. The question is whether there's
anything worth taking when it does.

---

*Next in the threat lens: your `.npmrc` is a bearer token - a closer look at
how the npm worms turned one plaintext line into a self-replicating supply
chain attack.*

### Sources

- [The Shai-Hulud 2.0 npm worm: analysis - Datadog Security Labs](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [s1ngularity's aftermath: analysis of the Nx supply chain attack - Wiz](https://www.wiz.io/blog/s1ngularitys-aftermath)
- [Why AMOS matters - Sophos](https://www.sophos.com/en-us/blog/why-amos-matters-the-macos-malware-stealing-data-at-scale)
- [Atomic Stealer (AMOS) threat analysis - Picus Security](https://www.picussecurity.com/resource/blog/atomic-stealer-amos-macos-threat-analysis)
- [NPM ecosystem: two AI-enabled credential-stealing supply chain attacks - InfoQ](https://www.infoq.com/news/2025/10/npm-s1ngularity-shai-hulud/)
