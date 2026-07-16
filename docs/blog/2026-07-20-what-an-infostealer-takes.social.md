---
title: Social versions - "What an infostealer actually takes from a dev laptop"
description: X thread and LinkedIn post for the anchor infostealer article. Not a published page.
track: threat-lens
---

# Distribution package

Companion to
[2026-07-20-what-an-infostealer-takes.md](./2026-07-20-what-an-infostealer-takes.md).
Ship these as **native content**, not a bare link. Suggested visual for both:
a terminal capture of `jit audit` output (see the [example
report](../audit/example-report.md)) - the CRITICAL banner plus the file list
is the single most arresting image for this post.

---

## X thread (10 tweets)

**1/**
An infostealer is on a dev laptop for ~4 seconds.

No encryption. No ransom note. No root.

It runs once, as you, reads a short list of plaintext files, zips them, and
POSTs them to a random hosting IP.

Here's the exact grab list - from real 2025 campaigns. 🧵

**2/**
First, why a *dev* laptop is the top prize:

It's not one set of creds. It's the keyring for a whole org - cloud keys,
source-control tokens, SSH keys, live browser sessions, all in one place.

Steal a developer, and you've often stolen everything they can reach.

**3/**
Two ways in, same loot:

🚪 You run it - "cracked" apps + ClickFix lures ("paste this in Terminal to
fix your browser"). That paste IS the exploit. See: AMOS, ~40% of macOS
malware detections in 2025.

🚪 Your build runs it - a malicious npm postinstall. See: s1ngularity,
Shai-Hulud.

**4/** The crown jewels - cloud keys, plaintext, standing 24/7:

```
~/.aws/credentials
~/.config/gcloud/application_default_credentials.json
```

Shai-Hulud read these AND hit cloud metadata endpoints to mint fresh
temporary creds. "Stole a key" → "is enumerating your buckets."

**5/** The spreader - `~/.npmrc`.

That auth token is a bearer credential sitting in plaintext.

Shai-Hulud used it to backdoor up to 100 of the victim's OWN npm packages,
then used on-disk GitHub creds to dump the loot into a public repo.

Your token isn't stolen. It's the engine.

**6/** Your live sessions - the keychain + browser cookies.

AMOS can't read `login.keychain-db` without your password… so it just asks:
a fake "enter your password to enable auto-updates" dialog.

Then it grabs browser cookies. A live cookie skips your password AND your
MFA.

**7/** The free wins - SSH keys + a small-file sweep.

```
~/.ssh/id_ed25519   (no passphrase = clean lateral movement)
Desktop/ + Documents/   (files <50KB, by extension)
```

That <50KB filter is deliberate: it's hunting text. Notes, seed phrases,
that secrets.txt you meant to delete.

**8/** Why does ANY of this work with no exploit, no CVE?

One assumption:

> anything running as your user can read anything your user can read.

That's the whole boundary. And it's paper.

**9/** Your UID runs a LOT of untrusted code.

Every npm install. Every pip install. Every VS Code extension. Every MCP
server.

s1ngularity was the first attack to notice your AI CLIs run as you too -
invoking claude/gemini/q with --yolo to help hunt secrets.

**10/** 30-second audit, on your machine right now:

- `.env` files with real values?
- `~/.aws/credentials` populated even though you're not deploying?
- SSH key actually passphrase-protected?

Every "yes" is a file on the grab list.

Full writeup + what actually helps 👇
[repo/blog link]

---

## LinkedIn post (~280 words)

**A modern infostealer is on a developer's laptop for about four seconds.**

No encryption. No ransom note. No root access. It runs once, as you, reads a
short list of files sitting in plaintext exactly where your tools expect
them, zips them up, and sends them to a server you've never heard of. By the
time your fan spins up, someone has your cloud keys, your GitHub token, your
session cookies, and a copy of your SSH key.

I dug into the real file-grab lists from 2025's biggest campaigns - AMOS on
macOS, and the s1ngularity and Shai-Hulud npm supply-chain worms. The
targets are strikingly consistent:

• `~/.aws/credentials` and gcloud credentials - long-lived, plaintext,
standing 24/7 whether you're deploying or not
• `~/.npmrc` - a bearer token in the clear; Shai-Hulud used it to backdoor
the victim's own published packages
• The macOS keychain and browser cookies - a live session cookie skips both
your password and your MFA
• SSH keys and a sweep of small text files from Desktop and Documents

Here's the part worth sitting with: **none of it needs an exploit.** It
works because of one quiet assumption - *anything running as your user can
read anything your user can read.* On a machine where you run thousands of
lines of other people's code every day (`npm install`, extensions, MCP
servers), that's a bet you make constantly without noticing.

The credentials aren't protected. They're just lying there, on the theory
that nothing hostile will ever run as you.

Full breakdown - including an honest section on what a vault does and doesn't
stop - in the comments. 👇

*(link in first comment)*

#cybersecurity #devsecops #supplychainsecurity #infosec #appsec
