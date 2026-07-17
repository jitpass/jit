---
title: Launch distribution package — Show HN, X, LinkedIn
description: One-time product-launch posts (Show HN + X thread + LinkedIn). Not a published page.
track: launch
---

# Launch distribution package

One-time posts for the **product launch** (distinct from the biweekly blog
promotion in the other `.social.md` files). Same rules as
[the editorial plan](./editorial-plan.md): native content per platform, repo
link last on X / in the first comment on LinkedIn, and at least one visual —
here, a terminal capture of `jit audit`'s CRITICAL banner + file list (see the
[example report](../audit/example-report.md)), the single most arresting image
we have.

Ship order: **Show HN first** (weekday morning US time), then X + LinkedIn
pointing at the same audit screenshot, not at the HN thread.

---

## Show HN

**Title options** (keep it factual, no adjectives — HN punishes hype):

1. `Show HN: Jit – find the plaintext secrets on your Mac and vault them`
2. `Show HN: Jit – move dev secrets out of plaintext without breaking your tools`
3. `Show HN: A read-only audit of every plaintext secret on your dev laptop`

**Body:**

Every working dev machine ends up with secrets in plaintext: `.env` files,
`~/.aws/credentials`, `export STRIPE_KEY=…` in `.zshrc`, `.npmrc` tokens,
tokens embedded in `mcp.json`. Anything running as your user can read all of
it — an infostealer from one bad `curl | sh`, a malicious `npm install`
postinstall, or one of the AI agents now running in your editor with your full
permissions.

`jit` starts with `jit audit`: a strictly read-only scan (it never writes
anything, under any flag) that ranks what's exposed. Eight scanners — shell
configs, `.env`, credential files, MCP/AI-tool configs, private keys, IaC
vars, suspicious filenames, wrappable CLI tokens — and it never prints a real
value, only a masked preview.

If you want to fix what it finds, `jit migrate` moves each secret into a local
encrypted vault (per-secret envelope encryption, gated by Touch ID) and
rewrites each file so your tools keep working through their *own* native
mechanisms: `.env` files become live mounts that serve decoy values until a
short reveal window; AWS uses `credential_process`; kubeconfig uses an exec
plugin; `gh`/`stripe`/`doctl` get a PATH shim that injects the token per call.
Every rewritten file is backed up (encrypted) first, and `jit migrate undo`
restores it byte-for-byte.

Two things I want to be upfront about:

- **It's macOS-only and the released binaries aren't code-signed yet.** The
  Developer ID signing + notarization (and the Homebrew tap that depends on
  it) is the main thing between this and a one-line install. For now it's
  `go install`, or a prebuilt Apple-Silicon binary you un-quarantine by hand.
- **The Touch ID gate is app-enforced, not yet OS-enforced.** The real
  Secure-Enclave guarantee is blocked on the same signing identity. The
  [security architecture doc](https://github.com/jitpass/jit/blob/main/docs/security/architecture.md)
  spells out exactly what jit does and doesn't defend against — browser
  cookies and the login keychain, for instance, are explicitly out of scope.

If you'd rather not point a secrets tool at your real machine on day one,
there's a [playground](https://github.com/jitpass/jitpass-playground): a mock
app seeded with synthetic secrets and a 10-minute guided tour. Audit it,
migrate it, watch the decoys flip, undo it all.

It's free for personal and internal company use (BUSL-1.1). Repo, source, and
docs: https://github.com/jitpass/jit — I'd genuinely like feedback on the
threat model and the migration flow.

---

## X thread (8 tweets)

Suggested visual on tweet 1: the `jit audit` CRITICAL banner + file list.

**1/**
I ran a read-only scan on my own dev laptop and it found 18 secrets sitting in
plaintext — including a prod database URL and live AWS keys.

None of them were behind anything. They were just files.

So I built `jit`. 🧵

**2/**
The uncomfortable part isn't that the secrets exist. It's *who can read them.*

Anything running as your user can: an infostealer from one bad `curl | sh`, a
malicious `npm install`, or the AI agent in your editor running with your full
permissions.

No exploit needed. The file is just readable.

**3/**
Step one is `jit audit` — strictly read-only, never writes a thing, never
prints a real value (masked previews only).

Eight scanners: shell configs, `.env`, credential files, MCP/AI-tool configs,
private keys, IaC vars, suspicious filenames, wrappable CLI tokens.

**4/**
Step two, if you want it: `jit migrate` moves each secret into a local
encrypted vault gated by Touch ID — and rewrites the file so your tools keep
working.

`.env` files become live mounts that serve *decoy* values until you open a
short reveal window. `cat` gets a fake. Your app gets the real one.

**5/**
Every tool keeps working through its own native path — not a wrapper:

• AWS → `credential_process`
• kubeconfig → exec plugin
• `gh`/`stripe`/`doctl` → a PATH shim, injected per call, works in scripts

No keys on disk. Backed up first; `jit migrate undo` restores byte-for-byte.

**6/**
The part I'm proudest of: every Touch ID prompt tells you *why* it appeared.

> unlock the vault for profile "mcp-jamf", **launched by claude**

That provenance comes from the kernel, can't be faked by the caller, and it's
kept afterward so you can audit "why did that happen?" later.

**7/**
Honest limits, because a secrets tool that oversells is worse than none:

• macOS only, binaries not code-signed yet (working on it)
• Touch ID gate is app-enforced, not yet Secure-Enclave
• browser cookies + login keychain are out of scope, on purpose

Full threat model in the repo.

**8/**
Don't want to point it at your real machine yet? There's a playground — a mock
app full of synthetic secrets and a 10-min tour. Audit, migrate, watch the
decoys flip, undo it all.

Free for personal + internal use. Source, docs, threat model:
github.com/jitpass/jit

---

## LinkedIn post (~260 words)

**I scanned my own dev laptop last month and found 18 secrets sitting in
plaintext — including a production database URL and live cloud keys.**

None of them were protected by anything. They were just files, readable by
anything running as me.

That's the whole problem, and it's easy to forget how big "anything running as
me" has become. It's every `npm install`, every VS Code extension, every MCP
server, and now every AI agent in your editor — all running with your full
permissions. A single malicious dependency, or one prompt-injected agent,
doesn't need an exploit. It just reads the files you left in the clear.

So I built `jit`. It starts with a strictly read-only audit that ranks every
plaintext secret on the machine — shell configs, `.env` files, cloud
credentials, MCP configs, SSH keys — without ever printing a real value. If
you want to fix what it finds, it moves each secret into a local, Touch-ID-
gated encrypted vault and rewrites the files so your tools keep working through
their own native mechanisms. Nothing sits on disk in plaintext; everything is
backed up and reversible.

I'm being deliberately upfront about the limits: it's macOS-only, the binaries
aren't code-signed yet, and browser cookies and the login keychain are out of
scope. The repo has a full, honest threat model — naming what a tool *doesn't*
protect is what earns the right to be trusted with what it does.

It's free for personal and internal company use. There's a playground with
synthetic secrets if you'd rather not start on your real machine. Link in the
first comment. 👇

#devsecops #cybersecurity #infosec #supplychainsecurity #macos
