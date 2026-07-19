---
title: Social versions - "docker login stores your password in base64"
description: X thread and LinkedIn post for the v0.16 release article. Not a published page.
track: inside-jit
---

# Distribution package

Companion to
[2026-07-18-docker-login-base64.md](./2026-07-18-docker-login-base64.md).
Ship these as **native content**, not a bare link. Suggested visual: a
two-pane terminal capture - left, the `jq` one-liner decoding
`~/.docker/config.json` to a plaintext `alice:s3cret-pass`; right, the same
file after `jit migrate --only docker` showing only `{}` markers and
`"credHelpers"`.

---

## X thread (8 tweets)

**1/**
Run this on any machine that's done a `docker login` without Docker
Desktop:

jq -r '.auths[].auth // empty' ~/.docker/config.json | base64 -d

If it prints user:password, that's your registry login. On disk. In
base64. Since whenever you last logged in. 🧵

**2/**
This is documented behavior, not a bug: with no credential store
configured, docker stores logins "in a base64-encoded format" in
config.json.

Docker's own docs call it "less secure." base64 is encoding, not
encryption.

**3/**
Who's affected splits cleanly:

Docker Desktop users: fine. Desktop wires the OS keychain out of the box.

Homebrew docker CLI, colima, lima, Linux without `pass`, CI runners, dev
VMs: plaintext, silently, and `docker login` says "Login Succeeded"
either way.

**4/**
Why it matters more than a read leak: a registry credential that can PUSH
images other machines PULL is a supply-chain foothold.

And the same file hides twice: a k8s dockerconfigjson Secret is this
exact JSON, base64'd again, sitting in a manifest.

**5/**
The fix has shipped inside docker since 2016: credential helpers.

Any executable named docker-credential-<name> speaking 4 verbs over
stdin: get / store / erase / list.

Docker Desktop is one. AWS, Google, and Azure ship official ECR/GCR/ACR
helpers on the same protocol.

**6/**
The design detail worth stealing: per-registry `credHelpers` beat the
default `credsStore`.

So a tool can take over exactly the registries that are plaintext without
touching the keychain store that owns the rest.

Every serious credential consumer grows this hook eventually.

**7/**
jit v0.16 uses it as the exit ramp:

- jit audit flags every registry still carrying a real secret
- jit migrate vaults them behind docker-credential-jit
- docker login/logout keep working; re-login IS rotation
- compose + buildx come along for free
- one command undoes it, byte-for-byte

**8/**
It never replaces an existing store, and a fetch still needs the vault
unlocked - jit shrinks exposure from "always, at rest" to "at the moment
of use," not to zero.

Docs and code: github.com/jitpass/jit

Check yourself first, it's read-only: jit audit

---

## LinkedIn post

**Your docker login might be a plaintext file, and it's documented
behavior.**

If you use the docker CLI without Docker Desktop (homebrew, colima, a
Linux box, a CI runner), run this:

jq -r '.auths[].auth // empty' ~/.docker/config.json | base64 -d

If that prints a username:password pair, your registry credential has
been sitting on disk in base64 since you last logged in. Docker's docs
say it directly: without a credential store, logins are kept
base64-encoded in config.json, which is "less secure." base64 is
encoding, not encryption - and a credential that can push images other
machines pull is a supply-chain problem, not just a leaked password.

The interesting part is that docker already ships the fix: the
credential-helper protocol. Four verbs over stdin (get, store, erase,
list), any executable on PATH named docker-credential-<name>, and a
precedence rule where per-registry helpers beat the default store. It's
the same "run a program instead of reading a file" pattern as AWS's
credential_process, Terraform's credentials_helper, and kubectl's exec
plugins - the escape hatch every serious credential consumer eventually
grows.

We just shipped jit v0.16 on exactly that hook: jit audit flags the
plaintext registries, jit migrate moves them into an encrypted vault
behind a docker-credential-jit helper, and docker login/logout, compose,
and buildx keep working unchanged - rotation is just logging in again
with a scoped access token. It never replaces an existing keychain store,
and everything is reversible byte-for-byte with jit migrate undo. This
builds on v0.15, where jit migrate went whole-machine by default: one
command from audit report to fixed.

Honest limits, as always: a process running as your user can still
trigger a fetch at the moment of use; jit shrinks the exposure window, it
doesn't make you unstealable.

Repo: github.com/jitpass/jit
