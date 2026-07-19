---
title: docker login stores your password in base64 - and the 4-verb protocol that fixes it
description: Where docker login actually puts registry credentials, who has them in plaintext right now, and how Docker's own credential-helper protocol works - plus what jit v0.16 does with it.
date: 2026-07-18
track: inside-jit
---

# docker login stores your password in base64 - and the 4-verb protocol that fixes it

*Track: inside jit · 2026-07-18 · ~6 min read*

Run this on a machine that has ever done a `docker login` without Docker
Desktop:

```sh
jq -r '.auths | to_entries[] | select(.value.auth) | "\(.key): \(.value.auth)"' ~/.docker/config.json
```

If you get output like `registry.example.com: YWxpY2U6czNjcmV0LXBhc3M=`,
that second field is your registry username and password. Not hashed, not
encrypted - base64. One `| base64 -d` away from `alice:s3cret-pass`.

Docker's own documentation says this plainly: if no credential store is
configured, credentials are stored "in a base64-encoded format" in
`config.json`, and "this method is less secure than configuring and using
a credential store." Base64 is encoding, not encryption. The same
observation drives how jit's audit treats Kubernetes Secret manifests: it
decodes `data:` values *before* judging them, because an attacker will
too.

## Who actually has this problem

Not everyone, and it's worth being precise, because the split is exactly
the line between "already fine" and "plaintext for years."

**Docker Desktop users are mostly fine.** Desktop configures
`"credsStore": "desktop"` out of the box, so logins land in the macOS
keychain (or wincred/pass elsewhere). This is the path most tutorials
assume.

**Everyone else accumulates plaintext.** The docker CLI via homebrew,
colima, lima, a Linux box without `pass` set up, CI runners, remote dev
VMs - none of these configure a store, and docker's documented fallback
on every one of them is base64 in the file. The failure is silent: `docker
login` prints `Login Succeeded` either way. And because pushes to a
private registry are something you set up once and forget, that
credential commonly sits there for years. Registry credentials are also
not small loot: a token that can *push* images to a registry other
machines *pull* from is a supply-chain foothold, not just a read leak.

The same shape hides in one more place: a Kubernetes
`kubernetes.io/dockerconfigjson` Secret is this exact file, base64'd a
second time, checked into a manifest.

## The fix Docker already ships: a 4-verb protocol

Here's the part worth knowing even if you stop reading after this
section. Docker's credential mechanism is pluggable, and the plug is
about as simple as inter-process protocols get.

A *credential helper* is any executable on `$PATH` named
`docker-credential-<name>` that speaks four verbs, payloads over stdin:

- `get` - reads a registry address, prints
  `{"ServerURL","Username","Secret"}` as JSON. "Nothing stored" is a
  documented sentinel string plus a non-zero exit, so anonymous pulls of
  public images fall through cleanly.
- `store` - reads that same JSON; this is what `docker login` calls.
- `erase` - reads a registry address; this is `docker logout`.
- `list` - prints a map of stored registries.

Two config keys wire it up: `credsStore` names the default helper for
everything, and `credHelpers` maps individual registries to specific
helpers - and per-registry entries win over the default. That precedence
rule matters more than it looks: it means a second tool can take over
*one* registry without touching whatever store already owns the rest.

The protocol has been stable since 2016, and it's load-bearing far beyond
Docker's CLI: Docker Desktop is itself a helper, AWS/Google/Azure ship
official ECR/GCR/ACR helpers on it, and buildkit, compose, kaniko, and
most of the OCI tool ecosystem resolve credentials through the same
config. This is the transferable design idea: AWS has
`credential_process`, Terraform has `credentials_helper`, kubectl has
exec credential plugins, sops has `SOPS_AGE_KEY_CMD`. Every serious
credential consumer eventually grows a "run this program instead of
reading a file" hook, because file-at-rest is the only design that can't
be fixed later. If you're building a tool that reads a secret from
config, this is the escape hatch to leave yourself.

## What jit v0.16 does with it

[jit](https://github.com/jitpass/jit) v0.16 turns that protocol into the
exit ramp for the base64 case:

- **`jit audit`** now flags every registry in `~/.docker/config.json`
  whose entry still carries a real secret - base64 `auth`, identity
  token, or literal password - and skips docker's own empty markers.
- **`jit migrate`** (category `docker`) moves each credential into the
  encrypted vault and rewrites the config to route that registry through
  a `docker-credential-jit` helper. Because per-registry `credHelpers`
  win, it never replaces an existing store: Docker Desktop keeps its
  keychain, jit takes only the registries that were plaintext. Only when
  the config had *no* store at all does jit claim the default, so future
  logins to new registries land in the vault instead of back in base64.
- **`docker login` and `logout` keep working** - that's the point of
  using the native hook instead of a wrapper. Re-login is also the whole
  rotation story: mint a new
  [scoped access token](https://docs.docker.com/security/access-tokens/),
  `docker login`, done. Compose and buildx pulls resolve through the same
  config, so they come along for free.
- Like every migrate category, the original file is backed up encrypted
  first, and `jit migrate undo` restores it byte-for-byte.

This lands on top of v0.15, which made bare `jit migrate` whole-machine
by default - audit scans the whole machine, so the fix command now covers
the same ground, one command from report to fixed.

**What this doesn't cover, in the usual spirit of naming it:** a process
running as you can still trigger a legitimate credential fetch at the
moment of use; jit shrinks exposure from *always* to *at the moment of
use*, not to zero. Compose `secrets: file:` sources and swarm's
cluster-side secrets are out of scope (the docs page shows the patterns).
And the helper's `list` verb deliberately returns an empty set, because a
truthful listing would require a vault unlock inside headless docker
calls - docker resolves every registry through `get` regardless.

The full walkthrough is in the
[Docker migration guide](../migrate/docker.md).

### Sources

- [docker login - credential stores and the helper protocol](https://docs.docker.com/reference/cli/docker/login/)
- [docker/docker-credential-helpers](https://github.com/docker/docker-credential-helpers)
- [Docker access tokens](https://docs.docker.com/security/access-tokens/)
- [Compose: how to use secrets](https://docs.docker.com/compose/how-tos/use-secrets/)
