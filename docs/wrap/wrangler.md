---
title: Wrap the Cloudflare Wrangler CLI with jit
description: Keep your Cloudflare API token in the vault - injected as CLOUDFLARE_API_TOKEN just-in-time.
---

# wrangler - Cloudflare Workers CLI

Wrangler reads its credential from `CLOUDFLARE_API_TOKEN`. Interactive
`wrangler login` instead stores a short-lived OAuth access token in
`~/.config/.wrangler/config/default.toml` (newer wrangler encrypts it into
`default.enc` with the key in your OS keychain). That OAuth token is
refresh-only and expires, so wrap targets the durable path: a
[Cloudflare API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
created in the dashboard, kept in the vault and injected per invocation.

## Wrap it

Because the login file holds only a short-lived OAuth token, put a real
API token in the vault first, then wrap:

```sh
jit vault set wrap-wrangler/CLOUDFLARE_API_TOKEN   # prompts for the token
jit wrap wrangler
```

This installs the `~/.jit/shims/wrangler` shim and the `wrap-wrangler`
profile.

## Verify

```sh
wrangler whoami
```

It authenticates without `CLOUDFLARE_API_TOKEN` appearing in your shell
environment or any file.

## How it works

The shim injects `CLOUDFLARE_API_TOKEN` from the vault into each
`wrangler` process. It's wrangler's highest-priority credential, so the
injection wins over any lingering `wrangler login` session. If you had an
`export CLOUDFLARE_API_TOKEN=...` line, remove it (or let
[`jit migrate home`](../migrate/shell-configs.md) convert it) - a shell
export overrides the shim. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo wrangler
```

## Notes

- The same token works for any Cloudflare SDK script you run through
  [`jit run`](../run/index.md): point a profile at
  `wrap-wrangler/CLOUDFLARE_API_TOKEN` and the token never touches your
  shell.
- `CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL` (the older auth pair) aren't
  wrapped - create a scoped API token instead, which is what Cloudflare
  recommends.
