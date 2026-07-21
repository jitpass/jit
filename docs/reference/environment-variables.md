---
title: Environment variables
description: Variables jit injects into wrapped and run processes, and the ones it uses itself.
---

# Environment variables

## Injected into processes

`jit run` injects whatever the resolved [profile](../run/profiles.md)
maps - your `.env` variables under their own names. Wrapped tools get
their token in the variable the tool documents:

| Wrapped tool | Injected variable |
|---|---|
| `gh` | `GH_TOKEN` |
| `glab` | `GITLAB_TOKEN` |
| `stripe` | `STRIPE_API_KEY` |
| `ngrok` | `NGROK_AUTHTOKEN` |
| `doctl` | `DIGITALOCEAN_ACCESS_TOKEN` |
| `hcloud` | `HCLOUD_TOKEN` |
| `flyctl` | `FLY_API_TOKEN` |
| `vercel` | `VERCEL_TOKEN` |
| `railway` | `RAILWAY_TOKEN` |
| `databricks` | `DATABRICKS_TOKEN` |
| `wrangler` | `CLOUDFLARE_API_TOKEN` |
| `openai` | `OPENAI_API_KEY` |

(`aws`, `terraform`, `docker`, and `git` don't inject variables - they use
[native credential hooks](../wrap/index.md#native-hook-plugins-no-shim--stronger).)

An injected variable exists only inside that one process, for its
lifetime - it is never exported to your shell or written anywhere.

## Used by jit itself

| Variable | Role |
|---|---|
| `JIT_SHIM_GUARD_<TOOL>` | set by a running [shim](../wrap/index.md) so a tool that re-invokes itself doesn't loop through the shim twice; never set it yourself |
| `PATH` | `~/.jit/shims` must precede the real tools' directories for wrapping to take effect - `jit wrap doctor` verifies this |
| `SHELL` | used when wiring shell-specific integration |
