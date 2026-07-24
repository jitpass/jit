---
title: Wrap CLI tools
description: jit wrap - move a CLI's token into the vault behind a PATH shim, and keep typing the command as before.
---

# Wrap CLI tools - `jit wrap`

Plenty of developer CLIs keep a long-lived token in a plaintext dotfile -
`gh` in `~/.config/gh/hosts.yml`, `stripe` in its `config.toml`, `ngrok`
in `ngrok.yml`. Those files are each tool's own territory, which
[`jit migrate`](../migrate/index.md) doesn't cover - `jit wrap` does:

```sh
jit wrap gh                # discover the token, vault it, scrub the file
gh pr list                 # works exactly as before - token injected per call
jit wrap list              # what's wrapped, shim health, PATH position
jit wrap undo gh           # restore the original file byte-for-byte
```

Under the hood it installs a PATH shim named after the tool (in
`~/.jit/shims/`, like rbenv/mise use). On each invocation the shim injects
the token from the vault into just that one process, gated by the same
[biometric service](../service/index.md) as every other jit flow. Because it's
a shim and not a shell alias, it keeps working inside scripts, Makefiles,
git hooks, and any subprocess that spawns the tool - the paths aliases
miss - at about 25 ms overhead per call with an unlocked service.

[`jit scan`](../audit/index.md) flags the tokens worth wrapping and
prints the one-command fix next to each.

## Shim-based plugins

One page per tool - requirements, verification, and per-tool gotchas:

| Tool | Injected variable | Where the plaintext lives today |
|---|---|---|
| [`gh`](./gh.md) | `GH_TOKEN` | `~/.config/gh/hosts.yml` (or the keyring - exported via `gh auth token`) |
| [`glab`](./glab.md) | `GITLAB_TOKEN` | `~/.config/glab-cli/config.yml` |
| [`stripe`](./stripe.md) | `STRIPE_API_KEY` | `~/.config/stripe/config.toml` |
| [`ngrok`](./ngrok.md) | `NGROK_AUTHTOKEN` | `ngrok.yml` (v3 `agent:` block or v2 top-level) |
| [`doctl`](./doctl.md) | `DIGITALOCEAN_ACCESS_TOKEN` | `doctl/config.yaml` |
| [`hcloud`](./hcloud.md) | `HCLOUD_TOKEN` | `~/.config/hcloud/cli.toml` |
| [`flyctl`](./flyctl.md) | `FLY_API_TOKEN` | `~/.fly/config.yml` |
| [`vercel`](./vercel.md) | `VERCEL_TOKEN` | `~/Library/Application Support/com.vercel.cli/auth.json` |
| [`railway`](./railway.md) | `RAILWAY_TOKEN` | `~/.railway/config.json` |
| [`databricks`](./databricks.md) | `DATABRICKS_TOKEN` | `~/.databrickscfg` |
| [`hf`](./hf.md) | `HF_TOKEN` | `~/.cache/huggingface/token` (the whole file is the token) |
| [`supabase`](./supabase.md) | `SUPABASE_ACCESS_TOKEN` | `~/.supabase/access-token` when the OS keyring isn't available |
| [`wrangler`](./wrangler.md) | `CLOUDFLARE_API_TOKEN` | login stores a short-lived OAuth token; vault a real API token: `jit vault set wrap-wrangler/CLOUDFLARE_API_TOKEN` first |
| [`openai`](./openai.md) | `OPENAI_API_KEY` | nowhere standard - `jit vault set wrap-openai/OPENAI_API_KEY` first |
| [`claude`](./claude-code.md) | `ANTHROPIC_API_KEY` | nowhere standard - `jit vault set wrap-claude/ANTHROPIC_API_KEY` first |
| [`gemini`](./gemini.md) | `GEMINI_API_KEY` | `~/.gemini/.env` (or `~/.env` as a fallback) |
| [`codex`](./codex.md) | `CODEX_API_KEY` | `~/.codex/auth.json`'s `OPENAI_API_KEY` field (API-key logins only) |
| [`sentry-cli`](./sentry-cli.md) | `SENTRY_AUTH_TOKEN` | `~/.sentryclirc` (the `[auth] token`) |
| [`snyk`](./snyk.md) | `SNYK_TOKEN` | `~/.config/configstore/snyk.json` (the `api` field) |
| [`circleci`](./circleci.md) | `CIRCLECI_CLI_TOKEN` | `~/.circleci/cli.yml` |
| [`vault`](./vault.md) | `VAULT_TOKEN` | `~/.vault-token` (the whole file is the token; wrap a long-lived one) |
| [`pulumi`](./pulumi.md) | `PULUMI_ACCESS_TOKEN` | no auto-migrate (URL-keyed file); `jit vault set wrap-pulumi/PULUMI_ACCESS_TOKEN` first |
| [`descope`](./descope.md) | `DESCOPE_MANAGEMENT_KEY` | env-only (docs export it in `~/.zshrc`); `jit vault set wrap-descope/DESCOPE_MANAGEMENT_KEY` first |

## Native-hook plugins (no shim - stronger)

These tools have their own pluggable credential mechanism, which jit
already hooks. `jit wrap <tool>` routes to that migration instead of
installing a shim, because the native hook also covers what a shim can't
see: SDKs inside your language runtime, and login/logout flows.

| Tool | Mechanism | Also covers |
|---|---|---|
| [`aws`](./aws.md) | `credential_process` in `~/.aws/config` | boto3, aws-sdk-go, Terraform's AWS provider - every SDK that reads the shared config |
| [`terraform`](./terraform.md) | `credentials_helper` in `~/.terraformrc` | `terraform login` / `logout` |
| [`docker`](./docker.md) | credential helper in `~/.docker/config.json` | `docker login` / `logout`, compose and buildx pulls |
| [`git`](./git.md) | `credential.helper` in your git config | `git push` / `fetch` over HTTPS, submodules, LFS |

## Not in the catalog?

Any tool that reads its credential from an environment variable works even
without a catalog entry: see **[Custom tools](./custom-tools.md)**
(`jit wrap add <tool> --env VAR=<vault-path>`).

## Tools that read a credential *file* (gcloud, sops)

Some tools don't read an env var - they read a machine-wide credential
*file* (Google SDKs read the gcp ADC JSON; sops reads its age key). For
those, wrap with `--grant` instead of `--env`:

```
jit migrate ~/.config/gcloud/application_default_credentials.json  # into the vault, mount the file
jit wrap add gcloud --grant gcp # shim: `gcloud` now runs jit run --with gcp
gcloud storage ls               # native; the shim grants the real ADC
```

The shim runs `jit run --with <name>`, so each invocation grants the mount
to that one process (scoped, gone when it exits) and prompts a **disclosed
Touch ID** naming the credential - a global credential is never granted
silently. Names: `gcp`, `sops`, `npm`, `netrc`. See
[Delivering a secret](../getting-started/delivering-secrets.md).

## Adding a tool

A catalog entry is one data block in `internal/wrap/catalog_data.go` plus
one sanitized config sample in `internal/wrap/testdata/<tool>/` - no logic.
The entry states which env var the tool reads, where its plaintext token
lives, and how to verify after wrapping; `jit scan` picks new entries up
automatically, since detection and migration share the same extractors.
PRs welcome - if your CLI reads a token from an env var, it belongs here.

## Something off?

`jit wrap list`, `jit wrap doctor`, and `jit wrap undo` are covered in
**[Wrap troubleshooting](./troubleshooting.md)**.
