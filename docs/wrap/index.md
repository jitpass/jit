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
jit wrap undo gh           # take the shim back off PATH
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

Unwrapping is two steps, because two things changed. `jit wrap undo <tool>`
removes the shim and the `wrap-<tool>` profile; the tool's config file was
scrubbed by `jit wrap`, so putting the token back in it is
[`jit migrate undo`](../migrate/undo-and-remove.md) on that file. Run only
the first and the tool stays logged out. A store wrap (gcloud, az) is the
exception: `jit wrap undo` writes the sealed login back itself. See
[troubleshooting](./troubleshooting.md#unwrap-jit-wrap-undo-tool).

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
| [`railway`](./railway.md) | `RAILWAY_API_TOKEN` | `~/.railway/config.json` (older logins; OAuth logins: `jit vault set` an account token first) |
| [`databricks`](./databricks.md) | `DATABRICKS_TOKEN` | `~/.databrickscfg` |
| [`hf`](./hf.md) | `HF_TOKEN` | `~/.cache/huggingface/token` (the whole file is the token) |
| [`supabase`](./supabase.md) | `SUPABASE_ACCESS_TOKEN` | `~/.supabase/access-token` when the OS keyring isn't available |
| [`wrangler`](./wrangler.md) | `CLOUDFLARE_API_TOKEN` | login stores a short-lived OAuth token; vault a real API token: `jit vault set wrap-wrangler/CLOUDFLARE_API_TOKEN` first |
| [`openai`](./openai.md) | `OPENAI_API_KEY` | nowhere standard - `jit vault set wrap-openai/OPENAI_API_KEY` first |
| [`claude`](./claude-code.md) | `ANTHROPIC_API_KEY` | nowhere standard - `jit vault set wrap-claude/ANTHROPIC_API_KEY` first |
| [`gemini`](./gemini.md) | `GEMINI_API_KEY` | `~/.gemini/.env` (or `~/.env` as a fallback) |
| [`codex`](./codex.md) | `CODEX_API_KEY` | `~/.codex/auth.json`'s `OPENAI_API_KEY` field (API-key logins only) |
| [`cursor-agent`](./cursor-agent.md) | `CURSOR_API_KEY` | nowhere standard - `jit vault set wrap-cursor-agent/CURSOR_API_KEY` first |
| [`copilot`](./copilot.md) | `COPILOT_GITHUB_TOKEN` | nowhere standard (login stores OAuth, not the PAT) - `jit vault set wrap-copilot/COPILOT_GITHUB_TOKEN` first |
| [`cline`](./cline.md) | `ANTHROPIC_API_KEY` | `~/.cline/settings/providers.json` (the Anthropic provider's `apiKey`) |
| [`opencode`](./opencode.md) | `ANTHROPIC_API_KEY` | `~/.local/share/opencode/auth.json` (the `anthropic` entry's `key`; OAuth logins untouched) |
| [`kiro-cli`](./kiro-cli.md) | `KIRO_API_KEY` | nowhere standard (login is subscription OAuth) - `jit vault set wrap-kiro-cli/KIRO_API_KEY` first |
| [`sentry-cli`](./sentry-cli.md) | `SENTRY_AUTH_TOKEN` | `~/.sentryclirc` (the `[auth] token`) |
| [`snyk`](./snyk.md) | `SNYK_TOKEN` | `~/.config/configstore/snyk.json` (the `api` field) |
| [`circleci`](./circleci.md) | `CIRCLE_TOKEN` + `CIRCLECI_CLI_TOKEN` | `~/.config/circleci/config.yml` or `~/.circleci/cli.yml` (keyring: `jit vault set` first) |
| [`vault`](./vault.md) | `VAULT_TOKEN` | `~/.vault-token` (the whole file is the token; wrap a long-lived one) |
| [`pulumi`](./pulumi.md) | `PULUMI_ACCESS_TOKEN` | no auto-migrate (URL-keyed file); `jit vault set wrap-pulumi/PULUMI_ACCESS_TOKEN` first |
| [`descope`](./descope.md) | `DESCOPE_MANAGEMENT_KEY` | env-only (docs export it in `~/.zshrc`); `jit vault set wrap-descope/DESCOPE_MANAGEMENT_KEY` first |
| [`okta-cli-client`](./okta-cli-client.md) | `OKTA_CLIENT_TOKEN` | `~/.okta/okta.yaml` (`okta.client.token`) when present, else `jit vault set` first |
| [`snow`](./snow.md) | `SNOWFLAKE_PASSWORD` | `~/.snowflake/config.toml` (first `[connections.<name>]` block's `password`) |
| [`jira`](./jira.md) | `JIRA_API_TOKEN` | env-only (docs export it in `~/.zshrc`); `jit vault set wrap-jira/JIRA_API_TOKEN` first |

### Logging in, out, and switching accounts

Most tools give a token in the environment priority over their own saved
login. So once a tool is wrapped, its account commands stop doing what
they say. A login refuses or changes nothing. A logout can revoke the
wrapped token (`vercel logout` does). A context or profile switch is
ignored. jit answers these commands itself:

| You run | jit does |
|---|---|
| A login (`flyctl auth login`, `glab auth login`, `supabase login`, …) | Runs it with no token injected, then moves the new token into the vault and deletes the plaintext copy. |
| A login whose token can expire (`vercel login`, `railway login`, `wrangler login`, `vault login`, `hf auth login`) | Runs it with no token injected and leaves the result where the tool saved it, so the wrap keeps its durable token. It says how to store a durable one. |
| A logout (`vercel logout`, `glab auth logout`, …) | Runs it with no token injected, so the wrapped token is never revoked. Then says the vault copy is still in use: `jit vault rm` deletes it. |
| An account switch (`vercel switch`, `hcloud context use`, `databricks auth switch`, `wrangler auth activate`, …) | Doesn't run it. One token is wrapped, so there is nothing to switch to. It tells you how to swap the token. |
| A flag naming another profile (`stripe -p other`, `databricks -p prod`, `snow -c prod`, `hcloud --context work`, `wrangler --profile work`) | Runs with that profile's own saved login, and says so, rather than sending the wrapped token to another account. Naming the wrapped profile itself keeps the wrap. |

`gh` keeps one vault secret per account, so `gh auth switch` works:
see [gh](./gh.md#more-than-one-account).

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

## Capture plugins: tools that MINT credentials

An SSO CLI doesn't carry a token worth moving - it logs into an identity
provider and mints a fresh secret on every run, which it would then write
to a plaintext file. For these the shim captures the tool's own
machine-readable output, in your terminal (so MFA prompts work exactly as
before), and stores it in the vault instead:

| Tool | Captured from | Served back via |
|---|---|---|
| [`clisso`](./clisso.md) | `clisso get`'s own `--output credential_process` JSON | `credential_process` in `~/.aws/config` - never `~/.aws/credentials` |

## Run-grant plugins: tools that read a jit-mounted project file

A tool that reads a project file jit serves as a decoy mount (a
[migrated Kubernetes Secret manifest](../migrate/kubernetes-secret-manifests.md))
needs to run inside a `jit run` grant to see the real content. The shim
makes that automatic - no token is moved and nothing is injected; the
wrap only removes the need to type `jit run --` first:

| Tool | Grants | Outside the grant |
|---|---|---|
| [`kubectl`](./kubectl.md) | the project's mounted Secret manifests at the tool's cwd | decoy `data:` values, never valid base64 - `kubectl apply` fails loudly |

The same wrap also vaults the tool's own long-lived secret (clisso's
OneLogin `client-secret`), leaving a `jit://vault/` pointer in
`~/.clisso.yaml` and serving the real config per run over a pipe.

## Store plugins: tools that keep their own login

Some CLIs keep their login in a store they write themselves, in a shape no
mount can serve: the Google Cloud CLI's `credentials.db` is a SQLite file
holding a refresh token that does not expire on its own, and the Azure
CLI rewrites its token cache on every refresh. The wrap seals that store
in the vault. Each run unpacks it into a private folder for that one
command and seals it again if the command changed it (a login, a refresh,
a revoke). One wrap covers every tool that reads the store:

| Tool | Reads | Why it has its own shim |
|---|---|---|
| [`gcloud`](./gcloud.md) | the login store in `~/.config/gcloud` | the CLI itself; also covers the GKE auth plugin, which runs `gcloud` |
| [`bq`](./bq.md) | the same store | its own entry point |
| [`gsutil`](./gsutil.md) | the same store's `legacy_credentials/` | its own entry point |
| [`docker-credential-gcloud`](./docker-credential-gcloud.md) | the same store, in-process | docker runs it by name |
| [`git-credential-gcloud`](./git-credential-gcloud.md) | the same store, in-process | git runs it by name |
| [`az`](./az.md) | the Azure CLI's login in `~/.azure` | the CLI itself; the Azure SDKs, Terraform and kubelogin borrow the login by running `az` |

```
jit wrap gcloud      # shims all five that are installed, seals the store
gcloud auth list     # as before; the login is unsealed for this one run
jit wrap az          # the same for the Azure CLI
```

## Not in the catalog?

Any tool that reads its credential from an environment variable works even
without a catalog entry: see **[Custom tools](./custom-tools.md)**
(`jit wrap add <tool> --env VAR=<vault-path>`).

## Grant plugins: tools that read a credential *file*

Some tools don't read an env var - they read a machine-wide credential
*file* that a migrate category vaults and serves as a global mount. The
shim runs `jit run --with <mount>`, so each invocation grants the mount to
that one process (scoped, gone when it exits) and prompts a **disclosed
Touch ID** naming the credential - a global credential is never granted
silently. Migrate the file first; the wrap only takes the grant for you:

| Tool | Grants | Migrate first |
|---|---|---|
| [`sops`](./sops.md) | the `sops` mount: the age private key | [`jit migrate ~/.config/sops/age/keys.txt`](../migrate/sops.md) |

```
jit migrate ~/.config/sops/age/keys.txt  # into the vault, mount the file
jit wrap sops                            # shim: `sops` now runs jit run --with sops
sops --decrypt secrets.enc.yaml          # native; the shim grants the real key
```

Application-default credentials (the `gcp` mount) are still granted this
way to `gcloud auth application-default` commands, through the gcloud
store wrap above.

Any other tool that reads one of these files wraps the same way by hand:
`jit wrap add <tool> --grant <name>`, with names `gcp`, `sops`, `npm`,
`netrc`, `pypi`. See
[Delivering a secret](../getting-started/delivering-secrets.md).

## Adding a tool

A catalog entry is one data block in `internal/wrap/catalog_data.go` plus
one sanitized config sample in `internal/wrap/testdata/<tool>/` - no logic.
The entry states which env var the tool reads, where its plaintext token
lives, and how to verify after wrapping; `jit scan` picks new entries up
automatically, since detection and migration share the same extractors.
PRs welcome - if your CLI reads a token from an env var, it belongs here.

## Something off?

`jit wrap list`, `jit doctor --wrap`, and `jit wrap undo` are covered in
**[Wrap troubleshooting](./troubleshooting.md)**.
