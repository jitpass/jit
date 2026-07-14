# Supported CLI plugins — `jit wrap`

Every tool `jit wrap <tool>` knows out of the box. One command per tool:
the token moves into the encrypted vault, a PATH shim keeps the command
working exactly as you type it today, and the plaintext line is scrubbed
from the config file (backed up encrypted first — `jit migrate undo`
restores it byte-for-byte). Unlike alias-based shell plugins, PATH shims
also cover scripts, Makefiles, git hooks, and tools spawning tools.

Any tool that reads its credential from an environment variable works even
without a catalog entry: `jit wrap add <tool> --env VAR=<vault-path>`.

## Shim-based plugins

| Tool | Injected variable | Where the plaintext lives today |
|---|---|---|
| `gh` | `GH_TOKEN` | `~/.config/gh/hosts.yml` (or the keyring — exported via `gh auth token`) |
| `glab` | `GITLAB_TOKEN` | `~/.config/glab-cli/config.yml` |
| `stripe` | `STRIPE_API_KEY` | `~/.config/stripe/config.toml` |
| `ngrok` | `NGROK_AUTHTOKEN` | `ngrok.yml` (v3 `agent:` block or v2 top-level) |
| `doctl` | `DIGITALOCEAN_ACCESS_TOKEN` | `doctl/config.yaml` |
| `hcloud` | `HCLOUD_TOKEN` | `~/.config/hcloud/cli.toml` |
| `flyctl` | `FLY_API_TOKEN` | `~/.fly/config.yml` |
| `vercel` | `VERCEL_TOKEN` | `~/Library/Application Support/com.vercel.cli/auth.json` |
| `railway` | `RAILWAY_TOKEN` | `~/.railway/config.json` |
| `databricks` | `DATABRICKS_TOKEN` | `~/.databrickscfg` |
| `openai` | `OPENAI_API_KEY` | nowhere standard — `jit vault set wrap-openai/OPENAI_API_KEY` first |

## Native-hook plugins (no shim — stronger)

These tools have their own pluggable credential mechanism, which jit
already hooks. `jit wrap <tool>` routes to that migration instead of
installing a shim, because the native hook also covers what a shim can't
see: SDKs inside your language runtime, and login/logout flows.

| Tool | Mechanism | Also covers |
|---|---|---|
| `aws` | `credential_process` in `~/.aws/config` | boto3, aws-sdk-go, Terraform's AWS provider — every SDK that reads the shared config |
| `terraform` | `credentials_helper` in `~/.terraformrc` | `terraform login` / `logout` |

## Adding a tool

A catalog entry is one data block in `internal/wrap/catalog_data.go` plus
one sanitized config sample in `internal/wrap/testdata/<tool>/` — no logic.
The entry states which env var the tool reads, where its plaintext token
lives, and how to verify after wrapping; `jit audit` picks new entries up
automatically, since detection and migration share the same extractors.
PRs welcome — if your CLI reads a token from an env var, it belongs here.
