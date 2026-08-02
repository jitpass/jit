---
title: Supported tools
description: What to type to run each tool after jit migrate - nothing, jit wrap, jit run, --live, --with, or --profile - and why.
---

# Supported tools

After `jit migrate`, most tools keep working exactly as before. A few need a
short prefix. Here's what to type for your tool, and why.

## At a glance

| Your tool | Run it with | Why |
|---|---|---|
| AWS, Terraform, git, Docker, kubectl, shell exports, MCP servers | **nothing** | After migrate they fetch from the vault themselves. |
| `gh`, `glab`, `stripe`, and other CLIs with their own login token | **`jit wrap <tool>`** once, then the tool by name | Moves the token to the vault; you keep typing the command. |
| A project `.env`, Terraform `tfvars` | **`jit run -- <cmd>`** | The tool reads secrets from environment variables. |
| `docker compose`, `podman`, tools that read the `.env` file itself | **`jit run --live -- <cmd>`** | jit serves the real file to that run (auto-picked for these). |
| `gcp`, `sops`, `npm`, `netrc`, `pypi` | **run it** and approve the prompt, or **`jit run --with <name> -- <cmd>`** | A machine-global credential file: consent prompts on first read, or `--with` grants it explicitly. |
| A specific named set of secrets (an MCP server, a one-off) | **`jit run --profile <name> -- <cmd>`** | Loads that profile instead of the ambient project `.env`. |

## Just run them (nothing to type)

`jit migrate` wires these into the vault so the tool fetches its secret on its
own. You run them exactly as before:

- **AWS**: the CLI and every SDK (boto3, aws-sdk-go, Terraform's AWS provider).
  [aws](./migrate/aws.md)
- **Terraform**: `terraform login` / `logout` and provider auth.
  [terraform](./migrate/terraform.md)
- **git**: `git push` / `fetch` over HTTPS, submodules, LFS. [git](./migrate/git.md)
- **Docker**: `docker login` / `logout`, and compose/buildx registry pulls.
  [docker](./migrate/docker.md)
- **kubectl**: and any kubeconfig-based client. [kubernetes](./migrate/kubernetes.md);
  Secret manifests on disk are their own surface, see
  [Kubernetes Secret manifests](./migrate/kubernetes-secret-manifests.md)
- **Shell exports**: your `~/.zshrc` vars, in every new shell. [shell configs](./migrate/shell-configs.md)
- **MCP servers**: the server launches through jit automatically. [MCP / AI tools](./migrate/mcp.md)

Nothing about the command you type changes. The credential-backed ones (AWS,
Terraform, git, Docker, kubectl) do prompt Touch ID the first time each reaches
for its credential in a session, naming what's asking, and remember your answer
until the vault locks - that's [per-process consent](./service/consent.md), on
by default. Shell exports and MCP servers aren't gated by it.

## `jit wrap <tool>`: CLIs that carry their own token

These CLIs keep a long-lived token in their own config file. `jit wrap <tool>`
moves it to the vault once; after that you keep typing the command by name and
the token is injected per call.

`gh`, `glab`, `stripe`, `ngrok`, `doctl`, `hcloud`, `flyctl`, `vercel`,
`railway`, `databricks`, `hf`, `supabase`, `wrangler`, `openai`, `claude`,
`gemini`, `codex`, `sentry-cli`, `snyk`, `circleci`, `vault`, `pulumi`,
`descope`, `okta-cli-client`, `snow`, `jira`.

One tool works the other way around: `clisso` doesn't carry a token, it
*mints* AWS credentials at every SSO login. `jit wrap clisso` captures
each mint into the vault instead of letting it land in
`~/.aws/credentials` — MFA prompts unchanged. See [clisso](./wrap/clisso.md).

Any other tool that reads its token from an environment variable can be added
with `jit wrap add <tool> --env VAR=<vault-path>`. See
[custom tools](./wrap/custom-tools.md). The [wrap catalog](./wrap/index.md) has a
page per tool with the exact variable and where its plaintext lives today.

## `jit run -- <cmd>`: tools that read env vars

The common case. The tool reads its secrets from **environment variables**
(`process.env`, dotenv loaders, shell scripts), so `jit run` injects them into
just that one process. The file on disk stays an inert decoy.

```sh
jit run -- npm run dev
```

Covers a project [`.env`](./migrate/env-files.md) and Terraform
[`tfvars`](./migrate/tfvars.md) (stored as `TF_VAR_<name>`).

## `jit run --live -- <cmd>`: tools that read the file itself

Some tools read the `.env` **file** directly instead of the environment, so an
inert decoy would feed them nothing. `--live` serves the real file to that run's
processes only. jit picks it automatically for `docker`, `docker-compose`, and
`podman`; for anything else, pin `read_as_file: true` in `.jit/config.yaml`.

```sh
jit run -- docker compose up     # jit adds --live for you
```

See [live-mounted files](./run/mounts.md).

## `jit run --with <name> -- <cmd>`: machine-global credential files

Some credentials aren't tied to a project: one file per machine that any project
could read. Nothing gets one silently, and there are two ways to use them:

- **Everyday (per-process consent on, the default):** just run the tool. The
  first time it reads the file, jit prompts a Touch ID that names the reader and
  serves the real value on approval. The identity on these prompts is
  best-effort (a process scan), so treat the name as a hint.
- **Explicit:** `jit run --with <name>` names the credential up front behind a
  kernel-vouched intent gate. Use it for scripts and CI (no prompt to answer), or
  when you want the hard guarantee that a project can never even prompt for the
  credential.

| Name | The file | Read by |
|---|---|---|
| `gcp` | `~/.config/gcloud/application_default_credentials.json` | Google SDKs, `gcloud`, Terraform |
| `sops` | your age key (`keys.txt`) | sops, kluctl, Flux, helm-secrets |
| `npm` | global `~/.npmrc` | npm, yarn |
| `netrc` | `~/.netrc` | curl, git, ftp, wget |
| `pypi` | `~/.pypirc` | twine, `uv publish`, poetry |

```sh
terraform apply                  # everyday: just run it, approve the prompt
jit run --with gcp -- terraform apply   # explicit grant: scripts/CI, or a hard gate
```

**Don't want to type `--with` every time?** Wrap the tool once so a shim adds it
for you, then keep typing the tool by name:

```sh
jit wrap add gcloud --grant gcp   # once
gcloud storage ls                 # the shim runs `jit run --with gcp` per call
```

Note what you **can't** do: a project's `.jit/config.yaml` can auto-select
`--live` for its own `.env` (`read_as_file: true`), but it can **never**
auto-grant a `--with` credential. A repo file travels with the repo, so letting
one reach your machine-global creds would let any cloned project pull them
silently. The credential only ever flows on a user action on your machine
(approving the consent prompt, a typed `--with`, or the `--grant` shim you
installed), never from a repo file alone.

How each is delivered under the hood (sops uses a native hook; gcp and netrc are
masked files) is in
[Delivering a secret](./getting-started/delivering-secrets.md).

## `jit run --profile <name> -- <cmd>`: a specific named set

When a command needs a **named set** of secrets rather than the current
project's `.env` (an MCP server, a scheduled task, a script that isn't tied to
a repo), load that profile for the run:

```sh
jit run --profile mcp-jamf -- uv --directory ~/servers/jamf run server.py
```

## Anything else

A bare token in a plain file (a JWT in `token.txt`) is handled by
`jit migrate <path>`: the value moves to the vault and the file becomes a
git-safe pointer, or with `--mount` it stays live at its path. See the
[migrate guide](./migrate/index.md).

The source-of-truth lists are the generated
[command reference](./reference/commands/jit.md), the
[wrap catalog](./wrap/index.md), and the [migrate categories](./migrate/index.md).
