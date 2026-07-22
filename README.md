# jitpass: the `jit` CLI

**Just-in-time credentials for your dev machine.**

Your `.env` files, `~/.aws/credentials`, shell exports, `.npmrc` tokens, and MCP
configs are full of secrets sitting in plaintext, readable by anything running
as you: an infostealer from one bad `curl | sh`, a malicious `npm install`, or
one of the AI agents now running in your editor with your full permissions.
`jit` moves each secret into a local vault gated by Touch ID and rewrites the
files so everything keeps working. The result is a biometric prompt between your
tools (and your agents) and your credentials, and a decoy on disk the rest of
the time.

**[Documentation](./docs/index.md)** ·
[Quickstart](./docs/getting-started/quickstart.md) ·
[Supported tools](./docs/wrap/index.md) ·
[Command reference](./docs/reference/commands/jit.md) ·
[Security](./docs/security/architecture.md)

> **Status:** early development, macOS-only, Apple Silicon. Builds from source
> today; code signing and a Homebrew tap are what stand between this and
> packaged releases.

## Install

Apple Silicon prebuilt binary, no Go required:

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/
```

That's it. The background agent that lets you unlock once per session (instead of
once per command) sets itself up automatically the first time you run
`jit migrate` or `jit run` — no separate install step.

Use `curl`, not the browser: Gatekeeper blocks quarantined unsigned binaries
(un-quarantine with `xattr -d com.apple.quarantine jit` if needed). Checksums are
on the [release page](https://github.com/jitpass/jit/releases/latest). Upgrading
is just reinstalling the binary; the running agent notices the new build and
restarts itself on it. On an Intel Mac, build from source instead: see the
[install guide](./docs/getting-started/install.md).

### Shell completion

`jit <TAB>` completes subcommands, flags, vault paths, `migrate undo` paths,
profile names, and wrappable tool names:

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc && exec zsh
```

If that prints `command not found`, see the
[install guide](./docs/getting-started/install.md#shell-completion). bash and
fish are covered there too.

## Quick start

```sh
jit scan                     # 1. see the problem (read-only, safe to run anywhere)
jit vault init                # 2. create the vault (master key in your login keychain)
jit agent install             # 3. (optional) start the shared-session agent now; migrate/run auto-start it too
jit migrate --dry-run         # 4. preview the fix (same whole-machine scope as audit)
jit migrate                   # 5. apply it: plan, [y/N], one Touch ID prompt
jit status                    # 6. vault / agent / mounts / backup health, one screen
```

Every mutating command prints its plan and asks first. Every rewritten file is
backed up (encrypted, into the vault) before it's touched, and `jit migrate undo`
restores it byte-for-byte.

> **Try it without touching your real machine.** The
> [jitpass-playground](https://github.com/jitpass/jitpass-playground) is a mock
> app seeded with synthetic secrets and a 10-minute guided tour: audit, migrate,
> watch decoys flip to real values, undo it all.

## After migrate: how does the tool still get its secret?

Migrate does two things to each secret: it moves the value into the vault, and it
leaves a **hook** where the secret was, a pointer that fetches it back from the
vault the instant the tool needs it. The hook differs per tool:

| Secret | The hook migrate leaves | At use |
| --- | --- | --- |
| **`.env`** | jit records the file's secrets against the project | `jit run` reads the **vault** (not the decoy file) and injects the values into your process |
| **`~/.zshrc` exports** | an `eval "$(jit export ...)"` line | each new shell runs it, so the vars are just there, nothing to type |
| **`aws` / Terraform** | `credential_process = jit ...` in `~/.aws/config` | AWS calls jit on demand, so `aws s3 ls` and `terraform apply` need no prefix |
| **wrapped CLI (`gh`)** | a `PATH` shim named `gh` | the shim runs the real tool through `jit run`, injecting its token |

The pattern: the secret lives in the vault; the hook reconnects it at use time,
either because you launched through `jit run` or because the tool or shell runs
the hook itself. Plaintext never sits on disk between uses.

**Multiple `.env` files** are merged for you: jit walks upward from your directory
(like git finds a repo root) and layers them (`.env` < `.env.local`; mode layers
like `.env.production` only with `--mode`). `jit run` prints what it merged.

## Which command do I use?

`jit migrate` sets everything up; day to day you run your tools through one of
these. Most of the time it's `jit run` (or nothing, once a tool is wrapped).

| Situation | What to run | Why |
| --- | --- | --- |
| Tool reads env vars (`process.env`, dotenv, shell scripts), the 99% case | `jit run -- <cmd>` | Default swap: inert file on disk, real values injected into the environment. |
| You want a named set of secrets, not the project's `.env` (e.g. an MCP server) | `jit run --profile <name> -- <cmd>` | Loads that profile's secrets for the run instead of the ambient project file. |
| The command needs a machine-global credential (gcloud, SOPS) not tied to the project | `jit run --with gcp -- <cmd>` | Grants a named global credential to just this run; project config never authorizes global creds, so you opt in explicitly. |
| Tool is a CLI carrying its own token (`gh`, `glab`, `stripe`, …) | `jit wrap gh` once, then `gh` as normal | Installs a shim so the token is injected per call. You keep typing the command, no `jit run` prefix, and it works in scripts too. |
| Tool is `docker` / `docker-compose` / `podman` | `jit run -- <cmd>` | Auto-detected as a file-reader; jit picks `--live` for you, no flag needed. |
| Tool reads the file itself and isn't auto-detected (rare) | `jit run --live -- <cmd>` | Keeps the file real for the run's tree so the parse sees real values. |
| A project always reads the file | pin `read_as_file: true` in `.jit/config.yaml` | jit picks `--live` automatically; you never type `--live` there again. |

## Common scenarios

```sh
# A dev server that reads a project .env
jit run -- npm run dev

# AWS CLI or any AWS SDK: after migrate, credentials resolve on demand.
# jit is hooked into the AWS credential mechanism, so there's no prefix to type.
aws s3 ls

# Terraform using those same AWS creds: nothing special, they resolve the same way
terraform apply

# Terraform that ALSO needs a machine-global GCP credential (gcloud ADC)
jit run --with gcp -- terraform apply

# Secrets that used to be `export KEY=...` in ~/.zshrc: migrate added a hook that
# loads them from the vault into each new shell, so scripts that read them just work
./deploy.sh                    # sees the vars, nothing to prefix

# A CLI that carries its own token: wrap it once, then use it as normal forever
jit wrap gh                    # one time
gh pr list                     # from now on, token injected per call

# An MCP server (or any process) that needs a specific named profile
jit run --profile mcp-jamf -- uv --directory ~/servers/jamf run server.py
```

## The command surface

- **`jit scan`**: the read-only scan. Ranks every plaintext secret on the
  machine by exposure; never writes, moves, or prints a real value. Safe to run
  against anything, ~340 ms.
- **`jit migrate`**: the bulk mover. Vaults the secrets in files it understands
  and wires up each one's delivery model (whole-machine default; `local` vs
  `home` scope). Every change is reversible with `jit migrate undo`, byte-for-byte.
- **`jit wrap <tool>`**: the per-CLI bridge. Moves one tool's token into the
  vault and keeps you typing the command as before; ~19 supported tools (`gh`,
  `glab`, `stripe`, `aws`, `terraform`, `docker`, `claude`, `gemini`, and more).
- **`jit run`**: inject secrets into a process, no file on disk. Flags:
  `--profile`, `--with`, `--live`.
- **`jit vault`**: `set` / `get` / `list` / `rm`, `history` / `restore`,
  `rekey`, `backup export` / `import`. These sensitive commands always prompt for
  Touch ID.
- **`jit agent`**: the background helper. It holds the unlock session (so
  everyday commands share one Touch ID) *and* serves your live mounts, flipping a
  decoy file to real values only for a granted `jit run`. `install` / `uninstall`
  / `restart` the launchd helper, `status` to inspect it, `lock` / `unlock` the
  session, and `history` / `log` for the audit trail of who unlocked what.

## What it covers

`jit migrate` moves each secret into the vault and rewires its tool to fetch it
from there, so everything keeps working:

| Where the secret lives | After `jit migrate` |
| --- | --- |
| `.env` files | The file shows decoys; the real values reach only a `jit run` you launch. |
| Shell config exports | A one-line hook in your shell config pulls them from the vault at login. |
| MCP server configs | The server starts through `jit run`, which supplies its secrets. |
| AWS credentials | The AWS CLI and SDKs fetch the key from the vault on demand, no file at all. |
| kubeconfig | kubectl fetches the token from the vault on demand. |
| Terraform Cloud token | The token comes from the vault; `terraform login` / `logout` keep working. |
| Docker registry logins | Login comes from the vault; `docker login`, compose, and buildx keep working. |
| GCP application-default creds | Google SDKs read the usual path; it shows real values only when granted. |
| `.npmrc` / `.netrc` tokens | The file shows decoys; non-secret settings stay untouched. |
| CLI tool tokens (`gh`, `glab`, `stripe`, …) | Keep typing the command as before; the token is injected per call. |

## How it works under the hood

**At rest:** each secret is its own encrypted file (envelope encryption: a
per-secret key, all wrapped by one master key). The master key lives in your macOS
login keychain, released only behind Touch ID. A background agent holds the unlock
so commands share one prompt, and re-locks on idle, screen lock, or sleep.

**At use:** `jit run` resolves the secrets a command needs and injects them into
just that process (or the agent serves real values through the decoy file for that
process tree). They vanish when it exits; anything else sees decoys. A `jit wrap`
shim is the same machinery behind the tool's own name.

## Learn more

The docs live under **[docs/](./docs/index.md)**, organized by task:

- **[Quickstart](./docs/getting-started/quickstart.md)**: setup, migrating, living with the fix, step by step
- **[How it works](./docs/getting-started/how-it-works.md)**: the vault, the agent, mounts, and shims in one page
- **[How it all fits together](./docs/getting-started/how-it-fits.md)**: the mental model behind the three delivery models
- **[FAQ](./docs/faq.md)**: developer and security questions, answered bluntly
- **[Command reference](./docs/reference/commands/jit.md)**: every command and flag, generated from the CLI
- **[Security architecture](./docs/security/architecture.md)**: the threat model and the honest limits
- **[CONTRIBUTING.md](./CONTRIBUTING.md)**: build/test setup; sign-off via DCO (`git commit -s`), no CLA

## License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](./LICENSE). In plain terms:

- **Free for almost everyone**: individual developers, non-commercial use, and
  internal use inside any company (including commercial ones), in production.
- **Not allowed**: offering jit as part of a commercial product or service that
  competes with it (credentials injection, secrets management, CLI wrapping).
  That needs a commercial license.
- **It converts to open source**: on the Change Date in [LICENSE](./LICENSE) (or
  four years after a version's first release, whichever comes first), that version
  becomes available under Apache 2.0.

This summary is informational only; the [LICENSE](./LICENSE) text governs.
</content>
