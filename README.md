# jitpass: the `jit` CLI

**Just-in-time credentials for your dev machine.**

**[Documentation](./docs/index.md)** ·
[Quickstart](./docs/getting-started/quickstart.md) ·
[Supported tools](./docs/tools.md) ·
[Command reference](./docs/reference/commands/jit.md) ·
[Security](./docs/security/architecture.md)

> **Status:** macOS-only (Apple Silicon), and still in development.

## What jit is (30 seconds)

Your secrets live in plaintext all over your machine: `.env` files,
`~/.aws/credentials`, `~/.zshrc` exports, `.npmrc` tokens, MCP configs. Anything
running as you can read them. A bad `curl | sh`, a sketchy `npm install`, or one
of the AI agents now running in your editor with your full permissions.

`jit` moves each secret into a local encrypted vault gated by Touch ID, and
rewrites the files so your tools keep working. On disk there's now a decoy. The
real value only appears, in memory, for the specific process that asked for it,
after a biometric prompt. The result: you unlock once, `jit` asks before handing
a credential to a tool (or an agent), and there's a decoy on disk the rest of
the time.

## Install

Apple Silicon prebuilt binary, no Go required:

```sh
curl -sLO https://github.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz
tar -xzf jitpass_darwin_arm64.tar.gz jit
sudo mv jit /usr/local/bin/
```

**Upgrading:**

```sh
jit upgrade   # verified self-update: checksum-checked swap, restarts the service. Your vault is untouched.
```

Recommended: turn on shell completion, so `jit <TAB>` completes subcommands,
flags, vault paths, and wrappable tool names:

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc && exec zsh
```

## How you actually use it

```sh
jit scan                            # read-only. shows every plaintext secret. writes nothing.
jit vault init                      # make the vault (master key in your login keychain)
jit migrate ~/code/myapp --dry-run  # preview the fix
jit migrate ~/code/myapp            # apply: shows plan, asks [y/N], one Touch ID
jit run -- npm run dev              # run your tool; real values injected into that process only
```

`jit scan` with no path sweeps your whole home directory, so give it a moment on
a large one. To go straight at one place, point it at a path: `jit scan ~/.aws`.

Day to day it's mostly `jit run -- <cmd>`. For CLIs that carry their own login
token (`gh`, `glab`, `stripe`, and more) you `jit wrap gh` once and then keep
typing `gh` as normal forever.

Not sure whether something needs `jit wrap`, `jit migrate`, or nothing? You don't
have to know. `jit scan` classifies every finding (it has a **Wrappable CLI
Tokens** section for exactly this) and prints the exact fix command for what it
found. Start with `scan` and follow the hint:

```console
$ jit scan
  ...
  [.env Files]
    • ~/code/myapp/.env
      HIGH  contains "API_KEY", a variable name that looks like a real credential

  [Wrappable CLI Tokens]
    • ~/.config/gh/hosts.yml
      HIGH  GitHub CLI token found: wrap it so it's injected per call

Run `jit migrate ~/code/myapp --dry-run` to see the guided fix plan for it.
```

## Your everyday tools

Migrate the credential once, then keep using the tool the way you always have.

```sh
# AWS (and Terraform, and every AWS SDK)
jit migrate ~/.aws/credentials       # keys move to the vault; no plaintext file left
aws s3 ls                            # resolves from the vault on demand. no prefix, no flag.
terraform apply                      # same creds, same command

# GCP application-default credentials (a machine-wide credential)
jit migrate ~/.config/gcloud/application_default_credentials.json
terraform apply                      # google provider reads ADC; works after a Touch ID prompt

# Docker / docker-compose
jit migrate ~/.docker/config.json    # registry logins move to the vault
jit run -- docker compose up         # jit injects them for this run
docker login ghcr.io                 # still works; the helper stores to the vault

# Shell exports that used to sit in ~/.zshrc
jit migrate ~/.zshrc                 # leaves a one-line hook; new shells just have the vars
./deploy.sh                          # scripts that read those vars work unchanged

# A CLI that carries its own token (gh, stripe, glab)
jit wrap gh                          # one time
gh pr list                           # token injected per call, forever
```

The first time each tool reaches for a real credential, `jit` asks once and
remembers your answer until the vault locks. See [Two Touch ID moments](#two-touch-id-moments-not-one)
for how that sits on top of the vault unlock, what `--trust` does, and how to
turn the per-tool prompts off.

Why do some tools need no setup while others take a `jit run`? One rule: **can
the tool ask jit for the secret itself?** AWS (via `credential_process`), your
shell at login, and docker's registry logins (via a credential helper) all can,
so you type nothing extra. Tools that only read a file at runtime (docker
compose, plain SDKs) can't ask, so `jit run` hands them the value.

The machine-global credential files (GCP ADC, `sops`, `npm`, `netrc`) work the
same everyday way: run your tool and approve the per-process prompt. Add `jit run
--with <name>` only when you want it explicit: for scripts and CI where there's
no prompt to answer, or when you want a hard gate a project's own config can
never reach. **[Supported tools](./docs/tools.md)** lists exactly what to type
for every tool, and how each is delivered.

## Two Touch ID moments, not one

`jit` asks for your fingerprint at two different moments, doing two different jobs:

1. **Unlocking your vault.** The first time you use `jit` after it locks, one
   Touch ID opens the vault for the whole session (5 minutes of activity, then it
   re-locks). You unlock once, not once per command.
2. **Handing a credential to a tool.** On top of that, the first time a given
   tool reaches for a real credential, `jit` asks before handing it over and
   names what's asking. This is what stops a program you didn't run from quietly
   using your keys while the vault is open.

```console
$ aws s3 ls
  Touch ID  ->  unlock your vault              # gate 1: opens the vault for 5 min
  Touch ID  ->  aws wants your aws credential   # gate 2: this tool, this credential
  ...your buckets...

$ aws s3 cp ./file s3://bucket/   # same tool, same session: no prompt

$ terraform apply
  Touch ID  ->  terraform wants your aws credential   # a different tool: it asks on its own
```

Gate 2 is what keeps an unlocked vault from being a free-for-all: even after
you've used `aws` yourself, a sketchy `npm install` reaching for those same keys
still triggers a prompt naming it, so you can say no.

Don't want the second gate? Turn it off; the vault lock stays (turning it off
itself takes a Touch ID, since it reopens the window it closes):

```sh
jit service consent off   # tools resolve silently while the vault is unlocked
jit service consent on    # ask per tool again (the default)
```

Kicking off something that needs several credentials at once? `jit run --trust
-- terraform apply` approves that whole run's tools in one gesture. Full details:
[per-process consent](./docs/service/consent.md).

## The audit trail: what happened, and who did it

Every jit command and every unlock lands in a durable log you read back with
`jit audit`, newest first, one `key=value` line per event, so it greps like a
real service log. Command arguments are masked, so the log proves a command ran
without ever storing the secret it carried.

```console
$ jit audit --since 1h
time=2026-07-24 10:15:04 level=info kind=cmd status=ok dur=312ms cmd="jit migrate ~/.aws/credentials" user=meni parent=claude
time=2026-07-24 10:16:22 level=info kind=use op="read a secret" cmd="aws s3 ls" parent=claude secrets=aws/default
time=2026-07-24 10:31:09 level=warn kind=unlock status=denied method=touchid-or-passcode cmd="node postinstall.js" parent=npm secrets=aws/default
```

The middle line is the story jit exists to tell: `aws/default` was read by `aws
s3 ls`, launched by `claude`. The last is a prompt you declined: a `node
postinstall.js` under `npm` reaching for those same keys, refused. jit also logs
what the service turned away at its socket (a process the kernel says isn't
yours, probing the agent) as `kind=error`.

Narrow it with flags instead of grep: `--kind`, `--status ok|failed|denied`,
`--since`/`--until` (an age like `2h`/`3d` or a date), `--parent claude`,
`--secret aws`, `--user`, `--grep <regexp>`. Add `--follow` (`-f`) to stream new
events live like `tail -f`, or `--format json` for a machine-parseable dump. Both
halves are durable files beside the vault, so it answers for last week as readily
as the last hour.

## What it supports

`.env` files, shell exports, AWS and Terraform, kubeconfig, Docker registry
logins, GCP ADC, `.npmrc` / `.netrc` tokens, MCP server configs, bare token
files, and wrappable CLIs (`gh`, `stripe`, `vercel`, …). In every case the file
keeps working and the real value comes from the vault on demand.

The full catalog, grouped by exactly what to type for each tool, is
**[Supported tools](./docs/tools.md)**: it tracks the code as tools are added or
removed. Anything not listed can still be wrapped with
[`jit wrap add`](./docs/wrap/custom-tools.md).

## Can I undo it? Always.

`jit` never destroys a credential. Migrate **moves** the value into the vault and
leaves a **working hook** where it was (a decoy `.env`, an `eval "$(jit export)"`
line in your shell config, `credential_process = jit …` in `~/.aws/config`, or a
`PATH` shim), so your tools keep resolving it on demand. The credential still
exists, just encrypted instead of sitting in plaintext.

And every change is reversible. Before touching a file, jit backs it up encrypted
into the vault, so `jit migrate undo` puts it back byte-for-byte:

```sh
jit migrate ~/code/myapp        # applied the fix, one Touch ID
# changed your mind, or something broke?
jit migrate undo ~/code/myapp   # every touched file restored, byte-for-byte
```

## Learn more

The docs live under **[docs/](./docs/index.md)**, organized by task:

- **[Quickstart](./docs/getting-started/quickstart.md)**: setup, migrating, living with the fix, step by step
- **[How it works](./docs/getting-started/how-it-works.md)**: the vault, the service, mounts, and shims in one page
- **[FAQ](./docs/faq.md)**: developer and security questions, answered bluntly
- **[Per-process consent](./docs/service/consent.md)**: what the per-tool prompts do, and how to tune or turn them off
- **[Audit trail](./docs/reference/commands/jit_audit.md)**: read back every command, unlock, and refusal, filterable and followable
- **[Command reference](./docs/reference/commands/jit.md)**: every command and flag, generated from the CLI
- **[Security architecture](./docs/security/architecture.md)**: the threat model and the honest limits
- **[CONTRIBUTING.md](./CONTRIBUTING.md)**: build/test setup; sign-off via DCO (`git commit -s`), no CLA

## License

[PolyForm Perimeter License 1.0.0](./LICENSE). In plain terms:

- **Free for almost everyone**: individual developers, non-commercial use, and
  internal use inside any company (including commercial ones), in production.
- **Not allowed**: providing others a product that competes with jit (a
  substitute for its functionality or value), in any form: commercial or free,
  as a service, library, or plugin, on any platform. That needs a commercial
  license.
- **Source-available, not open source**: the code is public and you can read,
  modify, and self-host it under the terms above, but it does not convert to an
  open-source license.

**Commercial licensing**: if you want to do something the license doesn't permit
(for example, ship a competing product), a commercial license is available.
Contact **jitpass@outlook.com**.

**Trademarks**: the "jitpass" name and logo are trademarks and are not granted by
the license. See [TRADEMARKS.md](./TRADEMARKS.md); rename forks and redistributions.

This summary is informational only; the [LICENSE](./LICENSE) text governs.
