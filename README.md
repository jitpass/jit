# jitpass - just-in-time passwords

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

| launched by Code | launched by claude |
| :---: | :---: |
| <img width="1917" height="946" alt="image" src="https://github.com/user-attachments/assets/e797790b-aadc-4616-8165-c6ca816ff80a" /> | <img width="1917" height="946" alt="image" src="https://github.com/user-attachments/assets/1487988e-b21a-4fe5-a196-94268dd284b6" /> |

 

**What it does not do:** it does not make an already-compromised account safe,
and it does not protect a secret once it is in the memory of the process that
asked for it. The boundaries are stated on one page, up front:
**[the deliberate limits](./docs/security/brief.md#deliberate-limits-stated-plainly)**.

## How it works, mechanically

No kernel extension, no filesystem driver, no FUSE. Three mechanisms, picked
by what the tool can do:

1. **Environment variables into one process, then `execve`.** jit's own image
   is replaced by your command, so the value lives in that one process and jit
   is gone from memory.
2. **The tool's native credential protocol**, where one exists: AWS
   `credential_process`, docker and git credential helpers, kubectl exec
   plugins, Terraform's credentials helper. The tool asks, jit answers, no
   file involved.
3. **A named-pipe mount**, for tools that can only read a file.

That third one is the one people ask about. The "file" is a POSIX FIFO made
with `mkfifo(2)` at mode `0600`. When a program calls `open(".env")`, the
kernel blocks that open until a writer connects. The background service is the
writer: it opens the path `O_WRONLY`, which releases the reader, writes the
decrypted bytes from memory straight into the kernel pipe buffer, closes, then
loops back to `open(2)` for the next reader. Nothing touches the disk, and
what gets written is decided per read: decoy values for an ambient reader,
real values only for a process inside a run you authorized.

One caveat worth stating plainly, since it is the obvious follow-up question:
**caller identity explains and audits, it never decides.** Process names are
forgeable and a fast-closing FIFO reader can evade identification entirely.
The human answering the prompt is the gate; the process name only tells you
what to answer. Full detail in
**[how it works](./docs/getting-started/how-it-works.md)** and
**[live mounts](./docs/run/mounts.md)**.

## Install

```sh
brew install jitpass/tap/jitpass
```

That is the recommended route, and for a security tool the reason matters.
Releases are signed with an Apple Developer ID and notarized by Apple.
Homebrew quarantines what it downloads, so Gatekeeper checks the binary
against its notarization ticket before it is ever allowed to run. To verify
that yourself rather than take our word for it, run `jit doctor`: its `jit`
line reports `signed CZC6BH93GJ`, the same check `jit upgrade` runs before it
will install anything.

<details>
<summary>Without Homebrew (the weaker path, and why)</summary>

```sh
curl -sL https://dl.jitpass.com/jitpass/jit/releases/latest/download/jitpass_darwin_arm64.tar.gz | tar -xz jit
shasum -a 256 jit   # compare against checksums.txt on the release page
codesign -dv --verify --verbose=2 ./jit   # expect: Developer ID, TeamIdentifier=CZC6BH93GJ
sudo mv jit /usr/local/bin/
```

This is here for people without Homebrew, and it is genuinely the weaker
path: `curl` sets no quarantine bit, so Gatekeeper never consults the
notarization ticket, and the same is true of `go install`. The binary is
still signed and still notarized, so the two lines above let you check both
before you run it, but you have to actually run them. If you have Homebrew,
use Homebrew.

</details>

Apple Silicon only. On an Intel Mac, build from source with
`go install github.com/jitpass/jit/cmd/jit@latest`.

Pick one route. If you installed from the tarball before and are switching to
Homebrew, remove the old copy after the `brew install` (`sudo rm
/usr/local/bin/jit`); otherwise two jits sit on PATH upgrading separately, and
`jit doctor` will flag it.

**Upgrading:** `brew upgrade jitpass`, or `jit upgrade`: a verified
self-update (Developer-ID signature and checksum both checked before the
swap, restarts the service). Either way your vault is untouched.

Homebrew installs shell completion with the binary, so `jit <TAB>` completes
subcommands, flags, vault paths, and wrappable tool names out of the box.
Installed from the tarball or from source, add it yourself:

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc && exec zsh
```

Either way, `jit doctor` tells you if completion isn't reaching your shell.

## How you actually use it

```sh
jit scan                            # read-only. changes no file it scans, prints no real value.
jit vault init                      # make the vault (master key in your login keychain)
jit migrate --dry-run               # preview the whole machine-wide fix plan
jit migrate                         # apply it: shows plan, asks [y/N], one Touch ID
jit migrate ~/code/myapp            # or fix just one project
jit run -- npm run dev              # run your tool; real values injected into that process only
```

`jit scan` with no path sweeps your whole home directory, so give it a moment on
a large one. To go straight at one place, point it at a path: `jit scan ~/.aws`.

Day to day it's mostly `jit run -- <cmd>`. For CLIs that carry their own login
token (`gh`, `glab`, `stripe`, and more) you `jit wrap gh` once and then keep
typing `gh` as normal forever.

Not sure whether something needs `jit wrap`, `jit migrate`, or nothing? You
don't have to know. `jit scan` splits everything it finds into what jit will
protect (one command - the wraps included) and what only you can fix, and
bare `jit migrate` runs that whole plan:

```console
$ jit scan
  YOUR SECRETS: 7 — 0 protected by jit (0%)
  ▱▱▱▱▱▱▱▱▱▱  to 100%: one command +71% · 2 secrets only you can fix +29%

  jit will protect these — 5 secrets in 4 files, 0% → 71%
      → jit migrate
        ~/.zshrc            STRIPE_API_KEY, DB_PASSWORD
        ~/.config/gh/hosts.yml  GitHub CLI token · wraps gh
        ...

  only you can protect these — 2 secrets, 71% → 100%

    [rotate, then delete every copy]
    ! A production database password in 2 files
      → rotate it now, then delete every copy
```

(`jit scan --full` still gives the classic per-category inventory with
severities, including the **Wrappable CLI Tokens** section.)

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

# Tokens you once typed at the prompt, now sitting in your shell history
jit migrate ~/.zsh_history           # each one moves to the vault; your commands stay, the secrets don't
jit guard history                    # and stop the next one being recorded at all (zsh)
                                     # (bare `jit migrate` offers this too, in the plan it asks you to confirm)

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
   re-locks; and never longer than 8 hours, however busy you are). You unlock
   once, not once per command.
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

## Leaving the keyboard? `jit grant`

Both gates assume a human is there to answer. An AI agent working overnight, a
long build, a scheduled job: the screen locks, the session drops, and the run
stalls on a prompt nobody will see. A **process grant** moves your decision
earlier instead of removing it - one Touch ID, given while you're still there,
that names exactly what you're signing:

```console
$ jit grant --process claude --profile jamf --for 8h
  Touch ID  ->  let claude under iTerm2 use 2 secrets (jamf) unattended for 8h
✓ granted g-7f3a2c81   claude -> jamf   until 17:42
  └ covers claude under iTerm2: 1 running now, any started before 17:42
```

For the next 8 hours, every `claude` under **the terminal you typed that in**
(and what it launches) gets those secrets with no prompts - through screen lock
and all, including sessions you start later: a new tab, the next `claude`, a
script that fires at 3am. It's your terminal being named, not a name being
trusted: a program calling itself `claude` somewhere else on the machine
doesn't descend from that tree and inherits nothing. The grant ends at its
deadline, when you quit that terminal, or the moment you type `jit grant
revoke` (which needs no fingerprint - taking access away is always free). Want
one exact process instead, gone when it exits? `--pid`. Every serve lands in
the audit trail as its own event, so the morning after you can read exactly
what your agent touched while you slept. Full details:
[process grants](./docs/service/grants.md).

## AI agents and MCP servers

The agent in your editor runs as you, with your permissions, and reads files
for you all day. That is the whole point of it, and it is also why a plaintext
`.env` in your repo is now a very different risk than it was two years ago.
jit treats agents as first-class, on four fronts:

```sh
jit migrate ~/.claude.json           # MCP server configs: keys move to the vault,
                                     # each server now launches through `jit run`
jit wrap claude                      # the AI CLIs themselves: claude, codex, gemini,
                                     # cursor-agent, copilot, cline, opencode, kiro-cli
jit grant --process claude --profile myapp --for 8h
                                     # let it work overnight without a prompt nobody answers
jit audit --parent claude            # read back exactly what it touched while you slept
```

- **The prompt names the agent.** With per-process consent on (the default),
  the first time a tool reaches for a real credential you get a Touch ID that
  says which program is asking. That is what the two screenshots at the top of
  this page show: the same secret requested by VS Code and by `claude`, each
  named. An agent quietly reading `~/.aws/credentials` is a prompt, not a
  silent success.
- **MCP servers launch through `jit run`.** A migrated MCP config holds vault
  paths, not keys, so the config file itself is safe to have on disk and safe
  to hand to the agent that reads it.
- **A decoy is what an unauthorized read gets.** An agent that greps your repo
  for `.env` and reads it cold gets placeholder values, and the read is logged.
- **`jit audit --parent claude`** shows every secret an agent used, every
  prompt it triggered, and every one you declined.

More in [MCP / AI tools](./docs/migrate/mcp.md) and
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
files, credentials recorded in your shell history, wrappable CLIs (`gh`,
`stripe`, `vercel`, …), and SSO CLIs that mint credentials at login
(`clisso`). In every case the file keeps working and the real value comes
from the vault on demand.

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
- **[Process grants](./docs/service/grants.md)**: pre-approve a running tool to work unattended for a bounded, revocable, audited window
- **[Audit trail](./docs/reference/commands/jit_audit.md)**: read back every command, unlock, and refusal, filterable and followable
- **[Command reference](./docs/reference/commands/jit.md)**: every command and flag, generated from the CLI
- **[Security architecture](./docs/security/architecture.md)**: the threat model and the honest limits
- **[CONTRIBUTING.md](./CONTRIBUTING.md)**: build/test setup; sign-off via DCO (`git commit -s`), no CLA

## License

[PolyForm Perimeter License 1.0.0](./LICENSE) - free for personal and internal
company use only.
