# Command reference

Every jit command, flag by flag. For the guided "how do I live with this
day to day" walkthrough, read [USAGE.md](./USAGE.md) first; this file is the
lookup table you come back to. `jit <command> --help` always has the same
information at the terminal.

Commands are grouped the way `jit --help` groups them:

- [Find and fix exposed secrets](#find-and-fix-exposed-secrets): `audit`, `migrate`, `doctor`, `status`
- [Vault and profiles](#vault-and-profiles): `vault`, `profile`, `run`, `export`, `unmount`
- [Background agent](#background-agent): `agent`
- [Invoked by other tools](#invoked-by-other-tools): `aws-credential-process`, `k8s-exec-credential`, `terraform-credentials`
- [Everything else](#everything-else): `completion`, global flags

---

## Find and fix exposed secrets

### `jit audit`

Scans shell configs, `.env` files, credential files, MCP/AI-tool configs,
private keys, IaC variable files, and suspicious filenames for plaintext
secrets. Strictly read-only under every flag: it never touches, encrypts,
or rewrites a single file, and never prints a real secret value in full,
only a masked preview. Always scans your whole home directory, regardless
of where you run it.

| Flag | Meaning |
|---|---|
| `--format <f>` | `text` (default), `markdown`/`md`, or `ndjson` |
| `-o, --output <file>` | write the report to a file instead of stdout |

```sh
jit audit
jit audit --format ndjson | jq .
jit audit --format md -o report.md
```

### `jit migrate`

Moves the plaintext secrets `jit audit` finds into the encrypted vault and
rewrites each file so everything keeps working without the secret sitting
on disk. Deliberately a separate command from `audit`, so the read-only
scanner can never be turned into a mutating one by a mistyped flag.

Every run prints the full plan and asks for confirmation before touching
anything, and every modified file's exact original bytes are backed up,
encrypted, into the vault first. If a migrated file was ever committed to
git, the plan warns per file: migrating never scrubs git history, so the
old value stays recoverable via `git log -p` regardless.

Flags shared by `local` and `home`:

| Flag | Meaning |
|---|---|
| `--dry-run` | preview the plan without changing anything; runs the exact discovery a real run would |
| `--only <cats>` | limit to comma-separated categories: `env,shell,mcp,aws,kube,terraform,npmrc` |
| `-y, --yes` | skip the confirmation prompt |

#### `jit migrate local`

Converts findings under the current directory tree only; nothing outside
the project you're standing in is discovered or touched. Covers project
`.env` files, project `mcp.json`, and project `.npmrc`. Machine-wide files
live at fixed paths under `$HOME`, so only `home` ever includes them.

#### `jit migrate home`

Everything `local` finds, discovered across every project under `$HOME`,
plus the machine-wide files: shell configs, `~/.aws/credentials`,
`~/.kube/config`, the Terraform Cloud token file
(`~/.terraform.d/credentials.tfrc.json`), Claude Desktop's MCP config, and
the global `~/.npmrc`.

Skips anything under a directory named `archive`, `archived`, `backup`,
`backups`, or `.trash` unless you pass `--include-archived`: converting a
forgotten project's `.env` into a live mount nothing will ever read again
makes it unreadable, which is worse than plaintext. `local` never applies
this filter.

| Extra flag | Meaning |
|---|---|
| `--include-archived` | also convert findings under archived/backup-looking directories |

What each category turns into:

| Category | Vault gets | The original file becomes |
|---|---|---|
| `env` | one secret per variable | a live-mounted named pipe, plus a git-safe `<file>.pointers` companion listing each variable's vault path |
| `shell` | one secret per `export KEY=value` line | the export line replaced with `eval "$(jit export --profile ...)"` |
| `mcp` | one secret per server's env-block value | the server's `command` rewritten to launch via `jit run` |
| `aws` | the profile's access key/secret/session token | a `credential_process` line in `~/.aws/config`; no file with the real value at all |
| `kube` | the user's bearer token or cert/key pair | an `exec` block calling jit (client-go's exec-plugin protocol) |
| `terraform` | each host's API token | a `credentials_helper` wired into `~/.terraformrc`; `terraform login`/`logout` keep working. Fails loud, before touching anything, if a different credentials helper is already configured |
| `npmrc` | just the secret lines (`_authToken`, etc.) | a live-mounted pipe serving a template; non-secret settings preserved verbatim |

GCP application-default credentials are detected by `audit` but have no
migrate path yet.

#### `jit migrate undo [path...]`

Restores migrated files, of any category, from their encrypted
pre-migration backups, byte-for-byte. No argument restores every file with
a recorded backup; a file path restores just that file; a directory path
restores every migrated file under that tree, so you can undo one project
without disturbing anything migrated elsewhere.

Per file: a registered live mount stops being served first (other mounts
undisturbed), the registry entry and `.pointers` companion are removed,
then the backed-up content is written back. The current content is
snapshotted into the vault before being overwritten, so an undo is itself
undoable. Reveal hooks migrate wired into `.envrc`/`package.json` are
removed surgically: only jit's own marked command for the mount being
restored, never your edits or another mount's hook.

A file that can't be restored is reported and skipped; the rest still
restore, and the command exits non-zero if any failed. Vault secrets and
profile manifests stay (that's `remove`'s job). Because this writes real
secret values back to disk, it always requires its own fresh Touch
ID/passcode approval, even with the agent unlocked. Takes `--dry-run` and
`--yes` like the other subcommands.

#### `jit migrate remove`

The full exit from the current project: every live mount and pointer file
under the directory tree becomes a plain file again, MCP servers launching
through `jit run` get their plaintext env blocks back (written from the
*current* vault values, so `jit vault set` edits since migration are
kept), and then the project's profiles, the vault secrets they reference,
its encrypted backups, its reveal hooks, and the `.jit/` directory are all
deleted.

Machine-level migrations (shell configs, AWS, kubeconfig, Terraform Cloud,
global npmrc, Claude Desktop) are not touched; reverse those with
`jit migrate undo`. A vault secret also referenced by a profile outside
this project is kept and reported, never deleted out from under the other
profile. Writes plaintext to disk *and* permanently deletes vault secrets,
so it always requires its own fresh Touch ID/passcode approval.

### `jit doctor`

Checks that every secret path a profile references actually exists in the
vault, failing fast with a named missing secret instead of letting an app
crash later on an empty environment variable. Only checks existence, never
decrypts, so it never needs Touch ID and is safe to run constantly.

By default checks every profile visible from the current directory (both
project-local and global); exits non-zero on any problem, in JSON mode
too, so it works as a CI health check.

| Flag | Meaning |
|---|---|
| `--profile <name>` | check only this profile |
| `--format <f>` | `text` (default) or `json` |

### `jit status`

One read-only screen answering: is the vault initialized, is the agent
running and unlocked (and when does it lock), do this project's profiles
resolve, are mounts being served. Never decrypts a value or triggers Touch
ID. Also warns when the running agent was built from an older binary than
the CLI you're typing.

| Flag | Meaning |
|---|---|
| `--format <f>` | `text` (default) or `json` |

---

## Vault and profiles

### `jit vault`

Each secret is its own encrypted file under jit's data directory; no
monolithic database. Access is gated by a Touch ID/passcode prompt.

#### `jit vault init`

Sets up the vault and generates the master encryption key, stored in your
macOS Keychain. Expect one Touch ID/passcode prompt.

#### `jit vault set <path> [value]`

Stores a secret at `<path>` (e.g. `stripe/dev-key`). With `[value]`
omitted, prompts with hidden input; prefer that or `--stdin` over a bare
argument, which lands in shell history.

| Flag | Meaning |
|---|---|
| `--stdin` | read the value from stdin (for scripts) |
| `-f, --force` | overwrite an existing secret without confirmation |

#### `jit vault get <path>`

Decrypts and prints one value to stdout, where it lands in scrollback and
any output capture. Prefer `--copy`.

| Flag | Meaning |
|---|---|
| `-c, --copy` | copy to the clipboard instead of printing |

#### `jit vault list`

Lists every stored secret path, never a value. Migrate's encrypted file
backups are summarized in the count line rather than listed.

| Flag | Meaning |
|---|---|
| `--all` | also list the encrypted file backups (`_backups/...`) |
| `--format <f>` | `text` (default) or `json` |

#### `jit vault rm <path>`

Deletes one secret. Confirms first unless `-f, --force`.

#### `jit vault clean`

Deletes every secret in the vault, including migrate's encrypted file
backups (after this, `jit migrate undo` has nothing to restore from). The
vault itself stays initialized, so `set`/`migrate` keep working
immediately. Refuses while any file is still live-mounted; unmount first.
Confirms unless `-y, --yes`.

#### `jit vault prune`

Deletes stale encrypted file backups, keeping each file's newest — the one
`jit migrate undo` restores from, so undo keeps working. Backups accumulate
on purpose: every `jit migrate` rewrite stores one, and every `jit migrate
undo` snapshots the pre-undo state too (undo is itself undoable), with no
automatic TTL or cap — a recovery snapshot silently aging out would be
worse. Run this whenever the `plus N encrypted file backup(s)` count in
`jit status`/`jit vault list` grows past what you care to keep. Confirms
unless `-y, --yes`.

#### `jit vault delete`

Destroys the entire vault: every secret, the backups and their undo index,
the device identity, and the encryption key in the macOS Keychain. Nothing
on this machine can decrypt anything afterward; only a
passphrase-encrypted `jit vault export` file survives. Refuses while any
file is still live-mounted. Confirms unless `-y, --yes`.

#### `jit vault export <file>`

Re-encrypts the whole vault under a passphrase you supply (Argon2id), which
is what makes the file restorable on a different machine; the vault's own
encryption is bound to this device and useless elsewhere. jit never stores
the passphrase and never uploads the file. `--stdin` reads the passphrase
from stdin (one line, no double-entry) for scripting. Always requires its
own fresh Touch ID/passcode approval.

#### `jit vault import <file>`

Restores secrets from an export file, overwriting any existing secret at
the same path. Confirms before asking for the passphrase, so declining
never costs a wasted attempt at typing it. Flags: `--stdin`, `-y, --yes`.

### `jit profile`

A profile maps environment-variable names to vault secret paths. These
subcommands never decrypt or print a secret value, which is exactly why a
profile manifest is safe to commit.

- `jit profile list`: every manifest visible from the current directory,
  both project-local (`.jit/profiles/`) and the home-rooted global ones
  migrate creates for shell/MCP/AWS/kubeconfig/terraform/npmrc secrets.
- `jit profile show <name>`: one profile's variable-to-vault-path mapping.

### `jit run [--profile <name>] [--mode <m>] [--] <command> [args...]`

Decrypts a profile's secrets and replaces the jit process entirely with
the target command (`execve`); jit is gone from memory the instant the
target starts. The target holds the plaintext once running: jit narrows
the exposure window, it doesn't sandbox the target.

Without `--profile`, resolves the project's migrated `.env` layers
(looking upward from the current directory, like git) and injects their
merged result in dotenv order, `.env` overridden by `.env.local`, printing
exactly what it merged. A mode layer is never merged without being asked
for.

| Flag | Meaning |
|---|---|
| `--profile <name>` | inject one profile verbatim; disables merging |
| `--mode <m>` | also merge `.env.<m>` and `.env.<m>.local` (precedence: `.env` < `.env.<m>` < `.env.local` < `.env.<m>.local`) |

The `--` is optional: jit stops reading its own flags at the first
non-flag argument.

```sh
jit run -- npm start
jit run --mode production -- npm start
jit run --profile aws-admin -- terraform plan
```

### `jit export [--profile <name>] [--mode <m>]`

Prints POSIX `export VAR='value'` statements to stdout, meant to be
evaluated into the current shell; nothing is written to disk or any shell
init file. Profile selection works exactly like `jit run`, and the merge
announcement goes to stderr so `eval` never swallows it. Run it without
`eval` to peek at a profile's resolved values.

```sh
eval "$(jit export)"
eval "$(jit export --profile aws-admin)"
```

### `jit unmount <path>`

Reverses a single live mount: decrypts the mounted file's secrets and
writes them back as a plain file at the same path, replacing the pipe. The
vault secrets and profile stay put. If the agent is running, it stops
serving just this one mount first; every other mount keeps being served.
Because this restores plaintext to disk, it always requires its own fresh
Touch ID/passcode approval. Confirms unless `-y, --yes`.

---

## Background agent

### `jit agent`

A small background helper that keeps one unlocked session other jit
commands share, instead of each prompting Touch ID separately, and that
serves any live-mounted files. The process itself needs no Touch ID just
to keep running; only the session inside it locks after `--ttl` of
inactivity, prompting again on next use.

#### `jit agent install`

Registers a launchd LaunchAgent so the helper starts at every login and
restarts itself if it crashes, until `uninstall`. Safe to run again to
change `--ttl` (or after upgrading the binary): an already-installed
instance is unloaded first, so the change takes effect immediately.

| Flag | Meaning |
|---|---|
| `--ttl <duration>` | how long a session stays unlocked after the last prompt, baked into the plist (default `15m`) |
| `-y, --yes` | skip the confirmation prompt |

#### `jit agent uninstall`

Stops the helper and removes it from login startup. Live-mounted files go
quiet (they don't disappear) until you install again. Doesn't touch the
vault or any stored secret.

#### `jit agent status`

Is it running, is the session unlocked (and for how long), which mounts
are revealed and for how long, and what the most recent reader of each
mount was actually served (real or decoy values, and by which process).
Warns if the running agent is an older build than the CLI. `--format json`
for scripting.

It also answers *who put the session in this state* — the command that
unlocked it, what launched that command, and what dropped the session
afterwards:

```
jit agent is running and locked.

Session (most recent first):
  • locked   48m ago (11:48:04) — 15m0s idle timeout
  • unlocked 1h ago (11:33:04) — launched by claude
      ~/go/bin/jit run --profile mcp-jamf -- uv --directory ~/Documents/…
```

Read that as: an MCP server your editor started asked for the `mcp-jamf`
profile's secrets, and the session then lapsed on its own 15 minutes later.
Both facts come from the kernel, not from anything the calling process
claimed about itself.

#### `jit agent history`

The same session events, all of them, most recent first — every unlock (with
the command that triggered the prompt and what launched it) and every lock
(with its cause). This is the answer to "why does it keep asking me?", which
`status` can only ever half-answer, since it holds just the latest of each.

```
Session history (most recent first):
  • unlocked 4s ago (13:19:19) — launched by claude
      ~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve
  • locked   10s ago (13:19:13) — explicit lock, launched by claude
  • unlocked 10s ago (13:19:13) — launched by claude
      ~/go/bin/jit run --profile mcp-jamf -- uv --directory ~/Documents/…
```

In-memory and bounded, so a restart empties it (launchd restarts the agent at
every login). The same events are appended to the agent's log file, which is
the durable record. Asking never triggers a prompt. `--format json` for
scripting.

#### `jit agent unlock` / `jit agent lock`

Pre-warm the shared session so the next command doesn't prompt, or drop it
immediately without waiting for the TTL.

#### `jit agent reveal <mount-path>`

Temporarily serves real values in a live-mounted file. Every
unlock/refresh already reveals every mount for a short window
automatically; this is for when that's not enough (a dev server that reads
`.env` well after the window closed). Fails loudly if the mount's secrets
can't be resolved from the vault. Meant both for hand use and for
embedding in a pre-run hook, which migrate wires up automatically for
direnv/npm projects.

| Flag | Meaning |
|---|---|
| `--for <duration>` | how long to serve real content, clamped to `10m` (default `5m`) |
| `-q, --quiet` | suppress the success message, for hooks |

#### `jit agent run`

Runs the agent in the foreground. Normally started by launchd via
`install`, not by hand. `--ttl` as in `install`.

---

## Invoked by other tools

You don't run these; migrated configs do. All three resolve the vault the
same way `jit run` does: a reachable unlocked agent, or an interactive
Touch ID/passcode prompt. From a fully headless context (cron, CI) with
neither, they hang or fail, the same tradeoff `jit run`/`export` accept.

- `jit aws-credential-process --profile <name>`: wired into `~/.aws/config`
  as a `credential_process` line; the AWS CLI/SDKs call it to get
  credentials with no file on disk.
- `jit k8s-exec-credential --profile <name>`: wired into the kubeconfig
  user's `exec` block; kubectl/client-go call it.
- `jit terraform-credentials <get|store|forget> <hostname>`: Terraform's
  credentials-helper protocol. `get` prints the token as JSON (an empty
  object for an unknown host, answered before any vault access, so it
  never costs a surprise prompt); `store` is what `terraform login` calls,
  landing the re-login in the vault instead of a plaintext file; `forget`
  is `terraform logout`.

---

## Everything else

### `jit completion <bash|zsh|fish|powershell>`

Generates the shell completion script. Setup instructions, including the
PATH/compinit ordering fix for a fresh zsh setup, are in
[USAGE.md](./USAGE.md#shell-completion); `jit completion <shell> --help`
covers system-wide install locations.

### Global flags

`-h, --help` on any command; `-v, --version` on the root command. Every
confirmation prompt in a mutating command has a `-y`/`--yes` escape hatch
for scripting, and every destructive-toward-plaintext operation (`unmount`,
`migrate undo`, `migrate remove`, `vault export`) demands its own fresh
Touch ID/passcode approval even when an unlocked agent session exists.
