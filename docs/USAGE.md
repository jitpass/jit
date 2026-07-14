# Using jit day to day

This is the practical guide: set jit up once, then live with it. Installing
the binary is covered in the [README](../README.md#install), and the README's
security-model section covers what jit deliberately does *not* protect
against.

The short version of daily life with jit: you set it up once, migrate your
projects once, and after that you mostly just work. Your app starts normally,
`aws`/`kubectl`/`terraform` behave exactly as before, and roughly once per
15 minutes of active use, macOS asks for a Touch ID confirmation.

---

## First-time setup

### 1. See what's exposed: `jit audit`

Start here. `audit` is strictly read-only under every flag: it never touches,
encrypts, or rewrites anything, and never prints a real secret value in full,
only a masked preview.

```
$ jit audit
jit audit — risk report for alex@Alexs-MacBook-Pro
scan time: 2026-07-07T14:48:08.370Z          duration: 2ms

  RISK LEVEL: HIGH

  Shell Configs          1 finding(s)
  .env Files             1 finding(s)
  Credential Files       0 finding(s)
  AI Tool / MCP Configs  0 finding(s)
  Private Keys           0 finding(s)
  IaC Variable Files     0 finding(s)
  Suspicious Filenames   0 finding(s)
  ───────────────────────────────────
  Total: 2 finding(s)

[Shell Configs]
  /Users/alex/.zshrc
    :1  [high]  key: AWS_SECRET_ACCESS_KEY
        value:  AKIA**********
        why:    export statement assigns a value to a key name that looks like a secret

[.env Files]
  /Users/alex/code/myapp/.env
    [high]
        why:    contains a value matching Stripe Test Secret Key's known token format
```

`audit` always scans your whole home directory, not your current directory.
The question it answers is "is my machine clean," not "is this one project
clean." Useful flags: `--format markdown` or `--format ndjson` for a saved
report or piping into another tool, `-o report.md` to write to a file.

### 2. Create the vault: `jit vault init`

```
$ jit vault init
Vault initialized at /Users/alex/Library/Application Support/jitpass.
Run `jit vault set <path>` to add a secret, or `jit migrate` to move existing secrets in.
```

This generates a master encryption key and stores it in your macOS Keychain.
You'll see a Touch ID / passcode prompt; that's expected.

### 3. Install the background agent: `jit agent install`

Without the agent, every vault-touching command asks for Touch ID
independently. With it, you unlock once and everything shares that session
for the next 15 minutes of activity:

```
$ jit agent install
Set up jit agent to start automatically at every login (and restart itself if it crashes), staying unlocked for up to 15m0s after each Touch ID prompt, until you run `jit agent uninstall`? [y/N] y
Installed — jit agent now starts automatically every time you log in (survives reboots) and stays unlocked for up to 15m0s after your last Touch ID prompt.
```

The agent process itself runs indefinitely and never needs Touch ID just to
exist; only the cached key inside it locks after 15 minutes of inactivity
(`--ttl` to change that), re-prompting on next use. The agent is also what
serves live-mounted files (more on those below), so if you migrate a `.env`
file, you want it installed. Everything still works without it, just with
more prompts.

### 4. Fix a project: `jit migrate local`

`migrate` is a separate command from `audit`, deliberately: a read-only
scanner can never be turned into a mutating one by a mistyped flag.

Always preview first. `--dry-run` runs the exact same discovery a real run
would, so the preview is accurate:

```
$ cd ~/code/myapp
$ jit migrate local --dry-run
jit migrate — plan (local scope)
Each modified file is backed up before it's rewritten.

Scoped to this run — under the current directory tree

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

────────────────────────────────────────────
  1 change(s) planned across 1 category

[DRY RUN] No files will be changed. Run without --dry-run to apply this plan.
```

Then apply it by dropping `--dry-run`. The same plan prints again, followed
by a `Proceed? [y/N]` confirmation; answering `y` triggers the vault writes
(one Touch ID prompt if the agent isn't unlocked yet). Declining aborts with
nothing changed.

Before any file is rewritten, its exact original bytes are backed up,
encrypted, into the vault. `jit migrate undo` restores them byte-for-byte
at any point later. If a file being migrated has ever been committed to git,
`migrate` warns explicitly: it never scrubs git history, so the old value is
still recoverable via `git log -p` no matter what happens going forward.

### 5. Or fix the whole machine: `jit migrate home`

`local` only ever touches what's under the directory you're standing in.
`home` covers everything under `$HOME`: every project's `.env`/`mcp.json`/
`.npmrc`, plus the machine-wide files that have no project-scoped form at
all: shell configs, `~/.aws/credentials`, `~/.kube/config`, the Terraform
Cloud token file, Claude Desktop's MCP config, and the global `~/.npmrc`.
The plan groups those under a separate "Machine-wide" section so it's clear
they're not part of a directory walk.

`home` skips anything under a directory named `archive`, `archived`,
`backup`, `backups`, or `.trash` by default (pass `--include-archived` to
override): converting a forgotten project's `.env` into a live mount nothing
will ever read again makes it *less* recoverable, not more secure. `local`
never applies this filter; deliberately standing in an old project and
migrating it is an explicit choice.

To limit either scope to specific categories, use `--only`:

```
$ jit migrate home --only=env,aws
```

Valid categories: `env`, `shell`, `mcp`, `aws`, `kube`, `terraform`, `npmrc`.

**What each category turns into** (each credential flows back through the
consuming tool's own native mechanism, so everything keeps working):

| Category | Vault gets | The original file becomes |
|---|---|---|
| `.env` | one secret per variable | a live-mounted named pipe, plus a git-safe `.env.pointers` companion listing each variable's vault path |
| shell config | one secret per `export KEY=value` line | the export line replaced with `eval "$(jit export --profile ...)"` |
| MCP config | one secret per server's env-block value | the server's `command` rewritten to launch via `jit run` |
| AWS (`~/.aws/credentials`) | the profile's access key/secret/session token | a `credential_process` line in `~/.aws/config`; no file with the real value at all |
| kubeconfig (`~/.kube/config`) | the user's bearer token or cert/key pair | an `exec` block calling jit (client-go's exec-plugin protocol) |
| Terraform Cloud (`~/.terraform.d/credentials.tfrc.json`) | each host's API token | a `credentials_helper` wired into `~/.terraformrc`; `terraform login`/`logout` keep working |
| npmrc | just the secret lines (`_authToken`, etc.) | a live-mounted pipe serving a template; everything else in the file untouched |

GCP application-default credentials are detected by `audit` but have no
migrate path yet.

---

## Day to day

### Starting your app just works (usually)

A migrated `.env` is no longer a regular file: it's a named pipe the agent
serves fresh content into on every read. One thing to know up front: **the
mount serves fake-looking placeholder values by default, and real values
only during a short revealed window.** A file that served real secrets to
whatever opened it would defeat the point of moving them off disk.

In practice you rarely think about this:

- `jit migrate` wires an automatic reveal into your `.envrc` (direnv) or
  `package.json` `dev`/`start` script, so `npm run dev` and friends just
  work. The window also opens automatically for 60 seconds whenever the
  agent unlocks or a migrate runs.
- If a process reads `.env` outside a window (say, a dev server restarted
  minutes later), reveal by hand: `jit agent reveal <path>`, with
  `--for <duration>` for a longer window (up to 10 minutes). Revealing fails
  loudly, instead of pretending to work, if a referenced secret is missing
  from the vault; `jit doctor` shows what's missing.
- Wondering whether a mount is revealed right now, or why your app saw
  placeholders? `jit agent status` shows each mount's reveal countdown and
  what the most recent reader was actually served, real or decoy, and by
  which process.

### Run anything with secrets: `jit run`

```
$ cd myapp
$ jit run -- npm run dev
jit run: merging .env, .env.local (last wins) — profiles myapp, myapp-local
```

From inside a migrated project, `jit run` needs no arguments beyond your
command. It finds the project's migrated `.env`-family files (looking upward
from wherever you are, the way git finds `.git`) and injects their merged
result in standard dotenv order: `.env` first, `.env.local` overriding it.
It always prints what it merged (real secrets are entering a process, so it
never does that silently), and warns if a layer file exists on disk but was
never migrated.

Mode-specific layers (`.env.production`, `.env.development`, ...) are never
merged unless you ask, so production secrets can't ride into a dev run just
because a file exists:

```
$ jit run --mode production -- npm start
jit run: merging .env, .env.production, .env.local (last wins) — profiles myapp, myapp-production, myapp-local
```

Full precedence with a mode: `.env` < `.env.<mode>` < `.env.local` <
`.env.<mode>.local` (the Next.js/CRA convention).

The `--` is optional (jit stops reading its own flags at the first non-flag
argument), and your command's flags pass straight through. Naming a profile
explicitly turns merging off and uses exactly that one, handy for a global
profile like AWS:

```
$ jit run --profile aws-admin -- terraform plan
```

`jit run` replaces its own process with your command (`execve`); jit itself
is gone from memory the instant your command starts.

### Secrets in your current shell: `jit export`

```
$ eval "$(jit export)"
jit export: merging .env, .env.local (last wins) — profiles myapp, myapp-local
```

`jit export` selects profiles exactly like `jit run`: same layer merge, same
`--mode`, same `--profile` override. The merge announcement goes to stderr,
so `eval` never swallows it.

### Peeking at a value

Don't `cat` or open a live-mounted file to "just check what's in it".
Outside the revealed window you'll see decoy values, not an error, and a
named pipe can't support everything a regular file can (`stat` for size,
`mmap`), so editors may behave oddly against it regardless. Instead:

- **Where does a variable live?** Open the `.env.pointers` file next to the
  mount. It's a plain, regular, git-safe file mapping each variable to its
  vault path (`KEY=jit://vault/<path>`), never to a value.
- **What's the actual value?** `jit vault get <path>` prints one secret
  (`--copy` sends it to the clipboard instead), or run `jit export` *without*
  `eval` to see a whole profile's resolved values in your terminal.

### AWS, kubectl, and Terraform: nothing changes

For these three there's no file and no window to think about. Migration
wired each tool's own credential-helper protocol directly to jit, so the
AWS CLI/SDKs, kubectl, and terraform fetch credentials on demand, invisibly.
Each fetch needs the vault unlocked (the agent's shared session, or a Touch
ID prompt). `terraform login` and `logout` keep working; a re-login lands
in the vault instead of back in a plaintext file.

### Quick health checks: `jit status` and `jit doctor`

Neither ever decrypts a secret or triggers Touch ID; both are safe to run as
often as you like.

`jit status` is the one-screen rollup:

```
$ jit status
Vault: 5 secret(s) stored.
Agent: running and unlocked (locks in 12m30s).
Profiles: 2 profile(s), 5 secret reference(s) all resolve cleanly.
Mounts: 1 registered, agent unlocked and serving them.
```

`jit doctor` verifies every path a profile references actually exists in the
vault, catching "the profile says X but nothing's stored there" before an
app crashes on an empty environment variable:

```
$ jit doctor
✓ 2 profile(s), 5 secret reference(s) all resolve cleanly
```

Both take `--format json` for scripting; `doctor` also exits non-zero on a
problem, so it works as a CI health check.

### Behind the scenes: profiles

Migration's bookkeeping unit is the **profile**: a small YAML manifest
mapping environment-variable names to vault paths. `jit migrate` creates
them automatically; `jit run`, `jit export`, and `jit doctor` resolve them.
You can inspect them any time:

```
$ jit profile list
aws-admin    global    /Users/alex/.jit/profiles/aws-admin.yaml
myapp        project   /Users/alex/code/myapp/.jit/profiles/myapp.yaml

$ jit profile show myapp
myapp (project: /Users/alex/code/myapp/.jit/profiles/myapp.yaml)
  DATABASE_URL -> myapp/DATABASE_URL
  STRIPE_API_KEY -> myapp/STRIPE_API_KEY
```

These never print a secret value, only names and vault paths, which is
exactly why a profile manifest is safe to commit.

---

## If something looks wrong

- **Your app got placeholder values.** The mount wasn't revealed when the
  app read it. `jit agent status` confirms (it shows what the last reader
  was served); `jit agent reveal <path>` fixes it, then restart the app.
- **A command hangs reading `.env`.** The agent probably isn't running or
  serving that mount; `jit status` will say. `jit agent install` (re)starts
  it.
- **"No secret stored at ..." or a doctor failure.** A profile references a
  vault path that's gone (usually a `jit vault rm` after migration).
  Re-set it with `jit vault set <path>`, or update the profile.
- **A Touch ID prompt appeared and you don't know why.** Read it — it names
  what it's for and what set it off ("unlock the vault for profile
  `mcp-jamf`, launched by claude"). If it's already gone, `jit agent status`
  shows who unlocked the current session and what dropped it, and
  `jit agent history` lists every unlock and lock since the agent started:

  ```
  Session history (most recent first):
    • unlocked 4s ago (13:19:19) — launched by claude
        ~/go/bin/jit run --profile mcp-caido -- caido-mcp-server serve
    • locked   10s ago (13:19:13) — explicit lock, launched by claude
  ```

  A common surprise: opening an editor. If your project's `.mcp.json` wraps
  an MCP server in `jit run --profile ...`, then starting that editor starts
  a secret-injecting process, which prompts if the session has lapsed.
- **Touch ID prompts feel too frequent.** First find out what's asking —
  `jit agent history` (above) names each one. If they're all legitimate,
  install the agent (§3) or lengthen its window: `jit agent install --ttl 1h`.
- **"different build" warning from `jit status`.** The running agent is an
  older binary than the CLI you're typing. Run `jit agent install` again to
  restart it on the current one (see the README's
  [Upgrading](../README.md#upgrading) section).

## Occasional tasks

### Manage secrets by hand: `jit vault set/get/list/rm`

Not everything comes in through `migrate`. `jit vault set myapp/NEW_KEY`
prompts for a value and stores it (add `-f` to overwrite an existing
path, `--stdin` to pipe the value in); `jit vault rm <path>` deletes one
secret (it confirms first). `jit vault list` shows what's stored (names
and paths only, never values), one path per line, so it pipes cleanly
into `grep`:

```
$ jit vault list
myapp/DATABASE_URL
myapp/STRIPE_API_KEY
notion-sync/NOTION_API_KEY
wiz/WIZ_CLIENT_ID
wiz/WIZ_CLIENT_SECRET

5 secret(s) stored, plus 2 encrypted file backup(s) kept for `jit migrate undo` (list with --all).
```

Those file backups accumulate by design — every `jit migrate` rewrite
stores one, and every `jit migrate undo` snapshots the pre-undo state too
(so an undo is itself undoable). Nothing expires them automatically. If
repeated migrate/undo cycles have grown the count past what you care to
keep, `jit vault prune` deletes the stale ones while keeping each file's
newest backup, so undo keeps working.

To replace a value that's already there, like a rotated API key or a
new token, see the next section.

### Changed an API key? Update the vault, not the file

After migration, the file on disk is no longer where a secret lives, so
when a provider issues you a new key, don't paste it into `.env`. Update
the vault value instead:

1. **Find the secret's path.** Open the `.env.pointers` file next to the
   mount, or run `jit profile show <name>`; both map each variable to its
   vault path.
2. **Set the new value:**

   ```
   $ jit vault set myapp/STRIPE_API_KEY
   Enter value for myapp/STRIPE_API_KEY:
   myapp/STRIPE_API_KEY already exists in the vault. Overwrite it? The current value can't be recovered afterward. [y/N] y
   Stored myapp/STRIPE_API_KEY
   ```

   (`-f` skips the overwrite confirmation, `--stdin` reads the value from
   a pipe for scripting.)

No re-migration needed; everything downstream picks the new value up on
its next fetch:

- A live-mounted `.env`/`.npmrc` serves fresh vault content on every read,
  so the next revealed read sees the new key.
- `jit run`, `jit export`, the AWS CLI/SDKs, and kubectl all resolve the
  vault on demand.
- Anything already *holding* the old value keeps it until restarted: a
  running dev server, an MCP server, or a shell that ran
  `eval "$(jit export ...)"` at startup. Restart the process (or open a
  new shell) and it picks up the new key.

One special case: for a new **Terraform Cloud** token, just run
`terraform login` again. Migration wired terraform's credentials helper to
jit, so the re-login lands directly in the vault instead of back in a
plaintext file.

### Put a file back on disk: `jit unmount` and `jit migrate undo`

- `jit unmount <path>` reverses a single live mount: decrypts the vault
  values and writes them out as a regular plain file again. The vault
  secrets and profile stay put.
- `jit migrate undo [path...]` restores migrated files, of any category,
  from their encrypted pre-migration backups, byte-for-byte. No path means
  everything; a file restores that file; a directory restores everything
  under it. The vault stays untouched.

Both always ask for their own fresh Touch ID/passcode approval, even with
the agent unlocked: putting secrets back on disk should never happen
silently on a cached session.

### Remove jit from a project: `jit migrate remove`

Run from the project, this is the full exit: every file back to plaintext,
plus the project's profiles, vault secrets, encrypted backups, reveal hooks,
and `.jit/` directory all deleted. Also always a fresh Touch ID.

### Back up the vault: `jit vault export` / `jit vault import`

For disaster recovery (laptop loss, a reformat), not a sync mechanism:

```
$ jit vault export ~/backup.json
Enter a passphrase to encrypt this export: ********
Confirm passphrase: ********
Exported 5 secret(s) to /Users/alex/backup.json.
```

The vault's day-to-day encryption is bound to this machine's keychain and
useless anywhere else, so the export derives its key from the passphrase you
type (Argon2id). That passphrase is the only way back in; jit never stores
it, on purpose. Restore with `jit vault import ~/backup.json`.

## Shell completion

`jit <TAB>` completes subcommands, flags, and their descriptions. With
completion installed, `jit vault get <TAB>` (and `set`/`rm`) also completes
the secret paths currently stored in your vault — names only, read straight
from the vault's file listing, so it never decrypts anything and never
triggers a Touch ID prompt mid-keystroke.

**zsh** (macOS default):

```sh
echo 'source <(jit completion zsh)' >> ~/.zshrc
exec zsh
```

If you use oh-my-zsh/prezto and `jit` is already on your PATH, that's all. On
a *plain* zsh setup (say, Go freshly installed via Homebrew and nothing else
configured), two things must come **before** that line in `~/.zshrc`, in this
order:

```sh
# 1. make jit findable (go install puts it in ~/go/bin)
export PATH="$HOME/go/bin:$PATH"

# 2. init zsh's completion system (skip if oh-my-zsh already does this)
autoload -Uz compinit && compinit

# 3. now this works: jit is on PATH and compdef exists
source <(jit completion zsh)
```

How to tell which piece is missing: `command not found: jit` means PATH,
`command not found: compdef` means `compinit` hasn't run, and `jit <TAB>`
completing plain filenames means the source line never ran at all.

**bash** (requires the `bash-completion` package):

```sh
echo 'source <(jit completion bash)' >> ~/.bashrc
```

**fish**:

```sh
jit completion fish > ~/.config/fish/completions/jit.fish
```

`jit completion <shell> --help` has per-shell details, including system-wide
install locations.

---

## Command reference

Every command and flag, including the ones this walkthrough doesn't cover
(`jit vault clean`/`delete`, `--stdin`, `--force`, the credential-helper
verbs), is documented in **[COMMANDS.md](./COMMANDS.md)**. At the terminal,
`jit <command> --help` has the same information.
