# Using jit

A walkthrough of the actual command surface, in the order you'd realistically use it: find what's exposed, fix it, then live with the fix day to day. For *why* jit works this way (threat model, what it doesn't protect against), see [RFC.md](../RFC.md). For what's still short of the target design, see [GAPS.md](../GAPS.md).

**Platform:** macOS only today (Windows/Linux are unbuilt — GAPS.md #15). No Homebrew tap yet — clone the repo and build it yourself:

```
git clone https://github.com/jitpass/jit.git
cd jit
go build -o jit ./cmd/jit
sudo mv jit /usr/local/bin/
jit --help
```

`go build -o jit` only puts the binary in your current directory — the `mv` into `/usr/local/bin` (already on `PATH` for virtually every macOS shell setup) is what makes plain `jit audit` etc. work from anywhere, which every example below assumes. If you'd rather not install it system-wide, skip the `mv` and run `./jit audit` (from inside the repo directory) instead — every command below works identically either way, just with that prefix.

---

## 1. Find out what's exposed: `jit audit`

Start here, always — `audit` is strictly read-only under every flag. It never touches, encrypts, or rewrites anything, and never prints a real secret value in full, only a masked preview.

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

No secret values are ever printed in full. Run `jit audit --format ndjson` for machine-readable output (same redaction rules apply).
```

**Important:** `audit` always scans relative to `$HOME`, not your current directory — running it from inside a project doesn't narrow the scan, it's a whole-machine (well, whole-home) pass every time. That's by design: the point is "is my machine clean," not "is this one project clean."

Other flags:
- `--format markdown` / `--format ndjson` — for a saved report or piping into another tool.
- `-o report.md` — write to a file instead of stdout.

## 2. Set up the vault: `jit vault init`

Before anything can be fixed, jit needs somewhere to put real secrets:

```
$ jit vault init
Vault initialized at /Users/alex/Library/Application Support/jitpass.
Run `jit vault set <path>` to add a secret, or `jit migrate` to move existing secrets in.
```

This generates a Master Encryption Key and stores it in your macOS Keychain. **You'll see a Touch ID / passcode prompt** — that's expected, and it's the same prompt you'll see the first time anything touches the vault in a given session (see §4 on `jit agent` for how to stop seeing it repeatedly).

## 3. Fix it: `jit migrate local` or `jit migrate home`

`migrate` is a **separate command from `audit`**, deliberately — a read-only scanner can never be turned into a mutating one by a mistyped flag. It has two subcommands, picking an explicit scope instead of one flag whose preview and real behavior used to silently disagree:

- **`jit migrate local`** — `.env`/MCP/npmrc findings under the **current directory tree only**. Touches nothing outside the project you're standing in — no shell configs, AWS, kubeconfig, Claude Desktop's config, or global `~/.npmrc`, since none of those live under this directory.
- **`jit migrate home`** — everything under `$HOME`: `.env`/MCP/npmrc findings **anywhere under `$HOME`**, plus shell configs, AWS, kubeconfig, Claude Desktop's config, and the global `~/.npmrc` — these five have no project-scoped form at all, so they only ever show up here, never under `local`.

Both take `--dry-run` (preview only — and it's an *accurate* preview: it runs the exact same discovery a real run in that scope would, so what you're shown is exactly what would happen), `--only` (scope to specific categories), and `--yes` (skip the confirmation prompt, for scripting).

**Preview first**, from inside the project you want to fix:

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
This only covers what jit migrate can act on — run `jit audit` for a complete picture, including findings it can never auto-fix, like private keys.
```

**Then apply it** — drop `--dry-run`:

```
$ jit migrate local
jit migrate — plan (local scope)
Each modified file is backed up before it's rewritten.

Scoped to this run — under the current directory tree

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

────────────────────────────────────────────
  1 change(s) planned across 1 category
Proceed? [y/N] y
```

Answering `y` (or passing `--yes`/`-y` up front) triggers the actual vault writes — a Touch ID prompt if you don't have `jit agent` running yet (§4). Declining aborts with nothing changed and no vault access at all.

**Want to actually clean the whole machine in one run?** Use `home` instead of `local`. This also picks up shell configs/AWS/kubeconfig/Claude Desktop's config/global `~/.npmrc`, which `local` never touches — the plan groups those under a separate "Machine-wide" section so it's clear they're not part of the current-directory walk:

```
$ jit migrate home --dry-run
jit migrate — plan (home scope)
Each modified file is backed up before it's rewritten.

Scoped to this run — anywhere under $HOME

[.env file(s) → secrets move to the vault; the file keeps working as a live, auto-updating mount] (1)
  • /Users/alex/code/myapp/.env

Machine-wide config files — only included on a home-scope run

[shell config(s) → secrets move to the vault; loaded back automatically when your shell starts] (1)
  • /Users/alex/.zshrc

  Use --only env to leave these machine-wide files out of the plan.

────────────────────────────────────────────
  2 change(s) planned across 2 categories

(Skipped 1 finding(s) under an archived/backup-looking directory — rerun with --include-archived to include them.)

[DRY RUN] No files will be changed. Run without --dry-run to apply this plan.
This only covers what jit migrate can act on — run `jit audit` for a complete picture, including findings it can never auto-fix, like private keys.
```

`home` skips anything under a directory literally named `archive`, `archived`, `backup`, `backups`, or `.trash` **by default** — converting a forgotten project's `.env` into a live-mounted pipe that nothing will ever serve again turns "insecure but readable" into "permanently unreadable," which is worse. Pass `--include-archived` if you really want those too. `local` never applies this filter — deliberately `cd`-ing into an old project and running `migrate local` there is an explicit action, not an implicit sweep.

To scope either subcommand to just one or two categories, use `--only` (now works with `--dry-run` too):

```
$ jit migrate home --only=env,aws
```

Valid categories: `env`, `shell`, `mcp`, `aws`, `kube`, `npmrc`.

**What actually happens to each category:**

| Category | Vault gets | The original file becomes |
|---|---|---|
| `.env` | one secret per variable | a live-mounted named pipe (see §5), plus a git-safe `.env.pointers` companion listing each variable's vault path — safe to open in an editor or commit, unlike the mount itself |
| shell config | one secret per `export KEY=value` line | the export line replaced with `eval "$(jit export --profile ...)"` |
| MCP config | one secret per server's env-block value | the server's `command` rewritten to launch via `jit run` |
| AWS (`~/.aws/credentials`) | the profile's access key/secret/session token | a `credential_process` line in `~/.aws/config` — no file with the real value at all |
| kubeconfig (`~/.kube/config`) | the user's bearer token or cert/key pair | an `exec` block calling jit (client-go's exec-plugin protocol) |
| npmrc | just the secret lines (`_authToken`, etc.) | a live-mounted pipe serving a template (plus its own `.pointers` companion) — everything else in the file untouched |

Every rewritten file gets a `<file>.jit-bak-<timestamp>` backup first. If a file being migrated has ever been committed to git, `migrate` warns explicitly — it never scrubs git history, so the old value is still recoverable via `git log -p` regardless of what happens going forward.

Terraform Cloud and GCP application-default-credentials are detected by `audit` but have no `migrate` path yet (GAPS.md #16).

## 4. Stop re-entering Touch ID: `jit agent`

Every vault-touching command so far has needed a fresh Touch ID/passcode challenge. `jit agent` is a small persistent background helper that other jit commands share one unlocked session with instead:

```
$ jit agent install
Set up jit agent to start automatically at every login (and restart itself if it crashes), staying unlocked for up to 15m0s after each Touch ID prompt, until you run `jit agent uninstall`? [y/N] y
Installed — jit agent now starts automatically every time you log in (survives reboots) and stays unlocked for up to 15m0s after your last Touch ID prompt.
Run `jit agent uninstall` to remove it. (~/Library/LaunchAgents/com.jitpass.agent.plist)
```

This registers a launchd LaunchAgent. The **process** runs indefinitely without needing Touch ID at all; only the **cached key inside it** locks after 15 minutes of inactivity (`--ttl` to change that), re-challenging on next use. Once it's running, `jit vault get`, `jit run`, `jit export`, and `jit migrate` all transparently use its shared session instead of prompting independently — unlock once, and everything else "just works" for the rest of that window.

Other agent commands:
- `jit agent status` — is it running, is it unlocked right now, which mounts are revealed (and for how long), when the last reveal window ended, and what the most recent reader of each mount was actually served (real or decoy values, and by which process). It also warns if the running agent was built from an older version than the CLI you're typing — run `jit agent install` to restart it on the current binary.
- `jit agent unlock` / `jit agent lock` — pre-warm the session, or drop it immediately without waiting for the TTL.
- `jit agent uninstall` — stop and remove it.

If the agent isn't running, every vault-touching command still works — it just falls back to its own independent Touch ID challenge every time.

## 5. Living with a live-mounted `.env`

Once `.env` is migrated, the file at that path is no longer a regular file — it's a named pipe that `jit agent` re-serves fresh content into on every read. This has one real consequence worth knowing up front: **the mount serves fake-looking placeholder values by default, and only real values during a short window** (auto-revealed for 60 seconds right after `jit agent` unlocks or `jit migrate` runs, or explicitly via `jit agent reveal` — an unlock caused by `jit agent reveal` itself reveals only the file you named, never the rest). This is deliberate — see GAPS.md #2 — not a bug: a mount that always served real content the moment anything opened the file would defeat most of the point of moving secrets off disk.

In practice:
- **Starting your app normally just works.** `jit migrate` tries to wire an automatic reveal call into an existing `.envrc` (direnv) or your `package.json`'s `dev`/`start` script, so the common case needs no manual step.
- **If a dev server reads `.env` well after the window closed** (long-running process, restarted after 60s), run `jit agent reveal <path>` by hand first, or `--for <duration>` for a longer window (clamped to 10 minutes). Revealing fails loudly — instead of pretending to work — if the mount's secrets can't actually be resolved from the vault (e.g. a referenced secret was removed); `jit doctor` shows what's missing.
- **Not sure whether a mount is revealed, or why your app got placeholder values?** `jit agent status` answers both: it shows each mount's reveal countdown (or when the last window ended) and what the most recent reader was served.
- **Don't `cat`/open the live-mounted file itself to "just check what's in it."** Outside the revealed window you'll see decoy values, not an error — and even during the window, a FIFO can't support everything a real file can (`stat` for size, `lseek`, `mmap` — GAPS.md #6), so some tools (text editors included) may behave oddly against it regardless. Instead:
  - Open the **`.env.pointers`** file `migrate` writes right next to the mount — a plain, regular, git-safe file listing each variable as `KEY=jit://vault/<path>` instead of its value. Opening it in an editor, `cat`-ing it, or committing it all work exactly like a normal file, since it *is* one — it just tells you *where* a value lives, never the value itself.
  - Use `jit export --profile <name>` or `jit vault get <path>` (§7) to actually see a real value — those go straight to the vault, no mount involved.
- **Reverse it** with `jit unmount <path>` if you want the plain file back — it decrypts the vault values and writes them out as a regular file again, replacing the pipe. The vault secrets and profile stay put; this only reverses the file.
- **Leave entirely** with `jit migrate remove` (run from the project) — restores every file in the project to plaintext AND deletes the project's profiles, its vault secrets, its encrypted backups, any reveal hooks migrate wired in, and the `.jit/` directory. It always asks for its own Touch ID/passcode approval, even with the agent unlocked. (`jit migrate undo` is the gentler sibling: it restores each file's exact pre-migration content and keeps the vault untouched.)

## 6. AWS and kubeconfig: no file at all

For AWS and kubeconfig, migration doesn't create a mount — it wires the AWS CLI/kubectl's own native credential-helper protocol directly to jit (`aws-credential-process`, `k8s-exec-credential`). You won't normally run these yourself; the AWS CLI/SDK or kubectl invoke them automatically, and each needs the vault unlocked (agent or Touch ID) to answer.

## 7. Using secrets day to day: `jit run` and `jit export`

For anything that isn't a migrated `.env`/shell-config/AWS/kubeconfig file, or when you just want a secret in one shell session without touching any file:

**Run one command with secrets injected, nothing left behind:**

```
$ cd myapp
$ jit run -- npm run dev
jit run: merging .env, .env.local (last wins) — profiles myapp, myapp-local
```

From inside a migrated project, `jit run` **resolves the project's `.env` layers by itself** — you don't have to name a profile. It finds the project's migrated `.env`-family files (looking upward from the current directory, the way git finds `.git`, so it works from any subfolder) and injects their merged result in standard dotenv order: `.env` first, `.env.local` overriding it — the same effective environment your app sees when it reads those files directly. It always prints exactly what it merged (real secrets are going into the process, so it never does that silently), and warns if a layer file exists on disk but was never migrated.

Mode-specific layers (`.env.production`, `.env.development`, …) are **never merged unless you ask** — production secrets shouldn't ride into a dev run because a file exists. Ask with `--mode`:

```
$ jit run --mode production -- npm start
jit run: merging .env, .env.production, .env.local (last wins) — profiles myapp, myapp-production, myapp-local
```

The full precedence with a mode is `.env < .env.<mode> < .env.local < .env.<mode>.local` (the Next.js/CRA convention). If nothing is migrated here at all, jit falls back to the project's single profile if exactly one exists, and otherwise asks you to name one with `--profile` rather than guessing.

The `--` separating jit's own flags from your command is optional too — jit stops reading its flags at the first non-flag argument, so `jit run npm run dev` is equivalent, and your command's own flags (`npm run dev -- --port 3000`) pass straight through. Naming a profile explicitly turns all merging off and uses exactly that one — handy for a home-rooted global profile like AWS:

```
$ jit run --profile aws-admin -- terraform plan
```

This replaces the current process image (`execve`) with your command — jit itself is gone from memory the instant it starts. The target process holds the plaintext once running (jit narrows the exposure window, it can't sandbox what the target does with it — RFC.md B1).

**Print `export` statements for the current shell:**

```
$ eval "$(jit export)"
jit export: merging .env, .env.local (last wins) — profiles myapp, myapp-local
```

`jit export` selects profiles exactly like `jit run` — same layer merge, same `--mode`, same explicit `--profile` override (`eval "$(jit export --profile aws-admin)"`). The merge announcement goes to stderr, so `eval` never swallows it. Run it without `eval` to see the resolved values printed to your terminal — this is the sanctioned way to "peek" at what's in a profile, instead of opening a live-mounted file.

Both commands resolve **profiles** — see §8 for what those are.

## 8. Profiles: `jit profile`

A profile is a small YAML manifest mapping environment-variable names to vault paths — `jit migrate` creates these automatically, but you can inspect them directly:

```
$ jit profile list
aws-admin    global    /Users/alex/.jit/profiles/aws-admin.yaml
myapp        project   /Users/alex/code/myapp/.jit/profiles/myapp.yaml

$ jit profile show myapp
myapp (project: /Users/alex/code/myapp/.jit/profiles/myapp.yaml)
  DATABASE_URL -> myapp/DATABASE_URL
  STRIPE_API_KEY -> myapp/STRIPE_API_KEY
```

Never prints a secret value — names and vault paths only. It's git-safe to commit a profile manifest for exactly that reason.

## 9. Sanity checks: `jit doctor` and `jit status`

**`jit doctor`** verifies every path a profile references actually exists in the vault — catches "the profile says X, but nothing's actually stored there" before an app crashes on an empty environment variable at runtime:

```
$ jit doctor
✓ 2 profile(s), 5 secret reference(s) all resolve cleanly
```

**`jit status`** is a one-shot rollup of vault/agent/profile/mount health — what used to take four separate commands:

```
$ jit status
Vault: 5 secret(s) stored.
Agent: running and unlocked (locks in 12m30s).
Profiles: 2 profile(s), 5 secret reference(s) all resolve cleanly.
Mounts: 1 registered, agent unlocked and serving them.
```

Both support `--format json` for scripting or a CI health check:

```
$ jit status --format json
{
  "vault": { "secrets_stored": 5 },
  "agent": { "running": true, "unlocked": true, "locks_in_seconds": 750 },
  "profiles": { "profiles_found": 2, "secret_references": 5, "problems": 0 },
  "mounts": { "registered": 1, "being_served": true }
}
```

`doctor` still exits non-zero on a problem in JSON mode too — a CI check needs both the parseable body and a reliable exit code.

Neither ever decrypts a secret value or needs Touch ID — both are safe to run as often as you like.

## 10. Backup and restore: `jit vault export` / `jit vault import`

For disaster recovery (laptop loss, a reformat) — **not** a cloud-sync mechanism, just a local file you move around however you choose:

```
$ jit vault export ~/backup.json
Enter a passphrase to encrypt this export: ********
Confirm passphrase: ********
Exported 5 secret(s) to /Users/alex/backup.json.
```

This is deliberately **not** the same encryption the vault uses day to day — that's bound to this specific device's Touch ID/Secure Enclave and useless on a different machine. The export instead derives its key from the passphrase you type (via Argon2id), which is the only thing that makes the file restorable somewhere else:

```
$ jit vault import ~/backup.json
Import secrets from /Users/alex/backup.json, overwriting any existing secret at the same path? [y/N] y
Enter the export's passphrase: ********
Restored 5 secret(s) from /Users/alex/backup.json.
```

There's no way to recover a forgotten passphrase — jit never stores it anywhere, on purpose.

---

## Command reference

| Command | What it does |
|---|---|
| `jit audit` | Read-only whole-home scan for exposed plaintext secrets. |
| `jit migrate local [--dry-run] [--only=...] [--yes]` | Fix `.env`/MCP/npmrc findings under the current directory tree only — no shell config/AWS/kubeconfig/Claude Desktop/global npmrc. |
| `jit migrate home [--dry-run] [--only=...] [--yes] [--include-archived]` | Same three, but anywhere under `$HOME`, plus shell config/AWS/kubeconfig/Claude Desktop/global npmrc (home scope only) — skips archived-looking directories by default. |
| `jit vault init/set/get/list/rm/export/import` | Manage the encrypted vault directly. |
| `jit run [--profile <name>] [--mode <m>] [--] <cmd>` | Inject secrets into a subprocess's environment, nothing on disk. By default merges the project's migrated `.env` layers in dotenv order (found from any subfolder); `--mode` layers `.env.<m>` in; `--profile` uses one profile verbatim. `--` optional. |
| `jit export [--profile <name>] [--mode <m>]` | Print `export` statements — eval into your shell, or just read the values. Selects profiles exactly like `jit run`. |
| `jit agent install/status/unlock/lock/reveal/uninstall` | The shared-session broker + live mount server. |
| `jit vault clean` / `jit vault delete` | Wipe all secrets (vault stays set up) / destroy the vault entirely, encryption key included. Both confirm first; `delete` refuses while anything is still live-mounted. |
| `jit doctor [--profile <name>] [--format json]` | Verify a profile's secret references all exist in the vault. |
| `jit profile list/show` | Inspect profile manifests (names/paths only, never values). |
| `jit status [--format json]` | One-shot vault/agent/profile/mount health rollup. |
| `jit unmount <path>` | Reverse a live mount back into a plain file. |
| `jit migrate undo [path...]` | Restore migrated files from their encrypted pre-migration backups; vault and profiles stay. |
| `jit migrate remove` | Remove jit from the current project completely: plaintext back, profiles/secrets/backups/hooks/`.jit/` deleted. Always fresh Touch ID. |
| `jit aws-credential-process` / `jit k8s-exec-credential` | Internal — invoked by the AWS CLI/kubectl themselves, not by hand. |

Every command supports `--help` for its full flag list and a more detailed explanation than this walkthrough covers.
