# jit Pre-Release QA Playbook

**This is a procedure for the assistant (Claude) to execute as jit's personal QA — not a CI job.**
When the user says *"test release N"* (or "QA the release", "check the build before we ship"),
follow this end to end: install the release candidate, **use jit the way a real user would**
across every workflow, and actively **hunt for bugs and anything that feels off** — then hand
back a findings report.

The goal is not a green checkmark. A script can produce those (`scripts/pre-release-live-test.sh`
is that script, used here only as a fast mechanical baseline). The goal is the judgment a script
can't have: *is the output clear? is this flag consistent with its siblings? did a guard get an
awkward edge? did anything regress?* The real findings from past sessions — a `cp`-over-running-
binary SIGKILL, `vault restore` rejecting a `-y` its own help implies, `vault delete` blocked by a
mount with no clean escape — were all found by looking, not asserting.

## The QA team

This playbook is executed by a team of QA-engineer subagents, orchestrated by the `/qa-release`
skill (`.claude/skills/qa-release/`). Invoke the skill when the user says "test/QA release N".

| Agent | Lens |
|---|---|
| `jit-qa-functionality` | core secret engine — vault CRUD, scan, migrate mechanics, rekey, audit/status/doctor, export/import, delete drill |
| `jit-qa-integrations` | external tools — wrap, mounts, terraform, clisso/aws, docker/git, env files, shell, k8s/sops/netrc/npmrc (drives real programs) |
| `jit-qa-ux` | output clarity, help, error messages, flag consistency, house style |
| `jit-qa-bughunter` | adversarial — malformed inputs, edge cases, guard bypass, weird states, concurrency |
| `jit-qa-code` | read-only review of the release diff for correctness/security/regressions |
| `jit-qa-docs` | docs match the shipped CLI; implementation follows the design docs |

The orchestrator runs the read-only agents (code, ux, docs) in parallel and the vault-mutating
agents (functionality, integrations, bughunter) **sequentially** — there is one machine-global
vault, so they can't safely mutate it at once. The sections below are the shared charter.

## Automate the mechanical; spend agent effort on judgment

Anything deterministic goes in `scripts/pre-release-live-test.sh` so agents don't burn tokens or
Touch ID re-doing it. Two levers keep the cost down:
- **One unlock per run.** Only `jit vault <sub>` commands force a fresh gesture; everything else
  (migrate, run, clisso, docker/git, mounts) rides one `jit unlock`. Prompt-free runs (cmdtree,
  scan, audit/status/doctor) skip the unlock entirely — **zero** Touch ID.
- **Focused baselines via `--phase`.** Each agent runs *its* surface as a fast scripted baseline,
  then adds judgment on top. Named aliases:

  | `--phase` | covers | prompts? |
  |---|---|---|
  | `cmdtree` | every command/subcommand: `--help` renders + unknown flag rejected, no panic | none |
  | `scan` | scan + all flags | none |
  | `vault` | vault CRUD + history + restore + multi-path rm | a few |
  | `rekey` | rekey round-trip | a few |
  | `migrate` / `mounts` | migrate lifecycle, mounts, run/export, `--only`, unmount | a few |
  | `wrap` | wrap shim inject/list/undo | one |
  | `aws`/`clisso`/`terraform` | credential_process chain | one |
  | `docker`/`git` | credential helpers (writes real config) | one |
  | `audit`/`status`/`doctor` | reporting surfaces | none |

  e.g. `scripts/pre-release-live-test.sh --phase cmdtree` (prompt-free, ~150 checks) or
  `--phase migrate` for just the migrate surface.

**Command-tree completeness:** `--phase cmdtree` walks the entire tree from the binary (via cobra
`__complete`) so no command/subcommand — including `service consent` and the plumbing helpers — can
be silently missing or broken. Run it every release; it costs nothing.

---

## 0. Mindset

- **Be the user, not the script.** Read every output as if you'd never seen it. Confusing wording,
  a wrong path in a hint, a stack-trace where a sentence belonged — those are bugs.
- **Follow your nose.** When something looks off, stop and dig. Go off-playbook. The playbook is a
  floor for coverage, not a ceiling.
- **Diff against expectations.** You know how jit behaved last release (git log, memories, docs). A
  silent behavior change is a finding even if nothing "fails".
- **Every finding gets a severity** (blocker / major / minor / nit) and a repro.

## 1. Safety (jit has one machine-global vault, no isolation)

- The vault under test is the **real** one. Namespace every secret you create with `jit-e2e` so
  cleanup can tell yours from the user's.
- **Snapshot first, restore last:** note `jit vault list` and `jit status` before you start; at the
  end the vault must be back to exactly that. The helper script asserts this automatically.
- The docker/git/aws checks write real paths (`~/.aws`, `~/.docker`, `~/.gitconfig`). Back them up
  before, restore after. (The helper script does this; if hand-driving, do it yourself.)
- **Never** run `jit vault delete`, `vault clean`, or `orphans --prune` against the real vault
  except in the deliberate, export-first delete drill (§8). Those are machine-wide.
- Unlock once (`jit unlock`) and bump the TTL (`jit service ttl 45m`) so session-backed commands
  (migrate, run, export, mounts, credential_process, docker/git helpers) don't re-prompt. Only the
  literal `jit vault <sub>` commands force a fresh Touch ID by design — restore the TTL when done.

## 2. Pre-flight — get the release candidate running

1. Identify the RC: the tag/commit you're validating (`git describe`, or the `JIT_BIN` the user
   hands you).
2. Build it with the release version injected, the way goreleaser does:
   ```
   go build -ldflags "-s -w -X github.com/jitpass/jit/internal/agent.version=<VER>" -o /tmp/jit-rc ./cmd/jit
   ```
3. **Install gotcha (known, will recur):** never `cp` a fresh build over the running binary — it
   corrupts the live service's mmap'd, signed pages and macOS SIGKILLs it (exit 137). Atomic-replace:
   ```
   cp /tmp/jit-rc ~/.local/bin/.jit.new && mv -f ~/.local/bin/.jit.new ~/.local/bin/jit
   jit service restart
   ```
4. **Verify the swap took:** `jit service status` — service build and CLI build must match. A stale
   service on the old build is the #1 release-day trap.
5. `jit doctor` — should resolve cleanly. Anything already broken here is either a real bug or
   leftover test state; investigate before proceeding.

## 3. Fast mechanical baseline (the helper script)

Run the script to catch obvious breakage fast and to scaffold/clean state, then spend your attention
on the hand-driven parts:
```
JIT_BIN=/path/to/jit-rc scripts/pre-release-live-test.sh --os-creds --destructive
```
- Read the summary. Every `✗` is a finding (or a bug in the script — decide which).
- Confirm the final line: **vault returned to baseline**. If not, the run leaked state — investigate.
- Budget: ~7 gestures default, ~13 with `--os-creds --destructive`.

The script covers the mechanical happy-paths. The sections below are where you *use* jit and *hunt*.

## 4. The playground run (real tools, real programs)

Clone the purpose-built sandbox and drive its actual programs through jit — this catches integration
bugs hermetic fixtures never will.

```
git clone https://github.com/jitpass/jitpass-playground /tmp/jit-qa-playground
cd /tmp/jit-qa-playground
```
It ships: `.env` / `.env.local` (a `server.js` that parses `.env` itself), `.mcp.json`, `.npmrc`,
`credentials.json`, `docker-compose.yml` + `Dockerfile`, `infra/terraform/terraform.tfvars`,
`infra/k8s/secrets.yaml`, `scripts/reveal.sh`. Every secret in it is fake.

**Drive the full lifecycle and watch each step like a user:**

| Step | Do | Watch for |
|---|---|---|
| Scan | `jit scan` (repo) and `jit scan .` | Does it find every planted secret? Right risk level? Any false negative on a real vendor token? Is the report readable? |
| Preview | `jit migrate --dry-run` | Plan matches what scan found? Nothing touched on disk? |
| Migrate | `jit migrate` (or per-file) | Files become mounts + `.pointers`; profiles created; confirm messages name real paths, not `<path>` |
| **Run the app** | `jit run -- npm start` then `curl localhost:<port>` | The **app** reads real values from the live-mounted `.env`; raw `cat .env` shows inert/decoy. This is the core promise — verify the app actually works. |
| Docker | `jit run -- docker compose config` / `up` (if docker present) | env reaches the container; no plaintext on disk |
| Terraform | migrate `terraform.tfvars`, then `jit run -- terraform plan` (if installed) | `TF_VAR_*` delivered; tfvars secret-shaped values vaulted, settings left |
| Reveal | `bash scripts/reveal.sh` under `jit run` | behaves; no unexpected plaintext leak |
| **Undo it all** | `jit migrate undo` / `jit migrate remove` | every file restored to plaintext exactly; vault + profiles cleaned; repo back to git-clean (`git status`) |

Then `rm -rf /tmp/jit-qa-playground` and confirm no playground secrets remain in the vault.

## 5. Per-surface QA (exercise / expect / hunt-for)

Work each surface as a user. Hermetic if you prefer, or reuse the playground.

### vault (`set` / `get` / `list` / `history` / `restore` / `rm`)
- **Exercise:** set a secret, list, get (round-trip), overwrite, `history`, `restore`,
  `restore --version <stamp>`, `rm` (single and **multi-path** `rm a b c`).
- **Expect:** values round-trip; overwrite archives the prior; restore flips reversibly; multi-path
  rm deletes all under **one** gesture and reports any missing path without stranding the rest.
- **Hunt:** flag consistency (`-y` accepted where help claims it is?); Touch ID demanded on every
  read/write/destroy (never rides the session); clear message on a missing path / no-history case;
  `list` never prints a value.

### scan
- **Exercise:** `scan` (whole machine), `scan <dir>`, `scan <file>` explicit; `--score`,
  `--fail-on <level>` (exit 2 when tripped, 0 on clean), `--format ndjson`, `--full`, `--unfiltered`.
- **Expect:** dir walk uses name rules; an explicitly named file gets the content sweep (bare
  `ghp_`+36, JWT, `AKIA` non-EXAMPLE all caught); placeholders (`EXAMPLE`, low-entropy) filtered.
- **Hunt:** false negatives on real-shaped tokens; false positives on settings; ndjson valid &
  redacted; fix-hint names the real path; is the machine-wide summary honest about what it skipped?

### migrate (+ flags) / mounts / profiles
- **Exercise:** `--dry-run`, real migrate of `.env`/`tfvars`/`.npmrc`/`.mcp.json`; `--only <cats>`;
  `--mount` on a loose/bare secret; `migrate undo`; `migrate remove`.
- **Expect:** file→FIFO mount + git-safe `.pointers`; `jit run` injects real values, ambient stays
  empty; `--only` scopes precisely; undo restores byte-for-byte.
- **Hunt:** does the mount serve decoy when locked and real only inside `jit run`? does `--only`
  leak an out-of-scope file? does undo/remove leave orphan profiles or secrets (a real past bug)?

### run / export
- **Exercise:** `jit run --profile`, project-`.env` `jit run`, `--live` vs compat swap, `--with
  netrc`; `jit export` + `eval "$(jit export)"`.
- **Expect:** secrets only in the child process; compat file inert; grants scoped to the run.
- **Hunt:** anything leaking to the parent shell; `--live` vs default behavior as documented.

### wrap
- **Exercise:** `wrap add --env`, `--grant`; run the tool through the shim; `wrap list`/`jit doctor --wrap`/`wrap undo`.
- **Expect:** shim injects JIT into that one process; `undo` removes shim+profile+PATH line, keeps vault.
- **Hunt:** honest `jit doctor --wrap` (PATH/real-binary checks); catalog tool discovery.

### clisso / aws credential_process
- **Exercise:** `clisso-capture` (real clisso, or a fake emitting the credential_process JSON);
  `aws configure list`; a real `aws sts get-caller-identity`.
- **Expect:** cred JSON captured off stdout (never echoed), stored `aws-<app>`, `~/.aws/config`
  wired; `aws` reports `custom-process`; a real call reaches AWS (`InvalidClientTokenId` on fakes =
  creds delivered end-to-end).
- **Hunt:** stdout stays clean for scripts; nothing written to `~/.aws/credentials` in plaintext.

### docker / git credential helpers
- **Exercise:** migrate `~/.docker/config.json` and `~/.git-credentials` (backed up first!); run the
  helpers (`docker-credential-jit get`, `git config credential.helper`).
- **Expect:** helper scripts on PATH; config routes to them; helper returns creds from the vault.
- **Hunt:** it refuses to steal a registry from a helper you configured; git config left sane.

### service / consent
- **Exercise:** `jit service status/ttl/restart`; `jit service consent` (prints state), `consent on`,
  `consent off`; then trigger a migrated credential from a new process and observe the per-process
  consent prompt (who's asking, count on refusal).
- **Expect:** consent on = a fresh Touch ID the first time each tool reaches a credential, remembered
  for the session; a refusal pauses that caller (escalating) without a lasting lockout; `consent off`
  is itself Touch-ID-gated and restarts the service.
- **Hunt:** a credential served silently when consent is on; a refusal that hard-locks; the prompt
  not naming the real caller; `consent off` not actually loosening (or not gated).

### audit / status / doctor / rekey
- **Exercise:** `audit` + `--kind/--status/--since/--parent/--secret/--grep/--follow`; `status` +
  `--secrets`; `doctor` + `--json/--orphans/--verbose`; `vault rekey`.
- **Expect:** audit records commands (secrets masked), unlocks, errors; status reconciles vault vs
  profiles; doctor json is valid; rekey re-wraps and every secret still decrypts.
- **Hunt:** audit masking never leaks a value; doctor/status numbers agree with reality.

## 6. Cross-cutting hunts (do these across ALL commands)

- **Flag consistency:** `-y/--yes`, `--quiet`, `--json/--format`, `-h` behave the same everywhere;
  help text matches actual accepted flags (the `restore -y` mismatch was exactly this).
- **Output style:** consistent with the house style (docs/design); no raw Go errors surfacing to
  users; hints name real paths, not literal `<path>`.
- **Error quality:** feed each command a bad path, a missing secret, a locked state — is the message
  a clear next step or a stack trace?
- **Touch ID enforcement:** every vault read/write/destroy prompts; nothing that touches a secret
  value silently rides the session when it shouldn't.
- **Reversibility:** every mutating command (migrate, wrap, unmount, rekey) has a clean inverse that
  leaves no orphan profiles/secrets/mounts.
- **Version/upgrade:** `jit version`, `jit upgrade --help` sane; service self-restart onto a new build.

## 7. Known-gotcha watchlist (regression guards)

Re-check these each time — they've bitten before or are inherent edges:
- `cp`-over-running-binary → SIGKILL 137 (install must be atomic). *(pre-flight)*
- `vault restore` and `-y`: does help still over-promise `-y` "on every command"?
- `vault delete` blocked by a live mount with no non-plaintext escape — still the case? note it.
- `migrate remove`/`undo` leaving orphan secrets a prior release fixed — confirm still fixed.
- stale service on old build after upgrade/restart.

## 8. The delete drill (destructive — deliberate, export-first)

Only on a mount-free vault (or after unmounting your own mounts). Proves the disaster-recovery path:
```
jit vault export /tmp/qa-backup.jitx     # passphrase; safety net
jit vault delete                         # destroys keychain key too
jit vault init                           # fresh vault, new master key
jit vault import /tmp/qa-backup.jitx      # restore
jit vault get <a-known-secret>           # decrypts under the NEW key → round-trip proven
```
**Hunt:** the mount guard fires when it should; export/import round-trips; nothing of the user's is lost.

## 9. Findings report (what I hand back each run)

```
## jit <version> pre-release QA — <date>

Verdict: SHIP / SHIP WITH NOTES / DO NOT SHIP

Coverage: <surfaces exercised; script default/full; playground yes/no>

Findings:
  [BLOCKER] <one-liner> — repro — expected vs actual
  [MAJOR]   ...
  [MINOR]   ...
  [NIT]     ...

Regressions vs <prev version>: <none | ...>
Notes / accepted gaps: <...>
State: vault restored to baseline (list/status match pre-run)
```

Keep it to what I actually observed. If a step was skipped (tool not installed, etc.), say so —
never imply coverage that didn't happen.
