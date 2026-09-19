# Doctor repair: knowing who launches a profile, and fixes that can't break one

**Status:** Phase 1 built 2026-09-19 (jit branches `migrate-mcp-atomic`,
`doctor-origin-scope`, `vault-rm-in-use`; app branch `doctor-safe-actions`).
Phase 2's foundation (F1, F2 and the owner list) built 2026-09-19 on
`launcher-map`, with no output change. The rest of Phase 2, and Phase 3, are
plans. Covers `jitpass/jit` and the
Doctor window in `jitpass/jit-app`. Every claim below was checked against the
code and this Mac on 2026-09-19, and corrected where the check disagreed.

## The incident

In the Doctor window the user clicked **Remove Secrets** on two "Origin files
gone" rows. After the app's confirmation and a fresh Touch ID, it ran
`jit vault rm mcp-google-workspace-investigate --yes` and
`jit vault rm mcp-okta-mcp-server --yes` (audit log, 10:28:50 and 10:31:37).
Each recheck showed new **Missing secrets** rows. `inject.Resolve` fails on the
first missing secret, so the `google-workspace-investigate` and
`okta-mcp-server` servers in `~/Security-Ops/.mcp.json` **no longer start at
all**. `Vault.Remove` deletes version history too, and no export exists, so
`GOOGLE_CLOUD_PROJECT`, `OKTA_ORG_URL` and `OKTA_SCOPES` must be re-entered.

Five faults lined up:

1. **Doctor's advice.** `originGoneFindings` only reports secrets a profile
   still references (`profilecheck.go`, `if !referenced[p] continue`), yet its
   action offers `jit vault rm <group>`. Following it always breaks a profile.
   It names only `groups[0]` when a row lists several. (Its comment even says
   "No action line", then sets one.)
2. **The app.** The group note keeps "nothing to do if you still use them",
   but the row's only action is the red delete. The confirmation names the
   command, not the profile that breaks. `vault rm` printed its own "wired to
   profile X" warning before its y/N, but `--yes` meant nothing stopped for it,
   and the app discarded the output.
3. **The engine never refuses.** `vault rm`'s reference warning is advisory,
   and `--yes` skips everything but Touch ID. The Touch ID reason says "delete
   the secret …", not which profile breaks.
4. **Ownership nobody acts on.** MCP profiles carry a `.source` sidecar naming
   the config that created it (not all: `mcp-google-workspace` and
   `mcp-urlscan` have none). Five name
   `~/Documents/ai_security_workspace/.mcp.json`, which is deleted, and all five
   are launched by `~/Security-Ops/.mcp.json`. `claimMCPNamespace` compares the
   recorded path as a string, so a gone owner still counts as foreign.
   `vault rm`'s warning, the vault list footer and `migrate remove` read the
   sidecar, but nothing reports a gone owner.
5. **"Referenced" is not "launched".** Doctor knows which profiles name a
   secret. It does not know which configs, helpers, pointer files or project
   scripts launch a profile. Every delete decision needs that answer.

## The same flaw elsewhere

- **`jit vault duplicates`:** `pickRemoval` prefers the copy whose origin is
  gone before checking whether a profile uses it, and then prints
  `jit vault rm <paths>` for a referenced copy (`vaultduplicates.go:682,701`).
  `vaultduplicates_test.go:71-77` asserts exactly that.
- **Lenient reference lookup in deleting commands:** `duplicates --prune` and
  `migrate remove` build their "still used" set with `referencesForPaths`,
  which skips unloadable profiles and ignores list errors
  (`vaultrefs.go:67-92`, `migrateremove.go:1003-1016`). That breaks the
  fail-closed contract written for deleting callers (`vault.go:2106-2113`).
- **Project stores are invisible from `~`:** every reference check uses
  `ListAll(cwd)`: cwd's own `.jit/profiles`, the global store and mounts, no
  walk. `~/Security-Ops/.jit/profiles` holds 4 `custom_scripts-*` profiles,
  launched by `jit run ./run_all_exports.sh` from a terminal. From `~` they are
  unseen, so their secrets look orphaned and "Delete All" would remove them.
- **Pointer files:** `~/.clisso.yaml` holds `jit://vault/wrap-clisso/…`
  references that no profile names. `orphans --prune` treats them as orphans.
  One points at a secret that no longer exists, and nothing reports it.
- **The app's Delete Profile** (`ProfileStore.trashGlobal`) trashes only the
  manifest. It leaves the sidecar and the secrets, needs no Touch ID, runs no
  launcher check and is not in `jit audit`. It is hidden today only because of
  the scope-label bug (F3). Fixing F3 alone would switch it on.
- **Delete chains:** unwrapping a tool and trashing a profile both leave
  secrets behind, and "Delete All" orphans then removes them.

## What re-migrating would do today

`jit migrate ~/Security-Ops/.mcp.json` is not the fix it looks like:

- `needsMCPMigration` selects only entries with plaintext or more than one
  wrapper layer. `jamf` and `urlscan` are never touched.
- Servers run in sorted order. `caido` bumps past `mcp-caido` (foreign owner)
  and `mcp-caido-2` (ai-bugbounty) to `mcp-caido-3`, and writes the secret,
  manifest and sidecar at once (`mcpconfig.go:425-446`).
- `google-workspace-investigate` then fails in `carriedProfileValues`: its
  outer profile names a deleted secret, an error by design. The run aborts
  (`mcpconfig.go:280`) with `mcp-caido-3` already written. The config is not
  rewritten. There is no rollback.
- Even with every value present, the result is `-2`/`-3` copies beside the
  untouched originals.
- `jit migrate remove <config>` refuses a path that doesn't exist. Pointed at
  `~/Security-Ops/.mcp.json` it takes the whole Security-Ops project, because
  `~/Security-Ops/.jit` exists.

## Principles

- **A fix must not create a finding worse than the one it clears.** Every
  delete path checks the launcher map (F1) and fails closed.
- **The engine refuses, not only the app.** Scripts and the app pass `--yes`.
  A delete that would break a profile needs an explicit flag.
- **Doctor stays read-only.** No `doctor --fix`: `design/jit-path-refresh.md`
  rejected it, because it opens a write path in a report and rebuilds what
  migrate already has. Doctor names the command. The command that owns the
  consent runs it. The app gets that command as structured data.
- **Say "no known launcher", never "unused".** Scripts, aliases and a bare
  `jit run` can't be discovered. A project-scope profile never gets a
  deletable verdict.
- **Deleting a profile removes its manifest, its sidecar and every secret no
  other profile or pointer references.** Secrets alone break the profile. The
  profile alone leaves orphans.
- **Ownership is bookkeeping, not a runtime gate.** `jit run` never checks
  which folder launched it: the caller can't be identified reliably, and
  `aws-prod` or a wrapped tool is meant to run from anywhere.

## Foundation

**F1. The launcher and reference map.** A read-only function returns, for
every profile and every vault path, what uses it. It is strict: an unreadable
manifest or config is an error for deleting callers, never a skip.

| source | where | today |
|---|---|---|
| MCP entries, **every** wrapper layer | discovered configs | outer layer only |
| AWS `credential_process --profile` | `~/.aws/config` | only the jit path is checked |
| kubeconfig exec args | `~/.kube/config` (`$KUBECONFIG` is read by nothing) | only the jit path |
| wrapped tools | `~/.jit/wrap.json` | yes |
| mounts | `mounts.yaml` | yes |
| docker/git/terraform/cargo helpers | helper scripts | jit path only |
| shell rc | the `jit export --profile` marker in the rc file itself (not the backups index, which Phase 3's prune would erase) | no |
| pointer files | `jit://vault/...` in `~/.clisso.yaml` and other pointer files | no |
| project profile stores | every `.jit/profiles` under `~` (`discoverNestedProjectRoots`) | cwd only |

Last use from `agent-history.jsonl` is evidence, never a verdict.

**Built (`launcher-map`).** `internal/launchers` (`Discover`), read-only and
below `internal/cli`. Every row above is read, plus Claude Desktop,
`~/.claude.json`, VS Code's user and per-profile `mcp.json` and Windsurf's
`mcp_config.json` as fixed files. A launcher attaches to profiles the way
`jit run` resolves a name: every global profile of that name, a project one
only from inside its project. A by-name launcher (MCP, AWS, kube, env-wrap,
rc) that resolves to nothing is `Broken`. A pointer whose secret the vault
lacks is a `MissingPointer` when the caller passes `SecretExists`. Every
unreadable source is a `SourceError`. `Strict` turns any of them into a
failed discovery; `Map.Err(sources...)` lets a caller be strict about some.
Phase 1's `collectVaultUsers` is now this map flattened by vault path, strict
about profiles, mounts and pointers as before. `LaunchedBy` still shows MCP
launchers only, so no output changed. Not read: `$AWS_CONFIG_FILE` and
`$KUBECONFIG` (no jit writer honours them), grant and capture wraps (they
name a mount or a capture command, counted through the registry and
`~/.clisso.yaml`). Helpers name no profile, so a helper script counts as a
launcher of every global profile under its prefix (`docker-`, `git-`,
`terraform-`, `cargo-`).

Checked on this Mac: `aws-dev` and `aws-admin` are broken launchers in
`~/.aws/config`; `k8s-docker-desktop`, `token` and `zsh_history` have no
known launcher; `mcp-okta` is launched only as the inner layer of
`okta-mcp-server`; the four `custom_scripts-*` profiles are seen from `~`.
Two pointers name missing secrets: `~/.clisso.yaml` →
`wrap-clisso/blockaid-client-secret`, and
`~/Documents/jitpass-playground/.env.bak` → `jitpass-playground-bak/API_KEY`.

**F2. Discover from home.** Discovery walks down from cwd today. From a
subfolder it misses `~/Security-Ops`. From `/` it walks the whole disk and finds
each config twice via `/System/Volumes/Data`. Always start at `~`, plus the
fixed files, plus VS Code's user `mcp.json` (under `Library`, pruned by name
today) and Windsurf's `mcp_config.json`. A "nothing uses it" verdict is only
issued when the walk covered `~`.

**Built (`launcher-map`).** `Discover` walks `~` once for project stores,
pointer files and MCP configs, pruning what migrate prunes plus the Trash. It
refuses a home of `/`. `Map.Coverage` records whether it read `~` and which
directories it could not enter; `Coverage.Complete()` is the precondition for
`unlaunched`. The editor configs are launcher sources only:
`audit.FixedMCPConfigPaths` is unchanged, so `jit scan` and `jit migrate` see
the same files as before. Doctor's `mcpFindings` still walks from cwd; moving
it onto `Map.MCPEntries` changes doctor's output and waits for a preview.

**F3. Scope label.** `profile.ListAll` and `LoadWithScope` label
`~/.jit/profiles` as `project` when cwd is `~` and skip the global pass. That
explains doctor's `(project)` on global profiles and `jit status`'s
`wired_profiles: 15`. Label them `global`. **Ship it with the app's Delete
Profile removed or routed to `jit profile rm` in the same release.**

## Phase 1: stop the harm

jit:
- **`vault rm` refuses a referenced path** unless `--break-profiles` is given
  (name to settle). It is a refusal, not a trash can, so "rm means gone"
  (`vault.go:555`) stands. Add `--dry-run --format json`, so the app can show
  the expanded paths and affected profiles *before* confirming. Put the
  profile name in the Touch ID reason.
- **Strict references** in `vault rm`, `orphans --prune`, `duplicates --prune`
  and `migrate remove`, all through one collector covering project stores and
  pointer files (the F1 subset these need now).
- **origin_gone:** drop the `vault rm` clause, list every group, add the
  referencing `profiles` to the JSON. Fix the self-contradicting comment.
- **duplicates:** a referenced pick gets no `vault rm`. Invert the test.
- **Atomic MCP migrate:** validate every selected server (namespace claim,
  carried values readable) before writing anything.
- **Structured fixes in doctor JSON:** `fixes: [{argv, destructive,
  presence}]` beside the prose `action`, so the app stops parsing backticks
  and guessing "destructive" from a prefix.
- **service:** move the build-mismatch and missing-binary commands from
  `detail` to `action`.
- **Audit:** a delete event naming the expanded paths and the profiles that
  lost a secret. The app may pass an action label as audit-only context.
- **F3**, with the app change above.
- Terminal text changes here (origin_gone, the rm refusal) get a preview script
  first. Changed help text for `vault rm`, `orphans`, `duplicates` needs
  `docs-gen`.

App:
- origin_gone rows lose **Remove Secrets**.
- Delete Profile goes, or runs `jit profile rm` once it exists.
- Destructive confirmations come from `--dry-run --format json`: they name the
  paths, the profiles affected and the count, before anything runs.
- **Snapshot drift:** Delete All and the maintenance sheets confirm a list
  that can be 300s old, while `--prune --yes` deletes what qualifies at run
  time. Prune takes the explicit paths, or an `--expect <digest>`, and refuses
  on a mismatch.
- `mount_stale` stops passing `--yes`: it would also skip unmount's "write
  PLAINTEXT back" question if the manifest reappears.
- `install`: when the extra copy is Homebrew's, the options are
  `brew uninstall jitpass` (which now removes the app) or `sudo rm <winner>`.
  The confirmation's "jit asks once more" is false for both.
- `1password_link`: `<op://…>` is caught as a file placeholder and opens a file
  panel. Treat it as a reference.
- The "Missing secrets" note says a tool "gets an empty value". It doesn't
  start at all. Fix the wording.
- Read `schema_version`. Mark an unknown fix destructive unless the engine says
  otherwise. Terminal commands run whatever `jit` is on PATH, which may be
  older than the bundled one.
- Unique row ids (`DoctorItem.id` collides without path or profile). Per-row
  busy state like the Vault window's `vaultBusy`. Buttons disabled while
  anything runs.
- Tests: `DoctorReportTests` pins the old origin_gone and mount_stale
  behaviour and a fake `"global"` scope. Update them.

## Phase 2: ownership

**Owners are a list (decided 2026-09-19).** A profile's `.source` sidecar
holds one config path per line. A single line is today's format, so every
existing sidecar stays valid.

**Built (`launcher-map`):** `migrate.ProfileOwners`, `ReadProfileOwners`,
`LiveProfileOwners`, `WriteProfileOwners` and `OwnerFile`.
`ProfileOwnerConfig` returns the first owner. `claimMCPNamespace` treats a
sidecar that lists this config as its own and keeps the other owners when it
refreshes. It still bumps on a list without this config, live owners or not:
the adopt rule below is not built.

- **Same values, several configs:** one profile, every config an owner. No
  copies, so a rotation happens once, and doctor and the app can say "used by
  A, B".
- **Different values:** separate profiles, as today (`claimMCPNamespace`
  already bumps when a stored value differs).
- **An older jit reading a multi-owner sidecar** sees a mismatch and bumps. It
  makes a copy and never overwrites, so a downgrade is safe.
- An owner whose file is gone doesn't count. A profile is deletable only with
  no live owner **and** no known launcher.

New findings (each gets a preview script first):

| kind | severity | when | fix |
|---|---|---|---|
| `owner_gone` | warning | an owner file is gone, a live config launches the profile | `jit profile adopt <config> <profile>` |
| `unowned_launch` | warning | a config launches a profile it doesn't own (a copied config) | `jit profile adopt <config> <profile>` |
| `unlaunched` | warning, permanently (decided) | global profile, no live owner, no known launcher, walk covered `~` | `jit profile rm <profile>` |
| `launcher_broken` | problem | a launcher names a profile that doesn't exist (`aws-dev`, `aws-admin` in `~/.aws/config`) | mint it (`clisso get`), or `jit migrate undo <file>` |
| `pointer_missing` | problem | a `jit://vault/...` pointer names a missing secret (`~/.clisso.yaml` today) | `jit vault set <path>` |

Correlation:
- A **missing** secret on a profile with no known launcher gets
  `profile rm`, not `vault set`. `k8s-docker-desktop` came from a kubeconfig
  that has since been deleted.
- A **missing** secret in the outer layer of a nested entry gets one combined
  fix, not a `set` row plus a `migrate` row.

Migrate:
- `claimMCPNamespace` reads the owner list: this config already an owner →
  refresh; every other owner gone and this config launches it → adopt; values
  identical → add this config as an owner; otherwise bump.
- Nested collapse lands on the adopted outer profile.
- `jit migrate remove <project>` drops that project's configs from each owner
  list and deletes a profile only when the list is then empty. It also has to
  count copied projects' profiles as users (today it skips other trees).

Commands, explicit by decision so the app can run them and doctor can name
them. Both need `docs-gen`.
- `jit profile adopt <config> [profile...]`: adds the owner and drops gone
  ones. With no profiles it adopts every profile that config launches but
  doesn't own. It widens what a later `migrate remove` of that config
  deletes, so it shows that and asks y/N. No Touch ID, no secret read.
- `jit profile rm <profile>`: manifest, sidecar and every secret nothing else
  uses. Refuses a profile with a launcher. y/N plus fresh Touch ID. Reuses
  `migrate.RemoveOwnedProfile`.

## Phase 3: other things that go stale unnoticed

| gap | seen here | fix |
|---|---|---|
| guard hook drift: rc line and hook file disagree, or the hook differs from `HookScript()` after an upgrade | not checked | `jit guard history` (idempotent) |
| launchd plist runs a deleted or foreign jit while the service is stopped | repointed only by restart and upgrade | `jit service restart` |
| migrate backups whose original file is gone: 129 files, 141 of 285 backups; 20 stale | `status` counts stale ones, doctor nothing | `jit vault prune`; new `--gone` for the deleted-original case |
| plaintext `*.jit-bak-*` from old builds | `jitpass-playground/package.json.jit-bak-…` | delete, or `migrate --clean` |
| `source <(jit completion zsh)` three times | `.zshrc` lines 118–120 | dedupe the rc lines |
| a mount path that is a regular file, not a FIFO | none today (all 9 are FIFOs). Serve may rename a FIFO over it: **verify before claiming** | unmount, re-migrate |
| wrapped tool no longer installed | detected, no action | `jit wrap undo <tool>` |
| 37 empty vault groups; `mcp-google-workspace.yaml` at 0644 | minor | cleanup in `vault prune` |

## Tests required

- Replay the incident: a referenced group whose origin is gone gets no
  `vault rm` from doctor, from duplicates, or from the app.
- `vault rm` refuses a referenced path without the flag, in every scope
  (global, project outside cwd, pointer file).
- Strict references: a malformed manifest makes every prune fail closed.
- A project store outside cwd is seen from `~`.
- Atomic migrate: a failing second server leaves no trace of the first.
- Prune refuses on snapshot drift.
- Owner list: multi-line sidecar round-trip; an old single-line one reads the
  same; an older-jit-style string compare bumps and never overwrites.
- App: no Delete Profile once scope is `global`; an unknown destructive fix is
  marked destructive; origin_gone has no destructive button.

## Order

1. Phase 1, jit then app pinned to it, one release pair.
2. F1 in full and F2, then Phase 2's owner list, commands and findings, then
   the migrate adopt rule.
3. Phase 3, one finding per PR.

## Decided (2026-09-19)

- `jit profile adopt` is an explicit command, not only a migrate side effect.
- `unlaunched` stays a warning. "No known launcher" is never proof of unused.
- One profile launched by several configs: one profile with a list of owners,
  not a split. Separate profiles only when the values differ.
- No `doctor --fix`, per `design/jit-path-refresh.md`. The app runs the named
  commands.
- `jit profile adopt <config> [profile...]`, config first. With no profiles
  it adopts every profile that config launches but doesn't own. (Was
  `adopt <profile> <config>`.)
- A profile doctor reports under "no known launcher" is dropped from
  origin_gone, so each profile appears in one section.
- A `missing` secret on a profile with no known launcher is reported under
  "no known launcher", not `[missing]`.
- Owners are a list in the `.source` sidecar, one config path per line; a
  single line is today's format. An owner whose file is gone doesn't count.
  Separate profiles only when the values differ.

## Still open

- The flag name for deleting a referenced secret (`--break-profiles`?).
- Whether unwrapping a tool should offer to delete its profile's secrets in
  the same step, closing the delete chain at its source.
