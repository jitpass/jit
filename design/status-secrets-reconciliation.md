# Spec: reconcile vault and profiles in `jit status`, retire `jit profile list`

Status: proposed (2026-07-23)
Scope: `jit status` output + JSON, a new `--secrets` detail view, deprecation of `jit profile list`.
Non-goals: detecting plaintext secrets on disk (that is `jit scan`'s job), any secret decryption, any Touch ID prompt.

## Problem

`jit profile list` and `jit vault list` answer two different questions and nothing
tells the user that. On a real machine:

- `jit profile list` (from a project dir) shows **3** manifests: `mcp-caido`,
  `mcp-internal-tool`, `mcp-jamf`.
- `jit vault list` shows **20 groups, 65 secrets**: descope, `custom_scripts-jamf`
  (14 keys), notion, wiz, hibob, terraform tfvars, the playgrounds, npmrc,
  `services-api`, and the three mcp groups.

`profile list` is scoped to `.jit/profiles/` in the current directory. The vault is
a flat, global store. So a secret existing in the vault says nothing about whether
anything references it from where the user is standing. The 17 non-mcp groups are
either wired from another project directory, or genuinely orphaned. Two are already
known-bad: `custom_scripts-wiz` duplicates `wiz`, and `jitpass-playground-bak` is a
stale backup. Nothing in `profile list` surfaces any of this.

The naming collisions make it worse: vault group `custom_scripts-jamf` (14 keys,
`JAMF_CLIENT_ID...`) and profile `mcp-jamf` (3 keys, `JAMF_PRO_CLIENT_ID...`) are two
unrelated Jamf integrations that share a word.

`profile list` structurally can only ever say "manifests in this folder." The thing
the user actually wants is a **reconciliation**: for this project, which vault groups
are wired to a profile, which are stored but referenced only elsewhere, and which are
referenced by nothing jit can see.

## The three states

For a vault secret path `P`, computed read-only from the current working directory:

| State | Definition | Meaning |
| --- | --- | --- |
| **wired here** | `P` is referenced by a **project-local** profile (a `.jit/profiles/*.yaml` under cwd) | This project actively uses it. |
| **managed elsewhere** | `P` is referenced by a **global** profile or by a **registered mount's** profile, but not by any project-local profile | Stored and reachable, just not by this project's local config. |
| **unreferenced here** | `P` is referenced by nothing jit can see from here | Candidate orphan: may belong to a different project, or be genuinely dead. |

A fourth leg, **loose plaintext** (secrets never migrated into the vault, e.g. the
Jamf creds still in `~/ai_security_workspace/.mcp.json`), is deliberately out of scope
for `status`: it requires scanning the filesystem, which is `jit scan`'s job. `status`
only points at it (see UI copy below), it does not detect it.

### Why not just "referenced / not referenced"

`collectReferencedPaths` (internal/cli/vault.go) already computes a single
referenced-set by unioning project-local profiles, global profiles, and mount
profiles. `jit vault orphans` keys off exactly that union. The reconciliation view
needs the union **split** into project-local vs (global + mount), because "my project
uses it" and "it is merely reachable" are the two things the user is trying to tell
apart. So the implementation refines `collectReferencedPaths`, it does not replace it.

## Data model

Reuse what exists. No new provenance, no envelope changes.

- All secret paths: `vault.List()` then `splitBackupPaths` (drops `_backups/...`),
  exactly as `gatherVaultStatus` and `jit vault orphans` already do.
- Group = first path segment (`P` up to the first `/`), same grouping
  `printOrphanGroups` (vault.go) and `jit vault list` use.
- Project-local referenced-set: union of `profile.LoadFile(info.Path)` values over
  `profile.ListAll(cwd)` entries whose `info.Scope == profile.ScopeProject`.
- Elsewhere referenced-set: union over `ScopeGlobal` entries **plus** every registered
  mount's `ProfilePath` (`mount.LoadRegistry`).
- Per group, tally members by state. A group is reported by its dominant state, with a
  count when members disagree (rare, but a re-migration can split a group).
- Origin/age for the unreferenced list: `v.Info(P).Origin` / `OriginSeenUnix`, rendered
  by the same helper `printOrphanGroups` already uses, so a secret that belongs to
  another project is recognizable before anyone acts on it.

Factor a shared helper so the rollup and the detail view can never disagree, mirroring
how `runProfileCheck` is shared by `jit status` and `jit doctor` today:

```go
// internal/cli/secretsreconcile.go (new)
type secretState int
const (
    stateWiredHere secretState = iota
    stateManagedElsewhere
    stateUnreferenced
)

type secretGroup struct {
    Name        string           // first path segment, e.g. "custom_scripts-jamf"
    Members     []string         // full vault paths in the group
    State       secretState      // dominant state
    Mixed       bool             // members disagree on state
    ProfileName string           // the project-local profile that wires it, if any
}

type secretsReconciliation struct {
    Groups        []secretGroup
    TotalSecrets  int
    TotalGroups   int
    WiredGroups   int
    ElsewhereGroups int
    UnrefGroups   int
    UnrefSecrets  int
}

func reconcileSecrets(root, cwd string, v *vault.Vault) (secretsReconciliation, error)
```

## `jit status` text output

Replace the single `Profiles:` line (status.go:341-352) with a `Secrets:` section.
Keep it a rollup: counts per bucket, then point at the detail command. Do not list
groups inline (the whole point is that there can be 20 of them).

Existing line:

```
Profiles: 3 profile(s), 6 secret reference(s) all resolve cleanly. Run `jit doctor` to also verify secret integrity.
```

New section (healthy-ish example matching the real machine above):

```
Secrets: 65 stored in 20 groups.
  Wired here:        3 groups via 3 profiles (6 references), all resolve.
  Managed elsewhere: 0 groups (referenced only by global profiles or mounts).
  Unreferenced here: 17 groups, 59 secrets. May belong to another project.
                     Run `jit status --secrets` to inspect, `jit vault orphans` to prune.
```

Rules:

- The "all resolve" clause on **Wired here** carries the existing `runProfileCheck`
  existence result. If a wired reference is broken (secret missing), that line turns
  red and reads `N reference(s), M problem(s), run jit doctor for details`, preserving
  today's behavior for the wired set.
- **Unreferenced here** is yellow when non-zero (advisory, not an error, matching
  `jit doctor --orphans`), plain when zero (`Unreferenced here: none.`).
- When there are unreferenced groups **and** the current project has any plaintext-prone
  config nearby, we still do not scan from `status`; the pointer copy is fixed:
  append `; \`jit scan .\` to find secrets still in plaintext.` only when cwd looks like
  a project (has a `.jit/` dir). Keep it a hint, never a claim.
- Empty vault keeps the existing "no secrets stored yet" line unchanged.

## `jit status --secrets` (new detail view)

This is where the retired `profile list` content lives, enriched into the full
reconciliation table. Text form:

```
Wired here (3 groups, 3 profiles):
  mcp-caido           1 secret   profile mcp-caido (.jit/profiles/mcp-caido.yaml)
  mcp-internal-tool   2 secrets  profile mcp-internal-tool (.jit/profiles/mcp-internal-tool.yaml)
  mcp-jamf            3 secrets  profile mcp-jamf (.jit/profiles/mcp-jamf.yaml)

Managed elsewhere (0 groups): none.

Unreferenced here (17 groups, 59 secrets):
  custom_scripts-jamf/ (14)   from ~/ai_security_workspace/scripts/jamf/.env, seen 3d ago
  wiz/ (5)                    from ~/... , seen 5d ago   [duplicate of custom_scripts-wiz]
  jitpass-playground-bak/ (1) no recorded origin (pre-provenance, or set directly)
  ...
  Inspect with `jit vault list`, prune with `jit vault orphans --prune`.
```

The Unreferenced block is exactly `printOrphanGroups`' output (reuse it verbatim), so
the detail view and `jit vault orphans` render identically. The duplicate annotation is
a stretch goal: flag when two groups hold the same key set (the vault-list footer note
already computes this).

`--secrets` is a flag on `status`, not a subcommand, matching `--format json`.
`jit status --secrets --format json` emits the full `secretsReconciliation` including
per-group members.

## JSON shape change

`statusResult.Profiles` (`statusProfiles`) is replaced by `statusResult.Secrets`
(`statusSecrets`). Pre-1.0, so a clean rename rather than a compatibility shim.

```go
type statusSecrets struct {
    TotalSecrets      int `json:"total_secrets"`
    TotalGroups       int `json:"total_groups"`
    WiredGroups       int `json:"wired_groups"`
    WiredProfiles     int `json:"wired_profiles"`
    WiredReferences   int `json:"wired_references"`
    WiredProblems     int `json:"wired_problems"`
    ManagedElsewhere  int `json:"managed_elsewhere_groups"`
    UnreferencedGroups  int `json:"unreferenced_groups"`
    UnreferencedSecrets int `json:"unreferenced_secrets"`
    // Groups present only with --secrets, to keep the default snapshot small.
    Groups []statusSecretGroup `json:"groups,omitempty"`
}
```

`gatherProfileStatus` (status.go:248) is replaced by `gatherSecretsStatus`, which calls
the shared `reconcileSecrets` and additionally runs `runProfileCheck` for the wired
problem count (so the existing existence-check semantics survive intact).

## Retiring `jit profile list`

- `jit profile list` stays registered for one release as a **deprecation shim**: it
  prints its existing table (so no one's scripts break today) preceded by a stderr
  notice: `note: 'jit profile list' is deprecated; use 'jit status --secrets' for the
  full picture (which secrets are wired, managed elsewhere, or orphaned).`
- `jit profile show <name>` stays as-is. Nothing replaces the per-profile
  variable-to-vault-path mapping, and it is not the source of the confusion.
- After the deprecation window, remove `profileListCmd` (profile.go:54-88) and its test.
  `completeProfileNames` (profile.go:128) stays; it backs `profile show` and every
  `--profile` flag.
- Update `jit profile`'s group `Long` (profile.go:46) to stop advertising `list`.

### Update (v0.44.0): whole command removed, not just `list`

The deprecation shim shipped in v0.36.0 as planned above. In v0.44.0 the retirement
was taken all the way: the entire `jit profile` command was removed — `list`, `show`,
and the parent — with no shim, so `jit status --secrets` is now the single
vault/profile reconciliation surface and `jit doctor` verifies a profile's secrets.

Divergences from the plan above:

- `jit profile show` was **not** kept. Its per-profile variable-to-vault-path mapping
  has no direct replacement; `jit status --secrets` is the recommended surface, and
  a manifest under `.jit/profiles/` is plaintext (names and vault paths only) if you
  need the raw mapping.
- `completeProfileNames` survived, moved to `internal/cli/profilecomplete.go`; it now
  backs only the `--profile` flags (run/export/doctor/aws/k8s/sops), since `profile
  show` is gone. `LoadWithScope`/`ListAll` stay (doctor + completion).
- `profile.go` and `profile_test.go` were deleted; docs-gen dropped the three
  `jit_profile*.md` reference pages; every help string, error, and doc that named
  `jit profile list`/`show` now points at `jit status --secrets`.

## Files touched

- `internal/cli/secretsreconcile.go` (new): `reconcileSecrets` + shared render helpers.
- `internal/cli/status.go`: swap `statusProfiles`->`statusSecrets`,
  `gatherProfileStatus`->`gatherSecretsStatus`, rewrite the section in
  `printStatusText`, add `--secrets` flag and its detail renderer.
- `internal/cli/vault.go`: extract the split (project-local vs elsewhere) out of
  `collectReferencedPaths` so both it and `reconcileSecrets` share one implementation.
- `internal/cli/profile.go`: deprecation notice on `profileListCmd`, update `Long`.
- Tests: `status_test.go` (new section + `--secrets`), `profile_test.go` (deprecation
  notice), a `secretsreconcile_test.go` covering the three states + mixed group.
- Docs: `docs/reference` status page, `docs/USAGE.md`, `COMMANDS.md`.

## Verification

- `jit status` on the real 20-group vault shows 3 wired / 0 elsewhere / 17 unreferenced,
  59 unreferenced secrets, matching hand-count from `jit vault list`.
- `jit status --secrets` lists the same unreferenced groups, in the same order and with
  the same origins, as `jit vault orphans`.
- From a directory whose project-local profile wires a group, that group moves from
  "unreferenced" to "wired here"; `cd` away and it returns to unreferenced (proving the
  scope split, not just the union).
- Read-only: no Touch ID, no secret value ever printed, safe to run repeatedly (same bar
  as `jit doctor` / `jit status` today).

## Open questions

1. Detail view as `--secrets` flag vs `jit status secrets` subcommand. Flag chosen for
   parity with `--format json`; revisit if it grows options.
2. Do we ever want "managed elsewhere" to name *which* other project? We only know Origin,
   not the referencing project's path, so probably no. Origin + age is the honest signal.
3. Duplicate-group detection in the detail view: reuse the vault-list footer's logic, or
   leave it to that footer. Stretch goal, not blocking.
