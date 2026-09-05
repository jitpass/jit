# Refreshing a recorded jit path: migrate owns what migrate wrote

**Status: proposed 2026-09-05. Supersedes the "PR 2 — `jit doctor --fix`"
section of `design/sessions-and-path-repair.md`, which loses for the
reasons in "Why not doctor --fix".**

## The defect

`jit doctor` reports a `~/.kube/config` whose exec command points at
`/opt/homebrew/Caskroom/jitpass/0.84.0/jit` — written by a jit that
predates `internal/selfpath`, deleted by the `brew upgrade` that followed —
and prescribes `jit migrate ~/.kube/config`. On an already-migrated file
migrate prints "Nothing to migrate: none of the path(s) you named contain
plaintext secrets jit can move" and changes nothing. Every run of doctor
shows the same `✗`; every run of the command it names does nothing. There
is no repair path for a recorded jit path anywhere in jit.

Doctor's prescription was right. Migrate wrote that line, backs the file up,
and undoes it; a stale line in it is migrate's to refresh. Migrate is wrong
because it looks for plaintext secrets and nothing else.

## What the code read established

- `discoverFileTarget` routes a named fixed path by exact match:
  `~/.aws/credentials`, `~/.kube/config`, the Terraform/Docker/git
  credential files, GCP ADC, netrc, pypirc. **`~/.aws/config` is not a
  target**, and neither are the three helper scripts under `~/.jit/shims`.
  So `jit migrate --only aws` — doctor's action for a stale
  `credential_process` line — cannot reach the file it is meant to fix.
- `applyMigrate` scopes `--only` through one `categorySlices` table keyed
  by `migrateCategories` token, with a fail-loud guard that every token
  has an entry; the "nothing to migrate" test is `total == 0` over that
  table; note-only slices (`tfvarsComplexOnly`, `wrapOwnedSkipped`) render
  as skip hints and are never counted.
- `printMigratePlan` is the one rendering both `--dry-run` and the real
  `[y/N]` share (`TestMigrateDryRunMatchesRealPlanExactly`); a category
  enters the plan via `printMigratePlanCategoryAnnotated` and the subtotal
  via the explicit slice list at its foot.
- `resolveJitExecutable` (`selfpath.Durable`) is a package var so tests can
  pin it; `TestEveryRecorderGoesThroughResolveJitExecutable` lists every
  file that records jit's path and fails any that resolves it another way.
- `BackupTracker.backupOnce` stores the pristine bytes encrypted, records
  the undo entry with the file's mode, and dedups per run; the CLI threads
  one tracker through every category's Apply loop.
- Doctor's detector (`jitPathArtifacts` + `recordedJitPath`, in
  `internal/cli/doctorsections.go`) already enumerates all five artifacts
  with a per-artifact anchor key, so an unrelated `/usr/bin/jit` in a
  comment is never a finding. It is the right rule; it lives in the wrong
  package for migrate to share.

## Why not `doctor --fix`

1. "Scan is read-only in every mode; migrate is the guided fix path" is a
   stated guarantee, and doctor sits on the read-only side of it. A `--fix`
   opens a write path in a report — under a generic name every future
   finding would have to decide whether it belongs to.
2. Migrate already has everything the fix needs, and doctor would rebuild
   it: encrypted backup into the undo ledger, `--dry-run`, the confirm
   before `openVault`, `--only`, per-file targeting, and the `Durable()`
   refusal with its message already written.
3. Home-wide `jit migrate` heals the not-yet-broken case
   (`[jit path: after the next upgrade]`) on any ordinary run — most of the
   value of an auto-heal, under a command the user typed, with a plan they
   can preview.
4. The plan already carries rows that are not secrets (`wraps`, the guard,
   the cache sweep). A `[recorded jit path]` row is the same shape.

## Decisions

**D1. The detector moves to `internal/migrate`.** `jitpathrefresh.go`:

    type RecordedJitPath struct {
        Label    string // "~/.kube/config", "the git credential helper"
        Path     string // the artifact
        Category string // the --only token that owns it: kube, aws, docker, git, terraform
        Recorded string // the jit path the line carries
    }
    func DiscoverRecordedJitPaths(home string) []RecordedJitPath   // all five, best-effort, read-only
    func (r RecordedJitPath) Stale() (reason string)              // "isn't there" / "version-pinned" / ""

Same table, same anchor keys, same regex as doctor's today. Doctor's
`jitPathFindings` becomes a consumer: kinds, details and action strings are
unchanged — they were right. `selfpath` sits below `migrate`, so
`VersionedBrew` is reachable.

**D2. A refresh is a counted plan row, scoped by its owning category.**
`discovered` gains `jitPaths []jitPathRefresh` (artifact path, category,
recorded path, reason). It counts in `total()`, in the plan subtotal, and in
the "nothing to migrate" test. `--only` scopes it by the artifact's
category — `--only aws` refreshes `~/.aws/config`, `--only kube`
`~/.kube/config` — so every action doctor already prints becomes true. No
new `--only` token: a refresh is maintenance of a category's artifact, not a
category.

**D3. Discovery.** A named artifact (`jit migrate ~/.kube/config`,
`~/.aws/config`, a helper under `~/.jit/shims`) checks its own recorded
path *in addition to* its category discovery, so a kubeconfig with both a
plaintext token and a stale exec line gets both rows. Bare `jit migrate`
checks all five: cheap, read-only, and independent of the scan — the scan
is about secrets and stays that way (`scan and migrate agree` is about what
scan promises, not what migrate may additionally maintain). The
"Nothing to protect" early return counts refresh rows.

**D4. Refusal is decided at plan time.** `resolveJitExecutable()` runs
during discovery — prompt-free, no vault — and an error turns every refresh
row into one note-only slice rendered like `tfvarsComplexOnly`:

    2 recorded jit paths can't be refreshed: this jit is running from a
    temporary or removable location (~/Downloads/jit); …
      ~/.kube/config, ~/.aws/config

Not counted, never applied, and shown even when it is the only content.
Today's alternative — every `Apply*` failing after the user confirmed — is
what this replaces.

**D5. Apply.** `RefreshRecordedJitPath(v, home, r, tracker)`: `backupOnce`
(pristine bytes, mode, undo record), then a line-anchored substitution —
only lines containing the artifact's anchor key, only the regex match equal
to `r.Recorded` — preserving every other byte, quoting included; write with
the file's own mode via `vault.AtomicWriteFile`. Idempotent by
construction: a durable path is not stale, so it is never a row. A durable
path containing whitespace or a quote is refused as a note (D4's slice):
the writers' quoting rules differ per artifact and the case does not occur
on a Homebrew or `/usr/local` install.

**D6. Rendering.** Plan, in the machine-wide group:

    [recorded jit path] 2
      → the jit these configs run is gone or version-pinned; rewritten to
        /opt/homebrew/bin/jit (backed up encrypted first)
      • ~/.kube/config (was ~/../Caskroom/jitpass/0.84.0/jit)
      • ~/.aws/config (was ~/../Caskroom/jitpass/0.84.0/jit)

Result, in the mutation log:

    [recorded jit paths refreshed] 2
      • ~/.kube/config -> /opt/homebrew/bin/jit; backup: jit vault get …
      • ~/.aws/config -> /opt/homebrew/bin/jit; backup: jit vault get …

Both previewed by eye before wiring (CLAUDE.md rule).

**D7. Doctor is untouched on the surface.** Its detector is swapped for
D1's; its action strings stay: `jit migrate ~/.kube/config`,
`jit migrate --only aws|docker|git|terraform`. Their truth is what this
work restores.

## Invariants preserved

- `--dry-run` and the real confirm render one plan (D6 goes through
  `printMigratePlan`; the parity test gains a refresh fixture).
- The confirm precedes `openVault`; a refusal (D4) costs no prompt.
- `jit scan` is untouched. `jit doctor` stays read-only.
- Every recorder goes through `resolveJitExecutable`
  (`jitPathRecorders` gains `jitpathrefresh.go`).
- `jit migrate undo` restores the artifact byte-for-byte, mode included.

## Tests

- migrate: discovery over each of the five artifacts (stale-missing,
  stale-versioned, durable → no row, unrelated path in a comment → no row,
  absent file → no row); the substitution as a pure function on golden
  lines (YAML `command:`, INI `credential_process`, `exec '…'` in a shell
  helper) leaving quoting and every other byte intact; refusal note when
  `resolveJitExecutable` fails; undo round trip with mode.
- cli: `jit migrate ~/.kube/config` on a migrated file with a stale path
  plans and applies one row; `--only aws` scopes to `~/.aws/config`;
  `--only env` leaves refresh rows out; bare `jit migrate` with nothing but
  a stale path proceeds to a plan; two `[DRY RUN]` markers on a
  refresh-only dry run; parity; doctor's findings and actions unchanged
  through the shared detector.

## Phases

1. D1 + D7: move the detector, swap doctor to it. No behaviour change;
   doctor's tests pass unchanged.
2. D2–D6: discovery, plan row, apply, note; preview approved first.
3. Tests, `jit migrate --help` mention, `docs-gen`, the pinned gate.

## Out of scope

- Auto-heal from `jit service` at login: still deferred; this covers the
  proactive case through bare `jit migrate`.
- MCP configs: `mcpFindings` names the server and its own re-migration
  path already; unchanged here.
