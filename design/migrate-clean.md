# Migrate --clean: finishing the deletion the user already chose

**Status:** implemented on branch `migrate-clean`, 2026-09-06 (audit
predicates, migrate core, CLI wiring, undo label, scan prose). Companion to
`design/dry-run-refactor.md` (the plan frame it extends) and
`internal/audit/triage.go`'s red section (the prose it automates).
Deviations the build settled are folded into D2/D3/D4/D9 below.

Three promises this doc makes:

1. `jit scan` stays read-only in every mode. `--clean` lives entirely in
   migrate; the only scan change is prose (which command an arrow names).
2. `--clean` deletes only what it can prove condemned or redundant, and it
   encrypts a backup of every byte before the unlink, so
   `jit migrate undo <path>` restores any file it removed. The deletion is
   final for everyone except the vault owner.
3. The consent surface is at least as strict as `jit migrate remove`'s:
   a complete counted plan, a dedicated [y/N] that stands apart from the
   migrate consent, and a fresh Touch ID that `--yes` cannot skip.

## The gap today

The red "only you can protect these" section (`triage.go:241`) holds every
finding migrate refuses to act on. Three of its groups state deletion as the
remedy, as prose the user must execute by hand:

- **Trash.** `kindTrash` renders "empty the Trash, then rotate anything it
  held" (`triage.go:2087`), with the note "this file is already on its way
  out — migrating it would preserve what deletion is about to fix"
  (`triage.go:2202`). The comment above it (`triage.go:2084`) is the whole
  argument for this feature: the user already decided this file should not
  exist. Finishing the deletion IS the remedy. Nothing finishes it.
- **Archived copies.** `archivedDeletionNote` (`triage.go:2213`): "already
  protected the live copy? deleting the archived one is the cleaner fix."
  The comment beside it concedes "only the note can say so because scan
  never deletes anything." The note is correct and inert.
- **Agent leftovers.** `remedy.go:118-128` forces manual for anything inside
  an agent directory: "The credential's home is the file it came from; its
  copy here is something to delete, not to relocate." And the redaction
  sweep's own skip advice (`migratecaches.go:273`) ends in "delete those
  files yourself."

So the product's most confident deletion advice terminates in the user
opening a terminal and typing `rm`. Every other remedy class got an
automated path (migrate, wrap, redact); this one got a sentence.

## What the code read established

- There is no delete remedy class. `Finding.Remedy` is exactly
  `migrate | wrap | manual` (`remedy.go:21-25`); delete-ness is a
  render-time `kind` (`triage.go:2044-2058`) computed by `manualAction`
  and never serialized. NDJSON cannot drive this feature: a pure `.env`
  in `~/.Trash` streams `remedy:"migrate"` with a `fix_command` reaching
  into the Trash, while the human report says empty it
  (`docs/reference/scan-ndjson.md:39`). `--clean` must classify in-process,
  from the same `Finding` values the triage renderer uses.
- The "is the live copy already protected?" question is authenticated by
  construction. Scan cannot see a vaulted value (`agentcache.go:61-67`
  states this and assigns the check to migrate). `liveGroups`
  (`triage.go:1121`) answers only "a live *plaintext* sibling exists";
  once the original is migrated, only vault decryption can prove the
  archived copy redundant.
- migrate never deletes user credential data anywhere today. Every
  `os.Remove` in the tree targets jit's own artifacts. The nearest
  precedents: `jit migrate caches` (consented redaction pass:
  `migratecaches.go:66-132`), `jit vault duplicates --prune` (reports by
  default, acts on one provably-safe shape), and the encrypted-backup +
  `backups.yaml` + `RestoreFromBackup` idiom (`migrate/undo.go`) that makes
  a mutation undoable without ever staging plaintext on disk.
- The irreversible-mutation gate is a settled four-step:
  plan, [y/N], `openVaultFreshAuth()` (`vault.go:2766`, refuses the broker),
  `requireFreshUserPresence()` (`vault.go:2754`, the explicit challenge that
  exists because a deletion-only operation never touches the KeyWrapper,
  GAPS #60). `--yes` skips the typed prompt only; uninstall documents that
  wording verbatim (`uninstall.go:261`).
- The plan contract: every mutation a run will perform appears as a counted
  category in one frame (`planExtras`, `migrateplan.go:55`;
  `design/dry-run-refactor.md` D1-D4), the dry-run frame carries exactly
  two `[DRY RUN]` markers, and plan and result render the same rows with
  tense as the only difference (`migratesummary.go:30`).

## Why not

**Why not a `clean` subcommand.** `jit migrate caches` set the subcommand
precedent, but a standalone `jit migrate clean` forfeits the ordering win
that makes most archived copies eligible at all: migrate the live original
*first*, and its archived siblings become provably redundant in the same
run, same consent ceremony, same scan. A subcommand would tell the user to
run two commands in the right order, which is the prose problem again. It
would also sit one keystroke from `jit vault clean`, which means "delete
every secret in the vault"; two subcommands named clean with opposite blast
radii is a trap (`design/vault-duplicates.md:142` already declined a name
for this reason). A flag on migrate reads as "migrate, and also clean up
after", which is exactly what it is.

**Why not delete without a backup.** "Trash files are already condemned" is
true and still not a reason: the eligibility tests are heuristics over
paths and values, the user confirms a list they may not fully read, and the
repo's history (`shellconfig.go:282-293`) shows why staging plaintext
backups on disk was abandoned. The vault backup namespace already solves
this: encrypted, indexed, restorable through an existing command. The cost
is one vault write per deleted file; the benefit is that the scariest
sentence in this feature ("permanently delete") becomes false for its own
user.

**Why not empty the Trash.** The finding is a file; the remedy `--clean`
automates is deleting *that file*. Emptying the whole Trash deletes data
jit never scanned and cannot enumerate in a plan, and macOS reserves the
real "empty" gesture (and its TCC protections) for Finder. The result
output keeps pointing at the Trash for the rest.

**Why not delete redactable agent files.** `migrate/agentcache.go:466`:
"Redaction keeps the agent's undo history intact, where deletion would
remove a step of it." That decision stands. `--clean` takes only the files
redaction *cannot* fix (binary blobs) plus the sweep-dir leftovers whose
whole existence is the copy, and never a text file the redaction sweep can
splice.

**Why not run the value check before consent.** `jit migrate caches`
authenticates before its plan because its plan cannot exist without vault
needles. `--clean`'s candidates are identifiable without the vault (paths,
archive predicates, in-run raw values); only the final "is this value
vaulted?" proof needs decryption. Keeping plan → [y/N] → Touch ID preserves
the doctrine that declining never costs a fingerprint (GAPS #17,
`migrateremove.go:320`), and makes `--dry-run --clean` auth-free. The price
is honest wording: the plan lists candidates, and the pass reports which
ones the post-auth check declined to touch.

## Decisions

**D1. `--clean` is a phase on `jit migrate`, not a subcommand.** It
registers as a flag on `migrateCmd` (bare and `<path>` forms). The run
order is fixed: migrate phase first, clean phase second, so a live original
vaulted seconds ago already counts toward its archived copy's eligibility.
`jit migrate --clean` with nothing to migrate runs the clean phase alone.
`migrateApplyCommand` carries `--clean` into the dry-run trailer (and keeps
dropping `--yes`).

**D2. Eligibility is a whitelist of three provable shapes.** Anything not
matching stays exactly where it is today, in the red section, with its
existing prose.

| class | test | unit deleted |
|---|---|---|
| trash | counted secret finding, `audit.InTrash(path)` (exported from `archived.go:46`), regular file, not a symlink | the flagged file |
| redundant archived copy | `f.Archived`, not in Trash, and *every* secret detected in the file is value-identical to a vault secret (vaulted earlier, or vaulted by this run's migrate phase) | the flagged file |
| agent leftover | a secret-holding file strictly inside `agentCacheSweepDirs` (paste-cache, shell snapshots, agent-made backups), every detected value vault-verified | the blob |

Permanently out, stated here so nobody relitigates them item by item:
IAM / private-key findings (`kindIAMKey`, `kindKeyByHand`: rotation is the
fix, deletion without rotation destroys evidence while the key stays
valid, and key bodies are never vaulted so the value test can never pass);
shell-history spans (redaction's job, line-granular); `kindRotateDelete`
copies (arbitrary user data in arbitrary places); derived credentials
(`derived.go:12-28`: outside the model by construction); agent
*credential stores* (`agentCredentialStores`: those are the tool's live
sign-in, deleting them breaks the tool); files a live agent session holds
(`SkipLive`); hard links (unlinking one name removes nothing, note it
instead); anything reached through a symlink.

**D3. Every deletion is backed up encrypted first.** For each file:
`storeSecretBackup` into the vault's `_backups/` namespace, a
`BackupRecord` appended to `backups.yaml` (ordinary record, `Snapshot`
false, mode preserved; a new `Cleaned` marker labels it, since
`RestoreWith` already means linked restores), then the unlink. `jit migrate undo <path>` restores it through the existing
`RestoreFromBackup` path, `O_EXCL|O_NOFOLLOW`, snapshot-first, already
audited. No plaintext ever touches disk between backup and delete. The
undo listing distinguishes "deleted by --clean" from "migrated" so a
restore is never a surprise.

**D4. The clean phase gets its own consent, and Touch ID survives
`--yes`.** One run, two decisions: vaulting is reversible and rides the
existing `Proceed? [y/N]`; deletion is destructive and gets its own block
after the migrate phase completes, listing every path, then its own
prompt:

    Delete these 4 files from disk? Encrypted copies are kept for
    jit migrate undo. [y/N]

`--yes` skips both typed prompts and never the fingerprint, with
uninstall's exact flag wording ("still requires the Touch ID/passcode
gate"). Decline prints "Deletions skipped. Nothing was deleted." — not the
migrate-tree "Aborted. Nothing was changed.", which would be false: the
migrate phase's work stands (it was separately consented). A run whose
plan holds ONLY deletions skips the main `Proceed?` gate — the deletion
prompt, which names every path, is that plan's consent, and two prompts
for one category teach people to stop reading them.

**D5. Fresh presence, forced explicitly, after consent.** The clean phase
opens its own vault handle via `openVaultFreshAuth()` (never the broker)
and calls `requireFreshUserPresence` with a length-bounded reason naming
the act, e.g. `jit migrate --clean: delete 4 flagged files`. The explicit
challenge is not optional politeness: backups and the value check do touch
the KeyWrapper, but the gate must not depend on that incidental fact
(GAPS #60 is the scar). Priming means a batch prompts once. The stamp
lands in the audit log as `auth: local-userpresence` via the existing
generic hook, plus one `recordSideEffect` naming the deleted paths, the
same idiom as the guard install (`migrate.go:1669`).

**D6. Verification runs inside the gate; the plan is candidates, the
result is proof.** Cross-run redundancy (live original migrated last
week) is only provable after decryption, so the plan lists those rows as
conditional and the pass re-verifies everything post-auth: value match
against `CollectVaultSecrets` plus this run's vaulted values, and a
content re-hash against the plan-time sha256 immediately before each
unlink (the file may have changed between plan and consent; any mismatch
skips the file with a note). `os.Remove` only, never `RemoveAll`, never a
directory, parent dirs left in place even when emptied.

**D7. The plan category and result render in lockstep.** `planExtras`
gains a clean group; it counts into "N changes planned across M
categories" and appears under the two-marker dry-run frame unchanged.
Render sketch (report shape, rule-1 header, count only when >1, `└`
evidence, one arrow last):

    [clean] 4
      ~/.Trash/old-project/.env
        └ in the Trash — finishing the deletion you started
      ~/work/archive/api/.env.bak
        └ every secret matches the vault (from ~/work/api/.env)
      ~/backups/2024/.env.old
        └ redundant once this run migrates ~/proj/.env
      ~/.claude/paste-cache/3f2a91…
        └ binary copy of OPENAI_API_KEY; redaction can't splice it
      Encrypted copies are kept; jit migrate undo restores any of them.

    Left alone (2):
      - ~/backups/prod.env — its secret isn't in the vault; migrate it first
      - ~/.claude/shell-snapshots/9c11… — a live agent session holds it

Result, same rows, past tense, `✓` action-completed glyph, rotation caveat
kept because deletion rotates nothing, single cyan arrow last:

    ✓ Deleted 4 files (encrypted copies kept for undo)
        ~/.Trash/old-project/.env
        …
      Deleting a copy rotates nothing — rotate anything production above.
      → jit migrate undo <path> restores a file

No new glyphs, no new inks; plan rows are stateless so they carry no
glyph at all (the trap `design/output-style.md` warns about).

**D8. Scan changes are prose only.** The red section keeps its groups and
its count; what changes is where the arrows point. `kindTrash`'s arrow
becomes `jit migrate --clean`; `archivedDeletionNote` gains the command
("already protected the live copy? `jit migrate --clean` deletes the
archived one"); the caches skip advice names it for binary leftovers. The
coverage ledger does not move in v1: scan cannot verify eligibility
without auth, so it must not promise a percentage it cannot prove. The
read-only guarantee is untouched; `readonly_test.go` keeps passing without
edits.

**D9. Flag interactions are boring on purpose.** `--dry-run --clean` shows
the full plan, auth-free, frame unchanged. `--only` filters migrate
categories exactly as today and does not filter the clean phase (the flag
that requested it is consent enough to *plan* it; the [y/N] still gates
the act). `jit migrate <path> --clean` scopes candidates to the named
paths, and routes a named delete-class file to the delete pass INSTEAD of
migration: naming a Trash file with `--clean` means finish its deletion,
and vaulting it would preserve what deletion is about to fix — the scan
report's own stance. `--clean` is a local flag on migrate/path only, so
`remove`/`undo`/`caches` reject it as unknown.

**D10. Classification helpers live in audit, consumption in migrate.**
`InTrash` gets exported beside `LooksArchived`; a small exported
`audit.DeleteClass(f)` (or equivalent predicate set) is the one place the
triage renderer and the clean planner both call, so the red section and
the plan can never disagree about what is delete-class, the same no-drift
move the guard admit rule made. Audit gains predicates, never a writer.

## Invariants preserved (do not regress)

- audit read-only in every mode; no writer enters the package.
- Exactly two `[DRY RUN]` markers per run (`TestDryRunFrameExactlyTwoMarkers`).
- Plan and result render the same rows, tense only (GAPS #26).
- Declining a prompt never costs a Touch ID (GAPS #17).
- A destructive act that might not touch the KeyWrapper still forces the
  explicit presence challenge (GAPS #60).
- No plaintext staging copies on disk, ever (`shellconfig.go:282` history).
- `--yes` never skips a presence gate, only typed prompts.
- Redaction, not deletion, for anything redaction can splice
  (`migrate/agentcache.go:466`).
- Style guards: no new colors or glyph literals; everything through
  `internal/style`; prompt strings length-bounded for the macOS dialog.

## Tests

- `TestCleanPlanIsACountedCategory` — clean rows fold into the subtotal
  and the frame test still sees two markers with `--clean`.
- `TestCleanEligibilityWhitelist` — table-driven over the D2 matrix,
  including every "permanently out" row (IAM key, history span, credential
  store, symlink, hard link, live session).
- `TestCleanRefusesSymlinkAndRehashesBeforeUnlink` — TOCTOU: mutate the
  file between plan and apply, assert skip + note.
- `TestCleanBacksUpThenDeletes` — backup record exists and decrypts to the
  original bytes before the file is gone; failure to back up aborts that
  file's deletion.
- `TestCleanUndoRestoresDeletedFile` — end-to-end through
  `jit migrate undo`, mode preserved.
- `TestCleanArchivedRequiresVaultMatch` — archived file with one
  unmatched secret is left alone and reported.
- `TestCleanSameRunOrdering` — live original migrated in the same run
  makes its archived copy eligible.
- `TestCleanForcesFreshPresence` / `TestCleanYesKeepsTouchID` — the
  KeyWrapper type assertion path, and `--yes` semantics.
- `TestCleanNeverTouchesCredentialStores` — fixture tree with
  `hosts.json` / `auth.json` present and flagged.
- `TestTriageArrowsNameClean` — red-section prose points at the command;
  `readonly_test.go` untouched and green.

## Phases

One commit each, ordered so every intermediate state ships.

1. **audit predicates.** Export `InTrash`; add the shared delete-class
   predicate the triage renderer switches onto. Pure refactor of
   `manualAction`'s existing branches; behavior identical, pinned by the
   existing triage tests.
2. **migrate core.** `internal/migrate/clean.go`: candidate builder (from
   in-process findings + `SnapshotsOf`), post-auth verifier (value match +
   re-hash), executor (backup, record, unlink). Unit tests against a
   fixture tree. No CLI wiring yet.
3. **preview script.** Before any CLI rendering lands: a script rendering
   the proposed plan block, left-alone block, confirm prompt, and result,
   honoring `$COLUMNS` plus forced 50/60, handed to the user as
   `! zsh <path>`. Wait for the eye test; adjust; only then wire renders.
4. **CLI wiring.** `--clean` flag, `planExtras` clean group, the render
   pair sharing one row helper, the dedicated confirm, fresh-auth gate,
   `recordSideEffect`, `migrateApplyCommand` update. The frame and
   summary tests extend here.
5. **undo surface.** Clean records in the undo listing with their own
   labeling; restore path test.
6. **scan prose + docs.** Arrow/note changes in triage, caches skip hint,
   `jit migrate` Long/flag help, `go run ./cmd/jit docs-gen` (new flag
   lands in `jit_migrate.md` options; remember CI checks with
   `git status --porcelain`, so untracked doc pages count), GAPS.md
   entries for the new invariants.
7. **dogfood + QA.** Run against a seeded VM tree (Trash, archive,
   paste-cache fixtures), then `/qa-release` before tagging.

## Out of scope, recorded

- Emptying the Trash, or deleting directories of any kind.
- Deleting the redaction sweep's `SkipBinary` residue (binary blobs the
  sweep can't splice, whose advice stays "delete those files yourself").
  Identifying them needs the post-auth sweep's skip set, which cannot
  appear in a pre-auth plan the user consents to — a follow-up needs its
  own plan/consent shape for them.
- A scan-side "cleanable" coverage number (needs auth scan doesn't have;
  revisit only if the red section's count proves misleading in practice).
- Serializing `kind`/`in_trash`/`KeyKind` into NDJSON (real gaps, listed
  in the research; none block an in-process feature, and schema bumps
  deserve their own change).
- Deleting derived-credential caches (`~/.aws/cli/cache` and friends);
  they expire on their own and sit outside the model on purpose.
- An `--include-archived` style bulk-vault flag; considered and abandoned
  once already (`migrate/doc.go:110-122`), and `--clean` addresses the
  same itch from the deletion side.
- Finder-Trash semantics (`NSFileManager.trashItem`) as a soft-delete:
  jit's soft-delete is the encrypted backup; adding a second, weaker one
  via a new CGo surface expands the review perimeter for no safety gain.
