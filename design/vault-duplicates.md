# Spec: handling duplicates in the vault

Status: implemented (2026-08-13)
Scope: `jit vault list`'s group headers and duplicate note, a `jit vault rm`
reference warning, a new `jit vault duplicates` command, and a migrate-time
disclosure note.
Non-goals: deduplicating storage, any new envelope field, any new deleting
command.

## Problem

On a real machine (118 secrets, 28 groups), `jit vault list` closed with three
notes of the form:

```
note: claude-inventory-export, developer-secrets-export, jamf-2 hold the same
keys, a re-migrated file? jit vault rm the stale copy.
```

All three were wrong, and the one real duplicate went unreported.

`printDuplicateGroupNudge` fingerprinted a group by **key names alone**, with a
three-key floor. That rule cannot distinguish the two situations that produce
identical key sets:

- Five separate export scripts, each a live `.env` with its own mount, all
  holding the same Jamf API client. Deleting any one breaks that script.
- `mcp-caido` and `mcp-caido-2`: one `.mcp.json` in a workspace folder that was
  copied, with both copies migrated. A genuine duplicate - and invisible to the
  old rule, because the group holds a single key.

Worse, the remedy it named is the wrong command even when a group *is* stale.
`jit vault rm` deletes envelope files only: the profile manifest keeps naming
the deleted path and the mount keeps serving a FIFO nothing can fill. It also
had no referenced-by check at all, so following the note broke a live mount with
no warning.

The two existing duplicate surfaces both missed this case for the same reason:
`jit vault orphans` keys on "referenced by nothing", and `jit status`'s
`DuplicateOf` (secretsreconcile.go) only annotates *unreferenced* groups. Both
caido groups are referenced, by their own live profiles.

## Verdicts

Origin is the discriminator, not the name and not the key set.

| Verdict | Evidence | Remedy |
| --- | --- | --- |
| **Re-migration fork** | two groups, identical recorded `Origin` | retire one |
| **Copied-file parallel migration** | same key set, same origin *tail* (`ws/.mcp.json`), different prefix | retire one |
| **Abandoned namespace** | `Origin` no longer exists on disk | retire it |
| **Shared credential** | same value, same key, independent live origins | **keep all** |
| **Coincidental key names** | same key names, different values | not a duplicate |

The origin tail is one segment beyond the basename on purpose: every project has
a `.mcp.json`, so a bare basename would call two unrelated projects' configs
copies of each other.

The remedy differs per verdict, and routing it correctly is most of the value:

- origin file still exists -> `jit migrate remove <file>` (file, profile and
  secrets together). Note it writes that file's values back as PLAINTEXT on
  its way out - it un-migrates the copy, it does not shred it - so retiring a
  copy you want gone is two steps: `migrate remove`, then delete the file or
  folder. It also refuses to delete a secret another project's profile
  references, which is what makes retiring one copy of a shared credential
  safe.
- origin gone, nothing references it -> `jit vault orphans --prune`
- origin gone, still wired -> `jit vault rm <paths>`
- values diverged -> **no removal pick**; which copy is right is the user's call
- shared credential -> no removal at all. Collapsed to a count by default,
  since the answer is "nothing to do"; `--shared` expands it into the list of
  every place a rotation must reach. That list must name EVERY holder,
  including groups already reported as a same-file finding: excluding them
  under-reported JAMF_CLIENT_ID from six profiles to four on a real vault,
  which would have left two copies stale after a rotation

## Identity, not deduplication

The vault keeps N copies. It learns which ones are the same credential; it does
not collapse them.

Three reasons. The envelope AAD binds ciphertext to its exact path, so a shared
object needs an indirection layer with its own delete-ownership semantics.
Removal is destructive and every other jit surface is non-destructive by default
(`scan` never writes; `migrate` has `undo`). And the actual pain is not disk: it
is "which can I safely delete" and "I rotated this, which places are now stale" -
both of which identity answers and deduplication does not.

Sharing already exists where it belongs. Profile manifests map a variable name to
a full vault path and are explicitly decoupled from the vault tree
(`internal/profile/doc.go`), so two profiles referencing one path is already a
legal, supported state. Nothing new was needed to make sharing possible; what was
missing was jit *noticing*.

## Why value comparison needs no envelope change

Comparing values needs plaintext, which needs an unlock. An earlier draft
proposed an envelope v4 field holding a keyed HMAC of each value so comparison
could happen without decrypting.

That was solving an invented problem. `jit vault duplicates` is a dedicated
command that is *allowed* to prompt, and `jit vault export` already sets the
precedent for bulk decryption under one unlock. So the command decrypts in
memory, hashes, compares, and persists nothing. No envelope change, no new
crypto surface.

It also sidesteps a real hazard the stored-fingerprint design created: a plain
digest per secret would turn the vault directory into a guess-confirmation
oracle for low-entropy values (`http://127.0.0.1:8080`, `true`, a file path) for
exactly the attacker envelope encryption exists to stop. A keyed HMAC avoids
that, but its key must be MEK-wrapped, which means comparison needs an unlock
anyway - the same constraint, with a format migration attached.

## What `--prune` may delete, and why the rest is out of reach

An earlier draft of this spec argued the command should be read-only outright,
on the scan-reports/migrate-fixes split. That was the wrong frame: that split is
about `jit scan` vs `jit migrate`, not about every report. `jit vault orphans
--prune` and `jit vault prune` are both vault reports with deleting flags, and
this is the same namespace and the same idiom (confirmation, then a fresh
user-presence check, since `Remove` only unlinks envelope files and would
otherwise need no gesture at all).

So `--prune` exists, scoped to the one shape that is unambiguously vault
garbage: **origin file gone AND referenced by nothing**. That is exactly the
object class `orphans --prune` already deletes, reached by duplicate evidence
instead of by reference-counting.

Everything else keeps a printed command, and `--prune` reports what it left
behind rather than skipping silently (a cleanup that quietly passes over most of
what it just listed reads as "cleaned everything"):

- **origin file still on disk** - retiring the copy means un-migrating it.
  Deleting the secrets alone would leave a registered mount serving a FIFO no
  writer can fill. `jit migrate remove` is the command that already does the
  whole job, including refusing to delete a secret another project references.
- **origin gone, but a profile still names the paths** - deleting leaves that
  manifest pointing at holes. A per-path `jit vault rm` decision.
- **diverged values, or a shared credential** - not jit's call at all.

The flag is `--prune`, not `--clean`: `jit vault clean` already means "delete
every secret in the vault", so `--clean` here would read as "delete all the
duplicates" at the exact moment some findings are shared credentials that must
be kept.

## Surfaces

1. **Group headers carry provenance** (`sharedGroupNote`). A top-level group whose
   members share one `Origin` states `class · from <origin> · <age>` once on the
   header, per the house "shared fact on the group header" rule. A uniformly
   manual group reads `set directly`; mixed origins say nothing; nested headers
   never restate the top-level fact; a long origin is middle-truncated to the
   window and dropped entirely below 12 remaining columns.

   This alone dissolves much of the confusion: `[jamf] 14 · dotenv · from
   ~/custom_scripts/.env` and `[jamf-2] 8 · dotenv · from
   ~/custom_scripts/computer_inventory/.env` are visibly two different scripts,
   not a stale copy, before any detector runs.

2. **The note is origin-backed** and routes to `jit vault duplicates`. It never
   recommends `rm`. Because origin evidence is strong, it has no key-count floor
   (the old three-key floor is what hid the single-key caido pair).

3. **`jit vault rm` warns** when a doomed path is still wired, naming the profile
   and mount and printing the `jit migrate remove` that cleans up properly.
   Advisory and fail-open (`referencesForPaths` is deliberately lenient where
   `collectReferencedPaths` is strict - the strict one feeds a deleter, this one
   feeds a warning).

4. **`jit vault duplicates`** renders the verdicts above, with `--format json`.

5. **Migrate discloses at birth**: storing a value the vault already holds under
   another group prints one note on the result line. Disclosure only - the file
   migrates normally into its own profile. Config-named keys (`looksLikeConfig`)
   and values under 6 bytes are excluded, so `OUTPUT_FILE` and `8080` never read
   as shared credentials.
