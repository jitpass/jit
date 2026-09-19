# Project relocation: a mount that survives a folder move, and a doctor that stops guessing

**Status:** proposed (2026-09-19). Nothing built. Covers `jitpass/jit` and the
Doctor surface in `jitpass/jit-app`. Every claim below was checked against the
code and run on this Mac on 2026-09-19; where a doc comment disagreed with the
code, the code won and the disagreement is noted.

## Why

The mount registry records absolute paths and nothing ever reconciles them.
Rename or move a migrated project folder and both paths in its entry point at
nothing, permanently. Three failures follow, and they contradict each other.

Measured, on a fixture with one mount:

| | registry says | the FIFO is | doctor says | migrate says |
|---|---|---|---|---|
| rename `hibob` → `hibob-api` | `…/hibob/.env` (gone) | `…/hibob-api/.env`, unserved | "project deleted without unmounting first" | — |
| move `hibob` → `~/work/hibob` | `…/hibob/.env` (gone) | `~/work/hibob/.env`, unserved | identical, byte for byte | — |
| duplicate to `hibob2` | unchanged | an **extra** unserved FIFO | nothing at all | "nothing to migrate" |

Four faults line up.

**1. The mount silently stops working.** `ensureServing` never stats
`MountPath` (`mountmanager.go:489-625`). It builds decoys, inserts into
`m.served`, starts the Serve goroutine, and `openForWriteOrCancel` then fails
`ENOENT` (`mount.go:278`). Meanwhile the real FIFO moved with the folder and is
registered nowhere, so nothing writes to it — and a FIFO nobody writes to hangs
its reader in `open()`. `saveRegistry`'s own doc comment names this outcome for
a different cause: it *"does not merely stop serving: it hangs every reader in
`open()` forever"* (`registry.go:137-150`).

**2. The failure re-logs forever and escapes the machinery built to stop that.**
`Serve`'s structural exit is logged in full at `mountmanager.go:606`, then
`:617-621` deletes the entry from `m.served` — so the next unlock and every
`OpRefresh` retries and logs again. `noteServeError`'s `readLogMinGap` collapse
(`:988-1008`) covers write/close errors only, and the transition-gated
`logMountSkip` built after the 2026-08-17 log-flood incident (`:123-131`) fires
only for a bad profile or template. The one runtime symptom a folder rename
actually produces is the one that escaped both.

**3. Doctor asserts a cause it cannot know, and offers a destructive fix.**
`kindMountStale` triggers on `os.Stat(e.ProfilePath)` returning `IsNotExist`
(`profilecheck.go:951`) and reports *"project deleted without unmounting
first"* (`:956`). That sentence is exactly as true of a project that was
renamed, moved, or is sitting on an unmounted volume. Its action names
`jit vault orphans --prune` (`:963-964`), which permanently deletes every
orphaned secret. The same wording is repeated at `unmount.go:83-85` and
`vault.go:2341`.

**4. `jit status` says the opposite.** `noteFolderRename` (`migrate.go:220-233`)
prints *"Nothing is broken… No action is needed."* while the above is true. It
is also already inert: it reads only `<root>/*.pointers`
(`renameadvisory.go:40-83`), and migrate stopped writing companions
(`pointerfile/pointerfile.go:46-66`). It never caught a move in any case — it
compares the recorded namespace against `filepath.Base(root)`, so `~/a/proj` →
`~/b/proj` keeps the basename and stays silent.

Duplication is the quietest of the four and the least safe. `cp -R` recreates
the FIFO as a FIFO, so the copy has a `.env` that looks entirely normal and
hangs on read, with no jit surface mentioning it: doctor produces no finding,
and `DiscoverEnvFiles` skips non-regular files (`apply.go:227`) so
`jit migrate` reports nothing to migrate rather than offering a repair.

## What it is not

- **Not a change to what the agent trusts.** `internal/agent` reads no project
  files today, and the mount manager reads manifests only at registry-recorded
  paths. The record proposed here is read by `jit doctor` and by an explicit
  command, never by the service. Discovery stays machine-local.
- **Not a new authority.** The record names no vault path, no grant and no
  command. It cannot enlarge what a project may reach; it can only help jit
  recognise a project it already knew about.
- **Not automatic repair.** Nothing re-points a registry entry without a human
  gesture. Doctor stays read-only (`doctor-repair.md:136-142`).
- **Not a project identity system.** One record per manifest, written by
  migrate beside it, listing that manifest's mounts. No registry of projects,
  no ids minted for projects that have none, and no id invented where
  `vault.Meta.GroupID` already exists.

## Vocabulary (decided 2026-09-19)

| term | means |
|---|---|
| **relocated** | a registry entry whose recorded paths are gone, and whose project has been found elsewhere |
| **unregistered mount** | a jit FIFO in a project this machine's registry does not list (the duplicate case) |
| **stale mount** | registered, project genuinely not found — what `kindMountStale` should have meant all along |

## How it works today

The registry is `~/Library/Application Support/jitpass/mounts.yaml`:
`[{mount_path, profile_path, template_path?}]`, all absolute
(`registry.go:16-32`). It carries no name, id or project field; the only name a
mount has is derived from its manifest's basename
(`profilecheck.go:989-991`).

**Written by one command.** Every `AddMount` call is `jit migrate`, through the
single choke point `addMount` (`migrate.go:890-896`), nine call sites, one per
category. Removal has seven callers (`unmount`, `migrate undo`,
`migrate remove` ×2, `uninstall`, `vault orphans --prune`), each ordering
`StopMount` before touching the file (`mountmanager.go:1176-1184`).

**Read on four triggers**, always whole-file: process start
(`servicerun.go:241`), `OnUnlock`, `OnRefresh` — both routed to `start`
(`servicerun.go:148-150`) — and swap teardown (`mountswap.go:145`).

**Writers lock, readers do not.** `AddMount`/`RemoveMount` take
`vault.WithFileLock` on a `.mounts.yaml.lock` sidecar (`filelock.go:39-63`);
`loadRegistry` takes none (`registry.go:122-135`) and relies on rename
atomicity. Correct for a single read; it is not a read-compare-write
primitive, which matters for anything that reconciles.

**Per-project artifacts today**, and their disposition:

| artifact | paths inside | committed by design |
|---|---|---|
| `.jit/profiles/<name>.yaml` | vault paths only | **yes**, stated (`profile.go:31-35`) |
| `.jit/profiles/<name>.source` | **absolute** config paths | no; in practice global, MCP only |
| `.jit/profiles/<name>.<kind>.tmpl` | content | **unstated** — see Open questions |
| `.jit/config.yaml` | none (`read_as_file` bool) | yes, user-authored |

**No per-project artifact records an identity.** The closest was the
`.pointers` companion's recorded namespace, and migrate no longer writes it.

**But an identity already exists, unused.** `vault.Meta.GroupID` is 128 random
bits minted once per migration batch (`vault.go:116-126`,
`migrate/provenance.go:25-29`), preserved across every rotation
(`vault.go:212`), and its own doc says *"the group survives any later rename of
the source or of the secrets' vault paths (nothing about it is derived from a
path)"*. It is read by three sites, all of them display or JSON passthrough
(`vault.go:834,1159,1373`). **There is no lookup by group id anywhere.** The
anchor this design needs was built and never connected.

## Why not

**Why not revive the folder-rename advisory.** Its output is false. Restoring
its input would make jit more confidently wrong: a working detector feeding
*"Nothing is broken. No action is needed."* at a dead mount, while doctor
offers `--prune` for the same event. The sentence has to change before the
signal is worth having, and once the sentence is honest it wants a fix, which
the advisory has no way to offer.

**Why not record the project's absolute path in the manifest.** The manifest is
the part designed to travel — *"Safe to commit: without it the vault's secrets
cannot be resolved on another machine"* (`profile.go:255-258`). An absolute
path is true on exactly one machine, so every clone would read as relocated,
and every checkout would want to rewrite a committed file. It also duplicates
machine-local state into a portable one, which is precisely the `.pointers`
mistake this repo removed on 2026-09-19. `.source` is the cautionary case
already in-tree: it records absolute paths and `os.Stat`s them
(`owners.go:127-136`), so on a second machine every owner silently drops to
zero, which flips `claimMCPNamespace` into its `mcpClaimAdopt` branch
(`mcpconfig.go:628`) and lets a config overwrite a profile's vault values in
place.

**Why not move the registry into each project.** The service must know what to
serve at login. One file is a read; scattered files are a search — and the
search is bounded in ways that would silently drop mounts. `launchers`' walk
covers `$HOME` only (`walk.go:33`, `validHome` refuses `/`), prunes
`node_modules`, `.git`, `vendor`, `dist`, `build`, `target`, `.venv`,
`.cache`, `Library` and `.Trash` (`audit/fsutil.go:34-56`), records
permission-denied directories rather than failing, and **filters to regular
files** (`walk.go:62`) so it cannot see a FIFO at all. A project in a pruned
folder would simply never be served, at every login, with nothing reported. A
stale path at least produces a symptom.

The second reason is the load-bearing one. `mounts.yaml` is machine-local and
never committed, so **which** files this machine trusts is machine-local state;
only their **contents** come from the repo. Letting a cloned repo contribute
registry entries would let it say *"create a pipe here and have your background
service feed it"*, and collides with the invariant stated at
`docs/getting-started/how-it-fits.md:117-131`: *"project-local configuration may
reconfigure a project's own secrets, but it never authorizes access to a
machine-global credential."*

**Why not reconcile by heuristic alone** (match a stale entry against any
manifest with the same name and equal values). It works, and it is what this
design would fall back to, but it guesses. Two projects each owning an `api`
profile is not exotic, and a copy produces two identical candidates. With a
record carried by the project, the match is exact and the ambiguous case is
detectable rather than silently resolved.

**Why not key on `GroupID` alone, with no per-project file.** Tempting, since
the id already exists and survives renames. But the id lives in the vault
envelope, and the vault has no reverse index — finding *which project* a group
belongs to still means walking the disk for manifests. The id disambiguates; it
does not locate.

## Decisions

**D1. Identity travels with the project; authority stays on the machine.**
`<project>/.jit/profiles/<name>.mount` records what is true everywhere: this
manifest backs a mount at a relative path. `mounts.yaml`
records what is true here: which of those this Mac actually serves. Relocation
is the two disagreeing, and reconciling them is a human-approved write to the
machine-local file only.

**D2. The service never reads the record.** Only `jit doctor` (read-only) and
the explicit registration command do. This keeps `internal/agent`'s current
property — it reads no project files — and keeps the mount manager reading
manifests only at registry-recorded paths. The trust boundary does not move.

**D3. Relative paths, validated like a restore destination.** Every path in the
record is relative to the record's own project root. On read: reject absolute,
reject any `..` segment, resolve and canonicalise, require the result to remain
under the project root, and refuse a symlink. This is the shape `migrate undo`
was given after the 2026-07 self-review found *"a tampered or corrupted index
could redirect a decrypted secret to an arbitrary destination, using the user's
own authenticated undo"* (`docs/security/self-reviews/2026-07.md:88-92`). A
mount path is a serve destination; it gets the same treatment.

**D4. The record names no vault path.** The manifest beside it already does,
and a manifest is an unscoped reference into a machine-global vault
(`namespace.go:37-46`). Adding a second file that can name vault paths would
inherit that reach for no gain. The record points at a manifest; it does not
restate one.

**D5. The record carries the group id as a tie-breaker, never as an authority.**
`group: <hex>` from `vault.Meta.GroupID` disambiguates when several candidates
match. It is compared, never trusted: a record claiming another project's group
id changes which candidate is *offered*, and the human sees both paths before
anything is written.

**D6. Doctor distinguishes three states it currently conflates.** `relocated`
(found elsewhere — offer to re-point), `unregistered` (a jit FIFO in a project
this machine does not serve — offer to register), `stale` (genuinely not found
— what the existing wording should have said). Only the third keeps today's
message, and none of the three offers `--prune`.

**D7. Coverage limits are stated in the finding, not implied.** When the walk
could not read a directory, `Coverage.Unreadable` is already recorded
(`walk.go:40-43`); a "not found" says *"not found under your home directory"*
and names how many folders it could not read. "Can't tell" must not read as
"gone" — the rule `LiveProfileOwners` already follows (`owners.go:118-134`).

## Shape

The record is a **sibling of the manifest**, matching the convention already in
`.jit/profiles/`: `<name>.yaml`, `<name>.source`, `<name>.<kind>.tmpl`, and now
`<name>.mount`. A first draft of this note put a single `<project>/.jit/mount.yaml`
at the project root, which does not survive contact with the tree — a project
with `.env` and `.env.local` has two manifests, and one manifest can back
several mounts (`profiledrop.go:406-435` rewrites a companion per mount for
exactly that reason). One file per manifest, holding the list, has neither
problem.

```
# <project>/.jit/profiles/hibob.mount
# jit project record — no secret values, no vault paths, no absolute paths.
# Lets jit recognise this project after it is renamed, moved or copied.
mounts:
  - .env
group: 6cd2a4a569b34b2e0fbf796b7671fb7a
```

Paths are relative to the **project root**, defined as three `Dir`s up from the
record — the manifest store's grandparent. That is `scopeOfManifest`'s existing
answer (`launchers.go:632-638`), so the new file adopts a rule the tree already
has rather than adding a third.

Three flows, all beginning in `jit doctor`:

**Relocated.** A registry entry's paths are gone; the home walk finds a project
carrying a record whose `profile` resolves to a manifest matching the entry's
basename, and whose `group` matches. Doctor reports the old and new locations.
`jit mount relocate <new project dir>` rewrites the one registry entry and
refreshes the service.

**Unregistered.** A project carries a record, its mount path is a FIFO, and no
registry entry claims it. Doctor reports that anything reading it will hang.
`jit mount register <project dir>` adds the entry, after showing which vault
group it will serve.

**Stale.** A registry entry's paths are gone and nothing was found. Today's
finding, with honest wording and no prune.

Ambiguity refuses rather than guesses, as `jit profile drop` and
`jit migrate forget` already do: several candidates are reported with their
paths, and the user names one.

## Security notes

A file inside a repo that jit reads is not a new category here.
`<project>/.jit/config.yaml` is read on every run by walking up from cwd, with
no confirmation (`projectconfig.go:33-53`), and `<project>/.jit/profiles/*.yaml`
is committed, repo-controlled, and auto-selected and injected without
confirmation when it is a project's only manifest (`envlayers.go:511-514`).

What keeps that safe is the class of thing repo content is allowed to change.
`config.yaml` holds one boolean selecting a delivery mechanism for secrets the
user already migrated, and *"fails toward the safe default"* on any read or
parse failure (`projectconfig.go:30-32`). This record is deliberately in the
same class: it can make jit **recognise** a project, and it can make a finding
**appear**. It cannot make jit serve anything, reach any secret, or write
anything without a human gesture. That is what lets D2 and D4 be stated as
guarantees rather than intentions.

Repo-supplied values go through allowlists that reject rather than sanitize —
`varNamePattern` (`profile.go:44-61`, which names hostile manifests as *"an
ordinary pull-request-shaped delivery of exactly the malicious-repo-content
attack RFC §1 names as jit's reason to exist"*) and `ValidatePath`
(`vault/path.go:55-84`). D3 applies the same posture to the filesystem side.

Two hazards inherited rather than introduced, recorded here because a reader of
this note will ask. The vault is one machine-global namespace and a project
manifest is an unscoped reference into it (`vault.go:78-80`,
`namespace.go:37-46`); this design does not change that, and D4 keeps the new
file from widening it. And the same-user adversary is a conceded boundary
(`docs/security/self-reviews/2026-07.md:61-79`), unchanged here.

## Invariants preserved (do not regress)

- **Doctor stays read-only.** No `doctor --fix`; doctor names the command and
  the command owns the consent (`doctor-repair.md:136-142`,
  `jit-path-refresh.md:51`).
- **A fix must not create a finding worse than the one it clears.**
  Registration and relocation touch `mounts.yaml` only — no secret, no
  manifest, no FIFO content.
- **`StopMount` completes before anything touches a mount file**
  (`mountmanager.go:1176-1184`). Relocation re-points an entry whose old path
  is already gone, so there is nothing to stop; the new path is served by the
  ordinary `ensureServing` pass after refresh.
- **GAPS.md #17: plan → y/N → Touch ID.** Neither new command reads a secret,
  so neither needs auth; both still show what they will write before writing.
- **The agent reads no project files.** D2.
- **`internal/audit` is read-only in every mode.** Untouched.

## Tests required

- Rename, move, and copy of a migrated project, each asserting the finding kind
  and that no action offers `--prune`.
- A record with an absolute path, a `..` segment, a symlinked mount, and a path
  escaping the project root — each refused, nothing written.
- Two candidates (a copy plus a moved original): refuses, names both.
- A record whose `group` matches nothing: falls back to name-and-values
  matching, and says the id did not match.
- A project under a pruned directory and one outside `$HOME`: reported as not
  found, with the coverage caveat, never as deleted.
- Registration is the only path that writes `mounts.yaml`; doctor with every
  finding present writes nothing.
- Negative controls: each new test fails against the current tree.

## Phases and how each reverts

| Phase | Lands where | Revert |
|---|---|---|
| 1. Honest wording: split `kindMountStale`, drop `--prune` from its action, fix the three call sites asserting "deleted" | `profilecheck.go`, `unmount.go`, `vault.go` | revert the commit; wording only |
| 2. Rate-limit the `ENOENT` serve-exit log through the existing transition gate | `mountmanager.go` | revert; logging only |
| 3. Doctor finds a registered mount whose FIFO is gone (nothing stats `MountPath` today outside `audit`'s counters) | `profilecheck.go` | revert; a finding disappears |
| 4. migrate writes `<name>.mount`; readers and validation (D3) | `migrate/`, new package or `pointerfile`-shaped leaf | revert; older jits ignore an unknown file |
| 5. `relocated` / `unregistered` findings and their two commands | `cli/`, `doctorfixes.go` | revert; findings disappear, registry untouched |
| 6. App: cards and buttons for both | `jit-app` | revert; generic Run buttons return |
| 7. Delete `renameadvisory.go` and `noteFolderRename` | `migrate/`, `cli/migrate.go`, `cli/status.go` | revert; restores an inert advisory |

Phases 1–3 are independently useful and depend on nothing else here. If this
design is not built, they should still land.

## Out of scope, recorded

- **Projects outside `$HOME`.** The walk has one root plus cwd
  (`launchers.go:258-271`). A project moved to `/Volumes` is found only when
  jit runs inside it. Stated in the finding, not solved.
- **`.tmpl` git disposition.** Eight categories write
  `<name>.<kind>.tmpl` beside the manifest at 0600, and a template-backed mount
  cannot be reconstituted without one — yet nothing states whether it should be
  committed. A record meant to survive a clone makes this question live.
- **Re-pointing `Origin`.** `vault.Meta.Origin` is frozen at birth
  (`vault.go:200-213`) and feeds the duplicates and origin-gone sweeps, so a
  moved project reads as "origin gone" forever. Separate change.
- **`claimNamespace` after a move.** It keys on the folder basename
  (`namespace.go:54-98`), so re-migrating a renamed project claims a new
  namespace and duplicates every secret. Separate change, but the same root
  cause.
- **Reading `mounts.yaml` under the lock.** Every writer locks, no reader does
  (`registry.go:122-135`). Fine for today's single reads; a future
  read-compare-write reconciler would need it.

## Open questions

- **Which directory is "the project"?** Profile stores nest per *directory of
  the migrated file*, not per repo root (`migrate.go:952-953`), and the tree
  answers this two ways already: `findProjectRoot` takes the nearest ancestor
  with a `.jit` (`migrateremove.go:272-280`), `scopeOfManifest` goes three
  `Dir`s up (`launchers.go:632-638`). *Proposed:* `scopeOfManifest`'s rule, as
  Shape states — the record sits in a profile store, and that store's
  grandparent is the only root it can name without guessing. `findProjectRoot`
  keeps its current meaning for removal, where "nearest ancestor holding a
  `.jit`" is the right question.
- **Should `jit migrate` backfill a record for existing mounts?** *Proposed:*
  no. Phase 5's `register` writes one as a side effect when the user
  approves, so records accumulate by use rather than by a migration pass.
- **Does the app need a "register" affordance, or is doctor's card enough?**
  *Proposed:* card only, matching every other repair: the engine refuses, the
  app confirms.
