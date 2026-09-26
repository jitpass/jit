# Secure Enclave: rotating the vault key

**Status: plan, 2026-09-26. No code yet.** Built from a read of jit `main`
at `f863975` and jit-app `origin/main` on the same day. Companion to
`secure-enclave.md` (the design) and `secure-enclave-plan.md` (the order of
work for the move). The owner wants this working before v2.3.0 ships.

Two problems, one plan:

1. `jit vault rekey` refuses on an enclave vault: "this vault's key is in
   the Secure Enclave, and rotating it is not available yet"
   (`internal/cli/vaultrekey.go:85`).
2. On **both** key stores, a rotation breaks every AI job and standing
   grant (QA). Confirmed in the code below. Rotation must re-pin them, with
   no re-approval, and only where the secret's value is provably unchanged.

## The decisions, in one table

| # | Decision | Recommendation |
|---|---|---|
| 1 | Same enclave key, or a new one per rotation | **A new one.** Two fixed tags ("slots"), used in turn; the old key is deleted at the end |
| 2 | How many dialogs | **One**, from one `LAContext` opening both sealed files. Needs spike S7b; if it fails, two |
| 3 | How jobs and grants keep working | A **digest map** (old wrapped-key hash to new), written before any envelope changes; the **service** applies it |
| 4 | Who writes `grants.json` and `jobs.json` | **Only the service**, which owns them in memory. The CLI asks it over the socket |
| 5 | The service during a rotation | **Quiet**: job runs, approvals, new grants and unlocks are refused, never stickily |
| 6 | Ship order | The keychain re-pin fix first (it fixes QA's bug on its own); the slot format **must** be in v2.3.0 |

## What rotation protects against, stated honestly

Rotation makes a new master key (MEK), re-wraps every data key (DEK) under
it, and destroys the old MEK. The DEKs and the encrypted values themselves
never change (`internal/vault/rekey.go:18`).

- **It protects:** vault files read *after* the rotation, and every secret
  written after it, from someone who holds the old MEK. Reasons to fear
  that: the MEK sat in the login keychain in the clear for the vault's whole
  life before a move into the enclave (any program running as you could
  read it, `keychainwrap.go`'s own comment); an older jit's keychain copy
  (S3g); the MEK in the service's memory (a crash dump, a debugger against
  a build without the hardened runtime).
- **It does not protect:** a value someone already read, or a copy of an
  old envelope file plus the old MEK. That pair still opens the value,
  because the DEK and the payload did not change. The fix for an exposed
  value is rotating the value itself. The docs should say so (task 9).
- **The enclave key itself** never leaves the enclave, so rotating it
  guards no key material. A new one per rotation matters for two other
  reasons, below.

## What is there today (checked in the code)

**Keychain rotation** (`internal/cli/vaultrekey.go:64`): marker
`rekey.inprogress` with the line `started <time>`; one challenge
(`primary.RequireUserPresence(reasonRekey)`, or `keychainwrap.Challenge`
on a resume after promote); `lockAgent()` before and after;
`EnsureStagedRekeyMEK` (keychain account `…rekey-next`);
`v.Rewrap(oldKW, primary.StagedRekeyWrapper())`;
`PromoteStagedRekeyMEK` (write, read back, then delete the staged item);
remove the marker. Proven lost-key copies are kept and reported
(`vault.Rewrap`, `RewrapResult.Kept`, `printKeptLostKeyCopies`).

**The QA bug, confirmed.**

| Where | What it does |
|---|---|
| `internal/vault/rekey.go:213` | `rewrapFile` replaces every recipient's wrapped DEK |
| `internal/agent/job.go:313` | a job pins `DeviceDigest = wrappedDigest(src.Wrapped)` (sha256 of the wrapped DEK) |
| `internal/agent/job.go:658` | every run, **both ask modes**, compares it before any prompt: "X was rotated since you approved it" |
| `internal/agent/job.go:818` | `refuseJob` sets `Stopped`, which is sticky until re-approval |
| `internal/agent/job.go:593` | `rotatedSecrets` marks the job Rotated in every list |
| `internal/agent/standing.go:801` | a standing grant looks up `g.secrets[wrappedDigest(wrapped)]`: after a rekey it misses, so a grant that never asked starts asking |
| `internal/agent/standing.go:948` | the grant list marks every secret rotated |
| `internal/agent/grant.go:523` | a timed grant misses the same way |

A second hazard the re-pin alone does not fix: a never-ask job or a
standing grant needs no session, so `lockAgent()` does not stop one from
running **during** the rewrap. A job that runs after its envelope was
rewritten stops, stickily, with a false reason. Hence decision 5.

**Grant and job keys do not change on rotation. Confirmed.** They are keys
of their own (`g-`/`j-` ids, keychain items or enclave keys tagged
`com.jitpass.grant.<id>`, `internal/secureenclave/grantkey.go:36`). They
seal the DEK (`GrantWrapped`, `KeyWrapped`), and rotation never changes a
DEK. Only the pin (`DeviceDigest`) goes stale. `MoveGrantKeys` follows the
vault's *kind*, which a rotation does not change, so it moves nothing.

## Part 1: rotation on an enclave vault

### Decision 1: a new enclave key per rotation, in two slots

The sealed file records its key's tag (`kek_tag`), and the `Wrapper`
checks it against its own fixed tag and never follows it
(`internal/secureenclave/wrapper.go:230`). Keeping one key would be the
smallest change: seal the new MEK to the same key, and S2 already proved
one `LAContext` opens it twice with one dialog. It is not enough:

- **"The old master key has been destroyed" would be false.** Any copy of
  the old `vault-key.sealed` (Time Machine, a disk clone, a `cp`) would
  open the old MEK on this Mac for as long as the key lives.
- **A rolled-back file would be used quietly.** A program running as you
  puts the old sealed file back; the next unlock opens the *old*, exposed
  MEK; every secret written after that is sealed under a key the attacker
  holds. With the old key deleted, that file no longer opens at all.

**Design:** two production tags, used in turn:

| Slot | Tag | Notes |
|---|---|---|
| A | `com.jitpass.vault.kek` | every enclave vault today, including the owner's (moved in, PR #173) |
| B | `com.jitpass.vault.kek.b` | the first rotation's target; the next rotation goes back to A with a **fresh** key |

- The `Wrapper` follows the file's tag **only when it is one of its two
  slots**. A grant tag (a key with no `UserPresence`) or any other tag is
  refused as today, so the file can never choose a key that opens without a
  dialog. Tests: `NewTesting` gets `<TEST-ONLY base>` and `<base>.b`.
- A key found in the target slot at the start of a rotation, with no staged
  file naming it, is deleted and made again: a key is never reused. Nothing
  can need it: `vault-key.sealed` names the other slot.
- `Wrapper.Delete` (vault delete, uninstall, the move back) removes **both**
  slots' keys, without reading the file: `jit vault delete` calls it after
  `DeleteLocalState` has already taken the file (`vault.go:2601`, `:2621`).
- `Presence` reads the tag from the file, then checks that slot's key
  (`se_present`, never prompts). An unreadable file is `Indeterminate`.
- The move (`--wrapper secure-enclave`) keeps using slot A, unchanged.
- **This is a format decision, so it must ship in v2.3.0**, the first
  release where a jit chooses the enclave (B3 is in no tag: v2.2.8 lacks
  `#160`). A 2.3.0 with one fixed tag would read a later jit's slot-B vault
  as a **lost key**, and its `jit vault init` would set the vault aside.

### Files and keys during a rotation

| Item | Where | Notes |
|---|---|---|
| Current sealed MEK | `vault-key.sealed` | names slot X |
| Staged sealed MEK | `vault-key.sealed.next` (the move's existing name, `stagedSuffix`) | names the other slot; 0600, atomic |
| Marker | `rekey.inprogress`: line 1 `started <RFC3339>`, line 2 `from <slot X tag>` | line 1 is what `readRekeyMarker` already proves; older jits read only line 1 |
| Digest map | `rekey.digests` (part 2) | same folder and tier as `jobs.json` |

The `from` line is what makes resume provable: the promote is an atomic
rename, so whether `vault-key.sealed` still names X says, with no
guessing, whether the promote happened. Without it, "marker, no staged
file" means either "crashed before staging" or "crashed after promote",
and treating the first as the second would report a rotation that never
happened.

### Order of operations (a fresh run)

| # | Step | Code (new unless noted) | Dialog | A crash here leaves |
|---|---|---|---|---|
| 1 | Refuse a move or unknown marker (as today); `Presence` must be `Present`; ask `[y/N]` | `vaultrekey.go` | no | nothing changed |
| 2 | `lockAgent()`, and again at the end (as today) | existing | no | nothing changed |
| 3 | Write the marker, both lines | `keyRotator` | no | marker; vault refuses writes; re-run stages |
| 4 | Stage: remove a stale `.next`; replace any key in the other slot; create it (`UserPresence`, `WhenUnlockedThisDeviceOnly`, as slot A); generate 32 bytes; seal (S1b: no prompt); write `.next` | `secureenclave.StageRotation` | no | staged file and key; re-run reuses them |
| 5 | **One dialog**: open the current and the staged file with one `LAContext`; compare the staged plaintext with the generated MEK (constant time) | `se_open_pair`, `secureenclave.OpenForRotation` | **1** | as 4. A Cancel or a mismatch aborts cleanly: staged file, new key and marker removed, "nothing changed" (the move's `abort`) |
| 6 | Plan the rewrap: every envelope read, re-wrapped and verified **in memory**; lost-key copies classified | `vault.RewrapWith` | no | as 4 |
| 7 | Write the digest map | `rekeymap.Write` (atomicfile) | no | as 4, plus a map |
| 8 | Write each envelope (atomic, as today) | `vault.RewrapWith` | no | envelopes under either MEK, both keys open; the map covers every one written |
| 9 | Ask the service to re-pin; on success remove the map | op `rekey_repin` | no | pins re-pinned, or the map kept for the service |
| 10 | A keychain copy (a move left it) that holds the **old** MEK is deleted | `kcMatches`, `kcDelete` (the mover's) | no | the copy, still reported by doctor |
| 11 | Promote: rename `.next` over `vault-key.sealed` | `secureenclave.PromoteStaged` (existing) | no | the vault opens from the new key; the old key still exists |
| 12 | Delete the old slot's key | `secureenclave.DeleteSlot` | no | as 11 |
| 13 | Remove the marker; print the result | `keyRotator.finish` | no | done |

Why stage (4) before the dialog (5): one C call can then open both files
under one `LAContext`, which is the only way to one dialog without a
context object crossing into Go. Nothing is at stake before the dialog: the
new key protects nothing yet, and a Cancel removes it. The marker comes
first, as in the move (`toEnclaveAs` writes it before `kcFetch`), so a
crash in 4 or 5 is finished by `jit vault rekey`, which again cannot pass
step 5 without the dialog. No crash is a way around the approval.

Step 10 is a small addition: after a rotation, a keychain copy of the old
MEK is exactly the key the rotation set out to destroy, still readable by
any program running as you. It is deleted only when the quiet read proves
it holds the old MEK (the move's `MatchesMEK`); anything else is left and
doctor's `vault_key_copy` keeps reporting it, as today (decision D4 below).

### Resume

The marker is a rotation's (`started …`, `markerRotation`); X is its
`from` tag; Y is the other slot.

| `vault-key.sealed` names | `.next` | Means | `jit vault rekey` does |
|---|---|---|---|
| X | absent | stopped before staging finished | step 4 from the start (a key left in Y is replaced) |
| X | names Y | staged | step 5 (no compare: the staged file's MEK *is* the new one), then 6 on; envelopes already under the new MEK count as current |
| Y | absent | promoted | one dialog to open the new key; `Rewrap` with no old key, so every envelope must already be current (today's keychain resume); then 12, 13 |
| anything else (`.next` names X, both name Y, a tag that is no slot, no `from` line) | | can't prove | refuse, naming the files; nothing changed |

The last row's wording follows the proven-marker rule
(`secure-enclave.md`, "A rotation resumes only over a marker it can prove
is a rotation's"). It says what jit found and that nothing changed, and it
names no file to remove.

### Decision 2: one dialog

| Run | Keychain vault | Enclave vault |
|---|---|---|
| Fresh | 1 (today) | **1** if S7b passes, else 2 |
| Resume before promote | 1 | 1 (or 2) |
| Resume after promote | 1 (today's bare challenge) | 1 |

`se_open` makes a new `LAContext` per call (`enclave.m`, `se_open`). S2
measured a second open of the **same** key on one context: 0.008 s, no
dialog. Whether one context covers a **second** key is unmeasured (S7b).
The new C function, `se_open_pair(tagA, blobA, tagB, blobB, reason, …)`,
does both opens on one context and returns both plaintexts; Go wipes both
C copies as `takeBytes` does. `OpenForRotation(cur, next, reason)` primes
both `Wrapper`s' caches, so `RewrapWith` uses them with no further dialog.
Reasons stay `reasonRekey` / `reasonRekeyFinish`, read after "JitPass is
trying to" (C5).

### Lost-key copies

Unchanged in substance: rotation never stops on a PROVEN lost-key copy and
never destroys one (`secure-enclave.md`, "Copies sealed to the lost key are
kept for good"). The plan pass classifies each file exactly as
`vault.Rewrap` does today (`lostKeyCopies`, `matchFile`, `provenLost`); a
kept file is never written and gets no map entry. One improvement falls
out: an unproven file now stops the rotation **before any envelope is
written**, instead of part way through.

Init over a lost key while an enclave rotation's marker exists: both slots
are keys on the same enclave, so a reset loses both. `jit vault init` must
set `.next` aside with `vault-key.sealed` (never delete it) and clear the
rotation's marker, since that rotation can never finish. The lost-key
record already hashes every envelope, under either MEK (task 7).

### The move's marker and staged file

A move and a rotation share the marker and never finish each other's work
(today: `vaultrekey.go:77`, `runVaultMove`'s `markerRotation` refusal).
They also share `vault-key.sealed.next`; the marker says whose it is, and
a fresh rotation removes a stale one first, as a fresh move does
(`seRemoveStaged`). `keychainCopyLeft` already says nothing under any
marker, so doctor does not report the copy twice mid-rotation.

### What the keychain path shares

Refactor `vaultrekey.go`'s `RunE` into a **`keyRotator`**
(`internal/cli/vaultrotate.go`), shaped like `keyMover`: every operation a
func field, a `crash func(step string) error` hook, two constructors.

| Shared (one code path) | Per store |
|---|---|
| marker, confirm, `lockAgent`, `RewrapWith`, the digest map, `rekey_repin`, lost-key report, result text | stage, the one dialog, promote, delete the old key |
| | keychain: `EnsureStagedRekeyMEK`, `RequireUserPresence` / `Challenge`, `PromoteStagedRekeyMEK` (unchanged) |
| | enclave: `StageRotation`, `OpenForRotation`, `PromoteStaged`, `DeleteSlot` |

The keychain marker stays one line: its resume already proves itself
through `HasMEK`.

## Part 2: jobs and grants keep working

### Why a digest map is sound

A pin says "the wrapped DEK at path P hashed to D when the human approved".
After a rewrap the same DEK is wrapped again, so its hash changes while the
value cannot: `rewrapFile` checks the new wrapped key opens to the same
DEK before writing (`rekey.go:204`), the payload bytes are untouched, and
`Set` always makes a fresh DEK (`vault.go:224`), so the same DEK means the
same write of the same value.

**The rule:** re-pin (P, D) to C only when C is the hash of the envelope at
P **now** (`OnWrappedDEK(P)`), and the map holds a chain D to … to C. Each
link was written by a rewrap that proved the DEK unchanged, so the chain
proves the DEK at P now is the approved one. A value changed since
approval (a new DEK) is never reached by a chain: the job still says
"rotated", correctly. A pin can never move to another path, because C is
read at P. Chains cover several rotations while the service was down;
following one is bounded by the map's length, so a cycle cannot loop.

**Trust.** The map lives beside `jobs.json` and `grants.json`, 0600, in
the folder sandboxed callers must never write (`internal/job/store.go:21` to `:24`).
A program that can write the map can already rewrite a job's pin directly,
so the map adds no capability. A MAC keyed from the MEK was considered
and rejected: it guards nothing beyond that tier, and the service has no
MEK while locked, which is exactly when never-ask jobs run.

### The map file

`rekey.digests`, owned by a small new package `internal/rekeymap` (pure
Go, atomicfile only), because the CLI writes it and the agent reads it and
neither imports the other's packages:

```json
{"version": 1, "changes": [{"old": "<sha256 hex>", "new": "<sha256 hex>", "file": "aws/key.enc"}]}
```

- `rekeymap.Digest` becomes the one definition of the hash;
  `agent.wrappedDigest` calls it (a test pins them together).
- Written **once per run**, whole, with `atomicfile.WriteFile`, merging
  what an earlier crashed run wrote, **before the first envelope write**.
  That is why `RewrapWith` plans every file first: the new wrapped bytes
  are random, so they are only known once made, and a map written after
  the envelopes would lose, in a crash, the old hashes nothing can
  recompute. One extra file write per run, not one per envelope.
- An entry for an envelope a crash never wrote is harmless: no pin can
  chain to a hash no envelope has.
- `file` is for reading by people only; the rule above never uses it.
- A version it does not know, or a file that does not parse, is an error:
  nothing is applied, the file is kept, the service logs why.

`vault.RewrapWith(oldKW, newKW, RewrapOptions{BeforeWrite func([]WrapChange) error})`:
pass 1 reads, re-wraps and verifies every file in memory (DEKs wiped per
file as now; about 1 KB per envelope held); pass 2 calls `BeforeWrite`,
then writes each planned file after checking its bytes are still the ones
planned from (a file changed under the marker stops the rotation, both
keys intact). `Rewrap` and `RewrapAll` stay, calling it with no hook.

### Decision 3 and 4: the service applies it

`grants.json` and `jobs.json` are the running service's: it holds them in
memory and rewrites them on every structural change and on serve
bookkeeping (`saveLedger`, `saveJobsLocked`, both through `writeState`,
atomic and durable). A CLI that edited them on disk would be overwritten
by the service's next save. So:

- **`Server.ApplyRekeyMap() (repinned int, err error)`**: reads the map;
  snapshots every pin (standing grant secrets, job secrets, timed grants'
  in-memory `deks` keys); reads each P's current hash **outside** the
  locks; then, under `grantMu` / `jobMu`, re-pins those still at their old
  hash; saves the ledger and the job list. Unread entries (`verbatim`,
  `unread`, `Kept` records) are left byte for byte, as every save leaves
  them. `Stopped` is never cleared: a stop stays sticky.
- It runs **at service start** (`servicerun.go`, after `SetJobStore`, before
  `MoveGrantKeys` and before the socket opens), **on the new op
  `rekey_repin`** (no payload, no prompt: it only applies a file in the
  service's own folder), and **lazily** when a job run, a standing grant's
  miss or a list finds a mismatch while the map file exists (one `stat`).
- It removes the map only when both files were saved **and no rotation
  marker exists** (the CLI may still be writing it). Under the marker the
  CLI removes it, after `rekey_repin` reports success.
- Mid-apply failure: memory may be ahead of disk, but the map stays, so a
  restart applies it again. Applying is idempotent.
- Service unreachable (not running, or older than the CLI and the op
  unknown): the CLI goes on and says when the re-pin happens: "AI jobs and
  grants switch to the new key when the jit service next starts." For an
  older running service: "Restart the jit service (`jit service restart`)
  so your AI jobs and grants keep working."
- The result line, on success: "Kept N AI jobs and M grants working under
  the new key."

### Decision 5: the service during a rotation

New hook `Server.RotationUnderway func() bool`, wired to
`readRekeyMarker(root)` (a rotation's marker, or one jit can't read; not a
known move, which leaves every digest alone). While it says yes:

| Request | Answer | Sticky |
|---|---|---|
| `job_run`, either ask mode | "the vault key is being rotated; run it again once `jit vault rekey` finishes" | **no**: `Stopped` untouched |
| `job_allow`, `grant_create` | the same, refused | n/a |
| an unlock (`FetchMEK`) | refused: mid-rotation a session would open only part of the vault | n/a |
| a standing grant's serve | a miss, as today, falls through to the ordinary path (locked) | n/a |

And whatever the marker says: **a digest mismatch while the map file
exists is never sticky.** The service applies the map and checks again;
if it still mismatches, the refusal names the cause ("jit couldn't update
this job after the key rotation: …") without stopping the job.

### Crash windows

| A crash between | Pins on disk | Envelopes | Service | Recovery |
|---|---|---|---|---|
| marker and map | old | old | quiet | re-run |
| map and the last envelope | old | mixed | quiet | re-run: the map already covers every envelope written; the rest get new entries |
| last envelope and re-pin | old | new | quiet | re-run: everything current, then `rekey_repin` |
| re-pin and promote | new | new | quiet | re-run finishes |
| promote and marker removal | new | new | quiet | re-run deletes the old key |
| re-pin failed, rotation finished | old | new | map present, no marker | start applies it before the socket opens; a running service applies it at the first mismatch, never stickily |

At no instant is a pin left with nothing that can re-pin it, and at no
instant can a job stop stickily because of the rotation. The order
"re-pin before promote" puts everything that can fail harmlessly while both
keys exist, and leaves the promote and the old key's deletion last.

## Part 3: spikes on hardware

All through `scripts/se-test.sh`, TEST-ONLY tags and a fixture vault,
never the real key. Results go into `spike/secure-enclave-mek/FINDINGS.md`.

| # | Question | Pass |
|---|---|---|
| S7a | A second sealed MEK, under the same key and under a **new** key made while unlocked, with no dialog | no dialog for create or seal; both open |
| S7b | One `LAContext` opens two **different** `UserPresence` keys | second open under 0.1 s, no dialog. Control: two contexts show two dialogs |
| S7c | After the old key is deleted, a copy of the old sealed file | fails with `ErrNoKey`; after A to B to A (a fresh A), the first era's A file fails to open (an authentication error, never a wrong plaintext) |
| S7d | Timing: a fixture of 30 secrets and 500 backups | wall time per phase (dialog excluded): plan, map write, envelope writes, promote. Same fixture on the keychain path. Record the numbers; target under 10 s |
| S7e | A crash at every step on hardware (the crash hook), then resume | every envelope opens after each crash and after the re-run |

## Part 4: status and doctor

| State | `jit status --format json` | `jit doctor` kind | Fix |
|---|---|---|---|
| An enclave rotation did not finish (a marker with `from`) | nothing new | `rekey`, today's text | `jit vault rekey` |
| An enclave vault with a rotation marker that has no `from`, or names no slot | nothing new | `rekey_unknown` | "update jit, then finish it with the newer jit" |
| The old slot's key could not be deleted | nothing new | `rekey` (the marker stays, decision D3) | `jit vault rekey` |
| The map is waiting for the service | nothing | nothing: the service applies it at start, and the lists apply it lazily | none |

No new status field: the app already turns `rekey` into "Unfinished key
rotation" with a "Finish Rotation" button. Every line follows the rule
already kept here: it says what happened; the step is a jit command or the
person's own choice; nothing says "delete". New sentences, drafts:

- "This vault's key in the Secure Enclave is lost, so it can't be rotated.
  `jit doctor` says what to do." (Presence `KeyLost`)
- "The vault now uses the new key, but the old key in the Secure Enclave
  couldn't be removed (<err>). Run `jit vault rekey` to finish."
- "Master key rotated. 530 envelopes re-wrapped. The old master key has
  been destroyed." then "Kept 3 AI jobs and 1 grant working under the new
  key."

## Part 5: the app (jit-app)

`Vault Maintenance → Rekey…` (`VaultMaintenanceSheet.swift:33`) opens
`rekeyVault()` (`StatusItemController+VaultMaintenance.swift:180`), which
says "… Touch ID follows." and runs `jit vault rekey --yes`. Doctor's
"Finish Rotation" (`DoctorAdvice.swift:240`) runs the same.

- **If S7b passes: no app change.** One dialog, the same text is true, and
  the "rekeyed" notice stays.
- **If it fails:** the alert must say the enclave asks twice. That is UI
  text: mockup first, then the change.
- The jobs' Rotated state and the grants' rotated rows stop appearing after
  a rotation; nothing to change.
- Not proposed: a notice counting the jobs kept working. Nice, but a new
  sentence in the UI, so it would need its own mockup.

## Part 6: tests

Every safeguard gets a test that was run against the code without it.

**Unit, with fakes** (plain `go test`):

| Package | Test | Negative control |
|---|---|---|
| `rekeymap` | chains resolve; a cycle stops; an unknown version or garbage applies nothing | remove the bound: the cycle test hangs (timeout) |
| `vault` | `RewrapWith` calls `BeforeWrite` with every change before the first write | call the hook after the writes: a crash in the hook leaves a rewritten file with no entry |
| `vault` | an unproven envelope stops the rotation before any write | today's one-pass loop fails it |
| `vault` | a file changed between plan and write stops it, both keys intact | drop the recheck |
| `agent` | a never-ask job runs unasked after a rotation plus `ApplyRekeyMap` | without the apply: "rotated", `Stopped` set |
| `agent` | a value changed since approval stays rotated (no chain reaches it) | apply by `old` alone, ignoring the current hash: the job re-pins to the new value |
| `agent` | a chain to another path's envelope is never applied | the same |
| `agent` | `job_run` under `RotationUnderway` refuses without setting `Stopped` | remove the check: the job stops stickily mid-rewrap |
| `agent` | a standing grant serves the new wrapped bytes; a timed grant too | no apply: miss |
| `agent` | a save failure keeps the map; a restart re-applies | remove the "both saved" guard: the map is gone, the pins are old |
| `agent` | unread entries and kept records come back byte for byte | re-marshal them |
| `secureenclave` | the file's tag is followed only among the two slots; a grant tag is refused | follow any tag: the fake opens a file sealed to a no-presence key |
| `secureenclave` | `Delete` with no file removes both slots | the file-driven `Delete`: slot B stays |
| `secureenclave` | the fake counts contexts: one per `OpenForRotation` | two `FetchMEK` calls: two |
| `cli` | `TestRotateSurvivesACrashAfterEveryStep`, both stores, in the style of `TestMoveSurvivesACrashAfterEveryStep` (below) | skip the map write: a crash after "written 1" leaves a job with no chain |
| `cli` | every resume row, and every refusal row | resume without `from`: the "promoted" row claims a rotation that did not happen |
| `cli` | a Cancel at the dialog leaves nothing: no marker, no `.next`, no slot-Y key | leave the marker: every vault command refuses |
| `cli` | one dialog per run, each store, each resume | two opens: the count is 2 |
| `cli` | a two-line rotation marker is still `markerRotation` for doctor, status and the move's refusal | read the whole file as one line |

**Crash points** (the hook, after each step): `marker`, `staged`, `opened`,
`mapped`, `written 1` (after the first envelope), `rewritten`, `repinned`,
`copy removed`, `promoted`, `old key deleted`. After each: some key
present opens every envelope; the marker is there; every pin is current or
reaches the current hash through the map; a re-run finishes; then every
envelope opens under the final key alone, every job runs (unasked for
never-ask), every grant serves, and the old slot is empty.

**Hardware** (`scripts/se-test.sh`, `JIT_SE_INTERACTIVE=1` where a dialog
shows): `TestHardwareRotateRoundTrip` (fixture vault, two rotations,
A to B to A, one dialog each, with the S7d timings logged),
`TestHardwareOpenPairOneDialog` (control: two contexts),
`TestHardwareOldSealedFileNeverOpens`, and the crash-then-resume of S7e.
Manual pre-release check: a real never-ask job and a standing grant, a
rotation, then the job run with the screen locked for 15 s or more (S4's
recipe).

## Part 7: docs to update when it lands

| File | Change |
|---|---|
| `design/secure-enclave.md` | lines 201 to 203 point here; the status and doctor table's rotation row; the slots in "Keys" |
| `design/secure-enclave-plan.md` | the status table gains these tasks; B4's "Rotating the MEK stays plain `vault rekey`" |
| `design/standing-grants.md` | "Rotation, and anything else that uncovers a secret": a `vault rekey` no longer uncovers |
| `design/agent-jobs.md` | a rotated secret: `vault rekey` re-pins; a value change still stops |
| `docs/vault/maintenance.md` | enclave vaults; one dialog; jobs and grants keep working; what rotation protects against, honestly |
| `internal/cli/vaultrekey.go` help, then `go run ./cmd/jit docs-gen` | regenerates `docs/reference/commands/jit_vault_rekey.md` |
| `docs/security/architecture.md:26` | "the master key lives in the macOS login Keychain" is half true since B3 |
| `docs/testing/pre-release-playbook.md` | the rekey rows: an enclave vault, and jobs and grants after it |
| `internal/keystore/keystore.go` doc (lines 22 to 24) | "Rekey … keychain-specific until step B4" |
| `internal/secureenclave/doc.go`, `vault/rekey.go`, `keychainwrap/rekey.go` comments | slots; `RewrapWith`; the map |
| `CLAUDE.md` | the `secureenclave` paragraph: rotation also writes a sealed file; two slots |
| `scripts/se-test.sh` usage | the new hardware tests |

## Part 8: risks and open decisions

| # | Question | Recommendation |
|---|---|---|
| D1 | New enclave key per rotation, or keep one | **New, in two slots.** Keeping one leaves old sealed files able to open the old MEK and lets a rolled-back file be used quietly |
| D2 | If S7b fails | **Two dialogs, keep the new key.** The alternative (same key, one dialog) buys one tap with the two properties D1 is for |
| D3 | The old slot's key won't delete | **Keep the marker**; `jit vault rekey` finishes by deleting it. The rotation's promise is that the old key is gone; the alternative (finish and warn) needs a new doctor state. Such a failure should be rare |
| D4 | A keychain copy holding the old MEK | **Delete it in the rotation** when the quiet read proves it is the old MEK; leave anything else to doctor, as today |
| D5 | Who re-pins | **The service**, from the map. The CLI writing `jobs.json` would be overwritten by the running service |
| D6 | How quiet the service is mid-rotation | **Refuse job runs, approvals, new grants and unlocks, never stickily.** Making mismatches non-sticky alone would still let a job run between rewrap and re-pin with a refusal the user can't explain |
| D7 | Jobs already stopped by an earlier rekey | **Leave them stopped.** The old hashes are gone, so nothing can prove them; re-approval is the way, as the sticky rule says |
| D8 | Ship order | Keychain fix first (tasks 2 to 4, fixing QA's bug on 2.2.x vaults); slots (task 5) are **required** in v2.3.0 even if enclave rotation slipped |

| Risk | How it is handled |
|---|---|
| A CLI newer than the running service (op unknown) | The map waits; the CLI asks for `jit service restart`; the stale-binary self-retirement usually restarts it first |
| A sealed file naming an empty slot while the other slot has a key (a planted old file) | Reads as `KeyLost`, as a missing key does today. Accepted: `jit vault init` never deletes, so putting the right file back still works. Called out for the reviewer |
| Memory of the plan pass | New wrapped keys only, about 1 KB per envelope; DEKs are wiped per file as now |
| Time | One extra atomic write per run; S7d measures the rest |
| Rotation read as "secrets are safe again" | The docs say what it does not do (Part 7) |

## Part 9: tasks

Sizes: S up to a day, M two to three days, L about a week. **Review**:
every task touching Secure Enclave or key code gets a code review before
merge (the owner's rule).

| # | Task | Repo | Size | After | Review |
|---|---|---|---|---|---|
| 1 | Spikes S7a to S7e on hardware; findings | jit (`spike/`) | S | none | owner reads |
| 2 | `internal/rekeymap`; `vault.RewrapWith` (plan, map hook, write, recheck) | jit | M | none | **yes** |
| 3 | Service: `ApplyRekeyMap`, op `rekey_repin`, start and lazy apply, `RotationUnderway`, non-sticky refusals | jit | M | 2 | **yes** |
| 4 | `keyRotator` refactor; the keychain rotation through 2 and 3. **Fixes QA's bug on keychain vaults** | jit | M | 3 | **yes** |
| 5 | `secureenclave` slots (tag from the file, two accepted, `Delete` both, `Presence`), `se_open_pair`, `StageRotation`, `OpenForRotation`, `DeleteSlot` | jit | M to L | 1 (S7b decides the pair) | **yes** (CGo) |
| 6 | Enclave rotation in `keyRotator`: order, resume table, keychain copy, texts; lift the refusal at `vaultrekey.go:85` | jit | M | 4, 5 | **yes** |
| 7 | Clean-up: `DeleteLocalState` also removes `.next` and `rekey.digests`; `jit vault delete` removes the marker (promised in B3, not done); init over a lost key under a rotation marker | jit | S | 6 | **yes** |
| 8 | Hardware tests; `se-test.sh` usage | jit | S | 6 | **yes** |
| 9 | Docs (Part 7) | jit | S | 6 | owner reads |
| 10 | Only if S7b fails: the alert's text, mockup first | jit-app | S | 1 | UI review |

```
now      1 ─────────────┐
         2 ─▶ 3 ─▶ 4 ───┤  (4 can ship alone: keychain vaults fixed)
                        5 ─▶ 6 ─▶ 7, 8 ─▶ 9
v2.3.0   5 at least; 2 to 9 as the goal
```

About two weeks of work, plus review time, with 1 and 2 to 4 in parallel.
