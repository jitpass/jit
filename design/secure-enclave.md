# Secure Enclave: the master key behind hardware, nothing else moves

**Status: jit built and merged (B1–B4, C1–C2, 2026-09-25); the app side (jit-app #52, #53) waits on a signed test build, so no user can move a vault yet. `design/secure-enclave-plan.md` has the per-step table; the spikes are in `spike/secure-enclave-mek/FINDINGS.md`.** Read
`standing-grants.md` ("For the Secure Enclave move") and
`agent-jobs.md` (branch `ai-jobs`) first; this page keeps both working
unchanged.

Today the Touch ID prompt is a check jit runs on itself
(`keychainwrap.go:19`, "not cryptographically enforced"): the master key
(MEK) is a plain item in the login keychain, and any program running as the
user that can read that item skips the prompt. Moving the key into the Secure
Enclave makes the prompt the hardware's decision, not jit's.

## Are we ready? (checked 2026-09-25)

| Area | Ready? | Evidence |
|---|---|---|
| One place the key enters the service | **Yes** | `agent.MEKFetcher.FetchMEK` (`internal/agent/fetcher.go`). Every prompt goes through it (`promptOrBroker`, `consentbroker.go:189`), including an AI Job's per-run Touch ID |
| Stored secrets independent of how the MEK is stored | **Yes** | Envelopes hold DEKs wrapped by the MEK (`vault.go:229`); nothing records where the MEK lives |
| Grant and job keys behind an interface | **Yes** | `agent.GrantKeyStore` (`standing.go:61`); jobs reuse it (`ai-jobs` branch, `job.go:226`, `:555`) |
| Key formats versioned, unknown ones refused | **Yes** | `standingWrapAEAD = "aead-v1"`; the grant loader skips an unknown wrap (`standing.go:271`); the job runner refuses one (`ai-jobs`, `job.go:643`) |
| Enclave crypto works for our shape | **Yes, measured** | S1: a sealed 113-byte MEK, 4.5 ms to open, tamper and wrong-key refused. S1b: sealing never prompts |
| Machinery to swap keys safely | **Yes** | `vault rekey`'s staged key, marker file and resume (`vaultrekey.go`) |
| The agent runs from inside the app | **Yes** | The plist points at `/Applications/JitPass.app/Contents/MacOS/jit` |
| A provisioning profile | **Half** | App ID `com.jitpass.agent` and the development profile `JitPass Agent Dev` exist (2026-09-25), carrying `keychain-access-groups = CZC6BH93GJ.*`. The Developer ID profile for CI is not made yet |
| **Entitlements on jit's own signature** | **No** | jit-app's `sign.sh` signs without `--deep`, so the bundled `jit` keeps the signature goreleaser gave it, which carries no entitlements. The entitlement has to be on *that* binary |
| **A helper bundle for the agent** | **No, and now required by measurement** | S3a: a second executable in a correctly signed bundle is killed at launch (exit 137); only the main executable gets the profile. `Contents/MacOS/jit` is a second executable in `JitPass.app` |
| CLI commands that read the key without the service | **Yes** | Eleven call sites build `keychainwrap.New()` in the CLI process (below). S3c: a Go `jit` as the helper's main executable, reached through a symlink and a `PATH` lookup, creates and opens the key |
| **Grants and never-ask jobs while the screen is locked** | **At risk, fix measured** | S4: `WhenUnlocked` fails `-25308` about 9 s after locking; `AfterFirstUnlock` keeps working. Today's items are in the file-based login keychain (checked: `login.keychain-db`), which ignores `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Enclave keys live in the data-protection keychain, which enforces it. A straight port stops never-ask jobs whenever the Mac is locked |
| **Moving to a new Mac** | **Regression to design for** | A file-based login keychain item is carried by Migration Assistant; an enclave key never is. S6 confirms today's behaviour |
| Macs without Touch ID | **Covered** | S2: a `UserPresence` key's dialog offers "Use Password…". The old spike used `BiometryAny`, which fails with no fingerprint enrolled. Use `UserPresence` (Touch ID or the login password), matching today's fallback |
| Tarball / `go install` users | **Stay as they are** | A bare binary can never hold the entitlement (`spike/secure-enclave/FINDINGS.md`). They keep `keychainwrap` |

**Verdict.** The code is ready: one seam, versioned formats, interfaces
where the keys live, and nothing in AI Jobs or MCP that depends on how the
MEK is stored. The packaging is not ready: profile, helper bundle,
entitlements on jit's signature. Three behaviours need a decision before
the first line of code: screen lock, a new Mac, and Macs without Touch ID.

## The decision: the enclave key seals the MEK, the MEK stays

The enclave holds a P-256 key. The MEK stays a 32-byte AES key, stored
**sealed** to that enclave key (ECIES) instead of in the clear. Unlocking
opens the sealed MEK, which asks for Touch ID in hardware. From there
everything is today's code.

```
today      FetchMEK → jit's own LAContext check → read plain keychain item → MEK
enclave    FetchMEK → SecKeyCreateDecryptedData(enclave key, sealed MEK)
                        └ the enclave asks (Touch ID or password) → MEK
```

What does **not** change:

- **Envelopes.** Every secret, backup and archived version stays wrapped by
  the same MEK. Nothing is rewritten.
- **The service's session.** The agent still keeps the MEK in memory for the
  idle TTL, still drops it on lock and sleep, and still names the caller in
  the prompt (the reason travels on the LAContext).
- **Standing grants and AI Jobs.** In phase 1 they don't notice. Phase 2
  moves their keys without a prompt and without re-approval (below).
- **`jit mcp`.** A socket client that never unwraps.

**Rejected: an enclave key per secret.** Each read would reach the enclave
and could prompt; the session model, grants, the ledger and every envelope
would change, and the whole vault would need rewriting. It costs far more
and adds little: the MEK already sits in the service's memory during a
session, whatever wraps it at rest.

**What it buys, stated honestly.** At rest, the MEK can no longer be read by
another program running as you, not even with the keychain unlocked. During
a session, the MEK is still in the service's memory, as it is today. A
hardened-runtime binary without `get-task-allow` cannot be attached to by a
same-user debugger, which S3 confirms on the signed helper.

## Phase 1: the master key

**Keys.**

| Item | Where | Access control |
|---|---|---|
| Vault key-encryption key | Secure Enclave, tag `com.jitpass.vault.kek` (slot A) or `com.jitpass.vault.kek.b` (slot B, a rotation's; `secure-enclave-rotation.md`, D1) | `PrivateKeyUsage \| UserPresence`, `WhenUnlockedThisDeviceOnly` |
| Sealed MEK | `<vault root>/vault-key.sealed`, 0600, JSON `{version, wrap: "se-p256-ecies-v1", kek_tag, blob}` | ciphertext; its presence is how every jit knows this vault uses the enclave. `kek_tag` names the slot; a jit follows it only to one of the two, and refuses a slot it does not know as "sealed by a newer jit; update jit", never as a lost key |

Both keys live in the keychain access group **`CZC6BH93GJ.com.jitpass.vault`**,
not one derived from a bundle ID. `menu-bar-app.md` warns that a key tied to
the bundle ID is orphaned if the ID changes; a named group can be granted to
whichever signed binary needs it.

**Code.** A new `internal/secureenclave` implementation of `agent.MEKFetcher`
and `vault.KeyWrapper` (the package exists and holds only `doc.go`), plus one
factory both the service and the CLI call, `keystore.Open(root)`, that
returns the enclave wrapper when `vault-key.sealed` exists and
`keychainwrap` otherwise. The eleven direct call sites move to the factory:

| Call site | What it does |
|---|---|
| `servicerun.go:136` | the service's fetcher |
| `vault.go:65`, `:1614`, `:2748` | fresh-auth commands: a presence check, restoring a version, `migrate caches`, export |
| `vault.go:1009` | `vault init` |
| `vault.go:2441`, `uninstallsteps.go:92` | deleting the key |
| `vault.go:2775` | the CLI's fallback when the service is down |
| `vaultrekey.go:64` | rekey |
| `doctorsections.go:80` (which `status` also reads), `firstrun.go:148` | presence checks without a prompt: the sealed file exists **and** the enclave key is found by tag |

If S3c fails (the CLI through the symlink doesn't get the entitlement), the
fresh-auth commands need a new service op, and the service-down fallback
becomes an error: *"Start the jit service: this vault's key is in the Secure
Enclave."*

**Migrating a vault.** `jit vault rekey --wrapper secure-enclave`, the name
`menu-bar-app.md` already reserves, run by hand first:

1. Fresh Touch ID; read the plain MEK. Write the rekey marker.
2. Create the enclave key; seal the MEK; write `vault-key.sealed.next`.
3. Open it back through the enclave and compare it with the MEK. S2 checks
   whether the LAContext from step 1 covers this, so there is only one
   prompt.
4. Rename to `vault-key.sealed`; `lockAgent()` so the service reloads.
5. Only then delete the plain keychain item. Remove the marker.

A crash anywhere before step 5 leaves the plain key in place and working.
Step 5 is the one that may fail without blocking the vault: once the sealed
file is in place the vault opens from the enclave, so a keychain copy that
won't delete (an older jit's item refused the delete on real hardware,
S3g in `spike/secure-enclave-mek/FINDINGS.md`) finishes the move anyway and
is reported until removed. The move says an older jit elsewhere on this Mac
can still read it: that copy is the key, readable, not a dead leftover. Its
way out depends on a quiet read of the copy made right after: a locked
keychain (-25293) is "unlock it, then `jit vault rekey --wrapper
secure-enclave`"; a copy this jit isn't allowed to read (-25308) or can't
use never names that command as the fix, since its removal would fail the
same way. When the enclave opened in the same run, Keychain Access is
named as the person's choice (this vault doesn't need the copy);
otherwise the command, which opens the enclave first and then names it.

**A key left in the keychain.** `jit vault delete` deletes the vault's key,
and for an enclave vault the keychain copy too, through the reference
fallback when an older jit made it (S3g). If a keychain item under the vault
key's name still won't go, delete finishes and says so, naming the item:
"couldn't delete the old copy of the vault key from your keychain (<err>).
Delete "com.jitpass.vault.mek" in Keychain Access, or a new vault made with
`jit vault init` reuses it." (for a keychain vault, "the vault key" rather
than "the old copy"). The enclave key and the copy each get their own
warning (`ErrEnclaveKeyKept`, `ErrKeychainCopyKept`).

`jit vault init` on a keychain vault then does what it always has:
`kw_ensure_mek` keeps an item it finds. That is a known weakness, chosen
over the alternative. PR #170 first wrote a `keychain-key.leftover` marker
and refused every use of the key until init had asked about it. A review
found that worse: an older jit that ignored the marker could init and store
secrets under the key, after which every command, the service's unlock and
rekey were refused on a vault that worked, and the only way out deleted the
key those secrets needed; `jit status`, `jit doctor` and the app could not
see the marker; and a service session already unlocked walked past it. The
weakness left is narrow and visible: it needs a delete that failed even
through the fallback, which the warning names on the spot, and the reused
key is one that was already on this Mac, readable by the same programs as
before. A lockout of a working vault is neither.

**Init over a lost enclave key.** `jit vault init` over a LOST enclave key
measures an item it finds (`keystore.KeychainKeyOpens`: read with no
challenge and no dialog, always, and tried against every live secret): if
it opens every live secret, it is the vault's own key and the vault is
restored from it, said in three lines, with `vault-key.sealed` set aside
as `vault-key.sealed.recovered-<time>` and nothing pending. Anything else
is refused with nothing changed, and one rule decides the wording: **jit
advises removing a keychain item only when it has proven the item opens
none of this vault's secrets** (read, every live secret tried, none
untested, none opened, at least one secret). That case alone says "Remove
"com.jitpass.vault.mek" in Keychain Access, then run `jit vault init`
again". Otherwise:

- a LOCKED login keychain (presence answers, the quiet read fails at once
  with -25293, `QuietReadError.MayBeLocked`): "your keychain may be
  locked … Unlock it, then run `jit vault init` again".
- an item this copy of jit isn't allowed to read (-25308,
  `QuietReadError.NotAllowed`; another signer's or another path's item):
  not a lock, and every run of this jit fails the same way. It says so,
  and leaves removing the item to the person, recovery file first: "If
  your recovery file has your secrets, you can remove that key yourself in
  Keychain Access (…), run `jit vault init` again, then import the file;
  jit can't tell whether that key is still needed".
- an item jit can't use (not a master key, another status), or a vault
  with no secrets to try it on: the same person's-choice line.
- secrets whose envelope couldn't be read (untested): "jit couldn't test N
  secrets against the key in your keychain … Nothing changed; jit won't
  use that key or remove it. Once jit can read them, run `jit vault init`
  again".
- a key that opens some of the secrets: the cost said plainly ("Removing
  it loses those N unless your recovery file has them. jit won't use it or
  remove it"), then the person's-choice line.

Nothing in these refusals says "delete".

The reverse, `--wrapper keychain`, writes the plain item back, verifies it,
then deletes the sealed file and the enclave key. An item already under
the vault key's name that it can't read quietly
(`keychainwrap.ErrExistingKeyUnreadable`) is never written over: the move
stops with nothing changed, worded by the cause as above. **The reverse ships
tested before the forward** (`menu-bar-app.md:133`). Rotating the MEK
itself stays today's `vault rekey`; under the enclave, staging a new MEK is
sealing it, which S1b shows needs no prompt.

**What status and doctor say about the key** (files only, never a prompt):

| State | `jit status --format json` | `jit doctor` kind | Fix |
|---|---|---|---|
| A move did not finish | `vault.move_unfinished`: `"secure-enclave"` or `"keychain"` | `vault_move` | `jit vault rekey --wrapper <target>` |
| A rotation did not finish | nothing new | `rekey` (unchanged) | `jit vault rekey` |
| A marker jit can't read, or a change it doesn't recognise (a move to a target only a newer jit knows) | nothing new | `rekey_unknown` | none: "update jit, then finish it with the newer jit", or make the file readable |
| Secrets still sealed to a lost enclave key | `vault.restore_pending`: `true` | `vault_restore` | `jit vault import <file>` |
| The lost-key record can't be checked | `vault.restore_pending`: `true`, `vault.restore_check_error`: why | `vault_restore`, detail "couldn't check the vault for secrets sealed to a lost key: …" | `jit vault import --finish` |
| The key is in the enclave and a key is still in the keychain under its name (usually a copy a move could not delete; S3g) | `vault.keychain_copy_left`: `true` (the keychain item's metadata, no prompt); the status row is red, like doctor's | `vault_key_copy`, a problem | `jit vault rekey --wrapper secure-enclave` (one enclave dialog; deletes the item when it is the same key; a different key is refused, naming `--force`; an unreadable one is refused, worded by the cause: a locked keychain (-25293) is "unlock it and run this again", and an item this copy of jit isn't allowed to read (-25308) or can't use names Keychain Access as the person's choice (the enclave opened, so this vault doesn't need it), never `--force`, whose measure would fail the same way. `--force` needs a typed yes to a question that names the risk, so it refuses `--yes` and a stdin that isn't a terminal, and it first measures the item, which it always reads: one that opens any of this vault's secrets is refused, and so is one it couldn't read or test against every live secret (an unreadable envelope: "jit couldn't test N secrets against that key; it was left alone"); only one read, tried on every secret, and opening none is deleted) |

A rotation resumes only over a marker it can prove is a rotation's (the
`started …` line `jit vault rekey` writes). Resuming over a move this jit
can't read would rewrap under a key the move may be about to delete, so
`jit vault rekey`, with or without `--wrapper`, refuses any other marker.

### A lost key's restore

`jit vault init` renames `vault-key.sealed` to `vault-key.sealed.lost` and
writes `vault-key.sealed.lost.envelopes`: the SHA-256 of every envelope file
under `vault/` (live secrets, `_backups/` and `_history/` alike), all sealed
to the lost key. Envelopes name no key, so this record is the only way to
know, without a key, which envelopes the new key can't open: a restored
envelope has a new data key and different bytes. Init also drops the
service's session on both sides, as rekey does: a service still holding
the lost key would otherwise keep sealing writes under it.

**Init is never blocked.** It is the only way back. A file it can't read
is recorded by name as unknown; a walk that can't see every file marks the
record incomplete. Both fail closed: an unknown file counts as sealed until
it is rewritten after the set-aside (its modification time says so), and an
incomplete record counts every secret as pending, like no record at all.

**Pending counts live secrets only.** `restore_pending` holds while any
live secret's bytes match any recorded hash, whatever path it sits at now:
`jit vault restore <path> --version <old>` renames an archived copy into
place byte for byte. A live file jit can't read counts as pending. Archived
copies are kept, never pending. A record that is there but unreadable is an
error, never "no record": status and doctor report it as pending and say
they couldn't check, and nothing settles on it. Only an absent record (a
vault set aside by an older jit) means every secret counts as pending.

**Settling.** When no live secret is left sealed to the lost key, both files
are renamed with a timestamp, never deleted: if the key was reported lost by
mistake, the sealed file is what could still open the old envelopes. An
import settles it once it has brought everything back; an import with no
usable record settles it anyway and says it couldn't check. `jit vault rm`
settles it once it removes the last one (and, with no record, only once the
vault is empty). An import whose file leaves some out keeps the state and
names them. Neither deletes what it did not name: the secrets an import
could not restore stay on disk, and it is up to the user to import another
file or run `jit vault rm`, which deletes that secret's history too, as rm
always has.

**Copies sealed to the lost key are kept for good.** Every record, current
or retired, keeps two promises for as long as it exists:

- History pruning never deletes an archived version that is, or may be,
  sealed to a lost key, and those versions take none of the five places
  `jit vault history` keeps. "May be" is generous, since keeping is safe:
  a record that couldn't list everything (unknown or incomplete, missing or
  unreadable) keeps every version last written at or before the set-aside
  (the record's own time), or the retirement when that is all jit knows.
  If jit can't read the records at all, it prunes nothing.
- `jit vault rekey` never stops on a PROVEN lost-key copy and never destroys
  one. It still tries the old key first, so an envelope that key opens is
  rotated whatever a record says. An envelope neither key opens is left
  exactly as it is, and reported, only when a readable record lists its
  bytes, or names it as unreadable at the set-aside and it hasn't been
  written since. No key on this Mac ever opened it, so rotating can't make
  it less readable. Anything short of that stops the rotation, as it always
  has, naming the file and saying why jit can't prove it: finishing
  destroys the old master key, so "presumed" is not enough. With no usable
  record, that is every envelope neither key opens.

One rule decides all three (status, history, rekey): proven, presumed, or
not a lost-key copy (`lostKeyRecord.match` in `internal/vault/lostkey.go`).
The records are read once per command, and not at all while a secret has
five versions or fewer.

**The record's format.** Version 2 hashes every envelope file (`files`,
`unknown`, `incomplete`, `set_aside_unix_nano`). Version 1 (never released)
listed live secrets only, under `envelopes`, and is still read: its list
becomes `files`, its set-aside time is the record file's own, and the
`_history/` copies it never listed are presumed, never proven.

**When the record can't say.** A record that is there but unreadable
settles nothing, so it would leave the restore pending forever.
`jit vault import --finish` is the way out, once every recovery file has
been imported: it asks first (or takes `--yes`), renames the lost key's
file and record with a timestamp (never a delete), and lists the secrets
last changed before the key was lost, which may not open. It refuses while
a readable record still lists secrets: an import or `jit vault rm` settles
those. Doctor's `vault_restore` finding names it when
`restore_check_error` is set.

## Phase 2: grant and job keys

`standing-grants.md` has this rule: both keys move, one flag apart. If only
the MEK moved, a grant key in the clear would be the weakest item in the
vault.

- Each grant or never-ask job gets an enclave key **without** `UserPresence`.
  Only the signed service can use it, and it never asks.
- Accessibility **`AfterFirstUnlockThisDeviceOnly`**, not `WhenUnlocked`.
  This is the lock-screen trap from the readiness table: grants and never-ask
  jobs are meant to work while you are away, and today they do only because
  the file keychain ignores the setting. S4 checks it.
- A DEK copy is sealed to the grant key's public half (`wrap:
  "se-p256-v1"`, the name `standing-grants.md` already reserved). Revoking
  deletes the enclave key, and every sealed copy becomes unreadable forever.
- **The move needs no prompt and no re-approval.** On start, the service
  opens each `aead-v1` copy with the old plain grant key (never prompts),
  seals it to a new enclave key (never prompts, S1b), writes the ledger or
  `jobs.json` atomically, then deletes the plain key. An older jit that meets
  `se-p256-v1` refuses it, which is already tested behaviour (`standing.go:271`,
  `job.go:643`).
- Cost: 4.5 ms per secret per use (S1). A three-secret job adds about 14 ms
  to a run.

## Packaging (jit-app)

1. **Apple Developer portal:** an App ID for the helper (`com.jitpass.agent`)
   with the keychain access group above, and a **Developer ID** provisioning
   profile for it. Stored as a CI secret beside `MACOS_SIGN_P12`.
2. **Helper bundle:** `JitPass.app/Contents/Helpers/JitPass Agent.app/Contents/MacOS/jit`,
   with its own `Info.plist` (`CFBundleExecutable = jit`) and
   `embedded.provisionprofile`. The Homebrew cask's `binary` and the app's
   `JitCLI` point at this path. `selfpath.Stable` writes it into the plist.
3. **Signing inside out:** `fetch-jit.sh` still verifies goreleaser's
   signature, then `sign.sh` re-signs the helper with
   `Resources/Agent.entitlements` (`keychain-access-groups`,
   `com.apple.application-identifier`, `com.apple.developer.team-identifier`),
   then signs the outer app. Notarization covers the whole thing as today.
4. **`verify.sh`** asserts the helper's entitlements, the embedded profile's
   team and access group, and the profile's expiry date.
5. **Updating the plist:** the first service start from a new app rewrites
   `com.jitpass.agent.plist` to the helper path. The bundled-jit swap trap
   (remove, copy, re-sign) applies to the helper as well.

`upgrade.go`'s `inAppBundle` already refuses any `.app/Contents/MacOS/` path,
so it covers the nested helper without a change.

## Spike plan

Each spike states what counts as a pass. S1 and S1b ran here
(`spike/secure-enclave-mek/FINDINGS.md`).

| # | Question | Needs | Pass |
|---|---|---|---|
| S1 | Seal and open the MEK with an enclave key | nothing | **Passed 2026-09-25:** identical round trip, tamper and wrong key refused, open p50 4.5 ms |
| S1b | Sealing to a Touch ID key never prompts | nothing | **Passed 2026-09-25:** 0.31 s, no dialog |
| — | **The name in the dialog** | — | S2 found the dialog says "<CFBundleName> is trying to …", so the helper's bundle name is user-facing text. Choose it on purpose ("JitPass") |
| S2 | The prompt: our reason text, the password fallback, one LAContext covering two opens | a human, profile | **Passed 2026-09-25:** the 74-character AI Jobs sentence shows in full; "Use Password…" offered; the same LAContext's second open took 0.008 s with no dialog |
| S3a | A **persistent** enclave key from the helper's main executable | profile | **Passed 2026-09-25:** created, found from two later processes, MEK round trip. Controls reproduce `-34018` (no entitlements) and exit 137 (no bundle). A second executable in the bundle is killed (137); a symlink to the main executable works |
| S3b | The same, started by launchd | profile | **Passed 2026-09-25:** ppid 1, create, find, round trip, delete, exit 0. The prompt from a LaunchAgent is still to see; S2 ran from a terminal |
| S3c | A Go `jit` through a symlink → the helper | profile | **Passed 2026-09-25** via symlink, `PATH` lookup and direct path. The real cask install is confirmed when the helper ships |
| S3d | Hardened runtime blocks a same-user debugger | profile | `lldb -p <agent pid>` is refused |
| S4 | A grant key while the screen is locked | profile, a human | **Passed 2026-09-25:** `AfterFirstUnlock` opened throughout a 45 s lock; `WhenUnlocked` failed `-25308` from about 9 s in. Hold a lock for at least 15 s when testing |
| S3e | Existing installs: the old path as a symlink into the helper | profile | **Passed 2026-09-25:** direct, through an outside symlink, and under launchd; outer app verifies `--strict --deep` |
| S5 | Migration both ways on test identifiers | profile | keychain → enclave → keychain with a test service name and tag; every envelope in a fixture vault opens at each step; a crash injected at each step leaves a working vault |
| S6 | What a new Mac inherits today | a second Mac or a VM | Migration Assistant carries `com.jitpass.vault.mek`: yes or no. Yes means the enclave move needs a recovery step (below) |

S3–S5 are one signed build: a minimal helper bundle made by the spike's own
script, signed with the Developer ID identity and the new profile, on a Mac
where CI's identity is imported. None of them touch the real MEK: test tag
`com.jitpass.spike.kek`, test service names, per `keychainwrap`'s rule that
no test ever shares a production identifier.

## Open decisions

1. **A new Mac.** If S6 says today's key travels with Migration Assistant,
   the enclave takes that away. Options: (a) the migration command requires a
   `jit vault export` first and says why; (b) a second recipient (a recovery
   key the user writes down), which needs `wrappedDEKFor`'s single-recipient
   fallback replaced first (`standing-grants.md`). Recommendation: (a) for
   phase 1; (b) as its own design.
2. **Default or opt-in.** Recommendation: opt-in via `vault rekey --wrapper
   secure-enclave` for one release, then the default for new vaults only,
   then an offer in the app for existing ones. An automatic flip for
   existing vaults is the one-way door `menu-bar-app.md` warns about.
3. **Order against AI Jobs.** AI Jobs and MCP can merge first; nothing on the
   branch depends on how keys are stored. Two follow-ups to keep it that way:
   the orphan-key reconciler both designs still lack must know enclave tags
   as well as `j-` ids, and a job's per-run prompt text must stay within the
   limit S2 measures.
