# Secure Enclave: working plan

**Status (2026-09-25):**

| Step | State |
|---|---|
| Design, spikes, plan | merged, #156 |
| B1 `internal/secureenclave` | merged, #157 |
| B2 `internal/keystore` | merged, #159 |
| B3 per-vault backend | merged, #160 |
| B4 `vault rekey --wrapper` (hidden) | merged, #161; hardware move test passed |
| C1 ledger keeps each wrap | merged, #162 |
| C2 enclave grant and job keys | merged, #163 |
| C3 move existing keys at start | open, #164 |
| C4 delete unused keys at start | open, #165 |
| C5 prompt wording | open, #166 |
| B5 docs | open, this PR |
| A1 helper bundle, A2 entitlement and profile | open, jit-app #52, #53; waiting on a signed test build |
| A4 app UI | not started: now one row in the Settings v2 Protection card (the Settings redesign, not yet approved), not frame A's Vault card |

**Plan, 2026-09-25.** Companion to `secure-enclave.md` (the design,
the readiness table and the spike results). This page is the order of work:
which pull request, in which repo, touching which files, proven by which test.
Built from a read of `main` (jit `ecf558a`), branch `ai-jobs`, and jit-app
`main` on the same day.

Rules that shape the order:

- **AI Jobs goes first.** Nothing here may block or conflict with branch
  `ai-jobs`. Work that edits files that branch edits waits for it to merge.
- **Every step ships alone** and leaves every install working: Homebrew
  cask, website zip, curl tarball, `go install`.
- **The reverse ships before the forward** (`menu-bar-app.md:133`): a vault
  can leave the enclave before any vault can enter it.
- **Each test runs against the code before the change and fails there.**
- **No test ever uses a production identifier**, per `keychainwrap`'s
  incident: test tags and services carry `TEST-ONLY`.

## Decisions (accepted as recommended by Meni, 2026-09-25)

| # | Decision | Decided | Why it matters |
|---|---|---|---|
| D1 | The helper's name (`CFBundleName`) | **JitPass** | The Touch ID dialog reads "*<name>* is trying to …" (S2). Today it says "jit". The folder can be `JitPass Agent.app`; the name users read is `CFBundleName` |
| D2 | Where the sealed master key lives | **`<vault root>/vault-key.sealed`**, and `DeleteLocalState` learns to remove it | `vault delete` today removes only `vault/`, `device.id` and the export marker (`vault/localstate.go:23`). A sealed file it missed would keep choosing the enclave |
| D3 | New Mac | `vault rekey --wrapper secure-enclave` first requires a recent `jit vault export`, and says why | An enclave key never moves to another Mac; today's key probably does (S6 not run) |
| D4 | Opt-in, then default | CLI opt-in for one release, then an app offer, then the default for **new** vaults only | Moving an existing vault automatically is the one-way door |

Also accepted from the mockup's list: the offer lives in Doctor
(Recommended); a recovery file is required before the move; it counts when
it holds as many secrets as the vault (30 days as the fallback); the dialog
says JitPass.

## The work, as pull requests

Sizes: S is up to a day, M is 2–3 days, L is about a week.

### Track A: jit-app, the helper bundle (after jit-app `ai-jobs` merges)

These touch packaging and two Swift files. The AI Jobs session also has a jit-app `ai-jobs` branch, and agreed on 2026-09-25 to say when it merges; track A starts after that, so the two never collide.

**A1. Move `jit` into a helper bundle, with no entitlements yet (M).**
This ships the layout change on its own, so any fallout from moving the path
is separate from any fallout from the Secure Enclave.

- `scripts/lib.sh`: add `HELPER_NAME`, `HELPER_ID=com.jitpass.agent`,
  `HELPER="$APP/Contents/Helpers/$HELPER_NAME.app"`.
- `Resources/Agent-Info.plist` (new): `CFBundleExecutable=jit`,
  `CFBundleIdentifier=com.jitpass.agent`, `CFBundleName` per D1,
  `LSUIElement`. `bundle.sh` copies it and stamps versions like L28–30.
- `scripts/bundle.sh:24`: copy `jit` to `$HELPER/Contents/MacOS/jit`. Keep a
  **compat symlink** `Contents/MacOS/jit → ../Helpers/…/Contents/MacOS/jit`,
  because every existing launchd plist points at the old path
  (`selfpath.Stable` resolved the cask symlink into the bundle) and nothing
  rewrites a plist whose path still exists (`ensureAgentInstalled` repoints
  only an orphaned one, `servicelaunchd.go:321`).
- `scripts/sign.sh:19`: sign inside out. First the helper, with
  `--options runtime --timestamp --identifier jit` (this replaces
  goreleaser's signature, so the hardened runtime must be passed again; the
  identifier stays `jit` because every existing keychain vault key's ACL
  trusts `identifier jit`, spike S3f), then the outer app. Nothing
  uses `--deep`; keep it that way.
- `scripts/verify.sh:35`: the helper path, plus strict verify of the helper,
  its `CFBundleIdentifier` and its `(runtime)` flag.
- `scripts/cask.sh:38`: `binary` points into the helper.
- Swift: one shared `bundledJit` for `JitCLI.swift:14` and
  `StatusItemController+Updates.swift:113`; fixture paths in
  `CommandLineToolTests.swift:28,37,44`.
- **Spike S3e passed 2026-09-25:** the old path as a symlink into the
  helper works run directly, through an outside symlink and under launchd,
  and the outer app still passes `codesign --verify --strict --deep`. Its
  `realpath` is the helper, so `jit service restart` repoints old plists
  (`servicecmds.go:287`); the compat symlink can go a release or two later.
- **Check, not assume:** Full Disk Access is granted to JitPass, the app
  (`ScanReportView+Header.swift:33`). Confirm a scheduled scan still runs
  without prompts after the move, since the service binary gets a new code
  identity.
- Tests: the gate passes; an upgraded install (old plist) still unlocks; a
  fresh install writes the helper path; `jit upgrade` still refuses inside
  the bundle (`upgrade.go:89` matches the nested `.app/Contents/MacOS`).

**A2. Entitlements and the profile (S).** The Developer ID profile exists (2026-09-25, `JitPass Agent Developer ID`); it becomes a CI secret here.

- `Resources/Agent.entitlements` (new): `com.apple.application-identifier
  = CZC6BH93GJ.com.jitpass.agent`, `com.apple.developer.team-identifier`,
  `keychain-access-groups = [CZC6BH93GJ.com.jitpass.vault]`.
  `JitPass.entitlements` stays empty; fix its comment.
- `bundle.sh` embeds `$AGENT_PROFILE` as `embedded.provisionprofile`; it
  must tolerate its absence, because `ci.yml:26` bundles unsigned.
- `release.yml:35–48`: a sixth secret, `MACOS_AGENT_PROFILE` (base64);
  preflight refuses when it is empty. Decode it beside the p12 (L58).
- `gate.sh`: a local sign reads the profile from `~/.apple-signing`.
- `verify.sh`: assert the entitlements, the embedded profile's team,
  app identifier and access group, and at least 90 days left on **both**
  the profile and the certificate inside it. The profile made 2026-09-25
  says 2044, its certificate 2031-07-31; the certificate is the real limit.
- **Spike S3d** on the first Developer ID build: `lldb -p` against the
  helper is refused.

**A4. The app surfaces (M), for R3.** Built from the mockup at
<https://claude.ai/artifact/LUYNYiqniK546yh3WMhA6U> once Meni approves it:
a "Where the vault key is kept" card in Settings › Vault, the move sheet
(recovery file first), the banner and the failure row, the Move Back alert
in `···`, and two Doctor cards (Recommended: the offer; Fix now: the enclave
has no key). It needs the engine to report the backend: `jit doctor
--format json` gains the key's place, so the app runs no new command to
learn it.

**A3. Docs (S).** `menu-bar-app.md` (the Shape drawing L42–50 is stale
twice over; Identity L63–65 moves to `com.jitpass.agent`; phase 3 L129–136;
the stapling risk L217 contradicts `notarize.sh`), CLAUDE.md L114–131 (five
secrets become six; `Contents/MacOS/jit`), README L16–17, L84.

### Track B: jit, the seam (new files can start now; edits after AI Jobs merges)

**B1. `internal/secureenclave`, the package (L). New files only, no
conflicts.** The fifth CGo package.

- C: create, find and delete an enclave key by tag and access group in the
  data-protection keychain; ECIES seal to the public half; open with an
  `LAContext` carrying the reason; a no-prompt presence check
  (`kSecUseAuthenticationUI` fail). Lifted from the spike's `probe.m`.
- Go: the `vault-key.sealed` format (`version`, `wrap:
  "se-p256-ecies-v1"`, `kek_tag`, `blob`), written atomically at 0600;
  `Wrapper` implementing `agent.MEKFetcher`, `ClosableFetcher`,
  `vault.KeyWrapper`, `LabeledKeyWrapper` and `RequireUserPresence(reason)`
  (`vault.go:2723` asserts that method), with the same mlock/wipe/Close
  discipline as `keychainwrap.Wrapper`.
- Key: `UserPresence | PrivateKeyUsage`, `WhenUnlockedThisDeviceOnly`
  (the service already drops its session on lock).
- Tests: the file format and wrapper logic in pure Go with a fake enclave;
  the CGo half through **`scripts/se-test.sh`**, which builds `go test -c`,
  wraps it in a bundle, signs it with the development profile and runs it.
  CI cannot run that half until the Developer ID profile is a CI secret, so
  until then it is a pre-release gate run on a Mac.
- Tag: `com.jitpass.vault.kek`; tests use `…kek.TEST-ONLY.<random>`.

**B2. `internal/keystore`, one factory (M). After AI Jobs merges.** No
behaviour change: it returns `keychainwrap` for every vault.

- `keystore.Open(root)` returns a backend with `Presence()` (no prompt),
  `Fetcher()`, `KeyWrapper()`, `RequireUserPresence()`, `Init()`,
  `Delete()`, and the rekey staging calls.
- Move the eleven call sites: `servicerun.go:136`,
  `vault.go:64,1009,1614,2441,2748,2775`, `vaultrekey.go:64`,
  `uninstallsteps.go:91`, `doctorsections.go:80` (which `status.go` reads),
  `firstrun.go:148`. The last one uses `HasMEK`, which reads the key's
  bytes and can raise the keychain dialog; move it to the no-prompt
  `Presence()` while here.
- Guard test in the style of `TestPaletteIsCentralised`: nothing outside
  `internal/keystore` and `internal/keychainwrap` calls `keychainwrap.New()`.
  It fails on today's tree, which is its negative control.

**B3. Choose the enclave when the vault has one (M).**

- `keystore.Open` returns the enclave backend when `vault-key.sealed`
  exists. A binary that cannot reach the enclave (tarball, `go install`, the
  entitlement missing) refuses with one sentence: *"This vault's key is in
  the Secure Enclave. Use the jit inside JitPass.app."* It never falls back
  to the keychain.
- `vault.DeleteLocalState` removes `vault-key.sealed` (D2);
  `deleteVaultKeys` (`uninstallsteps.go:91`) deletes the enclave key too;
  `jit vault delete` also clears a staged rekey key and marker (it doesn't
  today).
- `doctor` and `status` report the backend ("master key: Secure Enclave" or
  "keychain") and the mixed case: a sealed file with no enclave key is the
  lost-key state, reported as loudly as `MEKAbsent` is now.

**B4. `jit vault rekey --wrapper keychain|secure-enclave` (L).** The
reverse is written and tested first.

- Reuses the marker (`rekey.inprogress`) and resume. Forward: fresh auth,
  read the plain MEK, create the enclave key, seal, write
  `vault-key.sealed.next`, open it again on the **same LAContext** (S2:
  0.008 s, no second dialog), rename, `lockAgent()`, and only then delete
  the plain keychain item. Reverse: open the sealed MEK, write the plain
  item, read it back and compare, then delete the sealed file and the
  enclave key.
- The MEK does not change, so there is no `RewrapAll`: no envelope, grant
  or job is touched. Rotating the MEK stays plain `vault rekey`, which on
  the enclave stages by sealing (S1b: no prompt).
- D3's export check before the forward move.
- Tests: crash injection after every step, each leaving a vault that opens;
  a fixture vault's every envelope opens after each direction; resume from
  each crash point.
- The flag is hidden until A2 has shipped in an app release.

**B4 status (2026-09-25):** built in PR #161. The flag is hidden until A2.
Two dialogs into the enclave (not one: the keychain's and the enclave's are
separate contexts; the mockup's frame D caption needs that correction), one
back. It passed on hardware with TEST-ONLY names.

**B5. Docs (S).** Every sentence the read found false once B1–B4 land:
`keychainwrap.go:6–9,30–32`, `grantkey.go:13–17,23–26`, `rekey.go:127–129`
(already false today), `secureenclave/doc.go`, `vault/keywrapper.go:8–10`,
`vault/doc.go:8–9`, `agent/fetcher.go:14`, `standing.go:59–60`,
`vault.go:2593–2609`, CLAUDE.md L79–85 (four CGo packages become five),
TECH_STACK.md L55–67, L141, L168, L232, L238.

### Track C: grant and job keys (phase 2, after AI Jobs merges and B ships)

**C1. Keep each secret's wrap on save (S). Prerequisite.** `saveLedger`
always writes `Wrap: standingWrapAEAD` (`standing.go:376`), so a ledger with
both wraps would be rewritten wrongly. Store the wrap per secret and write
back what was loaded. Test: load a ledger with an unknown wrap, save it,
and the value survives. It fails today.

**C2. An enclave `GrantKeyStore` (M).** Enclave keys **without**
`UserPresence`, **`AfterFirstUnlockThisDeviceOnly`** (S4: `WhenUnlocked`
fails `-25308` about 9 s into a lock), tag `com.jitpass.grant.<id>`,
`wrap: "se-p256-v1"`. Same `Create/Load/Delete` interface
(`standing.go:61`), so `standing.go` and the AI Jobs `job.go` do not change.
Cost 4.5 ms per secret per use (S1).

**C3. Silent migration at service start (M).** For every `aead-v1` grant
or job secret: open with the old plain key (never prompts), seal to a new
enclave key (never prompts), write the ledger or `jobs.json` atomically,
then delete the plain key. Tests: a crash at each step leaves the grant
serving; an older jit meeting `se-p256-v1` refuses the job
(`job.go:707`) and skips the grant (`standing.go:271`), as today.

**C4. The orphan-key reconciler (M).** Neither design has one yet
(`standing.go:352`, `grant.go:218,279`, `job.go:327`). It lists `g-` and
`j-` keychain items and `com.jitpass.grant.*` enclave tags, and deletes
any the ledger and `jobs.json` don't name, reporting through `doctor`.

**C5. Prompt text (S).** Every reason now reads after "JitPass is trying
to". Re-read the agent's reasons (`caller.go:164–229`, `grant.go:402`,
`consent.go:81`, the AI Jobs `job.go:347,403`) in that frame; the 90-rune
tests stay. The CLI's fixed reasons (`vaultrekey.go:88,92`,
`vault.go:1615,2420`, `uninstall.go:387`) get a length test too.

## Order and releases

```
now          B1 (new files only)
AI Jobs ✓    A1 ──▶ A2 (needs the Developer ID profile) ──▶ A3
             B2 ──▶ B3 ──▶ B4 ──▶ B5
release R1   A1 alone: the helper layout, no Secure Enclave
release R2   A2 + B1–B4: `vault rekey --wrapper secure-enclave`, hidden;
             Meni's own vault first, then the reverse, then forward again
release R3   flag documented; the app's Settings card, move sheet and Doctor offer
             (mockup: https://claude.ai/artifact/LUYNYiqniK546yh3WMhA6U)
release R4   the default for new vaults (D4)
release R5   C1–C5: grant and job keys, migrated silently
```

## Risks and how each is caught

| Risk | Caught by |
|---|---|
| Existing plists point at the old path | Compat symlink, proven by S3e; `jit service restart` repoints |
| Full Disk Access or another permission tied to the old identity | The scheduled-scan check in A1 |
| Keys orphaned by a changed bundle ID or access group | The group is `CZC6BH93GJ.com.jitpass.vault`, not the bundle ID; A2's `verify.sh` asserts it on every release |
| The Developer ID profile or its certificate expires | `verify.sh` refuses under 90 days left on either (the certificate ends first: 2031-07-31) |
| A tarball jit meets an enclave vault | B3's refusal sentence, tested |
| Grants or jobs stop while locked | `AfterFirstUnlock` in C2; S4's recipe (hold the lock 15 s or more) as a manual pre-release check |
| Losing the Mac loses the vault | D3's export check; S6 on a second Mac before R4 |
| Enclave code untested in CI | `scripts/se-test.sh` as a pre-release gate until the profile is a CI secret |
