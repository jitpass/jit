# Spike: the Secure Enclave as the MEK's key-encryption key

Design: `design/secure-enclave.md`. Question: can a Secure Enclave P-256 key
hold jit's existing 32-byte master key sealed (ECIES), so the vault, the
agent's session, grants and AI Jobs keep the MEK they use today and only its
storage at rest changes?

Environment: macOS 27.0 (26A428), Apple Silicon, Go 1.26.4, ad-hoc signed
(`Signature=adhoc`, `TeamIdentifier=not set`). Ad-hoc signing permits only
**ephemeral** enclave keys (`spike/secure-enclave/FINDINGS.md`), so S1 tests
everything except persistence.

## S1: seal and open a MEK with an enclave key (2026-09-25, PASS)

`go build -o sem . && ./sem`

    keygen (SE, ephemeral, presence=false): 7.648791ms
    seal 32-byte MEK: 645.083µs, blob 113 bytes (65 ephemeral pub + 32 ct + 16 tag)
    round trip identical: true
    tampered blob refused: true
    other SE key refused: true
    open  x200: p50 4.468542ms  p99 4.563875ms
    ecdh  x200: p50 5.740959ms  p99 6.1315ms (includes a software peer keygen)

- Algorithm: `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`.
  The sealed MEK is 113 bytes.
- A flipped byte is refused, and so is a different enclave key.
- Opening costs 4.5 ms. That is once per unlock for the MEK. For a key that
  never asks (a grant or a never-ask job), it is once per secret per run:
  about 14 ms for a job with three secrets.

## S1b: sealing never prompts, even to a Touch ID key (2026-09-25, PASS)

`./sem -presence -seal-only`: the key has `kSecAccessControlUserPresence`,
and the program returned in 0.31 s wall time with no dialog. Sealing uses only
the public half. This lets a new MEK (rekey) or a new grant/job key be sealed
without asking, and it is what a later prompt-free Protect would need.

## Signing setup on this Mac (2026-09-25)

- Portal: App ID `CZC6BH93GJ.com.jitpass.agent` (explicit, no capabilities);
  device `Meni MacBook Pro`, Provisioning UDID `00006040-001E488602A3801C`.
- Xcode 27 made `Apple Development: Meni Tasa (PKB9L7KK78)`, `OU=CZC6BH93GJ`,
  valid to 2027-09-25. `security find-identity -v` still said **0 valid**:
  the leaf is issued by WWDR **G3**, and the only WWDR intermediate on the Mac
  was the one that expired 2023-02-07 (System keychain). This is the same
  wall as `spike/secure-enclave/FINDINGS.md`'s 2026-07-11 update, and it will
  hit any new Mac.
- Fix: `AppleWWDRCAG3.cer` from apple.com/certificateauthority
  (SHA-256 `DC:F2:18:78:…:60:1F`, valid to 2030-02-20), verified with
  `openssl verify` against the system's Apple Root CA, then
  `security add-certificates` into the login keychain. After: 1 valid identity.
- Profile `JitPass Agent Dev` (macOS App Development, UUID
  `4825a148-e54a-47e1-9846-9c4c1bdec0ef`, expires 2027-09-25) decoded with
  `security cms -D`: `com.apple.application-identifier =
  CZC6BH93GJ.com.jitpass.agent`, `com.apple.developer.team-identifier =
  CZC6BH93GJ`, **`keychain-access-groups = [CZC6BH93GJ.*]`** (so the
  design's `CZC6BH93GJ.com.jitpass.vault` group is authorized with no portal
  capability), `ProvisionedDevices = [this Mac]`, and its one certificate's
  SHA-1 matches the local identity's (`3DCDB451…F139`).
- Profile `JitPass Agent Developer ID` (Developer ID, UUID
  `e38f5a5f-731c-4e23-82a2-5a5772250e38`, made 2026-09-25): same app
  identifier, team and `keychain-access-groups = [CZC6BH93GJ.*]`,
  `ProvisionsAllDevices = true` (no device list). Its one certificate is
  `Developer ID Application: Meni Tasa (CZC6BH93GJ)`, SHA-1
  `996392D0…0944`, the **same** leaf that signs the shipped JitPass.app and
  its bundled jit (checked with `codesign -d --extract-certificates`), so
  CI's p12 matches it.
- **The profile's own ExpirationDate is 2044-09-20, but its certificate
  expires 2031-07-31**, which is the real limit: `verify.sh` must check the
  embedded certificate's notAfter, not only the profile's (plan A2).
- The Developer ID Application key stays in CI only. Spikes sign with the
  development identity; S3d (debugger refused) needs the Developer ID build.

## S3a: a persistent enclave key from a signed bundle (2026-09-25, PASS)

`s3a/build.sh`, then the commands below. `s3a/sekey.m` is Objective-C
compiled with clang, not Go: the question is about signing and
entitlements, not the language. Test tag `com.jitpass.spike.kek`, access
group `CZC6BH93GJ.com.jitpass.vault`, data-protection keychain, key
`PrivateKeyUsage` only with `AfterFirstUnlockThisDeviceOnly` (the grant-key
shape, so it runs without a prompt). Signed with the development identity,
hardened runtime, `embedded.provisionprofile` = `JitPass Agent Dev`.
Machine: M4 Pro, macOS 27.0.

| Variant | Result |
|---|---|
| Bundle `com.jitpass.agent` + profile + entitlements, main executable | **create OK; found by tag from a 2nd and a 3rd process; MEK round trip identical** |
| Control: same bundle and profile, no entitlements | `-34018` (errSecMissingEntitlement), July's failure |
| Control: entitlements, bare binary, no bundle | **exit 137**, killed at launch, July's failure |
| A second executable in a correctly signed bundle (`Contents/MacOS/jit` beside `CFBundleExecutable`), signed with the entitlements inside out | **exit 137**. The profile authorizes only the bundle's main executable |
| A symlink elsewhere pointing at the bundle's main executable (the `/opt/homebrew/bin/jit` shape) | **create, find, round trip OK** |
| Cleanup | deleted; find → `-25300` |

What it settles:

- The July wall was the missing profile, not the account and not the
  certificate: with a profile, persistence works; without one, both failures
  come back on cue.
- **jit needs its own helper bundle** with `CFBundleExecutable = jit`. It
  cannot stay a second executable inside `JitPass.app`. That was the design's
  assumption and is now measured.
- The Homebrew symlink is fine as long as it points into the helper bundle,
  so the CLI's direct key reads (the eleven call sites) can stay in the CLI
  process. This is S3c's question, answered here for a symlink; the real
  jit binary through the real cask is still to confirm.
- The named access group `CZC6BH93GJ.com.jitpass.vault` works under the
  profile's `CZC6BH93GJ.*` wildcard.

## S3c and S3b: a Go `jit`, through a symlink and from launchd (2026-09-25, PASS)

`s3c/build.sh`: the S3a Objective-C compiled into a **Go** binary (cgo),
named `jit`, as the bundle's `CFBundleExecutable`, same entitlements and
profile.

- **S3c:** through a symlink `…/bin/jit` pointing at the bundle, through a
  `PATH` lookup (`sh -c 'jit find'`), and directly: create, find, MEK round
  trip and delete all OK. `os.Executable()` reports the symlink's path, not
  the bundle's, which is why `selfpath.Stable` resolves it with
  `EvalSymlinks` before writing the plist.
- **S3b:** `launchctl bootstrap gui/$UID` of a plist in the scratchpad (label
  `com.jitpass.spike.s3b`, never in `~/Library/LaunchAgents`); the job ran
  with ppid 1 and did delete, create, find, round trip, delete, **exit 0**.
  Booted out afterwards; `com.jitpass.agent` was never touched.

## S4: a key while the screen is locked (2026-09-25, PASS, the trap is real)

`s2s4/probe s4 180`: two enclave keys, `PrivateKeyUsage` only, one
`AfterFirstUnlockThisDeviceOnly` and one `WhenUnlockedThisDeviceOnly`,
opened every 3 s while Meni locked the screen (⌃⌘Q) for about 45 s.

    10:59:02  LOCKED    ok                 ok
    10:59:08  LOCKED    ok                 ok
    10:59:11  LOCKED    ok                 open failed -25308
    ...
    10:59:44  LOCKED    ok                 open failed -25308
    10:59:47  unlocked  ok                 ok

- `AfterFirstUnlock` opened throughout. `WhenUnlocked` failed with
  **`-25308` (errSecInteractionNotAllowed) from about 9 s after the lock**
  until unlock.
- So a grant or never-ask job key ported with today's
  `WhenUnlockedThisDeviceOnly` would stop while the Mac is locked. Today it
  doesn't, only because the file-based login keychain ignores the setting.
  Grant and job keys must be `AfterFirstUnlockThisDeviceOnly`.
- The ~9 s grace period means a quick lock-and-unlock test would pass
  wrongly; hold the lock for at least 15 s.

## S2: the prompt (2026-09-25, PASS)

`s2s4/probe s2 "<reason>"`: a persistent enclave key with
`PrivateKeyUsage | UserPresence`, the reason set as the `LAContext`'s
`localizedReason` and passed to the lookup as
`kSecUseAuthenticationContext`. The reason was the AI Jobs per-run
sentence, 74 characters. Screenshots were taken by Meni with ⇧⌘4; a
background `screencapture` from the terminal did not capture the dialog.

The dialog read:

> **JitPass Agent Spike is trying to run notion-guests (3 secrets) for
> Claude; it sees output, never the values.**
> Touch ID or enter your password to continue with JitPass Agent Spike.
> [Use Password…] [Cancel]

| Step | Result |
|---|---|
| Open 1, new LAContext | ok, 5.64 s (a person approving) |
| Open 2, **same** LAContext | ok, **0.008 s, no dialog** |
| Open 3, a second new LAContext | ok, 6.71 s; the second dialog offered Use Password… |

- **The name in the dialog is the bundle's `CFBundleName`.** Today's
  keychainwrap prompt reads "jit is trying to …"; after the move it reads
  "<helper name> is trying to …". Choose the name deliberately ("JitPass"),
  and the agent's reason strings must still read correctly after it.
- The 74-character sentence shows in full, wrapped over four lines, not cut
  off; macOS adds the full stop.
- `UserPresence` offers the password in the dialog, so Macs without Touch
  ID are covered. Confirmed on
  hardware 2026-09-25 by the B1 package's interactive test (PR #157): its
  dialog read "Enter the password for the user … to continue with jit
  test", was approved with the login password, and the key opened.
- One LAContext covers several opens: migration step 3 (open what was just
  sealed, to verify) adds no second prompt, and the agent's one-prompt-per-
  unlock holds.

## S3e: existing installs through the old path (2026-09-25, PASS)

`s3e/build.sh` builds the layout track A ships: an outer app
(`OuterSpike.app`, no entitlements) whose old path `Contents/MacOS/jit` is
a **symlink** to `../Helpers/JitPassAgentSpike.app/Contents/MacOS/jit`, the
helper being the S3c Go `jit` with the entitlements and the dev profile.
Signed inside out (helper, then outer). `codesign --verify --strict --deep`
on the outer app: OK.

| Reached as | Result |
|---|---|
| The old path inside the app (what every existing plist names) | create, find, MEK round trip, delete: OK |
| An outside symlink to the old path (today's `/opt/homebrew/bin/jit`) | OK |
| launchd, `ProgramArguments[0]` = the old path, label `com.jitpass.spike.s3e` | ppid 1, `last exit code = 0`, full cycle OK; booted out |

- The compat symlink is enough: an upgraded install keeps its service, its
  PATH link and its plist without a repair step.
- `realpath` of the old path is the helper's path, so `selfpath.Stable`
  (EvalSymlinks) records the new location. `jit service restart`'s
  `agentPlistNeedsRepoint` sees the recorded old path differ and rewrites
  the plist. The old path can be dropped a release or two later.

## S3f: existing keychain keys after the move into a helper (2026-09-25, a bug found and fixed)

Found by the code review of track A1, then measured. `s3f/run.sh` creates a
test login-keychain item the way `kw_ensure_mek` makes every vault's key (a
plain generic password, no access control) from a bare binary signed with
identifier `jit`, then reads it back from three signers. Reads run with user
interaction disallowed, so a would-be dialog comes back as an error code.

| Reader | Result |
|---|---|
| The same `jit` (control) | read OK, no dialog |
| Helper bundle signed as `com.jitpass.agent` (A1 as first built) | **`errSecAuthFailed` (-25293)**: the "wants to use your confidential information" dialog, for every existing user after the update |
| Helper bundle signed with `codesign -i jit` | read OK, no dialog |
| That `-i jit` helper creating, opening and deleting an enclave key (the S3c Go program) | OK: the profile authorizes the entitlement, not the code identifier |

The shipped jit's designated requirement is `identifier jit and anchor apple
generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate
leaf[subject.OU] = CZC6BH93GJ`: a helper CI re-signs with the same Developer
ID certificate and `-i jit` satisfies every clause. jit-app PR #52 now signs
the helper with `--identifier jit`, and `sign.sh` and `verify.sh` refuse any
other identifier.

## B4 on hardware: the move, both ways (2026-09-25, PASS)

Not a spike: the production `keyMover` from PR #161 on the real enclave,
with TEST-ONLY names. Run by Meni:
`PKG=./internal/cli JIT_SE_INTERACTIVE=1 scripts/se-test.sh -test.run TestHardwareMoveRoundTrip`
gave `--- PASS: TestHardwareMoveRoundTrip (11.69s)`, three approvals. The
TEST-ONLY keychain key went into the enclave (keychain dialog, then the
enclave's check of the staged copy, then promote, then the keychain copy
deleted) and came back (enclave dialog, keychain write read back). It was
byte-identical to the original, with no sealed file and no marker left.

## Not run yet

- **S3d** (a same-user debugger is refused): needs the Developer ID build,
  since development signing allows debugging.
- **S5** (migration both ways): left to the implementation's own tests; it
  adds nothing about the platform that S1 and S3 have not shown.
- **S6** (what a new Mac inherits today): needs a second Mac or a VM.
