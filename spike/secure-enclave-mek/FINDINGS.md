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

## Not run here: needs a human or a provisioning profile

Listed with their exit criteria in `design/secure-enclave.md`, section
"Spike plan": S2 (the prompt itself: its wording, the passcode fallback, one
LAContext for two operations), S3 (a persistent key from the signed helper
bundle, from launchd, and from the CLI through the Homebrew symlink), S4
(a grant key while the screen is locked), S5 (the reverse migration), S6
(what a new Mac inherits today).
