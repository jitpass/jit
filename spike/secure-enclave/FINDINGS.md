# Spike Findings: Secure Enclave + Touch ID + ECDH

**Question:** can jit, from Go via CGo, generate a Secure-Enclave-backed key, gate it with Touch ID/passcode, and perform ECDH with it — the foundation RFC.md Pillar II assumes?

**Environment:** macOS 26.5.1, Apple M5 Pro (arm64), Go 1.26.4, Xcode Command Line Tools only (no full Xcode.app).

## Result: core mechanism confirmed working

Running `secure-enclave-spike` (ad-hoc signed, `codesign -s -`) against an **ephemeral** (non-persisted) Secure-Enclave key:

- `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` + `kSecAccessControlBiometryAny` succeeded.
- `SecKeyCopyKeyExchangeResult` (ECDH) against that key returned a 32-byte shared secret.
- **A real Touch ID prompt appeared and was approved by the user during this call** — confirmed by direct observation, not inferred. The biometric gate is real, not a no-op.

This validates the riskiest unknown flagged in TECH_STACK.md §2.3: Go/CGo can drive the Secure Enclave + LocalAuthentication + ECDH flow end-to-end.

## Finding: persisting the key requires a real signing identity — this is a development-time requirement, not just a distribution one

Attempting the same key generation with `kSecAttrIsPermanent: YES` (required for a real MEK, which must survive across separate `jit` process invocations) failed under ad-hoc signing:

```
OSStatus error -34018 (errSecMissingEntitlement)
```

`codesign -dv` on the ad-hoc-signed binary shows `TeamIdentifier=not set` — macOS refuses to write a keychain-backed Secure Enclave key without a code signature carrying a real Team ID. This was previously documented in TECH_STACK.md §5 only as a *distribution* requirement (Gatekeeper blocking unsigned binaries); this spike shows it's also required to develop/test the persistent-key path **locally**, before any distribution question arises.

**Not yet independently re-verified:** the persisted-key path with a real Developer ID / Apple Development signing identity. This machine has only Xcode Command Line Tools installed, not the full Xcode.app needed to get a free "Personal Team" certificate. Deferred deliberately (see decision log below) rather than installing Xcode just to re-confirm a well-documented macOS behavior.

## Decision: defer full persistence re-verification to real signing setup

Rather than installing full Xcode now for a one-off free "Personal Team" cert, persistence gets re-verified naturally once a real Developer ID Application certificate is set up as part of repo/release scaffolding (goreleaser + codesign + notarization pipeline, TECH_STACK.md §5) — that identity is needed for real distribution anyway, so there's no separate signing setup to redo later.

## How to reproduce

```bash
cd spike/secure-enclave
go build -o secure-enclave-spike .
codesign -s - --force secure-enclave-spike   # ad-hoc; sufficient for the ephemeral path only
./secure-enclave-spike
```

Expect: biometry-available check passes, persistent key generation fails with `-34018`, ephemeral generate+ECDH succeeds and prompts Touch ID.

## Update (2026-07-11): the signing identity is necessary but NOT sufficient — the real blocker is a provisioning profile in an `.app` bundle

A real **Apple Development** signing identity was finally obtained (free Xcode "Personal Team", a Team ID present) and the persistent-key path re-tested end-to-end on this machine. **`-34018` does not clear.** The blocker is deeper than "no Team ID," and it collides head-on with jit's distribution model.

What was tested, in order:

1. Fixed the identity itself first: Xcode issued the `Apple Development` leaf but its chain was broken (`find-identity -v` showed 0 valid; `codesign` → *"unable to build chain to self-signed root"*). Cause: only the **expired** (Feb 2023) WWDR intermediate was installed, but the leaf is issued by WWDR **G3**. Installing Apple's public **WWDR G3** intermediate made the identity valid.
2. Signed the spike with the now-valid identity, **no entitlements** → `codesign -dv` shows `TeamIdentifier=<id>`, but persistent gen still `-34018`. **A Team ID alone is not enough.**
3. Added a `keychain-access-groups` entitlement and re-signed → the binary is **SIGKILLed at launch (exit 137)** by AMFI. `keychain-access-groups` is a *restricted* entitlement; with no provisioning profile authorizing it, the kernel refuses to `exec` the binary at all.

Why — from Apple's own documentation, not inference:

- Persisting an SE key needs `kSecAttrIsPermanent: true`, so the item lands in the (data-protection) keychain — ["Protecting keys with the Secure Enclave"](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave).
- Using that keychain requires the `application-identifier` entitlement, and that entitlement **must be authorized by a provisioning profile** — Apple DTS (Quinn), [DevForums 728150](https://developer.apple.com/forums/thread/728150) / [125510](https://developer.apple.com/forums/thread/125510).
- A provisioning profile **cannot be embedded in a bare Mach-O.** Apple's official ["Signing a daemon with a restricted entitlement"](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement) states it verbatim: *"a daemon is a standalone executable, so you can't embed a provisioning profile in it. To get around this limitation, wrap your daemon in an app-like structure."* The profile must live at `<Bundle>.app/Contents/embedded.provisionprofile`, with Hardened Runtime + notarization.

**Consequence for jit:** `go install` and Homebrew *formula* produce a bare Mach-O with no bundle, profile, or notarization — so the SE persistent-key path **cannot work through jit's current distribution shape at all**, no matter the code. Same class of wall as `fifo-reader-identify`'s Endpoint Security finding. This **corrects** the earlier framing (here, in TECH_STACK.md §5, and in `internal/secureenclave`) that a free "Personal Team" cert is "sufficient for local dev/testing" — it is not; the missing piece is the provisioning-profile/`.app`-bundle structure, which a CLI tool has nowhere to carry.

**Path forward (deferred, adoption-gated — decision 2026-07-11):** the SE-bound key would live in the **jit-agent**, shipped as a notarized `.app`-wrapped launchd daemon (`embedded.provisionprofile`, Developer ID, Hardened Runtime), while the `jit` CLI stays a bare `go install` binary talking to it over the existing Unix socket — localizing the distribution change to one component instead of the whole tool. Parked until jit has enough adoption to justify the paid Developer ID + notarization + app-bundle repackaging. `internal/keychainwrap` (app-level `LAContext` challenge) remains the shipped interim until then.
